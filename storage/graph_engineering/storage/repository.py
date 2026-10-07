"""Atomic event/head/snapshot/catalog repository implementation."""

from __future__ import annotations

import copy
import os
import stat
import threading
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from contextvars import ContextVar
from types import MappingProxyType
from typing import Callable, Final

from .codec import (
    canonical_json,
    parse_canonical_json,
    require_jcs_digest,
    require_object_digest,
    semantic_record_digest,
)
from .clock import strict_trusted_now, trusted_now
from .connection import ConnectionFactory, ManagedConnection
from .errors import ObjectIntegrityError, RepositoryConflictError, RepositoryIntegrityError
from .locks import LockedFileRegistry
from .objects import ObjectRepository
from .ports import CommitBatch, CommitResult
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.graph.definition import GraphDefinition, GraphValidationError
from graph_engineering.core.project import ProjectScope
from graph_engineering.core.contracts.immutable import FrozenMap, freeze


FaultHook = Callable[[str], None]
_MAINTENANCE_REPOSITORY_SEAL = object()
_RECOVERY_INSTALLATION_CONTEXT = ContextVar("recovery_installation_context", default=None)


class _RecoveryReadReservation:
    """One allocation's lifetime; transfer keeps the same charge alive."""

    def __init__(self, owner, context, units, byte_count):
        self.owner, self.context = owner, context
        self.units, self.byte_count = units, byte_count
        self.transferred = False
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *ignored):
        if not self.transferred:
            self.release()

    def transfer(self, projection: object) -> None:
        self.owner._require_active()
        if self.closed or self.transferred:
            raise ValueError("recovery reservation was already transferred or released")
        key = id(projection)
        entry = self.owner._projections.setdefault(key, (projection, []))
        if entry[0] is not projection:
            raise ValueError("recovery projection identity changed")
        entry[1].append(self)
        self.transferred = True

    def grow(self, *, units: int, byte_count: int, source_id: str) -> None:
        if self.closed or self.transferred:
            raise ValueError("recovery reservation cannot grow after transfer or release")
        self.owner._charge(self.context, units=units, byte_count=byte_count, source_id=source_id)
        self.units += units
        self.byte_count += byte_count

    def shrink(self, *, units: int, byte_count: int) -> None:
        if (self.closed or self.transferred or type(units) is not int
                or type(byte_count) is not int or not 0 <= units <= self.units
                or not 0 <= byte_count <= self.byte_count):
            raise ValueError("recovery reservation can only shrink before transfer")
        self.context.release_temporary(self.units - units)
        self.context._recovery_result_bytes -= self.byte_count - byte_count
        self.owner.retained_units -= self.units - units
        self.owner.retained_bytes -= self.byte_count - byte_count
        self.units, self.byte_count = units, byte_count

    def release(self) -> None:
        if self.closed:
            raise ValueError("recovery reservation was already released")
        self.context.release_temporary(self.units)
        self.context._recovery_result_bytes -= self.byte_count
        self.owner.retained_units -= self.units
        self.owner.retained_bytes -= self.byte_count
        self.owner._reservations.remove(self)
        self.closed = True


class _RecoveryReadBudget:
    """Private no-I/O owner for the complete cold read's retained allocations.

    The installed WorkContexts still enforce their local limits and work charges.
    This additional owner prevents their individually bounded results from
    exceeding the smallest remaining allowance when retained together.
    """

    def __init__(self, contexts, *, task_id=None, command_scope=None):
        from graph_engineering.core.contracts.resources import WorkContext

        contexts = tuple(dict.fromkeys(contexts))
        if not contexts or any(type(context) is not WorkContext for context in contexts):
            raise ValueError("recovery budget needs exact installed contexts")
        self.contexts = contexts
        self.task_id, self.command_scope = task_id, command_scope
        self._task_binding = (task_id, command_scope)
        self._profiles = tuple(context.profile for context in contexts)
        self._baseline = tuple(context._temporary_units for context in contexts)
        self._byte_baseline = tuple(getattr(context, "_recovery_result_bytes", 0) for context in contexts)
        self.unit_limit = min(context.profile.limits["temporary_units"] - prior
                              for context, prior in zip(contexts, self._baseline))
        self.byte_limit = min(context.profile.limits["result_bytes"] - prior
                              for context, prior in zip(contexts, self._byte_baseline))
        if min(self.unit_limit, self.byte_limit) < 0:
            raise ValueError("installed recovery allowance is already exhausted")
        self.retained_units = self.retained_bytes = 0
        self.peak_units = self.peak_bytes = 0
        self._reservations = set()
        self._projections = {}
        self._active = self._closed = False
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._ports = ()

    def _require_owner(self):
        if self._closed or (self._pid, self._thread) != (os.getpid(), threading.get_ident()):
            raise ValueError("recovery budget is closed or belongs to another thread")

    def _require_current(self):
        self._require_owner()
        if self.task_id != self._task_binding[0] or self.command_scope is not self._task_binding[1]:
            raise ValueError("recovery task or command scope changed")
        if any(context.profile is not profile for context, profile in zip(self.contexts, self._profiles)):
            raise ValueError("installed recovery context changed")

    def _require_active(self):
        self._require_current()
        if (self.task_id is not None and self.command_scope is not None
                and _RECOVERY_INSTALLATION_CONTEXT.get() is not self.contexts[0]):
            raise ValueError("recovery installation context is missing or foreign")
        if not self._active or any(getattr(context, "_recovery_read_budget", None) is not self
                                   for context in self.contexts):
            raise ValueError("recovery budget is not bound to every exact context")
        if any(getattr(port, "_recovery_read_budget", None) is not self for port in self._ports):
            raise ValueError("recovery budget port binding changed")

    @contextmanager
    def bind(self, *, ports: tuple[object, ...]=()) -> Iterator[None]:
        self._require_current()
        control = self.task_id is not None and self.command_scope is not None
        if _RECOVERY_INSTALLATION_CONTEXT.get() is not None:
            raise ValueError("overlapping recovery installation context")
        if control:
            from .migration import InstallationCommandScope
            if (type(self.command_scope) is not InstallationCommandScope
                    or type(self.task_id) is not str or not self.task_id):
                raise ValueError("recovery installation scope or task is invalid")
            ports = (*ports, self.command_scope, self.command_scope._manager)
        ports = tuple(dict.fromkeys(ports))
        if self._active or any(getattr(value, "_recovery_read_budget", None) is not None
                               for value in (*self.contexts, *ports)):
            raise ValueError("overlapping or reentrant recovery budget")
        if any(getattr(context, "_recovery_read_owner", self) is not self for context in self.contexts):
            raise ValueError("recovery context has another retained owner")
        bound, lexical_token = [], None
        try:
            for value in (*self.contexts, *ports):
                value._recovery_read_budget = self
                bound.append(value)
            for context in self.contexts:
                context._recovery_read_owner = self
                if not hasattr(context, "_recovery_result_bytes"):
                    context._recovery_result_bytes = 0
            self._ports, self._active = ports, True
            if control:
                lexical_token = _RECOVERY_INSTALLATION_CONTEXT.set(self.contexts[0])
            yield self
        finally:
            if lexical_token is not None:
                _RECOVERY_INSTALLATION_CONTEXT.reset(lexical_token)
            self._active = False
            self._ports = ()
            for value in reversed(bound):
                if getattr(value, "_recovery_read_budget", None) is self:
                    del value._recovery_read_budget

    def _charge(self, context, *, units, byte_count, source_id):
        self._require_active()
        if (not any(context is item for item in self.contexts)
                or type(units) is not int or type(byte_count) is not int
                or min(units, byte_count) < 0):
            raise ValueError("recovery allocation context or size is invalid")
        if self.retained_units + units > self.unit_limit:
            context.check_limit("temporary_units", context.profile.limits["temporary_units"] + 1,
                                source_id=source_id)
        if self.retained_bytes + byte_count > self.byte_limit:
            context.check_limit("result_bytes", context.profile.limits["result_bytes"] + 1,
                                source_id=source_id)
        context.check_limit("result_bytes", context._recovery_result_bytes + byte_count,
                            source_id=source_id)
        context.acquire_temporary(units, source_id=source_id, operation_path=())
        context._recovery_result_bytes += byte_count
        self.retained_units += units
        self.retained_bytes += byte_count
        self.peak_units = max(self.peak_units, self.retained_units)
        self.peak_bytes = max(self.peak_bytes, self.retained_bytes)
    def reserve(self, context: object, *, units: int, byte_count: int, source_id: str) -> _RecoveryReadReservation:
        self._charge(context, units=units, byte_count=byte_count, source_id=source_id)
        reservation = _RecoveryReadReservation(self, context, units, byte_count)
        self._reservations.add(reservation)
        return reservation

    def remaining(self, context: object) -> tuple[int, int]:
        self._require_active()
        if not any(context is item for item in self.contexts):
            raise ValueError("foreign recovery allocation context")
        return (
            min(self.unit_limit - self.retained_units,
                context.profile.limits["temporary_units"] - context._temporary_units),
            min(self.byte_limit - self.retained_bytes,
                context.profile.limits["result_bytes"] - context._recovery_result_bytes),
        )

    def release_projection(self, projection: object) -> None:
        self._require_owner()
        entry = self._projections.pop(id(projection), None)
        if entry is None or entry[0] is not projection:
            raise ValueError("recovery projection is not owned by this budget")
        for reservation in entry[1]:
            reservation.release()

    def move_projection(self, source: object, target: object) -> None:
        """Move an existing charge when a caller retains the same immutable data."""
        self._require_active()
        entry = self._projections.pop(id(source), None)
        if entry is None or entry[0] is not source:
            raise ValueError("recovery projection is not owned by this budget")
        destination = self._projections.setdefault(id(target), (target, []))
        if destination[0] is not target:
            raise ValueError("recovery projection identity changed")
        destination[1].extend(entry[1])

    def close(self) -> None:
        self._require_owner()
        if self._active:
            raise ValueError("cannot close an active recovery budget")
        self._projections.clear()
        for reservation in tuple(self._reservations):
            reservation.release()
        for context in self.contexts:
            if getattr(context, "_recovery_read_owner", None) is self:
                del context._recovery_read_owner
        self._closed = True


def _recovery_text_size(value):
    # Count without constructing another whole UTF-8 representation.
    return sum(len(character.encode("utf-8", errors="strict")) for character in value)


def _recovery_clear_exception_frames(error):
    """Drop retired payload frames while preserving the original exception."""
    import traceback

    pending, seen = [error], set()
    while pending:
        cause = pending.pop()
        if cause is None or id(cause) in seen:
            continue
        seen.add(id(cause))
        traceback.clear_frames(cause.__traceback__)
        pending.extend((cause.__cause__, cause.__context__))


def _recovery_adopt(root, context, budget, *, record_fields, source_id):
    """Keep existing installed data charged without serializing or copying it.

    The private caller supplies a closed exact-type/field table, never a reader
    callback. Identity deduplication applies to objects, not to container slots
    or separately allocated equal payloads. Walker frames and seen identities
    are admitted before allocation and released after the retained charge moves.
    """
    try:
        if id(root) in budget._projections:
            raise ValueError("recovery configuration is already adopted")

        def children(value: object, names: tuple[str, ...]) -> Iterator[object]:
            if type(value) in (dict, MappingProxyType):
                for key, item in value.items():
                    yield key
                    yield item
            elif type(value) in (tuple, list, set, frozenset):
                yield from value
            else:
                for name in names:
                    yield object.__getattribute__(value, name)

        frames = seen = value = None
        with budget.reserve(context, units=12, byte_count=8, source_id=source_id) as scratch, \
                budget.reserve(context, units=0, byte_count=0, source_id=source_id) as retained:
            try:
                seen, frames = set(), [iter((root,))]
                while frames:
                    try:
                        value = next(frames[-1])
                    except StopIteration:
                        frames.pop()
                        scratch.shrink(units=scratch.units - 4, byte_count=scratch.byte_count)
                        continue
                    identity = id(value)
                    if identity in seen:
                        value = None
                        continue
                    # The ID integer and set slot are scratch, not retained data.
                    scratch.grow(units=2, byte_count=8, source_id=source_id)
                    seen.add(identity)
                    kind, names, slots, payload, headers = type(value), (), 0, 0, 1
                    if kind is str:
                        payload = _recovery_text_size(value)
                    elif kind is bytes:
                        payload = len(value)
                    elif value is None or kind in (bool, int, object):
                        pass
                    elif kind in (tuple, list, set, frozenset):
                        slots = len(value)
                        context.check_limit("array_items", slots, source_id=source_id)
                    elif kind in (dict, MappingProxyType):
                        slots = 2 * len(value)
                        # MappingProxyType owns a view plus its backing mapping.
                        headers += kind is MappingProxyType
                        context.check_limit("array_items", len(value), source_id=source_id)
                    elif kind is FrozenMap:
                        names, slots = ("_values",), 1
                    elif kind in record_fields:
                        names = record_fields[kind]
                        if type(names) is not tuple or any(type(name) is not str for name in names):
                            raise ValueError("recovery configuration field table is invalid")
                        slots = len(names)
                    else:
                        raise ValueError("unsupported recovery configuration type")
                    retained.grow(units=headers + slots + payload, byte_count=payload, source_id=source_id)
                    if slots:
                        context.check_limit("parse_depth", len(frames), source_id=source_id)
                        scratch.grow(units=4, byte_count=0, source_id=source_id)
                        frames.append(children(value, names))
                    value = None
                retained.transfer(root)
                return root
            except BaseException as error:
                _recovery_clear_exception_frames(error)
                raise
            finally:
                root = record_fields = None
                if frames is not None: frames.clear()
                if seen is not None: seen.clear()
                frames = seen = value = None

    except BaseException as error:
        _recovery_clear_exception_frames(error)
        raise
    finally:
        root = record_fields = frames = seen = value = None


@contextmanager
def _recovery_scope(context, *ports):
    """Join the exact lexical owner, or bound a standalone security read."""
    budget = getattr(context, "_recovery_read_budget", None)
    if budget is None:
        budget = _RecoveryReadBudget((context,))
        try:
            with budget.bind(ports=ports):
                yield budget
        finally:
            budget.close()
    else:
        if type(budget) is not _RecoveryReadBudget:
            raise RepositoryIntegrityError("foreign recovery owner")
        budget._require_active()
        if any(getattr(port, "_recovery_read_budget", None) is not budget for port in ports):
            raise RepositoryIntegrityError("recovery participant is not bound")
        yield budget


def _recovery_freeze(value, context, budget, *, source_id):
    from graph_engineering.core.contracts.canonical import canonical_byte_length

    result = None
    try:
        size = canonical_byte_length(value)
        # A JSON byte bounds a scalar payload unit; punctuation bounds the
        # container slots/headers (including FrozenMap's proxy). Four units per
        # byte also cover transient input dictionaries during construction,
        # including empty mappings. Retain the actual closed graph afterward,
        # rather than keeping an entire parser/copy allowance for its lifetime.
        with budget.reserve(context, units=4 * size, byte_count=size, source_id=source_id) as frame:
            result = freeze(value)
            # Recursive constructor dictionaries are gone; only the completed
            # immutable graph overlaps the exact identity walk below.
            frame.shrink(units=2 * size, byte_count=size)
            return _recovery_adopt(result, context, budget, record_fields={}, source_id=source_id)
    except BaseException as error:
        _recovery_clear_exception_frames(error)
        raise
    finally:
        value = result = context = budget = None


def _recovery_record_digest(value, context, budget, *, source_id):
    """Admit a canonical digest after its parser scratch has been retired."""
    from graph_engineering.core.contracts.canonical import canonical_byte_length

    try:
        if budget is None:
            return semantic_record_digest(value)
        size = canonical_byte_length(value)
        with budget.reserve(context, units=6 * size, byte_count=4 * size, source_id=source_id):
            context.emit("digest.input_byte", size, source_id=source_id, operation_path=())
            return semantic_record_digest(value)
    except BaseException as error:
        _recovery_clear_exception_frames(error)
        raise
    finally:
        value = context = budget = None


def _recovery_equal(left, right, context, budget):
    """Exact JSON equality without allocating either canonical serialization."""
    def compare(a: object, b: object, depth: int) -> bool:
        context.check_limit("parse_depth", depth, source_id="recovery-comparison")
        with budget.reserve(context, units=1, byte_count=0, source_id="recovery-comparison"):
            if isinstance(a, Mapping) and isinstance(b, Mapping):
                return len(a) == len(b) and all(key in b and compare(value, b[key], depth + 1)
                                               for key, value in a.items())
            if type(a) in (list, tuple) and type(b) in (list, tuple):
                return len(a) == len(b) and all(compare(x, y, depth + 1) for x, y in zip(a, b))
            return type(a) is type(b) and type(a) in (str, int, bool, type(None)) and a == b
    return compare(left, right, 0)


@contextmanager
def _recovery_rows(connection, groups, parameters, context, budget, *, source_id, ctes=()):
    """Capture fixed internal SELECT groups after a same-statement size gate.

    The metadata branch returns only counts. No large field crosses sqlite3's
    Python boundary unless the entire bounded result fits the reserved space.
    Callers supply only source-code-owned expressions, never user SQL.
    """
    units, byte_count = budget.remaining(context)
    width = max(4, max(len(columns) for _tag, columns, _table in groups))
    # execute returns only the fixed bounds header. Its fresh installation
    # check must finish before the still-unallocated data fields are reserved.
    header_bytes = 8 * (width + 1) + len("bounds")
    header_units = header_bytes + 4 * (width + 1)
    if units < header_units or byte_count < header_bytes:
        raise RepositoryIntegrityError("recovery SQL metadata is over limit")
    with budget.reserve(context, units=header_units, byte_count=header_bytes,
                        source_id=source_id), ExitStack() as fields_scope:
        field_units, field_bytes = units - header_units, byte_count - header_bytes
        ctes, metadata, selections = list(ctes), [], []
        for index, (tag, columns, table) in enumerate(groups):
            names = ["v" + str(i) for i in range(len(columns))]
            projection = ",".join(column + " AS " + name for column, name in zip(columns, names))
            ctes.append(f"g{index} AS NOT MATERIALIZED (SELECT {projection} FROM {table} LIMIT :row_limit)")
            sizes = [f"CASE WHEN typeof({name})='text' THEN length(CAST({name} AS BLOB)) ELSE 8 END" for name in names]
            raw_size = "(" + "+".join(sizes) + ")"
            invalid = " OR ".join(
                f"typeof({name}) NOT IN ('text','integer','null') OR "
                f"(typeof({name})='text' AND length(CAST({name} AS BLOB))>:text_limit)" for name in names)
            metadata.append(f"SELECT COUNT(*) AS n,COALESCE(SUM({raw_size}),0) AS b,"
                            f"COALESCE(SUM({raw_size}+{4 * len(columns) + 4}),0) AS u,"
                            f"COALESCE(SUM(CASE WHEN {invalid} THEN 1 ELSE 0 END),0) AS bad FROM g{index}")
            padded = names + ["NULL"] * (width - len(names))
            selections.append("SELECT '" + tag + "'," + ",".join(padded)
                              + f" FROM g{index},bounds WHERE bounds.n<=:max_rows "
                              "AND bounds.b<=:byte_limit AND bounds.u<=:unit_limit AND bounds.bad=0")
        ctes.append("sizes AS (" + " UNION ALL ".join(metadata) + ")")
        ctes.append("bounds AS (SELECT SUM(n) AS n,SUM(b) AS b,SUM(u) AS u,SUM(bad) AS bad FROM sizes)")
        header = ["n", "b", "u", "bad"] + ["NULL"] * (width - 4)
        query = "WITH " + ",".join(ctes) + " SELECT 'bounds'," + ",".join(header) + " FROM bounds"
        query += " UNION ALL " + " UNION ALL ".join(selections)
        values = dict(parameters)
        values.update(row_limit=context.profile.limits["array_items"] + 1,
                      max_rows=context.profile.limits["array_items"],
                      text_limit=context.profile.limits["raw_document_bytes"],
                      byte_limit=field_bytes, unit_limit=field_units)
        cursor = connection.execute(query, values)
        captured = {tag: [] for tag, _columns, _table in groups}
        lengths = {tag: len(columns) for tag, columns, _table in groups}
        try:
            row = cursor.fetchone()
            if row is None or row[0] != "bounds" or any(type(value) is not int for value in row[1:5]):
                raise RepositoryIntegrityError("recovery SQL bounds are invalid")
            count, raw_bytes, raw_units, invalid = row[1:5]
            context.check_limit("array_items", count, source_id=source_id)
            if invalid or raw_bytes > field_bytes or raw_units > field_units:
                raise RepositoryIntegrityError("recovery SQL value or aggregate is over limit")
            fields_scope.enter_context(budget.reserve(context, units=raw_units, byte_count=raw_bytes,
                source_id=source_id))
            seen = 0
            while (row := cursor.fetchone()) is not None:
                if row[0] not in lengths or seen >= count:
                    raise RepositoryIntegrityError("recovery SQL result changed")
                fields = row[1:1 + lengths[row[0]]]
                if any(type(value) not in (str, int, type(None)) for value in fields):
                    raise RepositoryIntegrityError("recovery SQL type is invalid")
                captured[row[0]].append(fields)
                seen += 1
            if seen != count:
                raise RepositoryIntegrityError("recovery SQL capture is incomplete")
            yield captured
        finally:
            try:
                cursor.close()
            finally:
                captured.clear()
                row = fields = None


@contextmanager
def _recovery_json(encoded, context, budget, *, source_id):
    from graph_engineering.core.contracts.strict_json import parse_json

    body = value = None
    try:
        size = len(encoded) if type(encoded) is bytes else _recovery_text_size(encoded)
        context.check_limit("raw_document_bytes", size, source_id=source_id)
        # SQL input is separately owned; encoding, parsed strings and
        # simultaneous raw/decoded long-token copies must also remain charged.
        with budget.reserve(context, units=6 * size, byte_count=6 * size, source_id=source_id):
            try:
                body = encoded if type(encoded) is bytes else encoded.encode("utf-8")
                value = parse_json(body, context=context, source_id=source_id, operation_path=context.child_path(()))
                if canonical_json(value) != body.decode("utf-8"):
                    raise RepositoryIntegrityError("recovery JSON is not canonical")
                yield value
            except BaseException as error:
                _recovery_clear_exception_frames(error)
                raise
            finally:
                value = body = encoded = None
    except BaseException as error:
        _recovery_clear_exception_frames(error)
        raise
    finally:
        value = body = encoded = None


def _no_fault(_step: str) -> None:
    return


EVENT_KEYS: Final[frozenset[str]] = frozenset({
    "schema_version", "task_id", "sequence", "event_id", "event_type", "occurred_at",
    "actor", "expected_task_revision", "baseline_digests", "payload",
    "previous_event_digest", "event_digest",
})


def event_digest(event: Mapping[str, object]) -> str:
    projection = dict(event)
    projection.pop("event_digest", None)
    return semantic_record_digest({"contract": "event-envelope-v1", "value": projection})


def make_event(
    *,
    task_id: str,
    sequence: int,
    event_id: str,
    event_type: str,
    occurred_at: str,
    actor: dict[str, object],
    expected_task_revision: int,
    baseline_digests: list[str],
    payload: dict[str, object],
    previous_event_digest: str | None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0",
        "task_id": task_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": copy.deepcopy(actor),
        "expected_task_revision": expected_task_revision,
        "baseline_digests": list(baseline_digests),
        "payload": copy.deepcopy(payload),
        "previous_event_digest": previous_event_digest,
    }
    value["event_digest"] = event_digest(value)
    return value


class TaskRepository:
    def __init__(
        self,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        *,
        fault_hook: FaultHook = _no_fault,
        action_journal: object | None = None,
        concrete_action_schemas: object | None = None,
        concrete_action_context: object | None = None,
        command_scope: object | None = None,
        extension_pin_authority: object | None = None,
        _maintenance_seal: object | None = None,
    ) -> None:
        if command_scope is not None:
            from .migration import InstallationCommandScope
            if type(command_scope) is not InstallationCommandScope:
                raise RepositoryIntegrityError("repository command scope is missing or forged")
            factory = factory.bind_command_scope(command_scope)
            command_scope.require_current()
            self._context_validator: Callable[[], None] | None = command_scope.require_current
            self._command_scope = command_scope
        elif _maintenance_seal is _MAINTENANCE_REPOSITORY_SEAL:
            self._context_validator = None
            self._command_scope = None
        else:
            raise RepositoryIntegrityError("repository production command scope is required")
        self._factory = factory
        self._locks = locks
        self._objects = objects
        self._fault = fault_hook
        if action_journal is not None:
            from .actions import ActionJournalRepository
            if type(action_journal) is not ActionJournalRepository:
                raise RepositoryIntegrityError("repository action verifier is not exact")
        self._action_journal = action_journal
        if concrete_action_schemas is not None or concrete_action_context is not None:
            from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
            from graph_engineering.core.contracts.resources import WorkContext
            if (
                type(concrete_action_schemas) is not ClosedSchemaRegistry
                or type(concrete_action_context) is not WorkContext
            ):
                raise RepositoryIntegrityError(
                    "concrete action repository schemas are missing or forged",
                )
        self._concrete_action_schemas = concrete_action_schemas
        self._concrete_action_context = concrete_action_context
        if extension_pin_authority is not None:
            from .extension_activation import ExtensionTaskPinAuthority

            try:
                ExtensionTaskPinAuthority.require_attested(extension_pin_authority)
            except Exception as error:
                raise RepositoryIntegrityError(
                    "extension task pin authority is missing or forged",
                ) from error
            if command_scope is None or extension_pin_authority._scope is not command_scope:
                raise RepositoryIntegrityError(
                    "extension task pin authority is not bound to the repository command scope",
                )
        self._extension_pin_authority = extension_pin_authority

    def dependency_security_clock_ns(self) -> int:
        """Return the repository-owned strict clock for advisory currentness."""

        if self._context_validator is None:
            raise RepositoryIntegrityError(
                "dependency security clock requires a production command scope",
            )
        self._context_validator()
        with self._factory.open("application") as connection:
            return strict_trusted_now(connection)

    @classmethod
    def _for_maintenance(
        cls,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        *,
        fault_hook: FaultHook = _no_fault,
        action_journal: object | None = None,
    ) -> TaskRepository:
        maintenance_factory = factory._for_maintenance()
        return cls(
            maintenance_factory, locks, objects,
            fault_hook=fault_hook, action_journal=action_journal,
            _maintenance_seal=_MAINTENANCE_REPOSITORY_SEAL,
        )

    @property
    def command_context_bound(self) -> bool:
        return self._context_validator is not None

    @property
    def command_scope(self) -> object:
        if self._command_scope is None:
            raise RepositoryIntegrityError("maintenance repository has no command scope")
        return self._command_scope

    def _require_command_context(self) -> None:
        if self._context_validator is None:
            raise RepositoryIntegrityError("repository production command context is missing")
        self._context_validator()

    @staticmethod
    def _validate_identity(value: object, label: str) -> str:
        if type(value) is not str or not value:
            raise RepositoryIntegrityError(f"{label} is invalid")
        return value

    @classmethod
    def _validate_event(
        cls,
        event: object,
        *,
        task_id: str,
        sequence: int,
        expected_revision: int,
        previous_digest: str | None,
        _copy: bool = True,
    ) -> dict[str, object]:
        if not isinstance(event, dict) or set(event) != EVENT_KEYS:
            raise RepositoryIntegrityError("event envelope shape is not exact")
        if (
            event["schema_version"] != "1.0"
            or event["task_id"] != task_id
            or type(event["sequence"]) is not int
            or event["sequence"] != sequence
            or type(event["expected_task_revision"]) is not int
            or event["expected_task_revision"] != expected_revision
            or event["previous_event_digest"] != previous_digest
        ):
            raise RepositoryIntegrityError("event sequence, revision, or chain is invalid")
        for name in ("event_id", "event_type", "occurred_at"):
            cls._validate_identity(event[name], name)
        if type(event["actor"]) is not dict or type(event["payload"]) is not dict:
            raise RepositoryIntegrityError("event actor or payload is not an object")
        baselines = event["baseline_digests"]
        if (
            not isinstance(baselines, list)
            or any(type(item) is not str for item in baselines)
            or baselines != sorted(set(baselines))
        ):
            raise RepositoryIntegrityError("event baseline digests are not canonical")
        if previous_digest is not None:
            require_jcs_digest(previous_digest)
        require_jcs_digest(event["event_digest"])
        if event["event_digest"] != event_digest(event):
            raise RepositoryIntegrityError("event digest mismatch")
        canonical_json(event)
        return copy.deepcopy(event) if _copy else event

    @classmethod
    def _validate_batch(cls, batch: CommitBatch) -> None:
        cls._validate_identity(batch.transaction_id, "transaction ID")
        cls._validate_identity(batch.task_id, "task ID")
        if type(batch.expected_task_revision) is not int or batch.expected_task_revision < 0:
            raise RepositoryIntegrityError("expected task revision is invalid")
        if not batch.events or any(type(item) is not dict for item in batch.events):
            raise RepositoryIntegrityError("commit event batch is empty or invalid")
        if (
            type(batch.snapshot) is not dict
            or type(batch.catalog_delta) is not dict
            or type(batch.lease_assertion) is not dict
        ):
            raise RepositoryIntegrityError("snapshot, catalog delta, or lease assertion is invalid")
        if (
            any(type(item) is not str for item in batch.object_digests)
            or tuple(sorted(set(batch.object_digests))) != batch.object_digests
        ):
            raise RepositoryIntegrityError("object digest set is not canonical")
        for digest in batch.object_digests:
            require_object_digest(digest)
        canonical_json(batch.snapshot)
        canonical_json(batch.catalog_delta)
        canonical_json(batch.lease_assertion)
        if batch.extension_pin_delta is not None and (
            type(batch.extension_pin_delta) is not dict
            or set(batch.extension_pin_delta) != {"operation", "pin_digest"}
            or batch.extension_pin_delta.get("operation") not in {"create", "rebase"}
            or type(batch.extension_pin_delta.get("pin_digest")) is not str
        ):
            raise RepositoryIntegrityError("extension task pin delta is not exact")
        if batch.extension_pin_delta is not None:
            expected_extension_event = {
                "create": "task.created", "rebase": "task.extension_pin_rebased",
            }[str(batch.extension_pin_delta["operation"])]
            if (
                len(batch.events) != 1
                or batch.events[0].get("event_type") != expected_extension_event
                or expected_extension_event == "task.extension_pin_rebased"
                and batch.events[0].get("payload")
                != {"pin_digest": batch.extension_pin_delta["pin_digest"]}
            ):
                raise RepositoryIntegrityError(
                    "extension task pin is not in its exact task event transaction",
                )
        if batch.concrete_action_delta is not None:
            delta = batch.concrete_action_delta
            operation = delta.get("operation") if type(delta) is dict else None
            expected = {
                "invocation": ("start", "action.execution_started"),
                "receipt": ("receipt", "action.receipt_recorded"),
                "observation": ("reconcile", "action.reconciled_effect_verified"),
            }.get(operation)
            if (
                type(delta) is not dict
                or set(delta) != {"operation", "record"}
                or type(delta.get("record")) is not dict
                or expected is None
                or type(batch.action_journal_delta) is not dict
                or batch.action_journal_delta.get("operation") != expected[0]
                or len(batch.events) != 1
                or batch.events[0].get("event_type") != expected[1]
            ):
                raise RepositoryIntegrityError(
                    "concrete action record is not in its exact coordination transaction",
                )
        if batch.claim_compensation_delta is not None and (
            batch.claim_delta is not None or batch.claim_reconciliation_delta is not None
        ):
            raise RepositoryIntegrityError(
                "claim compensation cannot be combined with another claim mutation class",
            )
        if batch.claim_compensation_delta is not None:
            compensation_operation = batch.claim_compensation_delta.get("operation")
            expected_journal_operation = {
                "start_claim_compensation": "compensation_start",
                "record_compensation_receipt": "compensation_receipt",
                "reconcile_claim_compensation": "compensation_reconcile",
            }.get(batch.claim_compensation_delta.get("operation"))
            expected_objects: tuple[object, ...] = (
                (batch.claim_compensation_delta.get("receipt_object_digest"),)
                if compensation_operation == "record_compensation_receipt"
                else ()
            )
            if (
                expected_journal_operation is None
                or type(batch.action_journal_delta) is not dict
                or batch.action_journal_delta.get("operation") != expected_journal_operation
                or batch.catalog_delta
                or batch.object_digests != expected_objects
            ):
                raise RepositoryIntegrityError(
                    "claim compensation transaction contains a missing or unrelated mutation",
                )
        elif (
            type(batch.action_journal_delta) is dict
            and batch.action_journal_delta.get("operation") == "receipt"
        ):
            receipt = batch.action_journal_delta.get("receipt")
            if (
                type(receipt) is not dict
                or batch.object_digests != (receipt.get("raw_receipt_object_digest"),)
            ):
                raise RepositoryIntegrityError(
                    "action receipt transaction requires its exact durable object reference",
                )

    @staticmethod
    def _request_value(batch: CommitBatch) -> dict[str, object]:
        return {
            "transaction_id": batch.transaction_id,
            "task_id": batch.task_id,
            "expected_task_revision": batch.expected_task_revision,
            "events": list(batch.events),
            "snapshot": batch.snapshot,
            "catalog_delta": batch.catalog_delta,
            "lease_assertion": batch.lease_assertion,
            "object_digests": list(batch.object_digests),
            "claim_delta": batch.claim_delta,
            "claim_reconciliation_delta": batch.claim_reconciliation_delta,
            "claim_compensation_delta": batch.claim_compensation_delta,
            "action_journal_delta": batch.action_journal_delta,
            "project_scope_delta": batch.project_scope_delta,
            "lifecycle_assertion": batch.lifecycle_assertion,
            "lifecycle_plan_delta": batch.lifecycle_plan_delta,
            "concrete_action_delta": batch.concrete_action_delta,
            "extension_pin_delta": batch.extension_pin_delta,
        }

    @staticmethod
    def _extension_binding_digest(body: Mapping[str, object]) -> str:
        return semantic_record_digest({
            "contract": "task-extension-pin-binding-v1", "value": dict(body),
        })

    def _extension_pin_rows_locked(
        self,
        connection: ManagedConnection,
        task_id: str,
    ) -> list[dict[str, object]]:
        rows = connection.execute(
            "SELECT generation,pin_digest,previous_pin_digest,binding_json,"
            "binding_digest,transaction_id FROM task_extension_pin_bindings "
            "WHERE task_id=? ORDER BY generation",
            (task_id,),
        ).fetchall()
        result: list[dict[str, object]] = []
        previous: str | None = None
        for expected_generation, row in enumerate(rows, start=1):
            body = parse_canonical_json(row[3])
            if not isinstance(body, dict):
                raise RepositoryIntegrityError("task extension pin binding is not an object")
            expected_fields = {
                "schema_version", "task_id", "generation", "pin_digest",
                "previous_pin_digest", "pin_record", "transaction_id",
            }
            pin_record = body.get("pin_record")
            if (
                set(body) != expected_fields
                or body.get("schema_version") != "1.0.0"
                or body.get("task_id") != task_id
                or body.get("generation") != expected_generation
                or body.get("pin_digest") != row[1]
                or body.get("previous_pin_digest") != previous
                or body.get("transaction_id") != row[5]
                or not isinstance(pin_record, dict)
                or pin_record.get("record_digest") != row[1]
                or row[0] != expected_generation
                or row[2] != previous
                or row[4] != self._extension_binding_digest(body)
            ):
                raise RepositoryIntegrityError("task extension pin binding chain is invalid")
            require_jcs_digest(str(row[1]))
            require_jcs_digest(str(row[4]))
            transaction = connection.execute(
                "SELECT task_id,revision FROM transactions WHERE transaction_id=?",
                (row[5],),
            ).fetchone()
            event_rows = connection.execute(
                "SELECT event_type,body_json FROM events WHERE transaction_id=? ORDER BY sequence",
                (row[5],),
            ).fetchall()
            expected_event = "task.created" if expected_generation == 1 else "task.extension_pin_rebased"
            event = parse_canonical_json(event_rows[0][1]) if len(event_rows) == 1 else None
            if (
                transaction is None
                or transaction[0] != task_id
                or type(transaction[1]) is not int
                or len(event_rows) != 1
                or event_rows[0][0] != expected_event
                or not isinstance(event, dict)
                or expected_generation > 1
                and event.get("payload") != {"pin_digest": row[1]}
            ):
                raise RepositoryIntegrityError(
                    "task extension pin transaction binding is invalid",
                )
            result.append(body)
            previous = str(row[1])
        return result

    @staticmethod
    def _extension_pin_matches_snapshot(
        pin: Mapping[str, object],
        snapshot: Mapping[str, object],
    ) -> bool:
        domain = snapshot.get("domain")
        identity = domain.get("identity") if isinstance(domain, Mapping) else None
        graph_ref = domain.get("graph_ref") if isinstance(domain, Mapping) else None
        return bool(
            isinstance(identity, Mapping)
            and pin.get("task_id") == snapshot.get("task_id")
            and pin.get("owner_id") == identity.get("owner_id")
            and pin.get("runtime_kind") == identity.get("runtime_kind")
            and pin.get("runtime_lineage_id") == identity.get("runtime_lineage_id")
            and (
                not graph_ref
                or isinstance(graph_ref, Mapping)
                and graph_ref.get("graph_digest") == pin.get("graph_digest")
            )
        )

    def _load_pin_from_authority(
        self,
        pin_digest: str,
        *,
        require_current: bool,
    ) -> dict[str, object]:
        if self._extension_pin_authority is None:
            raise RepositoryIntegrityError("extension task is unavailable")
        try:
            return self._extension_pin_authority.load(
                pin_digest, require_current=require_current,
            )
        except Exception as error:
            raise RepositoryIntegrityError("extension task is unavailable") from error

    def _validate_extension_pin_commit_locked(
        self,
        connection: ManagedConnection,
        batch: CommitBatch,
        *,
        task_exists: bool,
    ) -> dict[str, object] | None:
        bindings = self._extension_pin_rows_locked(connection, batch.task_id)
        delta = batch.extension_pin_delta
        if not bindings and delta is None:
            return None
        if delta is None:
            pin = self._load_pin_from_authority(
                str(bindings[-1]["pin_digest"]), require_current=True,
            )
            if not self._extension_pin_matches_snapshot(pin, batch.snapshot):
                raise RepositoryIntegrityError("extension task is unavailable")
            return None
        operation = str(delta["operation"])
        if operation == "create" and (task_exists or bindings):
            raise RepositoryIntegrityError("extension task create pin is not initial")
        if operation == "rebase" and (not task_exists or not bindings):
            raise RepositoryIntegrityError("extension task rebase has no prior pin")
        if operation == "rebase":
            self._load_pin_from_authority(
                str(bindings[-1]["pin_digest"]), require_current=False,
            )
        pin = self._load_pin_from_authority(str(delta["pin_digest"]), require_current=True)
        if not self._extension_pin_matches_snapshot(pin, batch.snapshot):
            raise RepositoryIntegrityError("extension task is unavailable")
        generation = len(bindings) + 1
        previous = None if not bindings else bindings[-1]["pin_digest"]
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "task_id": batch.task_id,
            "generation": generation,
            "pin_digest": pin["record_digest"],
            "previous_pin_digest": previous,
            "pin_record": pin,
            "transaction_id": batch.transaction_id,
        }
        return {**body, "binding_digest": self._extension_binding_digest(body)}

    def _validate_current_extension_pin_locked(
        self,
        connection: ManagedConnection,
        task_id: str,
    ) -> dict[str, object] | None:
        bindings = self._extension_pin_rows_locked(connection, task_id)
        if not bindings:
            return None
        pin = self._load_pin_from_authority(
            str(bindings[-1]["pin_digest"]), require_current=True,
        )
        return {**bindings[-1], **pin}

    @staticmethod
    def _scope_source_digest(source: Mapping[str, object]) -> str:
        return semantic_record_digest({"contract": "project-scope-source-v1", "value": source})

    @staticmethod
    def identity_observation_digest(source: Mapping[str, object]) -> str:
        return semantic_record_digest({
            "contract": "repository-identity-observation-v1", "value": source,
        })

    @staticmethod
    def lifecycle_facts_digest(source: Mapping[str, object]) -> str:
        body = dict(source)
        body.pop("facts_digest", None)
        return semantic_record_digest({"contract": "lifecycle-facts-v1", "value": body})

    @staticmethod
    def _scope_projection(source: Mapping[str, object]) -> dict[str, object]:
        try:
            repositories = [{
                key: item[key]
                for key in (
                    "binding_id", "mode", "vcs", "canonical_identity", "planned_target_id",
                    "allowed_path_boundary", "default_branch_ref", "command_refs",
                )
            } for item in source["repositories"]]  # type: ignore[index]
            environments = [{
                key: item[key]
                for key in (
                    "binding_id", "kind", "canonical_identity", "service_ids", "sensitivity",
                    "operation_classes", "target_state_validator_ref",
                )
            } for item in source["environments"]]  # type: ignore[index]
            return {
                "schema_version": source["schema_version"], "scope_id": source["scope_id"],
                "version": source["version"], "mode": source["mode"],
                "repositories": repositories, "services": source["services"],
                "environments": environments, "target_bindings": source["target_bindings"],
                "discovery_digest": source["discovery_digest"],
            }
        except (KeyError, TypeError) as error:
            raise RepositoryIntegrityError("durable ProjectScope source is malformed") from error

    @classmethod
    def _scope_change(
        cls,
        current_source: Mapping[str, object],
        candidate_source: Mapping[str, object],
    ) -> dict[str, object]:
        before = cls._scope_projection(current_source)
        after = cls._scope_projection(candidate_source)
        if before["scope_id"] != after["scope_id"]:
            raise RepositoryIntegrityError("ProjectScope identity cannot change")
        if before == after:
            if (
                candidate_source.get("version") != current_source.get("version")
                or type(candidate_source.get("metadata_revision")) is not int
                or type(current_source.get("metadata_revision")) is not int
                or candidate_source["metadata_revision"] <= current_source["metadata_revision"]  # type: ignore[operator]
            ):
                raise RepositoryIntegrityError("metadata-only ProjectScope revision is invalid")
            body: dict[str, object] = {
                "change_class": "metadata-only", "changed_binding_ids": [],
                "invalidated_target_ids": [], "requires_reapproval": False,
                "requires_authority_expansion": False,
            }
        else:
            if candidate_source.get("version") != current_source.get("version", 0) + 1:  # type: ignore[operator]
                raise RepositoryIntegrityError("semantic ProjectScope version is not consecutive")
            changed: set[str] = set()
            for group in ("repositories", "services", "environments", "target_bindings"):
                identity = "target_id" if group == "target_bindings" else "binding_id"
                left = {item[identity]: item for item in before[group]}  # type: ignore[index]
                right = {item[identity]: item for item in after[group]}  # type: ignore[index]
                changed.update(key for key in left.keys() | right.keys() if left.get(key) != right.get(key))
            invalidated: list[str] = []
            left_targets = {item["target_id"]: item for item in before["target_bindings"]}  # type: ignore[index]
            right_targets = {item["target_id"]: item for item in after["target_bindings"]}  # type: ignore[index]
            for target_id in sorted(left_targets.keys() | right_targets.keys()):
                target = left_targets.get(target_id) or right_targets[target_id]
                refs = tuple(target["repository_ids"] + target["service_ids"] + target["environment_ids"])
                if target_id in changed or any(item in changed for item in refs):
                    invalidated.append(target_id)
            before_resources = {
                resource
                for target in before["target_bindings"]  # type: ignore[union-attr]
                for resource in target["resource_ids"]
            }
            after_resources = {
                resource
                for target in after["target_bindings"]  # type: ignore[union-attr]
                for resource in target["resource_ids"]
            }
            before_operations = {
                operation
                for environment in before["environments"]  # type: ignore[union-attr]
                for operation in environment["operation_classes"]
            }
            after_operations = {
                operation
                for environment in after["environments"]  # type: ignore[union-attr]
                for operation in environment["operation_classes"]
            }
            added_resources = sorted(after_resources - before_resources)
            added_operations = sorted(after_operations - before_operations)
            expansion = bool(added_resources or added_operations)
            body = {
                "change_class": "authority-expansion" if expansion else "semantic",
                "changed_binding_ids": sorted(changed), "invalidated_target_ids": invalidated,
                "requires_reapproval": True, "requires_authority_expansion": expansion,
                "added_resource_ids": added_resources,
                "added_operation_classes": added_operations,
            }
        body["change_digest"] = semantic_record_digest({
            "contract": "project-scope-change-v1", "current_scope_digest": current_source["scope_digest"],
            "candidate_scope_digest": candidate_source["scope_digest"], "change": body,
        })
        return body

    @classmethod
    def _bind_scope_run_dependencies(
        cls,
        current_source: Mapping[str, object],
        candidate_source: Mapping[str, object],
        change: Mapping[str, object],
        snapshot_json: object,
        graph: object,
    ) -> dict[str, object]:
        if type(graph) is not GraphDefinition or not isinstance(snapshot_json, Mapping):
            raise RepositoryIntegrityError("durable task snapshot is malformed")
        domain = snapshot_json.get("domain")
        runs = domain.get("node_runs") if isinstance(domain, Mapping) else None
        graph_ref = domain.get("graph_ref") if isinstance(domain, Mapping) else None
        if (
            not isinstance(runs, Mapping)
            or not isinstance(graph_ref, Mapping)
            or graph_ref.get("graph_id") != graph.graph_id
            or graph_ref.get("graph_version") != graph.graph_version
            or graph_ref.get("graph_digest") != graph.digest
        ):
            raise RepositoryIntegrityError("durable node-run dependency state is malformed")
        invalidated_targets = change.get("invalidated_target_ids")
        if not isinstance(invalidated_targets, list):
            raise RepositoryIntegrityError("ProjectScope invalidated targets are malformed")
        targets: dict[str, Mapping[str, object]] = {}
        for source in (current_source, candidate_source):
            values = source.get("target_bindings")
            if not isinstance(values, list):
                raise RepositoryIntegrityError("ProjectScope TargetBindings are malformed")
            for target in values:
                if not isinstance(target, Mapping) or type(target.get("target_id")) is not str:
                    raise RepositoryIntegrityError("ProjectScope TargetBinding is malformed")
                targets[target["target_id"]] = target  # type: ignore[index]
        normalized_runs: dict[str, Mapping[str, object]] = {}
        run_fields = {"run_id", "node_id", "attempt", "status"}
        for run_id, record in runs.items():
            if (
                type(run_id) is not str
                or not isinstance(record, Mapping)
                or set(record) != run_fields
                or record.get("run_id") != run_id
                or type(record.get("node_id")) is not str
                or record.get("node_id") not in graph.nodes
                or type(record.get("attempt")) is not int
                or record.get("attempt", 0) < 1  # type: ignore[operator]
                or type(record.get("status")) is not str
            ):
                raise RepositoryIntegrityError("durable node-run dependency is malformed or stale")
            normalized_runs[run_id] = record
        dependencies: list[dict[str, object]] = []
        invalidated_runs: set[str] = set()
        for target_id in invalidated_targets:
            target = targets.get(target_id) if type(target_id) is str else None
            acceptance_id = target.get("acceptance_id") if isinstance(target, Mapping) else None
            if type(target_id) is not str or type(acceptance_id) is not str:
                raise RepositoryIntegrityError("ProjectScope invalidated target is invalid")
            try:
                root, node_ids, edge_ids, matched_tags = graph.invalidation_dependency(
                    (target_id, acceptance_id),
                )
            except GraphValidationError as error:
                raise RepositoryIntegrityError("ProjectScope graph dependency is invalid") from error
            target_runs = sorted(
                run_id for run_id, record in normalized_runs.items()
                if record["node_id"] in node_ids
                and record["status"] not in {"invalidated", "cancelled"}
            )
            invalidated_runs.update(target_runs)
            dependencies.append({
                "target_id": target_id,
                "acceptance_id": acceptance_id,
                "matched_invalidation_tags": list(matched_tags),
                "root_node_id": root,
                "downstream_node_ids": list(node_ids),
                "edge_ids": list(edge_ids),
                "run_ids": target_runs,
            })
        bound = dict(change)
        bound["graph_digest"] = graph.digest
        bound["run_dependencies"] = dependencies
        bound["invalidated_run_ids"] = sorted(invalidated_runs)
        bound.pop("change_digest", None)
        bound["change_digest"] = semantic_record_digest({
            "contract": "project-scope-change-v1",
            "current_scope_digest": current_source["scope_digest"],
            "candidate_scope_digest": candidate_source["scope_digest"],
            "change": bound,
        })
        return bound

    @classmethod
    def _validate_scope_source(cls, source: object, *, _copy: bool = True) -> dict[str, object]:
        if not isinstance(source, dict):
            raise RepositoryIntegrityError("ProjectScope source is not an exact object")
        required = {
            "schema_version", "scope_id", "version", "mode", "repositories", "services",
            "environments", "target_bindings", "discovery_digest", "metadata_revision", "scope_digest",
        }
        if set(source) != required or ProjectScope.digest_document(source) != source.get("scope_digest"):
            raise RepositoryIntegrityError("ProjectScope source digest is invalid")
        canonical_json(source)
        return copy.deepcopy(source) if _copy else source

    @classmethod
    def _apply_project_scope_delta(
        cls,
        connection: ManagedConnection,
        batch: CommitBatch,
        events: list[dict[str, object]],
        prior_snapshot_json: object,
    ) -> None:
        delta = batch.project_scope_delta
        scope_events = [item for item in events if item["event_type"].startswith("project.")]
        if delta is None:
            if scope_events:
                raise RepositoryIntegrityError("ProjectScope event requires its exact durable delta")
            return
        operation = delta.get("operation") if type(delta) is dict else None
        if operation == "draft":
            if set(delta) != {"operation", "source", "source_digest", "change"}:
                raise RepositoryIntegrityError("ProjectScope draft delta is not exact")
            source = cls._validate_scope_source(delta["source"])
            if delta["source_digest"] != cls._scope_source_digest(source):
                raise RepositoryIntegrityError("ProjectScope source record digest is invalid")
            if len(scope_events) != 1 or scope_events[0]["event_type"] not in {
                "project.scope_drafted", "project.scope_change_proposed",
            }:
                raise RepositoryIntegrityError("ProjectScope draft event binding is invalid")
            reference = scope_events[0]["payload"].get("project_scope_ref")  # type: ignore[union-attr]
            expected_ref = {
                "scope_id": source["scope_id"], "version": source["version"],
                "digest": source["scope_digest"], "status": "drafted",
            }
            if reference != expected_ref:
                raise RepositoryIntegrityError("ProjectScope draft reference is not exact")
            frozen = connection.execute(
                "SELECT source_json FROM project_scopes WHERE task_id=? AND status='frozen'",
                (batch.task_id,),
            ).fetchall()
            change = delta["change"]
            if scope_events[0]["event_type"] == "project.scope_drafted":
                if frozen or change is not None:
                    raise RepositoryIntegrityError("initial ProjectScope draft conflicts with durable state")
                change_json = change_digest = None
            else:
                if len(frozen) != 1 or not isinstance(change, dict):
                    raise RepositoryIntegrityError("ProjectScope change has no exact frozen predecessor")
                current_source = parse_canonical_json(frozen[0][0])
                expected_change = (
                    None if not isinstance(current_source, dict) or prior_snapshot_json is None
                    else cls._bind_scope_run_dependencies(
                        current_source,
                        source,
                        cls._scope_change(current_source, source),
                        prior_snapshot_json,
                        batch.scope_graph_definition,
                    )
                )
                if expected_change != change:
                    raise RepositoryIntegrityError("ProjectScope change classification is not exact")
                if scope_events[0]["payload"].get("scope_diff_digest") != change["change_digest"]:  # type: ignore[union-attr]
                    raise RepositoryIntegrityError("ProjectScope change event digest is not exact")
                invalidation = [item for item in events if item["event_type"] == "task.downstream_invalidated"]
                if (
                    len(invalidation) != 1
                    or invalidation[0]["payload"].get("run_ids")  # type: ignore[union-attr]
                    != change.get("invalidated_run_ids")
                ):
                    raise RepositoryIntegrityError("ProjectScope invalidation is not minimally derived")
                change_json = canonical_json(change)
                change_digest = change["change_digest"]
            connection.execute(
                "INSERT INTO project_scopes(task_id,scope_id,version,metadata_revision,scope_digest,status,"
                "source_json,source_digest,change_json,change_digest,created_transaction_id) "
                "VALUES(?,?,?,?,?,'drafted',?,?,?,?,?)",
                (
                    batch.task_id, source["scope_id"], source["version"], source["metadata_revision"],
                    source["scope_digest"], canonical_json(source), delta["source_digest"],
                    change_json, change_digest, batch.transaction_id,
                ),
            )
            return
        if operation == "approve":
            if set(delta) != {"operation", "scope_digest", "authority_expansion"}:
                raise RepositoryIntegrityError("ProjectScope approval delta is not exact")
            approval_events = [item for item in events if item["event_type"] in {
                "project.scope_frozen", "project.scope_rebased",
            }]
            if len(approval_events) != 1:
                raise RepositoryIntegrityError("ProjectScope approval event is absent")
            event = approval_events[0]
            decision_events = [item for item in events if item["event_type"] in {
                "task.prd_approved", "task.prd_reapproved",
            }]
            if len(decision_events) != 1:
                raise RepositoryIntegrityError("ProjectScope approval decision event is absent")
            decision = decision_events[0]
            row = connection.execute(
                "SELECT scope_id,version,scope_digest,change_json FROM project_scopes "
                "WHERE task_id=? AND scope_digest=? AND status='drafted'",
                (batch.task_id, delta["scope_digest"]),
            ).fetchone()
            if row is None or event["payload"].get("project_scope_ref") != {  # type: ignore[union-attr]
                "scope_id": row[0], "version": row[1], "digest": row[2], "status": "frozen",
            }:
                raise RepositoryIntegrityError("ProjectScope approval does not bind the current draft")
            if (event["event_type"] == "project.scope_rebased") != (row[3] is not None):
                raise RepositoryIntegrityError("ProjectScope approval kind conflicts with durable history")
            change = None if row[3] is None else parse_canonical_json(row[3])
            if isinstance(change, dict) and change.get("requires_authority_expansion") is True:
                previous = connection.execute(
                    "SELECT a.record_json FROM project_scope_approvals a JOIN project_scopes s "
                    "ON s.task_id=a.task_id AND s.scope_digest=a.scope_digest "
                    "WHERE a.task_id=? AND s.status='frozen'",
                    (batch.task_id,),
                ).fetchone()
                previous_record = parse_canonical_json(previous[0]) if previous is not None else None
                before_authorities = (
                    previous_record.get("authority_refs") if isinstance(previous_record, dict) else None
                )
                after_authorities = decision["payload"].get("authority_refs")  # type: ignore[union-attr]
                expansion = delta.get("authority_expansion")
                expansion_fields = {
                    "schema_version", "authority_id", "task_id", "owner_id",
                    "candidate_scope_digest", "owner_decision_ref",
                    "authorized_resource_ids", "authorized_operation_classes",
                    "status", "authority_digest",
                }
                domain = batch.snapshot.get("domain")
                identity = domain.get("identity") if isinstance(domain, Mapping) else None
                if (
                    not isinstance(before_authorities, list)
                    or not isinstance(after_authorities, list)
                    or not isinstance(expansion, dict)
                    or set(expansion) != expansion_fields
                    or expansion.get("schema_version") != "1.0"
                    or expansion.get("task_id") != batch.task_id
                    or not isinstance(identity, Mapping)
                    or expansion.get("owner_id") != identity.get("owner_id")
                    or expansion.get("status") != "active"
                    or expansion.get("candidate_scope_digest") != row[2]
                    or expansion.get("owner_decision_ref")
                    != decision["payload"].get("owner_decision_ref")  # type: ignore[union-attr]
                    or expansion.get("authorized_resource_ids") != change.get("added_resource_ids")
                    or expansion.get("authorized_operation_classes")
                    != change.get("added_operation_classes")
                    or type(expansion.get("authority_id")) is not str
                    or after_authorities
                    != sorted(before_authorities + [expansion["authority_id"]])
                    or expansion.get("authority_digest") != semantic_record_digest({
                        "contract": "project-scope-authority-envelope-v1",
                        "value": {
                            key: expansion[key] for key in expansion_fields
                            if key != "authority_digest"
                        },
                    })
                ):
                    raise RepositoryIntegrityError("ProjectScope rebase lacks exact authority expansion")
            else:
                expansion = None
            approval_record = {
                "schema_version": "1.0", "task_id": batch.task_id,
                "scope_digest": row[2], "transaction_id": batch.transaction_id,
                "scope_event_digest": event["event_digest"],
                "approval_event_digest": decision["event_digest"],
                "owner_decision_ref": decision["payload"].get("owner_decision_ref"),  # type: ignore[union-attr]
                "baseline_refs": decision["payload"].get("baseline_refs"),  # type: ignore[union-attr]
                "graph_ref": decision["payload"].get("graph_ref"),  # type: ignore[union-attr]
                "authority_refs": list(decision["payload"].get("authority_refs", ())),  # type: ignore[union-attr]
                "authority_expansion": expansion,
                "change_digest": None if not isinstance(change, dict) else change.get("change_digest"),
            }
            approval_digest = semantic_record_digest({
                "contract": "project-scope-approval-v1", "value": approval_record,
            })
            connection.execute(
                "UPDATE project_scopes SET status='superseded' WHERE task_id=? AND status='frozen'",
                (batch.task_id,),
            )
            changed = connection.execute(
                "UPDATE project_scopes SET status='frozen',approved_transaction_id=?,approved_event_digest=? "
                "WHERE task_id=? AND scope_digest=? AND status='drafted'",
                (batch.transaction_id, event["event_digest"], batch.task_id, delta["scope_digest"]),
            ).rowcount
            if changed != 1:
                raise RepositoryConflictError("ProjectScope approval lost its exact CAS")
            connection.execute(
                "INSERT INTO project_scope_approvals(task_id,scope_digest,transaction_id,record_json,record_digest) "
                "VALUES(?,?,?,?,?)",
                (
                    batch.task_id, row[2], batch.transaction_id,
                    canonical_json(approval_record), approval_digest,
                ),
            )
            return
        if operation == "metadata":
            if set(delta) != {"operation", "source", "source_digest", "change"}:
                raise RepositoryIntegrityError("ProjectScope metadata delta is not exact")
            source = cls._validate_scope_source(delta["source"])
            if delta["source_digest"] != cls._scope_source_digest(source):
                raise RepositoryIntegrityError("ProjectScope metadata source digest is invalid")
            row = connection.execute(
                "SELECT source_json FROM project_scopes WHERE task_id=? AND scope_digest=? AND status='frozen'",
                (batch.task_id, source["scope_digest"]),
            ).fetchone()
            current = parse_canonical_json(row[0]) if row is not None else None
            if (
                not isinstance(current, dict)
                or cls._scope_change(current, source) != delta["change"]
                or delta["change"].get("change_class") != "metadata-only"  # type: ignore[union-attr]
                or len(scope_events) != 1
                or scope_events[0]["event_type"] != "project.scope_metadata_updated"
                or scope_events[0]["payload"] != {  # type: ignore[comparison-overlap]
                    "scope_digest": source["scope_digest"],
                    "metadata_revision": source["metadata_revision"],
                    "source_digest": delta["source_digest"],
                }
            ):
                raise RepositoryIntegrityError("ProjectScope metadata update is not exact")
            record = {
                "task_id": batch.task_id, "scope_digest": source["scope_digest"],
                "metadata_revision": source["metadata_revision"], "source_digest": delta["source_digest"],
                "event_digest": scope_events[0]["event_digest"], "transaction_id": batch.transaction_id,
            }
            connection.execute(
                "INSERT INTO project_scope_metadata_history(task_id,scope_digest,metadata_revision,source_json,"
                "source_digest,event_digest,transaction_id,record_digest) VALUES(?,?,?,?,?,?,?,?)",
                (
                    batch.task_id, source["scope_digest"], source["metadata_revision"], canonical_json(source),
                    delta["source_digest"], scope_events[0]["event_digest"], batch.transaction_id,
                    semantic_record_digest({"contract": "project-scope-metadata-v1", "value": record}),
                ),
            )
            changed = connection.execute(
                "UPDATE project_scopes SET metadata_revision=?,source_json=?,source_digest=? "
                "WHERE task_id=? AND scope_digest=? AND status='frozen'",
                (
                    source["metadata_revision"], canonical_json(source), delta["source_digest"],
                    batch.task_id, source["scope_digest"],
                ),
            ).rowcount
            if changed != 1:
                raise RepositoryConflictError("ProjectScope metadata update lost its exact CAS")
            return
        if operation == "realize":
            required = {
                "operation", "observation", "action_id", "prepared_action_digest",
                "receipt_digest",
            }
            if set(delta) != required or len(scope_events) != 1 or scope_events[0]["event_type"] != "project.repository_realized":
                raise RepositoryIntegrityError("repository realization delta/event is not exact")
            observation = delta["observation"]
            observation_fields = {
                "resolver_id", "scope_digest", "binding_id", "planned_target_id", "locator_ref",
                "allowed_path_boundary", "observed_path_boundary", "actual_git_identity",
                "observed_at", "observation_digest",
            }
            if not isinstance(observation, dict) or set(observation) != observation_fields:
                raise RepositoryIntegrityError("repository identity observation is not exact")
            unsigned_observation = {
                key: value for key, value in observation.items() if key != "observation_digest"
            }
            if observation["observation_digest"] != cls.identity_observation_digest(unsigned_observation):
                raise RepositoryIntegrityError("repository identity observation digest is invalid")
            row = connection.execute(
                "SELECT source_json FROM project_scopes WHERE task_id=? AND scope_digest=? AND status='frozen'",
                (batch.task_id, observation["scope_digest"]),
            ).fetchone()
            if row is None:
                raise RepositoryIntegrityError("repository realization does not bind the frozen scope")
            source = parse_canonical_json(row[0])
            repositories = source.get("repositories") if isinstance(source, dict) else None
            binding = next((item for item in repositories if item.get("binding_id") == observation["binding_id"]), None) if isinstance(repositories, list) else None
            event = scope_events[0]
            if (
                not isinstance(binding, dict) or binding.get("mode") != "create_new"
                or binding.get("planned_target_id") != observation["planned_target_id"]
                or binding.get("locator_ref") != observation["locator_ref"]
                or binding.get("allowed_path_boundary") != observation["allowed_path_boundary"]
                or observation["observed_path_boundary"] != observation["allowed_path_boundary"]
                or event["payload"] != {
                    "binding_id": observation["binding_id"],
                    "git_identity": observation["actual_git_identity"],
                }
            ):
                raise RepositoryIntegrityError("repository realization planned target is invalid")
            action = connection.execute(
                "SELECT task_id,state,prepared_json,prepared_digest,receipt_json,reconciliation_json FROM action_journal "
                "WHERE action_id=?",
                (delta["action_id"],),
            ).fetchone()
            prepared = parse_canonical_json(action[2]) if action is not None else None
            receipt = parse_canonical_json(action[4]) if action is not None and action[4] is not None else None
            reconciliation = parse_canonical_json(action[5]) if action is not None and action[5] is not None else None
            if (
                action is None or action[0] != batch.task_id or action[1] != "reconciled"
                or action[3] != delta["prepared_action_digest"]
                or not isinstance(prepared, dict)
                or prepared.get("prepared_action_digest") != delta["prepared_action_digest"]
                or prepared.get("action_id") != delta["action_id"]
                or prepared.get("task_id") != batch.task_id
                or prepared.get("target_id") != observation["planned_target_id"]
                or prepared.get("target_digest") != observation["scope_digest"]
                or f"repository:{observation['binding_id']}" not in prepared.get("resources", [])
                or not isinstance(receipt, dict)
                or receipt.get("action_id") != delta["action_id"]
                or receipt.get("prepared_action_digest") != delta["prepared_action_digest"]
                or receipt.get("target_id") != observation["planned_target_id"]
                or receipt.get("result") != "succeeded"
                or receipt.get("receipt_digest") != delta["receipt_digest"]
                or not isinstance(reconciliation, dict)
                or reconciliation.get("fresh") is not True
                or reconciliation.get("target_id") != observation["planned_target_id"]
                or reconciliation.get("resource_id") != f"repository:{observation['binding_id']}"
            ):
                raise RepositoryIntegrityError("repository realization action/receipt binding is invalid")
            from .actions import ActionJournalRepository
            ActionJournalRepository._validate_stored_receipt(receipt)
            record = {
                "task_id": batch.task_id, "scope_digest": observation["scope_digest"],
                "binding_id": observation["binding_id"],
                "planned_target_id": observation["planned_target_id"],
                "actual_git_identity": observation["actual_git_identity"],
                "boundary_evidence_digest": observation["observation_digest"],
                "action_id": delta["action_id"],
                "prepared_action_digest": delta["prepared_action_digest"],
                "receipt_digest": delta["receipt_digest"],
                "observation": observation,
                "event_digest": event["event_digest"], "transaction_id": batch.transaction_id,
            }
            connection.execute(
                "INSERT INTO project_scope_realizations(task_id,scope_digest,binding_id,planned_target_id,"
                "actual_git_identity,boundary_evidence_digest,action_id,prepared_action_digest,receipt_digest,"
                "observation_json,observation_digest,event_digest,transaction_id,record_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    batch.task_id, observation["scope_digest"], observation["binding_id"],
                    observation["planned_target_id"], observation["actual_git_identity"],
                    observation["observation_digest"], delta["action_id"],
                    delta["prepared_action_digest"], delta["receipt_digest"], canonical_json(observation),
                    observation["observation_digest"], event["event_digest"], batch.transaction_id,
                    semantic_record_digest({"contract": "repository-realization-v1", "value": record}),
                ),
            )
            return
        raise RepositoryIntegrityError("unknown ProjectScope delta operation")

    @staticmethod
    def _lifecycle_facts_locked(
        connection: ManagedConnection,
        task_id: str,
        *,
        exclude_lease_id: str | None = None,
    ) -> dict[str, object]:
        task = connection.execute(
            "SELECT revision,snapshot_json FROM tasks WHERE task_id=?", (task_id,),
        ).fetchone()
        if task is None:
            raise RepositoryConflictError("unknown task")
        snapshot = parse_canonical_json(task[1])
        domain = snapshot.get("domain") if isinstance(snapshot, dict) else None
        domain_digest = domain.get("snapshot_digest") if isinstance(domain, dict) else None
        lease_rows = connection.execute(
            "SELECT lease_id FROM leases WHERE task_id=? AND state='live' ORDER BY lease_id",
            (task_id,),
        ).fetchall()
        live_leases = tuple(row[0] for row in lease_rows if row[0] != exclude_lease_id)
        unresolved_claims = tuple(row[0] for row in connection.execute(
            "SELECT claim_id FROM claims WHERE task_id=? AND state='unresolved' ORDER BY claim_id",
            (task_id,),
        ).fetchall())
        action_states = tuple(connection.execute(
            "SELECT action_id,state,revision,prepared_digest,authority_digest FROM action_journal "
            "WHERE task_id=? ORDER BY action_id",
            (task_id,),
        ).fetchall())
        compensable = tuple(
            action_id for action_id, state, _revision, _prepared, _authority in action_states
            if state in {"succeeded", "reconciled"}
        )
        fences = tuple(connection.execute(
            "SELECT resource_id,fencing_token FROM resource_fences ORDER BY resource_id",
        ).fetchall())
        security = connection.execute(
            "SELECT task_revision,task_snapshot_digest,state_digest FROM task_security_states WHERE task_id=?",
            (task_id,),
        ).fetchone()
        facts: dict[str, object] = {
            "schema_version": "1.0", "task_id": task_id, "repository_revision": task[0],
            "task_snapshot_digest": domain_digest, "live_leases": list(live_leases),
            "unresolved_claims": list(unresolved_claims),
            "action_states": [list(row) for row in action_states],
            "compensable_action_refs": list(compensable),
            "fencing_high_water": [list(row) for row in fences],
            "security_state": None if security is None else list(security),
        }
        facts["facts_digest"] = TaskRepository.lifecycle_facts_digest(facts)
        return facts

    @classmethod
    def _validate_lifecycle_assertion(
        cls,
        connection: ManagedConnection,
        batch: CommitBatch,
        events: list[dict[str, object]],
    ) -> None:
        guarded = {
            "task.paused", "task.pause_deferred", "task.resumed", "task.cancel_requested",
            "task.canceled", "authority.revoked", "task.authority_reconciliation_required",
            "task.rollback_requested", "task.archived",
        }
        required = any(item["event_type"] in guarded for item in events)
        assertion = batch.lifecycle_assertion
        if not required:
            if assertion is not None:
                current = cls._lifecycle_facts_locked(
                    connection, batch.task_id,
                    exclude_lease_id=batch.lease_assertion.get("lease_id"),
                )
                if assertion != current:
                    raise RepositoryConflictError("lifecycle facts changed before the commit transaction")
            return
        if not isinstance(assertion, dict):
            raise RepositoryIntegrityError("lifecycle transition requires an exact durable fact assertion")
        current = cls._lifecycle_facts_locked(
            connection, batch.task_id,
            exclude_lease_id=batch.lease_assertion.get("lease_id"),
        )
        if assertion != current:
            raise RepositoryConflictError("lifecycle facts changed before the commit transaction")

    @classmethod
    def _current_rollback_request_authority(
        cls,
        connection: ManagedConnection,
        task_id: str,
        authority_ref: str,
        facts: Mapping[str, object],
    ) -> tuple[str, str]:
        security_row = connection.execute(
            "SELECT task_revision,task_snapshot_digest,state_json,state_digest "
            "FROM task_security_states WHERE task_id=?",
            (task_id,),
        ).fetchone()
        state = parse_canonical_json(security_row[2]) if security_row is not None else None
        state_keys = {
            "schema_version", "task_id", "task_revision", "task_snapshot_digest",
            "binding", "destinations", "authority_digests", "data_refs",
            "evidence_expectations", "retention_subjects",
        }
        if (
            security_row is None or not isinstance(state, dict) or set(state) != state_keys
            or state.get("schema_version") != "1.0.0" or state.get("task_id") != task_id
            or security_row[0] != facts.get("repository_revision")
            or security_row[1] != facts.get("task_snapshot_digest")
            or state.get("task_revision") != security_row[0]
            or state.get("task_snapshot_digest") != security_row[1]
            or semantic_record_digest({
                "contract": "task-security-state-v1", "value": state,
            }) != security_row[3]
        ):
            raise RepositoryIntegrityError("rollback request authority requires exact current security state")
        authority_digests = state.get("authority_digests")
        if (
            not isinstance(authority_digests, list)
            or authority_digests != sorted(set(authority_digests))
        ):
            raise RepositoryIntegrityError("rollback request authority set is not canonical")
        for digest in authority_digests:
            require_jcs_digest(digest)

        matches: list[str] = []
        rows = connection.execute(
            "SELECT state,prepared_json,prepared_digest,authority_json,authority_digest "
            "FROM action_journal WHERE task_id=? AND authority_digest IS NOT NULL ORDER BY action_id",
            (task_id,),
        ).fetchall()
        for row in rows:
            prepared = parse_canonical_json(row[1])
            authority = parse_canonical_json(row[3])
            if not isinstance(authority, dict) or authority.get("authority_id") != authority_ref:
                continue
            resources = prepared.get("resources") if isinstance(prepared, dict) else None
            if (
                row[0] != "authorized" or not isinstance(prepared, dict)
                or prepared.get("task_id") != task_id
                or prepared.get("action_kind") != "rollback-request"
                or prepared.get("prepared_action_digest") != row[2]
                or not isinstance(resources, list) or resources != sorted(set(resources))
                or not isinstance(authority, dict) or authority.get("task_id") != task_id
                or authority.get("status") != "active"
                or authority.get("authorized_action_kind") != "rollback-request"
                or authority.get("authorized_resources") != resources
                or authority.get("prepared_action_digest") != row[2]
                or authority.get("authority_digest") != row[4]
                or row[4] not in authority_digests
            ):
                raise RepositoryConflictError("rollback request authority is not current")
            matches.append(row[4])
        if len(matches) != 1:
            raise RepositoryConflictError("rollback request authority is missing, duplicated, or revoked")
        return matches[0], security_row[3]

    @staticmethod
    def _canonical_rollback_order(
        dependencies: Mapping[str, tuple[str, ...]],
    ) -> tuple[str, ...]:
        remaining = {action_id: set(values) for action_id, values in dependencies.items()}
        order: list[str] = []
        while remaining:
            ready = sorted(action_id for action_id, values in remaining.items() if not values)
            if not ready:
                raise RepositoryIntegrityError("controlled rollback graph must be acyclic")
            for action_id in ready:
                order.append(action_id)
                remaining.pop(action_id)
            for values in remaining.values():
                values.difference_update(ready)
        return tuple(order)

    @classmethod
    def _validate_rollback_graph(
        cls,
        steps: object,
        compensable_actions: object,
        current_fences: object,
        *,
        task_resource: str | None = None,
        current_task_fence: int | None = None,
    ) -> None:
        if (
            not isinstance(compensable_actions, list)
            or compensable_actions != sorted(set(compensable_actions))
            or not compensable_actions
            or not isinstance(steps, list)
            or len(steps) != len(compensable_actions)
            or not isinstance(current_fences, list)
        ):
            raise RepositoryIntegrityError("controlled rollback graph shape is invalid")
        fence_map = {
            row[0]: row[1] for row in current_fences
            if isinstance(row, list) and len(row) == 2
        }
        if len(fence_map) != len(current_fences):
            raise RepositoryIntegrityError("controlled rollback fence projection is invalid")
        dependencies: dict[str, tuple[str, ...]] = {}
        compensation_ids: set[str] = set()
        seen_originals: list[str] = []
        step_keys = {
            "step_id", "original_action_id", "compensation_action_id",
            "compensation_prepared_digest", "compensation_authority_digest",
            "resources", "fencing_tokens", "depends_on_action_ids",
        }
        for step in steps:
            if not isinstance(step, dict) or set(step) != step_keys:
                raise RepositoryIntegrityError("controlled rollback step shape is not exact")
            original_id = step.get("original_action_id")
            compensation_id = step.get("compensation_action_id")
            resources = step.get("resources")
            fences = step.get("fencing_tokens")
            depends_on = step.get("depends_on_action_ids")
            if (
                type(original_id) is not str or original_id not in compensable_actions
                or step.get("step_id") != f"rollback:{original_id}"
                or type(compensation_id) is not str or not compensation_id
                or compensation_id == original_id or compensation_id in compensation_ids
                or not isinstance(resources, list) or not resources
                or resources != sorted(set(resources))
                or not isinstance(depends_on, list)
                or depends_on != sorted(set(depends_on))
                or original_id in depends_on
                or any(item not in compensable_actions for item in depends_on)
                or not isinstance(fences, list)
                or any(not isinstance(row, list) or len(row) != 2 for row in fences)
                or [row[0] for row in fences] != resources
            ):
                raise RepositoryIntegrityError("controlled rollback graph is not canonical one-to-one")
            for digest_name in ("compensation_prepared_digest", "compensation_authority_digest"):
                require_jcs_digest(step.get(digest_name))
            for resource, planned_fence in fences:
                if type(planned_fence) is not int or planned_fence < 1:
                    raise RepositoryIntegrityError("controlled rollback resource fence is invalid")
                actual_fence = fence_map.get(resource)
                expected_fence = planned_fence
                if resource == task_resource:
                    if current_task_fence is None or actual_fence != current_task_fence:
                        raise RepositoryConflictError("controlled rollback task fence is stale")
                    expected_fence += 1
                if actual_fence != expected_fence:
                    raise RepositoryConflictError("controlled rollback resource fence changed")
            seen_originals.append(original_id)
            compensation_ids.add(compensation_id)
            dependencies[original_id] = tuple(depends_on)
        order = cls._canonical_rollback_order(dependencies)
        if tuple(seen_originals) != order or set(seen_originals) != set(compensable_actions):
            raise RepositoryIntegrityError("controlled rollback steps are not in canonical topological order")

    @classmethod
    def _apply_lifecycle_plan_delta(
        cls,
        connection: ManagedConnection,
        batch: CommitBatch,
        events: list[dict[str, object]],
    ) -> None:
        delta = batch.lifecycle_plan_delta
        lifecycle_types = {item["event_type"] for item in events}
        requires_plan = bool(lifecycle_types & {
            "task.rollback_requested", "task.archived", "task.canceled",
            "task.cancel_requested",
        })
        if delta is None:
            if requires_plan:
                raise RepositoryIntegrityError("lifecycle transition requires a durable lifecycle plan")
            return
        if not isinstance(delta, dict) or set(delta) != {"plan_id", "trigger"}:
            raise RepositoryIntegrityError("lifecycle plan consumption delta is not exact")
        row = connection.execute(
            "SELECT task_id,kind,trigger,task_revision,task_snapshot_digest,facts_digest,body_json,"
            "body_digest,state FROM lifecycle_plans WHERE plan_id=?",
            (delta["plan_id"],),
        ).fetchone()
        body = parse_canonical_json(row[6]) if row is not None else None
        if (
            row is None or row[0] != batch.task_id or row[2] != delta["trigger"]
            or row[8] != "prepared" or not isinstance(body, dict)
            or semantic_record_digest({"contract": "lifecycle-plan-v1", "value": body}) != row[7]
            or delta["plan_id"] != f"lifecycle-plan:{row[7]}"
            or body.get("task_revision") != batch.expected_task_revision
            or body.get("task_snapshot_digest") != batch.lifecycle_assertion.get("task_snapshot_digest")  # type: ignore[union-attr]
        ):
            raise RepositoryConflictError("durable lifecycle plan is stale, consumed, or substituted")
        current = batch.lifecycle_assertion
        if not isinstance(current, dict):
            raise RepositoryIntegrityError("lifecycle plan lacks same-transaction facts")
        if body["kind"] == "retention":
            if body.get("security_state_digest") != (
                current.get("security_state")[2]
                if isinstance(current.get("security_state"), list)
                else None
            ):
                raise RepositoryConflictError("retention plan security state is stale")
            event_type = "task.archived" if delta["trigger"] == "archive" else (
                "task.canceled" if "task.canceled" in lifecycle_types else "task.cancel_requested"
            )
            event = next((item for item in events if item["event_type"] == event_type), None)
            if event is None:
                raise RepositoryIntegrityError("retention plan trigger event is absent")
            if event_type == "task.archived" and event["payload"] != {
                "retention_plan_ref": delta["plan_id"],
                "rollback_clearance_ref": body["rollback_clearance_ref"],
            }:
                raise RepositoryIntegrityError("archive event does not bind the durable retention plan")
            schedule = {
                "schema_version": "1.0", "plan_id": delta["plan_id"],
                "task_id": batch.task_id, "trigger": delta["trigger"],
                "subject_schedules": body["schedules"], "physical_purge_claimed": False,
                "audit_preserved": True,
            }
        elif body["kind"] == "rollback":
            event = next((item for item in events if item["event_type"] == "task.rollback_requested"), None)
            if event is None or event["payload"] != {
                "compensable_action_refs": body["compensable_action_refs"],
                "rollback_plan_ref": delta["plan_id"],
                "authority_ref": body["request_authority_ref"],
            }:
                raise RepositoryIntegrityError("rollback event does not bind the durable compensation graph")
            if current.get("compensable_action_refs") != body["compensable_action_refs"]:
                raise RepositoryConflictError("rollback compensable action set changed after planning")
            request_authority_digest, security_state_digest = cls._current_rollback_request_authority(
                connection, batch.task_id, body["request_authority_ref"], current,
            )
            if (
                body.get("request_authority_digest") != request_authority_digest
                or body.get("security_state_digest") != security_state_digest
            ):
                raise RepositoryConflictError("rollback request authority changed after planning")
            cls._validate_rollback_graph(
                body.get("steps"), body.get("compensable_action_refs"),
                current.get("fencing_high_water"),
                task_resource=batch.lease_assertion.get("resource_id"),
                current_task_fence=batch.lease_assertion.get("fencing_token"),
            )
            for step in body["steps"]:
                action = connection.execute(
                    "SELECT state,prepared_json,prepared_digest,authority_json,authority_digest "
                    "FROM action_journal WHERE action_id=? AND task_id=?",
                    (step["compensation_action_id"], batch.task_id),
                ).fetchone()
                prepared = parse_canonical_json(action[1]) if action is not None else None
                authority = parse_canonical_json(action[3]) if action is not None else None
                if (
                    action is None or action[0] != "authorized"
                    or not isinstance(prepared, dict)
                    or prepared.get("action_id") != step["compensation_action_id"]
                    or prepared.get("task_id") != batch.task_id
                    or prepared.get("action_kind") != "rollback"
                    or prepared.get("resources") != step["resources"]
                    or prepared.get("prepared_action_digest") != action[2]
                    or action[2] != step["compensation_prepared_digest"]
                    or not isinstance(authority, dict) or authority.get("status") != "active"
                    or authority.get("task_id") != batch.task_id
                    or authority.get("authorized_action_kind") != "rollback"
                    or authority.get("authorized_resources") != step["resources"]
                    or authority.get("prepared_action_digest") != action[2]
                    or authority.get("authority_digest") != action[4]
                    or action[4] != step["compensation_authority_digest"]
                ):
                    raise RepositoryConflictError("rollback step authority changed after planning")
            schedule = {
                "schema_version": "1.0", "plan_id": delta["plan_id"],
                "task_id": batch.task_id, "trigger": "rollback", "steps": body["steps"],
                "physical_purge_claimed": False, "audit_preserved": True,
            }
        else:
            raise RepositoryIntegrityError("durable lifecycle plan kind is invalid")
        schedule_digest = semantic_record_digest({
            "contract": "lifecycle-plan-execution-v1", "value": schedule,
        })
        changed = connection.execute(
            "UPDATE lifecycle_plans SET state='consumed',consumed_transaction_id=? "
            "WHERE plan_id=? AND state='prepared'",
            (batch.transaction_id, delta["plan_id"]),
        ).rowcount
        if changed != 1:
            raise RepositoryConflictError("lifecycle plan consumption lost its exact CAS")
        connection.execute(
            "INSERT INTO lifecycle_plan_executions(plan_id,transaction_id,trigger,schedule_json,schedule_digest) "
            "VALUES(?,?,?,?,?)",
            (
                delta["plan_id"], batch.transaction_id, delta["trigger"],
                canonical_json(schedule), schedule_digest,
            ),
        )

    @staticmethod
    def _validate_lease_assertion(
        connection: ManagedConnection,
        task_id: str,
        assertion: dict[str, object],
        reconciliation_claim_id: str | None,
    ) -> None:
        required = {"lease_id", "resource_id", "fencing_token"}
        if not isinstance(assertion, dict) or set(assertion) != required:
            raise RepositoryIntegrityError("task lease assertion shape is not exact")
        if (
            type(assertion["lease_id"]) is not str
            or not assertion["lease_id"]
            or assertion["resource_id"] != f"task:{task_id}"
            or type(assertion["fencing_token"]) is not int
            or assertion["fencing_token"] <= 0
        ):
            raise RepositoryIntegrityError("task lease assertion is invalid")
        row = connection.execute(
            "SELECT lr.fencing_token,rf.fencing_token,l.state,l.expires_at "
            "FROM lease_resources lr JOIN resource_fences rf ON rf.resource_id=lr.resource_id "
            "JOIN leases l ON l.lease_id=lr.lease_id "
            "WHERE lr.lease_id=? AND lr.resource_id=?",
            (assertion["lease_id"], assertion["resource_id"]),
        ).fetchone()
        token = assertion["fencing_token"]
        now = trusted_now(connection)
        live = (
            row is not None
            and row[0] == token
            and row[1] == token
            and row[2] == "live"
            and row[3] > now
        )
        reconciliation_authorized = False
        if not live and reconciliation_claim_id is not None and row is not None:
            claim = connection.execute(
                "SELECT task_id,lease_id,state FROM claims WHERE claim_id=?",
                (reconciliation_claim_id,),
            ).fetchone()
            reconciliation_authorized = (
                claim is not None
                and claim[0] == task_id
                and claim[1] == assertion["lease_id"]
                and claim[2] == "unresolved"
                and row[0] == token
                and row[1] == token
            )
        if not live and not reconciliation_authorized:
            raise RepositoryConflictError("task lease assertion is stale or expired")

    def _verify_objects(self, connection: ManagedConnection, digests: tuple[str, ...]) -> None:
        for digest in digests:
            row = connection.execute(
                "SELECT size,state FROM objects WHERE digest=?", (digest,),
            ).fetchone()
            if row is None or row[1] != "available":
                raise RepositoryIntegrityError("referenced object is not available")
            self._objects._verify_file(self._objects._path(digest), digest, row[0])

    @staticmethod
    def _insert_claim(
        connection: ManagedConnection,
        claim: dict[str, object],
        events_by_digest: dict[str, dict[str, object]],
        task_lease_id: object,
    ) -> None:
        required = {
            "claim_id", "action_id", "task_id", "lease_id", "resources",
            "fencing_tokens", "started_event_digest", "object_digests",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            raise RepositoryIntegrityError("claim delta shape is not exact")
        for name in ("claim_id", "action_id", "task_id", "lease_id"):
            if type(claim[name]) is not str or not claim[name]:
                raise RepositoryIntegrityError("claim identity is invalid")
        if claim["lease_id"] != task_lease_id:
            raise RepositoryIntegrityError("claim lease does not match the task commit lease")
        resources = claim["resources"]
        tokens = claim["fencing_tokens"]
        objects = claim["object_digests"]
        if (
            not isinstance(resources, list)
            or resources != sorted(set(resources))
            or any(type(item) is not str or not item for item in resources)
            or not isinstance(tokens, dict)
            or set(tokens) != set(resources)
            or any(type(value) is not int or value <= 0 for value in tokens.values())
            or not isinstance(objects, list)
            or objects != sorted(set(objects))
        ):
            raise RepositoryIntegrityError("claim resources, fences, or objects are invalid")
        lease_resources = connection.execute(
            "SELECT resource_id,fencing_token FROM lease_resources "
            "WHERE lease_id=? ORDER BY resource_id",
            (claim["lease_id"],),
        ).fetchall()
        exact_resources = [row[0] for row in lease_resources]
        exact_tokens = {row[0]: row[1] for row in lease_resources}
        if resources != exact_resources or tokens != exact_tokens:
            raise RepositoryIntegrityError(
                "claim must freeze the complete exact lease resource and fence set",
            )
        started = require_jcs_digest(claim["started_event_digest"])
        started_event = events_by_digest.get(started)
        if (
            started_event is None
            or started_event["event_type"] != "action.execution_started"
            or started_event["task_id"] != claim["task_id"]
            or started_event["payload"].get("action_id") != claim["action_id"]  # type: ignore[union-attr]
        ):
            raise RepositoryIntegrityError(
                "claim is not bound to its exact execution-started event",
            )
        now = trusted_now(connection)
        lease = connection.execute(
            "SELECT task_id,state,expires_at FROM leases WHERE lease_id=?", (claim["lease_id"],),
        ).fetchone()
        if (
            lease is None
            or lease[0] != claim["task_id"]
            or lease[1] != "live"
            or lease[2] <= now
        ):
            raise RepositoryConflictError("claim lease is not live or task-bound")
        for resource in resources:
            row = connection.execute(
                "SELECT lr.fencing_token,rf.fencing_token FROM lease_resources lr "
                "JOIN resource_fences rf ON rf.resource_id=lr.resource_id "
                "WHERE lr.lease_id=? AND lr.resource_id=?",
                (claim["lease_id"], resource),
            ).fetchone()
            if row is None or row[0] != tokens[resource] or row[1] != tokens[resource]:
                raise RepositoryConflictError("claim fence does not match lease")
        for digest in objects:
            require_object_digest(digest)
            row = connection.execute(
                "SELECT state FROM objects WHERE digest=?", (digest,),
            ).fetchone()
            if row is None or row[0] != "available":
                raise RepositoryIntegrityError("claim object is not available")
        connection.execute(
            "INSERT INTO claims(claim_id,action_id,task_id,lease_id,started_event_digest,state,outcome_digest) "
            "VALUES(?,?,?,?,?,'unresolved',NULL)",
            (
                claim["claim_id"], claim["action_id"], claim["task_id"],
                claim["lease_id"], started,
            ),
        )
        connection.executemany(
            "INSERT INTO claim_resources(claim_id,resource_id,fencing_token) VALUES(?,?,?)",
            [(claim["claim_id"], resource, tokens[resource]) for resource in resources],
        )
        connection.executemany(
            "INSERT INTO claim_objects(claim_id,digest) VALUES(?,?)",
            [(claim["claim_id"], digest) for digest in objects],
        )

    @staticmethod
    def _reconcile_claim(
        connection: ManagedConnection,
        reconciliation: dict[str, object],
        events_by_digest: dict[str, dict[str, object]],
    ) -> None:
        required = {
            "claim_id", "outcome", "outcome_record", "reconciled_event_digest",
        }
        if not isinstance(reconciliation, dict) or set(reconciliation) != required:
            raise RepositoryIntegrityError("claim reconciliation shape is not exact")
        outcome = reconciliation["outcome"]
        event_by_outcome = {
            "reconciled_no_effect": "action.reconciled_no_effect",
            "reconciled_effect_verified": "action.reconciled_effect_verified",
            "compensation_reconciled": "action.compensation_reconciled",
        }
        if (
            type(reconciliation["claim_id"]) is not str
            or not reconciliation["claim_id"]
            or outcome not in event_by_outcome
            or type(reconciliation["outcome_record"]) is not dict
        ):
            raise RepositoryIntegrityError("claim reconciliation identity or outcome is invalid")
        event_digest_value = require_jcs_digest(reconciliation["reconciled_event_digest"])
        reconciled_event = events_by_digest.get(event_digest_value)
        if (
            reconciled_event is None
            or reconciled_event["event_type"] != event_by_outcome[outcome]
            or reconciled_event["payload"].get("claim_id") != reconciliation["claim_id"]  # type: ignore[union-attr]
        ):
            raise RepositoryIntegrityError("claim reconciliation is not bound to its exact event")
        canonical_json(reconciliation["outcome_record"])
        outcome_digest = semantic_record_digest({
            "contract": "claim-outcome-v1",
            "state": outcome,
            "value": reconciliation["outcome_record"],
        })
        changed = connection.execute(
            "UPDATE claims SET state=?,outcome_digest=?,revision=revision+1 WHERE claim_id=? AND state='unresolved'",
            (outcome, outcome_digest, reconciliation["claim_id"]),
        ).rowcount
        if changed != 1:
            raise RepositoryConflictError("action claim is unknown or already reconciled")

    @staticmethod
    def _evolve_security_state(
        connection: ManagedConnection,
        task_id: str,
        new_revision: int,
        snapshot_digest: str,
    ) -> None:
        row = connection.execute(
            "SELECT task_revision,state_json FROM task_security_states WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            return
        if row[0] != new_revision - 1:
            raise RepositoryIntegrityError("task security state revision is not current")
        state = parse_canonical_json(row[1])
        if type(state) is not dict or type(state.get("binding")) is not dict:
            raise RepositoryIntegrityError("task security state body is invalid")
        state = copy.deepcopy(state)
        binding = state["binding"]
        binding["snapshot_digest"] = snapshot_digest
        binding["binding_digest"] = SecurityBinding.digest_document(binding)
        state["task_revision"] = new_revision
        state["task_snapshot_digest"] = snapshot_digest
        for subject in state.get('retention_subjects',{}).values():
            if isinstance(subject,dict) and subject.get('category')=='pmf-aggregate':
                subject['snapshot_digest']=snapshot_digest
        state_digest = semantic_record_digest({
            "contract": "task-security-state-v1",
            "value": state,
        })
        changed = connection.execute(
            "UPDATE task_security_states SET task_revision=?,task_snapshot_digest=?,state_json=?,state_digest=? "
            "WHERE task_id=? AND task_revision=?",
            (
                new_revision, snapshot_digest, canonical_json(state), state_digest,
                task_id, new_revision - 1,
            ),
        ).rowcount
        if changed != 1:
            raise RepositoryConflictError("task security state evolution lost its CAS")

    def _apply_claim_compensation(
        self,
        connection: ManagedConnection,
        delta: dict[str, object],
        events_by_digest: dict[str, dict[str, object]],
    ) -> None:
        operation = delta.get("operation") if type(delta) is dict else None
        common = {
            "operation", "attempt_id", "protocol_version", "claim_id", "task_id", "original_action_id",
            "original_started_event_digest",
            "compensation_action_id", "compensation_authority_digest",
            "compensation_prepared_digest", "lease_id", "resources", "fencing_tokens",
            "expected_claim_revision", "target_id", "target_digest", "baseline_digest",
            "snapshot_digest", "disclosure_plan_digest",
        }
        required_by_operation = {
            "start_claim_compensation": common | {"start_event_digest"},
            "record_compensation_receipt": common | {
                "expected_attempt_revision", "start_event_digest", "receipt_event_digest",
                "receipt_object_digest", "receipt",
            },
            "reconcile_claim_compensation": common | {
                "expected_attempt_revision", "start_event_digest", "receipt_event_digest",
                "reconciled_event_digest", "fresh_observation",
            },
        }
        if operation not in required_by_operation or set(delta) != required_by_operation[operation]:
            raise RepositoryIntegrityError("claim compensation delta shape is not exact")
        resources = delta["resources"]
        fences = delta["fencing_tokens"]
        if (
            type(delta["attempt_id"]) is not str
            or not delta["attempt_id"]
            or delta["protocol_version"] != "1.0.0"
            or type(resources) is not list
            or resources != sorted(set(resources))
            or type(fences) is not dict
            or set(fences) != set(resources)
            or any(type(value) is not int or value <= 0 for value in fences.values())
            or type(delta["expected_claim_revision"]) is not int
            or delta["expected_claim_revision"] <= 0
        ):
            raise RepositoryIntegrityError("claim compensation identity/resources are invalid")
        claim = connection.execute(
            "SELECT action_id,task_id,lease_id,started_event_digest,state,revision FROM claims WHERE claim_id=?",
            (delta["claim_id"],),
        ).fetchone()
        claim_resources = connection.execute(
            "SELECT cr.resource_id,cr.fencing_token,rf.fencing_token FROM claim_resources cr "
            "JOIN resource_fences rf ON rf.resource_id=cr.resource_id "
            "WHERE cr.claim_id=? ORDER BY cr.resource_id",
            (delta["claim_id"],),
        ).fetchall()
        if (
            claim is None
            or claim[0] != delta["original_action_id"]
            or claim[1] != delta["task_id"]
            or claim[2] != delta["lease_id"]
            or claim[4] != "unresolved"
            or claim[5] != delta["expected_claim_revision"]
            or claim[3] != delta["original_started_event_digest"]
            or [row[0] for row in claim_resources] != resources
            or {row[0]: row[1] for row in claim_resources} != fences
            or any(row[1] != row[2] for row in claim_resources)
        ):
            raise RepositoryConflictError("recovery request does not match exact unresolved claim/latest fences")
        event_by_operation = {
            "start_claim_compensation": ("start_event_digest", "action.compensation_execution_started"),
            "record_compensation_receipt": ("receipt_event_digest", "action.compensation_receipt_recorded"),
            "reconcile_claim_compensation": ("reconciled_event_digest", "action.compensation_reconciled"),
        }
        event_field, event_type = event_by_operation[operation]
        event = events_by_digest.get(require_jcs_digest(delta[event_field]))
        if (
            event is None
            or event["event_type"] != event_type
            or event["task_id"] != delta["task_id"]
            or event["payload"].get("attempt_id") != delta["attempt_id"]  # type: ignore[union-attr]
            or event["payload"].get("claim_id") != delta["claim_id"]  # type: ignore[union-attr]
            or event["payload"].get("compensation_action_id") != delta["compensation_action_id"]  # type: ignore[union-attr]
        ):
            raise RepositoryIntegrityError("claim compensation delta is not bound to its exact event")
        if operation == "start_claim_compensation":
            expected_payload = {
                "attempt_id": delta["attempt_id"], "claim_id": delta["claim_id"],
                "original_action_id": delta["original_action_id"],
                "original_started_event_digest": delta["original_started_event_digest"],
                "compensation_action_id": delta["compensation_action_id"],
                "compensation_authority_digest": delta["compensation_authority_digest"],
                "compensation_prepared_digest": delta["compensation_prepared_digest"],
                "task_id": delta["task_id"], "lease_id": delta["lease_id"],
                "resources": delta["resources"], "fencing_tokens": delta["fencing_tokens"],
                "target_id": delta["target_id"], "target_digest": delta["target_digest"],
                "baseline_digest": delta["baseline_digest"], "snapshot_digest": delta["snapshot_digest"],
                "disclosure_plan_digest": delta["disclosure_plan_digest"],
            }
        elif operation == "record_compensation_receipt":
            receipt_value = delta["receipt"]
            if type(receipt_value) is not dict:
                raise RepositoryIntegrityError("claim compensation receipt is invalid")
            expected_payload = {
                "attempt_id": delta["attempt_id"], "start_event_digest": delta["start_event_digest"],
                "claim_id": delta["claim_id"], "compensation_action_id": delta["compensation_action_id"],
                "task_id": delta["task_id"], "receipt_digest": receipt_value.get("receipt_digest"),
                "raw_receipt_object_digest": delta["receipt_object_digest"],
                "receipt_source": receipt_value.get("receipt_source"), "target_id": delta["target_id"],
                "target_digest": delta["target_digest"], "lease_id": delta["lease_id"],
                "resources": delta["resources"], "fencing_tokens": delta["fencing_tokens"],
                "result": receipt_value.get("result"),
            }
        else:
            observation = delta["fresh_observation"]
            if type(observation) is not dict:
                raise RepositoryIntegrityError("claim compensation observation is invalid")
            expected_payload = {
                "attempt_id": delta["attempt_id"], "claim_id": delta["claim_id"],
                "compensation_action_id": delta["compensation_action_id"],
                "start_event_digest": delta["start_event_digest"],
                "receipt_event_digest": delta["receipt_event_digest"],
                "receipt_digest": observation.get("bound_receipt_digest"),
                "fresh_observation_digest": observation.get("observation_digest"),
                "fresh_observation_revision": observation.get("observation_revision"),
                "verified_outcome": "compensation_reconciled",
            }
        if event["payload"] != expected_payload:
            raise RepositoryIntegrityError("claim compensation event payload is not exact")
        if operation == "start_claim_compensation":
            existing = connection.execute(
                "SELECT attempt_id FROM claim_recovery_attempts WHERE claim_id=? OR compensation_action_id=?",
                (delta["claim_id"], delta["compensation_action_id"]),
            ).fetchone()
            if existing is not None:
                raise RepositoryConflictError("unresolved claim already has a recovery attempt")
            connection.execute(
                "INSERT INTO claim_recovery_attempts(attempt_id,claim_id,protocol_version,task_id,original_action_id,"
                "original_started_event_digest,compensation_action_id,compensation_authority_digest,"
                "compensation_prepared_digest,lease_id,resources_json,fencing_tokens_json,target_id,target_digest,"
                "baseline_digest,snapshot_digest,disclosure_plan_digest,state,revision,start_event_digest) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'started',1,?)",
                (
                    delta["attempt_id"], delta["claim_id"], delta["protocol_version"], delta["task_id"],
                    delta["original_action_id"], delta["original_started_event_digest"],
                    delta["compensation_action_id"], delta["compensation_authority_digest"],
                    delta["compensation_prepared_digest"], delta["lease_id"], canonical_json(resources),
                    canonical_json(fences), delta["target_id"], delta["target_digest"], delta["baseline_digest"],
                    delta["snapshot_digest"], delta["disclosure_plan_digest"], delta["start_event_digest"],
                ),
            )
            return
        attempt = connection.execute(
            "SELECT claim_id,protocol_version,task_id,original_action_id,original_started_event_digest,"
            "compensation_action_id,compensation_authority_digest,compensation_prepared_digest,lease_id,"
            "resources_json,fencing_tokens_json,target_id,target_digest,baseline_digest,snapshot_digest,"
            "disclosure_plan_digest,state,revision,start_event_digest,receipt_event_digest,receipt_digest "
            "FROM claim_recovery_attempts WHERE attempt_id=?",
            (delta["attempt_id"],),
        ).fetchone()
        expected_common = (
            delta["claim_id"], delta["protocol_version"], delta["task_id"], delta["original_action_id"],
            delta["original_started_event_digest"], delta["compensation_action_id"],
            delta["compensation_authority_digest"], delta["compensation_prepared_digest"], delta["lease_id"],
            canonical_json(resources), canonical_json(fences), delta["target_id"], delta["target_digest"],
            delta["baseline_digest"], delta["snapshot_digest"], delta["disclosure_plan_digest"],
        )
        if attempt is None or attempt[:16] != expected_common or attempt[18] != delta["start_event_digest"]:
            raise RepositoryConflictError("recovery attempt binding changed")
        if operation == "record_compensation_receipt":
            receipt = delta["receipt"]
            receipt_keys = {
                "protocol_version", "attempt_id", "claim_id", "task_id", "original_action_id",
                "compensation_action_id", "start_event_digest", "authority_digest",
                "prepared_action_digest", "target_id", "target_digest", "lease_id", "resources",
                "fencing_tokens", "receipt_source", "result", "raw_result_digest",
                "raw_receipt_object_digest", "receipt_digest",
            }
            if (
                attempt[16] != "started"
                or attempt[17] != delta["expected_attempt_revision"]
                or type(receipt) is not dict
                or set(receipt) != receipt_keys
                or receipt.get("protocol_version") != delta["protocol_version"]
                or receipt.get("attempt_id") != delta["attempt_id"]  # type: ignore[union-attr]
                or receipt.get("start_event_digest") != delta["start_event_digest"]  # type: ignore[union-attr]
                or receipt.get("claim_id") != delta["claim_id"]
                or receipt.get("task_id") != delta["task_id"]
                or receipt.get("original_action_id") != delta["original_action_id"]
                or receipt.get("compensation_action_id") != delta["compensation_action_id"]
                or receipt.get("authority_digest") != delta["compensation_authority_digest"]
                or receipt.get("prepared_action_digest") != delta["compensation_prepared_digest"]
                or receipt.get("target_id") != delta["target_id"]
                or receipt.get("target_digest") != delta["target_digest"]
                or receipt.get("lease_id") != delta["lease_id"]
                or receipt.get("resources") != delta["resources"]
                or receipt.get("fencing_tokens") != delta["fencing_tokens"]
                or receipt.get("receipt_source") not in {"tool-return", "post-crash-target-query"}
                or receipt.get("result") not in {"succeeded", "failed", "unknown"}
                or receipt.get("raw_receipt_object_digest") != delta["receipt_object_digest"]
            ):
                raise RepositoryConflictError("recovery receipt state/binding is invalid")
            receipt_digest = receipt.get("receipt_digest")
            require_jcs_digest(receipt_digest)
            require_jcs_digest(receipt.get("raw_result_digest"))
            require_object_digest(delta["receipt_object_digest"])
            actual_receipt_digest = semantic_record_digest({
                "contract": "claim-compensation-receipt-v1",
                "value": {key: value for key, value in receipt.items() if key != "receipt_digest"},
            })
            if receipt_digest != actual_receipt_digest:
                raise RepositoryIntegrityError("recovery receipt body digest is invalid")
            if event["payload"].get("receipt_digest") != receipt_digest:  # type: ignore[union-attr]
                raise RepositoryIntegrityError("recovery receipt event digest binding is invalid")
            changed = connection.execute(
                "UPDATE claim_recovery_attempts SET state='receipt_recorded',revision=revision+1,"
                "receipt_event_digest=?,receipt_json=?,receipt_digest=?,receipt_object_digest=? "
                "WHERE attempt_id=? AND state='started' AND revision=?",
                (
                    delta["receipt_event_digest"], canonical_json(receipt), receipt_digest,
                    delta["receipt_object_digest"], delta["attempt_id"],
                    delta["expected_attempt_revision"],
                ),
            ).rowcount
        else:
            observation = delta["fresh_observation"]
            observation_keys = {
                "target_id", "target_digest", "resource_id", "fresh", "observation_revision",
                "state", "bound_receipt_digest", "observation_digest",
            }
            if (
                attempt[16] != "receipt_recorded"
                or attempt[17] != delta["expected_attempt_revision"]
                or attempt[19] != delta["receipt_event_digest"]
                or type(observation) is not dict
                or set(observation) != observation_keys
                or observation.get("fresh") is not True
                or type(observation.get("observation_revision")) is not int
                or observation.get("observation_revision", 0) <= 0
                or observation.get("target_id") != delta["target_id"]
                or observation.get("target_digest") != delta["target_digest"]
                or observation.get("bound_receipt_digest") != attempt[20]
            ):
                raise RepositoryConflictError("recovery reconciliation state/observation is invalid")
            canonical_json(observation)
            actual_observation_digest = semantic_record_digest({
                "contract": "fresh-target-observation-v1",
                "value": {
                    key: value for key, value in observation.items()
                    if key not in {"bound_receipt_digest", "observation_digest"}
                },
            })
            if observation.get("observation_digest") != actual_observation_digest:
                raise RepositoryIntegrityError("fresh target observation digest is invalid")
            if self._action_journal is None:
                raise RepositoryIntegrityError(
                    "recovery reconciliation requires the bounded durable action verifier",
                )
            compensation_prepared = self._action_journal.load_prepared_in_transaction(
                connection,
                delta["compensation_prepared_digest"],
            )
            target_resources = tuple(
                resource for resource in compensation_prepared.resources
                if resource != f"task:{compensation_prepared.task_id}"
            )
            if (
                compensation_prepared.action_id != delta["compensation_action_id"]
                or compensation_prepared.task_id != delta["task_id"]
                or compensation_prepared.action_kind != "rollback"
                or compensation_prepared.target_id != delta["target_id"]
                or compensation_prepared.target_digest != delta["target_digest"]
                or tuple(resources) != compensation_prepared.resources
                or len(target_resources) != 1
                or observation.get("resource_id") != target_resources[0]
                or observation.get("state") != dict(compensation_prepared.expected_postcondition)
            ):
                raise RepositoryIntegrityError(
                    "fresh observation does not match durable rollback postcondition",
                )
            outcome_digest = semantic_record_digest({
                "contract": "claim-outcome-v1", "state": "compensation_reconciled", "value": observation,
            })
            changed = connection.execute(
                "UPDATE claims SET state='compensation_reconciled',outcome_digest=?,revision=revision+1 "
                "WHERE claim_id=? AND state='unresolved' AND revision=?",
                (outcome_digest, delta["claim_id"], delta["expected_claim_revision"]),
            ).rowcount
            if changed == 1:
                changed = connection.execute(
                    "UPDATE claim_recovery_attempts SET state='reconciled',revision=revision+1 "
                    "WHERE attempt_id=? AND state='receipt_recorded' AND revision=?",
                    (delta["attempt_id"], delta["expected_attempt_revision"]),
                ).rowcount
        if changed != 1:
            raise RepositoryConflictError("claim compensation delta lost its exact CAS")

    def commit(
        self,
        batch: CommitBatch,
        *,
        fence_token: object | None = None,
        source_fence_token: object | None = None,
        learning_observation: object | None = None,
    ) -> CommitResult:
        if self._context_validator is not None:
            self._context_validator()
        if fence_token is not None:
            from graph_engineering.application.profile_execution import (
                TargetObservationFence,
            )

            if type(fence_token) is not TargetObservationFence:
                raise RepositoryIntegrityError(
                    "category target observation fence is missing or forged",
                )
        if source_fence_token is not None:
            from graph_engineering.application.profile_execution import (
                CategorySourceFenceRequest,
            )

            if type(source_fence_token) is not CategorySourceFenceRequest:
                raise RepositoryIntegrityError(
                    "category source fence is missing or forged",
                )
        self._validate_batch(batch)
        request_digest = semantic_record_digest({
            "contract": "repository-commit-v1", "value": self._request_value(batch),
        })
        installation = None if self._locks.installation_held_by_current_thread() else self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                self._fault("commit.before_transaction")
                with self._factory.open("application") as connection:
                    result: CommitResult | None = None
                    with connection.transaction():
                        if self._context_validator is not None:
                            self._context_validator()
                        duplicate = connection.execute(
                            "SELECT request_digest,revision,head_digest FROM transactions "
                            "WHERE transaction_id=?",
                            (batch.transaction_id,),
                        ).fetchone()
                        if duplicate is not None:
                            if duplicate[0] != request_digest:
                                raise RepositoryConflictError("transaction ID was reused for another request")
                            self._validate_current_extension_pin_locked(
                                connection, batch.task_id,
                            )
                            result = CommitResult("COMMITTED", duplicate[1], duplicate[2])
                        else:
                            head = connection.execute(
                                "SELECT revision,head_sequence,head_digest,snapshot_json FROM tasks WHERE task_id=?",
                                (batch.task_id,),
                            ).fetchone()
                            if head is None:
                                if batch.expected_task_revision != 0:
                                    raise RepositoryConflictError("task CAS revision does not exist")
                                previous_sequence = 0
                                previous_digest: str | None = None
                                prior_snapshot_json: object = None
                            else:
                                if head[0] != batch.expected_task_revision:
                                    raise RepositoryConflictError("task CAS revision mismatch")
                                previous_sequence = head[1]
                                previous_digest = head[2]
                                prior_snapshot_json = parse_canonical_json(head[3])
                            if (batch.claim_delta is not None
                                    or any(event.get("event_type") in {"action.execution_started",
                                        "action.compensation_execution_started"} for event in batch.events)
                                    or batch.claim_compensation_delta is not None
                                    and batch.claim_compensation_delta.get("operation")=="start_claim_compensation"
                                    or batch.action_journal_delta is not None
                                    and batch.action_journal_delta.get("operation") in {"start","compensation_start"}):
                                from .action_authority import ActionAuthorityLedger, installed_policy
                                if self._action_journal is None:
                                    raise RepositoryIntegrityError("action start requires a bound journal")
                                ActionAuthorityLedger(self._factory,installed_policy())._validate_start_locked(
                                    connection,self._action_journal,batch)
                            extension_pin_binding = self._validate_extension_pin_commit_locked(
                                connection, batch, task_exists=head is not None,
                            )
                            validated: list[dict[str, object]] = []
                            for offset, event in enumerate(batch.events, start=1):
                                checked = self._validate_event(
                                    event,
                                    task_id=batch.task_id,
                                    sequence=previous_sequence + offset,
                                    expected_revision=batch.expected_task_revision,
                                    previous_digest=previous_digest,
                                )
                                validated.append(checked)
                                previous_digest = checked["event_digest"]  # type: ignore[assignment]
                            assert previous_digest is not None
                            if batch.claim_compensation_delta is not None:
                                expected_event_type = {
                                    "start_claim_compensation": "action.compensation_execution_started",
                                    "record_compensation_receipt": "action.compensation_receipt_recorded",
                                    "reconcile_claim_compensation": "action.compensation_reconciled",
                                }.get(batch.claim_compensation_delta.get("operation"))
                                if (
                                    len(validated) != 1
                                    or expected_event_type is None
                                    or validated[0]["event_type"] != expected_event_type
                                ):
                                    raise RepositoryIntegrityError(
                                        "claim compensation transaction requires its one exact event type",
                                    )
                            new_revision = batch.expected_task_revision + 1
                            snapshot = copy.deepcopy(batch.snapshot)
                            if (
                                snapshot.get("task_id") != batch.task_id
                                or type(snapshot.get("revision")) is not int
                                or snapshot.get("revision") != new_revision
                            ):
                                raise RepositoryIntegrityError("snapshot task or revision mismatch")
                            snapshot_json = canonical_json(snapshot)
                            snapshot_digest = semantic_record_digest({
                                "contract": "repository-snapshot-v1", "value": snapshot,
                            })
                            self._verify_objects(connection, batch.object_digests)
                            self._validate_lease_assertion(
                                connection,
                                batch.task_id,
                                batch.lease_assertion,
                                (
                                    batch.claim_reconciliation_delta.get("claim_id")
                                    if batch.claim_reconciliation_delta is not None
                                    else batch.claim_compensation_delta.get("claim_id")
                                    if batch.claim_compensation_delta is not None
                                    else None
                                ),
                            )
                            self._validate_lifecycle_assertion(connection, batch, validated)
                            if head is None:
                                connection.execute(
                                    "INSERT INTO tasks(task_id,revision,head_sequence,head_digest,snapshot_json,snapshot_digest,integrity_status) "
                                    "VALUES(?,?,?,?,?,?,'ok')",
                                    (
                                        batch.task_id, new_revision, previous_sequence + len(validated),
                                        previous_digest, snapshot_json, snapshot_digest,
                                    ),
                                )
                            else:
                                changed = connection.execute(
                                    "UPDATE tasks SET revision=?,head_sequence=?,head_digest=?,snapshot_json=?,snapshot_digest=?,integrity_status='ok' "
                                    "WHERE task_id=? AND revision=?",
                                    (
                                        new_revision, previous_sequence + len(validated), previous_digest,
                                        snapshot_json, snapshot_digest, batch.task_id,
                                        batch.expected_task_revision,
                                    ),
                                ).rowcount
                                if changed != 1:
                                    raise RepositoryConflictError("task CAS update lost")
                            connection.executemany(
                                "INSERT INTO events(task_id,sequence,event_id,event_type,body_json,previous_event_digest,event_digest,transaction_id) "
                                "VALUES(?,?,?,?,?,?,?,?)",
                                [
                                    (
                                        batch.task_id, item["sequence"], item["event_id"],
                                        item["event_type"], canonical_json(item),
                                        item["previous_event_digest"], item["event_digest"],
                                        batch.transaction_id,
                                    )
                                    for item in validated
                                ],
                            )
                            self._apply_project_scope_delta(
                                connection, batch, validated, prior_snapshot_json,
                            )
                            self._apply_lifecycle_plan_delta(connection, batch, validated)
                            if extension_pin_binding is not None:
                                connection.execute(
                                    "INSERT INTO task_extension_pin_bindings"
                                    "(task_id,generation,pin_digest,previous_pin_digest,binding_json,"
                                    "binding_digest,transaction_id) VALUES(?,?,?,?,?,?,?)",
                                    (
                                        extension_pin_binding["task_id"],
                                        extension_pin_binding["generation"],
                                        extension_pin_binding["pin_digest"],
                                        extension_pin_binding["previous_pin_digest"],
                                        canonical_json({
                                            key: value for key, value in extension_pin_binding.items()
                                            if key != "binding_digest"
                                        }),
                                        extension_pin_binding["binding_digest"],
                                        extension_pin_binding["transaction_id"],
                                    ),
                                )
                            self._fault("commit.after_events")
                            existing_catalog = connection.execute(
                                "SELECT fields_json FROM catalog WHERE task_id=?", (batch.task_id,),
                            ).fetchone()
                            catalog = {} if existing_catalog is None else parse_canonical_json(existing_catalog[0])
                            if not isinstance(catalog, dict):
                                raise RepositoryIntegrityError("catalog record is not an object")
                            catalog.update(copy.deepcopy(batch.catalog_delta))
                            connection.execute(
                                "INSERT INTO catalog(task_id,fields_json) VALUES(?,?) "
                                "ON CONFLICT(task_id) DO UPDATE SET fields_json=excluded.fields_json",
                                (batch.task_id, canonical_json(catalog)),
                            )
                            connection.executemany(
                                "INSERT INTO object_references(task_id,digest,ref_kind,transaction_id) "
                                "VALUES(?,?,'task',?) ON CONFLICT(task_id,digest,ref_kind) DO NOTHING",
                                [
                                    (batch.task_id, digest, batch.transaction_id)
                                    for digest in batch.object_digests
                                ],
                            )
                            if batch.claim_delta is not None:
                                if batch.claim_delta.get("task_id") != batch.task_id:
                                    raise RepositoryIntegrityError("claim task does not match commit task")
                                self._insert_claim(
                                    connection, batch.claim_delta,
                                    {
                                        item["event_digest"]: item
                                        for item in validated
                                    },  # type: ignore[misc]
                                    batch.lease_assertion.get("lease_id"),
                                )
                            if batch.claim_reconciliation_delta is not None:
                                self._reconcile_claim(
                                    connection, batch.claim_reconciliation_delta,
                                    {
                                        item["event_digest"]: item
                                        for item in validated
                                    },  # type: ignore[misc]
                                )
                            if batch.claim_compensation_delta is not None:
                                if batch.claim_compensation_delta.get("task_id") != batch.task_id:
                                    raise RepositoryIntegrityError(
                                        "claim compensation task does not match commit task",
                                    )
                                self._apply_claim_compensation(
                                    connection,
                                    batch.claim_compensation_delta,
                                    {
                                        item["event_digest"]: item
                                        for item in validated
                                    },  # type: ignore[misc]
                                )
                            if batch.action_journal_delta is not None:
                                from .actions import ActionJournalRepository
                                ActionJournalRepository.apply_delta(
                                    connection,
                                    batch.action_journal_delta,
                                    {item["event_digest"]: item for item in validated},  # type: ignore[misc]
                                )
                                if (
                                    batch.claim_compensation_delta is not None
                                    and batch.claim_compensation_delta.get("operation")
                                    == "record_compensation_receipt"
                                ):
                                    self._fault("commit.after_recovery_journal_apply")
                            if batch.concrete_action_delta is not None:
                                from .concrete_actions import ConcreteActionRecordRepository
                                if (
                                    self._concrete_action_schemas is None
                                    or self._concrete_action_context is None
                                ):
                                    raise RepositoryIntegrityError(
                                        "concrete action installed schema registry is unavailable",
                                    )
                                ConcreteActionRecordRepository.apply_delta(
                                    connection,
                                    batch.concrete_action_delta,
                                    schema_registry=self._concrete_action_schemas,
                                    context=self._concrete_action_context,
                                )
                            self._evolve_security_state(
                                connection,
                                batch.task_id,
                                new_revision,
                                snapshot_digest,
                            )
                            from .learning import _observe_task_commit
                            _observe_task_commit(
                                self, connection, batch, validated, prior_snapshot_json,
                                snapshot, learning_observation,
                            )
                            connection.execute(
                                "INSERT INTO transactions(transaction_id,request_digest,task_id,revision,head_digest) "
                                "VALUES(?,?,?,?,?)",
                                (
                                    batch.transaction_id, request_digest, batch.task_id,
                                    new_revision, previous_digest,
                                ),
                            )
                            self._fault("commit.before_commit")
                            if source_fence_token is not None:
                                source_fence_token._authority.consume_source_fence_locked(
                                    source_fence_token,
                                    self,
                                    connection,
                                    prior_snapshot_json,
                                )
                            if fence_token is not None:
                                fence_token._authority.consume_fence(fence_token)
                            result = CommitResult("COMMITTED", new_revision, previous_digest)
                    self._fault("commit.after_commit")
                    assert result is not None
                    return result
            finally:
                self._locks.release(object_lock)
        finally:
            if installation is not None:
                self._locks.release(installation)


    def _require_provenance_scope(self) -> None:
        """Require exact, idle command ports before entering the read lock order."""
        from .actions import ActionJournalRepository
        from graph_engineering.core.contracts.resources import WorkContext

        self._require_command_context()
        scope = self.command_scope
        if (
            type(self._action_journal) is not ActionJournalRepository
            or type(self._objects) is not ObjectRepository
            or type(self._locks) is not LockedFileRegistry
            or type(self._action_journal._context) is not WorkContext
            or self._objects._locks is not self._locks
            or self._objects._closed
            or self._locks._root != scope.repository_root
        ):
            raise RepositoryIntegrityError("provenance repository ports are foreign")
        for port in (self, self._action_journal, self._objects):
            factory = port._factory
            if (type(factory) is not ConnectionFactory
                    or factory._command_scope is not scope
                    or factory.data_root != scope.repository_root):
                raise RepositoryIntegrityError("provenance repository scope differs")
        self._locks._check()
        with LockedFileRegistry._ACTIVE_GUARD:
            registries = tuple(LockedFileRegistry._ACTIVE_ROOTS.values())
        for registry in registries:
            with registry._registry_guard:
                if registry._thread_tokens.get(threading.get_ident()):
                    raise RepositoryIntegrityError("provenance repository token is held")
        if scope._connections:
            raise RepositoryIntegrityError("provenance repository connection is held")

    def _read_provenance_object(
        self, digest: str, size: int, *, retained_bytes: int,
    ) -> bytes:
        """Read one CAS body with descriptor preflight and a growth sentinel."""
        require_object_digest(digest)
        if type(size) is not int or size < 0 or type(retained_bytes) is not int or retained_bytes < 0:
            raise ObjectIntegrityError("provenance object size is invalid")
        context = self._action_journal._context
        directory = self._objects._object_directory(digest, create=False)
        descriptor = None
        reserved = 0
        try:
            _fanout, filename = self._objects._object_names(digest)
            named = directory.stat(filename)
            descriptor = directory.open_file(filename, os.O_RDONLY | os.O_NONBLOCK)
            metadata = os.fstat(descriptor)

            def identity(value: os.stat_result) -> tuple[int, ...]:
                return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                        value.st_size, value.st_mtime_ns, value.st_ctime_ns)

            def trusted(value: os.stat_result) -> bool:
                return (stat.S_ISREG(value.st_mode) and value.st_uid == os.getuid()
                        and stat.S_IMODE(value.st_mode) == self._objects._policy.file_mode)

            if not trusted(named) or not trusted(metadata) or identity(named) != identity(metadata):
                raise ObjectIntegrityError("provenance object descriptor/path binding is invalid")
            actual = metadata.st_size
            context.check_limit("raw_document_bytes", actual, source_id=digest)
            for limit in ("result_bytes", "temporary_units"):
                context.check_limit(limit, retained_bytes + actual, source_id=digest)
            if actual != size:
                raise ObjectIntegrityError("provenance object actual size differs from metadata")
            context.acquire_temporary(actual, source_id=digest, operation_path=context.child_path(()))
            reserved = actual
            # One admitted allocation avoids retaining both chunks and a joined copy.
            # A short regular-file read rejects; no retry can accumulate more buffers.
            body = os.read(descriptor, actual)
            if len(body) != actual:
                raise ObjectIntegrityError("provenance object short read")
            if os.read(descriptor, 1):
                raise ObjectIntegrityError("provenance object grew during bounded read")
            if (identity(os.fstat(descriptor)) != identity(metadata)
                    or identity(directory.stat(filename)) != identity(metadata)):
                raise ObjectIntegrityError("provenance object changed during bounded read")
            if self._objects.digest(body) != digest:
                raise ObjectIntegrityError("provenance object digest mismatch")
            return body
        except OSError as error:
            raise ObjectIntegrityError("provenance object is missing or untrusted") from error
        finally:
            if reserved:
                context.release_temporary(reserved)
            if descriptor is not None:
                os.close(descriptor)
            directory.close()

    def _capture_action_provenance(self, task_id: str, action_id: str) -> FrozenMap:
        participants = (self, self._objects, self._action_journal, self._action_journal._context)
        budget = next((getattr(port, "_recovery_read_budget", None) for port in participants
                       if getattr(port, "_recovery_read_budget", None) is not None), None)
        if budget is not None:
            if (type(budget) is not _RecoveryReadBudget or budget.task_id != task_id
                    or budget.command_scope is not self.command_scope
                    or any(getattr(port, "_recovery_read_budget", None) is not budget
                           for port in participants)):
                raise RepositoryIntegrityError("action capture has a foreign recovery owner")
            budget._require_active()
        with ExitStack() as stack:
            return self._capture_action_provenance_scoped(task_id, action_id, stack, budget)

    def _capture_action_provenance_scoped(self, task_id, action_id, stack, budget):
        """One bounded SQL statement captures all cross-table provenance facts."""
        from contextlib import nullcontext
        from graph_engineering.core.actions import AuthorityEnvelope, PreparedAction
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.core.contracts.strict_json import parse_json

        journal = self._action_journal
        context = journal._context
        source_id = "action-provenance"
        claim_id = "claim:" + action_id
        recovery_columns = (
            "attempt_id", "claim_id", "protocol_version", "task_id", "original_action_id",
            "original_started_event_digest", "compensation_action_id", "compensation_authority_digest",
            "compensation_prepared_digest", "lease_id", "resources_json", "fencing_tokens_json",
            "target_id", "target_digest", "baseline_digest", "snapshot_digest", "disclosure_plan_digest",
            "state", "revision", "start_event_digest", "receipt_event_digest", "receipt_json",
            "receipt_digest", "receipt_object_digest",
        )
        claim_columns = ("claim_id", "action_id", "task_id", "lease_id", "started_event_digest",
                         "revision", "state", "outcome_digest")
        journal_columns = ("action_id", "task_id", "state", "revision", "idempotency_key",
                           "prepared_json", "prepared_digest", "authority_json", "authority_digest",
                           "receipt_json", "reconciliation_json")
        groups = (
            ("task", ("task_id", "revision", "head_sequence", "head_digest",
                      "snapshot_json", "snapshot_digest", "integrity_status"),
             "tasks WHERE task_id=:task_id"),
            ("journal", journal_columns,
             "action_journal WHERE action_id IN (SELECT action_id FROM selected_ids) "
             "OR prepared_digest IN (SELECT prepared_digest FROM selected_journals) "
             "OR authority_digest IN (SELECT authority_digest FROM selected_journals)"),
            ("claim", claim_columns, "selected_claims"),
            ("resource", ("claim_id", "resource_id", "fencing_token"),
             "claim_resources WHERE claim_id IN (SELECT claim_id FROM selected_claims)"),
            ("recovery", recovery_columns, "selected_attempts"),
            ("event", ("e.sequence", "e.body_json", "e.event_id", "e.event_type",
                       "e.previous_event_digest", "e.event_digest", "e.transaction_id",
                       "t.task_id", "t.revision", "t.head_digest", "t.request_digest"),
             "events e LEFT JOIN transactions t ON t.transaction_id=e.transaction_id "
             "WHERE e.task_id=:task_id"),
            ("reference", ("r.digest", "r.ref_kind", "r.transaction_id", "o.size", "o.state"),
             "object_references r LEFT JOIN objects o ON o.digest=r.digest WHERE r.task_id=:task_id"),
        )
        if budget is not None:
            ctes = (
                "selected_attempts AS (SELECT * FROM claim_recovery_attempts "
                "WHERE claim_id=:claim_id OR original_action_id=:action_id OR compensation_action_id=:action_id)",
                "selected_ids AS (SELECT :action_id AS action_id UNION "
                "SELECT compensation_action_id FROM selected_attempts UNION SELECT original_action_id FROM selected_attempts)",
                "selected_journals AS (SELECT * FROM action_journal WHERE action_id IN (SELECT action_id FROM selected_ids))",
                "selected_claims AS (SELECT * FROM claims WHERE claim_id=:claim_id "
                "OR action_id IN (SELECT action_id FROM selected_ids) OR claim_id IN (SELECT claim_id FROM selected_attempts))",
            )
            connection = stack.enter_context(self._factory.open("doctor"))
            captured = stack.enter_context(_recovery_rows(connection, groups,
                {"task_id": task_id, "action_id": action_id, "claim_id": claim_id},
                context, budget, source_id=source_id, ctes=ctes))
        else:
            # Expressions and table names are fixed above; only IDs/limits are parameters.
            # A BLOB sentinel prevents SQLite from returning an oversized TEXT value.
            selects = []
            for tag, columns, table in groups:
                bounded = [f"CASE WHEN typeof({column})='text' AND "
                           f"length(CAST({column} AS BLOB))>:text_limit THEN zeroblob(1) "
                           f"ELSE {column} END" for column in columns]
                bounded += ["NULL"] * (24 - len(columns))
                selects.append("SELECT '" + tag + "'," + ",".join(bounded) + " FROM " + table)
            query = (
                "WITH selected_attempts AS (SELECT * FROM claim_recovery_attempts "
                "WHERE claim_id=:claim_id OR original_action_id=:action_id OR compensation_action_id=:action_id), "
                "selected_ids AS (SELECT :action_id AS action_id UNION "
                "SELECT compensation_action_id FROM selected_attempts UNION "
                "SELECT original_action_id FROM selected_attempts), "
                "selected_journals AS (SELECT * FROM action_journal WHERE action_id IN (SELECT action_id FROM selected_ids)), "
                "selected_claims AS (SELECT * FROM claims WHERE claim_id=:claim_id "
                "OR action_id IN (SELECT action_id FROM selected_ids) "
                "OR claim_id IN (SELECT claim_id FROM selected_attempts)) "
                + " UNION ALL ".join(selects) + " LIMIT :row_limit"
            )
            captured = {tag: [] for tag, _columns, _table in groups}
            lengths = {tag: len(columns) for tag, columns, _table in groups}
            count = retained = 0
            with self._factory.open("doctor") as connection:
                cursor = connection.execute(query, {
                    "task_id": task_id, "action_id": action_id, "claim_id": claim_id,
                    "text_limit": context.profile.limits["raw_document_bytes"],
                    "row_limit": context.profile.limits["array_items"] + 1,
                })
                try:
                    while (row := cursor.fetchone()) is not None:
                        count += 1
                        context.check_limit("array_items", count, source_id=source_id)
                        values = row[1:1 + lengths[row[0]]]
                        for value in values:
                            if type(value) not in (str, int, type(None)):
                                raise RepositoryIntegrityError("provenance SQL value is invalid or over limit")
                            retained += len(value.encode("utf-8")) if type(value) is str else 8
                        context.check_limit("temporary_units", retained, source_id=source_id)
                        context.check_limit("result_bytes", retained, source_id=source_id)
                        captured[row[0]].append(values)
                finally:
                    cursor.close()

        def parsed(encoded: str) -> object:
            if budget is not None:
                with _recovery_json(encoded, context, budget, source_id=source_id) as value:
                    _recovery_adopt(value, context, budget, record_fields={}, source_id=source_id)
                    stack.callback(budget.release_projection, value)
                    return value
            value = parse_json(encoded, context=context, source_id=source_id,
                               operation_path=context.child_path(()))
            if canonical_json(value) != encoded:
                raise RepositoryIntegrityError("provenance JSON is not canonical")
            return value

        if len(captured["task"]) != 1 or len(captured["claim"]) != 1 or len(captured["recovery"]) > 1:
            raise RepositoryIntegrityError("provenance task, claim or recovery is missing or ambiguous")
        task = dict(zip(groups[0][1], captured["task"][0]))
        snapshot = parsed(task.pop("snapshot_json"))
        if (type(snapshot) is not dict or snapshot.get("task_id") != task_id
                or type(snapshot.get("revision")) is not int
                or snapshot.get("revision") != task["revision"]
                or task["snapshot_digest"] != _recovery_record_digest({
                    "contract": "repository-snapshot-v1", "value": snapshot}, context, budget,
                    source_id="cold-action-snapshot-digest")):
            raise RepositoryIntegrityError("provenance snapshot binding is invalid")
        event_rows = sorted(captured["event"], key=lambda row: row[0])
        events = self._validate_replay_rows(
            task_id, (task["revision"], task["head_sequence"], task["head_digest"], task["integrity_status"]),
            event_rows, parser=parsed, _budget=budget, _context=context,
        )
        task.pop("integrity_status")
        event_values = [
            {"event": event, "transaction_id": row[6], "transaction_revision": row[8],
             "transaction_head_digest": row[9], "transaction_request_digest": row[10]}
            for row, event in zip(event_rows, events)
        ]
        transaction_ids = {row[6] for row in event_rows}
        references = []
        for digest, kind, transaction_id, size, state in sorted(captured["reference"]):
            require_object_digest(digest)
            if (kind != "task" or transaction_id not in transaction_ids or type(size) is not int
                    or size < 0 or state != "available"):
                raise RepositoryIntegrityError("provenance object reference is unavailable or foreign")
            references.append({"digest": digest, "kind": kind, "transaction_id": transaction_id,
                               "size": size, "state": state})
        if len({item["digest"] for item in references}) != len(references):
            raise RepositoryIntegrityError("provenance object reference is ambiguous")

        claim = dict(zip(claim_columns, captured["claim"][0]))
        if (claim["claim_id"] != claim_id or claim["action_id"] != action_id
                or claim["task_id"] != task_id or type(claim["revision"]) is not int
                or claim["revision"] <= 0):
            raise RepositoryIntegrityError("provenance original claim identity is invalid")
        require_jcs_digest(claim["started_event_digest"])
        if claim["outcome_digest"] is not None:
            require_jcs_digest(claim["outcome_digest"])
        resources = {}
        for selected_claim, resource, token in sorted(captured["resource"]):
            if (selected_claim != claim_id or type(resource) is not str or not resource
                    or resource in resources or type(token) is not int or token <= 0):
                raise RepositoryIntegrityError("provenance claim resource is invalid")
            resources[resource] = token
        if not resources:
            raise RepositoryIntegrityError("provenance claim has no resources")
        claim["resources"], claim["fencing_tokens"] = list(resources), resources
        recovery = None
        selected_ids = {action_id}
        if captured["recovery"]:
            recovery = dict(zip(recovery_columns, captured["recovery"][0]))
            for key in ("resources", "fencing_tokens", "receipt"):
                encoded = recovery.pop(key + "_json")
                recovery[key] = None if encoded is None else parsed(encoded)
            if (recovery["claim_id"] != claim_id or recovery["task_id"] != task_id
                    or recovery["original_action_id"] != action_id
                    or recovery["compensation_action_id"] == action_id):
                raise RepositoryIntegrityError("provenance recovery identity is invalid")
            selected_ids.add(recovery["compensation_action_id"])

        journals = []
        for row in sorted(captured["journal"]):
            value = dict(zip(journal_columns, row))
            if value["action_id"] not in selected_ids or value["task_id"] != task_id:
                raise RepositoryIntegrityError("provenance journal digest alias or identity is invalid")
            for key, schema in (("prepared", "prepared-action"), ("authority", "authority-envelope")):
                encoded = value.pop(key + "_json")
                if budget is None:
                    value[key] = journal._parse_stored(
                        encoded, schema_id=f"urn:gew:schema:{schema}:1.0.0", source_id=source_id)
                else:
                    value[key] = parsed(encoded)
                    size = canonical_byte_length(value[key]) + 256
                    with budget.reserve(context, units=6 * size, byte_count=4 * size,
                                        source_id="provenance-journal-schema"):
                        if (type(value[key]) is not dict
                                or journal._schemas.validate(f"urn:gew:schema:{schema}:1.0.0", value[key], context)):
                            raise RepositoryIntegrityError("provenance journal body fails installed schema")
            size = 0 if budget is None else canonical_byte_length(value)
            with (nullcontext() if budget is None else budget.reserve(context,
                    units=8 * size, byte_count=3 * size, source_id="provenance-journal-validation")):
                try:
                    prepared = PreparedAction.from_dict(value["prepared"], context=context)
                    authority = AuthorityEnvelope.from_dict(value["authority"], context=context)
                    if (prepared.action_id != value["action_id"] or prepared.task_id != task_id
                            or value["idempotency_key"] != prepared.idempotency_key
                            or value["prepared_digest"] != prepared.prepared_action_digest
                            or value["authority_digest"] != authority.authority_digest
                            or authority.task_id != task_id
                            or authority.prepared_action_digest != prepared.prepared_action_digest
                            or type(value["revision"]) is not int or value["revision"] <= 0):
                        raise RepositoryIntegrityError("provenance journal index binding is invalid")
                finally:
                    prepared = authority = None
            for key, validator in (("receipt", journal._validate_stored_receipt),
                                   ("reconciliation", journal._validate_stored_reconciliation)):
                encoded = value.pop(key + "_json")
                value[key] = None if encoded is None else (
                    parsed(encoded) if budget is not None
                    else journal._parse_stored_generic(encoded, source_id=source_id))
                if value[key] is not None:
                    size = 0 if budget is None else canonical_byte_length(value[key]) + 256
                    with (nullcontext() if budget is None else budget.reserve(context,
                            units=6 * size, byte_count=4 * size, source_id="provenance-receipt-validation")):
                        validator(value[key])
            journals.append(value)
        if {value["action_id"] for value in journals} != selected_ids or len(journals) != len(selected_ids):
            raise RepositoryIntegrityError("provenance selected journal is missing or ambiguous")

        receipts = [value["receipt"] for value in journals if value["receipt"] is not None]
        if recovery is not None and recovery["receipt"] is not None:
            if type(recovery["receipt"]) is not dict:
                raise RepositoryIntegrityError("provenance recovery receipt is invalid")
            size = 0 if budget is None else canonical_byte_length(recovery["receipt"]) + 256
            with (nullcontext() if budget is None else budget.reserve(context,
                    units=6 * size, byte_count=4 * size, source_id="provenance-recovery-validation")):
                journal._validate_stored_receipt(recovery["receipt"])
            receipts.append(recovery["receipt"])
        objects = []
        receipt_bytes = 0
        for digest in sorted({receipt["raw_receipt_object_digest"] for receipt in receipts}):
            selected = [reference for reference in references if reference["digest"] == digest]
            if len(selected) != 1:
                raise RepositoryIntegrityError("provenance receipt has no committed reference")
            if budget is not None:
                stack.enter_context(budget.reserve(context, units=selected[0]["size"],
                    byte_count=selected[0]["size"], source_id=digest))
            body = self._read_provenance_object(digest, selected[0]["size"],
                retained_bytes=receipt_bytes if budget is None else budget.retained_bytes - selected[0]["size"])
            receipt_bytes += len(body)
            value = parsed(body.decode("utf-8") if budget is None else body)
            objects.append({"digest": digest, "document": value})
        result = {"schema_version": "1.0", "task": task, "journals": journals, "claim": claim,
                  "recovery": recovery, "events": event_values, "references": references,
                  "receipt_objects": objects}
        # Account for the fixed-width digest before serializing the whole result.
        result["source_digest"] = "sha256-jcs-v1:" + "0" * 64
        context.check_limit("result_bytes", canonical_byte_length(result), source_id=source_id)
        result.pop("source_digest")
        if budget is None:
            result["source_digest"] = semantic_record_digest({"contract": "action-provenance-v1", "value": result})
            return freeze(result)
        size = canonical_byte_length(result)
        with budget.reserve(context, units=4 * size, byte_count=2 * size, source_id=source_id):
            result["source_digest"] = semantic_record_digest({"contract": "action-provenance-v1", "value": result})
        return _recovery_freeze(result, context, budget, source_id=source_id)

    def read_action_provenance(self, task_id: str, action_id: str) -> FrozenMap:
        """Return bounded immutable durable facts, never execution authority."""
        for value, label in ((task_id, "task ID"), (action_id, "action ID")):
            self._validate_identity(value, label)
            if "\x00" in value:
                raise RepositoryIntegrityError("provenance identity contains NUL")
        self._require_provenance_scope()
        for value in (task_id, action_id):
            self._action_journal._context.check_limit(
                "raw_document_bytes", len(value.encode("utf-8")), source_id="action-provenance-identity")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                context = self._action_journal._context
                budget = getattr(context, "_recovery_read_budget", None)
                first = self._capture_action_provenance(task_id, action_id)
                current = None
                try:
                    current = self._capture_action_provenance(task_id, action_id)
                    equal = first == current if budget is None else _recovery_equal(first, current, context, budget)
                    if not equal:
                        raise RepositoryConflictError("action provenance changed during query")
                except BaseException:
                    if current is not None and budget is not None:
                        budget.release_projection(current)
                    raise
                finally:
                    if budget is not None:
                        budget.release_projection(first)
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)
        self._require_provenance_scope()
        return current

    def read_category_recovery_sources(self, task_id: str, *, phase: str) -> Mapping[str, object]:
        """Return fixed, immutable cold-source facts under the caller's budget.

        The locator is data only. The application must validate the complete
        sources, current authority and physical target before issuing a handle.
        """
        self._validate_identity(task_id, "cold source task ID")
        if type(phase) is not str or phase not in {"locator", "sources"}:
            raise RepositoryIntegrityError("cold source phase is not supported")
        context = self._action_journal._context
        budget = getattr(context, "_recovery_read_budget", None)
        if (type(budget) is not _RecoveryReadBudget or budget.task_id != task_id
                or budget.command_scope is not self.command_scope
                or any(getattr(port, "_recovery_read_budget", None) is not budget
                       for port in (self, self._objects))):
            raise RepositoryIntegrityError("cold source has no exact recovery budget")
        budget._require_active()
        self._require_provenance_scope()
        context.check_limit("raw_document_bytes", _recovery_text_size(task_id), source_id="cold-source-task")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                result = self._capture_category_recovery_sources(task_id, phase, context, budget)
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)
        self._require_provenance_scope()
        return result

    def _read_release_rejection_sources(self, task_id):
        """Read only an uncompleted task under the exact caller-owned budget."""
        self._validate_identity(task_id, "rejected release task ID")
        context = self._action_journal._context
        budget = getattr(context, "_recovery_read_budget", None)
        if (type(budget) is not _RecoveryReadBudget or budget.task_id != task_id
                or budget.command_scope is not self.command_scope
                or any(getattr(port, "_recovery_read_budget", None) is not budget
                    for port in (self, self._objects))):
            raise RepositoryIntegrityError("rejected release source has no exact recovery budget")
        budget._require_active()
        self._require_provenance_scope()
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                result = self._capture_category_recovery_sources(task_id, "sources", context, budget, rejected=True)
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)
        self._require_provenance_scope()
        return result

    def _read_release_rejected_action_source(self, task_id, action_id):
        """Capture the pre-claim rejection journal without issuing an action."""
        self._validate_identity(task_id, "rejected release task ID")
        self._validate_identity(action_id, "rejected release action ID")
        context = self._action_journal._context
        budget = getattr(context, "_recovery_read_budget", None)
        if (type(budget) is not _RecoveryReadBudget or budget.task_id != task_id
                or budget.command_scope is not self.command_scope
                or getattr(self, "_recovery_read_budget", None) is not budget):
            raise RepositoryIntegrityError("rejected action has no exact recovery budget")
        budget._require_active()
        self._require_provenance_scope()
        groups = (
            ("journal", ("action_id", "task_id", "state", "revision", "prepared_json", "prepared_digest",
                "authority_json", "authority_digest", "receipt_json", "reconciliation_json"),
                "action_journal WHERE action_id=:action_id"),
            ("claim", ("claim_id", "action_id", "task_id", "state"),
                "claims WHERE action_id=:action_id OR claim_id=:claim_id"),
            ("recovery", ("attempt_id", "original_action_id", "compensation_action_id", "state"),
                "claim_recovery_attempts WHERE original_action_id=:action_id OR compensation_action_id=:action_id"),
        )
        with self._factory.open("doctor") as connection, _recovery_rows(connection, groups,
                {"task_id": task_id, "action_id": action_id, "claim_id": "claim:" + action_id},
                context, budget, source_id="release-rejected-action") as captured:
            if (len(captured["journal"]) != 1 or captured["claim"] or captured["recovery"]
                    or captured["journal"][0][1] != task_id or captured["journal"][0][2] != "authorized"
                    or any(value is not None for value in captured["journal"][0][-2:])):
                raise RepositoryIntegrityError("release rejection acquired a claim or changed journal state")
            result = _recovery_freeze(captured, context, budget, source_id="release-rejected-action-result")
        self._require_provenance_scope()
        return result

    def _capture_category_recovery_sources(self, task_id, phase, context, budget, *, rejected=False):
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        source_id = "category-recovery-" + phase
        task_columns = ("task_id", "revision", "head_sequence", "head_digest",
                        "snapshot_json", "snapshot_digest", "integrity_status")
        reference_columns = ("r.digest", "r.ref_kind", "r.transaction_id", "o.size", "o.state",
                             "t.task_id", "t.revision")
        scope_columns = ("scope_id", "version", "metadata_revision", "scope_digest", "status",
                         "source_json", "source_digest", "change_json", "change_digest",
                         "created_transaction_id", "approved_transaction_id", "approved_event_digest")
        groups = [("task", task_columns, "tasks WHERE task_id=:task_id")]
        if phase == "sources":
            groups.extend((
                ("event", ("e.sequence", "e.body_json", "e.event_id", "e.event_type",
                           "e.previous_event_digest", "e.event_digest", "e.transaction_id",
                           "t.task_id", "t.revision", "t.head_digest", "t.request_digest"),
                 "events e LEFT JOIN transactions t ON t.transaction_id=e.transaction_id WHERE e.task_id=:task_id"),
                ("reference", reference_columns, "object_references r LEFT JOIN objects o ON o.digest=r.digest "
                 "LEFT JOIN transactions t ON t.transaction_id=r.transaction_id WHERE r.task_id=:task_id"),
                ("scope", scope_columns, "project_scopes WHERE task_id=:task_id"),
                ("approval", ("scope_digest", "transaction_id", "record_json", "record_digest"),
                 "project_scope_approvals WHERE task_id=:task_id"),
                ("realization", ("binding_id",), "project_scope_realizations WHERE task_id=:task_id"),
                ("extension", ("generation", "pin_digest"), "task_extension_pin_bindings WHERE task_id=:task_id"),
            ))
        with ExitStack() as stack:
            connection = stack.enter_context(self._factory.open("doctor"))
            captured = stack.enter_context(_recovery_rows(connection, groups, {"task_id": task_id},
                                                         context, budget, source_id=source_id))
            def parsed(encoded: str) -> object:
                with _recovery_json(encoded, context, budget, source_id=source_id) as value:
                    _recovery_adopt(value, context, budget, record_fields={}, source_id=source_id)
                    stack.callback(budget.release_projection, value)
                    return value

            if len(captured["task"]) != 1:
                raise RepositoryIntegrityError("cold source task is missing or ambiguous")
            task = dict(zip(task_columns, captured["task"][0]))
            snapshot = parsed(task.pop("snapshot_json"))
            if (type(snapshot) is not dict or snapshot.get("task_id") != task_id
                    or type(snapshot.get("revision")) is not int
                    or type(task["revision"]) is not int or task["revision"] < 1
                    or snapshot["revision"] != task["revision"] or task["integrity_status"] != "ok"
                    or type(task["head_sequence"]) is not int or task["head_sequence"] < 1
                    or task["snapshot_digest"] != _recovery_record_digest({
                        "contract": "repository-snapshot-v1", "value": snapshot}, context, budget,
                        source_id="cold-task-snapshot-digest")):
                raise RepositoryIntegrityError("cold source task snapshot is stale or invalid")
            require_jcs_digest(task["head_digest"])
            task.pop("integrity_status")
            domain = snapshot.get("domain")
            evidence = domain.get("evidence") if type(domain) is dict else None
            if type(evidence) is not list or any(type(item) is not dict for item in evidence):
                raise RepositoryIntegrityError("cold source task evidence is invalid")
            selected = [item for item in evidence if item.get("evidence_type") == "category-completion-assessment"]
            if rejected:
                if selected:
                    raise RepositoryIntegrityError("rejected release source has a successful assessment")
                assessment_ref = assessment_digest = None
            else:
                if len(selected) != 1:
                    raise RepositoryIntegrityError("cold source assessment is missing or ambiguous")
                assessment_ref = selected[0]
                if (set(assessment_ref) != {"evidence_id", "evidence_type", "source_ref", "digest", "trust"}
                        or assessment_ref["trust"] != "factory-attested"
                        or assessment_ref["evidence_id"] != assessment_ref["digest"]):
                    raise RepositoryIntegrityError("cold source assessment reference is invalid")
                require_jcs_digest(assessment_ref["digest"])
                assessment_digest = require_object_digest(assessment_ref["source_ref"])
            if phase == "locator":
                references_capture = stack.enter_context(_recovery_rows(connection,
                    [("reference", reference_columns,
                      "object_references r LEFT JOIN objects o ON o.digest=r.digest "
                      "LEFT JOIN transactions t ON t.transaction_id=r.transaction_id "
                      "WHERE r.task_id=:task_id AND r.digest=:digest")],
                    {"task_id": task_id, "digest": assessment_digest}, context, budget, source_id=source_id))
                reference_rows = references_capture["reference"]
                events, event_values, scope = (), [], None
            else:
                if captured["extension"] or captured["realization"]:
                    raise RepositoryIntegrityError("cold source extension or external realization authority is unavailable")
                event_rows = sorted(captured["event"], key=lambda row: row[0])
                events = self._validate_replay_rows(task_id,
                    (task["revision"], task["head_sequence"], task["head_digest"], "ok"), event_rows,
                    parser=parsed, _budget=budget, _context=context)
                event_values = [{"event": event, "transaction_id": row[6], "transaction_revision": row[8],
                                 "transaction_head_digest": row[9], "transaction_request_digest": row[10]}
                                for row, event in zip(event_rows, events)]
                reference_rows = captured["reference"]
                scope = self._validate_captured_recovery_scope(
                    domain, captured, scope_columns, event_values, parsed, context, budget)
            transaction_ids = {item["transaction_id"] for item in event_values}
            references = []
            for digest, kind, transaction_id, size, state, ref_task, revision in sorted(reference_rows):
                require_object_digest(digest)
                if (kind != "task" or ref_task != task_id or type(revision) is not int
                        or not 0 < revision <= task["revision"] or type(size) is not int or size < 0
                        or state != "available" or phase == "sources" and transaction_id not in transaction_ids):
                    raise RepositoryIntegrityError("cold source reference is unavailable or foreign")
                references.append({"digest": digest, "kind": kind, "transaction_id": transaction_id,
                                   "size": size, "state": state})
            if len({item["digest"] for item in references}) != len(references):
                raise RepositoryIntegrityError("cold source reference is ambiguous")
            if not rejected and sum(item["digest"] == assessment_digest for item in references) != 1:
                raise RepositoryIntegrityError("cold source assessment is not uniquely referenced")
            objects, body_reservations, assessment_body = [], [], None
            for reference in references:
                reservation = stack.enter_context(budget.reserve(context, units=reference["size"],
                    byte_count=reference["size"], source_id=reference["digest"]))
                body = self._read_provenance_object(reference["digest"], reference["size"],
                    retained_bytes=budget.retained_bytes - reference["size"])
                objects.append((reference["digest"], body))
                body_reservations.append(reservation)
                if reference["digest"] == assessment_digest:
                    assessment_body = body
            if not rejected:
                assessment = parsed(assessment_body)
                if (type(assessment) is not dict or assessment.get("task_id") != task_id
                        or assessment.get("assessment_digest") != assessment_ref["digest"]):
                    raise RepositoryIntegrityError("cold source assessment body differs from its reference")
            projection = {"phase": phase, "task": task, "assessment_ref": assessment_ref,
                          "references": references}
            if phase == "sources":
                projection.update(snapshot=snapshot, events=event_values, scope=scope)
            encoded_size = canonical_byte_length(projection)
            with budget.reserve(context, units=4 * encoded_size + 4 * len(objects) + 16,
                                byte_count=encoded_size, source_id=source_id) as frame:
                result = dict(freeze(projection))
                result["assessment_body"] = assessment_body
                result["objects"] = tuple(objects)
                result = MappingProxyType(result)
                frame.shrink(units=2 * encoded_size + 4 * len(objects) + 16, byte_count=encoded_size)
                return _recovery_adopt(result, context, budget, record_fields={}, source_id=source_id)

    def _validate_captured_recovery_scope(self, domain, captured, columns, events, parsed, context, budget):
        reference = domain.get("project_scope_ref")
        if not reference:
            if captured["scope"] or captured["approval"]:
                raise RepositoryIntegrityError("cold source has unbound ProjectScope state")
            return None
        if type(reference) is not dict:
            raise RepositoryIntegrityError("cold source ProjectScope reference is invalid")
        matching = [row for row in captured["scope"]
                    if row[3] == reference.get("digest") and row[4] == reference.get("status")]
        if len(matching) != 1:
            raise RepositoryIntegrityError("cold source ProjectScope is missing or ambiguous")
        value = dict(zip(columns, matching[0]))
        source = parsed(value.pop("source_json"))
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        size = canonical_byte_length(source)
        with budget.reserve(context, units=8 * size, byte_count=4 * size, source_id="cold-scope-validation"):
            self._validate_scope_source(source, _copy=False)
            if value["source_digest"] != self._scope_source_digest(source):
                raise RepositoryIntegrityError("cold source ProjectScope source digest differs")
        for column, field in (("scope_id", "scope_id"), ("version", "version"),
                              ("metadata_revision", "metadata_revision"), ("scope_digest", "scope_digest")):
            if type(value[column]) is not type(source[field]) or value[column] != source[field]:
                raise RepositoryIntegrityError("cold source ProjectScope source differs")
        encoded = value.pop("change_json")
        change = None if encoded is None else parsed(encoded)
        if ((change is None) != (value["change_digest"] is None)
                or change is not None and (type(change) is not dict or change.get("change_digest") != value["change_digest"])):
            raise RepositoryIntegrityError("cold source ProjectScope change differs")
        if value["status"] == "frozen":
            approvals = [row for row in captured["approval"] if row[0] == value["scope_digest"]]
            accepted = [row for row in events if row["event"]["event_digest"] == value["approved_event_digest"]]
            if (len(approvals) != 1 or len(accepted) != 1
                    or accepted[0]["transaction_id"] != value["approved_transaction_id"]
                    or accepted[0]["event"]["event_type"] not in {"project.scope_frozen", "project.scope_rebased"}):
                raise RepositoryIntegrityError("cold source ProjectScope approval event differs")
            approval = parsed(approvals[0][2])
            if (approvals[0][1] != value["approved_transaction_id"] or type(approval) is not dict
                    or approval.get("scope_digest") != value["scope_digest"]
                    or approval.get("scope_event_digest") != value["approved_event_digest"]
                    or _recovery_record_digest({"contract": "project-scope-approval-v1", "value": approval},
                        context, budget, source_id="cold-scope-approval-digest") != approvals[0][3]):
                raise RepositoryIntegrityError("cold source ProjectScope approval record differs")
        elif value["approved_transaction_id"] is not None or value["approved_event_digest"] is not None:
            raise RepositoryIntegrityError("cold source non-frozen scope has approval bindings")
        value.update(source=source, change=change)
        return value

    def _validate_replay_rows(self, task_id, head, rows, *, parser=parse_canonical_json,
                              _budget=None, _context=None):
        """Pure event/index/transaction validation shared with doctor snapshots."""
        if head[3] != "ok":
            raise RepositoryIntegrityError("task is integrity blocked")
        previous: str | None = None
        result: list[dict[str, object]] = []
        current_transaction: str | None = None
        current_transaction_head: str | None = None
        seen_transactions: set[str] = set()
        transaction_revision = 0
        for expected_sequence, row in enumerate(rows, start=1):
            value = parser(row[1])
            if not isinstance(value, dict):
                raise RepositoryIntegrityError("stored event body is not an object")
            from contextlib import nullcontext
            from graph_engineering.core.contracts.canonical import canonical_byte_length
            size = 0 if _budget is None else canonical_byte_length(value)
            with (nullcontext() if _budget is None else _budget.reserve(_context,
                    units=6 * size, byte_count=4 * size, source_id="cold-event-validation")):
                checked = self._validate_event(value, task_id=task_id, sequence=expected_sequence,
                    expected_revision=value["expected_task_revision"], previous_digest=previous,
                    _copy=_budget is None)
            transaction_id = row[6]
            if (
                type(transaction_id) is not str
                or not transaction_id
                or row[7] != task_id
                or type(row[8]) is not int
                or row[8] <= 0
                or checked["expected_task_revision"] != row[8] - 1
                or require_jcs_digest(row[9]) != row[9]
                or require_jcs_digest(row[10]) != row[10]
            ):
                raise RepositoryIntegrityError("stored event transaction binding is invalid")
            if transaction_id != current_transaction:
                if current_transaction is not None and previous != current_transaction_head:
                    raise RepositoryIntegrityError("stored transaction head digest is invalid")
                if transaction_id in seen_transactions or row[8] != transaction_revision + 1:
                    raise RepositoryIntegrityError("stored transaction order or revision is invalid")
                seen_transactions.add(transaction_id)
                current_transaction = transaction_id
                transaction_revision = row[8]
                current_transaction_head = row[9]
            elif row[8] != transaction_revision or row[9] != current_transaction_head:
                raise RepositoryIntegrityError("stored transaction batch is inconsistent")
            if (
                row[0] != expected_sequence
                or row[2] != checked["event_id"]
                or row[3] != checked["event_type"]
                or row[4] != checked["previous_event_digest"]
                or row[5] != checked["event_digest"]
            ):
                raise RepositoryIntegrityError("stored event index columns or digest mismatch")
            result.append(checked)
            previous = checked["event_digest"]  # type: ignore[assignment]
        if current_transaction is not None and previous != current_transaction_head:
            raise RepositoryIntegrityError("stored final transaction head digest is invalid")
        if len(rows) != head[1] or previous != head[2] or transaction_revision != head[0]:
            raise RepositoryIntegrityError("event stream does not match committed head")
        return tuple(result)

    def _replay_locked(
        self,
        connection: ManagedConnection,
        task_id: str,
    ) -> tuple[dict[str, object], ...]:
        head = connection.execute(
            "SELECT revision,head_sequence,head_digest,integrity_status FROM tasks WHERE task_id=?",
            (task_id,),
        ).fetchone()
        if head is None:
            raise RepositoryConflictError("unknown task")
        if head[3] != "ok":
            raise RepositoryIntegrityError("task is integrity blocked")
        rows = connection.execute(
            "SELECT e.sequence,e.body_json,e.event_id,e.event_type,e.previous_event_digest,"
            "e.event_digest,e.transaction_id,t.task_id,t.revision,t.head_digest,t.request_digest "
            "FROM events e LEFT JOIN transactions t ON t.transaction_id=e.transaction_id "
            "WHERE e.task_id=? ORDER BY e.sequence",
            (task_id,),
        ).fetchall()
        result = self._validate_replay_rows(task_id, head, rows)
        references = connection.execute(
            "SELECT r.digest,o.size,o.state FROM object_references r "
            "JOIN objects o ON o.digest=r.digest WHERE r.task_id=? ORDER BY r.digest",
            (task_id,),
        ).fetchall()
        for digest, size, state in references:
            if state != "available":
                raise RepositoryIntegrityError("committed object reference is unavailable")
            self._objects._verify_file(self._objects._path(digest), digest, size)
        return tuple(result)

    def replay(self, task_id: str) -> tuple[dict[str, object], ...]:
        self._validate_identity(task_id, "task ID")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    result = self._replay_locked(connection, task_id)
                    self._validate_current_extension_pin_locked(connection, task_id)
                    return result
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def referenced_objects(self, task_id: str) -> tuple[tuple[str, bytes], ...]:
        """Return exact verified bodies already transaction-bound to one task."""

        self._validate_identity(task_id, "task ID")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    self._replay_locked(connection, task_id)
                    rows = connection.execute(
                        "SELECT r.digest,o.size,o.state FROM object_references r "
                        "JOIN objects o ON o.digest=r.digest "
                        "WHERE r.task_id=? ORDER BY r.digest",
                        (task_id,),
                    ).fetchall()
                    result: list[tuple[str, bytes]] = []
                    for digest, size, state in rows:
                        if state != "available":
                            raise RepositoryIntegrityError(
                                "committed object reference is unavailable",
                            )
                        result.append((
                            digest,
                            self._objects._verify_file(
                                self._objects._path(digest), digest, size,
                            ),
                        ))
                    return tuple(result)
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def _category_source_seal_locked(
        self,
        connection: ManagedConnection,
        task_id: str,
        snapshot: object,
        excluded_object_digest: str,
    ) -> str:
        """Digest every durable WP-08 category source under repository locks."""

        if not isinstance(snapshot, dict):
            raise RepositoryIntegrityError(
                "category source seal has no current task snapshot",
            )
        rows = connection.execute(
            "SELECT r.digest,o.size,o.state FROM object_references r "
            "JOIN objects o ON o.digest=r.digest "
            "WHERE r.task_id=? ORDER BY r.digest",
            (task_id,),
        ).fetchall()
        source_objects: list[dict[str, object]] = []
        for digest, size, state in rows:
            if digest == excluded_object_digest:
                continue
            if state != "available":
                raise RepositoryIntegrityError(
                    "category source object reference is unavailable",
                )
            self._objects._verify_file(
                self._objects._path(digest), digest, size,
            )
            source_objects.append({
                "object_digest": digest,
                "size": size,
            })
        action_rows = connection.execute(
            "SELECT action_id,state,revision,idempotency_key,prepared_json,"
            "prepared_digest,authority_json,authority_digest,receipt_json,"
            "reconciliation_json FROM action_journal WHERE task_id=? "
            "ORDER BY action_id",
            (task_id,),
        ).fetchall()
        claim_rows = connection.execute(
            "SELECT claim_id,action_id,lease_id,started_event_digest,state,revision "
            "FROM claims WHERE task_id=? ORDER BY claim_id",
            (task_id,),
        ).fetchall()
        claim_resources = connection.execute(
            "SELECT c.claim_id,r.resource_id,r.fencing_token FROM claims c "
            "JOIN claim_resources r ON r.claim_id=c.claim_id "
            "WHERE c.task_id=? ORDER BY c.claim_id,r.resource_id",
            (task_id,),
        ).fetchall()
        return semantic_record_digest({
            "contract": "category-source-seal-v1",
            "value": {
                "task_id": task_id,
                "snapshot": snapshot,
                "source_objects": source_objects,
                "action_journal": [list(item) for item in action_rows],
                "claims": [list(item) for item in claim_rows],
                "claim_resources": [list(item) for item in claim_resources],
            },
        })

    def category_source_seal(
        self,
        task_id: str,
        excluded_object_digest: str,
    ) -> str:
        """Read one exact category source seal before issuing a commit fence."""

        self._validate_identity(task_id, "task ID")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    self._replay_locked(connection, task_id)
                    row = connection.execute(
                        "SELECT snapshot_json FROM tasks WHERE task_id=?",
                        (task_id,),
                    ).fetchone()
                    if row is None:
                        raise RepositoryIntegrityError(
                            "category source task is unavailable",
                        )
                    return self._category_source_seal_locked(
                        connection,
                        task_id,
                        parse_canonical_json(row[0]),
                        excluded_object_digest,
                    )
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    @classmethod
    def _scope_state_locked(
        cls,
        connection: ManagedConnection,
        task_id: str,
        *,
        scope_digest: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        clauses = ["task_id=?"]
        values: list[object] = [task_id]
        if scope_digest is not None:
            clauses.append("scope_digest=?")
            values.append(scope_digest)
        if status is not None:
            clauses.append("status=?")
            values.append(status)
        rows = connection.execute(
            "SELECT scope_id,version,metadata_revision,scope_digest,status,source_json,source_digest,"
            "change_json,change_digest,created_transaction_id,approved_transaction_id,approved_event_digest "
            f"FROM project_scopes WHERE {' AND '.join(clauses)} ORDER BY version DESC,metadata_revision DESC",
            tuple(values),
        ).fetchall()
        if len(rows) != 1:
            raise RepositoryIntegrityError("task has no unique exact durable ProjectScope")
        row = rows[0]
        source = parse_canonical_json(row[5])
        source = cls._validate_scope_source(source)
        if (
            row[0] != source["scope_id"] or row[1] != source["version"]
            or row[2] != source["metadata_revision"] or row[3] != source["scope_digest"]
            or row[6] != cls._scope_source_digest(source)
        ):
            raise RepositoryIntegrityError("durable ProjectScope columns do not match its exact source")
        change = None if row[7] is None else parse_canonical_json(row[7])
        if (change is None) != (row[8] is None) or (
            isinstance(change, dict) and change.get("change_digest") != row[8]
        ):
            raise RepositoryIntegrityError("durable ProjectScope change record is invalid")
        if row[4] == "frozen":
            if type(row[10]) is not str or type(row[11]) is not str:
                raise RepositoryIntegrityError("frozen ProjectScope approval binding is absent")
            event = connection.execute(
                "SELECT transaction_id,event_digest,event_type,body_json FROM events WHERE event_digest=?",
                (row[11],),
            ).fetchone()
            if event is None or event[0] != row[10] or event[1] != row[11] or event[2] not in {
                "project.scope_frozen", "project.scope_rebased",
            }:
                raise RepositoryIntegrityError("frozen ProjectScope approval event binding is invalid")
            approval = connection.execute(
                "SELECT transaction_id,record_json,record_digest FROM project_scope_approvals "
                "WHERE task_id=? AND scope_digest=?",
                (task_id, row[3]),
            ).fetchone()
            approval_record = parse_canonical_json(approval[1]) if approval is not None else None
            if (
                approval is None or approval[0] != row[10]
                or not isinstance(approval_record, dict)
                or approval_record.get("scope_digest") != row[3]
                or approval_record.get("scope_event_digest") != row[11]
                or semantic_record_digest({
                    "contract": "project-scope-approval-v1", "value": approval_record,
                }) != approval[2]
            ):
                raise RepositoryIntegrityError("frozen ProjectScope approval record is invalid")
        elif row[10] is not None or row[11] is not None:
            raise RepositoryIntegrityError("non-frozen ProjectScope has approval bindings")
        realizations = connection.execute(
            "SELECT scope_digest,binding_id,planned_target_id,actual_git_identity,boundary_evidence_digest,"
            "action_id,prepared_action_digest,receipt_digest,observation_json,observation_digest,"
            "event_digest,transaction_id,record_digest FROM project_scope_realizations WHERE task_id=? ORDER BY binding_id",
            (task_id,),
        ).fetchall()
        for realization in realizations:
            observation = parse_canonical_json(realization[8])
            record = {
                "task_id": task_id, "scope_digest": realization[0], "binding_id": realization[1],
                "planned_target_id": realization[2], "actual_git_identity": realization[3],
                "boundary_evidence_digest": realization[4], "action_id": realization[5],
                "prepared_action_digest": realization[6], "receipt_digest": realization[7],
                "observation": observation, "event_digest": realization[10],
                "transaction_id": realization[11],
            }
            if (
                not isinstance(observation, dict)
                or observation.get("observation_digest") != realization[9]
                or realization[4] != realization[9]
                or realization[12] != semantic_record_digest({
                "contract": "repository-realization-v1", "value": record,
                })
            ):
                raise RepositoryIntegrityError("repository realization record digest is invalid")
        return {
            "scope_id": row[0], "version": row[1], "metadata_revision": row[2],
            "scope_digest": row[3], "status": row[4], "source": source,
            "source_digest": row[6], "change": change, "change_digest": row[8],
            "created_transaction_id": row[9], "approved_transaction_id": row[10],
            "approved_event_digest": row[11],
        }

    def project_scope_state(self, task_id: str) -> dict[str, object]:
        self._validate_identity(task_id, "task ID")
        with self._factory.open("doctor") as connection:
            rows = connection.execute(
                "SELECT scope_digest,status FROM project_scopes WHERE task_id=? "
                "AND status IN ('drafted','frozen') ORDER BY CASE status WHEN 'drafted' THEN 0 ELSE 1 END",
                (task_id,),
            ).fetchall()
            if not rows:
                raise RepositoryIntegrityError("task has no durable ProjectScope")
            return self._scope_state_locked(
                connection, task_id, scope_digest=rows[0][0], status=rows[0][1],
            )

    def project_scope_change(
        self, task_id: str, candidate: ProjectScope, graph: object | None = None,
    ) -> dict[str, object]:
        if type(candidate) is not ProjectScope:
            raise RepositoryIntegrityError("candidate ProjectScope is missing or forged")
        with self._factory.open("doctor") as connection:
            current = self._scope_state_locked(connection, task_id, status="frozen")
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT snapshot_json FROM tasks WHERE task_id=?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("task durable snapshot is absent")
        source = current["source"]
        candidate_source = candidate.to_dict()
        change = self._scope_change(source, candidate_source)  # type: ignore[arg-type]
        if change.get("requires_reapproval") is not True:
            return change
        if type(graph) is not GraphDefinition:
            raise RepositoryIntegrityError("semantic ProjectScope change requires the approved graph")
        return self._bind_scope_run_dependencies(
            source,  # type: ignore[arg-type]
            candidate_source,
            change,
            parse_canonical_json(row[0]),
            graph,
        )

    def project_action_state(self, task_id: str, action_id: str) -> dict[str, object]:
        with self._factory.open("doctor") as connection:
            row = connection.execute(
            "SELECT task_id,state,prepared_json,prepared_digest,receipt_json,reconciliation_json FROM action_journal "
                "WHERE action_id=?",
                (action_id,),
            ).fetchone()
        if row is None or row[0] != task_id or row[1] != "reconciled":
            raise RepositoryIntegrityError("repository realization action is not durably reconciled")
        prepared = parse_canonical_json(row[2])
        receipt = parse_canonical_json(row[4]) if row[4] is not None else None
        reconciliation = parse_canonical_json(row[5]) if row[5] is not None else None
        if (
            not isinstance(prepared, dict) or prepared.get("prepared_action_digest") != row[3]
            or not isinstance(receipt, dict) or not isinstance(reconciliation, dict)
        ):
            raise RepositoryIntegrityError("repository realization action bodies are invalid")
        from .actions import ActionJournalRepository
        ActionJournalRepository._validate_stored_receipt(receipt)
        ActionJournalRepository._validate_stored_reconciliation(reconciliation)
        return {
            "prepared": prepared,
            "prepared_digest": row[3],
            "receipt": receipt,
            "reconciliation": reconciliation,
        }

    def concrete_action_records(self, action_id: str) -> dict[str, dict[str, object]]:
        """Reparse the exact durable concrete protocol prefix for recovery."""

        self._validate_identity(action_id, "action ID")
        with self._factory.open("doctor") as connection:
            rows = tuple(connection.execute(
                "SELECT record_type,record_digest,invocation_digest,receipt_digest,record_json "
                "FROM concrete_action_records WHERE action_id=? ORDER BY "
                "CASE record_type WHEN 'invocation' THEN 1 WHEN 'receipt' THEN 2 ELSE 3 END",
                (action_id,),
            ))
        records: dict[str, dict[str, object]] = {}
        invocation = None
        receipt = None
        from .concrete_actions import ConcreteActionRecordRepository
        for row in rows:
            value = parse_canonical_json(row[4])
            if type(value) is not dict or canonical_json(value) != row[4]:
                raise RepositoryIntegrityError("durable concrete action record is not canonical")
            if row[0] == "invocation":
                parsed = ConcreteActionRecordRepository._parse_invocation(value)
                if (
                    row[1] != parsed.invocation_digest
                    or row[2] != parsed.invocation_digest
                    or row[3] is not None
                ):
                    raise RepositoryIntegrityError("durable concrete invocation metadata changed")
                invocation = parsed
            elif row[0] == "receipt":
                if invocation is None:
                    raise RepositoryIntegrityError("durable concrete receipt has no invocation")
                parsed_receipt = ConcreteActionRecordRepository._parse_receipt(value)
                parsed_receipt.require_invocation(invocation)
                if (
                    row[1] != parsed_receipt.receipt_digest
                    or row[2] != parsed_receipt.invocation_digest
                    or row[3] != parsed_receipt.receipt_digest
                ):
                    raise RepositoryIntegrityError("durable concrete receipt metadata changed")
                receipt = parsed_receipt
            elif row[0] == "observation":
                if receipt is None:
                    raise RepositoryIntegrityError("durable concrete observation has no receipt")
                parsed_observation = ConcreteActionRecordRepository._parse_observation(value)
                parsed_observation.require_receipt(receipt)
                if (
                    row[1] != parsed_observation.observation_digest
                    or row[2] != parsed_observation.invocation_digest
                    or row[3] != parsed_observation.receipt_digest
                ):
                    raise RepositoryIntegrityError("durable concrete observation metadata changed")
            else:
                raise RepositoryIntegrityError("durable concrete record type is invalid")
            records[row[0]] = value
        if tuple(records) not in {
            (),
            ("invocation",),
            ("invocation", "receipt"),
            ("invocation", "receipt", "observation"),
        }:
            raise RepositoryIntegrityError("durable concrete record prefix is not consecutive")
        return records

    def concrete_action_audit(self, action_id: str) -> dict[str, object]:
        """Return the exact current concrete-action journal/claim/record closure."""

        self._validate_identity(action_id, "action ID")
        records = self.concrete_action_records(action_id)
        with self._factory.open("doctor") as connection:
            journal = connection.execute(
                "SELECT state FROM action_journal WHERE action_id=?",
                (action_id,),
            ).fetchall()
            claims = connection.execute(
                "SELECT state FROM claims WHERE action_id=? ORDER BY claim_id",
                (action_id,),
            ).fetchall()
        if len(journal) != 1 or len(claims) > 1:
            raise RepositoryIntegrityError(
                "concrete action audit identity is missing or duplicated"
            )
        journal_state = journal[0][0]
        claim_state = None if not claims else claims[0][0]
        if (
            type(journal_state) is not str
            or (claim_state is not None and type(claim_state) is not str)
        ):
            raise RepositoryIntegrityError("concrete action audit state is invalid")
        return {
            "journal_state": journal_state,
            "claim_state": claim_state,
            "records": records,
        }

    def project_realizations(self, task_id: str) -> tuple[dict[str, object], ...]:
        with self._factory.open("doctor") as connection:
            frozen = connection.execute(
                "SELECT 1 FROM project_scopes WHERE task_id=? AND status='frozen'",
                (task_id,),
            ).fetchone()
            if frozen is None:
                return ()
            self._scope_state_locked(connection, task_id, status="frozen")
            rows = connection.execute(
                "SELECT binding_id,observation_json,action_id,prepared_action_digest,receipt_digest "
                "FROM project_scope_realizations WHERE task_id=? ORDER BY binding_id",
                (task_id,),
            ).fetchall()
        result = []
        for row in rows:
            observation = parse_canonical_json(row[1])
            if not isinstance(observation, dict):
                raise RepositoryIntegrityError("repository realization observation is invalid")
            result.append({
                "binding_id": row[0], "observation": observation, "action_id": row[2],
                "prepared_action_digest": row[3], "receipt_digest": row[4],
            })
        return tuple(result)

    def require_project_realizations(
        self,
        task_id: str,
        observations: Mapping[str, str],
    ) -> None:
        if not isinstance(observations, Mapping):
            raise RepositoryIntegrityError("repository realization observations are invalid")
        with self._factory.open("doctor") as connection:
            state = self._scope_state_locked(connection, task_id, status="frozen")
            rows = connection.execute(
                "SELECT binding_id,actual_git_identity FROM project_scope_realizations "
                "WHERE task_id=? AND scope_digest=? ORDER BY binding_id",
                (task_id, state["scope_digest"]),
            ).fetchall()
        durable = {row[0]: row[1] for row in rows}
        if dict(observations) != durable:
            raise RepositoryIntegrityError("current Git identity differs from approved realization")

    def extension_pin_state(self, task_id: str) -> dict[str, object] | None:
        self._validate_identity(task_id, "task ID")
        self._require_command_context()
        with self._factory.open("application") as connection:
            return self._validate_current_extension_pin_locked(connection, task_id)

    def load_for_extension_rebase(
        self,
        task_id: str,
        new_pin_digest: str,
    ) -> dict[str, object]:
        """Load a stale pinned task only while validating its exact current successor pin."""

        self._validate_identity(task_id, "task ID")
        self._validate_identity(new_pin_digest, "extension pin digest")
        self._require_command_context()
        with self._factory.open("application") as connection:
            self._replay_locked(connection, task_id)
            row = connection.execute(
                "SELECT snapshot_json,snapshot_digest FROM tasks WHERE task_id=?", (task_id,),
            ).fetchone()
            if row is None:
                raise RepositoryConflictError("unknown task")
            snapshot = parse_canonical_json(row[0])
            if (
                not isinstance(snapshot, dict)
                or row[1] != semantic_record_digest({
                    "contract": "repository-snapshot-v1", "value": snapshot,
                })
            ):
                raise RepositoryIntegrityError("snapshot digest or shape is invalid")
            bindings = self._extension_pin_rows_locked(connection, task_id)
            if not bindings:
                raise RepositoryIntegrityError("extension task is unavailable")
            self._load_pin_from_authority(
                str(bindings[-1]["pin_digest"]), require_current=False,
            )
            successor = self._load_pin_from_authority(new_pin_digest, require_current=True)
            if not self._extension_pin_matches_snapshot(successor, snapshot):
                raise RepositoryIntegrityError("extension task is unavailable")
            return snapshot

    def replay_for_extension_rebase(
        self,
        task_id: str,
        new_pin_digest: str,
    ) -> tuple[dict[str, object], ...]:
        self.load_for_extension_rebase(task_id, new_pin_digest)
        with self._factory.open("application") as connection:
            return self._replay_locked(connection, task_id)

    def load(self, task_id: str) -> dict[str, object]:
        self._validate_identity(task_id, "task ID")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    self._replay_locked(connection, task_id)
                    row = connection.execute(
                        "SELECT snapshot_json,snapshot_digest FROM tasks WHERE task_id=?", (task_id,),
                    ).fetchone()
                    assert row is not None
                    snapshot = parse_canonical_json(row[0])
                    expected = semantic_record_digest({
                        "contract": "repository-snapshot-v1", "value": snapshot,
                    })
                    if row[1] != expected or not isinstance(snapshot, dict):
                        raise RepositoryIntegrityError("snapshot digest or shape is invalid")
                    pin = self._validate_current_extension_pin_locked(connection, task_id)
                    if pin is not None and not self._extension_pin_matches_snapshot(pin, snapshot):
                        raise RepositoryIntegrityError("extension task is unavailable")
                    domain = snapshot.get("domain")
                    scope_ref = domain.get("project_scope_ref") if isinstance(domain, dict) else None
                    if isinstance(scope_ref, dict) and scope_ref:
                        self._scope_state_locked(
                            connection, task_id,
                            scope_digest=scope_ref.get("digest") if type(scope_ref.get("digest")) is str else "",
                            status=scope_ref.get("status") if type(scope_ref.get("status")) is str else "",
                        )
                    return snapshot
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def recover(self, transaction_id: str) -> CommitResult | None:
        self._validate_identity(transaction_id, "transaction ID")
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    row = connection.execute(
                        "SELECT request_digest,task_id,revision,head_digest "
                        "FROM transactions WHERE transaction_id=?",
                        (transaction_id,),
                    ).fetchone()
                    if row is None:
                        return None
                    require_jcs_digest(row[0])
                    self._validate_identity(row[1], "transaction task ID")
                    if type(row[2]) is not int or row[2] <= 0:
                        raise RepositoryIntegrityError("transaction revision is invalid")
                    require_jcs_digest(row[3])
                    event_rows = connection.execute(
                        "SELECT sequence,event_digest FROM events "
                        "WHERE transaction_id=? AND task_id=? ORDER BY sequence",
                        (transaction_id, row[1]),
                    ).fetchall()
                    if not event_rows or event_rows[-1][1] != row[3]:
                        raise RepositoryIntegrityError(
                            "transaction recovery has no exact authoritative event batch",
                        )
                    try:
                        self._replay_locked(connection, row[1])
                    except RepositoryConflictError as error:
                        raise RepositoryIntegrityError(
                            "transaction recovery references an unknown task",
                        ) from error
                    self._validate_current_extension_pin_locked(connection, row[1])
                    return CommitResult("COMMITTED", row[2], row[3])
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def repair_snapshot(
        self,
        task_id: str,
        expected_head_digest: str,
        rebuilt_snapshot: dict[str, object],
    ) -> str:
        """Replace only a derived snapshot after authoritative event replay succeeds."""

        self._validate_identity(task_id, "task ID")
        require_jcs_digest(expected_head_digest)
        if type(rebuilt_snapshot) is not dict:
            raise RepositoryIntegrityError("rebuilt snapshot is not an object")
        canonical_json(rebuilt_snapshot)
        installation = self._locks.acquire_installation("exclusive")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    with connection.transaction():
                        events = self._replay_locked(connection, task_id)
                        head = connection.execute(
                            "SELECT revision,head_digest FROM tasks WHERE task_id=?", (task_id,),
                        ).fetchone()
                        if head is None or head[1] != expected_head_digest:
                            raise RepositoryConflictError("snapshot repair head is stale")
                        if (
                            rebuilt_snapshot.get("task_id") != task_id
                            or rebuilt_snapshot.get("revision") != head[0]
                            or type(rebuilt_snapshot.get("revision")) is not int
                            or not events
                        ):
                            raise RepositoryIntegrityError("rebuilt snapshot identity is invalid")
                        encoded = canonical_json(rebuilt_snapshot)
                        digest = semantic_record_digest({
                            "contract": "repository-snapshot-v1", "value": rebuilt_snapshot,
                        })
                        changed = connection.execute(
                            "UPDATE tasks SET snapshot_json=?,snapshot_digest=? "
                            "WHERE task_id=? AND head_digest=?",
                            (encoded, digest, task_id, expected_head_digest),
                        ).rowcount
                        if changed != 1:
                            raise RepositoryConflictError("snapshot repair CAS lost")
                        return digest
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def query_catalog(self, filters: dict[str, object]) -> tuple[dict[str, object], ...]:
        if type(filters) is not dict:
            raise RepositoryIntegrityError("catalog filters are invalid")
        canonical_json(filters)
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                rows = connection.execute(
                    "SELECT task_id,fields_json FROM catalog ORDER BY task_id"
                ).fetchall()
                results = []
                for task_id, encoded in rows:
                    fields = parse_canonical_json(encoded)
                    if not isinstance(fields, dict):
                        raise RepositoryIntegrityError("catalog row is invalid")
                    if all(fields.get(key) == value for key, value in filters.items()):
                        results.append({"task_id": task_id, "fields": fields})
                return tuple(results)
        finally:
            self._locks.release(installation)

    def lifecycle_facts(self, task_id: str) -> dict[str, object]:
        """Return one read-only, digest-bound lifecycle precondition snapshot."""

        self._validate_identity(task_id, "task ID")
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("doctor") as connection:
                assertion = self._lifecycle_facts_locked(connection, task_id)
            live_leases = tuple(assertion["live_leases"])
            unresolved_claims = tuple(assertion["unresolved_claims"])
            action_states = tuple((row[0], row[1]) for row in assertion["action_states"])
            compensable = tuple(assertion["compensable_action_refs"])
            fences = tuple(tuple(row) for row in assertion["fencing_high_water"])
            security_row = assertion["security_state"]
            security_digest = security_row[2] if isinstance(security_row, list) else None
            retention_plan_ref = (
                None if security_digest is None else f"retention-plan:{security_digest}"
            )
            rollback_clearance_ref = semantic_record_digest({
                "contract": "lifecycle-rollback-clearance-v1",
                "task_id": task_id,
                "live_leases": live_leases,
                "unresolved_claims": unresolved_claims,
                "action_states": action_states,
                "fencing_high_water": fences,
                "security_state_digest": security_digest,
            })
            return {
                "live_leases": live_leases,
                "unresolved_claims": unresolved_claims,
                "action_states": action_states,
                "compensable_action_refs": compensable,
                "fencing_high_water": fences,
                "security_state_digest": security_digest,
                "retention_plan_ref": retention_plan_ref,
                "rollback_clearance_ref": rollback_clearance_ref,
                "assertion": assertion,
            }
        finally:
            self._locks.release(installation)

    def prepare_lifecycle_plan(
        self,
        task_id: str,
        *,
        kind: str,
        trigger: str,
        authority_ref: str | None,
        lease_assertion: dict[str, object],
    ) -> dict[str, object]:
        if (kind, trigger) not in {("retention", "archive"), ("retention", "cancel"), ("rollback", "rollback")}:
            raise RepositoryIntegrityError("lifecycle plan kind/trigger is invalid")
        installation = None if self._locks.installation_held_by_current_thread() else self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                with connection.transaction():
                    self._validate_lease_assertion(connection, task_id, lease_assertion, None)
                    facts = self._lifecycle_facts_locked(
                        connection, task_id, exclude_lease_id=lease_assertion["lease_id"],
                    )
                    if facts["live_leases"] or facts["unresolved_claims"]:
                        raise RepositoryConflictError("lifecycle plan requires clear durable coordination")
                    body: dict[str, object]
                    if kind == "retention":
                        security = connection.execute(
                            "SELECT state_json,state_digest FROM task_security_states WHERE task_id=?",
                            (task_id,),
                        ).fetchone()
                        state = parse_canonical_json(security[0]) if security is not None else None
                        if security is not None and (
                            not isinstance(state, dict)
                            or semantic_record_digest({
                                "contract": "task-security-state-v1", "value": state,
                            }) != security[1]
                        ):
                            raise RepositoryIntegrityError("retention plan requires exact durable security state")
                        subjects = {} if state is None else state.get("retention_subjects")
                        if not isinstance(subjects, dict):
                            raise RepositoryIntegrityError("retention subjects are not exact")
                        if any(
                            isinstance(subject, Mapping) and subject.get("legal_hold") is True
                            for subject in subjects.values()
                        ):
                            raise RepositoryConflictError("retention legal hold forbids lifecycle scheduling")
                        if trigger == "archive" and facts["compensable_action_refs"]:
                            raise RepositoryConflictError("unfinished rollback forbids archive")
                        clearance = semantic_record_digest({
                            "contract": "lifecycle-rollback-clearance-v1", "facts": facts,
                        })
                        schedules = [{
                            "subject_ref": subject_ref, "disposition": "pending-policy-execution",
                            "physical_purge_claimed": False,
                        } for subject_ref in sorted(subjects)]
                        body = {
                            "schema_version": "1.0", "kind": kind, "trigger": trigger,
                            "task_id": task_id, "task_revision": facts["repository_revision"],
                            "task_snapshot_digest": facts["task_snapshot_digest"],
                            "facts_digest": facts["facts_digest"],
                            "security_state_digest": None if security is None else security[1],
                            "retention_subjects": subjects, "schedules": schedules,
                            "rollback_clearance_ref": clearance,
                        }
                    else:
                        if type(authority_ref) is not str or not authority_ref:
                            raise RepositoryIntegrityError("rollback request authority is invalid")
                        request_authority_digest, security_state_digest = (
                            self._current_rollback_request_authority(
                                connection, task_id, authority_ref, facts,
                            )
                        )
                        actions = facts["compensable_action_refs"]
                        if not actions:
                            raise RepositoryConflictError("controlled rollback has no compensable actions")
                        unordered_steps: dict[str, dict[str, object]] = {}
                        dependency_graph: dict[str, tuple[str, ...]] = {}
                        for original_id in actions:
                            original_row = connection.execute(
                                "SELECT prepared_json,prepared_digest FROM action_journal WHERE action_id=? AND task_id=? "
                                "AND state IN ('succeeded','reconciled')",
                                (original_id, task_id),
                            ).fetchone()
                            original = parse_canonical_json(original_row[0]) if original_row is not None else None
                            rollback = original.get("rollback_plan") if isinstance(original, dict) else None
                            compensation_id = rollback.get("compensation_action_id") if isinstance(rollback, dict) else None
                            compensation_row = connection.execute(
                                "SELECT state,prepared_json,prepared_digest,authority_json,authority_digest "
                                "FROM action_journal WHERE action_id=? AND task_id=?",
                                (compensation_id, task_id),
                            ).fetchone()
                            compensation = parse_canonical_json(compensation_row[1]) if compensation_row is not None else None
                            authority = parse_canonical_json(compensation_row[3]) if compensation_row is not None and compensation_row[3] is not None else None
                            resources = compensation.get("resources") if isinstance(compensation, dict) else None
                            if (
                                original_row is None or not isinstance(original, dict)
                                or original.get("action_id") != original_id
                                or original.get("task_id") != task_id
                                or original.get("prepared_action_digest") != original_row[1]
                                or type(compensation_id) is not str or not compensation_id
                                or compensation_row is None or compensation_row[0] != "authorized"
                                or not isinstance(compensation, dict) or compensation.get("action_kind") != "rollback"
                                or compensation.get("action_id") != compensation_id
                                or compensation.get("task_id") != task_id
                                or compensation.get("prepared_action_digest") != compensation_row[2]
                                or not isinstance(authority, dict) or authority.get("status") != "active"
                                or authority.get("task_id") != task_id
                                or authority.get("authorized_action_kind") != "rollback"
                                or authority.get("authorized_resources") != resources
                                or authority.get("authority_digest") != compensation_row[4]
                                or authority.get("prepared_action_digest") != compensation_row[2]
                                or not isinstance(resources, list) or not resources
                                or resources != sorted(set(resources))
                            ):
                                raise RepositoryIntegrityError("controlled rollback step lacks separate current authority")
                            fences = {
                                resource: token for resource, token in facts["fencing_high_water"]  # type: ignore[misc]
                                if resource in resources
                            }
                            if set(fences) != set(resources):
                                raise RepositoryIntegrityError("controlled rollback step lacks exact resource fences")
                            depends_on = rollback.get("depends_on_action_ids", [])
                            if (
                                not isinstance(depends_on, list)
                                or depends_on != sorted(set(depends_on))
                                or original_id in depends_on
                                or any(item not in actions for item in depends_on)
                            ):
                                raise RepositoryIntegrityError("controlled rollback compensation graph is invalid")
                            dependency_graph[original_id] = tuple(depends_on)
                            unordered_steps[original_id] = {
                                "step_id": f"rollback:{original_id}", "original_action_id": original_id,
                                "compensation_action_id": compensation_id,
                                "compensation_prepared_digest": compensation_row[2],
                                "compensation_authority_digest": compensation_row[4],
                                "resources": resources,
                                "fencing_tokens": [[resource, fences[resource]] for resource in resources],
                                "depends_on_action_ids": depends_on,
                            }
                        order = self._canonical_rollback_order(dependency_graph)
                        steps = [unordered_steps[action_id] for action_id in order]
                        self._validate_rollback_graph(
                            steps, list(actions), facts["fencing_high_water"],
                        )
                        body = {
                            "schema_version": "1.0", "kind": kind, "trigger": trigger,
                            "task_id": task_id, "task_revision": facts["repository_revision"],
                            "task_snapshot_digest": facts["task_snapshot_digest"],
                            "facts_digest": facts["facts_digest"], "request_authority_ref": authority_ref,
                            "request_authority_digest": request_authority_digest,
                            "security_state_digest": security_state_digest,
                            "compensable_action_refs": list(actions), "steps": steps,
                        }
                    body_digest = semantic_record_digest({
                        "contract": "lifecycle-plan-v1", "value": body,
                    })
                    plan_id = f"lifecycle-plan:{body_digest}"
                    existing = connection.execute(
                        "SELECT body_digest,state FROM lifecycle_plans WHERE plan_id=?", (plan_id,),
                    ).fetchone()
                    if existing is None:
                        connection.execute(
                            "INSERT INTO lifecycle_plans(plan_id,task_id,kind,trigger,task_revision,"
                            "task_snapshot_digest,facts_digest,body_json,body_digest,state) "
                            "VALUES(?,?,?,?,?,?,?,?,?,'prepared')",
                            (
                                plan_id, task_id, kind, trigger, body["task_revision"],
                                body["task_snapshot_digest"], body["facts_digest"],
                                canonical_json(body), body_digest,
                            ),
                        )
                    elif existing != (body_digest, "prepared"):
                        raise RepositoryConflictError("lifecycle plan identity conflicts with durable history")
                    return {"plan_id": plan_id, "body": body, "body_digest": body_digest, "state": "prepared"}
        finally:
            if installation is not None:
                self._locks.release(installation)

    def lifecycle_plan(self, plan_id: str) -> dict[str, object]:
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT task_id,kind,trigger,body_json,body_digest,state,consumed_transaction_id "
                "FROM lifecycle_plans WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            execution = connection.execute(
                "SELECT transaction_id,trigger,schedule_json,schedule_digest FROM lifecycle_plan_executions "
                "WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("lifecycle plan is not durable")
        body = parse_canonical_json(row[3])
        if not isinstance(body, dict) or semantic_record_digest({
            "contract": "lifecycle-plan-v1", "value": body,
        }) != row[4] or plan_id != f"lifecycle-plan:{row[4]}":
            raise RepositoryIntegrityError("durable lifecycle plan digest is invalid")
        result = {
            "plan_id": plan_id, "task_id": row[0], "kind": row[1], "trigger": row[2],
            "body": body, "body_digest": row[4], "state": row[5],
            "consumed_transaction_id": row[6], "execution": None,
        }
        if execution is not None:
            schedule = parse_canonical_json(execution[2])
            if not isinstance(schedule, dict) or semantic_record_digest({
                "contract": "lifecycle-plan-execution-v1", "value": schedule,
            }) != execution[3]:
                raise RepositoryIntegrityError("lifecycle plan execution digest is invalid")
            result["execution"] = schedule
        return result
