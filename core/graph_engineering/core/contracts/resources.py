"""Deterministic resource limits, cost schedules, and charge traces."""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import MAX_SAFE_INTEGER, canonical_byte_length
from graph_engineering.core.contracts.errors import ContractError, ErrorDetail
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw


EVENT_IDS = frozenset({
    "parse.input_byte",
    "parse.token",
    "parse.string_scalar",
    "parse.member",
    "parse.item",
    "parse.container",
    "registry.resource",
    "registry.schema_byte",
    "registry.schema_location",
    "registry.ref_edge",
    "registry.pointer_token",
    "registry.digest_compare",
    "schema.instance_visit",
    "schema.keyword",
    "schema.property",
    "schema.item",
    "schema.branch",
    "schema.ref",
    "schema.format",
    "format.scalar",
    "format.decoded_byte",
    "compare.base",
    "compare.node",
    "compare.member",
    "compare.item",
    "compare.string_scalar",
    "compare.canonical_byte",
    "unique.pair",
    "geel.node",
    "geel.operand",
    "geel.path_token",
    "geel.membership_item",
    "executable.base",
    "executable.input_node",
    "executable.input_scalar",
    "executable.input_byte",
    "canonical.value",
    "canonical.member",
    "canonical.item",
    "canonical.string_scalar",
    "canonical.output_byte",
    "digest.input_byte",
    "result.field",
    "result.node",
    "result.output_byte",
})
LIMIT_IDS = frozenset({
    "raw_document_bytes",
    "schema_bytes",
    "utf8_scalars",
    "parse_tokens",
    "parse_depth",
    "object_properties",
    "array_items",
    "registry_resources",
    "registry_ref_depth",
    "schema_locations",
    "ast_nodes",
    "ast_depth",
    "path_tokens",
    "result_bytes",
    "temporary_units",
})
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
RP_CONTRACT_ID = "urn:gew:contract:resource-profile"
RP_SCHEMA_ID = "urn:gew:schema:resource-profile:1.0.0"
COST_SCHEDULE_CONTRACT = "urn:gew:contract:cost-schedule"
COST_SCHEDULE_SCHEMA = "urn:gew:schema:cost-schedule:1.0.0"


def _positive_integer(value: object, label: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{label} must be a positive safe integer")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
        raise ValueError(f"{label} must be a nonnegative safe integer")
    return value


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    """Finite hard limits and a finite work balance."""

    profile_id: str
    schema_version: str
    limits: Mapping[str, int]
    work_budget: int

    def __post_init__(self) -> None:
        if type(self.profile_id) is not str or type(self.schema_version) is not str:
            raise ValueError("ResourceProfile IDs must be strings")
        if not isinstance(self.limits, Mapping) or set(self.limits) != LIMIT_IDS:
            raise ValueError("ResourceProfile limit set is not exact")
        checked = {key: _positive_integer(item, f"limit/{key}") for key, item in self.limits.items()}
        frozen = freeze(checked)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("frozen limits must be a map")
        object.__setattr__(self, "limits", frozen)
        object.__setattr__(self, "work_budget", _nonnegative_integer(self.work_budget, "work_budget"))

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ResourceProfile:
        if set(value) != {"profile_id", "schema_version", "limits", "work_budget"}:
            raise ValueError("ResourceProfile properties are not exact")
        limits = value["limits"]
        if not isinstance(limits, Mapping) or set(limits) != LIMIT_IDS:
            raise ValueError("ResourceProfile limit set is not exact")
        checked = {key: _positive_integer(item, f"limit/{key}") for key, item in limits.items()}
        profile_id = value["profile_id"]
        schema_version = value["schema_version"]
        if type(profile_id) is not str or type(schema_version) is not str:
            raise ValueError("ResourceProfile IDs must be strings")
        frozen = freeze(checked)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("frozen limits must be a map")
        return cls(profile_id, schema_version, frozen, _nonnegative_integer(value["work_budget"], "work_budget"))

    def narrowed_by(self, override: Mapping[str, object]) -> ResourceProfile:
        candidate = ResourceProfile.from_dict(override)
        if candidate.work_budget > self.work_budget or any(
            candidate.limits[key] > self.limits[key] for key in LIMIT_IDS
        ):
            raise ValueError("ResourceProfile override may only lower limits")
        return candidate

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "schema_version": self.schema_version,
            "limits": dict(self.limits),
            "work_budget": self.work_budget,
        }

    @property
    def body_digest(self) -> str:
        from graph_engineering.core.contracts.digest import semantic_digest

        return semantic_digest(
            self.to_dict(),
            contract_type=RP_CONTRACT_ID,
            projection_id=IDENTITY_PROJECTION,
            schema_id=RP_SCHEMA_ID,
        )


@dataclass(frozen=True, slots=True)
class CostSchedule:
    """Closed coefficient registry for charge event IDs."""

    schedule_id: str
    schema_version: str
    coefficients: Mapping[str, int]

    def __post_init__(self) -> None:
        if type(self.schedule_id) is not str or type(self.schema_version) is not str:
            raise ValueError("CostSchedule IDs must be strings")
        if not isinstance(self.coefficients, Mapping) or set(self.coefficients) != EVENT_IDS:
            raise ValueError("CostSchedule event set is not exact")
        checked = {
            event_id: _positive_integer(coefficient, f"coefficient/{event_id}")
            for event_id, coefficient in self.coefficients.items()
        }
        frozen = freeze(checked)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("frozen coefficients must be a map")
        object.__setattr__(self, "coefficients", frozen)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> CostSchedule:
        if set(value) != {"schedule_id", "schema_version", "coefficients"}:
            raise ValueError("CostSchedule properties are not exact")
        coefficients = value["coefficients"]
        if not isinstance(coefficients, Mapping) or set(coefficients) != EVENT_IDS:
            raise ValueError("CostSchedule event set is not exact")
        checked = {
            event_id: _positive_integer(coefficient, f"coefficient/{event_id}")
            for event_id, coefficient in coefficients.items()
        }
        schedule_id = value["schedule_id"]
        schema_version = value["schema_version"]
        if type(schedule_id) is not str or type(schema_version) is not str:
            raise ValueError("CostSchedule IDs must be strings")
        frozen = freeze(checked)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("frozen coefficients must be a map")
        return cls(schedule_id, schema_version, frozen)

    def to_dict(self) -> dict[str, object]:
        return {
            "schedule_id": self.schedule_id,
            "schema_version": self.schema_version,
            "coefficients": dict(self.coefficients),
        }

    @property
    def body_digest(self) -> str:
        from graph_engineering.core.contracts.digest import semantic_digest

        return semantic_digest(
            self.to_dict(),
            contract_type=COST_SCHEDULE_CONTRACT,
            projection_id=IDENTITY_PROJECTION,
            schema_id=COST_SCHEDULE_SCHEMA,
        )


@dataclass(frozen=True, slots=True)
class Measure:
    nodes: int
    members: int
    items: int
    string_scalars: int
    canonical_bytes: int


def measure(value: object) -> Measure:
    """Measure a JSON value using the ADR-0003 recursive count model."""

    nodes = 1
    members = 0
    items = 0
    string_scalars = len(value) if type(value) is str else 0
    if isinstance(value, Mapping):
        members = len(value)
        string_scalars += sum(len(key) for key in value)
        for child in value.values():
            child_measure = measure(child)
            nodes += child_measure.nodes
            members += child_measure.members
            items += child_measure.items
            string_scalars += child_measure.string_scalars
    elif type(value) in (list, tuple):
        items = len(value)
        for child in value:
            child_measure = measure(child)
            nodes += child_measure.nodes
            members += child_measure.members
            items += child_measure.items
            string_scalars += child_measure.string_scalars
    return Measure(nodes, members, items, string_scalars, canonical_byte_length(value))


def measure_counts(value: object) -> tuple[int, int, int, int, int]:
    """Independent public shape for cross-implementation corpus checks."""

    result = measure(value)
    return result.nodes, result.members, result.items, result.string_scalars, result.canonical_bytes


def bounded_measure(
    value: object,
    context: WorkContext,
    *,
    source_id: str,
    operation_path: tuple[int, ...],
) -> Measure:
    """Measure an ingress value with per-occurrence limit and stack checks."""

    nodes = 0
    members = 0
    items = 0
    string_scalars = 0

    def visit(current: object, depth: int) -> None:
        nonlocal nodes, members, items, string_scalars
        context.check_limit("parse_depth", depth, source_id=source_id)
        context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
        try:
            nodes += 1
            if type(current) is str:
                for _ in current:
                    string_scalars += 1
                    context.check_limit("utf8_scalars", string_scalars, source_id=source_id)
            elif isinstance(current, Mapping):
                for key, child in current.items():
                    members += 1
                    context.check_limit("object_properties", members, source_id=source_id)
                    for _ in key:
                        string_scalars += 1
                        context.check_limit("utf8_scalars", string_scalars, source_id=source_id)
                    visit(child, depth + 1)
            elif type(current) in (list, tuple):
                for child in current:
                    items += 1
                    context.check_limit("array_items", items, source_id=source_id)
                    visit(child, depth + 1)
        finally:
            context.release_temporary(1)

    visit(value, 1)
    encoded_size = canonical_byte_length(value)
    context.check_limit("result_bytes", encoded_size, source_id=source_id)
    return Measure(nodes, members, items, string_scalars, encoded_size)


@dataclass(slots=True)
class _ChargeRun:
    """Lossless consecutive attempts; ordinals are assigned when inspected."""

    event_id: str
    coefficient: int
    count: int
    multiplier: int
    operation_path: tuple[int, ...]
    pre_balance: int
    amount: int
    rejected: bool
    length: int = 1

    def attempt(self, ordinal: int, offset: int = 0) -> dict[str, object]:
        balance = self.pre_balance - offset * self.amount
        value: dict[str, object] = {
            "amount": str(self.amount),
            "coefficient": str(self.coefficient),
            "count": str(self.count),
            "event_id": self.event_id,
            "event_ordinal": str(ordinal),
            "multiplier": str(self.multiplier),
            "operation_path": list(self.operation_path),
            "pre_balance": str(balance),
        }
        if self.rejected:
            value["status"] = "rejected"
        else:
            value["post_balance"] = str(balance - self.amount)
            value["status"] = "charged"
        return value


class WorkContext:
    """Single-operation atomic work balance with a deterministic trace."""

    def __init__(
        self,
        profile: ResourceProfile,
        schedule: CostSchedule,
        *,
        initial_balance: int | None = None,
    ) -> None:
        self.profile = profile
        self.schedule = schedule
        balance = profile.work_budget if initial_balance is None else _nonnegative_integer(
            initial_balance, "initial_balance",
        )
        if balance > profile.work_budget:
            raise ValueError("initial balance cannot exceed the resource profile budget")
        self.balance = balance
        self._trace: list[dict[str, object]] | None = None
        self._trace_runs: list[_ChargeRun] = []
        self._next_operation_ordinal: dict[tuple[int, ...], int] = {}
        self._temporary_units = 0

    @property
    def trace(self) -> list[dict[str, object]]:
        """Return the complete live list, expanding unread runs only once.

        Inspection deliberately restores the original mutable list contract.
        Callers requesting all events also take on their full memory cost.
        """
        if self._trace is None:
            trace: list[dict[str, object]] = []
            for run in self._trace_runs:
                first = len(trace)
                trace.extend(run.attempt(first + offset, offset) for offset in range(run.length))
            self._trace = trace
            self._trace_runs.clear()
        return self._trace

    @trace.setter
    def trace(self, value: list[dict[str, object]]) -> None:
        # Preserve callers' existing ability to replace the public trace list.
        self._trace = value
        self._trace_runs.clear()

    def _record_attempt(
        self, event_id: str, coefficient: int, count: int, multiplier: int,
        operation_path: tuple[int, ...], amount: int, rejected: bool,
    ) -> None:
        path = tuple(operation_path)
        if self._trace is None and self._trace_runs and not rejected:
            last = self._trace_runs[-1]
            if (
                not last.rejected
                and last.event_id == event_id
                and last.coefficient == coefficient
                and last.count == count
                and last.multiplier == multiplier
                and last.operation_path == path
                and last.pre_balance - last.length * last.amount == self.balance
            ):
                last.length += 1
                return
        run = _ChargeRun(
            event_id, coefficient, count, multiplier, path, self.balance, amount, rejected,
        )
        if self._trace is None:
            self._trace_runs.append(run)
        else:
            self._trace.append(run.attempt(len(self._trace)))

    def child_path(self, parent_path: tuple[int, ...]) -> tuple[int, ...]:
        ordinal = self._next_operation_ordinal.get(parent_path, 0)
        self._next_operation_ordinal[parent_path] = ordinal + 1
        return (*parent_path, ordinal)

    def check_limit(
        self,
        limit_id: str,
        value: int,
        *,
        source_id: str,
        rule_id: str | None = None,
        instance_path: tuple[str | int, ...] = (),
        definition_path: tuple[str | int, ...] = (),
        evaluation_path: tuple[str | int, ...] = (),
    ) -> None:
        if limit_id not in LIMIT_IDS or type(value) is not int or value < 0:
            raise ValueError("invalid hard-limit check")
        if value > self.profile.limits[limit_id]:
            raise ContractError(ErrorDetail(
                code="E_LIMIT",
                phase="limit",
                rule_id=rule_id or f"limit/{limit_id}",
                source_id=source_id,
                instance_path=instance_path,
                definition_path=definition_path,
                evaluation_path=evaluation_path,
            ))

    def acquire_temporary(self, count: int, *, source_id: str, operation_path: tuple[int, ...]) -> None:
        del operation_path
        if type(count) is not int or count < 0:
            raise ValueError("temporary unit count must be nonnegative")
        self.check_limit("temporary_units", self._temporary_units + count, source_id=source_id)
        self._temporary_units += count

    def release_temporary(self, count: int) -> None:
        if type(count) is not int or not 0 <= count <= self._temporary_units:
            raise ValueError("invalid temporary release")
        self._temporary_units -= count

    def emit(
        self,
        event_id: str,
        count: int,
        *,
        operation_path: tuple[int, ...] = (),
        multiplier: int = 1,
        source_id: str,
        instance_path: tuple[str | int, ...] = (),
        definition_path: tuple[str | int, ...] = (),
        evaluation_path: tuple[str | int, ...] = (),
    ) -> None:
        if event_id not in EVENT_IDS:
            raise ValueError(f"unknown charge event: {event_id}")
        if type(count) is not int or count < 0:
            raise ValueError("charge count must be nonnegative")
        if count == 0:
            return
        checked_multiplier = _positive_integer(multiplier, "multiplier")
        coefficient = self.schedule.coefficients[event_id]
        amount = coefficient * count * checked_multiplier
        self._record_attempt(
            event_id, coefficient, count, checked_multiplier,
            operation_path, amount, amount > self.balance,
        )
        if amount > self.balance:
            raise ContractError(ErrorDetail(
                code="E_BUDGET",
                phase="budget",
                rule_id=f"budget/{event_id}",
                source_id=source_id,
                instance_path=instance_path,
                definition_path=definition_path,
                evaluation_path=evaluation_path,
            ))
        self.balance -= amount


def compare_charge(
    left: object,
    right: object,
    context: WorkContext,
    *,
    operation_path: tuple[int, ...],
    source_id: str,
    evaluation_path: tuple[str | int, ...] = (),
) -> None:
    context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
    try:
        _compare_charge_inner(left, right, context, operation_path=operation_path, source_id=source_id, evaluation_path=evaluation_path)
    finally:
        context.release_temporary(1)


def _compare_charge_inner(
    left: object,
    right: object,
    context: WorkContext,
    *,
    operation_path: tuple[int, ...],
    source_id: str,
    evaluation_path: tuple[str | int, ...] = (),
) -> None:
    context.emit("compare.base", 1, operation_path=operation_path, source_id=source_id, evaluation_path=evaluation_path)
    left_measure = bounded_measure(left, context, source_id=source_id, operation_path=operation_path)
    right_measure = bounded_measure(right, context, source_id=source_id, operation_path=operation_path)
    for event_id, count in (
        ("compare.node", left_measure.nodes + right_measure.nodes),
        ("compare.member", left_measure.members + right_measure.members),
        ("compare.item", left_measure.items + right_measure.items),
        ("compare.string_scalar", left_measure.string_scalars + right_measure.string_scalars),
        ("compare.canonical_byte", left_measure.canonical_bytes + right_measure.canonical_bytes),
    ):
        context.emit(event_id, count, operation_path=operation_path, source_id=source_id, evaluation_path=evaluation_path)


class _FieldView(Mapping[str, object]):
    """Allocation-light result view used only to price a future result record."""

    def __init__(self, fields: tuple[tuple[str, object], ...]) -> None:
        self._fields = fields

    def __getitem__(self, key: str) -> object:
        for name, value in self._fields:
            if name == key:
                return value
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        return (name for name, _ in self._fields)

    def __len__(self) -> int:
        return len(self._fields)


def build_result_record(
    fields: Sequence[tuple[str, object]],
    context: WorkContext,
    *,
    source_id: str,
    parent_path: tuple[int, ...] = (),
) -> dict[str, object]:
    """Charge exact result work before allocating the returned mapping."""

    frozen_fields = tuple(fields)
    names = [name for name, _ in frozen_fields]
    if any(type(name) is not str for name in names) or len(names) != len(set(names)):
        raise ValueError("result fields must be exact unique strings")
    result = _FieldView(frozen_fields)
    operation_path = context.child_path(parent_path)
    result_measure = bounded_measure(result, context, source_id=source_id, operation_path=operation_path)
    context.emit("result.field", result_measure.members, operation_path=operation_path, source_id=source_id)
    context.emit("result.node", result_measure.nodes, operation_path=operation_path, source_id=source_id)
    acquired = 0
    try:
        for _ in range(result_measure.canonical_bytes):
            context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
            acquired += 1
            context.emit("result.output_byte", 1, operation_path=operation_path, source_id=source_id)
    finally:
        context.release_temporary(acquired)
    return {name: thaw(freeze(value)) for name, value in frozen_fields}
