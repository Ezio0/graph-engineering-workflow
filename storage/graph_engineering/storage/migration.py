"""Repository-native export/import and stable installation activation control."""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
import pathlib
import secrets
import sqlite3
import stat
import tempfile
import threading
from dataclasses import dataclass
from contextlib import AbstractContextManager, ExitStack, contextmanager
from typing import Callable, ClassVar, Mapping

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.migration import (
    ActiveRepositoryManifest,
    ExportSnapshotIdentity,
    MigrationControlError,
    MigrationState,
    RepositoryCommandContext,
    RestoreGap,
    select_committed_manifest,
)

from .codec import (
    canonical_json,
    object_digest,
    parse_canonical_json,
    require_jcs_digest,
    semantic_record_digest,
)
from .connection import ConnectionFactory
from .errors import RepositoryError
from .locks import LockedFileRegistry
from .objects import ObjectRepository
from .policy import RepositoryPolicy
from .repository import TaskRepository


class MigrationRepositoryError(RepositoryError):
    """A bundle, import, or installation activation is not trustworthy."""


def _no_fault(_point: str) -> None:
    return


@dataclass(frozen=True, slots=True)
class MigrationStoragePolicy:
    policy_id: str
    initial_release_id: str
    repository_contract_id: str
    control_lock_filename: str
    active_manifest_filename: str
    repository_locator_registry_filename: str
    manifest_history_directory: str
    bundle_manifest_filename: str
    bundle_records_filename: str
    bundle_objects_directory: str
    max_bundle_member_bytes: int
    max_bundle_objects: int
    max_bundle_total_bytes: int
    max_json_depth: int
    max_json_nodes: int
    root_mode: int
    file_mode: int

    @classmethod
    def from_dict(cls, value: object) -> MigrationStoragePolicy:
        fields = {
            "schema_version", "policy_id", "initial_release_id", "repository_contract_id",
            "control_lock_filename", "active_manifest_filename",
            "repository_locator_registry_filename",
            "manifest_history_directory", "bundle_manifest_filename",
            "bundle_records_filename", "bundle_objects_directory",
            "max_bundle_member_bytes", "max_bundle_objects", "max_bundle_total_bytes",
            "max_json_depth", "max_json_nodes", "root_mode", "file_mode",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != "1.0":
            raise MigrationRepositoryError("migration storage policy is not exact")
        names = tuple(field for field in fields if field.endswith("filename") or field.endswith("directory"))
        if any(
            type(value[field]) is not str
            or not value[field]
            or value[field] in {".", ".."}
            or "/" in value[field]
            or "\\" in value[field]
            for field in names
        ):
            raise MigrationRepositoryError("migration storage name is invalid")
        if any(
            type(value.get(field)) is not str or not value[field]
            for field in ("policy_id", "initial_release_id", "repository_contract_id")
        ):
            raise MigrationRepositoryError("migration storage policy identity is invalid")
        if any(type(value.get(field)) is not int or value[field] < 0 or value[field] & 0o077 for field in ("root_mode", "file_mode")):
            raise MigrationRepositoryError("migration storage permissions are not owner-only")
        if any(
            type(value.get(field)) is not int or value[field] < 1
            for field in (
                "max_bundle_member_bytes", "max_bundle_objects", "max_bundle_total_bytes",
                "max_json_depth", "max_json_nodes",
            )
        ):
            raise MigrationRepositoryError("migration storage bounds are invalid")
        return cls(*(value[field] for field in (
            "policy_id", "initial_release_id", "repository_contract_id", "control_lock_filename",
            "active_manifest_filename", "repository_locator_registry_filename", "manifest_history_directory",
            "bundle_manifest_filename", "bundle_records_filename", "bundle_objects_directory",
            "max_bundle_member_bytes", "max_bundle_objects", "max_bundle_total_bytes",
            "max_json_depth", "max_json_nodes", "root_mode", "file_mode",
        )))


@dataclass(frozen=True, slots=True)
class MigrationBundle:
    root: pathlib.Path
    export_id: str
    source_repository_id: str
    source_manifest_digest: str
    source_repository_digest: str
    snapshot_digest: str
    records_digest: str
    object_digests: tuple[str, ...]
    source_fencing_high_water: tuple[tuple[str, int], ...]
    snapshot_identity: ExportSnapshotIdentity
    bundle_digest: str
    _policy: MigrationStoragePolicy

    def object_path(self, value: str) -> pathlib.Path:
        if value not in self.object_digests:
            raise MigrationRepositoryError("object is outside the verified bundle manifest")
        return self.root / self._policy.bundle_objects_directory / value.removeprefix("sha256:")

    def object_body(self, value: str) -> bytes:
        body = _read_bounded_regular(
            self.root / self._policy.bundle_objects_directory,
            value.removeprefix("sha256:"),
            self._policy.file_mode,
            self._policy.root_mode,
            self._policy.max_bundle_member_bytes,
        )
        if object_digest(body) != value:
            raise MigrationRepositoryError("bundle object digest mismatch")
        return body


@dataclass(slots=True)
class ImportedRepository:
    root: pathlib.Path
    factory: ConnectionFactory
    locks: LockedFileRegistry
    objects: ObjectRepository
    repository: TaskRepository
    bundle_digest: str
    repository_digest: str
    source_manifest_digest: str
    source_repository_digest: str
    bundle_root: pathlib.Path
    candidate_records_digest: str

    def close(self) -> None:
        self.objects.close()
        self.locks.close()


@dataclass(slots=True)
class CompletedMigration:
    migration_id: str
    active_manifest: ActiveRepositoryManifest
    imported: ImportedRepository
    history: tuple[dict[str, object], ...]

    def close(self) -> None:
        self.imported.close()


_NAMESPACE_SEQUENCE = (
    "repository_meta", "schema_versions", "tasks", "events", "transactions",
    "task_extension_pin_bindings", "catalog",
    "project_scopes", "project_scope_realizations", "project_scope_approvals",
    "project_scope_metadata_history",
    "lifecycle_plans", "lifecycle_plan_executions",
    "objects", "object_references", "resource_fences", "leases", "lease_resources", "claims",
    "claim_recovery_attempts", "claim_resources", "claim_objects", "export_holds",
    "migration_ledger", "migration_ledger_transitions",
    "security_runtime_installation", "task_security_states",
    "disclosure_journal", "purge_authorizations", "action_journal", "concrete_action_records",
)


def _repository_digest_from_records(
    records: Mapping[str, object],
    repository_id: str,
) -> str:
    def project(namespace: str, names: tuple[str, ...]) -> tuple[tuple[object, ...], ...]:
        record = records.get(namespace)
        if not isinstance(record, Mapping):
            raise MigrationRepositoryError("repository digest namespace is absent")
        columns = record.get("columns")
        rows = record.get("rows")
        if not isinstance(columns, list) or not isinstance(rows, list):
            raise MigrationRepositoryError("repository digest namespace is malformed")
        try:
            indexes = tuple(columns.index(name) for name in names)
        except ValueError as error:
            raise MigrationRepositoryError("repository digest column is absent") from error
        projected = tuple(tuple(row[index] for index in indexes) for row in rows)
        return tuple(sorted(projected))

    return semantic_record_digest({
        "repository_id": repository_id,
        "tasks": project(
            "tasks",
            ("task_id", "revision", "head_digest", "snapshot_digest", "integrity_status"),
        ),
        "schemas": project("schema_versions", ("component", "version")),
    })


def _read_live_records(factory: ConnectionFactory) -> dict[str, object]:
    records: dict[str, object] = {}
    with factory.open("doctor") as connection:
        for namespace in _NAMESPACE_SEQUENCE:
            cursor = connection.execute(f'SELECT * FROM "{namespace}"')
            columns = [item[0] for item in cursor.description]
            records[namespace] = {
                "columns": columns,
                "rows": [list(row) for row in cursor.fetchall()],
            }
    return records


def _candidate_projection(
    records: Mapping[str, object],
    *,
    repository_id: str,
    object_digests: tuple[str, ...],
) -> dict[str, object]:
    projected: dict[str, object] = {"repository_id": repository_id, "namespaces": {}}
    namespaces = projected["namespaces"]
    assert isinstance(namespaces, dict)
    for namespace in _NAMESPACE_SEQUENCE:
        if namespace in {
            "export_holds", "migration_ledger", "migration_ledger_transitions",
        }:
            namespaces[namespace] = {"columns": records[namespace]["columns"], "rows": []}  # type: ignore[index]
            continue
        if namespace == "repository_meta":
            rows = [list(row) for row in records[namespace]["rows"]]  # type: ignore[index]
            for row in rows:
                if row[0] == "repository_id":
                    row[1] = repository_id
            namespaces[namespace] = {
                "columns": records[namespace]["columns"],  # type: ignore[index]
                "rows": sorted(rows),
            }
            continue
        if namespace == "objects":
            values = set(object_digests)
            rows = _project_rows(records, namespace, ("digest", "size", "state"))
            namespaces[namespace] = tuple(row for row in rows if row[0] in values)
            continue
        namespaces[namespace] = records[namespace]
    return projected


def _require_bounded_directory(path: pathlib.Path, mode: int) -> None:
    if path.is_symlink():
        raise MigrationRepositoryError("bundle directory cannot be a symlink")
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise MigrationRepositoryError("bundle directory is missing") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise MigrationRepositoryError("bundle directory is not exact owner-only storage")


def _read_bounded_regular(
    root: pathlib.Path,
    name: str,
    mode: int,
    root_mode: int,
    maximum_bytes: int,
) -> bytes:
    if (
        type(name) is not str
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
    ):
        raise MigrationRepositoryError("bundle member name is invalid")
    _require_bounded_directory(root, mode=root_mode)
    root_descriptor = os.open(
        root,
        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        root_before_metadata = os.fstat(root_descriptor)
        root_before = (root_before_metadata.st_dev, root_before_metadata.st_ino)
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_descriptor,
            )
        except OSError as error:
            raise MigrationRepositoryError("bundle member is missing or no-follow rejected") from error
        try:
            metadata = os.fstat(descriptor)
            before = (
                metadata.st_dev, metadata.st_ino, metadata.st_size,
                metadata.st_uid, stat.S_IMODE(metadata.st_mode), metadata.st_nlink,
            )
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != mode
                or metadata.st_size > maximum_bytes
                or metadata.st_nlink != 1
            ):
                raise MigrationRepositoryError("bundle member is not an exact regular file")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            body = b"".join(chunks)
            after_metadata = os.fstat(descriptor)
            after = (
                after_metadata.st_dev, after_metadata.st_ino, after_metadata.st_size,
                after_metadata.st_uid, stat.S_IMODE(after_metadata.st_mode),
                after_metadata.st_nlink,
            )
            root_after_metadata = os.fstat(root_descriptor)
            path_after_metadata = root.lstat()
            root_after = (root_after_metadata.st_dev, root_after_metadata.st_ino)
            if (
                before != after
                or len(body) != before[2]
                or after_metadata.st_nlink != 1
                or root_before != root_after
                or root_after != (path_after_metadata.st_dev, path_after_metadata.st_ino)
            ):
                raise MigrationRepositoryError("bundle member changed during bounded read")
            return body
        finally:
            os.close(descriptor)
    finally:
        os.close(root_descriptor)


def _require_json_bounds(value: object, *, maximum_nodes: int, maximum_depth: int) -> None:
    pending: list[tuple[object, int]] = [(value, 1)]
    observed = 0
    while pending:
        current, depth = pending.pop()
        observed += 1
        if observed > maximum_nodes or depth > maximum_depth:
            raise MigrationRepositoryError("bundle canonical JSON exceeds policy bounds")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


def _project_rows(
    records: Mapping[str, object],
    namespace: str,
    names: tuple[str, ...],
) -> tuple[tuple[object, ...], ...]:
    record = records.get(namespace)
    if not isinstance(record, Mapping):
        raise MigrationRepositoryError("snapshot identity namespace is absent")
    columns = record.get("columns")
    rows = record.get("rows")
    if not isinstance(columns, list) or not isinstance(rows, list):
        raise MigrationRepositoryError("snapshot identity namespace is malformed")
    try:
        indexes = tuple(columns.index(name) for name in names)
    except ValueError as error:
        raise MigrationRepositoryError("snapshot identity column is absent") from error
    try:
        return tuple(sorted(tuple(row[index] for index in indexes) for row in rows))
    except (IndexError, TypeError) as error:
        raise MigrationRepositoryError("snapshot identity row is malformed") from error


def _export_snapshot_identity(
    records: Mapping[str, object],
    *,
    export_id: str,
    source_repository_id: str,
    activation_epoch: int,
    object_digests: tuple[str, ...],
) -> ExportSnapshotIdentity:
    tasks = _project_rows(records, "tasks", ("task_id", "revision", "head_digest"))
    transactions = _project_rows(
        records, "transactions", ("transaction_id", "task_id", "revision", "head_digest"),
    )
    unresolved_claims = tuple(
        row for row in _project_rows(
            records, "claims", ("claim_id", "task_id", "state", "started_event_digest"),
        )
        if row[2] == "unresolved"
    )
    unresolved_actions = tuple(
        row for row in _project_rows(
            records,
            "action_journal",
            ("action_id", "task_id", "state", "revision", "prepared_digest", "authority_digest"),
        )
        if row[2] in {"executing", "unknown"}
    )
    fences = _project_rows(records, "resource_fences", ("resource_id", "fencing_token"))
    object_values = set(object_digests)
    object_manifest = tuple(
        row for row in _project_rows(records, "objects", ("digest", "size", "state"))
        if row[0] in object_values
    )
    if (
        {row[0] for row in object_manifest} != object_values
        or any(row[2] != "available" for row in object_manifest)
    ):
        raise MigrationRepositoryError("snapshot referenced object manifest is incomplete")
    return ExportSnapshotIdentity.create(
        export_id=export_id,
        source_repository_id=source_repository_id,
        activation_epoch=activation_epoch,
        backup_head_digest=semantic_record_digest({
            "tasks": tasks,
            "transactions": transactions,
            "fencing_high_water": fences,
            "unresolved_claims": unresolved_claims,
            "unresolved_actions": unresolved_actions,
        }),
        backup_revision=len(transactions) + 1,
        schema_manifest_digest=semantic_record_digest({
            "schema_versions": _project_rows(
                records, "schema_versions", ("component", "version", "applied_at"),
            ),
        }),
        object_manifest_digest=semantic_record_digest({
            "objects": object_manifest,
        }),
        object_digests=object_digests,
    )


def _candidate_object_manifest_digest(
    objects: ObjectRepository,
    records: Mapping[str, object],
    object_digests: tuple[str, ...],
) -> str:
    expected = {
        row[0]: (row[1], row[2])
        for row in _project_rows(records, "objects", ("digest", "size", "state"))
        if row[0] in set(object_digests)
    }
    observed: list[tuple[str, int, str]] = []
    for value in object_digests:
        try:
            body = objects._verify_object(value)
        except RepositoryError as error:
            raise MigrationRepositoryError(
                "candidate object body recomputation failed",
            ) from error
        metadata = expected.get(value)
        if metadata != (len(body), "available"):
            raise MigrationRepositoryError("candidate object metadata or body is not exact")
        observed.append((value, len(body), "available"))
    return semantic_record_digest({"objects": tuple(observed)})


def _snapshot_identity_body(identity: ExportSnapshotIdentity) -> dict[str, object]:
    value = dataclasses.asdict(identity)
    value["object_digests"] = list(identity.object_digests)
    return value


def _load_snapshot_identity(value: object) -> ExportSnapshotIdentity:
    fields = {
        "export_id", "source_repository_id", "activation_epoch", "backup_head_digest",
        "backup_revision", "schema_manifest_digest", "object_manifest_digest",
        "object_digests", "snapshot_digest",
    }
    if not isinstance(value, dict) or set(value) != fields or type(value.get("object_digests")) is not list:
        raise MigrationRepositoryError("export snapshot identity is not exact")
    try:
        identity = ExportSnapshotIdentity.create(
            export_id=value["export_id"],
            source_repository_id=value["source_repository_id"],
            activation_epoch=value["activation_epoch"],
            backup_head_digest=value["backup_head_digest"],
            backup_revision=value["backup_revision"],
            schema_manifest_digest=value["schema_manifest_digest"],
            object_manifest_digest=value["object_manifest_digest"],
            object_digests=tuple(value["object_digests"]),
        )
    except (TypeError, MigrationControlError) as error:
        raise MigrationRepositoryError("export snapshot identity is invalid") from error
    if identity.snapshot_digest != value["snapshot_digest"]:
        raise MigrationRepositoryError("export snapshot identity digest mismatch")
    return identity


@dataclass(frozen=True, slots=True)
class _RepositoryLocator:
    locator_ref: str
    repository_id: str
    root: pathlib.Path
    device: int
    inode: int
    locator_digest: str

    @classmethod
    def from_factory(cls, factory: ConnectionFactory) -> _RepositoryLocator:
        root = factory.data_root
        metadata = root.lstat()
        body = {
            "schema_version": "1.0",
            "locator_ref": "repository-locator:" + hashlib.sha256(factory.repository_id.encode()).hexdigest(),
            "repository_id": factory.repository_id,
            "root": root.as_posix(),
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
        }
        return cls(
            body["locator_ref"], body["repository_id"], root,
            body["device"], body["inode"], semantic_record_digest(body),
        )

    def body(self) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "locator_ref": self.locator_ref,
            "repository_id": self.repository_id,
            "root": self.root.as_posix(),
            "device": self.device,
            "inode": self.inode,
            "locator_digest": self.locator_digest,
        }

    @classmethod
    def load(cls, value: object) -> _RepositoryLocator:
        fields = {
            "schema_version", "locator_ref", "repository_id", "root", "device", "inode",
            "locator_digest",
        }
        if not isinstance(value, dict) or set(value) != fields or value.get("schema_version") != "1.0":
            raise MigrationRepositoryError("repository locator record is not exact")
        if any(type(value.get(name)) is not str or not value[name] for name in ("locator_ref", "repository_id", "root", "locator_digest")):
            raise MigrationRepositoryError("repository locator identity is invalid")
        if any(type(value.get(name)) is not int or value[name] < 0 for name in ("device", "inode")):
            raise MigrationRepositoryError("repository locator filesystem identity is invalid")
        root = pathlib.Path(value["root"])
        if not root.is_absolute():
            raise MigrationRepositoryError("repository locator root is not absolute")
        body = {name: value[name] for name in fields if name != "locator_digest"}
        locator = cls(
            value["locator_ref"], value["repository_id"], root,
            value["device"], value["inode"], value["locator_digest"],
        )
        if semantic_record_digest(body) != locator.locator_digest:
            raise MigrationRepositoryError("repository locator digest mismatch")
        return locator

    def verify_root(self) -> pathlib.Path:
        if self.root.is_symlink():
            raise MigrationRepositoryError("repository locator root is a symlink")
        try:
            metadata = self.root.lstat()
        except FileNotFoundError as error:
            raise MigrationRepositoryError("repository locator root is missing") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or (metadata.st_dev, metadata.st_ino) != (self.device, self.inode)
        ):
            raise MigrationRepositoryError("repository locator root identity changed")
        return self.root.resolve(strict=True)


_COMMAND_SCOPE_SEAL = object()


class InstallationCommandScope(AbstractContextManager["InstallationCommandScope"]):
    """PID/thread-bound authority holding the stable installation shared lock."""

    def __init__(self, manager: InstallationMigrationRepository, *, seal: object) -> None:
        if seal is not _COMMAND_SCOPE_SEAL:
            raise MigrationRepositoryError("installation command scope is factory-only")
        self._manager = manager
        self._context: RepositoryCommandContext | None = None
        self._root: pathlib.Path | None = None
        self.__control_token: _ControlLockToken | None = None
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._closed = False
        self._connections: set[object] = set()

    def __enter__(self) -> InstallationCommandScope:
        self._manager._enter_command_scope(self)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore[no-untyped-def]
        self._require_owner()
        if self._connections:
            raise MigrationRepositoryError(
                "installation command scope cannot close with open connections",
            )
        self._manager._exit_command_scope(self)
        self._closed = True

    def _bind(
        self,
        context: RepositoryCommandContext,
        root: pathlib.Path,
        control_token: _ControlLockToken,
    ) -> None:
        if self._context is not None:
            raise MigrationRepositoryError("installation command scope is already bound")
        self._context = context
        self._root = root
        self.__control_token = control_token

    def _control_token(self) -> _ControlLockToken:
        self._require_owner()
        if self.__control_token is None:
            raise MigrationRepositoryError("installation command scope has no control token")
        return self.__control_token

    def _require_owner(self) -> None:
        if self._closed or self._pid != os.getpid() or self._thread != threading.get_ident():
            raise MigrationRepositoryError("installation command scope is closed or foreign")
        if self._context is None or self._root is None:
            raise MigrationRepositoryError("installation command scope is not entered")

    def require_current(self) -> None:
        self._require_owner()
        self._manager._require_command_scope(self)

    def _connection_opened(self, token: object) -> None:
        self.require_current()
        if token in self._connections:
            raise MigrationRepositoryError("command connection token is duplicated")
        self._connections.add(token)

    def _connection_closed(self, token: object) -> None:
        self._require_owner()
        if token not in self._connections:
            raise MigrationRepositoryError("command connection token is missing")
        self._connections.remove(token)

    @property
    def context(self) -> RepositoryCommandContext:
        self._require_owner()
        assert self._context is not None
        return self._context

    @property
    def repository_root(self) -> pathlib.Path:
        self._require_owner()
        assert self._root is not None
        return self._root

    def __getattr__(self, name: str) -> object:
        if name in {
            "installation_id", "generation", "activation_epoch", "repository_id",
            "repository_locator_ref", "repository_locator_digest", "manifest_digest",
        }:
            return getattr(self.context, name)
        raise AttributeError(name)


@dataclass(frozen=True, slots=True)
class _ControlLockToken:
    token_id: int
    handle_id: int
    pid: int
    thread_id: int
    mode: str


@dataclass(slots=True)
class _ControlLockEntry:
    descriptor: int
    device: int
    inode: int
    holders: dict[int, _ControlLockToken]
    guard: threading.Lock
    references: int
    next_token_id: int


class _ControlLockRegistry:
    _GUARD: ClassVar[threading.Lock] = threading.Lock()
    _ENTRIES: ClassVar[dict[tuple[int, str], _ControlLockEntry]] = {}
    _NEXT_HANDLE: ClassVar[int] = 1

    def __init__(self, root: pathlib.Path, name: str, mode: int) -> None:
        self._root = root
        self._name = name
        self._mode = mode
        self._pid = os.getpid()
        self._closed = False
        self._tokens: dict[int, _ControlLockToken] = {}
        self._key = (self._pid, (root / name).as_posix())
        with self._GUARD:
            entry = self._ENTRIES.get(self._key)
            if entry is None:
                parent_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    descriptor = os.open(
                        self._name,
                        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                        mode,
                        dir_fd=parent_descriptor,
                    )
                finally:
                    os.close(parent_descriptor)
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != mode
                ):
                    os.close(descriptor)
                    raise MigrationRepositoryError("installation control lock is untrusted")
                entry = _ControlLockEntry(
                    descriptor, metadata.st_dev, metadata.st_ino, {}, threading.Lock(), 0, 1,
                )
                self._ENTRIES[self._key] = entry
            entry.references += 1
            self._entry = entry
            self._handle_id = self._NEXT_HANDLE
            type(self)._NEXT_HANDLE += 1

    @classmethod
    def _after_fork_child(cls) -> None:
        for entry in cls._ENTRIES.values():
            try:
                os.close(entry.descriptor)
            except OSError:
                pass
        cls._ENTRIES = {}
        cls._GUARD = threading.Lock()
        cls._NEXT_HANDLE = 1

    def _check(self) -> None:
        if self._closed or self._pid != os.getpid():
            raise MigrationRepositoryError("installation control registry is closed or foreign")
        descriptor = os.fstat(self._entry.descriptor)
        path = (self._root / self._name).lstat()
        if (
            not stat.S_ISREG(path.st_mode)
            or path.st_uid != os.getuid()
            or stat.S_IMODE(path.st_mode) != self._mode
            or (descriptor.st_dev, descriptor.st_ino) != (self._entry.device, self._entry.inode)
            or (path.st_dev, path.st_ino) != (self._entry.device, self._entry.inode)
        ):
            raise MigrationRepositoryError("installation control lock inode changed")

    @property
    def inode_identity(self) -> tuple[int, int]:
        self._check()
        return self._entry.device, self._entry.inode

    def acquire(self, mode: str = "exclusive") -> _ControlLockToken:
        self._check()
        if mode not in {"shared", "exclusive"}:
            raise MigrationRepositoryError("installation control lock mode is invalid")
        thread_id = threading.get_ident()
        with self._entry.guard:
            if any(token.thread_id == thread_id for token in self._entry.holders.values()):
                raise MigrationRepositoryError("installation control lock is not reentrant")
            readers = any(token.mode == "shared" for token in self._entry.holders.values())
            writer = any(token.mode == "exclusive" for token in self._entry.holders.values())
            if writer or mode == "exclusive" and readers:
                raise MigrationRepositoryError("installation control lock is busy")
            if not self._entry.holders:
                try:
                    operation = fcntl.LOCK_SH if mode == "shared" else fcntl.LOCK_EX
                    fcntl.lockf(self._entry.descriptor, operation | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise MigrationRepositoryError("installation control lock is busy") from error
            token = _ControlLockToken(
                self._entry.next_token_id, self._handle_id, self._pid, thread_id, mode,
            )
            self._entry.next_token_id += 1
            self._entry.holders[token.token_id] = token
            self._tokens[token.token_id] = token
            return token

    def require_held(self, token: _ControlLockToken, mode: str) -> None:
        self._check()
        if (
            type(token) is not _ControlLockToken
            or token.mode != mode
            or token.pid != self._pid
            or token.thread_id != threading.get_ident()
            or token.handle_id != self._handle_id
            or self._tokens.get(token.token_id) is not token
            or self._entry.holders.get(token.token_id) is not token
        ):
            raise MigrationRepositoryError("installation control scope token is missing or foreign")

    def release(self, token: _ControlLockToken) -> None:
        self.require_held(token, token.mode)
        with self._entry.guard:
            self._entry.holders.pop(token.token_id)
            self._tokens.pop(token.token_id)
            if not self._entry.holders:
                fcntl.lockf(self._entry.descriptor, fcntl.LOCK_UN)

    def close(self) -> None:
        self._check()
        if self._tokens:
            raise MigrationRepositoryError("cannot close a held installation control lock")
        with self._GUARD:
            self._entry.references -= 1
            if self._entry.references == 0:
                if self._entry.holders:
                    raise MigrationRepositoryError("cannot close the final active control registry")
                os.close(self._entry.descriptor)
                self._ENTRIES.pop(self._key, None)
        self._closed = True


os.register_at_fork(after_in_child=_ControlLockRegistry._after_fork_child)


def _manifest_body(value: ActiveRepositoryManifest) -> dict[str, object]:
    result = dataclasses.asdict(value)
    result["fencing_high_water"] = [list(item) for item in value.fencing_high_water]
    return result


def _restore_gap_body(value: RestoreGap) -> dict[str, object]:
    result = dataclasses.asdict(value)
    result["resources"] = [list(item) for item in value.resources]
    return result


def _load_manifest(value: object) -> ActiveRepositoryManifest:
    if not isinstance(value, Mapping):
        raise MigrationRepositoryError("active repository manifest is not an object")
    required = {
        "installation_id", "generation", "activation_epoch", "repository_id", "repository_digest",
        "repository_locator_ref", "repository_locator_digest",
        "release_id", "contract_id", "mode", "previous_manifest_digest", "fencing_high_water",
        "restore_gap_digest", "manifest_digest",
    }
    if set(value) != required or type(value.get("fencing_high_water")) is not list:
        raise MigrationRepositoryError("active repository manifest is not exact")
    try:
        manifest = ActiveRepositoryManifest.create(
            installation_id=value["installation_id"],  # type: ignore[arg-type]
            generation=value["generation"],  # type: ignore[arg-type]
            activation_epoch=value["activation_epoch"],  # type: ignore[arg-type]
            repository_id=value["repository_id"],  # type: ignore[arg-type]
            repository_digest=value["repository_digest"],  # type: ignore[arg-type]
            repository_locator_ref=value["repository_locator_ref"],  # type: ignore[arg-type]
            repository_locator_digest=value["repository_locator_digest"],  # type: ignore[arg-type]
            release_id=value["release_id"],  # type: ignore[arg-type]
            contract_id=value["contract_id"],  # type: ignore[arg-type]
            mode=value["mode"],  # type: ignore[arg-type]
            previous_manifest_digest=value["previous_manifest_digest"],  # type: ignore[arg-type]
            fencing_high_water=tuple(tuple(item) for item in value["fencing_high_water"]),  # type: ignore[misc]
            restore_gap_digest=value["restore_gap_digest"],  # type: ignore[arg-type]
        )
    except (TypeError, ValueError, MigrationControlError) as error:
        raise MigrationRepositoryError(str(error)) from error
    if manifest.manifest_digest != value.get("manifest_digest"):
        raise MigrationRepositoryError("active repository manifest digest mismatch")
    return manifest


def _write_atomic(
    root: pathlib.Path,
    name: str,
    body: bytes,
    mode: int,
    *,
    replace_existing: bool = True,
) -> None:
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    temporary = f".{name}.{secrets.token_hex(8)}"
    try:
        output = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            mode,
            dir_fd=descriptor,
        )
        try:
            view = memoryview(body)
            offset = 0
            while offset < len(body):
                offset += os.write(output, view[offset:])
            os.fsync(output)
        finally:
            os.close(output)
        if replace_existing:
            os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        else:
            os.link(
                temporary,
                name,
                src_dir_fd=descriptor,
                dst_dir_fd=descriptor,
                follow_symlinks=False,
            )
            os.unlink(temporary, dir_fd=descriptor)
        os.fsync(descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)


class InstallationMigrationRepository:
    """Single ADR-0002 export/import/activation implementation for the local backend."""

    def __init__(
        self,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        control_root: pathlib.Path,
        policy: MigrationStoragePolicy,
        control_lock: _ControlLockRegistry,
        fault_hook: Callable[[str], None],
    ) -> None:
        self._factory = factory._for_maintenance()
        self._locks = locks
        self._objects = objects
        self._control = control_root
        self._policy = policy
        self._control_lock = control_lock
        self._fault = fault_hook

    @classmethod
    def initialize(
        cls,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        *,
        control_root: pathlib.Path,
        policy_document: object,
        fault_hook: Callable[[str], None] = _no_fault,
    ) -> InstallationMigrationRepository:
        policy = MigrationStoragePolicy.from_dict(policy_document)
        if not control_root.is_absolute() or control_root.is_symlink():
            raise MigrationRepositoryError("installation control root is invalid")
        control_root.mkdir(mode=policy.root_mode, parents=False, exist_ok=True)
        metadata = control_root.lstat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != policy.root_mode:
            raise MigrationRepositoryError("installation control root is not owner-only")
        history = control_root / policy.manifest_history_directory
        history.mkdir(mode=policy.root_mode, exist_ok=True)
        manager = cls(
            factory,
            locks,
            objects,
            control_root,
            policy,
            _ControlLockRegistry(control_root, policy.control_lock_filename, policy.file_mode),
            fault_hook,
        )
        active_file = control_root / policy.active_manifest_filename
        exists = active_file.exists()
        control_token = manager._control_lock.acquire("exclusive")
        try:
            locator = manager._register_locator(factory, control_token)
            if not exists:
                fences = manager._fences()
                initial = ActiveRepositoryManifest.create(
                    installation_id="installation-" + hashlib.sha256(control_root.as_posix().encode()).hexdigest(),
                    generation=1,
                    activation_epoch=1,
                    repository_id=factory.repository_id,
                    repository_digest=manager._repository_digest(),
                    repository_locator_ref=locator.locator_ref,
                    repository_locator_digest=locator.locator_digest,
                    release_id=policy.initial_release_id,
                    contract_id=policy.repository_contract_id,
                    mode="active",
                    previous_manifest_digest=None,
                    fencing_high_water=fences,
                    restore_gap_digest=None,
                )
                manager._publish_manifest(initial)
        finally:
            manager._control_lock.release(control_token)
        if exists:
            manager.recover_activation()
        return manager

    @classmethod
    def attach_command_plane(
        cls,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        *,
        control_root: pathlib.Path,
        policy_document: object,
    ) -> InstallationMigrationRepository:
        """Attach read-only command routing without running migration recovery."""

        policy = MigrationStoragePolicy.from_dict(policy_document)
        if not control_root.is_absolute() or control_root.is_symlink():
            raise MigrationRepositoryError("installation control root is invalid")
        metadata = control_root.lstat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != policy.root_mode:
            raise MigrationRepositoryError("installation control root is not owner-only")
        for target in (
            control_root / policy.manifest_history_directory,
            control_root / policy.active_manifest_filename,
            control_root / policy.repository_locator_registry_filename,
        ):
            if not target.exists() or target.is_symlink():
                raise MigrationRepositoryError("installation command-plane state is incomplete")
        return cls(
            factory,
            locks,
            objects,
            control_root,
            policy,
            _ControlLockRegistry(control_root, policy.control_lock_filename, policy.file_mode),
            _no_fault,
        )

    def _cold_control_owner(self):
        from graph_engineering.core.contracts.resources import WorkContext
        from .repository import _RECOVERY_INSTALLATION_CONTEXT, _RecoveryReadBudget

        context = _RECOVERY_INSTALLATION_CONTEXT.get()
        owner = getattr(self, "_recovery_read_budget", None)
        if context is None:
            if owner is not None:
                raise MigrationRepositoryError("cold installation context is missing")
            return None
        if (type(context) is not WorkContext or type(owner) is not _RecoveryReadBudget
                or getattr(context, "_recovery_read_budget", None) is not owner
                or owner.contexts[0] is not context
                or type(owner.command_scope) is not InstallationCommandScope
                or owner.command_scope._manager is not self):
            raise MigrationRepositoryError("cold installation context is foreign")
        owner._require_active()
        self._control_lock.require_held(owner.command_scope._control_token(), "shared")
        return context, owner

    @contextmanager
    def _cold_control_document(self, name, context, owner):
        """Keep admitted raw/parsed control data charged through its caller."""
        from graph_engineering.core.contracts.strict_json import parse_json

        if name not in (self._policy.active_manifest_filename,
                        self._policy.repository_locator_registry_filename):
            raise MigrationRepositoryError("cold control member is not configured")
        _require_bounded_directory(self._control, mode=self._policy.root_mode)
        root_before = self._control.lstat()
        root_fd = descriptor = None
        body = value = None
        def identity(metadata: os.stat_result) -> tuple[int, ...]:
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                    metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        def root_identity(metadata: os.stat_result) -> tuple[int, ...]:
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid)
        try:
            root_fd = os.open(self._control, os.O_RDONLY | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            root_metadata = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != os.getuid()
                    or stat.S_IMODE(root_metadata.st_mode) != self._policy.root_mode
                    or root_identity(root_metadata) != root_identity(root_before)):
                raise MigrationRepositoryError("cold control root identity changed")
            named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            descriptor = os.open(name, os.O_RDONLY | os.O_NONBLOCK
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
            metadata = os.fstat(descriptor)
            if (identity(named) != identity(metadata) or not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid() or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != self._policy.file_mode):
                raise MigrationRepositoryError("cold control descriptor/path is untrusted")
            size = metadata.st_size
            context.check_limit("raw_document_bytes", size, source_id=name)
            # Raw bytes, decoded text, parsed containers, canonical validation,
            # domain objects and the growth sentinel overlap in this frame.
            with owner.reserve(context, units=8 * size + 1, byte_count=6 * size + 1, source_id=name):
                try:
                    body = os.read(descriptor, size)
                    if len(body) != size:
                        raise MigrationRepositoryError("cold control short read")
                    if os.read(descriptor, 1):
                        raise MigrationRepositoryError("cold control grew during bounded read")
                    if (identity(os.fstat(descriptor)) != identity(metadata)
                            or identity(os.stat(name, dir_fd=root_fd, follow_symlinks=False)) != identity(metadata)
                            or root_identity(os.fstat(root_fd)) != root_identity(root_before)
                            or root_identity(self._control.lstat()) != root_identity(root_before)):
                        raise MigrationRepositoryError("cold control changed during bounded read")
                    owner._require_active()
                    value = parse_json(body, context=context, source_id=name,
                        operation_path=context.child_path(()))
                    if canonical_bytes(value) != body:
                        raise MigrationRepositoryError("cold control JSON is not canonical")
                    yield value
                finally:
                    body = value = None
        except OSError as error:
            raise MigrationRepositoryError("cold control member is missing or untrusted") from error
        finally:
            try:
                if descriptor is not None:
                    os.close(descriptor)
            finally:
                if root_fd is not None:
                    os.close(root_fd)

    def _load_locators(self, *, _cold_stack=None) -> tuple[_RepositoryLocator, ...]:
        cold = self._cold_control_owner()
        target = self._control / self._policy.repository_locator_registry_filename
        if cold is None and not target.exists():
            return ()
        metadata = target.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != self._policy.file_mode
        ):
            raise MigrationRepositoryError("repository locator registry is untrusted")
        if cold is None:
            value = parse_canonical_json(target.read_text())
        else:
            if type(_cold_stack) is not ExitStack:
                raise MigrationRepositoryError("cold locator read has no retained frame")
            context, owner = cold
            value = _cold_stack.enter_context(self._cold_control_document(
                self._policy.repository_locator_registry_filename, context, owner))
        if not isinstance(value, dict) or set(value) != {"schema_version", "repositories"} or value.get("schema_version") != "1.0":
            raise MigrationRepositoryError("repository locator registry is not exact")
        repositories = value.get("repositories")
        if type(repositories) is not list:
            raise MigrationRepositoryError("repository locator registry entries are invalid")
        if cold is not None:
            context.check_limit("array_items", len(repositories), source_id="cold-locators")
        loaded = tuple(_RepositoryLocator.load(item) for item in repositories)
        if tuple(item.locator_ref for item in loaded) != tuple(sorted({item.locator_ref for item in loaded})):
            raise MigrationRepositoryError("repository locator registry is not canonical")
        if len({item.repository_id for item in loaded}) != len(loaded):
            raise MigrationRepositoryError("repository locator repository identity is duplicated")
        return loaded

    def _register_locator(
        self,
        factory: ConnectionFactory,
        control_token: _ControlLockToken,
    ) -> _RepositoryLocator:
        self._control_lock.require_held(control_token, "exclusive")
        locator = _RepositoryLocator.from_factory(factory)
        existing = self._load_locators()
        by_ref = {item.locator_ref: item for item in existing}
        by_repository = {item.repository_id: item for item in existing}
        conflict = by_ref.get(locator.locator_ref) or by_repository.get(locator.repository_id)
        if conflict is not None:
            if conflict != locator:
                raise MigrationRepositoryError("repository locator cannot be rebound")
            return conflict
        entries = tuple(sorted(existing + (locator,), key=lambda item: item.locator_ref))
        _write_atomic(
            self._control,
            self._policy.repository_locator_registry_filename,
            canonical_bytes({
                "schema_version": "1.0",
                "repositories": [item.body() for item in entries],
            }),
            self._policy.file_mode,
        )
        return locator

    def _resolve_locator(self, manifest: ActiveRepositoryManifest, *, _cold_stack=None) -> pathlib.Path:
        matches = tuple(
            item for item in self._load_locators(_cold_stack=_cold_stack)
            if item.locator_ref == manifest.repository_locator_ref
        )
        if len(matches) != 1:
            raise MigrationRepositoryError("active repository locator is missing or duplicated")
        locator = matches[0]
        if (
            locator.repository_id != manifest.repository_id
            or locator.locator_digest != manifest.repository_locator_digest
        ):
            raise MigrationRepositoryError("active repository locator binding mismatch")
        return locator.verify_root()

    def _factory_for_manifest(
        self,
        manifest: ActiveRepositoryManifest,
    ) -> ConnectionFactory:
        root = self._resolve_locator(manifest)
        try:
            return ConnectionFactory._attach_existing_for_maintenance(
                root,
                self._factory.policy,
                manifest.repository_id,
            )
        except RepositoryError as error:
            raise MigrationRepositoryError(
                "active repository cannot be attached from its exact locator",
            ) from error

    def _current_factory(
        self,
        control_token: _ControlLockToken,
        *,
        require_active: bool = True,
    ) -> tuple[ActiveRepositoryManifest, ConnectionFactory]:
        self._control_lock.require_held(control_token, control_token.mode)
        current = self._current_manifest()
        if require_active and not current.ordinary_commands_allowed:
            raise MigrationRepositoryError(
                f"current repository is {current.mode}, not verified active",
            )
        return current, self._factory_for_manifest(current)

    def _read_repository_object(self, factory: ConnectionFactory, digest: str) -> bytes:
        try:
            hexadecimal = digest.removeprefix("sha256:")
            if len(hexadecimal) != 64 or any(value not in "0123456789abcdef" for value in hexadecimal):
                raise MigrationRepositoryError("object digest is invalid")
            split = factory.policy.object_fanout_chars
            directory = factory.data_root / factory.policy.objects_directory / hexadecimal[:split]
            body = _read_bounded_regular(
                directory,
                hexadecimal[split:],
                self._policy.file_mode,
                self._policy.root_mode,
                self._policy.max_bundle_member_bytes,
            )
        except (OSError, ValueError) as error:
            raise MigrationRepositoryError("referenced repository object is unavailable") from error
        if object_digest(body) != digest:
            raise MigrationRepositoryError("referenced repository object digest changed")
        return body

    def command_scope(self) -> InstallationCommandScope:
        return InstallationCommandScope(self, seal=_COMMAND_SCOPE_SEAL)

    def _enter_command_scope(self, scope: InstallationCommandScope) -> None:
        control_token = self._control_lock.acquire("shared")
        try:
            current, factory = self._current_factory(control_token)
            with factory.open("doctor") as connection:
                open_gaps = connection.execute(
                    "SELECT COUNT(*) FROM migration_ledger WHERE state='restore_gap_open'",
                ).fetchone()[0]
            if open_gaps:
                raise MigrationRepositoryError("installation restore gap blocks commands")
            root = self._resolve_locator(current)
            scope._bind(RepositoryCommandContext.from_active_manifest(current), root, control_token)
        except BaseException:
            self._control_lock.release(control_token)
            raise

    def _require_command_scope(self, scope: InstallationCommandScope) -> None:
        control_token = scope._control_token()
        self._control_lock.require_held(control_token, "shared")
        cold = self._cold_control_owner()
        if cold is not None and cold[1].command_scope is not scope:
            raise MigrationRepositoryError("cold installation command scope is foreign")
        with ExitStack() as stack:
            current = None
            try:
                current = self._current_manifest(_cold_stack=stack)
                if current.manifest_digest != scope.context.manifest_digest:
                    raise MigrationRepositoryError("installation command context is stale")
                if self._resolve_locator(current, _cold_stack=stack) != scope.repository_root:
                    raise MigrationRepositoryError("installation command locator changed")
            except BaseException as error:
                if cold is not None:
                    # Returned failures must not retain charged parse/domain
                    # payloads through frames that have already unwound.
                    import traceback
                    pending, seen = [error], set()
                    while pending:
                        cause = pending.pop()
                        if cause is None or id(cause) in seen:
                            continue
                        seen.add(id(cause))
                        traceback.clear_frames(cause.__traceback__)
                        pending.extend((cause.__cause__, cause.__context__))
                raise
            finally:
                current = None

    def _exit_command_scope(self, scope: InstallationCommandScope) -> None:
        control_token = scope._control_token()
        self._control_lock.require_held(control_token, "shared")
        self._control_lock.release(control_token)

    def _repository_digest(self, factory: ConnectionFactory | None = None) -> str:
        selected = self._factory if factory is None else factory
        with selected.open("doctor") as connection:
            tasks = connection.execute(
                "SELECT task_id,revision,head_digest,snapshot_digest,integrity_status FROM tasks ORDER BY task_id"
            ).fetchall()
            schemas = connection.execute(
                "SELECT component,version FROM schema_versions ORDER BY component"
            ).fetchall()
        return semantic_record_digest({"repository_id": selected.repository_id, "tasks": tasks, "schemas": schemas})

    def _fences(self, factory: ConnectionFactory | None = None) -> tuple[tuple[str, int], ...]:
        selected = self._factory if factory is None else factory
        with selected.open("doctor") as connection:
            return tuple(connection.execute(
                "SELECT resource_id,fencing_token FROM resource_fences ORDER BY resource_id"
            ).fetchall())

    def _history_root(self) -> pathlib.Path:
        return self._control / self._policy.manifest_history_directory

    def _publish_manifest(self, manifest: ActiveRepositoryManifest) -> None:
        body = canonical_bytes(_manifest_body(manifest))
        history_name = f"{manifest.generation:020d}-{manifest.manifest_digest.removeprefix('sha256-jcs-v1:')}.json"
        try:
            _write_atomic(
                self._history_root(),
                history_name,
                body,
                self._policy.file_mode,
                replace_existing=False,
            )
        except FileExistsError:
            existing = self._history_root() / history_name
            metadata = existing.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != self._policy.file_mode
                or existing.read_bytes() != body
            ):
                raise MigrationRepositoryError("manifest history no-replace conflict")
        _write_atomic(self._control, self._policy.active_manifest_filename, body, self._policy.file_mode)

    def close(self) -> None:
        self._control_lock.close()

    def _publish_blocked(self, current: ActiveRepositoryManifest) -> ActiveRepositoryManifest:
        blocked = ActiveRepositoryManifest.create(
            installation_id=current.installation_id,
            generation=current.generation + 1,
            activation_epoch=current.activation_epoch + 1,
            repository_id=current.repository_id,
            repository_digest=current.repository_digest,
            repository_locator_ref=current.repository_locator_ref,
            repository_locator_digest=current.repository_locator_digest,
            release_id=current.release_id,
            contract_id=current.contract_id,
            mode="blocked",
            previous_manifest_digest=current.manifest_digest,
            fencing_high_water=current.fencing_high_water,
            restore_gap_digest=current.restore_gap_digest,
        )
        blocked.require_successor_of(current)
        self._publish_manifest(blocked)
        return blocked

    @staticmethod
    def _require_exact_current_chain(
        current: ActiveRepositoryManifest,
        manifests: tuple[ActiveRepositoryManifest, ...],
    ) -> None:
        by_digest = {item.manifest_digest: item for item in manifests}
        if len(by_digest) != len(manifests):
            raise MigrationRepositoryError("manifest history contains duplicate records")
        node = current
        seen: set[str] = set()
        while True:
            if node.manifest_digest in seen or by_digest.get(node.manifest_digest) != node:
                raise MigrationRepositoryError("active manifest chain is incomplete or cyclic")
            seen.add(node.manifest_digest)
            if node.previous_manifest_digest is None:
                if node.generation != 1:
                    raise MigrationRepositoryError("active manifest chain has no generation-one root")
                return
            previous = by_digest.get(node.previous_manifest_digest)
            if previous is None:
                raise MigrationRepositoryError("active manifest predecessor is absent")
            try:
                node.require_successor_of(previous)
            except MigrationControlError as error:
                raise MigrationRepositoryError(str(error)) from error
            node = previous

    def _current_manifest(self, *, _cold_stack=None) -> ActiveRepositoryManifest:
        cold = self._cold_control_owner()
        if cold is None:
            value = parse_canonical_json(
                (self._control / self._policy.active_manifest_filename).read_text(),
            )
        else:
            if type(_cold_stack) is not ExitStack:
                raise MigrationRepositoryError("cold manifest read has no retained frame")
            value = _cold_stack.enter_context(self._cold_control_document(
                self._policy.active_manifest_filename, *cold))
        return _load_manifest(value)

    def _migration_record(
        self,
        state: MigrationState,
        *,
        source: ActiveRepositoryManifest,
        request: Mapping[str, object],
        previous_transition_digest: str | None,
        bundle: MigrationBundle | None,
        imported: ImportedRepository | None,
        verifying: ActiveRepositoryManifest | None,
        active: ActiveRepositoryManifest | None,
    ) -> tuple[dict[str, object], str]:
        self._control_lock.inode_identity
        record: dict[str, object] = {
            "schema_version": "1.0",
            "migration": dataclasses.asdict(state),
            "request": dict(request),
            "source_manifest": _manifest_body(source),
            "bundle": None if bundle is None else {
                "bundle_digest": bundle.bundle_digest,
                "snapshot_digest": bundle.snapshot_digest,
                "source_manifest_digest": bundle.source_manifest_digest,
                "source_repository_digest": bundle.source_repository_digest,
                "source_fencing_high_water": [list(item) for item in bundle.source_fencing_high_water],
            },
            "candidate": None if imported is None else {
                "repository_id": imported.factory.repository_id,
                "repository_digest": imported.repository_digest,
                "candidate_records_digest": imported.candidate_records_digest,
                "bundle_digest": imported.bundle_digest,
                "source_manifest_digest": imported.source_manifest_digest,
                "source_repository_digest": imported.source_repository_digest,
                "repository_locator_ref": (
                    None if verifying is None else verifying.repository_locator_ref
                ),
                "repository_locator_digest": (
                    None if verifying is None else verifying.repository_locator_digest
                ),
                "release_id": None if verifying is None else verifying.release_id,
                "contract_id": None if verifying is None else verifying.contract_id,
                "activated_repository_digest": (
                    None if verifying is None else verifying.repository_digest
                ),
            },
            "verifying_manifest": None if verifying is None else _manifest_body(verifying),
            "active_manifest": None if active is None else _manifest_body(active),
            "recovered_manifest": None,
            "control_lock_identity": list(self._control_lock.inode_identity),
            "previous_transition_digest": previous_transition_digest,
        }
        return record, semantic_record_digest({
            "contract": "migration-ledger-transition-v1", "value": record,
        })

    def _persist_migration_state(
        self,
        control_token: _ControlLockToken,
        state: MigrationState,
        *,
        source: ActiveRepositoryManifest,
        request: Mapping[str, object],
        previous_state: MigrationState | None,
        previous_transition_digest: str | None,
        bundle: MigrationBundle | None,
        imported: ImportedRepository | None,
        verifying: ActiveRepositoryManifest | None,
        active: ActiveRepositoryManifest | None,
        source_factory: ConnectionFactory,
        mirror_factory: ConnectionFactory | None = None,
    ) -> str:
        self._control_lock.require_held(control_token, "exclusive")
        if previous_state is None:
            if state.state != "requested" or state.revision != 1 or previous_transition_digest is not None:
                raise MigrationRepositoryError("migration ledger start state is invalid")
        else:
            try:
                if previous_state.advance(state.state) != state:
                    raise MigrationRepositoryError("migration ledger transition is not consecutive")
            except MigrationControlError as error:
                raise MigrationRepositoryError("migration ledger transition is not consecutive") from error
        record, record_digest = self._migration_record(
            state, source=source, request=request,
            previous_transition_digest=previous_transition_digest,
            bundle=bundle, imported=imported, verifying=verifying, active=active,
        )
        def persist_to(factory: ConnectionFactory) -> None:
            with factory.open("migration") as connection, connection.transaction():
                if previous_state is None:
                    existing = connection.execute(
                        "SELECT 1 FROM migration_ledger WHERE migration_id=?",
                        (state.migration_id,),
                    ).fetchone()
                    if existing is not None:
                        raise MigrationRepositoryError("migration identity is already durable")
                    connection.execute(
                        "INSERT INTO migration_ledger(migration_id,state,record_json,record_digest) "
                        "VALUES(?,?,?,?)",
                        (state.migration_id, state.state, canonical_json(record), record_digest),
                    )
                else:
                    changed = connection.execute(
                        "UPDATE migration_ledger SET state=?,record_json=?,record_digest=? "
                        "WHERE migration_id=? AND state=? AND record_digest=?",
                        (
                            state.state, canonical_json(record), record_digest,
                            state.migration_id, previous_state.state, previous_transition_digest,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise MigrationRepositoryError("migration ledger head CAS failed")
                connection.execute(
                    "INSERT INTO migration_ledger_transitions(migration_id,revision,state,"
                    "previous_transition_digest,record_json,record_digest) VALUES(?,?,?,?,?,?)",
                    (
                        state.migration_id, state.revision, state.state,
                        previous_transition_digest, canonical_json(record), record_digest,
                    ),
                )
        persist_to(source_factory)
        if mirror_factory is not None:
            self._fault("migration.after_source_head")
            persist_to(mirror_factory)
            self._fault("migration.after_mirror_head")
        self._fault(f"migration.after_state.{state.state}")
        return record_digest

    def _synchronize_migration_ledger(
        self,
        migration_id: str,
        source_factory: ConnectionFactory,
        candidate_factory: ConnectionFactory,
    ) -> None:
        with source_factory.open("doctor") as connection:
            head = connection.execute(
                "SELECT state,record_json,record_digest FROM migration_ledger WHERE migration_id=?",
                (migration_id,),
            ).fetchone()
            transitions = connection.execute(
                "SELECT revision,state,previous_transition_digest,record_json,record_digest "
                "FROM migration_ledger_transitions WHERE migration_id=? ORDER BY revision",
                (migration_id,),
            ).fetchall()
        if head is None or not transitions:
            raise MigrationRepositoryError("source migration ledger cannot seed candidate")
        with candidate_factory.open("doctor") as connection:
            candidate_head = connection.execute(
                "SELECT state,record_json,record_digest FROM migration_ledger WHERE migration_id=?",
                (migration_id,),
            ).fetchone()
            candidate_transitions = connection.execute(
                "SELECT revision,state,previous_transition_digest,record_json,record_digest "
                "FROM migration_ledger_transitions WHERE migration_id=? ORDER BY revision",
                (migration_id,),
            ).fetchall()
        if (
            not candidate_transitions
            or len(candidate_transitions) > len(transitions)
            or transitions[:len(candidate_transitions)] != candidate_transitions
            or candidate_head != (
                candidate_transitions[-1][1], candidate_transitions[-1][3],
                candidate_transitions[-1][4],
            )
        ):
            raise MigrationRepositoryError("candidate migration ledger is not an exact source prefix")
        missing = transitions[len(candidate_transitions):]
        if not missing:
            if candidate_head != head:
                raise MigrationRepositoryError("candidate migration ledger head diverged")
            return
        with candidate_factory.open("migration") as connection, connection.transaction():
            expected_state, _expected_json, expected_digest = candidate_head
            for revision, state_name, prior, record_json, record_digest in missing:
                if prior != expected_digest:
                    raise MigrationRepositoryError("candidate migration prefix link is invalid")
                changed = connection.execute(
                    "UPDATE migration_ledger SET state=?,record_json=?,record_digest=? "
                    "WHERE migration_id=? AND state=? AND record_digest=?",
                    (
                        state_name, record_json, record_digest, migration_id,
                        expected_state, expected_digest,
                    ),
                ).rowcount
                if changed != 1:
                    raise MigrationRepositoryError("candidate migration prefix CAS failed")
                connection.execute(
                    "INSERT INTO migration_ledger_transitions(migration_id,revision,state,"
                    "previous_transition_digest,record_json,record_digest) VALUES(?,?,?,?,?,?)",
                    (migration_id, revision, state_name, prior, record_json, record_digest),
                )
                expected_state, expected_digest = state_name, record_digest

    def migration_history(self, migration_id: str) -> tuple[dict[str, object], ...]:
        token = self._control_lock.acquire("shared")
        try:
            _current, factory = self._current_factory(token, require_active=False)
            return self._migration_history(migration_id, factory)
        finally:
            self._control_lock.release(token)

    def _migration_history(
        self,
        migration_id: str,
        factory: ConnectionFactory,
    ) -> tuple[dict[str, object], ...]:
        if type(migration_id) is not str or not migration_id:
            raise MigrationRepositoryError("migration history identity is invalid")
        with factory.open("doctor") as connection:
            rows = connection.execute(
                "SELECT revision,state,previous_transition_digest,record_json,record_digest "
                "FROM migration_ledger_transitions WHERE migration_id=? ORDER BY revision",
                (migration_id,),
            ).fetchall()
            head = connection.execute(
                "SELECT state,record_json,record_digest FROM migration_ledger WHERE migration_id=?",
                (migration_id,),
            ).fetchone()
        if not rows or head is None:
            raise MigrationRepositoryError("migration history is absent")
        expected_state: MigrationState | None = None
        previous_digest: str | None = None
        source_manifest: ActiveRepositoryManifest | None = None
        bundle_tuple: dict[str, object] | None = None
        candidate_tuple: dict[str, object] | None = None
        verifying_manifest: ActiveRepositoryManifest | None = None
        active_manifest: ActiveRepositoryManifest | None = None
        control_identity: list[object] | None = None
        request_tuple: dict[str, object] | None = None
        history: list[dict[str, object]] = []
        record_keys = {
            "schema_version", "migration", "source_manifest", "bundle", "candidate",
            "verifying_manifest", "active_manifest", "recovered_manifest", "control_lock_identity",
            "previous_transition_digest", "request",
        }
        for revision, state_name, prior, record_json, record_digest in rows:
            record = parse_canonical_json(record_json)
            migration = record.get("migration") if isinstance(record, dict) else None
            if (
                not isinstance(record, dict) or set(record) != record_keys
                or record.get("schema_version") != "1.0"
                or not isinstance(migration, dict)
                or set(migration) != {"migration_id", "source_manifest_digest", "state", "revision"}
                or migration.get("migration_id") != migration_id
                or migration.get("state") != state_name or migration.get("revision") != revision
                or prior != previous_digest or record.get("previous_transition_digest") != prior
                or semantic_record_digest({
                    "contract": "migration-ledger-transition-v1", "value": record,
                }) != record_digest
            ):
                raise MigrationRepositoryError("migration transition history is invalid")
            current = MigrationState(
                migration_id, migration["source_manifest_digest"], state_name, revision,
            )
            if expected_state is None:
                if current.state != "requested" or current.revision != 1:
                    raise MigrationRepositoryError("migration history has no exact start")
            else:
                try:
                    expected_next = (
                        expected_state.recover(current.state)
                        if current.state in {
                            "recovered_old_active", "recovered_rolled_back",
                            "recovered_new_active", "blocked",
                        }
                        else expected_state.advance(current.state)
                    )
                    if expected_next != current:
                        raise MigrationRepositoryError("migration history transition is not consecutive")
                except MigrationControlError as error:
                    raise MigrationRepositoryError("migration history transition is not consecutive") from error
            try:
                observed_source = _load_manifest(record["source_manifest"])
            except MigrationRepositoryError as error:
                raise MigrationRepositoryError("migration source tuple is invalid") from error
            observed_control = record.get("control_lock_identity")
            observed_request = record.get("request")
            request_keys = {
                "migration_id", "export_id", "bundle_destination", "candidate_destination",
                "candidate_repository_id", "release_id", "contract_id",
            }
            if (
                current.source_manifest_digest != observed_source.manifest_digest
                or observed_source.mode != "active"
                or not isinstance(observed_control, list) or len(observed_control) != 2
                or any(type(item) is not int or item < 1 for item in observed_control)
                or not isinstance(observed_request, dict) or set(observed_request) != request_keys
                or observed_request.get("migration_id") != migration_id
                or any(
                    type(observed_request.get(name)) is not str
                    or not observed_request.get(name)
                    for name in request_keys
                )
            ):
                raise MigrationRepositoryError("migration source/control tuple is invalid")
            if source_manifest is None:
                source_manifest = observed_source
                control_identity = observed_control
                request_tuple = observed_request
            elif (
                observed_source != source_manifest or observed_control != control_identity
                or observed_request != request_tuple
            ):
                raise MigrationRepositoryError("migration source/control authority changed")
            recovery_state = current.state in {
                "recovered_old_active", "recovered_rolled_back", "recovered_new_active", "blocked",
            }
            if recovery_state:
                try:
                    recovered_manifest = _load_manifest(record.get("recovered_manifest"))
                except MigrationRepositoryError as error:
                    raise MigrationRepositoryError("migration recovery manifest is invalid") from error
                expected_mode = "blocked" if current.state == "blocked" else "active"
                if recovered_manifest.mode != expected_mode:
                    raise MigrationRepositoryError("migration recovery outcome is not exact")
                if current.state == "recovered_old_active" and recovered_manifest != source_manifest:
                    raise MigrationRepositoryError("migration old-active recovery tuple changed")
                if (
                    current.state == "recovered_new_active"
                    and recovered_manifest.repository_id != request_tuple["candidate_repository_id"]
                ):
                    raise MigrationRepositoryError("migration new-active recovery tuple changed")
                expected_state = current
                previous_digest = record_digest
                history.append(record)
                continue
            if record.get("recovered_manifest") is not None:
                raise MigrationRepositoryError("migration recovery tuple appeared on normal path")
            state_index = (
                "requested", "upgrade_locked", "quiescence_verified", "exported",
                "imported_isolated", "replayed", "compatible", "activation_prepared",
                "verifying_reference", "post_switch_verified", "active", "completed",
            ).index(current.state)
            observed_bundle = record.get("bundle")
            if state_index < 3:
                if observed_bundle is not None:
                    raise MigrationRepositoryError("migration bundle appeared before export")
            else:
                bundle_keys = {
                    "bundle_digest", "snapshot_digest", "source_manifest_digest",
                    "source_repository_digest", "source_fencing_high_water",
                }
                if (
                    not isinstance(observed_bundle, dict) or set(observed_bundle) != bundle_keys
                    or observed_bundle.get("source_manifest_digest") != source_manifest.manifest_digest
                ):
                    raise MigrationRepositoryError("migration bundle tuple is invalid")
                for name in (
                    "bundle_digest", "snapshot_digest", "source_manifest_digest",
                    "source_repository_digest",
                ):
                    require_jcs_digest(observed_bundle.get(name))
                if bundle_tuple is None:
                    bundle_tuple = observed_bundle
                elif observed_bundle != bundle_tuple:
                    raise MigrationRepositoryError("migration bundle tuple changed")
            observed_candidate = record.get("candidate")
            if state_index < 4:
                if observed_candidate is not None:
                    raise MigrationRepositoryError("migration candidate appeared before import")
            else:
                candidate_keys = {
                    "repository_id", "repository_digest", "candidate_records_digest",
                    "bundle_digest", "source_manifest_digest", "source_repository_digest",
                    "repository_locator_ref", "repository_locator_digest", "release_id",
                    "contract_id", "activated_repository_digest",
                }
                if (
                    not isinstance(observed_candidate, dict)
                    or set(observed_candidate) != candidate_keys
                    or observed_candidate.get("bundle_digest") != bundle_tuple["bundle_digest"]
                    or observed_candidate.get("source_manifest_digest") != source_manifest.manifest_digest
                    or observed_candidate.get("source_repository_digest")
                    != bundle_tuple["source_repository_digest"]
                ):
                    raise MigrationRepositoryError("migration candidate tuple is invalid")
                for name in ("repository_digest", "candidate_records_digest"):
                    require_jcs_digest(observed_candidate.get(name))
                if candidate_tuple is None:
                    candidate_tuple = observed_candidate
                elif state_index < 7 and observed_candidate != candidate_tuple:
                    raise MigrationRepositoryError("migration isolated candidate tuple changed")
                elif state_index >= 7:
                    for name, value in candidate_tuple.items():
                        if name not in {
                            "repository_locator_ref", "repository_locator_digest", "release_id",
                            "contract_id", "activated_repository_digest",
                        } and observed_candidate.get(name) != value:
                            raise MigrationRepositoryError("migration candidate identity changed")
            observed_verifying = record.get("verifying_manifest")
            if state_index < 7:
                if observed_verifying is not None:
                    raise MigrationRepositoryError("verifying manifest appeared before preparation")
            else:
                try:
                    loaded_verifying = _load_manifest(observed_verifying)
                    loaded_verifying.require_successor_of(source_manifest)
                except (MigrationRepositoryError, MigrationControlError) as error:
                    raise MigrationRepositoryError("migration verifying tuple is invalid") from error
                if (
                    loaded_verifying.mode != "verifying"
                    or observed_candidate.get("repository_id") != loaded_verifying.repository_id
                    or observed_candidate.get("repository_locator_ref")
                    != loaded_verifying.repository_locator_ref
                    or observed_candidate.get("repository_locator_digest")
                    != loaded_verifying.repository_locator_digest
                    or observed_candidate.get("activated_repository_digest")
                    != loaded_verifying.repository_digest
                    or observed_candidate.get("release_id") != loaded_verifying.release_id
                    or observed_candidate.get("contract_id") != loaded_verifying.contract_id
                ):
                    raise MigrationRepositoryError("migration verifying candidate binding is invalid")
                if verifying_manifest is None:
                    verifying_manifest = loaded_verifying
                elif loaded_verifying != verifying_manifest:
                    raise MigrationRepositoryError("migration verifying manifest changed")
            observed_active = record.get("active_manifest")
            if state_index < 10:
                if observed_active is not None:
                    raise MigrationRepositoryError("active manifest appeared before activation")
            else:
                try:
                    loaded_active = _load_manifest(observed_active)
                    loaded_active.require_successor_of(verifying_manifest)
                except (MigrationRepositoryError, MigrationControlError) as error:
                    raise MigrationRepositoryError("migration active tuple is invalid") from error
                if loaded_active.mode != "active":
                    raise MigrationRepositoryError("migration active tuple is not executable")
                if active_manifest is None:
                    active_manifest = loaded_active
                elif loaded_active != active_manifest:
                    raise MigrationRepositoryError("migration active manifest changed")
            expected_state = current
            previous_digest = record_digest
            history.append(record)
        if head != (expected_state.state, canonical_json(history[-1]), previous_digest):
            raise MigrationRepositoryError("migration ledger head does not bind the exact history")
        return tuple(history)

    def export_bundle(self, destination: pathlib.Path, *, export_id: str) -> MigrationBundle:
        try:
            token = self._control_lock.acquire("exclusive")
        except MigrationRepositoryError as error:
            raise MigrationRepositoryError(
                "installation export control lock is unavailable (busy or reentrant)",
            ) from error
        try:
            return self.export_bundle_under_installation_exclusive(token, destination, export_id=export_id)
        finally:
            self._control_lock.release(token)

    def export_bundle_under_installation_exclusive(
        self,
        token: _ControlLockToken,
        destination: pathlib.Path,
        *,
        export_id: str,
    ) -> MigrationBundle:
        try:
            self._control_lock.require_held(token, "exclusive")
        except MigrationRepositoryError as error:
            raise MigrationRepositoryError(
                "export requires the current exact control-exclusive token",
            ) from error
        if type(export_id) is not str or not export_id or not destination.is_absolute() or destination.exists():
            raise MigrationRepositoryError("export identity or destination is invalid")
        source_manifest, source_factory = self._current_factory(token)
        destination.mkdir(mode=self._policy.root_mode)
        objects_root = destination / self._policy.bundle_objects_directory
        objects_root.mkdir(mode=self._policy.root_mode)
        backup_file = destination / source_factory.policy.database_filename
        self._fault("export.before_backup")
        with source_factory.open("backup") as connection:
            connection.online_backup(backup_file)
        self._fault("export.after_backup")
        records = self._read_backup_records(backup_file)
        records_body = canonical_bytes(records)
        records_digest = "sha256-raw-v1:" + hashlib.sha256(records_body).hexdigest()
        source_repository_digest = _repository_digest_from_records(
            records, source_factory.repository_id,
        )
        referenced = {
            row[0] for row in _project_rows(records, "object_references", ("digest",))
        } | {
            row[0] for row in _project_rows(records, "claim_objects", ("digest",))
        }
        object_states = dict(_project_rows(records, "objects", ("digest", "state")))
        if any(object_states.get(value) != "available" for value in referenced):
            raise MigrationRepositoryError("referenced export object is unavailable")
        object_digests = tuple(sorted(referenced))
        if len(object_digests) > self._policy.max_bundle_objects:
            raise MigrationRepositoryError("referenced export object count exceeds policy")
        snapshot = _export_snapshot_identity(
            records,
            export_id=export_id,
            source_repository_id=source_factory.repository_id,
            activation_epoch=source_manifest.activation_epoch,
            object_digests=object_digests,
        )
        with source_factory.open("migration") as connection:
            with connection.transaction():
                connection.executemany(
                    "INSERT INTO export_holds(export_id,digest,snapshot_digest) VALUES(?,?,?)",
                    tuple((export_id, value, snapshot.snapshot_digest) for value in object_digests),
                )
        self._fault("export.after_hold")
        records_file = destination / self._policy.bundle_records_filename
        _write_atomic(destination, records_file.name, records_body, self._policy.file_mode)
        self._fault("export.before_objects")
        for value in object_digests:
            body = self._read_repository_object(source_factory, value)
            _write_atomic(
                objects_root,
                value.removeprefix("sha256:"),
                body,
                self._policy.file_mode,
            )
        self._fault("export.after_objects")
        source_fences = _project_rows(
            records, "resource_fences", ("resource_id", "fencing_token"),
        )
        manifest_unsigned = {
            "schema_version": "1.0",
            "source_manifest_digest": source_manifest.manifest_digest,
            "source_repository_digest": source_repository_digest,
            "source_fencing_high_water": [list(item) for item in source_fences],
            "snapshot_identity": _snapshot_identity_body(snapshot),
            "records_digest": records_digest,
        }
        bundle_digest = semantic_record_digest(manifest_unsigned)
        manifest = dict(manifest_unsigned, bundle_digest=bundle_digest)
        self._fault("export.before_bundle_manifest")
        _write_atomic(
            destination,
            self._policy.bundle_manifest_filename,
            canonical_bytes(manifest),
            self._policy.file_mode,
        )
        self._fault("export.after_bundle_manifest")
        bundle = self.validate_bundle(destination)
        self._fault("export.before_hold_clear")
        with source_factory.open("migration") as connection:
            with connection.transaction():
                connection.execute("DELETE FROM export_holds WHERE export_id=?", (export_id,))
        return bundle

    def recover_export(self, export_id: str, root: pathlib.Path) -> None:
        if type(export_id) is not str or not export_id:
            raise MigrationRepositoryError("export recovery identity is invalid")
        token = self._control_lock.acquire("exclusive")
        try:
            _current, active_factory = self._current_factory(token)
            with active_factory.open("doctor") as connection:
                held = connection.execute(
                    "SELECT COUNT(*) FROM export_holds WHERE export_id=?", (export_id,),
                ).fetchone()[0]
            if not held:
                return
            manifest_file = root / self._policy.bundle_manifest_filename
            if manifest_file.exists():
                bundle = self.validate_bundle(root)
                if bundle.export_id != export_id:
                    raise MigrationRepositoryError("published bundle export identity conflicts with hold")
            with active_factory.open("migration") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM export_holds WHERE export_id=?", (export_id,))
        finally:
            self._control_lock.release(token)

    def _read_backup_records(self, backup_file: pathlib.Path) -> dict[str, object]:
        connection = sqlite3.connect(f"file:{backup_file.as_posix()}?mode=ro", uri=True)
        try:
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise MigrationRepositoryError("backup database integrity failed")
            records: dict[str, object] = {}
            for namespace in _NAMESPACE_SEQUENCE:
                cursor = connection.execute(f'SELECT * FROM "{namespace}"')
                columns = [item[0] for item in cursor.description]
                records[namespace] = {"columns": columns, "rows": [list(row) for row in cursor.fetchall()]}
            return records
        finally:
            connection.close()

    def validate_bundle(self, root: pathlib.Path) -> MigrationBundle:
        if not root.is_absolute():
            raise MigrationRepositoryError("bundle root must be absolute")
        _require_bounded_directory(root, self._policy.root_mode)
        expected_top = {
            self._policy.bundle_manifest_filename,
            self._policy.bundle_records_filename,
            self._policy.bundle_objects_directory,
            self._factory.policy.database_filename,
        }
        try:
            if {item.name for item in root.iterdir()} != expected_top:
                raise MigrationRepositoryError("bundle root members are not exact")
            manifest_value = parse_canonical_json(
                _read_bounded_regular(
                    root, self._policy.bundle_manifest_filename,
                    self._policy.file_mode, self._policy.root_mode,
                    self._policy.max_bundle_member_bytes,
                ).decode(),
            )
            records_body = _read_bounded_regular(
                root, self._policy.bundle_records_filename,
                self._policy.file_mode, self._policy.root_mode,
                self._policy.max_bundle_member_bytes,
            )
            backup_body = _read_bounded_regular(
                root, self._factory.policy.database_filename,
                self._policy.file_mode, self._policy.root_mode,
                self._policy.max_bundle_member_bytes,
            )
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise MigrationRepositoryError("bundle files are missing or non-canonical") from error
        total_bytes = len(canonical_bytes(manifest_value)) + len(records_body) + len(backup_body)
        if total_bytes > self._policy.max_bundle_total_bytes:
            raise MigrationRepositoryError("bundle aggregate bytes exceed policy")
        _require_json_bounds(
            manifest_value,
            maximum_nodes=self._policy.max_json_nodes,
            maximum_depth=self._policy.max_json_depth,
        )
        fields = {
            "schema_version", "source_manifest_digest", "source_repository_digest",
            "source_fencing_high_water", "snapshot_identity", "records_digest",
            "bundle_digest",
        }
        if (
            not isinstance(manifest_value, dict)
            or set(manifest_value) != fields
            or manifest_value.get("schema_version") != "1.0"
        ):
            raise MigrationRepositoryError("bundle manifest is not exact")
        unsigned = {key: value for key, value in manifest_value.items() if key != "bundle_digest"}
        if semantic_record_digest(unsigned) != manifest_value["bundle_digest"]:
            raise MigrationRepositoryError("bundle manifest digest mismatch")
        if "sha256-raw-v1:" + hashlib.sha256(records_body).hexdigest() != manifest_value["records_digest"]:
            raise MigrationRepositoryError("bundle records digest mismatch")
        records = json.loads(records_body)
        _require_json_bounds(
            records,
            maximum_nodes=self._policy.max_json_nodes,
            maximum_depth=self._policy.max_json_depth,
        )
        if canonical_bytes(records) != records_body or set(records) != set(_NAMESPACE_SEQUENCE):
            raise MigrationRepositoryError("bundle logical namespaces are invalid")
        identity = _load_snapshot_identity(manifest_value["snapshot_identity"])
        if _repository_digest_from_records(
            records, identity.source_repository_id,
        ) != manifest_value["source_repository_digest"]:
            raise MigrationRepositoryError("bundle source repository digest mismatch")
        fences = _project_rows(
            records, "resource_fences", ("resource_id", "fencing_token"),
        )
        raw_fences = manifest_value["source_fencing_high_water"]
        if (
            type(raw_fences) is not list
            or any(type(item) is not list or len(item) != 2 for item in raw_fences)
            or tuple(tuple(item) for item in raw_fences) != fences
        ):
            raise MigrationRepositoryError("bundle fencing high-water is not exact")
        rebuilt = _export_snapshot_identity(
            records,
            export_id=identity.export_id,
            source_repository_id=identity.source_repository_id,
            activation_epoch=identity.activation_epoch,
            object_digests=identity.object_digests,
        )
        if rebuilt != identity:
            raise MigrationRepositoryError("bundle snapshot identity recomputation failed")
        values = list(identity.object_digests)
        if len(values) > self._policy.max_bundle_objects:
            raise MigrationRepositoryError("bundle object count exceeds policy")
        objects_root = root / self._policy.bundle_objects_directory
        _require_bounded_directory(objects_root, self._policy.root_mode)
        if {item.name for item in objects_root.iterdir()} != {
            value.removeprefix("sha256:") for value in values
        }:
            raise MigrationRepositoryError("bundle object members are not exact")
        for value in values:
            body = _read_bounded_regular(
                objects_root, value.removeprefix("sha256:"),
                self._policy.file_mode, self._policy.root_mode,
                self._policy.max_bundle_member_bytes,
            )
            if object_digest(body) != value:
                raise MigrationRepositoryError("bundle object is missing or corrupt")
            total_bytes += len(body)
            if total_bytes > self._policy.max_bundle_total_bytes:
                raise MigrationRepositoryError("bundle aggregate bytes exceed policy")
        if (
            {item.name for item in root.iterdir()} != expected_top
            or {item.name for item in objects_root.iterdir()}
            != {value.removeprefix("sha256:") for value in values}
        ):
            raise MigrationRepositoryError("bundle entries changed during bounded validation")
        with tempfile.TemporaryDirectory(prefix="gew-verified-bundle-db-") as directory:
            backup = pathlib.Path(directory) / self._factory.policy.database_filename
            backup.write_bytes(backup_body)
            backup.chmod(self._policy.file_mode)
            if self._read_backup_records(backup) != records:
                raise MigrationRepositoryError("bundle backup and logical records differ")
        return MigrationBundle(
            root.resolve(strict=True),
            identity.export_id,
            identity.source_repository_id,
            manifest_value["source_manifest_digest"],
            manifest_value["source_repository_digest"],
            identity.snapshot_digest,
            manifest_value["records_digest"],
            tuple(values),
            fences,
            identity,
            manifest_value["bundle_digest"],
            self._policy,
        )

    def import_bundle(
        self,
        root: pathlib.Path,
        destination: pathlib.Path,
        *,
        repository_id: str,
    ) -> ImportedRepository:
        bundle = self.validate_bundle(root)
        if destination.exists() or not destination.is_absolute():
            raise MigrationRepositoryError("isolated import destination is invalid")
        target_factory = ConnectionFactory.initialize(
            destination, self._factory.policy, repository_id,
        )._for_maintenance()
        target_locks = LockedFileRegistry(target_factory)
        target_objects = ObjectRepository(target_factory, target_locks)
        target_repository = TaskRepository._for_maintenance(
            target_factory, target_locks, target_objects,
        )
        try:
            self._fault("import.before_objects")
            for value in bundle.object_digests:
                target_objects.put_verified(bundle.object_body(value), value)
            self._fault("import.after_objects")
            records = json.loads(_read_bounded_regular(
                bundle.root,
                self._policy.bundle_records_filename,
                self._policy.file_mode,
                self._policy.root_mode,
                self._policy.max_bundle_member_bytes,
            ))
            self._fault("import.before_records")
            with target_factory.open("migration") as connection:
                with connection.transaction():
                    for namespace in _NAMESPACE_SEQUENCE:
                        if namespace in {"schema_versions", "objects", "export_holds"}:
                            continue
                        record = records[namespace]
                        columns = record["columns"]
                        rows = record["rows"]
                        if namespace == "repository_meta":
                            rows = [row for row in rows if row[0] != "repository_id"]
                        if not rows:
                            continue
                        names = ",".join(f'"{name}"' for name in columns)
                        placeholders = ",".join("?" for _ in columns)
                        conflict = (
                            " ON CONFLICT(key) DO UPDATE SET value=excluded.value"
                            if namespace == "repository_meta" else ""
                        )
                        connection.executemany(
                            f'INSERT INTO "{namespace}"({names}) VALUES({placeholders}){conflict}',
                            rows,
                        )
            self._fault("import.after_records")
            for task in target_repository.query_catalog({}):
                target_repository.replay(task["task_id"])
            self._fault("import.after_replay")
            candidate_records = _read_live_records(target_factory)
            expected_projection = _candidate_projection(
                records,
                repository_id=repository_id,
                object_digests=bundle.object_digests,
            )
            actual_projection = _candidate_projection(
                candidate_records,
                repository_id=repository_id,
                object_digests=bundle.object_digests,
            )
            if actual_projection != expected_projection:
                raise MigrationRepositoryError("candidate import does not exactly match bundle")
            self._fault("import.after_candidate_verify")
            candidate_records_digest = semantic_record_digest(actual_projection)
            repository_digest = _repository_digest_from_records(candidate_records, repository_id)
            return ImportedRepository(
                destination,
                target_factory,
                target_locks,
                target_objects,
                target_repository,
                bundle.bundle_digest,
                repository_digest,
                bundle.source_manifest_digest,
                bundle.source_repository_digest,
                bundle.root,
                candidate_records_digest,
            )
        except BaseException:
            target_objects.close()
            target_locks.close()
            raise

    def migrate(
        self,
        *,
        migration_id: str,
        export_id: str,
        bundle_destination: pathlib.Path,
        candidate_destination: pathlib.Path,
        candidate_repository_id: str,
        release_id: str,
        contract_id: str,
    ) -> CompletedMigration:
        """Run the approved migration graph under one stable installation authority."""

        if any(type(value) is not str or not value or value != value.strip() for value in (
            migration_id, export_id, candidate_repository_id, release_id, contract_id,
        )):
            raise MigrationRepositoryError("migration orchestration identity is invalid")
        control_token = self._control_lock.acquire("exclusive")
        imported: ImportedRepository | None = None
        try:
            source, source_factory = self._current_factory(control_token)
            state = MigrationState.start(migration_id, source)
            request = {
                "migration_id": migration_id, "export_id": export_id,
                "bundle_destination": bundle_destination.as_posix(),
                "candidate_destination": candidate_destination.as_posix(),
                "candidate_repository_id": candidate_repository_id,
                "release_id": release_id, "contract_id": contract_id,
            }
            previous_state: MigrationState | None = None
            transition_digest: str | None = None
            bundle: MigrationBundle | None = None
            verifying: ActiveRepositoryManifest | None = None
            active: ActiveRepositoryManifest | None = None

            def persist(target: str | None = None) -> None:
                nonlocal state, previous_state, transition_digest
                if target is not None:
                    previous_state = state
                    state = state.advance(target)
                transition_digest = self._persist_migration_state(
                    control_token, state, source=source, previous_state=previous_state,
                    request=request,
                    previous_transition_digest=(
                        None if previous_state is None else transition_digest
                    ),
                    bundle=bundle, imported=imported, verifying=verifying, active=active,
                    source_factory=source_factory,
                    mirror_factory=None if imported is None else imported.factory,
                )

            persist()
            persist("upgrade_locked")
            with source_factory.open("doctor") as connection:
                live = connection.execute(
                    "SELECT COUNT(*) FROM leases WHERE state='live'",
                ).fetchone()[0]
                claims = connection.execute(
                    "SELECT COUNT(*) FROM claims WHERE state='unresolved'",
                ).fetchone()[0]
                executing = connection.execute(
                    "SELECT COUNT(*) FROM action_journal WHERE state IN ('executing','unknown')",
                ).fetchone()[0]
            if live or claims or executing:
                raise MigrationRepositoryError("migration quiescence is not proven")
            persist("quiescence_verified")
            bundle = self.export_bundle_under_installation_exclusive(
                control_token, bundle_destination, export_id=export_id,
            )
            persist("exported")
            imported = self.import_bundle(
                bundle.root, candidate_destination, repository_id=candidate_repository_id,
            )
            self._synchronize_migration_ledger(
                migration_id, source_factory, imported.factory,
            )
            persist("imported_isolated")
            for task in imported.repository.query_catalog({}):
                imported.repository.replay(task["task_id"])
            persist("replayed")
            if contract_id != self._policy.repository_contract_id:
                raise MigrationRepositoryError("migration candidate contract is incompatible")
            self.validate_bundle(bundle.root)
            persist("compatible")

            def activation_transition(
                target: str,
                observed_bundle: MigrationBundle,
                observed_imported: ImportedRepository,
                observed_verifying: ActiveRepositoryManifest | None,
                observed_active: ActiveRepositoryManifest | None,
            ) -> None:
                nonlocal bundle, imported, verifying, active
                if (
                    observed_bundle.bundle_digest != bundle.bundle_digest
                    or observed_imported is not imported
                ):
                    raise MigrationRepositoryError("migration activation tuple was substituted")
                verifying = observed_verifying
                active = observed_active
                persist(target)

            active = self._activate_under_control_exclusive(
                control_token, imported, release_id=release_id, contract_id=contract_id,
                transition=activation_transition,
            )
            persist("completed")
            history = self._migration_history(migration_id, imported.factory)
            return CompletedMigration(migration_id, active, imported, history)
        except BaseException:
            if imported is not None:
                imported.close()
            raise
        finally:
            self._control_lock.release(control_token)

    def recover_migration(self, migration_id: str) -> ActiveRepositoryManifest:
        """Recover one incomplete durable migration under the same stable authority."""

        control_token = self._control_lock.acquire("exclusive")
        try:
            _current, ledger_factory = self._current_factory(
                control_token, require_active=False,
            )
            history = self._migration_history(migration_id, ledger_factory)
            last = history[-1]
            migration = last["migration"]
            state = MigrationState(
                migration_id, migration["source_manifest_digest"],
                migration["state"], migration["revision"],
            )
            request = last["request"]
            source_manifest = _load_manifest(history[0]["source_manifest"])
            source_factory = self._factory_for_manifest(source_manifest)
            candidate_factory: ConnectionFactory | None = None
            normal_states = (
                "requested", "upgrade_locked", "quiescence_verified", "exported",
                "imported_isolated", "replayed", "compatible", "activation_prepared",
                "verifying_reference", "post_switch_verified", "active", "completed",
            )
            if state.state in normal_states and normal_states.index(state.state) >= 4:
                candidate_root = pathlib.Path(request["candidate_destination"])
                database = candidate_root / source_factory.policy.database_filename
                if candidate_root.is_absolute() and database.exists():
                    candidate_factory = ConnectionFactory._attach_existing_for_maintenance(
                        candidate_root, source_factory.policy,
                        request["candidate_repository_id"],
                    )
                    if candidate_factory.data_root != source_factory.data_root:
                        self._synchronize_migration_ledger(
                            migration_id, source_factory, candidate_factory,
                        )
                    else:
                        candidate_factory = None
            if state.state == "completed":
                current = self._current_manifest()
                active_body = last.get("active_manifest")
                if current.mode != "active" or _load_manifest(active_body) != current:
                    raise MigrationRepositoryError("completed migration active tuple changed")
                return current
            if state.state in {
                "recovered_old_active", "recovered_rolled_back", "recovered_new_active", "blocked",
            }:
                current = self._current_manifest()
                if _load_manifest(last.get("recovered_manifest")) != current:
                    raise MigrationRepositoryError("recovered migration manifest changed")
                return current
            export_id = request["export_id"]
            bundle_root = pathlib.Path(request["bundle_destination"])
            if not bundle_root.is_absolute():
                raise MigrationRepositoryError("migration recovery bundle locator is invalid")
            self._fault("recovery.before_export_hold_recovery")
            with source_factory.open("doctor") as connection:
                held = connection.execute(
                    "SELECT COUNT(*) FROM export_holds WHERE export_id=?", (export_id,),
                ).fetchone()[0]
            if held:
                manifest_file = bundle_root / self._policy.bundle_manifest_filename
                if manifest_file.exists():
                    recovered_bundle = self.validate_bundle(bundle_root)
                    if recovered_bundle.export_id != export_id:
                        raise MigrationRepositoryError("migration recovery export hold is substituted")
                with source_factory.open("migration") as connection, connection.transaction():
                    connection.execute("DELETE FROM export_holds WHERE export_id=?", (export_id,))
            self._fault("recovery.after_export_hold_recovery")
            recovered = self._recover_activation_under_control_exclusive(control_token)
            source = source_manifest
            if recovered.mode == "blocked":
                outcome = "blocked"
            elif recovered.manifest_digest == source.manifest_digest:
                outcome = "recovered_old_active"
            elif recovered.repository_id == request["candidate_repository_id"]:
                outcome = "recovered_new_active"
            elif recovered.repository_id == source.repository_id:
                outcome = "recovered_rolled_back"
            else:
                raise MigrationRepositoryError("migration recovery selected an unrelated repository")
            terminal = state.recover(outcome)
            previous_digest = semantic_record_digest({
                "contract": "migration-ledger-transition-v1", "value": last,
            })
            terminal_record = dict(last)
            terminal_record["migration"] = dataclasses.asdict(terminal)
            terminal_record["previous_transition_digest"] = previous_digest
            terminal_record["recovered_manifest"] = _manifest_body(recovered)
            terminal_digest = semantic_record_digest({
                "contract": "migration-ledger-transition-v1", "value": terminal_record,
            })
            def persist_terminal(factory: ConnectionFactory) -> None:
                with factory.open("migration") as connection, connection.transaction():
                    changed = connection.execute(
                        "UPDATE migration_ledger SET state=?,record_json=?,record_digest=? "
                        "WHERE migration_id=? AND state=? AND record_digest=?",
                        (
                            terminal.state, canonical_json(terminal_record), terminal_digest,
                            migration_id, state.state, previous_digest,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise MigrationRepositoryError("migration recovery head CAS failed")
                    connection.execute(
                        "INSERT INTO migration_ledger_transitions(migration_id,revision,state,"
                        "previous_transition_digest,record_json,record_digest) VALUES(?,?,?,?,?,?)",
                        (
                            migration_id, terminal.revision, terminal.state, previous_digest,
                            canonical_json(terminal_record), terminal_digest,
                        ),
                    )
            persist_terminal(source_factory)
            if candidate_factory is not None:
                self._fault("migration.after_source_head")
                persist_terminal(candidate_factory)
                self._fault("migration.after_mirror_head")
            self._fault(f"migration.after_state.{terminal.state}")
            terminal_factory = candidate_factory or source_factory
            self._migration_history(migration_id, terminal_factory)
            return recovered
        finally:
            self._control_lock.release(control_token)

    def activate(
        self,
        imported: ImportedRepository,
        *,
        release_id: str,
        contract_id: str,
    ) -> ActiveRepositoryManifest:
        control_token = self._control_lock.acquire("exclusive")
        try:
            return self._activate_under_control_exclusive(
                control_token, imported, release_id=release_id, contract_id=contract_id,
            )
        finally:
            self._control_lock.release(control_token)

    def _activate_under_control_exclusive(
        self,
        control_token: _ControlLockToken,
        imported: ImportedRepository,
        *,
        release_id: str,
        contract_id: str,
        transition: Callable[[
            str, MigrationBundle, ImportedRepository,
            ActiveRepositoryManifest | None, ActiveRepositoryManifest | None,
        ], None] | None = None,
    ) -> ActiveRepositoryManifest:
        self._control_lock.require_held(control_token, "exclusive")
        if (
            type(release_id) is not str
            or not release_id
            or release_id != release_id.strip()
            or contract_id != self._policy.repository_contract_id
        ):
            raise MigrationRepositoryError("candidate release or repository contract is incompatible")
        try:
            current, source_factory = self._current_factory(control_token)
            with source_factory.open("doctor") as connection:
                live = connection.execute("SELECT COUNT(*) FROM leases WHERE state='live'").fetchone()[0]
                claims = connection.execute("SELECT COUNT(*) FROM claims WHERE state='unresolved'").fetchone()[0]
            if live or claims:
                raise MigrationRepositoryError("activation quiescence is not proven")
            if current.manifest_digest != imported.source_manifest_digest:
                raise MigrationRepositoryError("source manifest changed after export")
            if self._repository_digest(source_factory) != imported.source_repository_digest:
                raise MigrationRepositoryError("source repository changed after export")
            bundle = self.validate_bundle(imported.bundle_root)
            if (
                bundle.bundle_digest != imported.bundle_digest
                or bundle.source_manifest_digest != imported.source_manifest_digest
                or bundle.source_repository_digest != imported.source_repository_digest
                or imported.root.resolve(strict=True) != imported.factory.data_root
            ):
                raise MigrationRepositoryError("candidate bundle tuple changed before activation")
            candidate_records = _read_live_records(imported.factory)
            candidate_projection = _candidate_projection(
                candidate_records,
                repository_id=imported.factory.repository_id,
                object_digests=bundle.object_digests,
            )
            candidate_digest = semantic_record_digest(candidate_projection)
            candidate_repository_digest = _repository_digest_from_records(
                candidate_records, imported.factory.repository_id,
            )
            candidate_object_manifest_digest = _candidate_object_manifest_digest(
                imported.objects, candidate_records, bundle.object_digests,
            )
            if (
                candidate_digest != imported.candidate_records_digest
                or candidate_repository_digest != imported.repository_digest
                or candidate_object_manifest_digest
                != bundle.snapshot_identity.object_manifest_digest
            ):
                raise MigrationRepositoryError("candidate exact tuple recomputation failed")
            compatibility_digest = semantic_record_digest({
                "bundle_digest": bundle.bundle_digest,
                "candidate_repository_id": imported.factory.repository_id,
                "release_id": release_id,
                "contract_id": contract_id,
            })
            for task in imported.repository.query_catalog({}):
                imported.repository.replay(task["task_id"])
            candidate_locator = self._register_locator(imported.factory, control_token)
            fences = dict(current.fencing_high_water)
            for resource, counter in bundle.source_fencing_high_water:
                fences[resource] = max(fences.get(resource, 0), counter)
            for resource, counter in self._fences(source_factory):
                fences[resource] = max(fences.get(resource, 0), counter)
            with imported.factory.open("doctor") as connection:
                for resource, counter in connection.execute(
                    "SELECT resource_id,fencing_token FROM resource_fences ORDER BY resource_id"
                ).fetchall():
                    fences[resource] = max(fences.get(resource, 0), counter)
            self._fault("activation.before_candidate_fence_seed")
            with imported.factory.open("migration") as connection:
                with connection.transaction():
                    connection.executemany(
                        "INSERT INTO resource_fences(resource_id,fencing_token) VALUES(?,?) "
                        "ON CONFLICT(resource_id) DO UPDATE SET fencing_token="
                        "MAX(resource_fences.fencing_token,excluded.fencing_token)",
                        tuple(sorted(fences.items())),
                    )
            self._fault("activation.after_candidate_fence_seed")
            seeded_records = _read_live_records(imported.factory)
            seeded_candidate_digest = semantic_record_digest(_candidate_projection(
                seeded_records,
                repository_id=imported.factory.repository_id,
                object_digests=bundle.object_digests,
            ))
            seeded_repository_digest = _repository_digest_from_records(
                seeded_records, imported.factory.repository_id,
            )
            self._fault("activation.after_post_seed_tuple")
            verifying = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=current.generation + 1,
                activation_epoch=current.activation_epoch + 1,
                repository_id=imported.factory.repository_id,
                repository_digest=seeded_repository_digest,
                repository_locator_ref=candidate_locator.locator_ref,
                repository_locator_digest=candidate_locator.locator_digest,
                release_id=release_id,
                contract_id=contract_id,
                mode="verifying",
                previous_manifest_digest=current.manifest_digest,
                fencing_high_water=tuple(sorted(fences.items())),
                restore_gap_digest=None,
            )
            verifying.require_successor_of(current)
            if transition is not None:
                transition("activation_prepared", bundle, imported, verifying, None)
            self._fault("activation.before_verifying_manifest")
            self._publish_manifest(verifying)
            self._fault("activation.after_verifying_manifest")
            if transition is not None:
                transition("verifying_reference", bundle, imported, verifying, None)
            revalidated_bundle = self.validate_bundle(imported.bundle_root)
            if revalidated_bundle != bundle:
                raise MigrationRepositoryError(
                    "post-switch bundle and snapshot tuple changed",
                )
            bundle = revalidated_bundle
            if self._resolve_locator(verifying) != imported.root.resolve(strict=True):
                raise MigrationRepositoryError("post-switch candidate locator tuple changed")
            post_switch_records = _read_live_records(imported.factory)
            if (
                semantic_record_digest(_candidate_projection(
                    post_switch_records,
                    repository_id=imported.factory.repository_id,
                    object_digests=bundle.object_digests,
                )) != seeded_candidate_digest
                or _repository_digest_from_records(
                    post_switch_records, imported.factory.repository_id,
                ) != seeded_repository_digest
                or _candidate_object_manifest_digest(
                    imported.objects, post_switch_records, bundle.object_digests,
                ) != bundle.snapshot_identity.object_manifest_digest
                or verifying.release_id != release_id
                or verifying.contract_id != contract_id
                or semantic_record_digest({
                    "bundle_digest": bundle.bundle_digest,
                    "candidate_repository_id": verifying.repository_id,
                    "release_id": verifying.release_id,
                    "contract_id": verifying.contract_id,
                }) != compatibility_digest
            ):
                raise MigrationRepositoryError("post-switch candidate exact tuple recomputation failed")
            for task in imported.repository.query_catalog({}):
                imported.repository.replay(task["task_id"])
            if transition is not None:
                transition("post_switch_verified", bundle, imported, verifying, None)
            active = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=verifying.generation + 1,
                activation_epoch=verifying.activation_epoch + 1,
                repository_id=verifying.repository_id,
                repository_digest=verifying.repository_digest,
                repository_locator_ref=verifying.repository_locator_ref,
                repository_locator_digest=verifying.repository_locator_digest,
                release_id=release_id,
                contract_id=contract_id,
                mode="active",
                previous_manifest_digest=verifying.manifest_digest,
                fencing_high_water=verifying.fencing_high_water,
                restore_gap_digest=None,
            )
            active.require_successor_of(verifying)
            self._fault("activation.before_active_manifest")
            self._publish_manifest(active)
            self._fault("activation.after_active_manifest")
            if transition is not None:
                transition("active", bundle, imported, verifying, active)
            return active
        except RepositoryError as error:
            if isinstance(error, MigrationRepositoryError):
                raise
            raise MigrationRepositoryError("activation repository verification failed") from error

    def recover_activation(self) -> ActiveRepositoryManifest:
        control_token = self._control_lock.acquire("exclusive")
        try:
            return self._recover_activation_under_control_exclusive(control_token)
        finally:
            self._control_lock.release(control_token)

    def _recover_activation_under_control_exclusive(
        self,
        control_token: _ControlLockToken,
    ) -> ActiveRepositoryManifest:
        self._control_lock.require_held(control_token, "exclusive")
        try:
            current = self._current_manifest()
            try:
                current_factory = self._factory_for_manifest(current)
            except MigrationRepositoryError:
                if current.mode != "verifying":
                    return current if current.mode == "blocked" else self._publish_blocked(current)
                current_factory = None
            if current_factory is None:
                open_gap = None
                reconciled_gap = None
            else:
                try:
                    open_gap = self._load_open_restore_gap(current_factory)
                    reconciled_gap = self._load_reconciled_restore_gap(current_factory)
                except MigrationRepositoryError:
                    return current if current.mode == "blocked" else self._publish_blocked(current)
            if current.restore_gap_digest is not None:
                if open_gap is not None and (
                    current.mode != "blocked"
                    or open_gap.gap_digest != current.restore_gap_digest
                    or open_gap.source_manifest_digest != current.previous_manifest_digest
                    or open_gap.resources != current.fencing_high_water
                ):
                    return current
                if open_gap is None and reconciled_gap is not None:
                    original_gap, reconciled = reconciled_gap
                    if (
                        current.mode != "blocked"
                        or original_gap.gap_digest != current.restore_gap_digest
                        or original_gap.source_manifest_digest != current.previous_manifest_digest
                        or any(
                            counter <= dict(original_gap.resources).get(resource, 0)
                            for resource, counter in reconciled.resources
                        )
                    ):
                        return current
                    active = ActiveRepositoryManifest.create(
                        installation_id=current.installation_id,
                        generation=current.generation + 1,
                        activation_epoch=current.activation_epoch + 1,
                        repository_id=current.repository_id,
                        repository_digest=self._repository_digest(current_factory),
                        repository_locator_ref=current.repository_locator_ref,
                        repository_locator_digest=current.repository_locator_digest,
                        release_id=current.release_id,
                        contract_id=current.contract_id,
                        mode="active",
                        previous_manifest_digest=current.manifest_digest,
                        fencing_high_water=reconciled.resources,
                        restore_gap_digest=None,
                    )
                    active.require_successor_of(current)
                    self._fault("restore_gap.before_reactivation_manifest")
                    self._publish_manifest(active)
                    self._fault("restore_gap.after_reactivation_manifest")
                    return active
                if open_gap is None:
                    return current
            elif open_gap is not None:
                if (
                    current.mode != "active"
                    or open_gap.source_manifest_digest != current.manifest_digest
                ):
                    return current if current.mode == "blocked" else self._publish_blocked(current)
                blocked = ActiveRepositoryManifest.create(
                    installation_id=current.installation_id,
                    generation=current.generation + 1,
                    activation_epoch=current.activation_epoch + 1,
                    repository_id=current.repository_id,
                    repository_digest=current.repository_digest,
                    repository_locator_ref=current.repository_locator_ref,
                    repository_locator_digest=current.repository_locator_digest,
                    release_id=current.release_id,
                    contract_id=current.contract_id,
                    mode="blocked",
                    previous_manifest_digest=current.manifest_digest,
                    fencing_high_water=open_gap.resources,
                    restore_gap_digest=open_gap.gap_digest,
                )
                blocked.require_successor_of(current)
                self._publish_manifest(blocked)
                return blocked
            loaded: list[ActiveRepositoryManifest] = []
            damaged = False
            for item in sorted(self._history_root().glob("*.json")):
                try:
                    loaded.append(_load_manifest(parse_canonical_json(item.read_text())))
                except (OSError, ValueError, MigrationRepositoryError):
                    damaged = True
            manifests = tuple(loaded)
            if current.mode == "blocked":
                self._require_exact_current_chain(current, manifests)
                return current
            if damaged:
                return self._publish_blocked(current)
            try:
                selected = select_committed_manifest(manifests)
            except (MigrationControlError, ValueError):
                return self._publish_blocked(current)
            by_digest = {item.manifest_digest: item for item in manifests}
            if current.manifest_digest not in by_digest:
                return self._publish_blocked(current)
            latest = max(manifests, key=lambda item: item.generation)
            if latest.mode == "verifying":
                previous = by_digest.get(latest.previous_manifest_digest)
                if previous is None or previous.mode != "active":
                    raise MigrationRepositoryError("verifying manifest has no verified rollback target")
                recovered = ActiveRepositoryManifest.rollback_to(
                    current=latest,
                    previous=previous,
                    repository_digest=previous.repository_digest,
                )
                self._fault("recovery.before_rollback_manifest")
                self._publish_manifest(recovered)
                self._fault("recovery.after_rollback_manifest")
                return recovered
            if selected.manifest_digest != latest.manifest_digest:
                raise MigrationRepositoryError("highest committed manifest is not executable or blocked")
            if current.manifest_digest != selected.manifest_digest:
                self._publish_manifest(selected)
            return selected
        except RepositoryError as error:
            if isinstance(error, MigrationRepositoryError):
                raise
            raise MigrationRepositoryError("activation recovery repository is invalid") from error

    def _load_open_restore_gap(
        self,
        factory: ConnectionFactory,
    ) -> RestoreGap | None:
        with factory.open("doctor") as connection:
            rows = connection.execute(
                "SELECT migration_id,record_json,record_digest FROM migration_ledger "
                "WHERE state='restore_gap_open' ORDER BY migration_id",
            ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise MigrationRepositoryError("installation has multiple open restore gaps")
        migration_id, record_json, record_digest = rows[0]
        record = parse_canonical_json(record_json)
        if (
            not isinstance(record, dict)
            or semantic_record_digest(record) != record_digest
            or set(record) != {
                "schema_version", "gap", "bundle_digest", "bundle_snapshot_digest",
                "unresolved_claim_ids", "unresolved_action_ids", "fresh_observations",
            }
            or record.get("schema_version") != "1.0"
            or record.get("fresh_observations") != []
        ):
            raise MigrationRepositoryError("durable open restore-gap record is not exact")
        gap_body = record.get("gap")
        fields = {
            "gap_id", "source_manifest_digest", "restored_manifest_digest", "resources",
            "authority_digest", "state", "gap_digest",
        }
        if (
            not isinstance(gap_body, dict)
            or set(gap_body) != fields
            or gap_body.get("gap_id") != migration_id
            or gap_body.get("authority_digest") is not None
            or gap_body.get("state") != "open"
            or type(gap_body.get("resources")) is not list
        ):
            raise MigrationRepositoryError("durable restore-gap body is not exact")
        try:
            gap = RestoreGap.create(
                gap_id=gap_body["gap_id"],
                source_manifest_digest=gap_body["source_manifest_digest"],
                restored_manifest_digest=gap_body["restored_manifest_digest"],
                resources=tuple(tuple(item) for item in gap_body["resources"]),
            )
        except (TypeError, MigrationControlError) as error:
            raise MigrationRepositoryError("durable restore-gap body is invalid") from error
        if gap.gap_digest != gap_body["gap_digest"]:
            raise MigrationRepositoryError("durable restore-gap digest mismatch")
        return gap

    def _load_reconciled_restore_gap(
        self,
        factory: ConnectionFactory,
    ) -> tuple[RestoreGap, RestoreGap] | None:
        with factory.open("doctor") as connection:
            rows = connection.execute(
                "SELECT migration_id,record_json,record_digest FROM migration_ledger "
                "WHERE state='restore_gap_reconciled' ORDER BY migration_id",
            ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise MigrationRepositoryError("installation has multiple reconciled restore gaps")
        migration_id, record_json, record_digest = rows[0]
        record = parse_canonical_json(record_json)
        if (
            not isinstance(record, dict) or semantic_record_digest(record) != record_digest
            or set(record) != {
                "schema_version", "gap", "bundle_digest", "bundle_snapshot_digest",
                "unresolved_claim_ids", "unresolved_action_ids", "fresh_observations",
                "reconciled_gap",
            }
            or record.get("schema_version") != "1.0"
            or not isinstance(record.get("fresh_observations"), list)
        ):
            raise MigrationRepositoryError("durable reconciled restore-gap record is not exact")
        open_body = record.get("gap")
        reconciled_body = record.get("reconciled_gap")
        if not isinstance(open_body, dict) or not isinstance(reconciled_body, dict):
            raise MigrationRepositoryError("durable reconciled restore-gap body is absent")
        try:
            original = RestoreGap.create(
                gap_id=open_body["gap_id"],
                source_manifest_digest=open_body["source_manifest_digest"],
                restored_manifest_digest=open_body["restored_manifest_digest"],
                resources=tuple(tuple(item) for item in open_body["resources"]),
            )
            reconciled = original.reconcile(
                tuple(tuple(item) for item in reconciled_body["resources"]),
                authority_digest=reconciled_body["authority_digest"],
            )
        except (KeyError, TypeError, MigrationControlError) as error:
            raise MigrationRepositoryError("durable reconciled restore-gap body is invalid") from error
        if (
            migration_id != original.gap_id
            or open_body != _restore_gap_body(original)
            or reconciled_body != _restore_gap_body(reconciled)
        ):
            raise MigrationRepositoryError("durable reconciled restore-gap binding is invalid")
        return original, reconciled

    def register_restore_gap(
        self,
        bundle: MigrationBundle,
        *,
        resources: tuple[tuple[str, int], ...],
    ) -> RestoreGap:
        control_token = self._control_lock.acquire("exclusive")
        try:
            verified_bundle = self.validate_bundle(bundle.root)
            if verified_bundle.bundle_digest != bundle.bundle_digest:
                raise MigrationRepositoryError("restore bundle identity changed")
            current, active_factory = self._current_factory(control_token)
            high_water = dict(current.fencing_high_water)
            for resource, counter in verified_bundle.source_fencing_high_water:
                high_water[resource] = max(high_water.get(resource, 0), counter)
            for resource, counter in self._fences(active_factory):
                high_water[resource] = max(high_water.get(resource, 0), counter)
            derived_resources = tuple(sorted(high_water.items()))
            if resources != derived_resources:
                raise MigrationRepositoryError(
                    "restore-gap resources must equal the exact durable audit projection",
                )
            gap = RestoreGap.create(
                gap_id="restore-gap-" + bundle.bundle_digest.removeprefix("sha256-jcs-v1:"),
                source_manifest_digest=current.manifest_digest,
                restored_manifest_digest=verified_bundle.source_manifest_digest,
                resources=derived_resources,
            )
            with active_factory.open("doctor") as connection:
                unresolved_claims = tuple(row[0] for row in connection.execute(
                    "SELECT claim_id FROM claims WHERE state='unresolved' ORDER BY claim_id",
                ).fetchall())
                unresolved_actions = tuple(row[0] for row in connection.execute(
                    "SELECT action_id FROM action_journal WHERE state IN ('executing','unknown') "
                    "ORDER BY action_id",
                ).fetchall())
            record = {
                "schema_version": "1.0",
                "gap": _restore_gap_body(gap),
                "bundle_digest": verified_bundle.bundle_digest,
                "bundle_snapshot_digest": verified_bundle.snapshot_digest,
                "unresolved_claim_ids": list(unresolved_claims),
                "unresolved_action_ids": list(unresolved_actions),
                "fresh_observations": [],
            }
            record_digest = semantic_record_digest(record)
            self._fault("restore_gap.before_ledger_commit")
            with active_factory.open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO migration_ledger(migration_id,state,record_json,record_digest) "
                        "VALUES(?,?,?,?)",
                        (gap.gap_id, "restore_gap_open", canonical_json(record), record_digest),
                    )
            self._fault("restore_gap.after_ledger_commit")
            blocked = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=current.generation + 1,
                activation_epoch=current.activation_epoch + 1,
                repository_id=current.repository_id,
                repository_digest=current.repository_digest,
                repository_locator_ref=current.repository_locator_ref,
                repository_locator_digest=current.repository_locator_digest,
                release_id=current.release_id,
                contract_id=current.contract_id,
                mode="blocked",
                previous_manifest_digest=current.manifest_digest,
                fencing_high_water=gap.resources,
                restore_gap_digest=gap.gap_digest,
            )
            blocked.require_successor_of(current)
            self._fault("restore_gap.before_blocked_manifest")
            self._publish_manifest(blocked)
            self._fault("restore_gap.after_blocked_manifest")
            return gap
        finally:
            self._control_lock.release(control_token)

    def clear_restore_gap(
        self,
        gap: RestoreGap,
        *,
        fences: tuple[tuple[str, int], ...],
        authority_digest: str | None,
        fresh_observations: tuple[Mapping[str, object], ...] = (),
        trusted_observers: Mapping[str, object] | None = None,
    ) -> RestoreGap:
        control_token = self._control_lock.acquire("exclusive")
        try:
            current, active_factory = self._current_factory(
                control_token, require_active=False,
            )
            if (
                current.mode != "blocked"
                or current.restore_gap_digest != gap.gap_digest
                or current.previous_manifest_digest != gap.source_manifest_digest
            ):
                raise MigrationRepositoryError("restore gap is not bound to current blocked manifest")
            with active_factory.open("doctor") as connection:
                row = connection.execute(
                    "SELECT state,record_json,record_digest FROM migration_ledger WHERE migration_id=?",
                    (gap.gap_id,),
                ).fetchone()
            if row is None or row[0] != "restore_gap_open":
                raise MigrationRepositoryError("durable restore gap is missing or not open")
            record = parse_canonical_json(row[1])
            if (
                not isinstance(record, dict)
                or semantic_record_digest(record) != row[2]
                or record.get("gap") != _restore_gap_body(gap)
            ):
                raise MigrationRepositoryError("durable restore gap binding is invalid")
            observation_map: dict[str, Mapping[str, object]] = {}
            expected_observation_fields = {
                "resource_id", "target_id", "target_state_digest", "observation_revision",
                "observed_at_ns", "observer_binding_digest", "gap_digest",
                "blocked_manifest_digest", "observation_digest",
            }
            for observation in fresh_observations:
                if not isinstance(observation, Mapping) or set(observation) != expected_observation_fields:
                    raise MigrationRepositoryError("restore-gap observation record is not exact")
                resource = observation.get("resource_id")
                target = observation.get("target_id")
                revision = observation.get("observation_revision")
                observed_at = observation.get("observed_at_ns")
                if (
                    type(resource) is not str
                    or type(target) is not str
                    or not target
                    or type(revision) is not int
                    or revision < 1
                    or type(observed_at) is not int
                    or observed_at < 1
                    or observation.get("gap_digest") != gap.gap_digest
                    or observation.get("blocked_manifest_digest") != current.manifest_digest
                ):
                    raise MigrationRepositoryError("restore-gap observation binding is invalid")
                for name in ("target_state_digest", "observer_binding_digest"):
                    digest = observation.get(name)
                    if (
                        type(digest) is not str
                        or not digest.startswith("sha256-jcs-v1:")
                        or len(digest) != len("sha256-jcs-v1:") + 64
                        or any(character not in "0123456789abcdef" for character in digest.removeprefix("sha256-jcs-v1:"))
                    ):
                        raise MigrationRepositoryError("restore-gap observation digest is invalid")
                unsigned_observation = {
                    key: observation[key] for key in expected_observation_fields
                    if key != "observation_digest"
                }
                if observation.get("observation_digest") != semantic_record_digest(unsigned_observation):
                    raise MigrationRepositoryError("restore-gap observation digest mismatch")
                if resource in observation_map:
                    raise MigrationRepositoryError("restore-gap observation resource is duplicated")
                observation_map[resource] = observation
            if (
                set(observation_map) != {resource for resource, _ in gap.resources}
            ):
                raise MigrationRepositoryError("restore gap requires exact fresh observations")
            for resource, observation in observation_map.items():
                if resource.startswith("task:"):
                    task_id = resource.removeprefix("task:")
                    with active_factory.open("doctor") as connection:
                        task_row = connection.execute(
                            "SELECT revision,snapshot_digest,integrity_status FROM tasks WHERE task_id=?",
                            (task_id,),
                        ).fetchone()
                    expected_observer_binding = semantic_record_digest({
                        "kind": "repository-task-observer",
                        "repository_id": current.repository_id,
                        "task_id": task_id,
                        "blocked_manifest_digest": current.manifest_digest,
                    })
                    if (
                        task_row is None
                        or task_row[2] != "ok"
                        or observation["target_id"] != task_id
                        or observation["target_state_digest"] != task_row[1]
                        or observation["observation_revision"] != task_row[0]
                        or observation["observer_binding_digest"] != expected_observer_binding
                    ):
                        raise MigrationRepositoryError(
                            "restore-gap task observation is stale or substituted",
                        )

            if authority_digest is None:
                raise MigrationRepositoryError("restore gap requires current durable reauthorization")
            task_ids = {
                resource.removeprefix("task:")
                for resource, _counter in gap.resources
                if resource.startswith("task:")
            }
            expected_actions = tuple(record.get("unresolved_action_ids", ()))
            with active_factory.open("doctor") as connection:
                action_rows = tuple(connection.execute(
                    "SELECT action_id,task_id,state,authority_digest FROM action_journal "
                    "WHERE state IN ('executing','unknown') ORDER BY action_id",
                ).fetchall())
                if tuple(row[0] for row in action_rows) != expected_actions:
                    raise MigrationRepositoryError("restore-gap unresolved action audit changed")
                task_ids.update(row[1] for row in action_rows)
                for task_id in sorted(task_ids):
                    state_row = connection.execute(
                        "SELECT s.state_json,s.state_digest,s.task_revision,s.task_snapshot_digest,"
                        "t.revision,t.snapshot_digest,t.integrity_status "
                        "FROM task_security_states s JOIN tasks t ON t.task_id=s.task_id "
                        "WHERE s.task_id=?",
                        (task_id,),
                    ).fetchone()
                    if state_row is None:
                        raise MigrationRepositoryError("restore-gap durable task reauthorization is missing")
                    state = parse_canonical_json(state_row[0])
                    state_keys = {
                        "schema_version", "task_id", "task_revision", "task_snapshot_digest",
                        "binding", "destinations", "authority_digests", "data_refs",
                        "evidence_expectations", "retention_subjects",
                    }
                    if (
                        not isinstance(state, dict)
                        or set(state) != state_keys
                        or state.get("schema_version") != "1.0.0"
                        or state.get("task_id") != task_id
                        or state.get("task_revision") != state_row[2]
                        or state.get("task_snapshot_digest") != state_row[3]
                        or state_row[2] != state_row[4]
                        or state_row[3] != state_row[5]
                        or state_row[6] != "ok"
                        or not isinstance(state.get("binding"), dict)
                        or state["binding"].get("task_id") != task_id
                        or state["binding"].get("snapshot_digest") != state_row[3]
                        or any(
                            type(state.get(name)) is not dict
                            for name in (
                                "destinations", "data_refs", "evidence_expectations",
                                "retention_subjects",
                            )
                        )
                        or type(state.get("authority_digests")) is not list
                        or state["authority_digests"] != sorted(set(state["authority_digests"]))
                        or semantic_record_digest({
                            "contract": "task-security-state-v1", "value": state,
                        }) != state_row[1]
                        or authority_digest not in state.get("authority_digests", ())
                    ):
                        raise MigrationRepositoryError("restore-gap task reauthorization is not current")
                    action_authorities = {
                        row[3] for row in action_rows if row[1] == task_id
                    }
                    if None in action_authorities or not action_authorities.issubset(
                        set(state.get("authority_digests", ())),
                    ):
                        raise MigrationRepositoryError("restore-gap action authority is not durable")
                external_resources = {
                    resource for resource, _counter in gap.resources
                    if not resource.startswith("task:")
                }
                if external_resources:
                    if trusted_observers is None or set(trusted_observers) != external_resources:
                        raise MigrationRepositoryError("restore-gap trusted observer set is incomplete")
                    action_bindings: dict[str, tuple[str, str]] = {}
                    for action_id, _task_id, _state, _authority in action_rows:
                        prepared_row = connection.execute(
                            "SELECT prepared_json FROM action_journal WHERE action_id=?",
                            (action_id,),
                        ).fetchone()
                        prepared = parse_canonical_json(prepared_row[0])
                        if not isinstance(prepared, dict):
                            raise MigrationRepositoryError("restore-gap durable action is malformed")
                        for resource in prepared.get("resources", ()):
                            if resource in external_resources:
                                action_bindings[resource] = (
                                    prepared.get("target_id"), prepared.get("target_digest"),
                                )
                    if set(action_bindings) != external_resources:
                        raise MigrationRepositoryError("restore-gap external target binding is absent")
                    for resource in sorted(external_resources):
                        observer = trusted_observers[resource]
                        target_id, target_digest = action_bindings[resource]
                        if (
                            getattr(observer, "is_read_only_observer", False) is not True
                            or getattr(observer, "resource_id", None) != resource
                            or getattr(observer, "target_id", None) != target_id
                            or getattr(observer, "target_digest", None) != target_digest
                        ):
                            raise MigrationRepositoryError("restore-gap observer binding is substituted")
                        observed = observer.observe()
                        supplied = observation_map[resource]
                        expected_binding = semantic_record_digest({
                            "resource_id": resource,
                            "target_id": target_id,
                            "target_digest": target_digest,
                            "capabilities": tuple(sorted(getattr(observer, "capabilities", ()))),
                        })
                        if (
                            not isinstance(observed, dict)
                            or observed.get("fresh") is not True
                            or observed.get("resource_id") != resource
                            or observed.get("target_id") != target_id
                            or observed.get("target_digest") != target_digest
                            or supplied["observation_revision"] != observed.get("observation_revision")
                            or supplied["target_state_digest"]
                            != semantic_record_digest({"state": observed.get("state")})
                            or supplied["observer_binding_digest"] != expected_binding
                        ):
                            raise MigrationRepositoryError("restore-gap observer result is stale")
            issued_fences = tuple(
                (resource, counter + 1) for resource, counter in gap.resources
            )
            if fences != issued_fences:
                raise MigrationRepositoryError("restore-gap fence is not repository-issued next high-water")
            try:
                reconciled = gap.reconcile(issued_fences, authority_digest=authority_digest)
            except MigrationControlError as error:
                raise MigrationRepositoryError(str(error)) from error
            self._fault("restore_gap.before_reconcile_commit")
            with active_factory.open("migration") as connection:
                with connection.transaction():
                    connection.executemany(
                        "INSERT INTO resource_fences(resource_id,fencing_token) VALUES(?,?) "
                        "ON CONFLICT(resource_id) DO UPDATE SET fencing_token="
                        "MAX(resource_fences.fencing_token,excluded.fencing_token)",
                        reconciled.resources,
                    )
                    reconciled_record = dict(record)
                    reconciled_record["reconciled_gap"] = _restore_gap_body(reconciled)
                    reconciled_record["fresh_observations"] = [
                        dict(observation_map[resource]) for resource in sorted(observation_map)
                    ]
                    reconciled_digest = semantic_record_digest(reconciled_record)
                    connection.execute(
                        "UPDATE migration_ledger SET state=?,record_json=?,record_digest=? "
                        "WHERE migration_id=? AND state='restore_gap_open'",
                        (
                            "restore_gap_reconciled", canonical_json(reconciled_record),
                            reconciled_digest, gap.gap_id,
                        ),
                    )
            self._fault("restore_gap.after_reconcile_commit")
            active = ActiveRepositoryManifest.create(
                installation_id=current.installation_id,
                generation=current.generation + 1,
                activation_epoch=current.activation_epoch + 1,
                repository_id=current.repository_id,
                repository_digest=self._repository_digest(),
                repository_locator_ref=current.repository_locator_ref,
                repository_locator_digest=current.repository_locator_digest,
                release_id=current.release_id,
                contract_id=current.contract_id,
                mode="active",
                previous_manifest_digest=current.manifest_digest,
                fencing_high_water=reconciled.resources,
                restore_gap_digest=None,
            )
            active.require_successor_of(current)
            self._fault("restore_gap.before_reactivation_manifest")
            self._publish_manifest(active)
            self._fault("restore_gap.after_reactivation_manifest")
            return reconciled
        finally:
            self._control_lock.release(control_token)
