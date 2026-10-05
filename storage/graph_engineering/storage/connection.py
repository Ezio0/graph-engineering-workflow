"""Fail-closed SQLite connection factory for ADR-0002."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import os
import pathlib
import platform
import re
import shutil
import sqlite3
import weakref
import stat
import subprocess
import threading
import time
from types import MappingProxyType
from typing import Callable, Final, Iterator, Sequence
from urllib.parse import quote

from .errors import (
    RepositoryBusyError,
    RepositoryConfigurationError,
    RepositoryProcessError,
)
from .policy import RepositoryPolicy


_CAPABILITY_SEAL = object()
_CONNECTION_FACTORY_SEAL = object()
_MAINTENANCE_FACTORY_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class FilesystemCapability:
    schema_version: str
    platform: str
    local_filesystem: bool
    durable_sync: bool
    sqlite_vfs: str
    filesystem_identity: str
    mount_point: str
    mount_options: tuple[str, ...]
    sqlite_version: str

    def __init__(self) -> None:
        raise RepositoryConfigurationError("filesystem capability is factory-only")

    @classmethod
    def _from_verified(
        cls,
        *,
        platform_name: str,
        local_filesystem: bool,
        durable_sync: bool,
        sqlite_vfs: str,
        filesystem_identity: str,
        mount_point: str,
        mount_options: tuple[str, ...],
        sqlite_version: str,
        seal: object,
    ) -> FilesystemCapability:
        if seal is not _CAPABILITY_SEAL:
            raise RepositoryConfigurationError("filesystem capability is not doctor-attested")
        instance = object.__new__(cls)
        values = {
            "schema_version": "1.0", "platform": platform_name,
            "local_filesystem": local_filesystem, "durable_sync": durable_sync,
            "sqlite_vfs": sqlite_vfs, "filesystem_identity": filesystem_identity,
            "mount_point": mount_point, "mount_options": mount_options,
            "sqlite_version": sqlite_version,
        }
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        return instance

    def require_mutation_safe(self) -> None:
        if not self.local_filesystem or not self.durable_sync:
            raise RepositoryConfigurationError("filesystem power-loss capability is unverified")


def _sqlite_uri(path: pathlib.Path, vfs: str, *, mode: str = "rw") -> str:
    if mode not in {"ro", "rw"}:
        raise RepositoryConfigurationError("SQLite URI mode is invalid")
    return f"file:{quote(str(path), safe='/')}?mode={mode}&vfs={quote(vfs, safe='')}"


class RepositoryDoctor:
    """Derive the repository mutation capability from the live path and SQLite runtime."""

    _DARWIN_MOUNT = re.compile(
        r"^(?P<source>.+) on (?P<mount>.+) \((?P<options>.+)\)$",
    )
    _LINUX_MOUNT = re.compile(
        r"^(?P<source>.+) on (?P<mount>.+) type (?P<filesystem>[^ ]+) \((?P<options>.*)\)$",
    )

    @staticmethod
    def _decode_mount_path(value: str) -> str:
        return value.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")

    @classmethod
    def _mount_observation(cls, root: pathlib.Path) -> dict[str, object]:
        system = platform.system()
        executable = shutil.which("mount")
        df_executable = shutil.which("df")
        if system not in {"Darwin", "Linux"} or executable is None or df_executable is None:
            raise RepositoryConfigurationError("supported mount capability probe is unavailable")
        df_result = subprocess.run(
            [df_executable, "-P", str(root)],
            check=False, capture_output=True, text=True, timeout=5,
        )
        df_lines = [line for line in df_result.stdout.splitlines() if line.strip()]
        if df_result.returncode != 0 or len(df_lines) < 2:
            raise RepositoryConfigurationError("filesystem identity probe failed")
        df_fields = df_lines[-1].split()
        if len(df_fields) < 6:
            raise RepositoryConfigurationError("filesystem identity probe is malformed")
        expected_source = cls._decode_mount_path(df_fields[0])
        expected_mount = cls._decode_mount_path(df_fields[-1])
        result = subprocess.run(
            [executable], check=False, capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            raise RepositoryConfigurationError("mount capability probe failed")
        candidates: list[tuple[pathlib.Path, str, tuple[str, ...], str]] = []
        for line in result.stdout.splitlines():
            match = cls._DARWIN_MOUNT.match(line) if system == "Darwin" else cls._LINUX_MOUNT.match(line)
            if match is None:
                continue
            source = cls._decode_mount_path(match.group("source"))
            mount_value = cls._decode_mount_path(match.group("mount"))
            mount_path = pathlib.Path(mount_value)
            if source != expected_source or mount_value != expected_mount:
                continue
            options = tuple(sorted(set(
                item.strip().casefold() for item in match.group("options").split(",") if item.strip()
            )))
            filesystem = (
                options[0] if system == "Darwin" and options else match.group("filesystem").casefold()
            )
            candidates.append((mount_path, filesystem, options, line))
        if not candidates:
            raise RepositoryConfigurationError("repository filesystem mount is unresolved")
        mount_path, filesystem, options, identity = max(
            candidates, key=lambda item: len(item[0].parts),
        )
        return {
            "platform": system,
            "mount_point": str(mount_path),
            "filesystem_type": filesystem,
            "mount_options": options,
            "filesystem_identity": identity,
        }

    @classmethod
    def require_approved_filesystem(
        cls,
        root: pathlib.Path,
        policy: RepositoryPolicy,
    ) -> dict[str, object]:
        observation = cls._mount_observation(root)
        system = observation.get("platform")
        filesystem = observation.get("filesystem_type")
        options = observation.get("mount_options")
        local = (
            system in {"Darwin", "Linux"}
            and type(filesystem) is str
            and filesystem in policy.approved_filesystem_types
            and isinstance(options, tuple)
            and (system != "Darwin" or "local" in options)
        )
        if not local:
            raise RepositoryConfigurationError("repository filesystem is not approved local storage")
        return observation

    @classmethod
    def probe(
        cls,
        root: pathlib.Path,
        database: pathlib.Path,
        policy: RepositoryPolicy,
    ) -> FilesystemCapability:
        observation = cls.require_approved_filesystem(root, policy)
        system = observation["platform"]
        options = observation["mount_options"]
        raw = sqlite3.connect(
            _sqlite_uri(database, policy.required_sqlite_vfs),
            timeout=0, isolation_level=None, uri=True,
        )
        try:
            if system == "Darwin":
                raw.execute("PRAGMA fullfsync=ON")
            fullfsync = int(raw.execute("PRAGMA fullfsync").fetchone()[0])
            durable_sync = system == "Linux" or fullfsync == 1
        finally:
            raw.close()
        capability = FilesystemCapability._from_verified(
            platform_name=system,
            local_filesystem=True,
            durable_sync=durable_sync,
            sqlite_vfs=policy.required_sqlite_vfs,
            filesystem_identity=str(observation["filesystem_identity"]),
            mount_point=str(observation["mount_point"]),
            mount_options=options,
            sqlite_version=sqlite3.sqlite_version,
            seal=_CAPABILITY_SEAL,
        )
        capability.require_mutation_safe()
        return capability


SCHEMA_SQL: Final[str] = """
CREATE TABLE IF NOT EXISTS repository_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS schema_versions (
    component TEXT PRIMARY KEY,
    version TEXT NOT NULL,
    applied_at TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL CHECK(revision >= 0),
    head_sequence INTEGER NOT NULL CHECK(head_sequence >= 0),
    head_digest TEXT NOT NULL,
    snapshot_json TEXT NOT NULL,
    snapshot_digest TEXT NOT NULL,
    integrity_status TEXT NOT NULL CHECK(integrity_status IN ('ok','blocked'))
) STRICT;
CREATE TABLE IF NOT EXISTS events (
    task_id TEXT NOT NULL REFERENCES tasks(task_id) DEFERRABLE INITIALLY DEFERRED,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    body_json TEXT NOT NULL,
    previous_event_digest TEXT,
    event_digest TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    PRIMARY KEY(task_id, sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS transactions (
    transaction_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    task_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    head_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS task_extension_pin_bindings (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    generation INTEGER NOT NULL CHECK(generation > 0),
    pin_digest TEXT NOT NULL UNIQUE,
    previous_pin_digest TEXT,
    binding_json TEXT NOT NULL,
    binding_digest TEXT NOT NULL UNIQUE,
    transaction_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(task_id, generation)
) STRICT;
CREATE TABLE IF NOT EXISTS catalog (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    fields_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS project_scopes (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    scope_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version > 0),
    metadata_revision INTEGER NOT NULL CHECK(metadata_revision > 0),
    scope_digest TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('drafted','frozen','superseded')),
    source_json TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    change_json TEXT,
    change_digest TEXT,
    created_transaction_id TEXT NOT NULL,
    approved_transaction_id TEXT,
    approved_event_digest TEXT,
    PRIMARY KEY(task_id, scope_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS project_scope_realizations (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    scope_digest TEXT NOT NULL,
    binding_id TEXT NOT NULL,
    planned_target_id TEXT NOT NULL,
    actual_git_identity TEXT NOT NULL,
    boundary_evidence_digest TEXT NOT NULL,
    action_id TEXT NOT NULL,
    prepared_action_digest TEXT NOT NULL,
    receipt_digest TEXT NOT NULL,
    observation_json TEXT NOT NULL,
    observation_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    PRIMARY KEY(task_id, binding_id),
    FOREIGN KEY(task_id, scope_digest) REFERENCES project_scopes(task_id, scope_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS project_scope_approvals (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    scope_digest TEXT NOT NULL,
    transaction_id TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    PRIMARY KEY(task_id, scope_digest),
    FOREIGN KEY(task_id, scope_digest) REFERENCES project_scopes(task_id, scope_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS project_scope_metadata_history (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    scope_digest TEXT NOT NULL,
    metadata_revision INTEGER NOT NULL CHECK(metadata_revision > 0),
    source_json TEXT NOT NULL,
    source_digest TEXT NOT NULL,
    event_digest TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    PRIMARY KEY(task_id, scope_digest, metadata_revision),
    FOREIGN KEY(task_id, scope_digest) REFERENCES project_scopes(task_id, scope_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS lifecycle_plans (
    plan_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    kind TEXT NOT NULL CHECK(kind IN ('retention','rollback')),
    trigger TEXT NOT NULL CHECK(trigger IN ('archive','cancel','rollback')),
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    task_snapshot_digest TEXT NOT NULL,
    facts_digest TEXT NOT NULL,
    body_json TEXT NOT NULL,
    body_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('prepared','consumed')),
    consumed_transaction_id TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS lifecycle_plan_executions (
    plan_id TEXT PRIMARY KEY REFERENCES lifecycle_plans(plan_id),
    transaction_id TEXT NOT NULL UNIQUE,
    trigger TEXT NOT NULL,
    schedule_json TEXT NOT NULL,
    schedule_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS objects (
    digest TEXT PRIMARY KEY,
    size INTEGER NOT NULL CHECK(size >= 0),
    state TEXT NOT NULL CHECK(state IN ('available','deleting','deleted','quarantined')),
    write_id TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS object_references (
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    digest TEXT NOT NULL REFERENCES objects(digest),
    ref_kind TEXT NOT NULL,
    transaction_id TEXT NOT NULL,
    PRIMARY KEY(task_id, digest, ref_kind)
) STRICT;
CREATE TABLE IF NOT EXISTS resource_fences (
    resource_id TEXT PRIMARY KEY,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0)
) STRICT;
CREATE TABLE IF NOT EXISTS leases (
    lease_id TEXT PRIMARY KEY,
    request_digest TEXT NOT NULL,
    task_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK(expires_at > issued_at),
    heartbeat_revision INTEGER NOT NULL CHECK(heartbeat_revision >= 0),
    state TEXT NOT NULL CHECK(state IN ('live','released','expired'))
) STRICT;
CREATE TABLE IF NOT EXISTS lease_resources (
    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
    resource_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    PRIMARY KEY(lease_id, resource_id)
) STRICT;
CREATE TABLE IF NOT EXISTS claims (
    claim_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL,
    lease_id TEXT NOT NULL REFERENCES leases(lease_id),
    started_event_digest TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
    state TEXT NOT NULL CHECK(state IN ('unresolved','reconciled_no_effect','reconciled_effect_verified','compensation_reconciled')),
    outcome_digest TEXT
) STRICT;
            CREATE TABLE IF NOT EXISTS claim_recovery_attempts (
                attempt_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE REFERENCES claims(claim_id),
                protocol_version TEXT NOT NULL,
                task_id TEXT NOT NULL,
                original_action_id TEXT NOT NULL,
                original_started_event_digest TEXT NOT NULL,
                compensation_action_id TEXT NOT NULL UNIQUE,
                compensation_authority_digest TEXT NOT NULL,
                compensation_prepared_digest TEXT NOT NULL,
                lease_id TEXT NOT NULL REFERENCES leases(lease_id),
                resources_json TEXT NOT NULL,
                fencing_tokens_json TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_digest TEXT NOT NULL,
                baseline_digest TEXT NOT NULL,
                snapshot_digest TEXT NOT NULL,
                disclosure_plan_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('started','receipt_recorded','reconciled')),
    revision INTEGER NOT NULL CHECK(revision > 0),
    start_event_digest TEXT NOT NULL,
    receipt_event_digest TEXT,
    receipt_json TEXT,
    receipt_digest TEXT,
    receipt_object_digest TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS claim_resources (
    claim_id TEXT NOT NULL REFERENCES claims(claim_id),
    resource_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    PRIMARY KEY(claim_id, resource_id)
) STRICT;
CREATE TABLE IF NOT EXISTS claim_objects (
    claim_id TEXT NOT NULL REFERENCES claims(claim_id),
    digest TEXT NOT NULL REFERENCES objects(digest),
    PRIMARY KEY(claim_id, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS export_holds (
    export_id TEXT NOT NULL,
    digest TEXT NOT NULL REFERENCES objects(digest),
    snapshot_digest TEXT NOT NULL,
    PRIMARY KEY(export_id, digest)
) STRICT;
CREATE TABLE IF NOT EXISTS migration_ledger (
    migration_id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS migration_ledger_transitions (
    migration_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision > 0),
    state TEXT NOT NULL,
    previous_transition_digest TEXT,
    record_json TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    PRIMARY KEY(migration_id, revision),
    UNIQUE(record_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS security_runtime_installation (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    manifest_json TEXT NOT NULL,
    manifest_id TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    schema_registry_id TEXT NOT NULL,
    schema_registry_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS task_security_states (
    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
    task_revision INTEGER NOT NULL CHECK(task_revision > 0),
    task_snapshot_digest TEXT NOT NULL,
    state_json TEXT NOT NULL,
    state_digest TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS disclosure_journal (
    receipt_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    entry_json TEXT NOT NULL,
    entry_digest TEXT NOT NULL,
    reconciliation_state TEXT NOT NULL CHECK(reconciliation_state IN ('prepared','delivered','reconciled'))
) STRICT;
CREATE TABLE IF NOT EXISTS purge_authorizations (
    authorization_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    subject_ref TEXT NOT NULL,
    subject_snapshot_digest TEXT NOT NULL,
    security_state_digest TEXT NOT NULL,
    decision_digest TEXT NOT NULL,
    consumed_at_ns INTEGER NOT NULL CHECK(consumed_at_ns >= 0),
    UNIQUE(task_id, subject_ref, subject_snapshot_digest, security_state_digest, decision_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS action_journal (
    action_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(task_id),
    state TEXT NOT NULL CHECK(state IN ('prepared','authorized','executing','succeeded','failed','unknown','reconciled','compensated','revoked')),
    revision INTEGER NOT NULL CHECK(revision > 0),
    idempotency_key TEXT NOT NULL,
    prepared_json TEXT NOT NULL,
    prepared_digest TEXT NOT NULL,
    authority_json TEXT,
    authority_digest TEXT,
    receipt_json TEXT,
    reconciliation_json TEXT,
    UNIQUE(task_id, idempotency_key)
) STRICT;
CREATE TABLE IF NOT EXISTS concrete_action_records (
    record_digest TEXT PRIMARY KEY,
    record_type TEXT NOT NULL CHECK(record_type IN ('invocation','receipt','observation')),
    task_id TEXT NOT NULL,
    action_id TEXT NOT NULL REFERENCES action_journal(action_id),
    invocation_digest TEXT NOT NULL,
    receipt_digest TEXT,
    record_json TEXT NOT NULL,
    UNIQUE(record_type, action_id),
    UNIQUE(record_type, invocation_digest),
    UNIQUE(record_type, receipt_digest)
) STRICT;
"""

_IMMUTABILITY_TRIGGERS: Final[tuple[str, ...]] = (
    "CREATE TRIGGER IF NOT EXISTS task_extension_pin_no_update "
    "BEFORE UPDATE ON task_extension_pin_bindings BEGIN "
    "SELECT RAISE(ABORT, 'task extension pins are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS task_extension_pin_no_delete "
    "BEFORE DELETE ON task_extension_pin_bindings BEGIN "
    "SELECT RAISE(ABORT, 'task extension pins are append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS security_runtime_installation_single_write "
    "BEFORE INSERT ON security_runtime_installation "
    "WHEN EXISTS(SELECT 1 FROM security_runtime_installation) BEGIN "
    "SELECT RAISE(ABORT, 'security runtime installation is immutable'); END",
    "CREATE TRIGGER IF NOT EXISTS security_runtime_installation_no_update "
    "BEFORE UPDATE ON security_runtime_installation BEGIN "
    "SELECT RAISE(ABORT, 'security runtime installation is immutable'); END",
    "CREATE TRIGGER IF NOT EXISTS security_runtime_installation_no_delete "
    "BEFORE DELETE ON security_runtime_installation BEGIN "
    "SELECT RAISE(ABORT, 'security runtime installation is immutable'); END",
)


def _owner_only_regular(path: pathlib.Path, owner: int, mode: int) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        raise RepositoryConfigurationError("repository path is missing") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RepositoryConfigurationError("repository file is not a regular no-symlink file")
    if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != mode:
        raise RepositoryConfigurationError("repository file owner or mode is invalid")


def _owner_only_directory(path: pathlib.Path, owner: int, mode: int) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise RepositoryConfigurationError("repository root is not a no-symlink directory")
    if metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != mode:
        raise RepositoryConfigurationError("repository directory owner or mode is invalid")


def _create_owner_only_directory(path: pathlib.Path, owner: int, mode: int) -> None:
    os.mkdir(path, mode)
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != owner:
            raise RepositoryConfigurationError("new repository directory is not owner-bound")
        os.fchmod(descriptor, mode)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
            raise RepositoryConfigurationError("new repository directory mode is invalid")
    finally:
        os.close(descriptor)


def _ensure_owner_only_directory(path: pathlib.Path, owner: int, mode: int) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        _create_owner_only_directory(path, owner, mode)
    else:
        _owner_only_directory(path, owner, mode)


def _create_owner_only_regular(path: pathlib.Path, owner: int, mode: int) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != owner:
            raise RepositoryConfigurationError("new repository file is not owner-bound")
        os.fchmod(descriptor, mode)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode:
            raise RepositoryConfigurationError("new repository file mode is invalid")
    finally:
        os.close(descriptor)


DirectoryIdentity = tuple[int, int, int, int]


def _directory_identity(metadata: os.stat_result) -> DirectoryIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        stat.S_IMODE(metadata.st_mode),
    )


class BoundDirectory:
    """A no-follow directory capability bound to one verified inode."""

    def __init__(
        self,
        path: pathlib.Path,
        descriptor: int,
        identity: DirectoryIdentity,
        *,
        parent: BoundDirectory | None = None,
        name: str | None = None,
    ) -> None:
        self._path = path
        self._descriptor = descriptor
        self._identity = identity
        self._parent = parent
        self._name = name
        self._closed = False

    @staticmethod
    def _name_value(name: str) -> str:
        if (
            type(name) is not str
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\x00" in name
        ):
            raise RepositoryConfigurationError("bound directory child name is invalid")
        return name

    @staticmethod
    def _flags() -> int:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        return flags

    @classmethod
    def open_root(
        cls,
        path: pathlib.Path,
        expected: DirectoryIdentity,
    ) -> BoundDirectory:
        try:
            descriptor = os.open(path, cls._flags())
        except OSError as error:
            raise RepositoryConfigurationError(
                "attested repository root cannot be descriptor-bound",
            ) from error
        instance = cls(path, descriptor, expected)
        try:
            instance.verify()
        except BaseException:
            os.close(descriptor)
            instance._closed = True
            raise
        return instance

    def verify(self) -> None:
        if self._closed:
            raise RepositoryConfigurationError("bound directory is closed")
        if self._parent is None:
            try:
                current = self._path.lstat()
            except FileNotFoundError as error:
                raise RepositoryConfigurationError(
                    "attested repository root is missing",
                ) from error
        else:
            self._parent.verify()
            assert self._name is not None
            try:
                current = os.stat(
                    self._name,
                    dir_fd=self._parent._descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError as error:
                raise RepositoryConfigurationError(
                    "attested repository directory is missing",
                ) from error
        descriptor_metadata = os.fstat(self._descriptor)
        if (
            not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(descriptor_metadata.st_mode)
            or _directory_identity(current) != self._identity
            or _directory_identity(descriptor_metadata) != self._identity
        ):
            raise RepositoryConfigurationError(
                "attested repository directory was replaced or weakened",
            )

    def open_child(
        self,
        name: str,
        *,
        expected: DirectoryIdentity | None = None,
        create: bool = False,
        mode: int | None = None,
    ) -> BoundDirectory:
        child_name = self._name_value(name)
        self.verify()
        try:
            descriptor = os.open(child_name, self._flags(), dir_fd=self._descriptor)
        except FileNotFoundError as missing:
            if not create or mode is None:
                raise RepositoryConfigurationError(
                    "attested repository child directory is missing",
                ) from missing
            try:
                os.mkdir(child_name, mode, dir_fd=self._descriptor)
                descriptor = os.open(child_name, self._flags(), dir_fd=self._descriptor)
                os.fchmod(descriptor, mode)
            except OSError as error:
                raise RepositoryConfigurationError(
                    "repository child directory creation failed",
                ) from error
        except OSError as error:
            raise RepositoryConfigurationError(
                "repository child directory is not a no-follow directory",
            ) from error
        metadata = os.fstat(descriptor)
        identity = _directory_identity(metadata) if expected is None else expected
        child = BoundDirectory(
            self._path / child_name,
            descriptor,
            identity,
            parent=self,
            name=child_name,
        )
        try:
            child.verify()
            if mode is not None and identity[3] != mode:
                raise RepositoryConfigurationError(
                    "repository child directory mode is invalid",
                )
        except BaseException:
            os.close(descriptor)
            child._closed = True
            raise
        return child

    def open_file(self, name: str, flags: int, mode: int = 0o600) -> int:
        child_name = self._name_value(name)
        self.verify()
        safe_flags = flags
        if hasattr(os, "O_NOFOLLOW"):
            safe_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            safe_flags |= os.O_CLOEXEC
        return os.open(child_name, safe_flags, mode, dir_fd=self._descriptor)

    def stat(self, name: str) -> os.stat_result:
        child_name = self._name_value(name)
        self.verify()
        return os.stat(child_name, dir_fd=self._descriptor, follow_symlinks=False)

    def names(self) -> tuple[str, ...]:
        self.verify()
        return tuple(sorted(os.listdir(self._descriptor)))

    def link(self, source_name: str, destination: BoundDirectory, destination_name: str) -> None:
        source = self._name_value(source_name)
        target = self._name_value(destination_name)
        self.verify()
        destination.verify()
        os.link(
            source,
            target,
            src_dir_fd=self._descriptor,
            dst_dir_fd=destination._descriptor,
            follow_symlinks=False,
        )

    def unlink(self, name: str) -> None:
        child_name = self._name_value(name)
        self.verify()
        os.unlink(child_name, dir_fd=self._descriptor)

    def fsync(self) -> None:
        self.verify()
        os.fsync(self._descriptor)

    def close(self) -> None:
        if not self._closed:
            os.close(self._descriptor)
            self._closed = True

    def close_chain(self) -> None:
        current: BoundDirectory | None = self
        while current is not None:
            parent = current._parent
            current.close()
            current = parent


_READ_ONLY_SQLITE_ACTIONS: Final[frozenset[int]] = frozenset({
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    getattr(sqlite3, "SQLITE_RECURSIVE", -1),
})


def _read_only_authorizer(
    action: int,
    _argument_one: str | None,
    argument_two: str | None,
    _database: str | None,
    _trigger: str | None,
) -> int:
    if action in _READ_ONLY_SQLITE_ACTIONS:
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and argument_two is None:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


_ISSUED_CONNECTION_OWNERS = weakref.WeakKeyDictionary()


class ManagedConnection:
    """PID/thread-bound explicit-transaction connection."""

    ROLE_PREFIXES: Final[dict[str, tuple[str, ...]]] = {
        "application": ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH"),
        "backup": ("SELECT", "WITH", "EXPLAIN"),
        "doctor": ("SELECT", "WITH", "EXPLAIN"),
        "migration": ("SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP"),
    }

    def __init__(
        self,
        raw: sqlite3.Connection,
        role: str,
        policy: RepositoryPolicy,
        context_validator: Callable[[], None] | None = None,
        on_close: Callable[[], None] | None = None,
    ) -> None:
        self._raw = raw
        self._role = role
        self._policy = policy
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._read_only = role in {"backup", "doctor"}
        self._closed = False
        self._in_transaction = False
        self._context_validator = context_validator
        self._on_close = on_close

    def _check_owner(self) -> None:
        if self._closed:
            raise RepositoryProcessError("connection is closed")
        if os.getpid() != self._pid or threading.get_ident() != self._thread:
            raise RepositoryProcessError("connection crossed its PID or thread boundary")

    def _check(self) -> None:
        self._check_owner()
        if self._context_validator is not None:
            self._context_validator()

    def _check_statement(self, sql: str) -> None:
        statement = sql.lstrip().upper()
        if statement.startswith(("PRAGMA", "ATTACH", "DETACH", "VACUUM")):
            raise RepositoryConfigurationError("raw SQLite control or copy statement is forbidden")
        if not statement.startswith(self.ROLE_PREFIXES[self._role]):
            raise RepositoryConfigurationError("connection role cannot execute statement")

    def execute(self, sql: str, parameters: Sequence[object] = ()) -> sqlite3.Cursor:
        self._check()
        self._check_statement(sql)
        try:
            return self._raw.execute(sql, parameters)
        except sqlite3.DatabaseError as error:
            if self._read_only and (
                "not authorized" in str(error).casefold()
                or "readonly" in str(error).casefold()
            ):
                raise RepositoryConfigurationError(
                    "read-only connection rejected a mutation",
                ) from error
            raise

    def executemany(
        self,
        sql: str,
        parameters: Sequence[Sequence[object]],
    ) -> sqlite3.Cursor:
        self._check()
        self._check_statement(sql)
        try:
            return self._raw.executemany(sql, parameters)
        except sqlite3.DatabaseError as error:
            if self._read_only and (
                "not authorized" in str(error).casefold()
                or "readonly" in str(error).casefold()
            ):
                raise RepositoryConfigurationError(
                    "read-only connection rejected a mutation",
                ) from error
            raise

    def _begin_immediate(self) -> None:
        last_error: sqlite3.OperationalError | None = None
        for delay_ms in self._policy.busy_retry_delays_ms:
            if delay_ms:
                time.sleep(delay_ms / 1000)
            try:
                self._raw.execute("BEGIN IMMEDIATE")
                self._in_transaction = True
                return
            except sqlite3.OperationalError as error:
                if "locked" not in str(error).casefold() and "busy" not in str(error).casefold():
                    raise
                last_error = error
        raise RepositoryBusyError("SQLite writer retry budget exhausted") from last_error

    @contextlib.contextmanager
    def transaction(self) -> Iterator[ManagedConnection]:
        self._check()
        if self._role in {"backup", "doctor"}:
            raise RepositoryConfigurationError("read-only role cannot begin immediate")
        if self._in_transaction:
            raise RepositoryConfigurationError("nested repository transaction is forbidden")
        self._begin_immediate()
        try:
            yield self
            if self._context_validator is not None:
                self._context_validator()
            self._raw.execute("COMMIT")
            self._in_transaction = False
        except BaseException:
            if self._in_transaction:
                self._raw.execute("ROLLBACK")
                self._in_transaction = False
            raise

    def pragma_snapshot(self) -> dict[str, object]:
        self._check()
        return {
            "journal_mode": str(self._raw.execute("PRAGMA journal_mode").fetchone()[0]).upper(),
            "synchronous": int(self._raw.execute("PRAGMA synchronous").fetchone()[0]),
            "foreign_keys": int(self._raw.execute("PRAGMA foreign_keys").fetchone()[0]),
            "busy_timeout": int(self._raw.execute("PRAGMA busy_timeout").fetchone()[0]),
            "locking_mode": str(self._raw.execute("PRAGMA locking_mode").fetchone()[0]).upper(),
            "fullfsync": int(self._raw.execute("PRAGMA fullfsync").fetchone()[0]),
            "query_only": int(self._raw.execute("PRAGMA query_only").fetchone()[0]),
        }

    def online_backup(self, destination: pathlib.Path) -> None:
        """Create one fsynced SQLite online-backup image from a read-only source."""

        self._check()
        if self._role not in {"backup", "migration"}:
            raise RepositoryConfigurationError("connection role cannot create an online backup")
        if not destination.is_absolute() or destination.exists() or destination.is_symlink():
            raise RepositoryConfigurationError("backup destination must be a new absolute regular file")
        parent = destination.parent.resolve(strict=True)
        _owner_only_directory(parent, os.getuid(), self._policy.root_mode)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            descriptor = os.open(
                destination.name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                self._policy.file_mode,
                dir_fd=parent_descriptor,
            )
            os.close(descriptor)
        finally:
            os.close(parent_descriptor)
        target = sqlite3.connect(destination)
        try:
            self._raw.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise RepositoryConfigurationError("online backup integrity check failed")
            target.commit()
        finally:
            target.close()
        descriptor = os.open(destination, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        parent_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    def close(self) -> None:
        # Cleanup must remain possible after an activation makes the bound
        # command tuple stale.  No further statement or commit is permitted,
        # but the owning thread must still be able to roll back and close.
        self._check_owner()
        if self._in_transaction:
            self._raw.execute("ROLLBACK")
            self._in_transaction = False
        self._raw.close()
        self._closed = True
        if self._on_close is not None:
            self._on_close()
            self._on_close = None

    def __enter__(self) -> ManagedConnection:
        self._check()
        return self

    def __exit__(self, *_errors: object) -> None:
        self.close()


class ConnectionFactory:
    """The only supported SQLite open path."""

    def _require_owned_transaction(self, connection):
        if (type(connection) is not ManagedConnection
                or _ISSUED_CONNECTION_OWNERS.get(connection) is not self
                or not connection._in_transaction or connection._role!='application'):
            raise RepositoryConfigurationError("connection is not this repository's active transaction")
        connection._check()

    SCHEMA_VERSION: Final[str] = "1.0"
    SYNCHRONOUS_EXTRA_CODE: Final[int] = 3

    def __init__(
        self,
        data_root: pathlib.Path,
        policy: RepositoryPolicy,
        capability: FilesystemCapability,
        repository_id: str,
        *,
        seal: object,
        context_validator: Callable[[], None] | None = None,
        command_scope: object | None = None,
        maintenance_seal: object | None = None,
    ) -> None:
        if seal is not _CONNECTION_FACTORY_SEAL:
            raise RepositoryConfigurationError("connection factory is not initialized by its verifier")
        if type(repository_id) is not str or not repository_id:
            raise RepositoryConfigurationError("repository identity is invalid")
        capability.require_mutation_safe()
        canonical_root = data_root.resolve(strict=True)
        self._root = canonical_root
        self._policy = policy
        self._capability = capability
        self._repository_id = repository_id
        self._context_validator = context_validator
        self._command_scope = command_scope
        self._maintenance = maintenance_seal is _MAINTENANCE_FACTORY_SEAL
        self._owner = os.getuid()
        self._database = canonical_root / policy.database_filename
        self._verify_layout()
        self._directory_identities = MappingProxyType({
            (): _directory_identity(self._root.lstat()),
            (policy.objects_directory,): _directory_identity(
                (self._root / policy.objects_directory).lstat(),
            ),
            (policy.staging_directory,): _directory_identity(
                (self._root / policy.staging_directory).lstat(),
            ),
            (policy.locks_directory,): _directory_identity(
                (self._root / policy.locks_directory).lstat(),
            ),
            (
                policy.locks_directory,
                policy.resources_directory,
            ): _directory_identity((
                self._root / policy.locks_directory / policy.resources_directory
            ).lstat()),
        })

    @classmethod
    def initialize(
        cls,
        data_root: pathlib.Path,
        policy: RepositoryPolicy,
        repository_id: str,
    ) -> ConnectionFactory:
        if type(repository_id) is not str or not repository_id:
            raise RepositoryConfigurationError("repository identity is invalid")
        if not data_root.is_absolute():
            raise RepositoryConfigurationError("repository root must be absolute")
        if data_root.is_symlink():
            raise RepositoryConfigurationError("repository root cannot be a symlink")
        owner = os.getuid()
        if data_root.exists():
            _owner_only_directory(data_root, owner, policy.root_mode)
            RepositoryDoctor.require_approved_filesystem(data_root, policy)
            canonical_root = data_root.resolve(strict=True)
        else:
            parent = data_root.parent.resolve(strict=True)
            RepositoryDoctor.require_approved_filesystem(parent, policy)
            candidate = parent / data_root.name
            _create_owner_only_directory(candidate, owner, policy.root_mode)
            canonical_root = candidate.resolve(strict=True)
        _owner_only_directory(canonical_root, owner, policy.root_mode)
        for name in (
            policy.objects_directory, policy.staging_directory, policy.locks_directory,
        ):
            target = canonical_root / name
            _ensure_owner_only_directory(target, owner, policy.root_mode)
        resources = canonical_root / policy.locks_directory / policy.resources_directory
        _ensure_owner_only_directory(resources, owner, policy.root_mode)
        database = canonical_root / policy.database_filename
        try:
            database.lstat()
        except FileNotFoundError:
            _create_owner_only_regular(database, owner, policy.file_mode)
        else:
            _owner_only_regular(database, owner, policy.file_mode)
        capability = RepositoryDoctor.probe(canonical_root, database, policy)
        factory = cls(
            canonical_root, policy, capability, repository_id,
            seal=_CONNECTION_FACTORY_SEAL,
        )
        from .locks import LockedFileRegistry

        bootstrap_locks = LockedFileRegistry(factory)
        token = bootstrap_locks.acquire_installation("exclusive")
        try:
            with factory._for_maintenance().open("migration") as connection:
                for statement in SCHEMA_SQL.split(";"):
                    if statement.strip():
                        connection.execute(statement)
                for statement in _IMMUTABILITY_TRIGGERS:
                    connection.execute(statement)
                with connection.transaction():
                    existing = connection.execute(
                        "SELECT value FROM repository_meta WHERE key='repository_id'"
                    ).fetchone()
                    if existing is not None and existing[0] != repository_id:
                        raise RepositoryConfigurationError("repository identity mismatch")
                    connection.execute(
                        "INSERT OR IGNORE INTO repository_meta(key,value) VALUES('repository_id',?)",
                        (repository_id,),
                    )
                    connection.execute(
                        "INSERT OR IGNORE INTO schema_versions(component,version,applied_at) VALUES(?,?,?)",
                        ("storage", cls.SCHEMA_VERSION, "initial"),
                    )
        finally:
            bootstrap_locks.release(token)
            bootstrap_locks.close()
        return factory

    @classmethod
    def _attach_existing_for_maintenance(
        cls,
        data_root: pathlib.Path,
        policy: RepositoryPolicy,
        repository_id: str,
    ) -> ConnectionFactory:
        """Verify and attach an existing repository without creating or migrating it."""

        if type(repository_id) is not str or not repository_id:
            raise RepositoryConfigurationError("repository identity is invalid")
        if not data_root.is_absolute() or data_root.is_symlink():
            raise RepositoryConfigurationError("repository root is invalid")
        canonical_root = data_root.resolve(strict=True)
        owner = os.getuid()
        _owner_only_directory(canonical_root, owner, policy.root_mode)
        database = canonical_root / policy.database_filename
        _owner_only_regular(database, owner, policy.file_mode)
        capability = RepositoryDoctor.probe(canonical_root, database, policy)
        factory = cls(
            canonical_root,
            policy,
            capability,
            repository_id,
            seal=_CONNECTION_FACTORY_SEAL,
            maintenance_seal=_MAINTENANCE_FACTORY_SEAL,
        )
        with factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT value FROM repository_meta WHERE key='repository_id'",
            ).fetchone()
        if row != (repository_id,):
            raise RepositoryConfigurationError("repository identity mismatch")
        return factory

    @property
    def data_root(self) -> pathlib.Path:
        return self._root

    @property
    def policy(self) -> RepositoryPolicy:
        return self._policy

    @property
    def repository_id(self) -> str:
        return self._repository_id

    @property
    def filesystem_capability(self) -> FilesystemCapability:
        return self._capability

    @property
    def command_context_bound(self) -> bool:
        return self._context_validator is not None

    def require_mutation_authority(self) -> None:
        if self._context_validator is not None:
            self._context_validator()
            return
        if not self._maintenance:
            raise RepositoryConfigurationError(
                "repository mutation requires command scope or maintenance authority",
            )

    def bind_command_scope(self, scope: object) -> ConnectionFactory:
        from .migration import InstallationCommandScope

        if type(scope) is not InstallationCommandScope:
            raise RepositoryConfigurationError("connection command scope is missing or forged")
        scope.require_current()
        if scope.repository_id != self._repository_id or scope.repository_root != self._root:
            raise RepositoryConfigurationError("connection factory does not match command repository")
        return type(self)(
            self._root,
            self._policy,
            self._capability,
            self._repository_id,
            seal=_CONNECTION_FACTORY_SEAL,
            context_validator=scope.require_current,
            command_scope=scope,
        )

    def _for_maintenance(self) -> ConnectionFactory:
        return type(self)(
            self._root,
            self._policy,
            self._capability,
            self._repository_id,
            seal=_CONNECTION_FACTORY_SEAL,
            maintenance_seal=_MAINTENANCE_FACTORY_SEAL,
        )

    def bind_directory(self, *parts: str) -> BoundDirectory:
        key = tuple(parts)
        if key not in self._directory_identities or any(type(part) is not str for part in key):
            raise RepositoryConfigurationError("directory is outside the attested layout")
        root = BoundDirectory.open_root(self._root, self._directory_identities[()])
        current = root
        try:
            prefix: tuple[str, ...] = ()
            for part in key:
                prefix += (part,)
                expected = self._directory_identities.get(prefix)
                if expected is None:
                    raise RepositoryConfigurationError(
                        "directory path is not an attested layout component",
                    )
                current = current.open_child(part, expected=expected)
            return current
        except BaseException:
            current.close_chain()
            raise

    def _verify_layout(self) -> None:
        _owner_only_directory(self._root, self._owner, self._policy.root_mode)
        _owner_only_regular(self._database, self._owner, self._policy.file_mode)
        for target in (
            self._root / self._policy.objects_directory,
            self._root / self._policy.staging_directory,
            self._root / self._policy.locks_directory,
            self._root / self._policy.locks_directory / self._policy.resources_directory,
        ):
            _owner_only_directory(target, self._owner, self._policy.root_mode)

    def open(self, role: str) -> ManagedConnection:
        if role not in self._policy.connection_roles:
            raise RepositoryConfigurationError("unknown connection role")
        if role in {"application", "migration"} and self._context_validator is None and not self._maintenance:
            raise RepositoryConfigurationError("mutable connection requires command scope or maintenance authority")
        if self._context_validator is not None:
            self._context_validator()
        self._capability.require_mutation_safe()
        self._verify_layout()
        current_capability = RepositoryDoctor.probe(
            self._root, self._database, self._policy,
        )
        if current_capability != self._capability:
            raise RepositoryConfigurationError("repository filesystem capability changed")
        read_only = role in {"backup", "doctor"}
        raw = sqlite3.connect(
            _sqlite_uri(
                self._database,
                self._policy.required_sqlite_vfs,
                mode="ro" if read_only else "rw",
            ),
            timeout=0,
            isolation_level=None,
            check_same_thread=True,
            uri=True,
        )
        try:
            raw.execute(f"PRAGMA busy_timeout={self._policy.busy_timeout_ms}")
            raw.execute("PRAGMA foreign_keys=ON")
            raw.execute(f"PRAGMA locking_mode={self._policy.locking_mode}")
            raw.execute(f"PRAGMA journal_mode={self._policy.journal_mode}")
            raw.execute(f"PRAGMA synchronous={self._policy.synchronous}")
            if platform.system() == "Darwin":
                raw.execute("PRAGMA fullfsync=ON")
            if read_only:
                raw.execute("PRAGMA query_only=ON")
            snapshot = {
                "journal": str(raw.execute("PRAGMA journal_mode").fetchone()[0]).upper(),
                "sync": int(raw.execute("PRAGMA synchronous").fetchone()[0]),
                "foreign": int(raw.execute("PRAGMA foreign_keys").fetchone()[0]),
                "busy": int(raw.execute("PRAGMA busy_timeout").fetchone()[0]),
                "locking": str(raw.execute("PRAGMA locking_mode").fetchone()[0]).upper(),
                "fullfsync": int(raw.execute("PRAGMA fullfsync").fetchone()[0]),
                "query_only": int(raw.execute("PRAGMA query_only").fetchone()[0]),
            }
            if (
                snapshot["journal"] != self._policy.journal_mode
                or snapshot["sync"] != self.SYNCHRONOUS_EXTRA_CODE
                or snapshot["foreign"] != 1
                or snapshot["busy"] != self._policy.busy_timeout_ms
                or snapshot["locking"] != self._policy.locking_mode
                or (platform.system() == "Darwin" and snapshot["fullfsync"] != 1)
                or snapshot["query_only"] != (1 if read_only else 0)
            ):
                raise RepositoryConfigurationError("SQLite open contract mismatch")
            try:
                identity = raw.execute(
                    "SELECT value FROM repository_meta WHERE key='repository_id'"
                ).fetchone()
            except sqlite3.OperationalError as error:
                if role != "migration" or "no such table" not in str(error).casefold():
                    raise
                identity = None
            if identity is not None and identity[0] != self._repository_id:
                raise RepositoryConfigurationError("SQLite repository identity mismatch")
            if read_only:
                raw.set_authorizer(_read_only_authorizer)
            connection_token = object()
            on_close: Callable[[], None] | None = None
            if self._command_scope is not None:
                opened = getattr(self._command_scope, "_connection_opened")
                closed = getattr(self._command_scope, "_connection_closed")
                opened(connection_token)
                on_close = lambda: closed(connection_token)
            connection = ManagedConnection(
                raw, role, self._policy, self._context_validator, on_close,
            )
            _ISSUED_CONNECTION_OWNERS[connection] = self
            return connection
        except BaseException:
            raw.close()
            raise
