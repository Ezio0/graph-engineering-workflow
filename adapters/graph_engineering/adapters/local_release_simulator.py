"""Factory-confined filesystem simulator for ADR-0009 release operations."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import pathlib
import secrets
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import thaw
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.release_operations import (
    ReleaseArtifactManifest,
    ReleaseOperationsError,
    ReleaseOperationsRegistry,
    ReleaseRecoveryBinding,
    evaluate_health,
)


class ReleaseSimulatorError(ReleaseOperationsError):
    """The local simulator rejected an unsafe or stale operation."""


def _semantic(value: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        value,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _result_digest(value: Mapping[str, object]) -> str:
    return _semantic(value, "local-release-simulator-result")


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=False,
    ).encode("ascii")


def _retained_identity(metadata: os.stat_result) -> dict[str, object]:
    """Use the platform's stable birth identity, not mutable mtime/ctime."""

    birth = getattr(metadata, "st_birthtime", None)
    if not isinstance(birth, (int, float)) or not 0 <= birth < 2**53:
        raise ReleaseSimulatorError("retained directory birth identity is unavailable")
    seconds = int(birth)
    return {
        "kind": "posix-directory-birthtime-f64-v1",
        "device": metadata.st_dev, "inode": metadata.st_ino, "owner": metadata.st_uid,
        "birth_seconds": seconds, "birth_nanoseconds": int((birth - seconds) * 1_000_000_000),
    }


def _retained_directory(path: pathlib.Path) -> int:
    """Open the exact absolute component chain; never resolve a symlink."""

    if (
        not isinstance(path, pathlib.Path) or not path.is_absolute()
        or any(part in {".", ".."} for part in path.parts)
        or not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0)
        or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
    ):
        raise ReleaseSimulatorError("retained directory path or primitives are unavailable")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise ReleaseSimulatorError("retained namespace is not private and owner-bound")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class _RetainedNamespace:
    """Internal physical storage only; not a runtime or recovery capability.

    Production session/evidence issuance must separately enforce the approved
    typed runtime, repository, installation and lock-entry authority. No such
    issuance is wired to these primitives by this implementation slice.
    """

    def __init__(self, path: pathlib.Path) -> None:
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._closed = False
        self._active: set[int] = set()
        self.path = path
        try:
            self._descriptor = _retained_directory(path)
        except OSError as error:
            raise ReleaseSimulatorError("retained namespace cannot be opened") from error
        try:
            self.identity = _retained_identity(os.fstat(self._descriptor))
        except BaseException:
            os.close(self._descriptor)
            raise

    @property
    def active_leases(self) -> int:
        self._require_current()
        return len(self._active)

    def _require_current(self) -> None:
        if self._closed or (self._pid, self._thread) != (os.getpid(), threading.get_ident()):
            raise ReleaseSimulatorError("retained namespace is closed or foreign")
        try:
            current = _retained_directory(self.path)
            try:
                if self.identity != _retained_identity(os.fstat(current)) or self.identity != _retained_identity(os.fstat(self._descriptor)):
                    raise ReleaseSimulatorError("retained namespace identity changed")
            finally:
                os.close(current)
        except OSError as error:
            raise ReleaseSimulatorError("retained namespace is unavailable") from error

    @staticmethod
    def _key(task_id: str, target_id: str) -> str:
        for value in (task_id, target_id):
            if type(value) is not str or not 1 <= len(value) <= 255 or any(not 33 <= ord(c) <= 126 for c in value):
                raise ReleaseSimulatorError("retained task/target ID is invalid")
        return "root-v1-" + hashlib.sha256(canonical_bytes([task_id, target_id])).hexdigest()

    def _open(self, task_id: str, target_id: str, members: Mapping[str, int], *, create: bool) -> "_RetainedRootLease":
        self._require_current()
        checked = _RetainedRootLease.check_members(members)
        key = self._key(task_id, target_id)
        try:
            if create:
                os.mkdir(key, 0o700, dir_fd=self._descriptor)
                os.fsync(self._descriptor)
            descriptor = os.open(key, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self._descriptor)
        except OSError as error:
            raise ReleaseSimulatorError("retained root is absent, unsafe or already exists") from error
        try:
            lease = _RetainedRootLease(self, key, descriptor, checked, create=create)
        except BaseException:
            os.close(descriptor)
            raise
        self._active.add(id(lease))
        return lease

    def create(self, task_id: str, target_id: str, *, members: Mapping[str, int]) -> "_RetainedRootLease":
        return self._open(task_id, target_id, members, create=True)

    def open_readonly(self, binding: ReleaseRecoveryBinding, *, members: Mapping[str, int], context: WorkContext) -> "_RetainedRootLease":
        if type(binding) is not ReleaseRecoveryBinding or type(context) is not WorkContext:
            raise ReleaseSimulatorError("retained read requires exact binding data and work context")
        value = binding.to_dict()
        lease = self._open(value["task_id"], value["target_id"], members, create=False)
        try:
            lease._validate_binding(binding, context)
            return lease
        except BaseException:
            lease.close()
            raise

    def destroy(self, binding: ReleaseRecoveryBinding, *, members: Mapping[str, int], context: WorkContext) -> None:
        """Owner-plane primitive: revoke durably before deleting exact members."""

        with self.open_readonly(binding, members=members, context=context) as lease:
            lease._destroy_owned_root(binding, context)

    def close(self) -> None:
        if (self._pid, self._thread) != (os.getpid(), threading.get_ident()):
            raise ReleaseSimulatorError("retained namespace close is foreign")
        if self._closed:
            return
        if self._active:
            raise ReleaseSimulatorError("retained namespace still owns a live root")
        self._closed = True
        os.close(self._descriptor)

    def __enter__(self) -> "_RetainedNamespace":
        self._require_current()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class _RetainedRootLease:
    """PID/thread-bound nonblocking mutex plus an independent OS root lock."""

    BINDING_NAME = ".release-simulator-root"
    _GATES: dict[tuple[int, ...], int] = {}
    _GUARD = threading.Lock()

    @classmethod
    def check_members(cls, members: Mapping[str, int]) -> dict[str, int]:
        if not isinstance(members, Mapping) or not members:
            raise ReleaseSimulatorError("retained members are missing")
        checked = {}
        for name, mode in members.items():
            if (
                type(name) is not str or not name or name in {".", "..", cls.BINDING_NAME}
                or "/" in name or "\\" in name or "\x00" in name
                or type(mode) is not int or mode != 0o600
            ):
                raise ReleaseSimulatorError("retained member name or mode is unsafe")
            checked[name] = mode
        return {**checked, cls.BINDING_NAME: 0o400}

    def __init__(self, namespace: _RetainedNamespace, key: str, descriptor: int, members: dict[str, int], *, create: bool) -> None:
        import fcntl

        self._namespace, self._key, self._descriptor = namespace, key, descriptor
        self._pid, self._thread = os.getpid(), threading.get_ident()
        self._closed, self._sealed, self._readonly = False, False, not create
        self._members = MappingProxyType(members)
        self.path = namespace.path / key
        self.identity = _retained_identity(os.fstat(descriptor))
        self._nonce = secrets.token_hex(32) if create else None
        self._gate_key = (self._pid, *[self.identity[k] for k in ("device", "inode", "birth_seconds", "birth_nanoseconds")])
        self._require_location()
        with self._GUARD:
            if self._gate_key in self._GATES:
                raise ReleaseSimulatorError("retained root is busy")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise ReleaseSimulatorError("retained root is busy or OS locking is unavailable") from error
            self._GATES[self._gate_key] = descriptor

    @classmethod
    def _after_fork(cls) -> None:
        for descriptor in cls._GATES.values():
            os.close(descriptor)
        cls._GATES = {}
        cls._GUARD = threading.Lock()

    def _require_owner(self) -> None:
        if self._closed or (self._pid, self._thread) != (os.getpid(), threading.get_ident()):
            raise ReleaseSimulatorError("retained root lease is closed or foreign")

    def _require_location(self) -> None:
        self._require_owner()
        self._namespace._require_current()
        try:
            named = os.stat(self._key, dir_fd=self._namespace._descriptor, follow_symlinks=False)
            opened = os.fstat(self._descriptor)
            for metadata in (named, opened):
                if (
                    not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                    or _retained_identity(metadata) != self.identity
                ):
                    raise ReleaseSimulatorError("retained root identity changed")
        except OSError as error:
            raise ReleaseSimulatorError("retained root is unavailable") from error

    def _member_metadata(self, name: str) -> os.stat_result:
        if name not in self._members:
            raise ReleaseSimulatorError("retained member is unowned")
        try:
            metadata = os.stat(name, dir_fd=self._descriptor, follow_symlinks=False)
        except OSError as error:
            raise ReleaseSimulatorError("retained member is unavailable") from error
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != self._members[name]
        ):
            raise ReleaseSimulatorError("retained member identity or permissions are unsafe")
        return metadata

    def _validate_members(self) -> tuple[str, ...]:
        self._require_location()
        names = []
        seen = set()
        with os.scandir(self._descriptor) as entries:
            for entry in entries:
                if len(names) >= len(self._members):
                    raise ReleaseSimulatorError("retained directory exceeds member bound")
                metadata = self._member_metadata(entry.name)
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in seen:
                    raise ReleaseSimulatorError("retained members alias")
                seen.add(identity)
                names.append(entry.name)
        return tuple(names)

    def binding_parts(self) -> dict[str, object]:
        self._require_location()
        return {"namespace_identity": dict(self._namespace.identity), "root_identity": dict(self.identity), "root_nonce": self._nonce}

    def initialize_file(self, name: str, body: bytes) -> None:
        self._require_location()
        if self._readonly or self._sealed or name == self.BINDING_NAME or name not in self._members or type(body) is not bytes:
            raise ReleaseSimulatorError("retained initialization write is not allowed")
        self._write_new(name, body)

    def _write_new(self, name: str, body: bytes) -> None:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, self._members[name], dir_fd=self._descriptor)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(body)
                stream.flush()
                os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self._descriptor)

    def seal(self, binding: ReleaseRecoveryBinding) -> None:
        self._validate_members()
        if self._readonly or self._sealed or type(binding) is not ReleaseRecoveryBinding:
            raise ReleaseSimulatorError("retained binding publication is not allowed")
        value = binding.to_dict()
        if any(value[k] != v for k, v in self.binding_parts().items()) or self._key != self._namespace._key(value["task_id"], value["target_id"]):
            raise ReleaseSimulatorError("retained binding differs from physical root")
        self._write_new(self.BINDING_NAME, canonical_bytes(value))
        os.fsync(self._namespace._descriptor)
        self._sealed = True

    def read(self, name: str, *, max_bytes: int) -> bytes:
        self._validate_members()
        if type(max_bytes) is not int or max_bytes < 1:
            raise ReleaseSimulatorError("retained read bound is invalid")
        before = self._member_metadata(name)
        if before.st_size > max_bytes:
            raise ReleaseSimulatorError("retained member exceeds read bound")
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=self._descriptor)
        except OSError as error:
            raise ReleaseSimulatorError("retained member cannot be opened safely") from error
        def signature(metadata: os.stat_result) -> tuple[int, ...]:
            return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
                    metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)
        try:
            if signature(os.fstat(descriptor)) != signature(before):
                raise ReleaseSimulatorError("retained member changed before read")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                body = stream.read(max_bytes + 1)
            after = self._member_metadata(name)
            if len(body) > max_bytes or signature(before) != signature(after) or signature(before) != signature(os.fstat(descriptor)):
                raise ReleaseSimulatorError("retained member changed during read")
            self._require_location()
            return body
        finally:
            os.close(descriptor)

    def _validate_binding(self, expected: ReleaseRecoveryBinding, context: WorkContext) -> None:
        body = self.read(self.BINDING_NAME, max_bytes=context.profile.limits["raw_document_bytes"])
        try:
            parsed = ReleaseRecoveryBinding.from_bytes(body, context=context)
        except ReleaseOperationsError as error:
            raise ReleaseSimulatorError("retained binding is invalid") from error
        value = parsed.to_dict()
        if body != canonical_bytes(value) or value != expected.to_dict():
            raise ReleaseSimulatorError("retained binding bytes changed")
        self._nonce = value["root_nonce"]
        if any(value[k] != v for k, v in self.binding_parts().items()):
            raise ReleaseSimulatorError("retained binding physical identity changed")
        self._sealed = True

    def close(self) -> None:
        import fcntl

        if (self._pid, self._thread) != (os.getpid(), threading.get_ident()):
            raise ReleaseSimulatorError("retained root close is foreign")
        if self._closed:
            return
        self._closed = True
        try:
            with self._GUARD:
                self._GATES.pop(self._gate_key)
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._descriptor)
            self._namespace._active.discard(id(self))

    def _destroy_owned_root(self, binding: ReleaseRecoveryBinding, context: WorkContext) -> None:
        """Owner-plane cleanup after admission; never borrow a live writer lease."""

        self._require_owner()
        if not self._readonly or not self._sealed:
            raise ReleaseSimulatorError("retained destruction requires a new owner lease")
        self._validate_binding(binding, context)
        names = self._validate_members()
        os.unlink(self.BINDING_NAME, dir_fd=self._descriptor)
        os.fsync(self._descriptor)
        for name in sorted(set(names) - {self.BINDING_NAME}):
            self._require_location()
            self._member_metadata(name)
            os.unlink(name, dir_fd=self._descriptor)
        os.fsync(self._descriptor)
        self._require_location()
        os.rmdir(self._key, dir_fd=self._namespace._descriptor)
        os.fsync(self._namespace._descriptor)

    def __enter__(self) -> "_RetainedRootLease":
        self._require_location()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_RetainedRootLease._after_fork)


class _PrivateRoot:
    __slots__ = (
        "_temporary", "_root_path", "_root_fd", "root_identity", "target_id",
        "fixture", "names", "baseline", "baseline_artifact_bytes",
        "authorized_artifacts", "closed", "mutation_count", "query_count",
        "health_count", "observation_revision", "fault_hook",
        "currentness_check", "phase_roles", "fault_roles", "phase_transitions",
        "last_fault_point", "last_execution", "original_binding", "_retained_lease",
    )

    def __init__(
        self,
        *,
        target_id: str,
        fixture: Mapping[str, object],
        baseline: ReleaseArtifactManifest,
        baseline_artifact_bytes: bytes,
        authorized_artifacts: Mapping[str, tuple[ReleaseArtifactManifest, bytes]],
        fault_hook: Callable[[str], None],
        currentness_check: Callable[[], None],
        phase_roles: Mapping[str, str],
        fault_roles: Mapping[str, str],
    ) -> None:
        self._retained_lease = None
        temporary = tempfile.TemporaryDirectory(prefix="gew-release-simulator-")
        root = pathlib.Path(temporary.name).resolve(strict=True)
        root.chmod(0o700)
        metadata = os.lstat(root)
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
            temporary.cleanup()
            raise ReleaseSimulatorError("release simulator root is not private")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        root_fd = os.open(root, flags)
        descriptor_metadata = os.fstat(root_fd)
        identity = (metadata.st_dev, metadata.st_ino, metadata.st_uid)
        if identity != (
            descriptor_metadata.st_dev,
            descriptor_metadata.st_ino,
            descriptor_metadata.st_uid,
        ):
            os.close(root_fd)
            temporary.cleanup()
            raise ReleaseSimulatorError("release simulator root descriptor changed")
        self._temporary = temporary
        self._root_path = root
        self._root_fd = root_fd
        self.root_identity = identity
        self.target_id = target_id
        self.fixture = fixture
        configured = {
            "stage": str(fixture["stage_relative_path"]),
            "active": str(fixture["active_relative_path"]),
            "state": str(fixture["state_relative_path"]),
        }
        for name in configured.values():
            path = pathlib.PurePosixPath(name)
            if path.is_absolute() or len(path.parts) != 1 or path.name != name:
                os.close(root_fd)
                temporary.cleanup()
                raise ReleaseSimulatorError("release simulator path escaped private root")
        self.names = MappingProxyType({
            **configured,
            "stage_artifact": pathlib.PurePosixPath(configured["stage"]).stem + ".bin",
            "active_artifact": pathlib.PurePosixPath(configured["active"]).stem + ".bin",
            "identity": ".release-simulator-root",
        })
        if len(set(self.names.values())) != len(self.names):
            os.close(root_fd)
            temporary.cleanup()
            raise ReleaseSimulatorError("release simulator members alias")
        self.baseline = baseline
        self.baseline_artifact_bytes = baseline_artifact_bytes
        self.authorized_artifacts = MappingProxyType(dict(authorized_artifacts))
        self.closed = False
        self.mutation_count = 0
        self.query_count = 0
        self.health_count = 0
        self.observation_revision = 0
        self.fault_hook = fault_hook
        self.currentness_check = currentness_check
        self.phase_roles = MappingProxyType(dict(phase_roles))
        self.fault_roles = MappingProxyType(dict(fault_roles))
        self.phase_transitions: list[dict[str, object]] = []
        self.last_fault_point: str | None = None
        self.last_execution: dict[str, object] | None = None
        self.original_binding: dict[str, object] | None = None
        self._require_artifact_bytes(baseline, baseline_artifact_bytes)
        self._durable_write(self.names["identity"], target_id.encode("ascii"), 0o400)
        self._durable_write(self.names["active_artifact"], baseline_artifact_bytes, 0o600)
        self._durable_write(self.names["active"], _json_bytes(baseline.to_dict()), 0o600)
        self._write_state({
            "schema_version": "1.0.0",
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": None,
        })
        self._record_phase(self.phase_roles["baseline"])

    def _require_open(self) -> None:
        self.currentness_check()
        if self.closed:
            raise ReleaseSimulatorError("release simulator root is closed")
        try:
            descriptor = os.fstat(self._root_fd)
            pathname = os.lstat(self._root_path)
        except OSError as error:
            raise ReleaseSimulatorError("release simulator root is unavailable") from error
        descriptor_identity = (descriptor.st_dev, descriptor.st_ino, descriptor.st_uid)
        pathname_identity = (pathname.st_dev, pathname.st_ino, pathname.st_uid)
        if (
            not stat.S_ISDIR(descriptor.st_mode)
            or not stat.S_ISDIR(pathname.st_mode)
            or stat.S_IMODE(descriptor.st_mode) & 0o077
            or descriptor_identity != self.root_identity
            or pathname_identity != self.root_identity
        ):
            raise ReleaseSimulatorError("release simulator root identity changed")
        try:
            names = os.listdir(self._root_fd)
        except OSError as error:
            raise ReleaseSimulatorError("release simulator root cannot be listed") from error
        if any(name not in self.names.values() for name in names):
            raise ReleaseSimulatorError("release simulator contains unowned residue")
        for name in names:
            metadata = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ReleaseSimulatorError("release simulator contains an unsafe member")
        if self._read(self.names["identity"], require_open=False) != self.target_id.encode("ascii"):
            raise ReleaseSimulatorError("release simulator root authority changed")

    def _exists(self, name: str) -> bool:
        try:
            metadata = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseSimulatorError("release simulator member is unsafe")
        return True

    def _read(self, name: str, *, require_open: bool = True) -> bytes:
        if require_open:
            self._require_open()
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self._root_fd,
            )
        except OSError as error:
            raise ReleaseSimulatorError("release simulator member is unavailable") from error
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise ReleaseSimulatorError("release simulator member is not regular")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                body = stream.read()
            after = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise ReleaseSimulatorError("release simulator member changed during read")
            return body
        finally:
            os.close(descriptor)

    def _durable_write(self, name: str, body: bytes, mode: int) -> None:
        if name not in self.names.values() or "/" in name or "\\" in name:
            raise ReleaseSimulatorError("release simulator write member is unsafe")
        temporary = "." + name + ".next"
        if self._exists(temporary):
            raise ReleaseSimulatorError("release simulator temporary member exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, mode, dir_fd=self._root_fd)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        os.replace(
            temporary, name, src_dir_fd=self._root_fd, dst_dir_fd=self._root_fd,
        )
        os.fsync(self._root_fd)

    def _durable_unlink(self, name: str) -> None:
        if name not in self.names.values() or "/" in name or "\\" in name:
            raise ReleaseSimulatorError("release simulator unlink member is unsafe")
        self._require_open()
        if not self._exists(name):
            raise ReleaseSimulatorError("release simulator cleanup member is absent")
        os.unlink(name, dir_fd=self._root_fd)
        os.fsync(self._root_fd)
        self._require_open()

    def _write_state(self, state: Mapping[str, object]) -> None:
        self._durable_write(self.names["state"], _json_bytes(state), 0o600)

    @staticmethod
    def _require_artifact_bytes(
        manifest: ReleaseArtifactManifest,
        body: bytes,
    ) -> None:
        if (
            type(body) is not bytes
            or len(body) != manifest.size
            or hashlib.sha256(body).hexdigest() != manifest.raw_sha256
        ):
            raise ReleaseSimulatorError("release artifact bytes differ from manifest")

    def state(self) -> dict[str, object]:
        self._require_open()
        try:
            value = json.loads(self._read(self.names["state"], require_open=False))
            active = ReleaseArtifactManifest.from_dict(
                json.loads(self._read(self.names["active"], require_open=False))
            )
            active_bytes = self._read(self.names["active_artifact"], require_open=False)
        except (OSError, UnicodeError, json.JSONDecodeError, ReleaseOperationsError) as error:
            raise ReleaseSimulatorError("release simulator state is corrupt") from error
        fields = (
            "schema_version", "generation", "active_artifact_digest",
            "staged_artifact_digest",
        )
        if type(value) is not dict or tuple(value) != fields or value["schema_version"] != "1.0.0":
            raise ReleaseSimulatorError("release simulator state shape changed")
        if (
            type(value["generation"]) is not int or value["generation"] < 0
            or value["active_artifact_digest"] != active.manifest_digest
        ):
            raise ReleaseSimulatorError("release simulator pointer or generation changed")
        self._require_artifact_bytes(active, active_bytes)
        stage_exists = self._exists(self.names["stage"])
        if stage_exists != self._exists(self.names["stage_artifact"]):
            raise ReleaseSimulatorError("release simulator staged bytes are incomplete")
        if stage_exists:
            try:
                staged = ReleaseArtifactManifest.from_dict(
                    json.loads(self._read(self.names["stage"], require_open=False))
                )
                staged_bytes = self._read(self.names["stage_artifact"], require_open=False)
            except (OSError, UnicodeError, json.JSONDecodeError, ReleaseOperationsError) as error:
                raise ReleaseSimulatorError("release simulator staged state is corrupt") from error
            self._require_artifact_bytes(staged, staged_bytes)
            if value["staged_artifact_digest"] != staged.manifest_digest:
                raise ReleaseSimulatorError("release simulator staged pointer changed")
        elif value["staged_artifact_digest"] is not None:
            raise ReleaseSimulatorError("release simulator staged pointer is dangling")
        return value

    def state_raw_sha256(self) -> str:
        self._require_open()
        return hashlib.sha256(
            self._read(self.names["state"], require_open=False)
        ).hexdigest()

    def _record_phase(self, phase_id: str) -> None:
        state = self.state()
        row = {
            "phase_id": phase_id,
            "generation": state["generation"],
            "state_digest": _result_digest(state),
        }
        if not self.phase_transitions or self.phase_transitions[-1] != row:
            self.phase_transitions.append(row)

    def fault(self, point: str) -> None:
        try:
            self.fault_hook(point)
        except BaseException:
            self.last_fault_point = point
            raise
        self._require_open()

    def bind_original_action(
        self,
        *,
        claim_id: str,
        receipt_digest: str,
        applied_artifact_digest: str,
        before_state: Mapping[str, object],
        after_state: Mapping[str, object],
    ) -> None:
        self._require_open()
        if self.original_binding is not None:
            raise ReleaseSimulatorError("release original action is already bound")
        state = self.state()
        before = dict(before_state)
        after = dict(after_state)
        active = (
            after.get("active_artifact_digest") == applied_artifact_digest
            and after.get("generation") == before.get("generation", -1) + 1
        )
        partial = (
            after.get("active_artifact_digest")
            == before.get("active_artifact_digest")
            and after.get("staged_artifact_digest") == applied_artifact_digest
            and after.get("generation") == before.get("generation")
        )
        if (
            state != after
            or not (active or partial)
            or before.get("staged_artifact_digest") is not None
        ):
            raise ReleaseSimulatorError("release original action target is not current")
        self.original_binding = {
            "claim_id": claim_id,
            "receipt_digest": receipt_digest,
            "applied_artifact_digest": applied_artifact_digest,
            "generation": after["generation"],
            "mode": "active" if active else "partial",
            "before_state": copy.deepcopy(before),
            "bound_state": copy.deepcopy(after),
        }

    def tree_digest(self) -> str:
        self._require_open()
        rows: list[tuple[str, int, str]] = []
        for name in sorted(os.listdir(self._root_fd)):
            metadata = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ReleaseSimulatorError("release simulator tree contains a non-file")
            rows.append((
                name, stat.S_IMODE(metadata.st_mode),
                hashlib.sha256(self._read(name, require_open=False)).hexdigest(),
            ))
        return hashlib.sha256(canonical_bytes(rows)).hexdigest()

    def snapshot(self) -> dict[str, object]:
        return {
            "state": self.state(),
            "phase_transitions": copy.deepcopy(self.phase_transitions),
            "fault_point": self.last_fault_point,
            "last_execution": copy.deepcopy(self.last_execution),
        }

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            os.close(self._root_fd)
            self._temporary.cleanup()


def _retained_members(fixture: Mapping[str, object]) -> dict[str, str]:
    configured = {name: str(fixture[name + "_relative_path"]) for name in ("stage", "active", "state")}
    for name in configured.values():
        path = pathlib.PurePosixPath(name)
        if path.is_absolute() or len(path.parts) != 1 or path.name != name:
            raise ReleaseSimulatorError("release retained member escaped private root")
    names = {**configured,
        "stage_artifact": pathlib.PurePosixPath(configured["stage"]).stem + ".bin",
        "active_artifact": pathlib.PurePosixPath(configured["active"]).stem + ".bin",
        "identity": _RetainedRootLease.BINDING_NAME}
    if len(set(names.values())) != len(names):
        raise ReleaseSimulatorError("release retained members alias")
    return names


class _RetainedPrivateRoot(_PrivateRoot):
    """Original live session storage. This is not a cold recovery reader."""

    __slots__ = ("_recovery_binding", "_read_bound", "_close_check")

    def __init__(self, *, lease: _RetainedRootLease, binding: ReleaseRecoveryBinding,
                 max_read_bytes: int, close_check: Callable[[], None], **values: object) -> None:
        self._retained_lease = lease
        self._recovery_binding = binding
        self._read_bound = max_read_bytes
        self._close_check = close_check
        self._temporary = None
        self._root_path, self._root_fd = lease.path, lease._descriptor
        self.root_identity = tuple(lease.identity[k] for k in ("device", "inode", "owner"))
        for name in ("target_id", "fixture", "baseline", "baseline_artifact_bytes", "fault_hook", "currentness_check"):
            setattr(self, name, values[name])
        self.names = MappingProxyType(_retained_members(self.fixture))
        self.authorized_artifacts = MappingProxyType(dict(values["authorized_artifacts"]))
        self.phase_roles = MappingProxyType(dict(values["phase_roles"]))
        self.fault_roles = MappingProxyType(dict(values["fault_roles"]))
        self.closed = False
        self.mutation_count = self.query_count = self.health_count = self.observation_revision = 0
        self.phase_transitions = []
        self.last_fault_point = self.last_execution = self.original_binding = None
        self._require_artifact_bytes(self.baseline, self.baseline_artifact_bytes)
        lease.seal(binding)
        self._durable_write(self.names["active_artifact"], self.baseline_artifact_bytes, 0o600)
        self._durable_write(self.names["active"], _json_bytes(self.baseline.to_dict()), 0o600)
        self._write_state({"schema_version": "1.0.0", "generation": 0,
            "active_artifact_digest": self.baseline.manifest_digest, "staged_artifact_digest": None})
        self._record_phase(self.phase_roles["baseline"])

    def _require_open(self) -> None:
        if self.closed:
            raise ReleaseSimulatorError("retained release session is closed")
        self.currentness_check()
        self._retained_lease._validate_members()
        expected = canonical_bytes(self._recovery_binding.to_dict())
        if self._retained_lease.read(self.names["identity"], max_bytes=len(expected)) != expected:
            raise ReleaseSimulatorError("retained release session binding changed")

    def _read(self, name: str, *, require_open: bool = True) -> bytes:
        if require_open:
            self._require_open()
        return self._retained_lease.read(name, max_bytes=self._read_bound)

    def _durable_write(self, name: str, body: bytes, mode: int) -> None:
        self._require_open()
        if name == self.names["identity"] or mode != 0o600 or len(body) > self._read_bound:
            raise ReleaseSimulatorError("retained release write is not allowed")
        super()._durable_write(name, body, mode)
        self._require_open()

    def close(self) -> None:
        if not self.closed:
            self._close_check()
            self._retained_lease.close()
            self.closed = True


class LocalReleaseTarget:
    """ActionTargetPort for apply/restore after a durable coordinator start."""

    is_test_double = True

    def __init__(
        self,
        root: _PrivateRoot,
        *,
        target_id: str,
        target_digest: str,
        resource_id: str,
        generation_limit: int,
        operation_ids: Mapping[str, str],
        durable_execution_gate: object,
    ) -> None:
        self._root = root
        self.target_id = target_id
        self.target_digest = target_digest
        self.resource_id = resource_id
        self.capabilities = (
            "deterministic-fake-target-v1", "fake-compensation",
            "fresh-target-query", "local-release-simulator-v1",
        )
        self._generation_limit = generation_limit
        self._operation_ids = MappingProxyType(dict(operation_ids))
        self._durable_execution_gate = durable_execution_gate

    @property
    def apply_count(self) -> int:
        return self._root.mutation_count

    def invoke(
        self,
        *,
        payload: dict[str, object],
        fencing_token: int,
        started_was_durable: bool,
    ) -> dict[str, object]:
        self._root._require_open()
        if type(payload) is not dict:
            raise ReleaseSimulatorError("release payload is not exact")
        payload = thaw(payload)
        if type(payload) is not dict:
            raise ReleaseSimulatorError("release payload did not thaw exactly")
        operation = payload.get("operation_id")
        if operation == self._operation_ids["query"]:
            if set(payload) != {"operation_id"}:
                raise ReleaseSimulatorError("release query payload is not exact")
            state = self._root.state()
            body = {"result": "succeeded", "state_digest": _result_digest(state)}
            return {"result": "succeeded", "result_digest": _result_digest(body)}
        if operation == self._operation_ids["apply"]:
            expected_fields = {
                "operation_id", "expected_generation", "artifact_manifest",
                "artifact_bytes_base64",
            }
        elif operation == self._operation_ids["restore"]:
            expected_fields = {
                "operation_id", "expected_generation", "artifact_manifest",
                "artifact_bytes_base64", "original_claim_id",
                "original_receipt_digest",
            }
        else:
            raise ReleaseSimulatorError("release operation is not authorized")
        try:
            execution_binding = self._durable_execution_gate.consume(
                payload=payload,
                fencing_token=fencing_token,
                started_was_durable=started_was_durable,
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise ReleaseSimulatorError(
                "release mutation lacks an exact durable coordinator capability"
            ) from error
        if set(payload) != expected_fields:
            raise ReleaseSimulatorError("release mutation payload is not exact")
        expected_generation = payload["expected_generation"]
        if type(expected_generation) is not int:
            raise ReleaseSimulatorError("release expected generation is invalid")
        manifest = ReleaseArtifactManifest.from_dict(payload["artifact_manifest"])
        encoded = payload["artifact_bytes_base64"]
        if type(encoded) is not str or not encoded.isascii():
            raise ReleaseSimulatorError("release artifact bytes are not canonical base64")
        try:
            artifact_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ReleaseSimulatorError("release artifact bytes are not canonical base64") from error
        if base64.b64encode(artifact_bytes).decode("ascii") != encoded:
            raise ReleaseSimulatorError("release artifact bytes are not canonical base64")
        self._root._require_artifact_bytes(manifest, artifact_bytes)
        authorized = self._root.authorized_artifacts.get(manifest.manifest_digest)
        if authorized is None or authorized[0].to_dict() != manifest.to_dict() or authorized[1] != artifact_bytes:
            raise ReleaseSimulatorError("release artifact is not factory-issued for this session")
        state = self._root.state()
        if state["generation"] != expected_generation:
            raise ReleaseSimulatorError("release generation precondition changed")
        if expected_generation >= self._generation_limit:
            raise ReleaseSimulatorError("release generation limit reached")
        if operation == self._operation_ids["restore"]:
            binding = self._root.original_binding
            if (
                binding is None
                or payload["original_claim_id"] != binding["claim_id"]
                or payload["original_receipt_digest"] != binding["receipt_digest"]
                or expected_generation != binding["generation"]
                or manifest.to_dict() != self._root.baseline.to_dict()
                or artifact_bytes != self._root.baseline_artifact_bytes
                or state != binding["bound_state"]
            ):
                raise ReleaseSimulatorError(
                    "release restore is not bound to exact A and original receipt"
                )
        before_state = copy.deepcopy(state)
        self._root.fault(self._root.fault_roles["before_stage_write"])
        if (
            operation == self._operation_ids["restore"]
            and self._root.original_binding["mode"] == "partial"
        ):
            self._root._durable_unlink(self._root.names["stage"])
            self._root._durable_unlink(self._root.names["stage_artifact"])
            restored = copy.deepcopy(self._root.original_binding["before_state"])
            self._root._write_state(restored)
            self._root._record_phase(self._root.phase_roles["restored"])
            self._root.mutation_count += 1
            self._root.last_execution = {
                "action_id": execution_binding["action_id"],
                "claim_id": execution_binding["claim_id"],
                "prepared_action_digest": execution_binding["prepared_action_digest"],
                "operation_id": operation,
                "expected_generation": expected_generation,
                "artifact_manifest_digest": manifest.manifest_digest,
                "before_state": before_state,
                "after_state": copy.deepcopy(restored),
            }
            body = {
                "operation_id": operation,
                "generation": restored["generation"],
                "artifact_manifest_digest": manifest.manifest_digest,
                "effect": "applied",
            }
            return {
                "result": "succeeded", "effect": "applied",
                "result_digest": _result_digest(body),
            }
        self._root._durable_write(
            self._root.names["stage_artifact"], artifact_bytes, 0o600,
        )
        self._root._require_open()
        self._root._durable_write(
            self._root.names["stage"], _json_bytes(manifest.to_dict()), 0o600,
        )
        staged = dict(state)
        staged["staged_artifact_digest"] = manifest.manifest_digest
        self._root._write_state(staged)
        self._root._record_phase(self._root.phase_roles["staged"])
        self._root.last_execution = {
            "action_id": execution_binding["action_id"],
            "claim_id": execution_binding["claim_id"],
            "prepared_action_digest": execution_binding["prepared_action_digest"],
            "operation_id": operation,
            "expected_generation": expected_generation,
            "artifact_manifest_digest": manifest.manifest_digest,
            "before_state": before_state,
            "after_state": copy.deepcopy(staged),
        }
        self._root.fault(self._root.fault_roles["after_stage_durable"])
        self._root.fault(self._root.fault_roles["before_active_switch"])
        self._root._durable_write(
            self._root.names["active_artifact"], artifact_bytes, 0o600,
        )
        self._root._require_open()
        self._root._durable_write(
            self._root.names["active"], _json_bytes(manifest.to_dict()), 0o600,
        )
        switched = dict(staged)
        switched["generation"] = expected_generation + 1
        switched["active_artifact_digest"] = manifest.manifest_digest
        self._root._write_state(switched)
        phase = (
            self._root.phase_roles["restored"]
            if operation == self._operation_ids["restore"]
            else self._root.phase_roles["active"]
        )
        self._root._record_phase(phase)
        self._root.mutation_count += 1
        self._root.last_execution = {
            "action_id": execution_binding["action_id"],
            "claim_id": execution_binding["claim_id"],
            "prepared_action_digest": execution_binding["prepared_action_digest"],
            "operation_id": operation,
            "expected_generation": expected_generation,
            "artifact_manifest_digest": manifest.manifest_digest,
            "before_state": before_state,
            "after_state": copy.deepcopy(switched),
        }
        self._root.fault(self._root.fault_roles["after_active_switch_durable"])
        self._root.fault(self._root.fault_roles["before_health_observe"])
        body = {
            "operation_id": operation,
            "generation": switched["generation"],
            "artifact_manifest_digest": manifest.manifest_digest,
            "effect": "applied",
        }
        return {
            "result": "succeeded", "effect": "applied",
            "result_digest": _result_digest(body),
        }


class LocalReleaseObserver:
    """Independent filesystem-only observer used by execute and reconciliation."""

    is_test_double = True
    is_read_only_observer = True

    def __init__(self, root: _PrivateRoot, target: LocalReleaseTarget) -> None:
        self._root = root
        self.target_id = target.target_id
        self.target_digest = target.target_digest
        self.resource_id = target.resource_id
        self.capabilities = ("fresh-target-query", "local-release-query-v1")

    def observe(self) -> dict[str, object]:
        state = self._root.state()
        self._root.query_count += 1
        self._root.observation_revision += 1
        return {
            "target_id": self.target_id,
            "target_digest": self.target_digest,
            "resource_id": self.resource_id,
            "fresh": True,
            "observation_revision": self._root.observation_revision,
            "state": {
                "generation": state["generation"],
                "active_artifact_digest": state["active_artifact_digest"],
                "staged_artifact_digest": state["staged_artifact_digest"],
            },
        }


class LocalReleaseHealthObserver:
    """Read local simulator state only; this class has no network/process imports."""

    def __init__(
        self,
        root: _PrivateRoot,
        registry: ReleaseOperationsRegistry,
        *,
        task_id: str,
        target_id: str,
    ) -> None:
        self._root = root
        self._registry = registry
        self._task_id = task_id
        self._target_id = target_id

    def observe(
        self,
        *,
        expected_generation: int,
        expected_artifact_digest: str,
    ) -> dict[str, object]:
        state = self._root.state()
        predicate_roles = self._registry.predicate_roles
        artifact_current = state["active_artifact_digest"] == expected_artifact_digest
        generation_current = state["generation"] == expected_generation
        service_ready = artifact_current and generation_current
        values = {
            predicate_roles["artifact_current"]: artifact_current,
            predicate_roles["generation_current"]: generation_current,
            predicate_roles["service_ready"]: service_ready,
        }
        results, outcome = evaluate_health(self._registry, values)
        self._root.health_count += 1
        self._root._record_phase(self._root.phase_roles["health_observed"])
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "task_id": self._task_id,
            "target_id": self._target_id,
            "generation": state["generation"],
            "policy_digest": self._registry.policy["registry_digest"],
            "active_artifact_digest": state["active_artifact_digest"],
            "state_raw_sha256": self._root.state_raw_sha256(),
            "predicate_results": list(results),
            "outcome": outcome,
        }
        body["observation_digest"] = _semantic(body, "release-health-observation")
        return body


class LocalReleaseSimulatorSession:
    __slots__ = ("_root", "_factory", "target", "observer", "health_observer")

    def __init__(
        self,
        root: _PrivateRoot,
        factory: object,
        target: LocalReleaseTarget,
        observer: LocalReleaseObserver,
        health_observer: LocalReleaseHealthObserver,
    ) -> None:
        self._root = root
        self._factory = factory
        self.target = target
        self.observer = observer
        self.health_observer = health_observer

    def tree_digest(self) -> str:
        return self._root.tree_digest()

    @property
    def recovery_binding(self) -> ReleaseRecoveryBinding | None:
        if type(self._root) is _RetainedPrivateRoot:
            self._root._require_open()
            return self._root._recovery_binding
        return None

    def _release_snapshot(self) -> dict[str, object]:
        return self._root.snapshot()

    def close(self) -> None:
        self._root.close()

    def __enter__(self) -> "LocalReleaseSimulatorSession":
        self._root._require_open()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # type: ignore[no-untyped-def]
        del exc_type, exc, traceback
        self.close()


class _LocalReleaseSimulatorFactory:
    """Application-internal issuer of private simulator roots and capabilities."""

    def __init__(
        self,
        registry: ReleaseOperationsRegistry,
        *,
        currentness_check: Callable[[], None],
        durable_execution_gate: object,
        issuer: object,
    ) -> None:
        if (
            type(registry) is not ReleaseOperationsRegistry
            or not callable(currentness_check)
            or durable_execution_gate is None
            or issuer is None
        ):
            raise ReleaseSimulatorError("release simulator authority is missing or forged")
        self._registry = registry
        self._currentness_check = currentness_check
        self._durable_execution_gate = durable_execution_gate
        self._issuer = issuer

    def create(
        self,
        *,
        task_id: str,
        fixture_id: str,
        target_id: str,
        resource_id: str,
        baseline_manifest: ReleaseArtifactManifest,
        baseline_artifact_bytes: bytes,
        authorized_artifacts: Sequence[tuple[ReleaseArtifactManifest, bytes]],
        fault_hook: Callable[[str], None] = lambda _step: None,
        retained_lease: _RetainedRootLease | None = None,
        recovery_binding: ReleaseRecoveryBinding | None = None,
        max_read_bytes: int | None = None,
        retained_close_check: Callable[[], None] | None = None,
    ) -> LocalReleaseSimulatorSession:
        if (
            type(task_id) is not str or not task_id
            or type(target_id) is not str or not target_id
            or type(resource_id) is not str or not resource_id
            or type(baseline_manifest) is not ReleaseArtifactManifest
            or type(baseline_artifact_bytes) is not bytes
            or not callable(fault_hook)
        ):
            raise ReleaseSimulatorError("release simulator issuance input is invalid")
        issued_artifacts: dict[str, tuple[ReleaseArtifactManifest, bytes]] = {}
        for manifest, body in authorized_artifacts:
            if type(manifest) is not ReleaseArtifactManifest or type(body) is not bytes:
                raise ReleaseSimulatorError("release authorized artifact is invalid")
            _PrivateRoot._require_artifact_bytes(manifest, body)
            if manifest.manifest_digest in issued_artifacts:
                raise ReleaseSimulatorError("release authorized artifact aliases")
            issued_artifacts[manifest.manifest_digest] = (manifest, body)
        if issued_artifacts.get(baseline_manifest.manifest_digest) != (
            baseline_manifest, baseline_artifact_bytes,
        ):
            raise ReleaseSimulatorError("release baseline is not in the authorized closure")
        fixture = thaw(self._registry.fixture(fixture_id))
        if type(fixture) is not dict:
            raise AssertionError("release fixture did not thaw")
        if fixture["expected_rollback_artifact_id"] != baseline_manifest.artifact_id:
            raise ReleaseSimulatorError("release baseline is not the configured rollback artifact")
        operation_ids = dict(self._registry.operation_roles)
        root_type = _PrivateRoot if retained_lease is None else _RetainedPrivateRoot
        retained_args = {} if retained_lease is None else {
            "lease": retained_lease, "binding": recovery_binding, "max_read_bytes": max_read_bytes,
            "close_check": retained_close_check}
        root = root_type(
            **retained_args,
            target_id=target_id,
            fixture=fixture,
            baseline=baseline_manifest,
            baseline_artifact_bytes=baseline_artifact_bytes,
            authorized_artifacts=issued_artifacts,
            fault_hook=fault_hook,
            currentness_check=self._currentness_check,
            phase_roles=dict(self._registry.phase_roles),
            fault_roles=dict(self._registry.fault_roles),
        )
        target_digest = semantic_digest(
            {"fixture_id": fixture_id, "resource_id": resource_id, "target_id": target_id},
            contract_type="urn:gew:contract:local-release-target",
            projection_id="urn:gew:digest-projection:local-release-target:1.0.0",
            schema_id="urn:gew:schema:local-release-target:1.0.0",
        )
        if retained_lease is not None:
            target_digest = recovery_binding.target_digest()
        generation_limit = self._registry.policy["deployment_policy"]["generation_limit"]
        target = LocalReleaseTarget(
            root,
            target_id=target_id,
            target_digest=target_digest,
            resource_id=resource_id,
            generation_limit=generation_limit,
            operation_ids=operation_ids,
            durable_execution_gate=self._durable_execution_gate,
        )
        return LocalReleaseSimulatorSession(
            root,
            self._issuer,
            target,
            LocalReleaseObserver(root, target),
            LocalReleaseHealthObserver(
                root, self._registry, task_id=task_id, target_id=target_id,
            ),
        )
