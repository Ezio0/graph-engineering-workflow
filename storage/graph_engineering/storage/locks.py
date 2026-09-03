"""PID/fork-safe process mutex + POSIX record lock registry."""

from __future__ import annotations

from dataclasses import dataclass
import fcntl
import hashlib
import os
import pathlib
import stat
import threading
import time
from typing import ClassVar, Final

from .connection import BoundDirectory, ConnectionFactory
from .errors import (
    LockUnavailableError,
    RepositoryConfigurationError,
    RepositoryProcessError,
)
from .policy import RepositoryPolicy


class _ProcessGate:
    def __init__(self) -> None:
        self.condition = threading.Condition()
        self.readers: set[int] = set()
        self.writer: int | None = None

    def try_acquire(self, mode: str) -> bool:
        identity = threading.get_ident()
        with self.condition:
            if identity in self.readers or self.writer == identity:
                raise RepositoryConfigurationError("lock acquisition is not reentrant")
            if mode == "shared" and self.writer is None:
                self.readers.add(identity)
                return True
            if mode == "exclusive" and self.writer is None and not self.readers:
                self.writer = identity
                return True
            return False

    def release(self, mode: str) -> None:
        identity = threading.get_ident()
        with self.condition:
            if mode == "shared":
                if identity not in self.readers:
                    raise RepositoryProcessError("thread does not own shared lock")
                self.readers.remove(identity)
            else:
                if self.writer != identity:
                    raise RepositoryProcessError("thread does not own exclusive lock")
                self.writer = None
            self.condition.notify_all()

    def empty(self) -> bool:
        with self.condition:
            return self.writer is None and not self.readers

    def count(self) -> int:
        with self.condition:
            return len(self.readers) + (1 if self.writer is not None else 0)


@dataclass(slots=True)
class _Entry:
    lock_id: str
    path: pathlib.Path
    directory: BoundDirectory
    filename: str
    descriptor: int
    device: int
    inode: int
    gate: _ProcessGate
    transition_guard: threading.Lock
    os_mode: str | None = None


@dataclass(frozen=True, slots=True)
class LockToken:
    lock_ids: tuple[str, ...]
    mode: str
    pid: int
    generation: int


class LockedFileRegistry:
    """The only descriptor owner for stable repository lock inodes."""

    INSTALLATION_ID: Final[str] = "installation-maintenance"
    OBJECT_ID: Final[str] = "object-maintenance"
    _ACTIVE_GUARD: ClassVar[threading.Lock] = threading.Lock()
    _ACTIVE_ROOTS: ClassVar[dict[tuple[int, str], LockedFileRegistry]] = {}

    def __init__(self, factory: ConnectionFactory) -> None:
        self._factory = factory
        self._root = factory.data_root
        self._policy = factory.policy
        self._lock_root = self._root / self._policy.locks_directory
        self._resource_root = self._lock_root / self._policy.resources_directory
        self._lock_directory = factory.bind_directory(self._policy.locks_directory)
        try:
            self._resource_directory = factory.bind_directory(
                self._policy.locks_directory,
                self._policy.resources_directory,
            )
        except BaseException:
            self._lock_directory.close_chain()
            raise
        self._pid = os.getpid()
        self._generation = 0
        self._poisoned = False
        self._closed = False
        self._entries: dict[str, _Entry] = {}
        self._thread_tokens: dict[int, list[LockToken]] = {}
        self._registry_guard = threading.Lock()
        key = (self._pid, self._root.as_posix())
        with self._ACTIVE_GUARD:
            existing = self._ACTIVE_ROOTS.get(key)
            if existing is not None and not existing._closed:
                self._resource_directory.close_chain()
                self._lock_directory.close_chain()
                raise RepositoryConfigurationError(
                    "one PID cannot own multiple lock registries for one repository"
                )
            self._ACTIVE_ROOTS[key] = self
        os.register_at_fork(after_in_child=self._after_fork_child)

    def _after_fork_child(self) -> None:
        for entry in self._entries.values():
            try:
                os.close(entry.descriptor)
            except OSError:
                pass
        self._entries.clear()
        self._thread_tokens.clear()
        self._resource_directory.close_chain()
        self._lock_directory.close_chain()
        type(self)._ACTIVE_ROOTS = {}
        type(self)._ACTIVE_GUARD = threading.Lock()
        self._pid = os.getpid()
        self._generation += 1
        self._poisoned = True
        self._registry_guard = threading.Lock()

    def reinitialize_after_fork(self) -> None:
        if os.getpid() != self._pid or not self._poisoned:
            raise RepositoryProcessError("registry is not a poisoned fork child")
        lock_directory = self._factory.bind_directory(self._policy.locks_directory)
        try:
            resource_directory = self._factory.bind_directory(
                self._policy.locks_directory,
                self._policy.resources_directory,
            )
        except BaseException:
            lock_directory.close_chain()
            raise
        key = (self._pid, self._root.as_posix())
        with self._ACTIVE_GUARD:
            if key in self._ACTIVE_ROOTS:
                resource_directory.close_chain()
                lock_directory.close_chain()
                raise RepositoryConfigurationError("fork child lock registry is already active")
            self._ACTIVE_ROOTS[key] = self
        self._lock_directory = lock_directory
        self._resource_directory = resource_directory
        self._poisoned = False

    def _check(self) -> None:
        if self._closed:
            raise RepositoryProcessError("lock registry is closed")
        if os.getpid() != self._pid or self._poisoned:
            raise RepositoryProcessError("lock registry crossed or has not recovered from fork")

    def _path_for(self, lock_id: str) -> pathlib.Path:
        if lock_id == self.INSTALLATION_ID:
            return self._lock_root / "installation-maintenance.lock"
        if lock_id == self.OBJECT_ID:
            return self._lock_root / "object-maintenance.lock"
        if lock_id.startswith("publication:"):
            identity = lock_id.removeprefix("publication:")
            if not identity:
                raise RepositoryConfigurationError("empty publication identity")
            filename = "publication-" + hashlib.sha256(identity.encode("utf-8")).hexdigest() + ".lock"
            return self._resource_root / filename
        if not lock_id.startswith("resource:"):
            raise RepositoryConfigurationError("unknown lock identity")
        resource = lock_id.removeprefix("resource:")
        if not resource:
            raise RepositoryConfigurationError("empty canonical resource identity")
        filename = hashlib.sha256(resource.encode("utf-8")).hexdigest() + ".lock"
        return self._resource_root / filename

    def _location_for(self, lock_id: str) -> tuple[BoundDirectory, str]:
        if lock_id == self.INSTALLATION_ID:
            return self._lock_directory, "installation-maintenance.lock"
        if lock_id == self.OBJECT_ID:
            return self._lock_directory, "object-maintenance.lock"
        if lock_id.startswith("publication:"):
            identity = lock_id.removeprefix("publication:")
            if not identity:
                raise RepositoryConfigurationError("empty publication identity")
            filename = "publication-" + hashlib.sha256(identity.encode("utf-8")).hexdigest() + ".lock"
            return self._resource_directory, filename
        if not lock_id.startswith("resource:"):
            raise RepositoryConfigurationError("unknown lock identity")
        resource = lock_id.removeprefix("resource:")
        if not resource:
            raise RepositoryConfigurationError("empty canonical resource identity")
        return self._resource_directory, hashlib.sha256(resource.encode("utf-8")).hexdigest() + ".lock"

    def _open_entry(self, lock_id: str) -> _Entry:
        path = self._path_for(lock_id)
        directory, filename = self._location_for(lock_id)
        try:
            descriptor = directory.open_file(
                filename,
                os.O_RDWR | os.O_CREAT | os.O_EXCL,
                self._policy.lock_mode,
            )
            created = True
        except FileExistsError:
            try:
                descriptor = directory.open_file(filename, os.O_RDWR)
                created = False
            except OSError as error:
                raise RepositoryConfigurationError("cannot open stable lock inode") from error
        except OSError as error:
            raise RepositoryConfigurationError("cannot open stable lock inode") from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or (not created and stat.S_IMODE(metadata.st_mode) != self._policy.lock_mode)
        ):
            os.close(descriptor)
            raise RepositoryConfigurationError("lock inode owner, type, or mode is invalid")
        if created:
            os.fchmod(descriptor, self._policy.lock_mode)
            metadata = os.fstat(descriptor)
            if stat.S_IMODE(metadata.st_mode) != self._policy.lock_mode:
                os.close(descriptor)
                raise RepositoryConfigurationError("new lock inode mode is invalid")
        return _Entry(
            lock_id, path, directory, filename, descriptor, metadata.st_dev, metadata.st_ino,
            _ProcessGate(), threading.Lock(),
        )

    def _entry(self, lock_id: str) -> _Entry:
        with self._registry_guard:
            entry = self._entries.get(lock_id)
            if entry is None:
                entry = self._open_entry(lock_id)
                self._entries[lock_id] = entry
            return entry

    @staticmethod
    def _verify_inode(entry: _Entry) -> None:
        descriptor_stat = os.fstat(entry.descriptor)
        try:
            path_stat = entry.directory.stat(entry.filename)
        except FileNotFoundError as error:
            raise RepositoryProcessError("stable lock inode was unlinked") from error
        if (
            stat.S_ISLNK(path_stat.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or descriptor_stat.st_nlink != 1
            or path_stat.st_nlink != 1
            or (descriptor_stat.st_dev, descriptor_stat.st_ino) != (entry.device, entry.inode)
            or (path_stat.st_dev, path_stat.st_ino) != (entry.device, entry.inode)
        ):
            raise RepositoryProcessError("stable lock inode was replaced")

    def acquire(
        self,
        lock_ids: tuple[str, ...],
        mode: str,
    ) -> LockToken:
        self._check()
        if mode not in {"shared", "exclusive"}:
            raise RepositoryConfigurationError("lock mode is invalid")
        if not lock_ids or len(set(lock_ids)) != len(lock_ids):
            raise RepositoryConfigurationError("lock identity set is empty or duplicated")
        if tuple(sorted(lock_ids)) != lock_ids:
            raise RepositoryConfigurationError("lock identities are not canonical sorted")
        ranks = tuple(self._rank(lock_id) for lock_id in lock_ids)
        thread_tokens = self._thread_tokens.get(threading.get_ident(), [])
        if thread_tokens:
            held_ids = tuple(
                lock_id for token in thread_tokens for lock_id in token.lock_ids
            )
            previous_rank = max(self._rank(lock_id) for lock_id in held_ids)
            if min(ranks) < previous_rank:
                raise RepositoryConfigurationError("global repository lock order was violated")
            held_resources = tuple(
                lock_id for lock_id in held_ids if lock_id.startswith("resource:")
            )
            new_resources = tuple(
                lock_id for lock_id in lock_ids if lock_id.startswith("resource:")
            )
            if (
                held_resources
                and new_resources
                and min(new_resources) <= max(held_resources)
            ):
                raise RepositoryConfigurationError(
                    "resource locks must increase across the complete held sequence",
                )
        acquired: list[_Entry] = []
        try:
            for lock_id in lock_ids:
                entry = self._entry(lock_id)
                self._verify_inode(entry)
                process_acquired = False
                with entry.transition_guard:
                    for delay_ms in self._policy.busy_retry_delays_ms:
                        if delay_ms:
                            time.sleep(delay_ms / 1000)
                        if entry.gate.try_acquire(mode):
                            process_acquired = True
                            break
                    if not process_acquired:
                        raise LockUnavailableError("process-local lock retry budget exhausted")
                    if entry.gate.count() == 1:
                        operation = fcntl.LOCK_SH if mode == "shared" else fcntl.LOCK_EX
                        os_acquired = False
                        for delay_ms in self._policy.busy_retry_delays_ms:
                            if delay_ms:
                                time.sleep(delay_ms / 1000)
                            try:
                                fcntl.lockf(entry.descriptor, operation | fcntl.LOCK_NB)
                                os_acquired = True
                                entry.os_mode = mode
                                break
                            except BlockingIOError:
                                continue
                        if not os_acquired:
                            entry.gate.release(mode)
                            raise LockUnavailableError("OS lock retry budget exhausted")
                    elif entry.os_mode != mode:
                        entry.gate.release(mode)
                        raise RepositoryProcessError("process and OS lock modes diverged")
                acquired.append(entry)
            token = LockToken(lock_ids, mode, self._pid, self._generation)
            self._thread_tokens.setdefault(threading.get_ident(), []).append(token)
            return token
        except BaseException:
            for entry in reversed(acquired):
                self._release_entry(entry, mode)
            raise

    def acquire_installation(self, mode: str) -> LockToken:
        return self.acquire((self.INSTALLATION_ID,), mode)

    def acquire_object(self, mode: str) -> LockToken:
        return self.acquire((self.OBJECT_ID,), mode)

    def acquire_publication(self, identity: str) -> LockToken:
        if type(identity) is not str or not identity:
            raise RepositoryConfigurationError("publication identity is invalid")
        return self.acquire((f"publication:{identity}",), "exclusive")

    def acquire_resources(self, resources: tuple[str, ...]) -> LockToken:
        if any(type(item) is not str or not item for item in resources):
            raise RepositoryConfigurationError("canonical resource ID is invalid")
        canonical = tuple(sorted(set(resources)))
        if len(canonical) != len(resources):
            raise RepositoryConfigurationError("canonical resource IDs contain duplicates")
        return self.acquire(tuple(f"resource:{item}" for item in canonical), "exclusive")

    def resources_held_by_current_thread(self, resources: tuple[str, ...]) -> bool:
        """Return whether this thread owns the exact exclusive resource fence."""

        if (
            type(resources) is not tuple
            or not resources
            or tuple(sorted(set(resources))) != resources
        ):
            return False
        expected = tuple(f"resource:{item}" for item in resources)
        tokens = self._thread_tokens.get(threading.get_ident(), ())
        return any(
            token.mode == "exclusive"
            and all(lock_id in token.lock_ids for lock_id in expected)
            for token in tokens
        )

    def installation_held_by_current_thread(self) -> bool:
        self._check()
        tokens = self._thread_tokens.get(threading.get_ident(), ())
        held = any(self.INSTALLATION_ID in token.lock_ids for token in tokens)
        if held:
            self._verify_inode(self._entries[self.INSTALLATION_ID])
        return held

    @classmethod
    def _rank(cls, lock_id: str) -> int:
        if lock_id == cls.INSTALLATION_ID:
            return 0
        if lock_id.startswith("resource:"):
            return 1
        if lock_id.startswith("publication:"):
            return 2
        if lock_id == cls.OBJECT_ID:
            return 3
        raise RepositoryConfigurationError("unknown lock identity")

    def _release_entry(self, entry: _Entry, mode: str) -> None:
        self._verify_inode(entry)
        with entry.transition_guard:
            entry.gate.release(mode)
            if entry.gate.empty():
                fcntl.lockf(entry.descriptor, fcntl.LOCK_UN)
                entry.os_mode = None

    def release(self, token: LockToken) -> None:
        self._check()
        if token.pid != self._pid or token.generation != self._generation:
            raise RepositoryProcessError("lock token belongs to another PID or generation")
        tokens = self._thread_tokens.get(threading.get_ident(), [])
        if not tokens or tokens[-1] is not token:
            raise RepositoryProcessError("locks must be released by owner in global reverse order")
        for lock_id in reversed(token.lock_ids):
            entry = self._entries.get(lock_id)
            if entry is None:
                raise RepositoryProcessError("lock token references unopened inode")
            self._release_entry(entry, token.mode)
        tokens.pop()
        if not tokens:
            self._thread_tokens.pop(threading.get_ident(), None)

    def close(self) -> None:
        self._check()
        if self._thread_tokens or any(not entry.gate.empty() for entry in self._entries.values()):
            raise RepositoryProcessError("cannot close registry with held locks")
        for entry in self._entries.values():
            self._verify_inode(entry)
            os.close(entry.descriptor)
        self._entries.clear()
        self._resource_directory.close_chain()
        self._lock_directory.close_chain()
        self._closed = True
        key = (self._pid, self._root.as_posix())
        with self._ACTIVE_GUARD:
            if self._ACTIVE_ROOTS.get(key) is self:
                self._ACTIVE_ROOTS.pop(key)
