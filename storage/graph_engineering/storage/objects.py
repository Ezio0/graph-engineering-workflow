"""Verified filesystem content-addressed object repository."""

from __future__ import annotations

import os
import pathlib
import secrets
import stat
from typing import Callable

from .codec import object_digest, require_object_digest
from .connection import BoundDirectory, ConnectionFactory
from .errors import ObjectIntegrityError, RepositoryConfigurationError, RepositoryConflictError
from .locks import LockedFileRegistry


FaultHook = Callable[[str], None]


def _no_fault(_step: str) -> None:
    return


class ObjectRepository:
    def __init__(
        self,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
        *,
        fault_hook: FaultHook = _no_fault,
    ) -> None:
        self._factory = factory
        self._locks = locks
        self._policy = factory.policy
        self._objects = factory.data_root / self._policy.objects_directory
        self._staging = factory.data_root / self._policy.staging_directory
        self._objects_directory = factory.bind_directory(self._policy.objects_directory)
        try:
            self._staging_directory = factory.bind_directory(self._policy.staging_directory)
        except BaseException:
            self._objects_directory.close_chain()
            raise
        self._closed = False
        self._fault = fault_hook

    @staticmethod
    def digest(body: bytes) -> str:
        if type(body) is not bytes:
            raise ObjectIntegrityError("object body must be exact bytes")
        return object_digest(body)

    def _path(self, digest: str) -> pathlib.Path:
        require_object_digest(digest)
        hexadecimal = digest.removeprefix("sha256:")
        split = self._policy.object_fanout_chars
        return self._objects / hexadecimal[:split] / hexadecimal[split:]

    def _object_names(self, digest: str) -> tuple[str, str]:
        require_object_digest(digest)
        hexadecimal = digest.removeprefix("sha256:")
        split = self._policy.object_fanout_chars
        return hexadecimal[:split], hexadecimal[split:]

    def _object_directory(self, digest: str, *, create: bool) -> BoundDirectory:
        fanout, _filename = self._object_names(digest)
        try:
            return self._objects_directory.open_child(
                fanout,
                create=create,
                mode=self._policy.root_mode,
            )
        except RepositoryConfigurationError as error:
            raise ObjectIntegrityError(
                "object fanout directory is missing or untrusted",
            ) from error

    def _verify_object(self, expected: str, size: int | None = None) -> bytes:
        directory = self._object_directory(expected, create=False)
        try:
            _fanout, filename = self._object_names(expected)
            descriptor = self._open_verified_descriptor(
                directory,
                filename,
                expected,
                size,
            )
            try:
                body = self._verify_descriptor_binding(
                    directory,
                    filename,
                    descriptor,
                    expected,
                    size,
                )
            finally:
                os.close(descriptor)
        except FileNotFoundError as error:
            raise ObjectIntegrityError("referenced object file is missing") from error
        except OSError as error:
            raise ObjectIntegrityError(
                "referenced object file is not a no-follow regular file",
            ) from error
        finally:
            directory.close()
        if (size is not None and len(body) != size) or object_digest(body) != expected:
            raise ObjectIntegrityError("object size or digest mismatch")
        return body

    @staticmethod
    def _inode(metadata: os.stat_result) -> tuple[int, int]:
        return metadata.st_dev, metadata.st_ino

    @staticmethod
    def _read_descriptor(descriptor: int) -> bytes:
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def _open_verified_descriptor(
        self,
        directory: BoundDirectory,
        filename: str,
        expected: str,
        size: int | None,
        *,
        expected_inode: tuple[int, int] | None = None,
    ) -> int:
        try:
            name_metadata = directory.stat(filename)
            descriptor = directory.open_file(filename, os.O_RDONLY)
        except FileNotFoundError as error:
            raise ObjectIntegrityError("referenced object file is missing") from error
        except OSError as error:
            raise ObjectIntegrityError(
                "referenced object file is not a no-follow regular file",
            ) from error
        try:
            descriptor_metadata = os.fstat(descriptor)
            if (
                stat.S_ISLNK(name_metadata.st_mode)
                or not stat.S_ISREG(name_metadata.st_mode)
                or not stat.S_ISREG(descriptor_metadata.st_mode)
                or name_metadata.st_uid != os.getuid()
                or stat.S_IMODE(name_metadata.st_mode) != self._policy.file_mode
                or self._inode(name_metadata) != self._inode(descriptor_metadata)
                or (
                    expected_inode is not None
                    and self._inode(descriptor_metadata) != expected_inode
                )
            ):
                raise ObjectIntegrityError("object file inode or mode binding is invalid")
            body = self._read_descriptor(descriptor)
            if (size is not None and len(body) != size) or object_digest(body) != expected:
                raise ObjectIntegrityError("object size or digest mismatch")
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _verify_descriptor_binding(
        self,
        directory: BoundDirectory,
        filename: str,
        descriptor: int,
        expected: str,
        size: int | None,
    ) -> bytes:
        try:
            name_metadata = directory.stat(filename)
        except FileNotFoundError as error:
            raise ObjectIntegrityError("published object name disappeared") from error
        descriptor_metadata = os.fstat(descriptor)
        if (
            self._inode(name_metadata) != self._inode(descriptor_metadata)
            or not stat.S_ISREG(name_metadata.st_mode)
            or name_metadata.st_uid != os.getuid()
            or stat.S_IMODE(name_metadata.st_mode) != self._policy.file_mode
        ):
            raise ObjectIntegrityError("published object name no longer binds verified inode")
        body = self._read_descriptor(descriptor)
        if (size is not None and len(body) != size) or object_digest(body) != expected:
            raise ObjectIntegrityError("published object changed after verification")
        return body

    def _verify_file(self, path: pathlib.Path, expected: str, size: int | None = None) -> bytes:
        if path != self._path(expected):
            raise ObjectIntegrityError("object path does not match its digest")
        return self._verify_object(expected, size)

    def _quarantine_existing_metadata(self, object_digest_value: str) -> None:
        with self._factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "UPDATE objects SET state='quarantined' "
                    "WHERE digest=? AND state='available'",
                    (object_digest_value,),
                )

    def _observed_name_inode(
        self,
        directory: BoundDirectory,
        filename: str,
    ) -> tuple[int, int] | None:
        try:
            return self._inode(directory.stat(filename))
        except FileNotFoundError:
            return None

    def _unlink_observed_name(
        self,
        directory: BoundDirectory,
        filename: str,
        observed_inode: tuple[int, int] | None,
    ) -> None:
        if observed_inode is None:
            return
        try:
            current_inode = self._inode(directory.stat(filename))
        except FileNotFoundError:
            return
        if current_inode == observed_inode:
            directory.unlink(filename)

    def put_verified(self, body: bytes, object_digest_value: str) -> None:
        self._factory.require_mutation_authority()
        if type(body) is not bytes or object_digest(body) != require_object_digest(object_digest_value):
            raise ObjectIntegrityError("object body does not match declared digest")
        self._objects_directory.verify()
        self._staging_directory.verify()
        installation = None
        if not self._locks.installation_held_by_current_thread():
            installation = self._locks.acquire_installation("shared")
        try:
            publication_lock = self._locks.acquire_publication(object_digest_value)
            try:
                object_lock = self._locks.acquire_object("shared")
            except BaseException:
                self._locks.release(publication_lock)
                raise
            try:
                self._objects_directory.verify()
                self._staging_directory.verify()
                _fanout, filename = self._object_names(object_digest_value)
                object_directory = self._object_directory(object_digest_value, create=True)
                staging_descriptor: int | None = None
                final_descriptor: int | None = None
                write_id: str | None = None
                cleanup_staging = False
                cleanup_final = False
                cleanup_final_inode: tuple[int, int] | None = None
                metadata_committed = False
                try:
                    self._fault("object.before_staging_open")
                    write_id = secrets.token_hex(16)
                    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
                    staging_descriptor = self._staging_directory.open_file(
                        write_id, flags, self._policy.file_mode,
                    )
                    view = memoryview(body)
                    offset = 0
                    while offset < len(body):
                        written = os.write(staging_descriptor, view[offset:])
                        if written <= 0:
                            raise ObjectIntegrityError(
                                "object staging write made no progress",
                            )
                        offset += written
                    os.fsync(staging_descriptor)
                    self._fault("object.after_file_fsync")
                    staged_metadata = os.fstat(staging_descriptor)
                    if staged_metadata.st_size != len(body):
                        raise ObjectIntegrityError("object staging size mismatch")
                    self._staging_directory.fsync()
                    self._fault("object.after_staging_directory_fsync")
                    cleanup_staging = True
                    current_staging = self._staging_directory.stat(write_id)
                    if self._inode(current_staging) != self._inode(staged_metadata):
                        raise ObjectIntegrityError(
                            "staging name no longer binds the verified descriptor",
                        )
                    published_new = False
                    try:
                        self._staging_directory.link(write_id, object_directory, filename)
                        published_new = True
                        self._fault("object.after_publication")
                    except FileExistsError:
                        published_new = False
                    try:
                        final_descriptor = self._open_verified_descriptor(
                            object_directory,
                            filename,
                            object_digest_value,
                            len(body),
                            expected_inode=(
                                self._inode(staged_metadata) if published_new else None
                            ),
                        )
                    except BaseException:
                        cleanup_final = True
                        cleanup_final_inode = self._observed_name_inode(
                            object_directory,
                            filename,
                        )
                        self._quarantine_existing_metadata(object_digest_value)
                        raise
                    object_directory.fsync()
                    self._fault("object.after_object_directory_fsync")
                    try:
                        self._verify_descriptor_binding(
                            object_directory,
                            filename,
                            final_descriptor,
                            object_digest_value,
                            len(body),
                        )
                    except (ObjectIntegrityError, RepositoryConfigurationError):
                        cleanup_final = True
                        cleanup_final_inode = self._observed_name_inode(
                            object_directory,
                            filename,
                        )
                        self._quarantine_existing_metadata(object_digest_value)
                        raise
                    transaction_binding_mismatch = False
                    try:
                        with self._factory.open("application") as connection:
                            with connection.transaction():
                                try:
                                    self._verify_descriptor_binding(
                                        object_directory,
                                        filename,
                                        final_descriptor,
                                        object_digest_value,
                                        len(body),
                                    )
                                    self._fault("object.before_metadata_commit")
                                    self._verify_descriptor_binding(
                                        object_directory,
                                        filename,
                                        final_descriptor,
                                        object_digest_value,
                                        len(body),
                                    )
                                except (ObjectIntegrityError, RepositoryConfigurationError):
                                    cleanup_final = True
                                    cleanup_final_inode = self._observed_name_inode(
                                        object_directory,
                                        filename,
                                    )
                                    transaction_binding_mismatch = True
                                    raise
                                existing = connection.execute(
                                    "SELECT size,state FROM objects WHERE digest=?",
                                    (object_digest_value,),
                                ).fetchone()
                                if existing is not None and (
                                    existing[0] != len(body) or existing[1] == "quarantined"
                                ):
                                    raise ObjectIntegrityError("object metadata conflicts with body")
                                connection.execute(
                                    "INSERT INTO objects(digest,size,state,write_id) "
                                    "VALUES(?,?,'available',?) ON CONFLICT(digest) "
                                    "DO UPDATE SET state='available',write_id=excluded.write_id",
                                    (object_digest_value, len(body), write_id),
                                )
                    except BaseException:
                        if transaction_binding_mismatch:
                            self._quarantine_existing_metadata(object_digest_value)
                        raise
                    metadata_committed = True
                    self._fault("object.after_metadata_commit")
                    try:
                        self._verify_descriptor_binding(
                            object_directory,
                            filename,
                            final_descriptor,
                            object_digest_value,
                            len(body),
                        )
                    except BaseException:
                        cleanup_final = True
                        cleanup_final_inode = self._observed_name_inode(
                            object_directory,
                            filename,
                        )
                        self._quarantine_existing_metadata(object_digest_value)
                        metadata_committed = False
                        raise
                finally:
                    if cleanup_staging and write_id is not None:
                        try:
                            self._staging_directory.unlink(write_id)
                        except FileNotFoundError:
                            pass
                        self._staging_directory.fsync()
                    if cleanup_final:
                        self._unlink_observed_name(
                            object_directory,
                            filename,
                            cleanup_final_inode,
                        )
                        object_directory.fsync()
                    if final_descriptor is not None:
                        os.close(final_descriptor)
                    if staging_descriptor is not None:
                        os.close(staging_descriptor)
                    object_directory.close()
                if not metadata_committed:
                    raise ObjectIntegrityError("object publication did not commit verified metadata")
            finally:
                try:
                    self._locks.release(object_lock)
                finally:
                    self._locks.release(publication_lock)
        finally:
            if installation is not None:
                self._locks.release(installation)

    def get(self, object_digest_value: str, *, require_referenced: bool = True) -> bytes:
        require_object_digest(object_digest_value)
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("shared")
            try:
                with self._factory.open("application") as connection:
                    row = connection.execute(
                        "SELECT size,state FROM objects WHERE digest=?",
                        (object_digest_value,),
                    ).fetchone()
                    if row is None or row[1] != "available":
                        raise ObjectIntegrityError("object is not available")
                    if require_referenced:
                        referenced = connection.execute(
                            "SELECT 1 FROM object_references WHERE digest=? LIMIT 1",
                            (object_digest_value,),
                        ).fetchone()
                        if referenced is None:
                            raise ObjectIntegrityError("object has no committed reference")
                    return self._verify_object(object_digest_value, row[0])
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def quarantine(self, object_digest_value: str) -> None:
        self._factory.require_mutation_authority()
        require_object_digest(object_digest_value)
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("exclusive")
            try:
                with self._factory.open("application") as connection:
                    with connection.transaction():
                        changed = connection.execute(
                            "UPDATE objects SET state='quarantined' WHERE digest=? AND state='available'",
                            (object_digest_value,),
                        ).rowcount
                        if changed != 1:
                            raise ObjectIntegrityError("object cannot be quarantined")
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def _eligible(self, connection: object, digest: str) -> bool:
        execute = connection.execute  # type: ignore[attr-defined]
        blockers = (
            "SELECT 1 FROM object_references WHERE digest=? LIMIT 1",
            "SELECT 1 FROM export_holds WHERE digest=? LIMIT 1",
            "SELECT 1 FROM claim_objects co JOIN claims c ON c.claim_id=co.claim_id "
            "WHERE co.digest=? AND c.state='unresolved' LIMIT 1",
        )
        return all(execute(query, (digest,)).fetchone() is None for query in blockers)

    def purge(self, object_digest_value: str) -> bool:
        self._factory.require_mutation_authority()
        require_object_digest(object_digest_value)
        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("exclusive")
            try:
                with self._factory.open("application") as connection:
                    with connection.transaction():
                        row = connection.execute(
                            "SELECT state FROM objects WHERE digest=?",
                            (object_digest_value,),
                        ).fetchone()
                        if row is None or row[0] not in {"available", "deleting"}:
                            return False
                        if not self._eligible(connection, object_digest_value):
                            return False
                        connection.execute(
                            "UPDATE objects SET state='deleting' WHERE digest=?",
                            (object_digest_value,),
                        )
                self._fault("purge.after_deleting_commit")
                object_directory = self._object_directory(object_digest_value, create=False)
                _fanout, filename = self._object_names(object_digest_value)
                try:
                    object_directory.unlink(filename)
                    object_directory.fsync()
                except FileNotFoundError:
                    pass
                finally:
                    object_directory.close()
                self._fault("purge.after_directory_fsync")
                with self._factory.open("application") as connection:
                    with connection.transaction():
                        if not self._eligible(connection, object_digest_value):
                            raise RepositoryConflictError("object gained a protected reference while deleting")
                        connection.execute(
                            "UPDATE objects SET state='deleted' WHERE digest=? AND state='deleting'",
                            (object_digest_value,),
                        )
                return True
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def recover_deleting(self) -> tuple[str, ...]:
        self._factory.require_mutation_authority()
        with self._factory.open("application") as connection:
            rows = connection.execute(
                "SELECT digest FROM objects WHERE state='deleting' ORDER BY digest"
            ).fetchall()
        recovered = []
        for row in rows:
            if self.purge(row[0]):
                recovered.append(row[0])
        return tuple(recovered)

    def recover_untrusted(self) -> tuple[str, ...]:
        self._factory.require_mutation_authority()
        """Remove crash-left staging files and unreferenced physical files absent from metadata."""

        installation = self._locks.acquire_installation("shared")
        try:
            object_lock = self._locks.acquire_object("exclusive")
            try:
                removed: list[str] = []
                for name in self._staging_directory.names():
                    metadata = self._staging_directory.stat(name)
                    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                        raise ObjectIntegrityError("staging recovery encountered an untrusted node")
                    self._staging_directory.unlink(name)
                    removed.append(f"staging:{name}")
                self._staging_directory.fsync()
                with self._factory.open("application") as connection:
                    rows = connection.execute(
                        "SELECT digest FROM objects WHERE state!='deleted' ORDER BY digest"
                    ).fetchall()
                trusted = {row[0] for row in rows}
                for directory_name in self._objects_directory.names():
                    try:
                        directory = self._objects_directory.open_child(
                            directory_name,
                            mode=self._policy.root_mode,
                        )
                    except RepositoryConfigurationError as error:
                        raise ObjectIntegrityError(
                            "object recovery encountered an untrusted directory",
                        ) from error
                    try:
                        for filename in directory.names():
                            path_metadata = directory.stat(filename)
                            if (
                                stat.S_ISLNK(path_metadata.st_mode)
                                or not stat.S_ISREG(path_metadata.st_mode)
                            ):
                                raise ObjectIntegrityError(
                                    "object recovery encountered an untrusted file",
                                )
                            digest = "sha256:" + directory_name + filename
                            require_object_digest(digest)
                            if digest not in trusted:
                                directory.unlink(filename)
                                removed.append(digest)
                        directory.fsync()
                    finally:
                        directory.close()
                self._objects_directory.fsync()
                return tuple(removed)
            finally:
                self._locks.release(object_lock)
        finally:
            self._locks.release(installation)

    def close(self) -> None:
        if not self._closed:
            self._staging_directory.close_chain()
            self._objects_directory.close_chain()
            self._closed = True
