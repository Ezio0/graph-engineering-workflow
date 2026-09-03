"""Durable offline extension ingest under the stable installation authority."""

from __future__ import annotations

import os
import pathlib
import hmac
import shutil
import sqlite3
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.application.tasks import RuntimeContext
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.extension_bundle import ExtensionInstallRequest, ExtensionSourceAttestation
from graph_engineering.core.extensions import Ed25519Verifier

from .codec import canonical_json, parse_canonical_json
from .extension_bundle import ExtensionBundleReader, _metadata_document, verify_extension_bundle
from .extensions import ExtensionTrustRepository


_INGEST_SCHEMA = """
CREATE TABLE IF NOT EXISTS extension_ingest_ledger (
    record_sequence INTEGER PRIMARY KEY CHECK(record_sequence > 0),
    ingest_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL UNIQUE,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_ingest_packages (
    ingest_id TEXT PRIMARY KEY,
    record_digest TEXT NOT NULL UNIQUE,
    manifest_json TEXT NOT NULL,
    content_root_ref TEXT NOT NULL UNIQUE,
    content_root_digest TEXT NOT NULL UNIQUE,
    FOREIGN KEY(ingest_id) REFERENCES extension_ingest_ledger(ingest_id)
) STRICT;
CREATE TRIGGER IF NOT EXISTS extension_ingest_no_update
BEFORE UPDATE ON extension_ingest_ledger
BEGIN SELECT RAISE(ABORT, 'extension ingest ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_ingest_no_delete
BEFORE DELETE ON extension_ingest_ledger
BEGIN SELECT RAISE(ABORT, 'extension ingest ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_ingest_package_no_update
BEFORE UPDATE ON extension_ingest_packages
BEGIN SELECT RAISE(ABORT, 'extension ingest package is immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_ingest_package_no_delete
BEFORE DELETE ON extension_ingest_packages
BEGIN SELECT RAISE(ABORT, 'extension ingest package is immutable'); END;
"""

_INGEST_BODY_FIELDS = {
    "schema_version", "record_sequence", "previous_record_digest", "ingest_id",
    "installation_id", "request_digest", "owner_id", "runtime_kind", "runtime_lineage_id",
    "archive_raw_digest", "manifest_digest", "package_identity_digest",
    "source_attestation_digest", "build_attestation_digest", "publisher_signature_digest",
    "production_policy_digest",
    "payload_root_digest", "trust_policy_digest", "trust_head_digest", "owner_decision_digest",
    "owner_authority_digest", "content_root_ref", "content_root_digest",
    "ingested_at", "activation_status",
}


def _ingest_records(connection: sqlite3.Connection, maximum: int) -> tuple[Mapping[str, object], ...]:
    rows = connection.execute(
        "SELECT record_sequence,record_digest,record_json FROM extension_ingest_ledger "
        "ORDER BY record_sequence"
    ).fetchall()
    if len(rows) > maximum:
        raise ValueError("extension ingest ledger exceeds configured bound")
    records: list[Mapping[str, object]] = []
    previous: str | None = None
    for expected_sequence, (sequence, stored_digest, encoded) in enumerate(rows, 1):
        value = parse_canonical_json(str(encoded))
        if not isinstance(value, Mapping) or set(value) != {*_INGEST_BODY_FIELDS, "record_digest"}:
            raise ValueError("extension ingest record is not exact")
        body = dict(value)
        claimed = body.pop("record_digest")
        actual = semantic_digest(
            body,
            contract_type="urn:gew:contract:extension-ingest-record",
            projection_id="urn:gew:digest-projection:extension-ingest-record:1.0.0",
            schema_id="urn:gew:schema:extension-ingest-record-input:1.0.0",
        )
        if (
            sequence != expected_sequence
            or body["record_sequence"] != expected_sequence
            or body["previous_record_digest"] != previous
            or type(claimed) is not str
            or not hmac.compare_digest(claimed, actual)
            or not hmac.compare_digest(str(stored_digest), actual)
        ):
            raise ValueError("extension ingest ledger chain or digest is invalid")
        previous = actual
        records.append(value)
    return tuple(records)


@dataclass(frozen=True, slots=True)
class ExtensionIngestReceipt:
    ingest_id: str
    request_digest: str
    record_sequence: int
    archive_raw_digest: str
    manifest_digest: str
    package_identity_digest: str
    trust_policy_digest: str
    trust_head_digest: str
    content_root_ref: str
    content_root_digest: str
    record_digest: str


@dataclass(frozen=True, slots=True)
class ExtensionInstalledContentObservation:
    content_root_ref: str
    content_root_digest: str
    member_count: int


_ISSUED_INSTALLERS: dict[int, object] = {}


def _no_fault(_point: str) -> None:
    return


class ExtensionBundleInstaller:
    """Factory-issued data-only ingest service; it never activates executable code."""

    __slots__ = ("_repository", "_reader", "_verifier", "_fault")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension installers are factory-issued")

    @classmethod
    def create(
        cls,
        repository: ExtensionTrustRepository,
        reader: ExtensionBundleReader,
        verifier: Ed25519Verifier,
        *,
        fault_hook: Callable[[str], None] = _no_fault,
    ) -> ExtensionBundleInstaller:
        if (
            type(repository) is not ExtensionTrustRepository
            or type(reader) is not ExtensionBundleReader
            or not callable(fault_hook)
        ):
            raise TypeError("extension installer storage authority is invalid")
        require_attested = getattr(type(verifier), "require_attested", None)
        if not callable(require_attested) or require_attested(verifier) is not verifier:
            raise TypeError("extension verifier is not factory-attested")
        result = object.__new__(cls)
        result._repository = repository
        result._reader = reader
        result._verifier = verifier
        result._fault = fault_hook
        _ISSUED_INSTALLERS[id(result)] = result
        result._recover_orphaned_content()
        return result

    @staticmethod
    def fault_schedule() -> tuple[str, ...]:
        return (
            "extension-install.before-content",
            "extension-install.after-content",
            "extension-install.after-ledger",
            "extension-install.after-commit",
        )

    @classmethod
    def require_attested(cls, value: object) -> ExtensionBundleInstaller:
        if type(value) is not cls or _ISSUED_INSTALLERS.get(id(value)) is not value:
            raise TypeError("extension installer is not factory-attested")
        return value

    def install(
        self,
        request: ExtensionInstallRequest,
        runtime: RuntimeContext,
    ) -> ExtensionIngestReceipt:
        self.require_attested(self)
        if type(request) is not ExtensionInstallRequest or type(runtime) is not RuntimeContext:
            raise TypeError("extension install inputs are invalid")
        runtime.require_issued()
        body = request.to_dict()
        if (
            body["owner_id"] != runtime.owner_id
            or body["runtime_kind"] != runtime.runtime_kind
            or body["runtime_lineage_id"] != runtime.runtime_lineage_id
        ):
            raise ValueError("extension install owner runtime lineage is not authorized")
        path = pathlib.Path(str(body["bundle_path"]))
        try:
            if path.resolve(strict=True) != path:
                raise ValueError("extension bundle path is not canonical")
        except OSError as error:
            raise ValueError("extension bundle path is unavailable") from error

        repository = self._repository
        manager = repository._manager
        token = manager._control_lock.acquire("exclusive")
        try:
            manager._control_lock.require_held(token, "exclusive")
            manifest = manager._current_manifest()
            if body["installation_id"] != manifest.installation_id:
                raise ValueError("extension install installation binding mismatch")
            connection = repository._connect()
            try:
                connection.executescript(_INGEST_SCHEMA)
                existing = self._receipt_for_request(connection, request.request_digest)
                if existing is not None:
                    return existing
                snapshot = repository._load(
                    connection, expected_installation_id=manifest.installation_id
                )
                if (
                    body["expected_trust_head_digest"] != snapshot.head.head_digest
                    or body["expected_trust_policy_digest"] != snapshot.policy.policy_digest
                ):
                    raise ValueError("extension install trust CAS mismatch")
                bounded = self._reader.read(path)
                if bounded.archive_raw_digest != body["expected_bundle_raw_digest"]:
                    raise ValueError("extension bundle raw digest substitution")
                source = ExtensionSourceAttestation.from_dict(
                    _metadata_document(bounded, "META-INF/source-attestation.json")
                ).to_dict()
                production_policy = repository._production_policy(
                    connection,
                    policy_id=str(source["production_policy_id"]),
                    policy_digest=str(source["production_policy_digest"]),
                )
                verified = verify_extension_bundle(
                    bounded,
                    snapshot.policy,
                    self._verifier,
                    verified_at=runtime.occurred_at,
                    production_policy=production_policy,
                )
                manifest_body = verified.manifest.to_dict()
                self._fault("extension-install.before-content")
                content_root_ref, content_root_digest = self._publish_content(bounded)
                self._fault("extension-install.after-content")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    current = repository._load(
                        connection, expected_installation_id=manifest.installation_id
                    )
                    if current.head.head_digest != snapshot.head.head_digest:
                        raise ValueError("extension install trust head changed before commit")
                    records = _ingest_records(connection, repository._policy.max_ledger_records)
                    sequence = len(records) + 1
                    previous = None if not records else str(records[-1]["record_digest"])
                    record_body: dict[str, object] = {
                        "schema_version": "1.0.0",
                        "record_sequence": sequence,
                        "previous_record_digest": previous,
                        "ingest_id": body["ingest_id"],
                        "installation_id": manifest.installation_id,
                        "request_digest": request.request_digest,
                        "owner_id": runtime.owner_id,
                        "runtime_kind": runtime.runtime_kind,
                        "runtime_lineage_id": runtime.runtime_lineage_id,
                        "archive_raw_digest": bounded.archive_raw_digest,
                        "manifest_digest": manifest_body["manifest_digest"],
                        "package_identity_digest": verified.manifest.package_identity_digest,
                        "source_attestation_digest": verified.source_attestation.attestation_digest,
                        "build_attestation_digest": verified.build_attestation.attestation_digest,
                        "publisher_signature_digest": verified.publisher_signature.signature_record_digest,
                        "production_policy_digest": production_policy.policy_digest,
                        "payload_root_digest": verified.payload_root.payload_root_digest,
                        "trust_policy_digest": snapshot.policy.policy_digest,
                        "trust_head_digest": snapshot.head.head_digest,
                        "owner_decision_digest": body["owner_decision_digest"],
                        "owner_authority_digest": body["owner_authority_digest"],
                        "content_root_ref": content_root_ref,
                        "content_root_digest": content_root_digest,
                        "ingested_at": runtime.occurred_at,
                        "activation_status": "data-only-installed-executable-denied",
                    }
                    record_digest = semantic_digest(
                        record_body,
                        contract_type="urn:gew:contract:extension-ingest-record",
                        projection_id="urn:gew:digest-projection:extension-ingest-record:1.0.0",
                        schema_id="urn:gew:schema:extension-ingest-record-input:1.0.0",
                    )
                    record = {**record_body, "record_digest": record_digest}
                    connection.execute(
                        "INSERT INTO extension_ingest_ledger"
                        "(record_sequence,ingest_id,request_digest,record_digest,record_json) "
                        "VALUES(?,?,?,?,?)",
                        (
                            sequence, body["ingest_id"], request.request_digest,
                            record_digest, canonical_json(record),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO extension_ingest_packages"
                        "(ingest_id,record_digest,manifest_json,content_root_ref,content_root_digest) "
                        "VALUES(?,?,?,?,?)",
                        (
                            body["ingest_id"], record_digest,
                            canonical_json(manifest_body),
                            content_root_ref, content_root_digest,
                        ),
                    )
                    self._fault("extension-install.after-ledger")
                    connection.commit()
                    self._fault("extension-install.after-commit")
                except BaseException:
                    connection.rollback()
                    raise
            finally:
                connection.close()
            return ExtensionIngestReceipt(
                str(body["ingest_id"]), request.request_digest, sequence,
                bounded.archive_raw_digest, str(manifest_body["manifest_digest"]),
                verified.manifest.package_identity_digest, snapshot.policy.policy_digest,
                snapshot.head.head_digest, content_root_ref, content_root_digest, record_digest,
            )
        finally:
            manager._control_lock.release(token)

    def _receipt_for_request(
        self,
        connection: sqlite3.Connection,
        request_digest: str,
    ) -> ExtensionIngestReceipt | None:
        matches = [
            item for item in _ingest_records(
                connection, self._repository._policy.max_ledger_records
            )
            if item["request_digest"] == request_digest
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("extension install idempotency record is ambiguous")
        item = matches[0]
        return ExtensionIngestReceipt(
            str(item["ingest_id"]), str(item["request_digest"]),
            int(item["record_sequence"]), str(item["archive_raw_digest"]),
            str(item["manifest_digest"]), str(item["package_identity_digest"]),
            str(item["trust_policy_digest"]), str(item["trust_head_digest"]),
            str(item["content_root_ref"]), str(item["content_root_digest"]),
            str(item["record_digest"]),
        )

    @property
    def _content_base(self) -> pathlib.Path:
        return self._repository._manager._control / self._reader._policy.installed_content_directory

    def _recover_orphaned_content(self) -> None:
        manager = self._repository._manager
        token = manager._control_lock.acquire("exclusive")
        try:
            connection = self._repository._connect()
            try:
                connection.executescript(_INGEST_SCHEMA)
                references = {
                    str(row[0]).removeprefix("extension-content-v1:")
                    for row in connection.execute(
                        "SELECT content_root_ref FROM extension_ingest_packages"
                    ).fetchall()
                }
            finally:
                connection.close()
            base = self._content_base
            if not base.exists():
                return
            metadata = os.lstat(base)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise ValueError("extension content authority root is invalid")
            for entry in base.iterdir():
                if (
                    entry.name in references
                    or len(entry.name) != 64
                    or any(character not in "0123456789abcdef" for character in entry.name)
                ):
                    continue
                observed = os.lstat(entry)
                if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.getuid():
                    raise ValueError("extension orphan content identity is unsafe")
                for directory, _names, _files in os.walk(entry):
                    os.chmod(directory, 0o700, follow_symlinks=False)
                shutil.rmtree(entry)
        finally:
            manager._control_lock.release(token)

    def _publish_content(self, bundle: object) -> tuple[str, str]:
        from graph_engineering.storage.extension_bundle import BoundedExtensionBundle

        if type(bundle) is not BoundedExtensionBundle:
            raise TypeError("verified extension content is invalid")
        policy = self._reader._policy
        base = self._content_base
        base.mkdir(mode=0o700, parents=False, exist_ok=True)
        base_stat = os.lstat(base)
        if (
            not stat.S_ISDIR(base_stat.st_mode)
            or base_stat.st_uid != os.getuid()
            or stat.S_IMODE(base_stat.st_mode) != 0o700
        ):
            raise ValueError("extension content authority root is invalid")
        suffix = bundle.archive_raw_digest.removeprefix("sha256-raw-v1:")
        content_root_ref = f"extension-content-v1:{suffix}"
        destination = base / suffix
        if destination.exists() or destination.is_symlink():
            raise ValueError("extension immutable content identity already exists")
        attempt = pathlib.Path(tempfile.mkdtemp(prefix=f".{suffix}.", dir=base))
        try:
            entries: list[dict[str, object]] = []
            directories: set[pathlib.Path] = {attempt}
            total = 0
            for name in sorted(bundle.members):
                body = bundle.members[name]
                total += len(body)
                if total > policy.max_total_uncompressed_bytes:
                    raise ValueError("extension installed content exceeds configured bound")
                relative = pathlib.PurePosixPath(name)
                target = attempt.joinpath(*relative.parts)
                parent = target.parent
                missing: list[pathlib.Path] = []
                while parent != attempt and not parent.exists():
                    missing.append(parent)
                    parent = parent.parent
                for directory in reversed(missing):
                    directory.mkdir(mode=0o700)
                    directories.add(directory)
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    written = 0
                    while written < len(body):
                        written += os.write(descriptor, body[written:])
                    os.fsync(descriptor)
                    os.fchmod(descriptor, policy.installed_file_mode)
                finally:
                    os.close(descriptor)
                entries.append(
                    {
                        "path": name,
                        "size": len(body),
                        "raw_digest": raw_digest(body),
                        "archive_mode": bundle.member_modes[name],
                    }
                )
            manifest_body: dict[str, object] = {
                "schema_version": "1.0.0",
                "archive_raw_digest": bundle.archive_raw_digest,
                "members": entries,
            }
            content_root_digest = semantic_digest(
                manifest_body,
                contract_type="urn:gew:contract:extension-installed-content",
                projection_id="urn:gew:digest-projection:extension-installed-content:1.0.0",
                schema_id="urn:gew:schema:extension-installed-content-input:1.0.0",
            )
            installed_manifest = canonical_json(
                {**manifest_body, "content_root_digest": content_root_digest}
            ).encode()
            manifest_path = attempt / ".gew-installed-content.json"
            descriptor = os.open(
                manifest_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(descriptor, installed_manifest)
                os.fsync(descriptor)
                os.fchmod(descriptor, policy.installed_file_mode)
            finally:
                os.close(descriptor)
            for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
                os.chmod(directory, policy.installed_directory_mode, follow_symlinks=False)
            os.replace(attempt, destination)
            base_descriptor = os.open(base, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(base_descriptor)
            finally:
                os.close(base_descriptor)
            return content_root_ref, content_root_digest
        except BaseException:
            if attempt.exists():
                for directory, _names, _files in os.walk(attempt):
                    os.chmod(directory, 0o700, follow_symlinks=False)
                shutil.rmtree(attempt)
            raise

    def doctor(self, receipt: ExtensionIngestReceipt) -> ExtensionInstalledContentObservation:
        self.require_attested(self)
        if type(receipt) is not ExtensionIngestReceipt:
            raise TypeError("extension installed content receipt is invalid")
        token = self._repository._manager._control_lock.acquire("shared")
        try:
            connection = self._repository._connect()
            try:
                records = _ingest_records(
                    connection, self._repository._policy.max_ledger_records
                )
                matches = [
                    item for item in records if item["record_digest"] == receipt.record_digest
                ]
                row = connection.execute(
                    "SELECT record_digest,content_root_ref,content_root_digest "
                    "FROM extension_ingest_packages WHERE ingest_id=?",
                    (receipt.ingest_id,),
                ).fetchone()
                if (
                    len(matches) != 1
                    or row is None
                    or (
                        matches
                        and (
                            matches[0]["ingest_id"],
                            matches[0]["request_digest"],
                            matches[0]["record_sequence"],
                            matches[0]["archive_raw_digest"],
                            matches[0]["manifest_digest"],
                            matches[0]["package_identity_digest"],
                            matches[0]["trust_policy_digest"],
                            matches[0]["trust_head_digest"],
                            matches[0]["content_root_ref"],
                            matches[0]["content_root_digest"],
                            matches[0]["record_digest"],
                        )
                        != (
                            receipt.ingest_id,
                            receipt.request_digest,
                            receipt.record_sequence,
                            receipt.archive_raw_digest,
                            receipt.manifest_digest,
                            receipt.package_identity_digest,
                            receipt.trust_policy_digest,
                            receipt.trust_head_digest,
                            receipt.content_root_ref,
                            receipt.content_root_digest,
                            receipt.record_digest,
                        )
                    )
                    or tuple(row)
                    != (
                        receipt.record_digest,
                        receipt.content_root_ref,
                        receipt.content_root_digest,
                    )
                ):
                    raise ValueError("extension installed content ledger binding is invalid")
                return self._doctor_locked(receipt)
            finally:
                connection.close()
        finally:
            self._repository._manager._control_lock.release(token)

    def _doctor_locked(
        self, receipt: ExtensionIngestReceipt
    ) -> ExtensionInstalledContentObservation:
        suffix = receipt.content_root_ref.removeprefix("extension-content-v1:")
        if len(suffix) != 64 or any(character not in "0123456789abcdef" for character in suffix):
            raise ValueError("extension content reference is invalid")
        root = self._content_base / suffix
        policy = self._reader._policy
        root_stat = os.lstat(root)
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != os.getuid()
            or stat.S_IMODE(root_stat.st_mode) != policy.installed_directory_mode
        ):
            raise ValueError("extension content root identity is invalid")
        manifest_bytes = self._read_installed_file(
            root / ".gew-installed-content.json", policy.max_metadata_member_bytes
        )
        document = parse_canonical_json(manifest_bytes.decode())
        if not isinstance(document, Mapping) or set(document) != {
            "schema_version", "archive_raw_digest", "members", "content_root_digest"
        }:
            raise ValueError("extension content manifest is not exact")
        body = dict(document)
        claimed = body.pop("content_root_digest")
        actual = semantic_digest(
            body,
            contract_type="urn:gew:contract:extension-installed-content",
            projection_id="urn:gew:digest-projection:extension-installed-content:1.0.0",
            schema_id="urn:gew:schema:extension-installed-content-input:1.0.0",
        )
        if claimed != receipt.content_root_digest or actual != receipt.content_root_digest:
            raise ValueError("extension content manifest digest mismatch")
        members = body.get("members")
        if type(members) is not list or len(members) > policy.max_members:
            raise ValueError("extension content member manifest is invalid")
        expected_paths = {".gew-installed-content.json"}
        total = 0
        for item in members:
            if not isinstance(item, Mapping) or set(item) != {
                "path", "size", "raw_digest", "archive_mode"
            }:
                raise ValueError("extension content member is not exact")
            name = item["path"]
            if type(name) is not str or name in expected_paths:
                raise ValueError("extension content member path is invalid")
            expected_paths.add(name)
            size = item["size"]
            if type(size) is not int or size < 0 or size > policy.max_member_bytes:
                raise ValueError("extension content member size is invalid")
            payload = self._read_installed_file(root.joinpath(*pathlib.PurePosixPath(name).parts), size)
            total += len(payload)
            if len(payload) != size or raw_digest(payload) != item["raw_digest"]:
                raise ValueError("extension content member digest mismatch")
        if total > policy.max_total_uncompressed_bytes:
            raise ValueError("extension content aggregate exceeds configured bound")
        expected_directories = {
            str(parent)
            for name in expected_paths
            for parent in pathlib.PurePosixPath(name).parents
            if str(parent) != "."
        }
        observed_files: set[str] = set()
        observed_directories: set[str] = set()
        for directory, names, files in os.walk(root, followlinks=False):
            directory_path = pathlib.Path(directory)
            for name in names:
                path = directory_path / name
                information = os.lstat(path)
                relative = str(path.relative_to(root)).replace(os.sep, "/")
                if (
                    not stat.S_ISDIR(information.st_mode)
                    or information.st_uid != os.getuid()
                    or stat.S_IMODE(information.st_mode) != policy.installed_directory_mode
                ):
                    raise ValueError("extension content directory identity is invalid")
                observed_directories.add(relative)
            for name in files:
                path = directory_path / name
                information = os.lstat(path)
                if not stat.S_ISREG(information.st_mode):
                    raise ValueError("extension content has a non-regular member")
                observed_files.add(str(path.relative_to(root)).replace(os.sep, "/"))
        if observed_files != expected_paths or observed_directories != expected_directories:
            raise ValueError("extension content root has unexpected entries")
        return ExtensionInstalledContentObservation(
            receipt.content_root_ref, receipt.content_root_digest, len(members)
        )

    def _read_installed_file(self, path: pathlib.Path, maximum: int) -> bytes:
        descriptor = os.open(
            path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != self._reader._policy.installed_file_mode
                or before.st_size > maximum
            ):
                raise ValueError("extension content member identity is invalid")
            body = bytearray()
            while len(body) <= maximum:
                chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
            after = os.fstat(descriptor)
            if (
                len(body) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ValueError("extension content member changed during read")
            return bytes(body)
        finally:
            os.close(descriptor)

    def _load_installed_members_under_lock(
        self, receipt: ExtensionIngestReceipt
    ) -> Mapping[str, bytes]:
        self.require_attested(self)
        self._doctor_locked(receipt)
        suffix = receipt.content_root_ref.removeprefix("extension-content-v1:")
        root = self._content_base / suffix
        manifest = parse_canonical_json(
            self._read_installed_file(
                root / ".gew-installed-content.json",
                self._reader._policy.max_metadata_member_bytes,
            ).decode()
        )
        if not isinstance(manifest, Mapping) or type(manifest.get("members")) is not list:
            raise ValueError("extension content manifest is invalid")
        result: dict[str, bytes] = {}
        for item in manifest["members"]:
            if not isinstance(item, Mapping):
                raise ValueError("extension content member manifest is invalid")
            name = item.get("path")
            size = item.get("size")
            if type(name) is not str or type(size) is not int:
                raise ValueError("extension content member manifest is invalid")
            result[name] = self._read_installed_file(
                root.joinpath(*pathlib.PurePosixPath(name).parts), size
            )
        return MappingProxyType(result)

    def _test_content_path(self, receipt: ExtensionIngestReceipt) -> pathlib.Path:
        suffix = receipt.content_root_ref.removeprefix("extension-content-v1:")
        return self._content_base / suffix

    def _test_records(self) -> tuple[Mapping[str, object], ...]:
        repository = self._repository
        token = repository._manager._control_lock.acquire("exclusive")
        try:
            connection = repository._connect()
            try:
                return _ingest_records(connection, repository._policy.max_ledger_records)
            finally:
                connection.close()
        finally:
            repository._manager._control_lock.release(token)
