"""Stable-control-root extension trust policy ledger."""

from __future__ import annotations

import hmac
import os
import pathlib
import sqlite3
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from graph_engineering.application.tasks import RuntimeContext
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.extension_bundle import ExtensionAttestationProductionPolicy
from graph_engineering.core.extensions import Ed25519Verifier
from graph_engineering.core.security._common import (
    exact_mapping,
    parse_timestamp,
    require_digest,
    require_id,
)
from graph_engineering.core.security.extensions import (
    ExtensionPublisherRevocationStatement,
    ExtensionTrustLedgerRecord,
    ExtensionTrustOperation,
    ExtensionTrustPolicy,
    ExtensionTrustPolicyReducer,
    ExtensionTrustPolicyHead,
)

from .codec import canonical_json, parse_canonical_json
from .migration import InstallationMigrationRepository, MigrationRepositoryError


def _no_fault(_point: str) -> None:
    return


@dataclass(frozen=True, slots=True)
class ExtensionTrustStoragePolicy:
    database_filename: str
    file_mode: int
    busy_timeout_ms: int
    max_ledger_records: int

    @classmethod
    def from_dict(cls, value: object) -> ExtensionTrustStoragePolicy:
        fields = {
            "schema_version",
            "database_filename",
            "file_mode",
            "busy_timeout_ms",
            "max_ledger_records",
        }
        document = exact_mapping(value, fields, "extension trust storage policy")
        filename = document.get("database_filename")
        if (
            document.get("schema_version") != "1.0.0"
            or type(filename) is not str
            or not filename
            or filename != pathlib.PurePath(filename).name
            or "/" in filename
        ):
            raise ValueError("extension trust storage policy identity is invalid")
        file_mode = document.get("file_mode")
        busy = document.get("busy_timeout_ms")
        maximum = document.get("max_ledger_records")
        if type(file_mode) is not int or file_mode != 0o600:
            raise ValueError("extension trust database mode must be owner-only")
        if type(busy) is not int or busy < 1 or busy > 60_000:
            raise ValueError("extension trust SQLite timeout is invalid")
        if type(maximum) is not int or maximum < 16 or maximum > 1_000_000:
            raise ValueError("extension trust ledger bound is invalid")
        return cls(filename, file_mode, busy, maximum)


@dataclass(frozen=True, slots=True)
class ExtensionTrustSnapshot:
    policy: ExtensionTrustPolicy
    head: ExtensionTrustPolicyHead
    ledger: tuple[ExtensionTrustLedgerRecord, ...]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS trust_policies (
    generation INTEGER PRIMARY KEY CHECK(generation >= 0),
    policy_digest TEXT NOT NULL UNIQUE,
    policy_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS trust_ledger (
    record_sequence INTEGER PRIMARY KEY CHECK(record_sequence > 0),
    record_type TEXT NOT NULL CHECK(record_type IN ('prepared','commit','abort','rollback')),
    transaction_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    UNIQUE(transaction_id, record_type)
) STRICT;
CREATE TABLE IF NOT EXISTS trust_head (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    head_digest TEXT NOT NULL UNIQUE,
    head_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS publisher_revocation_inputs (
    publisher_id TEXT NOT NULL,
    publisher_key_id TEXT NOT NULL,
    publisher_sequence INTEGER NOT NULL CHECK(publisher_sequence > 0),
    statement_digest TEXT NOT NULL UNIQUE,
    PRIMARY KEY(publisher_id,publisher_key_id,publisher_sequence)
) STRICT;
CREATE TABLE IF NOT EXISTS production_policy_materials (
    policy_id TEXT NOT NULL,
    policy_digest TEXT NOT NULL UNIQUE,
    policy_json TEXT NOT NULL,
    registered_generation INTEGER NOT NULL CHECK(registered_generation > 0),
    transaction_id TEXT NOT NULL UNIQUE,
    PRIMARY KEY(policy_id,policy_digest)
) STRICT;
CREATE TABLE IF NOT EXISTS trust_blocked (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    generation INTEGER NOT NULL CHECK(generation > 0),
    reason_code TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS trust_policy_no_update BEFORE UPDATE ON trust_policies
BEGIN SELECT RAISE(ABORT, 'extension trust policy is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trust_policy_no_delete BEFORE DELETE ON trust_policies
BEGIN SELECT RAISE(ABORT, 'extension trust policy is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trust_ledger_no_update BEFORE UPDATE ON trust_ledger
BEGIN SELECT RAISE(ABORT, 'extension trust ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS trust_ledger_no_delete BEFORE DELETE ON trust_ledger
BEGIN SELECT RAISE(ABORT, 'extension trust ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS publisher_revocation_no_update BEFORE UPDATE ON publisher_revocation_inputs
BEGIN SELECT RAISE(ABORT, 'publisher revocation inputs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS publisher_revocation_no_delete BEFORE DELETE ON publisher_revocation_inputs
BEGIN SELECT RAISE(ABORT, 'publisher revocation inputs are append-only'); END;
CREATE TRIGGER IF NOT EXISTS production_policy_material_no_update BEFORE UPDATE ON production_policy_materials
BEGIN SELECT RAISE(ABORT, 'extension production policy material is immutable'); END;
CREATE TRIGGER IF NOT EXISTS production_policy_material_no_delete BEFORE DELETE ON production_policy_materials
BEGIN SELECT RAISE(ABORT, 'extension production policy material is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trust_blocked_no_update BEFORE UPDATE ON trust_blocked
BEGIN SELECT RAISE(ABORT, 'extension trust blocked state is immutable'); END;
CREATE TRIGGER IF NOT EXISTS trust_blocked_no_delete BEFORE DELETE ON trust_blocked
BEGIN SELECT RAISE(ABORT, 'extension trust blocked state is immutable'); END;
"""


@dataclass(frozen=True, slots=True)
class VerifiedPublisherRevocation:
    statement: ExtensionPublisherRevocationStatement
    policy_digest: str
    publisher_sequence: int


_ISSUED_PUBLISHER_REVOCATIONS: dict[int, object] = {}
_ISSUED_TRUST_REPOSITORIES: dict[int, object] = {}


class ExtensionTrustRepository:
    """One installation trust authority guarded by the WP-06 stable exclusive lock."""

    def __init__(
        self,
        manager: InstallationMigrationRepository,
        policy: ExtensionTrustStoragePolicy,
        fault_hook: Callable[[str], None],
    ) -> None:
        if type(manager) is not InstallationMigrationRepository:
            raise TypeError("extension trust manager is invalid")
        self._manager = manager
        self._policy = policy
        self._fault = fault_hook
        self._path = manager._control / policy.database_filename
        self._reducer: ExtensionTrustPolicyReducer | None = None

    @classmethod
    def initialize(
        cls,
        manager: InstallationMigrationRepository,
        genesis: ExtensionTrustPolicy,
        *,
        policy_document: object,
        bootstrap_terminal_record_digest: str,
        fault_hook: Callable[[str], None] = _no_fault,
    ) -> ExtensionTrustRepository:
        if type(genesis) is not ExtensionTrustPolicy or not callable(fault_hook):
            raise TypeError("extension trust initialization inputs are invalid")
        require_digest(bootstrap_terminal_record_digest, "bootstrap terminal record digest")
        repository = cls(manager, ExtensionTrustStoragePolicy.from_dict(policy_document), fault_hook)
        repository._reducer = ExtensionTrustPolicyReducer.issue(genesis)
        token = manager._control_lock.acquire("exclusive")
        try:
            manager._control_lock.require_held(token, "exclusive")
            manifest = manager._current_manifest()
            if genesis.installation_id != manifest.installation_id:
                raise ValueError("extension trust genesis installation mismatch")
            connection = repository._connect(create=True)
            try:
                connection.executescript(_SCHEMA)
                row = connection.execute("SELECT head_json FROM trust_head WHERE singleton=1").fetchone()
                if row is None:
                    head = repository._head(
                        genesis,
                        terminal_record_digest=bootstrap_terminal_record_digest,
                        ledger_sequence=0,
                        previous_head_digest=None,
                    )
                    connection.execute("BEGIN IMMEDIATE")
                    try:
                        connection.execute(
                            "INSERT INTO trust_policies(generation,policy_digest,policy_json) VALUES(?,?,?)",
                            (genesis.generation, genesis.policy_digest, canonical_json(genesis.to_dict())),
                        )
                        connection.execute(
                            "INSERT INTO trust_head(singleton,head_digest,head_json) VALUES(1,?,?)",
                            (head.head_digest, canonical_json(head.to_dict())),
                        )
                        connection.commit()
                    except BaseException:
                        connection.rollback()
                        raise
                repository._load(connection, expected_installation_id=manifest.installation_id)
            finally:
                connection.close()
            repository._verify_file()
            _ISSUED_TRUST_REPOSITORIES[id(repository)] = repository
            return repository
        finally:
            manager._control_lock.release(token)

    @classmethod
    def require_attested(cls, value: object) -> ExtensionTrustRepository:
        if type(value) is not cls or _ISSUED_TRUST_REPOSITORIES.get(id(value)) is not value:
            raise TypeError("extension trust repository is not installation-issued")
        return value

    @staticmethod
    def post_commit_fault_schedule() -> tuple[str, ...]:
        return (
            "extension-trust.after-commit-durability",
            "extension-trust.before-restoration-publication",
            "extension-trust.after-restoration-durability",
            "extension-trust.after-restoration-reread",
        )

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        existed = self._path.exists()
        if not existed and not create:
            raise MigrationRepositoryError("extension trust database is missing")
        connection = sqlite3.connect(
            self._path,
            timeout=self._policy.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            if not existed:
                os.chmod(self._path, self._policy.file_mode)
            self._verify_file()
            connection.execute(f"PRAGMA busy_timeout={self._policy.busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            return connection
        except BaseException:
            connection.close()
            raise

    def _verify_file(self) -> None:
        metadata = self._path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != self._policy.file_mode
            or metadata.st_nlink != 1
        ):
            raise MigrationRepositoryError("extension trust database identity is unsafe")

    @staticmethod
    def _complete(body: dict[str, object], contract_name: str, field: str) -> dict[str, object]:
        if field in body:
            raise ValueError("extension trust digest source contains the derived field")
        result = dict(body)
        result[field] = semantic_digest(
            body,
            contract_type=f"urn:gew:contract:{contract_name}",
            projection_id=f"urn:gew:digest-projection:{contract_name}:1.0.0",
            schema_id=f"urn:gew:schema:{contract_name}-input:1.0.0",
        )
        return result

    def _head(
        self,
        policy: ExtensionTrustPolicy,
        *,
        terminal_record_digest: str,
        ledger_sequence: int,
        previous_head_digest: str | None,
    ) -> ExtensionTrustPolicyHead:
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "installation_id": policy.installation_id,
            "generation": policy.generation,
            "policy_digest": policy.policy_digest,
            "revocation_high_water": policy.revocation_high_water,
            "terminal_record_digest": terminal_record_digest,
            "ledger_sequence": ledger_sequence,
            "previous_head_digest": previous_head_digest,
        }
        return ExtensionTrustPolicyHead.from_dict(
            self._complete(body, "extension-trust-policy-head", "head_digest"),
            policy=policy,
        )

    def _load(
        self,
        connection: sqlite3.Connection,
        *,
        expected_installation_id: str,
        allow_pending_prepared: bool = False,
    ) -> ExtensionTrustSnapshot:
        if connection.execute(
            "SELECT 1 FROM trust_blocked WHERE singleton=1"
        ).fetchone() is not None:
            raise MigrationRepositoryError("extension trust is blocked")
        policy_rows = connection.execute(
            "SELECT generation,policy_digest,policy_json FROM trust_policies ORDER BY generation"
        ).fetchall()
        if not policy_rows:
            raise MigrationRepositoryError("extension trust policy chain is empty")
        policies: list[ExtensionTrustPolicy] = []
        by_digest: dict[str, ExtensionTrustPolicy] = {}
        previous: ExtensionTrustPolicy | None = None
        for generation, digest, encoded in policy_rows:
            document = parse_canonical_json(encoded)
            if not isinstance(document, dict):
                raise MigrationRepositoryError("extension trust policy body is invalid")
            policy = ExtensionTrustPolicy.from_dict(document, previous=previous)
            if (
                policy.generation != generation
                or policy.policy_digest != digest
                or policy.installation_id != expected_installation_id
            ):
                raise MigrationRepositoryError("extension trust policy row binding mismatch")
            policies.append(policy)
            by_digest[policy.policy_digest] = policy
            previous = policy

        rows = connection.execute(
            "SELECT record_sequence,record_type,transaction_id,record_digest,record_json "
            "FROM trust_ledger ORDER BY record_sequence"
        ).fetchall()
        if len(rows) > self._policy.max_ledger_records:
            raise MigrationRepositoryError("extension trust ledger exceeds configured bound")
        ledger: list[ExtensionTrustLedgerRecord] = []
        prepared_by_transaction: dict[str, ExtensionTrustLedgerRecord] = {}
        previous_record_digest: str | None = None
        committed_policy_digests: list[str] = []
        for expected_sequence, row in enumerate(rows, 1):
            sequence, record_type, transaction_id, digest, encoded = row
            if sequence != expected_sequence:
                raise MigrationRepositoryError("extension trust ledger sequence is not consecutive")
            document = parse_canonical_json(encoded)
            if not isinstance(document, dict) or document.get("previous_record_digest") != previous_record_digest:
                raise MigrationRepositoryError("extension trust ledger chain is divergent")
            if record_type == "prepared":
                current = by_digest.get(str(document.get("expected_policy_digest")))
                if current is None or transaction_id in prepared_by_transaction:
                    raise MigrationRepositoryError("extension trust prepared policy is unknown")
            else:
                prepared = prepared_by_transaction.get(transaction_id)
                if prepared is None or document.get("prepared_record_digest") != prepared.record_digest:
                    raise MigrationRepositoryError("extension trust terminal record has no exact prepared record")
                prepared_document = prepared.to_dict()
                current = by_digest.get(str(prepared_document.get("expected_policy_digest")))
                if current is None:
                    raise MigrationRepositoryError("extension trust terminal base policy is unknown")
            record = ExtensionTrustLedgerRecord.from_dict(document, current_policy=current)
            if record.record_type != record_type or record.record_digest != digest:
                raise MigrationRepositoryError("extension trust ledger row binding mismatch")
            if record_type == "prepared":
                prepared_by_transaction[transaction_id] = record
            else:
                prepared_by_transaction.pop(transaction_id)
                if record_type in {"commit", "rollback"}:
                    candidate_digest = str(document.get("candidate_policy_digest"))
                    candidate = by_digest.get(candidate_digest)
                    if (
                        candidate is None
                        or candidate.generation != document.get("candidate_generation")
                        or candidate.revocation_high_water
                        != document.get("candidate_revocation_high_water")
                    ):
                        raise MigrationRepositoryError("extension trust terminal candidate is not exact")
                    committed_policy_digests.append(candidate_digest)
            ledger.append(record)
            previous_record_digest = record.record_digest
        if prepared_by_transaction and (
            not allow_pending_prepared
            or len(prepared_by_transaction) != 1
            or not ledger
            or ledger[-1].record_type != "prepared"
        ):
            raise MigrationRepositoryError("extension trust ledger has an unterminated prepared record")
        if [item.policy_digest for item in policies[1:]] != committed_policy_digests:
            raise MigrationRepositoryError("extension trust committed policy chain is incomplete")

        row = connection.execute("SELECT head_digest,head_json FROM trust_head WHERE singleton=1").fetchone()
        if row is None:
            raise MigrationRepositoryError("extension trust policy head is missing")
        head_document = parse_canonical_json(row[1])
        if not isinstance(head_document, dict):
            raise MigrationRepositoryError("extension trust policy head is invalid")
        current_policy = policies[-1]
        head = ExtensionTrustPolicyHead.from_dict(head_document, policy=current_policy)
        if head.head_digest != row[0]:
            raise MigrationRepositoryError("extension trust head row binding mismatch")
        if current_policy.generation > 0:
            terminal = next(
                (item for item in ledger if item.record_digest == head_document["terminal_record_digest"]),
                None,
            )
            if terminal is None or terminal.record_type not in {"commit", "rollback"}:
                raise MigrationRepositoryError("extension trust head terminal record is missing")
            if head_document["ledger_sequence"] != terminal.to_dict()["record_sequence"]:
                raise MigrationRepositoryError("extension trust head ledger sequence mismatch")
        material_rows = connection.execute(
            "SELECT policy_id,policy_digest,policy_json,registered_generation "
            "FROM production_policy_materials ORDER BY policy_id,policy_digest"
        ).fetchall()
        materials: dict[tuple[str, str], ExtensionAttestationProductionPolicy] = {}
        for policy_id, policy_digest, encoded, registered_generation in material_rows:
            document = parse_canonical_json(str(encoded))
            material = ExtensionAttestationProductionPolicy.from_dict(document)
            material_body = material.to_dict()
            if (
                material_body["policy_id"] != policy_id
                or material.policy_digest != policy_digest
                or type(registered_generation) is not int
                or registered_generation < 1
                or registered_generation > current_policy.generation
            ):
                raise MigrationRepositoryError("extension production policy material binding mismatch")
            materials[(str(policy_id), str(policy_digest))] = material
        for reference in current_policy.to_dict()["production_policies"]:
            if (
                isinstance(reference, Mapping)
                and reference.get("status") == "active"
                and (str(reference["policy_id"]), str(reference["policy_digest"])) not in materials
            ):
                raise MigrationRepositoryError("active extension production policy material is missing")
        return ExtensionTrustSnapshot(current_policy, head, tuple(ledger))

    def _production_policy(
        self,
        connection: sqlite3.Connection,
        *,
        policy_id: str,
        policy_digest: str,
    ) -> ExtensionAttestationProductionPolicy:
        row = connection.execute(
            "SELECT policy_json FROM production_policy_materials "
            "WHERE policy_id=? AND policy_digest=?",
            (policy_id, policy_digest),
        ).fetchone()
        if row is None:
            raise MigrationRepositoryError("extension production policy material is unavailable")
        material = ExtensionAttestationProductionPolicy.from_dict(
            parse_canonical_json(str(row[0]))
        )
        if material.policy_digest != policy_digest or material.to_dict()["policy_id"] != policy_id:
            raise MigrationRepositoryError("extension production policy material is substituted")
        return material

    def current(self) -> ExtensionTrustSnapshot:
        token = self._manager._control_lock.acquire("exclusive")
        try:
            self._manager._control_lock.require_held(token, "exclusive")
            manifest = self._manager._current_manifest()
            connection = self._connect()
            try:
                return self._load(connection, expected_installation_id=manifest.installation_id)
            finally:
                connection.close()
        finally:
            self._manager._control_lock.release(token)

    def recover(self) -> ExtensionTrustSnapshot:
        token = self._manager._control_lock.acquire("exclusive")
        try:
            manifest = self._manager._current_manifest()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    snapshot = self._load(
                        connection,
                        expected_installation_id=manifest.installation_id,
                        allow_pending_prepared=True,
                    )
                    if snapshot.ledger and snapshot.ledger[-1].record_type == "prepared":
                        prepared = snapshot.ledger[-1]
                        source = prepared.to_dict()
                        abort_body: dict[str, object] = {
                            "schema_version": "1.0.0",
                            "record_type": "abort",
                            "installation_id": snapshot.policy.installation_id,
                            "transaction_id": source["transaction_id"],
                            "record_sequence": source["record_sequence"] + 1,
                            "previous_record_digest": prepared.record_digest,
                            "expected_head_digest": snapshot.head.head_digest,
                            "owner_identity": source["owner_identity"],
                            "owner_decision_digest": source["owner_decision_digest"],
                            "owner_authority_digest": source["owner_authority_digest"],
                            "created_at": source["created_at"],
                            "prepared_record_digest": prepared.record_digest,
                            "observed_head_digest": snapshot.head.head_digest,
                            "reason_code": "recovery.incomplete",
                            "aborted_at": source["created_at"],
                        }
                        aborted = self._record(abort_body, "abort", snapshot.policy)
                        self._insert_record(connection, aborted)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                return self._load(connection, expected_installation_id=manifest.installation_id)
            finally:
                connection.close()
        finally:
            self._manager._control_lock.release(token)

    @staticmethod
    def _authorization(value: object) -> Mapping[str, object]:
        if value is None:
            raise ValueError("Owner authorization is required")
        document = exact_mapping(
            value,
            {
                "transaction_id",
                "expected_head_digest",
                "owner_identity",
                "owner_decision_digest",
                "owner_authority_digest",
                "ordered_operations_digest",
                "created_at",
                "owner_decision",
                "authority_envelope",
            },
            "extension trust Owner authorization",
        )
        require_id(document.get("transaction_id"), "transaction ID")
        require_id(document.get("owner_identity"), "Owner identity")
        for field in (
            "expected_head_digest",
            "owner_decision_digest",
            "owner_authority_digest",
            "ordered_operations_digest",
        ):
            require_digest(document.get(field), field)
        if type(document.get("created_at")) is not str:
            raise ValueError("Owner authorization time is invalid")
        decision = exact_mapping(
            document.get("owner_decision"),
            {
                "schema_version", "decision_id", "owner_identity",
                "operation_digests", "expansion_targets", "decision_digest",
            },
            "extension trust Owner decision",
        )
        envelope = exact_mapping(
            document.get("authority_envelope"),
            {
                "schema_version", "envelope_id", "owner_identity",
                "allowed_operation_kinds", "allowed_target_identities",
                "envelope_digest",
            },
            "extension trust Authority Envelope",
        )
        if decision.get("schema_version") != "1.0.0" or envelope.get("schema_version") != "1.0.0":
            raise ValueError("extension trust Owner authorization version is invalid")
        for nested, name, digest_field, expected in (
            (decision, "extension-trust-owner-decision", "decision_digest", document["owner_decision_digest"]),
            (envelope, "extension-trust-authority-envelope", "envelope_digest", document["owner_authority_digest"]),
        ):
            body = dict(nested)
            claimed = require_digest(body.pop(digest_field, None), digest_field)
            actual = semantic_digest(
                body,
                contract_type=f"urn:gew:contract:{name}",
                projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
                schema_id=f"urn:gew:schema:{name}-input:1.0.0",
            )
            if not hmac.compare_digest(claimed, actual) or not hmac.compare_digest(claimed, str(expected)):
                raise ValueError(f"{name} digest mismatch")
        if (
            decision.get("owner_identity") != document["owner_identity"]
            or envelope.get("owner_identity") != document["owner_identity"]
        ):
            raise ValueError("extension trust Owner identity binding mismatch")
        return document

    @staticmethod
    def _require_operation_authority(
        authorization: Mapping[str, object],
        operations: tuple[ExtensionTrustOperation, ...],
    ) -> None:
        decision = authorization["owner_decision"]
        envelope = authorization["authority_envelope"]
        assert isinstance(decision, Mapping) and isinstance(envelope, Mapping)
        documents = [item.to_dict() for item in operations]
        digests = [item.operation_digest for item in operations]
        kinds = sorted({str(item["operation_kind"]) for item in documents})
        targets = sorted({str(item["target_identity"]) for item in documents})
        expansions = ExtensionTrustPolicyReducer.expansion_targets(operations)
        if (
            decision.get("operation_digests") != digests
            or decision.get("expansion_targets") != expansions
            or envelope.get("allowed_operation_kinds") != kinds
            or envelope.get("allowed_target_identities") != targets
        ):
            raise ValueError("extension trust operation authority coverage mismatch")

    def _record(
        self,
        body: dict[str, object],
        kind: str,
        current_policy: ExtensionTrustPolicy,
    ) -> ExtensionTrustLedgerRecord:
        return ExtensionTrustLedgerRecord.from_dict(
            self._complete(body, f"extension-trust-{kind}", "record_digest"),
            current_policy=current_policy,
        )

    def _prepared(
        self,
        current: ExtensionTrustSnapshot,
        candidate: ExtensionTrustPolicy,
        authorization: Mapping[str, object],
        sequence: int,
        previous_record_digest: str | None,
    ) -> ExtensionTrustLedgerRecord:
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "record_type": "prepared",
            "installation_id": current.policy.installation_id,
            "transaction_id": authorization["transaction_id"],
            "record_sequence": sequence,
            "previous_record_digest": previous_record_digest,
            "expected_head_digest": authorization["expected_head_digest"],
            "owner_identity": authorization["owner_identity"],
            "owner_decision_digest": authorization["owner_decision_digest"],
            "owner_authority_digest": authorization["owner_authority_digest"],
            "created_at": authorization["created_at"],
            "expected_generation": current.policy.generation,
            "expected_policy_digest": current.policy.policy_digest,
            "expected_revocation_high_water": current.policy.revocation_high_water,
            "candidate_generation": candidate.generation,
            "candidate_policy_digest": candidate.policy_digest,
            "candidate_revocation_high_water": candidate.revocation_high_water,
            "ordered_operations_digest": authorization["ordered_operations_digest"],
        }
        return self._record(body, "prepared", current.policy)

    @staticmethod
    def _insert_record(connection: sqlite3.Connection, record: ExtensionTrustLedgerRecord) -> None:
        document = record.to_dict()
        connection.execute(
            "INSERT INTO trust_ledger(record_sequence,record_type,transaction_id,record_digest,record_json) "
            "VALUES(?,?,?,?,?)",
            (
                document["record_sequence"],
                record.record_type,
                document["transaction_id"],
                record.record_digest,
                canonical_json(document),
            ),
        )

    def _terminal_transaction(
        self,
        operations: tuple[ExtensionTrustOperation, ...],
        authorization_value: object,
        *,
        terminal_kind: str,
        rollback_of_record_digest: str | None = None,
        restore_content_from_policy_digest: str | None = None,
        runtime: RuntimeContext,
        verified_revocation: VerifiedPublisherRevocation | None = None,
        production_policy: ExtensionAttestationProductionPolicy | None = None,
        verifier: Ed25519Verifier | None = None,
    ) -> ExtensionTrustSnapshot:
        authorization = self._authorization(authorization_value)
        self._require_runtime_authority(authorization, runtime)
        token = self._manager._control_lock.acquire("exclusive")
        try:
            manifest = self._manager._current_manifest()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    current = self._load(connection, expected_installation_id=manifest.installation_id)
                    if not hmac.compare_digest(
                        str(authorization["expected_head_digest"]), current.head.head_digest
                    ):
                        raise ValueError("extension trust head CAS is stale")
                    if verified_revocation is not None:
                        self._require_verified_revocation(
                            connection, verified_revocation, current.policy.policy_digest
                        )
                    self._require_operation_authority(authorization, operations)
                    if self._reducer is None:
                        raise MigrationRepositoryError("extension trust reducer is unavailable")
                    candidate = self._reducer.reduce(current.policy, operations)
                    ordered_digest = semantic_digest(
                        {
                            "schema_version": "1.0.0",
                            "operations": [item.to_dict() for item in operations],
                        },
                        contract_type="urn:gew:contract:extension-trust-ordered-operations",
                        projection_id="urn:gew:digest-projection:extension-trust-ordered-operations:1.0.0",
                        schema_id="urn:gew:schema:extension-trust-ordered-operations-input:1.0.0",
                    )
                    if authorization["ordered_operations_digest"] != ordered_digest:
                        raise ValueError("extension trust ordered operations authorization mismatch")
                    new_material = self._validate_production_policy_registration(
                        connection,
                        current.policy,
                        candidate,
                        production_policy,
                        verifier,
                        observed_at=str(authorization["created_at"]),
                    )
                    sequence = len(current.ledger) + 1
                    previous_record = current.ledger[-1].record_digest if current.ledger else None
                    prepared = self._prepared(
                        current, candidate, authorization, sequence, previous_record
                    )
                    self._insert_record(connection, prepared)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                self._fault("extension-trust.after-prepared")
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.execute(
                        "INSERT INTO trust_policies(generation,policy_digest,policy_json) VALUES(?,?,?)",
                        (
                            candidate.generation,
                            candidate.policy_digest,
                            canonical_json(candidate.to_dict()),
                        ),
                    )
                    if new_material is not None:
                        connection.execute(
                            "INSERT INTO production_policy_materials"
                            "(policy_id,policy_digest,policy_json,registered_generation,transaction_id) "
                            "VALUES(?,?,?,?,?)",
                            (
                                new_material.to_dict()["policy_id"],
                                new_material.policy_digest,
                                canonical_json(new_material.to_dict()),
                                candidate.generation,
                                authorization["transaction_id"],
                            ),
                        )
                    self._fault("extension-trust.after-policy")
                    terminal_body: dict[str, object] = {
                        "schema_version": "1.0.0",
                        "record_type": terminal_kind,
                        "installation_id": current.policy.installation_id,
                        "transaction_id": authorization["transaction_id"],
                        "record_sequence": sequence + 1,
                        "previous_record_digest": prepared.record_digest,
                        "expected_head_digest": current.head.head_digest,
                        "owner_identity": authorization["owner_identity"],
                        "owner_decision_digest": authorization["owner_decision_digest"],
                        "owner_authority_digest": authorization["owner_authority_digest"],
                        "created_at": authorization["created_at"],
                        "prepared_record_digest": prepared.record_digest,
                        "candidate_generation": candidate.generation,
                        "candidate_policy_digest": candidate.policy_digest,
                        "candidate_revocation_high_water": candidate.revocation_high_water,
                        "committed_at": authorization["created_at"],
                    }
                    if terminal_kind == "rollback":
                        terminal_body.update(
                            rollback_of_record_digest=require_digest(
                                rollback_of_record_digest, "rollback record digest"
                            ),
                            restore_content_from_policy_digest=require_digest(
                                restore_content_from_policy_digest, "restore policy digest"
                            ),
                        )
                    terminal = self._record(terminal_body, terminal_kind, current.policy)
                    self._insert_record(connection, terminal)
                    self._fault("extension-trust.after-terminal")
                    head = self._head(
                        candidate,
                        terminal_record_digest=terminal.record_digest,
                        ledger_sequence=sequence + 1,
                        previous_head_digest=current.head.head_digest,
                    )
                    changed = connection.execute(
                        "UPDATE trust_head SET head_digest=?,head_json=? "
                        "WHERE singleton=1 AND head_digest=?",
                        (
                            head.head_digest,
                            canonical_json(head.to_dict()),
                            current.head.head_digest,
                        ),
                    ).rowcount
                    if changed != 1:
                        raise ValueError("extension trust head CAS lost")
                    self._fault("extension-trust.after-head-cas")
                    if verified_revocation is not None:
                        statement = verified_revocation.statement.to_dict()
                        connection.execute(
                            "INSERT INTO publisher_revocation_inputs"
                            "(publisher_id,publisher_key_id,publisher_sequence,statement_digest) "
                            "VALUES(?,?,?,?)",
                            (
                                statement["publisher_id"], statement["publisher_key_id"],
                                statement["publisher_sequence"],
                                verified_revocation.statement.statement_digest,
                            ),
                        )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                fault: BaseException | None = None
                observed: ExtensionTrustSnapshot | None = None
                try:
                    self._fault("extension-trust.after-commit-durability")
                    observed = self._load(
                        connection, expected_installation_id=manifest.installation_id
                    )
                    if (
                        observed.policy.policy_digest != candidate.policy_digest
                        or observed.head.to_dict()["policy_digest"] != candidate.policy_digest
                        or observed.ledger[-1].record_digest != terminal.record_digest
                    ):
                        raise MigrationRepositoryError(
                            "extension trust post-commit verification failed"
                        )
                except BaseException as error:
                    fault = error
                if fault is not None:
                    self._fault("extension-trust.before-restoration-publication")
                    self._restore_after_failed_publish(
                        connection,
                        previous=current,
                        published=candidate,
                        authorization=authorization,
                        rollback_of_record_digest=terminal.record_digest,
                        expected_installation_id=manifest.installation_id,
                    )
                    raise fault
                assert observed is not None
                return observed
            finally:
                connection.close()
        finally:
            self._manager._control_lock.release(token)

    def _restore_after_failed_publish(
        self,
        connection: sqlite3.Connection,
        *,
        previous: ExtensionTrustSnapshot,
        published: ExtensionTrustPolicy,
        authorization: Mapping[str, object],
        rollback_of_record_digest: str,
        expected_installation_id: str,
    ) -> ExtensionTrustSnapshot:
        """Publish a higher generation that restores content without lowering denies."""
        current = self._load(
            connection, expected_installation_id=expected_installation_id
        )
        if current.policy.policy_digest != published.policy_digest:
            raise MigrationRepositoryError(
                "extension trust post-verify rollback base is divergent"
            )
        if self._reducer is None:
            raise MigrationRepositoryError("extension trust reducer is unavailable")
        try:
            restored_policy = self._reducer.security_join(previous.policy, published)
        except ValueError as error:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT OR IGNORE INTO trust_blocked(singleton,generation,reason_code) "
                    "VALUES(1,?,?)",
                    (published.generation, "security-ordering-unprovable"),
                )
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
            raise MigrationRepositoryError(
                "extension trust restoration is blocked because security ordering is unprovable"
            ) from error
        sequence = len(current.ledger) + 1
        recovery_authorization = dict(authorization)
        recovery_authorization.update(
            transaction_id=f"{authorization['transaction_id']}.postverify",
            expected_head_digest=current.head.head_digest,
        )
        prepared = self._prepared(
            current,
            restored_policy,
            recovery_authorization,
            sequence,
            current.ledger[-1].record_digest,
        )
        terminal_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "record_type": "rollback",
            "installation_id": restored_policy.installation_id,
            "transaction_id": recovery_authorization["transaction_id"],
            "record_sequence": sequence + 1,
            "previous_record_digest": prepared.record_digest,
            "expected_head_digest": current.head.head_digest,
            "owner_identity": authorization["owner_identity"],
            "owner_decision_digest": authorization["owner_decision_digest"],
            "owner_authority_digest": authorization["owner_authority_digest"],
            "created_at": authorization["created_at"],
            "prepared_record_digest": prepared.record_digest,
            "rollback_of_record_digest": rollback_of_record_digest,
            "restore_content_from_policy_digest": previous.policy.policy_digest,
            "candidate_generation": restored_policy.generation,
            "candidate_policy_digest": restored_policy.policy_digest,
            "candidate_revocation_high_water": restored_policy.revocation_high_water,
            "committed_at": authorization["created_at"],
        }
        terminal = self._record(terminal_body, "rollback", current.policy)
        head = self._head(
            restored_policy,
            terminal_record_digest=terminal.record_digest,
            ledger_sequence=sequence + 1,
            previous_head_digest=current.head.head_digest,
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            self._insert_record(connection, prepared)
            connection.execute(
                "INSERT INTO trust_policies(generation,policy_digest,policy_json) VALUES(?,?,?)",
                (
                    restored_policy.generation,
                    restored_policy.policy_digest,
                    canonical_json(restored_policy.to_dict()),
                ),
            )
            self._insert_record(connection, terminal)
            changed = connection.execute(
                "UPDATE trust_head SET head_digest=?,head_json=? "
                "WHERE singleton=1 AND head_digest=?",
                (
                    head.head_digest,
                    canonical_json(head.to_dict()),
                    current.head.head_digest,
                ),
            ).rowcount
            if changed != 1:
                raise MigrationRepositoryError(
                    "extension trust post-verify rollback CAS failed"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._fault("extension-trust.after-restoration-durability")
        restored = self._load(
            connection, expected_installation_id=expected_installation_id
        )
        if (
            restored.policy.policy_digest != restored_policy.policy_digest
            or restored.head.to_dict()["policy_digest"] != restored_policy.policy_digest
            or restored.ledger[-1].record_digest != terminal.record_digest
        ):
            raise MigrationRepositoryError(
                "extension trust restoration reread binding failed"
            )
        self._fault("extension-trust.after-restoration-reread")
        return restored

    @staticmethod
    def _validate_production_policy_registration(
        connection: sqlite3.Connection,
        current: ExtensionTrustPolicy,
        candidate: ExtensionTrustPolicy,
        material: ExtensionAttestationProductionPolicy | None,
        verifier: Ed25519Verifier | None,
        *,
        observed_at: str,
    ) -> ExtensionAttestationProductionPolicy | None:
        current_refs = {
            (str(item["policy_id"]), str(item["policy_digest"]))
            for item in current.to_dict()["production_policies"]
            if isinstance(item, Mapping)
        }
        candidate_refs = {
            (str(item["policy_id"]), str(item["policy_digest"]))
            for item in candidate.to_dict()["production_policies"]
            if isinstance(item, Mapping) and item.get("status") == "active"
        }
        additions = candidate_refs - current_refs
        if not additions:
            if material is not None:
                raise ValueError("extension production policy material has no added reference")
            return None
        if len(additions) != 1 or type(material) is not ExtensionAttestationProductionPolicy:
            raise ValueError("exact extension production policy material is required")
        require_attested = getattr(type(verifier), "require_attested", None)
        if not callable(require_attested) or require_attested(verifier) is not verifier:
            raise TypeError("extension production policy verifier is not factory-attested")
        body = material.to_dict()
        if (str(body["policy_id"]), material.policy_digest) not in additions:
            raise ValueError("extension production policy material does not match candidate")
        if connection.execute(
            "SELECT 1 FROM production_policy_materials WHERE policy_id=? OR policy_digest=?",
            (body["policy_id"], material.policy_digest),
        ).fetchone() is not None:
            raise ValueError("extension production policy identity is already registered")
        observed = parse_timestamp(observed_at, "production policy registration time")
        if not (
            parse_timestamp(body["not_before"], "production policy not-before")
            <= observed
            <= parse_timestamp(body["not_after"], "production policy not-after")
        ):
            raise ValueError("extension production policy is not currently valid")
        matches = [
            item for item in candidate.to_dict()["trust_keys"]
            if isinstance(item, Mapping)
            and item.get("publisher_id") == body["issuer_id"]
            and item.get("key_id") == body["issuer_key_id"]
            and item.get("status") == "active"
            and "provenance-policy" in item.get("roles", [])
            and material.policy_digest in item.get("allowed_production_policy_digests", [])
            and parse_timestamp(item.get("not_before"), "trust key not-before")
            <= observed
            <= parse_timestamp(item.get("not_after"), "trust key not-after")
        ]
        if len(matches) != 1 or not verifier.verify(
            material.verification_request(str(matches[0]["ed25519_public_key"]))
        ).valid:
            raise ValueError("extension production policy provenance is invalid")
        return material

    @staticmethod
    def _require_runtime_authority(
        authorization: Mapping[str, object], runtime: RuntimeContext
    ) -> None:
        if type(runtime) is not RuntimeContext:
            raise TypeError("extension trust mutation requires application runtime authority")
        runtime.require_issued()
        if authorization.get("owner_identity") != runtime.owner_id:
            raise ValueError("extension trust Owner authority does not match the live runtime")

    def commit(self, *args: object, **kwargs: object) -> ExtensionTrustSnapshot:
        del args, kwargs
        raise TypeError("extension trust mutation requires the live application gateway")

    def _commit_operations_issued(
        self,
        operations: tuple[ExtensionTrustOperation, ...],
        *,
        authorization: object,
        runtime: RuntimeContext,
        production_policy: ExtensionAttestationProductionPolicy | None = None,
        verifier: Ed25519Verifier | None = None,
    ) -> ExtensionTrustSnapshot:
        return self._terminal_transaction(
            operations, authorization, terminal_kind="commit", runtime=runtime,
            production_policy=production_policy, verifier=verifier,
        )

    def rollback(self, *args: object, **kwargs: object) -> ExtensionTrustSnapshot:
        del args, kwargs
        raise TypeError("extension trust mutation requires the live application gateway")

    def _rollback_operations_issued(
        self,
        operations: tuple[ExtensionTrustOperation, ...],
        *,
        rollback_of_record_digest: str,
        restore_content_from_policy_digest: str,
        authorization: object,
        runtime: RuntimeContext,
    ) -> ExtensionTrustSnapshot:
        return self._terminal_transaction(
            operations,
            authorization,
            terminal_kind="rollback",
            rollback_of_record_digest=rollback_of_record_digest,
            restore_content_from_policy_digest=restore_content_from_policy_digest,
            runtime=runtime,
        )

    def abort(self, *args: object, **kwargs: object) -> ExtensionTrustSnapshot:
        del args, kwargs
        raise TypeError("extension trust mutation requires the live application gateway")

    def _abort_issued(
        self,
        *,
        operations: tuple[ExtensionTrustOperation, ...],
        authorization: object,
        reason_code: str,
        runtime: RuntimeContext,
    ) -> ExtensionTrustSnapshot:
        authorization = self._authorization(authorization)
        self._require_runtime_authority(authorization, runtime)
        self._require_operation_authority(authorization, operations)
        transaction_id = str(authorization["transaction_id"])
        expected_head_digest = str(authorization["expected_head_digest"])
        owner_identity = str(authorization["owner_identity"])
        owner_decision_digest = str(authorization["owner_decision_digest"])
        owner_authority_digest = str(authorization["owner_authority_digest"])
        ordered_operations_digest = str(authorization["ordered_operations_digest"])
        created_at = str(authorization["created_at"])
        token = self._manager._control_lock.acquire("exclusive")
        try:
            manifest = self._manager._current_manifest()
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    current = self._load(connection, expected_installation_id=manifest.installation_id)
                    if expected_head_digest != current.head.head_digest:
                        raise ValueError("extension trust head CAS is stale")
                    if self._reducer is None:
                        raise MigrationRepositoryError("extension trust reducer is unavailable")
                    candidate = self._reducer.reduce(current.policy, operations)
                    ordered_digest = semantic_digest(
                        {"schema_version": "1.0.0", "operations": [item.to_dict() for item in operations]},
                        contract_type="urn:gew:contract:extension-trust-ordered-operations",
                        projection_id="urn:gew:digest-projection:extension-trust-ordered-operations:1.0.0",
                        schema_id="urn:gew:schema:extension-trust-ordered-operations-input:1.0.0",
                    )
                    if ordered_operations_digest != ordered_digest:
                        raise ValueError("extension trust ordered operations authorization mismatch")
                    sequence = len(current.ledger) + 1
                    previous_record = current.ledger[-1].record_digest if current.ledger else None
                    prepared = self._prepared(current, candidate, authorization, sequence, previous_record)
                    self._insert_record(connection, prepared)
                    abort_body: dict[str, object] = {
                        "schema_version": "1.0.0",
                        "record_type": "abort",
                        "installation_id": current.policy.installation_id,
                        "transaction_id": transaction_id,
                        "record_sequence": sequence + 1,
                        "previous_record_digest": prepared.record_digest,
                        "expected_head_digest": current.head.head_digest,
                        "owner_identity": owner_identity,
                        "owner_decision_digest": owner_decision_digest,
                        "owner_authority_digest": owner_authority_digest,
                        "created_at": created_at,
                        "prepared_record_digest": prepared.record_digest,
                        "observed_head_digest": current.head.head_digest,
                        "reason_code": reason_code,
                        "aborted_at": created_at,
                    }
                    aborted = self._record(abort_body, "abort", current.policy)
                    self._insert_record(connection, aborted)
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
                return self._load(connection, expected_installation_id=manifest.installation_id)
            finally:
                connection.close()
        finally:
            self._manager._control_lock.release(token)

    def verify_publisher_revocation(
        self,
        statement: ExtensionPublisherRevocationStatement,
        verifier: Ed25519Verifier,
        *,
        observed_at: str,
    ) -> VerifiedPublisherRevocation:
        if type(statement) is not ExtensionPublisherRevocationStatement:
            raise TypeError("publisher revocation input is invalid")
        require_attested = getattr(type(verifier), "require_attested", None)
        if not callable(require_attested) or require_attested(verifier) is not verifier:
            raise TypeError("publisher revocation verifier is not factory-attested")
        inspected = ExtensionPublisherRevocationStatement.from_dict(statement.to_dict())
        document = inspected.to_dict()
        observed = parse_timestamp(observed_at, "publisher revocation observation time")
        issued = parse_timestamp(document["issued_at"], "publisher revocation issued-at")
        token = self._manager._control_lock.acquire("exclusive")
        try:
            connection = self._connect()
            try:
                manifest = self._manager._current_manifest()
                current = self._load(
                    connection, expected_installation_id=manifest.installation_id
                )
                matches = [
                    item
                    for item in current.policy.to_dict()["trust_keys"]
                    if isinstance(item, Mapping)
                    and item.get("publisher_id") == document["publisher_id"]
                    and item.get("key_id") == document["publisher_key_id"]
                    and item.get("status") == "active"
                    and "publisher-revocation" in item.get("roles", [])
                    and parse_timestamp(item.get("not_before"), "trust key not-before")
                    <= issued
                    <= observed
                    <= parse_timestamp(item.get("not_after"), "trust key not-after")
                ]
                if len(matches) != 1:
                    raise ValueError("publisher revocation key role or time is invalid")
                result = verifier.verify(
                    inspected.verification_request(str(matches[0]["ed25519_public_key"]))
                )
                if not result.valid:
                    raise ValueError("publisher revocation signature is invalid")
                sequence = int(document["publisher_sequence"])
                previous = connection.execute(
                    "SELECT MAX(publisher_sequence) FROM publisher_revocation_inputs "
                    "WHERE publisher_id=? AND publisher_key_id=?",
                    (document["publisher_id"], document["publisher_key_id"]),
                ).fetchone()[0]
                if previous is not None and sequence <= int(previous):
                    raise ValueError("publisher revocation sequence is stale")
                verified = VerifiedPublisherRevocation(
                    inspected, current.policy.policy_digest, sequence
                )
                _ISSUED_PUBLISHER_REVOCATIONS[id(verified)] = verified
                return verified
            finally:
                connection.close()
        finally:
            self._manager._control_lock.release(token)

    @staticmethod
    def _require_verified_revocation(
        connection: sqlite3.Connection,
        verified: VerifiedPublisherRevocation,
        policy_digest: str,
    ) -> None:
        if (
            type(verified) is not VerifiedPublisherRevocation
            or _ISSUED_PUBLISHER_REVOCATIONS.get(id(verified)) is not verified
            or verified.policy_digest != policy_digest
        ):
            raise ValueError("publisher revocation verification is missing or stale")
        document = verified.statement.to_dict()
        previous = connection.execute(
            "SELECT MAX(publisher_sequence) FROM publisher_revocation_inputs "
            "WHERE publisher_id=? AND publisher_key_id=?",
            (document["publisher_id"], document["publisher_key_id"]),
        ).fetchone()[0]
        if previous is not None and verified.publisher_sequence <= int(previous):
            raise ValueError("publisher revocation sequence is stale")

    def apply_publisher_revocation(self, *args: object, **kwargs: object) -> ExtensionTrustSnapshot:
        del args, kwargs
        raise TypeError("publisher revocation requires the live application gateway")

    def _apply_publisher_revocation_issued(
        self,
        verified: VerifiedPublisherRevocation,
        *,
        operation: ExtensionTrustOperation,
        authorization: object,
        runtime: RuntimeContext,
    ) -> ExtensionTrustSnapshot:
        if authorization is None:
            raise ValueError("Owner authorization is required for publisher revocation")
        if type(verified) is not VerifiedPublisherRevocation:
            raise TypeError("verified publisher revocation input is invalid")
        inspected = verified.statement
        if type(operation) is not ExtensionTrustOperation:
            raise TypeError("publisher revocation operation is invalid")
        authorization_document = self._authorization(authorization)
        current = self.current()
        if self._reducer is None:
            raise MigrationRepositoryError("extension trust reducer is unavailable")
        candidate = self._reducer.reduce(current.policy, (operation,))
        entry = operation.to_dict()["new_value"]
        statement_document = inspected.to_dict()
        if operation.operation_kind != "apply-publisher-revocation" or not isinstance(entry, dict) or (
            entry.get("target_kind") != statement_document["target_kind"]
            or entry.get("target_identity_digest") != statement_document["target_identity_digest"]
            or entry.get("input_kind") != "publisher-revocation"
            or entry.get("input_digest") != inspected.statement_digest
            or entry.get("reason_code") != statement_document["reason_code"]
            or entry.get("local_sequence") != current.policy.revocation_high_water + 1
            or entry.get("effective_generation") != current.policy.generation + 1
        ):
            raise ValueError("publisher revocation candidate binding is invalid")
        return self._terminal_transaction(
            (operation,),
            authorization_document,
            terminal_kind="commit",
            runtime=runtime,
            verified_revocation=verified,
        )
