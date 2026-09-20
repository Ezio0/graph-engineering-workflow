"""Durable trust roots and current-state reads for security gates."""

from __future__ import annotations

import datetime
import hmac
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts import canonical_text, parse_json
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security.retention import RetentionDecision

from .clock import trusted_now
from .codec import require_jcs_digest, semantic_record_digest
from .connection import ConnectionFactory, ManagedConnection
from .errors import RepositoryConflictError, RepositoryIntegrityError


_STATE_KEYS = frozenset({
    "schema_version",
    "task_id",
    "task_revision",
    "task_snapshot_digest",
    "binding",
    "destinations",
    "authority_digests",
    "data_refs",
    "evidence_expectations",
    "retention_subjects",
})
_JOURNAL_KEYS = frozenset({
    "schema_version",
    "receipt_id",
    "task_id",
    "action_id",
    "prepared_action_digest",
    "task_snapshot_digest",
    "receipt",
    "reconciliation_digest",
})


@dataclass(frozen=True, slots=True)
class InstalledSecurityRuntimeRecord:
    manifest: Mapping[str, object]
    manifest_id: str
    manifest_digest: str
    schema_registry_id: str
    schema_registry_digest: str


@dataclass(frozen=True, slots=True)
class CurrentTaskSecurityState:
    state: Mapping[str, object]
    state_digest: str
    current_time: str


@dataclass(frozen=True, slots=True)
class ReadOnlyTaskSecurityState:
    """Immutable current facts, without clock or mutation authority."""

    state: FrozenMap
    state_digest: str


@dataclass(frozen=True, slots=True)
class CurrentDisclosureJournalEntry:
    entry: Mapping[str, object]
    entry_digest: str


@dataclass(frozen=True, slots=True)
class ConsumedPurgeAuthorization:
    authorization_id: str
    task_id: str
    subject_ref: str
    subject_snapshot_digest: str
    security_state_digest: str
    decision_digest: str
    consumed_at_ns: int


class SecurityStateRepository:
    """Read current durable security state and consume purge fences atomically.

    This component deliberately has no public method that writes trust inputs.
    Task state and action-journal rows are committed by application transitions;
    installation state is created by the repository installation/migration path.
    """

    def __init__(self, factory: ConnectionFactory) -> None:
        if type(factory) is not ConnectionFactory:
            raise RepositoryIntegrityError("security state requires an attested repository")
        self._factory = factory

    @staticmethod
    def _mapping(value: object, keys: frozenset[str], label: str) -> dict[str, object]:
        if type(value) is not dict or set(value) != keys:
            raise RepositoryIntegrityError(f"{label} shape is not exact")
        return value

    @staticmethod
    def _identity(value: object, label: str) -> str:
        if type(value) is not str or not value or value != value.strip() or "\x00" in value:
            raise RepositoryIntegrityError(f"{label} is invalid")
        return value

    @staticmethod
    def _clock_text(value: int) -> str:
        try:
            result = datetime.datetime.fromtimestamp(
                value / 1_000_000_000,
                tz=datetime.timezone.utc,
            ).isoformat(timespec="seconds").replace("+00:00", "Z")
        except (OverflowError, OSError, ValueError) as error:
            raise RepositoryIntegrityError("repository security clock is invalid") from error
        return result

    @staticmethod
    def _parse_document(
        value: object,
        *,
        context: WorkContext,
        source_id: str,
    ) -> object:
        """Parse a durable canonical document inside the caller's work limits."""

        if type(value) is not str or type(context) is not WorkContext:
            raise RepositoryIntegrityError("durable security document input is invalid")
        try:
            body = value.encode("utf-8", errors="strict")
            parsed = parse_json(
                body,
                context=context,
                source_id=source_id,
                operation_path=context.child_path(()),
            )
            if canonical_text(parsed) != value:
                raise RepositoryIntegrityError("stored JSON is not canonical")
        except RepositoryIntegrityError:
            raise
        except (MemoryError, RecursionError, UnicodeError, TypeError, ValueError) as error:
            raise RepositoryIntegrityError("durable security document is invalid") from error
        return parsed

    def load_installed_runtime(
        self,
        context: WorkContext,
    ) -> InstalledSecurityRuntimeRecord:
        """Load the one immutable installation pin; callers cannot supply a substitute."""

        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT manifest_json,manifest_id,manifest_digest,schema_registry_id,"
                "schema_registry_digest FROM security_runtime_installation WHERE singleton=1",
            ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("installed security runtime is missing")
        manifest = self._parse_document(
            row[0],
            context=context,
            source_id="security-runtime-installation",
        )
        if type(manifest) is not dict:
            raise RepositoryIntegrityError("installed security runtime is not an object")
        manifest_id = self._identity(row[1], "installed security runtime ID")
        manifest_digest = require_jcs_digest(row[2])
        registry_id = self._identity(row[3], "installed security schema registry ID")
        registry_digest = require_jcs_digest(row[4])
        if (
            manifest.get("manifest_id") != manifest_id
            or manifest.get("manifest_digest") != manifest_digest
            or not isinstance(manifest.get("schema_registry"), dict)
            or manifest["schema_registry"].get("registry_id") != registry_id
            or manifest["schema_registry"].get("registry_digest") != registry_digest
        ):
            raise RepositoryIntegrityError("installed security runtime row is inconsistent")
        return InstalledSecurityRuntimeRecord(
            MappingProxyType(manifest),
            manifest_id,
            manifest_digest,
            registry_id,
            registry_digest,
        )

    @classmethod
    def _load_task_state(
        cls,
        connection: ManagedConnection,
        task_id: str,
        context: WorkContext,
    ) -> tuple[dict[str, object], str]:
        task_id = cls._identity(task_id, "task ID")
        row = connection.execute(
            "SELECT s.task_revision,s.task_snapshot_digest,s.state_json,s.state_digest,"
            "t.revision,t.snapshot_digest,t.integrity_status "
            "FROM task_security_states s JOIN tasks t ON t.task_id=s.task_id "
            "WHERE s.task_id=?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("current task security state is missing")
        task_revision, snapshot_digest, state_json, state_digest, current_revision, current_snapshot, status = row
        if (
            type(task_revision) is not int
            or task_revision != current_revision
            or snapshot_digest != current_snapshot
            or status != "ok"
        ):
            raise RepositoryIntegrityError("task security state is stale or task integrity is blocked")
        require_jcs_digest(snapshot_digest)
        require_jcs_digest(state_digest)
        state = cls._mapping(
            cls._parse_document(
                state_json,
                context=context,
                source_id=f"task-security-state:{task_id}",
            ),
            _STATE_KEYS,
            "task security state",
        )
        if (
            state.get("schema_version") != "1.0.0"
            or state.get("task_id") != task_id
            or state.get("task_revision") != task_revision
            or state.get("task_snapshot_digest") != snapshot_digest
            or not isinstance(state.get("binding"), dict)
            or state["binding"].get("task_id") != task_id
            or state["binding"].get("snapshot_digest") != snapshot_digest
        ):
            raise RepositoryIntegrityError("task security state does not bind the current task")
        actual = semantic_record_digest({
            "contract": "task-security-state-v1",
            "value": state,
        })
        if not hmac.compare_digest(state_digest, actual):
            raise RepositoryIntegrityError("task security state digest mismatch")
        for field in (
            "destinations",
            "data_refs",
            "evidence_expectations",
            "retention_subjects",
        ):
            if type(state.get(field)) is not dict:
                raise RepositoryIntegrityError(f"task security {field} is invalid")
        authorities = state.get("authority_digests")
        if (
            type(authorities) is not list
            or authorities != sorted(set(authorities))
        ):
            raise RepositoryIntegrityError("task security authority digests are not canonical")
        for digest in authorities:
            require_jcs_digest(digest)
        return state, state_digest

    def load_current_task_state_readonly(
        self,
        task_id: str,
        context: WorkContext,
    ) -> ReadOnlyTaskSecurityState:
        """Read one joined current row with SQLite-enforced zero-write access."""

        with self._factory.open("doctor") as connection:
            state, state_digest = self._load_task_state(connection, task_id, context)
        frozen = freeze(state)
        assert type(frozen) is FrozenMap
        return ReadOnlyTaskSecurityState(frozen, state_digest)

    def load_current_task_state(
        self,
        task_id: str,
        context: WorkContext,
    ) -> CurrentTaskSecurityState:
        """Read task state and the persisted non-decreasing clock in one transaction."""

        with self._factory.open("application") as connection:
            with connection.transaction():
                state, state_digest = self._load_task_state(connection, task_id, context)
                now = trusted_now(connection)
        return CurrentTaskSecurityState(
            MappingProxyType(state),
            state_digest,
            self._clock_text(now),
        )

    def load_disclosure_journal(
        self,
        receipt_id: str,
        context: WorkContext,
    ) -> CurrentDisclosureJournalEntry:
        """Read only a delivered/reconciled durable journal entry for a current task."""

        receipt_id = self._identity(receipt_id, "receipt ID")
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT task_id,entry_json,entry_digest,reconciliation_state "
                    "FROM disclosure_journal WHERE receipt_id=?",
                    (receipt_id,),
                ).fetchone()
                if row is None or row[3] not in {"delivered", "reconciled"}:
                    raise RepositoryIntegrityError("durable disclosure receipt is not delivered")
                state, _state_digest = self._load_task_state(connection, row[0], context)
                entry = self._mapping(
                    self._parse_document(
                        row[1],
                        context=context,
                        source_id=f"disclosure-journal:{receipt_id}",
                    ),
                    _JOURNAL_KEYS,
                    "disclosure journal entry",
                )
                entry_digest = require_jcs_digest(row[2])
                actual = semantic_record_digest({
                    "contract": "disclosure-journal-entry-v1",
                    "value": entry,
                    "reconciliation_state": row[3],
                })
                if not hmac.compare_digest(entry_digest, actual):
                    raise RepositoryIntegrityError("disclosure journal entry digest mismatch")
                receipt = entry.get("receipt")
                if (
                    entry.get("schema_version") != "1.0.0"
                    or entry.get("receipt_id") != receipt_id
                    or entry.get("task_id") != state["task_id"]
                    or entry.get("task_snapshot_digest") != state["task_snapshot_digest"]
                    or type(receipt) is not dict
                    or receipt.get("receipt_id") != receipt_id
                    or receipt.get("plan_digest") is None
                    or receipt.get("payload_digest") is None
                    or receipt.get("destination_identity_ref") is None
                    or receipt.get("receipt_digest") is None
                    or entry.get("prepared_action_digest") is None
                    or entry.get("reconciliation_digest") is None
                ):
                    raise RepositoryIntegrityError("disclosure journal entry binding is invalid")
                for field in (
                    "prepared_action_digest",
                    "task_snapshot_digest",
                    "reconciliation_digest",
                ):
                    require_jcs_digest(entry[field])
                for field in (
                    "plan_digest",
                    "payload_digest",
                    "target_receipt_digest",
                    "receipt_digest",
                ):
                    require_jcs_digest(receipt[field])
        return CurrentDisclosureJournalEntry(MappingProxyType(entry), entry_digest)

    def authorize_purge(
        self,
        task_id: str,
        decision: RetentionDecision,
        context: WorkContext,
    ) -> ConsumedPurgeAuthorization:
        """Re-read current blockers and atomically consume one exact purge decision."""

        if type(decision) is not RetentionDecision or decision.action != "purge":
            raise RepositoryIntegrityError("only an engine-issued purge decision can be authorized")
        task_id = self._identity(task_id, "task ID")
        with self._factory.open("application") as connection:
            with connection.transaction():
                state, state_digest = self._load_task_state(connection, task_id, context)
                if not hmac.compare_digest(decision.task_context_digest, state_digest):
                    raise RepositoryConflictError("purge decision is stale for current security state")
                subjects = state["retention_subjects"]
                assert isinstance(subjects, dict)
                subject = subjects.get(decision.subject_ref)
                if type(subject) is not dict:
                    raise RepositoryIntegrityError("retention subject is not current")
                snapshot_digest = require_jcs_digest(subject.get("snapshot_digest"))
                if not hmac.compare_digest(snapshot_digest, decision.subject_snapshot_digest):
                    raise RepositoryConflictError("retention subject changed after decision")
                if subject.get("sensitivity") == "secret" or any(
                    subject.get(field) is not False
                    for field in ("legal_hold", "rollback_dependency", "unresolved_action")
                ):
                    raise RepositoryConflictError("current durable retention blockers forbid purge")
                unresolved = connection.execute(
                    "SELECT 1 FROM claims WHERE task_id=? AND state='unresolved' LIMIT 1",
                    (task_id,),
                ).fetchone()
                if unresolved is not None:
                    raise RepositoryConflictError("current unresolved action claim forbids purge")
                if decision.tombstone_required is not True:
                    raise RepositoryIntegrityError("purge authorization requires an audit tombstone")
                decision_value = {
                    "action": decision.action,
                    "subject_ref": decision.subject_ref,
                    "category": decision.category,
                    "trigger": decision.trigger,
                    "tombstone_required": decision.tombstone_required,
                    "reason": decision.reason,
                    "subject_snapshot_digest": decision.subject_snapshot_digest,
                    "security_state_digest": decision.task_context_digest,
                }
                decision_digest = semantic_record_digest({
                    "contract": "retention-decision-v1",
                    "value": decision_value,
                })
                authorization_id = semantic_record_digest({
                    "contract": "consumed-purge-authorization-v1",
                    "task_id": task_id,
                    "decision_digest": decision_digest,
                })
                consumed_at = trusted_now(connection)
                try:
                    connection.execute(
                        "INSERT INTO purge_authorizations(authorization_id,task_id,subject_ref,"
                        "subject_snapshot_digest,security_state_digest,decision_digest,consumed_at_ns) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (
                            authorization_id,
                            task_id,
                            decision.subject_ref,
                            snapshot_digest,
                            state_digest,
                            decision_digest,
                            consumed_at,
                        ),
                    )
                except sqlite3.IntegrityError as error:
                    raise RepositoryConflictError("purge decision was already consumed") from error
        return ConsumedPurgeAuthorization(
            authorization_id,
            task_id,
            decision.subject_ref,
            snapshot_digest,
            state_digest,
            decision_digest,
            consumed_at,
        )
