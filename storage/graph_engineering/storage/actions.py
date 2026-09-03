"""Durable action journal and atomic journal deltas."""

from __future__ import annotations

import copy
import datetime
import hmac
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.actions import ActionJournalRecord, AuthorityEnvelope, PreparedAction
from graph_engineering.core.contracts.canonical import canonical_text
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.contracts.strict_json import parse_json

from .codec import canonical_json, parse_canonical_json, require_jcs_digest, semantic_record_digest
from .connection import ConnectionFactory, ManagedConnection
from .clock import trusted_now
from .errors import RepositoryConflictError, RepositoryIntegrityError


@dataclass(frozen=True, slots=True)
class CurrentTaskHead:
    revision: int
    sequence: int
    head_digest: str
    snapshot: dict[str, object]


class ActionJournalRepository:
    def __init__(
        self,
        factory: ConnectionFactory,
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> None:
        if (
            type(factory) is not ConnectionFactory
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise RepositoryIntegrityError("action journal requires attested bounded dependencies")
        self._factory = factory
        self._schemas = schema_registry
        self._context = context

    def record_prepared(self, prepared: PreparedAction) -> ActionJournalRecord:
        if type(prepared) is not PreparedAction:
            raise RepositoryIntegrityError("prepared action contract is invalid")
        document = self.prepared_document(prepared)
        with self._factory.open("application") as connection:
            with connection.transaction():
                existing = connection.execute(
                    "SELECT prepared_digest FROM action_journal WHERE action_id=?", (prepared.action_id,),
                ).fetchone()
                if existing is not None:
                    if not hmac.compare_digest(existing[0], prepared.prepared_action_digest):
                        raise RepositoryConflictError("action ID was reused for different prepared content")
                    return self._load(connection, prepared.action_id)
                duplicate = connection.execute(
                    "SELECT state FROM action_journal WHERE task_id=? AND idempotency_key=?",
                    (prepared.task_id, prepared.idempotency_key),
                ).fetchone()
                if duplicate is not None:
                    raise RepositoryConflictError("idempotency key already has journal history")
                connection.execute(
                    "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,prepared_json,prepared_digest) "
                    "VALUES(?,?,'prepared',1,?,?,?)",
                    (prepared.action_id, prepared.task_id, prepared.idempotency_key, canonical_json(document), prepared.prepared_action_digest),
                )
                return self._load(connection, prepared.action_id)

    def record_authorized(self, authority: AuthorityEnvelope) -> ActionJournalRecord:
        if type(authority) is not AuthorityEnvelope:
            raise RepositoryIntegrityError("authority contract is invalid")
        document = self.authority_document(authority)
        with self._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT task_id,state,prepared_digest FROM action_journal WHERE prepared_digest=?",
                    (authority.prepared_action_digest,),
                ).fetchone()
                if row is None or row[0] != authority.task_id or row[1] != "prepared":
                    raise RepositoryConflictError("authority does not bind one current prepared action")
                if authority.status != "active":
                    raise RepositoryConflictError("only active authority can authorize an action")
                connection.execute(
                    "UPDATE action_journal SET state='authorized',revision=revision+1,authority_json=?,authority_digest=? "
                    "WHERE prepared_digest=? AND state='prepared'",
                    (canonical_json(document), authority.authority_digest, authority.prepared_action_digest),
                )
                action_id = connection.execute(
                    "SELECT action_id FROM action_journal WHERE prepared_digest=?", (authority.prepared_action_digest,),
                ).fetchone()[0]
                return self._load(connection, action_id)

    def revoke(self, action_id: str, authority_id: str) -> ActionJournalRecord:
        with self._factory.open("application") as connection:
            with connection.transaction():
                record = self._load(connection, action_id)
                if record.authority is None or record.authority.authority_id != authority_id or record.state != "authorized":
                    raise RepositoryConflictError("authority is not active for this action")
                changed = connection.execute(
                    "UPDATE action_journal SET state='revoked',revision=revision+1 WHERE action_id=? AND state='authorized'",
                    (action_id,),
                ).rowcount
                if changed != 1:
                    raise RepositoryConflictError("authority revocation lost its journal CAS")
                return self._load(connection, action_id)

    def load(self, action_id: str) -> ActionJournalRecord:
        with self._factory.open("doctor") as connection:
            return self._load(connection, action_id)

    def find_prepared(self, prepared_digest: str) -> ActionJournalRecord:
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT action_id FROM action_journal WHERE prepared_digest=?", (prepared_digest,),
            ).fetchone()
            if row is None:
                raise RepositoryConflictError("prepared action is not durable")
            return self._load(connection, row[0])

    def load_prepared_in_transaction(
        self,
        connection: ManagedConnection,
        prepared_digest: str,
    ) -> PreparedAction:
        """Load one bounded, schema-validated PreparedAction on the caller transaction."""

        require_jcs_digest(prepared_digest)
        row = connection.execute(
            "SELECT action_id,prepared_json,prepared_digest FROM action_journal "
            "WHERE prepared_digest=?",
            (prepared_digest,),
        ).fetchone()
        if row is None or row[2] != prepared_digest:
            raise RepositoryConflictError("prepared action is not durable")
        value = self._parse_stored(
            row[1], schema_id="urn:gew:schema:prepared-action:1.0.0",
            source_id=f"action-journal:{row[0]}:repository-boundary-prepared",
        )
        prepared = PreparedAction.from_dict(value, context=self._context)
        if prepared.action_id != row[0] or prepared.prepared_action_digest != prepared_digest:
            raise RepositoryIntegrityError("durable prepared action binding is invalid")
        return prepared

    def current_task_head(self, task_id: str) -> CurrentTaskHead:
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT revision,head_sequence,head_digest,snapshot_json FROM tasks WHERE task_id=? AND integrity_status='ok'",
                (task_id,),
            ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("action task head is missing or blocked")
        snapshot = parse_canonical_json(row[3])
        if type(snapshot) is not dict:
            raise RepositoryIntegrityError("action task snapshot is invalid")
        return CurrentTaskHead(row[0], row[1], row[2], snapshot)

    def current_time(self) -> str:
        """Return the repository-owned clock; callers cannot supply reconciliation time."""
        with self._factory.open("doctor") as connection:
            value = trusted_now(connection)
        return datetime.datetime.fromtimestamp(
            value / 1_000_000_000,
            tz=datetime.timezone.utc,
        ).isoformat(timespec="seconds").replace("+00:00", "Z")

    def current_task_snapshot_digest(self, task_id: str) -> str:
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT snapshot_digest FROM tasks WHERE task_id=? AND integrity_status='ok'",
                (task_id,),
            ).fetchone()
        if row is None or type(row[0]) is not str:
            raise RepositoryIntegrityError("current task snapshot digest is missing")
        return row[0]

    @staticmethod
    def start_delta(record: ActionJournalRecord) -> dict[str, object]:
        if record.state != "authorized" or record.authority is None:
            raise RepositoryConflictError("action is not authorized")
        return {
            "operation": "start", "action_id": record.action_id, "expected_state": "authorized",
            "expected_revision": record.revision, "prepared_digest": record.prepared.prepared_action_digest,
            "authority_digest": record.authority.authority_digest,
        }

    @staticmethod
    def receipt_delta(
        record: ActionJournalRecord,
        *,
        state: str,
        receipt: dict[str, object],
        receipt_event_digest: str,
    ) -> dict[str, object]:
        if record.state != "executing" or state not in {"succeeded", "failed", "unknown"}:
            raise RepositoryConflictError("receipt requires one executing action")
        canonical_json(receipt)
        return {
            "operation": "receipt",
            "action_id": record.action_id,
            "task_id": record.task_id,
            "claim_id": f"claim:{record.action_id}",
            "expected_state": "executing",
            "expected_revision": record.revision,
            "next_state": state,
            "receipt": copy.deepcopy(receipt),
            "receipt_event_digest": receipt_event_digest,
        }

    @staticmethod
    def reconcile_delta(record: ActionJournalRecord, body: dict[str, object], *, compensated: bool = False) -> dict[str, object]:
        if record.state not in {"executing", "succeeded", "failed", "unknown"}:
            raise RepositoryConflictError("action has no reconcilable started state")
        canonical_json(body)
        return {
            "operation": "reconcile", "action_id": record.action_id, "expected_state": record.state,
            "expected_revision": record.revision, "next_state": "compensated" if compensated else "reconciled",
            "reconciliation": copy.deepcopy(body),
        }

    @staticmethod
    def compensation_start_delta(record: ActionJournalRecord) -> dict[str, object]:
        value = ActionJournalRepository.start_delta(record)
        value["operation"] = "compensation_start"
        return value

    @staticmethod
    def compensation_receipt_delta(
        record: ActionJournalRecord,
        *,
        state: str,
        receipt: dict[str, object],
    ) -> dict[str, object]:
        if record.state != "executing" or state not in {"succeeded", "failed", "unknown"}:
            raise RepositoryConflictError("compensation receipt requires one executing action")
        canonical_json(receipt)
        return {
            "operation": "compensation_receipt", "action_id": record.action_id,
            "expected_state": "executing", "expected_revision": record.revision,
            "next_state": state, "receipt": copy.deepcopy(receipt),
        }

    @staticmethod
    def compensation_reconcile_delta(
        original: ActionJournalRecord,
        compensation: ActionJournalRecord,
        body: dict[str, object],
    ) -> dict[str, object]:
        if original.state not in {"executing", "unknown"} or compensation.state != "succeeded":
            raise RepositoryConflictError("compensation reconciliation states are not current")
        canonical_json(body)
        return {
            "operation": "compensation_reconcile",
            "original_action_id": original.action_id,
            "original_expected_state": original.state,
            "original_expected_revision": original.revision,
            "compensation_action_id": compensation.action_id,
            "compensation_expected_revision": compensation.revision,
            "reconciliation": copy.deepcopy(body),
        }

    @classmethod
    def apply_delta(
        cls,
        connection: ManagedConnection,
        delta: dict[str, object],
        events_by_digest: dict[str, dict[str, object]],
    ) -> None:
        if type(delta) is not dict or delta.get("operation") not in {
            "start", "receipt", "reconcile", "compensation_start",
            "compensation_receipt", "compensation_reconcile",
        }:
            raise RepositoryIntegrityError("action journal delta is invalid")
        if delta["operation"] in {"start", "compensation_start"}:
            required = {"operation", "action_id", "expected_state", "expected_revision", "prepared_digest", "authority_digest"}
            if set(delta) != required:
                raise RepositoryIntegrityError("action start delta shape is not exact")
            changed = connection.execute(
                "UPDATE action_journal SET state='executing',revision=revision+1 WHERE action_id=? AND state=? "
                "AND revision=? AND prepared_digest=? AND authority_digest=?",
                (delta["action_id"], delta["expected_state"], delta["expected_revision"], delta["prepared_digest"], delta["authority_digest"]),
            ).rowcount
        elif delta["operation"] == "receipt":
            required = {
                "operation", "action_id", "task_id", "claim_id", "expected_state",
                "expected_revision", "next_state", "receipt", "receipt_event_digest",
            }
            if (
                set(delta) != required
                or delta["next_state"] not in {"succeeded", "failed", "unknown"}
                or type(delta["receipt"]) is not dict
            ):
                raise RepositoryIntegrityError("action receipt delta shape is not exact")
            event = events_by_digest.get(delta["receipt_event_digest"])
            claim = connection.execute(
                "SELECT action_id,task_id,state,started_event_digest FROM claims WHERE claim_id=?",
                (delta["claim_id"],),
            ).fetchone()
            receipt = delta["receipt"]
            if (
                event is None
                or event["event_type"] != "action.receipt_recorded"
                or event["task_id"] != delta["task_id"]
                or event["payload"].get("action_id") != delta["action_id"]  # type: ignore[union-attr]
                or event["payload"].get("claim_id") != delta["claim_id"]  # type: ignore[union-attr]
                or event["payload"].get("receipt_digest") != receipt.get("receipt_digest")  # type: ignore[union-attr]
                or event["payload"].get("raw_receipt_object_digest")  # type: ignore[union-attr]
                != receipt.get("raw_receipt_object_digest")
                or claim is None
                or claim[0] != delta["action_id"]
                or claim[1] != delta["task_id"]
                or claim[2] != "unresolved"
                or receipt.get("action_id") != delta["action_id"]  # type: ignore[union-attr]
                or receipt.get("task_id") != delta["task_id"]  # type: ignore[union-attr]
                or receipt.get("claim_id") != delta["claim_id"]  # type: ignore[union-attr]
                or receipt.get("started_event_digest") != claim[3]  # type: ignore[union-attr]
            ):
                raise RepositoryIntegrityError("receipt is not exactly bound to event/action/task/claim")
            cls._validate_stored_receipt(receipt)
            changed = connection.execute(
                "UPDATE action_journal SET state=?,revision=revision+1,receipt_json=? "
                "WHERE action_id=? AND task_id=? AND state=? AND revision=?",
                (
                    delta["next_state"], canonical_json(receipt), delta["action_id"],
                    delta["task_id"], delta["expected_state"], delta["expected_revision"],
                ),
            ).rowcount
        elif delta["operation"] == "reconcile":
            required = {"operation", "action_id", "expected_state", "expected_revision", "next_state", "reconciliation"}
            if set(delta) != required or delta["next_state"] not in {"reconciled", "compensated"} or type(delta["reconciliation"]) is not dict:
                raise RepositoryIntegrityError("action reconciliation delta shape is not exact")
            changed = connection.execute(
                "UPDATE action_journal SET state=?,revision=revision+1,reconciliation_json=? WHERE action_id=? AND state=? AND revision=?",
                (delta["next_state"], canonical_json(delta["reconciliation"]), delta["action_id"], delta["expected_state"], delta["expected_revision"]),
            ).rowcount
        elif delta["operation"] == "compensation_receipt":
            required = {
                "operation", "action_id", "expected_state", "expected_revision",
                "next_state", "receipt",
            }
            if set(delta) != required or delta["next_state"] not in {"succeeded", "failed", "unknown"}:
                raise RepositoryIntegrityError("compensation receipt journal delta is invalid")
            if type(delta["receipt"]) is not dict:
                raise RepositoryIntegrityError("compensation receipt body is invalid")
            cls._validate_stored_receipt(delta["receipt"])
            changed = connection.execute(
                "UPDATE action_journal SET state=?,revision=revision+1,receipt_json=? "
                "WHERE action_id=? AND state=? AND revision=?",
                (
                    delta["next_state"], canonical_json(delta["receipt"]), delta["action_id"],
                    delta["expected_state"], delta["expected_revision"],
                ),
            ).rowcount
        else:
            required = {
                "operation", "original_action_id", "original_expected_state",
                "original_expected_revision", "compensation_action_id",
                "compensation_expected_revision", "reconciliation",
            }
            if set(delta) != required or type(delta["reconciliation"]) is not dict:
                raise RepositoryIntegrityError("compensation reconciliation journal delta is invalid")
            original_changed = connection.execute(
                "UPDATE action_journal SET state='compensated',revision=revision+1,reconciliation_json=? "
                "WHERE action_id=? AND state=? AND revision=?",
                (
                    canonical_json(delta["reconciliation"]), delta["original_action_id"],
                    delta["original_expected_state"], delta["original_expected_revision"],
                ),
            ).rowcount
            compensation_changed = connection.execute(
                "UPDATE action_journal SET state='reconciled',revision=revision+1,reconciliation_json=? "
                "WHERE action_id=? AND state='succeeded' AND revision=?",
                (
                    canonical_json(delta["reconciliation"]), delta["compensation_action_id"],
                    delta["compensation_expected_revision"],
                ),
            ).rowcount
            changed = 1 if original_changed == 1 and compensation_changed == 1 else 0
        if changed != 1:
            raise RepositoryConflictError("action journal delta lost its exact CAS")

    @staticmethod
    def prepared_document(prepared: PreparedAction) -> dict[str, object]:
        return {
            "schema_version": "1.0.0", "action_id": prepared.action_id, "task_id": prepared.task_id,
            "action_kind": prepared.action_kind, "target_id": prepared.target_id, "target_digest": prepared.target_digest,
            "resources": list(prepared.resources), "payload": dict(prepared.payload), "payload_digest": prepared.payload_digest,
            "precondition": dict(prepared.precondition), "expected_postcondition": dict(prepared.expected_postcondition),
            "idempotency_class": prepared.idempotency_class, "idempotency_key": prepared.idempotency_key,
            "verification_plan": dict(prepared.verification_plan), "rollback_plan": dict(prepared.rollback_plan),
            "required_capabilities": list(prepared.required_capabilities), "baseline_digest": prepared.baseline_digest,
            "snapshot_digest": prepared.snapshot_digest, "prepared_action_digest": prepared.prepared_action_digest,
        }

    @staticmethod
    def authority_document(authority: AuthorityEnvelope) -> dict[str, object]:
        return {
            "schema_version": "1.0.0", "authority_id": authority.authority_id, "task_id": authority.task_id,
            "owner_id": authority.owner_id, "runtime_kind": authority.runtime_kind,
            "runtime_lineage_id": authority.runtime_lineage_id, "authorized_action_kind": authority.authorized_action_kind,
            "authorized_resources": list(authority.authorized_resources), "prepared_action_digest": authority.prepared_action_digest,
            "baseline_digest": authority.baseline_digest, "snapshot_digest": authority.snapshot_digest,
            "issued_at": authority.issued_at, "expires_at": authority.expires_at, "status": authority.status,
            "authority_digest": authority.authority_digest,
        }

    def _parse_stored(self, encoded: object, *, schema_id: str, source_id: str) -> dict[str, object]:
        if type(encoded) is not str:
            raise RepositoryIntegrityError("durable action journal body is invalid")
        try:
            parsed = parse_json(
                encoded,
                context=self._context,
                source_id=source_id,
                operation_path=self._context.child_path(()),
            )
            if type(parsed) is not dict or canonical_text(parsed) != encoded:
                raise ValueError("durable action journal body is not canonical")
            if self._schemas.validate(schema_id, parsed, self._context):
                raise ValueError("durable action journal body fails its installed schema")
            return parsed
        except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError) as error:
            raise RepositoryIntegrityError("durable action journal body is invalid or over budget") from error

    def _parse_stored_generic(self, encoded: object, *, source_id: str) -> dict[str, object]:
        if type(encoded) is not str:
            raise RepositoryIntegrityError("durable action result body is invalid")
        try:
            parsed = parse_json(
                encoded, context=self._context, source_id=source_id,
                operation_path=self._context.child_path(()),
            )
            if type(parsed) is not dict or canonical_text(parsed) != encoded:
                raise ValueError("durable action result body is not canonical")
            return parsed
        except (MemoryError, RecursionError, TypeError, UnicodeError, ValueError) as error:
            raise RepositoryIntegrityError("durable action result body is invalid or over budget") from error

    @staticmethod
    def _validate_stored_receipt(value: dict[str, object]) -> None:
        normal = {
            "action_id", "task_id", "claim_id", "started_event_digest",
            "prepared_action_digest", "authority_digest", "payload_digest", "target_id",
            "fencing_token", "result", "raw_result_digest", "raw_receipt_object_digest",
            "receipt_digest",
        }
        compensation = {
            "protocol_version", "attempt_id", "claim_id", "task_id", "original_action_id",
            "compensation_action_id", "start_event_digest", "authority_digest",
            "prepared_action_digest", "target_id", "target_digest", "lease_id", "resources",
            "fencing_tokens", "receipt_source", "result", "raw_result_digest",
            "raw_receipt_object_digest", "receipt_digest",
        }
        keys = set(value)
        contract = "action-receipt-v1" if keys == normal else (
            "claim-compensation-receipt-v1" if keys == compensation else None
        )
        if contract is None:
            raise RepositoryIntegrityError("durable action receipt shape is not exact")
        from .codec import require_object_digest
        require_object_digest(value.get("raw_receipt_object_digest"))
        expected = require_jcs_digest(value.get("receipt_digest"))
        actual = semantic_record_digest({
            "contract": contract,
            "value": {key: item for key, item in value.items() if key != "receipt_digest"},
        })
        if expected != actual:
            raise RepositoryIntegrityError("durable action receipt digest is invalid")

    @staticmethod
    def _validate_stored_reconciliation(value: dict[str, object]) -> None:
        observation = {
            "target_id", "target_digest", "resource_id", "fresh", "observation_revision", "state",
        }
        compensation = observation | {"bound_receipt_digest", "observation_digest"}
        keys = frozenset(value)
        if keys not in {frozenset(observation), frozenset(compensation)}:
            raise RepositoryIntegrityError("durable action reconciliation shape is not exact")
        if (
            value.get("fresh") is not True
            or type(value.get("observation_revision")) is not int
            or value.get("observation_revision", 0) <= 0
        ):
            raise RepositoryIntegrityError("durable action reconciliation evidence is invalid")
        if keys == frozenset(compensation):
            expected = require_jcs_digest(value.get("observation_digest"))
            actual = semantic_record_digest({
                "contract": "fresh-target-observation-v1",
                "value": {
                    key: item for key, item in value.items()
                    if key not in {"bound_receipt_digest", "observation_digest"}
                },
            })
            if expected != actual:
                raise RepositoryIntegrityError("durable action reconciliation digest is invalid")

    def _load(self, connection: ManagedConnection, action_id: str) -> ActionJournalRecord:
        row = connection.execute(
            "SELECT task_id,state,revision,prepared_json,authority_json,receipt_json,reconciliation_json FROM action_journal WHERE action_id=?",
            (action_id,),
        ).fetchone()
        if row is None:
            raise RepositoryConflictError("unknown action journal entry")
        prepared_value = self._parse_stored(
            row[3], schema_id="urn:gew:schema:prepared-action:1.0.0",
            source_id=f"action-journal:{action_id}:prepared",
        )
        authority_value = None if row[4] is None else self._parse_stored(
            row[4], schema_id="urn:gew:schema:authority-envelope:1.0.0",
            source_id=f"action-journal:{action_id}:authority",
        )
        receipt = None if row[5] is None else self._parse_stored_generic(
            row[5], source_id=f"action-journal:{action_id}:receipt",
        )
        reconciliation = None if row[6] is None else self._parse_stored_generic(
            row[6], source_id=f"action-journal:{action_id}:reconciliation",
        )
        if receipt is not None:
            self._validate_stored_receipt(receipt)
        if reconciliation is not None:
            self._validate_stored_reconciliation(reconciliation)
        if not isinstance(prepared_value, dict) or (authority_value is not None and not isinstance(authority_value, dict)):
            raise RepositoryIntegrityError("action journal contract body is invalid")
        prepared = PreparedAction.from_dict(prepared_value, context=self._context)
        authority = None if authority_value is None else AuthorityEnvelope.from_dict(
            authority_value, context=self._context,
        )
        if row[0] != prepared.task_id or type(row[2]) is not int or row[2] <= 0:
            raise RepositoryIntegrityError("action journal identity or revision is invalid")
        return ActionJournalRecord(action_id, row[0], row[1], row[2], prepared, authority, receipt, reconciliation)  # type: ignore[arg-type]
