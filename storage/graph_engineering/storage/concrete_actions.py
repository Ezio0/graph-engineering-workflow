"""Same-transaction validation for concrete action protocol records."""

from __future__ import annotations

from graph_engineering.core.action_adapters import (
    ActionAdapterContractError,
    ActionInvocation,
    ActionReceipt,
    TargetObservation,
)
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext

from .codec import canonical_json, parse_canonical_json
from .connection import ManagedConnection
from .errors import RepositoryIntegrityError


class ConcreteActionRecordRepository:
    """Apply typed concrete records only inside TaskRepository coordination."""

    @staticmethod
    def _parse_invocation(value: object) -> ActionInvocation:
        try:
            return ActionInvocation.from_dict(value)
        except ActionAdapterContractError as error:
            raise RepositoryIntegrityError("concrete invocation contract is invalid") from error

    @staticmethod
    def _parse_receipt(value: object) -> ActionReceipt:
        try:
            return ActionReceipt.from_dict(value)
        except ActionAdapterContractError as error:
            raise RepositoryIntegrityError("concrete receipt contract is invalid") from error

    @staticmethod
    def _parse_observation(value: object) -> TargetObservation:
        try:
            return TargetObservation.from_dict(value)
        except ActionAdapterContractError as error:
            raise RepositoryIntegrityError("concrete observation contract is invalid") from error

    @staticmethod
    def _stored(connection: ManagedConnection, record_type: str, action_id: str) -> dict[str, object]:
        row = connection.execute(
            "SELECT record_json FROM concrete_action_records WHERE record_type=? AND action_id=?",
            (record_type, action_id),
        ).fetchone()
        if row is None:
            raise RepositoryIntegrityError("prior concrete action record is missing")
        value = parse_canonical_json(row[0])
        if type(value) is not dict or canonical_json(value) != row[0]:
            raise RepositoryIntegrityError("prior concrete action record is not canonical")
        return value

    @staticmethod
    def _validate_invocation_state(
        connection: ManagedConnection,
        invocation: ActionInvocation,
    ) -> None:
        journal = connection.execute(
            "SELECT task_id,state,idempotency_key,prepared_json,prepared_digest,authority_digest "
            "FROM action_journal WHERE action_id=?",
            (invocation.action_id,),
        ).fetchone()
        if journal is None or journal[0] != invocation.task_id or journal[1] != "executing":
            raise RepositoryIntegrityError("concrete invocation action state is not executing")
        prepared = parse_canonical_json(journal[3])
        if type(prepared) is not dict:
            raise RepositoryIntegrityError("concrete invocation prepared action is invalid")
        exact_prepared = (
            journal[2] == invocation.idempotency_key,
            journal[4] == invocation.prepared_action_digest,
            journal[5] == invocation.authority_digest,
            prepared.get("task_id") == invocation.task_id,
            prepared.get("action_id") == invocation.action_id,
            prepared.get("target_id") == invocation.target_id,
            prepared.get("target_digest") == invocation.target_digest,
            tuple(prepared.get("resources", ())) == invocation.resources,
            prepared.get("idempotency_class") == invocation.idempotency_class,
            prepared.get("idempotency_key") == invocation.idempotency_key,
            prepared.get("payload_digest") == invocation.payload_digest,
        )
        if not all(exact_prepared):
            raise RepositoryIntegrityError("concrete invocation differs from durable action authority")
        claim = connection.execute(
            "SELECT task_id,lease_id,state FROM claims WHERE action_id=?",
            (invocation.action_id,),
        ).fetchone()
        if (
            claim is None
            or claim[0] != invocation.task_id
            or claim[1] != invocation.lease_id
            or claim[2] != "unresolved"
        ):
            raise RepositoryIntegrityError("concrete invocation claim binding is invalid")
        claim_rows = tuple(connection.execute(
            "SELECT cr.resource_id,cr.fencing_token FROM claim_resources cr "
            "JOIN claims c ON c.claim_id=cr.claim_id WHERE c.action_id=? ORDER BY cr.resource_id",
            (invocation.action_id,),
        ))
        lease_rows = tuple(connection.execute(
            "SELECT resource_id,fencing_token FROM lease_resources WHERE lease_id=? ORDER BY resource_id",
            (invocation.lease_id,),
        ))
        expected = tuple(
            (item["resource_id"], item["token"]) for item in invocation.fencing_tokens
        )
        if claim_rows != expected or lease_rows != expected:
            raise RepositoryIntegrityError("concrete invocation full fence set is not durable")
        latest = tuple(connection.execute(
            "SELECT resource_id,fencing_token FROM resource_fences "
            f"WHERE resource_id IN ({','.join('?' for _ in invocation.resources)}) ORDER BY resource_id",
            invocation.resources,
        ))
        if latest != expected:
            raise RepositoryIntegrityError("concrete invocation fence is not repository latest")

    @classmethod
    def apply_delta(
        cls,
        connection: ManagedConnection,
        delta: dict[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> None:
        if type(delta) is not dict or set(delta) != {"operation", "record"}:
            raise RepositoryIntegrityError("concrete action delta shape is not exact")
        operation = delta["operation"]
        record = delta["record"]
        schema_id = {
            "invocation": "urn:gew:schema:action-invocation:1.0.0",
            "receipt": "urn:gew:schema:action-receipt:1.0.0",
            "observation": "urn:gew:schema:target-observation:1.0.0",
        }.get(operation)
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or schema_id is None
            or schema_registry.validate(schema_id, record, context)
        ):
            raise RepositoryIntegrityError("concrete action record fails installed schema")
        if operation == "invocation":
            parsed = cls._parse_invocation(record)
            cls._validate_invocation_state(connection, parsed)
            record_digest = parsed.invocation_digest
            receipt_digest = None
            invocation_digest = parsed.invocation_digest
            task_id = parsed.task_id
            action_id = parsed.action_id
        elif operation == "receipt":
            parsed_receipt = cls._parse_receipt(record)
            invocation = cls._parse_invocation(cls._stored(
                connection, "invocation", parsed_receipt.action_id,
            ))
            try:
                parsed_receipt.require_invocation(invocation)
            except ActionAdapterContractError as error:
                raise RepositoryIntegrityError("concrete receipt invocation binding changed") from error
            journal = connection.execute(
                "SELECT state FROM action_journal WHERE action_id=?", (parsed_receipt.action_id,),
            ).fetchone()
            if journal is None or journal[0] != parsed_receipt.result:
                raise RepositoryIntegrityError("concrete receipt state is not journal current")
            record_digest = parsed_receipt.receipt_digest
            receipt_digest = parsed_receipt.receipt_digest
            invocation_digest = parsed_receipt.invocation_digest
            task_id = parsed_receipt.task_id
            action_id = parsed_receipt.action_id
        elif operation == "observation":
            parsed_observation = cls._parse_observation(record)
            receipt = cls._parse_receipt(cls._stored(
                connection, "receipt", parsed_observation.action_id,
            ))
            try:
                parsed_observation.require_receipt(receipt)
            except ActionAdapterContractError as error:
                raise RepositoryIntegrityError("concrete observation receipt binding changed") from error
            journal = connection.execute(
                "SELECT state FROM action_journal WHERE action_id=?", (parsed_observation.action_id,),
            ).fetchone()
            if journal is None or journal[0] != "reconciled":
                raise RepositoryIntegrityError("concrete observation is not reconciled in journal")
            record_digest = parsed_observation.observation_digest
            receipt_digest = parsed_observation.receipt_digest
            invocation_digest = parsed_observation.invocation_digest
            task_id = parsed_observation.task_id
            action_id = parsed_observation.action_id
        else:
            raise RepositoryIntegrityError("concrete action delta operation is invalid")
        encoded = canonical_json(record)
        connection.execute(
            "INSERT INTO concrete_action_records(record_digest,record_type,task_id,action_id,"
            "invocation_digest,receipt_digest,record_json) VALUES(?,?,?,?,?,?,?)",
            (
                record_digest, operation, task_id, action_id,
                invocation_digest, receipt_digest, encoded,
            ),
        )
