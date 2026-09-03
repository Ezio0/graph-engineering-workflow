"""Atomic global leases, monotonic fences, and durable action claims."""

from __future__ import annotations

from .clock import trusted_now
from .codec import canonical_json, require_jcs_digest, require_object_digest, semantic_record_digest
from .connection import ConnectionFactory, ManagedConnection
from .errors import RepositoryConflictError, RepositoryIntegrityError
from .locks import LockedFileRegistry
from .ports import LeaseGrant


class ResourceLeaseRepository:
    RECONCILED_STATES = frozenset({
        "reconciled_no_effect", "reconciled_effect_verified", "compensation_reconciled",
    })

    def __init__(
        self,
        factory: ConnectionFactory,
        locks: LockedFileRegistry,
    ) -> None:
        self._factory = factory
        self._locks = locks

    @staticmethod
    def _identity(value: object, label: str) -> str:
        if type(value) is not str or not value or "\x00" in value:
            raise RepositoryIntegrityError(f"{label} is invalid")
        return value

    @classmethod
    def _resources(cls, resources: tuple[str, ...]) -> tuple[str, ...]:
        if not resources or any(type(item) is not str for item in resources):
            raise RepositoryIntegrityError("resource set is empty or invalid")
        for item in resources:
            cls._identity(item, "resource ID")
        canonical = tuple(sorted(set(resources)))
        if len(canonical) != len(resources):
            raise RepositoryIntegrityError("resource set contains duplicates")
        return canonical

    @staticmethod
    def _grant(connection: ManagedConnection, lease_id: str) -> LeaseGrant:
        lease = connection.execute(
            "SELECT expires_at,heartbeat_revision FROM leases WHERE lease_id=?", (lease_id,),
        ).fetchone()
        if lease is None:
            raise RepositoryIntegrityError("lease disappeared")
        rows = connection.execute(
            "SELECT resource_id,fencing_token FROM lease_resources WHERE lease_id=? ORDER BY resource_id",
            (lease_id,),
        ).fetchall()
        return LeaseGrant(
            lease_id,
            tuple(row[0] for row in rows),
            tuple((row[0], row[1]) for row in rows),
            lease[1],
            lease[0],
        )

    def acquire_many(
        self,
        *,
        lease_id: str,
        task_id: str,
        run_id: str,
        operation_id: str,
        resources: tuple[str, ...],
        ttl_ns: int,
    ) -> LeaseGrant:
        for label, value in (
            ("lease ID", lease_id), ("task ID", task_id), ("run ID", run_id),
            ("operation ID", operation_id),
        ):
            self._identity(value, label)
        canonical = self._resources(resources)
        if type(ttl_ns) is not int or ttl_ns <= 0:
            raise RepositoryIntegrityError("lease TTL is invalid")
        request = {
            "lease_id": lease_id, "task_id": task_id, "run_id": run_id,
            "operation_id": operation_id, "resources": list(canonical),
            "ttl_ns": ttl_ns,
        }
        request_digest = semantic_record_digest({"contract": "resource-lease-v1", "value": request})
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                with connection.transaction():
                    issued_at = trusted_now(connection)
                    expires_at = issued_at + ttl_ns
                    duplicate = connection.execute(
                        "SELECT request_digest,state,expires_at FROM leases WHERE lease_id=?", (lease_id,),
                    ).fetchone()
                    if duplicate is not None:
                        if duplicate[0] != request_digest:
                            raise RepositoryConflictError("lease ID was reused for another request")
                        if duplicate[1] != "live" or duplicate[2] <= issued_at:
                            raise RepositoryConflictError("idempotent lease result is no longer live")
                        return self._grant(connection, lease_id)
                    placeholders = ",".join("?" for _ in canonical)
                    claims = connection.execute(
                        "SELECT cr.resource_id FROM claim_resources cr JOIN claims c ON c.claim_id=cr.claim_id "
                        f"WHERE c.state='unresolved' AND cr.resource_id IN ({placeholders}) LIMIT 1",
                        canonical,
                    ).fetchone()
                    if claims is not None:
                        raise RepositoryConflictError("resource is frozen by unresolved action claim")
                    connection.execute(
                        "UPDATE leases SET state='expired' WHERE state='live' AND expires_at<=?",
                        (issued_at,),
                    )
                    conflict = connection.execute(
                        "SELECT lr.resource_id FROM lease_resources lr JOIN leases l ON l.lease_id=lr.lease_id "
                        f"WHERE l.state='live' AND l.expires_at>? AND lr.resource_id IN ({placeholders}) LIMIT 1",
                        (issued_at, *canonical),
                    ).fetchone()
                    if conflict is not None:
                        raise RepositoryConflictError("resource has a live conflicting lease")
                    tokens: list[tuple[str, int]] = []
                    for resource in canonical:
                        current = connection.execute(
                            "SELECT fencing_token FROM resource_fences WHERE resource_id=?", (resource,),
                        ).fetchone()
                        token = 1 if current is None else current[0] + 1
                        connection.execute(
                            "INSERT INTO resource_fences(resource_id,fencing_token) VALUES(?,?) "
                            "ON CONFLICT(resource_id) DO UPDATE SET fencing_token=excluded.fencing_token",
                            (resource, token),
                        )
                        tokens.append((resource, token))
                    connection.execute(
                        "INSERT INTO leases(lease_id,request_digest,task_id,run_id,operation_id,issued_at,expires_at,heartbeat_revision,state) "
                        "VALUES(?,?,?,?,?,?,?,0,'live')",
                        (
                            lease_id, request_digest, task_id, run_id, operation_id,
                            issued_at, expires_at,
                        ),
                    )
                    connection.executemany(
                        "INSERT INTO lease_resources(lease_id,resource_id,fencing_token) VALUES(?,?,?)",
                        [(lease_id, resource, token) for resource, token in tokens],
                    )
                    return LeaseGrant(lease_id, canonical, tuple(tokens), 0, expires_at)
        finally:
            self._locks.release(installation)

    def renew(
        self,
        lease_id: str,
        *,
        expected_heartbeat_revision: int,
        ttl_ns: int,
    ) -> LeaseGrant:
        self._identity(lease_id, "lease ID")
        if (
            type(expected_heartbeat_revision) is not int
            or expected_heartbeat_revision < 0
            or type(ttl_ns) is not int
            or ttl_ns <= 0
        ):
            raise RepositoryIntegrityError("lease renewal bounds are invalid")
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                with connection.transaction():
                    now = trusted_now(connection)
                    expires_at = now + ttl_ns
                    changed = connection.execute(
                        "UPDATE leases SET expires_at=?,heartbeat_revision=heartbeat_revision+1 "
                        "WHERE lease_id=? AND state='live' AND expires_at>? AND heartbeat_revision=?",
                        (expires_at, lease_id, now, expected_heartbeat_revision),
                    ).rowcount
                    if changed != 1:
                        raise RepositoryConflictError("lease renewal is stale or expired")
                    return self._grant(connection, lease_id)
        finally:
            self._locks.release(installation)

    def validate_fence(
        self,
        *,
        lease_id: str,
        resource_id: str,
        fencing_token: int,
    ) -> bool:
        self._identity(lease_id, "lease ID")
        self._identity(resource_id, "resource ID")
        if type(fencing_token) is not int or fencing_token <= 0:
            raise RepositoryIntegrityError("fence is invalid")
        installation = None if self._locks.installation_held_by_current_thread() else self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                with connection.transaction():
                    now = trusted_now(connection)
                    row = connection.execute(
                        "SELECT lr.fencing_token,rf.fencing_token,l.state,l.expires_at "
                        "FROM lease_resources lr JOIN resource_fences rf ON rf.resource_id=lr.resource_id "
                        "JOIN leases l ON l.lease_id=lr.lease_id "
                        "WHERE lr.lease_id=? AND lr.resource_id=?",
                        (lease_id, resource_id),
                    ).fetchone()
                    return (
                        row is not None
                        and row[0] == fencing_token
                        and row[1] == fencing_token
                        and row[2] == "live"
                        and row[3] > now
                    )
        finally:
            if installation is not None:
                self._locks.release(installation)

    def release(self, lease_id: str) -> None:
        self._identity(lease_id, "lease ID")
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                with connection.transaction():
                    unresolved = connection.execute(
                        "SELECT 1 FROM claims WHERE lease_id=? AND state='unresolved' LIMIT 1",
                        (lease_id,),
                    ).fetchone()
                    if unresolved is not None:
                        raise RepositoryConflictError("lease has an unresolved action claim")
                    changed = connection.execute(
                        "UPDATE leases SET state='released' WHERE lease_id=? AND state IN ('live','expired')",
                        (lease_id,),
                    ).rowcount
                    if changed != 1:
                        raise RepositoryConflictError("lease is unknown or already released")
        finally:
            self._locks.release(installation)

    def claim_action(
        self,
        *,
        claim_id: str,
        action_id: str,
        task_id: str,
        lease: LeaseGrant,
        started_event_digest: str,
        object_digests: tuple[str, ...] = (),
    ) -> dict[str, object]:
        """Build the claim delta consumed atomically by TaskRepository.commit."""

        for label, value in (
            ("claim ID", claim_id), ("action ID", action_id), ("task ID", task_id),
            ("lease ID", lease.lease_id),
        ):
            self._identity(value, label)
        require_jcs_digest(started_event_digest)
        canonical_resources = self._resources(lease.resources)
        if canonical_resources != lease.resources:
            raise RepositoryIntegrityError("lease resources are not canonical")
        tokens = dict(lease.fencing_tokens)
        if set(tokens) != set(canonical_resources):
            raise RepositoryIntegrityError("lease fencing token set is incomplete")
        if tuple(sorted(set(object_digests))) != object_digests:
            raise RepositoryIntegrityError("claim objects are not canonical")
        for digest in object_digests:
            require_object_digest(digest)
        return {
            "claim_id": claim_id,
            "action_id": action_id,
            "task_id": task_id,
            "lease_id": lease.lease_id,
            "resources": list(canonical_resources),
            "fencing_tokens": tokens,
            "started_event_digest": started_event_digest,
            "object_digests": list(object_digests),
        }

    def reconcile_claim(
        self,
        claim_id: str,
        outcome: str,
        outcome_record: dict[str, object],
        reconciled_event_digest: str,
    ) -> dict[str, object]:
        """Build the reconciliation delta committed with the exact outcome event."""

        self._identity(claim_id, "claim ID")
        if outcome not in self.RECONCILED_STATES or type(outcome_record) is not dict:
            raise RepositoryIntegrityError("claim outcome is invalid")
        canonical_json(outcome_record)
        require_jcs_digest(reconciled_event_digest)
        return {
            "claim_id": claim_id,
            "outcome": outcome,
            "outcome_record": outcome_record,
            "reconciled_event_digest": reconciled_event_digest,
        }

    def unresolved_claims(self) -> tuple[dict[str, object], ...]:
        installation = self._locks.acquire_installation("shared")
        try:
            with self._factory.open("application") as connection:
                rows = connection.execute(
                    "SELECT claim_id,action_id,task_id,lease_id,started_event_digest "
                    "FROM claims WHERE state='unresolved' ORDER BY claim_id"
                ).fetchall()
                return tuple({
                    "claim_id": row[0], "action_id": row[1], "task_id": row[2],
                    "lease_id": row[3], "started_event_digest": row[4],
                } for row in rows)
        finally:
            self._locks.release(installation)

    def load_claim(self, claim_id: str) -> dict[str, object]:
        """Load the exact durable claim and its full frozen resource/fence set."""

        self._identity(claim_id, "claim ID")
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT action_id,task_id,lease_id,started_event_digest,state,revision "
                "FROM claims WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
            resources = connection.execute(
                "SELECT resource_id,fencing_token FROM claim_resources "
                "WHERE claim_id=? ORDER BY resource_id",
                (claim_id,),
            ).fetchall()
        if row is None:
            raise RepositoryConflictError("unknown action claim")
        return {
            "claim_id": claim_id,
            "action_id": row[0],
            "task_id": row[1],
            "lease_id": row[2],
            "started_event_digest": row[3],
            "state": row[4],
            "revision": row[5],
            "resources": [item[0] for item in resources],
            "fencing_tokens": {item[0]: item[1] for item in resources},
        }

    @staticmethod
    def compensation_attempt_id(
        claim: dict[str, object],
        *,
        compensation_action_id: str,
        compensation_authority_digest: str,
        compensation_prepared_digest: str,
    ) -> str:
        """Derive the immutable recovery transaction identity from repository state."""

        return "recovery:" + semantic_record_digest({
            "contract": "claim-compensation-attempt-v1",
            "protocol_version": "1.0.0",
            "claim_id": claim["claim_id"],
            "claim_revision": claim["revision"],
            "task_id": claim["task_id"],
            "original_action_id": claim["action_id"],
            "original_started_event_digest": claim["started_event_digest"],
            "lease_id": claim["lease_id"],
            "resources": claim["resources"],
            "fencing_tokens": claim["fencing_tokens"],
            "compensation_action_id": compensation_action_id,
            "compensation_authority_digest": compensation_authority_digest,
            "compensation_prepared_digest": compensation_prepared_digest,
        })

    @staticmethod
    def _compensation_common(
        claim: dict[str, object],
        *,
        attempt_id: str,
        compensation_action_id: str,
        compensation_authority_digest: str,
        compensation_prepared_digest: str,
        protocol_version: str,
        original_started_event_digest: str,
        target_id: str,
        target_digest: str,
        baseline_digest: str,
        snapshot_digest: str,
        disclosure_plan_digest: str,
    ) -> dict[str, object]:
        return {
            "attempt_id": attempt_id,
            "protocol_version": protocol_version,
            "claim_id": claim["claim_id"],
            "task_id": claim["task_id"],
            "original_action_id": claim["action_id"],
            "original_started_event_digest": original_started_event_digest,
            "compensation_action_id": compensation_action_id,
            "compensation_authority_digest": compensation_authority_digest,
            "compensation_prepared_digest": compensation_prepared_digest,
            "lease_id": claim["lease_id"],
            "resources": claim["resources"],
            "fencing_tokens": claim["fencing_tokens"],
            "expected_claim_revision": claim["revision"],
            "target_id": target_id,
            "target_digest": target_digest,
            "baseline_digest": baseline_digest,
            "snapshot_digest": snapshot_digest,
            "disclosure_plan_digest": disclosure_plan_digest,
        }

    def start_claim_compensation(
        self,
        claim: dict[str, object],
        *,
        attempt_id: str,
        compensation_action_id: str,
        compensation_authority_digest: str,
        compensation_prepared_digest: str,
        start_event_digest: str,
        target_id: str,
        target_digest: str,
        baseline_digest: str,
        snapshot_digest: str,
        disclosure_plan_digest: str,
    ) -> dict[str, object]:
        require_jcs_digest(start_event_digest)
        return {
            "operation": "start_claim_compensation",
            **self._compensation_common(
                claim,
                attempt_id=attempt_id,
                compensation_action_id=compensation_action_id,
                compensation_authority_digest=compensation_authority_digest,
                compensation_prepared_digest=compensation_prepared_digest,
                protocol_version="1.0.0",
                original_started_event_digest=str(claim["started_event_digest"]),
                target_id=target_id,
                target_digest=target_digest,
                baseline_digest=baseline_digest,
                snapshot_digest=snapshot_digest,
                disclosure_plan_digest=disclosure_plan_digest,
            ),
            "start_event_digest": start_event_digest,
        }

    def record_compensation_receipt(
        self,
        claim: dict[str, object],
        *,
        attempt: dict[str, object],
        receipt_event_digest: str,
        receipt: dict[str, object],
    ) -> dict[str, object]:
        receipt_object_digest = receipt.get("raw_receipt_object_digest")
        require_object_digest(receipt_object_digest)
        return {
            "operation": "record_compensation_receipt",
            **self._compensation_common(
                claim,
                attempt_id=str(attempt["attempt_id"]),
                compensation_action_id=str(attempt["compensation_action_id"]),
                compensation_authority_digest=str(attempt["compensation_authority_digest"]),
                compensation_prepared_digest=str(attempt["compensation_prepared_digest"]),
                protocol_version=str(attempt["protocol_version"]),
                original_started_event_digest=str(attempt["original_started_event_digest"]),
                target_id=str(attempt["target_id"]),
                target_digest=str(attempt["target_digest"]),
                baseline_digest=str(attempt["baseline_digest"]),
                snapshot_digest=str(attempt["snapshot_digest"]),
                disclosure_plan_digest=str(attempt["disclosure_plan_digest"]),
            ),
            "expected_attempt_revision": attempt["revision"],
            "start_event_digest": attempt["start_event_digest"],
            "receipt_event_digest": receipt_event_digest,
            "receipt_object_digest": receipt_object_digest,
            "receipt": receipt,
        }

    def reconcile_claim_compensation(
        self,
        claim: dict[str, object],
        *,
        attempt: dict[str, object],
        reconciled_event_digest: str,
        fresh_observation: dict[str, object],
    ) -> dict[str, object]:
        return {
            "operation": "reconcile_claim_compensation",
            **self._compensation_common(
                claim,
                attempt_id=str(attempt["attempt_id"]),
                compensation_action_id=str(attempt["compensation_action_id"]),
                compensation_authority_digest=str(attempt["compensation_authority_digest"]),
                compensation_prepared_digest=str(attempt["compensation_prepared_digest"]),
                protocol_version=str(attempt["protocol_version"]),
                original_started_event_digest=str(attempt["original_started_event_digest"]),
                target_id=str(attempt["target_id"]),
                target_digest=str(attempt["target_digest"]),
                baseline_digest=str(attempt["baseline_digest"]),
                snapshot_digest=str(attempt["snapshot_digest"]),
                disclosure_plan_digest=str(attempt["disclosure_plan_digest"]),
            ),
            "expected_attempt_revision": attempt["revision"],
            "start_event_digest": attempt["start_event_digest"],
            "receipt_event_digest": attempt["receipt_event_digest"],
            "reconciled_event_digest": reconciled_event_digest,
            "fresh_observation": fresh_observation,
        }

    def recovery_attempt(self, claim_id: str) -> dict[str, object] | None:
        self._identity(claim_id, "claim ID")
        with self._factory.open("doctor") as connection:
            row = connection.execute(
                "SELECT attempt_id,claim_id,protocol_version,task_id,original_action_id,"
                "original_started_event_digest,compensation_action_id,compensation_authority_digest,"
                "compensation_prepared_digest,lease_id,resources_json,fencing_tokens_json,target_id,"
                "target_digest,baseline_digest,snapshot_digest,disclosure_plan_digest,state,revision,"
                "start_event_digest,receipt_event_digest,receipt_json,receipt_object_digest "
                "FROM claim_recovery_attempts WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
        if row is None:
            return None
        from .codec import parse_canonical_json
        return {
            "attempt_id": row[0], "claim_id": row[1], "protocol_version": row[2],
            "task_id": row[3], "original_action_id": row[4],
            "original_started_event_digest": row[5], "compensation_action_id": row[6],
            "compensation_authority_digest": row[7], "compensation_prepared_digest": row[8],
            "lease_id": row[9], "resources": parse_canonical_json(row[10]),
            "fencing_tokens": parse_canonical_json(row[11]), "target_id": row[12],
            "target_digest": row[13], "baseline_digest": row[14], "snapshot_digest": row[15],
            "disclosure_plan_digest": row[16], "state": row[17], "revision": row[18],
            "start_event_digest": row[19], "receipt_event_digest": row[20],
            "receipt": None if row[21] is None else parse_canonical_json(row[21]),
            "receipt_object_digest": row[22],
        }
