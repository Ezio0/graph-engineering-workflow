from __future__ import annotations

import copy
import unittest

from graph_engineering.core.action_adapters import ActionInvocation
from graph_engineering.storage.ports import CommitBatch
from graph_engineering.storage.repository import make_event
from graph_engineering.storage.errors import RepositoryIntegrityError
from tests.support.wp05_actions import action_stack, authority_document, disclosure_plan, prepared_document


def concrete_invocation(fixture: object, prepared: object) -> dict[str, object]:
    record = fixture.journal.load(prepared.action_id)
    authority = record.authority
    assert authority is not None
    plan = disclosure_plan(fixture, prepared)
    lease = fixture.action_lease
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "invocation_id": "invocation-wp07a-storage",
        "task_id": prepared.task_id,
        "action_id": prepared.action_id,
        "prepared_action_digest": prepared.prepared_action_digest,
        "authority_digest": authority.authority_digest,
        "adapter_id": "git-native-v1",
        "operation_id": "git.update-ref",
        "target_id": prepared.target_id,
        "target_digest": prepared.target_digest,
        "resources": list(lease.resources),
        "lease_id": lease.lease_id,
        "fencing_tokens": [
            {"resource_id": resource, "token": token}
            for resource, token in lease.fencing_tokens
        ],
        "idempotency_class": prepared.idempotency_class,
        "idempotency_key": prepared.idempotency_key,
        "payload_digest": prepared.payload_digest,
        "disclosure_plan_digest": plan.plan_digest,
    }
    value["invocation_digest"] = ActionInvocation.digest_document(value)
    return value


def commit_started(fixture: object, invocation: dict[str, object]) -> None:
    raw = fixture.raw_coordinator
    prepared = fixture.journal.load("action-wp05").prepared
    record = fixture.journal.load(prepared.action_id)
    head = raw._journal.current_task_head(prepared.task_id)
    event = make_event(
        task_id=prepared.task_id,
        sequence=head.sequence + 1,
        event_id="action-wp05:started",
        event_type="action.execution_started",
        occurred_at=raw._journal.current_time(),
        actor={"kind": "runtime", "id": "lineage-wp05"},
        expected_task_revision=head.revision,
        baseline_digests=[prepared.baseline_digest],
        payload={
            "action_id": prepared.action_id,
            "authority_digest": record.authority.authority_digest,
            "prepared_action_digest": prepared.prepared_action_digest,
            "snapshot_digest": prepared.snapshot_digest,
            "lease_id": fixture.action_lease.lease_id,
            "fencing_tokens": dict(fixture.action_lease.fencing_tokens),
            "disclosure_plan_digest": invocation["disclosure_plan_digest"],
        },
        previous_event_digest=head.head_digest,
    )
    claim = raw._leases.claim_action(
        claim_id="claim:action-wp05",
        action_id=prepared.action_id,
        task_id=prepared.task_id,
        lease=fixture.action_lease,
        started_event_digest=event["event_digest"],
    )
    snapshot = copy.deepcopy(head.snapshot)
    snapshot.update({
        "task_id": prepared.task_id,
        "revision": head.revision + 1,
        "action_state": "executing",
    })
    fixture.repository.commit(CommitBatch(
        transaction_id="action-wp05:start",
        task_id=prepared.task_id,
        expected_task_revision=head.revision,
        events=(event,),
        snapshot=snapshot,
        catalog_delta={},
        lease_assertion=raw._lease_assertion(fixture.action_lease, prepared.task_id),
        claim_delta=claim,
        action_journal_delta=raw._journal.start_delta(record),
        concrete_action_delta={"operation": "invocation", "record": invocation},
    ))


class WP07AActionStorageTests(unittest.TestCase):
    def test_gew_act_004a_storage_reparses_and_commits_exact_invocation_with_started_fact(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            invocation = concrete_invocation(fixture, prepared)
            commit_started(fixture, invocation)
            with fixture.factory.open("doctor") as connection:
                row = connection.execute(
                    "SELECT record_json,record_digest FROM concrete_action_records "
                    "WHERE record_type='invocation' AND action_id=?",
                    (prepared.action_id,),
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[1], invocation["invocation_digest"])

    def test_gew_act_004b_storage_fence_substitution_rolls_back_event_claim_journal_and_record(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            before = fixture.raw_coordinator._journal.current_task_head(prepared.task_id)
            invocation = concrete_invocation(fixture, prepared)
            fences = invocation["fencing_tokens"]
            assert isinstance(fences, list) and isinstance(fences[0], dict)
            fences[0]["token"] += 1
            invocation["invocation_digest"] = ActionInvocation.digest_document(invocation)
            with self.assertRaises(RepositoryIntegrityError):
                commit_started(fixture, invocation)
            after = fixture.raw_coordinator._journal.current_task_head(prepared.task_id)
            self.assertEqual(after.revision, before.revision)
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "authorized")
            with fixture.factory.open("doctor") as connection:
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM claims WHERE action_id=?", (prepared.action_id,),
                ).fetchone())
                self.assertIsNone(connection.execute(
                    "SELECT 1 FROM concrete_action_records WHERE action_id=?", (prepared.action_id,),
                ).fetchone())


if __name__ == "__main__":
    unittest.main()
