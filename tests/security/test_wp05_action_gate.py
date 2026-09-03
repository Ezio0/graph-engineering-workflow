from __future__ import annotations

import copy
import unittest

from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
from tests.support.wp05_actions import action_stack, authority_document, disclosure_plan, prepared_document


class WP05ActionGateTests(unittest.TestCase):
    MUTATIONS = (
        "owner", "runtime", "lineage", "target", "baseline", "snapshot", "payload",
        "expiry", "revocation", "lease", "fence", "precondition", "idempotency",
        "rollback", "verification", "disclosure", "capability", "action-kind",
    )

    def test_every_gate_binding_rejects_before_tool_call(self) -> None:
        for mutation in self.MUTATIONS:
            with self.subTest(mutation=mutation), action_stack() as fixture:
                prepared_value = prepared_document()
                prepared = fixture.coordinator.prepare(prepared_value)
                authority_value = authority_document(prepared)
                fixture.coordinator.authorize(authority_value)
                if mutation == "expiry":
                    fixture.journal.test_only_mutate_authority(prepared.action_id, "expiry")
                if mutation == "revocation":
                    fixture.coordinator.revoke(prepared.action_id, "authority-wp05")
                target = DeterministicFakeTarget(
                    target_id="wrong-target" if mutation == "target" else "target-project",
                    target_digest=prepared.target_digest,
                    resource_id="target:project",
                    initial_state={"version": 9} if mutation == "precondition" else {"version": 1},
                    capabilities=("deterministic-fake-target-v1",) if mutation == "capability" else None,
                )
                owner = "wrong-owner" if mutation == "owner" else "owner-wp05"
                runtime = "hermes" if mutation == "runtime" else "codex"
                lineage = "wrong-lineage" if mutation == "lineage" else "lineage-wp05"
                lease = fixture.other_lease if mutation in {"lease", "fence"} else fixture.action_lease
                plan = disclosure_plan(fixture, prepared)
                if mutation == "disclosure":
                    plan = disclosure_plan(fixture, prepared, payload_override="wrong")
                if mutation in {"baseline", "snapshot", "payload", "idempotency", "rollback", "verification", "action-kind"}:
                    fixture.journal.test_only_mutate_prepared(prepared.action_id, mutation)
                with self.assertRaises(ValueError):
                    fixture.coordinator.execute(
                        prepared.action_id,
                        owner_id=owner,
                        runtime_kind=runtime,
                        runtime_lineage_id=lineage,
                        lease=lease,
                        target=target,
                        observer=target.observer_port(),
                        disclosure_plan=plan,
                    )
                self.assertEqual(target.call_count, 0)
                self.assertFalse(target.started_was_durable)


if __name__ == "__main__":
    unittest.main()
