from __future__ import annotations

import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.application.owner_turns import OwnerTurnRequest  # noqa: E402
from graph_engineering.core.runtime import runtime_record_digest  # noqa: E402


def turn(operation: str, *, task_id: str | None, payload: dict[str, object]) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0", "turn_id": f"turn:{operation}",
        "operation": operation, "task_id": task_id,
        "owner_id": "owner-fixture", "runtime_kind": "codex",
        "runtime_lineage_id": "lineage-fixture", "payload": payload,
    }
    return {
        **body, "request_digest": runtime_record_digest("owner-turn-request", body),
    }


class WP07OwnerTurnTests(unittest.TestCase):
    def test_gew_rt_045_each_owner_turn_is_one_exact_versioned_operation(self) -> None:
        digest = "sha256-jcs-v1:" + "1" * 64
        requests = (
            turn("discover", task_id=None, payload={}),
            turn("create", task_id=None, payload={
                "occurred_at": "2026-08-15T00:00:00Z", "lease_ttl_ns": 100,
            }),
            turn("clarify", task_id="task:existing", payload={
                "expected_task_revision": 1, "occurred_at": "turn:clarify",
                "lease_ttl_ns": 100, "project_scope": {},
                "prd_candidate_ref": "artifact:prd",
            }),
            turn("approve", task_id="task:existing", payload={
                "expected_task_revision": 3, "occurred_at": "turn:approve",
                "lease_ttl_ns": 100, "approval": {},
            }),
            turn("run", task_id="task:existing", payload={
                "expected_task_revision": 5, "occurred_at": "turn:run",
                "lease_ttl_ns": 100, "compatibility_evidence_ref": "evidence:compatible",
                "lease_plan_ref": "lease-plan:exact",
            }),
            turn("status", task_id="task:existing", payload={}),
            turn("resume", task_id="task:existing", payload={}),
            turn("escalate", task_id="task:existing", payload={
                "request_id": "decision:1", "decision_kind": "owner-review",
                "decision_payload_ref": "decision-payload:1",
                "decision_payload_digest": digest,
            }),
            turn("result", task_id="task:existing", payload={"presentation": {}}),
        )
        loaded = tuple(OwnerTurnRequest.from_dict(request) for request in requests)
        self.assertEqual(tuple(item.operation for item in loaded), (
            "discover", "create", "clarify", "approve", "run",
            "status", "resume", "escalate", "result",
        ))
        self.assertIsNone(loaded[0].task_id)
        self.assertIsNone(loaded[1].task_id)
        self.assertEqual(loaded[2].task_id, "task:existing")
        with self.assertRaisesRegex(Exception, "operation|task"):
            OwnerTurnRequest.from_dict(turn("create", task_id="task:forged", payload={
                "occurred_at": "2026-08-15T00:00:00Z", "lease_ttl_ns": 100,
            }))
        with self.assertRaisesRegex(Exception, "payload"):
            OwnerTurnRequest.from_dict(turn(
                "status", task_id="task:existing", payload={"unexpected": True},
            ))


if __name__ == "__main__":
    unittest.main()
