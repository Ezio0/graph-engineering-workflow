from __future__ import annotations

import json
import pathlib
import sys
import unittest
from dataclasses import replace as dataclass_replace


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.graph.state import (  # noqa: E402
    ArtifactRef,
    DomainEvent,
    EvidenceRef,
    LIFECYCLES,
    NODE_STATUSES,
    NODE_TRANSITIONS,
    NodeRun,
    ReducerError,
    TaskCommand,
    TaskSnapshot,
    apply_events as _apply_events,
    decide_command as _decide_command,
    transition_node,
)


def _contracts() -> tuple[ClosedSchemaRegistry, ResourceProfile, CostSchedule]:
    schema_root = ROOT / "config" / "contracts" / "schemas"
    names = (
        "completion-policy-1.0.0.json", "completion-policy-registry-1.0.0.json",
        "graph-definition-1.0.0.json", "graph-definition-digest-input-1.0.0.json",
        "loop-budget-1.0.0.json", "loop-budget-registry-1.0.0.json",
        "node-payload-1.0.0.json", "task-snapshot-1.0.0.json",
        "task-snapshot-digest-input-1.0.0.json",
    )
    bodies = {
        json.loads((schema_root / name).read_text())["$id"]: (schema_root / name).read_bytes()
        for name in names
    }
    profile = ResourceProfile.from_dict(
        json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
    )
    schedule = CostSchedule.from_dict(
        json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
    )
    policy = SchemaProfilePolicy.from_dict(
        json.loads((ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text())
    )
    manifest = json.loads(
        (ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text()
    )
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy), profile, schedule


SCHEMAS, PROFILE, SCHEDULE = _contracts()


def context() -> WorkContext:
    return WorkContext(PROFILE, SCHEDULE)


def apply_events(snapshot: TaskSnapshot | None, events: object) -> TaskSnapshot:
    return _apply_events(
        snapshot, events, schema_registry=SCHEMAS, context=context(),  # type: ignore[arg-type]
    )


def decide_command(snapshot: TaskSnapshot | None, command: TaskCommand) -> tuple[DomainEvent, ...]:
    return _decide_command(snapshot, command, schema_registry=SCHEMAS, context=context())


def replace(instance: object, **changes: object) -> object:
    if isinstance(instance, TaskSnapshot):
        changes.update({"schema_registry": SCHEMAS, "context": context()})
    return dataclass_replace(instance, **changes)  # type: ignore[type-var]


class ReducerTests(unittest.TestCase):
    def event(self, sequence: int, event_type: str, **payload: object) -> DomainEvent:
        return DomainEvent(sequence=sequence, expected_task_revision=sequence - 1, event_type=event_type, payload=payload)

    def identity(self) -> dict[str, object]:
        return {
            "task_id": "task-1",
            "owner_id": "owner-1",
            "runtime_kind": "codex",
            "runtime_lineage_id": "lineage-1",
        }

    def scope(self, status: str = "frozen") -> dict[str, object]:
        return {"scope_id": "scope-1", "version": 1, "digest": "scope-digest", "status": status}

    def approval(self) -> dict[str, object]:
        return {
            "owner_decision_ref": "decision:prd-approved-v1",
            "baseline_refs": [{
                "kind": "intent", "version": 1, "digest": "baseline-digest",
                "approved_by": "owner-1", "approved_at": "2026-08-14T00:00:00Z",
            }],
            "graph_ref": {
                "graph_id": "delivery", "graph_version": "1.0.0", "profile_id": "new-feature",
                "profile_version": "1.0.0", "risk_path": "full-planned",
                "graph_digest": "sha256-jcs-v1:" + "1" * 64,
            },
            "authority_refs": ["authority-1"],
        }

    def prd_request(self) -> dict[str, object]:
        return {"prd_candidate_ref": "artifact:prd-candidate-v1"}

    def run_guards(self) -> dict[str, object]:
        return {
            "compatibility_evidence_ref": "evidence:compatibility-v1",
            "lease_plan_ref": "lease-plan:none-v1",
        }

    def resume_guards(self) -> dict[str, object]:
        return {
            "resolution_evidence_refs": ["evidence:blockers-resolved-v1"],
            "compatibility_evidence_ref": "evidence:compatibility-v1",
        }

    def rollback_guards(self) -> dict[str, object]:
        return {
            "compensable_action_refs": ["action:executed-v1"],
            "rollback_plan_ref": "rollback-plan:v1",
            "authority_ref": "authority:rollback-v1",
        }

    def archive_guards(self) -> dict[str, object]:
        return {
            "retention_plan_ref": "retention-plan:v1",
            "rollback_clearance_ref": "rollback-clearance:v1",
        }

    def snapshot_for_state(self, state: str) -> TaskSnapshot | None:
        if state == "nonexistent":
            return None
        discovering = apply_events(None, (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
        ))
        if state == "discovering":
            return discovering
        awaiting = apply_events(discovering, (
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
        ))
        if state == "awaiting_prd_approval":
            return awaiting
        ready = apply_events(awaiting, (
            self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
            self.event(5, "task.prd_approved", **self.approval()),
        ))
        return ready if state == "ready" else replace(ready, lifecycle=state)

    def test_task_event_replay_is_pure_exact_and_rejects_unlisted_transitions(self) -> None:
        events = (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
            self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
            self.event(5, "task.prd_approved", **self.approval()),
            self.event(6, "task.run_started", **self.run_guards()),
            self.event(7, "task.completion_started"),
            self.event(8, "task.completed"),
        )
        first = apply_events(None, events)
        second = apply_events(None, events)
        self.assertEqual(first, second)
        self.assertEqual(first.lifecycle, "completed")
        self.assertEqual(first.authorities, ())
        self.assertEqual(first.task_revision, 8)
        self.assertEqual(first.last_event_seq, 8)
        restored = TaskSnapshot.from_dict(
            first.to_dict(), schema_registry=SCHEMAS, context=context(),
        )
        self.assertEqual(restored, first)
        tampered = first.to_dict()
        tampered["lifecycle"] = "failed"
        with self.assertRaisesRegex(ReducerError, "digest"):
            TaskSnapshot.from_dict(tampered, schema_registry=SCHEMAS, context=context())
        with self.assertRaisesRegex(ReducerError, "unlisted"):
            apply_events(first, (self.event(9, "task.run_started"),))
        with self.assertRaisesRegex(ReducerError, "archived"):
            archived = apply_events(first, (self.event(9, "task.archived", **self.archive_guards()),))
            apply_events(archived, (self.event(10, "task.scope_change_proposed"),))

    def test_reducer_checks_sequence_claim_lease_and_internal_states(self) -> None:
        base = apply_events(None, (self.event(1, "task.created", identity=self.identity()),))
        with self.assertRaisesRegex(ReducerError, "sequence"):
            apply_events(base, (self.event(3, "project.scope_drafted"),))
        stale = DomainEvent(2, 0, "task.prd_approval_requested", {})
        with self.assertRaisesRegex(ReducerError, "revision"):
            apply_events(base, (stale,))
        running = apply_events(
            base,
            (
                self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
                self.event(3, "task.prd_approval_requested", **self.prd_request()),
                self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
                self.event(5, "task.prd_approved", **self.approval()),
                self.event(6, "task.run_started", **self.run_guards()),
            ),
        )
        claimed = running.with_coordination(
            claims=("claim-1",), leases=(), schema_registry=SCHEMAS, context=context(),
        )
        deferred = apply_events(claimed, (self.event(7, "task.pause_deferred", desired_state="paused"),))
        self.assertEqual(deferred.lifecycle, "awaiting_human")
        with self.assertRaisesRegex(ReducerError, "coordination"):
            apply_events(deferred, (self.event(8, "task.paused"),))
        coordinated = deferred.with_coordination(
            claims=(), leases=(), schema_registry=SCHEMAS, context=context(),
        )
        paused = apply_events(coordinated, (self.event(8, "task.paused"),))
        self.assertEqual(paused.lifecycle, "paused")

    def test_node_run_state_machine_increments_attempt_only_on_retry(self) -> None:
        run = NodeRun(run_id="run-1", node_id="implementation", attempt=1, status="pending")
        for fields in (
            (1, "implementation", 1, "pending"),
            ("run-1", 2, 1, "pending"),
            ("run-1", "implementation", True, "pending"),
            ("run-1", "implementation", 1, 1),
        ):
            with self.subTest(fields=fields), self.assertRaises(ReducerError):
                NodeRun(*fields)  # type: ignore[arg-type]
        for event_type in (
            "node.ready",
            "node.leased",
            "node.started",
            "node.output_produced",
            "node.validation_started",
            "node.review_started",
        ):
            run = transition_node(run, event_type)
        self.assertEqual(run.status, "reviewing")
        retry = transition_node(run, "node.revise_requested")
        self.assertEqual((retry.status, retry.attempt), ("pending", 2))
        with self.assertRaisesRegex(ReducerError, "node transition"):
            transition_node(retry, "node.passed")
        invalidated = transition_node(run, "node.invalidated")
        self.assertEqual(invalidated.status, "invalidated")

        snapshot = apply_events(None, (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
            self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
            self.event(5, "task.prd_approved", **self.approval()),
            self.event(6, "task.run_started", **self.run_guards()),
            self.event(7, "node.run_created", run_id="run-1", node_id="implementation"),
            self.event(8, "node.ready", run_id="run-1"),
        ))
        self.assertEqual(snapshot.node_runs["run-1"].status, "ready")
        self.assertEqual(snapshot.task_revision, 8)

    def test_node_events_are_lifecycle_gated(self) -> None:
        running = apply_events(None, (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
            self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
            self.event(5, "task.prd_approved", **self.approval()),
            self.event(6, "task.run_started", **self.run_guards()),
            self.event(7, "node.run_created", run_id="run-1", node_id="implementation"),
        ))
        paused = replace(running, lifecycle="paused")
        with self.assertRaisesRegex(ReducerError, "lifecycle"):
            apply_events(paused, (self.event(8, "node.ready", run_id="run-1"),))
        canceling = replace(running, lifecycle="canceling")
        cancelled = apply_events(canceling, (self.event(8, "node.cancelled", run_id="run-1"),))
        self.assertEqual(cancelled.node_runs["run-1"].status, "cancelled")
        active_run = replace(running, node_runs={"run-1": NodeRun("run-1", "implementation", 1, "running")})
        active_canceling = replace(active_run, lifecycle="canceling")
        active_cancelled = apply_events(
            active_canceling, (self.event(8, "node.cancelled", run_id="run-1"),),
        )
        self.assertEqual(active_cancelled.node_runs["run-1"].status, "cancelled")

    def test_snapshot_instance_and_nested_state_are_immutable(self) -> None:
        snapshot = TaskSnapshot.initial(SCHEMAS, context())
        self.assertTrue(snapshot.snapshot_digest.startswith("sha256-jcs-v1:"))
        self.assertEqual(snapshot.to_dict()["snapshot_digest"], snapshot.snapshot_digest)
        with self.assertRaises((AttributeError, TypeError)):
            snapshot.lifecycle = "completed"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            snapshot.node_runs["x"] = NodeRun("r", "x", 1, "pending")  # type: ignore[index]
        populated = replace(
            self.snapshot_for_state("ready"),  # type: ignore[arg-type]
            artifacts=(ArtifactRef("artifact-1", "prd", "contract:prd", 1, "digest:a", "validated"),),
            evidence=(EvidenceRef("evidence-1", "test", "run-1", "digest:e", "validated"),),
        )
        self.assertEqual(populated.to_dict()["artifacts"][0]["artifact_id"], "artifact-1")  # type: ignore[index]

    def test_snapshot_self_digest_is_schema_projected_charged_and_budget_bounded(self) -> None:
        measured = context()
        snapshot = TaskSnapshot.initial(SCHEMAS, measured)
        events = [item["event_id"] for item in measured.trace]
        self.assertIn("schema.keyword", events)
        self.assertIn("canonical.output_byte", events)
        self.assertIn("digest.input_byte", events)
        spent = measured.profile.work_budget - measured.balance

        exact = WorkContext(PROFILE, SCHEDULE, initial_balance=spent)
        exact_snapshot = TaskSnapshot.initial(SCHEMAS, exact)
        self.assertEqual(exact_snapshot.snapshot_digest, snapshot.snapshot_digest)
        self.assertEqual(exact.balance, 0)

        insufficient = WorkContext(PROFILE, SCHEDULE, initial_balance=spent - 1)
        with self.assertRaises(ContractError) as captured:
            TaskSnapshot.initial(SCHEMAS, insufficient)
        self.assertEqual(captured.exception.detail.code, "E_BUDGET")
        self.assertEqual(insufficient.trace[-1]["status"], "rejected")

    def test_snapshot_digest_tamper_and_unattested_paths_fail_closed(self) -> None:
        snapshot = TaskSnapshot.initial(SCHEMAS, context())
        tampered = snapshot.to_dict()
        tampered["snapshot_digest"] = "sha256-jcs-v1:" + "0" * 64
        with self.assertRaisesRegex(ReducerError, "digest"):
            TaskSnapshot.from_dict(
                tampered, schema_registry=SCHEMAS, context=context(),
            )
        with self.assertRaisesRegex(ReducerError, "attested"):
            TaskSnapshot.initial(object(), context())  # type: ignore[arg-type]
        with self.assertRaisesRegex(ReducerError, "attested"):
            TaskSnapshot.initial(SCHEMAS, object())  # type: ignore[arg-type]

    def test_snapshot_exact_pins_reject_registry_profile_schedule_and_graph_drift(self) -> None:
        snapshot = self.snapshot_for_state("ready")
        serialized = snapshot.to_dict()

        changed_profile_value = json.loads(
            (ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()
        )
        changed_profile_value["limits"]["ast_nodes"] -= 1
        changed_profile = ResourceProfile.from_dict(changed_profile_value)
        with self.assertRaisesRegex(ReducerError, "resource_profile contract pin mismatch"):
            TaskSnapshot.from_dict(
                serialized,
                schema_registry=SCHEMAS,
                context=WorkContext(changed_profile, SCHEDULE),
            )

        changed_schedule_value = json.loads(
            (ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()
        )
        changed_schedule_value["coefficients"]["schema.keyword"] += 1
        changed_schedule = CostSchedule.from_dict(changed_schedule_value)
        changed_context = WorkContext(PROFILE, changed_schedule)
        with self.assertRaisesRegex(ReducerError, "cost_schedule contract pin mismatch"):
            TaskSnapshot.from_dict(
                serialized, schema_registry=SCHEMAS, context=changed_context,
            )
        with self.assertRaisesRegex(ReducerError, "cost_schedule contract pin mismatch"):
            _decide_command(
                snapshot,
                TaskCommand("run", snapshot.task_revision, self.run_guards()),
                schema_registry=SCHEMAS,
                context=WorkContext(PROFILE, changed_schedule),
            )

        schema_root = ROOT / "config" / "contracts" / "schemas"
        bodies = {
            json.loads(path.read_text())["$id"]: path.read_bytes()
            for path in schema_root.glob("*.json")
            if path.name in {
                "completion-policy-1.0.0.json", "completion-policy-registry-1.0.0.json",
                "graph-definition-1.0.0.json", "graph-definition-digest-input-1.0.0.json",
                "loop-budget-1.0.0.json", "loop-budget-registry-1.0.0.json",
                "node-payload-1.0.0.json", "task-snapshot-1.0.0.json",
                "task-snapshot-digest-input-1.0.0.json",
            }
        }
        rogue_body = json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:gew:schema:rogue:1.0.0",
            "type": "object",
            "properties": {"schema_version": {"const": "1.0.0"}},
            "required": ["schema_version"],
            "unevaluatedProperties": False,
        }, separators=(",", ":")).encode()
        bodies["urn:gew:schema:rogue:1.0.0"] = rogue_body
        different_registry_manifest = ClosedSchemaRegistry.create_manifest(
            "urn:gew:schema-registry:graph-test:1.0.0", bodies,
        )
        different_registry = ClosedSchemaRegistry.build(
            different_registry_manifest,
            bodies,
            PROFILE,
            SchemaProfilePolicy.from_dict(json.loads(
                (ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()
            )),
        )
        with self.assertRaisesRegex(ReducerError, "schema_registry contract pin mismatch"):
            TaskSnapshot.from_dict(
                serialized, schema_registry=different_registry, context=context(),
            )

        changed_graph_ref = dict(snapshot.graph_ref)
        changed_graph_ref["graph_digest"] = "sha256-jcs-v1:" + "2" * 64
        drifted = replace(snapshot, graph_ref=changed_graph_ref)
        self.assertNotEqual(drifted.snapshot_digest, snapshot.snapshot_digest)

    def test_public_commands_are_closed_revision_bound_and_emit_exact_batches(self) -> None:
        created_event = decide_command(None, TaskCommand("create", 0, {"identity": self.identity()}))
        created = apply_events(None, created_event)
        bound = apply_events(created, decide_command(
            created, TaskCommand("bind_project_scope", 1, {"project_scope_ref": self.scope("drafted")}),
        ))
        requested = apply_events(bound, decide_command(
            bound, TaskCommand("request_prd_approval", 2, self.prd_request()),
        ))
        approval = TaskCommand("approve_prd", 3, {"project_scope_ref": self.scope(), **self.approval()})
        batch = decide_command(requested, approval)
        self.assertEqual(tuple(event.event_type for event in batch), ("project.scope_frozen", "task.prd_approved"))
        ready = apply_events(requested, batch)
        self.assertEqual(ready.lifecycle, "ready")
        with self.assertRaisesRegex(ReducerError, "command expected"):
            decide_command(ready, TaskCommand("run", 1, {}))
        with self.assertRaisesRegex(ReducerError, "unknown task command"):
            decide_command(ready, TaskCommand("execute-arbitrary", ready.task_revision, {}))

    def test_scope_change_and_authority_revoke_emit_atomic_exact_batches(self) -> None:
        requested = apply_events(None, (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
        ))
        ready = apply_events(
            requested,
            decide_command(requested, TaskCommand(
                "approve_prd", requested.task_revision,
                {"project_scope_ref": self.scope(), **self.approval()},
            )),
        )
        scoped = decide_command(ready, TaskCommand(
            "propose_scope_change", ready.task_revision,
            {
                "project_scope_ref": {**self.scope("drafted"), "version": 2, "digest": "scope-digest-v2"},
                "scope_diff_digest": "diff-digest",
                "run_ids": [],
            },
        ))
        self.assertEqual(
            tuple(event.event_type for event in scoped),
            ("project.scope_change_proposed", "task.downstream_invalidated"),
        )
        awaiting = apply_events(ready, scoped)
        self.assertEqual((awaiting.lifecycle, awaiting.invalidation_epoch), ("awaiting_prd_approval", 1))

        authorized = replace(ready, authorities=("authority-1",))
        revoked = decide_command(
            authorized,
            TaskCommand("revoke", authorized.task_revision, {"authority_id": "authority-1"}),
        )
        self.assertEqual(tuple(event.event_type for event in revoked), ("authority.revoked", "task.paused"))
        paused = apply_events(authorized, revoked)
        self.assertEqual((paused.lifecycle, paused.authorities), ("paused", ()))

        running = apply_events(authorized, decide_command(
            authorized, TaskCommand("run", authorized.task_revision, self.run_guards()),
        ))
        claimed = running.with_coordination(
            claims=("claim-1",), leases=(), claim_authorities={"claim-1": "authority-1"},
            schema_registry=SCHEMAS, context=context(),
        )
        reconcile = decide_command(
            claimed,
            TaskCommand("revoke", claimed.task_revision, {"authority_id": "authority-1"}),
        )
        self.assertEqual(
            tuple(event.event_type for event in reconcile),
            ("authority.revoked", "task.authority_reconciliation_required"),
        )
        self.assertEqual(apply_events(claimed, reconcile).lifecycle, "awaiting_human")

    def test_public_command_preconditions_and_payloads_fail_closed(self) -> None:
        ready = apply_events(None, (
            self.event(1, "task.created", identity=self.identity()),
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
            self.event(3, "task.prd_approval_requested", **self.prd_request()),
            self.event(4, "project.scope_frozen", project_scope_ref=self.scope()),
            self.event(5, "task.prd_approved", **self.approval()),
        ))
        with self.assertRaisesRegex(ReducerError, "payload"):
            decide_command(ready, TaskCommand("run", ready.task_revision, {"unexpected": True}))
        with self.assertRaisesRegex(ReducerError, "payload"):
            decide_command(ready, TaskCommand("run", ready.task_revision, {}))
        claimed = ready.with_coordination(
            claims=("claim-1",), leases=(), schema_registry=SCHEMAS, context=context(),
        )
        with self.assertRaisesRegex(ReducerError, "clear coordination"):
            decide_command(claimed, TaskCommand("run", claimed.task_revision, {}))
        with self.assertRaisesRegex(ReducerError, "coordination"):
            decide_command(claimed, TaskCommand("pause", claimed.task_revision, {}))
        with self.assertRaisesRegex(ReducerError, "coordination"):
            decide_command(claimed, TaskCommand("propose_scope_change", claimed.task_revision, {
                "project_scope_ref": {**self.scope("drafted"), "version": 2},
                "scope_diff_digest": "diff", "run_ids": [],
            }))
        with self.assertRaisesRegex(ReducerError, "active"):
            decide_command(ready, TaskCommand("revoke", ready.task_revision, {"authority_id": "missing"}))
        created = apply_events(None, (self.event(1, "task.created", identity=self.identity()),))
        with self.assertRaisesRegex(ReducerError, "drafted project scope"):
            decide_command(created, TaskCommand(
                "request_prd_approval", created.task_revision, self.prd_request(),
            ))
        drafted = apply_events(created, (
            self.event(2, "project.scope_drafted", project_scope_ref=self.scope("drafted")),
        ))
        with self.assertRaisesRegex(ReducerError, "payload"):
            decide_command(drafted, TaskCommand("request_prd_approval", drafted.task_revision, {}))
        claimed_discovery = created.with_coordination(
            claims=("claim-1",), leases=(), schema_registry=SCHEMAS, context=context(),
        )
        deferred_cancel = decide_command(
            claimed_discovery, TaskCommand("cancel", claimed_discovery.task_revision, {}),
        )
        self.assertEqual(deferred_cancel[0].event_type, "task.cancel_requested")
        self.assertEqual(apply_events(claimed_discovery, deferred_cancel).lifecycle, "canceling")
        canceled = apply_events(ready, decide_command(
            ready, TaskCommand("cancel", ready.task_revision, {}),
        ))
        self.assertEqual((canceled.lifecycle, canceled.authorities), ("canceled", ()))

        running = apply_events(ready, decide_command(
            ready, TaskCommand("run", ready.task_revision, self.run_guards()),
        ))
        with self.assertRaisesRegex(ReducerError, "active coordination"):
            apply_events(running, (self.event(7, "task.pause_deferred", desired_state="paused"),))
        with self.assertRaisesRegex(ReducerError, "deferred cancellation"):
            apply_events(ready, (self.event(6, "task.cancel_requested"),))
        paused_with_finding = replace(ready, lifecycle="paused", open_findings=("finding-1",))
        with self.assertRaisesRegex(ReducerError, "resolved findings"):
            apply_events(paused_with_finding, (self.event(6, "task.resumed", **self.resume_guards()),))
        running_with_finding = replace(running, open_findings=("finding-1",))
        with self.assertRaisesRegex(ReducerError, "resolved findings"):
            apply_events(running_with_finding, (self.event(7, "task.completion_started"),))
        paused = replace(ready, lifecycle="paused")
        for command_type in ("resume", "rollback", "archive"):
            with self.subTest(command=command_type), self.assertRaisesRegex(ReducerError, "payload"):
                decide_command(paused, TaskCommand(command_type, paused.task_revision, {}))
        bad_rollback = self.rollback_guards()
        bad_rollback["compensable_action_refs"] = []
        with self.assertRaisesRegex(ReducerError, "compensable action"):
            decide_command(paused, TaskCommand("rollback", paused.task_revision, bad_rollback))

    def test_scope_reapproval_rebinds_scope_baselines_graph_and_authority(self) -> None:
        ready = self.snapshot_for_state("ready")
        self.assertIsNotNone(ready)
        scoped = apply_events(ready, decide_command(  # type: ignore[arg-type]
            ready,  # type: ignore[arg-type]
            TaskCommand("propose_scope_change", ready.task_revision, {  # type: ignore[union-attr]
                "project_scope_ref": {**self.scope("drafted"), "version": 2, "digest": "scope-v2"},
                "scope_diff_digest": "diff-v2", "run_ids": [],
            }),
        ))
        new_approval = self.approval()
        new_approval["baseline_refs"][0]["version"] = 2  # type: ignore[index]
        new_approval["baseline_refs"][0]["digest"] = "baseline-v2"  # type: ignore[index]
        new_approval["authority_refs"] = ["authority-2"]
        batch = decide_command(scoped, TaskCommand("approve_prd", scoped.task_revision, {
            "project_scope_ref": {**self.scope(), "version": 2, "digest": "scope-v2"},
            **new_approval,
        }))
        self.assertEqual(tuple(item.event_type for item in batch), ("project.scope_rebased", "task.prd_reapproved"))
        rebound = apply_events(scoped, batch)
        self.assertEqual(rebound.project_scope_ref["version"], 2)
        self.assertEqual(rebound.baseline_refs[0]["digest"], "baseline-v2")
        self.assertEqual(rebound.authorities, ("authority-2",))

    def test_approved_state_command_table_is_complete_and_default_deny(self) -> None:
        active_rollback = self.rollback_guards()
        active_rollback["authority_ref"] = "authority-1"
        command_payloads: dict[str, dict[str, object]] = {
            "create": {"identity": self.identity()},
            "bind_project_scope": {"project_scope_ref": self.scope("drafted")},
            "request_prd_approval": self.prd_request(),
            "revise_discovery": {},
            "approve_prd": {"project_scope_ref": self.scope(), **self.approval()},
            "propose_scope_change": {
                "project_scope_ref": {**self.scope("drafted"), "version": 2},
                "scope_diff_digest": "diff-digest",
                "run_ids": [],
            },
            "run": self.run_guards(),
            "pause": {},
            "resume": self.resume_guards(),
            "cancel": {},
            "revoke": {"authority_id": "authority-1"},
            "rollback": active_rollback,
            "archive": self.archive_guards(),
        }
        expected: dict[tuple[str, str], tuple[str, ...]] = {
            ("nonexistent", "create"): ("task.created",),
            ("discovering", "bind_project_scope"): ("project.scope_drafted",),
            ("discovering", "request_prd_approval"): ("task.prd_approval_requested",),
            ("awaiting_prd_approval", "revise_discovery"): ("task.discovery_reopened",),
            ("awaiting_prd_approval", "approve_prd"): ("project.scope_frozen", "task.prd_approved"),
            ("ready", "run"): ("task.run_started",),
            ("ready", "pause"): ("task.paused",),
            ("running", "pause"): ("task.paused",),
            ("running", "cancel"): ("task.cancel_requested",),
        }
        for state in ("paused", "awaiting_human", "blocked", "failed"):
            expected[(state, "resume")] = ("task.resumed",)
        for state in ("discovering", "awaiting_prd_approval", "ready", "paused", "awaiting_human", "blocked", "failed"):
            expected[(state, "cancel")] = ("task.canceled",)
        for state in ("ready", "paused", "awaiting_human", "blocked", "failed", "completed"):
            expected[(state, "propose_scope_change")] = (
                "project.scope_change_proposed", "task.downstream_invalidated",
            )
        for state in ("paused", "awaiting_human", "blocked", "failed", "canceled", "completed"):
            expected[(state, "rollback")] = ("task.rollback_requested",)
        for state in ("paused", "blocked", "failed", "canceled", "rolled_back", "completed"):
            expected[(state, "archive")] = ("task.archived",)
        for state in ("ready", "running"):
            expected[(state, "revoke")] = ("authority.revoked", "task.paused")
        for state in ("paused", "awaiting_human", "blocked", "failed", "canceling"):
            expected[(state, "revoke")] = ("authority.revoked",)
        for state in ("rollback_pending", "rolling_back", "completing"):
            expected[(state, "revoke")] = (
                "authority.revoked", "task.authority_reconciliation_required",
            )

        for state in sorted(LIFECYCLES):
            snapshot = self.snapshot_for_state(state)
            revision = 0 if snapshot is None else snapshot.task_revision
            for command_type, payload in command_payloads.items():
                key = (state, command_type)
                command = TaskCommand(command_type, revision, payload)
                if key not in expected:
                    with self.subTest(state=state, command=command_type), self.assertRaises(ReducerError):
                        decide_command(snapshot, command)
                    continue
                with self.subTest(state=state, command=command_type):
                    events = decide_command(snapshot, command)
                    self.assertEqual(tuple(item.event_type for item in events), expected[key])

    def test_finding_events_are_replayable_and_fail_closed(self) -> None:
        running = apply_events(
            self.snapshot_for_state("ready"),
            (self.event(6, "task.run_started", **self.run_guards()),),
        )
        opened = apply_events(running, (self.event(7, "finding.opened", finding_id="finding-1"),))
        self.assertEqual(opened.open_findings, ("finding-1",))
        with self.assertRaisesRegex(ReducerError, "already open"):
            apply_events(opened, (self.event(8, "finding.opened", finding_id="finding-1"),))
        closed = apply_events(opened, (self.event(8, "finding.closed", finding_id="finding-1"),))
        self.assertEqual(closed.open_findings, ())
        with self.assertRaisesRegex(ReducerError, "not open"):
            apply_events(closed, (self.event(9, "finding.closed", finding_id="finding-1"),))

    def test_node_transition_cartesian_model_matches_closed_table(self) -> None:
        event_types = sorted({event_type for _, event_type in NODE_TRANSITIONS})
        for status in sorted(NODE_STATUSES):
            for event_type in event_types:
                key = (status, event_type)
                run = NodeRun("run-1", "node-1", 2, status)
                if key not in NODE_TRANSITIONS:
                    with self.subTest(status=status, event=event_type), self.assertRaises(ReducerError):
                        transition_node(run, event_type)
                    continue
                with self.subTest(status=status, event=event_type):
                    updated = transition_node(run, event_type)
                    self.assertEqual(updated.status, NODE_TRANSITIONS[key])
                    expected_attempt = 3 if event_type in {"node.revise_requested", "node.retry_requested"} else 2
                    self.assertEqual(updated.attempt, expected_attempt)


if __name__ == "__main__":
    unittest.main()
