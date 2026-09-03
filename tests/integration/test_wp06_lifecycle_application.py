from __future__ import annotations

import sys
import unittest

from tests.integration.test_wp04_application import (
    ROOT,
    SCHEMAS,
    WORK,
    TaskApplicationIntegrationTests,
)


for responsibility in ("core", "storage", "application"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.application.tasks import ApplicationError, TaskApplication  # noqa: E402
from graph_engineering.core.actions import AuthorityEnvelope, PreparedAction  # noqa: E402
from graph_engineering.core.graph.state import TaskCommand  # noqa: E402
from graph_engineering.core.security.identity import SecurityBinding  # noqa: E402
from graph_engineering.storage.codec import (  # noqa: E402
    canonical_json,
    parse_canonical_json,
    semantic_record_digest,
)
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.application_queries import trusted_show  # noqa: E402


class WP06LifecycleApplicationTests(TaskApplicationIntegrationTests):
    @staticmethod
    def _write_security_state(
        factory,
        application: TaskApplication,
        authority_digests: tuple[str, ...] = (),
    ) -> str:
        view = trusted_show(application, "task-1")
        binding = {
            "schema_version": "1.0.0", "task_id": "task-1", "owner_id": "owner-1",
            "runtime_kind": "codex", "runtime_lineage_id": "lineage-1",
            "scope_id": "scope-main", "scope_digest": view.snapshot.project_scope_ref["digest"],
            "baselines": {"intent": "sha256-jcs-v1:" + "2" * 64},
            "snapshot_digest": view.snapshot.snapshot_digest,
            "targets": [{
                "target_id": "target-1", "target_kind": "repository",
                "canonical_identity": "repository-1", "target_digest": "sha256-jcs-v1:" + "3" * 64,
            }],
            "binding_digest": "sha256-jcs-v1:" + "0" * 64,
        }
        binding["binding_digest"] = SecurityBinding.digest_document(binding)
        state = {
            "schema_version": "1.0.0", "task_id": "task-1",
            "task_revision": view.repository_revision,
            "task_snapshot_digest": view.snapshot.snapshot_digest,
            "binding": binding, "destinations": {},
            "authority_digests": sorted(set(authority_digests)), "data_refs": {},
            "evidence_expectations": {},
            "retention_subjects": {
                "artifact-1": {"retention_class": "evidence-body", "legal_hold": False},
            },
        }
        state_digest = semantic_record_digest({"contract": "task-security-state-v1", "value": state})
        with factory._for_maintenance().open("migration") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO task_security_states(task_id,task_revision,task_snapshot_digest,state_json,state_digest) "
                    "VALUES(?,?,?,?,?)",
                    (
                        "task-1", view.repository_revision, view.snapshot.snapshot_digest,
                        canonical_json(state), state_digest,
                    ),
                )
        return state_digest

    @staticmethod
    def _write_rollback_actions(
        factory,
        application: TaskApplication,
        *,
        cyclic: bool = False,
    ) -> tuple[str, str]:
        target_digest = "sha256-jcs-v1:" + "3" * 64
        baseline = "sha256-jcs-v1:" + "2" * 64
        snapshot = "sha256-jcs-v1:" + "4" * 64

        def prepared(action_id, action_kind, rollback_plan):
            payload = {"operation": action_kind}
            value = {
                "schema_version": "1.0.0", "action_id": action_id, "task_id": "task-1",
                "action_kind": action_kind, "target_id": "target-1", "target_digest": target_digest,
                "resources": ["task:task-1"], "payload": payload,
                "payload_digest": PreparedAction.payload_digest_for(payload, WORK),
                "precondition": {"state": "before"}, "expected_postcondition": {"state": "after"},
                "idempotency_class": "non-idempotent", "idempotency_key": f"key-{action_id}",
                "verification_plan": {"kind": "fresh-target-query"},
                "rollback_plan": rollback_plan, "required_capabilities": ["fake-target"],
                "baseline_digest": baseline, "snapshot_digest": snapshot,
            }
            value["prepared_action_digest"] = PreparedAction.digest_document(value, WORK)
            return value

        original_specs = [
            (
                "action-original", "action-compensate",
                ["action-original-2"] if cyclic else [],
            ),
        ]
        if cyclic:
            original_specs.append((
                "action-original-2", "action-compensate-2", ["action-original"],
            ))

        def authority(authority_id: str, action: dict[str, object], kind: str) -> dict[str, object]:
            value = {
                "schema_version": "1.0.0", "authority_id": authority_id,
                "task_id": "task-1", "owner_id": "owner-1", "runtime_kind": "codex",
                "runtime_lineage_id": "lineage-1", "authorized_action_kind": kind,
                "authorized_resources": ["task:task-1"],
                "prepared_action_digest": action["prepared_action_digest"],
                "baseline_digest": baseline, "snapshot_digest": snapshot,
                "issued_at": "2026-08-14T00:00:00Z", "expires_at": "2026-08-14T01:00:00Z",
                "status": "active",
            }
            value["authority_digest"] = AuthorityEnvelope.digest_document(value, WORK)
            return value

        originals = [
            prepared(original_id, "commit", {
                "compensation_action_id": compensation_id,
                "depends_on_action_ids": dependencies,
            })
            for original_id, compensation_id, dependencies in original_specs
        ]
        compensations = [
            prepared(compensation_id, "rollback", {"kind": "verify-original"})
            for _original_id, compensation_id, _dependencies in original_specs
        ]
        compensation_authorities = [
            authority(f"authority-{action['action_id']}", action, "rollback")
            for action in compensations
        ]
        request = prepared(
            "action-rollback-request-authority", "rollback-request",
            {"kind": "authorize-controlled-rollback"},
        )
        request_authority = authority("authority-1", request, "rollback-request")
        with factory._for_maintenance().open("migration") as connection:
            with connection.transaction():
                for revision, original in enumerate(originals, start=1):
                    connection.execute(
                        "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                        "prepared_json,prepared_digest) VALUES(?,?,?,?,?,?,?)",
                        (
                            original["action_id"], "task-1", "succeeded", revision,
                            original["idempotency_key"], canonical_json(original),
                            original["prepared_action_digest"],
                        ),
                    )
                for revision, (compensation, envelope) in enumerate(
                    zip(compensations, compensation_authorities, strict=True),
                    start=len(originals) + 1,
                ):
                    connection.execute(
                        "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                        "prepared_json,prepared_digest,authority_json,authority_digest) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (
                            compensation["action_id"], "task-1", "authorized", revision,
                            compensation["idempotency_key"], canonical_json(compensation),
                            compensation["prepared_action_digest"], canonical_json(envelope),
                            envelope["authority_digest"],
                        ),
                    )
                connection.execute(
                    "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                    "prepared_json,prepared_digest,authority_json,authority_digest) "
                    "VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        request["action_id"], "task-1", "authorized",
                        len(originals) + len(compensations) + 1, request["idempotency_key"],
                        canonical_json(request), request["prepared_action_digest"],
                        canonical_json(request_authority), request_authority["authority_digest"],
                    ),
                )
        security_digest = WP06LifecycleApplicationTests._write_security_state(
            factory, application, (request_authority["authority_digest"],),
        )
        return request_authority["authority_digest"], security_digest
    def _paused(self, repository, leases) -> TaskApplication:
        application = TaskApplication(
            repository, repository, leases, schema_registry=SCHEMAS, context=WORK,
        )
        application.execute(
            "task-1", TaskCommand("create", 0, {"identity": self.identity()}), self.runtime("t-1"),
        )
        application.execute_scope(
            "task-1", TaskCommand("bind_project_scope", 1, {"project_scope_ref": self.scope("drafted")}),
            self.project_scope(), self.runtime("t-2"),
        )
        application.execute(
            "task-1", TaskCommand("request_prd_approval", 2, {"prd_candidate_ref": "artifact:prd-v1"}),
            self.runtime("t-3"),
        )
        application.execute(
            "task-1", TaskCommand("approve_prd", 3, self.approval()), self.runtime("t-4"),
        )
        application.execute("task-1", TaskCommand("pause", 5, {}), self.runtime("t-5"))
        return application

    def test_gew_lif_009_durable_coordination_drift_rejects_cancel_before_write(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            lease = leases.acquire_many(
                lease_id="untracked-live-lease", task_id="task-1", run_id="run-external",
                operation_id="external", resources=("resource-external",), ttl_ns=100,
            )
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "durable retention plan"):
                application.execute("task-1", TaskCommand("cancel", 6, {}), self.runtime("t-6"))
            self.assertEqual(repository.replay("task-1"), before)
            leases.release(lease.lease_id)

    def test_gew_lif_010_controlled_rollback_requires_exact_compensable_action_set(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            self._write_rollback_actions(factory, application)
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-plan"),
            )
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "durable rollback plan"):
                application.execute("task-1", TaskCommand("rollback", 6, {
                    "compensable_action_refs": ("action-other",),
                    "rollback_plan_ref": plan["plan_id"], "authority_ref": "authority-1",
                }), self.runtime("t-6"))
            self.assertEqual(repository.replay("task-1"), before)
            receipt = application.request_controlled_rollback(
                "task-1", 6, plan["plan_id"], self.runtime("t-7"),
            )
            self.assertEqual(receipt.lifecycle, "rollback_pending")

    def test_gew_lif_011_archive_requires_current_retention_and_rollback_clearance(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            security_digest = self._write_security_state(factory, application)
            plan = application.prepare_retention_plan("task-1", "archive", self.runtime("t-plan"))
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "durable retention plan"):
                application.execute("task-1", TaskCommand("archive", 6, {
                    "retention_plan_ref": "wrong", "rollback_clearance_ref": "wrong",
                }), self.runtime("t-6"))
            self.assertEqual(repository.replay("task-1"), before)
            receipt = application.archive_with_retention(
                "task-1", 6, plan["plan_id"], self.runtime("t-7"),
            )
            self.assertEqual(receipt.lifecycle, "archived")

    def test_gew_lif_012_lifecycle_transitions_preserve_fence_action_and_event_audit(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            self._write_rollback_actions(factory, application)
            before_facts = repository.lifecycle_facts("task-1")
            before_events = repository.replay("task-1")
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-plan"),
            )
            application.request_controlled_rollback(
                "task-1", 6, plan["plan_id"], self.runtime("t-6"),
            )
            after_facts = repository.lifecycle_facts("task-1")
            before_fences = dict(before_facts["fencing_high_water"])
            after_fences = dict(after_facts["fencing_high_water"])
            self.assertTrue(all(after_fences.get(resource, 0) >= counter for resource, counter in before_fences.items()))
            self.assertEqual(after_facts["action_states"], before_facts["action_states"])
            self.assertEqual(repository.replay("task-1")[:len(before_events)], before_events)

    def test_gew_lif_018_lifecycle_facts_are_revalidated_inside_commit_transaction(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            before = repository.replay("task-1")
            injected = False

            def inject(step: str) -> None:
                nonlocal injected
                if step != "commit.before_transaction" or injected:
                    return
                injected = True
                with factory._for_maintenance().open("migration") as connection:
                    with connection.transaction():
                        connection.execute(
                            "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                            "prepared_json,prepared_digest) VALUES(?,?,?,?,?,?,?)",
                            (
                                "action-raced", "task-1", "succeeded", 1, "key-raced", "{}",
                                semantic_record_digest({"prepared": "raced"}),
                            ),
                        )

            repository._fault = inject
            plan = application.prepare_retention_plan(
                "task-1", "cancel", self.runtime("t-plan-race"),
            )
            with self.assertRaisesRegex(Exception, "lifecycle facts changed"):
                application.cancel_with_retention(
                    "task-1", 6, plan["plan_id"], self.runtime("t-race"),
                )
            repository._fault = lambda _step: None
            self.assertEqual(repository.replay("task-1"), before)
            self.assertEqual(repository.lifecycle_facts("task-1")["action_states"], (
                ("action-raced", "succeeded"),
            ))

    def test_gew_lif_019_archive_consumes_durable_retention_plan_and_only_schedules_purge(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            security_digest = self._write_security_state(factory, application)
            plan = application.prepare_retention_plan("task-1", "archive", self.runtime("t-plan"))
            self.assertEqual(repository.lifecycle_plan(plan["plan_id"])["state"], "prepared")
            facts = repository.lifecycle_facts("task-1")
            with self.assertRaisesRegex(ApplicationError, "durable retention plan"):
                application.execute("task-1", TaskCommand("archive", 6, {
                    "retention_plan_ref": facts["retention_plan_ref"],
                    "rollback_clearance_ref": facts["rollback_clearance_ref"],
                }), self.runtime("t-raw"))
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE task_security_states SET state_digest=? WHERE task_id=?",
                        ("sha256-jcs-v1:" + "9" * 64, "task-1"),
                    )
            with self.assertRaisesRegex(Exception, "security state"):
                application.archive_with_retention(
                    "task-1", 6, plan["plan_id"], self.runtime("t-stale"),
                )
            self.assertEqual(repository.lifecycle_plan(plan["plan_id"])["state"], "prepared")
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE task_security_states SET state_digest=? WHERE task_id=?",
                        (security_digest, "task-1"),
                    )
            receipt = application.archive_with_retention(
                "task-1", 6, plan["plan_id"], self.runtime("t-archive"),
            )
            self.assertEqual(receipt.lifecycle, "archived")
            durable = repository.lifecycle_plan(plan["plan_id"])
            self.assertEqual(durable["state"], "consumed")
            self.assertEqual(durable["execution"]["trigger"], "archive")
            self.assertFalse(durable["execution"]["physical_purge_claimed"])

    def test_gew_lif_020_cancel_uses_durable_retention_schedule(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            self._write_security_state(factory, application)
            plan = application.prepare_retention_plan("task-1", "cancel", self.runtime("t-plan"))
            receipt = application.cancel_with_retention(
                "task-1", 6, plan["plan_id"], self.runtime("t-cancel"),
            )
            self.assertEqual(receipt.lifecycle, "canceled")
            execution = repository.lifecycle_plan(plan["plan_id"])["execution"]
            self.assertEqual((execution["trigger"], execution["physical_purge_claimed"]), ("cancel", False))

        with self.subTest("empty durable retention plan is still mandatory"):
            with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
                application = self._paused(repository, leases)
                before = repository.replay("task-1")
                with self.assertRaisesRegex(ApplicationError, "durable retention plan"):
                    application.execute(
                        "task-1", TaskCommand("cancel", 6, {}), self.runtime("t-direct"),
                    )
                self.assertEqual(repository.replay("task-1"), before)
                plan = application.prepare_retention_plan(
                    "task-1", "cancel", self.runtime("t-empty-plan"),
                )
                self.assertEqual(
                    (plan["body"]["security_state_digest"], plan["body"]["schedules"]),
                    (None, []),
                )
                receipt = application.cancel_with_retention(
                    "task-1", 6, plan["plan_id"], self.runtime("t-empty-cancel"),
                )
                self.assertEqual(receipt.lifecycle, "canceled")

    def test_gew_lif_021_controlled_rollback_consumes_exact_compensation_graph(self) -> None:
        with self.subTest("cyclic compensation graph commits no plan"):
            with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
                application = self._paused(repository, leases)
                self._write_rollback_actions(factory, application, cyclic=True)
                with self.assertRaisesRegex(Exception, "acyclic"):
                    application.prepare_controlled_rollback(
                        "task-1", "authority-1", self.runtime("t-cycle"),
                    )
                with factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT COUNT(*) FROM lifecycle_plans",
                    ).fetchone()[0], 0)

        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            request_authority_digest, _security_digest = self._write_rollback_actions(
                factory, application,
            )
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-plan"),
            )
            body = plan["body"]
            self.assertEqual(body["compensable_action_refs"], ["action-original"])
            self.assertEqual(body["steps"][0]["compensation_action_id"], "action-compensate")
            self.assertEqual(body["request_authority_digest"], request_authority_digest)
            with self.assertRaisesRegex(ApplicationError, "durable rollback plan"):
                application.execute("task-1", TaskCommand("rollback", 6, {
                    "compensable_action_refs": ("action-original",),
                    "rollback_plan_ref": plan["plan_id"], "authority_ref": "authority-1",
                }), self.runtime("t-raw"))
            with self.assertRaisesRegex(ApplicationError, "durable rollback plan"):
                application.request_controlled_rollback(
                    "task-1", 6, "lifecycle-plan:missing", self.runtime("t-missing"),
                )
            substituted = parse_canonical_json(canonical_json(body))
            substituted["steps"][0]["compensation_action_id"] = "action-substituted"
            substituted_digest = semantic_record_digest({
                "contract": "lifecycle-plan-v1", "value": substituted,
            })
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE lifecycle_plans SET body_json=?,body_digest=? WHERE plan_id=?",
                        (canonical_json(substituted), substituted_digest, plan["plan_id"]),
                    )
            with self.assertRaisesRegex(ApplicationError, "durable rollback plan"):
                application.request_controlled_rollback(
                    "task-1", 6, plan["plan_id"], self.runtime("t-substituted"),
                )
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE lifecycle_plans SET body_json=?,body_digest=? WHERE plan_id=?",
                        (canonical_json(body), plan["body_digest"], plan["plan_id"]),
                    )
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    row = connection.execute(
                        "SELECT state_json FROM task_security_states WHERE task_id='task-1'",
                    ).fetchone()
                    state = parse_canonical_json(row[0])
                    self.assertIsInstance(state, dict)
                    state["authority_digests"] = []
                    connection.execute(
                        "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id='task-1'",
                        (
                            canonical_json(state), semantic_record_digest({
                                "contract": "task-security-state-v1", "value": state,
                            }),
                        ),
                    )
            with self.assertRaisesRegex(Exception, "request authority"):
                application.request_controlled_rollback(
                    "task-1", 6, plan["plan_id"], self.runtime("t-authority-removed"),
                )
            self.assertEqual(repository.lifecycle_plan(plan["plan_id"])["state"], "prepared")
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    state["authority_digests"] = [request_authority_digest]
                    connection.execute(
                        "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id='task-1'",
                        (
                            canonical_json(state), semantic_record_digest({
                                "contract": "task-security-state-v1", "value": state,
                            }),
                        ),
                    )
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-replan-after-authority"),
            )
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE action_journal SET state='revoked' WHERE action_id=?",
                        ("action-compensate",),
                    )
            with self.assertRaisesRegex(Exception, "authority changed"):
                application.request_controlled_rollback(
                    "task-1", 6, plan["plan_id"], self.runtime("t-revoked"),
                )
            self.assertEqual(repository.lifecycle_plan(plan["plan_id"])["state"], "prepared")
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE action_journal SET state='authorized' WHERE action_id=?",
                        ("action-compensate",),
                    )
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-replan-after-compensation"),
            )
            receipt = application.request_controlled_rollback(
                "task-1", 6, plan["plan_id"], self.runtime("t-rollback"),
            )
            self.assertEqual(receipt.lifecycle, "rollback_pending")
            self.assertEqual(repository.lifecycle_plan(plan["plan_id"])["state"], "consumed")

    def test_gew_lif_022_rollback_plan_preserves_audit_and_fence_high_water(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            application = self._paused(repository, leases)
            self._write_rollback_actions(factory, application)
            before_events = repository.replay("task-1")
            before_facts = repository.lifecycle_facts("task-1")
            plan = application.prepare_controlled_rollback(
                "task-1", "authority-1", self.runtime("t-plan"),
            )
            application.request_controlled_rollback(
                "task-1", 6, plan["plan_id"], self.runtime("t-rollback"),
            )
            after = repository.lifecycle_facts("task-1")
            self.assertEqual(repository.replay("task-1")[:len(before_events)], before_events)
            self.assertEqual(after["action_states"], before_facts["action_states"])
            before_fences = dict(before_facts["fencing_high_water"])
            self.assertTrue(all(dict(after["fencing_high_water"]).get(key, 0) >= value for key, value in before_fences.items()))


if __name__ == "__main__":
    unittest.main()
