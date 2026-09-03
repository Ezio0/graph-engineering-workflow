from __future__ import annotations

import json
import copy
import pathlib
import sys
import unittest
from pkgutil import extend_path


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage", "application"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

import graph_engineering  # noqa: E402

graph_engineering.__path__ = extend_path(graph_engineering.__path__, graph_engineering.__name__)

from graph_engineering.application.tasks import (  # noqa: E402
    ApplicationError,
    RuntimeContext,
    TaskApplication,
)
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.resources import (  # noqa: E402
    CostSchedule,
    ResourceProfile,
    WorkContext,
)
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.graph.state import TaskCommand  # noqa: E402
from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.application_queries import trusted_list, trusted_search, trusted_show  # noqa: E402
from tests.support.runtime import runtime_context  # noqa: E402
from tests.unit.test_wp06_project_scope import load as load_project_scope, scope_document  # noqa: E402
from tests.unit import test_wp08_profile_contracts as wp08  # noqa: E402


def contracts() -> tuple[ClosedSchemaRegistry, WorkContext]:
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
    profile = ResourceProfile.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text()
    ))
    schedule = CostSchedule.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text()
    ))
    policy = SchemaProfilePolicy.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "schema-profile-v1.json").read_text()
    ))
    manifest = json.loads(
        (ROOT / "config" / "contracts" / "graph-schema-registry-v1.json").read_text()
    )
    return ClosedSchemaRegistry.build(manifest, bodies, profile, policy), WorkContext(profile, schedule)


SCHEMAS, WORK = contracts()


class TaskApplicationIntegrationTests(unittest.TestCase):
    def runtime(
        self,
        occurred_at: str,
        *,
        owner: str = "owner-1",
        kind: str = "codex",
        lineage: str = "lineage-1",
    ) -> RuntimeContext:
        return runtime_context(owner, kind, lineage, "actor-1", occurred_at, 100)

    @staticmethod
    def identity() -> dict[str, object]:
        return {
            "task_id": "task-1",
            "owner_id": "owner-1",
            "runtime_kind": "codex",
            "runtime_lineage_id": "lineage-1",
        }

    @staticmethod
    def scope(status: str) -> dict[str, object]:
        project_scope = load_project_scope(scope_document())
        return {
            "scope_id": project_scope.scope_id,
            "version": project_scope.version,
            "digest": project_scope.scope_digest,
            "status": status,
        }

    @staticmethod
    def project_scope():
        return load_project_scope(scope_document())

    @staticmethod
    def approval() -> dict[str, object]:
        return {
            "project_scope_ref": TaskApplicationIntegrationTests.scope("frozen"),
            "owner_decision_ref": "decision:prd-approved-v1",
            "baseline_refs": ({
                "kind": "intent",
                "version": 1,
                "digest": "baseline-digest",
                "approved_by": "owner-1",
                "approved_at": "2026-08-14T00:00:00Z",
            },),
            "graph_ref": {
                "graph_id": "delivery",
                "graph_version": "1.0.0",
                "profile_id": "new-feature",
                "profile_version": "1.0.0",
                "risk_path": "full-planned",
                "graph_digest": "sha256-jcs-v1:" + "1" * 64,
            },
            "authority_refs": ("authority-1",),
        }

    def test_command_transaction_query_and_idempotent_recovery(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=SCHEMAS, context=WORK,
                materialization_objects=_objects,
            )
            create = TaskCommand("create", 0, {"identity": self.identity()})
            first = application.execute("task-1", create, self.runtime("t-1"))
            self.assertEqual((first.lifecycle, first.task_revision, first.repository_revision), (
                "discovering", 1, 1,
            ))
            duplicate = application.execute("task-1", create, self.runtime("t-1"))
            self.assertTrue(duplicate.idempotent_replay)
            self.assertEqual(len(repository.replay("task-1")), 1)

            bound = application.execute_scope("task-1", TaskCommand(
                "bind_project_scope", 1, {"project_scope_ref": self.scope("drafted")},
            ), self.project_scope(), self.runtime("t-2"))
            requested = application.execute("task-1", TaskCommand(
                "request_prd_approval", 2, {"prd_candidate_ref": "artifact:prd-v1"},
            ), self.runtime("t-3"))
            approved = application.execute(
                "task-1", TaskCommand("approve_prd", 3, self.approval()), self.runtime("t-4"),
            )
            self.assertEqual(bound.task_revision, 2)
            self.assertEqual(requested.task_revision, 3)
            self.assertEqual(approved.event_types, (
                "project.scope_frozen", "task.prd_approved",
            ))
            self.assertEqual((approved.task_revision, approved.repository_revision), (5, 4))

            before_query = repository.replay("task-1")
            view = trusted_show(application, "task-1")
            matches = trusted_search(application, {"lifecycle": "ready"})
            listed = trusted_list(application)
            self.assertEqual((view.snapshot.lifecycle, view.snapshot.task_revision), ("ready", 5))
            self.assertEqual([item["task_id"] for item in matches], ["task-1"])
            self.assertEqual(listed, matches)
            self.assertEqual(repository.replay("task-1"), before_query)

            running = application.execute("task-1", TaskCommand(
                "run", 5, {
                    "compatibility_evidence_ref": "evidence:compatibility-v1",
                    "lease_plan_ref": "lease-plan:none-v1",
                },
            ), self.runtime("t-5"))
            paused = application.execute(
                "task-1", TaskCommand("pause", 6, {}), self.runtime("t-6"),
            )
            resumed = application.execute("task-1", TaskCommand(
                "resume", 7, {
                    "resolution_evidence_refs": ("evidence:pause-resolved-v1",),
                    "compatibility_evidence_ref": "evidence:compatibility-v1",
                },
            ), self.runtime("t-7"))
            self.assertEqual((running.lifecycle, paused.lifecycle, resumed.lifecycle), (
                "running", "paused", "ready",
            ))

    def test_wrong_owner_or_runtime_lineage_fails_before_mutation(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=SCHEMAS, context=WORK,
                materialization_objects=_objects,
            )
            application.execute(
                "task-1",
                TaskCommand("create", 0, {"identity": self.identity()}),
                self.runtime("t-1"),
            )
            before = repository.replay("task-1")
            for runtime in (
                self.runtime("t-2", owner="owner-2"),
                self.runtime("t-2", lineage="lineage-2"),
                self.runtime("t-2", kind="hermes"),
            ):
                with self.subTest(runtime=runtime), self.assertRaisesRegex(
                    ApplicationError, "runtime owner or lineage",
                ):
                    application.execute_scope(
                        "task-1",
                        TaskCommand("bind_project_scope", 1, {
                            "project_scope_ref": self.scope("drafted"),
                        }),
                        self.project_scope(),
                        runtime,
                    )
            self.assertEqual(repository.replay("task-1"), before)

            application.execute_scope(
                "task-1",
                TaskCommand("bind_project_scope", 1, {
                    "project_scope_ref": self.scope("drafted"),
                }),
                self.project_scope(),
                self.runtime("t-3"),
            )
            application.execute(
                "task-1",
                TaskCommand("request_prd_approval", 2, {
                    "prd_candidate_ref": "artifact:prd-v1",
                }),
                self.runtime("t-4"),
            )
            profile_api = wp08._profile_api()
            registry = wp08._approved_registry()
            profile = profile_api.ProfileDefinition.from_dict(
                wp08._profile_document(), approved_profiles=registry,
                coverage_policy=wp08._coverage_policy(),
                semantic_policy=wp08._semantic_policy(),
            )
            overlay = profile_api.RiskOverlayDefinition.from_dict(
                wp08._overlay_document(), approved_profiles=registry,
                coverage_policy=wp08._coverage_policy(),
            )
            matrix = profile_api.SupportMatrixDefinition.from_dict(
                wp08._support_matrix_document(), approved_profiles=registry,
                coverage_policy=wp08._coverage_policy(),
            )
            materialized = profile_api.ProfileMaterializer.materialize(
                base_graph_document={
                    "graph_id": "delivery",
                    "graph_version": "1.0.0",
                    "graph_digest": "sha256-jcs-v1:" + "1" * 64,
                    "node_ids": list(profile.required_node_ids),
                    "edge_ids": list(profile.required_edge_ids),
                },
                profile=profile,
                overlay=overlay,
                project_config={},
                approved_profiles=registry,
                support_matrix=matrix,
                semantic_policy=wp08._semantic_policy(),
            )
            valid_approval = self.approval()
            valid_approval["graph_ref"] = dict(materialized.graph_ref())
            record_clone = object.__new__(profile_api.MaterializationRecord)
            for field in profile_api.MaterializationRecord.__dataclass_fields__:
                object.__setattr__(record_clone, field, getattr(materialized.record, field))
            with self.assertRaises(ApplicationError):
                application.preauthorize_materialization(record_clone)
            materialization_reference = application.preauthorize_materialization(
                materialized.record,
            )
            persisted_materialization_body = _objects.get(
                materialization_reference.object_digest, require_referenced=False,
            )
            references_before = repository.referenced_objects("task-1")
            reference_clone = object.__new__(profile_api.MaterializationObjectReference)
            for field in profile_api.MaterializationObjectReference.__dataclass_fields__:
                object.__setattr__(
                    reference_clone, field, getattr(materialization_reference, field),
                )
            foreign_consumer = TaskApplication(
                repository, repository, leases, schema_registry=SCHEMAS, context=WORK,
                materialization_objects=_objects,
            )
            foreign_approval = copy.deepcopy(valid_approval)
            foreign_before = copy.deepcopy(foreign_approval)
            events_before = repository.replay("task-1")
            snapshot_before = repository.load("task-1")
            references_before = repository.referenced_objects("task-1")
            with self.assertRaises(ApplicationError):
                foreign_consumer.execute(
                    "task-1", TaskCommand("approve_prd", 3, foreign_approval),
                    self.runtime("t-foreign"),
                    materialization_reference=materialization_reference,
                )
            self.assertEqual(repository.replay("task-1"), events_before)
            self.assertEqual(repository.load("task-1"), snapshot_before)
            self.assertEqual(repository.referenced_objects("task-1"), references_before)
            self.assertEqual(
                _objects.get(
                    materialization_reference.object_digest,
                    require_referenced=False,
                ),
                persisted_materialization_body,
            )
            self.assertEqual(foreign_approval, foreign_before)
            for pin in (
                "graph_digest", "profile_digest", "overlay_digest",
                "project_config_digest", "support_matrix_digest",
            ):
                candidate = copy.deepcopy(valid_approval)
                graph_ref = candidate["graph_ref"]
                self.assertIsInstance(graph_ref, dict)
                graph_ref[pin] = "sha256-jcs-v1:" + "e" * 64  # type: ignore[index]
                materialization_body = {
                    "graph_id": graph_ref["graph_id"],  # type: ignore[index]
                    "graph_version": graph_ref["graph_version"],  # type: ignore[index]
                    "profile_id": graph_ref["profile_id"],  # type: ignore[index]
                    "profile_version": graph_ref["profile_version"],  # type: ignore[index]
                    "overlay_id": graph_ref["overlay_id"],  # type: ignore[index]
                    "overlay_version": graph_ref["overlay_version"],  # type: ignore[index]
                    "digest_pins": {
                        "base_graph_digest": graph_ref["graph_digest"],  # type: ignore[index]
                        "profile_digest": graph_ref["profile_digest"],  # type: ignore[index]
                        "overlay_digest": graph_ref["overlay_digest"],  # type: ignore[index]
                        "project_config_digest": graph_ref["project_config_digest"],  # type: ignore[index]
                        "support_matrix_digest": graph_ref["support_matrix_digest"],  # type: ignore[index]
                    },
                }
                graph_ref["materialization_digest"] = semantic_digest(  # type: ignore[index]
                    materialization_body,
                    contract_type="urn:gew:contract:profile-materialization",
                    projection_id="urn:gew:digest-projection:profile-materialization:1.0.0",
                    schema_id="urn:gew:schema:profile-materialization-input:1.0.0",
                )
                candidate_before = copy.deepcopy(candidate)
                events_before = repository.replay("task-1")
                snapshot_before = repository.load("task-1")
                with self.subTest(materialization_pin=pin), self.assertRaises(ApplicationError):
                    application.execute(
                        "task-1", TaskCommand("approve_prd", 3, candidate),
                        self.runtime("t-5"),
                        materialization_reference=reference_clone,
                    )
                self.assertEqual(repository.replay("task-1"), events_before)
                self.assertEqual(repository.load("task-1"), snapshot_before)
                self.assertEqual(repository.referenced_objects("task-1"), references_before)
                self.assertEqual(
                    _objects.get(
                        materialization_reference.object_digest,
                        require_referenced=False,
                    ),
                    persisted_materialization_body,
                )
                self.assertEqual(candidate, candidate_before)

            application.execute(
                "task-1", TaskCommand("approve_prd", 3, valid_approval),
                self.runtime("t-6"),
                materialization_reference=materialization_reference,
            )
            self.assertFalse(hasattr(profile_api.MaterializationRecord, "from_persisted_bytes"))
            restarted = TaskApplication(
                repository, repository, leases, schema_registry=SCHEMAS, context=WORK,
                materialization_objects=_objects,
            )
            self.assertEqual(
                dict(trusted_show(restarted, "task-1").snapshot.graph_ref),
                dict(materialized.graph_ref()),
            )


if __name__ == "__main__":
    unittest.main()
