from __future__ import annotations

import copy
import json
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

from graph_engineering.application.runner import (  # noqa: E402
    ApplicationRunner,
    Finding,
    NodeCandidate,
    NodeRuntimeFailure,
    ReviewResult,
    RunnerError,
    ValidationResult,
)
from graph_engineering.application.completion import CompletionGate  # noqa: E402
from graph_engineering.application.tasks import (  # noqa: E402
    ApplicationError,
    RuntimeContext,
    TaskApplication,
    _TransitionAuthority,
)
from graph_engineering.core.artifacts.records import (  # noqa: E402
    ARTIFACT_RECORD_SCHEMA,
    ArtifactValidator,
)
from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from graph_engineering.core.graph.budget import LoopBudgetRegistry  # noqa: E402
from graph_engineering.core.graph.state import DomainEvent, TaskCommand  # noqa: E402
from tests.contract.test_wp02_graph import (  # noqa: E402
    complete,
    graph_candidate,
    graph_schemas,
    load_graph,
    loop_budgets,
    error_rule_registry,
    predicate_registry,
    work_context,
)
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.application_queries import trusted_show  # noqa: E402
from tests.support.runtime import runtime_context  # noqa: E402
from tests.support.wp04a_artifacts import loaded_golden  # noqa: E402
from tests.unit.test_wp06_project_scope import load as load_project_scope, scope_document  # noqa: E402
from tests.unit import test_wp08_profile_contracts as wp08  # noqa: E402
from tests.unit import test_wp08_profile_expansion as wp08s2  # noqa: E402


class PassingRuntime:
    def execute(self, node, *, run_id, attempt, runtime):  # noqa: ANN001, ANN201
        del runtime
        body = f'{{"enabled":true,"node":"{node.node_id}","attempt":{attempt}}}'.encode()
        return NodeCandidate(
            body,
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            f"author-{node.node_id}",
            {"from_output": {"enabled": True}},
        )


class SameDigestRuntime:
    def execute(self, node, *, run_id, attempt, runtime):  # noqa: ANN001, ANN201
        del run_id, attempt, runtime
        body = f'{{"enabled":true,"node":"{node.node_id}"}}'.encode()
        return NodeCandidate(
            body,
            "sha256:" + __import__("hashlib").sha256(body).hexdigest(),
            f"author-{node.node_id}",
            {"from_output": {"enabled": True}},
        )


class FallbackRuntime(PassingRuntime):
    def execute(self, node, *, run_id, attempt, runtime):  # noqa: ANN001, ANN201
        if node.node_id == "start":
            raise NodeRuntimeFailure("E_RUNTIME")
        return super().execute(node, run_id=run_id, attempt=attempt, runtime=runtime)


class PassingValidator:
    def validate(self, node, candidate, *, context):  # noqa: ANN001, ANN201
        del node, candidate, context
        return ValidationResult(True, ("schema-validation",), "validated")


class PassingReviewer:
    def review(self, node, candidate, validation, *, runtime):  # noqa: ANN001, ANN201
        del candidate, validation, runtime
        return ReviewResult("PASS", f"reviewer-{node.node_id}")


class CountingPassingReviewer(PassingReviewer):
    def __init__(self) -> None:
        self.calls: list[str] = []

    def review(self, node, candidate, validation, *, runtime):  # noqa: ANN001, ANN201
        self.calls.append(node.node_id)
        return super().review(node, candidate, validation, runtime=runtime)


class RevisingReviewer:
    def review(self, node, candidate, validation, *, runtime):  # noqa: ANN001, ANN201
        del candidate, validation, runtime
        return ReviewResult("REVISE", f"reviewer-{node.node_id}", (Finding(
            f"finding-{node.node_id}",
            "major",
            ("review-evidence",),
            "change the candidate",
            "review the changed digest",
            node.node_id,
        ),))


class ReviseThenPassReviewer:
    def review(self, node, candidate, validation, *, runtime):  # noqa: ANN001, ANN201
        del candidate, validation, runtime
        if node.node_id == "start" and not getattr(self, "revised", False):
            self.revised = True
            return ReviewResult("REVISE", "reviewer-start", (Finding(
                "finding-start",
                "major",
                ("review-evidence",),
                "change the candidate",
                "review the changed digest",
                "start",
            ),))
        return ReviewResult("PASS", f"reviewer-{node.node_id}")


class ApplicationRunnerIntegrationTests(unittest.TestCase):
    def runtime(self, occurred_at: str) -> RuntimeContext:
        return runtime_context(
            "owner-1", "codex", "lineage-1", "runtime-actor", occurred_at, 100,
        )

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
            "scope_id": project_scope.scope_id, "version": project_scope.version,
            "digest": project_scope.scope_digest, "status": status,
        }

    @staticmethod
    def project_scope():
        return load_project_scope(scope_document())

    def prepare(
        self,
        application: TaskApplication,
        digest: str,
        *,
        baseline_digest: str = "baseline-digest",
    ) -> None:
        application.execute(
            "task-1", TaskCommand("create", 0, {"identity": self.identity()}), self.runtime("t-1"),
        )
        application.execute_scope("task-1", TaskCommand(
            "bind_project_scope", 1, {"project_scope_ref": self.scope("drafted")},
        ), self.project_scope(), self.runtime("t-2"))
        application.execute("task-1", TaskCommand(
            "request_prd_approval", 2, {"prd_candidate_ref": "artifact:prd-v1"},
        ), self.runtime("t-3"))
        application.execute("task-1", TaskCommand("approve_prd", 3, {
            "project_scope_ref": self.scope("frozen"),
            "owner_decision_ref": "decision:approved-v1",
            "baseline_refs": ({
                "kind": "intent", "version": 1, "digest": baseline_digest,
                "approved_by": "owner-1", "approved_at": "2026-08-14T00:00:00Z",
            },),
            "graph_ref": {
                "graph_id": "test-delivery", "graph_version": "1.0.0",
                "profile_id": "new-feature", "profile_version": "1.0.0",
                "risk_path": "full-planned", "graph_digest": digest,
            },
            "authority_refs": ("authority-1",),
        }), self.runtime("t-4"))
        application.execute("task-1", TaskCommand("run", 5, {
            "compatibility_evidence_ref": "evidence:compatibility-v1",
            "lease_plan_ref": "lease-plan:none-v1",
        }), self.runtime("t-5"))

    def stack(self, *, with_budget: bool = False):  # noqa: ANN201
        schemas = graph_schemas()
        context = work_context()
        candidate = graph_candidate()
        if with_budget:
            for node in candidate["nodes"]:
                node["loop_budget_ref"] = "loop:bounded-v1"
        graph = load_graph(complete(copy.deepcopy(candidate)), schemas=schemas, context=context)
        budgets = loop_budgets(schemas=schemas, context=context)
        return schemas, context, graph, budgets

    @staticmethod
    def materialization(graph, overlay_id: str):  # noqa: ANN001, ANN201
        api = wp08._profile_api()
        approved = wp08._approved_registry()
        coverage = wp08._coverage_policy()
        semantic = wp08._semantic_policy()
        profile = api.ProfileDefinition.from_dict(
            wp08s2._profile_document("new-feature"),
            approved_profiles=approved,
            coverage_policy=coverage,
            semantic_policy=semantic,
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            wp08s2._overlay_document(overlay_id),
            approved_profiles=approved,
            coverage_policy=coverage,
        )
        matrix = api.SupportMatrixDefinition.from_dict(
            wp08._support_matrix_document(),
            approved_profiles=approved,
            coverage_policy=coverage,
        )
        return api.ProfileMaterializer.materialize(
            base_graph_document={
                "graph_id": graph.graph_id,
                "graph_version": graph.graph_version,
                "graph_digest": graph.digest,
                "node_ids": sorted({*graph.nodes, *profile.required_node_ids}),
                "edge_ids": sorted({*graph.edges, *profile.required_edge_ids}),
            },
            profile=profile,
            overlay=overlay,
            project_config={},
            approved_profiles=approved,
            support_matrix=matrix,
            semantic_policy=semantic,
        )

    @staticmethod
    def attested_artifact(artifact_type: str, snapshot_digest: str):  # noqa: ANN201
        record, _manifest, _contracts, _schemas, context, validation = loaded_golden(artifact_type)
        record["task_id"] = "task-1"
        record["input_refs"][0]["task_id"] = "task-1"
        record["input_refs"][0]["digest"] = snapshot_digest
        record["target_refs"][0]["task_id"] = "task-1"
        validation["expected_task_id"] = "task-1"
        for item in validation["known_inputs"].values():
            item["task_id"] = "task-1"
            item["digest"] = snapshot_digest
        for item in validation["known_targets"].values():
            item["task_id"] = "task-1"
        record["artifact_digest"] = semantic_digest(
            {key: value for key, value in record.items() if key != "artifact_digest"},
            contract_type="urn:gew:contract:artifact-record",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id=ARTIFACT_RECORD_SCHEMA,
        )
        return ArtifactValidator.load(record, context=context, **validation)

    def test_runner_resumes_and_converges_two_nodes_without_background_work(self) -> None:
        schemas, context, graph, budgets = self.stack()
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(objects, budgets, context=context)

            stopped = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=1,
            )
            self.assertEqual(stopped.status, "step_limit")
            event_count = len(repository.replay("task-1"))
            self.assertEqual(len(repository.replay("task-1")), event_count)

            result = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=30,
            )
            self.assertEqual(result.status, "completion_ready")
            view = trusted_show(application, "task-1")
            self.assertEqual(
                {run.node_id: run.status for run in view.snapshot.node_runs.values()},
                {"start": "passed", "finish": "passed"},
            )
            self.assertEqual(view.runner_state["selected_edges"], ["start-to-finish"])
            self.assertEqual(view.snapshot.open_findings, ())
            final_count = len(repository.replay("task-1"))
            self.assertEqual(len(repository.replay("task-1")), final_count)

    def test_durable_review_resume_does_not_call_reviewer_twice(self) -> None:
        schemas, context, graph, budgets = self.stack()
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(objects, budgets, context=context)
            reviewer = CountingPassingReviewer()
            stopped = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), reviewer, max_steps=6,
            )
            self.assertEqual(stopped.status, "step_limit")
            recorded = trusted_show(application, "task-1")
            self.assertEqual(recorded.snapshot.node_runs["node:start:run:1"].status, "reviewing")
            self.assertEqual(recorded.runner_state["review_history"][-1]["verdict"], "PASS")
            self.assertEqual(reviewer.calls, ["start"])

            completed = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), reviewer, max_steps=30,
            )
            self.assertEqual(completed.status, "completion_ready")
            self.assertEqual(reviewer.calls, ["start", "finish"])

    def test_repeated_revise_without_digest_progress_escalates_stably(self) -> None:
        schemas, context, graph, budgets = self.stack(with_budget=True)
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            result = application.create_runner(objects, budgets, context=context).run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                SameDigestRuntime(), PassingValidator(), RevisingReviewer(), max_steps=30,
            )
            self.assertEqual((result.lifecycle, result.status), ("awaiting_human", "stable"))
            view = trusted_show(application, "task-1")
            self.assertEqual(view.snapshot.open_findings, ("finding-start",))
            self.assertEqual(view.snapshot.node_runs["node:start:run:1"].attempt, 2)
            self.assertEqual(len(view.runner_state["review_history"]), 2)

        installed_materialization = self.materialization(graph, "compact-planned")
        for label, mutate in (
            (
                "max-attempts",
                lambda value: value["budgets"][0].__setitem__("max_attempts", 9),
            ),
            (
                "max-revisions",
                lambda value: value["budgets"][0].__setitem__("max_revisions", 9),
            ),
            (
                "max-total-runs",
                lambda value: value["budgets"][0].__setitem__("max_total_runs", 33),
            ),
            (
                "exhausted-route",
                lambda value: value["budgets"][0].__setitem__(
                    "exhausted_route", "blocked",
                ),
            ),
            (
                "registry-id",
                lambda value: value.__setitem__(
                    "registry_id", "urn:gew:loop-budget-registry:substituted:1.0.0",
                ),
            ),
            (
                "registry-digest",
                lambda value: value["budgets"][0].__setitem__("version", "1.0.1"),
            ),
        ):
            candidate = json.loads(
                (ROOT / "config/contracts/loop-budgets-v1.json").read_text(
                    encoding="utf-8",
                )
            )
            mutate(candidate)
            substituted = LoopBudgetRegistry.from_dict(
                candidate,
                schema_registry=graph_schemas(),
                predicates=predicate_registry(),
                error_rules=error_rule_registry(),
                context=work_context(),
            )
            with self.subTest(loop_registry_substitution=label), repository_stack() as (
                _root, _factory, _locks, objects, repository, leases,
            ):
                application = TaskApplication(
                    repository, repository, leases,
                    schema_registry=schemas, context=context,
                )
                self.prepare(application, graph.digest)
                before = repository.replay("task-1")
                channels = len(application._TaskApplication__runner_channels)
                issued: list[object] = []
                with self.assertRaises((ApplicationError, RunnerError, ValueError)):
                    issued.append(application.create_runner(
                        objects,
                        substituted,
                        context=context,
                        materialization=installed_materialization,
                    ))
                self.assertEqual(issued, [])
                self.assertEqual(
                    len(application._TaskApplication__runner_channels), channels,
                )
                self.assertEqual(repository.replay("task-1"), before)

        with repository_stack() as (
            _root, _factory, _locks, objects, repository, leases,
        ):
            application = TaskApplication(
                repository, repository, leases,
                schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(
                objects,
                budgets,
                context=context,
                materialization=installed_materialization,
            )
            before = repository.replay("task-1")
            object.__setattr__(runner, "_budgets", substituted)
            with self.assertRaisesRegex(RunnerError, "materialization|budget|stale"):
                runner.run_until_stable(
                    "task-1", self.runtime("t-substituted"), graph,
                    PassingRuntime(), PassingValidator(), RevisingReviewer(),
                    max_steps=100,
                )
            self.assertEqual(repository.replay("task-1"), before)

        for overlay_id, expected_attempts in (
            ("compact-planned", 4),
            ("emergency", 2),
        ):
            schemas, context, graph, budgets = self.stack(with_budget=True)
            materialization = self.materialization(graph, overlay_id)
            with self.subTest(materialized_budget=overlay_id), repository_stack() as (
                _root, _factory, _locks, objects, repository, leases,
            ):
                application = TaskApplication(
                    repository, repository, leases,
                    schema_registry=schemas, context=context,
                )
                self.prepare(application, graph.digest)
                runner = application.create_runner(
                    objects, budgets, context=context,
                    materialization=materialization,
                )
                result = runner.run_until_stable(
                    "task-1", self.runtime("t-run"), graph,
                    PassingRuntime(), PassingValidator(), RevisingReviewer(),
                    max_steps=100,
                )
                self.assertEqual(
                    (result.lifecycle, result.status), ("awaiting_human", "stable"),
                )
                view = trusted_show(application, "task-1")
                self.assertEqual(
                    view.snapshot.node_runs["node:start:run:1"].attempt,
                    expected_attempts,
                )
                before = repository.replay("task-1")
                recovered = runner.run_until_stable(
                    "task-1", self.runtime("t-recovery"), graph,
                    PassingRuntime(), PassingValidator(), RevisingReviewer(),
                    max_steps=100,
                )
                self.assertEqual(
                    (recovered.lifecycle, recovered.status),
                    ("awaiting_human", "stable"),
                )
                self.assertEqual(repository.replay("task-1"), before)

    def test_revise_then_pass_without_digest_progress_escalates_stably(self) -> None:
        schemas, context, graph, budgets = self.stack(with_budget=True)
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            result = application.create_runner(objects, budgets, context=context).run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                SameDigestRuntime(), PassingValidator(), ReviseThenPassReviewer(), max_steps=30,
            )
            self.assertEqual((result.lifecycle, result.status), ("awaiting_human", "stable"))
            view = trusted_show(application, "task-1")
            self.assertEqual(view.snapshot.open_findings, ("finding-start",))
            self.assertEqual(view.snapshot.node_runs["node:start:run:1"].status, "awaiting_human")
            self.assertEqual(view.runner_state["findings"]["finding-start"]["status"], "open")
            reviews = view.runner_state["review_history"]
            self.assertEqual([item["verdict"] for item in reviews], ["REVISE", "PASS"])
            self.assertEqual(reviews[0]["body_digest"], reviews[1]["body_digest"])

    def test_internal_node_pass_and_task_completion_injection_write_nothing(self) -> None:
        schemas, context, graph, budgets = self.stack()
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.assertFalse(hasattr(application, "commit_internal"))
            self.prepare(application, graph.digest)
            with self.assertRaisesRegex(RunnerError, "created by TaskApplication"):
                ApplicationRunner(application, objects, budgets, context=context)
            runner = application.create_runner(objects, budgets, context=context)
            stopped = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=5,
            )
            self.assertEqual(stopped.status, "step_limit")
            reviewing = trusted_show(application, "task-1")
            run = reviewing.snapshot.node_runs["node:start:run:1"]
            self.assertEqual(run.status, "reviewing")
            forged_runner = copy.deepcopy(dict(reviewing.runner_state))
            output = forged_runner["node_outputs"]["start"]
            output.update(trust="independently_reviewed", verdict="PASS", reviewer_id="reviewer-start")
            forged_runner["review_history"].append({
                "node_id": "start",
                "run_id": run.run_id,
                "attempt": run.attempt,
                "body_digest": output["body_digest"],
                "reviewer_id": "reviewer-start",
                "verdict": "PASS",
                "finding_ids": [],
                "findings": [],
            })
            pass_event = DomainEvent(
                reviewing.snapshot.last_event_seq + 1,
                reviewing.snapshot.task_revision,
                "node.passed",
                {"run_id": run.run_id},
            )
            before = repository.replay("task-1")
            self.assertFalse(hasattr(application, "_issue_runner_transition_authority"))
            self.assertFalse(hasattr(application, "_TaskApplication__issue_transition_authority"))
            channel = runner._ApplicationRunner__transition_channel
            with self.assertRaisesRegex(ApplicationError, "critical review|durable review"):
                channel.commit(
                    "task-1",
                    reviewing.snapshot.snapshot_digest,
                    (pass_event,),
                    forged_runner,
                    self.runtime("t-forged-pass"),
                    operation_id="forged-pass",
                )
            self.assertEqual(repository.replay("task-1"), before)
            with self.assertRaisesRegex(ApplicationError, "authority"):
                application._commit_internal(  # type: ignore[arg-type]
                    object(),
                    "task-1",
                    (pass_event,),
                    forged_runner,
                    self.runtime("t-forged-pass"),
                    operation_id="forged-pass",
                )
            self.assertEqual(repository.replay("task-1"), before)

        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(objects, budgets, context=context)
            result = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=30,
            )
            self.assertEqual(result.status, "completion_ready")
            runner.begin_completion("task-1", self.runtime("t-completing"), graph)
            completing = trusted_show(application, "task-1")
            completion_event = DomainEvent(
                completing.snapshot.last_event_seq + 1,
                completing.snapshot.task_revision,
                "task.completed",
                {},
            )
            before = repository.replay("task-1")
            channel = runner._ApplicationRunner__transition_channel
            with self.assertRaisesRegex(ApplicationError, "critical review or completion"):
                channel.commit(
                    "task-1",
                    completing.snapshot.snapshot_digest,
                    (completion_event,),
                    completing.runner_state,
                    self.runtime("t-forged-completion"),
                    operation_id="forged-completion",
                )
            with self.assertRaisesRegex(ApplicationError, "authority"):
                application._commit_internal(  # type: ignore[arg-type]
                    object(),
                    "task-1",
                    (completion_event,),
                    completing.runner_state,
                    self.runtime("t-forged-completion"),
                    operation_id="forged-completion",
                )
            self.assertEqual(trusted_show(application, "task-1").snapshot.lifecycle, "completing")
            self.assertEqual(repository.replay("task-1"), before)

    def _assert_transition_grant_rejected(self, mutation: str) -> None:
        schemas, context, graph, budgets = self.stack()
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(objects, budgets, context=context)
            runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=5,
            )
            view = trusted_show(application, "task-1")
            run = view.snapshot.node_runs["node:start:run:1"]
            events = (
                DomainEvent(
                    view.snapshot.last_event_seq + 1,
                    view.snapshot.task_revision,
                    "node.awaiting_human",
                    {"run_id": run.run_id},
                ),
                DomainEvent(
                    view.snapshot.last_event_seq + 2,
                    view.snapshot.task_revision + 1,
                    "task.human_decision_required",
                    {},
                ),
            )
            grant: tuple[str, str, str, str, tuple[str, ...]] = (
                "runner",
                "task-1",
                view.snapshot.snapshot_digest,
                "grant-check",
                ("node.awaiting_human", "task.human_decision_required"),
            )
            if mutation == "stale":
                grant = (grant[0], grant[1], "stale-snapshot", grant[3], grant[4])
            elif mutation == "task":
                grant = (grant[0], "task-2", grant[2], grant[3], grant[4])
            elif mutation == "scope":
                grant = ("completion", grant[1], grant[2], grant[3], grant[4])
            elif mutation == "event":
                grant = (grant[0], grant[1], grant[2], grant[3], ("node.blocked",))
            else:
                self.fail(f"unknown grant mutation: {mutation}")
            authority = object.__new__(_TransitionAuthority)
            application._TaskApplication__transition_authorities[authority] = grant
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "authority"):
                application._commit_internal(
                    authority,
                    "task-1",
                    events,
                    view.runner_state,
                    self.runtime("t-grant-check"),
                    operation_id="grant-check",
                )
            self.assertEqual(repository.replay("task-1"), before)

    def test_transition_authority_stale_source_is_zero_write(self) -> None:
        self._assert_transition_grant_rejected("stale")

    def test_transition_authority_wrong_task_is_zero_write(self) -> None:
        self._assert_transition_grant_rejected("task")

    def test_transition_authority_wrong_scope_is_zero_write(self) -> None:
        self._assert_transition_grant_rejected("scope")

    def test_transition_authority_event_type_mismatch_is_zero_write(self) -> None:
        self._assert_transition_grant_rejected("event")

    def test_transition_authority_is_consumed_once(self) -> None:
        schemas, context, graph, budgets = self.stack()
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            runner = application.create_runner(objects, budgets, context=context)
            runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=5,
            )
            view = trusted_show(application, "task-1")
            run = view.snapshot.node_runs["node:start:run:1"]
            events = (
                DomainEvent(
                    view.snapshot.last_event_seq + 1,
                    view.snapshot.task_revision,
                    "node.awaiting_human",
                    {"run_id": run.run_id},
                ),
                DomainEvent(
                    view.snapshot.last_event_seq + 2,
                    view.snapshot.task_revision + 1,
                    "task.human_decision_required",
                    {},
                ),
            )
            authority = object.__new__(_TransitionAuthority)
            application._TaskApplication__transition_authorities[authority] = (
                "runner",
                "task-1",
                view.snapshot.snapshot_digest,
                "one-use",
                ("node.awaiting_human", "task.human_decision_required"),
            )
            application._commit_internal(
                authority,
                "task-1",
                events,
                view.runner_state,
                self.runtime("t-one-use"),
                operation_id="one-use",
            )
            after_first = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "authority"):
                application._commit_internal(
                    authority,
                    "task-1",
                    events,
                    view.runner_state,
                    self.runtime("t-one-use"),
                    operation_id="one-use",
                )
            self.assertEqual(repository.replay("task-1"), after_first)

    def test_routine_finding_closes_after_digest_progress_and_independent_review(self) -> None:
        schemas, context, graph, budgets = self.stack(with_budget=True)
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            result = application.create_runner(objects, budgets, context=context).run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), ReviseThenPassReviewer(), max_steps=30,
            )
            self.assertEqual(result.status, "completion_ready")
            view = trusted_show(application, "task-1")
            self.assertEqual(view.snapshot.open_findings, ())
            self.assertEqual(view.runner_state["findings"]["finding-start"]["status"], "closed")
            reviews = [
                item for item in view.runner_state["review_history"] if item["node_id"] == "start"
            ]
            self.assertEqual([item["verdict"] for item in reviews], ["REVISE", "PASS"])
            self.assertNotEqual(reviews[0]["body_digest"], reviews[1]["body_digest"])

    def test_graph_digest_mismatch_rejects_before_node_execution(self) -> None:
        schemas, context, graph, budgets = self.stack()
        other_candidate = graph_candidate()
        other_candidate["graph_version"] = "1.0.1"
        other = load_graph(complete(other_candidate), schemas=schemas, context=context)
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            with self.assertRaisesRegex(RunnerError, "graph binding"):
                application.create_runner(objects, budgets, context=context).run_until_stable(
                    "task-1", self.runtime("t-run"), other,
                    PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=1,
                )
            self.assertEqual(len(trusted_show(application, "task-1").snapshot.node_runs), 0)

    def test_declared_runtime_failure_selects_fallback_and_unlisted_failure_blocks(self) -> None:
        schemas = graph_schemas()
        context = work_context()
        candidate = graph_candidate()
        candidate["nodes"][0]["failure_routes"] = {"E_RUNTIME": "finish"}
        graph = load_graph(complete(candidate), schemas=schemas, context=context)
        budgets = loop_budgets(schemas=schemas, context=context)
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest)
            result = application.create_runner(objects, budgets, context=context).run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                FallbackRuntime(), PassingValidator(), PassingReviewer(), max_steps=30,
            )
            self.assertEqual(result.status, "completion_ready")
            view = trusted_show(application, "task-1")
            self.assertEqual(
                {run.node_id: run.status for run in view.snapshot.node_runs.values()},
                {"start": "blocked", "finish": "passed"},
            )
            self.assertEqual(view.runner_state["failure_routes"], {"start": "finish"})

        plain_graph = load_graph(
            complete(graph_candidate()), schemas=schemas, context=context,
        )
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, plain_graph.digest)
            result = application.create_runner(objects, budgets, context=context).run_until_stable(
                "task-1", self.runtime("t-run"), plain_graph,
                FallbackRuntime(), PassingValidator(), PassingReviewer(), max_steps=10,
            )
            self.assertEqual((result.lifecycle, result.status), ("blocked", "stable"))

    def test_completion_gate_rejects_each_missing_binding_before_completion(self) -> None:
        schemas, context, graph, budgets = self.stack()
        candidate_template = loaded_golden("candidate-review")[0]
        baseline_digest = candidate_template["baseline_digests"]["intent"]
        with repository_stack() as (_root, _factory, _locks, objects, repository, leases):
            application = TaskApplication(
                repository, repository, leases, schema_registry=schemas, context=context,
            )
            self.prepare(application, graph.digest, baseline_digest=baseline_digest)
            runner = application.create_runner(objects, budgets, context=context)
            result = runner.run_until_stable(
                "task-1", self.runtime("t-run"), graph,
                PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=30,
            )
            self.assertEqual(result.status, "completion_ready")
            runner.begin_completion("task-1", self.runtime("t-completing"), graph)
            snapshot = trusted_show(application, "task-1").snapshot
            candidate_record = self.attested_artifact("candidate-review", snapshot.snapshot_digest)
            completion_record = self.attested_artifact("completion-record", snapshot.snapshot_digest)
            evidence = {
                "task_id": "task-1",
                "snapshot_digest": snapshot.snapshot_digest,
                "graph_digest": graph.digest,
                "project_scope_digest": self.scope("frozen")["digest"],
                "baseline_digests": [baseline_digest],
                "authority_refs": ["authority-1"],
                "required_node_ids": ["finish"],
                "passed_node_ids": ["finish", "start"],
                "must_requirement_ids": ["FR-01"],
                "traced_requirement_ids": ["FR-01"],
                "required_gate_ids": ["tests"],
                "passed_gate_ids": ["tests"],
                "candidate_review": {
                    "artifact_id": candidate_record.artifact_id,
                    "artifact_digest": candidate_record.artifact_digest,
                    "verdict": "PASS",
                    "author_id": candidate_record.body["author_id"],
                    "reviewer_id": candidate_record.body["reviewer_id"],
                    "trust": "independently-reviewed",
                },
                "required_external_action_ids": [],
                "verified_external_action_ids": [],
                "target_binding_ids": [],
                "matched_target_binding_ids": [],
                "open_blocking_finding_ids": [],
                "unknown_side_effect_refs": [],
                "live_node_lease_ids": [],
                "live_tool_lease_ids": [],
                "evidence_task_id": "task-1",
                "evidence_snapshot_digest": snapshot.snapshot_digest,
                "evidence_baseline_digests": [baseline_digest],
                "completion_record": {
                    "artifact_id": completion_record.artifact_id,
                    "artifact_digest": completion_record.artifact_digest,
                    "status": "accepted_for_next_node",
                    "snapshot_digest": snapshot.snapshot_digest,
                },
            }
            gate = CompletionGate(context=context)
            self.assertTrue(gate.evaluate(
                snapshot,
                graph,
                evidence,
                candidate_review_record=candidate_record,
                completion_record=completion_record,
            ).passed)

            mutations = {
                "snapshot": lambda value: value.update(snapshot_digest="stale"),
                "nodes": lambda value: value.update(passed_node_ids=["finish"]),
                "baseline": lambda value: value.update(baseline_digests=[]),
                "authority": lambda value: value.update(authority_refs=[]),
                "scope": lambda value: value.update(project_scope_digest="stale"),
                "requirements": lambda value: value.update(traced_requirement_ids=[]),
                "gates": lambda value: value.update(passed_gate_ids=[]),
                "review": lambda value: value["candidate_review"].update(verdict="REVISE"),
                "actions": lambda value: value.update(required_external_action_ids=["action-1"]),
                "targets": lambda value: value.update(target_binding_ids=["target-1"]),
                "findings": lambda value: value.update(open_blocking_finding_ids=["finding-1"]),
                "evidence": lambda value: value.update(evidence_task_id="task-2"),
                "record": lambda value: value["completion_record"].update(status="draft"),
            }
            before = repository.replay("task-1")
            for name, mutate in mutations.items():
                changed = copy.deepcopy(evidence)
                mutate(changed)
                with self.subTest(name=name):
                    self.assertFalse(gate.complete(
                        application, "task-1", self.runtime("t-gate"), graph, changed,
                        candidate_review_record=candidate_record,
                        completion_record=completion_record,
                    ).passed)
            self.assertEqual(repository.replay("task-1"), before)

            decision = gate.complete(
                application, "task-1", self.runtime("t-gate"), graph, evidence,
                candidate_review_record=candidate_record,
                completion_record=completion_record,
            )
            self.assertTrue(decision.passed)
            completed = trusted_show(application, "task-1").snapshot
            self.assertEqual(completed.lifecycle, "completed")
            self.assertEqual(completed.authorities, ())


if __name__ == "__main__":
    unittest.main()
