"""WP-08A task/runner integration for exact extension pins (GEW-EXT-024..027)."""

from __future__ import annotations

import copy
import unittest
from contextlib import contextmanager

from graph_engineering.application.tasks import ApplicationError, TaskApplication
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.graph.state import TaskCommand
from graph_engineering.core.security.extensions import ExtensionTrustPolicy
from graph_engineering.storage.errors import RepositoryIntegrityError
from tests.contract.test_wp02_graph import (
    complete,
    graph_candidate,
    graph_schemas,
    load_graph,
    loop_budgets,
    work_context,
)
from tests.integration.test_wp04_runner import PassingReviewer, PassingRuntime, PassingValidator
from tests.integration.test_wp08a_extension_activation import (
    _activate,
    _activation_request,
    _authorization,
    _environment,
    _install,
    _points,
)
from tests.support.runtime import runtime_context
from tests.support.wp08a_extension_bundle import DIGEST, valid_bundle
from tests.support.wp08a_trust import authorize_operations, operations_for_candidate
from tests.unit.test_wp06_project_scope import load as load_project_scope, scope_document


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    return {**body, field: _digest(body, name)}


def _runtime(environment, occurred_at: str = "2026-08-20T01:00:00Z"):
    return runtime_context(
        environment.session.proof.owner_id,
        environment.session.capabilities.runtime_kind,
        environment.session.proof.lineage_id,
        "extension-task-actor",
        occurred_at,
        100,
    )


def _identity(environment, task_id: str) -> dict[str, object]:
    return {
        "task_id": task_id,
        "owner_id": environment.session.proof.owner_id,
        "runtime_kind": environment.session.capabilities.runtime_kind,
        "runtime_lineage_id": environment.session.proof.lineage_id,
    }


def _extension_pin_request(environment, task_id: str, graph_digest: str, activation_digest: str):
    from graph_engineering.core.extension_activation import ExtensionTaskPinRequest

    current = environment.trust.current()
    active = environment.activation.snapshot()
    return ExtensionTaskPinRequest.from_dict(
        _complete(
            {
                "schema_version": "1.0.0",
                "pin_id": f"pin.{task_id}.{active.active_manifest['generation']}",
                "task_id": task_id,
                "installation_id": environment.installation_id,
                "activation_record_digests": [activation_digest],
                "graph_digest": graph_digest,
                "expected_active_generation": active.active_manifest["generation"],
                "expected_active_manifest_digest": active.active_manifest["manifest_digest"],
                "expected_contract_registry_digest": active.data_registry["registry_digest"],
                "expected_capability_profile_digest": (
                    environment.activation.capability_profile_digest
                ),
                "owner_id": environment.session.proof.owner_id,
                "runtime_kind": environment.session.capabilities.runtime_kind,
                "runtime_lineage_id": environment.session.proof.lineage_id,
                "expected_trust_head_digest": current.head.head_digest,
                "expected_trust_policy_digest": current.policy.policy_digest,
                "expected_revocation_high_water": current.policy.revocation_high_water,
                "owner_decision_digest": DIGEST,
                "owner_authority_digest": DIGEST,
                "requested_at": "2026-08-20T01:00:00Z",
            },
            "extension-task-pin-request",
            "request_digest",
        )
    )


def _issue_pin(environment, task_id: str, graph_digest: str, activation_digest: str):
    return environment.management.pin_task(
        environment.session,
        environment.session.proof,
        _extension_pin_request(environment, task_id, graph_digest, activation_digest),
        occurred_at="2026-08-20T01:00:00Z",
        lease_ttl_ns=1,
    )


@contextmanager
def _task_stack(environment, schemas, context):  # type: ignore[no-untyped-def]
    from graph_engineering.storage.extension_activation import ExtensionTaskPinAuthority
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository

    scope = environment.manager.command_scope()
    scope.__enter__()
    bound_factory = environment.factory.bind_command_scope(scope)
    objects = ObjectRepository(bound_factory, environment.locks)
    leases = ResourceLeaseRepository(bound_factory, environment.locks)
    authority = ExtensionTaskPinAuthority.create(environment.activation, scope)
    repository = TaskRepository(
        bound_factory,
        environment.locks,
        objects,
        command_scope=scope,
        extension_pin_authority=authority,
    )
    application = TaskApplication(
        repository,
        repository,
        leases,
        schema_registry=schemas,
        context=context,
    )
    try:
        yield application, repository, objects, leases, authority
    finally:
        objects.close()
        scope.__exit__(None, None, None)


def _create_and_run_ready(
    environment,
    application: TaskApplication,
    task_id: str,
    graph_digest: str,
    pin_digest: str,
) -> None:
    runtime = _runtime(environment)
    application.create_with_extension_pin(
        task_id,
        TaskCommand("create", 0, {"identity": _identity(environment, task_id)}),
        pin_digest,
        runtime,
    )
    project_scope = load_project_scope(scope_document())
    scope_ref = {
        "scope_id": project_scope.scope_id,
        "version": project_scope.version,
        "digest": project_scope.scope_digest,
        "status": "drafted",
    }
    application.execute_scope(
        task_id,
        TaskCommand("bind_project_scope", 1, {"project_scope_ref": scope_ref}),
        project_scope,
        runtime,
    )
    application.execute(
        task_id,
        TaskCommand("request_prd_approval", 2, {"prd_candidate_ref": "artifact:prd-v1"}),
        runtime,
    )
    application.execute(
        task_id,
        TaskCommand(
            "approve_prd",
            3,
            {
                "project_scope_ref": {**scope_ref, "status": "frozen"},
                "owner_decision_ref": "decision:extension-task-approved",
                "baseline_refs": ({
                    "kind": "intent",
                    "version": 1,
                    "digest": "baseline-extension-task",
                    "approved_by": environment.session.proof.owner_id,
                    "approved_at": "2026-08-20T01:00:00Z",
                },),
                "graph_ref": {
                    "graph_id": "test-delivery",
                    "graph_version": "1.0.0",
                    "profile_id": "new-feature",
                    "profile_version": "1.0.0",
                    "risk_path": "full-planned",
                    "graph_digest": graph_digest,
                },
                "authority_refs": ("authority.extension-task",),
            },
        ),
        runtime,
    )
    application.execute(
        task_id,
        TaskCommand(
            "run",
            5,
            {
                "compatibility_evidence_ref": "evidence:extension-compatible",
                "lease_plan_ref": "lease-plan:none-v1",
            },
        ),
        runtime,
    )


class CountingRuntime(PassingRuntime):
    def __init__(self) -> None:
        self.calls = 0

    def execute(self, node, *, run_id, attempt, runtime):  # type: ignore[no-untyped-def]
        self.calls += 1
        return super().execute(
            node, run_id=run_id, attempt=attempt, runtime=runtime
        )


class ExtensionTaskIntegrationTests(unittest.TestCase):
    def _graph(self):  # type: ignore[no-untyped-def]
        schemas = graph_schemas()
        context = work_context()
        graph = load_graph(complete(copy.deepcopy(graph_candidate())), schemas=schemas, context=context)
        return schemas, context, graph, loop_budgets(schemas=schemas, context=context)

    def test_gew_ext_024_create_open_resume_and_graph_ref_pin_survive_restart(self) -> None:
        schemas, context, graph, _budgets = self._graph()
        with _environment(points=_points(("node", "extension.node"))) as environment:
            activation = _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.task.v1"
                ),
            )
            pin = _issue_pin(environment, "task-extension", graph.digest, activation.record_digest)
            active_manifest_digest = environment.activation.snapshot().active_manifest["manifest_digest"]
            with _task_stack(environment, schemas, context) as (application, repository, *_rest):
                _create_and_run_ready(
                    environment, application, "task-extension", graph.digest, pin.record_digest
                )
                application.execute(
                    "task-extension", TaskCommand("pause", 6, {}), _runtime(environment)
                )
                application.execute(
                    "task-extension",
                    TaskCommand(
                        "resume",
                        7,
                        {
                            "resolution_evidence_refs": ("evidence:pause-resolved",),
                            "compatibility_evidence_ref": "evidence:extension-compatible",
                        },
                    ),
                    _runtime(environment),
                )
                state = repository.extension_pin_state("task-extension")
                self.assertEqual(
                    (
                        state["generation"], state["pin_digest"], state["graph_digest"],
                        state["active_manifest_digest"],
                    ),
                    (1, pin.record_digest, graph.digest, active_manifest_digest),
                )
            with _task_stack(environment, schemas, context) as (application, repository, *_rest):
                self.assertEqual(
                    application.runtime_show("task-extension", _runtime(environment)).snapshot.lifecycle,
                    "ready",
                )
                self.assertEqual(repository.extension_pin_state("task-extension")["generation"], 1)

    def test_gew_ext_025_revocation_or_graph_incompatibility_blocks_without_disclosure(self) -> None:
        schemas, context, graph, _budgets = self._graph()
        with _environment(points=_points(("node", "extension.node"))) as environment:
            activation = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.block.v1"),
            )
            pin = _issue_pin(environment, "task-blocked", graph.digest, activation.record_digest)
            with _task_stack(environment, schemas, context) as (application, repository, *_rest):
                application.create_with_extension_pin(
                    "task-blocked",
                    TaskCommand("create", 0, {"identity": _identity(environment, "task-blocked")}),
                    pin.record_digest,
                    _runtime(environment),
                )
                project_scope = load_project_scope(scope_document())
                scope_ref = {
                    "scope_id": project_scope.scope_id,
                    "version": project_scope.version,
                    "digest": project_scope.scope_digest,
                    "status": "drafted",
                }
                application.execute_scope(
                    "task-blocked",
                    TaskCommand("bind_project_scope", 1, {"project_scope_ref": scope_ref}),
                    project_scope,
                    _runtime(environment),
                )
                application.execute(
                    "task-blocked",
                    TaskCommand("request_prd_approval", 2, {"prd_candidate_ref": "artifact:prd-v1"}),
                    _runtime(environment, "2026-08-20T01:01:00Z"),
                )
                before = repository.replay("task-blocked")
                with self.assertRaisesRegex(RepositoryIntegrityError, "unavailable"):
                    application.execute(
                        "task-blocked",
                        TaskCommand("approve_prd", 3, {
                            "project_scope_ref": {**scope_ref, "status": "frozen"},
                            "owner_decision_ref": "decision:wrong-graph",
                            "baseline_refs": ({
                                "kind": "intent", "version": 1,
                                "digest": "baseline-wrong-graph",
                                "approved_by": environment.session.proof.owner_id,
                                "approved_at": "2026-08-20T01:01:00Z",
                            },),
                            "graph_ref": {
                                "graph_id": "test-delivery", "graph_version": "1.0.0",
                                "profile_id": "new-feature", "profile_version": "1.0.0",
                                "risk_path": "full-planned",
                                "graph_digest": "sha256-jcs-v1:" + "f" * 64,
                            },
                            "authority_refs": ("authority.extension-task",),
                        }),
                        _runtime(environment, "2026-08-20T01:02:00Z"),
                    )
                self.assertEqual(repository.replay("task-blocked"), before)

            with environment.factory._for_maintenance().open("doctor") as connection:
                before_row = connection.execute(
                    "SELECT revision,head_digest FROM tasks WHERE task_id='task-blocked'",
                ).fetchone()
            current = environment.trust.current()
            candidate_body = current.policy.to_dict()
            candidate_body.update(
                generation=current.policy.generation + 1,
                previous_policy_digest=current.policy.policy_digest,
                revocation_high_water=current.policy.revocation_high_water + 1,
                revocations=[{
                    "target_kind": "extension",
                    "target_identity_digest": environment.initial_receipt.package_identity_digest,
                    "input_kind": "owner-revocation", "input_digest": DIGEST,
                    "reason_code": "extension.revoked", "local_sequence": 1,
                    "effective_generation": current.policy.generation + 1,
                    "owner_decision_digest": DIGEST,
                }],
            )
            candidate_body.pop("policy_digest")
            candidate = ExtensionTrustPolicy.from_dict(
                _complete(candidate_body, "extension-trust-policy", "policy_digest"),
                previous=current.policy,
            )
            operations = operations_for_candidate(current.policy, candidate)
            environment.trust._commit_operations_issued(
                operations,
                authorization=authorize_operations(
                    _authorization(
                        "transaction.extension.task-revocation", current.head.head_digest,
                    ),
                    operations,
                ),
                runtime=_runtime(environment, "2026-08-20T01:03:00Z"),
            )
            with _task_stack(environment, schemas, context) as (application, _repository, *_rest):
                with self.assertRaisesRegex(RepositoryIntegrityError, "unavailable"):
                    application.runtime_show("task-blocked", _runtime(environment))
            with environment.factory._for_maintenance().open("doctor") as connection:
                after_row = connection.execute(
                    "SELECT revision,head_digest FROM tasks WHERE task_id='task-blocked'",
                ).fetchone()
            self.assertEqual(after_row, before_row)

    def test_gew_ext_026_historical_pin_survives_side_by_side_active_set_change(self) -> None:
        schemas, context, graph, budgets = self._graph()
        with _environment(points=_points(("node", "extension.node"))) as environment:
            first = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.dispatch.v1"),
            )
            pin = _issue_pin(environment, "task-dispatch", graph.digest, first.record_digest)
            with _task_stack(environment, schemas, context) as (application, _repository, *_rest):
                _create_and_run_ready(
                    environment, application, "task-dispatch", graph.digest, pin.record_digest
                )

            second_ingest = _install(
                environment,
                valid_bundle(
                    extension_id="extension.example",
                    extension_version="2.0.0",
                    extension_points=_points(("node", "extension.node.v2")),
                    exported_identities=_points(("node", "extension.node.v2")),
                )[0],
            )
            override = _digest(
                {
                    "schema_version": "1.0.0",
                    "activation_id": "activation.dispatch.v2",
                    "candidate_ingest_record_digest": second_ingest.record_digest,
                    "existing_activation_record_digests": [first.record_digest],
                    "owner_decision_digest": DIGEST,
                },
                "extension-conflict-override",
            )
            _activate(
                environment,
                _activation_request(
                    environment, second_ingest, "activation.dispatch.v2", override
                ),
            )
            runtime = CountingRuntime()
            with _task_stack(environment, schemas, context) as (application, _repository, objects, *_rest):
                runner = application.create_runner(objects, budgets, context=context)
                runner.run_until_stable(
                    "task-dispatch",
                    _runtime(environment),
                    graph,
                    runtime,
                    PassingValidator(),
                    PassingReviewer(),
                    max_steps=10,
                )
                self.assertGreater(runtime.calls, 0)

    def test_gew_ext_027_owner_rebase_advances_task_and_pin_without_mutating_audit(self) -> None:
        schemas, context, graph, _budgets = self._graph()
        with _environment(points=_points(("node", "extension.node"))) as environment:
            first = _activate(
                environment,
                _activation_request(environment, environment.initial_receipt, "activation.rebase.v1"),
            )
            first_pin = _issue_pin(environment, "task-rebase", graph.digest, first.record_digest)
            with _task_stack(environment, schemas, context) as (application, repository, *_rest):
                application.create_with_extension_pin(
                    "task-rebase",
                    TaskCommand("create", 0, {"identity": _identity(environment, "task-rebase")}),
                    first_pin.record_digest,
                    _runtime(environment),
                )
                application.execute(
                    "task-unrelated",
                    TaskCommand("create", 0, {"identity": _identity(environment, "task-unrelated")}),
                    _runtime(environment),
                )
                audit_before = repository.replay("task-rebase")

            second_ingest = _install(
                environment,
                valid_bundle(
                    extension_id="extension.example",
                    extension_version="2.0.0",
                    extension_points=_points(("node", "extension.node.v2")),
                    exported_identities=_points(("node", "extension.node.v2")),
                )[0],
            )
            override = _digest(
                {
                    "schema_version": "1.0.0",
                    "activation_id": "activation.rebase.v2",
                    "candidate_ingest_record_digest": second_ingest.record_digest,
                    "existing_activation_record_digests": [first.record_digest],
                    "owner_decision_digest": DIGEST,
                },
                "extension-conflict-override",
            )
            second = _activate(
                environment,
                _activation_request(environment, second_ingest, "activation.rebase.v2", override),
            )
            second_pin = _issue_pin(
                environment, "task-rebase", graph.digest, second.record_digest
            )
            with _task_stack(environment, schemas, context) as (application, repository, *_rest):
                foreign = runtime_context(
                    "owner-foreign", environment.session.capabilities.runtime_kind,
                    environment.session.proof.lineage_id, "extension-task-actor",
                    "2026-08-20T01:04:00Z", 100,
                )
                with self.assertRaisesRegex(ApplicationError, "owner|lineage"):
                    application.rebase_extension_pin(
                        "task-rebase", 1, second_pin.record_digest, foreign,
                    )
                with environment.factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(
                        connection.execute(
                            "SELECT revision FROM tasks WHERE task_id='task-rebase'",
                        ).fetchone()[0],
                        1,
                    )
                receipt = application.rebase_extension_pin(
                    "task-rebase",
                    1,
                    second_pin.record_digest,
                    _runtime(environment),
                )
                state = repository.extension_pin_state("task-rebase")
                self.assertEqual((receipt.task_revision, state["generation"]), (2, 2))
                replay = repository.replay("task-rebase")
                self.assertEqual(replay[:-1], audit_before)
                self.assertEqual(replay[-1]["event_type"], "task.extension_pin_rebased")
                self.assertEqual(
                    application.runtime_show("task-unrelated", _runtime(environment)).snapshot.lifecycle,
                    "discovering",
                )


if __name__ == "__main__":
    unittest.main()
