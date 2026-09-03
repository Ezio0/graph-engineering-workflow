from __future__ import annotations

import copy
import sys
import unittest

from tests.integration.test_wp04_application import (
    ROOT,
    SCHEMAS,
    WORK,
    TaskApplicationIntegrationTests,
)
from tests.unit.test_wp06_project_scope import load, scope_document


for responsibility in ("core", "storage", "application"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.application.tasks import (  # noqa: E402
    ApplicationError,
    CanonicalGitIdentityResolver,
    RepositoryIdentityObservation,
    TaskApplication,
    _TransitionAuthority,
)
from graph_engineering.core.actions import PreparedAction  # noqa: E402
from graph_engineering.core.graph.state import DomainEvent, TaskCommand  # noqa: E402
from graph_engineering.core.project import ProjectScope  # noqa: E402
from graph_engineering.storage.codec import (  # noqa: E402
    canonical_json,
    object_digest,
    semantic_record_digest,
)
from graph_engineering.storage.errors import RepositoryIntegrityError  # noqa: E402
from tests.contract.test_wp02_graph import (  # noqa: E402
    complete,
    graph_candidate,
    graph_schemas,
    load_graph,
    work_context,
)
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.application_queries import trusted_show  # noqa: E402


class WP06ProjectScopeRepositoryTests(TaskApplicationIntegrationTests):
    @staticmethod
    def _ref(scope: ProjectScope, status: str) -> dict[str, object]:
        return {
            "scope_id": scope.scope_id,
            "version": scope.version,
            "digest": scope.scope_digest,
            "status": status,
        }

    def _created(
        self, repository, leases, *, resolver=None, schemas=SCHEMAS, context=WORK,
    ) -> TaskApplication:
        application = TaskApplication(
            repository, repository, leases, schema_registry=schemas, context=context,
            project_resolver=resolver,
        )
        application.execute(
            "task-1", TaskCommand("create", 0, {"identity": self.identity()}), self.runtime("t-1"),
        )
        return application

    @staticmethod
    def _succeeded_realization_action(
        factory,
        scope: ProjectScope,
        *,
        action_id="action-realize-repo-new",
        target_id="planned-parent-name",
        resource_id="repository:repo-new",
        state="reconciled",
    ) -> None:
        payload = {"binding_id": "repo-new", "planned_target_id": target_id}
        value: dict[str, object] = {
            "schema_version": "1.0.0", "action_id": action_id,
            "task_id": "task-1", "action_kind": "initialize-project", "target_id": target_id,
            "target_digest": scope.scope_digest, "resources": [resource_id],
            "payload": payload, "payload_digest": PreparedAction.payload_digest_for(payload, WORK),
            "precondition": {"planned_target_id": target_id},
            "expected_postcondition": {"repository_state": "initialized"},
            "idempotency_class": "non-idempotent", "idempotency_key": action_id,
            "verification_plan": {"kind": "fresh-git-identity"},
            "rollback_plan": {"kind": "remove-unpublished-project"},
            "required_capabilities": ["git-identity-resolver"],
            "baseline_digest": scope.discovery_digest,
            "snapshot_digest": "sha256-jcs-v1:" + "5" * 64,
        }
        value["prepared_action_digest"] = PreparedAction.digest_document(value, WORK)
        raw_digest = object_digest(b"realized")
        receipt = {
            "action_id": value["action_id"], "task_id": "task-1", "claim_id": "claim-realize",
            "started_event_digest": "sha256-jcs-v1:" + "6" * 64,
            "prepared_action_digest": value["prepared_action_digest"],
            "authority_digest": "sha256-jcs-v1:" + "7" * 64,
            "payload_digest": value["payload_digest"], "target_id": target_id,
            "fencing_token": 1, "result": "succeeded",
            "raw_result_digest": "sha256-jcs-v1:" + "8" * 64,
            "raw_receipt_object_digest": raw_digest,
        }
        receipt["receipt_digest"] = semantic_record_digest({
            "contract": "action-receipt-v1", "value": receipt,
        })
        reconciliation = None if state != "reconciled" else {
            "target_id": target_id,
            "target_digest": scope.scope_digest,
            "resource_id": resource_id,
            "fresh": True,
            "observation_revision": 1,
            "state": {"repository_state": "initialized"},
        }
        with factory._for_maintenance().open("migration") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                    "prepared_json,prepared_digest,receipt_json,reconciliation_json) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        value["action_id"], "task-1", state, 1, value["idempotency_key"],
                        canonical_json(value), value["prepared_action_digest"], canonical_json(receipt),
                        None if reconciliation is None else canonical_json(reconciliation),
                    ),
                )

    def _approve(
        self, application: TaskApplication, scope: ProjectScope, *, graph=None,
    ) -> None:
        application.execute_scope(
            "task-1",
            TaskCommand("bind_project_scope", 1, {
                "project_scope_ref": self._ref(scope, "drafted"),
            }),
            scope,
            self.runtime("t-2"),
        )
        application.execute(
            "task-1",
            TaskCommand("request_prd_approval", 2, {
                "prd_candidate_ref": "artifact:prd-v1",
            }),
            self.runtime("t-3"),
        )
        approval = self.approval()
        approval["project_scope_ref"] = self._ref(scope, "frozen")
        if graph is not None:
            approval["graph_ref"].update({
                "graph_id": graph.graph_id,
                "graph_version": graph.graph_version,
                "graph_digest": graph.digest,
            })
        application.execute(
            "task-1", TaskCommand("approve_prd", 3, approval), self.runtime("t-4"),
        )

    @staticmethod
    def _scope_dependency_graph(*, tagged_nodes: tuple[str, ...] = ("implementation",)):
        candidate = graph_candidate()
        template = candidate["nodes"][0]
        assert isinstance(template, dict)
        candidate["nodes"] = [
            {
                **copy.deepcopy(template), "node_id": node_id,
                "entrypoint": node_id == "start", "completion_eligible": node_id == "finish",
                "invalidation_tags": ["target-third"] if node_id in tagged_nodes else [node_id],
            }
            for node_id in ("start", "implementation", "verification", "unrelated", "finish")
        ]
        edge_template = candidate["edges"][0]
        assert isinstance(edge_template, dict)
        candidate["edges"] = [
            {
                **copy.deepcopy(edge_template), "edge_id": f"{source}-to-{target}",
                "from_node": source, "to_node": target,
                "route_priority": priority,
            }
            for priority, (source, target) in enumerate((
                ("start", "implementation"),
                ("implementation", "verification"),
                ("verification", "finish"),
                ("start", "unrelated"),
                ("unrelated", "finish"),
            ), start=1)
        ]
        schemas = graph_schemas()
        context = work_context()
        return schemas, context, load_graph(complete(candidate), schemas=schemas, context=context)

    def _schedule_ready_run(
        self, application: TaskApplication, *, run_id: str, node_id: str,
    ) -> None:
        view = trusted_show(application, "task-1")
        events = (
            DomainEvent(
                view.snapshot.last_event_seq + 1, view.snapshot.task_revision,
                "node.run_created", {"run_id": run_id, "node_id": node_id},
            ),
            DomainEvent(
                view.snapshot.last_event_seq + 2, view.snapshot.task_revision + 1,
                "node.ready", {"run_id": run_id},
            ),
        )
        authority = object.__new__(_TransitionAuthority)
        operation_id = f"schedule:{run_id}"
        application._TaskApplication__transition_authorities[authority] = (  # type: ignore[attr-defined]
            "runner", "task-1", view.snapshot.snapshot_digest,
            operation_id, ("node.run_created", "node.ready"),
        )
        application._commit_internal(
            authority, "task-1", events, view.runner_state,
            self.runtime(operation_id), operation_id=operation_id,
        )

    def test_gew_lif_013_scope_draft_and_approval_are_exact_durable_transitions(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = self._created(repository, leases)
            scope = load(scope_document())
            application.execute_scope(
                "task-1",
                TaskCommand("bind_project_scope", 1, {
                    "project_scope_ref": self._ref(scope, "drafted"),
                }),
                scope,
                self.runtime("t-2"),
            )
            drafted = repository.project_scope_state("task-1")
            self.assertEqual(
                (drafted["scope_digest"], drafted["status"], drafted["source"]),
                (scope.scope_digest, "drafted", scope.to_dict()),
            )
            application.execute(
                "task-1",
                TaskCommand("request_prd_approval", 2, {
                    "prd_candidate_ref": "artifact:prd-v1",
                }),
                self.runtime("t-3"),
            )
            approval = self.approval()
            approval["project_scope_ref"] = self._ref(scope, "frozen")
            receipt = application.execute(
                "task-1", TaskCommand("approve_prd", 3, approval), self.runtime("t-4"),
            )
            frozen = repository.project_scope_state("task-1")
            self.assertEqual(frozen["status"], "frozen")
            self.assertEqual(frozen["approved_transaction_id"], receipt.request_id)
            self.assertEqual(frozen["approved_event_digest"], repository.replay("task-1")[-2]["event_digest"])

    def test_gew_lif_014_refs_only_or_wrong_scope_binding_cannot_mutate(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = self._created(repository, leases)
            scope = load(scope_document())
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "ProjectScope"):
                application.execute(
                    "task-1", TaskCommand("bind_project_scope", 1, {
                        "project_scope_ref": self._ref(scope, "drafted"),
                    }), self.runtime("t-2"),
                )
            wrong = self._ref(scope, "drafted")
            wrong["digest"] = "sha256-jcs-v1:" + "0" * 64
            with self.assertRaisesRegex(ApplicationError, "ProjectScope"):
                application.execute_scope(
                    "task-1", TaskCommand("bind_project_scope", 1, {
                        "project_scope_ref": wrong,
                    }), scope, self.runtime("t-2"),
                )
            self.assertEqual(repository.replay("task-1"), before)
            with self.assertRaises(RepositoryIntegrityError):
                repository.project_scope_state("task-1")

    def test_gew_lif_015_rebase_invalidates_exact_targets_and_expands_authority(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            schemas, context, graph = self._scope_dependency_graph()
            application = self._created(
                repository, leases, schemas=schemas, context=context,
            )
            initial = load(scope_document())
            self._approve(application, initial, graph=graph)
            application.execute(
                "task-1", TaskCommand("run", 5, {
                    "compatibility_evidence_ref": "evidence:compatibility-v1",
                    "lease_plan_ref": "lease-plan:none-v1",
                }), self.runtime("t-run"),
            )
            implementation_run = "node:implementation:run:1"
            verification_run = "node:verification:run:1"
            unrelated_run = "node:unrelated:run:1"
            for run_id, node_id in (
                (implementation_run, "implementation"),
                (verification_run, "verification"),
                (unrelated_run, "unrelated"),
            ):
                self._schedule_ready_run(application, run_id=run_id, node_id=node_id)
            application.execute(
                "task-1", TaskCommand("pause", 12, {}), self.runtime("t-pause"),
            )
            candidate_document = copy.deepcopy(scope_document())
            candidate_document["version"] = 2
            candidate_document["target_bindings"].append({
                "target_id": "target-third", "acceptance_id": "acceptance-third",
                "repository_ids": ["repo-existing"], "service_ids": [], "environment_ids": [],
                "resource_ids": ["resource-third"], "required_final_state": "present",
                "verification_contract_ref": "verify-third",
            })
            candidate_document["scope_digest"] = ProjectScope.digest_document(candidate_document)
            candidate = load(candidate_document)
            proposed = application.propose_scope_change(
                "task-1", 13, candidate, graph, self.runtime("t-5"),
            )
            self.assertEqual(proposed.event_types, (
                "project.scope_change_proposed", "task.downstream_invalidated",
            ))
            proposed_events = repository.replay("task-1")[-2:]
            self.assertEqual(
                proposed_events[-1]["payload"]["run_ids"],
                [implementation_run, verification_run],
            )
            view = trusted_show(application, "task-1")
            self.assertEqual(view.snapshot.node_runs[implementation_run].status, "invalidated")
            self.assertEqual(view.snapshot.node_runs[verification_run].status, "invalidated")
            self.assertEqual(view.snapshot.node_runs[unrelated_run].status, "ready")
            self.assertEqual(
                repository.project_scope_state("task-1")["change"]["invalidated_target_ids"],
                ["target-third"],
            )
            dependency = repository.project_scope_state("task-1")["change"]["run_dependencies"][0]
            self.assertEqual(dependency["root_node_id"], "implementation")
            self.assertEqual(
                dependency["downstream_node_ids"],
                ["finish", "implementation", "verification"],
            )
            approval = self.approval()
            approval["project_scope_ref"] = self._ref(candidate, "frozen")
            approval["graph_ref"]["graph_digest"] = graph.digest
            with self.assertRaisesRegex(ApplicationError, "authority expansion"):
                application.execute(
                    "task-1", TaskCommand("approve_prd", 15, approval), self.runtime("t-6"),
                )
            envelope_ref = "authority:scope-expanded-v2"
            expansion = {
                "schema_version": "1.0",
                "authority_id": envelope_ref,
                "task_id": "task-1",
                "owner_id": "owner-1",
                "candidate_scope_digest": candidate.scope_digest,
                "owner_decision_ref": approval["owner_decision_ref"],
                "authorized_resource_ids": ["resource-third"],
                "authorized_operation_classes": [],
                "status": "active",
            }
            expansion["authority_digest"] = semantic_record_digest({
                "contract": "project-scope-authority-envelope-v1", "value": expansion,
            })
            approval["authority_refs"] = ("authority-1", envelope_ref)
            approval["authority_expansion"] = expansion
            substituted = copy.deepcopy(approval)
            substituted["authority_expansion"]["authorized_resource_ids"] = ["resource-substituted"]
            substituted["authority_expansion"]["authority_digest"] = semantic_record_digest({
                "contract": "project-scope-authority-envelope-v1",
                "value": {
                    key: value for key, value in substituted["authority_expansion"].items()
                    if key != "authority_digest"
                },
            })
            before_rebase = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "authority expansion"):
                application.execute(
                    "task-1", TaskCommand("approve_prd", 15, substituted),
                    self.runtime("t-substituted"),
                )
            self.assertEqual(repository.replay("task-1"), before_rebase)
            receipt = application.execute(
                "task-1", TaskCommand("approve_prd", 15, approval), self.runtime("t-7"),
            )
            self.assertEqual(receipt.event_types, ("project.scope_rebased", "task.prd_reapproved"))
            self.assertEqual(repository.project_scope_state("task-1")["scope_digest"], candidate.scope_digest)

    def test_scope_dependency_mapping_fails_closed(self) -> None:
        candidate_document = copy.deepcopy(scope_document())
        candidate_document["version"] = 2
        candidate_document["target_bindings"].append({
            "target_id": "target-third", "acceptance_id": "acceptance-third",
            "repository_ids": ["repo-existing"], "service_ids": [], "environment_ids": [],
            "resource_ids": ["resource-third"], "required_final_state": "present",
            "verification_contract_ref": "verify-third",
        })
        candidate_document["scope_digest"] = ProjectScope.digest_document(candidate_document)
        candidate_scope = load(candidate_document)
        for label, tagged_nodes in (
            ("missing", ()),
            ("ambiguous", ("implementation", "verification")),
        ):
            with self.subTest(label=label), repository_stack() as (
                _root, _factory, _locks, _objects, repository, leases,
            ):
                schemas, context, graph = self._scope_dependency_graph(tagged_nodes=tagged_nodes)
                application = self._created(
                    repository, leases, schemas=schemas, context=context,
                )
                self._approve(application, load(scope_document()), graph=graph)
                application.execute(
                    "task-1", TaskCommand("run", 5, {
                        "compatibility_evidence_ref": "evidence:compatibility-v1",
                        "lease_plan_ref": "lease-plan:none-v1",
                    }), self.runtime(f"t-run-{label}"),
                )
                application.execute(
                    "task-1", TaskCommand("pause", 6, {}), self.runtime(f"t-pause-{label}"),
                )
                before = repository.replay("task-1")
                with self.assertRaisesRegex(ApplicationError, "dependency"):
                    application.propose_scope_change(
                        "task-1", 7, candidate_scope, graph, self.runtime(f"t-propose-{label}"),
                    )
                self.assertEqual(repository.replay("task-1"), before)

        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            schemas, context, graph = self._scope_dependency_graph()
            application = self._created(repository, leases, schemas=schemas, context=context)
            self._approve(application, load(scope_document()), graph=graph)
            application.execute(
                "task-1", TaskCommand("run", 5, {
                    "compatibility_evidence_ref": "evidence:compatibility-v1",
                    "lease_plan_ref": "lease-plan:none-v1",
                }), self.runtime("t-run-stale"),
            )
            self._schedule_ready_run(
                application, run_id="node:retired:run:1", node_id="retired-node",
            )
            application.execute(
                "task-1", TaskCommand("pause", 8, {}), self.runtime("t-pause-stale"),
            )
            before = repository.replay("task-1")
            with self.assertRaisesRegex(ApplicationError, "dependency"):
                application.propose_scope_change(
                    "task-1", 9, candidate_scope, graph, self.runtime("t-propose-stale"),
                )
            self.assertEqual(repository.replay("task-1"), before)

            stale_schemas, stale_context, stale_graph = self._scope_dependency_graph(
                tagged_nodes=("verification",),
            )
            with self.assertRaisesRegex(ApplicationError, "graph"):
                application.propose_scope_change(
                    "task-1", 9, candidate_scope, stale_graph,
                    self.runtime("t-propose-wrong-graph"),
                )
            self.assertEqual(repository.replay("task-1"), before)
            del stale_schemas, stale_context

        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            schemas, context, graph = self._scope_dependency_graph()
            application = self._created(repository, leases, schemas=schemas, context=context)
            initial = load(scope_document())
            self._approve(application, initial, graph=graph)
            application.execute(
                "task-1", TaskCommand("run", 5, {
                    "compatibility_evidence_ref": "evidence:compatibility-v1",
                    "lease_plan_ref": "lease-plan:none-v1",
                }), self.runtime("t-run-substitution"),
            )
            for run_id, node_id in (
                ("node:implementation:run:substitution", "implementation"),
                ("node:verification:run:substitution", "verification"),
            ):
                self._schedule_ready_run(application, run_id=run_id, node_id=node_id)
            application.execute(
                "task-1", TaskCommand("pause", 10, {}),
                self.runtime("t-pause-substitution"),
            )
            exact_change = repository.project_scope_change("task-1", candidate_scope, graph)
            original_classifier = repository.project_scope_change
            for label in ("substituted-run-set", "malformed-dependency"):
                tampered = copy.deepcopy(exact_change)
                if label == "substituted-run-set":
                    tampered["invalidated_run_ids"] = []
                    for dependency in tampered["run_dependencies"]:
                        dependency["run_ids"] = []
                else:
                    del tampered["run_dependencies"][0]["edge_ids"]
                tampered.pop("change_digest")
                tampered["change_digest"] = semantic_record_digest({
                    "contract": "project-scope-change-v1",
                    "current_scope_digest": initial.scope_digest,
                    "candidate_scope_digest": candidate_scope.scope_digest,
                    "change": tampered,
                })
                repository.project_scope_change = (  # type: ignore[method-assign]
                    lambda _task_id, _candidate, _graph, value=tampered: value
                )
                before = repository.replay("task-1")
                with self.subTest(label=label), self.assertRaisesRegex(
                    RepositoryIntegrityError, "classification",
                ):
                    application.propose_scope_change(
                        "task-1", 11, candidate_scope, graph,
                        self.runtime(f"t-propose-{label}"),
                    )
                self.assertEqual(repository.replay("task-1"), before)
            repository.project_scope_change = original_classifier  # type: ignore[method-assign]

    def test_gew_lif_016_realization_and_restart_identity_checks_fail_closed(self) -> None:
        with repository_stack() as (_root, factory, _locks, _objects, repository, leases):
            observed = {"identity": "git-common-new-worktree-new"}
            resolver = CanonicalGitIdentityResolver("resolver-git-v1", lambda _locator, boundary: {
                "actual_git_identity": observed["identity"],
                "observed_path_boundary": boundary,
                "observed_at": "2026-08-14T00:00:00Z",
            })
            application = self._created(repository, leases, resolver=resolver)
            scope = load(scope_document())
            self._approve(application, scope)
            wrong_boundary = CanonicalGitIdentityResolver("resolver-wrong-boundary", lambda _locator, _boundary: {
                "actual_git_identity": observed["identity"],
                "observed_path_boundary": "other-boundary",
                "observed_at": "2026-08-14T00:00:00Z",
            })
            with self.assertRaisesRegex(ApplicationError, "path boundary"):
                wrong_boundary.observe(scope, "repo-new")
            self._succeeded_realization_action(factory, scope, target_id="wrong-planned-target")
            before = repository.replay("task-1")
            observation = resolver.observe(scope, "repo-new")
            forged = object.__new__(RepositoryIdentityObservation)
            for name, value in observation.to_dict().items():
                object.__setattr__(forged, name, value)
            object.__setattr__(forged, "observation_digest", "sha256-jcs-v1:" + "9" * 64)
            with self.assertRaisesRegex(ApplicationError, "not issued"):
                application.realize_repository(
                    "task-1", forged, "action-realize-repo-new", self.runtime("t-forged"),
                )
            with self.assertRaisesRegex(ApplicationError, "action target/resource"):
                application.realize_repository(
                    "task-1", observation, "action-realize-repo-new", self.runtime("t-5"),
                )
            self.assertEqual(repository.replay("task-1"), before)
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM action_journal WHERE action_id=?", ("action-realize-repo-new",))
            self._succeeded_realization_action(
                factory, scope, action_id="action-wrong-resource", resource_id="repository:other",
            )
            with self.assertRaisesRegex(ApplicationError, "action target/resource"):
                application.realize_repository(
                    "task-1", observation, "action-wrong-resource", self.runtime("t-resource"),
                )
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM action_journal WHERE action_id=?", ("action-wrong-resource",))
            self._succeeded_realization_action(factory, scope, state="succeeded")
            with self.assertRaisesRegex(ApplicationError, "action/receipt"):
                application.realize_repository(
                    "task-1", observation, "action-realize-repo-new", self.runtime("t-unreconciled"),
                )
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "DELETE FROM action_journal WHERE action_id=?", ("action-realize-repo-new",),
                    )
            self._succeeded_realization_action(factory, scope)
            with self.assertRaises(TypeError):
                RepositoryIdentityObservation()
            receipt = application.realize_repository(
                "task-1", observation, "action-realize-repo-new", self.runtime("t-6"),
            )
            self.assertEqual(receipt.event_types, ("project.repository_realized",))
            repository.require_project_realizations(
                "task-1", {"repo-new": "git-common-new-worktree-new"},
            )
            with self.assertRaises(RepositoryIntegrityError):
                repository.require_project_realizations(
                    "task-1", {"repo-new": "git-common-other-worktree-other"},
                )
            observed["identity"] = "git-common-drifted-worktree-drifted"
            with self.assertRaisesRegex(ApplicationError, "fresh Git resolver identity"):
                trusted_show(application, "task-1")
            observed["identity"] = "git-common-new-worktree-new"
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE project_scope_realizations SET actual_git_identity=? "
                        "WHERE task_id=? AND binding_id=?",
                        ("git-common-tampered", "task-1", "repo-new"),
                    )
            with self.assertRaises(RepositoryIntegrityError):
                trusted_show(application, "task-1")

    def test_gew_lif_017_metadata_only_scope_revision_is_durable_without_invalidation(self) -> None:
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = self._created(repository, leases)
            current = load(scope_document())
            self._approve(application, current)
            document = copy.deepcopy(scope_document())
            document["metadata_revision"] = 2
            document["repositories"][0]["locator_ref"] = "locator-existing-equivalent"
            document["environments"][0]["adapter_locator_ref"] = "adapter-equivalent"
            document["scope_digest"] = current.scope_digest
            candidate = load(document)
            before = trusted_show(application, "task-1")
            receipt = application.update_scope_metadata(
                "task-1", before.snapshot.task_revision, candidate, self.runtime("t-metadata"),
            )
            after = trusted_show(application, "task-1")
            state = repository.project_scope_state("task-1")
            self.assertEqual(receipt.event_types, ("project.scope_metadata_updated",))
            self.assertEqual(state["metadata_revision"], 2)
            self.assertEqual(state["scope_digest"], current.scope_digest)
            self.assertEqual(after.snapshot.invalidation_epoch, before.snapshot.invalidation_epoch)
            semantic = copy.deepcopy(document)
            semantic["version"] = 2
            semantic["target_bindings"][0]["required_final_state"] = "different"
            semantic["scope_digest"] = ProjectScope.digest_document(semantic)
            with self.assertRaisesRegex(ApplicationError, "metadata-only"):
                application.update_scope_metadata(
                    "task-1", after.snapshot.task_revision, load(semantic), self.runtime("t-semantic"),
                )


if __name__ == "__main__":
    unittest.main()
