from __future__ import annotations

import pathlib
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest import mock

from graph_engineering.application.release_operations import (
    ReleaseOperationsRegistryFactory,
    _semantic,
)
from graph_engineering.core.release_operations import ReleaseOperationsError
from tests.support import wp08_category_execution as category_fixture
from tests.support.wp05_actions import action_stack, authority_document
from tests.support.wp08_release_operations import (
    artifact_bytes,
    release_disclosure_plan,
    release_partial_restore_prepared_document,
    release_prepared_document,
    retarget_security_binding,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]


class WP08ReleaseOperationsIntegrationTests(unittest.TestCase):
    def test_non_release_completion_preserves_existing_fence_behavior(self) -> None:
        from tests.integration.test_wp08_category_execution import WP08CategoryExecutionTests

        _api, application, probe, target = WP08CategoryExecutionTests()._runtime(
            "new-feature", "normal",
        )
        try:
            receipt = application.assess_and_commit(
                category_fixture.candidate_document("new-feature", "normal"),
                observer=target,
            )
            self.assertEqual(receipt.assessment.schema_version, "1.0.0")
            self.assertIsNone(receipt.assessment.release_operations_projection)
            self.assertEqual(len(probe.signature()["object_references"]), 1)
        finally:
            probe.close()
            target.close()

    @contextmanager
    def _live_evidence(self):  # type: ignore[no-untyped-def]
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            session = factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05", fixture_id="release-foundation-v1",
                target_id="target-project", resource_id="target:project",
                baseline_manifest=baseline, authorized_artifacts=(baseline, candidate),
            )
            with session:
                outcome = self._assert_apply(
                    fixture, session, baseline, candidate, factory.artifact_bytes(candidate),
                )
                deployment = factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session, outcome=outcome,
                )
                health = factory.issue_health_observation(
                    session=session, terminal_observation=deployment,
                )
                digest = "sha256-jcs-v1:" + "a" * 64
                arguments = dict(
                    task_id="task-wp05", task_revision=1, snapshot_digest=digest,
                    invalidation_epoch=0,
                    graph_ref_pins={name: digest for name in (
                        "base_graph_digest", "profile_digest", "overlay_digest",
                        "project_config_digest", "support_matrix_digest",
                        "materialization_digest",
                    )},
                    artifact_manifest=candidate, deployment_observation=deployment,
                    health_observation=health, rollback_observation=None,
                    session=session, owner_route="reconciled-effect-verified",
                    column_id="normal",
                    scenario_id="GEW-PSC-RELEASE-OPERATIONS-ARTIFACT-PROVENANCE-P",
                    outcome="artifact-provenance-verified",
                )
                evidence = factory.issue_evidence(**arguments)
                yield fixture, factory, session, outcome, evidence, arguments

    def test_live_evidence_rejects_closed_destroyed_or_changed_target(self) -> None:
        for attack in ("closed", "destroyed", "generation", "artifact"):
            with self.subTest(attack=attack), self._live_evidence() as values:
                _fixture, factory, session, _outcome, evidence, _arguments = values
                self.assertIs(factory.require_current(evidence), evidence)
                mutations = session._root.mutation_count
                if attack == "closed":
                    session.close()
                elif attack == "destroyed":
                    session._root._temporary.cleanup()
                elif attack == "generation":
                    state = session._root.state()
                    session._root._write_state({**state, "generation": state["generation"] + 1})
                else:
                    session._root._durable_write(
                        session._root.names["active_artifact"], b"changed", 0o600,
                    )
                for check in (factory.require_current, factory.projection):
                    with self.assertRaises(ReleaseOperationsError):
                        check(evidence)
                self.assertEqual(session._root.mutation_count, mutations)
                self.assertEqual(session.target.apply_count, 1)

    def test_live_evidence_and_final_issuance_reject_action_authority_drift(self) -> None:
        for attack in ("journal", "claim", "receipt"):
            with self.subTest(attack=attack), self._live_evidence() as values:
                fixture, factory, session, outcome, evidence, arguments = values
                record = fixture.journal.load(outcome.action_id)
                claim = fixture.leases.load_claim(outcome.claim_id)
                if attack == "claim":
                    patch = mock.patch.object(
                        fixture.leases, "load_claim", return_value={**claim, "state": "unresolved"},
                    )
                else:
                    changed = (
                        replace(record, state="unknown") if attack == "journal"
                        else replace(record, receipt={**record.receipt, "receipt_digest": "sha256-jcs-v1:" + "f" * 64})
                    )
                    patch = mock.patch.object(
                        fixture.raw_coordinator._journal, "load", return_value=changed,
                    )
                before = session.tree_digest()
                with patch:
                    for check in (factory.require_current, factory.projection):
                        with self.assertRaises(ReleaseOperationsError):
                            check(evidence)
                    issued_count = len(factory._issued)
                    with self.assertRaises(ReleaseOperationsError):
                        factory.issue_evidence(**arguments)
                    self.assertEqual(len(factory._issued), issued_count)
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 1)

    def test_apply_runs_through_durable_action_coordinator_and_fresh_observer(self) -> None:
        with action_stack() as fixture:
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            baseline_bytes = release_factory.artifact_bytes(baseline)
            candidate_bytes = release_factory.artifact_bytes(candidate)
            self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())
            session = release_factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05",
                fixture_id="release-foundation-v1",
                target_id="target-project",
                resource_id="target:project",
                baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
            )
            with session:
                outcome = self._assert_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                deployment = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                with (
                    mock.patch("socket.socket") as socket_call,
                    mock.patch("socket.getaddrinfo") as dns_call,
                    mock.patch("socket.create_connection") as connect_call,
                    mock.patch("subprocess.Popen") as process_call,
                    mock.patch("subprocess.run") as process_run,
                    mock.patch("urllib.request.urlopen") as url_call,
                    mock.patch("urllib.request.getproxies") as proxy_call,
                ):
                    health = release_factory.issue_health_observation(
                        session=session,
                        terminal_observation=deployment,
                    )
                socket_call.assert_not_called()
                dns_call.assert_not_called()
                connect_call.assert_not_called()
                process_call.assert_not_called()
                process_run.assert_not_called()
                url_call.assert_not_called()
                proxy_call.assert_not_called()
                self.assertEqual(deployment.to_dict()["current_generation"], 1)
                self.assertEqual(health.to_dict()["outcome"], "healthy")

    def test_partial_unknown_uses_same_claim_compensation_and_restores_exact_a(self) -> None:
        with action_stack() as fixture:
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            baseline_bytes = release_factory.artifact_bytes(baseline)
            candidate_bytes = release_factory.artifact_bytes(candidate)
            self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())

            def fault(step: str) -> None:
                if step == "after-stage-durable":
                    raise TimeoutError("configured partial cut")

            session = release_factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05",
                fixture_id="release-foundation-v1",
                target_id="target-project",
                resource_id="target:project",
                baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
                fault_hook=fault,
            )
            with session:
                retarget_security_binding(
                    fixture, target_digest=session.target.target_digest,
                )
                original_document = release_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    candidate=candidate,
                    candidate_bytes=candidate_bytes,
                )
                original = fixture.coordinator.prepare(original_document)
                fixture.coordinator.authorize(authority_document(
                    original, context=fixture.context,
                ))
                unknown = fixture.coordinator.execute(
                    original.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=fixture.action_lease,
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, original),
                )
                self.assertEqual((unknown.state, unknown.route), (
                    "unknown", "manual-reconciliation",
                ))
                partial = session.observer.observe()["state"]
                self.assertEqual(partial, {
                    "generation": 0,
                    "active_artifact_digest": baseline.manifest_digest,
                    "staged_artifact_digest": candidate.manifest_digest,
                })
                deployment = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=unknown,
                )
                partial_health = release_factory.issue_health_observation(
                    session=session,
                    terminal_observation=deployment,
                )
                self.assertEqual(partial_health.to_dict()["outcome"], "unhealthy")
                digest = "sha256-jcs-v1:" + "a" * 64
                graph_pins = {
                    field: digest
                    for field in (
                        "base_graph_digest", "profile_digest", "overlay_digest",
                        "project_config_digest", "support_matrix_digest",
                        "materialization_digest",
                    )
                }
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "scenario/health/rollback",
                ):
                    release_factory.issue_evidence(
                        task_id="task-wp05",
                        task_revision=1,
                        snapshot_digest=digest,
                        invalidation_epoch=0,
                        graph_ref_pins=graph_pins,
                        artifact_manifest=candidate,
                        deployment_observation=deployment,
                        health_observation=partial_health,
                        rollback_observation=None,
                        session=session,
                        owner_route="release-operations-owner",
                        column_id="normal",
                        scenario_id=(
                            "GEW-PSC-RELEASE-OPERATIONS-PARTIAL-DEPLOY-P"
                        ),
                        outcome="partial-deploy-restored",
                    )
                compensation_document = release_partial_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=unknown.claim_id,
                    original_receipt_digest=str(unknown.receipt_digest),
                )
                compensation = fixture.coordinator.prepare(compensation_document)
                fixture.coordinator.authorize(authority_document(
                    compensation, context=fixture.context,
                ))
                restored = fixture.coordinator.compensate_unknown(
                    original.action_id,
                    compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, compensation),
                )
                self.assertEqual((restored.state, restored.route), (
                    "compensated", "compensation-reconciled",
                ))
                rollback = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=restored,
                )
                self.assertEqual(
                    rollback.to_dict()["action_id"], compensation.action_id,
                )
                self.assertEqual(session.observer.observe()["state"], {
                    "generation": 0,
                    "active_artifact_digest": baseline.manifest_digest,
                    "staged_artifact_digest": None,
                })
                self.assertEqual(session.target.apply_count, 1)
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                restored_health = release_factory.issue_health_observation(
                    session=session,
                    terminal_observation=rollback,
                )
                self.assertEqual(restored_health.to_dict()["outcome"], "healthy")
                evidence = release_factory.issue_evidence(
                    task_id="task-wp05",
                    task_revision=1,
                    snapshot_digest=digest,
                    invalidation_epoch=0,
                    graph_ref_pins=graph_pins,
                    artifact_manifest=candidate,
                    deployment_observation=deployment,
                    health_observation=restored_health,
                    rollback_observation=rollback,
                    session=session,
                    owner_route="release-operations-owner",
                    column_id="normal",
                    scenario_id="GEW-PSC-RELEASE-OPERATIONS-PARTIAL-DEPLOY-P",
                    outcome="partial-deploy-restored",
                )
                self.assertEqual(
                    release_factory.require_current(evidence), evidence,
                )

    def _assert_apply(
        self, fixture, session, baseline, candidate, candidate_bytes,
    ):  # type: ignore[no-untyped-def]
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        document = release_prepared_document(
            fixture,
            target_digest=session.target.target_digest,
            baseline=baseline,
            candidate=candidate,
            candidate_bytes=candidate_bytes,
        )
        prepared = fixture.coordinator.prepare(document)
        fixture.coordinator.authorize(authority_document(
            prepared, context=fixture.context,
        ))
        outcome = fixture.coordinator.execute(
            prepared.action_id,
            owner_id="owner-wp05",
            runtime_kind="codex",
            runtime_lineage_id="lineage-wp05",
            lease=fixture.action_lease,
            target=session.target,
            observer=session.observer,
            disclosure_plan=release_disclosure_plan(fixture, prepared),
        )
        self.assertEqual(outcome.route, "reconciled-effect-verified")
        self.assertEqual(session.target.apply_count, 1)
        state = session.observer.observe()["state"]
        self.assertEqual(state["generation"], 1)
        self.assertEqual(state["active_artifact_digest"], candidate.manifest_digest)
        record = fixture.journal.load(prepared.action_id)
        self.assertEqual(record.state, "reconciled")
        self.assertIsNotNone(record.receipt)
        self.assertEqual(fixture.leases.unresolved_claims(), ())
        return outcome

    def test_category_assessment_1_4_binds_and_restarts_release_evidence(self) -> None:
        self._category_assessment_case()

    def test_closed_release_evidence_cannot_issue_or_commit_assessment(self) -> None:
        for cut in ("issue", "precommit", "transaction", "observer"):
            with self.subTest(cut=cut):
                self._category_assessment_case(close_cut=cut)

    def _category_assessment_case(self, *, close_cut: str | None = None) -> None:
        api = category_fixture.load_slice3_api()
        profile_id = "release-operations"
        profile = category_fixture.profile_document(profile_id)
        materialized = category_fixture.materialized_profile(profile_id)
        policy = api.CategoryExecutionPolicy.from_installation(
            profile_document=profile,
            support_matrix_document=category_fixture.load_json(
                category_fixture.SUPPORT_MATRIX_PATH
            ),
            materialization_record=materialized.record,
        )
        target = category_fixture.DisposableLocalTarget(profile_id)
        try:
            (
                task_application,
                repository,
                objects,
                runtime,
                probe,
            ) = category_fixture.production_category_runtime(
                profile_id, "normal", target=target,
            )
            target_authority = api.CategoryTargetObservationAuthority(policy)
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            oracle = api.CategoryCompletionOracle(
                policy=policy,
                target_authority=target_authority,
                release_operations_factory=release_factory,
            )
            action_coordinator, action_context = category_fixture.action_rollback_binding(
                probe, target,
            )
            rollback = api.CategoryRollbackBridge(policy, action_coordinator)
            rollback.prepare_action(**action_context)
            probe.bind_rollback_evidence(rollback)
            application = api.CategoryExecutionApplication(
                repository=repository,
                object_repository=objects,
                policy=policy,
                reducer=api.CategoryExecutionReducer(policy),
                completion_oracle=oracle,
                rollback_bridge=rollback,
                assessment_resolver=api.CategoryAssessmentResolver(
                    repository,
                    objects,
                    task_application=task_application,
                    runtime=runtime,
                ),
                task_application=task_application,
                runtime=runtime,
                target_observer=target,
            )
            application.bind_current_sources(probe.task_id)
            candidate = category_fixture.candidate_document(profile_id, "normal")
            from graph_engineering.application.profile_execution import _category_selector

            _issued, current = application._authoritative_candidate(
                _category_selector(candidate), target,
            )
            with action_stack() as release_actions:
                baseline = release_factory.issue_artifact_manifest(
                    fixture_id="release-foundation-v1", artifact_id="artifact-a",
                )
                release_candidate = release_factory.issue_artifact_manifest(
                    fixture_id="release-foundation-v1", artifact_id="artifact-b",
                )
                baseline_bytes = release_factory.artifact_bytes(baseline)
                candidate_bytes = release_factory.artifact_bytes(release_candidate)
                self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())
                session = release_factory.issue_simulator(
                    action_coordinator=release_actions.raw_coordinator,
                    task_id=str(current["task_id"]),
                    fixture_id="release-foundation-v1",
                    target_id="target-project",
                    resource_id="target:project",
                    baseline_manifest=baseline,
                    authorized_artifacts=(baseline, release_candidate),
                )
                with session:
                    action_outcome = self._assert_apply(
                        release_actions, session, baseline, release_candidate,
                        candidate_bytes,
                    )
                    deployment = release_factory.issue_deployment_observation(
                        action_coordinator=release_actions.raw_coordinator,
                        session=session,
                        outcome=action_outcome,
                    )
                    health = release_factory.issue_health_observation(
                        session=session,
                        terminal_observation=deployment,
                    )
                    evidence = release_factory.issue_evidence(
                        task_id=str(current["task_id"]),
                        task_revision=int(current["task_revision"]),
                        snapshot_digest=str(current["snapshot_digest"]),
                        invalidation_epoch=int(current["invalidation_epoch"]),
                        graph_ref_pins=dict(current["digest_pins"]),
                        artifact_manifest=release_candidate,
                        deployment_observation=deployment,
                        health_observation=health,
                        rollback_observation=None,
                        session=session,
                        owner_route="reconciled-effect-verified",
                        column_id=str(current["column_id"]),
                        scenario_id=str(current["scenario_id"]),
                        outcome="artifact-provenance-verified",
                    )
                    coherently_resigned = evidence.to_dict()
                    health_body = coherently_resigned["health_observation"]
                    health_body["unexpected"] = "forged"
                    health_body.pop("observation_digest")
                    health_body["observation_digest"] = _semantic(
                        health_body, "release-health-observation",
                    )
                    coherently_resigned["health_observation_digest"] = (
                        health_body["observation_digest"]
                    )
                    coherently_resigned.pop("observation_digest")
                    coherently_resigned["observation_digest"] = _semantic(
                        coherently_resigned, "release-operations-observation",
                    )
                    with self.assertRaisesRegex(
                        ReleaseOperationsError, "violates",
                    ):
                        release_factory.restore_projection(coherently_resigned)
                    if close_cut is not None:
                        before = probe.signature()
                        mutations = session._root.mutation_count
                        if close_cut == "issue":
                            session.close()
                        elif close_cut == "precommit":
                            application._fault = lambda step: (
                                session.close()
                                if step == "category-assessment.before-commit" else None
                            )
                        elif close_cut == "transaction":
                            repository._fault = lambda step: (
                                session.close() if step == "commit.before_commit" else None
                            )
                        else:
                            armed = [False]
                            repository._fault = lambda step: (
                                armed.__setitem__(0, True)
                                if step == "commit.before_commit" else None
                            )
                            original_observe = target.observe

                            def close_during_final_observation():  # type: ignore[no-untyped-def]
                                if armed[0]:
                                    session.close()
                                return original_observe()

                            target.observe = close_during_final_observation
                        with self.assertRaises(api.CategoryExecutionError):
                            application.assess_and_commit(
                                candidate, observer=target,
                                release_operations_evidence=evidence,
                            )
                        self.assertEqual(probe.signature(), before)
                        self.assertEqual(session._root.mutation_count, mutations)
                        self.assertEqual(session.target.apply_count, 1)
                        return
                    receipt = application.assess_and_commit(
                        candidate,
                        observer=target,
                        release_operations_evidence=evidence,
                    )
            self.assertEqual(receipt.assessment.schema_version, "1.4.0")
            self.assertIsNotNone(receipt.assessment.release_operations_projection)
            self.assertIsNone(receipt.assessment.scenario_truth_projection)
            schemas, context = category_fixture.category_schema_registry()
            evidence_document = evidence.to_dict()
            for name, document in (
                ("release-deployment-observation", evidence_document["deployment_observation"]),
                ("release-health-observation", evidence_document["health_observation"]),
            ):
                self.assertEqual(schemas.validate(
                    f"urn:gew:schema:{name}:1.0.0", document, context,
                ), [])
                input_document = dict(document)
                input_document.pop("observation_digest")
                self.assertEqual(schemas.validate(
                    f"urn:gew:schema:{name}-input:1.0.0",
                    input_document,
                    context,
                ), [])
            self.assertEqual(schemas.validate(
                "urn:gew:schema:release-operations-observation:1.0.0",
                evidence_document,
                context,
            ), [])
            evidence_input = dict(evidence_document)
            evidence_input.pop("observation_digest")
            self.assertEqual(schemas.validate(
                "urn:gew:schema:release-operations-observation-input:1.0.0",
                evidence_input,
                context,
            ), [])
            self.assertEqual(schemas.validate(
                "urn:gew:schema:category-completion-assessment:1.4.0",
                category_fixture.load_json_bytes(receipt.assessment.to_bytes()),
                context,
            ), [])
            restarted_task, restarted_runtime = probe.restart_authorities()
            with self.assertRaisesRegex(
                ReleaseOperationsError, "live target/journal revalidation",
            ):
                application.restart(
                    restarted_task, restarted_runtime, target,
                )
        finally:
            target.close()


if __name__ == "__main__":
    unittest.main()
