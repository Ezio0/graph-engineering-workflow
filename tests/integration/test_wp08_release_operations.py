from __future__ import annotations

import pathlib
import unittest
from contextlib import ExitStack, contextmanager
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


class WP08RetainedReleaseSessionTests(unittest.TestCase):
    @contextmanager
    def _owner_root(self, *, applied=False):
        import tempfile
        from graph_engineering.application.runtime import RuntimeSessionError

        with action_stack(domain_task=True) as fixture, ExitStack() as stack:
            runtime = self._runtime()
            def close_current_runtime():
                try:
                    runtime.require_current()
                except RuntimeSessionError:
                    return  # Revocation cases already closed this exact runtime.
                runtime.close()
            stack.callback(close_current_runtime)
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="gew-retained-owner-"))
            namespace = stack.enter_context(runtime.bind_release_namespace(
                action_coordinator=fixture.raw_coordinator, namespace_path=pathlib.Path(directory).resolve()))
            factory, session, baseline, artifact = self._issue(fixture, namespace)
            stack.enter_context(session)
            if applied:
                outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                    fixture, session, baseline, artifact, factory.artifact_bytes(artifact))
            else:
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                outcome = None
            yield fixture, runtime, namespace, factory, session, session.recovery_binding, outcome

    def test_owner_destroy_quiesced_root_revokes_before_cleanup_without_repository_writes(self):
        import os

        for applied in (False, True):
            with self.subTest(applied=applied), self._owner_root(applied=applied) as values:
                fixture, _runtime, namespace, factory, session, binding, outcome = values
                coordinator = fixture.raw_coordinator
                native = namespace.require_current(coordinator)
                root = session._root._root_path
                session.close()
                before = fixture.repository.load("task-wp05")
                security = coordinator._issuer.read_task_state("task-wp05")
                journal = fixture.journal.load(outcome.action_id) if outcome else None
                claim = fixture.leases.load_claim(outcome.claim_id) if outcome else None
                events = []
                unlink, fsync = os.unlink, os.fsync

                def observe_unlink(name, *, dir_fd=None):
                    self.assertEqual(native.active_leases, 1)
                    events.append(("unlink", name))
                    if name != ".release-simulator-root":
                        self.assertEqual(events[:2], [("unlink", ".release-simulator-root"), ("fsync", None)])
                    return unlink(name, dir_fd=dir_fd)

                def observe_fsync(fd):
                    events.append(("fsync", None))
                    return fsync(fd)

                original_read = coordinator._issuer.read_task_state
                def read_under_lease(task_id):
                    self.assertEqual(native.active_leases, 1)
                    return original_read(task_id)

                with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=read_under_lease), \
                     mock.patch.object(coordinator._issuer, "issue_task_context", side_effect=AssertionError("mutable security read")), \
                     mock.patch("graph_engineering.adapters.local_release_simulator.os.unlink", side_effect=observe_unlink), \
                     mock.patch("graph_engineering.adapters.local_release_simulator.os.fsync", side_effect=observe_fsync):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                self.assertFalse(root.exists())
                self.assertEqual(native.active_leases, 0)
                self.assertEqual(fixture.repository.load("task-wp05"), before)
                self.assertEqual(coordinator._issuer.read_task_state("task-wp05"), security)
                if outcome:
                    self.assertEqual(fixture.journal.load(outcome.action_id), journal)
                    self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
                self.assertEqual(session.target.apply_count, int(applied))
                with self.assertRaises(ValueError):
                    session.observer.observe()
                with self.assertRaises(ValueError):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)

    def test_owner_destroy_rejects_live_foreign_cloned_and_repository_busy_entries(self):
        import copy
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, _binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with mock.patch.object(_RetainedNamespace, "open_readonly", side_effect=AssertionError("root opened")):
                with self.assertRaisesRegex(ValueError, "quiesced"):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                session.close()
                for candidate, authority in ((copy.copy(session), namespace), (session, copy.copy(namespace)),
                                              (session, pathlib.Path(root.parent))):
                    with self.subTest(candidate=type(candidate).__name__, authority=type(authority).__name__), self.assertRaises(ValueError):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=authority, session=candidate)
                with action_stack() as foreign:
                    with self.assertRaises(ValueError):
                        factory.destroy_retained_simulator(action_coordinator=foreign.raw_coordinator,
                            retained_namespace=namespace, session=session)
                token = fixture.locks.acquire_installation("shared")
                try:
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=namespace, session=session)
                finally:
                    fixture.locks.release(token)
                with fixture.repository._factory.open("doctor"):
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=namespace, session=session)
                with self.assertRaises(ValueError):
                    ReleaseOperationsRegistryFactory.from_installation().destroy_retained_simulator(
                        action_coordinator=coordinator, retained_namespace=namespace, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)

    def test_owner_destroy_busy_root_preserves_competing_reader_and_checks_owner_under_lease(self):
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, _retained_members

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            members = {name: 0o600 for role, name in _retained_members(factory.registry().fixture("release-foundation-v1")).items() if role != "identity"}
            session.close()
            with _RetainedNamespace(root.parent) as other:
                with other.open_readonly(binding, members=members, context=coordinator._policy._context) as reader:
                    with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=AssertionError("read before root admission")):
                        with self.assertRaisesRegex(ValueError, "busy"):
                            factory.destroy_retained_simulator(action_coordinator=coordinator,
                                retained_namespace=namespace, session=session)
                    self.assertEqual(reader.read(".release-simulator-root", max_bytes=10000), before[".release-simulator-root"])
            with self._runtime("wrong-owner") as stranger:
                with stranger.bind_release_namespace(action_coordinator=coordinator, namespace_path=root.parent) as foreign:
                    with self.assertRaisesRegex(ValueError, "own"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=foreign, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)

    def test_owner_destroy_rejects_changed_target_and_revoked_runtime_without_cleanup(self):
        from tests.support.wp05_actions import digest

        for attack in ("target", "runtime"):
            with self.subTest(attack=attack), self._owner_root() as values:
                fixture, runtime, namespace, factory, session, _binding, _outcome = values
                root = session._root._root_path
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                session.close()
                if attack == "target":
                    retarget_security_binding(fixture, target_digest=digest("other-target"))
                else:
                    runtime.close()
                with self.assertRaises((ValueError, RuntimeError)):
                    factory.destroy_retained_simulator(action_coordinator=fixture.raw_coordinator,
                        retained_namespace=namespace, session=session)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                self.assertEqual(namespace._record()[4].active_leases, 0)

    def test_owner_destroy_interrupted_cleanup_leaves_ineligible_orphan_and_releases_lease(self):
        import os

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, _binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            session.close()
            unlink = os.unlink
            def fail_cleanup(name, *, dir_fd=None):
                if name != ".release-simulator-root":
                    raise OSError("injected member cleanup interruption")
                return unlink(name, dir_fd=dir_fd)
            with mock.patch("graph_engineering.adapters.local_release_simulator.os.unlink", side_effect=fail_cleanup), \
                 self.assertRaisesRegex(OSError, "cleanup interruption"):
                factory.destroy_retained_simulator(action_coordinator=coordinator,
                    retained_namespace=namespace, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()},
                {k: v for k, v in before.items() if k != ".release-simulator-root"})
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)
            with self.assertRaises(ValueError):
                factory.destroy_retained_simulator(action_coordinator=coordinator,
                    retained_namespace=namespace, session=session)
            with self.assertRaises(ValueError):
                self._issue(fixture, namespace)

    def test_owner_destroy_final_security_and_runtime_rereads_reject_midflight_drift(self):
        from tests.support.wp05_actions import digest

        for attack in ("security", "runtime"):
            with self.subTest(attack=attack), self._owner_root() as values:
                fixture, runtime, namespace, factory, session, _binding, _outcome = values
                coordinator = fixture.raw_coordinator
                root = session._root._root_path
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                session.close()
                read = coordinator._issuer.read_task_state
                calls = []
                def drift(task_id):
                    value = read(task_id)
                    calls.append(task_id)
                    if len(calls) == 1 and attack == "security":
                        retarget_security_binding(fixture, target_digest=digest("midflight-target"))
                    if len(calls) == 2 and attack == "runtime":
                        runtime.close()
                    return value
                with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=drift), \
                     self.assertRaises((ValueError, RuntimeError)):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                self.assertEqual(calls, ["task-wp05", "task-wp05"])
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                self.assertEqual(namespace._record()[4].active_leases, 0)

    @contextmanager
    def _same_task_assessment(self):
        """RS-2 live lease proof, not RS-4 artifact/target provenance proof.

        The legacy category observer and synthetic runner/artifact records stay
        test fixtures; this does not make them eligible for cold recovery.
        """
        import tempfile
        from tests.contract.test_wp02_graph import graph_schemas, work_context
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.application.profile_execution import _category_selector

        profile_id = "release-operations"
        api = category_fixture.load_slice3_api()
        with ExitStack() as stack:
            fixture = stack.enter_context(action_stack(domain_task=True))
            # action_stack creates the domain before installing its action-aware
            # repository facade. Use one exact facade for subsequent consumers.
            fixture.task_application = TaskApplication(
                fixture.repository, fixture.repository, fixture.leases,
                schema_registry=graph_schemas(), context=work_context(),
                materialization_objects=fixture.objects)
            runtime = stack.enter_context(self._runtime())
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="gew-retained-assessment-"))
            namespace = stack.enter_context(runtime.bind_release_namespace(
                action_coordinator=fixture.raw_coordinator,
                namespace_path=pathlib.Path(directory).resolve()))
            factory, session, baseline, artifact = self._issue(fixture, namespace)
            stack.enter_context(session)
            outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                fixture, session, baseline, artifact, factory.artifact_bytes(artifact))
            fixture.leases.release(fixture.action_lease.lease_id)
            # Continue the existing domain task through its normal transitions.
            # Do not copy action rows or repair a wrapper snapshot after apply.
            shared = category_fixture.SharedProductionCategoryRuntime(
                profile_id, ExitStack(), fixture.factory, fixture.objects,
                fixture.repository, fixture.leases, graph_schemas(), work_context(),
                fixture.task_application, fixture.task_runtime)
            target = category_fixture.DisposableLocalTarget(profile_id)
            stack.callback(target.close)
            task_application, repository, objects, task_runtime, probe = (
                category_fixture.production_category_runtime(
                    profile_id, "normal", target=target, task_id="task-wp05",
                    shared_runtime=shared, existing_created_task=True))
            self.assertIs(repository, fixture.repository)
            self.assertIs(task_application, fixture.task_application)
            self.assertEqual(probe.task_id, fixture.journal.load(outcome.action_id).prepared.task_id)
            policy = api.CategoryExecutionPolicy.from_installation(
                profile_document=category_fixture.profile_document(profile_id),
                support_matrix_document=category_fixture.load_json(category_fixture.SUPPORT_MATRIX_PATH),
                materialization_record=category_fixture.materialized_profile(profile_id).record)
            target_authority = api.CategoryTargetObservationAuthority(policy)
            oracle = api.CategoryCompletionOracle(policy=policy,
                target_authority=target_authority, release_operations_factory=factory)
            # The unused rollback-column source remains the legacy fixture. The
            # normal release apply, task transitions and assessment share ports.
            rollback_coordinator, rollback_context = category_fixture.action_rollback_binding(probe, target)
            rollback = api.CategoryRollbackBridge(policy, rollback_coordinator)
            rollback.prepare_action(**rollback_context)
            probe.bind_rollback_evidence(rollback)
            application = api.CategoryExecutionApplication(repository=repository,
                object_repository=objects, policy=policy, reducer=api.CategoryExecutionReducer(policy),
                completion_oracle=oracle, rollback_bridge=rollback,
                assessment_resolver=api.CategoryAssessmentResolver(repository, objects,
                    task_application=task_application, runtime=task_runtime),
                task_application=task_application, runtime=task_runtime, target_observer=target)
            application.bind_current_sources(probe.task_id)
            candidate = category_fixture.candidate_document(profile_id, "normal")
            candidate["task_id"] = probe.task_id
            _issued, current = application._authoritative_candidate(_category_selector(candidate), target)
            deployment = factory.issue_deployment_observation(
                action_coordinator=fixture.raw_coordinator, session=session, outcome=outcome)
            health = factory.issue_health_observation(session=session, terminal_observation=deployment)
            evidence = factory.issue_evidence(task_id=probe.task_id,
                task_revision=int(current["task_revision"]), snapshot_digest=str(current["snapshot_digest"]),
                invalidation_epoch=int(current["invalidation_epoch"]), graph_ref_pins=dict(current["digest_pins"]),
                artifact_manifest=artifact, deployment_observation=deployment, health_observation=health,
                rollback_observation=None, session=session, owner_route="reconciled-effect-verified",
                column_id="normal", scenario_id=str(current["scenario_id"]), outcome="artifact-provenance-verified")
            yield api, fixture, session, application, probe, target, candidate, evidence, outcome

    def test_same_task_retained_assessment_commits_with_original_lease_and_preserves_root(self):
        with self._same_task_assessment() as values:
            api, fixture, session, application, probe, target, candidate, evidence, outcome = values
            root = session._root
            lease = root._retained_lease
            before = {p.name: p.read_bytes() for p in root._root_path.iterdir()}
            journal = fixture.journal.load(outcome.action_id)
            claim = fixture.leases.load_claim(outcome.claim_id)
            mutations = root.mutation_count
            observations = []

            def in_transaction(step):
                if step == "commit.before_commit":
                    root._require_open()
                    self.assertIs(root._retained_lease, lease)
                    # Closing under the repository fence must not release the
                    # root. Only the outer session owner can close after unwind.
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        session.close()
                    observations.append(step)

            fixture.repository._fault = in_transaction
            receipt = application.assess_and_commit(candidate, observer=target,
                release_operations_evidence=evidence)
            fixture.repository._fault = None
            self.assertEqual(observations, ["commit.before_commit"])
            self.assertEqual(receipt.assessment.schema_version, "1.4.0")
            self.assertIsNotNone(receipt.assessment.release_operations_projection)
            view = fixture.task_application.runtime_show(probe.task_id, fixture.task_runtime)
            self.assertEqual(view.snapshot.lifecycle, "completed")
            self.assertEqual(view.snapshot.task_revision, receipt.assessment.task_revision + 1)
            self.assertEqual(fixture.objects.get(receipt.assessment.object_digest), receipt.assessment.to_bytes())
            self.assertIn(receipt.assessment.object_digest,
                [item[0] for item in fixture.repository.referenced_objects(probe.task_id)])
            self.assertEqual(fixture.journal.load(outcome.action_id), journal)
            self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
            self.assertEqual(root.mutation_count, mutations)
            self.assertEqual(session.target.apply_count, 1)
            self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, before)
            session.close()
            self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, before)
            with self.assertRaises(ValueError):
                session.observer.observe()

    def test_existing_category_task_input_rejects_implicit_or_advanced_task_before_publication(self):
        from tests.contract.test_wp02_graph import graph_schemas, work_context

        with self._same_task_assessment() as values:
            _api, fixture, _session, _application, probe, target, *_rest = values
            shared = category_fixture.SharedProductionCategoryRuntime(
                "release-operations", ExitStack(), fixture.factory, fixture.objects,
                fixture.repository, fixture.leases, graph_schemas(), work_context(),
                fixture.task_application, fixture.task_runtime)
            before = probe.signature()
            with mock.patch.object(fixture.task_application, "preauthorize_materialization",
                    side_effect=AssertionError("unexpected publication")) as publish:
                for runtime, existing, message in (
                    (None, True, "explicit shared runtime"),
                    (shared, 1, "explicit shared runtime"),
                    (shared, True, "exact created domain task"),
                ):
                    with self.subTest(existing=existing, message=message), self.assertRaisesRegex(AssertionError, message):
                        category_fixture.production_category_runtime("release-operations", "normal",
                            target=target, task_id=probe.task_id, shared_runtime=runtime,
                            existing_created_task=existing)
                publish.assert_not_called()
            self.assertEqual(probe.signature(), before)

    def test_same_task_retained_assessment_close_cuts_do_not_commit_or_reapply(self):
        for cut in ("before", "precommit", "transaction", "observer"):
            with self.subTest(cut=cut), self._same_task_assessment() as values:
                api, fixture, session, application, probe, target, candidate, evidence, outcome = values
                before = probe.signature()
                root = session._root
                tree = {p.name: p.read_bytes() for p in root._root_path.iterdir()}
                journal = fixture.journal.load(outcome.action_id)
                claim = fixture.leases.load_claim(outcome.claim_id)
                mutations = root.mutation_count
                reached = []

                def close_at_cut():
                    reached.append(cut)
                    session.close()

                if cut == "before":
                    close_at_cut()
                elif cut == "precommit":
                    application._fault = lambda step: (
                        close_at_cut() if step == "category-assessment.before-commit" else None)
                elif cut == "transaction":
                    fixture.repository._fault = lambda step: (
                        close_at_cut() if step == "commit.before_commit" else None)
                else:
                    armed = [False]
                    fixture.repository._fault = lambda step: (
                        armed.__setitem__(0, True) if step == "commit.before_commit" else None)
                    original_observe = target.observe

                    def final_observe():
                        if armed[0]:
                            close_at_cut()
                        return original_observe()

                    target.observe = final_observe
                with self.assertRaises((api.CategoryExecutionError, ValueError)):
                    application.assess_and_commit(candidate, observer=target,
                        release_operations_evidence=evidence)
                fixture.repository._fault = None
                self.assertEqual(reached, [cut])
                self.assertEqual(probe.signature(), before)
                self.assertEqual(fixture.journal.load(outcome.action_id), journal)
                self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
                self.assertEqual(root.mutation_count, mutations)
                self.assertEqual(session.target.apply_count, 1)
                self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, tree)
                # Transaction/fence rejection leaves the original lease intact.
                if cut in ("transaction", "observer"):
                    root._require_open()
                session.close()

    @staticmethod
    def _runtime(owner_id="owner-wp05"):
        from graph_engineering.application.runtime import RuntimeSession
        from graph_engineering.core.runtime import RuntimeLineage
        from tests.unit.test_wp07_runtime_contract import FixtureAdapter, fixture_adapter, request, lineage, signed

        class Adapter(FixtureAdapter):
            def resolve_lineage(self, raw_input):
                value = lineage(value=raw_input["lineage_id"]).to_dict()
                value["owner_id"] = raw_input["owner_id"]
                value.pop("proof_digest")
                return RuntimeLineage.from_dict(signed("lineage", "proof_digest", value))
        return RuntimeSession.establish(fixture_adapter(Adapter),
            {"owner_id": owner_id, "lineage_id": "lineage-wp05"}, request())

    @staticmethod
    def _issue(fixture, namespace):
        factory = ReleaseOperationsRegistryFactory.from_installation()
        baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
        candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
        session = factory.issue_simulator(action_coordinator=fixture.raw_coordinator,
            retained_namespace=namespace, task_id="task-wp05", fixture_id="release-foundation-v1",
            target_id="target-project", resource_id="target:project", baseline_manifest=baseline,
            authorized_artifacts=(baseline, candidate))
        return factory, session, baseline, candidate

    def test_runtime_issued_namespace_creates_retained_target_and_close_preserves_bytes(self):
        import tempfile
        from graph_engineering.application.release_operations import RetainedReleaseNamespace

        with action_stack(domain_task=True) as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                self.assertIs(type(namespace), RetainedReleaseNamespace)
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    binding = session.recovery_binding
                    self.assertEqual(binding.target_digest(), session.target.target_digest)
                    WP08ReleaseOperationsIntegrationTests()._assert_apply(fixture, session, baseline, candidate, factory.artifact_bytes(candidate))
                    path = session._root._root_path
                    before = {p.name: p.read_bytes() for p in path.iterdir()}
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
                with self.assertRaises(ValueError):
                    session.observer.observe()
                with self.assertRaises(ValueError):
                    self._issue(fixture, namespace)

    def test_raw_cloned_foreign_and_expired_namespace_cannot_issue_session(self):
        import copy
        import tempfile
        with action_stack() as fixture, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            runtime = self._runtime()
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                for invalid in (pathlib.Path(directory), object(), copy.copy(namespace)):
                    with self.subTest(invalid=type(invalid).__name__), self.assertRaises(ValueError):
                        self._issue(fixture, invalid)
                with action_stack() as foreign:
                    with self.assertRaises(ValueError):
                        self._issue(foreign, namespace)
                runtime.close()
                with self.assertRaises((ValueError, RuntimeError)):
                    self._issue(fixture, namespace)
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_repository_tokens_and_connections_reject_before_root_creation(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                token = fixture.locks.acquire_installation("shared")
                try:
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        self._issue(fixture, namespace)
                finally:
                    fixture.locks.release(token)
                with fixture.repository._factory.open("doctor"):
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        self._issue(fixture, namespace)
                with action_stack() as other:
                    token = other.locks.acquire_installation("shared")
                    try:
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            self._issue(fixture, namespace)
                    finally:
                        other.locks.release(token)
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_closed_session_rejects_all_action_entries_before_repository_calls(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
                coordinator = fixture.raw_coordinator
                prepared = coordinator.prepare(document)
                authority = authority_document(prepared, context=fixture.context)
                session.close()
                with mock.patch.object(coordinator._journal, "record_prepared", side_effect=AssertionError("journal write")), \
                     mock.patch.object(coordinator._journal, "find_prepared", side_effect=AssertionError("journal read")), \
                     mock.patch.object(fixture.locks, "acquire_installation", side_effect=AssertionError("repository lock")):
                    attempts = (
                        lambda: coordinator.prepare(document),
                        lambda: coordinator.authorize(authority),
                        lambda: coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                            observer=session.observer, disclosure_plan=None),
                        lambda: coordinator.reconcile_unknown(prepared.action_id, lease=fixture.action_lease, observer=session.observer),
                        lambda: coordinator.compensate_unknown(prepared.action_id, compensation_action_id="unused",
                            recovery_lease=fixture.action_lease, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", target=session.target, observer=session.observer, disclosure_plan=None),
                    )
                    for index, attempt in enumerate(attempts):
                        with self.subTest(entry=index), self.assertRaises(ValueError):
                            attempt()
                self.assertEqual(session.target.apply_count, 0)

    def test_closed_session_rejects_observation_before_repository_reads(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                        fixture, session, baseline, candidate, factory.artifact_bytes(candidate))
                    deployment = factory.issue_deployment_observation(
                        action_coordinator=fixture.raw_coordinator, session=session, outcome=outcome)
                with mock.patch.object(fixture.raw_coordinator._journal, "load",
                        side_effect=AssertionError("repository read before lease check")):
                    with self.assertRaises(ValueError):
                        factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                            session=session, outcome=outcome)
                    with self.assertRaises(ValueError):
                        factory._require_live_projection({}, (session, deployment, None))

    def _unresolved_retained_action(self, fixture, session, factory, baseline, candidate):
        from graph_engineering.core.actions import PreparedAction

        def fault(step):
            if step == "after-active-switch-durable":
                raise TimeoutError("retained reconciliation cut")

        session._root.fault_hook = fault
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        document = release_prepared_document(fixture, target_digest=session.target.target_digest,
            baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
        document["snapshot_digest"] = fixture.current_task_snapshot_digest()
        document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
        prepared = fixture.coordinator.prepare(document)
        fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
        outcome = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
            observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
        self.assertEqual(outcome.route, "manual-reconciliation")
        self.assertEqual(fixture.journal.load(prepared.action_id).state, "unknown")
        return prepared

    def test_foreign_coordinator_rejects_live_and_closed_retained_observers_before_repository_access(self):
        import tempfile
        from graph_engineering.application.actions import ActionCoordinator

        for closed in (False, True):
            with self.subTest(closed=closed), action_stack(domain_task=True) as fixture, \
                 self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                        namespace_path=pathlib.Path(directory).resolve()) as namespace:
                    factory, session, baseline, candidate = self._issue(fixture, namespace)
                    with session:
                        prepared = self._unresolved_retained_action(fixture, session, factory, baseline, candidate)
                        owner = fixture.raw_coordinator
                        foreign = ActionCoordinator(journal=owner._journal, repository=owner._repository,
                            leases=owner._leases, locks=owner._locks, objects=owner._objects,
                            security_issuer=owner._issuer, action_policy=owner._policy,
                            installation_scope=owner._repository.command_scope)
                        self.assertIs(foreign._repository.command_scope, owner._repository.command_scope)
                        self.assertEqual(foreign._retained_actions, {})

                        def durable_state():
                            return (fixture.repository.load("task-wp05"), fixture.journal.load(prepared.action_id),
                                fixture.leases.load_claim("claim:" + prepared.action_id))

                        before = durable_state()
                        if closed:
                            session.close()
                        with mock.patch.object(fixture.locks, "acquire_installation", side_effect=AssertionError("repository lock")) as lock, \
                             mock.patch.object(owner._journal, "load", side_effect=AssertionError("journal read")) as journal, \
                             mock.patch.object(session.observer, "observe", side_effect=AssertionError("observer call")) as observe:
                            with self.assertRaisesRegex(ValueError, "live coordinator binding"):
                                foreign.reconcile_unknown(prepared.action_id, lease=fixture.action_lease,
                                    observer=session.observer)
                            lock.assert_not_called()
                            journal.assert_not_called()
                            observe.assert_not_called()
                        self.assertEqual(durable_state(), before)
                        self.assertEqual(session.target.apply_count, 1)

    def test_original_coordinator_reconciles_retained_and_disposable_actions(self):
        import tempfile
        from contextlib import nullcontext

        for retained in (True, False):
            with self.subTest(retained=retained), action_stack(domain_task=True) as fixture, \
                 self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                namespace_context = runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) if retained else nullcontext(None)
                with namespace_context as namespace:
                    factory, session, baseline, candidate = self._issue(fixture, namespace)
                    with session:
                        prepared = self._unresolved_retained_action(fixture, session, factory, baseline, candidate)
                        outcome = fixture.coordinator.reconcile_unknown(prepared.action_id,
                            lease=fixture.action_lease, observer=session.observer)
                        self.assertEqual(outcome.route, "reconciled-effect-verified")
                        self.assertEqual(fixture.journal.load(prepared.action_id).state, "reconciled")
                        self.assertEqual(fixture.leases.unresolved_claims(), ())
                        self.assertEqual(session.target.apply_count, 1)
                        if retained:
                            self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)
                        else:
                            self.assertIsNone(session.recovery_binding)

    def test_wrong_runtime_owner_and_failed_initialization_release_root_lease(self):
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedPrivateRoot
        for attack in ("owner", "initialization"):
            with self.subTest(attack=attack), action_stack(domain_task=True) as fixture, \
                 self._runtime("wrong-owner" if attack == "owner" else "owner-wp05") as runtime, \
                 tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                        namespace_path=pathlib.Path(directory).resolve()) as namespace:
                    before = fixture.repository.load("task-wp05")
                    if attack == "owner":
                        with self.assertRaisesRegex(ValueError, "does not own"):
                            self._issue(fixture, namespace)
                    else:
                        with mock.patch.object(_RetainedPrivateRoot, "_durable_write", side_effect=OSError("injected initial write failure")), self.assertRaises(OSError):
                            self._issue(fixture, namespace)
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 0)
                    self.assertEqual(fixture.repository.load("task-wp05"), before)
                    self.assertEqual(len(list(pathlib.Path(directory).iterdir())), 1)

    def test_live_namespace_cannot_close_and_runtime_revocation_invalidates_session(self):
        import tempfile
        with action_stack() as fixture, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            runtime = self._runtime()
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                _factory, session, _baseline, _candidate = self._issue(fixture, namespace)
                with session:
                    with self.assertRaises(ValueError):
                        namespace.close()
                    runtime.close()
                    with self.assertRaises(RuntimeError):
                        session.observer.observe()

    def test_close_waits_for_repository_tokens_and_connections_to_release(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                _factory, session, _baseline, _candidate = self._issue(fixture, namespace)
                with session:
                    token = fixture.locks.acquire_installation("shared")
                    try:
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            session.close()
                    finally:
                        fixture.locks.release(token)
                    with fixture.repository._factory.open("doctor"):
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            session.close()
                    self.assertFalse(session._root.closed)
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)

    def test_retained_partial_compensation_restores_baseline_under_same_lease(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    def fault(step):
                        if step == "after-stage-durable":
                            raise TimeoutError("retained partial cut")
                    session._root.fault_hook = fault
                    retarget_security_binding(fixture, target_digest=session.target.target_digest)
                    prepared = fixture.coordinator.prepare(release_prepared_document(fixture,
                        target_digest=session.target.target_digest, baseline=baseline, candidate=candidate,
                        candidate_bytes=factory.artifact_bytes(candidate)))
                    fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                    unknown = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                        observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
                    self.assertEqual(unknown.route, "manual-reconciliation")
                    factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                        session=session, outcome=unknown)
                    compensation = fixture.coordinator.prepare(release_partial_restore_prepared_document(fixture,
                        target_digest=session.target.target_digest, baseline=baseline, baseline_bytes=factory.artifact_bytes(baseline),
                        candidate=candidate, original_claim_id=unknown.claim_id, original_receipt_digest=unknown.receipt_digest))
                    fixture.coordinator.authorize(authority_document(compensation, context=fixture.context))
                    restored = fixture.coordinator.compensate_unknown(prepared.action_id,
                        compensation_action_id=compensation.action_id, recovery_lease=fixture.action_lease,
                        owner_id="owner-wp05", runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                        target=session.target, observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, compensation))
                    self.assertEqual(restored.route, "compensation-reconciled")
                    self.assertEqual(restored.claim_id, unknown.claim_id)
                    self.assertEqual(session.observer.observe()["state"], {"generation": 0,
                        "active_artifact_digest": baseline.manifest_digest, "staged_artifact_digest": None})
                    self.assertEqual(fixture.leases.unresolved_claims(), ())
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)


class WP08RetainedRootProcessTests(unittest.TestCase):
    """Fresh exec tests of storage only; no cold recovery evidence is issued."""

    CHILD = r'''
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.dont_write_bytecode = True
sys.path.insert(0, str(root))
from tests.support.source_checkout_attestation import (
    issue_source_checkout_attestation, CONTROL_OPTION, CONTROL_ENVIRONMENT,
)
def main(control):
    issue_source_checkout_attestation(root, pathlib.Path(control).resolve())
    sys._xoptions[CONTROL_OPTION] = str(pathlib.Path(control).resolve())
    os.environ[CONTROL_ENVIRONMENT] = sys._xoptions[CONTROL_OPTION]
    for part in ("core", "application", "storage", "adapters"):
        sys.path.insert(0, str(root / part))
    from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, ReleaseSimulatorError, _semantic
    from graph_engineering.core.release_operations import ReleaseRecoveryBinding
    from tests.support.wp05a_security import security_context
    request = json.loads(sys.stdin.read())
    members = {"active.bin": 0o600, "state.json": 0o600}
    with _RetainedNamespace(pathlib.Path(request["namespace"])) as namespace:
        if request["mode"] == "create":
            with namespace.create("task-wp05", "target-project", members=members) as lease:
                lease.initialize_file("active.bin", b"artifact-a\n")
                lease.initialize_file("state.json", b'{"generation":0}')
                value = request["binding"]
                value.update(lease.binding_parts())
                value["binding_digest"] = _semantic({k:v for k,v in value.items() if k != "binding_digest"}, "release-recovery-binding")
                lease.seal(ReleaseRecoveryBinding.from_dict(value))
                print(json.dumps({"pid": os.getpid(), "binding": value}), flush=True)
                if request["abrupt"]:
                    # Exit while owning the OS lock: no Python cleanup or inherited issuer.
                    os._exit(0)
        else:
            binding = ReleaseRecoveryBinding.from_dict(request["binding"])
            try:
                with namespace.open_readonly(binding, members=members, context=security_context()) as lease:
                    assert request["mode"] == "read", "competing exec acquired a live root"
                    print(json.dumps({"pid": os.getpid(), "artifact": lease.read("active.bin", max_bytes=1024).hex()}))
            except ReleaseSimulatorError as error:
                assert request["mode"] == "busy" and "busy" in str(error), str(error)
                assert namespace.active_leases == 0
                print(json.dumps({"pid": os.getpid(), "busy": True}))
main(sys.argv[2])
'''

    def _child(self, namespace, *, mode, binding, abrupt=False):  # type: ignore[no-untyped-def]
        import json
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory(prefix="gew-retained-child-control-") as control:
            result = subprocess.run(
                [sys.executable, "-B", "-c", self.CHILD, str(ROOT), control],
                input=json.dumps({"namespace": str(namespace), "mode": mode,
                    "binding": binding, "abrupt": abrupt}),
                text=True, capture_output=True, timeout=30, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_fresh_exec_reopens_retained_bytes_after_producer_exit(self) -> None:
        import os
        import tempfile
        from tests.unit.test_wp08_release_operations import WP08ReleaseRecoveryBindingTests

        for abrupt in (False, True):
            with self.subTest(abrupt=abrupt), tempfile.TemporaryDirectory(prefix="gew-retained-exec-") as directory:
                path = pathlib.Path(directory).resolve()
                producer = self._child(path, mode="create", binding=WP08ReleaseRecoveryBindingTests.document(), abrupt=abrupt)
                retained = next(path.iterdir())
                before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in retained.iterdir()}
                consumer = self._child(path, mode="read", binding=producer["binding"])
                self.assertNotEqual(producer["pid"], consumer["pid"])
                self.assertNotEqual(consumer["pid"], os.getpid())
                self.assertEqual(consumer["artifact"], b"artifact-a\n".hex())
                self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in retained.iterdir()}, before)

    def test_fresh_exec_is_busy_until_live_owner_closes(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.unit.test_wp08_release_operations import WP08RetainedRootPrimitiveTests

        with tempfile.TemporaryDirectory(prefix="gew-retained-exec-") as directory:
            path = pathlib.Path(directory).resolve()
            with _RetainedNamespace(path) as namespace:
                lease, binding = WP08RetainedRootPrimitiveTests()._create(namespace)
                with lease:
                    result = self._child(path, mode="busy", binding=binding.to_dict())
                    self.assertTrue(result["busy"])
                    self.assertEqual(lease.read("active.bin", max_bytes=1024), b"artifact-a\n")
                result = self._child(path, mode="read", binding=binding.to_dict())
                self.assertEqual(result["artifact"], b"artifact-a\n".hex())


class WP08ReleaseOperationsIntegrationTests(unittest.TestCase):
    def test_same_task_action_then_domain_command_and_runner(self) -> None:
        from graph_engineering.core.actions import PreparedAction
        from graph_engineering.core.graph.state import TaskCommand
        from tests.integration.test_wp04_runner import (
            ApplicationRunnerIntegrationTests, PassingRuntime, PassingValidator, PassingReviewer,
        )
        from tests.integration.test_wp04_application import TaskApplicationIntegrationTests

        with action_stack(domain_task=True) as fixture:
            application = fixture.task_application
            runtime = fixture.task_runtime
            before = application.runtime_show("task-wp05", runtime)
            factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
            candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
            with factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator, task_id="task-wp05",
                fixture_id="release-foundation-v1", target_id="target-project",
                resource_id="target:project", baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
            ) as session:
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
                document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                prepared = fixture.coordinator.prepare(document)
                fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                outcome = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=session.target, observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, prepared))
                self.assertEqual(outcome.route, "reconciled-effect-verified")
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                fixture.leases.release(fixture.action_lease.lease_id)
                after = application.runtime_show("task-wp05", runtime)
                self.assertEqual(after.snapshot.to_dict(), before.snapshot.to_dict())
                self.assertEqual(after.runner_state, before.runner_state)
                self.assertEqual(after.repository_revision, before.repository_revision + 3)
                self.assertEqual(set(fixture.repository.load("task-wp05")), {"task_id", "revision", "domain", "runner"})

                _schemas, context, graph, budgets = ApplicationRunnerIntegrationTests().stack()
                helper = TaskApplicationIntegrationTests()
                application.execute_scope("task-wp05", TaskCommand("bind_project_scope", 1,
                    {"project_scope_ref": helper.scope("drafted")}), helper.project_scope(), runtime)
                application.execute("task-wp05", TaskCommand("request_prd_approval", 2,
                    {"prd_candidate_ref": "artifact:bridge-prd"}), runtime)
                approval = helper.approval()
                approval["baseline_refs"][0]["approved_by"] = "owner-wp05"
                approval["graph_ref"].update(graph_id="test-delivery", graph_digest=graph.digest)
                application.execute("task-wp05", TaskCommand("approve_prd", 3, approval), runtime)
                application.execute("task-wp05", TaskCommand("run", 5, {
                    "compatibility_evidence_ref": "evidence:bridge-compatible", "lease_plan_ref": "lease-plan:none-v1",
                }), runtime)
                runner = application.create_runner(fixture.objects, budgets, context=context)
                result = runner.run_until_stable("task-wp05", runtime, graph,
                    PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=30)
                self.assertEqual(result.status, "completion_ready")
                final = application.runtime_show("task-wp05", runtime)
                history = fixture.repository.replay("task-wp05")
                self.assertEqual(len(history), final.snapshot.last_event_seq + 3)
                self.assertEqual({r.status for r in final.snapshot.node_runs.values()}, {"passed"})
                self.assertEqual(fixture.issuer.read_task_state("task-wp05").state["task_revision"], final.repository_revision)

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
        if fixture.task_application is not None:
            from graph_engineering.core.actions import PreparedAction

            document["snapshot_digest"] = fixture.current_task_snapshot_digest()
            document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
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
