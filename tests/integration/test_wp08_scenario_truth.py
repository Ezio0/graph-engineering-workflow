"""Focused P2a scenario-truth/category/coverage integration tests."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import pickle
import sys
import threading
import time
import unittest
from unittest import mock

from tests.support import wp08_release_coverage as fixture
from tests.support import wp08_scenario_truth as runtime_fixture
from tests.unit import test_wp08_profile_contracts as profile_fixture


class ScenarioTruthIntegrationTests(unittest.TestCase):
    @staticmethod
    def _private_tree_signature(root: pathlib.Path) -> tuple[tuple[str, int, str], ...]:
        return tuple(
            (
                member.relative_to(root).as_posix(),
                len(body),
                hashlib.sha256(body).hexdigest(),
            )
            for member in sorted(root.rglob("*"), key=lambda item: item.as_posix())
            if member.is_file()
            for body in (member.read_bytes(),)
        )

    @staticmethod
    def matrix():  # type: ignore[no-untyped-def]
        api = profile_fixture._profile_api()
        coverage = profile_fixture._coverage_policy()
        return api.SupportMatrixDefinition.from_dict(
            profile_fixture._support_matrix_document(),
            approved_profiles=profile_fixture._approved_registry(),
            coverage_policy=coverage,
        )

    def test_f1_generic_dependency_reopen_api_is_typed_and_opaque(self) -> None:
        from graph_engineering.application import dependency_security

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="dependency-security",
            column="artifacts",
            disposition="P",
        )
        foreign_result = None
        try:
            observation_factory, observation = (
                result.authority._dependency_security
            )
            authority = (
                dependency_security.DependencySecurityObservationReopenAuthority.
                from_current(observation_factory, observation)
            )
            seal = authority.seal_current(
                observation_factory, observation,
            )
            durable_before = fixture._serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            self.assertIs(
                type(seal), dependency_security.DependencySecurityObservationSeal,
            )
            self.assertIsNot(type(observation_factory), type(observation))
            with self.assertRaises(TypeError):
                copy.copy(seal)
            with self.assertRaises(TypeError):
                copy.deepcopy(seal)
            with self.assertRaises(TypeError):
                pickle.dumps(seal)
            self.assertEqual(
                seal._projection["schema_version"], "1.1.0",
            )
            graph_projection = seal._projection["graph"]
            self.assertEqual(
                set(graph_projection),
                {
                    "installation", "policy", "remediation", "before",
                    "after", "disposition",
                },
            )
            for field, replacement in (
                ("_capability", object()),
                ("_generation", False),
                ("_projection", observation._projection),
                ("_paths", tuple(list(seal._paths))),
            ):
                original = getattr(seal, field)
                object.__setattr__(seal, field, replacement)
                try:
                    with self.assertRaises(
                        dependency_security.DependencySecurityError
                    ):
                        authority.rehydrate_current(
                            seal,
                            repository=result.probe.repository,
                            category_application=result.application,
                        )
                finally:
                    object.__setattr__(seal, field, original)
                self.assertEqual(
                    (authority.state, authority.generation),
                    ("QUIESCED", 0),
                )
                self.assertEqual(
                    fixture._serial_state_signature(
                        result.probe, result.target, real_e2e=False,
                    ),
                    durable_before,
                )
            forged = object.__new__(
                dependency_security.DependencySecurityObservationSeal
            )
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    forged,
                    repository=result.probe.repository,
                    category_application=result.application,
                )
            graph_factory = result.application._oracle._dependency_graph_factory
            assessment = result.application.current_assessment(
                result.probe.task_id,
                expected_profile_id="dependency-security",
            )
            with self.assertRaises(dependency_security.DependencySecurityError):
                dependency_security.DependencySecurityObservationReopenAuthority.from_current(
                    graph_factory,
                    assessment._dependency_graph_evidence,
                )
            import graph_engineering

            parser = graph_engineering._dependency_advisory_preflight_observation
            thread_errors: list[BaseException] = []

            def cross_thread_reopen() -> None:
                try:
                    authority.rehydrate_current(
                        seal,
                        repository=result.probe.repository,
                        category_application=result.application,
                    )
                except BaseException as error:
                    thread_errors.append(error)

            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_preflight_observation",
                wraps=parser,
            ) as parser_reread:
                thread = threading.Thread(target=cross_thread_reopen)
                thread.start()
                thread.join()
                self.assertEqual(parser_reread.call_count, 0)
            self.assertEqual(len(thread_errors), 1)
            self.assertIs(
                type(thread_errors[0]), dependency_security.DependencySecurityError,
            )
            installed = graph_engineering._dependency_advisory_installation_resources()
            changed = list(installed)
            changed[1] = changed[1] + b"\n"
            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_installation_resources",
                return_value=tuple(changed),
            ), self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    seal,
                    repository=result.probe.repository,
                    category_application=result.application,
                )
            replaced_path = seal._paths[0]
            replaced_body = replaced_path.read_bytes()
            backup_path = replaced_path.with_name(replaced_path.name + ".f1-original")
            os.replace(replaced_path, backup_path)
            try:
                replaced_path.write_bytes(replaced_body)
                with self.assertRaises(dependency_security.DependencySecurityError):
                    authority.rehydrate_current(
                        seal,
                        repository=result.probe.repository,
                        category_application=result.application,
                    )
            finally:
                replaced_path.unlink(missing_ok=True)
                os.replace(backup_path, replaced_path)
            self.assertEqual(
                fixture._serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ),
                durable_before,
            )
            foreign_result = fixture.run_serial_profile_binding(
                api4=api4,
                plan=plan,
                profile_id="dependency-security",
                column="artifacts",
                disposition="R",
            )
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    seal,
                    repository=foreign_result.probe.repository,
                    category_application=foreign_result.application,
                )
            self.assertEqual(
                (authority.state, authority.generation), ("QUIESCED", 0),
            )
            reopened_factory, reopened_observation = authority.rehydrate_current(
                seal,
                repository=result.probe.repository,
                category_application=result.application,
            )
            self.assertEqual((authority.state, authority.generation), ("LIVE", 1))
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    seal,
                    repository=result.probe.repository,
                    category_application=result.application,
                )
            self.assertIs(
                reopened_factory.require_current(reopened_observation),
                reopened_observation,
            )
            self.assertEqual(
                fixture._serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ),
                durable_before,
            )
            terminal_seal = authority.seal_current(
                reopened_factory, reopened_observation,
            )
            authority.revoke(terminal_seal)
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    terminal_seal,
                    repository=result.probe.repository,
                    category_application=result.application,
                )
        finally:
            if foreign_result is not None:
                foreign_result.close()
            result.close()

    def test_f1_reentrant_terminal_revoke_cannot_revive_seal(self) -> None:
        import graph_engineering
        from graph_engineering.application import dependency_security

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="dependency-security",
            column="artifacts",
            disposition="P",
        )
        try:
            factory, observation = result.authority._dependency_security
            authority = (
                dependency_security.DependencySecurityObservationReopenAuthority.
                from_current(factory, observation)
            )
            seal = authority.seal_current(factory, observation)
            durable_before = fixture._serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            original = graph_engineering._dependency_advisory_preflight_observation
            revoked = False

            def revoke_during_parser(*args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal revoked
                if not revoked:
                    revoked = True
                    authority.revoke(seal)
                return original(*args, **kwargs)

            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_preflight_observation",
                revoke_during_parser,
            ), self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    seal,
                    repository=result.probe.repository,
                    category_application=result.application,
                )
            self.assertEqual(authority.state, "TERMINAL")
            self.assertEqual(
                fixture._serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ),
                durable_before,
            )
        finally:
            result.close()

    def test_f2_reentrant_terminal_revoke_cannot_issue_seal(self) -> None:
        import graph_engineering
        from graph_engineering.application import dependency_security

        network = mock.patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        )
        network.start()
        self.addCleanup(network.stop)
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="dependency-security",
            column="artifacts",
            disposition="P",
        )
        try:
            factory, observation = result.authority._dependency_security
            authority = (
                dependency_security.DependencySecurityObservationReopenAuthority.
                from_current(factory, observation)
            )
            durable_before = fixture._serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            resolver_before = (
                result.dependency_security_context.resolver_observation_count
            )
            original = graph_engineering._dependency_advisory_preflight_observation
            revoked = False

            def revoke_during_parser(*args, **kwargs):  # type: ignore[no-untyped-def]
                nonlocal revoked
                if not revoked:
                    revoked = True
                    authority.revoke()
                return original(*args, **kwargs)

            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_preflight_observation",
                revoke_during_parser,
            ), self.assertRaises(dependency_security.DependencySecurityError):
                authority.seal_current(factory, observation)
            self.assertTrue(revoked)
            self.assertEqual(authority.state, "TERMINAL")
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.seal_current(factory, observation)
            with self.assertRaises(dependency_security.DependencySecurityError):
                authority.rehydrate_current(
                    object.__new__(
                        dependency_security.DependencySecurityObservationSeal
                    ),
                    repository=result.probe.repository,
                    category_application=result.application,
                )
            self.assertEqual(
                result.dependency_security_context.resolver_observation_count,
                resolver_before,
            )
            self.assertEqual(
                fixture._serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ),
                durable_before,
            )
        finally:
            result.close()

    def test_dependency_pure_reuse_rejects_same_bytes_cold_replacement(self) -> None:
        from graph_engineering.application import dependency_security

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=self.matrix())
        result = fixture.run_serial_profile_binding(
            api4=api4, plan=plan, profile_id="dependency-security",
            column="normal", disposition="R", quiescent=False,
        )
        authority = None
        seal = None
        try:
            factory, observation = result.authority._dependency_security
            authority = dependency_security.DependencySecurityObservationReopenAuthority.from_current(
                factory, observation,
            )
            seal = authority.seal_current(factory, observation)
            # Keep the repository live while the dependency capability is sealed.
            before = fixture._serial_state_signature(result.probe, result.target, real_e2e=False)
            path = seal._paths[0]
            body = path.read_bytes()
            backup = path.with_name(path.name + ".pure-reuse-original")
            with dependency_security._dependency_pure_operation() as operation:
                dependency_security._bootstrap_projection()
                dependency_security._graph_installation_projection()
                self.assertEqual(set(operation.entries), {"bootstrap", "graph"})
                capability = seal._capability
                object.__setattr__(seal, "_capability", object())
                try:
                    with self.assertRaisesRegex(dependency_security.DependencySecurityError, "seal is foreign"):
                        authority.rehydrate_current(
                            seal, repository=result.probe.repository,
                            category_application=result.application,
                        )
                finally:
                    object.__setattr__(seal, "_capability", capability)
                os.replace(path, backup)
                try:
                    path.write_bytes(body)
                    self.assertNotEqual(path.stat().st_ino, backup.stat().st_ino)
                    with self.assertRaisesRegex(dependency_security.DependencySecurityError, "reopened projection changed"):
                        authority.rehydrate_current(
                            seal, repository=result.probe.repository,
                            category_application=result.application,
                        )
                finally:
                    path.unlink(missing_ok=True)
                    os.replace(backup, path)
                self.assertEqual((authority.state, authority.generation), ("QUIESCED", 0))
                # A restored source must really reopen, excluding a closed-runtime
                # error as a false positive for either negative assertion.
                reopened_factory, reopened = authority.rehydrate_current(
                    seal, repository=result.probe.repository,
                    category_application=result.application,
                )
                self.assertIs(reopened_factory.require_current(reopened), reopened)
                seal = authority.seal_current(reopened_factory, reopened)
            self.assertEqual(operation.entries, {})
            self.assertEqual((authority.state, authority.generation), ("QUIESCED", 1))
            self.assertEqual(fixture._serial_state_signature(
                result.probe, result.target, real_e2e=False,
            ), before)
        finally:
            try:
                if authority is not None:
                    authority.revoke(seal if authority.state == "QUIESCED" else None)
            finally:
                result.close()
        self.assertEqual(runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0)

    def test_dependency_pure_reuse_positive_issue(self) -> None:
        self._dependency_routes_reopen_all_four_phases(
            (("normal", "normal", None, "P"),), stop_after_issue=True,
        )

    def test_dependency_pure_reuse_positive_live_gate(self) -> None:
        api, coverage, matrix, profile, overlay = fixture._verified_runner_contracts("dependency-security")
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        started = time.monotonic()
        result = fixture.run_serial_profile_binding(
            api4=api4, plan=plan, profile_id="dependency-security",
            column="normal", disposition="P", quiescent=False,
        )
        factory = None
        try:
            self.assertIsNone(result.binding_lifecycle)
            before = (result.target.path.read_bytes(), result.target.mutation_count)
            context = result.dependency_security_context
            print(f"live-P setup {time.monotonic() - started:.3f}s", flush=True)
            observation = result.observe_current()
            factory = api.CoverageRecordFactory(
                execution_authority=result.authority, coverage_policy=coverage,
            )
            record = factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
            print(f"live-P record {time.monotonic() - started:.3f}s", flush=True)
            decision = api.ReleaseCoverageGate.evaluate(
                matrix, coverage_records=(record,), coverage_factory=factory,
            )
            self.assertFalse(decision.passed)  # One record cannot satisfy the whole matrix.
            self.assertEqual((result.target.path.read_bytes(), result.target.mutation_count), before)
            self.assertEqual(context.resolver_observation_count, 1)
            self.assertEqual(context.rehydration_count, 0)
        finally:
            if factory is not None:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0)
        print(f"live-P cleanup {time.monotonic() - started:.3f}s", flush=True)

    def test_dependency_pure_reuse_normal_rejection_all_phases(self) -> None:
        self._dependency_routes_reopen_all_four_phases((("normal", "normal", None, "R"),))

    def test_dependency_pure_reuse_scenario_rejection_all_phases(self) -> None:
        self._dependency_routes_reopen_all_four_phases((("vulnerable-graph", None, "vulnerable-graph", "R"),))

    def test_f1_generic_dependency_routes_reopen_all_four_phases(self) -> None:
        routes = (
            ("mandatory-artifacts", "artifacts", None, "P"),
            ("mandatory-artifacts", "artifacts", None, "R"),
            ("vulnerable-graph", None, "vulnerable-graph", "P"),
            ("vulnerable-graph", None, "vulnerable-graph", "R"),
            ("mandatory-real-e2e", "real-e2e", None, "P"),
            ("mandatory-real-e2e", "real-e2e", None, "R"),
        )
        self._dependency_routes_reopen_all_four_phases(routes)

    def _dependency_routes_reopen_all_four_phases(self, routes, *, stop_after_issue=False) -> None:
        import graph_engineering
        from graph_engineering.application import dependency_security

        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("dependency-security")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        phase_parses = {}

        def observe_parse(slot, parser):
            def parse(*args):
                operation = getattr(dependency_security._pure_projection_local, "current", None)
                if operation is not None:
                    counts = phase_parses.setdefault(operation, {})
                    counts[slot] = counts.get(slot, 0) + 1
                return parser(*args)
            return parse

        parser = graph_engineering._dependency_advisory_preflight_observation
        with mock.patch.object(
            graph_engineering,
            "_dependency_advisory_preflight_observation",
            wraps=parser,
        ) as parser_reread, mock.patch.object(
            dependency_security, "_parse_bootstrap_projection",
            side_effect=observe_parse("bootstrap", dependency_security._parse_bootstrap_projection),
        ) as bootstrap_parse, mock.patch.object(
            dependency_security, "_parse_graph_installation_projection",
            side_effect=observe_parse("graph", dependency_security._parse_graph_installation_projection),
        ) as graph_parse:
            for route, column, scenario_id, disposition in routes:
                with self.subTest(route=route, disposition=disposition):
                    started = time.monotonic()
                    result = (
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="dependency-security",
                            column=column,
                            disposition=disposition,
                            quiescent=True,
                        )
                        if column is not None
                        else fixture.run_serial_scenario_binding(
                            api4=api4,
                            plan=plan,
                            scenario_id=scenario_id,
                            disposition=disposition,
                            quiescent=True,
                        )
                    )
                    print(f"{route}-{disposition} setup {time.monotonic() - started:.3f}s", flush=True)
                    record_factory = None
                    closed = False
                    try:
                        reopen = result.dependency_reopen_authority
                        context = result.dependency_security_context
                        self.assertIs(
                            type(reopen),
                            dependency_security.
                            DependencySecurityObservationReopenAuthority,
                        )
                        self.assertEqual(
                            (reopen.state, reopen.generation), ("QUIESCED", 0),
                        )
                        parser_count = parser_reread.call_count
                        phase_parses.clear()
                        repository_bytes = self._private_tree_signature(
                            result.private_repository_root.root
                        )
                        if result.private_real_e2e_root is None:
                            state_after_execution = (
                                result.target.path.read_bytes(),
                                result.target.mutation_count,
                                result.target.query_count,
                                result.target._revision,
                            )
                            real_e2e_counts = None
                        else:
                            state_after_execution = None
                            real_e2e_root = result.private_real_e2e_root
                            real_e2e_counts = (
                                real_e2e_root.cumulative_mutation_count,
                                real_e2e_root.cumulative_launch_count,
                            )
                        observation = result.observe_current()
                        print(f"{route}-{disposition} issue {time.monotonic() - started:.3f}s", flush=True)
                        if not stop_after_issue:
                            record_factory = api.CoverageRecordFactory(
                                execution_authority=result.authority,
                                coverage_policy=coverage,
                            )
                            record = record_factory.issue_execution(
                                observation,
                                matrix=matrix,
                                profile=profile,
                                overlay=overlay,
                            )
                            decision = api.ReleaseCoverageGate.evaluate(
                                matrix,
                                coverage_records=(record,),
                                coverage_factory=record_factory,
                            )
                            self.assertFalse(decision.passed)
                            print(f"{route}-{disposition} gate {time.monotonic() - started:.3f}s", flush=True)
                        self.assertEqual(
                            (
                                result.binding_lifecycle.state,
                                result.binding_lifecycle.generation,
                                result.binding_lifecycle.expected_purpose,
                            ),
                            ("QUIESCED", 1, "use") if stop_after_issue else ("QUIESCED", 4, None),
                        )
                        self.assertEqual(
                            (reopen.state, reopen.generation,
                             reopen.rehydration_count),
                            ("QUIESCED", 1, 1) if stop_after_issue else ("QUIESCED", 4, 4),
                        )
                        self.assertGreaterEqual(
                            parser_reread.call_count - parser_count, 2 if stop_after_issue else 8,
                        )
                        # Each real phase starts fresh, while repeated pure reads
                        # within that phase reuse only their parsed projections.
                        self.assertEqual(len(phase_parses), 1 if stop_after_issue else 4)
                        for operation, counts in phase_parses.items():
                            self.assertEqual(counts["bootstrap"], 1)
                            self.assertTrue(set(counts) <= {"bootstrap", "graph"})
                            self.assertTrue(all(value == 1 for value in counts.values()))
                            self.assertEqual(operation.entries, {})
                        self.assertIsNone(getattr(
                            dependency_security._pure_projection_local, "current", None,
                        ))
                        self.assertEqual(context.resolver_observation_count, 1)
                        self.assertEqual(context.rehydration_count, 0)
                        self.assertEqual(
                            self._private_tree_signature(
                                result.private_repository_root.root
                            ),
                            repository_bytes,
                        )
                        if result.private_real_e2e_root is None:
                            self.assertEqual(
                                (
                                    result.target.path.read_bytes(),
                                    result.target.mutation_count,
                                    result.target.query_count,
                                    result.target._revision,
                                ),
                                state_after_execution,
                            )
                        else:
                            self.assertEqual(
                                (
                                    real_e2e_root.cumulative_mutation_count,
                                    real_e2e_root.cumulative_launch_count,
                                ),
                                real_e2e_counts,
                            )
                            self.assertEqual(
                                real_e2e_root.phase_mutation_deltas,
                                {
                                    "issue": 0, "use": 0,
                                    "precommit": 0, "gate": 0,
                                },
                            )
                            self.assertEqual(
                                result.private_real_e2e_root.phase_launch_deltas,
                                {
                                    "issue": 0, "use": 0,
                                    "precommit": 0, "gate": 0,
                                },
                            )
                        if disposition == "R":
                            self.assertEqual(result.state_after, result.state_before)
                        if record_factory is not None:
                            fixture.abort_uncommitted_coverage_factory(record_factory)
                            closed = True
                            self.assertEqual(
                                result.binding_lifecycle.state,
                                "PERMANENTLY_CLOSED",
                            )
                            self.assertEqual(reopen.state, "TERMINAL")
                    finally:
                        if record_factory is not None and not closed:
                            fixture.abort_uncommitted_coverage_factory(
                                record_factory
                            )
                        result.close()
                    print(f"{route}-{disposition} cleanup {time.monotonic() - started:.3f}s", flush=True)
                    self.assertEqual(
                        runtime_fixture.PrivateBindingReopenPort.
                        active_handle_count(),
                        0,
                    )

    def test_f1_generic_dependency_failed_runtime_rebind_requiesces(self) -> None:
        from graph_engineering.core.profile_coverage import BindingLifecycleError

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        for column in ("artifacts", "real-e2e"):
            with self.subTest(column=column):
                result = fixture.run_serial_profile_binding(
                    api4=api4,
                    plan=plan,
                    profile_id="dependency-security",
                    column=column,
                    disposition="P",
                    quiescent=True,
                )
                reopen = result.dependency_reopen_authority
                authority_type = type(result.authority)
                original = authority_type._rebind_binding_runtime

                def fail_after_rebind(self, **kwargs):  # type: ignore[no-untyped-def]
                    original(self, **kwargs)
                    raise AssertionError("injected post-rehydrate rebind failure")

                try:
                    repository_before = self._private_tree_signature(
                        result.private_repository_root.root
                    )
                    if result.private_real_e2e_root is None:
                        target_before = (
                            result.target.path.read_bytes(),
                            result.target.mutation_count,
                            result.target.query_count,
                            result.target._revision,
                        )
                        real_e2e_before = None
                    else:
                        real_e2e_root = result.private_real_e2e_root
                        target_before = None
                        real_e2e_before = (
                            real_e2e_root.cumulative_mutation_count,
                            real_e2e_root.cumulative_launch_count,
                        )
                    with mock.patch.object(
                        authority_type,
                        "_rebind_binding_runtime",
                        fail_after_rebind,
                    ), self.assertRaisesRegex(
                        BindingLifecycleError,
                        "binding lifecycle phase failed closed",
                    ) as raised:
                        result.observe_current()
                    self.assertIs(type(raised.exception.__cause__), AssertionError)
                    self.assertEqual(
                        str(raised.exception.__cause__),
                        "injected post-rehydrate rebind failure",
                    )
                    self.assertEqual(
                        (reopen.state, reopen.generation), ("QUIESCED", 1),
                    )
                    self.assertIsNotNone(result.dependency_reopen_seal)
                    self.assertIsNone(result.private_shared_runtime)
                    self.assertEqual(
                        self._private_tree_signature(
                            result.private_repository_root.root
                        ),
                        repository_before,
                    )
                    if result.private_real_e2e_root is None:
                        self.assertEqual(
                            (
                                result.target.path.read_bytes(),
                                result.target.mutation_count,
                                result.target.query_count,
                                result.target._revision,
                            ),
                            target_before,
                        )
                    else:
                        self.assertEqual(
                            (
                                real_e2e_root.cumulative_mutation_count,
                                real_e2e_root.cumulative_launch_count,
                            ),
                            real_e2e_before,
                        )
                    self.assertEqual(
                        runtime_fixture.PrivateBindingReopenPort.
                        active_handle_count(),
                        0,
                    )
                finally:
                    result.close()
                self.assertEqual(reopen.state, "TERMINAL")

    def test_multi_target_rejection_receipt_omission_cannot_issue_observation(self) -> None:
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=self.matrix())
        result = fixture.run_serial_scenario_binding(
            api4=api4, plan=plan,
            scenario_id=fixture.NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
            disposition="R", quiescent=True,
        )
        try:
            context = result.scenario_truth_context
            original = context.receipts
            context.receipts = ()
            try:
                with self.assertRaises(api4.ProfileCoverageError):
                    result.observe_current()
            finally:
                context.receipts = original
            self.assertEqual(result.state_after, result.state_before)
            self.assertEqual(result.target.mutation_count, 0)
        finally:
            result.close()

    def test_rejection_closure_tamper_fails_at_all_coverage_phases(self) -> None:
        api, coverage, matrix, profile, overlay = fixture._verified_runner_contracts("new-feature")
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        fd_before = len(os.listdir("/dev/fd"))
        for phase in ("issue", "use", "precommit", "gate"):
            with self.subTest(phase=phase):
                result = fixture.run_serial_scenario_binding(
                    api4=api4, plan=plan,
                    scenario_id=fixture.NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
                    disposition="R",
                )
                factory = None
                try:
                    context = result.scenario_truth_context
                    original = context.receipts
                    evidence = context.evidence
                    original_projection = evidence.projection
                    target = pathlib.Path(original[0].root_path) / original[0].projection["request"]["targets"][0]["path_id"]
                    target_body = target.read_bytes()
                    if phase != "issue":
                        observation = result.observe_current()
                        factory = api.CoverageRecordFactory(
                            execution_authority=result.authority, coverage_policy=coverage,
                        )
                    if phase == "gate":
                        record = factory.issue_execution(
                            observation, matrix=matrix, profile=profile, overlay=overlay,
                        )
                    for attack in ("omission", "reorder", "clone", "replacement", "false-boolean", "foreign-binding", "stale-target"):
                        with self.subTest(attack=attack):
                            def corrupt() -> None:
                                if attack == "omission": context.receipts = ()
                                elif attack == "reorder": context.receipts = original[::-1]
                                elif attack == "clone": context.receipts = (copy.copy(original[0]), *original[1:])
                                elif attack == "replacement": context.receipts = (object(), *original[1:])
                                elif attack == "false-boolean": object.__setattr__(original[0], "mutation_count", False)
                                elif attack == "foreign-binding":
                                    from graph_engineering.core.contracts.immutable import freeze, thaw
                                    body = thaw(original_projection)
                                    body["test_id"] = "foreign-test"
                                    object.__setattr__(evidence, "projection", freeze(body))
                                else: target.write_bytes(target_body + b"stale")
                            issued_before = None if factory is None else dict(factory._CoverageRecordFactory__issued)
                            try:
                                if phase == "precommit":
                                    registration_type = type(result.authority._coverage_registration)
                                    original_require = registration_type.require_observation
                                    def require(registration, authority, current, *, purpose="use"):
                                        if purpose == "precommit": corrupt()
                                        return original_require(registration, authority, current, purpose=purpose)
                                    with mock.patch.object(registration_type, "require_observation", new=require), self.assertRaises(api.ProfileContractError):
                                        factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
                                else:
                                    corrupt()
                                    with self.assertRaises((api4.ProfileCoverageError, api.ProfileContractError)):
                                        if phase == "issue": result.observe_current()
                                        elif phase == "use": factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
                                        else: api.ReleaseCoverageGate.evaluate(matrix, coverage_records=(record,), coverage_factory=factory)
                            finally:
                                context.receipts = original
                                object.__setattr__(evidence, "projection", original_projection)
                                object.__setattr__(original[0], "mutation_count", 0)
                                target.write_bytes(target_body)
                            if factory is not None:
                                self.assertEqual(factory._CoverageRecordFactory__issued, issued_before)
                            self.assertEqual(result.target.mutation_count, 0)
                            self.assertEqual(result.state_after, result.state_before)
                            self.assertEqual(fixture._serial_state_signature(result.probe, result.target, real_e2e=False), result.state_before)
                            self.assertTrue(all(receipt.mutation_count == 0 for receipt in context.receipts))
                finally:
                    if factory is not None: fixture.abort_uncommitted_coverage_factory(factory)
                    result.close()
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_multi_target_p_r_are_distinct_and_assessment_1_3_is_current(self) -> None:
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        self.assertEqual(len(plan.bindings), 244)
        self.assertEqual(len(plan.oracle_bindings), 122)
        positive = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id=fixture.NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
            disposition="P",
        )
        rejected = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id=fixture.NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
            disposition="R",
        )
        try:
            assessment = positive.application.current_assessment(
                positive.probe.task_id,
                expected_profile_id="new-feature",
            )
            self.assertEqual(assessment.schema_version, "1.3.0")
            self.assertIsNotNone(assessment.scenario_truth_projection)
            self.assertIsNone(assessment.performance_evidence_projection)
            self.assertIsNone(assessment.migration_rehearsal_projection)
            self.assertIsNone(assessment.dependency_graph_projection)
            self.assertEqual(
                positive.scenario_truth_context.observer.mutation_count, 2
            )
            self.assertEqual(positive.execution.result, "COMPLETED")
            self.assertEqual(rejected.execution.result, "EXPECTED_REJECTION")
            self.assertNotEqual(positive.probe.task_id, rejected.probe.task_id)
            rejection = rejected.scenario_truth_context
            self.assertIsNotNone(rejection)
            self.assertIsNot(
                positive.scenario_truth_context.registry_factory,
                rejection.registry_factory,
            )
            self.assertEqual(rejection.task_id, rejected.probe.task_id)
            self.assertEqual(rejection.test_id, rejected.execution.test_id)
            self.assertEqual(rejection.oracle_digest, rejected.execution.oracle_digest)
            self.assertEqual(rejected.execution.typed_evidence_object_digest, rejection.evidence.evidence_digest)
            self.assertIsNotNone(rejected.execution.typed_evidence_object_digest)
            receipts_before = rejection.receipts
            issued_before = dict(rejected.authority._ProfileCoverageAuthority__issued)
            oracle_type = type(rejected.authority)
            original_oracle = oracle_type._isolated_rejection_oracle
            def corrupt_before_issuance(authority, **kwargs):
                digest = original_oracle(authority, **kwargs)
                rejection.receipts = ()
                return digest
            try:
                with mock.patch.object(oracle_type, "_isolated_rejection_oracle", new=corrupt_before_issuance), self.assertRaises(api4.ProfileCoverageError):
                    rejected.authority.execute_rejection(
                        rejected.test_id, candidate=rejected.candidate,
                        observer=rejected.target, scenario_rejection_evidence=rejection.evidence,
                    )
            finally:
                rejection.receipts = receipts_before
            self.assertEqual(rejected.authority._ProfileCoverageAuthority__issued, issued_before)
            with mock.patch.object(rejected.authority, "_ProfileCoverageAuthority__scenario_rejection_factory", None), self.assertRaises(api4.ProfileCoverageError):
                rejected.authority.execute_rejection(
                    rejected.test_id, candidate=rejected.candidate,
                    observer=rejected.target, scenario_rejection_evidence=None,
                )
            for evidence in (None, positive.scenario_truth_context.evidence, copy.copy(rejection.evidence)):
                with self.subTest(substitution=type(evidence).__name__), self.assertRaises(api4.ProfileCoverageError):
                    rejected.authority.execute_rejection(
                        rejected.test_id, candidate=rejected.candidate,
                        observer=rejected.target, scenario_rejection_evidence=evidence,
                    )
            from graph_engineering.core.scenario_truth import ScenarioTruthError
            for receipts in ((), rejection.receipts[::-1],
                             (copy.copy(rejection.receipts[0]), *rejection.receipts[1:])):
                with self.assertRaises(ScenarioTruthError):
                    rejection.registry_factory.bind_rejections(
                        receipts, test_id=rejection.test_id, oracle_digest=rejection.oracle_digest,
                    )
            self.assertEqual(
                len({receipt.root_path for receipt in rejection.receipts}),
                8,
            )
            self.assertNotIn(
                str(positive.scenario_truth_context.temporary_root.name),
                {receipt.root_path for receipt in rejection.receipts},
            )
            self.assertEqual(
                tuple(receipt.attack_id for receipt in rejection.receipts),
                (
                    "missing-role",
                    "extra-role",
                    "aliased-role",
                    "one-target-only",
                    "cross-branch",
                    "partial-success",
                    "stale-target",
                    "wrong-rollback",
                ),
            )
            self.assertTrue(all(receipt.mutation_count == 0 for receipt in rejection.receipts))
            self.assertTrue(all(receipt.request_unchanged for receipt in rejection.receipts))
            self.assertTrue(all(receipt.target_bytes_unchanged for receipt in rejection.receipts))
            durable_before_restart = fixture._serial_state_signature(
                positive.probe, positive.target, real_e2e=False,
            )
            restarted = positive.application.restart(
                positive.probe.task_application,
                positive.probe.runtime,
                positive.target,
            )
            restored = restarted.current_assessment(
                positive.probe.task_id,
                expected_profile_id="new-feature",
            )
            self.assertIsNotNone(restored.scenario_truth_projection)
            self.assertEqual(
                positive.scenario_truth_context.observer.mutation_count, 2
            )
            self.assertEqual(
                fixture._serial_state_signature(
                    positive.probe, positive.target, real_e2e=False,
                ),
                durable_before_restart,
            )
        finally:
            positive.close()
            rejected.close()

    def test_refactor_p_r_bindings_are_current_and_fail_closed(self) -> None:
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("refactor-debt")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (244, 122))
        for scenario in fixture.REFACTOR_SCENARIO_IDS:
            for disposition in ("P", "R"):
                with self.subTest(scenario=scenario, disposition=disposition):
                    result = fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=scenario,
                        disposition=disposition,
                        quiescent=True,
                    )
                    record_factory = None
                    closed = False
                    try:
                        context = result.scenario_truth_context
                        lifecycle = result.binding_lifecycle
                        self.assertIsNotNone(context)
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation),
                            ("QUIESCED", 0),
                        )
                        if disposition == "P":
                            proof = context.evidence.to_dict()["refactor_proof"]
                            self.assertEqual(
                                tuple(
                                    row["gate_id"]
                                    for row in proof["gate_results"]
                                ),
                                tuple(
                                    context.observer._fixture_row[
                                        "refactor_contract"
                                    ]["gate_ids"]
                                ),
                            )
                            self.assertEqual(context.observer.mutation_count, 1)
                        else:
                            expected_attacks = context.registry_factory.rejection_attack_ids(
                                "refactor-debt", scenario,
                            )
                            self.assertEqual(
                                tuple(receipt.attack_id for receipt in context.receipts),
                                expected_attacks,
                            )
                            self.assertTrue(
                                all(receipt.mutation_count == 0 for receipt in context.receipts)
                            )
                            self.assertEqual(result.state_after, result.state_before)
                        observation = result.observe_current()
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation),
                            ("QUIESCED", 1),
                        )
                        record_factory = api.CoverageRecordFactory(
                            execution_authority=result.authority,
                            coverage_policy=coverage,
                        )
                        record = record_factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        decision = api.ReleaseCoverageGate.evaluate(
                            matrix,
                            coverage_records=(record,),
                            coverage_factory=record_factory,
                        )
                        self.assertFalse(decision.passed)
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation),
                            ("QUIESCED", 4),
                        )
                        fixture.abort_uncommitted_coverage_factory(record_factory)
                        closed = True
                        self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
                    finally:
                        if record_factory is not None and not closed:
                            fixture.abort_uncommitted_coverage_factory(record_factory)
                        result.close()

    def test_incident_response_p_r_bindings_are_current_and_fail_closed(
        self,
    ) -> None:
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("incident-response")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (244, 122))
        mandatory_recovery = next(
            row for row in plan.oracle_bindings
            if row["oracle_member"]
            == "config/test-oracles/profile-incident-response-recovery-v1.json"
        )
        self.assertEqual(
            mandatory_recovery["oracle_raw_sha256"],
            "6e223a032f5549ce5489bd11877ec1309c437cf858568539e437da694024527c",
        )
        for scenario in fixture.INCIDENT_SCENARIO_IDS:
            for disposition in ("P", "R"):
                with self.subTest(scenario=scenario, disposition=disposition):
                    result = fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=scenario,
                        disposition=disposition,
                        quiescent=True,
                    )
                    record_factory = None
                    closed = False
                    try:
                        context = result.scenario_truth_context
                        lifecycle = result.binding_lifecycle
                        self.assertIsNotNone(context)
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation),
                            ("QUIESCED", 0),
                        )
                        if disposition == "P":
                            projection = context.evidence.to_dict()
                            proof = projection["incident_proof"]
                            self.assertEqual(
                                tuple(row["gate_id"] for row in proof["gate_results"]),
                                tuple(
                                    context.observer._fixture_row[
                                        "incident_contract"
                                    ]["gate_ids"]
                                ),
                            )
                            if scenario == "unknown-effects":
                                self.assertEqual(context.observer.mutation_count, 0)
                                self.assertEqual(projection["ordered_transitions"], [])
                                self.assertEqual(proof["action_ids"], [])
                                self.assertTrue(proof["unknown_claim_retained"])
                                self.assertFalse(proof["service_restored"])
                            else:
                                self.assertEqual(context.observer.mutation_count, 1)
                        else:
                            expected_attacks = context.registry_factory.rejection_attack_ids(
                                "incident-response", scenario,
                            )
                            self.assertEqual(
                                tuple(receipt.attack_id for receipt in context.receipts),
                                expected_attacks,
                            )
                            self.assertTrue(
                                all(
                                    receipt.mutation_count == 0
                                    and receipt.request_unchanged
                                    and receipt.target_bytes_unchanged
                                    for receipt in context.receipts
                                )
                            )
                            self.assertEqual(result.state_after, result.state_before)
                        observation = result.observe_current()
                        record_factory = api.CoverageRecordFactory(
                            execution_authority=result.authority,
                            coverage_policy=coverage,
                        )
                        record = record_factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        decision = api.ReleaseCoverageGate.evaluate(
                            matrix,
                            coverage_records=(record,),
                            coverage_factory=record_factory,
                        )
                        self.assertFalse(decision.passed)
                        fixture.abort_uncommitted_coverage_factory(record_factory)
                        closed = True
                        self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
                    finally:
                        if record_factory is not None and not closed:
                            fixture.abort_uncommitted_coverage_factory(record_factory)
                        result.close()

    def test_refactor_proof_restores_from_cas_with_a_fresh_factory_without_replay(
        self,
    ) -> None:
        from graph_engineering.application.scenario_truth import (
            ScenarioTruthObservationFactory,
        )
        from graph_engineering.core.contracts.immutable import thaw

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix(),
        )
        result = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id="behavior-characterization",
            disposition="P",
        )
        restarted_factory = None
        try:
            durable_before = fixture._serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            original_projection = result.scenario_truth_context.evidence.to_dict()
            with mock.patch.object(
                ScenarioTruthObservationFactory,
                "execute",
                side_effect=AssertionError("refactor replay is forbidden"),
            ):
                restarted = result.application.restart(
                    result.probe.task_application,
                    result.probe.runtime,
                    result.target,
                )
                restarted_factory = restarted._oracle._scenario_truth_factory
                restored = restarted.current_assessment(
                    result.probe.task_id,
                    expected_profile_id="refactor-debt",
                )
            self.assertIsNotNone(restarted_factory)
            self.assertIsNot(
                restarted_factory,
                result.scenario_truth_context.registry_factory,
            )
            self.assertEqual(
                thaw(restored.scenario_truth_projection),
                original_projection,
            )
            self.assertEqual(
                len(restarted_factory._restored_evidence),
                2,
            )
            self.assertEqual(
                fixture._serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ),
                durable_before,
            )
            self.assertEqual(result.scenario_truth_context.observer.mutation_count, 1)
        finally:
            if restarted_factory is not None:
                restarted_factory.close()
            result.close()

    def test_representative_binding_is_quiesced_before_coverage_use(self) -> None:
        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=matrix
        )
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="new-feature",
            column="normal",
            disposition="R",
            quiescent=True,
        )
        factory = None
        factory_closed = False
        try:
            lifecycle = getattr(result, "binding_lifecycle", None)
            self.assertIsNotNone(lifecycle)
            self.assertEqual(lifecycle.state, "QUIESCED")
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
            )
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                0,
            )
            self.assertEqual(result.state_after, result.state_before)
            self.assertEqual(result.target.mutation_count, 0)
            observation = result.observe_current()
            self.assertEqual(observation.test_id, result.test_id)
            self.assertEqual(lifecycle.state, "QUIESCED")
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
            )
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                0,
            )
            self.assertEqual(result.state_after, result.state_before)
            self.assertEqual(result.target.mutation_count, 0)
            self.assertEqual((lifecycle.generation, lifecycle.expected_purpose), (1, "use"))
            factory = api.CoverageRecordFactory(
                execution_authority=result.authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            self.assertEqual(
                (lifecycle.state, lifecycle.generation, lifecycle.expected_purpose),
                ("QUIESCED", 3, "gate"),
            )
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation, lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            factory_closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        finally:
            if factory is not None and not factory_closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_precommit_and_gate_closure_tamper_are_zero_write(self) -> None:
        import graph_engineering

        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        installed = list(graph_engineering._profile_coverage_installation_resources())
        installed[0] += b" "
        replacement = tuple(installed)

        for attack_phase in ("precommit", "gate"):
            with self.subTest(phase=attack_phase):
                result = fixture.run_serial_profile_binding(
                    api4=api4,
                    plan=plan,
                    profile_id="new-feature",
                    column="normal",
                    disposition="R",
                    quiescent=True,
                )
                factory = None
                try:
                    lifecycle = result.binding_lifecycle
                    observation = result.observe_current()
                    factory = api.CoverageRecordFactory(
                        execution_authority=result.authority,
                        coverage_policy=coverage,
                    )
                    if attack_phase == "precommit":
                        registration_type = type(
                            result.authority._coverage_registration
                        )
                        original = registration_type.require_observation

                        def require_observation(
                            registration: object,
                            authority: object,
                            current: object,
                            *,
                            purpose: str = "use",
                        ) -> object:
                            if purpose == "precommit":
                                with mock.patch.object(
                                    graph_engineering,
                                    "_profile_coverage_installation_resources",
                                    return_value=replacement,
                                ):
                                    return original(
                                        registration,
                                        authority,
                                        current,
                                        purpose=purpose,
                                    )
                            return original(
                                registration,
                                authority,
                                current,
                                purpose=purpose,
                            )

                        with mock.patch.object(
                            registration_type,
                            "require_observation",
                            new=require_observation,
                        ), self.assertRaises(api.ProfileContractError):
                            factory.issue_execution(
                                observation,
                                matrix=matrix,
                                profile=profile,
                                overlay=overlay,
                            )
                        self.assertEqual(
                            len(factory._CoverageRecordFactory__issued), 0
                        )
                        self.assertEqual(
                            factory._CoverageRecordFactory__candidate_generation,
                            0,
                        )
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation,
                             lifecycle.expected_purpose),
                            ("QUIESCED", 2, "precommit"),
                        )
                    else:
                        record = factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        issued_before = dict(
                            factory._CoverageRecordFactory__issued
                        )
                        generation_before = (
                            factory._CoverageRecordFactory__candidate_generation
                        )
                        with mock.patch.object(
                            graph_engineering,
                            "_profile_coverage_installation_resources",
                            return_value=replacement,
                        ), self.assertRaises(api.ProfileContractError):
                            api.ReleaseCoverageGate.evaluate(
                                matrix,
                                coverage_records=(record,),
                                coverage_factory=factory,
                            )
                        self.assertEqual(
                            factory._CoverageRecordFactory__issued,
                            issued_before,
                        )
                        self.assertEqual(
                            factory._CoverageRecordFactory__candidate_generation,
                            generation_before,
                        )
                        self.assertEqual(
                            (lifecycle.state, lifecycle.generation,
                             lifecycle.expected_purpose),
                            ("QUIESCED", 3, "gate"),
                        )
                    self.assertEqual(
                        runtime_fixture.PrivateBindingReopenPort.active_handle_count(),
                        0,
                    )
                    self.assertEqual(
                        runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                        0,
                    )
                    self.assertEqual(result.state_after, result.state_before)
                    self.assertEqual(result.target.mutation_count, 0)
                finally:
                    if factory is not None:
                        fixture.abort_uncommitted_coverage_factory(factory)
                    result.close()
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_performance_positive_reopens_without_measurement_replay(self) -> None:
        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("performance")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="performance",
            column="normal",
            disposition="P",
            quiescent=True,
        )
        factory = None
        factory_closed = False
        try:
            lifecycle = result.binding_lifecycle
            launches = result.performance_context.cumulative_launch_count
            self.assertGreater(launches, 0)
            self.assertEqual(
                tuple(len(row) for row in result.performance_context.measurement_durations_ns),
                (5, 5, 5),
            )
            self.assertTrue(all(
                duration > 0
                for row in result.performance_context.measurement_durations_ns
                for duration in row
            ))
            observation = result.observe_current()
            factory = api.CoverageRecordFactory(
                execution_authority=result.authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            self.assertEqual(
                result.performance_context.cumulative_launch_count, launches,
            )
            self.assertEqual(
                result.performance_context.phase_launch_deltas,
                {"issue": 0, "use": 0, "precommit": 0, "gate": 0},
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            factory_closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        finally:
            if factory is not None and not factory_closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
            0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_real_e2e_positive_reopens_without_action_or_command_replay(self) -> None:
        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="new-feature",
            column="real-e2e",
            disposition="P",
            quiescent=True,
        )
        factory = None
        factory_closed = False
        try:
            lifecycle = result.binding_lifecycle
            tool_root = result.private_real_e2e_root
            identity = result.binding_identity_projection()
            self.assertIsNotNone(lifecycle)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 0, "issue"),
            )
            self.assertEqual(tool_root.cumulative_mutation_count, 1)
            self.assertEqual(tool_root.cumulative_launch_count, 1)
            self.assertEqual(identity["task"], result.probe.task_id)
            self.assertEqual(
                identity["branch_ref"][1],
                result.probe.real_e2e_authority._execution["after"]["head_ref"],
            )
            foreign_identity = tool_root.binding_identity_projection()
            foreign_identity["task"] = "task:foreign"
            lifecycle_before = (
                lifecycle.state, lifecycle.generation,
                lifecycle.expected_purpose,
            )
            with self.assertRaisesRegex(
                AssertionError, "binding identity changed",
            ):
                tool_root.seal_binding_identity(foreign_identity)
            self.assertEqual(
                tool_root.binding_identity_projection(), identity,
            )
            self.assertEqual(
                (
                    lifecycle.state, lifecycle.generation,
                    lifecycle.expected_purpose,
                ),
                lifecycle_before,
            )
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
            )
            observation = result.observe_current()
            factory = api.CoverageRecordFactory(
                execution_authority=result.authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            self.assertEqual(result.binding_identity_projection(), identity)
            self.assertEqual(
                tool_root.phase_mutation_deltas,
                {"issue": 0, "use": 0, "precommit": 0, "gate": 0},
            )
            self.assertEqual(
                tool_root.phase_launch_deltas,
                {"issue": 0, "use": 0, "precommit": 0, "gate": 0},
            )
            self.assertEqual(
                set(tool_root.observation_receipts),
                {"initial", "issue", "use", "precommit", "gate"},
            )
            for receipts in tool_root.observation_receipts.values():
                revisions = [revision for revision, _digest in receipts]
                digests = [digest for _revision, digest in receipts]
                self.assertEqual(revisions, sorted(set(revisions)))
                self.assertEqual(len(digests), len(set(digests)))
            receipt_copy = tool_root.observation_receipts
            receipt_copy["issue"] = ()
            self.assertTrue(tool_root.observation_receipts["issue"])
            fixture.abort_uncommitted_coverage_factory(factory)
            factory_closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        finally:
            if factory is not None and not factory_closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
            0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_ordinary_positive_and_rejection_use_distinct_quiescent_roots(self) -> None:
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        identities: list[dict[str, object]] = []
        for disposition in ("P", "R"):
            with self.subTest(disposition=disposition):
                result = fixture.run_serial_profile_binding(
                    api4=api4,
                    plan=plan,
                    profile_id="new-feature",
                    column="normal",
                    disposition=disposition,
                    quiescent=True,
                )
                factory = None
                closed = False
                try:
                    identities.append(result.binding_identity_projection())
                    observation = result.observe_current()
                    factory = api.CoverageRecordFactory(
                        execution_authority=result.authority,
                        coverage_policy=coverage,
                    )
                    record = factory.issue_execution(
                        observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    decision = api.ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(record,),
                        coverage_factory=factory,
                    )
                    self.assertFalse(decision.passed)
                    self.assertEqual(
                        (
                            result.binding_lifecycle.state,
                            result.binding_lifecycle.generation,
                            result.binding_lifecycle.expected_purpose,
                        ),
                        ("QUIESCED", 4, None),
                    )
                    if disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        self.assertEqual(result.target.mutation_count, 0)
                    fixture.abort_uncommitted_coverage_factory(factory)
                    closed = True
                    self.assertEqual(
                        result.binding_lifecycle.state, "PERMANENTLY_CLOSED",
                    )
                finally:
                    if factory is not None and not closed:
                        fixture.abort_uncommitted_coverage_factory(factory)
                    result.close()
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.active_handle_count(),
                    0,
                )
        self.assertEqual(len(identities), 2)
        for dimension in (
            "repository_root", "task", "target", "branch_ref",
            "action_root", "command_root",
        ):
            self.assertNotEqual(
                identities[0][dimension], identities[1][dimension],
                dimension,
            )
        self.assertEqual(
            len({tuple(
                repr(identity[dimension])
                for dimension in (
                    "repository_root", "task", "target", "branch_ref",
                    "action_root", "command_root",
                )
            ) for identity in identities}),
            2,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.maximum_active_reopened_binding_count(),
            1,
        )

    def test_multi_target_positive_uses_quiescent_binding_lifecycle(self) -> None:
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        identities = []
        for disposition in ("P", "R"):
            with self.subTest(disposition=disposition):
                result = fixture.run_serial_scenario_binding(
                    api4=api4,
                    plan=plan,
                    scenario_id=fixture.NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
                    disposition=disposition,
                    quiescent=True,
                )
                factory = None
                closed = False
                try:
                    lifecycle = result.binding_lifecycle
                    identities.append(result.binding_identity_projection())
                    self.assertEqual(
                        (lifecycle.state, lifecycle.generation,
                         lifecycle.expected_purpose),
                        ("QUIESCED", 0, "issue"),
                    )
                    scenario_marker = (
                        result.scenario_truth_context.observer.mutation_count
                        if disposition == "P"
                        else tuple(result.scenario_truth_context.receipts)
                    )
                    observation = result.observe_current()
                    factory = api.CoverageRecordFactory(
                        execution_authority=result.authority,
                        coverage_policy=coverage,
                    )
                    record = factory.issue_execution(
                        observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    decision = api.ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(record,),
                        coverage_factory=factory,
                    )
                    self.assertFalse(decision.passed)
                    self.assertEqual(
                        (lifecycle.state, lifecycle.generation,
                         lifecycle.expected_purpose),
                        ("QUIESCED", 4, None),
                    )
                    self.assertEqual(
                        (
                            result.scenario_truth_context.observer.mutation_count
                            if disposition == "P"
                            else tuple(result.scenario_truth_context.receipts)
                        ),
                        scenario_marker,
                    )
                    if disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                    fixture.abort_uncommitted_coverage_factory(factory)
                    closed = True
                    self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
                finally:
                    if factory is not None and not closed:
                        fixture.abort_uncommitted_coverage_factory(factory)
                    result.close()
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.active_handle_count(),
                    0,
                )
        for dimension in (
            "repository_root", "task", "target", "branch_ref",
            "action_root", "command_root",
        ):
            self.assertEqual(
                len({repr(identity[dimension]) for identity in identities}), 2,
                dimension,
            )

    def test_hotfix_guarded_p_r_quiescent_lifecycle_and_zero_replay(self):
        from graph_engineering.application.scenario_truth import ScenarioTruthObservationFactory
        from graph_engineering.core.scenario_truth import ScenarioTruthError
        api, coverage, matrix, profile, overlay = fixture._verified_runner_contracts("hotfix")
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (244, 122))
        identities = []
        for scenario in fixture.HOTFIX_GUARDED_SCENARIO_IDS:
            for disposition in ("P", "R"):
                with self.subTest(scenario=scenario, disposition=disposition):
                    result = fixture.run_serial_scenario_binding(api4=api4, plan=plan,
                        scenario_id=scenario, disposition=disposition, quiescent=True)
                    factory = None
                    try:
                        context = result.scenario_truth_context
                        identities.append(result.binding_identity_projection())
                        lifecycle = result.binding_lifecycle
                        self.assertEqual((lifecycle.state, lifecycle.generation), ("QUIESCED", 0))
                        if disposition == "P":
                            projection = context.evidence.to_dict()
                            self.assertEqual(projection["execution_proof"]["baseline"]["binding"]["task_id"], result.probe.task_id)
                            self.assertEqual(context.observer.mutation_count, 1)
                        else:
                            self.assertEqual(result.execution.typed_evidence_object_digest, context.evidence.evidence_digest)
                            expected = context.registry_factory.rejection_attack_ids("hotfix", scenario)
                            self.assertEqual(tuple(r.attack_id for r in context.receipts), expected)
                            self.assertEqual(len({r.root_path for r in context.receipts}), len(expected))
                            self.assertTrue(all(r.mutation_count == 0 for r in context.receipts))
                            self.assertEqual(result.state_after, result.state_before)
                            for receipts in ((), context.receipts[::-1],
                                    (copy.copy(context.receipts[0]), *context.receipts[1:])):
                                with self.assertRaises(ScenarioTruthError):
                                    context.registry_factory.bind_rejections(receipts, test_id=context.test_id,
                                        oracle_digest=context.oracle_digest)
                        with mock.patch.object(ScenarioTruthObservationFactory, "execute", side_effect=AssertionError("patch replay")):
                            observed = result.observe_current()
                            factory = api.CoverageRecordFactory(execution_authority=result.authority, coverage_policy=coverage)
                            record = factory.issue_execution(observed, matrix=matrix, profile=profile, overlay=overlay)
                            decision = api.ReleaseCoverageGate.evaluate(matrix, coverage_records=(record,), coverage_factory=factory)
                        self.assertFalse(decision.passed)
                        self.assertEqual((lifecycle.state, lifecycle.generation, lifecycle.expected_purpose), ("QUIESCED", 4, None))
                        fixture.abort_uncommitted_coverage_factory(factory)
                        factory = None
                        self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
                    finally:
                        if factory is not None: fixture.abort_uncommitted_coverage_factory(factory)
                        result.close()
                    self.assertEqual(runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0)
        for dimension in ("repository_root", "task", "target", "branch_ref", "action_root", "command_root"):
            self.assertEqual(len({repr(identity[dimension]) for identity in identities}), 4, dimension)

    def test_hotfix_guarded_control_drift_fails_all_coverage_phases(self):
        from graph_engineering.core.scenario_truth import ScenarioTruthError
        api, coverage, matrix, profile, overlay = fixture._verified_runner_contracts("hotfix")
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        fd_before = len(os.listdir("/dev/fd"))
        for scenario in fixture.HOTFIX_GUARDED_SCENARIO_IDS:
            for disposition in ("P", "R"):
                for phase in ("aggregate", "issue", "use", "precommit", "gate"):
                    if phase == "aggregate" and disposition == "P":
                        continue
                    with self.subTest(scenario=scenario, disposition=disposition, phase=phase):
                        result = fixture.run_serial_scenario_binding(api4=api4, plan=plan,
                            scenario_id=scenario, disposition=disposition)
                        factory = None
                        try:
                            context = result.scenario_truth_context
                            observer = (context.observer if disposition == "P" else
                                context.registry_factory._issued_rejections[id(context.receipts[0])][1])
                            control = observer._fixture_row["execution_contract"]["controls"][0]
                            control_path = observer._root / control["path_id"]
                            marker = observer._root / ".scenario-truth-root"
                            backing = observer._root / "marker-test-backing"
                            if phase not in ("aggregate", "issue"):
                                observation = result.observe_current()
                                factory = api.CoverageRecordFactory(execution_authority=result.authority, coverage_policy=coverage)
                            if phase == "gate":
                                record = factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
                            attacks = ("control",) if disposition == "P" else ("control", "marker-content", "marker-missing", "marker-symlink")
                            for attack in attacks:
                                with self.subTest(attack=attack):
                                    path = control_path if attack == "control" else marker
                                    original = path.read_bytes()
                                    before = fixture._serial_state_signature(result.probe, result.target, real_e2e=False)
                                    issued = None if factory is None else dict(factory._CoverageRecordFactory__issued)
                                    aggregates = dict(context.registry_factory._rejection_evidence)
                                    def corrupt():
                                        if attack == "marker-missing": path.unlink()
                                        elif attack == "marker-symlink":
                                            path.rename(backing)
                                            path.symlink_to(backing)
                                        else: path.write_bytes(original + b"drift")
                                    try:
                                        if phase == "precommit":
                                            registration_type = type(result.authority._coverage_registration)
                                            original_require = registration_type.require_observation
                                            def require(registration, authority, current, *, purpose="use"):
                                                if purpose == "precommit": corrupt()
                                                return original_require(registration, authority, current, purpose=purpose)
                                            with mock.patch.object(registration_type, "require_observation", new=require), self.assertRaises(api.ProfileContractError):
                                                factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
                                        else:
                                            corrupt()
                                            with self.assertRaises((ScenarioTruthError, api4.ProfileCoverageError, api.ProfileContractError)):
                                                if phase == "aggregate":
                                                    context.registry_factory.bind_rejections(context.receipts,
                                                        test_id=context.test_id, oracle_digest=context.oracle_digest)
                                                elif phase == "issue": result.observe_current()
                                                elif phase == "use": factory.issue_execution(observation, matrix=matrix, profile=profile, overlay=overlay)
                                                else: api.ReleaseCoverageGate.evaluate(matrix, coverage_records=(record,), coverage_factory=factory)
                                    finally:
                                        if path.is_symlink(): path.unlink()
                                        if backing.exists(): backing.rename(path)
                                        else:
                                            path.write_bytes(original)
                                            os.chmod(path, 0o600)
                                    self.assertEqual(fixture._serial_state_signature(result.probe, result.target, real_e2e=False), before)
                                    self.assertEqual(context.registry_factory._rejection_evidence, aggregates)
                                    if factory is not None: self.assertEqual(factory._CoverageRecordFactory__issued, issued)
                        finally:
                            if factory is not None: fixture.abort_uncommitted_coverage_factory(factory)
                            result.close()
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_dependency_graph_positive_reopens_without_resolver_replay(self) -> None:
        from graph_engineering.application import dependency_security

        network = mock.patch(
            "socket.socket", side_effect=AssertionError("network forbidden"),
        )
        network.start()
        self.addCleanup(network.stop)
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("dependency-security")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        result = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id="transitive-dependency",
            disposition="P",
            quiescent=True,
        )
        factory = None
        closed = False
        try:
            lifecycle = result.binding_lifecycle
            dependency_context = result.dependency_security_context
            product_reopen = result.dependency_reopen_authority
            self.assertEqual(dependency_context.resolver_observation_count, 1)
            self.assertEqual(dependency_context.rehydration_count, 0)
            self.assertIs(
                type(product_reopen),
                dependency_security.DependencySecurityObservationReopenAuthority,
            )
            signature = (
                result.target.path.read_bytes(),
                result.target.mutation_count,
                result.target.query_count,
                result.target._revision,
            )
            live_projections = []
            original_rebind = result.authority._rebind_binding_runtime

            def capture_rebind(**kwargs):  # type: ignore[no-untyped-def]
                rebound = original_rebind(**kwargs)
                current = result.authority._dependency_security
                self.assertIs(type(current), tuple)
                current_factory, current_observation = current
                self.assertIs(current_observation._authority, current_factory)
                self.assertEqual(
                    current_observation._projection["schema_version"], "1.1.0",
                )
                self.assertIs(
                    current_factory._category,
                    kwargs["category_application"],
                )
                live_projections.append(current_observation.to_dict())
                return rebound

            with mock.patch.object(
                result.authority,
                "_rebind_binding_runtime",
                side_effect=capture_rebind,
            ):
                observation = result.observe_current()
                factory = api.CoverageRecordFactory(
                    execution_authority=result.authority,
                    coverage_policy=coverage,
                )
                record = factory.issue_execution(
                    observation,
                    matrix=matrix,
                    profile=profile,
                    overlay=overlay,
                )
                decision = api.ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=(record,),
                    coverage_factory=factory,
                )
            self.assertFalse(decision.passed)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            self.assertEqual(dependency_context.resolver_observation_count, 1)
            self.assertEqual(dependency_context.rehydration_count, 0)
            self.assertEqual(
                (product_reopen.state, product_reopen.generation,
                 product_reopen.rehydration_count),
                ("QUIESCED", 4, 4),
            )
            self.assertEqual(len(live_projections), 4)
            self.assertTrue(all(
                projection == live_projections[0]
                for projection in live_projections
            ))
            self.assertIsNone(result.authority._dependency_security)
            sealed_projection = result.dependency_reopen_seal._projection
            self.assertEqual(
                sealed_projection["observation"]["schema_version"], "1.1.0",
            )
            self.assertIsNotNone(sealed_projection["graph"])
            self.assertEqual(
                (
                    result.target.path.read_bytes(),
                    result.target.mutation_count,
                    result.target.query_count,
                    result.target._revision,
                ),
                signature,
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
            self.assertEqual(product_reopen.state, "TERMINAL")
        finally:
            if factory is not None and not closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )

    def test_f1_legacy_graph_assessment_rehydrate_remains_distinct(self) -> None:
        from graph_engineering.application import dependency_security

        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(
            matrix=self.matrix()
        )
        result = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id="transitive-dependency",
            disposition="P",
        )
        try:
            assessment = result.application.current_assessment(
                result.probe.task_id,
                expected_profile_id="dependency-security",
            )
            projection = assessment.dependency_graph_projection
            self.assertEqual(assessment.schema_version, "1.2.0")
            self.assertIsNotNone(projection)
            state_before = (
                result.target.path.read_bytes(),
                result.target.mutation_count,
                result.target.query_count,
                result.target._revision,
            )
            factory = dependency_security.DependencyGraphAssessmentFactory.from_installation(
                result.probe.repository,
            )
            evidence = factory.rehydrate_projection(projection)
            self.assertIs(factory.require_current(evidence), evidence)
            self.assertIs(
                type(evidence), dependency_security.DependencyGraphAssessmentEvidence,
            )
            self.assertIsNone(evidence._source_factory)
            self.assertIsNone(evidence._source_observation)
            self.assertIsNot(
                type(evidence), dependency_security.DependencySecurityObservation,
            )
            self.assertEqual(
                (
                    result.target.path.read_bytes(),
                    result.target.mutation_count,
                    result.target.query_count,
                    result.target._revision,
                ),
                state_before,
            )
        finally:
            result.close()

    def test_migration_positive_reopens_without_action_or_command_replay(self) -> None:
        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("migration")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        result = fixture.run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id="forward",
            disposition="P",
            quiescent=True,
        )
        factory = None
        closed = False
        try:
            lifecycle = result.binding_lifecycle
            signature = result.state_after
            binding_identity = result.binding_identity_projection()
            from graph_engineering.core.contracts.immutable import thaw

            migration_projection = thaw(result.migration_rehearsal_projection)
            altered_projection = thaw(result.migration_rehearsal_projection)
            self.assertIsInstance(altered_projection, dict)
            altered_projection["profile_id"] = "foreign"
            self.assertEqual(
                thaw(result.migration_rehearsal_projection),
                migration_projection,
            )
            self.assertIsNone(result.private_shared_runtime)
            observation = result.observe_current()
            factory = api.CoverageRecordFactory(
                execution_authority=result.authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            self.assertEqual(result.state_after, signature)
            self.assertEqual(result.binding_identity_projection(), binding_identity)
            self.assertEqual(
                thaw(result.migration_rehearsal_projection),
                migration_projection,
            )
            self.assertIsNone(result.private_shared_runtime)
            self.assertLessEqual(
                runtime_fixture.PrivateBindingReopenPort.
                maximum_active_reopened_binding_count(),
                1,
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        finally:
            if factory is not None and not closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_f2_performance_rejection_rehydrates_without_launcher_replay(
        self,
    ) -> None:
        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("performance")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        result = fixture.run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="performance",
            column="artifacts",
            disposition="R",
            quiescent=True,
        )
        factory = None
        factory_closed = False
        try:
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkError,
                PerformanceBenchmarkRegistryFactory,
            )

            lifecycle = result.binding_lifecycle
            context = result.performance_context
            old_registry_factory = result.authority._performance_registry_factory
            old_registration = result.authority._performance_registration
            old_projection = old_registration._evidence_projection
            launches_before = context.cumulative_launch_count
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 0, "issue"),
            )
            self.assertGreater(launches_before, 0)
            self.assertIsNone(context.launcher)
            self.assertIsNone(context.session)
            self.assertIsNone(context.evidence)
            self.assertTrue(old_registration._session._closed)
            foreign_factory = PerformanceBenchmarkRegistryFactory.from_installation()
            foreign_authority = foreign_factory.registry()
            with self.assertRaises(PerformanceBenchmarkError):
                old_registry_factory._rehydrate_quiescent_profile_coverage_rejection(
                    old_registration,
                    object(),
                    foreign_factory,
                    foreign_authority,
                )

            observation = result.observe_current()
            restarted_factory = result.authority._performance_registry_factory
            restarted_registration = result.authority._performance_registration
            self.assertIsNot(restarted_factory, old_registry_factory)
            self.assertIsNone(restarted_registration._session)
            self.assertEqual(
                restarted_registration._evidence_projection, old_projection,
            )
            self.assertTrue(
                restarted_factory._rehydrated_evidence_ledger.contains(
                    restarted_registration._evidence
                )
            )
            self.assertEqual(context.cumulative_launch_count, launches_before)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 1, "use"),
            )

            factory = api.CoverageRecordFactory(
                execution_authority=result.authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(len(decision.missing_test_ids), 273)
            self.assertFalse(decision.invalid_test_ids)
            self.assertFalse(decision.stale_test_ids)
            self.assertEqual(context.cumulative_launch_count, launches_before)
            self.assertEqual(
                context.phase_launch_deltas,
                {"issue": 0, "use": 0, "precommit": 0, "gate": 0},
            )
            self.assertEqual(
                (lifecycle.state, lifecycle.generation,
                 lifecycle.expected_purpose),
                ("QUIESCED", 4, None),
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            factory_closed = True
            self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        finally:
            if factory is not None and not factory_closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.
            active_reopened_binding_count(),
            0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_ten_binding_strict_serial_quiescent_probe(self) -> None:
        started_ns = time.monotonic_ns()

        def progress(stage: str, **fields: object) -> None:
            print(
                json.dumps(
                    {
                        "elapsed_ns": time.monotonic_ns() - started_ns,
                        "stage": stage,
                        **fields,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )

        fd_before = len(os.listdir("/dev/fd"))
        api, coverage, matrix, profile, overlay = (
            fixture._verified_runner_contracts("new-feature")
        )
        api4 = fixture.load_slice4_api()
        plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
        test_ids = (
            "GEW-PRO-NEW-FEATURE-NORMAL-P",
            "GEW-PRO-NEW-FEATURE-NORMAL-R",
            "GEW-PRO-PERFORMANCE-NORMAL-P",
            "GEW-PRO-NEW-FEATURE-REAL-E2E-P",
            "GEW-PRO-BUG-FIX-REAL-E2E-R",
            "GEW-PSC-NEW-FEATURE-MULTI-TARGET-P",
            "GEW-PSC-NEW-FEATURE-MULTI-TARGET-R",
            "GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P",
            "GEW-PSC-MIGRATION-PARTIAL-DATA-P",
            "GEW-PSC-HOTFIX-MINIMAL-PATCH-R",
        )
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (244, 122))
        self.assertEqual(len(test_ids), len(set(test_ids)))

        results = []
        observations = []
        factory = None
        factory_closed = False
        try:
            for index, test_id in enumerate(test_ids, start=1):
                progress("binding-start", index=index, test_id=test_id)
                binding = plan.binding(test_id)
                if binding["selector_kind"] == "mandatory":
                    result = fixture.run_serial_profile_binding(
                        api4=api4,
                        plan=plan,
                        profile_id=str(binding["profile_id"]),
                        column=str(binding["column_id"]),
                        disposition=str(binding["disposition"]),
                        quiescent=True,
                    )
                elif binding["selector_kind"] == "scenario":
                    result = fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=str(binding["scenario_id"]),
                        disposition=str(binding["disposition"]),
                        quiescent=True,
                    )
                else:
                    self.fail("ten-binding probe selector kind changed")
                self.assertEqual(result.test_id, test_id)
                self.assertEqual(
                    (
                        result.binding_lifecycle.state,
                        result.binding_lifecycle.generation,
                        result.binding_lifecycle.expected_purpose,
                    ),
                    ("QUIESCED", 0, "issue"),
                )
                results.append(result)
                observations.append(result.observe_current())
                progress("binding-issued", index=index, test_id=test_id)
                self.assertEqual(
                    (
                        result.binding_lifecycle.state,
                        result.binding_lifecycle.generation,
                        result.binding_lifecycle.expected_purpose,
                    ),
                    ("QUIESCED", 1, "use"),
                )
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.active_handle_count(),
                    0,
                )
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.
                    active_reopened_binding_count(),
                    0,
                )

            identity_fields = (
                "repository_root", "task", "target", "branch_ref",
                "action_root", "command_root",
            )
            identities = tuple(
                result.binding_identity_projection() for result in results
            )

            def identity_key(value: object) -> str:
                return json.dumps(
                    value,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )

            for field in identity_fields:
                self.assertEqual(
                    len({identity_key(row[field]) for row in identities}),
                    len(test_ids),
                    field,
                )
            self.assertEqual(
                len({
                    tuple(identity_key(row[field]) for field in identity_fields)
                    for row in identities
                }),
                len(test_ids),
            )

            factory = api.CoverageRecordFactory(
                execution_authority=tuple(result.authority for result in results),
                coverage_policy=coverage,
            )
            progress("factory-issued", authorities=len(results))
            profile_contracts = {"new-feature": (profile, overlay)}
            records = []
            for index, (result, observation) in enumerate(
                zip(results, observations, strict=True), start=1,
            ):
                progress("record-start", index=index, test_id=result.test_id)
                current_profile = profile_contracts.get(result.profile_id)
                if current_profile is None:
                    loaded = fixture._verified_runner_contracts(result.profile_id)
                    current_profile = (loaded[3], loaded[4])
                    profile_contracts[result.profile_id] = current_profile
                records.append(factory.issue_execution(
                    observation,
                    matrix=matrix,
                    profile=current_profile[0],
                    overlay=current_profile[1],
                ))
                progress("record-issued", index=index, test_id=result.test_id)
                self.assertEqual(
                    (
                        result.binding_lifecycle.state,
                        result.binding_lifecycle.generation,
                        result.binding_lifecycle.expected_purpose,
                    ),
                    ("QUIESCED", 3, "gate"),
                )
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.active_handle_count(),
                    0,
                )

            progress("gate-start", records=len(records))
            decision = api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=tuple(records),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(len(records), 10)
            self.assertEqual(len(decision.missing_test_ids), 264)
            self.assertFalse(decision.invalid_test_ids)
            self.assertFalse(decision.stale_test_ids)
            progress(
                "gate-done",
                missing=len(decision.missing_test_ids),
                valid=len(records),
            )
            for result in results:
                self.assertEqual(
                    (
                        result.binding_lifecycle.state,
                        result.binding_lifecycle.generation,
                        result.binding_lifecycle.expected_purpose,
                    ),
                    ("QUIESCED", 4, None),
                )
            self.assertLessEqual(
                runtime_fixture.PrivateBindingReopenPort.
                maximum_active_reopened_binding_count(),
                1,
            )
            fixture.abort_uncommitted_coverage_factory(factory)
            factory_closed = True
            progress("terminal", results=len(results))
            self.assertTrue(all(
                result.binding_lifecycle.state == "PERMANENTLY_CLOSED"
                for result in results
            ))
        finally:
            if factory is not None and not factory_closed:
                fixture.abort_uncommitted_coverage_factory(factory)
            for result in reversed(results):
                result.close()
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.
            active_reopened_binding_count(),
            0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)



if __name__ == "__main__":
    unittest.main()
