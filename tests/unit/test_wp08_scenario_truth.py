"""ADR-0008 local scenario-truth authority contract tests."""

from __future__ import annotations

import copy
import gc
import hashlib
import json
import os
import pathlib
import pickle
import subprocess
import tempfile
import threading
import unittest
import weakref
from contextlib import ExitStack, contextmanager, redirect_stderr
from io import StringIO
from unittest import mock

import graph_engineering
from graph_engineering.application.scenario_truth import ScenarioTruthRegistryFactory
from graph_engineering.core import scenario_truth as scenario_core
from graph_engineering.core import profile_coverage as coverage_core
from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.scenario_truth import ScenarioTruthError


class WorkTraceMemoryRepairTests(unittest.TestCase):
    """Lossless trace storage and operation-local action fixture regressions."""

    def test_repeated_unread_events_use_one_run_and_decode_every_attempt(self) -> None:
        from tests.support.wp05a_security import security_context

        context = security_context()
        initial = context.balance
        event_id = "canonical.output_byte"
        coefficient = context.schedule.coefficients[event_id]
        repeats = 10_000
        for _ in range(repeats):
            context.emit(event_id, 1, operation_path=(3, 7), source_id="trace-test")
        self.assertIsNone(context._trace)
        self.assertEqual(len(context._trace_runs), 1)
        self.assertEqual(context.balance, initial - repeats * coefficient)
        trace = context.trace
        self.assertIs(type(trace), list)
        self.assertEqual(len(trace), repeats)
        self.assertEqual(context._trace_runs, [])
        for ordinal, attempt in enumerate(trace):
            self.assertEqual(attempt, {
                "amount": str(coefficient), "coefficient": str(coefficient),
                "count": "1", "event_id": event_id, "event_ordinal": str(ordinal),
                "multiplier": "1", "operation_path": [3, 7],
                "pre_balance": str(initial - ordinal * coefficient),
                "post_balance": str(initial - (ordinal + 1) * coefficient),
                "status": "charged",
            })
        self.assertIsNot(trace[0]["operation_path"], trace[1]["operation_path"])

    def test_trace_matches_reference_across_boundaries_and_rejections(self) -> None:
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.core.contracts.immutable import freeze, thaw
        from graph_engineering.core.contracts.resources import EVENT_IDS
        from graph_engineering.storage.codec import canonical_json
        from tests.support.wp05a_security import security_context

        for inspect_first in (False, True):
            with self.subTest(inspect_first=inspect_first):
                context = security_context()
                if inspect_first:
                    self.assertEqual(context.trace, [])
                expected = []
                events = sorted(EVENT_IDS)
                # Every event, varying count/path/multiplier, adjacent duplicates,
                # then a discontinuous balance and a rejected attempt.
                inputs = [(event, count, multiplier, path)
                          for event in events
                          for count, multiplier, path in (
                              (1, 1, ()), (1, 1, ()), (2, 1, ()),
                              (1, 2, ()), (1, 2, (0,)), (1, 2, (0, 1)),
                          )]
                inputs.extend([(events[0], 1, 1, ())] * 3)
                for index, (event, count, multiplier, path) in enumerate(inputs):
                    if index == len(inputs) - 2:
                        context.balance += 1
                    if index == len(inputs) - 1:
                        context.balance = 0
                    coefficient = context.schedule.coefficients[event]
                    amount = coefficient * count * multiplier
                    balance = context.balance
                    attempt = {
                        "amount": str(amount), "coefficient": str(coefficient),
                        "count": str(count), "event_id": event,
                        "event_ordinal": str(len(expected)),
                        "multiplier": str(multiplier), "operation_path": list(path),
                        "pre_balance": str(balance),
                    }
                    kwargs = {"operation_path": path, "multiplier": multiplier,
                              "source_id": "trace-reference"}
                    if amount > balance:
                        attempt["status"] = "rejected"
                        with self.assertRaises(ContractError) as caught:
                            context.emit(event, count, **kwargs)
                        self.assertEqual(caught.exception.detail.code, "E_BUDGET")
                        self.assertEqual(context.balance, balance)
                    else:
                        context.emit(event, count, **kwargs)
                        attempt.update(status="charged", post_balance=str(balance - amount))
                        self.assertEqual(context.balance, balance - amount)
                    expected.append(attempt)
                context.emit(events[0], 0, multiplier=0, source_id="zero-count")
                self.assertEqual(context.trace, expected)
                self.assertEqual(canonical_json(context.trace), canonical_json(expected))
                self.assertEqual(json.loads(json.dumps(context.trace)), expected)
                self.assertEqual(thaw(freeze(context.trace)), expected)

    def test_rejections_stay_separate_and_charging_can_resume(self) -> None:
        from graph_engineering.core.contracts.errors import ContractError
        from tests.support.wp05a_security import security_context

        context = security_context()
        event = "digest.input_byte"
        coefficient = context.schedule.coefficients[event]
        context.balance = 0
        for _ in range(3):
            with self.assertRaises(ContractError):
                context.emit(event, 1, source_id="rejected-run")
        context.balance = 3 * coefficient
        for _ in range(3):
            context.emit(event, 1, source_id="resumed-run")
        self.assertEqual(len(context._trace_runs), 4)
        self.assertEqual(context.balance, 0)
        trace = context.trace
        self.assertEqual([row["event_ordinal"] for row in trace], list(map(str, range(6))))
        self.assertEqual([row["status"] for row in trace], ["rejected"] * 3 + ["charged"] * 3)
        self.assertTrue(all("post_balance" not in row for row in trace[:3]))
        self.assertEqual([row["pre_balance"] for row in trace],
                         ["0"] * 3 + [str(index * coefficient) for index in (3, 2, 1)])

    def test_schedule_change_is_a_lossless_run_boundary(self) -> None:
        from dataclasses import replace
        from tests.support.wp05a_security import security_context

        context = security_context()
        event = "canonical.output_byte"
        original = context.schedule.coefficients[event]
        for _ in range(2):
            context.emit(event, 1, source_id="first-schedule")
        coefficients = dict(context.schedule.coefficients)
        coefficients[event] *= 2
        context.schedule = replace(context.schedule, coefficients=coefficients)
        for _ in range(2):
            context.emit(event, 1, source_id="second-schedule")
        self.assertEqual(len(context._trace_runs), 2)
        self.assertEqual([row["coefficient"] for row in context.trace],
                         [str(original)] * 2 + [str(original * 2)] * 2)

    def test_materialized_trace_retains_mutable_live_list_behavior(self) -> None:
        from tests.support.wp05a_security import security_context

        context = security_context()
        event = "digest.input_byte"
        context.emit(event, 1, source_id="live-list")
        trace = context.trace
        trace[0]["status"] = "caller-annotation"
        context.emit(event, 1, source_id="live-list")
        self.assertIs(context.trace, trace)
        self.assertEqual(trace[0]["status"], "caller-annotation")
        self.assertEqual(trace[-1]["event_ordinal"], "1")
        trace.clear()
        context.emit(event, 1, source_id="live-list")
        self.assertEqual(trace[0]["event_ordinal"], "0")
        replacement = [{"caller": "supplied"}]
        context.trace = replacement
        context.emit(event, 1, source_id="replacement-list")
        self.assertIs(context.trace, replacement)
        self.assertEqual(replacement[-1]["event_ordinal"], "1")

    def test_document_helpers_do_not_retain_process_global_context(self) -> None:
        from graph_engineering.core.actions import PreparedAction
        from tests.support import wp05_actions
        from tests.support.wp05a_security import security_context

        contexts = []
        before = wp05_actions.ACTION_DOCUMENT_CONTEXT.balance

        def fresh_context():
            context = security_context()
            contexts.append(weakref.ref(context))
            return context

        with mock.patch.object(wp05_actions, "security_context", side_effect=fresh_context):
            for _ in range(3):
                prepared = PreparedAction.from_dict(
                    wp05_actions.prepared_document(), context=security_context(),
                )
                wp05_actions.authority_document(prepared)
                wp05_actions.compensation_prepared_document()
        self.assertEqual(len(contexts), 9)
        gc.collect()
        self.assertTrue(all(reference() is None for reference in contexts))
        self.assertEqual(wp05_actions.ACTION_DOCUMENT_CONTEXT.balance, before)

    def test_explicit_document_context_keeps_full_trace_and_budget_fail_closed(self) -> None:
        from graph_engineering.core.contracts.errors import ContractError
        from tests.support import wp05_actions
        from tests.support.wp05a_security import security_context

        context = security_context()
        expected = wp05_actions.compensation_prepared_document()
        self.assertEqual(wp05_actions.compensation_prepared_document(context=context), expected)
        self.assertLess(context.balance, context.profile.work_budget)
        trace = context.trace
        self.assertTrue(trace)
        context.balance = 0
        with self.assertRaises(ContractError) as caught:
            wp05_actions.prepared_document(context=context)
        self.assertEqual(caught.exception.detail.code, "E_BUDGET")
        self.assertIs(context.trace, trace)
        self.assertEqual(trace[-1]["status"], "rejected")
        self.assertNotIn("post_balance", trace[-1])


class ScenarioTruthAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry_factory = ScenarioTruthRegistryFactory.from_installation()
        self.registry = self.registry_factory.registry()

    def tearDown(self) -> None:
        self.registry_factory.close()

    @staticmethod
    def binding() -> dict[str, object]:
        return {
            "task_id": "task:wp08-scenario:new-feature:multi-target:p",
            "task_revision": 1,
            "snapshot_digest": "sha256-jcs-v1:" + "1" * 64,
            "invalidation_epoch": 0,
            "profile_id": "new-feature",
            "profile_version": "1.0.0",
            "scenario_id": "multi-target",
            "graph_ref_pins": {
                "base_graph_digest": "sha256-jcs-v1:" + "2" * 64,
                "profile_digest": "sha256-jcs-v1:" + "3" * 64,
                "overlay_digest": "sha256-jcs-v1:" + "4" * 64,
                "project_config_digest": "sha256-jcs-v1:" + "5" * 64,
                "support_matrix_digest": "sha256-jcs-v1:" + "6" * 64,
                "materialization_digest": "sha256-jcs-v1:" + "7" * 64,
            },
            "branch_id": "branch:task:wp08-scenario:new-feature:multi-target:p",
            "ref_id": "ref:task:wp08-scenario:new-feature:multi-target:p",
        }

    def test_installed_registry_is_closed_and_multi_target_reaches_all_b_states(self) -> None:
        self.assertEqual(
            self.registry.profile_ids,
            ("hotfix", "incident-response", "new-feature", "refactor-debt"),
        )
        self.assertEqual(len(self.registry.scenario_pairs), 10)
        with tempfile.TemporaryDirectory(prefix="gew-scenario-p-") as root:
            observer = self.registry_factory.observation_factory(
                self.registry, binding=self.binding(), private_root=root,
            )
            request = observer.request()
            observation = observer.execute(request)
            self.registry_factory.require_current(observation)
            self.assertEqual(observer.mutation_count, 2)
            self.assertEqual(observation.scenario_outcome, "scenario-completed")
            self.assertEqual(
                tuple(row["role_id"] for row in observation.after_targets),
                ("component-a", "component-b"),
            )
            self.assertTrue(all(row["state_id"] == "B" for row in observation.after_targets))
            self.assertEqual(
                {row["assertion_id"].split(":", 1)[0] for row in observation.assertion_results},
                {"acceptance", "fresh-target", "regression"},
            )

    def test_symlink_targets_fail_before_mutation_and_during_restore(self) -> None:
        for phase in ("execute", "current", "restore", "restored-current"):
            for component, outside in (("file", False), ("directory", False),
                                       ("file", True), ("directory", True)):
                with self.subTest(phase=phase, component=component, outside=outside), tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as external:
                    observer = self.registry_factory.observation_factory(
                        self.registry, binding=self.binding(), private_root=root,
                    )
                    evidence = None
                    if phase != "execute":
                        evidence = observer.execute(observer.request())
                        projection = evidence.to_dict()
                        if phase == "restored-current":
                            evidence = self.registry_factory.restore_projection(projection)
                    target = observer._root / observer.request()["targets"][-1]["path_id"]
                    original_body = target.read_bytes()
                    link = target if component == "file" else target.parent
                    backing = (pathlib.Path(external) / "backing" if outside
                               else link.with_name(link.name + "-backing"))
                    link.rename(backing)
                    link.symlink_to(backing, target_is_directory=component == "directory")
                    count = observer.mutation_count
                    with self.assertRaises(ScenarioTruthError):
                        if phase == "execute":
                            observer.execute(observer.request())
                        elif phase == "restore":
                            self.registry_factory.restore_projection(projection)
                        else:
                            self.registry_factory.require_current(evidence)
                    self.assertEqual(observer.mutation_count, count)
                    self.assertEqual(target.read_bytes(), original_body)

    def test_testability_limits_are_config_owned_and_exact(self) -> None:
        testability = self.registry.testability
        self.assertEqual(testability["cumulative_runtime_limit_seconds"], 14400)
        self.assertEqual(testability["heartbeat_interval_seconds"], 60)
        self.assertLess(
            testability["heartbeat_interval_seconds"],
            testability["cumulative_runtime_limit_seconds"],
        )

    def test_testability_tamper_and_invalid_limits_fail_closed(self) -> None:
        policy_path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "config/profiles/scenario-truth-policy-registry-v1.json"
        )
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        attacks: list[dict[str, object]] = []
        for mutate in (
            lambda value: value.pop("testability"),
            lambda value: value["testability"].update({"extra": 1}),
            lambda value: value["testability"].update(
                {"cumulative_runtime_limit_seconds": True}
            ),
            lambda value: value["testability"].update(
                {"cumulative_runtime_limit_seconds": 0}
            ),
            lambda value: value["testability"].update(
                {"heartbeat_interval_seconds": value["testability"]["cumulative_runtime_limit_seconds"]}
            ),
        ):
            candidate = copy.deepcopy(policy)
            mutate(candidate)
            candidate["registry_digest"] = scenario_core._semantic(
                {
                    key: item
                    for key, item in candidate.items()
                    if key != "registry_digest"
                },
                "scenario-truth-policy-registry",
            )
            attacks.append(candidate)
        fixture_path = (
            pathlib.Path(__file__).resolve().parents[2]
            / "config/profiles/scenario-truth-fixture-registry-v1.json"
        )
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        for candidate in attacks:
            with self.assertRaises(ScenarioTruthError):
                scenario_core.parse_scenario_truth_registries(candidate, fixture)
        with self.assertRaises(TypeError):
            self.registry.testability["heartbeat_interval_seconds"] = 1

    def test_verified_runner_uses_immutable_limits_and_heartbeats(self) -> None:
        from tests.support import wp08_release_coverage as release_fixture

        testability = release_fixture._p2a_cumulative_runner_testability()
        raised_copy = dict(testability)
        raised_copy["cumulative_runtime_limit_seconds"] += 1
        self.assertNotEqual(
            raised_copy["cumulative_runtime_limit_seconds"],
            release_fixture._p2a_cumulative_runner_testability()[
                "cumulative_runtime_limit_seconds"
            ],
        )
        with self.assertRaises(TypeError):
            testability["heartbeat_interval_seconds"] = 1

        class FakeProcess:
            returncode = 0

            def __init__(self) -> None:
                self.calls = 0
                self.killed = False

            def communicate(self, *, timeout: float | None = None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired(
                        "verified-child", timeout, stderr="phase:g0"
                    )
                return ('{"selector":"p2a-cumulative-r2"}\n', "")

            def kill(self) -> None:
                self.killed = True

        process = FakeProcess()
        stderr = StringIO()
        with mock.patch.object(
            release_fixture.time,
            "monotonic_ns",
            side_effect=(0, 1_000_000_000, 1_000_000_000),
        ), redirect_stderr(stderr):
            receipt = release_fixture._wait_for_verified_child(
                process,
                selector="p2a-cumulative-r2",
                timeout_seconds=3,
                heartbeat_interval_seconds=1,
            )
        self.assertEqual(receipt, {"selector": "p2a-cumulative-r2"})
        self.assertFalse(process.killed)
        heartbeat = json.loads(stderr.getvalue())
        self.assertEqual(
            heartbeat,
            {
                "elapsed_seconds": 1,
                "heartbeat_sequence": 1,
                "last_child_stderr": "phase:g0",
                "selector": "p2a-cumulative-r2",
            },
        )

    def test_verified_runner_timeout_and_lifecycle_failure_remain_fatal(self) -> None:
        from tests.support import wp08_release_coverage as release_fixture

        class TimeoutProcess:
            returncode = None

            def __init__(self) -> None:
                self.calls = 0
                self.killed = False

            def communicate(self, *, timeout: float | None = None):
                self.calls += 1
                if not self.killed:
                    raise subprocess.TimeoutExpired(
                        "verified-child", timeout, stderr="phase:precommit"
                    )
                self.returncode = -9
                return ("", "lifecycle did not quiesce")

            def kill(self) -> None:
                self.killed = True

        timeout_process = TimeoutProcess()
        with mock.patch.object(
            release_fixture.time,
            "monotonic_ns",
            side_effect=(0, 1_000_000_000, 2_000_000_000),
        ), self.assertRaisesRegex(AssertionError, "timed out"):
            release_fixture._wait_for_verified_child(
                timeout_process,
                selector="p2a-cumulative-r2",
                timeout_seconds=2,
                heartbeat_interval_seconds=1,
            )
        self.assertTrue(timeout_process.killed)

        class FailedProcess:
            returncode = 7

            def communicate(self, *, timeout: float | None = None):
                return ("", "lifecycle currentness rejected")

            def kill(self) -> None:
                raise AssertionError("completed child must not be killed")

        raised_limits = dict(
            release_fixture._p2a_cumulative_runner_testability()
        )
        raised_limits["cumulative_runtime_limit_seconds"] += 1
        with mock.patch.object(
            release_fixture.time, "monotonic_ns", side_effect=(0, 0)
        ), self.assertRaisesRegex(AssertionError, "lifecycle currentness rejected"):
            release_fixture._wait_for_verified_child(
                FailedProcess(),
                selector="p2a-cumulative-r2",
                timeout_seconds=raised_limits[
                    "cumulative_runtime_limit_seconds"
                ],
                heartbeat_interval_seconds=raised_limits[
                    "heartbeat_interval_seconds"
                ],
            )

        class MissingReceiptProcess:
            returncode = 0

            def communicate(self, *, timeout: float | None = None):
                return ("{}", "")

            def kill(self) -> None:
                raise AssertionError("completed child must not be killed")

        with mock.patch.object(
            release_fixture.time, "monotonic_ns", return_value=0
        ), self.assertRaisesRegex(AssertionError, "receipt selector changed"):
            release_fixture._wait_for_verified_child(
                MissingReceiptProcess(),
                selector="p2a-cumulative-r2",
                timeout_seconds=2,
                heartbeat_interval_seconds=1,
            )

    def test_consumed_cumulative_gate_finalizes_instead_of_aborting(self) -> None:
        from tests.support import wp08_release_coverage as release_fixture

        decision = object()

        class ConsumedFactory:
            def __init__(self) -> None:
                self.finalized_with: list[object] = []

            def finalize_after_gate(self, candidate: object) -> None:
                self.finalized_with.append(candidate)

            def prepare_abort_uncommitted_candidate(self) -> object:
                raise AssertionError("consumed gate must not enter abort preparation")

        factory = ConsumedFactory()
        self.assertIs(
            release_fixture.finalize_consumed_coverage_factory(
                factory, decision,
            ),
            decision,
        )
        self.assertEqual(factory.finalized_with, [decision, decision])

    def test_currentness_closed_factory_and_stale_target_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-scenario-current-") as root:
            observer = self.registry_factory.observation_factory(
                self.registry, binding=self.binding(), private_root=root,
            )
            observation = observer.execute(observer.request())
            target = pathlib.Path(root) / "targets/component-a.state"
            target.write_bytes(b"stale\n")
            with self.assertRaises(ScenarioTruthError):
                self.registry_factory.require_current(observation)
        self.registry_factory.close()
        with self.assertRaises(ScenarioTruthError):
            self.registry_factory.registry()

    def test_stale_baseline_and_shared_root_are_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-scenario-stale-") as root:
            observer = self.registry_factory.observation_factory(
                self.registry, binding=self.binding(), private_root=root,
            )
            target = pathlib.Path(root) / "targets/component-a.state"
            target.write_bytes(b"stale\n")
            before = observer.target_bytes()
            with self.assertRaises(ScenarioTruthError):
                observer.execute(observer.request())
            self.assertEqual(observer.mutation_count, 0)
            self.assertEqual(observer.target_bytes(), before)
            with self.assertRaises(ScenarioTruthError):
                self.registry_factory.observation_factory(
                    self.registry, binding=self.binding(), private_root=root,
                )

    def test_foreign_same_suffix_branch_and_ref_are_rejected_before_write(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-scenario-foreign-suffix-") as root:
            binding = self.binding()
            binding["branch_id"] = "branch:foreign-task:p"
            binding["ref_id"] = "ref:foreign-task:p"
            with self.assertRaises(ScenarioTruthError):
                self.registry_factory.observation_factory(
                    self.registry, binding=binding, private_root=root,
                )
            self.assertEqual(tuple(pathlib.Path(root).iterdir()), ())

    def test_installed_resource_replacement_is_rejected_at_every_authority_phase(self) -> None:
        installed = graph_engineering._scenario_truth_installation_resources()
        policy_body = (
            json.dumps(
                json.loads(installed[1]),
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        bootstrap = json.loads(installed[3])
        old_bootstrap_digest = bootstrap["bootstrap_digest"]
        old_bootstrap_raw = hashlib.sha256(installed[3]).hexdigest()
        bootstrap["policy_registry_raw_sha256"] = hashlib.sha256(
            policy_body
        ).hexdigest()
        bootstrap["bootstrap_digest"] = scenario_core._semantic(
            {
                key: value
                for key, value in bootstrap.items()
                if key != "bootstrap_digest"
            },
            "scenario-truth-installation-bootstrap",
        )
        bootstrap_body = (
            json.dumps(
                bootstrap,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        provenance_body = installed[0].replace(
            old_bootstrap_digest.encode("ascii"),
            bootstrap["bootstrap_digest"].encode("ascii"),
        ).replace(
            old_bootstrap_raw.encode("ascii"),
            hashlib.sha256(bootstrap_body).hexdigest().encode("ascii"),
        )
        coherent_replacement = list(installed)
        coherent_replacement[0] = provenance_body
        coherent_replacement[1] = policy_body
        coherent_replacement[3] = bootstrap_body
        replacements = {
            "same-path-member": (
                installed[0] + b" ",
                *installed[1:],
            ),
            "coherent-full-closure": tuple(coherent_replacement),
        }

        with mock.patch.object(
            graph_engineering,
            "_scenario_truth_installation_resources",
            return_value=tuple(coherent_replacement),
        ):
            coherent_factory = ScenarioTruthRegistryFactory.from_installation()
            coherent_factory.close()

        def root_projection(root: str) -> tuple[tuple[str, bytes], ...]:
            base = pathlib.Path(root)
            return tuple(
                (path.relative_to(base).as_posix(), path.read_bytes())
                for path in sorted(base.rglob("*"))
                if path.is_file()
            )

        for replacement_id, replacement in replacements.items():
            for phase in (
                "registry", "issue", "use", "precommit", "coverage", "restart",
            ):
                with self.subTest(replacement=replacement_id, phase=phase):
                    factory = ScenarioTruthRegistryFactory.from_installation()
                    registry = factory.registry()
                    with tempfile.TemporaryDirectory(
                        prefix="gew-scenario-replaced-"
                    ) as root:
                        observer = None
                        observation = None
                        projection = None
                        if phase not in {"registry", "issue"}:
                            observer = factory.observation_factory(
                                registry, binding=self.binding(), private_root=root,
                            )
                            if phase in {"precommit", "coverage", "restart"}:
                                observation = observer.execute(observer.request())
                            if phase == "restart":
                                projection = factory.projection(observation)
                        before = root_projection(root)
                        with mock.patch.object(
                            graph_engineering,
                            "_scenario_truth_installation_resources",
                            return_value=replacement,
                        ), self.assertRaises(ScenarioTruthError):
                            if phase == "registry":
                                factory.registry()
                            elif phase == "issue":
                                factory.observation_factory(
                                    registry,
                                    binding=self.binding(),
                                    private_root=root,
                                )
                            elif phase == "use":
                                observer.execute(observer.request())
                            elif phase == "precommit":
                                factory.require_current(observation)
                            elif phase == "coverage":
                                factory.projection(observation)
                            else:
                                factory.restore_projection(projection)
                        self.assertEqual(root_projection(root), before)
                        if observer is not None and phase == "use":
                            self.assertEqual(observer.mutation_count, 0)
                        if observer is not None and phase == "restart":
                            self.assertEqual(observer.mutation_count, 2)
                    factory.close()

    def test_request_has_no_caller_declared_assertion_results(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-scenario-facts-") as root:
            observer = self.registry_factory.observation_factory(
                self.registry, binding=self.binding(), private_root=root,
            )
            request = observer.request()
            self.assertNotIn("assertion_results", request)
            request["assertion_results"] = [
                {"assertion_id": "caller", "passed": True}
            ]
            before = observer.target_bytes()
            with self.assertRaises(ScenarioTruthError):
                observer.execute(request)
            self.assertEqual(observer.mutation_count, 0)
            self.assertEqual(observer.target_bytes(), before)

    def test_assertion_evaluator_is_exact_ordered_and_fact_derived(self) -> None:
        expectations = [
            {
                "assertion_id": "acceptance:role-a",
                "kind": "acceptance",
                "expected": True,
            },
            {
                "assertion_id": "fresh-target:role-a",
                "kind": "fresh-target",
                "expected": True,
            },
            {
                "assertion_id": "regression:role-a",
                "kind": "regression",
                "expected": True,
            },
        ]
        facts = {
            "fact:acceptance:role-a": True,
            "fact:fresh-target:role-a": True,
            "fact:regression:role-a": True,
        }
        self.assertEqual(
            scenario_core.evaluate_scenario_assertions(expectations, facts),
            (
                {"assertion_id": "acceptance:role-a", "passed": True},
                {"assertion_id": "fresh-target:role-a", "passed": True},
                {"assertion_id": "regression:role-a", "passed": True},
            ),
        )
        attacks = []
        changed = copy.deepcopy(expectations)
        changed[0]["expected"] = False
        attacks.append((changed, facts))
        for fact_id in (
            "fact:fresh-target:role-a",
            "fact:regression:role-a",
        ):
            changed_facts = copy.deepcopy(facts)
            changed_facts[fact_id] = False
            attacks.append((expectations, changed_facts))
        omitted = copy.deepcopy(facts)
        omitted.pop("fact:acceptance:role-a")
        attacks.append((expectations, omitted))
        attacks.append((expectations, dict(reversed(tuple(facts.items())))))
        for changed_expectations, changed_facts in attacks:
            with self.assertRaises(ScenarioTruthError):
                scenario_core.evaluate_scenario_assertions(
                    changed_expectations, changed_facts,
                )

    def test_policy_required_facts_must_match_fixture_assertion_order(self) -> None:
        policy = json.loads(pathlib.Path(
            "config/profiles/scenario-truth-policy-registry-v1.json"
        ).read_bytes())
        fixture = json.loads(pathlib.Path(
            "config/profiles/scenario-truth-fixture-registry-v1.json"
        ).read_bytes())
        policy["scenarios"][0]["required_fact_ids"].reverse()
        row = policy["scenarios"][0]
        row["row_digest"] = scenario_core._semantic(
            {key: value for key, value in row.items() if key != "row_digest"},
            "scenario-truth-policy-row",
        )
        policy["registry_digest"] = scenario_core._semantic(
            {
                key: value
                for key, value in policy.items()
                if key != "registry_digest"
            },
            "scenario-truth-policy-registry",
        )
        with self.assertRaises(ScenarioTruthError):
            scenario_core.parse_scenario_truth_registries(policy, fixture)

    def test_multi_target_rejections_are_zero_write(self) -> None:
        attacks = (
            lambda value: value["targets"][0].pop("role_id"),
            lambda value: value["targets"].append({
                **copy.deepcopy(value["targets"][0]),
                "role_id": "extra-role",
                "path_id": "targets/extra.state",
            }),
            lambda value: value["targets"].__setitem__(1, copy.deepcopy(value["targets"][0])),
            lambda value: value["targets"].pop(),
            lambda value: value["targets"][1].__setitem__("apply", False),
            lambda value: value.__setitem__("branch_id", "branch:foreign"),
            lambda value: value["ordered_phase_ids"].clear(),
            lambda value: value["rollback_or_compensation"].__setitem__(
                "expected_state_id", "stale-A"
            ),
        )
        for index, attack in enumerate(attacks):
            with self.subTest(index=index), tempfile.TemporaryDirectory(
                prefix=f"gew-scenario-r-{index}-"
            ) as root:
                binding = self.binding()
                binding["task_id"] = f"task:wp08-scenario:new-feature:multi-target:r:{index}"
                binding["branch_id"] = f"branch:task:wp08-scenario:new-feature:multi-target:r:{index}"
                binding["ref_id"] = f"ref:task:wp08-scenario:new-feature:multi-target:r:{index}"
                observer = self.registry_factory.observation_factory(
                    self.registry, binding=binding, private_root=root,
                )
                request = observer.request()
                attack(request)
                before = observer.target_bytes()
                with self.assertRaises(ScenarioTruthError):
                    observer.execute(request)
                self.assertEqual(observer.mutation_count, 0)
                self.assertEqual(observer.target_bytes(), before)

    def test_process_local_quiescent_reopen_lifecycle_contract_exists(self) -> None:
        lifecycle_type = getattr(
            coverage_core, "ProcessLocalBindingLifecycle", None,
        )
        seal_type = getattr(coverage_core, "BindingLifecycleSeal", None)
        port_type = getattr(coverage_core, "RuntimeBindingReopenPort", None)
        error_type = getattr(coverage_core, "BindingLifecycleError", None)
        self.assertIsInstance(lifecycle_type, type)
        self.assertIsInstance(seal_type, type)
        self.assertIsInstance(port_type, type)
        self.assertIsInstance(error_type, type)

    def test_process_local_quiescent_reopen_lifecycle_is_opaque_and_monotonic(self) -> None:
        class ReopenPort(coverage_core.RuntimeBindingReopenPort):
            def __init__(self) -> None:
                self.active_handle_count = 1
                self.capability: object | None = None
                self.events: list[tuple[str, str, int]] = []
                self.handle_generation = 0
                self.root_identity = object()

            def _require(self, lifecycle: object, capability: object) -> None:
                if self.capability is None:
                    self.capability = capability
                if self.capability is not capability:
                    raise coverage_core.BindingLifecycleError("foreign capability")
                if type(lifecycle) is not coverage_core.ProcessLocalBindingLifecycle:
                    raise coverage_core.BindingLifecycleError("foreign lifecycle")

            def seal_current(
                self,
                lifecycle: object,
                handle: object,
                capability: object,
            ) -> tuple[object, str]:
                self._require(lifecycle, capability)
                if self.active_handle_count != 1 or handle is None:
                    raise coverage_core.BindingLifecycleError("handle is not live")
                self.events.append(
                    ("seal", lifecycle.state, lifecycle.generation),
                )
                snapshot = (
                    self.root_identity,
                    self.handle_generation,
                    "task-state-current",
                    "installation-closure-current",
                )
                return snapshot, coverage_core.profile_coverage_digest(
                    {
                        "handle_generation": self.handle_generation,
                        "task_state": "current",
                        "installation_closure": "current",
                    },
                    contract="binding-lifecycle-test",
                    schema="binding-lifecycle-test",
                )

            def quiesce(
                self,
                lifecycle: object,
                handle: object,
                capability: object,
            ) -> None:
                self._require(lifecycle, capability)
                if self.active_handle_count != 1 or handle is None:
                    raise coverage_core.BindingLifecycleError("handle cannot quiesce")
                self.events.append(
                    ("quiesce", lifecycle.state, lifecycle.generation),
                )
                self.active_handle_count = 0

            def reopen(
                self,
                lifecycle: object,
                sealed_snapshot: object,
                purpose: str,
                capability: object,
            ) -> object:
                self._require(lifecycle, capability)
                if self.active_handle_count != 0:
                    raise coverage_core.BindingLifecycleError("concurrent reopen")
                if (
                    type(sealed_snapshot) is not tuple
                    or sealed_snapshot[0] is not self.root_identity
                    or sealed_snapshot[1] != self.handle_generation
                ):
                    raise coverage_core.BindingLifecycleError("stale snapshot")
                self.events.append(
                    (f"reopen:{purpose}", lifecycle.state, lifecycle.generation),
                )
                self.handle_generation += 1
                self.active_handle_count = 1
                return object()

            def terminate(
                self,
                lifecycle: object,
                handle: object | None,
                terminal_action: str,
                capability: object,
            ) -> None:
                self._require(lifecycle, capability)
                self.events.append(
                    (terminal_action, lifecycle.state, lifecycle.generation),
                )
                self.active_handle_count = 0

        binding_digest = coverage_core.profile_coverage_digest(
            {"binding_id": "binding:a"},
            contract="binding-lifecycle-test-identity",
            schema="binding-lifecycle-test-identity",
        )
        port = ReopenPort()
        owner = object()
        lifecycle = coverage_core.ProcessLocalBindingLifecycle._issue(
            port=port,
            binding_digest=binding_digest,
            opened_handle=object(),
            owner=owner,
        )
        self.assertEqual(lifecycle.state, "OPEN")
        seal = lifecycle.seal_and_quiesce(owner)
        self.assertEqual((lifecycle.state, lifecycle.generation), ("QUIESCED", 0))
        self.assertEqual(port.active_handle_count, 0)
        with self.assertRaises(TypeError):
            coverage_core.ProcessLocalBindingLifecycle()
        with self.assertRaises(TypeError):
            coverage_core.BindingLifecycleSeal()
        with self.assertRaises(TypeError):
            copy.copy(seal)
        with self.assertRaises(TypeError):
            copy.deepcopy(seal)
        with self.assertRaises(TypeError):
            pickle.dumps(seal)
        with self.assertRaises(TypeError):
            vars(seal)

        prior_seals: list[coverage_core.BindingLifecycleSeal] = []
        for generation, purpose in enumerate(
            ("issue", "use", "precommit", "gate"), start=1,
        ):
            prior_seals.append(seal)
            value, seal = lifecycle.run_phase(
                seal,
                purpose,
                lambda handle, current=purpose: (
                    self.assertEqual(lifecycle.state, "REOPENED"),
                    self.assertIsNotNone(handle),
                    current,
                )[-1],
                owner,
            )
            self.assertEqual(value, purpose)
            self.assertEqual(
                (lifecycle.state, lifecycle.generation, seal.generation),
                ("QUIESCED", generation, generation),
            )
            self.assertEqual(port.active_handle_count, 0)
            with self.assertRaises(coverage_core.BindingLifecycleError):
                lifecycle.run_phase(
                    prior_seals[-1], purpose, lambda handle: handle, owner,
                )
        self.assertIsNone(lifecycle.expected_purpose)
        lifecycle.terminate(seal, "finalize", owner)
        self.assertEqual(lifecycle.state, "PERMANENTLY_CLOSED")
        self.assertEqual(port.active_handle_count, 0)
        with self.assertRaises(coverage_core.BindingLifecycleError):
            lifecycle.run_phase(seal, "gate", lambda handle: handle, owner)

        expected_event_states = (
            ("seal", "OPEN", 0),
            ("quiesce", "SEALED", 0),
            ("reopen:issue", "QUIESCED", 0),
            ("seal", "REOPENED", 0),
            ("quiesce", "SEALED", 1),
            ("reopen:use", "QUIESCED", 1),
            ("seal", "REOPENED", 1),
            ("quiesce", "SEALED", 2),
            ("reopen:precommit", "QUIESCED", 2),
            ("seal", "REOPENED", 2),
            ("quiesce", "SEALED", 3),
            ("reopen:gate", "QUIESCED", 3),
            ("seal", "REOPENED", 3),
            ("quiesce", "SEALED", 4),
            ("finalize", "QUIESCED", 4),
        )
        self.assertEqual(tuple(port.events), expected_event_states)

    def test_private_binding_runtime_reopen_port_exists(self) -> None:
        from tests.support import wp08_scenario_truth as runtime_fixture

        port_type = getattr(runtime_fixture, "PrivateBindingReopenPort", None)
        issuer = getattr(runtime_fixture, "issue_quiescent_binding", None)
        self.assertIsInstance(port_type, type)
        self.assertTrue(issubclass(port_type, coverage_core.RuntimeBindingReopenPort))
        self.assertTrue(callable(issuer))

    def test_private_binding_runtime_reopens_same_root_and_detects_tamper(self) -> None:
        from tests.support import wp08_scenario_truth as runtime_fixture

        class Handle:
            def __init__(self, path: pathlib.Path) -> None:
                self.stream = path.open("rb")

            def close(self) -> None:
                self.stream.close()

        with tempfile.TemporaryDirectory(prefix="gew-e1-runtime-port-") as directory:
            root = pathlib.Path(directory)
            member = root / "binding.state"
            member.write_bytes(b"current\n")
            terminated: list[str] = []

            def opened() -> Handle:
                return Handle(member)

            def project(handle: object) -> dict[str, object]:
                self.assertIsInstance(handle, Handle)
                self.assertFalse(handle.stream.closed)
                return {
                    "action_state": "current",
                    "command_state": "current",
                    "installation_closure": "current",
                    "member_sha256": hashlib.sha256(member.read_bytes()).hexdigest(),
                    "observation_state": "current",
                    "record_state": "current",
                    "task_state": "current",
                    "target_state": "current",
                }

            runtime = runtime_fixture.issue_quiescent_binding(
                binding_identity={"binding_id": "binding:test"},
                close_handle=lambda handle: handle.close(),
                opened_handle=opened(),
                private_root=root,
                project_current=project,
                reopen_handle=opened,
                terminate_root=lambda action: terminated.append(action),
            )
            self.assertEqual(runtime.state, "QUIESCED")
            self.assertEqual(runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0)
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                0,
            )
            with self.assertRaises(TypeError):
                copy.copy(runtime)
            with self.assertRaises(TypeError):
                copy.deepcopy(runtime)
            with self.assertRaises(TypeError):
                pickle.dumps(runtime)
            forged = object.__new__(type(runtime))
            for field in (
                "_ProfileCoverageBindingLifecycle__lifecycle",
                "_ProfileCoverageBindingLifecycle__seal",
            ):
                object.__setattr__(forged, field, getattr(runtime, field))
            with self.assertRaises(coverage_core.BindingLifecycleError):
                forged.run("issue", lambda handle: handle.stream.read())
            for purpose in ("issue", "use"):
                self.assertEqual(
                    runtime.run(purpose, lambda handle: handle.stream.read()),
                    b"current\n",
                )
                self.assertEqual(runtime.state, "QUIESCED")
                self.assertEqual(
                    runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
                )

            member.write_bytes(b"tampered\n")
            with self.assertRaises(coverage_core.BindingLifecycleError):
                runtime.run("precommit", lambda handle: handle.stream.read())
            self.assertEqual(runtime.state, "QUIESCED")
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
            )
            runtime.terminate("revoke")
            self.assertEqual(runtime.state, "PERMANENTLY_CLOSED")
            self.assertEqual(terminated, ["revoke"])

    def test_private_category_repository_reopens_same_inode_without_reinitializing(self) -> None:
        from tests.support import wp08_scenario_truth as runtime_fixture

        root = runtime_fixture.PrivateCategoryRepositoryRoot("new-feature")
        try:
            first = root.open()
            first_identity = root.identity_projection()
            root.close_handle(first)
            quiesced_identity = root.identity_projection()
            second = root.open()
            reopened_identity = root.identity_projection()
            self.assertEqual(first_identity, quiesced_identity)
            self.assertEqual(first_identity, reopened_identity)
            self.assertIsNot(first, second)
            self.assertEqual(second.profile_id, "new-feature")
            root.close_handle(second)
        finally:
            root.terminate("revoke")


class BindingLifecycleRuntimeTests(unittest.TestCase):
    def test_factory_capability_registration_requires_current_quiesced_generation(self) -> None:
        from graph_engineering.application.profile_coverage import (
            ProfileCoverageAuthority,
            ProfileCoverageBindingLifecycle,
        )
        from graph_engineering.core.profile_coverage import ProfileCoverageError
        from graph_engineering.core.profiles import CoverageRecordFactory
        from tests.support import wp08_scenario_truth as runtime_fixture

        class Handle:
            def __init__(self, member: pathlib.Path) -> None:
                self.stream = member.open("rb")

            def close(self) -> None:
                self.stream.close()

        with tempfile.TemporaryDirectory(
            prefix="gew-e1-factory-capability-"
        ) as directory:
            root = pathlib.Path(directory)
            member = root / "binding.state"
            member.write_bytes(b"current\n")

            def opened() -> Handle:
                return Handle(member)

            terminated: list[str] = []
            lifecycle = runtime_fixture.issue_quiescent_binding(
                binding_identity={"binding_id": "binding:factory-capability"},
                close_handle=lambda handle: handle.close(),
                opened_handle=opened(),
                private_root=root,
                project_current=lambda handle: {
                    "member_sha256": hashlib.sha256(member.read_bytes()).hexdigest(),
                    "stream_open": not handle.stream.closed,
                },
                reopen_handle=opened,
                terminate_root=terminated.append,
            )
            authority = object.__new__(ProfileCoverageAuthority)
            registration = object()
            factory = object.__new__(CoverageRecordFactory)
            capability = object()
            authority._ProfileCoverageAuthority__lifecycle_lock = threading.RLock()
            authority._ProfileCoverageAuthority__lifecycle_state = "active"
            authority._binding_lifecycle = lifecycle
            authority._coverage_registration = registration
            authority._ProfileCoverageAuthority__revoke_capabilities = {}
            authority._ProfileCoverageAuthority__revoked_capabilities = {}

            before = (
                lifecycle.state,
                lifecycle.generation,
                lifecycle.expected_purpose,
                member.read_bytes(),
            )
            with self.assertRaises(ProfileCoverageError):
                authority._register_factory_capability(
                    registration, factory, capability,
                )
            self.assertEqual(
                (
                    lifecycle.state,
                    lifecycle.generation,
                    lifecycle.expected_purpose,
                    member.read_bytes(),
                ),
                before,
            )
            self.assertEqual(
                authority._ProfileCoverageAuthority__revoke_capabilities, {},
            )

            lifecycle.run("issue", lambda handle: handle.stream.read())
            forged = object.__new__(ProfileCoverageBindingLifecycle)
            object.__setattr__(
                forged,
                "_ProfileCoverageBindingLifecycle__lifecycle",
                lifecycle._ProfileCoverageBindingLifecycle__lifecycle,
            )
            object.__setattr__(
                forged,
                "_ProfileCoverageBindingLifecycle__seal",
                lifecycle._ProfileCoverageBindingLifecycle__seal,
            )
            authority._binding_lifecycle = forged
            with self.assertRaises(coverage_core.BindingLifecycleError):
                authority._register_factory_capability(
                    registration, factory, capability,
                )
            authority._binding_lifecycle = lifecycle
            self.assertEqual(
                authority._ProfileCoverageAuthority__revoke_capabilities, {},
            )

            class ForgedCapability:
                pass

            with self.assertRaises(ProfileCoverageError):
                authority._register_factory_capability(
                    registration, factory, ForgedCapability(),
                )
            self.assertEqual(
                authority._ProfileCoverageAuthority__revoke_capabilities, {},
            )

            def nonquiesced(handle: Handle) -> bytes:
                with self.assertRaises(ProfileCoverageError):
                    authority._register_factory_capability(
                        registration, factory, capability,
                    )
                self.assertEqual(
                    authority._ProfileCoverageAuthority__revoke_capabilities, {},
                )
                return handle.stream.read()

            self.assertEqual(lifecycle.run("use", nonquiesced), b"current\n")
            with self.assertRaises(ProfileCoverageError):
                authority._register_factory_capability(
                    registration, factory, capability,
                )
            self.assertEqual(
                (
                    lifecycle.state,
                    lifecycle.generation,
                    lifecycle.expected_purpose,
                    authority._ProfileCoverageAuthority__revoke_capabilities,
                    member.read_bytes(),
                ),
                ("QUIESCED", 2, "precommit", {}, b"current\n"),
            )
            lifecycle.terminate("revoke")
            self.assertEqual(terminated, ["revoke"])

    def test_private_binding_runtime_rejects_cross_binding_and_reopen_attacks(self) -> None:
        from graph_engineering.application.profile_coverage import (
            ProfileCoverageBindingLifecycle,
        )
        from tests.support import wp08_scenario_truth as runtime_fixture

        fd_before = len(os.listdir("/dev/fd"))

        class Handle:
            def __init__(self, member: pathlib.Path) -> None:
                self.stream = member.open("rb")

            def close(self) -> None:
                self.stream.close()

        with tempfile.TemporaryDirectory(
            prefix="gew-e1-cross-a-"
        ) as directory_a, tempfile.TemporaryDirectory(
            prefix="gew-e1-cross-b-"
        ) as directory_b:
            roots = (pathlib.Path(directory_a), pathlib.Path(directory_b))
            members = tuple(root / "binding.state" for root in roots)
            for member in members:
                member.write_bytes(b"current\n")
            identities = [
                {
                    "binding_id": f"binding:{index}",
                    "profile_id": f"profile:{index}",
                    "branch_ref": [f"branch:task:{index}", f"ref:task:{index}"],
                }
                for index in range(2)
            ]
            terminated: list[tuple[int, str]] = []

            def issue(index: int) -> ProfileCoverageBindingLifecycle:
                member = members[index]

                def opened() -> Handle:
                    return Handle(member)

                def project(handle: object) -> dict[str, object]:
                    self.assertIsInstance(handle, Handle)
                    self.assertFalse(handle.stream.closed)
                    return {
                        "action_state": "current",
                        "binding_identity": copy.deepcopy(identities[index]),
                        "command_state": "current",
                        "installation_closure": "current",
                        "member_sha256": hashlib.sha256(
                            member.read_bytes()
                        ).hexdigest(),
                        "record_state": "current",
                        "target_state": "current",
                        "task_state": "current",
                    }

                return runtime_fixture.issue_quiescent_binding(
                    binding_identity=identities[index],
                    close_handle=lambda handle: handle.close(),
                    opened_handle=opened(),
                    private_root=roots[index],
                    project_current=project,
                    reopen_handle=opened,
                    terminate_root=lambda action: terminated.append((index, action)),
                )

            first = issue(0)
            second = issue(1)
            expected_bytes = tuple(member.read_bytes() for member in members)
            baseline = (
                first.state,
                first.generation,
                first.expected_purpose,
                second.state,
                second.generation,
                second.expected_purpose,
            )
            with self.assertRaises(coverage_core.BindingLifecycleError):
                first.run("use", lambda handle: handle.stream.read())
            self.assertEqual(
                (
                    first.state,
                    first.generation,
                    first.expected_purpose,
                    second.state,
                    second.generation,
                    second.expected_purpose,
                ),
                baseline,
            )

            forged = object.__new__(ProfileCoverageBindingLifecycle)
            object.__setattr__(
                forged,
                "_ProfileCoverageBindingLifecycle__lifecycle",
                first._ProfileCoverageBindingLifecycle__lifecycle,
            )
            object.__setattr__(
                forged,
                "_ProfileCoverageBindingLifecycle__seal",
                second._ProfileCoverageBindingLifecycle__seal,
            )
            with self.assertRaises(coverage_core.BindingLifecycleError):
                forged.run("issue", lambda handle: handle.stream.read())

            def cross_binding_phase(handle: Handle) -> bytes:
                with self.assertRaises(coverage_core.BindingLifecycleError):
                    second.run("issue", lambda nested: nested.stream.read())
                return handle.stream.read()

            self.assertEqual(first.run("issue", cross_binding_phase), b"current\n")
            self.assertEqual(
                (second.state, second.generation, second.expected_purpose),
                ("QUIESCED", 0, "issue"),
            )
            with self.assertRaises(coverage_core.BindingLifecycleError):
                first.run("issue", lambda handle: handle.stream.read())
            self.assertEqual(second.run("issue", lambda handle: handle.stream.read()), b"current\n")

            original_ref = identities[0]["branch_ref"]
            identities[0]["branch_ref"] = ["branch:task:0", "ref:foreign"]
            with self.assertRaises(coverage_core.BindingLifecycleError):
                first.run("use", lambda handle: handle.stream.read())
            self.assertEqual(
                (first.state, first.generation, first.expected_purpose),
                ("QUIESCED", 1, "use"),
            )
            identities[0]["branch_ref"] = original_ref
            self.assertEqual(first.run("use", lambda handle: handle.stream.read()), b"current\n")

            first.terminate("revoke")
            with self.assertRaises(coverage_core.BindingLifecycleError):
                first.run("precommit", lambda handle: handle.stream.read())
            with self.assertRaises(coverage_core.BindingLifecycleError):
                first.terminate("revoke")
            second.terminate("finalize")

            self.assertEqual(
                tuple(member.read_bytes() for member in members), expected_bytes,
            )
            self.assertEqual(terminated, [(0, "revoke"), (1, "finalize")])
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
            )
            self.assertEqual(
                runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                0,
            )

        with tempfile.TemporaryDirectory(prefix="gew-e1-symlink-") as directory:
            root = pathlib.Path(directory) / "binding"
            root.mkdir()
            member = root / "binding.state"
            member.write_bytes(b"current\n")

            def opened() -> Handle:
                return Handle(member)

            symlink_runtime = runtime_fixture.issue_quiescent_binding(
                binding_identity={"binding_id": "binding:symlink"},
                close_handle=lambda handle: handle.close(),
                opened_handle=opened(),
                private_root=root,
                project_current=lambda handle: {
                    "member_sha256": hashlib.sha256(member.read_bytes()).hexdigest()
                },
                reopen_handle=opened,
                terminate_root=lambda action: terminated.append((2, action)),
            )
            moved = pathlib.Path(directory) / "binding-moved"
            root.rename(moved)
            root.symlink_to(moved, target_is_directory=True)
            try:
                with self.assertRaises(coverage_core.BindingLifecycleError):
                    symlink_runtime.run(
                        "issue", lambda handle: handle.stream.read(),
                    )
                self.assertEqual(
                    (symlink_runtime.state, symlink_runtime.generation,
                     symlink_runtime.expected_purpose),
                    ("QUIESCED", 0, "issue"),
                )
            finally:
                root.unlink()
                moved.rename(root)
            symlink_runtime.terminate("revoke")

        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_handle_count(), 0,
        )
        self.assertEqual(
            runtime_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
            0,
        )
        self.assertEqual(len(os.listdir("/dev/fd")), fd_before)

    def test_private_action_repository_reopens_without_action_replay(self) -> None:
        from tests.support import wp05_actions
        from tests.support import wp08_scenario_truth as runtime_fixture

        root = runtime_fixture.PrivateActionRepositoryRoot()
        try:
            first = root.open()
            prepared_document = wp05_actions.compensation_prepared_document()
            prepared = first.coordinator.prepare(prepared_document)
            first.coordinator.authorize(wp05_actions.authority_document(prepared))
            before = first.journal.load(prepared.action_id)
            identity = root.identity_projection()
            root.close_handle(first)
            second = root.open()
            after = second.journal.load(prepared.action_id)
            self.assertEqual(before, after)
            self.assertEqual(after.state, "authorized")
            self.assertEqual(identity, root.identity_projection())
            root.close_handle(second)
        finally:
            root.terminate("revoke")


class GuardedScenarioTruthTests(unittest.TestCase):
    scenarios = ("emergency-baseline", "production-like-gate")

    def setUp(self):
        self.factory = ScenarioTruthRegistryFactory.from_installation()
        self.addCleanup(self.factory.close)

    def observer(self, scenario):
        binding = ScenarioTruthAuthorityTests.binding()
        binding["profile_id"] = "hotfix"
        binding["scenario_id"] = scenario
        root = tempfile.TemporaryDirectory(prefix="gew-p2b-unit-")
        self.addCleanup(root.cleanup)
        return self.factory.observation_factory(
            self.factory.registry(), binding=binding, private_root=root.name,
        )

    def test_guarded_execution_requires_fresh_opaque_baseline(self):
        for scenario in self.scenarios:
            with self.subTest(scenario=scenario):
                observer = self.observer(scenario)
                baseline = observer.capture_baseline()
                with self.assertRaises(ScenarioTruthError):
                    observer.execute(observer.request())
                self.assertEqual(observer.mutation_count, 0)
                with self.assertRaises(TypeError):
                    pickle.dumps(baseline)
                evidence = observer.execute(observer.request(), baseline_receipt=baseline)
                self.factory.require_current(evidence)
                self.assertIn("execution_proof", evidence.to_dict())
                self.assertEqual(observer.mutation_count, len(observer.request()["targets"]))
                with self.assertRaises(ScenarioTruthError):
                    observer.capture_baseline()

    def test_guarded_baseline_rejects_foreign_clone_serialized_and_stale_inputs(self):
        for scenario in self.scenarios:
            for attack in ("foreign", "clone", "serialized", "target", "control", "revision"):
                with self.subTest(scenario=scenario, attack=attack):
                    observer = self.observer(scenario)
                    baseline = observer.capture_baseline()
                    if attack == "foreign":
                        baseline = self.observer(scenario).capture_baseline()
                    elif attack == "clone":
                        baseline = object.__new__(type(baseline))
                    elif attack == "serialized":
                        baseline = dict(observer._baseline_receipts[id(baseline)][1])
                    elif attack == "target":
                        path = observer._root / observer.request()["targets"][0]["path_id"]
                        path.write_bytes(b"stale")
                    elif attack == "control":
                        path = observer._root / observer._fixture_row["execution_contract"]["controls"][0]["path_id"]
                        path.write_bytes(b"stale")
                    else:
                        from graph_engineering.core.contracts.immutable import freeze, thaw
                        changed = thaw(observer._binding)
                        changed["task_revision"] += 1
                        observer._binding = freeze(changed)
                    before = observer.target_bytes()
                    with self.assertRaises(ScenarioTruthError):
                        observer.execute(observer.request(), baseline_receipt=baseline)
                    self.assertEqual(observer.target_bytes(), before)
                    self.assertEqual(observer.mutation_count, 0)

    def test_capture_from_b_and_guard_request_tamper_fail_before_patch(self):
        for scenario in self.scenarios:
            observer = self.observer(scenario)
            row = observer._fixture_row["target_roles"][0]
            (observer._root / row["path_id"]).write_text(row["candidate_value"], encoding="ascii")
            with self.assertRaises(ScenarioTruthError):
                observer.capture_baseline()
            self.assertEqual(observer.mutation_count, 0)
            for attack in ("production", "environment", "omission", "order", "alias", "caller-health", "scope"):
                with self.subTest(scenario=scenario, attack=attack):
                    observer = self.observer(scenario)
                    baseline = observer.capture_baseline()
                    request = observer.request()
                    if attack == "production": request["environment"]["classification"] = "production"
                    elif attack == "environment": request["environment"]["environment_id"] += "-foreign"
                    elif attack == "omission": request["ordered_gate_ids"].pop()
                    elif attack == "order": request["ordered_gate_ids"].reverse()
                    elif attack == "alias": request["ordered_gate_ids"][1] = request["ordered_gate_ids"][0]
                    elif attack == "scope": request["targets"].pop()
                    else: request["healthy"] = True
                    before = observer.target_bytes()
                    with self.assertRaises(ScenarioTruthError):
                        observer.execute(request, baseline_receipt=baseline)
                    self.assertEqual(observer.target_bytes(), before)
                    self.assertEqual(observer.mutation_count, 0)

    def test_guarded_proof_restoration_is_exact_and_current_without_replay(self):
        from graph_engineering.core.contracts.immutable import thaw
        for scenario in self.scenarios:
            observer = self.observer(scenario)
            evidence = observer.execute(observer.request(), baseline_receipt=observer.capture_baseline())
            projection = json.loads(evidence.to_bytes())
            with mock.patch.object(type(observer), "execute", side_effect=AssertionError("replay")):
                restored = self.factory.restore_projection(projection)
                self.factory.require_current(restored)
            for attack in ("missing", "environment", "baseline", "sequence", "budget", "gates", "extra", "fixture", "before"):
                with self.subTest(scenario=scenario, attack=attack):
                    changed = copy.deepcopy(projection)
                    proof = changed["execution_proof"]
                    if attack == "missing": del changed["execution_proof"]
                    elif attack == "environment": proof["baseline"]["contract"]["environment_id"] += "-foreign"
                    elif attack == "baseline": proof["baseline"]["baseline_targets"][0]["state_id"] = "B"
                    elif attack == "sequence": proof["ordered_phases"][0]["sequence"] = True
                    elif attack == "budget": proof["baseline"]["change_bytes"] += 1
                    elif attack == "gates": proof["gate_results"].reverse()
                    elif attack == "extra": proof["extra"] = True
                    elif attack == "fixture": changed["fixture_row"]["execution_contract"]["authority_kind"] += "-foreign"
                    else: changed["before_targets"][0]["state_id"] = "B"
                    body = {k:v for k,v in changed.items() if k != "observation_digest"}
                    changed["observation_digest"] = scenario_core._semantic(body, "scenario-truth-observation")
                    with self.assertRaises(ScenarioTruthError): self.factory.restore_projection(changed)
            control = observer._fixture_row["execution_contract"]["controls"][-1]
            (observer._root / control["path_id"]).write_bytes(b"stale")
            for value in (evidence, restored):
                with self.assertRaises(ScenarioTruthError): self.factory.require_current(value)

    def test_post_patch_failure_is_not_a_zero_write_rejection_or_retry(self):
        import graph_engineering.application.scenario_truth as application_truth
        for scenario in self.scenarios:
            for drift in ("target", "control"):
                observer = self.observer(scenario)
                baseline = observer.capture_baseline()
                original = application_truth._guarded_proof
                def inject(*args):
                    row = (observer._fixture_row["target_roles"][0] if drift == "target"
                           else observer._fixture_row["execution_contract"]["controls"][0])
                    (observer._root / row["path_id"]).write_bytes(b"post-patch drift")
                    return original(*args)
                with mock.patch.object(application_truth, "_guarded_proof", side_effect=inject):
                    with self.assertRaises(ScenarioTruthError):
                        observer.execute(observer.request(), baseline_receipt=baseline)
                self.assertGreater(observer.mutation_count, 0)
                self.assertFalse(any(item[0] is observer for item in self.factory._issued_observations.values()))
                with self.assertRaises(ScenarioTruthError): observer.reject("missing-baseline", observer.request())
                with self.assertRaises(ScenarioTruthError): observer.execute(observer.request(), baseline_receipt=baseline)

    def test_every_guard_control_and_change_budget_are_pre_patch_prerequisites(self):
        from graph_engineering.core.contracts.immutable import freeze, thaw
        for scenario in self.scenarios:
            for index in range(5):
                observer = self.observer(scenario)
                baseline = observer.capture_baseline()
                control = observer._fixture_row["execution_contract"]["controls"][index]
                (observer._root / control["path_id"]).write_bytes(b"not authorized")
                with self.assertRaises(ScenarioTruthError): observer.capture_baseline()
                with self.assertRaises(ScenarioTruthError): observer.execute(observer.request(), baseline_receipt=baseline)
                self.assertEqual(observer.mutation_count, 0)
            observer = self.observer(scenario)
            fixture = thaw(observer._fixture_row)
            fixture["execution_contract"]["minimal_change_budget"] = 0
            observer._fixture_row = freeze(fixture)
            with self.assertRaises(ScenarioTruthError): observer.capture_baseline()
            self.assertEqual(observer.mutation_count, 0)

    def test_guarded_health_reads_exact_json_scalar_and_minimal_change_metric(self):
        from graph_engineering.application.scenario_truth import _guarded_proof
        self.assertEqual(scenario_core.minimal_change_bytes(b"prefixAsuffix", b"prefixBsuffix"), 2)
        self.assertEqual(scenario_core.minimal_change_bytes(b"same", b"same"), 0)
        self.assertEqual(scenario_core.minimal_change_bytes(b"abc", b"ab"), 1)
        from graph_engineering.core.contracts.immutable import freeze, thaw
        for scenario in self.scenarios:
            for candidate in ('{"healthy":1}', '{"healthy":false}', '{}', '{"healthy":true,"healthy":false}', 'malformed'):
                with self.subTest(scenario=scenario, candidate=candidate):
                    observer = self.observer(scenario)
                    fixture = thaw(observer._fixture_row)
                    fixture["target_roles"][0]["candidate_value"] = candidate
                    fixture["execution_contract"]["minimal_change_budget"] = 1024
                    (observer._root / fixture["target_roles"][0]["path_id"]).write_text(candidate, encoding="ascii")
                    with self.assertRaises(ScenarioTruthError):
                        _guarded_proof(observer._binding, freeze(fixture), self.factory.installation_pins,
                                       observer._root, observer._root_identity)

    def test_guarded_control_links_are_denied_at_capture_execute_and_restore(self):
        for phase in ("capture", "execute", "restore", "current"):
            observer = self.observer(self.scenarios[0])
            baseline = observer.capture_baseline()
            evidence = (observer.execute(observer.request(), baseline_receipt=baseline)
                        if phase in ("restore", "current") else None)
            control = observer._fixture_row["execution_contract"]["controls"][0]
            path = observer._root / control["path_id"]
            backing = path.with_name(path.name + "-backing")
            path.rename(backing)
            path.symlink_to(backing)
            count = observer.mutation_count
            with self.assertRaises(ScenarioTruthError):
                if phase == "capture": observer.capture_baseline()
                elif phase == "execute": observer.execute(observer.request(), baseline_receipt=baseline)
                elif phase == "restore": self.factory.restore_projection(evidence.to_dict())
                else: self.factory.require_current(evidence)
            self.assertEqual(observer.mutation_count, count)

    def test_guarded_root_marker_is_current_before_and_after_patch(self):
        for executed in (False, True):
            observer = self.observer(self.scenarios[0])
            baseline = observer.capture_baseline()
            evidence = observer.execute(observer.request(), baseline_receipt=baseline) if executed else None
            (observer._root / ".scenario-truth-root").write_bytes(b"foreign-task")
            count = observer.mutation_count
            with self.assertRaises(ScenarioTruthError):
                if executed: self.factory.require_current(evidence)
                else: observer.execute(observer.request(), baseline_receipt=baseline)
            self.assertEqual(observer.mutation_count, count)

    def test_guarded_rejection_marker_binding_at_issue_and_before_aggregation(self):
        for scenario in self.scenarios:
            for stage in ("issue", "aggregate"):
                for attack in ("content", "missing", "symlink"):
                    with self.subTest(scenario=scenario, stage=stage, attack=attack):
                        observer = self.observer(scenario)
                        receipt = (observer.reject("missing-baseline", observer.request())
                                   if stage == "aggregate" else None)
                        issued = dict(self.factory._issued_rejections)
                        marker = observer._root / ".scenario-truth-root"
                        if attack == "content": marker.write_bytes(b"foreign-task")
                        elif attack == "missing": marker.unlink()
                        else:
                            backing = marker.with_name("marker-backing")
                            marker.rename(backing)
                            marker.symlink_to(backing)
                        with self.assertRaises(ScenarioTruthError):
                            if stage == "issue": observer.reject("missing-baseline", observer.request())
                            else: self.factory._require_rejection_receipt(receipt)
                        self.assertEqual(self.factory._issued_rejections, issued)
                        self.assertEqual(observer.mutation_count, 0)


class RefactorScenarioTruthTests(unittest.TestCase):
    scenarios = {
        "behavior-characterization": ("behavior-equivalence",),
        "architecture-invariant": (
            "behavior-equivalence", "architecture-invariant",
        ),
        "nonfunctional-target": (
            "behavior-equivalence", "nonfunctional-target",
        ),
    }

    def setUp(self) -> None:
        self.factory = ScenarioTruthRegistryFactory.from_installation()
        self.addCleanup(self.factory.close)

    def observer(self, scenario: str):  # type: ignore[no-untyped-def]
        binding = ScenarioTruthAuthorityTests.binding()
        task_id = f"task:wp08-scenario:refactor-debt:{scenario}:p"
        binding.update(
            task_id=task_id,
            profile_id="refactor-debt",
            scenario_id=scenario,
            branch_id="branch:" + task_id,
            ref_id="ref:" + task_id,
        )
        root = tempfile.TemporaryDirectory(prefix="gew-p2c-unit-")
        self.addCleanup(root.cleanup)
        return self.factory.observation_factory(
            self.factory.registry(), binding=binding, private_root=root.name,
        )

    def test_refactor_scenarios_emit_ordered_config_owned_proofs(self) -> None:
        for scenario, expected_gates in self.scenarios.items():
            with self.subTest(scenario=scenario):
                observer = self.observer(scenario)
                contract = observer._fixture_row["refactor_contract"]
                self.assertEqual(tuple(contract["gate_ids"]), expected_gates)
                observation = observer.execute(observer.request())
                self.factory.require_current(observation)
                proof = observation.to_dict()["refactor_proof"]
                self.assertEqual(
                    tuple(row["gate_id"] for row in proof["gate_results"]),
                    expected_gates,
                )
                self.assertEqual(proof["before"]["state_id"], "A")
                self.assertEqual(proof["after"]["state_id"], "B")
                self.assertEqual(observer.mutation_count, 1)

    def test_refactor_post_gate_candidate_drift_cannot_issue_evidence(self) -> None:
        import graph_engineering.application.scenario_truth as application_truth

        observer = self.observer("nonfunctional-target")
        target = observer._fixture_row["target_roles"][0]
        target_path = observer._root / target["path_id"]
        original_evaluator = application_truth.evaluate_refactor_gates

        def drift_after_gates(contract, before, after):  # type: ignore[no-untyped-def]
            results = original_evaluator(contract, before, after)
            changed = copy.deepcopy(after)
            changed["environment_id"] = "foreign-after-gates"
            target_path.write_text(
                json.dumps(changed, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            return results

        with mock.patch.object(
            application_truth,
            "evaluate_refactor_gates",
            side_effect=drift_after_gates,
        ), self.assertRaises(ScenarioTruthError):
            observer.execute(observer.request())
        self.assertEqual(observer.mutation_count, 1)
        self.assertFalse(observer._executed)
        self.assertEqual(self.factory._issued_observations, {})
        self.assertNotEqual(
            target_path.read_bytes(), target["candidate_value"].encode("ascii"),
        )

    def test_refactor_contract_validation_is_generic_and_closed(self) -> None:
        self.assertTrue(hasattr(scenario_core, "validate_refactor_contract"))
        rows = self.factory.registry().registry.fixture_document["fixtures"]
        refactor_rows = tuple(
            row for row in rows if "refactor_contract" in row
        )
        self.assertEqual(len(refactor_rows), 3)
        for row in refactor_rows:
            scenario_core.validate_refactor_contract(
                row["refactor_contract"], row["target_roles"],
            )
            for mutate in (
                lambda value: value.update(extra=True),
                lambda value: (
                    value["gate_ids"].reverse()
                    if len(value["gate_ids"]) > 1
                    else value["gate_ids"].append("architecture-invariant")
                ),
                lambda value: value["behavior_cases"].append(
                    copy.deepcopy(value["behavior_cases"][0])
                ),
                lambda value: value["required_edges"].append(
                    copy.deepcopy(value["required_edges"][0])
                ) if value["required_edges"] else value.update(
                    required_edges=[
                        {"from_path_id": "layer/a", "to_path_id": "layer/a"},
                        {"from_path_id": "layer/a", "to_path_id": "layer/a"},
                    ]
                ),
                lambda value: value["nonfunctional_target"].update(threshold=True)
                if value["nonfunctional_target"] is not None else value.update(
                    nonfunctional_target={
                        "environment_id": "local",
                        "metric_id": "metric",
                        "comparator": "less-than-or-equal",
                        "threshold": 1.5,
                    }
                ),
            ):
                changed = thaw(freeze(row["refactor_contract"]))
                mutate(changed)
                with self.assertRaises(ScenarioTruthError):
                    scenario_core.validate_refactor_contract(
                        changed, row["target_roles"],
                    )

    def test_behavior_failure_short_circuits_every_later_gate(self) -> None:
        self.assertTrue(hasattr(scenario_core, "evaluate_refactor_gates"))
        for scenario in ("architecture-invariant", "nonfunctional-target"):
            observer = self.observer(scenario)
            row = observer._fixture_row
            before = json.loads(row["target_roles"][0]["baseline_value"])
            after = json.loads(row["target_roles"][0]["candidate_value"])
            after["behavior_observations"][0]["output_digest"] = (
                "sha256-jcs-v1:" + "f" * 64
            )
            later_name = (
                "_evaluate_architecture_gate"
                if scenario == "architecture-invariant"
                else "_evaluate_nonfunctional_gate"
            )
            with mock.patch.object(
                scenario_core, later_name, wraps=getattr(scenario_core, later_name),
            ) as later, self.assertRaises(ScenarioTruthError):
                scenario_core.evaluate_refactor_gates(
                    row["refactor_contract"], before, after,
                )
            self.assertEqual(later.call_count, 0)

    def test_architecture_and_nonfunctional_negative_vectors_fail_closed(self) -> None:
        attacks = {
            "architecture-invariant": (
                lambda value, contract: value["architecture_edges"].remove(
                    dict(contract["required_edges"][0])
                ),
                lambda value, contract: value["architecture_edges"].append(
                    dict(contract["forbidden_edges"][0])
                ),
            ),
            "nonfunctional-target": (
                lambda value, contract: value.update(environment_id="foreign"),
                lambda value, contract: value["metric_observations"][0].update(
                    value=contract["nonfunctional_target"]["threshold"] + 1
                ),
            ),
        }
        for scenario, mutations in attacks.items():
            observer = self.observer(scenario)
            row = observer._fixture_row
            before = json.loads(row["target_roles"][0]["baseline_value"])
            for mutate in mutations:
                with self.subTest(scenario=scenario, mutate=mutate):
                    after = json.loads(row["target_roles"][0]["candidate_value"])
                    mutate(after, row["refactor_contract"])
                    with self.assertRaises(ScenarioTruthError):
                        scenario_core.evaluate_refactor_gates(
                            row["refactor_contract"], before, after,
                        )


class CumulativeEntryTests(unittest.TestCase):
    """Entry/control-flow evidence only; never launches cumulative workloads."""

    def test_p2b_entry_is_distinct_and_checkpoint_oracles_are_immutable(self):
        from dataclasses import FrozenInstanceError
        from tests.support import wp08_release_coverage as fixture

        self.assertEqual(fixture.P2B_CUMULATIVE_R1_SELECTOR, "p2b-cumulative-r1")
        self.assertIn(fixture.P2B_CUMULATIVE_R1_SELECTOR, fixture.VERIFIED_RUNNER_SELECTORS)
        self.assertIn(fixture.P2A_CUMULATIVE_R2_SELECTOR, fixture.VERIFIED_RUNNER_SELECTORS)
        for selector, expected in (("p2a-cumulative-r2", (226, 113, 48, 2)),
                                   ("p2b-cumulative-r1", (230, 115, 44, 4))):
            checkpoint = fixture._cumulative_checkpoint(selector)
            self.assertEqual((checkpoint.plan_bindings, checkpoint.oracle_bindings,
                              checkpoint.missing_records, len(checkpoint.new_test_ids)), expected)
            with self.assertRaises(FrozenInstanceError): checkpoint.plan_bindings += 1
            with self.assertRaises(AttributeError): checkpoint.new_test_ids.add("foreign")
        with self.assertRaises(AssertionError): fixture._cumulative_checkpoint("foreign")

    @staticmethod
    def plan_double(selector):
        from types import SimpleNamespace as NS
        from tests.support import wp08_release_coverage as fixture
        checkpoint = fixture._cumulative_checkpoint(selector)
        ids = sorted(checkpoint.new_test_ids) + [
            f"simulated-retained-{i}" for i in range(
                checkpoint.plan_bindings - len(checkpoint.new_test_ids))]
        plan = NS(bindings={key: {"selector_kind": "scenario" if i % 2 else "mandatory",
                                 "profile_id": "new-feature", "column_id": key,
                                 "scenario_id": key, "disposition": "P"}
                            for i, key in enumerate(ids)},
                  oracle_bindings=[{"oracle_id": str(i), "profile_id": "new-feature",
                                    "selector_kind": "scenario", "column_id": "boundary",
                                    "scenario_id": str(i)}
                                   for i in range(checkpoint.oracle_bindings)])
        matrix = NS(profile_case_ids=tuple(ids), scenario_case_ids=tuple(
            f"simulated-missing-{i}" for i in range(checkpoint.missing_records)))
        return checkpoint, plan, matrix

    def test_plan_preflight_precedes_every_expensive_operation(self):
        from tests.support import wp08_release_coverage as fixture
        for attack in ("plan-count", "oracle-count", "oracle-duplicate", "new-id", "matrix-count"):
            checkpoint, plan, matrix = self.plan_double("p2b-cumulative-r1")
            if attack == "plan-count": plan.bindings.pop(next(iter(plan.bindings)))
            elif attack == "oracle-count": plan.oracle_bindings.pop()
            elif attack == "oracle-duplicate": plan.oracle_bindings[-1] = plan.oracle_bindings[0]
            elif attack == "matrix-count": matrix.scenario_case_ids += ("extra",)
            else:
                key = next(iter(checkpoint.new_test_ids))
                plan.bindings["substituted"] = plan.bindings.pop(key)
                matrix.profile_case_ids = tuple("substituted" if p == key else p
                                                for p in matrix.profile_case_ids)
            with self.subTest(attack=attack), redirect_stderr(StringIO()), \
                 mock.patch.object(fixture, "_verified_plan", return_value=(None, None, None, matrix, None, None, plan)), \
                 mock.patch.object(fixture, "_run_performance_remaining_r1_child") as sibling, \
                 mock.patch.object(fixture, "run_serial_profile_binding") as binding, \
                 self.assertRaisesRegex(AssertionError, "preflight"):
                fixture._run_p2b_cumulative_r1_child()
            sibling.assert_not_called()
            binding.assert_not_called()
        _, plan, matrix = self.plan_double("p2b-cumulative-r1")
        with self.assertRaisesRegex(AssertionError, "preflight"):
            fixture._validate_cumulative_plan(plan, matrix, fixture._cumulative_checkpoint("p2a-cumulative-r2"))

    def simulate(self, selector, attack=None):
        """All records/gates are doubles: never cumulative acceptance evidence."""
        from contextlib import ExitStack
        from types import SimpleNamespace as NS
        from tests.support import wp08_release_coverage as fixture
        from tests.support import wp08_scenario_truth as lifecycle_fixture
        from tests.unit import test_wp08_profile_contracts as contracts
        checkpoint, plan, matrix = self.plan_double(selector)
        made, closed, finalized, aborted, purposes = [], [], [], [], []
        self.last_simulation = (made, closed, finalized, aborted, purposes)

        class Result:
            profile_id = "new-feature"
            def __init__(self, key):
                self.test_id = "foreign" if attack == "execution-id" else key
                self.binding_lifecycle = NS(state="QUIESCED", generation=0, expected_purpose="issue")
                self.authority = self
                made.append(self)
            def observe_current(self):
                self.binding_lifecycle.generation = 2 if attack == "issue-generation" else 1
                self.binding_lifecycle.expected_purpose = "use"
                purposes.append((self.test_id, "issue"))
                return self
            def binding_identity_projection(self):
                key = "shared" if attack == "identity" else self.test_id
                return {field: key for field in ("repository_root", "task", "target", "branch_ref", "action_root", "command_root")}
            def close(self):
                closed.append(self.test_id)
                if attack == "close": raise AssertionError("simulated close failure")

        class Factory:
            def __init__(self, *, execution_authority=None, authority=None, **kwargs):
                self.production = execution_authority is not None
                self.rows = tuple(execution_authority or ())
                self.capability = object()
                if attack == "factory": raise AssertionError("simulated factory failure")
            def issue_execution(self, observation, **kwargs):
                observation.binding_lifecycle.generation = 2 if attack == "record-generation" else 3
                observation.binding_lifecycle.expected_purpose = "gate"
                purposes.append((observation.test_id, "use/precommit"))
                return NS(test_id=made[0].test_id if attack == "duplicate" else observation.test_id)
            def issue(self, *args, **kwargs): return NS(test_id="static-test-only")
            def finalize_after_gate(self, decision):
                finalized.append(decision)
                for row in self.rows: row.binding_lifecycle.state = "PERMANENTLY_CLOSED"
                if attack == "finalize": raise AssertionError("simulated finalize failure")
            def prepare_abort_uncommitted_candidate(self):
                if attack == "abort": raise AssertionError("simulated abort failure")
                return self.capability
            def abort_uncommitted_candidate(self, capability):
                assert capability is self.capability
                aborted.append(capability)

        def execute(**kwargs):
            self.assertTrue(kwargs["quiescent"])
            if attack == "binding" and len(made) == 2: raise AssertionError("simulated binding failure")
            return Result(kwargs.get("column", kwargs.get("scenario_id")))

        def gate(_matrix, *, coverage_records, coverage_factory):
            if coverage_factory.production:
                if attack in ("dynamic-error", "abort"): raise AssertionError("simulated dynamic failure")
                for row in made:
                    row.binding_lifecycle.generation = 3 if attack == "gate-generation" else 4
                    row.binding_lifecycle.expected_purpose = None
                    purposes.append((row.test_id, "gate"))
                missing = matrix.scenario_case_ids
                if attack == "missing": missing = missing[:-1]
                if attack == "wrong-missing": missing = ("wrong", *missing[1:])
                return NS(passed=attack == "passed", missing_test_ids=missing,
                          invalid_test_ids=("bad",) if attack == "invalid" else (),
                          stale_test_ids=("old",) if attack == "stale" else ())
            return NS(passed=attack == "static-passed",
                      missing_test_ids=matrix.profile_case_ids + matrix.scenario_case_ids,
                      invalid_test_ids=("bad",) if attack == "static-invalid" else (), stale_test_ids=())

        api = NS(CoverageRecordFactory=Factory, ReleaseCoverageGate=NS(evaluate=gate),
                 EvidenceObservationRegistry=NS(from_dict=lambda *a, **k: object()),
                 EvidenceObservationAuthority=lambda *a, **k: NS(observe=lambda *a, **k: object()))
        p1 = {"selector": fixture.PERFORMANCE_REMAINING_R1_SELECTOR,
              "plan_bindings": checkpoint.plan_bindings, "oracle_bindings": checkpoint.oracle_bindings}

        def load_plan(*, selector):
            self.assertEqual(selector, checkpoint.selector)
            return api, None, None, matrix, None, None, plan

        def load_p1(*, cumulative_selector):
            self.assertEqual(cumulative_selector, checkpoint.selector)
            return p1

        with ExitStack() as stack:
            stack.enter_context(redirect_stderr(StringIO()))
            for name, value in (("_verified_plan", load_plan),
                                ("_run_performance_remaining_r1_child", load_p1),
                                ("run_serial_profile_binding", execute), ("run_serial_scenario_binding", execute)):
                stack.enter_context(mock.patch.object(fixture, name, value))
            stack.enter_context(mock.patch.object(contracts, "_evidence_registry_document", return_value={}))
            stack.enter_context(mock.patch.object(contracts, "_oracle_manifest_bytes", return_value=b"{}"))
            stack.enter_context(mock.patch.object(fixture.os, "listdir", side_effect=([], ["leak"] if attack == "fd" else [])))
            for name, value in (("active_handle_count", 0), ("active_reopened_binding_count", 0),
                                ("maximum_active_reopened_binding_count", 2 if attack == "parallel" else 1)):
                stack.enter_context(mock.patch.object(lifecycle_fixture.PrivateBindingReopenPort, name, return_value=value))
            # Defense in depth: a missed mock must never launch any process.
            stack.enter_context(mock.patch.object(fixture.subprocess, "Popen", side_effect=AssertionError("native launch forbidden")))
            stack.enter_context(mock.patch.object(fixture.subprocess, "run", side_effect=AssertionError("native launch forbidden")))
            return fixture._run_cumulative_child(selector)

    def test_simulated_p2a_and_p2b_complete_serial_orchestration(self):
        from tests.support import wp08_release_coverage as fixture
        for selector in ("p2a-cumulative-r2", "p2b-cumulative-r1"):
            with self.subTest(selector=selector):
                receipt = self.simulate(selector)
                checkpoint = fixture._cumulative_checkpoint(selector)
                self.assertIs(fixture._validate_cumulative_receipt(receipt, checkpoint), receipt)
                made, closed, finalized, aborted, purposes = self.last_simulation
                self.assertEqual(len(made), checkpoint.plan_bindings)
                self.assertEqual(closed, [r.test_id for r in reversed(made)])
                self.assertEqual(len(finalized), 2)
                self.assertFalse(aborted)
                self.assertEqual(len(purposes), 3 * checkpoint.plan_bindings)
                self.assertTrue(all(r.binding_lifecycle.state == "PERMANENTLY_CLOSED" for r in made))

    def test_simulated_failures_preserve_denial_and_cleanup(self):
        for attack in ("execution-id", "issue-generation", "binding", "identity", "factory",
                       "record-generation", "duplicate", "dynamic-error", "abort", "passed",
                       "invalid", "stale", "missing", "wrong-missing", "gate-generation",
                       "parallel", "static-passed", "static-invalid", "finalize", "close", "fd"):
            with self.subTest(attack=attack), self.assertRaises(AssertionError):
                self.simulate("p2b-cumulative-r1", attack)
            made, closed, finalized, aborted, _ = self.last_simulation
            self.assertEqual(closed, [r.test_id for r in reversed(made)])
            if attack in ("dynamic-error", "record-generation"):
                self.assertEqual(len(aborted), 2)
                self.assertFalse(finalized)
            if attack in ("passed", "invalid", "stale", "missing", "duplicate", "static-invalid"):
                self.assertEqual(len(finalized), 2)
                self.assertFalse(aborted)

    def test_receipt_tampering_and_parent_limits(self):
        from tests.support import wp08_release_coverage as fixture
        receipt = self.simulate("p2b-cumulative-r1")
        checkpoint = fixture._cumulative_checkpoint("p2b-cumulative-r1")
        for mutate in (lambda r: r.update(selector="p2a-cumulative-r2"),
                       lambda r: r.update(extra=True), lambda r: r.pop("p1_sibling"),
                       lambda r: r.update(new_records=2), lambda r: r.update(retained_records=224),
                       lambda r: r["dynamic"].update(valid=226), lambda r: r["dynamic"].update(passed=True),
                       lambda r: r["dynamic"].update(invalid=False), lambda r: r["static"].update(valid=1),
                       lambda r: r["static"].update(duplicate=1), lambda r: r["static"].update(extra=0),
                       lambda r: r["p1_sibling"].update(plan_bindings=226)):
            bad = copy.deepcopy(receipt)
            mutate(bad)
            with self.assertRaises(AssertionError): fixture._validate_cumulative_receipt(bad, checkpoint)
        limits = fixture._cumulative_runner_testability()
        with self.assertRaises(TypeError): limits["cumulative_runtime_limit_seconds"] = 1
        with mock.patch.object(fixture, "_run_verified_selector_in_fresh_child", return_value=receipt) as launch:
            self.assertEqual(fixture.run_p2b_cumulative_r1_verified(), receipt)
        launch.assert_called_once_with("p2b-cumulative-r1", timeout_seconds=limits["cumulative_runtime_limit_seconds"],
                                       heartbeat_interval_seconds=limits["heartbeat_interval_seconds"])
        with mock.patch.object(fixture, "_run_verified_selector_in_fresh_child", return_value={}), self.assertRaises(AssertionError):
            fixture.run_p2b_cumulative_r1_verified()

    def test_parent_and_child_dispatch_do_not_cross_selectors(self):
        from contextlib import redirect_stdout
        from tests.support import wp08_release_coverage as fixture
        for selector, parent_name, child_name in (
            ("p2a-cumulative-r2", "run_p2a_cumulative_r2_verified", "_run_p2a_cumulative_r2_child"),
            ("p2b-cumulative-r1", "run_p2b_cumulative_r1_verified", "_run_p2b_cumulative_r1_child")):
            with mock.patch.object(fixture, parent_name, return_value={"selector": selector}) as parent, \
                 mock.patch.object(fixture, child_name, return_value={"selector": selector}) as child, \
                 redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(fixture._verified_runner_main([selector]), 0)
                parent.assert_called_once_with()
                child.assert_not_called()
                with mock.patch.dict(os.environ, {"GEW_WP08_VERIFIED_RUNNER_CHILD": "foreign"}), self.assertRaises(AssertionError):
                    fixture._verified_runner_main(["--verified-child", selector])
                child.assert_not_called()
                with mock.patch.dict(os.environ, {"GEW_WP08_VERIFIED_RUNNER_CHILD": selector}):
                    self.assertEqual(fixture._verified_runner_main(["--verified-child", selector]), 0)
                child.assert_called_once_with()
                self.assertEqual(fixture._verified_runner_main([selector, "extra"]), 2)
                self.assertEqual(fixture._verified_runner_main(["unknown"]), 2)


class OracleClosureEntryTests(unittest.TestCase):
    """Real installed loader paths, stopped before any acceptance workload."""

    class WorkloadBoundaryReached(RuntimeError):
        pass

    @contextmanager
    def forbid_workloads(self):
        from tests.support import wp08_release_coverage as fixture

        with ExitStack() as stack:
            for owner, name in (
                (fixture.subprocess, "Popen"),
                (fixture.subprocess, "run"),
                (fixture, "run_serial_profile_binding"),
                (fixture, "run_serial_scenario_binding"),
                (fixture, "performance_remaining_scenario_candidate"),
            ):
                stack.enter_context(mock.patch.object(
                    owner, name, side_effect=AssertionError("workload forbidden"),
                ))
            stack.enter_context(redirect_stderr(StringIO()))
            yield

    def test_checkpoint_sets_preserve_history_and_extend_current_p2c(self):
        from tests.support import wp08_release_coverage as fixture

        p2a = fixture.expected_oracle_binding_identities(
            selector=fixture.P2A_CUMULATIVE_R2_SELECTOR,
        )
        p2b = fixture.expected_oracle_binding_identities(
            selector=fixture.P2B_CUMULATIVE_R1_SELECTOR,
        )
        # Captured from the committed113 fixture before this repair, not P2b data.
        self.assertEqual(hashlib.sha256(json.dumps(
            p2a, separators=(",", ":"),
        ).encode()).hexdigest(),
            "b38cc66501af5c6e19aca36acd233ee49cd9dd2949bf69f7b6cff2db80d37f6e")
        additions = {
            ("ORA-PROFILE-HOTFIX", "hotfix", "scenario", "boundary", "emergency-baseline"),
            ("ORA-PROFILE-HOTFIX", "hotfix", "scenario", "boundary", "production-like-gate"),
        }
        self.assertEqual((len(p2a), len(set(p2a)), len(p2b), len(set(p2b))),
                         (113, 113, 115, 115))
        self.assertEqual(set(p2b), set(p2a) | additions)
        self.assertFalse(set(p2a) & additions)
        current = fixture.expected_oracle_binding_identities()
        refactor_additions = {
            (
                "ORA-PROFILE-REFACTOR-DEBT",
                "refactor-debt",
                "scenario",
                "boundary",
                scenario,
            )
            for scenario in fixture.REFACTOR_SCENARIO_IDS
        }
        self.assertEqual((len(current), len(set(current))), (118, 118))
        self.assertEqual(set(current), set(p2b) | refactor_additions)
        self.assertFalse(set(p2b) & refactor_additions)

    def test_real_installed_loader_uses_current_or_explicit_checkpoint(self):
        from tests.support import wp08_release_coverage as fixture

        with self.forbid_workloads():
            _, _, _, matrix, _, _, plan = fixture._verified_plan()
            self.assertEqual(
                (len(plan.bindings), len(plan.oracle_bindings)),
                (236, 118),
            )
            fixture._validate_cumulative_plan(
                plan, matrix, fixture._P2C_CURRENT_CHECKPOINT,
            )
            for selector in (
                fixture.P2A_CUMULATIVE_R2_SELECTOR,
                fixture.P2B_CUMULATIVE_R1_SELECTOR,
            ):
                with self.subTest(selector=selector), self.assertRaisesRegex(
                    AssertionError, "oracle closure",
                ):
                    fixture._verified_plan(selector=selector)

    def test_real_cumulative_entry_loads_plan_before_p1_work(self):
        from tests.support import wp08_release_coverage as fixture

        with self.forbid_workloads(), mock.patch.object(
            fixture, "_run_performance_remaining_r1_child",
            side_effect=self.WorkloadBoundaryReached,
        ) as boundary:
            with self.assertRaisesRegex(AssertionError, "oracle closure"):
                fixture._run_p2b_cumulative_r1_child()
            boundary.assert_not_called()
            with self.assertRaisesRegex(AssertionError, "oracle closure"):
                fixture._run_p2a_cumulative_r2_child()
            boundary.assert_not_called()

    def test_real_p1_sibling_loads_plan_before_performance_work(self):
        from tests.support import wp08_release_coverage as fixture

        with self.forbid_workloads(), mock.patch.object(
            fixture, "_scenario_attack_receipt", side_effect=self.WorkloadBoundaryReached,
        ) as boundary:
            with self.assertRaises(self.WorkloadBoundaryReached):
                fixture._run_performance_remaining_r1_child(
                    cumulative_selector=None,
                )
            self.assertEqual(boundary.call_count, 1)
            self.assertEqual(
                len(boundary.call_args.kwargs["plan"].oracle_bindings),
                118,
            )
        for selector in (
            fixture.P2A_CUMULATIVE_R2_SELECTOR,
            fixture.P2B_CUMULATIVE_R1_SELECTOR,
        ):
            with self.subTest(selector=selector), self.forbid_workloads(), mock.patch.object(
                fixture, "_scenario_attack_receipt", side_effect=self.WorkloadBoundaryReached,
            ) as boundary, self.assertRaisesRegex(AssertionError, "oracle closure"):
                fixture._run_performance_remaining_r1_child(
                    cumulative_selector=selector,
                )
            boundary.assert_not_called()

    def test_identity_closure_rejects_omission_duplicate_and_substitution(self):
        from types import SimpleNamespace as NS
        from tests.support import wp08_release_coverage as fixture

        fields = ("oracle_id", "profile_id", "selector_kind", "column_id", "scenario_id")
        for selector in (fixture.P2A_CUMULATIVE_R2_SELECTOR, fixture.P2B_CUMULATIVE_R1_SELECTOR):
            # Deliberately malformed plan doubles: validation evidence only.
            rows = [dict(zip(fields, row)) for row in fixture.expected_oracle_binding_identities(
                selector=selector,
            )]
            scenario_index = next(i for i, row in enumerate(rows) if row["selector_kind"] == "scenario")
            mutations = {"missing": rows[:-1], "duplicate": rows[:-1] + [rows[0]],
                         "extra": rows + [dict(rows[scenario_index], oracle_id="foreign")]}
            for field in fields:
                changed = copy.deepcopy(rows)
                changed[scenario_index][field] = "foreign"
                mutations[field] = changed
            for label, values in (("valid", rows), *mutations.items()):
                plan = NS(oracle_bindings=values)
                api4 = NS(ProfileCoverageExecutionPlan=NS(from_installation=lambda **kwargs: plan))
                with self.subTest(selector=selector, mutation=label), self.forbid_workloads(), \
                     mock.patch.object(fixture, "_verified_runner_contracts", return_value=(None,) * 5), \
                     mock.patch.object(fixture, "load_slice4_api", return_value=api4):
                    if label == "valid":
                        self.assertIs(fixture._verified_plan(selector=selector)[-1], plan)
                    else:
                        with self.assertRaisesRegex(AssertionError, "oracle closure"):
                            fixture._verified_plan(selector=selector)

    def test_unknown_checkpoint_fails_before_loading_contracts(self):
        from tests.support import wp08_release_coverage as fixture

        for selector in ("", "p2c", "performance-remaining-r1", True, 113, [], {}):
            with self.subTest(selector=selector), mock.patch.object(
                fixture, "_verified_runner_contracts", side_effect=AssertionError("loader invoked"),
            ) as loader:
                with self.assertRaisesRegex(AssertionError, "unknown cumulative checkpoint"):
                    fixture._verified_plan(selector=selector)
                loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
