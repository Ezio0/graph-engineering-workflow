"""ADR-0007 Slice-A benchmark-authority contract probes."""

from __future__ import annotations

import copy
import importlib
import json
import os
import pathlib
import socket
from collections.abc import Callable
from unittest import mock

from graph_engineering.adapters.command_native import (  # noqa: E402
    CommandExecutionRequest,
    SecretProviderPorts,
)
from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from graph_engineering.core.contracts.immutable import thaw  # noqa: E402
from tests.integration.test_wp07a_command_runtime import (  # noqa: E402
    SECRET_VALUE,
    adapter_factory,
    invocation_for,
    provider_registry,
    request,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
PERFORMANCE_BENCHMARK_SCHEMA_IDS = tuple(sorted({
    f"urn:gew:schema:{name}{suffix}:1.0.0"
    for name in (
        "performance-benchmark-case",
        "performance-benchmark-registry",
        "performance-benchmark-installation-bootstrap",
        "performance-environment-observation",
        "performance-correctness-observation",
        "performance-measurement-sample",
        "performance-sample-set-observation",
        "performance-statistics-observation",
        "performance-observation",
    )
    for suffix in ("", "-input")
}))


def _api():
    core = importlib.import_module("graph_engineering.core.performance_benchmark")
    application = importlib.import_module(
        "graph_engineering.application.performance_benchmark"
    )
    return core, application


def _resign(document: dict[str, object], name: str, field: str) -> None:
    document.pop(field, None)
    document[field] = semantic_digest(
        document,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _launcher(registry_factory: object, authority: object, root: object):
    provider_document = provider_registry()
    factory = adapter_factory(dict(registry_factory.command_configuration_pins(
        authority, root, provider_document["registry_digest"],
    )))
    provider = factory.issue_secret_provider(
        provider_document,
        SecretProviderPorts(resolve=lambda _reference: SECRET_VALUE),
    )
    launcher = registry_factory.command_launcher(
        authority, root, factory, provider,
    )
    request_document = request("clean")
    request_document["command_id"] = launcher.command_id
    request_document["parameters"] = {"mode": "correct"}
    request_document["secret_references"] = []
    request_document["request_digest"] = CommandExecutionRequest.digest_document(request_document)
    invocation_document, expected = invocation_for(request_document)
    correctness_digest = authority.registry.benchmark_cases[0].expected_correctness_digest
    return launcher, request_document, invocation_document, expected, correctness_digest


def _coherent_installation_replacement(resources: tuple[bytes, ...]) -> tuple[bytes, ...]:
    provenance, registry_raw, bootstrap_raw, *tail = resources
    registry = json.loads(registry_raw)
    registry["benchmark_cases"][0]["candidate_source_identity"] = (
        "source:performance-candidate-substituted-v1"
    )
    _resign(
        registry["benchmark_cases"][0],
        "performance-benchmark-case",
        "benchmark_case_digest",
    )
    _resign(registry, "performance-benchmark-registry", "registry_digest")
    changed_registry = json.dumps(registry, separators=(",", ":")).encode()
    return provenance, changed_registry, bootstrap_raw, *tail


def _forbid_network(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("performance benchmark attempted network access")


def _exercise_measurement(case, *, reject_clock: bool = False):
    core, application = _api()
    graph_engineering = importlib.import_module("graph_engineering")
    patches = [
        mock.patch.object(socket, "create_connection", _forbid_network),
        mock.patch.object(socket.socket, "connect", _forbid_network),
        mock.patch.object(socket, "getaddrinfo", _forbid_network),
    ]
    if reject_clock:
        patches.append(mock.patch.object(application.time, "monotonic_ns", return_value=10))
    entered = [item.__enter__() for item in patches]
    del entered
    launcher = None
    root = None
    session = None
    try:
        registry_factory = application.PerformanceBenchmarkRegistryFactory.from_installation()
        authority = registry_factory.registry()
        root = registry_factory.private_root(authority)
        launcher, request_document, invocation_document, expected, correctness = _launcher(
            registry_factory, authority, root,
        )
        if reject_clock:
            with case.assertRaises(core.PerformanceBenchmarkError):
                session = registry_factory.command_session(authority, root, launcher)
                registry_factory.observation_factory(authority, session)
            case.assertEqual(launcher.launch_count, 0)
            return None
        session = registry_factory.command_session(authority, root, launcher)
        hostile_external = root.root.parent / f"{root.root.name}-ambient-write"
        (root.work / "sitecustomize.py").write_text(
            "import pathlib,socket\n"
            f"pathlib.Path({os.fspath(hostile_external)!r}).write_text('loaded')\n"
            "socket.create_connection(('127.0.0.1', 9), timeout=0.01)\n",
            encoding="utf-8",
        )
        (root.work / "ambient.pth").write_text(
            "import sitecustomize\n", encoding="utf-8",
        )
        observation_factory = registry_factory.observation_factory(authority, session)
        arguments = {
            "case_id": "performance-local-command-v1",
            "invocation_document": invocation_document,
            "expected": expected,
            "request_document": request_document,
        }
        baseline_source = registry_factory.observe_source(authority, session)
        launch_baseline = launcher.launch_count
        with mock.patch.object(application.time, "monotonic_ns", return_value=100):
            with case.assertRaises(core.PerformanceBenchmarkError):
                observation_factory.measure(
                    sequence_kind="baseline", source_observation=baseline_source, **arguments,
                )
        case.assertEqual(launcher.launch_count, launch_baseline)
        rejected_request = copy.deepcopy(request_document)
        rejected_request["parameters"] = {"mode": "write"}
        rejected_request["request_digest"] = CommandExecutionRequest.digest_document(
            rejected_request,
        )
        rejected_invocation, rejected_expected = invocation_for(rejected_request)
        with case.assertRaises(core.PerformanceBenchmarkError):
            observation_factory.measure(
                sequence_kind="baseline", source_observation=baseline_source,
                invocation_document=rejected_invocation, expected=rejected_expected,
                request_document=rejected_request, case_id="performance-local-command-v1",
            )
        case.assertEqual(launcher.launch_count, launch_baseline)
        baseline = observation_factory.measure(
            sequence_kind="baseline", source_observation=baseline_source, **arguments,
        )
        registry_factory.transition_source(
            authority, session, "source:performance-candidate-v1",
        )
        candidate_source = registry_factory.observe_source(authority, session)
        with case.assertRaises(core.PerformanceBenchmarkError):
            observation_factory.measure(
                sequence_kind="candidate", source_observation=baseline_source, **arguments,
            )
        case.assertEqual(launcher.launch_count, 6)
        candidate = observation_factory.measure(
            sequence_kind="candidate", source_observation=candidate_source, **arguments,
        )
        registry_factory.transition_source(
            authority, session, "source:performance-baseline-v1",
        )
        rollback_source = registry_factory.observe_source(authority, session)
        altered_source = thaw(rollback_source.observation)
        altered_source["source_identity"] = "source:performance-candidate-v1"
        _resign(
            altered_source, "performance-source-observation", "source_observation_digest",
        )
        with case.assertRaises(core.PerformanceBenchmarkError):
            registry_factory.rehydrate_source_observation(
                authority, session, altered_source,
            )
        rollback = observation_factory.measure(
            sequence_kind="rollback", source_observation=rollback_source, **arguments,
        )
        target = observation_factory.compare_target(baseline, candidate)
        restored = observation_factory.compare_rollback(baseline, candidate, rollback)
        case.assertTrue(target.passed)
        case.assertTrue(restored.passed)
        case.assertIs(observation_factory.require_comparison_current(target), target)
        case.assertIs(observation_factory.require_comparison_current(restored), restored)
        case.assertEqual(launcher.launch_count, 18)
        case.assertFalse(hostile_external.exists())
        case.assertEqual(len(baseline.durations_ns), 5)
        case.assertGreater(baseline.median_ns, 0)
        case.assertGreaterEqual(baseline.mad_ns, 0)
        case.assertIs(
            registry_factory.rehydrate_source_observation(
                authority, session, thaw(rollback_source.observation),
            ),
            rollback_source,
        )
        with case.assertRaises(core.PerformanceBenchmarkError):
            observation_factory.require_current(copy.copy(baseline))
        previous_tz = os.environ.get("TZ")
        os.environ["TZ"] = "GEW-FOREIGN-TZ"
        try:
            with case.assertRaises(core.PerformanceBenchmarkError):
                observation_factory.require_current(baseline)
        finally:
            if previous_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = previous_tz
        task_binding = {
            "task_id": "task:performance-slice-a-v1",
            "task_revision": 7,
            "snapshot_digest": "sha256-jcs-v1:" + "1" * 64,
            "invalidation_epoch": 2,
            "profile_id": "performance",
            "profile_version": "1.0.0",
            "column_id": "normal",
            "graph_ref_pins": {
                key: "sha256-jcs-v1:" + character * 64
                for key, character in zip((
                    "base_graph_digest", "profile_digest", "overlay_digest",
                    "project_config_digest", "support_matrix_digest",
                    "materialization_digest",
                ), "234567", strict=True)
            },
        }
        evidence = observation_factory.issue_task_evidence(
            task_binding=task_binding,
            source_history=(baseline_source, candidate_source, rollback_source),
            baseline=baseline,
            candidate=candidate,
            rollback=rollback,
            target=target,
            restored=restored,
        )
        case.assertIs(
            registry_factory.require_performance_evidence_current(evidence), evidence,
        )
        durable_evidence = thaw(evidence.projection)
        restarted = application.PerformanceBenchmarkRegistryFactory.from_installation()
        with case.assertRaises(core.PerformanceBenchmarkError):
            restarted.require_current(authority)
        restarted_authority = restarted.registry()
        restarted_root = restarted.private_root(restarted_authority)
        restarted_launcher = None
        restarted_session = None
        try:
            restarted_launcher, *_ = _launcher(
                restarted, restarted_authority, restarted_root,
            )
            restarted_session = restarted.command_session(
                restarted_authority, restarted_root, restarted_launcher,
            )
            durable_history = tuple(
                thaw(item.observation)
                for item in (baseline_source, candidate_source, rollback_source)
            )
            rehydrated = restarted.rehydrate_source_history(
                restarted_authority, restarted_session, durable_history,
            )
            case.assertEqual(
                tuple(item.observation_digest for item in rehydrated),
                tuple(item.observation_digest for item in (
                    baseline_source, candidate_source, rollback_source,
                )),
            )
            case.assertEqual(restarted_launcher.launch_count, 0)
            restored_evidence = restarted.rehydrate_performance_evidence(
                restarted_authority, copy.deepcopy(durable_evidence),
            )
            case.assertEqual(
                restored_evidence.projection_digest, evidence.projection_digest,
            )
            case.assertEqual(restarted_launcher.launch_count, 0)
            changed_evidence = copy.deepcopy(durable_evidence)
            changed_evidence["source_history"] = list(reversed(
                changed_evidence["source_history"]
            ))
            _resign(
                changed_evidence,
                "performance-evidence-projection",
                "projection_digest",
            )
            with case.assertRaises(core.PerformanceBenchmarkError):
                restarted.rehydrate_performance_evidence(
                    restarted_authority, changed_evidence,
                )
            altered_history = list(copy.deepcopy(durable_history))
            altered_history[1]["source_raw_sha256"] = "0" * 64
            _resign(
                altered_history[1],
                "performance-source-observation",
                "source_observation_digest",
            )
            foreign_restart = application.PerformanceBenchmarkRegistryFactory.from_installation()
            foreign_authority = foreign_restart.registry()
            foreign_root = foreign_restart.private_root(foreign_authority)
            foreign_launcher = None
            foreign_session = None
            try:
                foreign_launcher, *_ = _launcher(
                    foreign_restart, foreign_authority, foreign_root,
                )
                foreign_session = foreign_restart.command_session(
                    foreign_authority, foreign_root, foreign_launcher,
                )
                with case.assertRaises(core.PerformanceBenchmarkError):
                    foreign_restart.rehydrate_source_history(
                        foreign_authority, foreign_session, tuple(altered_history),
                    )
                reordered_history = tuple(
                    dict(reversed(tuple(document.items())))
                    if index == 1 else copy.deepcopy(document)
                    for index, document in enumerate(durable_history)
                )
                with case.assertRaises(core.PerformanceBenchmarkError):
                    foreign_restart.rehydrate_source_history(
                        foreign_authority, foreign_session, reordered_history,
                    )
                case.assertEqual(foreign_launcher.launch_count, 0)
            finally:
                if foreign_session is not None:
                    foreign_session.close()
                else:
                    if foreign_launcher is not None:
                        foreign_launcher.close()
                    foreign_root.close()
        finally:
            if restarted_session is not None:
                restarted_session.close()
            else:
                if restarted_launcher is not None:
                    restarted_launcher.close()
                restarted_root.close()
        resources = graph_engineering._performance_benchmark_installation_resources()
        replacement = _coherent_installation_replacement(resources)
        with mock.patch.object(
            graph_engineering,
            "_performance_benchmark_installation_resources",
            return_value=replacement,
        ) as loader:
            with case.assertRaises(core.PerformanceBenchmarkError):
                observation_factory.require_current(baseline)
            case.assertGreaterEqual(loader.call_count, 1)
        with mock.patch.object(
            graph_engineering,
            "_performance_benchmark_installation_resources",
            return_value=resources[:-1],
        ) as loader:
            with case.assertRaises(core.PerformanceBenchmarkError):
                registry_factory.require_current(authority)
            case.assertGreaterEqual(loader.call_count, 1)
        return baseline, candidate, rollback, target, restored
    finally:
        for item in reversed(patches):
            item.__exit__(None, None, None)
        if session is not None:
            session.close()
        else:
            if launcher is not None:
                launcher.close()
            if root is not None:
                root.close()


def assert_performance_slice_a_schema_instances(case, registry, context: Callable[[], object]) -> None:
    del context
    for schema_id in PERFORMANCE_BENCHMARK_SCHEMA_IDS:
        with case.subTest(performance_schema=schema_id):
            case.assertIsNotNone(registry.resource(schema_id))


def assert_performance_slice_a_positive(
    case, schema_registry: object | None = None,
    context: Callable[[], object] | None = None,
) -> None:
    core, application = _api()
    document = json.loads(
        (ROOT / "config/performance/performance-benchmark-registry-v1.json").read_text(
            encoding="utf-8"
        )
    )
    parsed = core.parse_performance_benchmark_registry(document)
    case.assertEqual(parsed.profile_identities, ("performance",))
    case.assertEqual(parsed.case_ids, ("performance-local-command-v1",))
    policy = parsed.statistics_policies[0]
    case.assertGreaterEqual(policy.repetition_count, 3)
    case.assertEqual(policy.repetition_count % 2, 1)
    case.assertGreaterEqual(policy.warmup_count, 0)
    case.assertEqual(
        core.integer_statistics((101, 100, 103, 102, 99), policy),
        (101, 1, True),
    )
    case.assertTrue(core.ratio_within(100, 101, 1, 1))
    case.assertFalse(core.ratio_within(102, 101, 1, 1))
    factory = application.PerformanceBenchmarkRegistryFactory.from_installation()
    authority = factory.registry()
    case.assertIs(factory.require_current(authority), authority)
    restarted = application.PerformanceBenchmarkRegistryFactory.from_installation()
    with case.assertRaises(core.PerformanceBenchmarkError):
        restarted.require_current(authority)
    result = _exercise_measurement(case)
    case.assertIsNotNone(result)
    if schema_registry is None or context is None or result is None:
        return
    baseline, candidate, rollback, target, restored = result
    records: list[tuple[str, object, str]] = []
    for sequence in (baseline, candidate, rollback):
        records.extend((
            (
                "performance-environment-observation",
                sequence.before_environment,
                "environment_digest",
            ),
            (
                "performance-environment-observation",
                sequence.after_environment,
                "environment_digest",
            ),
            (
                "performance-sample-set-observation",
                sequence.sample_set_observation,
                "sample_set_observation_digest",
            ),
            (
                "performance-statistics-observation",
                sequence.statistics_observation,
                "statistics_observation_digest",
            ),
        ))
        records.extend(
            ("performance-correctness-observation", item, "correctness_digest")
            for item in sequence.warmup_correctness_observations
        )
        for sample in sequence.sample_documents:
            records.append(("performance-measurement-sample", sample, "sample_digest"))
            records.append((
                "performance-correctness-observation",
                sample["correctness_observation"],
                "correctness_digest",
            ))
    records.extend((
        ("performance-observation", target.observation, "performance_observation_digest"),
        ("performance-observation", restored.observation, "performance_observation_digest"),
    ))
    for stem, frozen_document, digest_field in records:
        document = thaw(frozen_document)
        with case.subTest(performance_record=stem):
            case.assertEqual(
                schema_registry.validate(
                    f"urn:gew:schema:{stem}:1.0.0", document, context(),
                ),
                [],
            )
            document.pop(digest_field)
            case.assertEqual(
                schema_registry.validate(
                    f"urn:gew:schema:{stem}-input:1.0.0", document, context(),
                ),
                [],
            )


def assert_performance_slice_a_rejections(case) -> None:
    core, application = _api()
    source = json.loads(
        (ROOT / "config/performance/performance-benchmark-registry-v1.json").read_text(
            encoding="utf-8"
        )
    )
    mutations: list[dict[str, object]] = []
    for field, value in (
        ("warmup_count", True),
        ("repetition_count", 4),
        ("repetition_count", 3.0),
        ("noise_ceiling_denominator", 0),
    ):
        changed = copy.deepcopy(source)
        changed["statistics_policies"][0][field] = value
        mutations.append(changed)
    reordered = copy.deepcopy(source)
    reordered["environment_policy"]["required_fingerprint_field_ids"] = list(reversed(
        reordered["environment_policy"]["required_fingerprint_field_ids"]
    ))
    mutations.append(reordered)
    duplicated = copy.deepcopy(source)
    duplicated["benchmark_cases"].append(copy.deepcopy(duplicated["benchmark_cases"][0]))
    mutations.append(duplicated)
    for changed in mutations:
        with case.subTest(performance_registry_mutation=changed), case.assertRaises(
            core.PerformanceBenchmarkError
        ):
            core.parse_performance_benchmark_registry(changed)
    for samples in (
        (1, 2),
        (1, True, 3),
        (1, 0, 3),
        (1, 2.0, 3),
    ):
        with case.subTest(samples=samples), case.assertRaises(
            core.PerformanceBenchmarkError
        ):
            core.integer_statistics(samples, core.parse_performance_benchmark_registry(source).statistics_policies[0])
    factory = application.PerformanceBenchmarkRegistryFactory.from_installation()
    authority = factory.registry()
    clone = object.__new__(type(authority))
    for candidate in (clone, object()):
        with case.subTest(authority=candidate), case.assertRaises(
            core.PerformanceBenchmarkError
        ):
            factory.require_current(candidate)
    case.assertIs(factory.require_current(authority), authority)
    _exercise_measurement(case, reject_clock=True)


def assert_performance_slice_a_r1_contracts(case) -> None:
    """Exact RED contracts for stable Slice-A reviewer findings 001..008."""

    core, application = _api()
    registry = json.loads(
        (ROOT / "config/performance/performance-benchmark-registry-v1.json").read_text(
            encoding="utf-8"
        )
    )
    bootstrap = json.loads(
        (
            ROOT
            / "config/performance/performance-benchmark-installation-bootstrap-v1.json"
        ).read_text(encoding="utf-8")
    )
    bootstrap_schema = json.loads(
        (
            ROOT
            / "config/contracts/schemas/"
            / "performance-benchmark-installation-bootstrap-1.0.0.json"
        ).read_text(encoding="utf-8")
    )
    with case.subTest(stable_finding="WP08-PERF-A-R1-001"):
        case.assertEqual(
            set(bootstrap_schema["properties"]),
            set(bootstrap),
            "shipped bootstrap must validate against its exact source schema",
        )
    with case.subTest(stable_finding="WP08-PERF-A-R1-002"):
        case.assertTrue(
            hasattr(application, "PerformanceBenchmarkClockAuthority"),
            "measurement clock must be factory-attested and strongly identified",
        )
    factory = application.PerformanceBenchmarkRegistryFactory.from_installation()
    authority = factory.registry()
    with case.subTest(stable_finding="WP08-PERF-A-R1-003"):
        with case.assertRaises(AttributeError):
            authority.projection = authority.projection
        for legacy_list in (
            "_authorities", "_sequence_factories", "_clock_authorities",
            "_sessions", "_source_observations",
        ):
            case.assertFalse(
                hasattr(factory, legacy_list),
                f"caller-mutable issuance list remains exposed: {legacy_list}",
            )
        clone = object.__new__(type(authority))
        for field in ("_owner", "registry", "projection", "_sealed"):
            object.__setattr__(clone, field, getattr(authority, field))
        with case.assertRaises(core.PerformanceBenchmarkError):
            factory.require_current(clone)
    with case.subTest(stable_finding="WP08-PERF-A-R1-004"):
        case.assertTrue(
            hasattr(application, "BenchmarkSourceObservationAuthority"),
            "source A/B/restored-A observations must be factory-issued",
        )
        case.assertTrue(
            hasattr(factory, "rehydrate_source_observation"),
            "restart must rehydrate exact durable source evidence without launch",
        )
        case.assertTrue(
            hasattr(application, "PerformanceBenchmarkEvidenceAuthority"),
            "task-unique durable performance evidence authority is absent",
        )
        case.assertTrue(
            hasattr(factory, "rehydrate_performance_evidence"),
            "restart must reissue exact task evidence without a launcher",
        )
        for version in ("category-completion-assessment", "category-completion-assessment-input"):
            case.assertTrue(
                (ROOT / "config/contracts/schemas" / f"{version}-1.1.0.json").is_file(),
                "Option B performance assessment schema 1.1 is absent",
            )
    command_binding = (
        ROOT / "config/performance/performance-command-binding-v1.json"
    )
    correctness_oracle = (
        ROOT / "config/performance/performance-correctness-oracle-v1.json"
    )
    with case.subTest(stable_finding="WP08-PERF-A-R1-005"):
        case.assertTrue(command_binding.is_file())
        case.assertTrue(correctness_oracle.is_file())
        case.assertTrue(hasattr(factory, "command_session"))
    required_fingerprint = set(
        registry["environment_policy"]["required_fingerprint_field_ids"]
    )
    with case.subTest(stable_finding="WP08-PERF-A-R1-006"):
        case.assertTrue({
            "installed-record", "command-cwd", "fixture-root", "source-history",
            "build-attestation", "protected-closure",
        }.issubset(required_fingerprint))
        case.assertTrue({
            "distribution_root", "distribution_version", "record_raw_sha256",
            "source_attestation_digest", "build_attestation_digest",
            "protected_closure_digest",
        }.issubset(set(authority.projection)))
    with case.subTest(stable_finding="WP08-PERF-A-R1-007"):
        case.assertIs(type(bootstrap["maximum_repetition_count"]), int)
        case.assertIs(type(bootstrap["maximum_warmup_count"]), int)
        case.assertGreaterEqual(bootstrap["maximum_repetition_count"], 3)
    with case.subTest(stable_finding="WP08-PERF-A-R1-008"):
        if command_binding.is_file():
            binding = json.loads(command_binding.read_text(encoding="utf-8"))
            case.assertEqual(binding["side_effect_class"], "benchmark-read-only")
            case.assertEqual(binding["root_mode"], "factory-private-disposable")
        else:
            case.fail("benchmark-safe read-only command binding is not shipped")

    root = factory.private_root(authority)
    launcher = None
    session = None
    try:
        launcher, *_ = _launcher(factory, authority, root)
        session = factory.command_session(authority, root, launcher)
        with case.subTest(stable_finding="WP08-PERF-A-R1-005"):
            case.assertEqual(
                session.command_registry_digest,
                launcher.command_registry_digest,
                "session must bind the actual attested command registry",
            )
            case.assertEqual(
                session.command_binding_digest,
                authority.projection["binding"]["binding_digest"],
                "binding-template provenance must remain separately named",
            )
        with case.subTest(stable_finding="WP08-PERF-A-R1-008"):
            case.assertEqual(
                launcher._entry.argv_prefix[:3],
                ("-I", "-S", "-B"),
                "benchmark child must be isolated from ambient Python state",
            )
    finally:
        if session is not None:
            session.close()
        else:
            if launcher is not None:
                launcher.close()
            root.close()

    # Keep the core parser in the same RED path so coherent registry repairs
    # cannot bypass the installation-owned bounds contract.
    case.assertEqual(
        core.parse_performance_benchmark_registry(
            registry,
            maximum_repetition_count=bootstrap["maximum_repetition_count"],
            maximum_warmup_count=bootstrap["maximum_warmup_count"],
        ).registry_id,
        registry["registry_id"],
    )
