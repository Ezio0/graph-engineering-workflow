"""ADR-0006 Slice A contract fixtures with no production-authority fallback."""

from __future__ import annotations

import copy
import base64
import hashlib
import importlib
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import warnings
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable
from unittest import mock

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import freeze, thaw
from tests.support.wp03_repository import ManualTime, repository_stack


ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "config/security/dependency-advisory-registry-v2.json"
BOOTSTRAP_PATH = ROOT / "config/security/dependency-advisory-installation-bootstrap-v1.2.json"
GRAPH_POLICY_PATH = ROOT / "config/security/dependency-graph-policy-registry-v1.json"
REMEDIATION_PATH = (
    ROOT / "config/security/dependency-remediation-disposition-registry-v1.json"
)
GRAPH_BOOTSTRAP_PATH = (
    ROOT / "config/security/dependency-advisory-installation-bootstrap-v1.1.json"
)
SOURCE_ARTIFACT_PATH = ROOT / "config/security/dependency-advisory-source-v2.json"
SOURCE_ATTESTATION_PATH = (
    ROOT / "config/security/dependency-advisory-source-attestation-v2.json"
)

DEPENDENCY_SECURITY_SCHEMA_IDS = frozenset({
    "urn:gew:schema:dependency-advisory-source-record:1.0.0",
    "urn:gew:schema:dependency-advisory-source-record-input:1.0.0",
    "urn:gew:schema:dependency-fixed-closure:1.0.0",
    "urn:gew:schema:dependency-fixed-closure-input:1.0.0",
    "urn:gew:schema:dependency-advisory-record:1.0.0",
    "urn:gew:schema:dependency-advisory-record-input:1.0.0",
    "urn:gew:schema:dependency-advisory-status-high-water:1.0.0",
    "urn:gew:schema:dependency-advisory-status-high-water-input:1.0.0",
    "urn:gew:schema:dependency-advisory-registry:1.0.0",
    "urn:gew:schema:dependency-advisory-registry-input:1.0.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.0.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.0.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.2.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.2.0",
    "urn:gew:schema:dependency-offline-closure-observation:1.0.0",
    "urn:gew:schema:dependency-offline-closure-observation-input:1.0.0",
    "urn:gew:schema:dependency-applicability-observation:1.0.0",
    "urn:gew:schema:dependency-applicability-observation-input:1.0.0",
    "urn:gew:schema:dependency-residual-exposure-observation:1.0.0",
    "urn:gew:schema:dependency-residual-exposure-observation-input:1.0.0",
    "urn:gew:schema:dependency-security-observation:1.0.0",
    "urn:gew:schema:dependency-security-observation-input:1.0.0",
})

DEPENDENCY_GRAPH_SCHEMA_IDS = frozenset({
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0",
    "urn:gew:schema:dependency-closure-graph-observation-input:1.0.0",
    "urn:gew:schema:dependency-closure-graph-observation:1.0.0",
    "urn:gew:schema:dependency-graph-policy-registry-input:1.0.0",
    "urn:gew:schema:dependency-graph-policy-registry:1.0.0",
    "urn:gew:schema:dependency-remediation-disposition-registry-input:1.0.0",
    "urn:gew:schema:dependency-remediation-disposition-registry:1.0.0",
    "urn:gew:schema:dependency-security-observation-input:1.1.0",
    "urn:gew:schema:dependency-security-observation:1.1.0",
})


class MissingDependencySecurityContract(AssertionError):
    """The production ADR-0006 Slice A surface has not been implemented."""


@dataclass(frozen=True, slots=True)
class SliceAAPI:
    DependencySecurityError: type[Exception]
    DependencyAdvisoryRegistryData: type
    DependencyEvaluation: type
    DependencyRegistryRollbackAuthority: type
    parse_dependency_advisory_registry: Callable[..., object]
    validate_dependency_registry_update: Callable[..., object]
    evaluate_dependency_closures: Callable[..., object]
    DependencyAdvisoryRegistryFactory: type
    DependencyAdvisoryRegistryAuthority: type
    DependencyAdvisorySourceAuthority: type
    DependencyAdvisoryIdentityAuthority: type
    DependencyOfflineClosureObservationFactory: type
    DependencyApplicabilityObservationFactory: type
    DependencyResidualExposureFactory: type
    DependencyOfflineClosureObservation: type
    DependencyApplicabilityObservation: type
    DependencyResidualExposureObservation: type


@dataclass(frozen=True, slots=True)
class SliceBAPI:
    DependencySecurityError: type[Exception]
    DependencySecurityObservation: type
    DependencySecurityObservationFactory: type


@dataclass(frozen=True, slots=True)
class DependencyGraphSliceAAPI:
    DependencySecurityError: type[Exception]
    DependencyGraphPolicyData: type
    DependencyRemediationRegistryData: type
    parse_dependency_graph_policy_registry: Callable[..., object]
    parse_dependency_remediation_registry: Callable[..., object]
    DependencyClosureGraphObservation: type
    DependencyGraphObservationFactory: type
    DependencyRemediationDispositionAuthority: type


def load_slice_a_api() -> SliceAAPI:
    missing: list[str] = []
    try:
        core = importlib.import_module("graph_engineering.core.dependency_security")
    except ModuleNotFoundError:
        core = None
        missing.append("graph_engineering.core.dependency_security")
    try:
        application = importlib.import_module(
            "graph_engineering.application.dependency_security"
        )
    except ModuleNotFoundError:
        application = None
        missing.append("graph_engineering.application.dependency_security")
    core_names = (
        "DependencySecurityError",
        "DependencyAdvisoryRegistryData",
        "DependencyEvaluation",
        "DependencyRegistryRollbackAuthority",
        "parse_dependency_advisory_registry",
        "validate_dependency_registry_update",
    )
    application_names = (
        "evaluate_dependency_closures",
        "DependencyAdvisoryRegistryFactory",
        "DependencyAdvisoryRegistryAuthority",
        "DependencyAdvisorySourceAuthority",
        "DependencyAdvisoryIdentityAuthority",
        "DependencyOfflineClosureObservationFactory",
        "DependencyApplicabilityObservationFactory",
        "DependencyResidualExposureFactory",
        "DependencyOfflineClosureObservation",
        "DependencyApplicabilityObservation",
        "DependencyResidualExposureObservation",
    )
    for name in core_names:
        if core is None or not hasattr(core, name):
            missing.append(name)
    for name in application_names:
        if application is None or not hasattr(application, name):
            missing.append(name)
    if missing:
        raise MissingDependencySecurityContract(
            "ADR-0006 Slice A production contract is absent: "
            + ", ".join(missing)
        )
    error = getattr(core, "DependencySecurityError")
    if not isinstance(error, type) or not issubclass(error, Exception):
        raise MissingDependencySecurityContract(
            "DependencySecurityError is not an exception type"
        )
    return SliceAAPI(
        **{name: getattr(core, name) for name in core_names},
        **{name: getattr(application, name) for name in application_names},
    )


def load_slice_b_api() -> SliceBAPI:
    """Load the closed final-observation boundary; never supply a test fallback."""

    application = importlib.import_module(
        "graph_engineering.application.dependency_security"
    )
    names = (
        "DependencySecurityObservation",
        "DependencySecurityObservationFactory",
    )
    missing = tuple(name for name in names if not hasattr(application, name))
    if missing:
        raise MissingDependencySecurityContract(
            "ADR-0006 Slice B production contract is absent: "
            + ", ".join(missing)
        )
    error = getattr(
        importlib.import_module("graph_engineering.core.dependency_security"),
        "DependencySecurityError",
    )
    return SliceBAPI(
        DependencySecurityError=error,
        **{name: getattr(application, name) for name in names},
    )


def load_dependency_graph_slice_a_api() -> DependencyGraphSliceAAPI:
    """Load only the ADR-0006 r7 graph/remediation foundation surface."""

    core = importlib.import_module("graph_engineering.core.dependency_security")
    application = importlib.import_module(
        "graph_engineering.application.dependency_security"
    )
    core_names = (
        "DependencySecurityError",
        "DependencyGraphPolicyData",
        "DependencyRemediationRegistryData",
        "parse_dependency_graph_policy_registry",
        "parse_dependency_remediation_registry",
    )
    application_names = (
        "DependencyClosureGraphObservation",
        "DependencyGraphObservationFactory",
        "DependencyRemediationDispositionAuthority",
    )
    missing = tuple(
        name for module, names in (
            (core, core_names), (application, application_names),
        )
        for name in names
        if not hasattr(module, name)
    )
    missing_paths = tuple(
        str(path.relative_to(ROOT)) for path in (
            GRAPH_POLICY_PATH, REMEDIATION_PATH, GRAPH_BOOTSTRAP_PATH,
        )
        if not path.is_file()
    )
    if missing or missing_paths:
        raise MissingDependencySecurityContract(
            "ADR-0006 r7 graph/remediation Slice A is absent: "
            + ", ".join((*missing, *missing_paths))
        )
    return DependencyGraphSliceAAPI(
        **{name: getattr(core, name) for name in core_names},
        **{name: getattr(application, name) for name in application_names},
    )


def assert_dependency_graph_slice_a_positive(
    case: object,
    schema_registry: object | None = None,
    context_factory: Callable[[], object] | None = None,
) -> None:
    """Require the exact installed graph/remediation production authority."""

    api = load_dependency_graph_slice_a_api()
    graph_policy = json.loads(GRAPH_POLICY_PATH.read_bytes())
    remediation = json.loads(REMEDIATION_PATH.read_bytes())
    parsed_policy = api.parse_dependency_graph_policy_registry(graph_policy)
    parsed_remediation = api.parse_dependency_remediation_registry(remediation)
    case.assertIs(type(parsed_policy), api.DependencyGraphPolicyData)
    case.assertIs(type(parsed_remediation), api.DependencyRemediationRegistryData)
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack:
        context = dependency_security_coverage_context(stack[4])
        try:
            transitive_advisory = context.registry_factory.advisory(
                "advisory:cffi:security-v1", 1,
            )
            unavailable_advisory = context.registry_factory.advisory(
                "advisory:example-dependency:security-v1", 2,
            )
            factory = api.DependencyGraphObservationFactory.from_registry_and_closures(
                context.registry_factory, context.closure_factory,
            )
            before = factory.observe(transitive_advisory, context.before)
            after = factory.observe(transitive_advisory, context.after)
            document = after.to_dict()
            case.assertEqual(len(document["nodes"]), 4)
            case.assertEqual(len(document["edges"]), 3)
            case.assertTrue(any(
                edge["normalized_name"] == "cffi"
                and edge["parent_node_id"].startswith("distribution:cryptography@")
                for edge in document["edges"]
            ))
            case.assertEqual(document["selected_distribution_name"], "cffi")
            case.assertEqual(document["reachability_path"], [
                "distribution:graph-engineering-workflow@0.1.0",
                "distribution:cryptography@50.0.0",
                "distribution:cffi@2.0.0",
            ])
            case.assertIs(factory.require_current(before), before)
            case.assertIs(factory.require_current(after), after)
            disposition = factory.disposition(unavailable_advisory)
            case.assertEqual(disposition.status, "approved-unavailable")
            case.assertEqual(disposition.owner_route, "owner:dependency-security")
            case.assertIs(
                factory.require_current_disposition(disposition), disposition,
            )
            if schema_registry is not None and context_factory is not None:
                for schema_id, instance in (
                    (
                        "urn:gew:schema:dependency-graph-policy-registry:1.0.0",
                        graph_policy,
                    ),
                    (
                        "urn:gew:schema:dependency-remediation-disposition-registry:1.0.0",
                        remediation,
                    ),
                    (
                        "urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0",
                        json.loads(GRAPH_BOOTSTRAP_PATH.read_bytes()),
                    ),
                    (
                        "urn:gew:schema:dependency-closure-graph-observation:1.0.0",
                        before.to_dict(),
                    ),
                ):
                    case.assertEqual(
                        schema_registry.validate(
                            schema_id, instance, context_factory(),
                        ),
                        [],
                    )
            with mock.patch.object(
                socket, "socket", side_effect=AssertionError("network forbidden"),
            ):
                case.assertIs(factory.require_current(after), after)
                case.assertIs(
                    factory.require_current_disposition(disposition), disposition,
                )
        finally:
            context.close()
    release_fixture = importlib.import_module(
        "tests.support.wp08_release_coverage"
    )
    _coverage_api, category_application, probe, target = (
        release_fixture.production_runtime(
            "boundary",
            profile_id="dependency-security",
            task_id="task:dependency-security:graph-slice-a",
        )
    )
    graph_context = dependency_security_coverage_context(
        probe.repository,
        after_fixed_closure=False,
    )
    try:
        final_factory, final_observation = graph_context.observe_graph(
            category_application,
            probe.task_id,
            scenario_id="fix-unavailable",
        )
        final_body = final_observation.to_dict()
        case.assertEqual(final_body["schema_version"], "1.1.0")
        case.assertEqual(final_body["scenario_id"], "fix-unavailable")
        case.assertEqual(final_body["owner_route"], "owner:dependency-security")
        case.assertIs(final_body["after_graph_digest"], None)
        case.assertIs(final_factory.require_current(final_observation), final_observation)
        case.assertIs(final_factory.precommit(final_observation), final_observation)
        case.assertIs(final_factory.restart(final_observation), final_observation)
        if schema_registry is not None and context_factory is not None:
            case.assertEqual(
                schema_registry.validate(
                    "urn:gew:schema:dependency-security-observation:1.1.0",
                    final_body,
                    context_factory(),
                ),
                [],
            )
        with case.assertRaises(api.DependencySecurityError):
            final_factory.require_current(copy.copy(final_observation))
    finally:
        graph_context.close()
        target.close()


def assert_dependency_graph_slice_a_rejections(case: object) -> None:
    """Require fail-closed graph/remediation aliases before Slice B wiring."""

    api = load_dependency_graph_slice_a_api()
    graph_policy = json.loads(GRAPH_POLICY_PATH.read_bytes())
    remediation = json.loads(REMEDIATION_PATH.read_bytes())
    for label, parser, document in (
        ("graph-policy-extra", api.parse_dependency_graph_policy_registry, graph_policy),
        ("remediation-extra", api.parse_dependency_remediation_registry, remediation),
    ):
        changed = copy.deepcopy(document)
        changed["caller_fact"] = True
        with case.subTest(attack=label), case.assertRaises(api.DependencySecurityError):
            parser(changed)
    for authority_type in (
        api.DependencyClosureGraphObservation,
        api.DependencyGraphObservationFactory,
        api.DependencyRemediationDispositionAuthority,
    ):
        with case.subTest(factory_owned=authority_type.__name__):
            with case.assertRaises(TypeError):
                authority_type()
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack:
        context = dependency_security_coverage_context(stack[4])
        try:
            advisory = context.registry_factory.advisory(
                "advisory:example-dependency:security-v1", 2,
            )
            factory = api.DependencyGraphObservationFactory.from_registry_and_closures(
                context.registry_factory, context.closure_factory,
            )
            graph = factory.observe(advisory, context.after)
            disposition = factory.disposition(advisory)
            with case.assertRaises(api.DependencySecurityError):
                factory.require_current(copy.copy(graph))
            with case.assertRaises(api.DependencySecurityError):
                factory.require_current_disposition(copy.copy(disposition))
            with case.assertRaises(TypeError):
                factory.observe(advisory, context.after, graph={})
            accepted_mutations: list[str] = []
            mutations = (
                ("owner_route", "owner:caller"),
                ("status", "approved-fixed-closure"),
                ("reason_code", "caller-inferred-unavailable"),
                ("residual_policy_id", "policy:caller"),
                ("expires_at", "2099-01-01T00:00:00Z"),
                ("disposition_digest", "sha256-jcs-v1:" + "f" * 64),
                ("_projection", freeze({
                    **disposition.to_dict(),
                    "owner_route": "owner:caller",
                })),
                ("_advisory", copy.copy(advisory)),
            )
            for field, replacement in mutations:
                original = getattr(disposition, field)
                try:
                    object.__setattr__(disposition, field, replacement)
                except (AttributeError, TypeError):
                    continue
                try:
                    factory.require_current_disposition(disposition)
                except api.DependencySecurityError:
                    pass
                else:
                    accepted_mutations.append(field)
                finally:
                    object.__setattr__(disposition, field, original)
            deep_clone = object.__new__(
                api.DependencyRemediationDispositionAuthority
            )
            object.__setattr__(
                deep_clone, "_projection",
                freeze(copy.deepcopy(disposition.to_dict())),
            )
            object.__setattr__(deep_clone, "_advisory", advisory)
            object.__setattr__(deep_clone, "_authority", factory)
            for clone in (
                copy.copy(disposition), deep_clone,
            ):
                with case.assertRaises(api.DependencySecurityError):
                    factory.require_current_disposition(clone)
            graph_engineering = importlib.import_module("graph_engineering")
            current_resources = graph_engineering._dependency_graph_installation_resources()
            changed_resources = list(current_resources)
            changed_policy = json.loads(changed_resources[1])
            changed_policy["root_distribution_policy"][
                "root_distribution_name"
            ] = "caller-root"
            _resign(
                changed_policy, "dependency-graph-policy-registry", "registry_digest",
            )
            changed_resources[1] = json.dumps(
                changed_policy, sort_keys=True, separators=(",", ":"),
            ).encode() + b"\n"
            with mock.patch.object(
                graph_engineering,
                "_dependency_graph_installation_resources",
                return_value=tuple(changed_resources),
            ):
                with case.assertRaises(api.DependencySecurityError):
                    factory.require_current(graph)
                with case.assertRaises(api.DependencySecurityError):
                    factory.require_current_disposition(disposition)
        finally:
            context.close()
    edge_attacks = (
        (
            "duplicate",
            (
                "cffi>=2.0.0", "cffi>=2.0.0",
            ),
        ),
        (
            "reordered",
            ("packaging==26.3", "cffi>=2.0.0"),
        ),
        (
            "normalized-alias",
            (
                "CFFI >= 2.0.0", "cffi>=2.0.0",
            ),
        ),
    )
    accepted_edges: list[str] = []
    for label, requirements in edge_attacks:
        with repository_stack(
            manual_time=ManualTime(_timestamp_ns("2026-08-29T12:00:00Z")),
        ) as stack:
            try:
                attacked_context = dependency_security_coverage_context(
                    stack[4], cryptography_requirements=requirements,
                )
            except api.DependencySecurityError:
                continue
            try:
                advisory = attacked_context.registry_factory.advisory(
                    "advisory:example-dependency:security-v1", 1,
                )
                factory = api.DependencyGraphObservationFactory.from_registry_and_closures(
                    attacked_context.registry_factory,
                    attacked_context.closure_factory,
                )
                try:
                    factory.observe(advisory, attacked_context.before)
                except api.DependencySecurityError:
                    pass
                else:
                    accepted_edges.append(label)
            finally:
                attacked_context.close()
    case.assertEqual({
        "disposition_mutations": accepted_mutations,
        "requirement_edge_attacks": accepted_edges,
    }, {
        "disposition_mutations": [],
        "requirement_edge_attacks": [],
    })
    with case.assertRaises(api.DependencySecurityError):
        factory.require_current_disposition(
            object.__new__(api.DependencyRemediationDispositionAuthority)
        )
    release_fixture = importlib.import_module(
        "tests.support.wp08_release_coverage"
    )
    _coverage_api, category_application, probe, target = (
        release_fixture.production_runtime(
            "boundary",
            profile_id="dependency-security",
            task_id="task:dependency-security:graph-slice-a-r",
        )
    )
    final_context = dependency_security_coverage_context(
        probe.repository,
        after_fixed_closure=False,
    )
    try:
        final_factory, final_observation = final_context.observe_graph(
            category_application,
            probe.task_id,
            scenario_id="fix-unavailable",
        )
        final_disposition = final_observation._disposition
        original_projection = final_disposition._projection
        changed_projection = freeze({
            **final_disposition.to_dict(),
            "owner_route": "owner:caller",
        })
        baseline_state = (
            len(probe.repository.replay(probe.task_id)),
            tuple(probe.repository.referenced_objects(probe.task_id)),
            target.mutation_count,
        )
        for current_check in (
            final_factory.require_current,
            final_factory.precommit,
            final_factory.restart,
        ):
            object.__setattr__(
                final_disposition, "_projection", changed_projection,
            )
            try:
                with case.assertRaises(api.DependencySecurityError):
                    current_check(final_observation)
            finally:
                object.__setattr__(
                    final_disposition, "_projection", original_projection,
                )
        case.assertEqual((
            len(probe.repository.replay(probe.task_id)),
            tuple(probe.repository.referenced_objects(probe.task_id)),
            target.mutation_count,
        ), baseline_state)
    finally:
        final_context.close()
        target.close()


def dependency_security_test_id(column: str, disposition: str) -> str:
    """Return one approved dependency-security mandatory stable identity."""

    columns = (
        "normal", "boundary", "revise", "authority", "drift",
        "invalidation", "recovery", "artifacts", "review", "target",
        "rollback", "real-e2e",
    )
    if column not in columns or disposition not in {"P", "R"}:
        raise AssertionError("unknown dependency-security coverage binding")
    return f"GEW-PRO-DEPENDENCY-SECURITY-{column.upper()}-{disposition}"


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    return {
        **body,
        field: semantic_digest(
            body,
            contract_type=f"urn:gew:contract:{name}",
            projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
            schema_id=f"urn:gew:schema:{name}-input:1.0.0",
        ),
    }


def _resign(document: dict[str, object], name: str, field: str) -> None:
    body = copy.deepcopy(document)
    body.pop(field, None)
    document[field] = semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _timestamp_ns(value: str) -> int:
    return int(
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
        .astimezone(timezone.utc)
        .timestamp()
        * 1_000_000_000
    )


def _installed_source_provenance_returncodes() -> tuple[int, int, int]:
    """Probe the exact clean, unpacked-tampered, and duplicate archive paths."""

    with tempfile.TemporaryDirectory(prefix="gew-ds-wheel-") as directory:
        temporary = pathlib.Path(directory)
        distribution = temporary / "dist"
        distribution.mkdir()
        built = subprocess.run(
            [sys.executable, str(ROOT / "scripts/build_wheel.py"), str(distribution)],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        if built.returncode:
            raise AssertionError(built.stderr.decode(errors="replace"))
        wheel = next(distribution.glob("*.whl"))
        source_member = (
            "graph_engineering/config/security/dependency-advisory-source-v1.json"
        )
        probe = (
            "import sys;sys.path.insert(0,sys.argv[1]);import graph_engineering;"
            "assert len(graph_engineering._dependency_advisory_installation_resources())==36"
        )
        clean = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(wheel)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )
        unpacked = temporary / "unpacked"
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(unpacked)
        source_path = unpacked / source_member
        source_path.write_bytes(source_path.read_bytes() + b"\n")
        unpacked_result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(unpacked)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )
        duplicate = temporary / "duplicate.whl"
        shutil.copyfile(wheel, duplicate)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "a") as archive:
                archive.writestr(source_member, archive.read(source_member))
        duplicate_result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(duplicate)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )
        return clean.returncode, unpacked_result.returncode, duplicate_result.returncode


def source_record(
    *,
    revision: int = 1,
    not_before: str = "2026-01-01T00:00:00Z",
    not_after: str = "2027-01-01T00:00:00Z",
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "source_id": "source:dependency-advisory:offline-v1",
        "source_revision": revision,
        "issuer_id": "issuer:wp08a-offline-advisory-v1",
        "issued_at": "2026-08-29T00:00:00Z",
        "not_before": not_before,
        "not_after": not_after,
        "source_artifact_raw_sha256": (
            "2a992cbaaa6e68f668ba3ae7673a2de5cdd15cb501b00ca01272ed2842d7867e"
        ),
        "source_attestation_digest": (
            "sha256-jcs-v1:6111664c8c79d991a5442ac829f1bac55bafe9b9645fc0dbb95e73a9d64e343d"
        ),
    }
    return _complete(body, "dependency-advisory-source-record", "source_record_digest")


def fixed_closure(*, version: str = "26.3") -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "closure_id": f"closure:packaging:{version}",
        "root_distribution_name": "packaging",
        "root_version": version,
        "required_distribution_pins": [{
            "distribution_name": "packaging",
            "distribution_version": version,
            "wheel_raw_sha256": (
                "aa5bb7e36d925da63fd90569b3b74fadf487da77252cded4832277c1dcba3b62"
            ),
            "record_raw_sha256": (
                "4f1e622b62515a663e9e892721a467309e679f2e4dca2f3a5fbc91e63b7df363"
            ),
        }],
        "security_regression_command_id": "command:dependency-security-regression-v1",
    }
    return _complete(body, "dependency-fixed-closure", "closure_digest")


def advisory_record(*, revision: int = 1) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "advisory_id": "advisory:example-dependency:security-v1",
        "advisory_revision": revision,
        "source_id": "source:dependency-advisory:offline-v1",
        "source_revision": 1,
        "ecosystem": "pypi",
        "distribution_name": "packaging",
        "affected_version_specifiers": [">=26.3,<27.0.0"],
        "applicability_kind": "verified-offline-closure-member",
        "fixed_closures": [fixed_closure()],
        "residual_exposure_policy_id": "policy:dependency-residual-owner-route-v1",
        "security_regression_policy_id": "policy:dependency-security-regression-v1",
    }
    return _complete(body, "dependency-advisory-record", "advisory_digest")


def registry_document() -> dict[str, object]:
    source = source_record()
    advisory = advisory_record()
    high_water_body: dict[str, object] = {
        "schema_version": "1.0.0",
        "generation": 1,
        "source_states": [{
            "source_id": source["source_id"],
            "source_revision": source["source_revision"],
            "status": "active",
            "status_generation": 1,
        }],
        "advisory_states": [{
            "advisory_id": advisory["advisory_id"],
            "advisory_revision": advisory["advisory_revision"],
            "status": "active",
            "status_generation": 1,
        }],
    }
    high_water = _complete(
        high_water_body,
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "registry_id": "urn:gew:dependency-advisory-registry:v1",
        "generation": 1,
        "update_kind": "genesis",
        "previous_registry_digest": None,
        "rollback_of_registry_digest": None,
        "revocation_high_water": high_water,
        "source_records": [source],
        "advisories": [advisory],
    }
    return _complete(body, "dependency-advisory-registry", "registry_digest")


def closure_members(version: str) -> list[dict[str, object]]:
    digests = {
        "26.2": (
            "cbc3f88dbf405177ed69f5e72d7d4e3c55f31eff3b596cafd7f12c30c2db2960",
            "724519de61e59ced1d4e474c0018e3a3fd2fba7cfa5a26a0b3ffb23500a7f4f3",
        ),
        "26.3": (
            "aa5bb7e36d925da63fd90569b3b74fadf487da77252cded4832277c1dcba3b62",
            "4f1e622b62515a663e9e892721a467309e679f2e4dca2f3a5fbc91e63b7df363",
        ),
    }
    wheel_digest, record_digest = digests[version]
    return [{
        "distribution_name": "packaging",
        "distribution_version": version,
        "wheel_raw_sha256": wheel_digest,
        "record_raw_sha256": record_digest,
    }]


def _write_wheel(
    path: pathlib.Path,
    name: str,
    version: str,
    *,
    requirements: tuple[str, ...] = (),
    metadata_lines: tuple[str, ...] = (),
) -> None:
    distribution = name.replace("-", "_")
    info = f"{distribution}-{version}.dist-info"
    members = {
        f"{distribution}/__init__.py": b"",
        f"{info}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {name}\nVersion: {version}\n"
            + "".join(f"Requires-Dist: {item}\n" for item in requirements)
            + "".join(f"{item}\n" for item in metadata_lines)
            + "\n"
        ).encode(),
        f"{info}/WHEEL": (
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
    }
    rows = []
    for member, body in members.items():
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(body).digest()
        ).rstrip(b"=").decode()
        rows.append(f"{member},sha256={digest},{len(body)}")
    rows.append(f"{info}/RECORD,,")
    members[f"{info}/RECORD"] = ("\n".join(rows) + "\n").encode()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for member, body in members.items():
            descriptor = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            descriptor.compress_type = zipfile.ZIP_DEFLATED
            descriptor.create_system = 3
            descriptor.external_attr = 0o100644 << 16
            archive.writestr(descriptor, body)


def _candidate_document() -> dict[str, object]:
    current = registry_document()
    candidate = copy.deepcopy(current)
    candidate["generation"] = 2
    candidate["update_kind"] = "forward"
    candidate["previous_registry_digest"] = current["registry_digest"]
    replacement = advisory_record(revision=2)
    candidate["advisories"].append(replacement)  # type: ignore[union-attr]
    states = candidate["revocation_high_water"]["advisory_states"]  # type: ignore[index]
    states[0]["status"] = "superseded"  # type: ignore[index]
    states[0]["status_generation"] = 2  # type: ignore[index]
    states.append({  # type: ignore[union-attr]
        "advisory_id": replacement["advisory_id"],
        "advisory_revision": replacement["advisory_revision"],
        "status": "active",
        "status_generation": 2,
    })
    candidate["revocation_high_water"]["generation"] = 2  # type: ignore[index]
    _resign(
        candidate["revocation_high_water"],  # type: ignore[arg-type]
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    _resign(candidate, "dependency-advisory-registry", "registry_digest")
    return candidate


@dataclass(slots=True)
class DependencySecurityCoverageContext:
    """One repository-bound offline authority graph shared by exact task rows."""

    temporary: tempfile.TemporaryDirectory[str]
    registry_factory: object
    registry: object
    closure_factory: object
    before: object
    after: object
    applicability_factory: object
    applicabilities: tuple[object, ...]
    residual_factory: object
    residual: object

    def observe(self, category_application: object, task_id: str) -> tuple[object, object]:
        api = load_slice_b_api()
        factory = api.DependencySecurityObservationFactory.from_authorities(
            registry=self.registry_factory,
            closures=self.closure_factory,
            applicability=self.applicability_factory,
            residual=self.residual_factory,
            category_application=category_application,
        )
        observation = factory.observe(
            registry=self.registry,
            before=self.before,
            after=self.after,
            applicabilities=self.applicabilities,
            residual=self.residual,
            task_id=task_id,
        )
        return factory, observation

    def observe_graph(
        self,
        category_application: object,
        task_id: str,
        *,
        scenario_id: str,
    ) -> tuple[object, object]:
        api = load_slice_b_api()
        graph_api = load_dependency_graph_slice_a_api()
        advisory = self.registry_factory.advisory(
            (
                "advisory:cffi:security-v1"
                if scenario_id == "transitive-dependency"
                else "advisory:example-dependency:security-v1"
            ),
            1 if scenario_id == "transitive-dependency" else 2,
        )
        selected_applicabilities = tuple(
            observation
            for observation in self.applicabilities
            if (
                observation.to_dict()["advisory_id"],
                observation.to_dict()["advisory_revision"],
            ) == (
                advisory.advisory_id,
                advisory.advisory_revision,
            )
        )
        if len(selected_applicabilities) != 1:
            raise AssertionError(
                "dependency graph fixture applicability is not exact"
            )
        graph = graph_api.DependencyGraphObservationFactory.from_registry_and_closures(
            self.registry_factory, self.closure_factory,
        )
        before_graph = graph.observe(advisory, self.before)
        disposition = (
            graph.disposition(advisory)
            if scenario_id == "fix-unavailable"
            else None
        )
        after_graph = (
            graph.observe(advisory, self.after)
            if scenario_id == "transitive-dependency"
            else None
        )
        factory = api.DependencySecurityObservationFactory.from_graph_authorities(
            registry=self.registry_factory,
            closures=self.closure_factory,
            applicability=self.applicability_factory,
            residual=self.residual_factory,
            graph=graph,
            category_application=category_application,
        )
        observation = factory.observe_graph(
            registry=self.registry,
            before=self.before,
            after=self.after,
            applicabilities=selected_applicabilities,
            residual=self.residual,
            before_graph=before_graph,
            after_graph=after_graph,
            disposition=disposition,
            scenario_id=scenario_id,
            task_id=task_id,
        )
        return factory, observation

    def close(self) -> None:
        self.temporary.cleanup()
        for field in (
            "registry_factory", "registry", "closure_factory", "before", "after",
            "applicability_factory", "applicabilities", "residual_factory", "residual",
        ):
            object.__setattr__(self, field, None)


def dependency_security_coverage_context(
    repository: object,
    *,
    after_fixed_closure: bool = True,
    root_requirements: tuple[str, ...] = (
        "cryptography==50.0.0", "packaging==26.3",
    ),
    cryptography_requirements: tuple[str, ...] = ("cffi>=2.0.0",),
    advisory_identity: tuple[str, int] = (
        "advisory:example-dependency:security-v1", 2,
    ),
) -> DependencySecurityCoverageContext:
    """Build the exact installed/offline Slice-B upstream authority graph."""

    api = load_slice_a_api()
    temporary: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="gew-wp08-dependency-security-"
    )
    try:
        root = pathlib.Path(temporary.name).resolve(strict=True)

        if type(after_fixed_closure) is not bool:
            raise AssertionError("dependency closure fixture disposition is invalid")
        if (
            type(root_requirements) is not tuple
            or not root_requirements
            or any(type(item) is not str or not item for item in root_requirements)
        ):
            raise AssertionError("dependency closure fixture requirements are invalid")
        if (
            type(cryptography_requirements) is not tuple
            or not cryptography_requirements
            or any(
                type(item) is not str or not item
                for item in cryptography_requirements
            )
        ):
            raise AssertionError(
                "dependency transitive fixture requirements are invalid"
            )

        def fixture(
            phase: str,
        ) -> tuple[pathlib.Path, pathlib.Path]:
            phase_root = root / phase
            phase_root.mkdir()
            candidate = phase_root / "graph_engineering_workflow-0.1.0-py3-none-any.whl"
            wheelhouse = phase_root / "wheelhouse"
            wheelhouse.mkdir()
            _write_wheel(
                candidate,
                "graph-engineering-workflow",
                "0.1.0",
                requirements=root_requirements,
            )
            _write_wheel(
                wheelhouse / "cryptography-50.0.0-py3-none-any.whl",
                "cryptography",
                "50.0.0",
                requirements=cryptography_requirements,
            )
            _write_wheel(
                wheelhouse / "packaging-26.3-py3-none-any.whl",
                "packaging",
                "26.3",
                metadata_lines=(
                    ()
                    if phase == "before" or after_fixed_closure
                    else ("X-GEW-Residual-Closure: true",)
                ),
            )
            _write_wheel(
                wheelhouse / "cffi-2.0.0-py3-none-any.whl",
                "cffi",
                "2.0.0",
            )
            return candidate, wheelhouse

        before_candidate, before_wheelhouse = fixture("before")
        after_candidate, after_wheelhouse = fixture("after")
        registry_factory = api.DependencyAdvisoryRegistryFactory.from_installation(
            repository,
        )
        registry = registry_factory.registry
        closure_factory = api.DependencyOfflineClosureObservationFactory.from_registry(
            registry_factory,
        )
        before = closure_factory.observe_candidate(
            before_candidate, before_wheelhouse, phase="before",
        )
        after = closure_factory.observe_candidate(
            after_candidate, after_wheelhouse, phase="after",
        )
        source = registry_factory.source(
            "source:dependency-advisory:offline-v2", 1,
        )
        active_advisory_identities = (
            ("advisory:cffi:security-v1", 1),
            ("advisory:example-dependency:security-v1", 2),
        )
        if advisory_identity not in active_advisory_identities:
            raise AssertionError("dependency closure fixture advisory is inactive")
        applicability_factory = (
            api.DependencyApplicabilityObservationFactory.from_registry_and_closures(
                registry_factory, closure_factory,
            )
        )
        applicabilities = tuple(
            applicability_factory.observe(
                registry,
                registry_factory.advisory(*identity),
                source,
                before,
                after,
            )
            for identity in active_advisory_identities
        )
        residual_factory = (
            api.DependencyResidualExposureFactory.from_registry_and_closures(
                registry_factory, closure_factory,
            )
        )
        residual = residual_factory.observe(registry, before, after)
        return DependencySecurityCoverageContext(
            temporary=temporary,
            registry_factory=registry_factory,
            registry=registry,
            closure_factory=closure_factory,
            before=before,
            after=after,
            applicability_factory=applicability_factory,
            applicabilities=applicabilities,
            residual_factory=residual_factory,
            residual=residual,
        )
    except BaseException:
        temporary.cleanup()
        raise


def assert_slice_a_positive(case: object) -> None:
    api = load_slice_a_api()
    if not REGISTRY_PATH.is_file():
        raise MissingDependencySecurityContract(
            "config/security/dependency-advisory-registry-v2.json is absent"
        )
    installed = json.loads(REGISTRY_PATH.read_bytes())
    historic = json.loads((
        ROOT / "config/security/dependency-advisory-registry-v1.json"
    ).read_bytes())
    parsed = api.parse_dependency_advisory_registry(installed)
    case.assertIs(type(parsed), api.DependencyAdvisoryRegistryData)
    case.assertEqual(parsed.generation, 2)
    case.assertEqual(parsed.registry_digest, installed["registry_digest"])

    updated = api.validate_dependency_registry_update(historic, installed)
    case.assertIs(type(updated), api.DependencyAdvisoryRegistryData)
    case.assertEqual(updated.generation, 2)

    repository_context = repository_stack(
        manual_time=ManualTime(_timestamp_ns("2026-08-29T12:00:00Z")),
    )
    repository_values = repository_context.__enter__()
    case.addCleanup(repository_context.__exit__, None, None, None)
    factory = api.DependencyAdvisoryRegistryFactory.from_installation(
        repository_values[4],
    )
    authority = factory.registry
    case.assertIs(type(authority), api.DependencyAdvisoryRegistryAuthority)
    case.assertIs(factory.require_current(authority), authority)
    case.assertEqual(authority.registry_digest, installed["registry_digest"])
    cffi_member = {
        "distribution_name": "cffi",
        "distribution_version": "2.0.0",
        "wheel_raw_sha256": (
            "828d3c089a39a57b70b98df41c62ac0949e4880a0995fadc0b6ae821a0bc035f"
        ),
        "record_raw_sha256": (
            "35619973c5fc1e8b00151fb14445bd6f091f616a3cdee1eb7e477cf7d29916d0"
        ),
    }
    before = [cffi_member, *closure_members("26.3")]
    after = [cffi_member, *closure_members("26.3")]
    evaluation = api.evaluate_dependency_closures(
        installed,
        before_closure=before,
        after_closure=after,
        clock_authority=factory,
    )
    case.assertIs(type(evaluation), api.DependencyEvaluation)
    rows = tuple(row.to_dict() for row in evaluation.rows)
    case.assertEqual(
        tuple((row["advisory_revision"], row["disposition"]) for row in rows),
        ((1, "fixed"), (1, "inactive"), (2, "fixed")),
    )
    case.assertEqual(evaluation.active_advisory_ids, (
        "advisory:cffi:security-v1@1",
        "advisory:example-dependency:security-v1@2",
    ))
    case.assertEqual(evaluation.residual_advisory_ids, ())
    clean_returncode, _unpacked_returncode, _duplicate_returncode = (
        _installed_source_provenance_returncodes()
    )
    case.assertEqual(clean_returncode, 0)
    source = factory.source("source:dependency-advisory:offline-v2", 1)
    advisory = factory.advisory("advisory:example-dependency:security-v1", 2)
    case.assertIs(factory.require_current_source(source), source)
    case.assertIs(factory.require_current_advisory(advisory), advisory)
    restarted = api.DependencyAdvisoryRegistryFactory.from_installation(
        repository_values[4],
    )
    case.assertIs(restarted.require_current(restarted.registry), restarted.registry)
    with case.assertRaises(api.DependencySecurityError):
        restarted.require_current(authority)
    for authority_type in (
        api.DependencyAdvisoryRegistryAuthority,
        api.DependencyAdvisorySourceAuthority,
        api.DependencyAdvisoryIdentityAuthority,
        api.DependencyRegistryRollbackAuthority,
        api.DependencyOfflineClosureObservationFactory,
        api.DependencyApplicabilityObservationFactory,
        api.DependencyResidualExposureFactory,
        api.DependencyOfflineClosureObservation,
        api.DependencyApplicabilityObservation,
        api.DependencyResidualExposureObservation,
    ):
        with case.subTest(factory_owned=authority_type.__name__):
            with case.assertRaises(TypeError):
                authority_type()

    with tempfile.TemporaryDirectory(prefix="gew-dependency-closure-") as directory:
        root = pathlib.Path(directory).resolve(strict=True)

        def fixture(
            phase: str, packaging_version: str,
        ) -> tuple[pathlib.Path, pathlib.Path]:
            phase_root = root / phase
            phase_root.mkdir()
            candidate_path = (
                phase_root / "graph_engineering_workflow-0.1.0-py3-none-any.whl"
            )
            wheelhouse_path = phase_root / "wheelhouse"
            wheelhouse_path.mkdir()
            _write_wheel(
                candidate_path,
                "graph-engineering-workflow",
                "0.1.0",
                requirements=(
                    "cryptography==50.0.0", f"packaging=={packaging_version}",
                ),
            )
            _write_wheel(
                wheelhouse_path / "cryptography-50.0.0-py3-none-any.whl",
                "cryptography", "50.0.0", requirements=("cffi>=2.0.0",),
            )
            _write_wheel(
                wheelhouse_path / f"packaging-{packaging_version}-py3-none-any.whl",
                "packaging", packaging_version,
            )
            _write_wheel(
                wheelhouse_path / "cffi-2.0.0-py3-none-any.whl",
                "cffi", "2.0.0",
            )
            return candidate_path, wheelhouse_path

        before_candidate, before_wheelhouse = fixture("before", "26.3")
        after_candidate, after_wheelhouse = fixture("after", "26.3")
        closure_factory = api.DependencyOfflineClosureObservationFactory.from_registry(
            factory,
        )
        before_observation = closure_factory.observe_candidate(
            before_candidate, before_wheelhouse, phase="before",
        )
        after_observation = closure_factory.observe_candidate(
            after_candidate, after_wheelhouse, phase="after",
        )
        case.assertIs(closure_factory.require_current(before_observation), before_observation)
        case.assertIs(closure_factory.require_current(after_observation), after_observation)
        case.assertNotEqual(
            before_observation.observation_digest,
            after_observation.observation_digest,
        )
        case.assertEqual(len(before_observation.to_dict()["members"]), 4)
        applicability_factory = (
            api.DependencyApplicabilityObservationFactory.from_registry_and_closures(
                factory, closure_factory,
            )
        )
        applicability = applicability_factory.observe(
            authority, advisory, source, before_observation, after_observation,
        )
        case.assertIs(applicability_factory.require_current(applicability), applicability)
        case.assertTrue(applicability.to_dict()["before_affected"])
        case.assertTrue(applicability.to_dict()["after_fixed"])
        residual_factory = (
            api.DependencyResidualExposureFactory.from_registry_and_closures(
                factory, closure_factory,
            )
        )
        residual = residual_factory.observe(
            authority, before_observation, after_observation,
        )
        case.assertIs(residual_factory.require_current(residual), residual)
        case.assertEqual(residual.residual_advisory_ids, ())
        case.assertEqual(residual.to_dict()["rows"][0]["disposition"], "fixed")
        with case.assertRaises(api.DependencySecurityError):
            applicability_factory.require_current(copy.copy(applicability))
        with case.assertRaises(api.DependencySecurityError):
            residual_factory.require_current(copy.copy(residual))
        with case.assertRaises(api.DependencySecurityError):
            closure_factory.require_current(copy.copy(before_observation))
        foreign_closure_factory = (
            api.DependencyOfflineClosureObservationFactory.from_registry(restarted)
        )
        with case.assertRaises(api.DependencySecurityError):
            foreign_closure_factory.require_current(before_observation)
        packaging_wheel = after_wheelhouse / "packaging-26.3-py3-none-any.whl"
        packaging_bytes = packaging_wheel.read_bytes()
        packaging_wheel.write_bytes(b"substituted")
        try:
            with case.assertRaises(api.DependencySecurityError):
                closure_factory.require_current(after_observation)
        finally:
            packaging_wheel.write_bytes(packaging_bytes)


def assert_slice_a_schema_instances(
    case: object,
    registry: object,
    context_factory: Callable[[], object],
) -> None:
    """Prove every published Slice A source record matches its source schema."""

    document = json.loads(REGISTRY_PATH.read_bytes())
    instances = (
        ("urn:gew:schema:dependency-advisory-source-record:1.0.0", document["source_records"][0]),
        ("urn:gew:schema:dependency-fixed-closure:1.0.0", document["advisories"][0]["fixed_closures"][0]),
        ("urn:gew:schema:dependency-advisory-record:1.0.0", document["advisories"][0]),
        ("urn:gew:schema:dependency-advisory-status-high-water:1.0.0", document["revocation_high_water"]),
        ("urn:gew:schema:dependency-advisory-registry:1.0.0", document),
        (
            "urn:gew:schema:dependency-advisory-installation-bootstrap:1.0.0",
            json.loads((
                ROOT
                / "config/security/dependency-advisory-installation-bootstrap-v1.json"
            ).read_bytes()),
        ),
        (
            "urn:gew:schema:dependency-advisory-installation-bootstrap:1.2.0",
            json.loads(BOOTSTRAP_PATH.read_bytes()),
        ),
        ("urn:gew:schema:dependency-graph-policy-registry:1.0.0", json.loads(GRAPH_POLICY_PATH.read_bytes())),
        ("urn:gew:schema:dependency-remediation-disposition-registry:1.0.0", json.loads(REMEDIATION_PATH.read_bytes())),
        ("urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0", json.loads(GRAPH_BOOTSTRAP_PATH.read_bytes())),
    )
    for schema_id, instance in instances:
        with case.subTest(dependency_schema=schema_id):
            case.assertEqual(registry.validate(schema_id, instance, context_factory()), [])


def assert_slice_a_rejections(case: object) -> None:
    api = load_slice_a_api()
    error = api.DependencySecurityError
    baseline = registry_document()
    mutations: list[tuple[str, dict[str, object]]] = []

    wrong_genesis = copy.deepcopy(baseline)
    wrong_genesis["generation"] = 2
    wrong_genesis["revocation_high_water"]["generation"] = 2  # type: ignore[index]
    _resign(
        wrong_genesis["revocation_high_water"],  # type: ignore[arg-type]
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    _resign(wrong_genesis, "dependency-advisory-registry", "registry_digest")
    mutations.append(("wrong-genesis", wrong_genesis))

    duplicate = copy.deepcopy(baseline)
    duplicate["revocation_high_water"]["advisory_states"].append(  # type: ignore[index,union-attr]
        copy.deepcopy(duplicate["revocation_high_water"]["advisory_states"][0])  # type: ignore[index]
    )
    _resign(
        duplicate["revocation_high_water"],  # type: ignore[arg-type]
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    _resign(duplicate, "dependency-advisory-registry", "registry_digest")
    mutations.append(("duplicate-high-water", duplicate))

    nested = copy.deepcopy(baseline)
    nested["advisories"][0]["fixed_closures"][0]["root_version"] = "9.9.9"  # type: ignore[index]
    _resign(nested["advisories"][0], "dependency-advisory-record", "advisory_digest")  # type: ignore[arg-type,index]
    _resign(nested, "dependency-advisory-registry", "registry_digest")
    mutations.append(("nested-closure-digest", nested))

    for label, document in mutations:
        before = copy.deepcopy(document)
        with case.subTest(registry_attack=label), case.assertRaises(error):
            api.parse_dependency_advisory_registry(document)
        case.assertEqual(document, before)

    current = registry_document()
    canonical = _candidate_document()
    candidate_mutations: list[tuple[str, dict[str, object]]] = []
    for label, mutate in (
        (
            "future-status-generation",
            lambda value: value["revocation_high_water"]["advisory_states"][1].__setitem__(  # type: ignore[index]
                "status_generation", 999
            ),
        ),
        (
            "stale-transition-generation",
            lambda value: value["revocation_high_water"]["advisory_states"][0].__setitem__(  # type: ignore[index]
                "status_generation", 1
            ),
        ),
        (
            "unchanged-status-bump",
            lambda value: value["revocation_high_water"]["source_states"][0].__setitem__(  # type: ignore[index]
                "status_generation", 2
            ),
        ),
        (
            "new-identity-wrong-generation",
            lambda value: value["revocation_high_water"]["advisory_states"][1].__setitem__(  # type: ignore[index]
                "status_generation", 1
            ),
        ),
    ):
        candidate = copy.deepcopy(canonical)
        mutate(candidate)
        _resign(
            candidate["revocation_high_water"],  # type: ignore[arg-type]
            "dependency-advisory-status-high-water",
            "high_water_digest",
        )
        _resign(candidate, "dependency-advisory-registry", "registry_digest")
        candidate_mutations.append((label, candidate))
    for label, candidate in candidate_mutations:
        before = copy.deepcopy(candidate)
        with case.subTest(update_attack=label), case.assertRaises(error):
            api.validate_dependency_registry_update(current, candidate)
        case.assertEqual(candidate, before)

    for observed_at, accepted in (
        ("2026-01-01T00:00:00Z", True),
        ("2026-12-31T23:59:59Z", True),
        ("2027-01-01T00:00:00Z", False),
    ):
        with case.subTest(half_open=observed_at):
            clock = ManualTime(_timestamp_ns(observed_at))
            with repository_stack(manual_time=clock) as stack:
                if accepted:
                    current_factory = (
                        api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
                    )
                    cffi_member = {
                        "distribution_name": "cffi",
                        "distribution_version": "2.0.0",
                        "wheel_raw_sha256": (
                            "828d3c089a39a57b70b98df41c62ac0949e4880a0995fadc0b6ae821a0bc035f"
                        ),
                        "record_raw_sha256": (
                            "35619973c5fc1e8b00151fb14445bd6f091f616a3cdee1eb7e477cf7d29916d0"
                        ),
                    }
                    api.evaluate_dependency_closures(
                        json.loads(REGISTRY_PATH.read_bytes()),
                        before_closure=[cffi_member, *closure_members("26.3")],
                        after_closure=[cffi_member, *closure_members("26.3")],
                        clock_authority=current_factory,
                    )
                else:
                    with case.assertRaises(error):
                        api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])

    repository_context = repository_stack(
        manual_time=ManualTime(_timestamp_ns("2026-08-29T12:00:00Z")),
    )
    repository_values = repository_context.__enter__()
    case.addCleanup(repository_context.__exit__, None, None, None)
    factory = api.DependencyAdvisoryRegistryFactory.from_installation(
        repository_values[4],
    )
    authority = factory.registry
    clone = copy.copy(authority)
    with case.assertRaises(error):
        factory.require_current(clone)
    with case.assertRaises(error):
        factory.require_current_source(copy.copy(factory.source(
            "source:dependency-advisory:offline-v2", 1,
        )))
    with case.assertRaises(error):
        factory.require_current_advisory(copy.copy(factory.advisory(
            "advisory:example-dependency:security-v1", 2,
        )))

    graph_engineering = importlib.import_module("graph_engineering")
    loader = getattr(graph_engineering, "_dependency_advisory_installation_resources")
    canonical_resources = loader()
    registry_index = 1
    changed = list(canonical_resources)
    replacement = json.loads(changed[registry_index])
    replacement["registry_id"] = "urn:gew:dependency-advisory-registry:substituted"
    _resign(replacement, "dependency-advisory-registry", "registry_digest")
    changed[registry_index] = json.dumps(
        replacement, sort_keys=True, separators=(",", ":")
    ).encode()
    with mock.patch.object(
        graph_engineering,
        "_dependency_advisory_installation_resources",
        return_value=tuple(changed),
    ) as current_loader:
        with case.assertRaises(error):
            factory.require_current(authority)
        case.assertGreaterEqual(current_loader.call_count, 1)

    network_calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        network_calls.append("network")
        raise AssertionError("dependency-security attempted network access")

    with mock.patch.object(socket, "create_connection", forbidden), mock.patch.object(
        socket.socket, "connect", forbidden
    ), mock.patch.object(socket, "getaddrinfo", forbidden):
        clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
        with repository_stack(manual_time=clock) as stack:
            repository = stack[4]
            fresh = api.DependencyAdvisoryRegistryFactory.from_installation(repository)
            fresh.require_current(fresh.registry)
    case.assertEqual(network_calls, [])


def assert_slice_a_reviewer_repairs(case: object) -> None:
    """Exact reviewer attacks for Slice-A R1-001 through R1-004."""

    api = load_slice_a_api()
    error = api.DependencySecurityError

    # R1-001: one repository-owned clock is the only time authority.  It is
    # consulted at issue and use; callers cannot substitute timestamps.
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack:
        factory = api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        source = factory.source("source:dependency-advisory:offline-v2", 1)
        case.assertIs(factory.require_current_source(source), source)
        with case.assertRaises(TypeError):
            api.evaluate_dependency_closures(
                registry_document(),
                before_closure=closure_members("26.3"),
                after_closure=closure_members("26.3"),
                observed_at="2026-08-29T12:00:00Z",
            )
        clock.set(_timestamp_ns("2027-01-01T00:00:00Z"))
        with case.assertRaises(error):
            factory.require_current(factory.registry)
        clock.set(_timestamp_ns("2026-08-29T12:00:00Z"))
        with case.assertRaises(error):
            factory.require_current(factory.registry)

    early = ManualTime(_timestamp_ns("2025-12-31T23:59:59Z"))
    with repository_stack(manual_time=early) as stack:
        with case.assertRaises(error):
            api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])

    # R1-002: a syntactically valid rollback cannot self-authorize an arbitrary
    # target digest.  Only an installation-factory history proof may authorize.
    current = registry_document()
    rollback = _candidate_document()
    rollback["update_kind"] = "rollback"
    rollback["rollback_of_registry_digest"] = "sha256-jcs-v1:" + "f" * 64
    _resign(rollback, "dependency-advisory-registry", "registry_digest")
    with case.assertRaises(error):
        api.validate_dependency_registry_update(current, rollback)
    forged_proof = object.__new__(api.DependencyRegistryRollbackAuthority)
    forged_owner = type(
        "ForgedRollbackOwner",
        (),
        {"_require_registry_rollback_authority": lambda *_args: None},
    )()
    forged_proof._owner = forged_owner
    forged_proof._current_digest = current["registry_digest"]
    forged_proof._historical_digests = (
        rollback["rollback_of_registry_digest"],
        current["registry_digest"],
    )
    forged_owner._issued_rollback_proofs = {  # type: ignore[attr-defined]
        id(forged_proof): (
            forged_proof,
            current["registry_digest"],
            forged_proof._historical_digests,
        ),
    }
    with case.assertRaises(error):
        api.validate_dependency_registry_update(
            current,
            rollback,
            rollback_authority=forged_proof,
        )
    core_module = importlib.import_module(
        "graph_engineering.core.dependency_security"
    )
    case.assertFalse(hasattr(
        core_module, "_issue_dependency_registry_rollback_authority",
    ))
    with mock.patch.object(
        core_module,
        "_ISSUED_ROLLBACK_PROOFS",
        {forged_proof: (forged_owner, *forged_proof._historical_digests)},
        create=True,
    ):
        with case.assertRaises(error):
            api.validate_dependency_registry_update(
                current,
                rollback,
                rollback_authority=forged_proof,
            )
    application_module = importlib.import_module(
        "graph_engineering.application.dependency_security"
    )
    case.assertFalse(hasattr(
        application_module, "_bind_dependency_registry_factory_issuance",
    ))
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack:
        history_factory = api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        current_target = _candidate_document()
        current_target["update_kind"] = "rollback"
        current_target["rollback_of_registry_digest"] = current["registry_digest"]
        _resign(current_target, "dependency-advisory-registry", "registry_digest")
        with case.assertRaises(error):
            api.validate_dependency_registry_update(
                current,
                current_target,
                rollback_authority=copy.copy(history_factory._rollback_authority),
            )
        foreign_factory = api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        with case.assertRaises(error):
            api.validate_dependency_registry_update(
                current,
                current_target,
                rollback_authority=foreign_factory._rollback_authority,
            )

    installed_successor = _candidate_document()
    rollback_successor = copy.deepcopy(installed_successor)
    rollback_successor["generation"] = 3
    rollback_successor["update_kind"] = "rollback"
    rollback_successor["previous_registry_digest"] = installed_successor[
        "registry_digest"
    ]
    rollback_successor["rollback_of_registry_digest"] = current["registry_digest"]
    rollback_successor["revocation_high_water"]["generation"] = 3  # type: ignore[index]
    _resign(
        rollback_successor["revocation_high_water"],  # type: ignore[arg-type]
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    _resign(rollback_successor, "dependency-advisory-registry", "registry_digest")
    parsed_successor = api.parse_dependency_advisory_registry(installed_successor)
    application = importlib.import_module(
        "graph_engineering.application.dependency_security"
    )
    _canonical_data, canonical_projection, canonical_schema_digests = (
        application._bootstrap_projection()
    )
    history_projection_body = thaw(canonical_projection)
    history_projection_body["registry_digest"] = parsed_successor.registry_digest
    history_projection_body["registry_history_digests"] = [
        current["registry_digest"], parsed_successor.registry_digest,
    ]
    history_projection = freeze(history_projection_body)
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack, mock.patch.object(
        application,
        "_bootstrap_projection",
        return_value=(
            parsed_successor, history_projection, canonical_schema_digests,
        ),
    ):
        verified_history_factory = (
            api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        )
        accepted_rollback = verified_history_factory.validate_update(
            rollback_successor,
        )
        case.assertEqual(accepted_rollback.generation, 3)

    # R1-003: inactive high-water members remain historical data but can never
    # receive a live source/advisory capability.
    inactive = _candidate_document()
    inactive["revocation_high_water"]["source_states"][0]["status"] = "revoked"  # type: ignore[index]
    inactive["revocation_high_water"]["source_states"][0]["status_generation"] = 2  # type: ignore[index]
    for state in inactive["revocation_high_water"]["advisory_states"]:  # type: ignore[index]
        state["status"] = "revoked"
        state["status_generation"] = 2
    _resign(
        inactive["revocation_high_water"],  # type: ignore[arg-type]
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    _resign(inactive, "dependency-advisory-registry", "registry_digest")
    parsed_inactive = api.parse_dependency_advisory_registry(inactive)
    application = importlib.import_module(
        "graph_engineering.application.dependency_security"
    )
    _canonical_data, canonical_projection, canonical_schema_digests = (
        application._bootstrap_projection()
    )
    inactive_projection_body = thaw(canonical_projection)
    inactive_projection_body["registry_digest"] = parsed_inactive.registry_digest
    inactive_projection_body["registry_history_digests"] = [
        parsed_inactive.registry_digest,
    ]
    inactive_projection = freeze(inactive_projection_body)
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack, mock.patch.object(
        application,
        "_bootstrap_projection",
        return_value=(
            parsed_inactive, inactive_projection, canonical_schema_digests,
        ),
    ):
        inactive_factory = api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        with case.assertRaises(error):
            inactive_factory.source("source:dependency-advisory:offline-v1", 1)
        with case.assertRaises(error):
            inactive_factory.advisory("advisory:example-dependency:security-v1", 1)

    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack:
        alias_factory = api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
        class StringAlias(str):
            pass

        class IntegerAlias(int):
            pass

        for value in (True, 1.0, IntegerAlias(2), 0, 9_007_199_254_740_992):
            with case.subTest(source_revision_alias=repr(value)), case.assertRaises(error):
                alias_factory.source("source:dependency-advisory:offline-v2", value)
            with case.subTest(advisory_revision_alias=repr(value)), case.assertRaises(error):
                alias_factory.advisory("advisory:example-dependency:security-v1", value)
        with case.assertRaises(error):
            alias_factory.source(StringAlias("source:dependency-advisory:offline-v2"), 1)
        with case.assertRaises(error):
            alias_factory.advisory(
                StringAlias("advisory:example-dependency:security-v1"), 2,
            )
        issued_source = alias_factory.source(
            "source:dependency-advisory:offline-v2", 1,
        )
        issued_advisory = alias_factory.advisory(
            "advisory:example-dependency:security-v1", 2,
        )
        issued_source.source_revision = True
        issued_advisory.advisory_revision = True
        with case.assertRaises(error):
            alias_factory.require_current_source(issued_source)
        with case.assertRaises(error):
            alias_factory.require_current_advisory(issued_advisory)
        issued_source.source_revision = 1
        issued_advisory.advisory_revision = 2

    # R1-004: both real protected source members are part of every installation
    # load and their raw/self-digested linkage is checked before authority issue.
    graph_engineering = importlib.import_module("graph_engineering")
    loader = getattr(graph_engineering, "_dependency_advisory_installation_resources")
    resources = loader()
    case.assertTrue(SOURCE_ARTIFACT_PATH.is_file())
    case.assertTrue(SOURCE_ATTESTATION_PATH.is_file())
    case.assertEqual(len(resources), 36)
    artifact = json.loads(resources[3])
    attestation = json.loads(resources[4])
    case.assertEqual(
        hashlib.sha256(resources[3]).hexdigest(),
        attestation["source_artifact_raw_sha256"],
    )
    case.assertEqual(
        attestation["attestation_digest"],
        next(
            row["source_attestation_digest"]
            for row in json.loads(resources[1])["source_records"]
            if row["source_id"] == "source:dependency-advisory:offline-v2"
        ),
    )
    historical_hashes = (
        "c8f085a572c97b63758d6ad60efc318e1f1659e18f4ffe08ab4b006c4476f0b2",
        "2a992cbaaa6e68f668ba3ae7673a2de5cdd15cb501b00ca01272ed2842d7867e",
        "79034ebc3eafd88c5d660837a2380d1785b5f79bda4c4ea79e2cfaa410391d89",
        "031df42d9aa2a8c57ee4b720dbae852aaa35b098511c07e9d614c5543523c01f",
        "7ff4f3137048266321df2271fa5f53220112fcdba169cfafeaa3300dbf3abee9",
        "a7fa8a37db55b536fa24bf65a3cccd7e157c37009a41d2e42bde7ebc9926f937",
        "ed7beba6ce8754dde49bb9a8fb6c149b72f51b2e937e692af4d83d51828ff09e",
        "fb343c66de46daca5438aca54745492e637cfc558fc217b5818bb620b9920b76",
    )
    case.assertEqual(
        tuple(hashlib.sha256(body).hexdigest() for body in resources[28:]),
        historical_hashes,
    )
    case.assertEqual(resources[1], resources[31])
    case.assertEqual(resources[3], resources[32])
    case.assertEqual(resources[4], resources[33])

    history_attacks: list[tuple[str, tuple[bytes, ...]]] = []
    history_attacks.append((
        "old-source-omission", resources[:28] + resources[29:],
    ))
    mixed = list(resources)
    mixed[29] = resources[32]
    history_attacks.append(("mixed-generation-snapshot", tuple(mixed)))
    crossed = list(resources)
    crossed[33] = resources[30]
    history_attacks.append(("artifact-attestation-cross-pair", tuple(crossed)))
    reordered = list(resources)
    reordered[28:34] = (*resources[31:34], *resources[28:31])
    history_attacks.append(("source-history-reorder", tuple(reordered)))
    bootstrap_reordered = list(resources)
    bootstrap_reordered[34], bootstrap_reordered[35] = (
        bootstrap_reordered[35], bootstrap_reordered[34],
    )
    history_attacks.append(("bootstrap-history-reorder", tuple(bootstrap_reordered)))
    replaced = list(resources)
    replaced[28] = replaced[28] + b"\n"
    history_attacks.append(("same-path-replacement", tuple(replaced)))
    coherently_resigned = list(resources)
    coherent_registry = json.loads(coherently_resigned[28])
    coherent_registry["registry_id"] = (
        "urn:gew:dependency-advisory-registry:coherent-replacement"
    )
    _resign(
        coherent_registry, "dependency-advisory-registry", "registry_digest",
    )
    coherently_resigned[28] = json.dumps(
        coherent_registry, sort_keys=True, separators=(",", ":"),
    ).encode()
    history_attacks.append(("coherent-history-resign", tuple(coherently_resigned)))
    for label, attacked_resources in history_attacks:
        clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
        with case.subTest(source_history_attack=label), repository_stack(
            manual_time=clock,
        ) as stack:
            with stack[4]._factory.open("application") as connection:
                before_counts = tuple(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("tasks", "events", "action_journal", "objects")
                )
            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_installation_resources",
                return_value=attacked_resources,
            ), case.assertRaises(error):
                api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
            with stack[4]._factory.open("application") as connection:
                after_counts = tuple(
                    connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    for table in ("tasks", "events", "action_journal", "objects")
                )
            case.assertEqual(after_counts, before_counts)
    clean_returncode, unpacked_returncode, duplicate_returncode = (
        _installed_source_provenance_returncodes()
    )
    case.assertEqual(clean_returncode, 0)
    case.assertNotEqual(unpacked_returncode, 0)
    case.assertNotEqual(duplicate_returncode, 0)
    tampered = list(resources)
    tampered[3] = tampered[3] + b"\n"
    clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
    with repository_stack(manual_time=clock) as stack, mock.patch.object(
        graph_engineering,
        "_dependency_advisory_installation_resources",
        return_value=tuple(tampered),
    ):
        with case.assertRaises(error):
            api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
    for label, replacement in (
        ("missing-source-artifact", resources[:3] + resources[4:]),
        (
            "source-attestation-replacement",
            resources[:4] + (resources[4] + b"\n",) + resources[5:],
        ),
    ):
        clock = ManualTime(_timestamp_ns("2026-08-29T12:00:00Z"))
        with case.subTest(source_provenance_attack=label), repository_stack(
            manual_time=clock,
        ) as stack, mock.patch.object(
            graph_engineering,
            "_dependency_advisory_installation_resources",
            return_value=replacement,
        ):
            with case.assertRaises(error):
                api.DependencyAdvisoryRegistryFactory.from_installation(stack[4])
