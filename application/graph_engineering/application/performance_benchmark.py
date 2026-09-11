"""Consumer-local ADR-0007 benchmark installation and measurement authority."""

from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.metadata as importlib_metadata
import json
import os
import pathlib
import sys
import time
import tomllib
from collections.abc import Mapping
from types import BuiltinFunctionType, MappingProxyType

from graph_engineering.adapters.command_native import (
    CommandExecutionResult,
    CommandRuntimePolicy,
    StructuredCommandLauncher,
)
from graph_engineering.adapters.action_adapters import ActionAdapterFactory
from graph_engineering.adapters.performance_environment import (
    PerformanceDisposableRoot,
    PerformanceEnvironmentInputs,
    capture_performance_environment_inputs,
    capture_performance_source_control_inputs,
    performance_command_registry_document,
)
from graph_engineering.core.contracts.schema import validate_instance
from graph_engineering.core.action_adapters import ActionInvocation
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.performance_benchmark import (
    PERFORMANCE_BENCHMARK_SCHEMA_IDS,
    BenchmarkCase,
    PerformanceBenchmarkError,
    PerformanceBenchmarkRegistryData,
    StatisticsPolicy,
    comparison_products,
    integer_statistics,
    parse_performance_benchmark_registry,
)


_BUILTIN_MONOTONIC_NS = time.monotonic_ns


def _installation_identity(
    provenance_bytes: bytes,
) -> tuple[str, str, str, str, str]:
    """Return exact current distribution/source installation identity pins."""

    try:
        project = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))["project"]
        distribution_name = project["name"]
        distribution_version = project["version"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise PerformanceBenchmarkError("performance distribution provenance is malformed") from error
    if type(distribution_name) is not str or type(distribution_version) is not str:
        raise PerformanceBenchmarkError("performance distribution identity is not exact")

    import graph_engineering

    module = pathlib.Path(graph_engineering.__file__).resolve(strict=True)
    try:
        distribution = importlib_metadata.distribution(distribution_name)
    except importlib_metadata.PackageNotFoundError:
        source_root = module.parents[2]
        try:
            source_control = capture_performance_source_control_inputs()
        except ValueError as error:
            raise PerformanceBenchmarkError(
                "performance source installation control is not exact"
            ) from error
        control = pathlib.Path(source_control.control_root).resolve(strict=True)
        attestation_bytes = (control / "source-checkout-attestation-v1.json").read_bytes()
        attestation = _strict_json(attestation_bytes, "performance source attestation")
        if (
            attestation.get("source_root") != os.fspath(source_root)
            or type(attestation.get("file_digests")) is not dict
            or type(attestation.get("runtime_manifest_digest")) is not str
        ):
            raise PerformanceBenchmarkError(
                "performance source installation attestation changed"
            )
        record_projection = json.dumps(
            {
                "file_digests": attestation["file_digests"],
                "runtime_manifest_digest": attestation["runtime_manifest_digest"],
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return (
            os.fspath(source_root),
            distribution_version,
            hashlib.sha256(record_projection).hexdigest(),
            hashlib.sha256(attestation_bytes).hexdigest(),
            "source-attested",
        )

    root = pathlib.Path(distribution.locate_file("")).resolve(strict=True)
    files = tuple(distribution.files or ())
    records = tuple(
        item for item in files if pathlib.PurePosixPath(str(item)).name == "RECORD"
        and ".dist-info" in pathlib.PurePosixPath(str(item)).as_posix()
    )
    if (
        distribution.version != distribution_version
        or len(records) != 1
        or not module.is_relative_to(root)
    ):
        raise PerformanceBenchmarkError("performance installed distribution changed")
    record_path = pathlib.Path(distribution.locate_file(records[0])).resolve(strict=True)
    record_bytes = record_path.read_bytes()
    return (
        os.fspath(root),
        distribution_version,
        hashlib.sha256(record_bytes).hexdigest(),
        hashlib.sha256(record_bytes + provenance_bytes).hexdigest(),
        "installed-record",
    )


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise PerformanceBenchmarkError(f"{label} has a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PerformanceBenchmarkError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise PerformanceBenchmarkError(f"{label} root is not an object")
    return value


def _raw(value: object, label: str) -> str:
    if (
        type(value) is not str or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PerformanceBenchmarkError(f"{label} is not a raw SHA-256")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or not value.isascii()
        or "\x00" in value
    ):
        raise PerformanceBenchmarkError(f"{label} is not exact text")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise PerformanceBenchmarkError(f"{label} is not a semantic digest")
    return value


def _semantic(document: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        freeze(document),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _self_digest(document: Mapping[str, object], name: str, field: str) -> str:
    expected = _digest(document.get(field), field)
    body = copy.deepcopy(dict(document))
    del body[field]
    actual = _semantic(body, name)
    if not hmac.compare_digest(expected, actual):
        raise PerformanceBenchmarkError(f"{name} self digest changed")
    return expected


def _load_projection() -> tuple[PerformanceBenchmarkRegistryData, FrozenMap, tuple[str, ...]]:
    from graph_engineering import (
        DistributionIdentityError,
        _performance_benchmark_installation_resources,
    )

    try:
        resources = _performance_benchmark_installation_resources()
        (
            provenance_bytes, registry_bytes, bootstrap_bytes, schema_registry_bytes,
            fixture_bytes, sample_bytes, binding_bytes, runtime_bytes, oracle_bytes,
            source_registry_bytes, child_bytes, build_backend_bytes,
        ) = resources[:12]
        schema_bodies = tuple(resources[12:12 + len(PERFORMANCE_BENCHMARK_SCHEMA_IDS)])
        provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
        project = provenance["project"]
        pin = provenance["tool"]["gew"]["profile"]["performance-benchmark"]
    except (
        DistributionIdentityError, KeyError, TypeError, UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise PerformanceBenchmarkError(
            "performance benchmark installation bootstrap is unavailable"
        ) from error
    expected_pin_fields = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "bootstrap-id",
        "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
        "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "fixture-id", "fixture-digest", "fixture-raw-sha256",
        "fixture-source", "fixture-resource", "sample-set-id",
        "sample-set-digest", "sample-raw-sha256", "sample-source",
        "sample-resource", "schema-vectors",
        "command-binding-id", "command-binding-digest", "command-binding-raw-sha256",
        "command-binding-source", "command-binding-resource",
        "command-runtime-policy-id", "command-runtime-policy-digest",
        "command-runtime-policy-raw-sha256", "command-runtime-policy-source",
        "command-runtime-policy-resource", "correctness-policy-id",
        "correctness-oracle-digest", "correctness-oracle-raw-sha256",
        "correctness-oracle-source", "correctness-oracle-resource",
        "source-registry-id", "source-registry-digest", "source-registry-raw-sha256",
        "source-registry-source", "source-registry-resource", "child-raw-sha256",
        "child-source", "child-resource", "build-backend-raw-sha256",
        "build-backend-source", "build-backend-resource", "distribution-name",
        "distribution-version", "source-attestation-policy-id",
        "maximum-warmup-count", "maximum-repetition-count", "protected-resources",
        "protected-closure-digest",
    }
    if type(pin) is not dict or set(pin) != expected_pin_fields:
        raise PerformanceBenchmarkError("performance benchmark independent pin is not exact")
    protected_pin = pin["protected-resources"]
    if (
        type(protected_pin) is not list
        or len(resources) != 12 + len(PERFORMANCE_BENCHMARK_SCHEMA_IDS) + len(protected_pin)
    ):
        raise PerformanceBenchmarkError(
            "performance benchmark installation resource closure is incomplete"
        )
    protected_bodies = tuple(resources[12 + len(PERFORMANCE_BENCHMARK_SCHEMA_IDS):])
    if (
        type(project) is not dict
        or type(project.get("name")) is not str
        or type(project.get("version")) is not str
        or not project["name"]
        or not project["version"]
    ):
        raise PerformanceBenchmarkError("performance benchmark distribution identity is invalid")
    for body, field in (
        (registry_bytes, "registry-raw-sha256"),
        (bootstrap_bytes, "bootstrap-raw-sha256"),
        (schema_registry_bytes, "profile-schema-registry-raw-sha256"),
        (fixture_bytes, "fixture-raw-sha256"),
        (sample_bytes, "sample-raw-sha256"),
        (binding_bytes, "command-binding-raw-sha256"),
        (runtime_bytes, "command-runtime-policy-raw-sha256"),
        (oracle_bytes, "correctness-oracle-raw-sha256"),
        (source_registry_bytes, "source-registry-raw-sha256"),
        (child_bytes, "child-raw-sha256"),
        (build_backend_bytes, "build-backend-raw-sha256"),
    ):
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), _raw(pin[field], field)):
            raise PerformanceBenchmarkError("performance benchmark installation bytes changed")
    profile_registry = _strict_json(schema_registry_bytes, "profile schema registry")
    if (
        profile_registry.get("registry_id") != pin["profile-schema-registry-id"]
        or profile_registry.get("registry_digest") != pin["profile-schema-registry-digest"]
    ):
        raise PerformanceBenchmarkError("performance schema registry pin changed")
    vectors = pin["schema-vectors"]
    vector_fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(vectors) is not list or len(vectors) != len(PERFORMANCE_BENCHMARK_SCHEMA_IDS)
        or any(type(item) is not dict or set(item) != vector_fields for item in vectors)
        or tuple(item["schema-id"] for item in vectors) != PERFORMANCE_BENCHMARK_SCHEMA_IDS
    ):
        raise PerformanceBenchmarkError("performance schema vector is not exact")
    for vector, body in zip(vectors, schema_bodies, strict=True):
        if not hmac.compare_digest(
            hashlib.sha256(body).hexdigest(), _raw(vector["raw-sha256"], "schema raw digest")
        ):
            raise PerformanceBenchmarkError("performance schema bytes changed")
    schema_documents: dict[str, dict[str, object]] = {}
    for vector, body in zip(vectors, schema_bodies, strict=True):
        document = _strict_json(body, "performance schema")
        if document.get("$id") != vector["schema-id"]:
            raise PerformanceBenchmarkError("performance schema identity changed")
        schema_documents[vector["schema-id"]] = document

    def resolve_schema(current_id: str, reference: str) -> tuple[object, str]:
        target_text, separator, fragment = reference.partition("#")
        target_id = current_id if not target_text else target_text
        if target_id not in schema_documents:
            raise PerformanceBenchmarkError("performance schema reference is not closed")
        target: object = schema_documents[target_id]
        if separator and fragment:
            if not fragment.startswith("/"):
                raise PerformanceBenchmarkError("performance schema pointer is invalid")
            for encoded in fragment[1:].split("/"):
                token = encoded.replace("~1", "/").replace("~0", "~")
                if type(target) is not dict or token not in target:
                    raise PerformanceBenchmarkError("performance schema pointer is unresolved")
                target = target[token]
        return target, target_id

    def validate_document(name: str, document: dict[str, object], derived: str) -> None:
        source_id = f"urn:gew:schema:{name}:1.0.0"
        input_id = f"urn:gew:schema:{name}-input:1.0.0"
        if validate_instance(
            schema_documents[source_id], document, source_id=source_id,
            resolver=resolve_schema,
        ):
            raise PerformanceBenchmarkError(f"{name} source schema rejected installed bytes")
        unsigned = copy.deepcopy(document)
        unsigned.pop(derived, None)
        if validate_instance(
            schema_documents[input_id], unsigned, source_id=input_id,
            resolver=resolve_schema,
        ):
            raise PerformanceBenchmarkError(f"{name} input schema rejected installed projection")

    registry_document = _strict_json(registry_bytes, "performance benchmark registry")
    validate_document("performance-benchmark-registry", registry_document, "registry_digest")
    for row in registry_document.get("benchmark_cases", []):
        if type(row) is not dict:
            raise PerformanceBenchmarkError("performance case is malformed")
        validate_document("performance-benchmark-case", row, "benchmark_case_digest")
    maximum_repetitions = pin["maximum-repetition-count"]
    maximum_warmups = pin["maximum-warmup-count"]
    if type(maximum_repetitions) is not int or type(maximum_warmups) is not int:
        raise PerformanceBenchmarkError("performance installation bounds are not exact")
    registry = parse_performance_benchmark_registry(
        registry_document,
        maximum_repetition_count=maximum_repetitions,
        maximum_warmup_count=maximum_warmups,
    )
    if registry.registry_id != pin["registry-id"] or registry.registry_digest != pin["registry-digest"]:
        raise PerformanceBenchmarkError("performance benchmark registry pin changed")
    fixture = _strict_json(fixture_bytes, "performance fixture")
    sample = _strict_json(sample_bytes, "performance sample")
    if (
        tuple(fixture) != ("schema_version", "fixture_id", "payload", "fixture_digest")
        or tuple(sample) != (
            "schema_version", "sample_set_id", "benchmark_case_id",
            "source_identities", "sample_set_digest",
        )
        or fixture["schema_version"] != "1.0.0"
        or sample["schema_version"] != "1.0.0"
        or fixture["fixture_id"] != pin["fixture-id"]
        or sample["sample_set_id"] != pin["sample-set-id"]
        or _self_digest(fixture, "performance-benchmark-fixture", "fixture_digest")
        != pin["fixture-digest"]
        or _self_digest(sample, "performance-benchmark-sample-set", "sample_set_digest")
        != pin["sample-set-digest"]
    ):
        raise PerformanceBenchmarkError("performance fixture/sample binding changed")
    installed_case = registry.benchmark_cases[0]
    if (
        installed_case.fixture_id != fixture["fixture_id"]
        or installed_case.fixture_digest != fixture["fixture_digest"]
        or installed_case.sample_set_id != sample["sample_set_id"]
        or installed_case.sample_set_digest != sample["sample_set_digest"]
    ):
        raise PerformanceBenchmarkError("performance case fixture/sample binding changed")
    bootstrap = _strict_json(bootstrap_bytes, "performance benchmark bootstrap")
    validate_document(
        "performance-benchmark-installation-bootstrap", bootstrap, "bootstrap_digest",
    )
    bootstrap_vectors = bootstrap["schema_resources"]
    if (
        bootstrap.get("schema_version") != "1.0.0"
        or bootstrap.get("bootstrap_id") != pin["bootstrap-id"]
        or _self_digest(
            bootstrap, "performance-benchmark-installation-bootstrap", "bootstrap_digest"
        ) != pin["bootstrap-digest"]
        or bootstrap.get("registry_id") != registry.registry_id
        or bootstrap.get("registry_digest") != registry.registry_digest
        or bootstrap.get("registry_raw_sha256") != pin["registry-raw-sha256"]
        or bootstrap.get("profile_schema_registry_digest")
        != pin["profile-schema-registry-digest"]
        or bootstrap.get("profile_schema_registry_raw_sha256")
        != pin["profile-schema-registry-raw-sha256"]
        or bootstrap.get("fixture_digest") != pin["fixture-digest"]
        or bootstrap.get("sample_set_digest") != pin["sample-set-digest"]
        or bootstrap.get("network_mode") != "offline-only"
        or bootstrap.get("fallback") != "none"
        or type(bootstrap_vectors) is not list
        or tuple(item.get("schema_id") for item in bootstrap_vectors if type(item) is dict)
        != PERFORMANCE_BENCHMARK_SCHEMA_IDS
        or tuple(item.get("raw_sha256") for item in bootstrap_vectors if type(item) is dict)
        != tuple(item["raw-sha256"] for item in vectors)
    ):
        raise PerformanceBenchmarkError("performance benchmark bootstrap binding changed")
    key_map = {
        key.replace("_", "-"): value for key, value in bootstrap.items()
        if key not in {"schema_version", "schema_resources", "protected_resources", "bootstrap_digest", "network_mode", "fallback"}
    }
    for key, value in key_map.items():
        if key in pin and pin[key] != value:
            raise PerformanceBenchmarkError("performance bootstrap and installation pin diverged")

    binding = _strict_json(binding_bytes, "performance command binding")
    runtime = _strict_json(runtime_bytes, "performance command runtime policy")
    oracle = _strict_json(oracle_bytes, "performance correctness oracle")
    source_registry = _strict_json(source_registry_bytes, "performance source registry")
    exact_documents = (
        (binding, "performance-command-binding", "binding_digest", "command-binding-id", "binding_id", "command-binding-digest"),
        (oracle, "performance-correctness-oracle", "oracle_digest", "correctness-policy-id", "correctness_policy_id", "correctness-oracle-digest"),
        (source_registry, "performance-source-registry", "source_registry_digest", "source-registry-id", "source_registry_id", "source-registry-digest"),
    )
    for document, name, field, pin_id, document_id, pin_digest in exact_documents:
        if _self_digest(document, name, field) != pin[pin_digest] or document.get(document_id) != pin[pin_id]:
            raise PerformanceBenchmarkError(f"{name} installation binding changed")
    try:
        parsed_runtime = CommandRuntimePolicy.from_dict(runtime)
    except ValueError as error:
        raise PerformanceBenchmarkError("performance command runtime policy changed") from error
    if (
        parsed_runtime.policy_id != pin["command-runtime-policy-id"]
        or parsed_runtime.policy_digest != pin["command-runtime-policy-digest"]
    ):
        raise PerformanceBenchmarkError("performance command runtime policy pin changed")
    source_rows = source_registry.get("sources")
    history = source_registry.get("transition_history")
    if (
        type(source_rows) is not list or len(source_rows) != 2
        or any(type(row) is not dict or set(row) != {"source_identity", "content_utf8", "raw_sha256"} for row in source_rows)
        or tuple(row["source_identity"] for row in source_rows) != tuple(sorted({row["source_identity"] for row in source_rows}))
        or type(history) is not list or len(history) != 3
        or history != [registry.benchmark_cases[0].baseline_source_identity, registry.benchmark_cases[0].candidate_source_identity, registry.benchmark_cases[0].baseline_source_identity]
        or any(type(row["content_utf8"]) is not str or hashlib.sha256(row["content_utf8"].encode()).hexdigest() != row["raw_sha256"] for row in source_rows)
    ):
        raise PerformanceBenchmarkError("performance source registry is not exact")
    if (
        binding.get("command_id") != registry.benchmark_cases[0].command_id
        or binding.get("binding_digest") != registry.benchmark_cases[0].command_binding_digest
        or binding.get("child_raw_sha256") != hashlib.sha256(child_bytes).hexdigest()
        or binding.get("side_effect_class") != "benchmark-read-only"
        or binding.get("root_mode") != "factory-private-disposable"
        or runtime.get("policy_digest") != registry.benchmark_cases[0].command_runtime_policy_digest
        or oracle.get("expected_correctness_digest") != registry.benchmark_cases[0].expected_correctness_digest
        or oracle.get("fixture_digest") != fixture["fixture_digest"]
    ):
        raise PerformanceBenchmarkError("performance command/correctness binding changed")
    protected = pin["protected-resources"]
    normalized_protected = [
        {"raw_sha256": item["raw-sha256"], "source": item["source"], "resource": item["resource"]}
        for item in protected
    ] if type(protected) is list and all(type(item) is dict for item in protected) else []
    if (
        type(protected) is not list or normalized_protected != bootstrap.get("protected_resources")
        or tuple(item["source"] for item in protected) != tuple(sorted({item["source"] for item in protected}))
        or any(type(item) is not dict or set(item) != {"raw-sha256", "source", "resource"} for item in protected)
    ):
        raise PerformanceBenchmarkError("performance protected closure changed")
    if _semantic({"resources": normalized_protected}, "performance-protected-resource-closure") != pin["protected-closure-digest"]:
        raise PerformanceBenchmarkError("performance protected closure digest changed")
    for vector, body in zip(protected, protected_bodies, strict=True):
        if hashlib.sha256(body).hexdigest() != vector["raw-sha256"]:
            raise PerformanceBenchmarkError("performance protected resource bytes changed")
    (
        distribution_root,
        distribution_version,
        record_raw_sha256,
        source_attestation_digest,
        installation_mode,
    ) = _installation_identity(provenance_bytes)
    projection = freeze({
        "registry_digest": registry.registry_digest,
        "registry_raw_sha256": hashlib.sha256(registry_bytes).hexdigest(),
        "bootstrap_digest": pin["bootstrap-digest"],
        "bootstrap_raw_sha256": hashlib.sha256(bootstrap_bytes).hexdigest(),
        "profile_schema_registry_digest": pin["profile-schema-registry-digest"],
        "profile_schema_registry_raw_sha256": hashlib.sha256(schema_registry_bytes).hexdigest(),
        "fixture_digest": pin["fixture-digest"],
        "fixture_raw_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "sample_set_digest": pin["sample-set-digest"],
        "sample_raw_sha256": hashlib.sha256(sample_bytes).hexdigest(),
        "schema_raw_sha256": tuple(item["raw-sha256"] for item in vectors),
        "distribution_identity": f"{project['name']}:{project['version']}",
        "distribution_root": distribution_root,
        "distribution_version": distribution_version,
        "record_raw_sha256": record_raw_sha256,
        "source_attestation_digest": source_attestation_digest,
        "installation_mode": installation_mode,
        "installation_record_digest": hashlib.sha256(b"\0".join(resources)).hexdigest(),
        "build_attestation_digest": hashlib.sha256(build_backend_bytes + provenance_bytes).hexdigest(),
        "protected_closure_digest": pin["protected-closure-digest"],
        "binding": binding,
        "runtime_policy": runtime,
        "correctness_oracle": oracle,
        "source_registry": source_registry,
        "fixture_document": fixture,
        "fixture_raw_sha256": hashlib.sha256(fixture_bytes).hexdigest(),
        "child_raw_sha256": hashlib.sha256(child_bytes).hexdigest(),
        "maximum_repetition_count": maximum_repetitions,
        "maximum_warmup_count": maximum_warmups,
    })
    return registry, projection, tuple(item["schema-id"] for item in vectors)


class _ImmutableIssued:
    __slots__ = ("_sealed",)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("factory-issued benchmark authorities are immutable")
        object.__setattr__(self, name, value)

    def _seal(self) -> None:
        object.__setattr__(self, "_sealed", True)


class _IdentityLedger:
    """Consumer-local append-only object-identity issuance ledger."""

    __slots__ = ("__issued",)

    def __init__(self) -> None:
        self.__issued: tuple[object, ...] = ()

    def issue(self, value: object) -> None:
        if any(item is value for item in self.__issued):
            raise PerformanceBenchmarkError("benchmark authority was issued twice")
        self.__issued = (*self.__issued, value)

    def contains(self, value: object) -> bool:
        return any(item is value for item in self.__issued)

    def values(self) -> tuple[object, ...]:
        return self.__issued


class PerformanceBenchmarkRegistryAuthority(_ImmutableIssued):
    __slots__ = ("_owner", "registry", "projection")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("performance benchmark registry authorities are factory-issued")


class PerformanceBenchmarkClockAuthority(_ImmutableIssued):
    __slots__ = ("_owner", "_reader", "_identity")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark clocks are factory-issued")


class BenchmarkSourceObservationAuthority(_ImmutableIssued):
    __slots__ = (
        "_owner", "_session", "source_identity", "generation", "previous_digest",
        "observation", "observation_digest",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark source observations are factory-issued")


class BenchmarkCommandSessionAuthority(_ImmutableIssued):
    __slots__ = (
        "_owner", "root", "launcher", "command_binding_digest",
        "command_registry_digest", "command_runtime_policy_digest",
        "executable_raw_sha256", "cwd_identity_digest", "session_digest",
        "_issued_snapshot", "_closed",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark command sessions are factory-issued")

    def close(self) -> None:
        if not self._closed:
            object.__setattr__(self, "_closed", True)
            self.root.close()
            self.launcher.close()


class BenchmarkSequenceAuthority(_ImmutableIssued):
    __slots__ = (
        "_owner", "case_id", "sequence_kind", "source_identity", "environment_digest",
        "durations_ns", "median_ns", "mad_ns", "noise_quiet", "sample_set_digest",
        "before_environment", "after_environment", "warmup_correctness_observations",
        "sample_documents", "sample_set_observation", "statistics_observation",
        "source_observation_digest", "request_digest", "_issued_snapshot",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark sequence authorities are factory-issued")


class BenchmarkComparisonAuthority(_ImmutableIssued):
    __slots__ = (
        "_owner", "kind", "passed", "left_product", "right_product", "observation",
        "_baseline_sequence", "_candidate_sequence", "_rollback_sequence",
        "_numerator", "_denominator", "_issued_snapshot",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark comparison authorities are factory-issued")


class PerformanceBenchmarkEvidenceAuthority(_ImmutableIssued):
    __slots__ = ("_owner", "projection", "projection_digest", "_issued_snapshot")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("performance evidence authorities are factory-issued")


class _PerformanceProfileCoverageRegistration(_ImmutableIssued):
    __slots__ = (
        "_owner", "_authority", "_application", "_task_application",
        "_repository", "_object_repository", "_runtime", "_plan",
        "_registry_authority", "_evidence", "_session", "_task_id",
        "_evidence_projection", "_plan_digest", "_plan_binding",
        "_assessment_digest",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("performance coverage registrations are factory-issued")


class PerformanceBenchmarkRegistryFactory:
    __slots__ = (
        "_registry", "_projection", "_schema_ids", "_registry_ledger",
        "_observation_factory_ledger", "_clock_ledger", "_session_ledger",
        "_source_ledger", "_evidence_ledger", "_rehydrated_evidence_ledger",
        "_task_evidence", "_profile_coverage_ledger",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("performance benchmark registry factories come from installation")

    @classmethod
    def from_installation(cls) -> "PerformanceBenchmarkRegistryFactory":
        registry, projection, schema_ids = _load_projection()
        factory = object.__new__(cls)
        factory._registry = registry
        factory._projection = projection
        factory._schema_ids = schema_ids
        factory._registry_ledger = _IdentityLedger()
        factory._observation_factory_ledger = _IdentityLedger()
        factory._clock_ledger = _IdentityLedger()
        factory._session_ledger = _IdentityLedger()
        factory._source_ledger = _IdentityLedger()
        factory._evidence_ledger = _IdentityLedger()
        factory._rehydrated_evidence_ledger = _IdentityLedger()
        factory._task_evidence: dict[str, PerformanceBenchmarkEvidenceAuthority] = {}
        factory._profile_coverage_ledger = _IdentityLedger()
        return factory

    def registry(self) -> PerformanceBenchmarkRegistryAuthority:
        self._revalidate()
        authority = object.__new__(PerformanceBenchmarkRegistryAuthority)
        authority._owner = self
        authority.registry = self._registry
        authority.projection = self._projection
        authority._seal()
        self._registry_ledger.issue(authority)
        return authority

    def _revalidate(self) -> None:
        registry, projection, schema_ids = _load_projection()
        if (
            registry != self._registry or projection != self._projection
            or schema_ids != self._schema_ids
        ):
            raise PerformanceBenchmarkError("performance benchmark installation changed")

    def require_current(self, authority: object) -> PerformanceBenchmarkRegistryAuthority:
        self._revalidate()
        if (
            type(authority) is not PerformanceBenchmarkRegistryAuthority
            or getattr(authority, "_owner", None) is not self
            or not self._registry_ledger.contains(authority)
            or getattr(authority, "registry", None) is not self._registry
            or getattr(authority, "projection", None) != self._projection
        ):
            raise PerformanceBenchmarkError("performance benchmark authority is foreign or stale")
        return authority

    def _profile_coverage_rejection_message(
        self,
        authority: object,
        oracle: object,
    ) -> str | None:
        """Recompute an optional installed performance rejection vector."""

        current = self.require_current(authority)
        if not isinstance(oracle, Mapping):
            raise PerformanceBenchmarkError(
                "performance coverage rejection oracle is invalid"
            )
        rejection_input = oracle.get("rejection_input")
        if rejection_input is None:
            return None
        if (
            not isinstance(rejection_input, Mapping)
            or set(rejection_input) != {"kind", "values"}
            or rejection_input["kind"] != "integer-vector"
            or type(rejection_input["values"]) is not tuple
        ):
            raise PerformanceBenchmarkError(
                "performance coverage rejection input changed"
            )
        benchmark_case = current.registry.benchmark_cases[0]
        policies = tuple(
            policy for policy in current.registry.statistics_policies
            if policy.statistics_policy_id == benchmark_case.statistics_policy_id
        )
        if len(policies) != 1:
            raise PerformanceBenchmarkError(
                "performance coverage statistics authority is ambiguous"
            )
        median, mad, quiet = integer_statistics(
            rejection_input["values"], policies[0],
        )
        left, right = comparison_products(
            mad,
            median,
            policies[0].noise_ceiling_numerator,
            policies[0].noise_ceiling_denominator,
        )
        if quiet or left <= right:
            raise PerformanceBenchmarkError(
                "performance coverage rejection vector is not noisy"
            )
        message = oracle.get("reject_error_message")
        if type(message) is not str or not message:
            raise PerformanceBenchmarkError(
                "performance coverage rejection diagnostic is invalid"
            )
        return message

    def observation_factory(
        self, authority: object, session: object,
    ) -> "PerformanceBenchmarkObservationFactory":
        current = self.require_current(authority)
        command_session = self.require_command_session_current(session)
        clock = self.clock()
        factory = PerformanceBenchmarkObservationFactory._issue(
            self, current, command_session, clock,
        )
        self._observation_factory_ledger.issue(factory)
        return factory

    def clock(self) -> PerformanceBenchmarkClockAuthority:
        self._revalidate()
        if (
            type(_BUILTIN_MONOTONIC_NS) is not BuiltinFunctionType
            or _BUILTIN_MONOTONIC_NS.__module__ != "time"
            or _BUILTIN_MONOTONIC_NS.__name__ != "monotonic_ns"
            or time.monotonic_ns is not _BUILTIN_MONOTONIC_NS
        ):
            raise PerformanceBenchmarkError("genuine monotonic clock identity changed")
        authority = object.__new__(PerformanceBenchmarkClockAuthority)
        authority._owner = self
        authority._reader = _BUILTIN_MONOTONIC_NS
        authority._identity = ("time", "monotonic_ns", id(_BUILTIN_MONOTONIC_NS))
        authority._seal()
        self._clock_ledger.issue(authority)
        return authority

    def require_clock_current(self, authority: object) -> PerformanceBenchmarkClockAuthority:
        self._revalidate()
        if (
            type(authority) is not PerformanceBenchmarkClockAuthority
            or authority._owner is not self
            or not self._clock_ledger.contains(authority)
            or authority._reader is not _BUILTIN_MONOTONIC_NS
            or authority._identity != ("time", "monotonic_ns", id(_BUILTIN_MONOTONIC_NS))
            or time.monotonic_ns is not _BUILTIN_MONOTONIC_NS
        ):
            raise PerformanceBenchmarkError("benchmark clock authority is foreign or stale")
        return authority

    def private_root(self, authority: object) -> PerformanceDisposableRoot:
        current = self.require_current(authority)
        rows = current.projection["source_registry"]["sources"]
        source_documents = {
            row["source_identity"]: row["content_utf8"].encode("utf-8") for row in rows
        }
        fixture_bytes = json.dumps(
            thaw(current.projection["fixture_document"]),
            ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8") + b"\n"
        return PerformanceDisposableRoot.create(
            fixture_bytes=fixture_bytes,
            source_documents=source_documents,
            baseline_identity=current.registry.benchmark_cases[0].baseline_source_identity,
        )

    def command_session(
        self, authority: object, root: object, launcher: object,
    ) -> BenchmarkCommandSessionAuthority:
        current = self.require_current(authority)
        if type(root) is not PerformanceDisposableRoot:
            raise PerformanceBenchmarkError("benchmark disposable root is foreign")
        try:
            attested = StructuredCommandLauncher.require_attested(launcher)
        except Exception as error:
            raise PerformanceBenchmarkError("benchmark command launcher is not attested") from error
        self._validate_command_binding(current, root, attested)
        session = object.__new__(BenchmarkCommandSessionAuthority)
        session._owner = self
        session.root = root
        session.launcher = attested
        session.command_binding_digest = current.projection["binding"]["binding_digest"]
        session.command_registry_digest = attested.command_registry_digest
        session.command_runtime_policy_digest = attested.command_runtime_policy_digest
        session.executable_raw_sha256 = attested.executable_raw_sha256
        session.cwd_identity_digest = _semantic(
            {"identity": list(attested._cwd_identity)},
            "performance-command-cwd-identity",
        )
        session.session_digest = _semantic({
            "command_binding_digest": session.command_binding_digest,
            "command_registry_digest": session.command_registry_digest,
            "command_runtime_policy_digest": session.command_runtime_policy_digest,
            "cwd_identity_digest": session.cwd_identity_digest,
            "executable_raw_sha256": session.executable_raw_sha256,
        }, "performance-command-session")
        session._issued_snapshot = freeze({
            "command_binding_digest": session.command_binding_digest,
            "command_registry_digest": session.command_registry_digest,
            "command_runtime_policy_digest": session.command_runtime_policy_digest,
            "cwd_identity_digest": session.cwd_identity_digest,
            "executable_raw_sha256": session.executable_raw_sha256,
            "session_digest": session.session_digest,
        })
        session._closed = False
        session._seal()
        self._session_ledger.issue(session)
        return session

    def command_configuration_pins(
        self,
        authority: object,
        root: object,
        secret_provider_registry_digest: object,
    ) -> MappingProxyType:
        current = self.require_current(authority)
        if type(root) is not PerformanceDisposableRoot:
            raise PerformanceBenchmarkError("benchmark disposable root is foreign")
        _digest(secret_provider_registry_digest, "secret provider registry digest")
        try:
            registry = performance_command_registry_document(
                current.projection["binding"], root,
            )
        except (TypeError, ValueError, OSError) as error:
            raise PerformanceBenchmarkError("benchmark command registry changed") from error
        return MappingProxyType({
            "command-registry": registry["registry_digest"],
            "command-runtime-policy": current.projection["runtime_policy"]["policy_digest"],
            "secret-provider-registry": secret_provider_registry_digest,
        })

    def command_launcher(
        self,
        authority: object,
        root: object,
        adapter_factory: object,
        provider: object,
    ) -> StructuredCommandLauncher:
        current = self.require_current(authority)
        if (
            type(root) is not PerformanceDisposableRoot
            or type(adapter_factory) is not ActionAdapterFactory
        ):
            raise PerformanceBenchmarkError("benchmark launcher issuer is foreign")
        try:
            registry = performance_command_registry_document(
                current.projection["binding"], root,
            )
            launcher = adapter_factory.issue_project_command(
                registry,
                thaw(current.projection["runtime_policy"]),
                provider=provider,
            )
            attested = StructuredCommandLauncher.require_attested(launcher)
            self._validate_command_binding(current, root, attested)
        except Exception as error:
            raise PerformanceBenchmarkError("benchmark launcher issuance failed") from error
        return attested

    def _validate_command_binding(
        self,
        current: PerformanceBenchmarkRegistryAuthority,
        root: PerformanceDisposableRoot,
        attested: StructuredCommandLauncher,
    ) -> None:
        binding = current.projection["binding"]
        runtime = current.projection["runtime_policy"]
        entry = attested._entry
        policy = attested._policy
        expected_child = pathlib.Path(__file__).resolve().parents[3] / binding["child_source"]
        if (
            attested.command_id != binding["command_id"]
            or entry.adapter_id != binding["adapter_id"]
            or entry.allowed_root != os.fspath(root.root)
            or entry.cwd_relative != "work"
            or entry.argv_prefix
            != ("-I", "-S", "-B", os.fspath(expected_child), os.fspath(root.fixture))
            or entry.parameter_order != ("mode",)
            or dict(entry.parameter_values) != {"mode": ("correct",)}
            or dict(entry.static_environment) != {"LANG": "C", "LC_ALL": "C"}
            or dict(entry.secret_environment)
            or entry.side_effect_class != binding["side_effect_class"]
            or entry.idempotency_class != binding["idempotency_class"]
            or policy.policy_digest != runtime["policy_digest"]
            or policy.launcher_mode != runtime["launcher_mode"]
            or policy.max_parameters != runtime["max_parameters"]
            or policy.max_parameter_bytes != runtime["max_parameter_bytes"]
            or policy.max_output_bytes != runtime["max_output_bytes"]
            or policy.read_chunk_bytes != runtime["read_chunk_bytes"]
            or policy.timeout_ms != runtime["timeout_ms"]
            or policy.poll_interval_ms != runtime["poll_interval_ms"]
            or policy.termination_grace_ms != runtime["termination_grace_ms"]
            or policy.termination_force_wait_ms != runtime["termination_force_wait_ms"]
            or policy.output_field_allowlist != tuple(runtime["output_field_allowlist"])
            or policy.secret_encodings != tuple(runtime["secret_encodings"])
        ):
            raise PerformanceBenchmarkError("benchmark command session binding changed")

    def require_command_session_current(self, session: object) -> BenchmarkCommandSessionAuthority:
        self._revalidate()
        if (
            type(session) is not BenchmarkCommandSessionAuthority
            or session._owner is not self or session._closed
            or not self._session_ledger.contains(session)
            or session.command_binding_digest
            != self._projection["binding"]["binding_digest"]
        ):
            raise PerformanceBenchmarkError("benchmark command session is foreign or stale")
        try:
            launcher = StructuredCommandLauncher.require_attested(session.launcher)
            session.root.current_source_identity()
            current = next(
                item for item in self._registry_ledger.values()
                if item.registry is self._registry and item.projection == self._projection
            )
            self._validate_command_binding(current, session.root, launcher)
            fresh_snapshot = freeze({
                "command_binding_digest": self._projection["binding"]["binding_digest"],
                "command_registry_digest": launcher.command_registry_digest,
                "command_runtime_policy_digest": launcher.command_runtime_policy_digest,
                "cwd_identity_digest": _semantic(
                    {"identity": list(launcher._cwd_identity)},
                    "performance-command-cwd-identity",
                ),
                "executable_raw_sha256": launcher.executable_raw_sha256,
                "session_digest": _semantic({
                    "command_binding_digest": self._projection["binding"]["binding_digest"],
                    "command_registry_digest": launcher.command_registry_digest,
                    "command_runtime_policy_digest": launcher.command_runtime_policy_digest,
                    "cwd_identity_digest": _semantic(
                        {"identity": list(launcher._cwd_identity)},
                        "performance-command-cwd-identity",
                    ),
                    "executable_raw_sha256": launcher.executable_raw_sha256,
                }, "performance-command-session"),
            })
            if fresh_snapshot != session._issued_snapshot:
                raise PerformanceBenchmarkError("benchmark command session seal changed")
        except Exception as error:
            raise PerformanceBenchmarkError("benchmark command session changed") from error
        return session

    def observe_source(
        self, authority: object, session: object,
    ) -> BenchmarkSourceObservationAuthority:
        self.require_current(authority)
        current_session = self.require_command_session_current(session)
        identity = current_session.root.current_source_identity()
        history = tuple(self._projection["source_registry"]["transition_history"])
        issued = tuple(
            item for item in self._source_ledger.values()
            if item._session is current_session
        )
        generation = len(issued) + 1
        if generation > len(history) or identity != history[generation - 1]:
            raise PerformanceBenchmarkError("benchmark source history is out of order")
        previous = None if not issued else issued[-1].observation_digest
        body = {
            "schema_version": "1.0.0", "benchmark_case_id": self._registry.case_ids[0],
            "source_identity": identity, "generation": generation,
            "previous_observation_digest": previous,
            "source_raw_sha256": next(
                row["raw_sha256"] for row in self._projection["source_registry"]["sources"]
                if row["source_identity"] == identity
            ),
            "source_history_digest": _semantic(
                {"history": list(history[:generation])}, "performance-source-history",
            ),
        }
        body["source_observation_digest"] = _semantic(body, "performance-source-observation")
        observation = object.__new__(BenchmarkSourceObservationAuthority)
        observation._owner = self
        observation._session = current_session
        observation.source_identity = identity
        observation.generation = generation
        observation.previous_digest = previous
        observation.observation = freeze(body)
        observation.observation_digest = body["source_observation_digest"]
        observation._seal()
        self._source_ledger.issue(observation)
        return observation

    def transition_source(
        self, authority: object, session: object, target_identity: object,
    ) -> None:
        self.require_current(authority)
        current = self.require_command_session_current(session)
        if type(target_identity) is not str:
            raise PerformanceBenchmarkError("benchmark source target is not exact")
        history = tuple(self._projection["source_registry"]["transition_history"])
        issued = tuple(
            item for item in self._source_ledger.values() if item._session is current
        )
        if not issued or len(issued) >= len(history) or target_identity != history[len(issued)]:
            raise PerformanceBenchmarkError("benchmark source transition is out of order")
        current.root.transition(issued[-1].source_identity, target_identity)

    def require_source_current(self, observation: object) -> BenchmarkSourceObservationAuthority:
        self._revalidate()
        if (
            type(observation) is not BenchmarkSourceObservationAuthority
            or observation._owner is not self
            or not self._source_ledger.contains(observation)
            or _self_digest(thaw(observation.observation), "performance-source-observation", "source_observation_digest") != observation.observation_digest
            or observation.observation["source_identity"] != observation.source_identity
            or observation.observation["generation"] != observation.generation
            or observation.observation["previous_observation_digest"] != observation.previous_digest
        ):
            raise PerformanceBenchmarkError("benchmark source observation is foreign or stale")
        same_session = tuple(
            item for item in self._source_ledger.values()
            if item._session is observation._session
        )
        index = same_session.index(observation)
        if index + 1 != observation.generation or (index and same_session[index - 1].observation_digest != observation.previous_digest):
            raise PerformanceBenchmarkError("benchmark source observation history changed")
        return observation

    def rehydrate_source_observation(
        self, authority: object, session: object, document: object,
    ) -> BenchmarkSourceObservationAuthority:
        self.require_current(authority)
        current = self.require_command_session_current(session)
        if type(document) is not dict:
            raise PerformanceBenchmarkError("durable source observation is malformed")
        digest = _self_digest(document, "performance-source-observation", "source_observation_digest")
        matches = tuple(
            item for item in self._source_ledger.values()
            if item._session is current and item.observation_digest == digest
            and thaw(item.observation) == document
        )
        if len(matches) != 1:
            raise PerformanceBenchmarkError("durable source observation is not current")
        return self.require_source_current(matches[0])

    def rehydrate_source_history(
        self, authority: object, session: object, documents: object,
    ) -> tuple[BenchmarkSourceObservationAuthority, ...]:
        """Reissue exact source authorities from a complete durable A/B/A chain."""

        self.require_current(authority)
        current = self.require_command_session_current(session)
        history = tuple(self._projection["source_registry"]["transition_history"])
        if (
            type(documents) is not tuple
            or len(documents) != len(history)
            or any(type(document) is not dict for document in documents)
            or any(item._session is current for item in self._source_ledger.values())
            or current.root.current_source_identity() != history[-1]
        ):
            raise PerformanceBenchmarkError("durable source history is not exact")
        expected_keys = (
            "schema_version", "benchmark_case_id", "source_identity", "generation",
            "previous_observation_digest", "source_raw_sha256",
            "source_history_digest", "source_observation_digest",
        )
        expected_previous: str | None = None
        issued: list[BenchmarkSourceObservationAuthority] = []
        for index, (document, identity) in enumerate(zip(documents, history, strict=True), 1):
            source_raw = next(
                row["raw_sha256"]
                for row in self._projection["source_registry"]["sources"]
                if row["source_identity"] == identity
            )
            expected_body = {
                "schema_version": "1.0.0",
                "benchmark_case_id": self._registry.case_ids[0],
                "source_identity": identity,
                "generation": index,
                "previous_observation_digest": expected_previous,
                "source_raw_sha256": source_raw,
                "source_history_digest": _semantic(
                    {"history": list(history[:index])}, "performance-source-history",
                ),
            }
            expected_body["source_observation_digest"] = _semantic(
                expected_body, "performance-source-observation",
            )
            if tuple(document) != expected_keys or document != expected_body:
                raise PerformanceBenchmarkError("durable source history changed")
            observation = object.__new__(BenchmarkSourceObservationAuthority)
            observation._owner = self
            observation._session = current
            observation.source_identity = identity
            observation.generation = index
            observation.previous_digest = expected_previous
            observation.observation = freeze(expected_body)
            observation.observation_digest = expected_body["source_observation_digest"]
            observation._seal()
            issued.append(observation)
            expected_previous = observation.observation_digest
        for observation in issued:
            self._source_ledger.issue(observation)
        for observation in issued:
            self.require_source_current(observation)
        return tuple(issued)

    def _issue_performance_evidence(
        self,
        document: dict[str, object],
        *,
        rehydrated: bool = False,
    ) -> PerformanceBenchmarkEvidenceAuthority:
        projection = _validate_performance_evidence_document(
            self._registry, self._projection, document,
        )
        task_id = projection["task_id"]
        if type(task_id) is not str or task_id in self._task_evidence:
            raise PerformanceBenchmarkError(
                "performance task evidence is duplicate or malformed"
            )
        evidence = object.__new__(PerformanceBenchmarkEvidenceAuthority)
        evidence._owner = self
        evidence.projection = projection
        evidence.projection_digest = projection["projection_digest"]
        evidence._issued_snapshot = projection
        evidence._seal()
        self._evidence_ledger.issue(evidence)
        if rehydrated:
            self._rehydrated_evidence_ledger.issue(evidence)
        self._task_evidence[task_id] = evidence
        return evidence

    def require_performance_evidence_current(
        self, evidence: object,
    ) -> PerformanceBenchmarkEvidenceAuthority:
        self._revalidate()
        if (
            type(evidence) is not PerformanceBenchmarkEvidenceAuthority
            or evidence._owner is not self
            or not self._evidence_ledger.contains(evidence)
            or evidence._issued_snapshot is not evidence.projection
            or evidence.projection_digest != evidence.projection["projection_digest"]
        ):
            raise PerformanceBenchmarkError(
                "performance evidence is foreign, cloned, or stale"
            )
        current = _validate_performance_evidence_document(
            self._registry, self._projection, thaw(evidence.projection),
        )
        if current != evidence._issued_snapshot:
            raise PerformanceBenchmarkError("performance evidence changed")
        return evidence

    def rehydrate_performance_evidence(
        self, authority: object, document: object,
    ) -> PerformanceBenchmarkEvidenceAuthority:
        """Reissue task evidence from exact immutable bytes without a launcher."""

        self.require_current(authority)
        if type(document) is not dict:
            raise PerformanceBenchmarkError("durable performance evidence is malformed")
        projection = _validate_performance_evidence_document(
            self._registry, self._projection, copy.deepcopy(document),
        )
        task_id = projection["task_id"]
        existing = self._task_evidence.get(task_id)
        if existing is not None:
            current = self.require_performance_evidence_current(existing)
            if current.projection != projection:
                raise PerformanceBenchmarkError(
                    "durable performance evidence changed"
                )
            return current
        return self._issue_performance_evidence(
            thaw(projection), rehydrated=True,
        )

    def _issue_profile_coverage_registration(
        self,
        *,
        authority: object,
        application: object,
        task_application: object,
        repository: object,
        object_repository: object,
        runtime: object,
        plan: object,
        registry_authority: object,
    ) -> _PerformanceProfileCoverageRegistration:
        """Register one exact performance coverage consumer and no duplicate."""

        from graph_engineering.application.profile_execution import (
            CategoryExecutionApplication,
        )
        from graph_engineering.application.tasks import RuntimeContext, TaskApplication
        from graph_engineering.core.profile_coverage import ProfileCoverageExecutionPlan
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository

        current_registry = self.require_current(registry_authority)
        if (
            type(application) is not CategoryExecutionApplication
            or type(task_application) is not TaskApplication
            or type(repository) is not TaskRepository
            or type(object_repository) is not ObjectRepository
            or type(runtime) is not RuntimeContext
            or type(plan) is not ProfileCoverageExecutionPlan
            or application._policy.profile_id != "performance"
            or application._task_application is not task_application
            or application._repository is not repository
            or application._objects is not object_repository
            or application._runtime is not runtime
            or task_application._repository is not repository
            or task_application._materialization_objects is not object_repository
            or application._oracle._performance_registry_factory is not self
            or application._oracle._performance_registry_authority
            is not current_registry
        ):
            raise PerformanceBenchmarkError(
                "performance coverage consumer inputs are foreign"
            )
        runtime.require_issued()
        task_id = application._facts._coverage_task_identity()
        matching_bindings = tuple(
            binding
            for binding in plan.bindings.values()
            if binding["task_id"] == task_id
        )
        if (
            len(matching_bindings) != 1
            or matching_bindings[0]["profile_id"] != "performance"
        ):
            raise PerformanceBenchmarkError(
                "performance coverage task or plan binding changed"
            )
        binding = matching_bindings[0]
        if any(
            registration._application is application
            or registration._task_id == task_id
            for registration in self._profile_coverage_ledger.values()
        ):
            raise PerformanceBenchmarkError(
                "performance coverage consumer is already registered"
            )
        assessment = None
        if binding["expected_result"] == "COMPLETED":
            # Restart rehydration is authorized only by the task-current,
            # byte-recomputed completion assessment.  No caller evidence or
            # cache is consulted before this consumer-local restore.
            assessment = application.current_assessment(
                task_id, expected_profile_id="performance",
            )
        evidence = self._task_evidence.get(task_id)
        if evidence is None:
            raise PerformanceBenchmarkError(
                "performance coverage evidence is unavailable"
            )
        current_evidence = self.require_performance_evidence_current(evidence)
        evidence_projection = current_evidence.projection
        if (
            evidence_projection["profile_id"] != "performance"
            or evidence_projection["task_id"] != task_id
            or evidence_projection["column_id"] != binding["column_id"]
        ):
            raise PerformanceBenchmarkError(
                "performance coverage task evidence changed"
            )
        snapshot = task_application.runtime_show(task_id, runtime).snapshot
        graph_ref = snapshot.graph_ref
        expected_pins = {
            "base_graph_digest": graph_ref["graph_digest"],
            "profile_digest": graph_ref["profile_digest"],
            "overlay_digest": graph_ref["overlay_digest"],
            "project_config_digest": graph_ref["project_config_digest"],
            "support_matrix_digest": graph_ref["support_matrix_digest"],
            "materialization_digest": graph_ref["materialization_digest"],
        }
        if binding["expected_result"] == "COMPLETED":
            task_binding_matches = (
                assessment is not None
                and assessment.performance_evidence_projection
                == evidence_projection
                and evidence_projection["task_revision"]
                == assessment.task_revision
                and evidence_projection["snapshot_digest"]
                == assessment.snapshot_digest
                and evidence_projection["invalidation_epoch"]
                == assessment.invalidation_epoch
                and snapshot.task_revision == assessment.task_revision + 1
            )
        else:
            task_binding_matches = (
                evidence_projection["task_revision"] == snapshot.task_revision
                and evidence_projection["snapshot_digest"]
                == snapshot.snapshot_digest
                and evidence_projection["invalidation_epoch"]
                == snapshot.invalidation_epoch
            )
        if (
            not task_binding_matches
            or thaw(evidence_projection["graph_ref_pins"]) != expected_pins
        ):
            raise PerformanceBenchmarkError(
                "performance coverage evidence task binding changed"
            )
        rehydrated = self._rehydrated_evidence_ledger.contains(current_evidence)
        sessions = tuple(
            session
            for session in self._session_ledger.values()
            if thaw(session._issued_snapshot)
            == thaw(evidence_projection["session_pins"])
        )
        if rehydrated:
            if sessions:
                raise PerformanceBenchmarkError(
                    "rehydrated performance coverage gained a launcher"
                )
            session = None
        else:
            if len(sessions) != 1:
                raise PerformanceBenchmarkError(
                    "performance coverage launcher is unavailable"
                )
            session = self.require_command_session_current(sessions[0])
        plan.isolated_runner_bytes()
        registration = object.__new__(_PerformanceProfileCoverageRegistration)
        registration._owner = self
        registration._authority = authority
        registration._application = application
        registration._task_application = task_application
        registration._repository = repository
        registration._object_repository = object_repository
        registration._runtime = runtime
        registration._plan = plan
        registration._registry_authority = current_registry
        registration._evidence = current_evidence
        registration._session = session
        registration._task_id = task_id
        registration._evidence_projection = evidence_projection
        registration._plan_digest = plan.plan_digest
        registration._plan_binding = binding
        registration._assessment_digest = (
            None if assessment is None else assessment.assessment_digest
        )
        registration._seal()
        self._profile_coverage_ledger.issue(registration)
        return registration

    def _rehydrate_quiescent_profile_coverage_rejection(
        self,
        registration: object,
        authority: object,
        restarted_factory: object,
        restarted_authority: object,
    ) -> PerformanceBenchmarkEvidenceAuthority:
        """Move only sealed rejection evidence across a quiescent restart."""

        if (
            type(restarted_factory) is not PerformanceBenchmarkRegistryFactory
            or restarted_factory is self
        ):
            raise PerformanceBenchmarkError(
                "restarted performance coverage factory is foreign"
            )
        restarted_factory.require_current(restarted_authority)
        if (
            type(registration) is not _PerformanceProfileCoverageRegistration
            or registration._owner is not self
            or registration._authority is not authority
            or not self._profile_coverage_ledger.contains(registration)
        ):
            raise PerformanceBenchmarkError(
                "quiescent performance coverage registration is foreign"
            )
        self.require_current(registration._registry_authority)
        evidence = self.require_performance_evidence_current(
            registration._evidence
        )
        current_bindings = tuple(
            binding
            for binding in registration._plan.bindings.values()
            if binding["task_id"] == registration._task_id
        )
        if (
            evidence.projection is not registration._evidence_projection
            or self._task_evidence.get(registration._task_id) is not evidence
            or registration._application._oracle._performance_registry_factory
            is not self
            or registration._application._oracle._performance_registry_authority
            is not registration._registry_authority
            or registration._application._facts._coverage_task_identity()
            != registration._task_id
            or registration._plan.plan_digest != registration._plan_digest
            or len(current_bindings) != 1
            or current_bindings[0] is not registration._plan_binding
            or registration._plan_binding["profile_id"] != "performance"
            or registration._plan_binding["expected_result"]
            != "EXPECTED_REJECTION"
            or registration._assessment_digest is not None
            or evidence.projection["task_id"] != registration._task_id
        ):
            raise PerformanceBenchmarkError(
                "quiescent performance coverage rejection binding changed"
            )
        session = registration._session
        closed_session = (
            type(session) is BenchmarkCommandSessionAuthority
            and session._owner is self
            and self._session_ledger.contains(session)
            and session._closed
            and thaw(session._issued_snapshot)
            == thaw(evidence.projection["session_pins"])
        )
        launcher_free_rehydration = (
            session is None
            and self._rehydrated_evidence_ledger.contains(evidence)
        )
        if not closed_session and not launcher_free_rehydration:
            raise PerformanceBenchmarkError(
                "quiescent performance coverage retained a live launcher"
            )
        return restarted_factory.rehydrate_performance_evidence(
            restarted_authority, thaw(evidence.projection),
        )

    def _require_profile_coverage_registration(
        self,
        registration: object,
        authority: object,
    ) -> _PerformanceProfileCoverageRegistration:
        """Revalidate the exact factory-issued coverage consumer at every use."""

        if (
            type(registration) is not _PerformanceProfileCoverageRegistration
            or registration._owner is not self
            or registration._authority is not authority
            or not self._profile_coverage_ledger.contains(registration)
        ):
            raise PerformanceBenchmarkError(
                "performance coverage registration is foreign or cloned"
            )
        self.require_current(registration._registry_authority)
        evidence = self.require_performance_evidence_current(
            registration._evidence
        )
        current_plan_bindings = tuple(
            binding
            for binding in registration._plan.bindings.values()
            if binding["task_id"] == registration._task_id
        )
        if (
            evidence.projection is not registration._evidence_projection
            or evidence.projection["task_id"] != registration._task_id
            or self._task_evidence.get(registration._task_id) is not evidence
            or registration._application._facts._coverage_task_identity()
            != registration._task_id
            or registration._application._task_application
            is not registration._task_application
            or registration._application._repository is not registration._repository
            or registration._application._objects
            is not registration._object_repository
            or registration._application._runtime is not registration._runtime
            or registration._application._oracle._performance_registry_factory
            is not self
            or registration._application._oracle._performance_registry_authority
            is not registration._registry_authority
            or registration._task_application._repository
            is not registration._repository
            or registration._task_application._materialization_objects
            is not registration._object_repository
            or registration._plan.plan_digest != registration._plan_digest
            or len(current_plan_bindings) != 1
            or current_plan_bindings[0] is not registration._plan_binding
        ):
            raise PerformanceBenchmarkError(
                "performance coverage registration binding changed"
            )
        registration._runtime.require_issued()
        registration._plan.isolated_runner_bytes()
        snapshot = registration._task_application.runtime_show(
            registration._task_id, registration._runtime,
        ).snapshot
        projection = evidence.projection
        if registration._plan_binding["expected_result"] == "COMPLETED":
            assessment = registration._application.current_assessment(
                registration._task_id,
                expected_profile_id="performance",
            )
            task_binding_matches = (
                assessment is not None
                and assessment.assessment_digest
                == registration._assessment_digest
                and assessment.performance_evidence_projection == projection
                and projection["task_revision"] == assessment.task_revision
                and projection["snapshot_digest"] == assessment.snapshot_digest
                and projection["invalidation_epoch"]
                == assessment.invalidation_epoch
                and snapshot.task_revision == assessment.task_revision + 1
            )
        else:
            task_binding_matches = (
                projection["task_revision"] == snapshot.task_revision
                and projection["snapshot_digest"] == snapshot.snapshot_digest
                and projection["invalidation_epoch"] == snapshot.invalidation_epoch
            )
        if not task_binding_matches:
            raise PerformanceBenchmarkError(
                "performance coverage registration is stale"
            )
        if registration._session is not None:
            self.require_command_session_current(registration._session)
        elif not self._rehydrated_evidence_ledger.contains(evidence):
            raise PerformanceBenchmarkError(
                "performance coverage launcher is unavailable"
            )
        return registration


_PERFORMANCE_EVIDENCE_FIELDS = frozenset({
    "schema_version", "evidence_kind", "task_id", "task_revision",
    "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
    "column_id", "graph_ref_pins", "installation_pins", "benchmark_case_digest",
    "factory_seal_digest", "environment_observation", "session_pins",
    "source_history", "sample_sets", "statistics_observations", "comparisons",
    "final_observation", "projection_digest",
})
_GRAPH_REF_PIN_FIELDS = frozenset({
    "base_graph_digest", "profile_digest", "overlay_digest",
    "project_config_digest", "support_matrix_digest", "materialization_digest",
})
_INSTALLATION_PIN_FIELDS = frozenset({
    "registry_digest", "registry_raw_sha256", "bootstrap_digest",
    "bootstrap_raw_sha256", "profile_schema_registry_digest",
    "profile_schema_registry_raw_sha256", "distribution_identity",
    "distribution_root", "distribution_version", "record_raw_sha256",
    "source_attestation_digest", "installation_mode", "build_attestation_digest",
    "protected_closure_digest", "command_binding_digest",
    "command_runtime_policy_digest", "correctness_oracle_digest",
    "source_registry_digest", "fixture_digest", "sample_set_digest",
    "child_raw_sha256",
})
_SESSION_PIN_FIELDS = frozenset({
    "command_binding_digest", "command_registry_digest",
    "command_runtime_policy_digest", "cwd_identity_digest",
    "executable_raw_sha256", "session_digest",
})


def _current_installation_pins(projection: FrozenMap) -> dict[str, object]:
    return {
        "registry_digest": projection["registry_digest"],
        "registry_raw_sha256": projection["registry_raw_sha256"],
        "bootstrap_digest": projection["bootstrap_digest"],
        "bootstrap_raw_sha256": projection["bootstrap_raw_sha256"],
        "profile_schema_registry_digest": projection["profile_schema_registry_digest"],
        "profile_schema_registry_raw_sha256": projection[
            "profile_schema_registry_raw_sha256"
        ],
        "distribution_identity": projection["distribution_identity"],
        "distribution_root": projection["distribution_root"],
        "distribution_version": projection["distribution_version"],
        "record_raw_sha256": projection["record_raw_sha256"],
        "source_attestation_digest": projection["source_attestation_digest"],
        "installation_mode": projection["installation_mode"],
        "build_attestation_digest": projection["build_attestation_digest"],
        "protected_closure_digest": projection["protected_closure_digest"],
        "command_binding_digest": projection["binding"]["binding_digest"],
        "command_runtime_policy_digest": projection["runtime_policy"]["policy_digest"],
        "correctness_oracle_digest": projection["correctness_oracle"]["oracle_digest"],
        "source_registry_digest": projection["source_registry"]["source_registry_digest"],
        "fixture_digest": projection["fixture_digest"],
        "sample_set_digest": projection["sample_set_digest"],
        "child_raw_sha256": projection["child_raw_sha256"],
    }


def _validate_performance_evidence_document(
    registry: PerformanceBenchmarkRegistryData,
    projection: FrozenMap,
    document: object,
) -> FrozenMap:
    if type(document) is not dict or set(document) != _PERFORMANCE_EVIDENCE_FIELDS:
        raise PerformanceBenchmarkError("performance evidence projection is not exact")
    expected_digest = _self_digest(
        document, "performance-evidence-projection", "projection_digest",
    )
    if (
        document["schema_version"] != "1.0.0"
        or document["evidence_kind"] != "performance-benchmark-evidence-v1"
        or document["profile_id"] != "performance"
        or document["profile_version"] != "1.0.0"
        or type(document["task_revision"]) is not int
        or document["task_revision"] < 0
        or type(document["invalidation_epoch"]) is not int
        or document["invalidation_epoch"] < 0
    ):
        raise PerformanceBenchmarkError("performance task evidence binding is invalid")
    _text(document["task_id"], "performance task ID")
    _text(document["column_id"], "performance column ID")
    _digest(document["snapshot_digest"], "performance snapshot digest")
    graph_pins = document["graph_ref_pins"]
    if type(graph_pins) is not dict or set(graph_pins) != _GRAPH_REF_PIN_FIELDS:
        raise PerformanceBenchmarkError("performance GraphRef pins are not exact")
    for key, value in graph_pins.items():
        _digest(value, key)
    installation = document["installation_pins"]
    current_installation = _current_installation_pins(projection)
    if (
        type(installation) is not dict
        or set(installation) != _INSTALLATION_PIN_FIELDS
        or installation != current_installation
    ):
        raise PerformanceBenchmarkError("performance installation pins changed")
    case = registry.case(registry.case_ids[0])
    if document["benchmark_case_digest"] != case.benchmark_case_digest:
        raise PerformanceBenchmarkError("performance case evidence changed")

    session = document["session_pins"]
    if type(session) is not dict or set(session) != _SESSION_PIN_FIELDS:
        raise PerformanceBenchmarkError("performance session pins are not exact")
    for field in (
        "command_binding_digest", "command_registry_digest",
        "command_runtime_policy_digest", "cwd_identity_digest", "session_digest",
    ):
        _digest(session[field], field)
    _raw(session["executable_raw_sha256"], "performance executable digest")
    current_executable = hashlib.sha256(
        pathlib.Path(sys.executable).resolve(strict=True).read_bytes()
    ).hexdigest()
    session_body = {key: value for key, value in session.items() if key != "session_digest"}
    if (
        session["command_binding_digest"] != projection["binding"]["binding_digest"]
        or session["command_runtime_policy_digest"]
        != projection["runtime_policy"]["policy_digest"]
        or session["executable_raw_sha256"] != current_executable
        or session["session_digest"] != _semantic(
            session_body, "performance-command-session",
        )
    ):
        raise PerformanceBenchmarkError("performance session evidence changed")
    if document["factory_seal_digest"] != _semantic({
        "installation_pins": installation,
        "session_pins": session,
    }, "performance-factory-seal"):
        raise PerformanceBenchmarkError("performance factory evidence seal changed")

    source_history = document["source_history"]
    installed_history = tuple(projection["source_registry"]["transition_history"])
    if type(source_history) is not list or len(source_history) != 3:
        raise PerformanceBenchmarkError("performance source evidence history is not exact")
    previous: str | None = None
    source_digests: list[str] = []
    for generation, (source, identity) in enumerate(
        zip(source_history, installed_history, strict=True), 1,
    ):
        if type(source) is not dict:
            raise PerformanceBenchmarkError("performance source evidence row is malformed")
        source_raw = next(
            row["raw_sha256"] for row in projection["source_registry"]["sources"]
            if row["source_identity"] == identity
        )
        expected_source = {
            "schema_version": "1.0.0",
            "benchmark_case_id": case.benchmark_case_id,
            "source_identity": identity,
            "generation": generation,
            "previous_observation_digest": previous,
            "source_raw_sha256": source_raw,
            "source_history_digest": _semantic(
                {"history": list(installed_history[:generation])},
                "performance-source-history",
            ),
        }
        expected_source["source_observation_digest"] = _semantic(
            expected_source, "performance-source-observation",
        )
        if source != expected_source:
            raise PerformanceBenchmarkError("performance source evidence history changed")
        previous = expected_source["source_observation_digest"]
        source_digests.append(previous)

    sample_sets = document["sample_sets"]
    statistics = document["statistics_observations"]
    if (
        type(sample_sets) is not list
        or type(statistics) is not list
        or len(sample_sets) != 3
        or len(statistics) != 3
    ):
        raise PerformanceBenchmarkError("performance sequence evidence is incomplete")
    policy = next(
        item for item in registry.statistics_policies
        if item.statistics_policy_id == case.statistics_policy_id
    )
    environment_digest: str | None = None
    computed_statistics: list[tuple[int, int, bool, dict[str, object]]] = []
    expected_kinds = ("baseline", "candidate", "rollback")
    for index, (sequence, stats, kind) in enumerate(
        zip(sample_sets, statistics, expected_kinds, strict=True)
    ):
        if type(sequence) is not dict or type(stats) is not dict:
            raise PerformanceBenchmarkError("performance sequence evidence is malformed")
        required_sequence = {
            "sequence_kind", "source_observation_digest", "request_digest",
            "before_environment", "after_environment",
            "warmup_correctness_observations", "samples", "sample_set_observation",
        }
        if set(sequence) != required_sequence or sequence["sequence_kind"] != kind:
            raise PerformanceBenchmarkError("performance sequence evidence kind changed")
        if sequence["source_observation_digest"] != source_digests[index]:
            raise PerformanceBenchmarkError("performance sequence source binding changed")
        _digest(sequence["request_digest"], "performance measurement request digest")
        before = sequence["before_environment"]
        after = sequence["after_environment"]
        if type(before) is not dict or type(after) is not dict or before != after:
            raise PerformanceBenchmarkError("performance sequence environment changed")
        observed_environment = _self_digest(
            before, "performance-environment-observation", "environment_digest",
        )
        if observed_environment != _self_digest(
            after, "performance-environment-observation", "environment_digest",
        ):
            raise PerformanceBenchmarkError("performance environment digest changed")
        if environment_digest is None:
            environment_digest = observed_environment
        elif environment_digest != observed_environment:
            raise PerformanceBenchmarkError("performance environments are incomparable")
        fields = before.get("fingerprint_fields")
        host = capture_performance_environment_inputs(tuple(
            registry.environment_policy["safe_environment_name_allowlist"]
        )).fingerprint_fields
        if type(fields) is not dict or any(fields.get(key) != value for key, value in host.items()):
            raise PerformanceBenchmarkError("performance host environment changed")
        if (
            fields.get("command-binding") != session["command_binding_digest"]
            or fields.get("command-registry") != session["command_registry_digest"]
            or fields.get("command-runtime-policy")
            != session["command_runtime_policy_digest"]
            or fields.get("command-executable") != session["executable_raw_sha256"]
            or fields.get("installed-record") != installation["record_raw_sha256"]
            or fields.get("distribution-root") != installation["distribution_root"]
            or fields.get("distribution-version") != installation["distribution_version"]
            or fields.get("source-attestation")
            != installation["source_attestation_digest"]
        ):
            raise PerformanceBenchmarkError("performance environment pins changed")
        warmups = sequence["warmup_correctness_observations"]
        samples = sequence["samples"]
        sample_set = sequence["sample_set_observation"]
        if (
            type(warmups) is not list
            or len(warmups) != policy.warmup_count
            or type(samples) is not list
            or len(samples) != policy.repetition_count
            or type(sample_set) is not dict
        ):
            raise PerformanceBenchmarkError("performance sample closure changed")
        for correctness in warmups:
            if type(correctness) is not dict:
                raise PerformanceBenchmarkError("performance warmup evidence is malformed")
            _self_digest(
                correctness, "performance-correctness-observation", "correctness_digest",
            )
        correctness_fields = {
            "schema_version", "benchmark_case_id", "iteration_kind",
            "iteration_index", "invocation_digest", "result_digest",
            "expected_correctness_digest", "observed_correctness_digest",
            "correctness_digest",
        }
        for iteration, correctness in enumerate(warmups):
            if (
                set(correctness) != correctness_fields
                or correctness.get("schema_version") != "1.0.0"
                or correctness.get("benchmark_case_id") != case.benchmark_case_id
                or correctness.get("iteration_kind") != "warmup"
                or correctness.get("iteration_index") != iteration
                or correctness.get("expected_correctness_digest")
                != case.expected_correctness_digest
                or correctness.get("observed_correctness_digest")
                != case.expected_correctness_digest
            ):
                raise PerformanceBenchmarkError(
                    "performance warmup correctness changed"
                )
            _digest(correctness.get("invocation_digest"), "invocation digest")
            _digest(correctness.get("result_digest"), "result digest")
        durations: list[int] = []
        for iteration, sample in enumerate(samples):
            if type(sample) is not dict or sample.get("iteration_index") != iteration:
                raise PerformanceBenchmarkError("performance sample order changed")
            _self_digest(sample, "performance-measurement-sample", "sample_digest")
            correctness = sample.get("correctness_observation")
            if type(correctness) is not dict:
                raise PerformanceBenchmarkError("performance sample correctness is missing")
            _self_digest(
                correctness, "performance-correctness-observation", "correctness_digest",
            )
            if (
                set(correctness) != correctness_fields
                or correctness.get("schema_version") != "1.0.0"
                or correctness.get("benchmark_case_id") != case.benchmark_case_id
                or correctness.get("iteration_kind") != "measurement"
                or correctness.get("iteration_index") != iteration
                or correctness.get("expected_correctness_digest")
                != case.expected_correctness_digest
                or correctness.get("observed_correctness_digest")
                != case.expected_correctness_digest
            ):
                raise PerformanceBenchmarkError(
                    "performance measurement correctness changed"
                )
            _digest(correctness.get("invocation_digest"), "invocation digest")
            _digest(correctness.get("result_digest"), "result digest")
            duration = sample.get("duration_ns")
            if type(duration) is not int or duration < 1:
                raise PerformanceBenchmarkError("performance sample duration changed")
            durations.append(duration)
        sample_set_digest = _self_digest(
            sample_set, "performance-sample-set-observation",
            "sample_set_observation_digest",
        )
        if (
            sample_set.get("sequence_kind") != kind
            or sample_set.get("samples") != samples
            or sample_set.get("warmup_correctness_observations") != warmups
            or sample_set.get("before_environment_digest") != observed_environment
            or sample_set.get("after_environment_digest") != observed_environment
        ):
            raise PerformanceBenchmarkError("performance sample-set evidence changed")
        stats_digest = _self_digest(
            stats, "performance-statistics-observation",
            "statistics_observation_digest",
        )
        median, mad, quiet = integer_statistics(tuple(durations), policy)
        noise_left, noise_right = comparison_products(
            mad, median, policy.noise_ceiling_numerator,
            policy.noise_ceiling_denominator,
        )
        if (
            stats.get("sample_set_observation") != sample_set
            or stats.get("ordered_durations_ns") != durations
            or stats.get("sorted_durations_ns") != sorted(durations)
            or stats.get("median_ns") != median
            or stats.get("sorted_deviations_ns")
            != sorted(abs(value - median) for value in durations)
            or stats.get("mad_ns") != mad
            or stats.get("noise_left_product") != noise_left
            or stats.get("noise_right_product") != noise_right
            or stats.get("outcome") != ("quiet" if quiet else "inconclusive-noise")
            or sample_set_digest != sample_set["sample_set_observation_digest"]
            or stats_digest != stats["statistics_observation_digest"]
        ):
            raise PerformanceBenchmarkError("performance statistics evidence changed")
        computed_statistics.append((median, mad, quiet, stats))

    if any(not quiet for _median, _mad, quiet, _stats in computed_statistics):
        raise PerformanceBenchmarkError(
            "performance evidence contains inconclusive noise"
        )

    comparisons = document["comparisons"]
    if type(comparisons) is not list or len(comparisons) != 2:
        raise PerformanceBenchmarkError("performance comparisons are incomplete")
    expected_comparisons = (
        (
            "target-proved", computed_statistics[1][0], computed_statistics[0][0],
            policy.target_ratio_numerator, policy.target_ratio_denominator, None,
        ),
        (
            "baseline-restored", computed_statistics[2][0], computed_statistics[0][0],
            policy.rollback_ratio_numerator, policy.rollback_ratio_denominator,
            computed_statistics[2][3],
        ),
    )
    for comparison, expected in zip(
        comparisons, expected_comparisons, strict=True,
    ):
        outcome, measured, baseline_median, numerator, denominator, rollback_stats = expected
        left, right = comparison_products(
            measured, baseline_median, numerator, denominator,
        )
        if type(comparison) is not dict or set(comparison) != {
            "schema_version", "benchmark_case_id", "registry_digest",
            "baseline_statistics", "candidate_statistics", "rollback_statistics",
            "environment_digest", "target_left_product", "target_right_product",
            "outcome", "performance_observation_digest",
        }:
            raise PerformanceBenchmarkError("performance comparison is malformed")
        _self_digest(
            comparison, "performance-observation", "performance_observation_digest",
        )
        if (
            comparison.get("schema_version") != "1.0.0"
            or comparison.get("benchmark_case_id") != case.benchmark_case_id
            or comparison.get("registry_digest") != registry.registry_digest
            or comparison.get("baseline_statistics") != computed_statistics[0][3]
            or comparison.get("candidate_statistics") != computed_statistics[1][3]
            or comparison.get("rollback_statistics") != rollback_stats
            or comparison.get("environment_digest") != environment_digest
            or comparison.get("target_left_product") != left
            or comparison.get("target_right_product") != right
            or comparison.get("outcome") != outcome
            or left > right
        ):
            raise PerformanceBenchmarkError("performance comparison outcome changed")
    final = document["final_observation"]
    if type(final) is not dict or set(final) != {
        "schema_version", "benchmark_case_id", "target_observation_digest",
        "rollback_observation_digest", "outcome", "final_observation_digest",
    }:
        raise PerformanceBenchmarkError("final performance observation is not exact")
    _self_digest(final, "performance-final-observation", "final_observation_digest")
    if (
        final["schema_version"] != "1.0.0"
        or final["benchmark_case_id"] != case.benchmark_case_id
        or final["target_observation_digest"]
        != comparisons[0]["performance_observation_digest"]
        or final["rollback_observation_digest"]
        != comparisons[1]["performance_observation_digest"]
        or final["outcome"] != "performance-baseline-restored"
    ):
        raise PerformanceBenchmarkError("final performance observation changed")
    if document["environment_observation"] != sample_sets[0]["before_environment"]:
        raise PerformanceBenchmarkError("performance evidence environment changed")
    return freeze(copy.deepcopy(document))


def _environment(
    case: BenchmarkCase,
    projection: FrozenMap,
    environment_policy: FrozenMap,
    launcher: StructuredCommandLauncher,
    host_inputs: PerformanceEnvironmentInputs,
    session: BenchmarkCommandSessionAuthority,
    source_observation: BenchmarkSourceObservationAuthority,
) -> FrozenMap:
    available = dict(host_inputs.fingerprint_fields)
    available.update({
        "command-executable": launcher.executable_raw_sha256,
        "command-binding": projection["binding"]["binding_digest"],
        "command-registry": launcher.command_registry_digest,
        "command-runtime-policy": projection["runtime_policy"]["policy_digest"],
        "fixture": projection["fixture_digest"],
        "installed-distribution": (
            f"{projection['distribution_identity']}:{projection['distribution_root']}"
        ),
        "distribution-root": projection["distribution_root"],
        "distribution-version": projection["distribution_version"],
        "installed-record": projection["record_raw_sha256"],
        "source-attestation": projection["source_attestation_digest"],
        "command-cwd": session.cwd_identity_digest,
        "fixture-root": hashlib.sha256(os.fspath(session.root.root).encode()).hexdigest(),
        "source-history": projection["source_registry"]["source_registry_digest"],
        "build-attestation": projection["build_attestation_digest"],
        "protected-closure": projection["protected_closure_digest"],
    })
    required = tuple(environment_policy["required_fingerprint_field_ids"])
    if any(name not in available for name in required):
        raise PerformanceBenchmarkError("benchmark environment field is unsupported")
    fields = {name: available[name] for name in required}
    if (
        tuple(fields) != required
        or any(type(value) not in (str, int) or value in ("", 0) for value in fields.values())
    ):
        raise PerformanceBenchmarkError("benchmark environment fingerprint is incomplete")
    body = {
        "schema_version": "1.0.0", "benchmark_case_id": case.benchmark_case_id,
        "registry_digest": projection["registry_digest"],
        "environment_policy_digest": environment_policy["environment_policy_digest"],
        "fingerprint_fields": fields,
    }
    body["environment_digest"] = _semantic(
        body, "performance-environment-observation"
    )
    return freeze(body)


class PerformanceBenchmarkObservationFactory:
    __slots__ = (
        "_owner", "_registry_authority", "_session", "_launcher", "_clock_authority",
        "_sequence_ledger", "_comparison_ledger", "_last_clock", "_environment_reader",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("benchmark observation factories are installation-issued")

    @classmethod
    def _issue(
        cls, owner: PerformanceBenchmarkRegistryFactory,
        authority: PerformanceBenchmarkRegistryAuthority,
        session: BenchmarkCommandSessionAuthority,
        clock_authority: PerformanceBenchmarkClockAuthority,
    ) -> "PerformanceBenchmarkObservationFactory":
        factory = object.__new__(cls)
        factory._owner = owner
        factory._registry_authority = authority
        factory._session = session
        factory._launcher = session.launcher
        factory._clock_authority = clock_authority
        factory._sequence_ledger = _IdentityLedger()
        factory._comparison_ledger = _IdentityLedger()
        factory._last_clock = -1
        factory._environment_reader = capture_performance_environment_inputs
        return factory

    def _current(self) -> None:
        if not self._owner._observation_factory_ledger.contains(self):
            raise PerformanceBenchmarkError("benchmark observation factory is foreign")
        self._owner.require_current(self._registry_authority)
        self._owner.require_command_session_current(self._session)
        self._owner.require_clock_current(self._clock_authority)
        StructuredCommandLauncher.require_attested(self._launcher)
        if self._environment_reader is not capture_performance_environment_inputs:
            raise PerformanceBenchmarkError("benchmark environment reader is foreign")

    def _clock_value(self) -> int:
        value = self._clock_authority._reader()
        if type(value) is not int or value <= self._last_clock:
            raise PerformanceBenchmarkError("benchmark monotonic clock regressed")
        self._last_clock = value
        return value

    def measure(
        self,
        *,
        case_id: str,
        sequence_kind: str,
        invocation_document: Mapping[str, object],
        expected: ActionInvocation,
        request_document: Mapping[str, object],
        source_observation: object,
    ) -> BenchmarkSequenceAuthority:
        self._current()
        source = self._owner.require_source_current(source_observation)
        if type(case_id) is not str or type(sequence_kind) is not str:
            raise PerformanceBenchmarkError("benchmark selector is not exact")
        case = self._registry_authority.registry.case(case_id)
        if (
            self._launcher.command_id != case.command_id
            or self._session.command_binding_digest != case.command_binding_digest
            or self._session.command_registry_digest
            != self._launcher.command_registry_digest
            or self._registry_authority.projection["runtime_policy"]["policy_digest"]
            != case.command_runtime_policy_digest
            or type(request_document) is not dict
            or freeze(request_document.get("parameters")) != case.parameter_projection
        ):
            raise PerformanceBenchmarkError("benchmark command binding changed")
        if sequence_kind not in ("baseline", "candidate", "rollback"):
            raise PerformanceBenchmarkError("benchmark sequence kind is invalid")
        source_identity = (
            case.baseline_source_identity if sequence_kind in ("baseline", "rollback")
            else case.candidate_source_identity
        )
        expected_generation = {"baseline": 1, "candidate": 2, "rollback": 3}[sequence_kind]
        if (
            source.source_identity != source_identity
            or source.generation != expected_generation
            or source._session is not self._session
            or self._session.root.current_source_identity() != source.source_identity
        ):
            raise PerformanceBenchmarkError("benchmark source observation does not match sequence")
        policy = next(
            item for item in self._registry_authority.registry.statistics_policies
            if item.statistics_policy_id == case.statistics_policy_id
        )
        before_environment = _environment(
            case, self._registry_authority.projection,
            self._registry_authority.registry.environment_policy, self._launcher,
            self._environment_reader(
                tuple(
                    self._registry_authority.registry.environment_policy[
                        "safe_environment_name_allowlist"
                    ]
                )
            ), self._session, source,
        )
        before_digest = before_environment["environment_digest"]
        durations: list[int] = []
        warmup_correctness: list[FrozenMap] = []
        samples: list[FrozenMap] = []
        total = policy.warmup_count + policy.repetition_count
        root_before = self._session.root.tree_digest()
        for iteration in range(total):
            self._current()
            self._owner.require_clock_current(self._clock_authority)
            start = self._clock_value()
            result = self._launcher.execute(
                invocation_document, expected=expected, request_document=request_document,
            )
            end = self._clock_value()
            self._owner.require_clock_current(self._clock_authority)
            self._current()
            if self._session.root.tree_digest() != root_before:
                raise PerformanceBenchmarkError("benchmark command mutated its private root")
            if (
                type(result) is not CommandExecutionResult
                or result.outcome != "succeeded" or result.failure_class is not None
                or result.reconciliation_required or result.exit_code != 0
                or type(result.output) is not MappingProxyType
                or tuple(result.output) != ("correctness_digest",)
                or result.output["correctness_digest"] != case.expected_correctness_digest
            ):
                raise PerformanceBenchmarkError("benchmark correctness result changed")
            duration = end - start
            if duration < 1:
                raise PerformanceBenchmarkError("benchmark duration is invalid")
            is_warmup = iteration < policy.warmup_count
            iteration_index = iteration if is_warmup else iteration - policy.warmup_count
            correctness_body = {
                "schema_version": "1.0.0",
                "benchmark_case_id": case.benchmark_case_id,
                "iteration_kind": "warmup" if is_warmup else "measurement",
                "iteration_index": iteration_index,
                "invocation_digest": result.invocation_digest,
                "result_digest": result.result_digest,
                "expected_correctness_digest": case.expected_correctness_digest,
                "observed_correctness_digest": result.output["correctness_digest"],
            }
            correctness_body["correctness_digest"] = _semantic(
                correctness_body, "performance-correctness-observation"
            )
            correctness_observation = freeze(correctness_body)
            if is_warmup:
                warmup_correctness.append(correctness_observation)
            else:
                durations.append(duration)
                sample_body = {
                    "schema_version": "1.0.0",
                    "benchmark_case_id": case.benchmark_case_id,
                    "sample_set_id": case.sample_set_id,
                    "iteration_index": iteration_index,
                    "duration_ns": duration,
                    "correctness_observation": thaw(correctness_observation),
                    "environment_digest": before_digest,
                }
                sample_body["sample_digest"] = _semantic(
                    sample_body, "performance-measurement-sample"
                )
                samples.append(freeze(sample_body))
        after_environment = _environment(
            case, self._registry_authority.projection,
            self._registry_authority.registry.environment_policy, self._launcher,
            self._environment_reader(
                tuple(
                    self._registry_authority.registry.environment_policy[
                        "safe_environment_name_allowlist"
                    ]
                )
            ), self._session, source,
        )
        after_digest = after_environment["environment_digest"]
        self._current()
        if before_environment != after_environment or before_digest != after_digest:
            raise PerformanceBenchmarkError("benchmark environment changed")
        median, mad, quiet = integer_statistics(tuple(durations), policy)
        sample_set_body = {
            "schema_version": "1.0.0",
            "benchmark_case_id": case.benchmark_case_id,
            "sample_set_id": case.sample_set_id,
            "sequence_kind": sequence_kind,
            "source_identity": source_identity,
            "before_environment_digest": before_digest,
            "after_environment_digest": after_digest,
            "warmup_correctness_observations": [
                thaw(item) for item in warmup_correctness
            ],
            "samples": [thaw(item) for item in samples],
        }
        sample_set_body["sample_set_observation_digest"] = _semantic(
            sample_set_body, "performance-sample-set-observation"
        )
        sample_set_observation = freeze(sample_set_body)
        ordered = tuple(durations)
        sorted_durations = tuple(sorted(ordered))
        deviations = tuple(sorted(abs(item - median) for item in ordered))
        noise_left, noise_right = comparison_products(
            mad, median, policy.noise_ceiling_numerator,
            policy.noise_ceiling_denominator,
        )
        statistics_body = {
            "schema_version": "1.0.0",
            "benchmark_case_id": case.benchmark_case_id,
            "sample_set_observation": thaw(sample_set_observation),
            "statistics_policy_digest": policy.statistics_policy_digest,
            "ordered_durations_ns": list(ordered),
            "sorted_durations_ns": list(sorted_durations),
            "median_ns": median,
            "sorted_deviations_ns": list(deviations),
            "mad_ns": mad,
            "noise_left_product": noise_left,
            "noise_right_product": noise_right,
            "outcome": "quiet" if quiet else "inconclusive-noise",
        }
        statistics_body["statistics_observation_digest"] = _semantic(
            statistics_body, "performance-statistics-observation"
        )
        statistics_observation = freeze(statistics_body)
        sequence = object.__new__(BenchmarkSequenceAuthority)
        sequence._owner = self
        sequence.case_id = case.benchmark_case_id
        sequence.sequence_kind = sequence_kind
        sequence.source_identity = source_identity
        sequence.environment_digest = before_digest
        sequence.durations_ns = tuple(durations)
        sequence.median_ns = median
        sequence.mad_ns = mad
        sequence.noise_quiet = quiet
        sequence.sample_set_digest = sample_set_observation[
            "sample_set_observation_digest"
        ]
        sequence.before_environment = before_environment
        sequence.after_environment = after_environment
        sequence.warmup_correctness_observations = tuple(warmup_correctness)
        sequence.sample_documents = tuple(samples)
        sequence.sample_set_observation = sample_set_observation
        sequence.statistics_observation = statistics_observation
        sequence.source_observation_digest = source.observation_digest
        sequence.request_digest = _semantic({
            "case_id": case_id, "sequence_kind": sequence_kind,
            "source_observation_digest": source.observation_digest,
            "invocation_digest": expected.invocation_digest,
            "request_digest": request_document.get("request_digest"),
        }, "performance-measurement-request")
        sequence._issued_snapshot = freeze({
            "case_id": sequence.case_id, "sequence_kind": sequence.sequence_kind,
            "source_identity": sequence.source_identity,
            "environment_digest": sequence.environment_digest,
            "durations_ns": list(sequence.durations_ns), "median_ns": sequence.median_ns,
            "mad_ns": sequence.mad_ns, "noise_quiet": sequence.noise_quiet,
            "sample_set_digest": sequence.sample_set_digest,
            "source_observation_digest": sequence.source_observation_digest,
            "request_digest": sequence.request_digest,
            "before_environment": thaw(sequence.before_environment),
            "after_environment": thaw(sequence.after_environment),
            "warmup_correctness_observations": [thaw(item) for item in sequence.warmup_correctness_observations],
            "sample_documents": [thaw(item) for item in sequence.sample_documents],
            "sample_set_observation": thaw(sequence.sample_set_observation),
            "statistics_observation": thaw(sequence.statistics_observation),
        })
        sequence._seal()
        self._sequence_ledger.issue(sequence)
        return sequence

    def require_current(self, sequence: object) -> BenchmarkSequenceAuthority:
        self._current()
        if (
            type(sequence) is not BenchmarkSequenceAuthority
            or sequence._owner is not self
            or not self._sequence_ledger.contains(sequence)
        ):
            raise PerformanceBenchmarkError("benchmark sequence is foreign or stale")
        case = self._registry_authority.registry.case(sequence.case_id)
        policy = next(
            item for item in self._registry_authority.registry.statistics_policies
            if item.statistics_policy_id == case.statistics_policy_id
        )
        median, mad, quiet = integer_statistics(sequence.durations_ns, policy)
        statistics = sequence.statistics_observation
        samples = sequence.sample_documents
        source_matches = tuple(
            item for item in self._owner._source_ledger.values()
            if item.observation_digest == sequence.source_observation_digest
            and item._session is self._session
        )
        if len(source_matches) != 1:
            raise PerformanceBenchmarkError("benchmark sequence source evidence changed")
        source = self._owner.require_source_current(source_matches[0])
        fresh_environment = _environment(
            case, self._registry_authority.projection,
            self._registry_authority.registry.environment_policy, self._launcher,
            self._environment_reader(tuple(
                self._registry_authority.registry.environment_policy[
                    "safe_environment_name_allowlist"
                ]
            )), self._session, source,
        )
        snapshot = freeze({
            "case_id": sequence.case_id, "sequence_kind": sequence.sequence_kind,
            "source_identity": sequence.source_identity,
            "environment_digest": sequence.environment_digest,
            "durations_ns": list(sequence.durations_ns), "median_ns": sequence.median_ns,
            "mad_ns": sequence.mad_ns, "noise_quiet": sequence.noise_quiet,
            "sample_set_digest": sequence.sample_set_digest,
            "source_observation_digest": sequence.source_observation_digest,
            "request_digest": sequence.request_digest,
            "before_environment": thaw(sequence.before_environment),
            "after_environment": thaw(sequence.after_environment),
            "warmup_correctness_observations": [thaw(item) for item in sequence.warmup_correctness_observations],
            "sample_documents": [thaw(item) for item in sequence.sample_documents],
            "sample_set_observation": thaw(sequence.sample_set_observation),
            "statistics_observation": thaw(sequence.statistics_observation),
        })
        if (
            snapshot != sequence._issued_snapshot
            or fresh_environment != sequence.before_environment
            or _self_digest(
                thaw(sequence.before_environment),
                "performance-environment-observation", "environment_digest",
            ) != sequence.environment_digest
            or sequence.before_environment != sequence.after_environment
            or _self_digest(
                thaw(sequence.sample_set_observation),
                "performance-sample-set-observation", "sample_set_observation_digest",
            ) != sequence.sample_set_digest
            or _self_digest(
                thaw(statistics), "performance-statistics-observation",
                "statistics_observation_digest",
            ) != statistics["statistics_observation_digest"]
            or tuple(sample["duration_ns"] for sample in samples) != sequence.durations_ns
            or tuple(sample["iteration_index"] for sample in samples)
            != tuple(range(policy.repetition_count))
            or (median, mad, quiet)
            != (sequence.median_ns, sequence.mad_ns, sequence.noise_quiet)
        ):
            raise PerformanceBenchmarkError("benchmark sequence statistics changed")
        return sequence

    def issue_task_evidence(
        self,
        *,
        task_binding: object,
        source_history: object,
        baseline: object,
        candidate: object,
        rollback: object,
        target: object,
        restored: object,
    ) -> PerformanceBenchmarkEvidenceAuthority:
        """Seal one task-unique A/B/A projection for category assessment."""

        self._current()
        if type(task_binding) is not dict or set(task_binding) != {
            "task_id", "task_revision", "snapshot_digest", "invalidation_epoch",
            "profile_id", "profile_version", "column_id", "graph_ref_pins",
        }:
            raise PerformanceBenchmarkError("performance task binding is not exact")
        if (
            task_binding["profile_id"] != "performance"
            or task_binding["profile_version"] != "1.0.0"
            or type(task_binding["task_revision"]) is not int
            or task_binding["task_revision"] < 0
            or type(task_binding["invalidation_epoch"]) is not int
            or task_binding["invalidation_epoch"] < 0
        ):
            raise PerformanceBenchmarkError("performance task binding changed")
        _text(task_binding["task_id"], "performance task ID")
        _text(task_binding["column_id"], "performance column ID")
        _digest(task_binding["snapshot_digest"], "performance snapshot digest")
        graph_pins = task_binding["graph_ref_pins"]
        if type(graph_pins) is not dict or set(graph_pins) != _GRAPH_REF_PIN_FIELDS:
            raise PerformanceBenchmarkError("performance GraphRef binding is not exact")
        for key, value in graph_pins.items():
            _digest(value, key)
        if type(source_history) is not tuple or len(source_history) != 3:
            raise PerformanceBenchmarkError("performance source authority history is not exact")
        sources = tuple(self._owner.require_source_current(item) for item in source_history)
        sequences = (
            self.require_current(baseline),
            self.require_current(candidate),
            self.require_current(rollback),
        )
        if (
            tuple(item.sequence_kind for item in sequences)
            != ("baseline", "candidate", "rollback")
            or tuple(item.source_observation_digest for item in sequences)
            != tuple(item.observation_digest for item in sources)
        ):
            raise PerformanceBenchmarkError("performance sequence authority chain changed")
        target_value = self.require_comparison_current(target)
        restored_value = self.require_comparison_current(restored)
        if target_value.kind != "target" or restored_value.kind != "rollback":
            raise PerformanceBenchmarkError("performance comparison authority kind changed")
        session_pins = thaw(self._session._issued_snapshot)
        installation_pins = _current_installation_pins(self._registry_authority.projection)
        factory_seal = _semantic({
            "installation_pins": installation_pins,
            "session_pins": session_pins,
        }, "performance-factory-seal")
        sample_sets = []
        statistics = []
        for sequence in sequences:
            sample_sets.append({
                "sequence_kind": sequence.sequence_kind,
                "source_observation_digest": sequence.source_observation_digest,
                "request_digest": sequence.request_digest,
                "before_environment": thaw(sequence.before_environment),
                "after_environment": thaw(sequence.after_environment),
                "warmup_correctness_observations": [
                    thaw(item) for item in sequence.warmup_correctness_observations
                ],
                "samples": [thaw(item) for item in sequence.sample_documents],
                "sample_set_observation": thaw(sequence.sample_set_observation),
            })
            statistics.append(thaw(sequence.statistics_observation))
        comparisons = [
            thaw(target_value.observation), thaw(restored_value.observation),
        ]
        final_observation = {
            "schema_version": "1.0.0",
            "benchmark_case_id": sequences[0].case_id,
            "target_observation_digest": comparisons[0][
                "performance_observation_digest"
            ],
            "rollback_observation_digest": comparisons[1][
                "performance_observation_digest"
            ],
            "outcome": "performance-baseline-restored",
        }
        final_observation["final_observation_digest"] = _semantic(
            final_observation, "performance-final-observation",
        )
        document = {
            "schema_version": "1.0.0",
            "evidence_kind": "performance-benchmark-evidence-v1",
            "task_id": task_binding["task_id"],
            "task_revision": task_binding["task_revision"],
            "snapshot_digest": task_binding["snapshot_digest"],
            "invalidation_epoch": task_binding["invalidation_epoch"],
            "profile_id": task_binding["profile_id"],
            "profile_version": task_binding["profile_version"],
            "column_id": task_binding["column_id"],
            "graph_ref_pins": copy.deepcopy(graph_pins),
            "installation_pins": installation_pins,
            "benchmark_case_digest": self._registry_authority.registry.case(
                sequences[0].case_id
            ).benchmark_case_digest,
            "factory_seal_digest": factory_seal,
            "environment_observation": thaw(sequences[0].before_environment),
            "session_pins": session_pins,
            "source_history": [thaw(item.observation) for item in sources],
            "sample_sets": sample_sets,
            "statistics_observations": statistics,
            "comparisons": comparisons,
            "final_observation": final_observation,
        }
        document["projection_digest"] = _semantic(
            document, "performance-evidence-projection",
        )
        evidence = self._owner._issue_performance_evidence(document)
        return self._owner.require_performance_evidence_current(evidence)

    def compare_target(
        self, baseline: object, candidate: object,
    ) -> BenchmarkComparisonAuthority:
        left = self.require_current(baseline)
        right = self.require_current(candidate)
        if (
            left.sequence_kind != "baseline" or right.sequence_kind != "candidate"
            or left.case_id != right.case_id or left.environment_digest != right.environment_digest
            or not left.noise_quiet or not right.noise_quiet
        ):
            raise PerformanceBenchmarkError("benchmark target inputs are incomparable")
        case = self._registry_authority.registry.case(left.case_id)
        policy = next(item for item in self._registry_authority.registry.statistics_policies if item.statistics_policy_id == case.statistics_policy_id)
        return self._comparison(
            "target", left, right, None, right.median_ns, left.median_ns,
            policy.target_ratio_numerator, policy.target_ratio_denominator,
        )

    def compare_rollback(
        self, baseline: object, candidate: object, restored: object,
    ) -> BenchmarkComparisonAuthority:
        left = self.require_current(baseline)
        middle = self.require_current(candidate)
        right = self.require_current(restored)
        if (
            left.sequence_kind != "baseline"
            or middle.sequence_kind != "candidate"
            or right.sequence_kind != "rollback"
            or len({left.case_id, middle.case_id, right.case_id}) != 1
            or len({left.environment_digest, middle.environment_digest, right.environment_digest}) != 1
            or not left.noise_quiet or not middle.noise_quiet or not right.noise_quiet
        ):
            raise PerformanceBenchmarkError("benchmark rollback inputs are incomparable")
        case = self._registry_authority.registry.case(left.case_id)
        policy = next(item for item in self._registry_authority.registry.statistics_policies if item.statistics_policy_id == case.statistics_policy_id)
        return self._comparison(
            "rollback", left, middle, right, right.median_ns, left.median_ns,
            policy.rollback_ratio_numerator, policy.rollback_ratio_denominator,
        )

    def _comparison(
        self,
        kind: str,
        baseline_sequence: BenchmarkSequenceAuthority,
        candidate_sequence: BenchmarkSequenceAuthority,
        rollback_sequence: BenchmarkSequenceAuthority | None,
        candidate: int,
        baseline: int,
        numerator: int,
        denominator: int,
    ) -> BenchmarkComparisonAuthority:
        comparison = object.__new__(BenchmarkComparisonAuthority)
        comparison._owner = self
        comparison._baseline_sequence = baseline_sequence
        comparison._candidate_sequence = candidate_sequence
        comparison._rollback_sequence = rollback_sequence
        comparison._numerator = numerator
        comparison._denominator = denominator
        comparison.kind = kind
        comparison.left_product, comparison.right_product = comparison_products(
            candidate, baseline, numerator, denominator,
        )
        comparison.passed = comparison.left_product <= comparison.right_product
        observation_body = {
            "schema_version": "1.0.0",
            "benchmark_case_id": baseline_sequence.case_id,
            "registry_digest": self._registry_authority.registry.registry_digest,
            "baseline_statistics": thaw(baseline_sequence.statistics_observation),
            "candidate_statistics": thaw(candidate_sequence.statistics_observation),
            "rollback_statistics": (
                None
                if rollback_sequence is None
                else thaw(rollback_sequence.statistics_observation)
            ),
            "environment_digest": baseline_sequence.environment_digest,
            "target_left_product": comparison.left_product,
            "target_right_product": comparison.right_product,
            "outcome": (
                "target-proved" if comparison.passed and kind == "target"
                else "baseline-restored" if comparison.passed
                else "target-missed"
            ),
        }
        observation_body["performance_observation_digest"] = _semantic(
            observation_body, "performance-observation"
        )
        comparison.observation = freeze(observation_body)
        comparison._issued_snapshot = freeze({
            "kind": comparison.kind, "passed": comparison.passed,
            "left_product": comparison.left_product,
            "right_product": comparison.right_product,
            "observation": thaw(comparison.observation),
        })
        comparison._seal()
        self._comparison_ledger.issue(comparison)
        return comparison

    def require_comparison_current(
        self, comparison: object,
    ) -> BenchmarkComparisonAuthority:
        self._current()
        if type(comparison) is not BenchmarkComparisonAuthority:
            raise PerformanceBenchmarkError("benchmark comparison is foreign or stale")
        baseline = self.require_current(comparison._baseline_sequence)
        candidate = self.require_current(comparison._candidate_sequence)
        rollback = (
            None
            if comparison._rollback_sequence is None
            else self.require_current(comparison._rollback_sequence)
        )
        case = self._registry_authority.registry.case(baseline.case_id)
        policy = next(
            item for item in self._registry_authority.registry.statistics_policies
            if item.statistics_policy_id == case.statistics_policy_id
        )
        expected_numerator = (
            policy.target_ratio_numerator
            if comparison.kind == "target"
            else policy.rollback_ratio_numerator
        )
        expected_denominator = (
            policy.target_ratio_denominator
            if comparison.kind == "target"
            else policy.rollback_ratio_denominator
        )
        measured = candidate.median_ns if comparison.kind == "target" else (
            rollback.median_ns if rollback is not None else -1
        )
        expected_left, expected_right = comparison_products(
            measured, baseline.median_ns, expected_numerator, expected_denominator,
        )
        expected_outcome = (
            "target-proved"
            if expected_left <= expected_right and comparison.kind == "target"
            else "baseline-restored"
            if expected_left <= expected_right and comparison.kind == "rollback"
            else "target-missed"
        )
        if (
            comparison._owner is not self
            or not self._comparison_ledger.contains(comparison)
            or comparison._numerator != expected_numerator
            or comparison._denominator != expected_denominator
            or comparison.left_product != expected_left
            or comparison.right_product != expected_right
            or comparison.observation["baseline_statistics"]
            != baseline.statistics_observation
            or comparison.observation["candidate_statistics"]
            != candidate.statistics_observation
            or comparison.observation["rollback_statistics"]
            != (None if rollback is None else rollback.statistics_observation)
            or comparison.observation["environment_digest"]
            != baseline.environment_digest
            or comparison.observation["outcome"] != expected_outcome
            or _self_digest(
                thaw(comparison.observation), "performance-observation",
                "performance_observation_digest",
            ) != comparison.observation["performance_observation_digest"]
            or comparison._issued_snapshot != freeze({
                "kind": comparison.kind, "passed": comparison.passed,
                "left_product": comparison.left_product,
                "right_product": comparison.right_product,
                "observation": thaw(comparison.observation),
            })
            or comparison.passed
            != (comparison.left_product <= comparison.right_product)
        ):
            raise PerformanceBenchmarkError("benchmark comparison is foreign or stale")
        return comparison
