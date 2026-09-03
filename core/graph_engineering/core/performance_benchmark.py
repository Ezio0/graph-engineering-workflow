"""Closed ADR-0007 benchmark data and exact integer statistics."""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw


SAFE_INTEGER = 9_007_199_254_740_991
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


class PerformanceBenchmarkError(ValueError):
    """A benchmark contract or authority failed closed."""


def _exact(value: object, fields: tuple[str, ...], label: str) -> Mapping[str, object]:
    if type(value) is not dict or tuple(value) != tuple(sorted(fields)):
        raise PerformanceBenchmarkError(f"{label} fields/order are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise PerformanceBenchmarkError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise PerformanceBenchmarkError(f"{label} is not an exact safe integer")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise PerformanceBenchmarkError(f"{label} is not a semantic digest")
    return result


def _raw(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise PerformanceBenchmarkError(f"{label} is not a raw SHA-256")
    return result


def _self_digest(value: Mapping[str, object], name: str, field: str) -> str:
    expected = _digest(value.get(field), field)
    body = thaw(freeze(value))
    if type(body) is not dict:
        raise AssertionError("benchmark document did not thaw")
    del body[field]
    actual = semantic_digest(
        freeze(body),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise PerformanceBenchmarkError(f"{name} self digest changed")
    return expected


@dataclass(frozen=True, slots=True)
class StatisticsPolicy:
    statistics_policy_id: str
    warmup_count: int
    repetition_count: int
    noise_ceiling_numerator: int
    noise_ceiling_denominator: int
    target_ratio_numerator: int
    target_ratio_denominator: int
    rollback_ratio_numerator: int
    rollback_ratio_denominator: int
    statistics_policy_digest: str


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    benchmark_case_id: str
    profile_id: str
    profile_version: str
    command_id: str
    command_binding_digest: str
    command_runtime_policy_digest: str
    parameter_projection: FrozenMap
    fixture_id: str
    fixture_digest: str
    sample_set_id: str
    sample_set_digest: str
    baseline_source_identity: str
    candidate_source_identity: str
    correctness_policy_id: str
    expected_correctness_digest: str
    statistics_policy_id: str
    environment_policy_id: str
    benchmark_case_digest: str


@dataclass(frozen=True, slots=True)
class PerformanceBenchmarkRegistryData:
    registry_id: str
    registry_digest: str
    environment_policy: FrozenMap
    statistics_policies: tuple[StatisticsPolicy, ...]
    benchmark_cases: tuple[BenchmarkCase, ...]
    document: FrozenMap

    @property
    def case_ids(self) -> tuple[str, ...]:
        return tuple(item.benchmark_case_id for item in self.benchmark_cases)

    @property
    def profile_identities(self) -> tuple[str, ...]:
        return tuple(sorted({item.profile_id for item in self.benchmark_cases}))

    def case(self, case_id: str) -> BenchmarkCase:
        if type(case_id) is not str:
            raise PerformanceBenchmarkError("benchmark case ID is not exact")
        matches = tuple(item for item in self.benchmark_cases if item.benchmark_case_id == case_id)
        if len(matches) != 1:
            raise PerformanceBenchmarkError("benchmark case is not installed")
        return matches[0]


_REGISTRY_FIELDS = (
    "schema_version", "registry_id", "environment_policy", "statistics_policies",
    "benchmark_cases", "registry_digest",
)
_ENVIRONMENT_FIELDS = (
    "environment_policy_id", "required_fingerprint_field_ids",
    "safe_environment_name_allowlist", "environment_policy_digest",
)
_STATISTICS_FIELDS = (
    "statistics_policy_id", "warmup_count", "repetition_count",
    "noise_ceiling_numerator", "noise_ceiling_denominator",
    "target_ratio_numerator", "target_ratio_denominator",
    "rollback_ratio_numerator", "rollback_ratio_denominator",
    "statistics_policy_digest",
)
_CASE_FIELDS = (
    "schema_version", "benchmark_case_id", "profile_id", "profile_version", "command_id",
    "command_binding_digest", "command_runtime_policy_digest", "parameter_projection",
    "fixture_id", "fixture_digest", "sample_set_id", "sample_set_digest",
    "baseline_source_identity", "candidate_source_identity", "correctness_policy_id",
    "expected_correctness_digest", "statistics_policy_id", "environment_policy_id",
    "benchmark_case_digest",
)


def _ordered_text(values: object, label: str) -> tuple[str, ...]:
    if type(values) is not list or not values:
        raise PerformanceBenchmarkError(f"{label} is empty")
    result = tuple(_text(value, label) for value in values)
    if result != tuple(sorted(set(result))):
        raise PerformanceBenchmarkError(f"{label} is not canonical and unique")
    return result


def parse_performance_benchmark_registry(
    value: object,
    *,
    maximum_repetition_count: int = SAFE_INTEGER,
    maximum_warmup_count: int = SAFE_INTEGER,
) -> PerformanceBenchmarkRegistryData:
    maximum_repetition_count = _integer(
        maximum_repetition_count, "maximum repetition count", minimum=3,
    )
    maximum_warmup_count = _integer(
        maximum_warmup_count, "maximum warmup count",
    )
    registry = _exact(value, _REGISTRY_FIELDS, "performance benchmark registry")
    if registry["schema_version"] != "1.0.0":
        raise PerformanceBenchmarkError("performance benchmark registry version changed")
    environment = _exact(
        registry["environment_policy"], _ENVIRONMENT_FIELDS, "environment policy"
    )
    required = _ordered_text(
        environment["required_fingerprint_field_ids"], "fingerprint fields"
    )
    safe_names = _ordered_text(
        environment["safe_environment_name_allowlist"], "safe environment names"
    )
    if set(required).intersection(safe_names):
        raise PerformanceBenchmarkError("environment policy namespaces overlap")
    _text(environment["environment_policy_id"], "environment policy ID")
    _self_digest(environment, "performance-environment-policy", "environment_policy_digest")
    raw_policies = registry["statistics_policies"]
    if type(raw_policies) is not list or not raw_policies:
        raise PerformanceBenchmarkError("statistics policies are empty")
    policies: list[StatisticsPolicy] = []
    for value_policy in raw_policies:
        row = _exact(value_policy, _STATISTICS_FIELDS, "statistics policy")
        warmup = _integer(row["warmup_count"], "warmup count")
        repetitions = _integer(row["repetition_count"], "repetition count", minimum=3)
        if warmup > maximum_warmup_count:
            raise PerformanceBenchmarkError("warmup count exceeds the installed bound")
        if repetitions % 2 != 1 or repetitions > maximum_repetition_count:
            raise PerformanceBenchmarkError("repetition count is not odd and bounded")
        ratios = tuple(
            _integer(row[field], field, minimum=1)
            for field in _STATISTICS_FIELDS[3:9]
        )
        policies.append(StatisticsPolicy(
            _text(row["statistics_policy_id"], "statistics policy ID"), warmup, repetitions,
            *ratios, _self_digest(row, "performance-statistics-policy", "statistics_policy_digest"),
        ))
    policy_ids = tuple(item.statistics_policy_id for item in policies)
    if policy_ids != tuple(sorted(set(policy_ids))):
        raise PerformanceBenchmarkError("statistics policies are not canonical")
    raw_cases = registry["benchmark_cases"]
    if type(raw_cases) is not list or not raw_cases:
        raise PerformanceBenchmarkError("benchmark cases are empty")
    cases: list[BenchmarkCase] = []
    for value_case in raw_cases:
        row = _exact(value_case, _CASE_FIELDS, "benchmark case")
        if row["schema_version"] != "1.0.0":
            raise PerformanceBenchmarkError("benchmark case version changed")
        profile_id = _text(row["profile_id"], "profile ID")
        profile_version = _text(row["profile_version"], "profile version")
        projection = row["parameter_projection"]
        if type(projection) is not dict or not projection or any(
            type(key) is not str or type(item) is not str for key, item in projection.items()
        ) or tuple(projection) != tuple(sorted(projection)):
            raise PerformanceBenchmarkError("benchmark parameter projection is not exact")
        policy_id = _text(row["statistics_policy_id"], "statistics policy ID")
        environment_id = _text(row["environment_policy_id"], "environment policy ID")
        if policy_id not in policy_ids or environment_id != environment["environment_policy_id"]:
            raise PerformanceBenchmarkError("benchmark policy binding is not installed")
        cases.append(BenchmarkCase(
            _text(row["benchmark_case_id"], "benchmark case ID"),
            profile_id, profile_version, _text(row["command_id"], "command ID"),
            _digest(row["command_binding_digest"], "command binding digest"),
            _digest(row["command_runtime_policy_digest"], "command runtime policy digest"),
            freeze(projection), _text(row["fixture_id"], "fixture ID"),
            _digest(row["fixture_digest"], "fixture digest"),
            _text(row["sample_set_id"], "sample set ID"),
            _digest(row["sample_set_digest"], "sample set digest"),
            _text(row["baseline_source_identity"], "baseline source identity"),
            _text(row["candidate_source_identity"], "candidate source identity"),
            _text(row["correctness_policy_id"], "correctness policy ID"),
            _digest(row["expected_correctness_digest"], "correctness digest"),
            policy_id, environment_id,
            _self_digest(row, "performance-benchmark-case", "benchmark_case_digest"),
        ))
    case_ids = tuple(item.benchmark_case_id for item in cases)
    if case_ids != tuple(sorted(set(case_ids))):
        raise PerformanceBenchmarkError("benchmark cases are not canonical")
    digest = _self_digest(registry, "performance-benchmark-registry", "registry_digest")
    return PerformanceBenchmarkRegistryData(
        _text(registry["registry_id"], "benchmark registry ID"), digest,
        freeze(environment), tuple(policies), tuple(cases), freeze(registry),
    )


def integer_statistics(
    samples: Sequence[object], policy: StatisticsPolicy,
) -> tuple[int, int, bool]:
    if type(policy) is not StatisticsPolicy or type(samples) not in (tuple, list):
        raise PerformanceBenchmarkError("statistics inputs are not exact")
    if len(samples) != policy.repetition_count:
        raise PerformanceBenchmarkError("sample count changed")
    values = tuple(_integer(item, "duration", minimum=1) for item in samples)
    ordered = tuple(sorted(values))
    median = ordered[len(ordered) // 2]
    deviations = tuple(sorted(abs(value - median) for value in values))
    mad = deviations[len(deviations) // 2]
    quiet = ratio_within(
        mad, median, policy.noise_ceiling_numerator, policy.noise_ceiling_denominator,
    )
    return median, mad, quiet


def ratio_within(
    candidate: object, baseline: object, numerator: object, denominator: object,
) -> bool:
    left, right = comparison_products(candidate, baseline, numerator, denominator)
    return left <= right


def comparison_products(
    candidate: object, baseline: object, numerator: object, denominator: object,
) -> tuple[int, int]:
    """Return the two exact bounded cross-products used by a comparison."""

    left = _integer(candidate, "candidate", minimum=0)
    right = _integer(baseline, "baseline", minimum=1)
    top = _integer(numerator, "ratio numerator", minimum=1)
    bottom = _integer(denominator, "ratio denominator", minimum=1)
    left_product = left * bottom
    right_product = right * top
    if left_product > SAFE_INTEGER or right_product > SAFE_INTEGER:
        raise PerformanceBenchmarkError("benchmark comparison product is not a safe integer")
    return left_product, right_product


def raw_sha256(value: object, label: str = "raw digest") -> str:
    return _raw(value, label)
