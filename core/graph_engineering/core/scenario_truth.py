"""Closed, profile-neutral ADR-0008 scenario-truth contracts.

All scenario meanings and fixture values are supplied by installed data.  This
module only implements exact document, digest, ordered-transition, and safe
integer validation.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.canonical import canonical_bytes


SAFE_INTEGER = 9_007_199_254_740_991
SCENARIO_TRUTH_SCHEMA_IDS = tuple(sorted({
    f"urn:gew:schema:{name}{suffix}:{version}"
    for name, version in (
        ("scenario-truth-policy-registry", "1.0.0"),
        ("scenario-truth-fixture-registry", "1.0.0"),
        ("scenario-truth-observation", "1.0.0"),
        ("scenario-truth-installation-bootstrap", "1.0.0"),
        ("category-completion-assessment", "1.3.0"),
    )
    for suffix in ("", "-input")
}))


class ScenarioTruthError(ValueError):
    """An installed scenario contract or consumer-local authority failed closed."""


def _exact(value: object, fields: tuple[str, ...], label: str) -> Mapping[str, object]:
    if type(value) is not dict or tuple(value) != fields:
        raise ScenarioTruthError(f"{label} fields/order are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise ScenarioTruthError(f"{label} is not exact text")
    return value


def _data_text(value: object, label: str) -> str:
    if type(value) is not str or not value or not value.isascii() or "\x00" in value:
        raise ScenarioTruthError(f"{label} is not exact data text")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise ScenarioTruthError(f"{label} is not an exact safe integer")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise ScenarioTruthError(f"{label} is not a semantic digest")
    return result


def _semantic(value: Mapping[str, object], name: str, version: str = "1.0.0") -> str:
    return semantic_digest(
        freeze(value),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:{version}",
        schema_id=f"urn:gew:schema:{name}-input:{version}",
    )


def _self_digest(
    value: Mapping[str, object], name: str, field: str, version: str = "1.0.0",
) -> str:
    expected = _digest(value.get(field), field)
    body = thaw(freeze(value))
    if type(body) is not dict:
        raise AssertionError("scenario contract did not thaw")
    del body[field]
    if not hmac.compare_digest(expected, _semantic(body, name, version)):
        raise ScenarioTruthError(f"{name} self digest changed")
    return expected


def _ordered_text(values: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if type(values) is not list or (not values and not allow_empty):
        raise ScenarioTruthError(f"{label} is not an exact list")
    result = tuple(_text(item, label) for item in values)
    if len(result) != len(set(result)):
        raise ScenarioTruthError(f"{label} is not unique")
    return result


def evaluate_scenario_assertions(
    expectations: object,
    fact_values: object,
) -> tuple[dict[str, object], ...]:
    """Compare exact, ordered config expectations with observed boolean facts."""

    if type(expectations) not in {list, tuple} or not expectations:
        raise ScenarioTruthError("scenario assertion expectations are absent")
    if type(fact_values) is not dict:
        raise ScenarioTruthError("scenario assertion facts are not exact")
    expected_fact_ids: list[str] = []
    assertion_ids: list[str] = []
    for value in expectations:
        if not isinstance(value, Mapping) or tuple(value) != _ASSERTION_FIELDS:
            raise ScenarioTruthError("scenario assertion expectation is not exact")
        assertion_id = _text(value["assertion_id"], "assertion ID")
        _text(value["kind"], "assertion kind")
        if type(value["expected"]) is not bool or value["expected"] is not True:
            raise ScenarioTruthError("scenario assertion expectation is not successful")
        assertion_ids.append(assertion_id)
        expected_fact_ids.append("fact:" + assertion_id)
    if (
        tuple(assertion_ids) != tuple(sorted(set(assertion_ids)))
        or tuple(fact_values) != tuple(expected_fact_ids)
        or any(type(value) is not bool for value in fact_values.values())
    ):
        raise ScenarioTruthError("scenario assertion fact closure is not exact")
    results: list[dict[str, object]] = []
    for expectation, fact_id in zip(expectations, expected_fact_ids, strict=True):
        actual = fact_values[fact_id]
        if actual is not expectation["expected"]:
            raise ScenarioTruthError("scenario assertion did not match observed fact")
        results.append({
            "assertion_id": expectation["assertion_id"],
            "passed": True,
        })
    return tuple(results)


_POLICY_FIELDS = (
    "schema_version", "registry_id", "testability", "profiles", "scenarios",
    "registry_digest",
)
_TESTABILITY_FIELDS = (
    "cumulative_runtime_limit_seconds", "heartbeat_interval_seconds",
)
_SUBJECT_FIELDS = ("profile_id", "profile_version")
_POLICY_ROW_FIELDS = (
    "profile_id", "profile_version", "scenario_id", "fixture_id", "fixture_digest",
    "required_target_roles", "ordered_phase_ids", "required_fact_ids",
    "success_outcome", "blocked_outcome", "owner_route_policy",
    "branch_isolation_policy", "mutation_budget", "rollback_required",
    "compensation_required", "row_digest",
)
_FIXTURE_FIELDS = (
    "schema_version", "registry_id", "fixtures", "registry_digest",
)
_FIXTURE_ROW_FIELDS = (
    "fixture_id", "profile_id", "scenario_id", "target_roles", "phase_expectations",
    "assertion_expectations", "rollback_or_compensation", "fixture_digest",
)
_TARGET_FIELDS = (
    "role_id", "path_id", "baseline_state_id", "baseline_value",
    "candidate_state_id", "candidate_value", "rollback_state_id", "rollback_value",
)
_PHASE_FIELDS = ("phase_id", "from_state_id", "to_state_id")
_ASSERTION_FIELDS = ("assertion_id", "kind", "expected")
_ROLLBACK_FIELDS = ("kind", "expected_state_id", "required")


@dataclass(frozen=True, slots=True)
class ScenarioTruthRegistry:
    policy_document: FrozenMap
    fixture_document: FrozenMap
    registry_digest: str
    testability: FrozenMap
    profile_ids: tuple[str, ...]
    scenario_pairs: tuple[tuple[str, str], ...]

    def policy_row(self, profile_id: str, scenario_id: str) -> FrozenMap:
        rows = self.policy_document["scenarios"]
        matches = tuple(
            row for row in rows
            if row["profile_id"] == profile_id and row["scenario_id"] == scenario_id
        )
        if len(matches) != 1:
            raise ScenarioTruthError("scenario policy row is not installed")
        return matches[0]

    def fixture_row(self, fixture_id: str) -> FrozenMap:
        rows = self.fixture_document["fixtures"]
        matches = tuple(row for row in rows if row["fixture_id"] == fixture_id)
        if len(matches) != 1:
            raise ScenarioTruthError("scenario fixture row is not installed")
        return matches[0]


def parse_scenario_truth_registries(
    policy_value: object, fixture_value: object,
) -> ScenarioTruthRegistry:
    policy = _exact(policy_value, _POLICY_FIELDS, "scenario policy registry")
    fixture = _exact(fixture_value, _FIXTURE_FIELDS, "scenario fixture registry")
    if policy["schema_version"] != "1.0.0" or fixture["schema_version"] != "1.0.0":
        raise ScenarioTruthError("scenario registry version changed")
    _text(policy["registry_id"], "scenario policy registry ID")
    _text(fixture["registry_id"], "scenario fixture registry ID")
    testability = _exact(
        policy["testability"], _TESTABILITY_FIELDS, "scenario testability",
    )
    cumulative_runtime_limit_seconds = _integer(
        testability["cumulative_runtime_limit_seconds"],
        "cumulative runtime limit seconds",
        minimum=1,
    )
    heartbeat_interval_seconds = _integer(
        testability["heartbeat_interval_seconds"],
        "heartbeat interval seconds",
        minimum=1,
    )
    if heartbeat_interval_seconds >= cumulative_runtime_limit_seconds:
        raise ScenarioTruthError(
            "scenario heartbeat interval must precede its runtime limit"
        )
    raw_profiles = policy["profiles"]
    if type(raw_profiles) is not list or not raw_profiles:
        raise ScenarioTruthError("scenario profiles are empty")
    profiles: list[tuple[str, str]] = []
    for value in raw_profiles:
        row = _exact(value, _SUBJECT_FIELDS, "scenario profile")
        profiles.append((
            _text(row["profile_id"], "scenario profile ID"),
            _text(row["profile_version"], "scenario profile version"),
        ))
    if tuple(profiles) != tuple(sorted(set(profiles))):
        raise ScenarioTruthError("scenario profiles are not canonical")
    raw_policy_rows = policy["scenarios"]
    if type(raw_policy_rows) is not list or not raw_policy_rows:
        raise ScenarioTruthError("scenario policy rows are empty")
    policy_pairs: list[tuple[str, str]] = []
    fixture_ids: list[str] = []
    for value in raw_policy_rows:
        row = _exact(value, _POLICY_ROW_FIELDS, "scenario policy row")
        profile = (
            _text(row["profile_id"], "scenario policy profile"),
            _text(row["profile_version"], "scenario policy profile version"),
        )
        if profile not in profiles:
            raise ScenarioTruthError("scenario policy profile is not installed")
        scenario_id = _text(row["scenario_id"], "scenario ID")
        fixture_id = _text(row["fixture_id"], "fixture ID")
        _digest(row["fixture_digest"], "fixture digest")
        roles = _ordered_text(row["required_target_roles"], "target roles")
        phases = _ordered_text(row["ordered_phase_ids"], "phase IDs")
        _ordered_text(row["required_fact_ids"], "fact IDs")
        _text(row["success_outcome"], "success outcome")
        if row["blocked_outcome"] is not None:
            _text(row["blocked_outcome"], "blocked outcome")
        _text(row["owner_route_policy"], "owner route policy")
        _text(row["branch_isolation_policy"], "branch isolation policy")
        budget = _integer(row["mutation_budget"], "mutation budget", minimum=1)
        if type(row["rollback_required"]) is not bool or type(row["compensation_required"]) is not bool:
            raise ScenarioTruthError("scenario rollback flags are not boolean")
        if budget < len(roles) or not phases:
            raise ScenarioTruthError("scenario mutation budget is incomplete")
        _self_digest(row, "scenario-truth-policy-row", "row_digest")
        policy_pairs.append((profile[0], scenario_id))
        fixture_ids.append(fixture_id)
    if tuple(policy_pairs) != tuple(sorted(set(policy_pairs))):
        raise ScenarioTruthError("scenario policy pairs are not canonical")
    if len(fixture_ids) != len(set(fixture_ids)):
        raise ScenarioTruthError("scenario fixture bindings are not unique")
    raw_fixture_rows = fixture["fixtures"]
    if type(raw_fixture_rows) is not list or not raw_fixture_rows:
        raise ScenarioTruthError("scenario fixture rows are empty")
    fixture_pairs: list[tuple[str, str]] = []
    installed_fixture_ids: list[str] = []
    fixture_digests: dict[str, str] = {}
    fixture_fact_ids: dict[str, tuple[str, ...]] = {}
    for value in raw_fixture_rows:
        fields = _FIXTURE_ROW_FIELDS
        if isinstance(value, Mapping) and "rejection_attack_ids" in value:
            fields = (*fields[:-1], "rejection_attack_ids", fields[-1])
        row = _exact(value, fields, "scenario fixture row")
        if "rejection_attack_ids" in row:
            _ordered_text(row["rejection_attack_ids"], "scenario rejection attacks")
        fixture_id = _text(row["fixture_id"], "scenario fixture ID")
        pair = (
            _text(row["profile_id"], "scenario fixture profile"),
            _text(row["scenario_id"], "scenario fixture scenario"),
        )
        targets = row["target_roles"]
        if type(targets) is not list or not targets:
            raise ScenarioTruthError("scenario fixture targets are empty")
        target_roles: list[str] = []
        path_ids: list[str] = []
        for target_value in targets:
            target = _exact(target_value, _TARGET_FIELDS, "scenario target role")
            target_roles.append(_text(target["role_id"], "target role ID"))
            path_ids.append(_text(target["path_id"], "target path ID"))
            for field in (
                "baseline_state_id", "candidate_state_id", "rollback_state_id",
            ):
                _text(target[field], f"target {field}")
            _data_text(target["baseline_value"], "target baseline_value")
            _data_text(target["candidate_value"], "target candidate_value")
            _data_text(target["rollback_value"], "target rollback_value")
        if tuple(target_roles) != tuple(sorted(set(target_roles))) or len(path_ids) != len(set(path_ids)):
            raise ScenarioTruthError("scenario target roles are not canonical and distinct")
        phases = row["phase_expectations"]
        if type(phases) is not list or not phases:
            raise ScenarioTruthError("scenario fixture phases are empty")
        phase_ids: list[str] = []
        for phase_value in phases:
            phase = _exact(phase_value, _PHASE_FIELDS, "scenario phase")
            phase_ids.append(_text(phase["phase_id"], "phase ID"))
            _text(phase["from_state_id"], "phase from state")
            _text(phase["to_state_id"], "phase to state")
        if len(phase_ids) != len(set(phase_ids)):
            raise ScenarioTruthError("scenario phases are not unique")
        assertions = row["assertion_expectations"]
        if type(assertions) is not list or not assertions:
            raise ScenarioTruthError("scenario fixture assertions are empty")
        assertion_ids: list[str] = []
        for assertion_value in assertions:
            assertion = _exact(assertion_value, _ASSERTION_FIELDS, "scenario assertion")
            assertion_id = _text(assertion["assertion_id"], "assertion ID")
            kind = _text(assertion["kind"], "assertion kind")
            if kind not in {"acceptance", "fresh-target", "regression"}:
                raise ScenarioTruthError("scenario assertion kind is unsupported")
            matching_roles = tuple(
                role for role in target_roles
                if assertion_id == kind + ":" + role
            )
            if len(matching_roles) != 1:
                raise ScenarioTruthError("scenario assertion role binding is not exact")
            if type(assertion["expected"]) is not bool or assertion["expected"] is not True:
                raise ScenarioTruthError("scenario assertion expectation is not successful")
            assertion_ids.append(assertion_id)
        if tuple(assertion_ids) != tuple(sorted(set(assertion_ids))):
            raise ScenarioTruthError("scenario assertions are not canonical")
        rollback = _exact(
            row["rollback_or_compensation"], _ROLLBACK_FIELDS,
            "scenario rollback or compensation",
        )
        _text(rollback["kind"], "rollback kind")
        _text(rollback["expected_state_id"], "rollback expected state")
        if type(rollback["required"]) is not bool:
            raise ScenarioTruthError("rollback requirement is not boolean")
        fixture_digest = _self_digest(
            row, "scenario-truth-fixture-row", "fixture_digest"
        )
        installed_fixture_ids.append(fixture_id)
        fixture_pairs.append(pair)
        fixture_digests[fixture_id] = fixture_digest
        fixture_fact_ids[fixture_id] = tuple(
            "fact:" + assertion_id for assertion_id in assertion_ids
        )
    if tuple(fixture_pairs) != tuple(policy_pairs) or tuple(installed_fixture_ids) != tuple(fixture_ids):
        raise ScenarioTruthError("scenario policy and fixture sets differ")
    for row in raw_policy_rows:
        if not hmac.compare_digest(
            str(row["fixture_digest"]), fixture_digests[str(row["fixture_id"])],
        ):
            raise ScenarioTruthError("scenario policy fixture digest changed")
        fixture_row = next(
            item for item in raw_fixture_rows if item["fixture_id"] == row["fixture_id"]
        )
        if tuple(row["required_target_roles"]) != tuple(
            target["role_id"] for target in fixture_row["target_roles"]
        ) or tuple(row["ordered_phase_ids"]) != tuple(
            phase["phase_id"] for phase in fixture_row["phase_expectations"]
        ) or tuple(row["required_fact_ids"]) != fixture_fact_ids[str(row["fixture_id"])]:
            raise ScenarioTruthError("scenario policy and fixture shape differ")
    policy_digest = _self_digest(
        policy, "scenario-truth-policy-registry", "registry_digest"
    )
    fixture_digest = _self_digest(
        fixture, "scenario-truth-fixture-registry", "registry_digest"
    )
    return ScenarioTruthRegistry(
        policy_document=freeze(policy),
        fixture_document=freeze(fixture),
        registry_digest=_semantic(
            {"policy_registry_digest": policy_digest, "fixture_registry_digest": fixture_digest},
            "scenario-truth-registry-projection",
        ),
        testability=freeze(testability),
        profile_ids=tuple(item[0] for item in profiles),
        scenario_pairs=tuple(policy_pairs),
    )


_OBSERVATION_FIELDS = (
    "schema_version", "evidence_kind", "task_id", "task_revision",
    "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
    "scenario_id", "graph_ref_pins", "installation_pins", "policy_row",
    "fixture_row", "branch_binding", "before_targets", "ordered_transitions",
    "after_targets", "assertion_results", "rollback_or_compensation",
    "owner_route", "scenario_outcome", "observation_digest",
)


@dataclass(frozen=True, slots=True, eq=False, init=False)
class ScenarioTruthObservation:
    schema_version: str
    evidence_kind: str
    task_id: str
    task_revision: int
    snapshot_digest: str
    invalidation_epoch: int
    profile_id: str
    profile_version: str
    scenario_id: str
    graph_ref_pins: FrozenMap
    installation_pins: FrozenMap
    policy_row: FrozenMap
    fixture_row: FrozenMap
    branch_binding: FrozenMap
    before_targets: tuple[FrozenMap, ...]
    ordered_transitions: tuple[FrozenMap, ...]
    after_targets: tuple[FrozenMap, ...]
    assertion_results: tuple[FrozenMap, ...]
    rollback_or_compensation: FrozenMap
    owner_route: str
    scenario_outcome: str
    observation_digest: str
    _authority: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ScenarioTruthObservation is factory-issued")

    def body(self) -> dict[str, object]:
        result: dict[str, object] = {}
        for field in _OBSERVATION_FIELDS[:-1]:
            result[field] = thaw(getattr(self, field))
        return result

    def to_dict(self) -> dict[str, object]:
        result = self.body()
        result["observation_digest"] = self.observation_digest
        return result

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.to_dict())


def issue_scenario_truth_observation(
    body: Mapping[str, object], *, authority: object,
) -> ScenarioTruthObservation:
    _exact(dict(body), _OBSERVATION_FIELDS[:-1], "scenario truth observation body")
    result = object.__new__(ScenarioTruthObservation)
    for field, value in body.items():
        if field in {
            "graph_ref_pins", "installation_pins", "policy_row", "fixture_row",
            "branch_binding", "rollback_or_compensation",
        }:
            value = freeze(value)
        elif field in {
            "before_targets", "ordered_transitions", "after_targets", "assertion_results",
        }:
            value = tuple(freeze(item) for item in value)
        object.__setattr__(result, field, value)
    digest = _semantic(dict(body), "scenario-truth-observation")
    object.__setattr__(result, "observation_digest", digest)
    object.__setattr__(result, "_authority", authority)
    return result


def scenario_observation_object_digest(body: bytes) -> str:
    if type(body) is not bytes:
        raise ScenarioTruthError("scenario observation object must be exact bytes")
    return "sha256:" + hashlib.sha256(body).hexdigest()


__all__ = (
    "SCENARIO_TRUTH_SCHEMA_IDS",
    "ScenarioTruthError",
    "ScenarioTruthObservation",
    "ScenarioTruthRegistry",
    "evaluate_scenario_assertions",
    "issue_scenario_truth_observation",
    "parse_scenario_truth_registries",
    "scenario_observation_object_digest",
)
