"""Digest-bound task Profiles, risk overlays, materialization, and coverage gates."""

from __future__ import annotations

import hmac
import hashlib
import json
import os
import pathlib
import re
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import ResourceProfile
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.graph.budget import LoopBudgetRegistry
from graph_engineering.core.migration_rehearsal import MIGRATION_REHEARSAL_SCHEMA_IDS
from graph_engineering.core.performance_benchmark import PERFORMANCE_BENCHMARK_SCHEMA_IDS
from graph_engineering.core.scenario_truth import SCENARIO_TRUTH_SCHEMA_IDS


_RAW_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OBJECT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
PROFILE_DOMAIN_SCHEMA_IDS = tuple(sorted({
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.2.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.2.0",
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
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.0.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.0.0",
    "urn:gew:schema:dependency-advisory-record-input:1.0.0",
    "urn:gew:schema:dependency-advisory-record:1.0.0",
    "urn:gew:schema:dependency-advisory-registry-input:1.0.0",
    "urn:gew:schema:dependency-advisory-registry:1.0.0",
    "urn:gew:schema:dependency-advisory-source-record-input:1.0.0",
    "urn:gew:schema:dependency-advisory-source-record:1.0.0",
    "urn:gew:schema:dependency-advisory-status-high-water-input:1.0.0",
    "urn:gew:schema:dependency-advisory-status-high-water:1.0.0",
    "urn:gew:schema:dependency-applicability-observation-input:1.0.0",
    "urn:gew:schema:dependency-applicability-observation:1.0.0",
    "urn:gew:schema:dependency-fixed-closure-input:1.0.0",
    "urn:gew:schema:dependency-fixed-closure:1.0.0",
    "urn:gew:schema:dependency-offline-closure-observation-input:1.0.0",
    "urn:gew:schema:dependency-offline-closure-observation:1.0.0",
    "urn:gew:schema:dependency-residual-exposure-observation-input:1.0.0",
    "urn:gew:schema:dependency-residual-exposure-observation:1.0.0",
    "urn:gew:schema:dependency-security-observation-input:1.0.0",
    "urn:gew:schema:dependency-security-observation:1.0.0",
    "urn:gew:schema:approved-profile-body-input:1.0.0",
    "urn:gew:schema:approved-profile-definition-body-input:1.0.0",
    "urn:gew:schema:approved-profile-identity-registry-input:1.0.0",
    "urn:gew:schema:approved-profile-identity-registry:1.0.0",
    "urn:gew:schema:approved-risk-overlay-body-input:1.0.0",
    "urn:gew:schema:category-completion-assessment-input:1.0.0",
    "urn:gew:schema:category-completion-assessment:1.0.0",
    "urn:gew:schema:category-completion-assessment-input:1.1.0",
    "urn:gew:schema:category-completion-assessment:1.1.0",
    "urn:gew:schema:category-completion-assessment-input:1.2.0",
    "urn:gew:schema:category-completion-assessment:1.2.0",
    "urn:gew:schema:category-execution-policy-input:1.0.0",
    "urn:gew:schema:category-execution-policy:1.0.0",
    "urn:gew:schema:category-execution-state-input:1.0.0",
    "urn:gew:schema:category-execution-state:1.0.0",
    "urn:gew:schema:category-rollback-assessment-input:1.0.0",
    "urn:gew:schema:category-rollback-assessment:1.0.0",
    "urn:gew:schema:category-target-observation-input:1.0.0",
    "urn:gew:schema:category-target-observation:1.0.0",
    "urn:gew:schema:coverage-record-input:1.0.0",
    "urn:gew:schema:coverage-record:1.0.0",
    "urn:gew:schema:evidence-observation-input:1.0.0",
    "urn:gew:schema:materialization-record-input:1.0.0",
    "urn:gew:schema:materialization-record:1.0.0",
    "urn:gew:schema:profile-coverage-assessment-reference:1.0.0",
    "urn:gew:schema:profile-coverage-execution-plan-input:1.0.0",
    "urn:gew:schema:profile-coverage-execution-record:1.0.0",
    "urn:gew:schema:profile-coverage-observation:1.0.0",
    "urn:gew:schema:profile-coverage-oracle-input:1.0.0",
    "urn:gew:schema:profile-coverage-oracle-input:1.1.0",
    "urn:gew:schema:profile-coverage-plan-selector:1.0.0",
    "urn:gew:schema:profile-coverage-policy-input:1.0.0",
    "urn:gew:schema:profile-coverage-policy:1.0.0",
    "urn:gew:schema:profile-coverage-request:1.0.0",
    "urn:gew:schema:profile-coverage-task-state:1.0.0",
    "urn:gew:schema:profile-definition-input:1.0.0",
    "urn:gew:schema:profile-definition:1.0.0",
    "urn:gew:schema:profile-evidence-observation-registry-input:1.0.0",
    "urn:gew:schema:profile-evidence-observation-registry:1.0.0",
    "urn:gew:schema:profile-materialization-input:1.0.0",
    "urn:gew:schema:profile-real-e2e-binding-registry-input:1.0.0",
    "urn:gew:schema:profile-real-e2e-predecessor-record:1.0.0",
    "urn:gew:schema:profile-semantic-policy-input:1.0.0",
    "urn:gew:schema:profile-semantic-policy:1.0.0",
    "urn:gew:schema:project-profile-configuration-input:1.0.0",
    "urn:gew:schema:project-tightening-policy-input:1.0.0",
    "urn:gew:schema:project-tightening-policy:1.0.0",
    "urn:gew:schema:release-coverage-assessment:1.0.0",
    "urn:gew:schema:risk-overlay-definition-input:1.0.0",
    "urn:gew:schema:risk-overlay-definition:1.0.0",
    "urn:gew:schema:support-matrix-definition-input:1.0.0",
    "urn:gew:schema:support-matrix-definition:1.0.0",
} | set(MIGRATION_REHEARSAL_SCHEMA_IDS) | set(PERFORMANCE_BENCHMARK_SCHEMA_IDS)
  | set(SCENARIO_TRUTH_SCHEMA_IDS)))


class ProfileContractError(ValueError):
    """A profile, overlay, materialization, or coverage contract failed closed."""


def build_profile_schema_registry(
    manifest: object,
    bodies: object,
    resource_profile: ResourceProfile,
    schema_policy: SchemaProfilePolicy,
) -> ClosedSchemaRegistry:
    """Build only the exact installed schema closure owned by the Profile domain."""

    if type(manifest) is not dict or type(bodies) is not dict:
        raise ProfileContractError("Profile schema registry inputs must be exact objects")
    _require_exact_type(resource_profile, ResourceProfile, "resource profile")
    _require_exact_type(schema_policy, SchemaProfilePolicy, "schema profile policy")
    resources = manifest.get("resources")
    if type(resources) is not list:
        raise ProfileContractError("Profile schema registry resources are invalid")
    schema_ids = tuple(
        item.get("schema_id") if type(item) is dict else None for item in resources
    )
    if schema_ids != PROFILE_DOMAIN_SCHEMA_IDS or set(bodies) != set(PROFILE_DOMAIN_SCHEMA_IDS):
        raise ProfileContractError("Profile schema registry closure is not exact")
    return ClosedSchemaRegistry.build(
        manifest, bodies, resource_profile, schema_policy,
    )


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ProfileContractError(f"{label} properties are not exact")
    return value


def _strict_json_object(value: object, label: str) -> dict[str, object]:
    if type(value) not in (str, bytes):
        raise ProfileContractError(f"{label} JSON input is invalid")

    def exact_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ProfileContractError(f"{label} JSON contains a duplicate key")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=exact_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileContractError(f"{label} JSON is malformed") from error
    if type(parsed) is not dict:
        raise ProfileContractError(f"{label} JSON root must be an object")
    return parsed


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or not value.isascii()
    ):
        raise ProfileContractError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise ProfileContractError(f"{label} is not a semantic digest")
    return result


def _strings(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
    canonical_order: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    if type(value) is not list or (not allow_empty and not value):
        raise ProfileContractError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if len(result) != len(set(result)):
        raise ProfileContractError(f"{label} contains duplicates")
    if canonical_order is not None and result != canonical_order:
        raise ProfileContractError(f"{label} does not match its approved order")
    return result


def _sorted_strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    result = _strings(value, label, allow_empty=allow_empty)
    if result != tuple(sorted(result)):
        raise ProfileContractError(f"{label} is not canonical")
    return result


def _frozen_mapping(value: object, label: str) -> FrozenMap:
    if not isinstance(value, Mapping):
        raise ProfileContractError(f"{label} must be an object")
    result = freeze(value)
    if not isinstance(result, FrozenMap):
        raise AssertionError(f"{label} did not freeze")
    return result


def _verify_self_digest(
    value: object,
    *,
    fields: frozenset[str],
    name: str,
    digest_field: str,
) -> Mapping[str, object]:
    record = _exact(value, fields, name)
    expected = _digest(record[digest_field], f"{name} digest")
    body = thaw(freeze(record))
    if not isinstance(body, dict):
        raise AssertionError(f"{name} did not copy to an object")
    del body[digest_field]
    actual = semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise ProfileContractError(f"{name} self digest mismatch")
    return record


def _require_exact_type(value: object, expected: type[object], label: str) -> None:
    if type(value) is not expected:
        raise ProfileContractError(f"{label} is missing or forged")


@dataclass(frozen=True, slots=True, init=False)
class ApprovedProfileIdentityRegistry:
    registry_id: str
    governing_spec_sha256: str
    profile_ids: tuple[str, ...]
    registry_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ApprovedProfileIdentityRegistry must be loaded from pinned configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ApprovedProfileIdentityRegistry is final")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        expected_registry_digest: object,
    ) -> ApprovedProfileIdentityRegistry:
        expected_pin = _digest(expected_registry_digest, "approved profile registry pin")
        record = _verify_self_digest(
            value,
            fields=frozenset({
                "schema_version", "registry_id", "governing_spec_sha256",
                "profile_ids", "registry_digest",
            }),
            name="approved-profile-identity-registry",
            digest_field="registry_digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("approved profile registry schema version is unsupported")
        registry_id = _text(record["registry_id"], "approved profile registry ID")
        governing = _text(record["governing_spec_sha256"], "governing Spec SHA-256")
        if _RAW_SHA256.fullmatch(governing) is None:
            raise ProfileContractError("governing Spec SHA-256 is invalid")
        profile_ids = _strings(record["profile_ids"], "approved profile IDs")
        registry_digest = _digest(record["registry_digest"], "approved profile registry digest")
        if not hmac.compare_digest(registry_digest, expected_pin):
            raise ProfileContractError("approved profile registry does not match its installation pin")
        result = object.__new__(cls)
        for name, item in (
            ("registry_id", registry_id),
            ("governing_spec_sha256", governing),
            ("profile_ids", profile_ids),
            ("registry_digest", registry_digest),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ProfileCoveragePolicy:
    policy_id: str
    approved_profile_registry_digest: str
    evidence_authority: FrozenMap
    profile_column_ids: tuple[str, ...]
    risk_path_ids: tuple[str, ...]
    risk_path_bodies: Mapping[str, FrozenMap]
    scenarios: Mapping[str, tuple[str, ...]]
    required_invariant_ids: tuple[str, ...]
    case_binding_profiles: Mapping[str, FrozenMap]
    evidence_type: str
    owner_gate: str
    runtime_pins: FrozenMap
    default_execution_kind: str
    real_e2e_column_id: str
    real_e2e_execution_kind: str
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileCoveragePolicy must be loaded from pinned configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ProfileCoveragePolicy is final")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        expected_policy_digest: object,
    ) -> ProfileCoveragePolicy:
        _require_exact_type(
            approved_profiles, ApprovedProfileIdentityRegistry,
            "approved profile registry",
        )
        expected_pin = _digest(expected_policy_digest, "profile coverage policy pin")
        record = _verify_self_digest(
            value,
            fields=frozenset({
                "schema_version", "policy_id", "approved_profile_registry_digest",
                "evidence_authority",
                "profile_column_ids", "risk_path_ids", "scenarios",
                "required_invariant_ids", "case_binding_policy", "runtime_pins",
                "execution_policy", "risk_path_policy", "policy_digest",
            }),
            name="profile-coverage-policy",
            digest_field="policy_digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("profile coverage policy schema version is unsupported")
        registry_digest = _digest(
            record["approved_profile_registry_digest"],
            "profile coverage registry digest",
        )
        if not hmac.compare_digest(registry_digest, approved_profiles.registry_digest):
            raise ProfileContractError("profile coverage registry binding changed")
        raw_evidence_authority = _exact(
            record["evidence_authority"],
            frozenset({"registry_digest", "oracle_manifest_sha256"}),
            "coverage evidence authority",
        )
        _digest(raw_evidence_authority["registry_digest"], "coverage evidence registry digest")
        oracle_manifest_sha256 = _text(
            raw_evidence_authority["oracle_manifest_sha256"],
            "coverage oracle manifest SHA-256",
        )
        if _RAW_SHA256.fullmatch(oracle_manifest_sha256) is None:
            raise ProfileContractError("coverage oracle manifest SHA-256 is invalid")
        columns = _strings(record["profile_column_ids"], "profile coverage columns")
        risk_paths = _strings(record["risk_path_ids"], "profile risk paths")
        raw_risk_path_policy = _exact(
            record["risk_path_policy"], frozenset({"overlays"}),
            "coverage risk path policy",
        )
        raw_overlay_bodies = raw_risk_path_policy["overlays"]
        if type(raw_overlay_bodies) is not list:
            raise ProfileContractError("coverage risk path approvals must be an array")
        risk_path_bodies: dict[str, FrozenMap] = {}
        ordered_risk_paths: list[str] = []
        for raw_overlay in raw_overlay_bodies:
            overlay = _exact(
                raw_overlay,
                frozenset({
                    "overlay_id", "overlay_version", "approved_body_digest",
                }),
                "coverage risk path approval",
            )
            overlay_id = _text(overlay["overlay_id"], "approved risk overlay ID")
            if overlay_id in risk_path_bodies:
                raise ProfileContractError("coverage risk path approval is duplicated")
            _text(overlay["overlay_version"], "approved risk overlay version")
            _digest(overlay["approved_body_digest"], "approved risk overlay body digest")
            ordered_risk_paths.append(overlay_id)
            risk_path_bodies[overlay_id] = _frozen_mapping(
                overlay, "coverage risk path approval",
            )
        if tuple(ordered_risk_paths) != risk_paths:
            raise ProfileContractError("coverage risk path approvals are not exact")
        raw_scenarios = record["scenarios"]
        if type(raw_scenarios) is not list:
            raise ProfileContractError("profile scenarios must be an array")
        scenarios: dict[str, tuple[str, ...]] = {}
        ordered_profiles: list[str] = []
        for raw in raw_scenarios:
            item = _exact(raw, frozenset({"profile_id", "scenario_ids"}), "profile scenarios")
            profile_id = _text(item["profile_id"], "scenario profile ID")
            if profile_id in scenarios:
                raise ProfileContractError("profile scenario identity is duplicated")
            ordered_profiles.append(profile_id)
            scenarios[profile_id] = _strings(item["scenario_ids"], "profile scenario IDs")
        if tuple(ordered_profiles) != approved_profiles.profile_ids:
            raise ProfileContractError("profile scenarios do not close over the approved registry")
        invariants = _sorted_strings(record["required_invariant_ids"], "required invariant IDs")
        raw_binding_policy = _exact(
            record["case_binding_policy"],
            frozenset({"evidence_type", "owner_gate", "profiles"}),
            "coverage case binding policy",
        )
        evidence_type = _text(raw_binding_policy["evidence_type"], "coverage evidence type")
        owner_gate = _text(raw_binding_policy["owner_gate"], "coverage owner gate")
        raw_profiles = raw_binding_policy["profiles"]
        if type(raw_profiles) is not list:
            raise ProfileContractError("coverage binding Profiles must be an array")
        binding_profiles: dict[str, FrozenMap] = {}
        ordered_binding_profiles: list[str] = []
        for raw_profile in raw_profiles:
            binding = _exact(
                raw_profile,
                frozenset({"profile_id", "profile_version", "fixture_id", "oracle_id"}),
                "coverage Profile binding",
            )
            profile_id = _text(binding["profile_id"], "coverage binding Profile ID")
            if profile_id in binding_profiles:
                raise ProfileContractError("coverage binding Profile is duplicated")
            ordered_binding_profiles.append(profile_id)
            for field in ("profile_version", "fixture_id", "oracle_id"):
                _text(binding[field], f"coverage binding {field}")
            binding_profiles[profile_id] = _frozen_mapping(
                binding, "coverage Profile binding",
            )
        if tuple(ordered_binding_profiles) != approved_profiles.profile_ids:
            raise ProfileContractError("coverage bindings do not close over approved Profiles")
        raw_runtime = _exact(
            record["runtime_pins"],
            frozenset({"runtime_kind", "runtime_lineage_id", "runtime_digest"}),
            "coverage runtime pins",
        )
        _text(raw_runtime["runtime_kind"], "coverage runtime kind")
        _text(raw_runtime["runtime_lineage_id"], "coverage runtime lineage")
        _digest(raw_runtime["runtime_digest"], "coverage runtime digest")
        execution = _exact(
            record["execution_policy"],
            frozenset({
                "default_execution_kind", "real_e2e_column_id",
                "real_e2e_execution_kind",
            }),
            "coverage execution policy",
        )
        for field in (
            "default_execution_kind", "real_e2e_column_id", "real_e2e_execution_kind",
        ):
            _text(execution[field], f"coverage {field}")
        if execution["real_e2e_column_id"] not in columns:
            raise ProfileContractError("coverage real E2E column is not approved")
        policy_digest = _digest(record["policy_digest"], "profile coverage policy digest")
        if not hmac.compare_digest(policy_digest, expected_pin):
            raise ProfileContractError("profile coverage policy does not match its installation pin")
        result = object.__new__(cls)
        for name, item in (
            ("policy_id", _text(record["policy_id"], "profile coverage policy ID")),
            ("approved_profile_registry_digest", registry_digest),
            ("evidence_authority", _frozen_mapping(
                raw_evidence_authority, "coverage evidence authority",
            )),
            ("profile_column_ids", columns),
            ("risk_path_ids", risk_paths),
            ("risk_path_bodies", MappingProxyType(dict(risk_path_bodies))),
            ("scenarios", MappingProxyType(dict(scenarios))),
            ("required_invariant_ids", invariants),
            ("case_binding_profiles", MappingProxyType(dict(binding_profiles))),
            ("evidence_type", evidence_type),
            ("owner_gate", owner_gate),
            ("runtime_pins", _frozen_mapping(raw_runtime, "coverage runtime pins")),
            ("default_execution_kind", str(execution["default_execution_kind"])),
            ("real_e2e_column_id", str(execution["real_e2e_column_id"])),
            ("real_e2e_execution_kind", str(execution["real_e2e_execution_kind"])),
            ("policy_digest", policy_digest),
        ):
            object.__setattr__(result, name, item)
        return result

    def approved_risk_overlay_body(self, overlay_id: str) -> FrozenMap:
        try:
            return self.risk_path_bodies[overlay_id]
        except KeyError as error:
            raise ProfileContractError("risk overlay has no approved semantic body") from error

    def profile_case_ids(self) -> tuple[str, ...]:
        return tuple(sorted(
            f"GEW-PRO-{profile_id.upper()}-{column_id.upper()}-{outcome}"
            for profile_id in self.scenarios
            for column_id in self.profile_column_ids
            for outcome in ("P", "R")
        ))

    def scenario_case_ids(self) -> tuple[str, ...]:
        return tuple(sorted(
            f"GEW-PSC-{profile_id.upper()}-{scenario_id.upper()}-{outcome}"
            for profile_id, scenario_ids in self.scenarios.items()
            for scenario_id in scenario_ids
            for outcome in ("P", "R")
        ))

    def cases_for_profile(self, profile_id: str) -> frozenset[str]:
        _text(profile_id, "profile ID")
        prefix_profile = f"GEW-PRO-{profile_id.upper()}-"
        prefix_scenario = f"GEW-PSC-{profile_id.upper()}-"
        return frozenset(
            case_id for case_id in (*self.profile_case_ids(), *self.scenario_case_ids())
            if case_id.startswith(prefix_profile) or case_id.startswith(prefix_scenario)
        )

    def profile_for_case_id(self, test_id: str) -> str:
        _text(test_id, "coverage test ID")
        matches = tuple(
            profile_id for profile_id in self.scenarios
            if test_id in self.cases_for_profile(profile_id)
        )
        if len(matches) != 1:
            raise ProfileContractError("coverage test ID has no exact Profile binding")
        return matches[0]

    def column_for_case_id(self, test_id: str) -> str | None:
        """Resolve the one closed Profile column encoded by a Profile case ID.

        Scenario cases intentionally have no Profile-column identity.
        """
        _text(test_id, "coverage test ID")
        if not test_id.startswith("GEW-PRO-"):
            if test_id in self.scenario_case_ids():
                return None
            raise ProfileContractError("coverage test ID has no exact column binding")
        matches = tuple(
            column_id
            for column_id in self.profile_column_ids
            if test_id.endswith(f"-{column_id.upper()}-P")
            or test_id.endswith(f"-{column_id.upper()}-R")
        )
        if len(matches) != 1 or test_id not in self.profile_case_ids():
            raise ProfileContractError("coverage test ID has no exact column binding")
        return matches[0]

    def expected_case_binding(self, test_id: str) -> FrozenMap:
        profile_id = self.profile_for_case_id(test_id)
        profile_binding = self.case_binding_profiles[profile_id]
        return FrozenMap.from_dict({
            "test_id": test_id,
            "fixture_id": profile_binding["fixture_id"],
            "oracle_id": profile_binding["oracle_id"],
            "evidence_type": self.evidence_type,
            "owner_gate": self.owner_gate,
        })

    def expected_execution_kind(self, test_id: str) -> str:
        marker = f"-{self.real_e2e_column_id.upper()}-"
        return (
            self.real_e2e_execution_kind
            if marker in test_id
            else self.default_execution_kind
        )

    def expected_plan_selector(self, test_id: str) -> FrozenMap:
        """Resolve the closed semantic selector encoded by one approved case ID."""

        profile_id = self.profile_for_case_id(test_id)
        disposition_matches = tuple(
            disposition
            for disposition in ("P", "R")
            if test_id.endswith(f"-{disposition}")
        )
        if len(disposition_matches) != 1:
            raise ProfileContractError(
                "coverage test ID has no exact disposition binding"
            )
        disposition = disposition_matches[0]
        if test_id in self.profile_case_ids():
            column_id = self.column_for_case_id(test_id)
            if column_id is None:
                raise ProfileContractError(
                    "mandatory coverage case has no exact column binding"
                )
            selector_kind = "mandatory"
            scenario_id = None
            boundary_case_id = None
        elif test_id in self.scenario_case_ids():
            scenario_matches = tuple(
                scenario_id
                for scenario_id in self.scenarios[profile_id]
                if test_id
                == f"GEW-PSC-{profile_id.upper()}-{scenario_id.upper()}-{disposition}"
            )
            if len(scenario_matches) != 1:
                raise ProfileContractError(
                    "scenario coverage case has no exact scenario binding"
                )
            selector_kind = "scenario"
            # Scenario column ownership remains with the installed oracle; the
            # coverage policy only authenticates the stable scenario identity.
            column_id = None
            scenario_id = scenario_matches[0]
            boundary_case_id = (
                f"GEW-PSC-{profile_id.upper()}-{scenario_id.upper()}-P"
            )
        else:
            raise ProfileContractError("coverage test ID is not approved")
        return FrozenMap.from_dict({
            "profile_id": profile_id,
            "selector_kind": selector_kind,
            "column_id": column_id,
            "scenario_id": scenario_id,
            "category_boundary_case_id": boundary_case_id,
            "disposition": disposition,
            "execution_kind": self.expected_execution_kind(test_id),
        })


def _budget_limit_map(
    value: object, label: str, *, allow_empty: bool = False,
) -> Mapping[str, int]:
    if type(value) is not list or (not allow_empty and not value):
        raise ProfileContractError(f"{label} must be an array")
    limits: dict[str, int] = {}
    ordered_ids: list[str] = []
    for raw in value:
        item = _exact(
            raw, frozenset({"budget_id", "maximum"}), f"{label} entry",
        )
        budget_id = _text(item["budget_id"], f"{label} budget ID")
        maximum = item["maximum"]
        if type(maximum) is not int or maximum <= 0:
            raise ProfileContractError(f"{label} maximum must be a positive integer")
        if budget_id in limits:
            raise ProfileContractError(f"{label} budget ID is duplicated")
        ordered_ids.append(budget_id)
        limits[budget_id] = maximum
    if tuple(ordered_ids) != tuple(sorted(ordered_ids)):
        raise ProfileContractError(f"{label} order is not canonical")
    return MappingProxyType(dict(limits))


@dataclass(frozen=True, slots=True, init=False)
class ProjectTighteningPolicy:
    policy_id: str
    loop_budget_registry_id: str
    loop_budget_registry_digest: str
    base_budget_limits: Mapping[str, int]
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProjectTighteningPolicy must be loaded from pinned configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ProjectTighteningPolicy is final")

    @classmethod
    def from_dict(
        cls, value: object, *, loop_budgets: LoopBudgetRegistry,
    ) -> ProjectTighteningPolicy:
        _require_exact_type(loop_budgets, LoopBudgetRegistry, "loop budget registry")
        record = _verify_self_digest(
            value,
            fields=frozenset({
                "schema_version", "policy_id", "loop_budget_registry_id",
                "loop_budget_registry_digest", "base_budget_limits", "policy_digest",
            }),
            name="project-tightening-policy",
            digest_field="policy_digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("project tightening policy version is unsupported")
        registry_id = _text(
            record["loop_budget_registry_id"], "project tightening loop registry ID",
        )
        registry_digest = _digest(
            record["loop_budget_registry_digest"],
            "project tightening loop registry digest",
        )
        if (
            registry_id != loop_budgets.registry_id
            or not hmac.compare_digest(registry_digest, loop_budgets.registry_digest)
        ):
            raise ProfileContractError("project tightening loop registry is not installed")
        base_limits = _budget_limit_map(
            record["base_budget_limits"], "project tightening base budgets",
        )
        if set(base_limits) != set(loop_budgets.budgets):
            raise ProfileContractError("project tightening budget set is not exact")
        for budget_id, maximum in base_limits.items():
            if maximum != loop_budgets.resolve(budget_id).max_attempts:
                raise ProfileContractError("project tightening base budget is stale")
        result = object.__new__(cls)
        for name, item in (
            ("policy_id", _text(record["policy_id"], "project tightening policy ID")),
            ("loop_budget_registry_id", registry_id),
            ("loop_budget_registry_digest", registry_digest),
            ("base_budget_limits", base_limits),
            (
                "policy_digest",
                _digest(record["policy_digest"], "project tightening policy digest"),
            ),
        ):
            object.__setattr__(result, name, item)
        return result


def _semantic_minimum(value: object, label: str) -> FrozenMap:
    record = _exact(
        value,
        frozenset({
            "required_node_ids", "required_edge_ids", "artifact_contract_ids",
            "validator_ids", "completion_predicate_ids", "rollback_verification_ids",
            "target_verification_ids", "required_capability_ids",
        }),
        label,
    )
    normalized = {
        field: _sorted_strings(record[field], f"{label} {field}")
        for field in (
            "required_node_ids", "required_edge_ids", "artifact_contract_ids",
            "validator_ids", "completion_predicate_ids", "rollback_verification_ids",
            "target_verification_ids", "required_capability_ids",
        )
    }
    frozen = freeze({
        field: list(items) for field, items in normalized.items()
    })
    if not isinstance(frozen, FrozenMap):
        raise AssertionError("Profile semantic minimum did not freeze")
    return frozen


def _base_semantic_sets(value: object) -> FrozenMap:
    record = _exact(
        value,
        frozenset({
            "required_node_ids", "required_edge_ids", "artifact_contract_ids",
            "validator_ids", "completion_predicate_ids", "required_invariant_ids",
        }),
        "base Profile semantic sets",
    )
    normalized = {
        field: _sorted_strings(
            record[field], f"base Profile {field}",
            allow_empty=field in {"required_edge_ids", "validator_ids"},
        )
        for field in record
    }
    return _frozen_mapping(
        {field: list(items) for field, items in normalized.items()},
        "base Profile semantic sets",
    )


def _risk_path_minimum(value: object, label: str) -> FrozenMap:
    record = _exact(
        value,
        frozenset({
            "overlay_id", "node_additions", "edge_additions",
            "entry_condition_ids", "exit_condition_ids", "required_invariant_ids",
            "budget_limits",
        }),
        label,
    )
    normalized: dict[str, object] = {
        "overlay_id": _text(record["overlay_id"], f"{label} ID"),
    }
    for field in (
        "node_additions", "edge_additions", "entry_condition_ids",
        "exit_condition_ids", "required_invariant_ids",
    ):
        normalized[field] = list(_sorted_strings(
            record[field], f"{label} {field}",
            allow_empty=field in {"node_additions", "edge_additions"},
        ))
    normalized["budget_limits"] = [
        {"budget_id": budget_id, "maximum": maximum}
        for budget_id, maximum in _budget_limit_map(
            record["budget_limits"], f"{label} budgets",
        ).items()
    ]
    return _frozen_mapping(normalized, label)


@dataclass(frozen=True, slots=True, init=False)
class ProfileSemanticPolicy:
    policy_id: str
    approved_profile_registry_digest: str
    coverage_policy_digest: str
    core_invariant_ids: tuple[str, ...]
    base_semantic_sets: FrozenMap
    profiles: Mapping[str, FrozenMap]
    risk_path_ids: tuple[str, ...]
    risk_path_minima: Mapping[str, FrozenMap]
    project_tightening_policy: ProjectTighteningPolicy
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileSemanticPolicy must be loaded from pinned configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ProfileSemanticPolicy is final")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        coverage_policy: ProfileCoveragePolicy,
        loop_budgets: LoopBudgetRegistry,
        expected_policy_digest: object,
    ) -> ProfileSemanticPolicy:
        _require_exact_type(
            approved_profiles, ApprovedProfileIdentityRegistry,
            "approved profile registry",
        )
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        _require_exact_type(loop_budgets, LoopBudgetRegistry, "loop budget registry")
        expected_pin = _digest(expected_policy_digest, "Profile semantic policy pin")
        record = _verify_self_digest(
            value,
            fields=frozenset({
                "schema_version", "policy_id", "approved_profile_registry_digest",
                "coverage_policy_digest", "core_invariant_ids", "base_semantic_sets",
                "profiles", "risk_path_minima", "project_tightening_policy",
                "policy_digest",
            }),
            name="profile-semantic-policy",
            digest_field="policy_digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("Profile semantic policy version is unsupported")
        registry_digest = _digest(
            record["approved_profile_registry_digest"],
            "Profile semantic registry digest",
        )
        coverage_digest = _digest(
            record["coverage_policy_digest"],
            "Profile semantic coverage digest",
        )
        if (
            not hmac.compare_digest(registry_digest, approved_profiles.registry_digest)
            or not hmac.compare_digest(coverage_digest, coverage_policy.policy_digest)
        ):
            raise ProfileContractError("Profile semantic policy binding changed")
        invariants = _sorted_strings(
            record["core_invariant_ids"], "Profile CoreInvariantSet",
        )
        if invariants != coverage_policy.required_invariant_ids:
            raise ProfileContractError("Profile CoreInvariantSet is not exact")
        base_sets = _base_semantic_sets(record["base_semantic_sets"])
        if base_sets["required_invariant_ids"] != invariants:
            raise ProfileContractError("base Profile invariant set is not exact")
        project_policy = ProjectTighteningPolicy.from_dict(
            record["project_tightening_policy"], loop_budgets=loop_budgets,
        )
        raw_profiles = record["profiles"]
        if type(raw_profiles) is not list:
            raise ProfileContractError("Profile semantic entries must be an array")
        profiles: dict[str, FrozenMap] = {}
        ordered_profiles: list[str] = []
        for raw_profile in raw_profiles:
            entry = _exact(
                raw_profile,
                frozenset({
                    "profile_id", "profile_version", "approved_body_digest",
                    "approved_definition_body_digest", "semantic_minima",
                }),
                "Profile semantic entry",
            )
            profile_id = _text(entry["profile_id"], "semantic Profile ID")
            profile_version = _text(entry["profile_version"], "semantic Profile version")
            if profile_id in profiles:
                raise ProfileContractError("Profile semantic identity is duplicated")
            minima = _semantic_minimum(
                entry["semantic_minima"], f"Profile semantic minimum {profile_id}",
            )
            available_targets = set((
                *base_sets["required_node_ids"],
                *base_sets["validator_ids"],
                *base_sets["completion_predicate_ids"],
                *minima["required_node_ids"],
                *minima["validator_ids"],
                *minima["completion_predicate_ids"],
            ))
            if not set(minima["target_verification_ids"]).issubset(available_targets):
                raise ProfileContractError("Profile target verification minimum is unresolved")
            approved_body_digest = _digest(
                entry["approved_body_digest"], "approved Profile body digest",
            )
            approved_definition_body_digest = _digest(
                entry["approved_definition_body_digest"],
                "approved ProfileDefinition body digest",
            )
            actual_body_digest = semantic_digest(
                {
                    "schema_version": "1.0.0",
                    "profile_id": profile_id,
                    "profile_version": profile_version,
                    "semantic_minima": thaw(minima),
                },
                contract_type="urn:gew:contract:approved-profile-body",
                projection_id="urn:gew:digest-projection:approved-profile-body:1.0.0",
                schema_id="urn:gew:schema:approved-profile-body-input:1.0.0",
            )
            if not hmac.compare_digest(approved_body_digest, actual_body_digest):
                raise ProfileContractError("approved Profile body digest mismatch")
            ordered_profiles.append(profile_id)
            frozen_entry = freeze({
                "profile_version": profile_version,
                "approved_body_digest": approved_body_digest,
                "approved_definition_body_digest": approved_definition_body_digest,
                "semantic_minima": thaw(minima),
            })
            if not isinstance(frozen_entry, FrozenMap):
                raise AssertionError("Profile semantic entry did not freeze")
            profiles[profile_id] = frozen_entry
        if tuple(ordered_profiles) != approved_profiles.profile_ids:
            raise ProfileContractError("Profile semantic policy does not close over registry")
        raw_risk_minima = record["risk_path_minima"]
        if type(raw_risk_minima) is not list:
            raise ProfileContractError("risk path semantic minima must be an array")
        risk_minima: dict[str, FrozenMap] = {}
        ordered_risks: list[str] = []
        for raw_minimum in raw_risk_minima:
            minimum = _risk_path_minimum(raw_minimum, "risk path semantic minimum")
            overlay_id = str(minimum["overlay_id"])
            if overlay_id in risk_minima:
                raise ProfileContractError("risk path semantic minimum is duplicated")
            ordered_risks.append(overlay_id)
            budget_entries = minimum["budget_limits"]
            if not isinstance(budget_entries, tuple):
                raise AssertionError("risk path budget minimum did not freeze")
            minimum_budgets = {
                str(item["budget_id"]): item["maximum"]
                for item in budget_entries if isinstance(item, FrozenMap)
            }
            if set(minimum_budgets) != set(project_policy.base_budget_limits):
                raise ProfileContractError("risk path budget set is not exact")
            for budget_id, maximum in minimum_budgets.items():
                if type(maximum) is not int or maximum > project_policy.base_budget_limits[budget_id]:
                    raise ProfileContractError("risk path budget weakens the installed limit")
            risk_minima[overlay_id] = minimum
        if tuple(ordered_risks) != coverage_policy.risk_path_ids:
            raise ProfileContractError("risk path semantic minima are not exact")
        policy_digest = _digest(record["policy_digest"], "Profile semantic policy digest")
        if not hmac.compare_digest(policy_digest, expected_pin):
            raise ProfileContractError("Profile semantic policy does not match installation pin")
        result = object.__new__(cls)
        for name, item in (
            ("policy_id", _text(record["policy_id"], "Profile semantic policy ID")),
            ("approved_profile_registry_digest", registry_digest),
            ("coverage_policy_digest", coverage_digest),
            ("core_invariant_ids", invariants),
            ("base_semantic_sets", base_sets),
            ("profiles", MappingProxyType(dict(profiles))),
            ("risk_path_ids", coverage_policy.risk_path_ids),
            ("risk_path_minima", MappingProxyType(dict(risk_minima))),
            ("project_tightening_policy", project_policy),
            ("policy_digest", policy_digest),
        ):
            object.__setattr__(result, name, item)
        return result

    def risk_minimum_for(self, overlay_id: str) -> FrozenMap:
        try:
            return self.risk_path_minima[overlay_id]
        except KeyError as error:
            raise ProfileContractError("risk overlay has no semantic minimum") from error

    def minimum_for(self, profile_id: str, version: str) -> FrozenMap:
        try:
            entry = self.profiles[profile_id]
        except KeyError as error:
            raise ProfileContractError("Profile has no approved semantic body") from error
        if entry["profile_version"] != version:
            raise ProfileContractError("Profile semantic version is not approved")
        minima = entry["semantic_minima"]
        if not isinstance(minima, FrozenMap):
            raise AssertionError("Profile semantic minimum did not freeze")
        return minima

    def approved_definition_body_digest_for(
        self, profile_id: str, version: str,
    ) -> str:
        try:
            entry = self.profiles[profile_id]
        except KeyError as error:
            raise ProfileContractError("Profile has no approved definition body") from error
        if entry["profile_version"] != version:
            raise ProfileContractError("Profile definition version is not approved")
        return str(entry["approved_definition_body_digest"])


@dataclass(frozen=True, slots=True, init=False)
class ProfileDefinition:
    profile_id: str
    version: str
    approved_profile_registry_digest: str
    coverage_policy_digest: str
    profile_semantic_policy_digest: str
    required_node_ids: tuple[str, ...]
    optional_node_ids: tuple[str, ...]
    required_edge_ids: tuple[str, ...]
    optional_edge_ids: tuple[str, ...]
    route_overrides: tuple[object, ...]
    artifact_contract_ids: tuple[str, ...]
    validator_ids: tuple[str, ...]
    completion_predicate_ids: tuple[str, ...]
    compatible_risk_paths: tuple[str, ...]
    rollback_contract: FrozenMap
    required_case_ids: tuple[str, ...]
    category_boundary_case_ids: tuple[str, ...]
    real_e2e_requirement_id: str
    required_capabilities: tuple[str, ...]
    unsupported_integrations: tuple[str, ...]
    evidence_policy: FrozenMap
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileDefinition must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ProfileDefinition is final")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        coverage_policy: ProfileCoveragePolicy,
        semantic_policy: ProfileSemanticPolicy,
    ) -> ProfileDefinition:
        _require_exact_type(approved_profiles, ApprovedProfileIdentityRegistry, "approved profile registry")
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        _require_exact_type(semantic_policy, ProfileSemanticPolicy, "Profile semantic policy")
        fields = frozenset({
            "schema_version", "profile_id", "version",
            "approved_profile_registry_digest", "coverage_policy_digest",
            "profile_semantic_policy_digest",
            "required_node_ids", "optional_node_ids", "required_edge_ids",
            "optional_edge_ids", "route_overrides", "artifact_contract_ids",
            "validator_ids", "completion_predicate_ids", "compatible_risk_paths",
            "rollback_contract", "required_case_ids", "category_boundary_case_ids",
            "real_e2e_requirement_id", "required_capabilities",
            "unsupported_integrations", "evidence_policy", "digest",
        })
        record = _verify_self_digest(
            value, fields=fields, name="profile-definition", digest_field="digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("ProfileDefinition schema version is unsupported")
        profile_id = _text(record["profile_id"], "Profile ID")
        version = _text(record["version"], "Profile version")
        if profile_id not in approved_profiles.profile_ids:
            raise ProfileContractError("Profile ID is not approved")
        registry_digest = _digest(record["approved_profile_registry_digest"], "Profile registry digest")
        policy_digest = _digest(record["coverage_policy_digest"], "Profile coverage policy digest")
        semantic_policy_digest = _digest(
            record["profile_semantic_policy_digest"], "Profile semantic policy digest",
        )
        if (
            not hmac.compare_digest(registry_digest, approved_profiles.registry_digest)
            or not hmac.compare_digest(policy_digest, coverage_policy.policy_digest)
            or not hmac.compare_digest(
                semantic_policy_digest, semantic_policy.policy_digest,
            )
        ):
            raise ProfileContractError("Profile registry, coverage, or semantic binding changed")
        required_nodes = _sorted_strings(record["required_node_ids"], "required Profile node IDs")
        optional_nodes = _sorted_strings(record["optional_node_ids"], "optional Profile node IDs", allow_empty=True)
        required_edges = _sorted_strings(record["required_edge_ids"], "required Profile edge IDs")
        optional_edges = _sorted_strings(record["optional_edge_ids"], "optional Profile edge IDs", allow_empty=True)
        if set(required_nodes) & set(optional_nodes) or set(required_edges) & set(optional_edges):
            raise ProfileContractError("required and optional Profile identities overlap")
        routes = record["route_overrides"]
        if type(routes) is not list:
            raise ProfileContractError("Profile route overrides must be an array")
        frozen_routes = freeze(routes)
        if type(frozen_routes) is not tuple:
            raise AssertionError("Profile route overrides did not freeze")
        compatible = _strings(
            record["compatible_risk_paths"], "compatible Profile risk paths",
        )
        if not set(compatible).issubset(coverage_policy.risk_path_ids):
            raise ProfileContractError("Profile risk path is not approved")
        rollback = _exact(
            record["rollback_contract"],
            frozenset({
                "eligible_action_kinds", "precondition_ids", "compensation_graph_ref",
                "authority_requirement", "verification_ids", "rollback_not_possible",
            }),
            "Profile rollback contract",
        )
        _sorted_strings(rollback["eligible_action_kinds"], "rollback eligible action kinds")
        _sorted_strings(rollback["precondition_ids"], "rollback precondition IDs")
        _text(rollback["compensation_graph_ref"], "rollback compensation graph ref")
        _text(rollback["authority_requirement"], "rollback authority requirement")
        _sorted_strings(rollback["verification_ids"], "rollback verification IDs")
        _text(rollback["rollback_not_possible"], "rollback-not-possible route")
        minima = semantic_policy.minimum_for(profile_id, version)
        semantic_sets = {
            "required_node_ids": set(required_nodes),
            "required_edge_ids": set(required_edges),
            "artifact_contract_ids": set(_strings(
                record["artifact_contract_ids"], "Profile artifact contracts",
            )),
            "validator_ids": set(_strings(record["validator_ids"], "Profile validator IDs")),
            "completion_predicate_ids": set(_strings(
                record["completion_predicate_ids"], "Profile completion predicates",
            )),
            "rollback_verification_ids": set(_strings(
                rollback["verification_ids"], "rollback verification IDs",
            )),
            "required_capability_ids": set(_strings(
                record["required_capabilities"], "Profile required capabilities",
            )),
        }
        for field, actual_values in semantic_sets.items():
            minimum_values = minima[field]
            if not isinstance(minimum_values, tuple):
                raise AssertionError("Profile semantic minimum is not an immutable array")
            if not set(minimum_values).issubset(actual_values):
                raise ProfileContractError(f"Profile weakens approved {field}")
        base_sets = semantic_policy.base_semantic_sets
        for field in (
            "required_node_ids", "required_edge_ids", "artifact_contract_ids",
            "validator_ids", "completion_predicate_ids",
        ):
            minimum = base_sets[field]
            if not isinstance(minimum, tuple):
                raise AssertionError("base Profile semantic set is not immutable")
            if not set(minimum).issubset(semantic_sets[field]):
                raise ProfileContractError(f"Profile weakens base {field}")
        target_minima = minima["target_verification_ids"]
        if not isinstance(target_minima, tuple):
            raise AssertionError("Profile target verification minimum is not immutable")
        target_actual = set((
            *required_nodes,
            *semantic_sets["validator_ids"],
            *semantic_sets["completion_predicate_ids"],
        ))
        if not set(target_minima).issubset(target_actual):
            raise ProfileContractError("Profile weakens target verification semantics")
        required_cases = _sorted_strings(record["required_case_ids"], "required Profile case IDs")
        if set(required_cases) != coverage_policy.cases_for_profile(profile_id):
            raise ProfileContractError("Profile required cases are not the exact approved set")
        boundary_cases = _sorted_strings(
            record["category_boundary_case_ids"], "Profile boundary case IDs",
        )
        expected_scenarios = tuple(sorted(
            case_id for case_id in coverage_policy.scenario_case_ids()
            if case_id in coverage_policy.cases_for_profile(profile_id)
        ))
        if boundary_cases != expected_scenarios:
            raise ProfileContractError("Profile boundary cases are not the exact category scenarios")
        real_e2e = _text(record["real_e2e_requirement_id"], "Profile real E2E requirement ID")
        if real_e2e not in required_cases or not real_e2e.endswith("-REAL-E2E-P"):
            raise ProfileContractError("Profile real E2E requirement is not exact")
        evidence = _exact(
            record["evidence_policy"],
            frozenset({"owner_gate", "required_oracle_ids"}),
            "Profile evidence policy",
        )
        owner_gate = _text(evidence["owner_gate"], "Profile evidence owner gate")
        oracle_ids = _sorted_strings(
            evidence["required_oracle_ids"], "Profile evidence oracle IDs",
        )
        approved_oracle = str(
            coverage_policy.case_binding_profiles[profile_id]["oracle_id"]
        )
        if owner_gate != coverage_policy.owner_gate or oracle_ids != (approved_oracle,):
            raise ProfileContractError("Profile evidence binding is not exact")
        result = object.__new__(cls)
        values = (
            ("profile_id", profile_id),
            ("version", version),
            ("approved_profile_registry_digest", registry_digest),
            ("coverage_policy_digest", policy_digest),
            ("profile_semantic_policy_digest", semantic_policy_digest),
            ("required_node_ids", required_nodes),
            ("optional_node_ids", optional_nodes),
            ("required_edge_ids", required_edges),
            ("optional_edge_ids", optional_edges),
            ("route_overrides", frozen_routes),
            ("artifact_contract_ids", _sorted_strings(record["artifact_contract_ids"], "Profile artifact contracts")),
            ("validator_ids", _sorted_strings(record["validator_ids"], "Profile validator IDs")),
            ("completion_predicate_ids", _sorted_strings(record["completion_predicate_ids"], "Profile completion predicates")),
            ("compatible_risk_paths", compatible),
            ("rollback_contract", _frozen_mapping(rollback, "Profile rollback contract")),
            ("required_case_ids", required_cases),
            ("category_boundary_case_ids", boundary_cases),
            ("real_e2e_requirement_id", real_e2e),
            ("required_capabilities", _sorted_strings(record["required_capabilities"], "Profile required capabilities")),
            ("unsupported_integrations", _sorted_strings(record["unsupported_integrations"], "Profile unsupported integrations", allow_empty=True)),
            ("evidence_policy", _frozen_mapping(evidence, "Profile evidence policy")),
            ("digest", _digest(record["digest"], "Profile digest")),
        )
        for name, item in values:
            object.__setattr__(result, name, item)
        return result


def _profile_definition_body_digest(profile: ProfileDefinition) -> str:
    body = {
        "schema_version": "1.0.0",
        "profile_id": profile.profile_id,
        "version": profile.version,
        "required_node_ids": list(profile.required_node_ids),
        "optional_node_ids": list(profile.optional_node_ids),
        "required_edge_ids": list(profile.required_edge_ids),
        "optional_edge_ids": list(profile.optional_edge_ids),
        "route_overrides": thaw(profile.route_overrides),
        "artifact_contract_ids": list(profile.artifact_contract_ids),
        "validator_ids": list(profile.validator_ids),
        "completion_predicate_ids": list(profile.completion_predicate_ids),
        "compatible_risk_paths": list(profile.compatible_risk_paths),
        "rollback_contract": thaw(profile.rollback_contract),
        "required_case_ids": list(profile.required_case_ids),
        "category_boundary_case_ids": list(profile.category_boundary_case_ids),
        "real_e2e_requirement_id": profile.real_e2e_requirement_id,
        "required_capabilities": list(profile.required_capabilities),
        "unsupported_integrations": list(profile.unsupported_integrations),
        "evidence_policy": thaw(profile.evidence_policy),
    }
    return semantic_digest(
        body,
        contract_type="urn:gew:contract:approved-profile-definition-body",
        projection_id=(
            "urn:gew:digest-projection:approved-profile-definition-body:1.0.0"
        ),
        schema_id="urn:gew:schema:approved-profile-definition-body-input:1.0.0",
    )


@dataclass(frozen=True, slots=True, init=False)
class ProfileDefinitionSet:
    profile_ids: tuple[str, ...]
    profiles: Mapping[str, ProfileDefinition]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProfileDefinitionSet must be issued from closed definitions")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ProfileDefinitionSet is final")

    @classmethod
    def from_documents(
        cls,
        definitions: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        semantic_policy: ProfileSemanticPolicy,
    ) -> ProfileDefinitionSet:
        _require_exact_type(
            approved_profiles, ApprovedProfileIdentityRegistry,
            "approved profile registry",
        )
        _require_exact_type(
            semantic_policy, ProfileSemanticPolicy, "Profile semantic policy",
        )
        if type(definitions) is not tuple or any(
            type(item) is not ProfileDefinition for item in definitions
        ):
            raise ProfileContractError("ProfileDefinition set contains a forged member")
        profile_ids = tuple(item.profile_id for item in definitions)
        if profile_ids != approved_profiles.profile_ids:
            raise ProfileContractError("ProfileDefinition set is not exact")
        if len(profile_ids) != len(set(profile_ids)):
            raise ProfileContractError("ProfileDefinition set contains duplicates")
        resolved: dict[str, ProfileDefinition] = {}
        for profile in definitions:
            if (
                not hmac.compare_digest(
                    profile.approved_profile_registry_digest,
                    approved_profiles.registry_digest,
                )
                or not hmac.compare_digest(
                    profile.profile_semantic_policy_digest,
                    semantic_policy.policy_digest,
                )
            ):
                raise ProfileContractError("ProfileDefinition set binding changed")
            expected = semantic_policy.approved_definition_body_digest_for(
                profile.profile_id, profile.version,
            )
            actual = _profile_definition_body_digest(profile)
            if not hmac.compare_digest(expected, actual):
                raise ProfileContractError("ProfileDefinition body is not approved")
            resolved[profile.profile_id] = profile
        result = object.__new__(cls)
        object.__setattr__(result, "profile_ids", profile_ids)
        object.__setattr__(result, "profiles", MappingProxyType(dict(resolved)))
        return result


def _risk_overlay_body_digest(body: Mapping[str, object]) -> str:
    return semantic_digest(
        body,
        contract_type="urn:gew:contract:approved-risk-overlay-body",
        projection_id="urn:gew:digest-projection:approved-risk-overlay-body:1.0.0",
        schema_id="urn:gew:schema:approved-risk-overlay-body-input:1.0.0",
    )


@dataclass(frozen=True, slots=True, init=False)
class RiskOverlayDefinition:
    overlay_id: str
    version: str
    approved_profile_registry_digest: str
    coverage_policy_digest: str
    node_additions: tuple[str, ...]
    edge_additions: tuple[str, ...]
    merge_rules: tuple[FrozenMap, ...]
    artifact_compaction_mapping: tuple[FrozenMap, ...]
    budget_policy: FrozenMap
    required_invariant_ids: tuple[str, ...]
    entry_condition_ids: tuple[str, ...]
    exit_condition_ids: tuple[str, ...]
    allowed_profile_ids: tuple[str, ...]
    forbidden_profile_ids: tuple[str, ...]
    digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RiskOverlayDefinition must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("RiskOverlayDefinition is final")

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        coverage_policy: ProfileCoveragePolicy,
    ) -> RiskOverlayDefinition:
        _require_exact_type(approved_profiles, ApprovedProfileIdentityRegistry, "approved profile registry")
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        fields = frozenset({
            "schema_version", "overlay_id", "version",
            "approved_profile_registry_digest", "coverage_policy_digest",
            "node_additions", "edge_additions", "merge_rules",
            "artifact_compaction_mapping", "budget_policy", "required_invariant_ids",
            "entry_condition_ids", "exit_condition_ids", "allowed_profile_ids",
            "forbidden_profile_ids", "digest",
        })
        record = _verify_self_digest(
            value, fields=fields, name="risk-overlay-definition", digest_field="digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("RiskOverlayDefinition schema version is unsupported")
        registry_digest = _digest(record["approved_profile_registry_digest"], "overlay registry digest")
        policy_digest = _digest(record["coverage_policy_digest"], "overlay coverage policy digest")
        if (
            not hmac.compare_digest(registry_digest, approved_profiles.registry_digest)
            or not hmac.compare_digest(policy_digest, coverage_policy.policy_digest)
        ):
            raise ProfileContractError("overlay registry or coverage policy binding changed")
        overlay_id = _text(record["overlay_id"], "risk overlay ID")
        if overlay_id not in coverage_policy.risk_path_ids:
            raise ProfileContractError("risk overlay ID is not approved")
        version = _text(record["version"], "risk overlay version")
        approval = coverage_policy.approved_risk_overlay_body(overlay_id)
        if approval["overlay_version"] != version:
            raise ProfileContractError("risk overlay version is not approved")
        node_additions = _sorted_strings(
            record["node_additions"], "overlay node additions", allow_empty=True,
        )
        edge_additions = _sorted_strings(
            record["edge_additions"], "overlay edge additions", allow_empty=True,
        )
        raw_merge_rules = record["merge_rules"]
        if type(raw_merge_rules) is not list:
            raise ProfileContractError("overlay merge rules must be an array")
        merge_rules: list[FrozenMap] = []
        merge_order: list[tuple[str, ...]] = []
        for raw_rule in raw_merge_rules:
            rule = _exact(
                raw_rule, frozenset({"operation", "logical_contract_ids"}),
                "overlay merge rule",
            )
            if rule["operation"] != "co-locate":
                raise ProfileContractError("overlay merge operation is not monotonic")
            logical_ids = _sorted_strings(
                rule["logical_contract_ids"], "overlay logical artifact IDs",
            )
            if len(logical_ids) < 2:
                raise ProfileContractError("overlay merge rule is not a real compaction")
            merge_order.append(logical_ids)
            merge_rules.append(_frozen_mapping(rule, "overlay merge rule"))
        if tuple(merge_order) != tuple(sorted(merge_order)):
            raise ProfileContractError("overlay merge rules are not canonical")
        raw_compaction = record["artifact_compaction_mapping"]
        if type(raw_compaction) is not list:
            raise ProfileContractError("overlay artifact compaction must be an array")
        compaction: list[FrozenMap] = []
        compacted_logical_ids: list[str] = []
        for raw_mapping in raw_compaction:
            mapping = _exact(
                raw_mapping,
                frozenset({"logical_contract_id", "physical_group_id"}),
                "overlay artifact compaction entry",
            )
            logical_id = _text(
                mapping["logical_contract_id"], "overlay compacted artifact ID",
            )
            _text(mapping["physical_group_id"], "overlay physical artifact group")
            if logical_id in compacted_logical_ids:
                raise ProfileContractError("overlay artifact compaction is duplicated")
            compacted_logical_ids.append(logical_id)
            compaction.append(_frozen_mapping(
                mapping, "overlay artifact compaction entry",
            ))
        if tuple(compacted_logical_ids) != tuple(sorted(compacted_logical_ids)):
            raise ProfileContractError("overlay artifact compaction is not canonical")
        merged_logical_ids = {
            logical_id for logical_ids in merge_order for logical_id in logical_ids
        }
        if merged_logical_ids != set(compacted_logical_ids):
            raise ProfileContractError("overlay compaction loses a logical artifact")
        budget = _exact(
            record["budget_policy"], frozenset({"mode", "overrides"}),
            "overlay budget policy",
        )
        budget_mode = _text(budget["mode"], "overlay budget mode")
        if budget_mode not in ("preserve", "tighten"):
            raise ProfileContractError("overlay budget mode is not monotonic")
        raw_budget_overrides = budget["overrides"]
        if budget_mode == "preserve":
            if raw_budget_overrides != []:
                raise ProfileContractError("preserving overlay changes a budget")
            budget_limits: Mapping[str, int] = MappingProxyType({})
        else:
            budget_limits = _budget_limit_map(
                raw_budget_overrides, "overlay budget overrides",
            )
        canonical_budget = {
            "mode": budget_mode,
            "overrides": [
                {"budget_id": budget_id, "maximum": maximum}
                for budget_id, maximum in budget_limits.items()
            ],
        }
        invariants = _sorted_strings(record["required_invariant_ids"], "overlay required invariants")
        if not set(coverage_policy.required_invariant_ids).issubset(invariants):
            raise ProfileContractError("risk overlay weakens the CoreInvariantSet")
        allowed = _strings(record["allowed_profile_ids"], "overlay allowed Profile IDs", allow_empty=True)
        forbidden = _strings(record["forbidden_profile_ids"], "overlay forbidden Profile IDs", allow_empty=True)
        if (
            set(allowed) & set(forbidden)
            or not set((*allowed, *forbidden)).issubset(approved_profiles.profile_ids)
        ):
            raise ProfileContractError("risk overlay Profile applicability is invalid")
        entry_conditions = _sorted_strings(
            record["entry_condition_ids"], "overlay entry conditions",
        )
        exit_conditions = _sorted_strings(
            record["exit_condition_ids"], "overlay exit conditions",
        )
        body = {
            "schema_version": "1.0.0",
            "overlay_id": overlay_id,
            "version": version,
            "node_additions": list(node_additions),
            "edge_additions": list(edge_additions),
            "merge_rules": thaw(tuple(merge_rules)),
            "artifact_compaction_mapping": thaw(tuple(compaction)),
            "budget_policy": canonical_budget,
            "required_invariant_ids": list(invariants),
            "entry_condition_ids": list(entry_conditions),
            "exit_condition_ids": list(exit_conditions),
            "allowed_profile_ids": list(allowed),
            "forbidden_profile_ids": list(forbidden),
        }
        if not hmac.compare_digest(
            _risk_overlay_body_digest(body), str(approval["approved_body_digest"]),
        ):
            raise ProfileContractError("risk overlay body is not approved")
        result = object.__new__(cls)
        values = (
            ("overlay_id", overlay_id),
            ("version", version),
            ("approved_profile_registry_digest", registry_digest),
            ("coverage_policy_digest", policy_digest),
            ("node_additions", node_additions),
            ("edge_additions", edge_additions),
            ("merge_rules", tuple(merge_rules)),
            ("artifact_compaction_mapping", tuple(compaction)),
            ("budget_policy", _frozen_mapping(
                canonical_budget, "overlay budget policy",
            )),
            ("required_invariant_ids", invariants),
            ("entry_condition_ids", entry_conditions),
            ("exit_condition_ids", exit_conditions),
            ("allowed_profile_ids", allowed),
            ("forbidden_profile_ids", forbidden),
            ("digest", _digest(record["digest"], "risk overlay digest")),
        )
        for name, item in values:
            object.__setattr__(result, name, item)
        return result


def _risk_overlay_definition_body(overlay: RiskOverlayDefinition) -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "overlay_id": overlay.overlay_id,
        "version": overlay.version,
        "node_additions": list(overlay.node_additions),
        "edge_additions": list(overlay.edge_additions),
        "merge_rules": thaw(overlay.merge_rules),
        "artifact_compaction_mapping": thaw(overlay.artifact_compaction_mapping),
        "budget_policy": thaw(overlay.budget_policy),
        "required_invariant_ids": list(overlay.required_invariant_ids),
        "entry_condition_ids": list(overlay.entry_condition_ids),
        "exit_condition_ids": list(overlay.exit_condition_ids),
        "allowed_profile_ids": list(overlay.allowed_profile_ids),
        "forbidden_profile_ids": list(overlay.forbidden_profile_ids),
    }


def _require_overlay_semantic_minimum(
    overlay: RiskOverlayDefinition,
    semantic_policy: ProfileSemanticPolicy,
) -> None:
    minimum = semantic_policy.risk_minimum_for(overlay.overlay_id)
    for field in (
        "node_additions", "edge_additions", "entry_condition_ids",
        "exit_condition_ids", "required_invariant_ids",
    ):
        expected = minimum[field]
        actual = getattr(overlay, field)
        if not isinstance(expected, tuple) or actual != expected:
            raise ProfileContractError(f"risk overlay {field} is not the approved set")
    raw_expected_budgets = minimum["budget_limits"]
    if not isinstance(raw_expected_budgets, tuple):
        raise AssertionError("risk overlay budget minimum is not immutable")
    expected_budgets = {
        str(item["budget_id"]): item["maximum"]
        for item in raw_expected_budgets if isinstance(item, FrozenMap)
    }
    actual_budgets = dict(semantic_policy.project_tightening_policy.base_budget_limits)
    for item in overlay.budget_policy["overrides"]:
        if not isinstance(item, FrozenMap):
            raise ProfileContractError("risk overlay budget authority is invalid")
        actual_budgets[str(item["budget_id"])] = item["maximum"]
    if actual_budgets != expected_budgets:
        raise ProfileContractError("risk overlay budget limits are not the approved set")


@dataclass(frozen=True, slots=True, init=False)
class RiskOverlayDefinitionSet:
    overlay_ids: tuple[str, ...]
    overlays: Mapping[str, RiskOverlayDefinition]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RiskOverlayDefinitionSet must be issued from closed definitions")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("RiskOverlayDefinitionSet is final")

    @classmethod
    def from_documents(
        cls,
        definitions: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        semantic_policy: ProfileSemanticPolicy,
    ) -> RiskOverlayDefinitionSet:
        _require_exact_type(
            approved_profiles, ApprovedProfileIdentityRegistry,
            "approved profile registry",
        )
        _require_exact_type(
            semantic_policy, ProfileSemanticPolicy, "Profile semantic policy",
        )
        if type(definitions) is not tuple or any(
            type(item) is not RiskOverlayDefinition for item in definitions
        ):
            raise ProfileContractError("risk overlay set contains a forged member")
        overlay_ids = tuple(item.overlay_id for item in definitions)
        if overlay_ids != semantic_policy.risk_path_ids:
            raise ProfileContractError("risk overlay set is not exact")
        if len(overlay_ids) != len(set(overlay_ids)):
            raise ProfileContractError("risk overlay set contains duplicates")
        resolved: dict[str, RiskOverlayDefinition] = {}
        for overlay in definitions:
            if (
                not hmac.compare_digest(
                    overlay.approved_profile_registry_digest,
                    approved_profiles.registry_digest,
                )
                or not hmac.compare_digest(
                    overlay.coverage_policy_digest,
                    semantic_policy.coverage_policy_digest,
                )
                or not set(semantic_policy.core_invariant_ids).issubset(
                    overlay.required_invariant_ids
                )
            ):
                raise ProfileContractError("risk overlay set binding changed")
            _require_overlay_semantic_minimum(overlay, semantic_policy)
            resolved[overlay.overlay_id] = overlay
        result = object.__new__(cls)
        object.__setattr__(result, "overlay_ids", overlay_ids)
        object.__setattr__(result, "overlays", MappingProxyType(dict(resolved)))
        return result


@dataclass(frozen=True, slots=True, init=False)
class SupportMatrixDefinition:
    matrix_id: str
    version: str
    approved_profile_registry_digest: str
    coverage_policy_digest: str
    profile_ids: tuple[str, ...]
    profile_column_ids: tuple[str, ...]
    risk_path_ids: tuple[str, ...]
    profile_case_ids: tuple[str, ...]
    scenario_case_ids: tuple[str, ...]
    case_bindings: Mapping[str, FrozenMap]
    digest: str
    _coverage_policy: ProfileCoveragePolicy

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SupportMatrixDefinition must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SupportMatrixDefinition is final")

    @classmethod
    def from_json(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        coverage_policy: ProfileCoveragePolicy,
    ) -> SupportMatrixDefinition:
        return cls.from_dict(
            _strict_json_object(value, "SupportMatrixDefinition"),
            approved_profiles=approved_profiles,
            coverage_policy=coverage_policy,
        )

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        approved_profiles: ApprovedProfileIdentityRegistry,
        coverage_policy: ProfileCoveragePolicy,
    ) -> SupportMatrixDefinition:
        _require_exact_type(approved_profiles, ApprovedProfileIdentityRegistry, "approved profile registry")
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        fields = frozenset({
            "schema_version", "matrix_id", "version", "approved_profile_registry_digest",
            "coverage_policy_digest", "profile_ids", "profile_column_ids", "risk_path_ids",
            "profile_case_ids", "scenario_case_ids", "case_bindings", "digest",
        })
        record = _verify_self_digest(
            value, fields=fields, name="support-matrix-definition", digest_field="digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("SupportMatrixDefinition schema version is unsupported")
        registry_digest = _digest(record["approved_profile_registry_digest"], "matrix registry digest")
        policy_digest = _digest(record["coverage_policy_digest"], "matrix coverage policy digest")
        if (
            not hmac.compare_digest(registry_digest, approved_profiles.registry_digest)
            or not hmac.compare_digest(policy_digest, coverage_policy.policy_digest)
        ):
            raise ProfileContractError("support matrix registry or policy binding changed")
        profiles = _strings(
            record["profile_ids"], "support matrix Profile IDs",
            canonical_order=approved_profiles.profile_ids,
        )
        columns = _strings(
            record["profile_column_ids"], "support matrix columns",
            canonical_order=coverage_policy.profile_column_ids,
        )
        risk_paths = _strings(
            record["risk_path_ids"], "support matrix risk paths",
            canonical_order=coverage_policy.risk_path_ids,
        )
        profile_cases = _sorted_strings(record["profile_case_ids"], "support matrix Profile cases")
        scenario_cases = _sorted_strings(record["scenario_case_ids"], "support matrix scenario cases")
        if profile_cases != coverage_policy.profile_case_ids():
            raise ProfileContractError("support matrix Profile case set is incomplete or unknown")
        if scenario_cases != coverage_policy.scenario_case_ids():
            raise ProfileContractError("support matrix scenario case set is incomplete or unknown")
        raw_bindings = record["case_bindings"]
        if type(raw_bindings) is not list:
            raise ProfileContractError("support matrix case bindings must be an array")
        bindings: dict[str, FrozenMap] = {}
        for raw in raw_bindings:
            binding = _exact(
                raw,
                frozenset({"test_id", "fixture_id", "oracle_id", "evidence_type", "owner_gate"}),
                "support matrix case binding",
            )
            for field in ("test_id", "fixture_id", "oracle_id", "evidence_type", "owner_gate"):
                _text(binding[field], f"support matrix {field}")
            test_id = str(binding["test_id"])
            if test_id in bindings:
                raise ProfileContractError("support matrix case binding is duplicated")
            expected_binding = coverage_policy.expected_case_binding(test_id)
            if freeze(binding) != expected_binding:
                raise ProfileContractError("support matrix case binding is not authoritative")
            bindings[test_id] = _frozen_mapping(binding, "support matrix case binding")
        expected_cases = frozenset((*profile_cases, *scenario_cases))
        if frozenset(bindings) != expected_cases:
            raise ProfileContractError("support matrix case bindings are not exact")
        result = object.__new__(cls)
        values = (
            ("matrix_id", _text(record["matrix_id"], "support matrix ID")),
            ("version", _text(record["version"], "support matrix version")),
            ("approved_profile_registry_digest", registry_digest),
            ("coverage_policy_digest", policy_digest),
            ("profile_ids", profiles),
            ("profile_column_ids", columns),
            ("risk_path_ids", risk_paths),
            ("profile_case_ids", profile_cases),
            ("scenario_case_ids", scenario_cases),
            ("case_bindings", MappingProxyType(dict(bindings))),
            ("digest", _digest(record["digest"], "support matrix digest")),
            ("_coverage_policy", coverage_policy),
        )
        for name, item in values:
            object.__setattr__(result, name, item)
        return result

    def expected_plan_selector(self, test_id: str) -> FrozenMap:
        if test_id not in self.case_bindings:
            raise ProfileContractError(
                "coverage plan selector is outside the support matrix"
            )
        return self._coverage_policy.expected_plan_selector(test_id)


@dataclass(frozen=True, slots=True, init=False)
class EvidenceObservationRegistry:
    registry_id: str
    oracle_manifest_sha256: str
    observations: Mapping[str, FrozenMap]
    registry_digest: str
    _coverage_policy: ProfileCoveragePolicy

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EvidenceObservationRegistry must be loaded from pinned configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("EvidenceObservationRegistry is final")

    @classmethod
    def from_json(
        cls,
        value: object,
        *,
        coverage_policy: ProfileCoveragePolicy,
        oracle_manifest_bytes: object,
    ) -> EvidenceObservationRegistry:
        return cls.from_dict(
            _strict_json_object(value, "EvidenceObservationRegistry"),
            coverage_policy=coverage_policy,
            oracle_manifest_bytes=oracle_manifest_bytes,
        )

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        coverage_policy: ProfileCoveragePolicy,
        oracle_manifest_bytes: object,
    ) -> EvidenceObservationRegistry:
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        if type(oracle_manifest_bytes) is not bytes:
            raise ProfileContractError("oracle manifest must be exact installed bytes")
        authority_pin = coverage_policy.evidence_authority
        expected_pin = _digest(
            authority_pin["registry_digest"], "evidence observation registry pin",
        )
        raw_manifest_sha256 = hashlib.sha256(oracle_manifest_bytes).hexdigest()
        if not hmac.compare_digest(
            raw_manifest_sha256, str(authority_pin["oracle_manifest_sha256"]),
        ):
            raise ProfileContractError("oracle manifest does not match installation authority")
        manifest = _exact(
            _strict_json_object(oracle_manifest_bytes, "oracle manifest"),
            frozenset({
                "schema_version", "manifest_id", "oracles", "fault_schedules",
                "trust_plane_network_counters",
            }),
            "oracle manifest",
        )
        raw_oracles = manifest["oracles"]
        if type(raw_oracles) is not list:
            raise ProfileContractError("oracle manifest entries are invalid")
        oracle_ids: list[str] = []
        for raw_oracle in raw_oracles:
            oracle = _exact(
                raw_oracle,
                frozenset({"oracle_id", "implementation", "independent_state"}),
                "oracle manifest entry",
            )
            oracle_ids.append(_text(oracle["oracle_id"], "oracle manifest ID"))
        if len(oracle_ids) != len(set(oracle_ids)):
            raise ProfileContractError("oracle manifest identity is duplicated")
        expected_profile_oracles = tuple(
            str(coverage_policy.case_binding_profiles[profile_id]["oracle_id"])
            for profile_id in coverage_policy.scenarios
        )
        if tuple(oracle_id for oracle_id in oracle_ids if oracle_id.startswith("ORA-PROFILE-")) != expected_profile_oracles:
            raise ProfileContractError("oracle manifest does not exactly resolve approved Profiles")
        record = _verify_self_digest(
            value,
            fields=frozenset({
                "schema_version", "registry_id", "oracle_manifest_sha256",
                "observations", "registry_digest",
            }),
            name="profile-evidence-observation-registry",
            digest_field="registry_digest",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("evidence observation registry version is unsupported")
        registry_manifest_sha256 = _text(
            record["oracle_manifest_sha256"], "evidence observation oracle manifest SHA-256",
        )
        if not hmac.compare_digest(registry_manifest_sha256, raw_manifest_sha256):
            raise ProfileContractError("evidence observation oracle manifest is stale")
        raw_observations = record["observations"]
        if type(raw_observations) is not list or not raw_observations:
            raise ProfileContractError("evidence observation registry is empty or invalid")
        observations: dict[str, FrozenMap] = {}
        ordered_ids: list[str] = []
        fields = frozenset({
            "test_id", "fixture_id", "oracle_id", "evidence_type", "owner_gate",
            "execution_kind", "observer_kind", "evidence_member",
            "evidence_bytes_sha256",
        })
        for raw in raw_observations:
            item = _exact(raw, fields, "evidence observation registration")
            test_id = _text(item["test_id"], "evidence observation test ID")
            if test_id in observations:
                raise ProfileContractError("evidence observation registration is duplicated")
            ordered_ids.append(test_id)
            expected = coverage_policy.expected_case_binding(test_id)
            for field in ("fixture_id", "oracle_id", "evidence_type", "owner_gate"):
                if item[field] != expected[field]:
                    raise ProfileContractError("evidence observation binding is not authoritative")
            if item["execution_kind"] != coverage_policy.expected_execution_kind(test_id):
                raise ProfileContractError("evidence observation execution kind is stale")
            observer_kind = _text(item["observer_kind"], "evidence observer kind")
            evidence_member = _text(item["evidence_member"], "evidence member")
            if pathlib.PurePosixPath(evidence_member).name != evidence_member:
                raise ProfileContractError("evidence member is not a portable local name")
            if (
                item["execution_kind"] == coverage_policy.real_e2e_execution_kind
                and observer_kind != "authoritative-target-observer"
            ):
                raise ProfileContractError("real E2E evidence lacks an authoritative target observer")
            raw_sha256 = _text(item["evidence_bytes_sha256"], "evidence bytes SHA-256")
            if _RAW_SHA256.fullmatch(raw_sha256) is None:
                raise ProfileContractError("evidence bytes SHA-256 is invalid")
            observations[test_id] = _frozen_mapping(item, "evidence observation registration")
        if tuple(ordered_ids) != tuple(sorted(ordered_ids)):
            raise ProfileContractError("evidence observation registry order is not canonical")
        registry_digest = _digest(record["registry_digest"], "evidence observation registry digest")
        if not hmac.compare_digest(registry_digest, expected_pin):
            raise ProfileContractError("evidence observation registry does not match its pin")
        result = object.__new__(cls)
        for name, item in (
            ("registry_id", _text(record["registry_id"], "evidence observation registry ID")),
            ("oracle_manifest_sha256", registry_manifest_sha256),
            ("observations", MappingProxyType(dict(observations))),
            ("registry_digest", registry_digest),
            ("_coverage_policy", coverage_policy),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class EvidenceObservation:
    test_id: str
    matrix_digest: str
    profile_id: str
    profile_version: str
    profile_digest: str
    overlay_id: str
    overlay_version: str
    overlay_digest: str
    runtime_kind: str
    runtime_lineage_id: str
    runtime_digest: str
    fixture_id: str
    oracle_id: str
    evidence_type: str
    owner_gate: str
    evidence_ref: str
    evidence_digest: str
    execution_kind: str
    observer_kind: str
    registry_digest: str
    observation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EvidenceObservation can only be issued by its resolver")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("EvidenceObservation is final")


class EvidenceObservationAuthority:
    """Attest current pinned evidence through descriptor-safe local-name reads."""

    def __init__(self, registry: EvidenceObservationRegistry, *, evidence_root: object) -> None:
        _require_exact_type(registry, EvidenceObservationRegistry, "evidence observation registry")
        if type(evidence_root) is not pathlib.PosixPath:
            raise ProfileContractError("evidence root must be an exact local path")
        self._registry = registry
        self._registry_policy = registry._coverage_policy
        self._evidence_root = evidence_root
        try:
            named_root = os.stat(evidence_root, follow_symlinks=False)
            root_descriptor = os.open(
                evidence_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                opened_root = os.fstat(root_descriptor)
            finally:
                os.close(root_descriptor)
        except OSError as error:
            raise ProfileContractError("evidence root is unavailable or unsafe") from error
        if (
            not stat.S_ISDIR(named_root.st_mode)
            or not stat.S_ISDIR(opened_root.st_mode)
            or named_root.st_uid != os.getuid()
            or opened_root.st_uid != os.getuid()
            or (named_root.st_dev, named_root.st_ino)
            != (opened_root.st_dev, opened_root.st_ino)
        ):
            raise ProfileContractError("evidence root identity is untrusted")
        self._evidence_root_identity = (opened_root.st_dev, opened_root.st_ino)
        self.__issued: dict[
            int, tuple[EvidenceObservation, str, tuple[int, int], str]
        ] = {}

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("EvidenceObservationAuthority is final")

    def _read_current(self, registration: FrozenMap) -> tuple[bytes, tuple[int, int]]:
        member = str(registration["evidence_member"])
        root_descriptor = os.open(
            self._evidence_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        descriptor: int | None = None
        try:
            opened_root = os.fstat(root_descriptor)
            if (opened_root.st_dev, opened_root.st_ino) != self._evidence_root_identity:
                raise ProfileContractError("evidence root was replaced")
            named = os.stat(member, dir_fd=root_descriptor, follow_symlinks=False)
            descriptor = os.open(
                member,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_descriptor,
            )
            opened = os.fstat(descriptor)
            identity = (opened.st_dev, opened.st_ino)
            if (
                not stat.S_ISREG(named.st_mode)
                or not stat.S_ISREG(opened.st_mode)
                or named.st_uid != os.getuid()
                or opened.st_uid != os.getuid()
                or named.st_nlink != 1
                or opened.st_nlink != 1
                or stat.S_IMODE(named.st_mode) & 0o022
                or (named.st_dev, named.st_ino) != identity
            ):
                raise ProfileContractError("evidence member identity or mode is untrusted")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            body = b"".join(chunks)
            rebound = os.stat(member, dir_fd=root_descriptor, follow_symlinks=False)
            if (rebound.st_dev, rebound.st_ino) != identity or os.fstat(descriptor).st_size != len(body):
                raise ProfileContractError("evidence member changed during observation")
            actual = hashlib.sha256(body).hexdigest()
            if not hmac.compare_digest(actual, str(registration["evidence_bytes_sha256"])):
                raise ProfileContractError("evidence bytes differ from the current registry")
            return body, identity
        except OSError as error:
            raise ProfileContractError("evidence member is unavailable or unsafe") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(root_descriptor)

    def observe(
        self,
        test_id: object,
        *,
        matrix: SupportMatrixDefinition,
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
    ) -> EvidenceObservation:
        _require_exact_type(matrix, SupportMatrixDefinition, "support matrix")
        _require_exact_type(profile, ProfileDefinition, "Profile definition")
        _require_exact_type(overlay, RiskOverlayDefinition, "risk overlay definition")
        test = _text(test_id, "evidence observation test ID")
        registration = self._registry.observations.get(test)
        if registration is None:
            raise ProfileContractError("evidence observation is not registered as current")
        evidence_bytes, file_identity = self._read_current(registration)
        raw_sha256 = hashlib.sha256(evidence_bytes).hexdigest()
        evidence = _exact(
            _strict_json_object(evidence_bytes, "profile evidence"),
            frozenset({
                "schema_version", "test_id", "outcome", "assertions_resolved",
                "fixture_id", "oracle_id", "evidence_type", "owner_gate",
                "execution_kind", "observer",
            }),
            "profile evidence",
        )
        observer = _exact(
            evidence["observer"],
            frozenset({
                "observer_id", "observer_kind", "observed_target", "fresh_query",
                "identity_verified",
            }),
            "profile evidence observer",
        )
        for field in ("observer_id", "observer_kind", "observed_target"):
            _text(observer[field], f"profile evidence observer {field}")
        if (
            evidence["schema_version"] != "1.0.0"
            or evidence["test_id"] != test
            or evidence["outcome"] != "PASS"
            or evidence["assertions_resolved"] is not True
            or observer["fresh_query"] is not True
            or observer["identity_verified"] is not True
        ):
            raise ProfileContractError("profile evidence is not a resolved current PASS")
        for field in ("fixture_id", "oracle_id", "evidence_type", "owner_gate", "execution_kind"):
            if evidence[field] != registration[field]:
                raise ProfileContractError("profile evidence registration binding changed")
        if observer["observer_kind"] != registration["observer_kind"]:
            raise ProfileContractError("profile evidence observer binding changed")
        expected_profile_id = self._registry.observations[test]["fixture_id"]
        if expected_profile_id != f"profile:{profile.profile_id}:{profile.version}":
            raise ProfileContractError("profile evidence fixture identity is stale")
        body = {
            "schema_version": "1.0.0",
            "registry_digest": self._registry.registry_digest,
            "evidence_bytes_sha256": raw_sha256,
            "evidence": thaw(freeze(evidence)),
            "matrix_digest": matrix.digest,
            "profile_digest": profile.digest,
            "overlay_digest": overlay.digest,
        }
        observation_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:evidence-observation",
            projection_id="urn:gew:digest-projection:evidence-observation:1.0.0",
            schema_id="urn:gew:schema:evidence-observation-input:1.0.0",
        )
        result = object.__new__(EvidenceObservation)
        values = {
            "test_id": test,
            "matrix_digest": matrix.digest,
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "profile_digest": profile.digest,
            "overlay_id": overlay.overlay_id,
            "overlay_version": overlay.version,
            "overlay_digest": overlay.digest,
            "runtime_kind": str(self._registry_policy.runtime_pins["runtime_kind"]),
            "runtime_lineage_id": str(
                self._registry_policy.runtime_pins["runtime_lineage_id"]
            ),
            "runtime_digest": str(self._registry_policy.runtime_pins["runtime_digest"]),
            **{
                field: str(evidence[field]) for field in (
                    "fixture_id", "oracle_id", "evidence_type", "owner_gate",
                    "execution_kind",
                )
            },
        }
        values.update({
            "evidence_ref": "evidence-bytes-sha256:" + raw_sha256,
            "evidence_digest": "sha256:" + raw_sha256,
            "observer_kind": str(observer["observer_kind"]),
            "registry_digest": self._registry.registry_digest,
            "observation_digest": observation_digest,
        })
        for name, item in values.items():
            object.__setattr__(result, name, item)
        self.__issued[id(result)] = (
            result, observation_digest, file_identity, test,
        )
        return result

    def require_issued(self, observation: object) -> EvidenceObservation:
        _require_exact_type(observation, EvidenceObservation, "evidence observation")
        issued = self.__issued.get(id(observation))
        if issued is None or issued[0] is not observation:
            raise ProfileContractError("evidence observation is not factory-issued and current")
        _original, expected, file_identity, test = issued
        if not hmac.compare_digest(expected, observation.observation_digest):
            raise ProfileContractError("evidence observation digest is stale")
        if not hmac.compare_digest(observation.registry_digest, self._registry.registry_digest):
            raise ProfileContractError("evidence observation registry is stale")
        registration = self._registry.observations[test]
        _body, current_identity = self._read_current(registration)
        if current_identity != file_identity:
            raise ProfileContractError("evidence member was replaced after observation")
        return observation


@dataclass(frozen=True, slots=True, init=False)
class CoverageRecord:
    test_id: str
    matrix_digest: str
    profile_id: str
    profile_version: str
    profile_digest: str
    overlay_id: str
    overlay_version: str
    overlay_digest: str
    runtime_kind: str
    runtime_lineage_id: str
    runtime_digest: str
    fixture_id: str
    oracle_id: str
    evidence_type: str
    owner_gate: str
    evidence_ref: str
    evidence_digest: str
    execution_kind: str
    record_digest: str
    _capability: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CoverageRecord can only be issued by its validating factory")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CoverageRecord is final")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            **{
                field: getattr(self, field)
                for field in (
                    "test_id", "matrix_digest", "profile_id", "profile_version",
                    "profile_digest", "overlay_id", "overlay_version", "overlay_digest",
                    "runtime_kind", "runtime_lineage_id", "runtime_digest", "fixture_id",
                    "oracle_id", "evidence_type", "owner_gate", "evidence_ref",
                    "evidence_digest", "execution_kind", "record_digest",
                )
            },
        }

_RELEASE_COVERAGE_GATE_CAPABILITY = object()


class _CoverageAbortCapability:
    """Opaque process-local authority for one frozen uncommitted candidate."""

    __slots__ = ()

    def __new__(cls) -> _CoverageAbortCapability:
        del cls
        raise TypeError("coverage abort capability is factory-issued")

    def __reduce_ex__(self, protocol: int) -> object:
        del self, protocol
        raise TypeError("coverage abort capability is not serializable")


@dataclass(frozen=True, slots=True, eq=False)
class _CoverageAbortPreparation:
    generation: int
    projection_version: int
    projection_digest: str
    registrations: tuple[tuple[object, object, object], ...]
    records: tuple[tuple[CoverageRecord, str, int], ...]
    capability: _CoverageAbortCapability


class CoverageRecordFactory:
    """Issue and attest coverage records from resolver-issued observations only."""

    def __init__(
        self,
        *,
        authority: EvidenceObservationAuthority | None = None,
        execution_authority: object | None = None,
        coverage_policy: ProfileCoveragePolicy,
    ) -> None:
        _require_exact_type(coverage_policy, ProfileCoveragePolicy, "profile coverage policy")
        if (authority is None) == (execution_authority is None):
            raise ProfileContractError("exactly one coverage record authority is required")
        self.__lifecycle_lock = threading.RLock()
        self.__lifecycle: tuple[str, object | None] = (
            "active-uncommitted",
            None,
        )
        self.__candidate_generation = 0
        registrations: tuple[tuple[object, object, object], ...] = ()
        if authority is not None:
            if type(authority) is not EvidenceObservationAuthority:
                raise ProfileContractError("coverage record authority is missing or forged")
            if authority._registry_policy is not coverage_policy:
                raise ProfileContractError("coverage record authority policy identity changed")
        else:
            from graph_engineering.core.profile_coverage import (
                ProfileCoverageAuthorityRegistration,
            )

            authorities = (
                execution_authority
                if type(execution_authority) is tuple
                else (execution_authority,)
            )
            if not authorities or len({id(item) for item in authorities}) != len(authorities):
                raise ProfileContractError("production coverage authorities are not unique")
            validated: list[tuple[object, object, object]] = []
            for production_authority in authorities:
                registration = getattr(
                    production_authority, "_coverage_registration", None,
                )
                if (
                    type(registration) is not ProfileCoverageAuthorityRegistration
                    or registration._authority is not production_authority
                ):
                    raise ProfileContractError(
                        "production coverage record authority is missing or forged"
                    )
                try:
                    lifecycle_capability = registration._register_factory(
                        production_authority, self,
                    )
                except ValueError as error:
                    raise ProfileContractError(
                        "production coverage lifecycle authority is unavailable"
                    ) from error
                validated.append((
                    production_authority,
                    registration,
                    lifecycle_capability,
                ))
            registrations = tuple(validated)
        self._authority = authority
        self._execution_registrations = registrations
        self._production_backed = bool(registrations)
        self._coverage_policy = coverage_policy
        self.__issued: dict[
            int, tuple[CoverageRecord, object, str, FrozenMap, object]
        ] = {}

    def _require_current(self, *, issuing: bool = False) -> None:
        with self.__lifecycle_lock:
            allowed = (
                {"active-uncommitted"}
                if issuing
                else {"active-uncommitted", "combined-gate-consumed"}
            )
            if self.__lifecycle[0] not in allowed:
                raise ProfileContractError("coverage record factory is closed")

    def _register_authority_capability(
        self,
        authority: object,
        registration: object,
        capability: object,
    ) -> None:
        with self.__lifecycle_lock:
            if self.__lifecycle[0] != "active-uncommitted":
                raise ProfileContractError(
                    "coverage candidate authority registration is closed"
                )
            register = getattr(
                authority, "_register_factory_capability", None
            )
            if not callable(register):
                raise ProfileContractError(
                    "coverage candidate authority is unavailable"
                )
            register(registration, self, capability)

    def _bind_combined_gate(
        self,
        decision: object,
        *,
        matrix: SupportMatrixDefinition,
        coverage_records: tuple[CoverageRecord, ...],
        capability: object,
    ) -> None:
        from graph_engineering.core.profile_coverage import (
            ProfileCoverageExecutionPlan,
        )

        with self.__lifecycle_lock:
            if capability is not _RELEASE_COVERAGE_GATE_CAPABILITY:
                raise ProfileContractError(
                    "coverage gate lifecycle authority is foreign"
                )
            self._require_current()
            if not self._production_backed or not self._execution_registrations:
                return
            plans = tuple(
                registration._plan
                for _authority, registration, _capability
                in self._execution_registrations
            )
            if (
                not plans
                or any(plan is not plans[0] for plan in plans)
                or type(plans[0]) is not ProfileCoverageExecutionPlan
            ):
                raise ProfileContractError(
                    "production coverage plan authority is foreign"
                )
            expected_ids = frozenset(plans[0].bindings)
            issued = tuple(item[0] for item in self.__issued.values())
            issued_by_identity = {id(item): item for item in issued}
            if (
                len(issued_by_identity) != len(issued)
                or len(coverage_records) != len(issued)
                or {id(item) for item in coverage_records}
                != set(issued_by_identity)
                or frozenset(item.test_id for item in coverage_records)
                != expected_ids
                or len(coverage_records) != len(expected_ids)
            ):
                return
            binding = (
                decision,
                matrix.digest,
                tuple(sorted(id(item) for item in coverage_records)),
                tuple(sorted(item.record_digest for item in coverage_records)),
            )
            if self.__lifecycle[0] == "active-uncommitted":
                self.__lifecycle = ("combined-gate-consumed", binding)

    def _current_abort_projection(
        self,
    ) -> tuple[
        tuple[tuple[object, object, object], ...],
        tuple[tuple[CoverageRecord, str, int], ...],
        str,
    ]:
        registrations = self._execution_registrations
        authority_ordinals = {
            id(authority): ordinal
            for ordinal, (authority, _registration, _capability)
            in enumerate(registrations)
        }
        registration_projection: list[dict[str, object]] = []
        for ordinal, (authority, registration, _capability) in enumerate(
            registrations
        ):
            plan = getattr(registration, "_plan", None)
            plan_digest = getattr(plan, "plan_digest", None)
            if type(plan_digest) is not str:
                raise ProfileContractError(
                    "coverage abort registration projection is stale"
                )
            registration_projection.append({
                "authority_kind": (
                    f"{type(authority).__module__}.{type(authority).__name__}"
                ),
                "ordinal": ordinal,
                "plan_digest": plan_digest,
            })
        records: list[tuple[CoverageRecord, str, int]] = []
        record_projection: list[dict[str, object]] = []
        for issued in self.__issued.values():
            record, observation, _matrix_digest, projection, _capability = issued
            authority_ordinal = authority_ordinals.get(
                id(getattr(observation, "_authority", None))
            )
            if authority_ordinal is None or freeze(record.to_dict()) != projection:
                raise ProfileContractError(
                    "coverage abort record projection is stale"
                )
            records.append((record, record.record_digest, authority_ordinal))
            record_projection.append({
                "authority_ordinal": authority_ordinal,
                "record": record.to_dict(),
            })
        records.sort(key=lambda item: (item[0].test_id, item[1]))
        record_projection.sort(
            key=lambda item: (
                str(item["record"]["test_id"]),
                str(item["record"]["record_digest"]),
            )
        )
        body = {
            "schema_version": "1.0.0",
            "candidate_generation": self.__candidate_generation,
            "projection_version": self.__candidate_generation,
            "coverage_policy_digest": self._coverage_policy.policy_digest,
            "registrations": registration_projection,
            "records": record_projection,
        }
        projection_digest = hashlib.sha256(
            json.dumps(
                body,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return registrations, tuple(records), projection_digest

    def _freeze_abort_preparation(self) -> _CoverageAbortPreparation:
        registrations, records, projection_digest = (
            self._current_abort_projection()
        )
        capability = object.__new__(_CoverageAbortCapability)
        return _CoverageAbortPreparation(
            generation=self.__candidate_generation,
            projection_version=self.__candidate_generation,
            projection_digest=projection_digest,
            registrations=registrations,
            records=records,
            capability=capability,
        )

    @staticmethod
    def _return_prepared_abort_capability(
        capability: _CoverageAbortCapability,
    ) -> _CoverageAbortCapability:
        return capability

    def prepare_abort_uncommitted_candidate(self) -> object:
        with self.__lifecycle_lock:
            state, payload = self.__lifecycle
            if state == "abort-prepared":
                if type(payload) is not _CoverageAbortPreparation:
                    raise ProfileContractError(
                        "coverage abort preparation is substituted"
                    )
                return self._return_prepared_abort_capability(
                    payload.capability
                )
            if state != "active-uncommitted":
                raise ProfileContractError(
                    "coverage candidate cannot enter abort preparation"
                )
            if not self._production_backed or not self._execution_registrations:
                raise ProfileContractError(
                    "coverage abort requires production-backed authority"
                )
            preparation = self._freeze_abort_preparation()
            self.__lifecycle = ("abort-prepared", preparation)
            return self._return_prepared_abort_capability(
                preparation.capability
            )

    @staticmethod
    def _same_registration_snapshot(
        left: tuple[tuple[object, object, object], ...],
        right: tuple[tuple[object, object, object], ...],
    ) -> bool:
        return len(left) == len(right) and all(
            all(a is b for a, b in zip(left_item, right_item, strict=True))
            for left_item, right_item in zip(left, right, strict=True)
        )

    def _require_abort_preparation_current(
        self,
        preparation: _CoverageAbortPreparation,
    ) -> None:
        registrations, records, projection_digest = (
            self._current_abort_projection()
        )
        if (
            self.__candidate_generation != preparation.generation
            or preparation.projection_version != preparation.generation
            or not hmac.compare_digest(
                projection_digest, preparation.projection_digest
            )
            or not self._same_registration_snapshot(
                registrations, preparation.registrations
            )
            or len(records) != len(preparation.records)
            or any(
                observed[0] is not expected[0]
                or observed[1:] != expected[1:]
                for observed, expected in zip(
                    records, preparation.records, strict=True
                )
            )
        ):
            raise ProfileContractError(
                "coverage abort frozen projection changed"
            )

    def abort_uncommitted_candidate(self, capability: object) -> None:
        with self.__lifecycle_lock:
            state, payload = self.__lifecycle
            if state == "aborted":
                if capability is payload:
                    return
                raise ProfileContractError(
                    "coverage abort capability is foreign"
                )
            if state == "abort-prepared":
                if (
                    type(payload) is not _CoverageAbortPreparation
                    or type(capability) is not _CoverageAbortCapability
                    or capability is not payload.capability
                ):
                    raise ProfileContractError(
                        "coverage abort capability is foreign"
                    )
                self._require_abort_preparation_current(payload)
                self.__lifecycle = ("aborting", (payload, 0))
                preparation = payload
                next_registration = 0
            elif state == "aborting":
                if (
                    type(payload) is not tuple
                    or len(payload) != 2
                    or type(payload[0]) is not _CoverageAbortPreparation
                    or type(payload[1]) is not int
                    or type(capability) is not _CoverageAbortCapability
                    or capability is not payload[0].capability
                ):
                    raise ProfileContractError(
                        "coverage abort capability is foreign"
                    )
                preparation = payload[0]
                next_registration = payload[1]
            else:
                raise ProfileContractError(
                    "coverage candidate is not abort-prepared"
                )

            while next_registration < len(preparation.registrations):
                authority, registration, registration_capability = (
                    preparation.registrations[next_registration]
                )
                try:
                    registration._revoke(
                        authority,
                        self,
                        registration_capability,
                        "revoke",
                    )
                except Exception as error:
                    raise ProfileContractError(
                        "coverage abort revocation is incomplete"
                    ) from error
                next_registration += 1
                self.__lifecycle = (
                    "aborting",
                    (preparation, next_registration),
                )

            self.__issued.clear()
            self._authority = None
            self._execution_registrations = ()
            self.__lifecycle = ("aborted", preparation.capability)

    def finalize_after_gate(self, decision: object) -> None:
        with self.__lifecycle_lock:
            state, payload = self.__lifecycle
            if state == "finalized":
                if (
                    type(payload) is tuple
                    and payload
                    and decision is payload[0]
                ):
                    return
                raise ProfileContractError(
                    "coverage lifecycle decision is foreign"
                )
            if (
                state != "combined-gate-consumed"
                or type(payload) is not tuple
                or not payload
                or decision is not payload[0]
            ):
                raise ProfileContractError(
                    "combined coverage gate was not consumed"
                )
            binding = payload
            self.__lifecycle = ("closing", binding)
            first_error: Exception | None = None
            registrations = self._execution_registrations
            try:
                for authority, registration, capability in registrations:
                    try:
                        registration._revoke(
                            authority, self, capability, "finalize",
                        )
                    except Exception as error:
                        if first_error is None:
                            first_error = error
            finally:
                self.__issued.clear()
                self._authority = None
                self._execution_registrations = ()
                self.__lifecycle = ("finalized", binding)
            if first_error is not None:
                raise ProfileContractError(
                    "coverage authority lifecycle closed with revocation failure"
                ) from first_error

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CoverageRecordFactory is final")

    def issue_json(self, value: object, **kwargs: object) -> CoverageRecord:
        self._require_current(issuing=True)
        del value, kwargs
        raise ProfileContractError("CoverageRecord issue does not accept caller JSON")

    def issue(
        self,
        observation: object,
        *,
        matrix: SupportMatrixDefinition,
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
    ) -> CoverageRecord:
        self._require_current(issuing=True)
        _require_exact_type(matrix, SupportMatrixDefinition, "support matrix")
        _require_exact_type(profile, ProfileDefinition, "Profile definition")
        _require_exact_type(overlay, RiskOverlayDefinition, "risk overlay definition")
        if self._authority is None:
            raise ProfileContractError("static evidence cannot enter production coverage")
        observed = self._authority.require_issued(observation)
        return self._issue_observed(
            observed,
            matrix=matrix,
            profile=profile,
            overlay=overlay,
        )

    def issue_execution(
        self,
        observation: object,
        *,
        matrix: SupportMatrixDefinition,
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
    ) -> CoverageRecord:
        self._require_current(issuing=True)
        _require_exact_type(matrix, SupportMatrixDefinition, "support matrix")
        _require_exact_type(profile, ProfileDefinition, "Profile definition")
        _require_exact_type(overlay, RiskOverlayDefinition, "risk overlay definition")
        from graph_engineering.core.profile_coverage import ProfileCoverageObservation

        if type(observation) is not ProfileCoverageObservation:
            raise ProfileContractError("production execution authority is unavailable")
        registration_binding = next(
            (
                (authority, registration)
                for authority, registration, _capability
                in self._execution_registrations
                if observation._authority is authority
            ),
            None,
        )
        if registration_binding is None:
            raise ProfileContractError("production execution authority is foreign")
        try:
            observed = registration_binding[1].require_observation(
                registration_binding[0],
                observation,
                purpose="use",
            )
        except ValueError as error:
            raise ProfileContractError(
                "production coverage observation is missing or stale"
            ) from error
        return self._issue_observed(
            observed,
            matrix=matrix,
            profile=profile,
            overlay=overlay,
            precommit=lambda: registration_binding[1].require_observation(
                registration_binding[0],
                observation,
                purpose="precommit",
            ),
        )

    def _issue_observed(
        self,
        observed: object,
        *,
        matrix: SupportMatrixDefinition,
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
        precommit: object | None = None,
    ) -> CoverageRecord:
        with self.__lifecycle_lock:
            self._require_current(issuing=True)
            return self._issue_observed_unlocked(
                observed,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
                precommit=precommit,
            )

    def _issue_observed_unlocked(
        self,
        observed: object,
        *,
        matrix: SupportMatrixDefinition,
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
        precommit: object | None = None,
    ) -> CoverageRecord:
        coverage_policy = self._coverage_policy
        if (
            not hmac.compare_digest(matrix.coverage_policy_digest, coverage_policy.policy_digest)
            or not hmac.compare_digest(profile.coverage_policy_digest, coverage_policy.policy_digest)
            or not hmac.compare_digest(overlay.coverage_policy_digest, coverage_policy.policy_digest)
        ):
            raise ProfileContractError("CoverageRecord coverage policy is stale")
        test_id = observed.test_id
        expected_profile_id = coverage_policy.profile_for_case_id(test_id)
        expected_column_id = coverage_policy.column_for_case_id(test_id)
        expected_scenario_id = next(
            (
                scenario_id
                for scenario_id in coverage_policy.scenarios[expected_profile_id]
                if test_id in {
                    f"GEW-PSC-{expected_profile_id.upper()}-"
                    f"{scenario_id.upper()}-P",
                    f"GEW-PSC-{expected_profile_id.upper()}-"
                    f"{scenario_id.upper()}-R",
                }
            ),
            None,
        )
        expected_profile_binding = coverage_policy.case_binding_profiles[expected_profile_id]
        if (
            observed.profile_id != expected_profile_id
            or observed.profile_version != expected_profile_binding["profile_version"]
            or profile.profile_id != expected_profile_id
            or observed.profile_id != profile.profile_id
            or observed.profile_version != profile.version
        ):
            raise ProfileContractError("CoverageRecord Profile identity is stale")
        if self._production_backed:
            mandatory_selector = (
                expected_column_id is not None
                and expected_scenario_id is None
                and getattr(observed, "selector_kind", None) == "mandatory"
                and getattr(observed, "column_id", None) == expected_column_id
                and getattr(observed, "scenario_id", None) is None
                and getattr(observed, "category_boundary_case_id", None) is None
            )
            scenario_selector = (
                expected_column_id is None
                and expected_scenario_id is not None
                and getattr(observed, "selector_kind", None) == "scenario"
                and getattr(observed, "column_id", None) == "boundary"
                and getattr(observed, "scenario_id", None) == expected_scenario_id
                and getattr(observed, "category_boundary_case_id", None)
                == (
                    f"GEW-PSC-{expected_profile_id.upper()}-"
                    f"{expected_scenario_id.upper()}-P"
                )
            )
            if not (mandatory_selector or scenario_selector):
                raise ProfileContractError("CoverageRecord column identity is stale")
            for field in ("plan_digest", "plan_selector_digest"):
                _digest(getattr(observed, field, None), f"CoverageRecord {field}")
            if observed.evidence_ref != (
                "profile-coverage-execution:" + observed.evidence_digest
            ):
                raise ProfileContractError("CoverageRecord evidence reference is stale")
        expected_binding = coverage_policy.expected_case_binding(test_id)
        for field in ("fixture_id", "oracle_id", "evidence_type", "owner_gate"):
            if getattr(observed, field) != expected_binding[field]:
                raise ProfileContractError("CoverageRecord binding is not authoritative")
        for field in ("evidence_ref", "execution_kind"):
            _text(getattr(observed, field), f"CoverageRecord {field}")
        for field in (
            "matrix_digest", "profile_digest", "overlay_digest", "runtime_digest",
            "evidence_digest",
        ):
            value = getattr(observed, field)
            if field == "evidence_digest":
                if _OBJECT_DIGEST.fullmatch(value) is None:
                    raise ProfileContractError("CoverageRecord evidence digest is invalid")
            else:
                _digest(value, f"CoverageRecord {field}")
        current_pins = {
            "matrix_digest": matrix.digest,
            "profile_digest": profile.digest,
            "overlay_digest": overlay.digest,
            "runtime_digest": coverage_policy.runtime_pins["runtime_digest"],
        }
        for field, expected in current_pins.items():
            if not hmac.compare_digest(getattr(observed, field), str(expected)):
                raise ProfileContractError(f"CoverageRecord {field} is stale")
        for field, expected in (
            ("overlay_id", overlay.overlay_id),
            ("overlay_version", overlay.version),
            ("runtime_kind", coverage_policy.runtime_pins["runtime_kind"]),
            ("runtime_lineage_id", coverage_policy.runtime_pins["runtime_lineage_id"]),
        ):
            if getattr(observed, field) != expected:
                raise ProfileContractError(f"CoverageRecord {field} is stale")
        if overlay.overlay_id not in profile.compatible_risk_paths:
            raise ProfileContractError("CoverageRecord overlay is incompatible")
        if observed.execution_kind != coverage_policy.expected_execution_kind(test_id):
            raise ProfileContractError("CoverageRecord real E2E execution is not authoritative")
        body = {
            "schema_version": "1.0.0",
            **{
                field: getattr(observed, field)
                for field in (
                    "test_id", "matrix_digest", "profile_id", "profile_version",
                    "profile_digest", "overlay_id", "overlay_version", "overlay_digest",
                    "runtime_kind", "runtime_lineage_id", "runtime_digest", "fixture_id",
                    "oracle_id", "evidence_type", "owner_gate", "evidence_ref",
                    "evidence_digest", "execution_kind",
                )
            },
        }
        if precommit is not None:
            try:
                current_observation = precommit() if callable(precommit) else None
            except ValueError as error:
                raise ProfileContractError(
                    "CoverageRecord precommit authority is stale"
                ) from error
            if current_observation is not observed:
                raise ProfileContractError(
                    "CoverageRecord precommit authority is stale"
                )
        issued = object.__new__(CoverageRecord)
        capability = object()
        for name, item in (
            *((field, str(getattr(observed, field))) for field in (
                "test_id", "matrix_digest", "profile_id", "profile_version",
                "profile_digest", "overlay_id", "overlay_version", "overlay_digest",
                "runtime_kind", "runtime_lineage_id", "runtime_digest", "fixture_id",
                "oracle_id", "evidence_type", "owner_gate", "evidence_ref",
                "evidence_digest", "execution_kind",
            )),
            ("record_digest", semantic_digest(
                body,
                contract_type="urn:gew:contract:coverage-record",
                projection_id="urn:gew:digest-projection:coverage-record:1.0.0",
                schema_id="urn:gew:schema:coverage-record-input:1.0.0",
            )),
            ("_capability", capability),
        ):
            object.__setattr__(issued, name, item)
        projection = freeze(issued.to_dict())
        if not isinstance(projection, FrozenMap):
            raise AssertionError("coverage record projection did not freeze")
        self.__issued[id(issued)] = (
            issued, observed, matrix.digest, projection, capability,
        )
        self.__candidate_generation += 1
        return issued

    def require_issued(
        self,
        record: object,
        *,
        matrix: SupportMatrixDefinition,
        purpose: str = "gate",
    ) -> CoverageRecord:
        with self.__lifecycle_lock:
            self._require_current()
            return self._require_issued_unlocked(
                record, matrix=matrix, purpose=purpose,
            )

    def _require_issued_unlocked(
        self,
        record: object,
        *,
        matrix: SupportMatrixDefinition,
        purpose: str = "gate",
    ) -> CoverageRecord:
        _require_exact_type(record, CoverageRecord, "coverage record")
        issued = self.__issued.get(id(record))
        if issued is None or issued[0] is not record:
            raise ProfileContractError("coverage record is not factory-issued")
        _original, observation, matrix_digest, projection, capability = issued
        if record._capability is not capability or freeze(record.to_dict()) != projection:
            raise ProfileContractError("coverage record immutable projection changed")
        if self._authority is not None:
            self._authority.require_issued(observation)
        elif self._execution_registrations:
            authority = getattr(observation, "_authority", None)
            registration_binding = next(
                (
                    (candidate, registration)
                    for candidate, registration, _capability
                    in self._execution_registrations
                    if authority is candidate
                ),
                None,
            )
            if registration_binding is None:
                raise ProfileContractError("production coverage observation is foreign")
            try:
                registration_binding[1].require_observation(
                    registration_binding[0],
                    observation,
                    purpose=purpose,
                )
            except ValueError as error:
                raise ProfileContractError(
                    "production coverage observation is stale"
                ) from error
        else:
            raise ProfileContractError("coverage record authority disappeared")
        fields = (
            "test_id", "matrix_digest", "profile_id", "profile_version",
            "profile_digest", "overlay_id", "overlay_version", "overlay_digest",
            "runtime_kind", "runtime_lineage_id", "runtime_digest", "fixture_id",
            "oracle_id", "evidence_type", "owner_gate", "evidence_ref",
            "evidence_digest", "execution_kind",
        )
        if (
            not hmac.compare_digest(matrix_digest, matrix.digest)
            or not hmac.compare_digest(record.matrix_digest, matrix.digest)
            or any(getattr(record, field) != getattr(observation, field) for field in fields)
        ):
            raise ProfileContractError("coverage record authority is stale")
        expected_digest = semantic_digest(
            {
                "schema_version": "1.0.0",
                **{field: getattr(record, field) for field in fields},
            },
            contract_type="urn:gew:contract:coverage-record",
            projection_id="urn:gew:digest-projection:coverage-record:1.0.0",
            schema_id="urn:gew:schema:coverage-record-input:1.0.0",
        )
        if not hmac.compare_digest(record.record_digest, expected_digest):
            raise ProfileContractError("coverage record self digest changed")
        return record


@dataclass(frozen=True, slots=True)
class ReleaseCoverageDecision:
    passed: bool
    missing_test_ids: tuple[str, ...]
    invalid_test_ids: tuple[str, ...]
    stale_test_ids: tuple[str, ...]
    assessment_digest: str


class ReleaseCoverageGate:
    """Pure fail-closed assessment; it has no record-issuance or storage capability."""

    @staticmethod
    def evaluate(
        matrix: SupportMatrixDefinition,
        *,
        coverage_records: tuple[CoverageRecord, ...],
        coverage_factory: CoverageRecordFactory,
    ) -> ReleaseCoverageDecision:
        _require_exact_type(matrix, SupportMatrixDefinition, "support matrix")
        if type(coverage_factory) is not CoverageRecordFactory:
            raise ProfileContractError("coverage record factory is missing or forged")
        if type(coverage_records) is not tuple or any(
            type(item) is not CoverageRecord for item in coverage_records
        ):
            raise ProfileContractError("coverage records must be factory-issued records")
        for item in coverage_records:
            coverage_factory.require_issued(item, matrix=matrix)
        effective_records = (
            coverage_records if coverage_factory._production_backed else ()
        )
        expected = frozenset((*matrix.profile_case_ids, *matrix.scenario_case_ids))
        record_ids = tuple(item.test_id for item in effective_records)
        actual = frozenset(record_ids)
        missing = tuple(sorted(expected - actual))
        invalid: set[str] = set(actual - expected)
        stale: set[str] = set()
        if len(record_ids) != len(actual):
            invalid.update(
                test_id for test_id in actual if record_ids.count(test_id) != 1
            )
        for item in effective_records:
            if not hmac.compare_digest(item.matrix_digest, matrix.digest):
                stale.add(item.test_id)
        invalid_ids = tuple(sorted(invalid))
        stale_ids = tuple(sorted(stale))
        passed = not missing and not invalid_ids and not stale_ids
        body = {
            "schema_version": "1.0.0",
            "matrix_digest": matrix.digest,
            "passed": passed,
            "missing_test_ids": list(missing),
            "invalid_test_ids": list(invalid_ids),
            "stale_test_ids": list(stale_ids),
            "coverage_record_digests": sorted(
                item.record_digest for item in effective_records
            ),
        }
        decision = ReleaseCoverageDecision(
            passed,
            missing,
            invalid_ids,
            stale_ids,
            semantic_digest(
                body,
                contract_type="urn:gew:contract:release-coverage-assessment",
                projection_id="urn:gew:digest-projection:release-coverage-assessment:1.0.0",
                schema_id="urn:gew:schema:release-coverage-assessment:1.0.0",
            ),
        )
        coverage_factory._bind_combined_gate(
            decision,
            matrix=matrix,
            coverage_records=coverage_records,
            capability=_RELEASE_COVERAGE_GATE_CAPABILITY,
        )
        return decision


class _MaterializationRecordIssuer:
    def __init__(self) -> None:
        self.__issued: dict[int, MaterializationRecord] = {}

    def issue(self, record: MaterializationRecord) -> None:
        self.__issued[id(record)] = record

    def require(self, record: MaterializationRecord) -> None:
        if self.__issued.get(id(record)) is not record:
            raise ProfileContractError("materialization record is missing or forged")


def _materialization_graph_ref_body(value: object) -> FrozenMap:
    fields = frozenset({
        "graph_id", "graph_version", "graph_digest", "profile_id",
        "profile_version", "risk_path", "profile_digest", "overlay_id",
        "overlay_version", "overlay_digest", "project_config_digest",
        "support_matrix_digest", "materialization_digest",
    })
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProfileContractError("materialization graph ref is not exact")
    normalized = {field: value[field] for field in fields}
    for field in (
        "graph_id", "graph_version", "profile_id", "profile_version", "risk_path",
        "overlay_id", "overlay_version",
    ):
        _text(normalized[field], f"materialization graph ref {field}")
    for field in (
        "graph_digest", "profile_digest", "overlay_digest", "project_config_digest",
        "support_matrix_digest", "materialization_digest",
    ):
        _digest(normalized[field], f"materialization graph ref {field}")
    if normalized["risk_path"] != normalized["overlay_id"]:
        raise ProfileContractError("materialization graph ref overlay identity changed")
    frozen = freeze(normalized)
    if not isinstance(frozen, FrozenMap):
        raise AssertionError("materialization graph ref did not freeze")
    return frozen


def _materialization_output_body(value: object) -> FrozenMap:
    output = _exact(
        value,
        frozenset({
            "node_ids", "edge_ids", "artifact_contract_ids", "validator_ids",
            "completion_predicate_ids", "required_invariant_ids", "budget_limits",
        }),
        "materialization output",
    )
    normalized: dict[str, object] = {}
    for field in (
        "node_ids", "edge_ids", "artifact_contract_ids", "validator_ids",
        "completion_predicate_ids", "required_invariant_ids",
    ):
        normalized[field] = list(_sorted_strings(
            output[field], f"materialization output {field}", allow_empty=True,
        ))
    raw_budgets = output["budget_limits"]
    if type(raw_budgets) is not dict or not raw_budgets:
        raise ProfileContractError("materialization output budgets are invalid")
    budgets: dict[str, int] = {}
    for budget_id, maximum in raw_budgets.items():
        normalized_id = _text(budget_id, "materialization output budget ID")
        if type(maximum) is not int or maximum <= 0:
            raise ProfileContractError("materialization output budget is invalid")
        budgets[normalized_id] = maximum
    if tuple(budgets) != tuple(sorted(budgets)):
        raise ProfileContractError("materialization output budgets are not canonical")
    normalized["budget_limits"] = budgets
    frozen = freeze(normalized)
    if not isinstance(frozen, FrozenMap):
        raise AssertionError("materialization output did not freeze")
    return frozen


def _materialization_digest_for(
    graph_ref: Mapping[str, object], output: FrozenMap,
) -> str:
    body = {
        "schema_version": "1.0.0",
        "graph_id": graph_ref["graph_id"],
        "graph_version": graph_ref["graph_version"],
        "profile_id": graph_ref["profile_id"],
        "profile_version": graph_ref["profile_version"],
        "overlay_id": graph_ref["overlay_id"],
        "overlay_version": graph_ref["overlay_version"],
        "digest_pins": {
            "base_graph_digest": graph_ref["graph_digest"],
            "profile_digest": graph_ref["profile_digest"],
            "overlay_digest": graph_ref["overlay_digest"],
            "project_config_digest": graph_ref["project_config_digest"],
            "support_matrix_digest": graph_ref["support_matrix_digest"],
        },
        "output": thaw(output),
    }
    return semantic_digest(
        body,
        contract_type="urn:gew:contract:profile-materialization",
        projection_id="urn:gew:digest-projection:profile-materialization:1.0.0",
        schema_id="urn:gew:schema:profile-materialization-input:1.0.0",
    )


@dataclass(frozen=True, slots=True, init=False)
class MaterializationRecord:
    graph_ref_body: Mapping[str, object]
    output_body: Mapping[str, object]
    loop_budget_registry_id: str
    loop_budget_registry_digest: str
    record_digest: str
    object_digest: str
    _issuer: _MaterializationRecordIssuer

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("MaterializationRecord can only be issued by ProfileMaterializer")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("MaterializationRecord is final")

    def to_dict(self) -> dict[str, object]:
        self.require_issued()
        return {
            "schema_version": "1.0.0",
            "graph_ref": thaw(self.graph_ref_body),
            "output": thaw(self.output_body),
            "loop_budget_registry_id": self.loop_budget_registry_id,
            "loop_budget_registry_digest": self.loop_budget_registry_digest,
            "record_digest": self.record_digest,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(
            self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

    def require_issued(self) -> None:
        if type(self._issuer) is not _MaterializationRecordIssuer:
            raise ProfileContractError("materialization record is missing or forged")
        self._issuer.require(self)
        if not isinstance(self.graph_ref_body, FrozenMap):
            raise ProfileContractError("materialization record graph ref is forged")
        validated_graph = _materialization_graph_ref_body(self.graph_ref_body)
        if validated_graph != self.graph_ref_body:
            raise ProfileContractError("materialization record graph ref changed")
        if not isinstance(self.output_body, FrozenMap):
            raise ProfileContractError("materialization record output is forged")
        registry_id = _text(
            self.loop_budget_registry_id,
            "materialization loop budget registry ID",
        )
        registry_digest = _digest(
            self.loop_budget_registry_digest,
            "materialization loop budget registry digest",
        )
        expected_materialization = _materialization_digest_for(
            self.graph_ref_body, self.output_body,
        )
        if not hmac.compare_digest(
            str(self.graph_ref_body["materialization_digest"]),
            expected_materialization,
        ):
            raise ProfileContractError("materialization output digest changed")
        body = {
            "schema_version": "1.0.0",
            "graph_ref": thaw(self.graph_ref_body),
            "output": thaw(self.output_body),
            "loop_budget_registry_id": registry_id,
            "loop_budget_registry_digest": registry_digest,
        }
        expected_record = semantic_digest(
            body,
            contract_type="urn:gew:contract:materialization-record",
            projection_id="urn:gew:digest-projection:materialization-record:1.0.0",
            schema_id="urn:gew:schema:materialization-record-input:1.0.0",
        )
        if not hmac.compare_digest(self.record_digest, expected_record):
            raise ProfileContractError("materialization record self digest changed")
        expected_object = "sha256:" + hashlib.sha256(self.to_bytes_unchecked()).hexdigest()
        if not hmac.compare_digest(self.object_digest, expected_object):
            raise ProfileContractError("materialization record object digest changed")

    def to_bytes_unchecked(self) -> bytes:
        return json.dumps(
            {
                "schema_version": "1.0.0",
                "graph_ref": thaw(self.graph_ref_body),
                "output": thaw(self.output_body),
                "loop_budget_registry_id": self.loop_budget_registry_id,
                "loop_budget_registry_digest": self.loop_budget_registry_digest,
                "record_digest": self.record_digest,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def require_graph_ref(self, graph_ref: object) -> Mapping[str, object]:
        self.require_issued()
        if not isinstance(graph_ref, Mapping):
            raise ProfileContractError("materialized graph ref is invalid")
        if freeze(graph_ref) != self.graph_ref_body:
            raise ProfileContractError("materialized graph ref differs from its issued record")
        return graph_ref

@dataclass(frozen=True, slots=True, init=False)
class UntrustedMaterializationRecord:
    graph_ref_body: Mapping[str, object]
    output_body: Mapping[str, object]
    loop_budget_registry_id: str
    loop_budget_registry_digest: str
    record_digest: str
    object_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("untrusted materialization data must be parsed from exact bytes")

    @classmethod
    def from_persisted_bytes(
        cls, body: object, *, expected_object_digest: object,
    ) -> UntrustedMaterializationRecord:
        if type(body) is not bytes:
            raise ProfileContractError("persisted materialization record is not exact bytes")
        object_digest = _text(expected_object_digest, "materialization record object digest")
        if _OBJECT_DIGEST.fullmatch(object_digest) is None or not hmac.compare_digest(
            object_digest, "sha256:" + hashlib.sha256(body).hexdigest(),
        ):
            raise ProfileContractError("persisted materialization object digest changed")
        record = _exact(
            _strict_json_object(body, "materialization record"),
            frozenset({
                "schema_version", "graph_ref", "output",
                "loop_budget_registry_id", "loop_budget_registry_digest",
                "record_digest",
            }),
            "materialization record",
        )
        if record["schema_version"] != "1.0.0":
            raise ProfileContractError("persisted materialization record is invalid")
        frozen_graph = _materialization_graph_ref_body(record["graph_ref"])
        result = object.__new__(cls)
        frozen_output = _materialization_output_body(record["output"])
        for name, item in (
            ("graph_ref_body", frozen_graph),
            ("output_body", frozen_output),
            (
                "loop_budget_registry_id",
                _text(
                    record["loop_budget_registry_id"],
                    "materialization loop budget registry ID",
                ),
            ),
            (
                "loop_budget_registry_digest",
                _digest(
                    record["loop_budget_registry_digest"],
                    "materialization loop budget registry digest",
                ),
            ),
            ("record_digest", _digest(record["record_digest"], "materialization record digest")),
            ("object_digest", object_digest),
        ):
            object.__setattr__(result, name, item)
        expected_record = semantic_digest(
            {
                "schema_version": "1.0.0",
                "graph_ref": thaw(result.graph_ref_body),
                "output": thaw(result.output_body),
                "loop_budget_registry_id": result.loop_budget_registry_id,
                "loop_budget_registry_digest": result.loop_budget_registry_digest,
            },
            contract_type="urn:gew:contract:materialization-record",
            projection_id="urn:gew:digest-projection:materialization-record:1.0.0",
            schema_id="urn:gew:schema:materialization-record-input:1.0.0",
        )
        if not hmac.compare_digest(result.record_digest, expected_record):
            raise ProfileContractError("persisted materialization record digest changed")
        expected_materialization = _materialization_digest_for(
            result.graph_ref_body, result.output_body,
        )
        if not hmac.compare_digest(
            str(result.graph_ref_body["materialization_digest"]),
            expected_materialization,
        ):
            raise ProfileContractError("persisted materialization output digest changed")
        return result


@dataclass(frozen=True, slots=True, init=False)
class MaterializationObjectReference:
    graph_ref_body: Mapping[str, object]
    record_digest: str
    object_digest: str
    _authority: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("materialization object reference requires repository authority")

    def require_graph_ref(self, graph_ref: object) -> Mapping[str, object]:
        require = getattr(self._authority, "_require_materialization_reference", None)
        if not callable(require):
            raise ProfileContractError("materialization object reference authority is missing")
        return require(self, graph_ref)


@dataclass(frozen=True, slots=True, init=False)
class MaterializedProfileGraph:
    graph_id: str
    graph_version: str
    graph_digest: str
    profile_id: str
    profile_version: str
    overlay_id: str
    overlay_version: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    artifact_contract_ids: tuple[str, ...]
    validator_ids: tuple[str, ...]
    completion_predicate_ids: tuple[str, ...]
    required_invariant_ids: tuple[str, ...]
    budget_limits: Mapping[str, int]
    loop_budget_registry_id: str
    loop_budget_registry_digest: str
    digest_pins: Mapping[str, str]
    record: MaterializationRecord

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("MaterializedProfileGraph is emitted only by ProfileMaterializer")

    def graph_ref(self) -> Mapping[str, object]:
        self.require_issued()
        return MappingProxyType({
            "graph_id": self.graph_id,
            "graph_version": self.graph_version,
            "graph_digest": self.graph_digest,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "risk_path": self.overlay_id,
            "profile_digest": self.digest_pins["profile_digest"],
            "overlay_id": self.overlay_id,
            "overlay_version": self.overlay_version,
            "overlay_digest": self.digest_pins["overlay_digest"],
            "project_config_digest": self.digest_pins["project_config_digest"],
            "support_matrix_digest": self.digest_pins["support_matrix_digest"],
            "materialization_digest": self.digest_pins["materialization_digest"],
        })

    def require_issued(self) -> None:
        self.record.require_issued()
        expected_graph_ref = {
            "graph_id": self.graph_id,
            "graph_version": self.graph_version,
            "graph_digest": self.graph_digest,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
            "risk_path": self.overlay_id,
            "profile_digest": self.digest_pins["profile_digest"],
            "overlay_id": self.overlay_id,
            "overlay_version": self.overlay_version,
            "overlay_digest": self.digest_pins["overlay_digest"],
            "project_config_digest": self.digest_pins["project_config_digest"],
            "support_matrix_digest": self.digest_pins["support_matrix_digest"],
            "materialization_digest": self.digest_pins["materialization_digest"],
        }
        expected_output = {
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "artifact_contract_ids": list(self.artifact_contract_ids),
            "validator_ids": list(self.validator_ids),
            "completion_predicate_ids": list(self.completion_predicate_ids),
            "required_invariant_ids": list(self.required_invariant_ids),
            "budget_limits": dict(self.budget_limits),
        }
        if (
            thaw(self.record.graph_ref_body) != expected_graph_ref
            or thaw(self.record.output_body) != expected_output
            or self.record.loop_budget_registry_id != self.loop_budget_registry_id
            or not hmac.compare_digest(
                self.record.loop_budget_registry_digest,
                self.loop_budget_registry_digest,
            )
        ):
            raise ProfileContractError("materialized Profile graph authority changed")

    def require_loop_budget_registry(self, registry: LoopBudgetRegistry) -> None:
        """Revalidate the exact installed registry and materialized tightening."""

        self.require_issued()
        _require_exact_type(registry, LoopBudgetRegistry, "loop budget registry")
        budgets = []
        for budget_id in sorted(registry.budgets):
            budget = registry.resolve(budget_id)
            budgets.append({
                "schema_version": "1.0.0",
                "budget_id": budget.budget_id,
                "version": budget.version,
                "max_attempts": budget.max_attempts,
                "max_revisions": budget.max_revisions,
                "max_total_runs": budget.max_total_runs,
                "exhausted_route": budget.exhausted_route,
            })
        manifest = LoopBudgetRegistry.create_manifest(registry.registry_id, budgets)
        current_digest = semantic_digest(
            manifest,
            contract_type="urn:gew:contract:loop-budget-registry",
            projection_id="urn:gew:digest-projection:identity:1.0.0",
            schema_id="urn:gew:schema:loop-budget-registry:1.0.0",
        )
        if (
            registry.registry_id != self.loop_budget_registry_id
            or not hmac.compare_digest(registry.registry_digest, current_digest)
            or not hmac.compare_digest(
                registry.registry_digest,
                self.loop_budget_registry_digest,
            )
            or set(self.budget_limits) != set(registry.budgets)
        ):
            raise ProfileContractError(
                "materialized loop budget registry authority changed"
            )
        for budget_id, maximum in self.budget_limits.items():
            budget = registry.resolve(budget_id)
            if maximum > min(
                budget.max_attempts,
                budget.max_revisions,
                budget.max_total_runs,
            ):
                raise ProfileContractError(
                    "materialized loop budget is not a monotonic tightening"
                )


class ProfileMaterializer:
    """Deterministically bind one already-complete graph to Profile configuration."""

    @staticmethod
    def materialize(
        *,
        base_graph_document: Mapping[str, object],
        profile: ProfileDefinition,
        overlay: RiskOverlayDefinition,
        project_config: Mapping[str, object],
        approved_profiles: ApprovedProfileIdentityRegistry,
        support_matrix: SupportMatrixDefinition,
        semantic_policy: ProfileSemanticPolicy,
    ) -> MaterializedProfileGraph:
        _require_exact_type(profile, ProfileDefinition, "Profile definition")
        _require_exact_type(overlay, RiskOverlayDefinition, "risk overlay definition")
        _require_exact_type(approved_profiles, ApprovedProfileIdentityRegistry, "approved profile registry")
        _require_exact_type(support_matrix, SupportMatrixDefinition, "support matrix")
        _require_exact_type(semantic_policy, ProfileSemanticPolicy, "Profile semantic policy")
        graph = _exact(
            base_graph_document,
            frozenset({"graph_id", "graph_version", "graph_digest", "node_ids", "edge_ids"}),
            "base graph materialization input",
        )
        graph_id = _text(graph["graph_id"], "base graph ID")
        graph_version = _text(graph["graph_version"], "base graph version")
        graph_digest = _digest(graph["graph_digest"], "base graph digest")
        node_ids = _sorted_strings(graph["node_ids"], "base graph node IDs")
        edge_ids = _sorted_strings(graph["edge_ids"], "base graph edge IDs")
        if (
            profile.profile_id not in approved_profiles.profile_ids
            or not hmac.compare_digest(
                profile.approved_profile_registry_digest,
                approved_profiles.registry_digest,
            )
            or not hmac.compare_digest(
                support_matrix.approved_profile_registry_digest,
                approved_profiles.registry_digest,
            )
            or not hmac.compare_digest(
                profile.profile_semantic_policy_digest,
                semantic_policy.policy_digest,
            )
        ):
            raise ProfileContractError("materialization Profile registry or semantic binding changed")
        expected_profile_body = semantic_policy.approved_definition_body_digest_for(
            profile.profile_id, profile.version,
        )
        if not hmac.compare_digest(
            expected_profile_body, _profile_definition_body_digest(profile),
        ):
            raise ProfileContractError("materialization Profile body is not approved")
        _require_overlay_semantic_minimum(overlay, semantic_policy)
        minima = semantic_policy.minimum_for(profile.profile_id, profile.version)
        for field, actual in (
            ("required_node_ids", profile.required_node_ids),
            ("validator_ids", profile.validator_ids),
            ("completion_predicate_ids", profile.completion_predicate_ids),
            ("rollback_verification_ids", profile.rollback_contract["verification_ids"]),
        ):
            minimum = minima[field]
            if not isinstance(minimum, tuple) or not set(minimum).issubset(actual):
                raise ProfileContractError("materialized Profile weakens approved semantics")
        if not set(semantic_policy.core_invariant_ids).issubset(
            overlay.required_invariant_ids
        ):
            raise ProfileContractError("materialized overlay weakens CoreInvariantSet")
        if overlay.overlay_id not in profile.compatible_risk_paths:
            raise ProfileContractError("risk overlay is incompatible with the Profile")
        if overlay.allowed_profile_ids and profile.profile_id not in overlay.allowed_profile_ids:
            raise ProfileContractError("risk overlay does not allow the Profile")
        if profile.profile_id in overlay.forbidden_profile_ids:
            raise ProfileContractError("risk overlay forbids the Profile")
        if not set(profile.required_node_ids).issubset(node_ids):
            raise ProfileContractError("base graph is missing a required Profile node")
        if not set(profile.required_edge_ids).issubset(edge_ids):
            raise ProfileContractError("base graph is missing a required Profile edge")
        matrix_cases = set((*support_matrix.profile_case_ids, *support_matrix.scenario_case_ids))
        if not set(profile.required_case_ids).issubset(matrix_cases):
            raise ProfileContractError("support matrix is missing a required Profile case")
        if (
            not hmac.compare_digest(
                profile.coverage_policy_digest, support_matrix.coverage_policy_digest,
            )
            or not hmac.compare_digest(
                overlay.coverage_policy_digest, support_matrix.coverage_policy_digest,
            )
        ):
            raise ProfileContractError("materialization coverage policy binding changed")
        budget_limits = dict(
            semantic_policy.project_tightening_policy.base_budget_limits
        )
        overlay_budget_mode = overlay.budget_policy["mode"]
        overlay_budget_overrides = overlay.budget_policy["overrides"]
        if not isinstance(overlay_budget_overrides, tuple):
            raise ProfileContractError("overlay budget authority is invalid")
        if overlay_budget_mode == "tighten":
            for raw_override in overlay_budget_overrides:
                if not isinstance(raw_override, FrozenMap):
                    raise ProfileContractError("overlay budget authority is invalid")
                budget_id = str(raw_override["budget_id"])
                maximum = raw_override["maximum"]
                if (
                    budget_id not in budget_limits
                    or type(maximum) is not int
                    or maximum >= budget_limits[budget_id]
                ):
                    raise ProfileContractError("overlay budget does not strictly decrease")
                budget_limits[budget_id] = maximum
        elif overlay_budget_mode != "preserve":
            raise ProfileContractError("overlay budget mode is not monotonic")
        if type(project_config) is not dict:
            raise ProfileContractError("project Profile configuration must be an exact object")
        project_additions: dict[str, tuple[str, ...]] = {
            "required_node_additions": (),
            "required_edge_additions": (),
            "validator_additions": (),
            "completion_predicate_additions": (),
            "artifact_contract_additions": (),
            "required_invariant_additions": (),
        }
        project_budgets: Mapping[str, int] = MappingProxyType({})
        if project_config:
            project = _exact(
                project_config,
                frozenset({
                    "schema_version", "required_node_additions",
                    "required_edge_additions", "validator_additions",
                    "completion_predicate_additions", "artifact_contract_additions",
                    "required_invariant_additions", "budget_tightenings",
                }),
                "project Profile configuration",
            )
            if project["schema_version"] != "1.0.0":
                raise ProfileContractError("project Profile configuration version is unsupported")
            for field in project_additions:
                project_additions[field] = _sorted_strings(
                    project[field], f"project Profile {field}", allow_empty=True,
                )
            project_budgets = _budget_limit_map(
                project["budget_tightenings"], "project budget tightenings",
                allow_empty=True,
            )
            for budget_id, maximum in project_budgets.items():
                if budget_id not in budget_limits or maximum >= budget_limits[budget_id]:
                    raise ProfileContractError("project budget does not strictly decrease")
                budget_limits[budget_id] = maximum
        canonical_project = (
            {
                "schema_version": "1.0.0",
                **{
                    field: list(values)
                    for field, values in project_additions.items()
                },
                "budget_tightenings": [
                    {"budget_id": budget_id, "maximum": maximum}
                    for budget_id, maximum in (
                        project_budgets.items() if project_config else ()
                    )
                ],
            }
        )
        frozen_project = freeze(canonical_project)
        project_digest = semantic_digest(
            frozen_project,
            contract_type="urn:gew:contract:project-profile-configuration",
            projection_id="urn:gew:digest-projection:project-profile-configuration:1.0.0",
            schema_id="urn:gew:schema:project-profile-configuration-input:1.0.0",
        )
        pins = {
            "base_graph_digest": graph_digest,
            "profile_digest": profile.digest,
            "overlay_digest": overlay.digest,
            "project_config_digest": project_digest,
            "support_matrix_digest": support_matrix.digest,
        }
        output_node_ids = tuple(sorted({
            *node_ids,
            *semantic_policy.base_semantic_sets["required_node_ids"],
            *profile.required_node_ids,
            *profile.optional_node_ids,
            *overlay.node_additions,
            *project_additions["required_node_additions"],
        }))
        output_edge_ids = tuple(sorted({
            *edge_ids,
            *semantic_policy.base_semantic_sets["required_edge_ids"],
            *profile.required_edge_ids,
            *profile.optional_edge_ids,
            *overlay.edge_additions,
            *project_additions["required_edge_additions"],
        }))
        output_artifacts = tuple(sorted({
            *semantic_policy.base_semantic_sets["artifact_contract_ids"],
            *profile.artifact_contract_ids,
            *(
                str(item["logical_contract_id"])
                for item in overlay.artifact_compaction_mapping
            ),
            *project_additions["artifact_contract_additions"],
        }))
        output_validators = tuple(sorted({
            *semantic_policy.base_semantic_sets["validator_ids"],
            *profile.validator_ids,
            *project_additions["validator_additions"],
        }))
        output_completion = tuple(sorted({
            *semantic_policy.base_semantic_sets["completion_predicate_ids"],
            *profile.completion_predicate_ids,
            *project_additions["completion_predicate_additions"],
        }))
        output_invariants = tuple(sorted({
            *semantic_policy.base_semantic_sets["required_invariant_ids"],
            *semantic_policy.core_invariant_ids,
            *overlay.required_invariant_ids,
            *project_additions["required_invariant_additions"],
        }))
        canonical_budgets = {
            budget_id: budget_limits[budget_id] for budget_id in sorted(budget_limits)
        }
        output = {
            "node_ids": list(output_node_ids),
            "edge_ids": list(output_edge_ids),
            "artifact_contract_ids": list(output_artifacts),
            "validator_ids": list(output_validators),
            "completion_predicate_ids": list(output_completion),
            "required_invariant_ids": list(output_invariants),
            "budget_limits": dict(canonical_budgets),
        }
        materialization_body = {
            "schema_version": "1.0.0",
            "graph_id": graph_id,
            "graph_version": graph_version,
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "overlay_id": overlay.overlay_id,
            "overlay_version": overlay.version,
            "digest_pins": dict(pins),
            "output": output,
        }
        pins["materialization_digest"] = semantic_digest(
            materialization_body,
            contract_type="urn:gew:contract:profile-materialization",
            projection_id="urn:gew:digest-projection:profile-materialization:1.0.0",
            schema_id="urn:gew:schema:profile-materialization-input:1.0.0",
        )
        record_graph_ref = {
            "graph_id": graph_id,
            "graph_version": graph_version,
            "graph_digest": graph_digest,
            "profile_id": profile.profile_id,
            "profile_version": profile.version,
            "risk_path": overlay.overlay_id,
            "profile_digest": pins["profile_digest"],
            "overlay_id": overlay.overlay_id,
            "overlay_version": overlay.version,
            "overlay_digest": pins["overlay_digest"],
            "project_config_digest": pins["project_config_digest"],
            "support_matrix_digest": pins["support_matrix_digest"],
            "materialization_digest": pins["materialization_digest"],
        }
        frozen_record_graph = freeze(record_graph_ref)
        if not isinstance(frozen_record_graph, FrozenMap):
            raise AssertionError("materialization record graph ref did not freeze")
        frozen_output = _materialization_output_body(output)
        record_body = {
            "schema_version": "1.0.0",
            "graph_ref": record_graph_ref,
            "output": output,
            "loop_budget_registry_id": (
                semantic_policy.project_tightening_policy.loop_budget_registry_id
            ),
            "loop_budget_registry_digest": (
                semantic_policy.project_tightening_policy.loop_budget_registry_digest
            ),
        }
        record_digest = semantic_digest(
            record_body,
            contract_type="urn:gew:contract:materialization-record",
            projection_id="urn:gew:digest-projection:materialization-record:1.0.0",
            schema_id="urn:gew:schema:materialization-record-input:1.0.0",
        )
        issuer = _MaterializationRecordIssuer()
        record = object.__new__(MaterializationRecord)
        for name, item in (
            ("graph_ref_body", frozen_record_graph),
            ("output_body", frozen_output),
            (
                "loop_budget_registry_id",
                semantic_policy.project_tightening_policy.loop_budget_registry_id,
            ),
            (
                "loop_budget_registry_digest",
                semantic_policy.project_tightening_policy.loop_budget_registry_digest,
            ),
            ("record_digest", record_digest),
            ("object_digest", ""),
            ("_issuer", issuer),
        ):
            object.__setattr__(record, name, item)
        object.__setattr__(
            record,
            "object_digest",
            "sha256:" + hashlib.sha256(record.to_bytes_unchecked()).hexdigest(),
        )
        issuer.issue(record)
        record.require_issued()
        result = object.__new__(MaterializedProfileGraph)
        for name, item in (
            ("graph_id", graph_id),
            ("graph_version", graph_version),
            ("graph_digest", graph_digest),
            ("profile_id", profile.profile_id),
            ("profile_version", profile.version),
            ("overlay_id", overlay.overlay_id),
            ("overlay_version", overlay.version),
            ("node_ids", output_node_ids),
            ("edge_ids", output_edge_ids),
            ("artifact_contract_ids", output_artifacts),
            ("validator_ids", output_validators),
            ("completion_predicate_ids", output_completion),
            ("required_invariant_ids", output_invariants),
            ("budget_limits", MappingProxyType(dict(canonical_budgets))),
            (
                "loop_budget_registry_id",
                semantic_policy.project_tightening_policy.loop_budget_registry_id,
            ),
            (
                "loop_budget_registry_digest",
                semantic_policy.project_tightening_policy.loop_budget_registry_digest,
            ),
            ("digest_pins", MappingProxyType(dict(pins))),
            ("record", record),
        ):
            object.__setattr__(result, name, item)
        return result
