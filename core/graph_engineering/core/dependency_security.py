"""Closed ADR-0006 dependency-advisory data and monotonic update semantics."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw


DEPENDENCY_SECURITY_SCHEMA_IDS = tuple(sorted({
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
}))

DEPENDENCY_GRAPH_SCHEMA_IDS = tuple(sorted({
    "urn:gew:schema:dependency-graph-policy-registry:1.0.0",
    "urn:gew:schema:dependency-graph-policy-registry-input:1.0.0",
    "urn:gew:schema:dependency-closure-graph-observation:1.0.0",
    "urn:gew:schema:dependency-closure-graph-observation-input:1.0.0",
    "urn:gew:schema:dependency-remediation-disposition-registry:1.0.0",
    "urn:gew:schema:dependency-remediation-disposition-registry-input:1.0.0",
    "urn:gew:schema:dependency-security-observation:1.1.0",
    "urn:gew:schema:dependency-security-observation-input:1.1.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0",
    "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0",
}))


class DependencySecurityError(ValueError):
    """A dependency-advisory contract or authority failed closed."""


@dataclass(frozen=True, slots=True)
class DependencyGraphPolicyData:
    registry_id: str
    registry_digest: str
    marker_environment: FrozenMap
    document: FrozenMap

    def to_dict(self) -> dict[str, object]:
        value = thaw(self.document)
        if not isinstance(value, dict):
            raise AssertionError("dependency graph policy did not thaw")
        return value


@dataclass(frozen=True, slots=True)
class DependencyRemediationRegistryData:
    registry_id: str
    registry_digest: str
    dispositions: tuple[FrozenMap, ...]
    document: FrozenMap

    def to_dict(self) -> dict[str, object]:
        value = thaw(self.document)
        if not isinstance(value, dict):
            raise AssertionError("dependency remediation registry did not thaw")
        return value


def _exact(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise DependencySecurityError(f"{label} properties are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "\x00" in value
        or not value.isascii()
    ):
        raise DependencySecurityError(f"{label} is invalid")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1 or value > 9_007_199_254_740_991:
        raise DependencySecurityError(f"{label} is invalid")
    return value


def _raw(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(item not in "0123456789abcdef" for item in result):
        raise DependencySecurityError(f"{label} is not a lowercase SHA-256")
    return result


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise DependencySecurityError(f"{label} is not a semantic digest")
    return result


def _timestamp(value: object, label: str) -> datetime:
    result = _text(value, label)
    if not result.endswith("Z"):
        raise DependencySecurityError(f"{label} is not an exact UTC timestamp")
    try:
        parsed = datetime.fromisoformat(result[:-1] + "+00:00")
    except ValueError as error:
        raise DependencySecurityError(f"{label} is invalid") from error
    if parsed.tzinfo != timezone.utc or parsed.microsecond:
        raise DependencySecurityError(f"{label} is not an exact UTC second")
    return parsed


def _self_digest(document: Mapping[str, object], name: str, field: str) -> str:
    expected = _digest(document.get(field), f"{name} digest")
    body = thaw(freeze(document))
    if not isinstance(body, dict):
        raise AssertionError("dependency record did not copy")
    del body[field]
    actual = semantic_digest(
        freeze(body),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise DependencySecurityError(f"{name} self digest changed")
    return expected


def _ordered_unique(values: object, key: object, label: str) -> tuple[Mapping[str, object], ...]:
    if type(values) is not list or not values:
        raise DependencySecurityError(f"{label} must be a non-empty array")
    records = tuple(
        item if type(item) is dict else _invalid_mapping(label)
        for item in values
    )
    identities = tuple(key(item) for item in records)  # type: ignore[operator]
    if identities != tuple(sorted(set(identities))):
        raise DependencySecurityError(f"{label} must be canonical and unique")
    return records


def _invalid_mapping(label: str) -> Mapping[str, object]:
    raise DependencySecurityError(f"{label} member is invalid")


_GRAPH_POLICY_FIELDS = frozenset({
    "schema_version", "registry_id", "root_distribution_policy",
    "marker_environment_policy", "edge_order_policy", "registry_digest",
})
_ROOT_POLICY_FIELDS = frozenset({
    "root_kind", "root_distribution_name", "require_exact_reachable_closure",
})
_MARKER_POLICY_FIELDS = frozenset({
    "packaging_version", "environment",
})
_MARKER_ROW_FIELDS = frozenset({"name", "value"})
_EDGE_POLICY_FIELDS = frozenset({"order", "edge_identity_fields"})
_REMEDIATION_REGISTRY_FIELDS = frozenset({
    "schema_version", "registry_id", "dispositions", "registry_digest",
})
_REMEDIATION_FIELDS = frozenset({
    "disposition_id", "advisory_id", "advisory_revision",
    "graph_policy_digest", "status", "reason_code", "residual_policy_id",
    "owner_route", "expires_at", "disposition_digest",
})


def parse_dependency_graph_policy_registry(value: object) -> DependencyGraphPolicyData:
    """Parse the exact config-owned offline graph derivation policy."""

    policy = _exact(value, _GRAPH_POLICY_FIELDS, "dependency graph policy")
    if policy["schema_version"] != "1.0.0":
        raise DependencySecurityError("dependency graph policy version is unsupported")
    registry_id = _text(policy["registry_id"], "dependency graph policy ID")
    root = _exact(
        policy["root_distribution_policy"],
        _ROOT_POLICY_FIELDS,
        "dependency root policy",
    )
    if (
        root["root_kind"] != "candidate-wheel"
        or not _text(root["root_distribution_name"], "dependency root distribution")
        or type(root["require_exact_reachable_closure"]) is not bool
        or root["require_exact_reachable_closure"] is not True
    ):
        raise DependencySecurityError("dependency root policy is unsupported")
    marker = _exact(
        policy["marker_environment_policy"],
        _MARKER_POLICY_FIELDS,
        "dependency marker policy",
    )
    if marker["packaging_version"] != "26.3":
        raise DependencySecurityError("dependency marker parser version is unsupported")
    rows = _ordered_unique(
        marker["environment"],
        lambda item: item.get("name"),
        "dependency marker environment",
    )
    environment: dict[str, str] = {}
    for row in rows:
        exact = _exact(row, _MARKER_ROW_FIELDS, "dependency marker row")
        name = _text(exact["name"], "dependency marker name")
        value = exact["value"]
        if (
            type(value) is not str
            or value != value.strip()
            or "\x00" in value
            or not value.isascii()
            or (not value and name != "extra")
        ):
            raise DependencySecurityError("dependency marker value is invalid")
        environment[name] = value
    edge = _exact(
        policy["edge_order_policy"],
        _EDGE_POLICY_FIELDS,
        "dependency edge policy",
    )
    required_edge_fields = (
        "parent_distribution", "child_distribution", "requirement_row_digest",
    )
    if (
        edge["order"] != "parent-child-requirement-digest"
        or type(edge["edge_identity_fields"]) is not list
        or tuple(edge["edge_identity_fields"]) != required_edge_fields
    ):
        raise DependencySecurityError("dependency edge order policy is unsupported")
    registry_digest = _self_digest(
        policy, "dependency-graph-policy-registry", "registry_digest"
    )
    frozen = freeze(policy)
    marker_environment = freeze(environment)
    if not isinstance(frozen, FrozenMap) or not isinstance(marker_environment, FrozenMap):
        raise AssertionError("dependency graph policy did not freeze")
    return DependencyGraphPolicyData(
        registry_id, registry_digest, marker_environment, frozen,
    )


def parse_dependency_remediation_registry(
    value: object,
) -> DependencyRemediationRegistryData:
    """Parse explicit remediation dispositions without inferring missing fixes."""

    registry = _exact(
        value, _REMEDIATION_REGISTRY_FIELDS, "dependency remediation registry"
    )
    if registry["schema_version"] != "1.0.0":
        raise DependencySecurityError(
            "dependency remediation registry version is unsupported"
        )
    registry_id = _text(registry["registry_id"], "remediation registry ID")
    rows = _ordered_unique(
        registry["dispositions"],
        lambda item: item.get("disposition_id"),
        "dependency remediation dispositions",
    )
    frozen_rows: list[FrozenMap] = []
    for row in rows:
        exact = _exact(row, _REMEDIATION_FIELDS, "dependency remediation row")
        _text(exact["disposition_id"], "dependency disposition ID")
        _text(exact["advisory_id"], "dependency disposition advisory ID")
        _positive(exact["advisory_revision"], "dependency disposition revision")
        _digest(exact["graph_policy_digest"], "dependency graph policy digest")
        status = exact["status"]
        if status not in {"approved-fixed-closure", "approved-unavailable"}:
            raise DependencySecurityError("dependency disposition status is invalid")
        _text(exact["reason_code"], "dependency disposition reason")
        _text(exact["residual_policy_id"], "dependency residual policy ID")
        owner_route = exact["owner_route"]
        if status == "approved-unavailable":
            _text(owner_route, "dependency residual owner route")
        elif owner_route is not None:
            raise DependencySecurityError(
                "fixed dependency disposition cannot own residual exposure"
            )
        _timestamp(exact["expires_at"], "dependency disposition expiry")
        _self_digest(
            exact,
            "dependency-remediation-disposition",
            "disposition_digest",
        )
        frozen = freeze(exact)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("dependency remediation row did not freeze")
        frozen_rows.append(frozen)
    registry_digest = _self_digest(
        registry,
        "dependency-remediation-disposition-registry",
        "registry_digest",
    )
    frozen_registry = freeze(registry)
    if not isinstance(frozen_registry, FrozenMap):
        raise AssertionError("dependency remediation registry did not freeze")
    return DependencyRemediationRegistryData(
        registry_id, registry_digest, tuple(frozen_rows), frozen_registry,
    )


_SOURCE_FIELDS = frozenset({
    "schema_version", "source_id", "source_revision", "issuer_id", "issued_at",
    "not_before", "not_after", "source_artifact_raw_sha256",
    "source_attestation_digest", "source_record_digest",
})
_PIN_FIELDS = frozenset({
    "distribution_name", "distribution_version", "wheel_raw_sha256",
    "record_raw_sha256",
})
_CLOSURE_FIELDS = frozenset({
    "schema_version", "closure_id", "root_distribution_name", "root_version",
    "required_distribution_pins", "security_regression_command_id", "closure_digest",
})
_ADVISORY_FIELDS = frozenset({
    "schema_version", "advisory_id", "advisory_revision", "source_id",
    "source_revision", "ecosystem", "distribution_name",
    "affected_version_specifiers", "applicability_kind", "fixed_closures",
    "residual_exposure_policy_id", "security_regression_policy_id", "advisory_digest",
})
_SOURCE_STATE_FIELDS = frozenset({
    "source_id", "source_revision", "status", "status_generation",
})
_ADVISORY_STATE_FIELDS = frozenset({
    "advisory_id", "advisory_revision", "status", "status_generation",
})
_HIGH_WATER_FIELDS = frozenset({
    "schema_version", "generation", "source_states", "advisory_states",
    "high_water_digest",
})
_REGISTRY_FIELDS = frozenset({
    "schema_version", "registry_id", "generation", "update_kind",
    "previous_registry_digest", "rollback_of_registry_digest",
    "revocation_high_water", "source_records", "advisories", "registry_digest",
})


@dataclass(frozen=True, slots=True)
class DependencyAdvisoryRegistryData:
    registry_id: str
    generation: int
    registry_digest: str
    document: FrozenMap

    def to_dict(self) -> dict[str, object]:
        value = thaw(self.document)
        if not isinstance(value, dict):
            raise AssertionError("dependency registry did not thaw")
        return value


@dataclass(frozen=True, slots=True)
class DependencyEvaluationRow:
    advisory_id: str
    advisory_revision: int
    disposition: str
    advisory_digest: str
    source_record_digest: str | None
    matched_before_version: str | None
    matched_after_closure_id: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "advisory_id": self.advisory_id,
            "advisory_revision": self.advisory_revision,
            "disposition": self.disposition,
            "advisory_digest": self.advisory_digest,
            "source_record_digest": self.source_record_digest,
            "matched_before_version": self.matched_before_version,
            "matched_after_closure_id": self.matched_after_closure_id,
        }


@dataclass(frozen=True, slots=True)
class DependencyEvaluation:
    registry_digest: str
    rows: tuple[DependencyEvaluationRow, ...]
    active_advisory_ids: tuple[str, ...]
    residual_advisory_ids: tuple[str, ...]
    evaluation_digest: str


def _validate_source(value: Mapping[str, object]) -> tuple[str, int]:
    source = _exact(value, _SOURCE_FIELDS, "dependency advisory source")
    if source["schema_version"] != "1.0.0":
        raise DependencySecurityError("dependency advisory source version is unsupported")
    identity = (
        _text(source["source_id"], "source ID"),
        _positive(source["source_revision"], "source revision"),
    )
    _text(source["issuer_id"], "source issuer")
    issued = _timestamp(source["issued_at"], "source issued_at")
    not_before = _timestamp(source["not_before"], "source not_before")
    not_after = _timestamp(source["not_after"], "source not_after")
    if not not_before < not_after or not issued < not_after:
        raise DependencySecurityError("dependency advisory source interval is invalid")
    _raw(source["source_artifact_raw_sha256"], "source artifact digest")
    _digest(source["source_attestation_digest"], "source attestation digest")
    _self_digest(source, "dependency-advisory-source-record", "source_record_digest")
    return identity


def _validate_closure(value: Mapping[str, object]) -> str:
    closure = _exact(value, _CLOSURE_FIELDS, "dependency fixed closure")
    if closure["schema_version"] != "1.0.0":
        raise DependencySecurityError("dependency fixed closure version is unsupported")
    closure_id = _text(closure["closure_id"], "closure ID")
    root_name = _text(closure["root_distribution_name"], "closure root name")
    root_version = _text(closure["root_version"], "closure root version")
    pins = _ordered_unique(
        closure["required_distribution_pins"],
        lambda item: (
            item.get("distribution_name"), item.get("distribution_version")
        ),
        "dependency fixed closure pins",
    )
    for value in pins:
        pin = _exact(value, _PIN_FIELDS, "dependency fixed closure pin")
        _text(pin["distribution_name"], "closure pin name")
        _text(pin["distribution_version"], "closure pin version")
        _raw(pin["wheel_raw_sha256"], "closure pin wheel digest")
        _raw(pin["record_raw_sha256"], "closure pin RECORD digest")
    if sum(
        1 for item in pins
        if item["distribution_name"] == root_name
        and item["distribution_version"] == root_version
    ) != 1:
        raise DependencySecurityError("fixed closure root pin is not exact")
    _text(closure["security_regression_command_id"], "security command ID")
    _self_digest(closure, "dependency-fixed-closure", "closure_digest")
    return closure_id


def _validate_advisory(value: Mapping[str, object]) -> tuple[str, int]:
    advisory = _exact(value, _ADVISORY_FIELDS, "dependency advisory")
    if advisory["schema_version"] != "1.0.0":
        raise DependencySecurityError("dependency advisory version is unsupported")
    identity = (
        _text(advisory["advisory_id"], "advisory ID"),
        _positive(advisory["advisory_revision"], "advisory revision"),
    )
    _text(advisory["source_id"], "advisory source ID")
    _positive(advisory["source_revision"], "advisory source revision")
    if advisory["ecosystem"] != "pypi":
        raise DependencySecurityError("dependency advisory ecosystem is unsupported")
    _text(advisory["distribution_name"], "advisory distribution")
    specifiers = advisory["affected_version_specifiers"]
    if (
        type(specifiers) is not list
        or not specifiers
        or any(type(item) is not str or not item for item in specifiers)
        or tuple(specifiers) != tuple(sorted(set(specifiers)))
    ):
        raise DependencySecurityError("advisory specifiers are not canonical")
    if advisory["applicability_kind"] != "verified-offline-closure-member":
        raise DependencySecurityError("advisory applicability kind is unsupported")
    _ordered_unique(
        advisory["fixed_closures"],
        lambda item: item.get("closure_id"),
        "dependency fixed closures",
    )
    for closure in advisory["fixed_closures"]:  # type: ignore[union-attr]
        _validate_closure(closure)
    _text(advisory["residual_exposure_policy_id"], "residual policy ID")
    _text(advisory["security_regression_policy_id"], "regression policy ID")
    _self_digest(advisory, "dependency-advisory-record", "advisory_digest")
    return identity


def _validate_state(
    value: Mapping[str, object],
    *,
    fields: frozenset[str],
    identity_fields: tuple[str, str],
    generation: int,
) -> tuple[str, int, str, int]:
    state = _exact(value, fields, "dependency advisory high-water state")
    identity = (
        _text(state[identity_fields[0]], "high-water identity"),
        _positive(state[identity_fields[1]], "high-water revision"),
    )
    status = state["status"]
    if status not in {"active", "superseded", "revoked"}:
        raise DependencySecurityError("dependency high-water status is invalid")
    status_generation = _positive(state["status_generation"], "status generation")
    if status_generation > generation:
        raise DependencySecurityError("status generation exceeds registry head")
    return identity[0], identity[1], str(status), status_generation


def parse_dependency_advisory_registry(value: object) -> DependencyAdvisoryRegistryData:
    registry = _exact(value, _REGISTRY_FIELDS, "dependency advisory registry")
    if registry["schema_version"] != "1.0.0":
        raise DependencySecurityError("dependency advisory registry version is unsupported")
    registry_id = _text(registry["registry_id"], "dependency registry ID")
    generation = _positive(registry["generation"], "dependency registry generation")
    if registry["update_kind"] not in {"genesis", "forward", "rollback"}:
        raise DependencySecurityError("dependency registry update kind is invalid")
    for field in ("previous_registry_digest", "rollback_of_registry_digest"):
        if registry[field] is not None:
            _digest(registry[field], field)
    sources = _ordered_unique(
        registry["source_records"],
        lambda item: (item.get("source_id"), item.get("source_revision")),
        "dependency advisory sources",
    )
    source_ids = tuple(_validate_source(item) for item in sources)
    advisories = _ordered_unique(
        registry["advisories"],
        lambda item: (item.get("advisory_id"), item.get("advisory_revision")),
        "dependency advisories",
    )
    advisory_ids = tuple(_validate_advisory(item) for item in advisories)
    high_water = _exact(
        registry["revocation_high_water"],
        _HIGH_WATER_FIELDS,
        "dependency advisory high-water",
    )
    if high_water["schema_version"] != "1.0.0" or high_water["generation"] != generation:
        raise DependencySecurityError("dependency high-water generation is wrong")
    source_states = _ordered_unique(
        high_water["source_states"],
        lambda item: (item.get("source_id"), item.get("source_revision")),
        "dependency source states",
    )
    advisory_states = _ordered_unique(
        high_water["advisory_states"],
        lambda item: (item.get("advisory_id"), item.get("advisory_revision")),
        "dependency advisory states",
    )
    parsed_source_states = tuple(
        _validate_state(
            item, fields=_SOURCE_STATE_FIELDS,
            identity_fields=("source_id", "source_revision"), generation=generation,
        )
        for item in source_states
    )
    parsed_advisory_states = tuple(
        _validate_state(
            item, fields=_ADVISORY_STATE_FIELDS,
            identity_fields=("advisory_id", "advisory_revision"), generation=generation,
        )
        for item in advisory_states
    )
    if (
        tuple(item[:2] for item in parsed_source_states) != source_ids
        or tuple(item[:2] for item in parsed_advisory_states) != advisory_ids
    ):
        raise DependencySecurityError("dependency high-water identity set is not exact")
    source_state = {item[:2]: item[2] for item in parsed_source_states}
    source_by_id = {
        (str(item["source_id"]), int(item["source_revision"])): item
        for item in sources
    }
    for advisory, identity, state in zip(
        advisories, advisory_ids, parsed_advisory_states, strict=True,
    ):
        source_identity = (
            str(advisory["source_id"]), int(advisory["source_revision"])
        )
        if source_identity not in source_by_id:
            raise DependencySecurityError("advisory source identity is missing")
        if state[2] == "active" and source_state[source_identity] != "active":
            raise DependencySecurityError("active advisory references inactive source")
    _self_digest(
        high_water,
        "dependency-advisory-status-high-water",
        "high_water_digest",
    )
    registry_digest = _self_digest(
        registry, "dependency-advisory-registry", "registry_digest"
    )
    if generation != 1 and registry["update_kind"] == "genesis":
        raise DependencySecurityError("dependency registry genesis generation is wrong")
    if generation == 1:
        if (
            registry["update_kind"] != "genesis"
            or registry["previous_registry_digest"] is not None
            or registry["rollback_of_registry_digest"] is not None
            or any(item[2:] != ("active", 1) for item in parsed_source_states)
            or any(item[2:] != ("active", 1) for item in parsed_advisory_states)
        ):
            raise DependencySecurityError("dependency registry genesis is not exact")
    frozen = freeze(registry)
    if not isinstance(frozen, FrozenMap):
        raise AssertionError("dependency registry did not freeze")
    return DependencyAdvisoryRegistryData(
        registry_id, generation, registry_digest, frozen,
    )


_TRANSITIONS = {
    "active": frozenset({"active", "superseded", "revoked"}),
    "superseded": frozenset({"superseded", "revoked"}),
    "revoked": frozenset({"revoked"}),
}


class DependencyRegistryRollbackAuthority:
    """Opaque proof that one installation factory verified a registry head chain."""

    __slots__ = (
        "_owner", "_current_digest", "_historical_digests", "__weakref__",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency registry rollback authority is factory-issued")

    def _require(self, current_digest: str, target_digest: str) -> None:
        del current_digest, target_digest
        raise DependencySecurityError(
            "dependency registry rollback proof requires its issuing factory"
        )


def validate_dependency_registry_update(
    current: object,
    candidate: object,
    *,
    rollback_authority: object | None = None,
) -> DependencyAdvisoryRegistryData:
    del rollback_authority
    return _validate_dependency_registry_update(
        current,
        candidate,
        verified_rollback_target=None,
    )


def _validate_verified_dependency_registry_update(
    current: object,
    candidate: object,
    *,
    verified_rollback_target: str,
) -> DependencyAdvisoryRegistryData:
    """Deterministic successor check after the application authority boundary."""

    _digest(verified_rollback_target, "verified dependency rollback target")
    return _validate_dependency_registry_update(
        current,
        candidate,
        verified_rollback_target=verified_rollback_target,
    )


def _validate_dependency_registry_update(
    current: object,
    candidate: object,
    *,
    verified_rollback_target: str | None,
) -> DependencyAdvisoryRegistryData:
    previous = parse_dependency_advisory_registry(current)
    successor = parse_dependency_advisory_registry(candidate)
    current_body = previous.to_dict()
    candidate_body = successor.to_dict()
    rollback_verified = False
    if (
        candidate_body["update_kind"] == "rollback"
        and type(candidate_body["rollback_of_registry_digest"]) is str
        and candidate_body["rollback_of_registry_digest"]
        == verified_rollback_target
    ):
        rollback_verified = True
    if (
        successor.registry_id != previous.registry_id
        or successor.generation != previous.generation + 1
        or candidate_body["update_kind"] not in {"forward", "rollback"}
        or candidate_body["previous_registry_digest"] != previous.registry_digest
        or (
            candidate_body["update_kind"] == "forward"
            and candidate_body["rollback_of_registry_digest"] is not None
        )
        or (candidate_body["update_kind"] == "rollback" and (
            candidate_body["rollback_of_registry_digest"] is None
            or not rollback_verified
        ))
    ):
        raise DependencySecurityError("dependency registry successor head is invalid")
    for collection, states, id_fields in (
        ("source_records", "source_states", ("source_id", "source_revision")),
        ("advisories", "advisory_states", ("advisory_id", "advisory_revision")),
    ):
        old_records = {
            (item[id_fields[0]], item[id_fields[1]]): freeze(item)
            for item in current_body[collection]  # type: ignore[union-attr]
        }
        new_records = {
            (item[id_fields[0]], item[id_fields[1]]): freeze(item)
            for item in candidate_body[collection]  # type: ignore[union-attr]
        }
        if not set(old_records).issubset(new_records) or any(
            new_records[key] != value for key, value in old_records.items()
        ):
            raise DependencySecurityError("dependency registry identities are not append-only")
        old_states = {
            (item[id_fields[0]], item[id_fields[1]]): item
            for item in current_body["revocation_high_water"][states]  # type: ignore[index]
        }
        new_states = {
            (item[id_fields[0]], item[id_fields[1]]): item
            for item in candidate_body["revocation_high_water"][states]  # type: ignore[index]
        }
        for identity, state in new_states.items():
            status = str(state["status"])
            status_generation = int(state["status_generation"])
            prior = old_states.get(identity)
            if prior is None:
                if status != "active" or status_generation != successor.generation:
                    raise DependencySecurityError("new dependency identity generation is wrong")
                continue
            previous_status = str(prior["status"])
            previous_generation = int(prior["status_generation"])
            if status not in _TRANSITIONS[previous_status]:
                raise DependencySecurityError("dependency status transition is invalid")
            if status == previous_status:
                if status_generation != previous_generation:
                    raise DependencySecurityError("unchanged dependency status generation changed")
            elif status_generation != successor.generation:
                raise DependencySecurityError("dependency transition generation is stale")
    return successor


def source_is_current(
    source: Mapping[str, object], observed_at: object,
) -> bool:
    observed = _timestamp(observed_at, "dependency observation time")
    return (
        _timestamp(source["not_before"], "source not_before")
        <= observed
        < _timestamp(source["not_after"], "source not_after")
    )
