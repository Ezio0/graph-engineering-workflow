"""Platform-neutral contracts for ADR-0009 offline release operations."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.errors import ContractError
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.contracts.strict_json import parse_json


SAFE_INTEGER = 9_007_199_254_740_991
_SCHEMA_VERSIONS = {
    "category-completion-assessment": "1.4.0",
    "release-artifact-manifest": "1.0.0",
    "release-deployment-observation": "1.0.0",
    "release-health-observation": "1.0.0",
    "release-operations-installation-bootstrap": "1.0.0",
    "release-operations-observation": "1.0.0",
    "release-operations-policy-registry": "1.0.0",
    "release-recovery-binding": "1.0.0",
    "release-simulator-fixture-registry": "1.0.0",
}
RELEASE_OPERATIONS_SCHEMA_IDS = tuple(sorted(
    f"urn:gew:schema:{name}{suffix}:{version}"
    for name, version in _SCHEMA_VERSIONS.items()
    for suffix in ("", "-input")
))


class ReleaseOperationsError(ValueError):
    """A release contract or installed authority failed closed."""


def _exact(value: object, fields: tuple[str, ...], label: str) -> Mapping[str, object]:
    if type(value) is not dict or tuple(value) != fields:
        raise ReleaseOperationsError(f"{label} fields/order are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise ReleaseOperationsError(f"{label} is not exact text")
    return value


def _relative(value: object, label: str) -> str:
    result = _text(value, label)
    parts = result.split("/")
    if result.startswith("/") or "\\" in result or any(
        part in {"", ".", ".."} for part in parts
    ):
        raise ReleaseOperationsError(f"{label} is not a canonical relative path")
    return result


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise ReleaseOperationsError(f"{label} is not a semantic digest")
    return result


def _raw(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise ReleaseOperationsError(f"{label} is not a raw SHA-256")
    return result


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise ReleaseOperationsError(f"{label} is not an exact safe integer")
    return value


def _ordered_text(value: object, label: str, *, sorted_values: bool = False) -> tuple[str, ...]:
    if type(value) is not list or not value:
        raise ReleaseOperationsError(f"{label} is not an exact non-empty list")
    result = tuple(_text(item, label) for item in value)
    if len(result) != len(set(result)) or (sorted_values and result != tuple(sorted(result))):
        raise ReleaseOperationsError(f"{label} is not exact and unique")
    return result


def _semantic(document: Mapping[str, object], name: str, version: str = "1.0.0") -> str:
    return semantic_digest(
        freeze(document),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:{version}",
        schema_id=f"urn:gew:schema:{name}-input:{version}",
    )


def _self_digest(
    document: Mapping[str, object], name: str, field: str, version: str = "1.0.0",
) -> str:
    expected = _digest(document.get(field), field)
    body = thaw(freeze(document))
    if type(body) is not dict:
        raise AssertionError("release contract did not thaw to an object")
    del body[field]
    if not hmac.compare_digest(expected, _semantic(body, name, version)):
        raise ReleaseOperationsError(f"{name} self digest changed")
    return expected


_RECOVERY_BINDING_FIELDS = (
    "schema_version", "binding_kind", "task_id", "fixture_id", "target_id",
    "resource_id", "repository_scope_digest", "namespace_identity", "root_identity",
    "root_nonce", "installation_pins", "binding_digest",
)
_RECOVERY_IDENTITY_FIELDS = (
    "kind", "device", "inode", "owner", "birth_seconds", "birth_nanoseconds",
)
_RECOVERY_PIN_FIELDS = (
    "bootstrap_id", "bootstrap_digest", "policy_registry_digest",
    "fixture_registry_digest", "profile_schema_registry_digest", "protected_closure_digest",
)


def _recovery_object(value: object, fields: tuple[str, ...], label: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != set(fields):
        raise ReleaseOperationsError(f"{label} fields are not exact")
    return {field: value[field] for field in fields}


def _recovery_id(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) > 255 or any(ord(character) < 33 or ord(character) > 126 for character in result):
        raise ReleaseOperationsError(f"{label} is not a bounded canonical ID")
    return result


@dataclass(frozen=True, slots=True, init=False)
class ReleaseRecoveryBinding:
    """Validated immutable lookup data, never an authority to open or mutate a root."""

    projection: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("release recovery bindings require validated input")

    @classmethod
    def from_bytes(cls, body: bytes, *, context: WorkContext) -> "ReleaseRecoveryBinding":
        if type(body) is not bytes or type(context) is not WorkContext:
            raise ReleaseOperationsError("release binding requires bytes and bounded work context")
        try:
            value = parse_json(body, context=context, source_id="release-recovery-binding")
        except (ValueError, TypeError, UnicodeError, ContractError) as error:
            raise ReleaseOperationsError("release binding JSON or resource bound is invalid") from error
        return cls.from_dict(value)

    @classmethod
    def from_dict(cls, value: object) -> "ReleaseRecoveryBinding":
        document = _recovery_object(value, _RECOVERY_BINDING_FIELDS, "release binding")
        if (
            document["schema_version"] != "1.0.0"
            or document["binding_kind"] != "retained-local-release-root"
        ):
            raise ReleaseOperationsError("release binding version or kind changed")
        for field in ("task_id", "fixture_id", "target_id", "resource_id"):
            _recovery_id(document[field], field)
        _digest(document["repository_scope_digest"], "repository scope digest")
        _raw(document["root_nonce"], "root nonce")
        for field in ("namespace_identity", "root_identity"):
            identity = _recovery_object(document[field], _RECOVERY_IDENTITY_FIELDS, field)
            _recovery_id(identity["kind"], "identity kind")
            for name in _RECOVERY_IDENTITY_FIELDS[1:]:
                _integer(identity[name], name)
            if identity["birth_nanoseconds"] >= 1_000_000_000:
                raise ReleaseOperationsError("identity birth nanoseconds are out of range")
            document[field] = identity
        pins = _recovery_object(document["installation_pins"], _RECOVERY_PIN_FIELDS, "installation pins")
        _recovery_id(pins["bootstrap_id"], "bootstrap ID")
        for field in _RECOVERY_PIN_FIELDS[1:]:
            _digest(pins[field], field)
        document["installation_pins"] = pins
        _self_digest(document, "release-recovery-binding", "binding_digest")
        result = object.__new__(cls)
        object.__setattr__(result, "projection", freeze(document))
        return result

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)

    def target_digest(self) -> str:
        return semantic_digest(
            {field: self.projection[field] for field in (
                "fixture_id", "resource_id", "target_id", "task_id", "binding_digest",
            )},
            contract_type="urn:gew:contract:local-release-target",
            projection_id="urn:gew:digest-projection:local-release-target:2.0.0",
            schema_id="urn:gew:schema:local-release-target:2.0.0",
        )


_POLICY_FIELDS = (
    "schema_version", "registry_id", "artifact_policy", "health_policy",
    "deployment_policy", "rollback_policy", "scenarios", "registry_digest",
)
_ARTIFACT_POLICY_FIELDS = ("required_provenance_fields", "allowed_evidence_kind")
_HEALTH_POLICY_FIELDS = (
    "predicate_ids", "predicate_roles", "healthy_outcome", "unhealthy_outcome",
)
_DEPLOYMENT_POLICY_FIELDS = (
    "operation_ids", "operation_roles", "ordered_phase_ids", "phase_roles",
    "fault_points", "fault_roles", "generation_limit", "stage_slot_id",
    "active_slot_id",
)
_ROLLBACK_POLICY_FIELDS = (
    "required_binding_fields", "restored_outcome", "owner_route",
)
_SCENARIO_FIELDS = ("scenario_id", "required_operation_ids", "success_outcome")
_FIXTURE_FIELDS = ("schema_version", "registry_id", "fixtures", "registry_digest")
_FIXTURE_ROW_FIELDS = (
    "fixture_id", "stage_relative_path", "active_relative_path",
    "state_relative_path", "artifact_vectors", "fault_schedule",
    "expected_rollback_artifact_id",
)
_ARTIFACT_VECTOR_FIELDS = (
    "artifact_id", "artifact_version", "artifact_base64",
    "distribution_name", "distribution_version",
)
_FAULT_FIELDS = ("fault_point", "result_class")


@dataclass(frozen=True, slots=True, init=False)
class ReleaseOperationsRegistry:
    policy: FrozenMap
    fixture_registry: FrozenMap
    operation_ids: tuple[str, ...]
    fault_points: tuple[str, ...]
    predicate_ids: tuple[str, ...]
    operation_roles: FrozenMap
    phase_roles: FrozenMap
    fault_roles: FrozenMap
    predicate_roles: FrozenMap
    health_outcomes: FrozenMap

    @classmethod
    def from_dicts(
        cls,
        policy_document: Mapping[str, object],
        fixture_document: Mapping[str, object],
    ) -> "ReleaseOperationsRegistry":
        policy = _exact(policy_document, _POLICY_FIELDS, "release policy registry")
        if policy["schema_version"] != "1.0.0":
            raise ReleaseOperationsError("release policy registry version changed")
        _text(policy["registry_id"], "release policy registry ID")
        artifact = _exact(policy["artifact_policy"], _ARTIFACT_POLICY_FIELDS, "artifact policy")
        required = _ordered_text(
            artifact["required_provenance_fields"], "artifact provenance fields",
        )
        expected_required = (
            "build_attestation_digest", "distribution_name", "distribution_version",
            "protected_closure_digest", "record_digest", "source_manifest_digest",
        )
        if required != expected_required:
            raise ReleaseOperationsError("artifact provenance policy changed")
        _text(artifact["allowed_evidence_kind"], "release evidence kind")
        health = _exact(policy["health_policy"], _HEALTH_POLICY_FIELDS, "health policy")
        predicate_ids = _ordered_text(health["predicate_ids"], "health predicate IDs")
        predicate_roles = _exact(
            health["predicate_roles"],
            ("artifact_current", "generation_current", "service_ready"),
            "health predicate roles",
        )
        if tuple(predicate_roles.values()) != predicate_ids:
            raise ReleaseOperationsError("health predicate roles changed")
        healthy_outcome = _text(health["healthy_outcome"], "healthy outcome")
        unhealthy_outcome = _text(health["unhealthy_outcome"], "unhealthy outcome")
        if healthy_outcome == unhealthy_outcome:
            raise ReleaseOperationsError("health outcomes alias")
        deployment = _exact(
            policy["deployment_policy"], _DEPLOYMENT_POLICY_FIELDS, "deployment policy",
        )
        operation_ids = _ordered_text(
            deployment["operation_ids"], "release operation IDs", sorted_values=True,
        )
        operation_roles = _exact(
            deployment["operation_roles"], ("apply", "query", "restore"),
            "release operation roles",
        )
        if set(operation_roles.values()) != set(operation_ids):
            raise ReleaseOperationsError("release operation roles changed")
        phases = _ordered_text(deployment["ordered_phase_ids"], "release phases")
        phase_roles = _exact(
            deployment["phase_roles"],
            ("baseline", "staged", "active", "health_observed", "restored"),
            "release phase roles",
        )
        if tuple(phase_roles.values()) != phases:
            raise ReleaseOperationsError("release phase roles changed")
        fault_points = _ordered_text(
            deployment["fault_points"], "release fault points", sorted_values=True,
        )
        fault_roles = _exact(
            deployment["fault_roles"],
            (
                "after_active_switch_durable", "after_stage_durable",
                "before_active_switch", "before_health_observe",
                "before_stage_write",
            ),
            "release fault roles",
        )
        if set(fault_roles.values()) != set(fault_points):
            raise ReleaseOperationsError("release fault roles changed")
        _integer(deployment["generation_limit"], "release generation limit", minimum=1)
        _text(deployment["stage_slot_id"], "stage slot ID")
        _text(deployment["active_slot_id"], "active slot ID")
        rollback = _exact(policy["rollback_policy"], _ROLLBACK_POLICY_FIELDS, "rollback policy")
        _ordered_text(rollback["required_binding_fields"], "rollback binding fields")
        _text(rollback["restored_outcome"], "restored outcome")
        _text(rollback["owner_route"], "rollback owner route")
        scenarios = policy["scenarios"]
        if type(scenarios) is not list or not scenarios:
            raise ReleaseOperationsError("release scenario closure changed")
        scenario_ids: list[str] = []
        for item in scenarios:
            row = _exact(item, _SCENARIO_FIELDS, "release scenario")
            scenario_ids.append(_text(row["scenario_id"], "release scenario ID"))
            operations = _ordered_text(row["required_operation_ids"], "scenario operations")
            if any(operation not in operation_ids for operation in operations):
                raise ReleaseOperationsError("scenario operation is foreign")
            _text(row["success_outcome"], "scenario success outcome")
        if tuple(scenario_ids) != tuple(sorted(set(scenario_ids))):
            raise ReleaseOperationsError("release scenarios are not canonical")
        _self_digest(policy, "release-operations-policy-registry", "registry_digest")

        fixture = _exact(fixture_document, _FIXTURE_FIELDS, "release fixture registry")
        if fixture["schema_version"] != "1.0.0":
            raise ReleaseOperationsError("release fixture registry version changed")
        _text(fixture["registry_id"], "release fixture registry ID")
        fixtures = fixture["fixtures"]
        if type(fixtures) is not list or not fixtures:
            raise ReleaseOperationsError("release fixtures are absent")
        fixture_ids: list[str] = []
        for item in fixtures:
            row = _exact(item, _FIXTURE_ROW_FIELDS, "release fixture")
            fixture_ids.append(_text(row["fixture_id"], "release fixture ID"))
            paths = tuple(_relative(row[field], field) for field in (
                "stage_relative_path", "active_relative_path", "state_relative_path",
            ))
            if len(paths) != len(set(paths)):
                raise ReleaseOperationsError("release fixture paths alias")
            artifacts = row["artifact_vectors"]
            if type(artifacts) is not list or len(artifacts) < 2:
                raise ReleaseOperationsError("release fixture artifacts are incomplete")
            artifact_ids: list[str] = []
            for value in artifacts:
                artifact = _exact(
                    value, _ARTIFACT_VECTOR_FIELDS, "release fixture artifact",
                )
                artifact_ids.append(_text(artifact["artifact_id"], "artifact ID"))
                _text(artifact["artifact_version"], "artifact version")
                _text(artifact["distribution_name"], "artifact distribution name")
                _text(artifact["distribution_version"], "artifact distribution version")
                encoded = _text(artifact["artifact_base64"], "artifact base64")
                try:
                    body = base64.b64decode(encoded, validate=True)
                except (ValueError, binascii.Error) as error:
                    raise ReleaseOperationsError(
                        "release fixture artifact base64 is invalid"
                    ) from error
                if not body or base64.b64encode(body).decode("ascii") != encoded:
                    raise ReleaseOperationsError(
                        "release fixture artifact bytes are not canonical"
                    )
            if tuple(artifact_ids) != tuple(sorted(set(artifact_ids))):
                raise ReleaseOperationsError("release fixture artifacts are not canonical")
            schedule = row["fault_schedule"]
            if type(schedule) is not list or len(schedule) != len(fault_points):
                raise ReleaseOperationsError("release fault schedule is incomplete")
            observed_faults = []
            for value in schedule:
                fault = _exact(value, _FAULT_FIELDS, "release fault")
                observed_faults.append(_text(fault["fault_point"], "release fault point"))
                if fault["result_class"] != "unknown":
                    raise ReleaseOperationsError("release fault result changed")
            if tuple(observed_faults) != fault_points:
                raise ReleaseOperationsError("release fault schedule changed")
            rollback_artifact = _text(
                row["expected_rollback_artifact_id"],
                "expected rollback artifact ID",
            )
            if rollback_artifact not in artifact_ids:
                raise ReleaseOperationsError(
                    "release rollback artifact is not a configured fixture"
                )
        if tuple(fixture_ids) != tuple(sorted(set(fixture_ids))):
            raise ReleaseOperationsError("release fixture IDs are not canonical")
        _self_digest(fixture, "release-simulator-fixture-registry", "registry_digest")

        issued = object.__new__(cls)
        object.__setattr__(issued, "policy", freeze(policy))
        object.__setattr__(issued, "fixture_registry", freeze(fixture))
        object.__setattr__(issued, "operation_ids", operation_ids)
        object.__setattr__(issued, "fault_points", fault_points)
        object.__setattr__(issued, "predicate_ids", predicate_ids)
        object.__setattr__(issued, "operation_roles", freeze(operation_roles))
        object.__setattr__(issued, "phase_roles", freeze(phase_roles))
        object.__setattr__(issued, "fault_roles", freeze(fault_roles))
        object.__setattr__(issued, "predicate_roles", freeze(predicate_roles))
        object.__setattr__(issued, "health_outcomes", freeze({
            "healthy": healthy_outcome, "unhealthy": unhealthy_outcome,
        }))
        return issued

    def fixture(self, fixture_id: str) -> FrozenMap:
        matches = tuple(
            row for row in self.fixture_registry["fixtures"]
            if row["fixture_id"] == fixture_id
        )
        if len(matches) != 1:
            raise ReleaseOperationsError("release fixture identity is not exact")
        return matches[0]

    def fixture_artifact(self, fixture_id: str, artifact_id: str) -> FrozenMap:
        fixture = self.fixture(fixture_id)
        matches = tuple(
            row for row in fixture["artifact_vectors"]
            if row["artifact_id"] == artifact_id
        )
        if len(matches) != 1:
            raise ReleaseOperationsError("release fixture artifact identity is not exact")
        return matches[0]


_MANIFEST_FIELDS = (
    "schema_version", "artifact_id", "artifact_version", "artifact_path",
    "raw_sha256", "size", "distribution_name", "distribution_version",
    "record_digest", "source_manifest_digest", "build_attestation_digest",
    "protected_closure_digest", "provenance_digest", "manifest_digest",
)


@dataclass(frozen=True, slots=True, init=False)
class ReleaseArtifactManifest:
    artifact_id: str
    artifact_version: str
    artifact_path: str
    raw_sha256: str
    size: int
    distribution_name: str
    distribution_version: str
    record_digest: str
    source_manifest_digest: str
    build_attestation_digest: str
    protected_closure_digest: str
    provenance_digest: str
    manifest_digest: str

    @classmethod
    def _issue(
        cls,
        *,
        artifact_id: str,
        artifact_version: str,
        artifact_bytes: bytes,
        distribution_name: str,
        distribution_version: str,
        record_digest: str,
        source_manifest_digest: str,
        build_attestation_digest: str,
        protected_closure_digest: str,
    ) -> "ReleaseArtifactManifest":
        if type(artifact_bytes) is not bytes or not artifact_bytes:
            raise ReleaseOperationsError("release artifact bytes are absent")
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "artifact_id": _text(artifact_id, "artifact ID"),
            "artifact_version": _text(artifact_version, "artifact version"),
            "artifact_path": _relative(f"artifacts/{artifact_id}.bin", "artifact path"),
            "raw_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            "size": len(artifact_bytes),
            "distribution_name": _text(distribution_name, "distribution name"),
            "distribution_version": _text(distribution_version, "distribution version"),
            "record_digest": _digest(record_digest, "RECORD digest"),
            "source_manifest_digest": _digest(source_manifest_digest, "source manifest digest"),
            "build_attestation_digest": _digest(build_attestation_digest, "build attestation digest"),
            "protected_closure_digest": _digest(protected_closure_digest, "protected closure digest"),
        }
        body["provenance_digest"] = _semantic(body, "release-artifact-provenance")
        body["manifest_digest"] = _semantic(body, "release-artifact-manifest")
        return cls.from_dict(body)

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> "ReleaseArtifactManifest":
        if not isinstance(value, Mapping) or set(value) != set(_MANIFEST_FIELDS):
            raise ReleaseOperationsError("release artifact manifest fields are not exact")
        document = {field: value[field] for field in _MANIFEST_FIELDS}
        if document["schema_version"] != "1.0.0":
            raise ReleaseOperationsError("release artifact manifest version changed")
        for field in (
            "artifact_id", "artifact_version", "distribution_name", "distribution_version",
        ):
            _text(document[field], field)
        _relative(document["artifact_path"], "artifact path")
        _raw(document["raw_sha256"], "artifact raw SHA-256")
        _integer(document["size"], "artifact size", minimum=1)
        for field in (
            "record_digest", "source_manifest_digest", "build_attestation_digest",
            "protected_closure_digest", "provenance_digest", "manifest_digest",
        ):
            _digest(document[field], field)
        provenance = {key: document[key] for key in _MANIFEST_FIELDS[:12]}
        if not hmac.compare_digest(
            str(document["provenance_digest"]),
            _semantic(provenance, "release-artifact-provenance"),
        ):
            raise ReleaseOperationsError("release artifact provenance changed")
        _self_digest(document, "release-artifact-manifest", "manifest_digest")
        result = object.__new__(cls)
        for field in _MANIFEST_FIELDS[1:]:
            object.__setattr__(result, field, document[field])
        return result

    def to_dict(self) -> dict[str, object]:
        return {"schema_version": "1.0.0", **{
            field: getattr(self, field) for field in _MANIFEST_FIELDS[1:]
        }}


def evaluate_health(
    registry: ReleaseOperationsRegistry,
    predicate_values: Mapping[str, object],
) -> tuple[tuple[dict[str, object], ...], str]:
    """Evaluate complete ordered local predicate truth without performing I/O."""

    if type(registry) is not ReleaseOperationsRegistry or type(predicate_values) is not dict:
        raise ReleaseOperationsError("release health input is not exact")
    if tuple(predicate_values) != registry.predicate_ids:
        raise ReleaseOperationsError("release health predicate closure changed")
    rows: list[dict[str, object]] = []
    healthy = True
    for predicate_id in registry.predicate_ids:
        value = predicate_values[predicate_id]
        if type(value) is not bool:
            raise ReleaseOperationsError("release health predicate is not boolean")
        rows.append({"predicate_id": predicate_id, "passed": value})
        healthy = healthy and value
    outcome = registry.health_outcomes["healthy" if healthy else "unhealthy"]
    return tuple(rows), str(outcome)
