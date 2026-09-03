"""Closed, digest-bound ArtifactContract registry."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext


ARTIFACT_CONTRACT_REGISTRY_SCHEMA = "urn:gew:schema:artifact-contract-registry:1.0.0"
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
ARTIFACT_TYPES = (
    "candidate-review",
    "completion-record",
    "impact",
    "implementation",
    "plan",
    "positioning",
    "prd",
    "tech-spec",
    "test-plan",
    "verification",
)
VALIDATOR_IDS = (
    "digests",
    "exit",
    "findings",
    "inputs",
    "review",
    "schema",
    "semantics",
    "status",
    "traces",
)
COMMON_STATUSES = frozenset({
    "candidate",
    "validating",
    "under_review",
    "reviewed",
    "awaiting_human",
    "approved",
    "accepted_for_next_node",
    "invalidated",
    "archived",
})


class ArtifactContractError(ValueError):
    """Invalid artifact contract declaration or registry."""


def _canonical_strings(value: object, name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        type(value) is not list
        or (not allow_empty and not value)
        or any(type(item) is not str or not item for item in value)
        or value != sorted(set(value))
    ):
        raise ArtifactContractError(f"{name} must be a canonical string set")
    return tuple(value)


@dataclass(frozen=True, slots=True, init=False)
class ArtifactContract:
    contract_id: str
    contract_version: str
    contract_digest: str
    artifact_type: str
    content_schema_ref: str
    required_semantic_fields: tuple[str, ...]
    required_trace_types: tuple[str, ...]
    validator_ids: tuple[str, ...]
    review_policy: Mapping[str, object]
    approval_policy: str
    exit_status: str
    allowed_statuses: tuple[str, ...]
    sensitivity_policy: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactContract must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ArtifactContract is final")

    @classmethod
    def _from_validated(
        cls,
        value: Mapping[str, object],
        context: WorkContext,
        *,
        operation_path: tuple[int, ...],
    ) -> ArtifactContract:
        fields = {
            "schema_version",
            "contract_id",
            "contract_version",
            "contract_digest",
            "artifact_type",
            "content_schema_ref",
            "required_semantic_fields",
            "required_trace_types",
            "validator_ids",
            "review_policy",
            "approval_policy",
            "exit_status",
            "allowed_statuses",
            "sensitivity_policy",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise ArtifactContractError("artifact contract properties are not exact")
        strings = tuple(value.get(name) for name in (
            "contract_id",
            "contract_version",
            "contract_digest",
            "artifact_type",
            "content_schema_ref",
            "approval_policy",
            "exit_status",
            "sensitivity_policy",
        ))
        if any(type(item) is not str or not item for item in strings):
            raise ArtifactContractError("artifact contract identity is invalid")
        contract_id, contract_version, expected_digest, artifact_type, content_schema_ref, approval_policy, exit_status, sensitivity = strings
        if (
            not contract_id.startswith("urn:gew:artifact-contract:")
            or not content_schema_ref.startswith("urn:gew:schema:")
            or SEMANTIC_DIGEST.fullmatch(expected_digest) is None
            or artifact_type not in ARTIFACT_TYPES
            or approval_policy not in {"agent", "human"}
            or sensitivity not in {"confidential", "internal", "public", "secret"}
        ):
            raise ArtifactContractError("artifact contract identity or policy is invalid")
        semantic_fields = _canonical_strings(value["required_semantic_fields"], "semantic fields")
        trace_types = _canonical_strings(value["required_trace_types"], "trace types")
        validators = _canonical_strings(value["validator_ids"], "validator IDs")
        statuses = _canonical_strings(value["allowed_statuses"], "allowed statuses")
        if validators != VALIDATOR_IDS or not set(statuses).issubset(COMMON_STATUSES):
            raise ArtifactContractError("artifact validator or status set is not approved")
        if exit_status not in statuses:
            raise ArtifactContractError("artifact exit status is not allowed")
        if approval_policy == "human" and exit_status != "approved":
            raise ArtifactContractError("human-approved artifact must exit approved")
        if approval_policy == "agent" and exit_status != "accepted_for_next_node":
            raise ArtifactContractError("agent-governed artifact must exit accepted_for_next_node")
        review = value["review_policy"]
        if not isinstance(review, Mapping) or set(review) != {"required", "independent", "minimum_trust"}:
            raise ArtifactContractError("review policy is not exact")
        if review.get("required") is not True or review.get("independent") is not True:
            raise ArtifactContractError("v1 artifact review must be required and independent")
        if review.get("minimum_trust") != "independently-reviewed":
            raise ArtifactContractError("artifact review trust is not approved")
        unsigned = dict(value)
        del unsigned["contract_digest"]
        actual_digest = semantic_digest_charged(
            unsigned,
            context,
            contract_type="urn:gew:contract:artifact-contract",
            projection_id=IDENTITY_PROJECTION,
            schema_id="urn:gew:schema:artifact-contract:1.0.0",
            operation_path=operation_path,
        )
        if not hmac.compare_digest(expected_digest, actual_digest):
            raise ArtifactContractError("artifact contract digest mismatch")
        frozen_review = freeze(review)
        if not isinstance(frozen_review, FrozenMap):
            raise AssertionError("review policy must freeze to an object")
        result = object.__new__(ArtifactContract)
        for name, item in (
            ("contract_id", contract_id),
            ("contract_version", contract_version),
            ("contract_digest", expected_digest),
            ("artifact_type", artifact_type),
            ("content_schema_ref", content_schema_ref),
            ("required_semantic_fields", semantic_fields),
            ("required_trace_types", trace_types),
            ("validator_ids", validators),
            ("review_policy", frozen_review),
            ("approval_policy", approval_policy),
            ("exit_status", exit_status),
            ("allowed_statuses", statuses),
            ("sensitivity_policy", sensitivity),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ArtifactContractRegistry:
    registry_id: str
    registry_digest: str
    contracts: Mapping[str, ArtifactContract]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ArtifactContractRegistry must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ArtifactContractRegistry is final")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        expected_registry_id: str,
        expected_registry_digest: str,
    ) -> ArtifactContractRegistry:
        if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
            raise ArtifactContractError("artifact registry requires attested schema registry and context")
        if schema_registry.validate(ARTIFACT_CONTRACT_REGISTRY_SCHEMA, value, context):
            raise ArtifactContractError("artifact contract registry schema validation failed")
        if set(value) != {"schema_version", "registry_id", "contracts", "registry_digest"}:
            raise ArtifactContractError("artifact contract registry properties are not exact")
        registry_id = value.get("registry_id")
        expected_digest = value.get("registry_digest")
        raw_contracts = value.get("contracts")
        if (
            value.get("schema_version") != "1.0.0"
            or type(registry_id) is not str
            or not registry_id.startswith("urn:gew:artifact-contract-registry:")
            or type(expected_digest) is not str
            or SEMANTIC_DIGEST.fullmatch(expected_digest) is None
            or type(raw_contracts) is not list
            or type(expected_registry_id) is not str
            or type(expected_registry_digest) is not str
            or SEMANTIC_DIGEST.fullmatch(expected_registry_digest) is None
            or registry_id != expected_registry_id
            or expected_digest != expected_registry_digest
        ):
            raise ArtifactContractError("artifact contract registry identity is invalid")
        contracts = []
        for raw in raw_contracts:
            if not isinstance(raw, Mapping):
                raise ArtifactContractError("artifact contract must be an object")
            contracts.append(ArtifactContract._from_validated(
                raw,
                context,
                operation_path=context.child_path(()),
            ))
        artifact_types = tuple(item.artifact_type for item in contracts)
        if artifact_types != ARTIFACT_TYPES:
            raise ArtifactContractError("artifact contract registry must contain the exact v1 type set")
        if len({item.contract_id for item in contracts}) != len(contracts):
            raise ArtifactContractError("artifact contract identities are duplicated")
        unsigned = dict(value)
        del unsigned["registry_digest"]
        actual_digest = semantic_digest_charged(
            unsigned,
            context,
            contract_type="urn:gew:contract:artifact-contract-registry",
            projection_id=IDENTITY_PROJECTION,
            schema_id=ARTIFACT_CONTRACT_REGISTRY_SCHEMA,
            operation_path=context.child_path(()),
        )
        if not hmac.compare_digest(expected_digest, actual_digest):
            raise ArtifactContractError("artifact contract registry digest mismatch")
        result = object.__new__(ArtifactContractRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", expected_digest)
        object.__setattr__(result, "contracts", MappingProxyType({
            item.artifact_type: item for item in contracts
        }))
        return result

    def resolve(self, artifact_type: str) -> ArtifactContract:
        try:
            return self.contracts[artifact_type]
        except KeyError as error:
            raise ArtifactContractError("unknown artifact type") from error
