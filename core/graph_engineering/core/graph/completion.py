"""Schema-validated, GEEL-evaluated completion policies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry
from graph_engineering.core.contracts.geel import (
    GEELProgram,
    PredicateRegistry,
    RootPathType,
    StaticRootRegistry,
)
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext


COMPLETION_POLICY_SCHEMA = "urn:gew:schema:completion-policy:1.0.0"
COMPLETION_REGISTRY_SCHEMA = "urn:gew:schema:completion-policy-registry:1.0.0"
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
COMPLETION_ROOTS = StaticRootRegistry((
    RootPathType("completion", (), "object"),
    RootPathType("completion", ("passed_count",), "integer"),
    RootPathType("completion", ("required_count",), "integer"),
))


class CompletionPolicyError(ValueError):
    """Invalid completion policy declaration or evaluation input."""


def completion_expression(kind: str, quorum: int | None) -> dict[str, object]:
    passed = {"op": "path", "root": "completion", "tokens": ["passed_count"]}
    required = {"op": "path", "root": "completion", "tokens": ["required_count"]}
    if kind == "all_required":
        return {"op": "eq", "left": passed, "right": required}
    if kind == "any_passed":
        return {"op": "gt", "left": passed, "right": {"op": "literal", "value": 0}}
    return {"op": "gte", "left": passed, "right": {"op": "literal", "value": quorum}}


@dataclass(frozen=True, slots=True, init=False)
class CompletionPolicy:
    policy_id: str
    version: str
    kind: str
    quorum: int | None
    condition: Mapping[str, object]
    _program: GEELProgram

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CompletionPolicy must be loaded from validated configuration")

    @classmethod
    def _from_validated(
        cls,
        value: Mapping[str, object],
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> CompletionPolicy:
        fields = {"schema_version", "policy_id", "version", "kind", "quorum", "condition"}
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise CompletionPolicyError("completion policy properties are not exact")
        policy_id = value["policy_id"]
        version = value["version"]
        kind = value["kind"]
        quorum = value["quorum"]
        if any(type(item) is not str or not item for item in (policy_id, version, kind)):
            raise CompletionPolicyError("completion policy identity is invalid")
        if kind not in {"all_required", "any_passed", "quorum"}:
            raise CompletionPolicyError("unknown completion policy kind")
        if kind == "quorum":
            if type(quorum) is not int or quorum < 1:
                raise CompletionPolicyError("quorum completion requires a positive exact integer")
        elif quorum is not None:
            raise CompletionPolicyError("non-quorum completion cannot declare quorum")
        condition = value["condition"]
        if not isinstance(condition, Mapping) or freeze(condition) != freeze(completion_expression(kind, quorum)):
            raise CompletionPolicyError("completion condition does not match declared kind")
        program = GEELProgram.load(condition, COMPLETION_ROOTS, predicates, error_rules, context)
        frozen_condition = freeze(condition)
        if not isinstance(frozen_condition, FrozenMap):
            raise AssertionError("completion condition must freeze to an object")
        result = object.__new__(CompletionPolicy)
        for name, item in (
            ("policy_id", policy_id), ("version", version), ("kind", kind),
            ("quorum", quorum), ("condition", frozen_condition), ("_program", program),
        ):
            object.__setattr__(result, name, item)
        return result

    def satisfied(
        self,
        passed_node_ids: Sequence[str],
        completion_node_ids: Sequence[str],
        context: WorkContext,
        *,
        operation_path: tuple[int, ...] = (),
    ) -> bool:
        if (
            type(context) is not WorkContext
            or type(passed_node_ids) not in (list, tuple)
            or type(completion_node_ids) not in (list, tuple)
            or any(type(item) is not str or not item for item in (*passed_node_ids, *completion_node_ids))
            or len(passed_node_ids) != len(set(passed_node_ids))
            or len(completion_node_ids) != len(set(completion_node_ids))
            or not completion_node_ids
        ):
            raise CompletionPolicyError("invalid completion predicate inputs")
        required = set(completion_node_ids)
        result = self._program.evaluate({
            "completion": {
                "passed_count": len(set(passed_node_ids) & required),
                "required_count": len(required),
            },
        }, context, operation_path=operation_path)
        if result.get("status") != "ok" or type(result.get("value")) is not bool:
            raise CompletionPolicyError("completion evaluation failed closed")
        return result["value"]  # type: ignore[return-value]


@dataclass(frozen=True, slots=True, init=False)
class CompletionPolicyRegistry:
    registry_id: str
    registry_digest: str
    policies: Mapping[str, CompletionPolicy]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CompletionPolicyRegistry must be loaded from validated configuration")

    @staticmethod
    def create_manifest(registry_id: str, policies: list[dict[str, object]]) -> dict[str, object]:
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:completion-policy-registry:"):
            raise CompletionPolicyError("invalid completion policy registry ID")
        identities = [item.get("policy_id") for item in policies if isinstance(item, Mapping)]
        if len(identities) != len(policies) or identities != sorted(identities) or len(identities) != len(set(identities)):
            raise CompletionPolicyError("completion policies must be sorted and unique")
        return {"schema_version": "1.0.0", "registry_id": registry_id, "policies": policies}

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> CompletionPolicyRegistry:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(predicates) is not PredicateRegistry
            or type(error_rules) is not ErrorRuleRegistry
            or type(context) is not WorkContext
        ):
            raise CompletionPolicyError("completion registry requires attested registries and work context")
        if schema_registry.validate(COMPLETION_REGISTRY_SCHEMA, value, context):
            raise CompletionPolicyError("completion registry schema validation failed")
        if set(value) != {"schema_version", "registry_id", "policies"} or value.get("schema_version") != "1.0.0":
            raise CompletionPolicyError("completion policy registry properties are not exact")
        registry_id = value.get("registry_id")
        policies = value.get("policies")
        if type(registry_id) is not str or not isinstance(policies, list):
            raise CompletionPolicyError("completion policy registry fields are invalid")
        if value != cls.create_manifest(registry_id, policies):
            raise CompletionPolicyError("completion policy registry is not canonical")
        digest = semantic_digest_charged(
            value,
            context,
            contract_type="urn:gew:contract:completion-policy-registry",
            projection_id=IDENTITY_PROJECTION,
            schema_id=COMPLETION_REGISTRY_SCHEMA,
        )
        loaded = [CompletionPolicy._from_validated(item, predicates, error_rules, context) for item in policies]
        result = object.__new__(CompletionPolicyRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", digest)
        object.__setattr__(result, "policies", MappingProxyType({item.policy_id: item for item in loaded}))
        return result

    def resolve(self, policy_id: str) -> CompletionPolicy:
        try:
            return self.policies[policy_id]
        except KeyError as error:
            raise CompletionPolicyError("unknown completion policy") from error
