"""Digest-bound executable graph definitions and static validation."""

from __future__ import annotations

import hmac
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import (
    DigestProjection,
    SEMANTIC_DIGEST,
    create_self_digest_charged,
    validate_projection_schema_pair,
    verify_self_digest_charged,
)
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry
from graph_engineering.core.contracts.errors import ContractError
from graph_engineering.core.contracts.geel import GEELProgram, PredicateRegistry, RootPathType, StaticRootRegistry
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.graph.budget import LoopBudgetRegistry
from graph_engineering.core.graph.completion import CompletionPolicy, CompletionPolicyRegistry


GRAPH_CONTRACT = "urn:gew:contract:graph-definition"
GRAPH_PROJECTION = "urn:gew:digest-projection:graph-definition:1.0.0"
GRAPH_SCHEMA = "urn:gew:schema:graph-definition:1.0.0"
GRAPH_DIGEST_INPUT_SCHEMA = "urn:gew:schema:graph-definition-digest-input:1.0.0"
GRAPH_DIGEST_PROJECTION = DigestProjection(
    projection_id=GRAPH_PROJECTION,
    source_schema_id=GRAPH_SCHEMA,
    digest_input_schema_id=GRAPH_DIGEST_INPUT_SCHEMA,
    derived_field="digest",
    contract_type=GRAPH_CONTRACT,
    schema_id=GRAPH_DIGEST_INPUT_SCHEMA,
)
NODE_KINDS = frozenset({"agent_loop", "deterministic"})
JOIN_KINDS = frozenset({"all_required", "any_passed", "quorum", "human_decision"})
INVALIDATION_RULES = frozenset({"propagate", "revalidate", "reconcile"})


class GraphValidationError(ValueError):
    """A stable fail-closed graph-definition rejection."""


def _exact_mapping(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise GraphValidationError(f"{label} properties are not exact")
    return value


def _identifier(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or not value.isascii():
        raise GraphValidationError(f"invalid {label}")
    return value


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(type(item) is not str or not item for item in value):
        raise GraphValidationError(f"invalid {label}")
    result = tuple(value)
    if len(result) != len(set(result)):
        raise GraphValidationError(f"duplicate {label}")
    return result


@dataclass(frozen=True, slots=True)
class TrustPolicy:
    levels: tuple[str, ...]
    upgrades: frozenset[tuple[str, str]]

    @classmethod
    def from_dict(cls, value: object) -> TrustPolicy:
        record = _exact_mapping(value, frozenset({"levels", "upgrades"}), "trust policy")
        levels = _string_tuple(record["levels"], "trust level")
        if not levels:
            raise GraphValidationError("trust policy must declare levels")
        raw_upgrades = record["upgrades"]
        if not isinstance(raw_upgrades, list):
            raise GraphValidationError("invalid trust upgrades")
        upgrades: list[tuple[str, str]] = []
        for raw in raw_upgrades:
            edge = _exact_mapping(raw, frozenset({"from", "to"}), "trust upgrade")
            pair = (_identifier(edge["from"], "trust source"), _identifier(edge["to"], "trust target"))
            if pair[0] not in levels or pair[1] not in levels or pair[0] == pair[1]:
                raise GraphValidationError("unknown or reflexive trust upgrade")
            upgrades.append(pair)
        if len(upgrades) != len(set(upgrades)):
            raise GraphValidationError("duplicate trust upgrade")
        policy = cls(levels, frozenset(upgrades))
        for left in levels:
            for right in levels:
                if left != right and policy._reachable(left, right) and policy._reachable(right, left):
                    raise GraphValidationError("trust upgrade cycle")
        return policy

    def _reachable(self, current: str, required: str) -> bool:
        if current == required:
            return True
        seen = {current}
        pending = [current]
        while pending:
            source = pending.pop()
            for left, right in self.upgrades:
                if left == source and right not in seen:
                    if right == required:
                        return True
                    seen.add(right)
                    pending.append(right)
        return False

    def satisfies(self, current: str, required: str) -> bool:
        if current not in self.levels or required not in self.levels:
            raise GraphValidationError("unknown trust level")
        return self._reachable(required, current)


@dataclass(frozen=True, slots=True)
class JoinPolicy:
    kind: str
    quorum: int | None
    _program: GEELProgram

    @classmethod
    def from_dict(
        cls,
        value: object,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> JoinPolicy:
        record = _exact_mapping(value, frozenset({"kind", "quorum"}), "join policy")
        kind = _identifier(record["kind"], "join kind")
        quorum = record["quorum"]
        if kind not in JOIN_KINDS:
            raise GraphValidationError("unknown join policy")
        if kind == "quorum":
            if type(quorum) is not int or quorum < 1:
                raise GraphValidationError("quorum join requires a positive exact integer")
        elif quorum is not None:
            raise GraphValidationError("non-quorum join cannot declare quorum")
        passed_count = {"op": "path", "root": "join", "tokens": ["passed_count"]}
        required = {"op": "path", "root": "join", "tokens": ["required_count"]}
        candidate_count = {"op": "path", "root": "join", "tokens": ["candidate_count"]}
        expression = (
            {"op": "literal", "value": False}
            if kind == "human_decision"
            else {
                "op": "all",
                "args": [
                    {"op": "eq", "left": passed_count, "right": required},
                    {"op": "eq", "left": candidate_count, "right": required},
                ],
            }
            if kind == "all_required"
            else {
                "op": "gt" if kind == "any_passed" else "gte",
                "left": passed_count,
                "right": {"op": "literal", "value": 0 if kind == "any_passed" else quorum},
            }
        )
        roots = StaticRootRegistry((
            RootPathType("join", (), "object"),
            RootPathType("join", ("passed_count",), "integer"),
            RootPathType("join", ("required_count",), "integer"),
            RootPathType("join", ("candidate_count",), "integer"),
        ))
        program = GEELProgram.load(expression, roots, predicates, error_rules, context)
        return cls(kind, quorum if type(quorum) is int else None, program)

    def satisfied(
        self,
        passed: Sequence[bool],
        required_count: int,
        context: WorkContext,
        *,
        operation_path: tuple[int, ...] = (),
    ) -> bool:
        if (
            type(required_count) is not int
            or required_count < 0
            or type(passed) not in (list, tuple)
            or any(type(item) is not bool for item in passed)
            or type(context) is not WorkContext
        ):
            raise GraphValidationError("invalid join inputs")
        result = self._program.evaluate({
            "join": {
                "passed_count": sum(passed),
                "required_count": required_count,
                "candidate_count": len(passed),
            },
        }, context, operation_path=operation_path)
        if result.get("status") != "ok" or type(result.get("value")) is not bool:
            raise GraphValidationError("join evaluation failed closed")
        return result["value"]  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class NodeDefinition:
    node_id: str
    node_kind: str
    input_schema_ref: str
    output_schema_ref: str
    executor_capability: str
    authority_requirement: str
    side_effect_class: str
    review_policy_ref: str
    loop_budget_ref: str | None
    timeout_policy_ref: str
    artifact_contract_refs: tuple[str, ...]
    failure_routes: Mapping[str, str]
    invalidation_tags: tuple[str, ...]
    entrypoint: bool
    completion_eligible: bool


@dataclass(frozen=True, slots=True)
class InputMapping:
    source_path: tuple[str | int, ...]
    target_path: tuple[str | int, ...]


@dataclass(frozen=True, slots=True)
class EdgeDefinition:
    edge_id: str
    from_node: str
    to_node: str
    input_mapping: tuple[InputMapping, ...]
    target_input_schema_ref: str
    route_condition: Mapping[str, object]
    route_priority: int
    required_trust: str
    evidence_requirements: tuple[str, ...]
    join_policy: JoinPolicy
    invalidation_rule: str
    failure_route: str | None


NODE_FIELDS = frozenset({
    "node_id", "node_kind", "input_schema_ref", "output_schema_ref", "executor_capability",
    "authority_requirement", "side_effect_class", "review_policy_ref", "loop_budget_ref",
    "timeout_policy_ref", "artifact_contract_refs", "failure_routes", "invalidation_tags",
    "entrypoint", "completion_eligible",
})
EDGE_FIELDS = frozenset({
    "edge_id", "from_node", "to_node", "input_mapping", "target_input_schema_ref",
    "route_condition", "route_priority", "required_trust", "evidence_requirements",
    "join_policy", "invalidation_rule", "failure_route",
})
GRAPH_FIELDS = frozenset({
    "schema_version", "graph_id", "graph_version", "completion_policy_ref", "trust_policy",
    "condition_roots", "nodes", "edges", "registry_pins", "resource_pins", "digest",
})
REGISTRY_PIN_NAMES = frozenset({
    "schema", "predicate", "error_rule", "completion_policy", "loop_budget",
})
RESOURCE_PIN_NAMES = frozenset({"resource_profile", "cost_schedule"})


@dataclass(frozen=True, slots=True, init=False)
class GraphDefinition:
    schema_version: str
    graph_id: str
    graph_version: str
    completion_policy_ref: str
    completion_policy: CompletionPolicy
    registry_pins: Mapping[str, object]
    resource_pins: Mapping[str, object]
    trust_policy: TrustPolicy
    condition_roots: tuple[RootPathType, ...]
    nodes: Mapping[str, NodeDefinition]
    edges: Mapping[str, EdgeDefinition]
    digest: str
    entrypoints: tuple[str, ...]
    completion_nodes: tuple[str, ...]
    cyclic_nodes: tuple[str, ...]
    _outgoing: Mapping[str, tuple[EdgeDefinition, ...]]
    _control_outgoing: Mapping[str, tuple[str, ...]]
    _route_programs: Mapping[str, GEELProgram | None]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("GraphDefinition must be loaded from a digest-bound document")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("GraphDefinition is final")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
        completion_policies: CompletionPolicyRegistry,
        loop_budgets: LoopBudgetRegistry,
        operation_path: tuple[int, ...] = (),
    ) -> GraphDefinition:
        if type(schema_registry) is not ClosedSchemaRegistry:
            raise GraphValidationError("graph requires an attested closed schema registry")
        if (
            type(predicates) is not PredicateRegistry
            or type(error_rules) is not ErrorRuleRegistry
            or type(context) is not WorkContext
        ):
            raise GraphValidationError("graph requires attested execution registries and work context")
        if (
            type(completion_policies) is not CompletionPolicyRegistry
            or type(loop_budgets) is not LoopBudgetRegistry
        ):
            raise GraphValidationError("graph policy registries must be attested exact registries")
        actual_registries = cls._actual_registry_pins(
            schema_registry, predicates, error_rules, completion_policies, loop_budgets,
        )
        registry_pins = cls._registry_pins(value.get("registry_pins"), actual_registries)
        resource_pins = cls._resource_pins(value.get("resource_pins"), context)
        cls._validate_projection(schema_registry)

        def validate_source(candidate: object, operation_path: tuple[int, ...]) -> None:
            if schema_registry.validate(
                GRAPH_SCHEMA, candidate, context, operation_path=operation_path,
            ):
                raise GraphValidationError("graph source schema validation failed")

        def validate_input(candidate: object, operation_path: tuple[int, ...]) -> None:
            if schema_registry.validate(
                GRAPH_DIGEST_INPUT_SCHEMA, candidate, context, operation_path=operation_path,
            ):
                raise GraphValidationError("graph digest-input schema validation failed")

        try:
            verified = verify_self_digest_charged(
                value,
                GRAPH_DIGEST_PROJECTION,
                context,
                validate_input=validate_input,
                validate_source=validate_source,
                operation_path=operation_path,
            )
        except (ContractError, GraphValidationError):
            raise
        except ValueError as error:
            raise GraphValidationError("graph digest verification failed") from error
        return cls._from_verified_record(
            verified,
            schema_registry=schema_registry,
            predicates=predicates,
            error_rules=error_rules,
            context=context,
            completion_policies=completion_policies,
            loop_budgets=loop_budgets,
            registry_pins=registry_pins,
            resource_pins=resource_pins,
        )

    @classmethod
    def _from_verified_record(
        cls,
        verified: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
        completion_policies: CompletionPolicyRegistry,
        loop_budgets: LoopBudgetRegistry,
        operation_path: tuple[int, ...] = (),
        registry_pins: Mapping[str, object],
        resource_pins: Mapping[str, object],
    ) -> GraphDefinition:
        record = _exact_mapping(verified, GRAPH_FIELDS, "graph")
        if record["schema_version"] != "1.0.0":
            raise GraphValidationError("unknown graph schema version")
        digest = record["digest"]
        if type(digest) is not str or SEMANTIC_DIGEST.fullmatch(digest) is None:
            raise GraphValidationError("invalid graph digest")
        graph_id = _identifier(record["graph_id"], "graph ID")
        graph_version = _identifier(record["graph_version"], "graph version")
        completion_policy_ref = _identifier(record["completion_policy_ref"], "completion policy")
        try:
            completion_policy = completion_policies.resolve(completion_policy_ref)
        except ValueError as error:
            raise GraphValidationError("graph references an unknown completion policy") from error
        trust = TrustPolicy.from_dict(record["trust_policy"])
        roots = cls._roots(record["condition_roots"])
        nodes = cls._nodes(record["nodes"])
        for node in nodes.values():
            try:
                schema_registry.resource(node.input_schema_ref)
                schema_registry.resource(node.output_schema_ref)
            except ValueError as error:
                raise GraphValidationError("node references an unknown schema") from error
        edges, route_programs = cls._edges(
            record["edges"], nodes, trust, roots, predicates, error_rules, context, schema_registry,
        )
        for node in nodes.values():
            unknown_failure_targets = set(node.failure_routes.values()) - set(nodes)
            if unknown_failure_targets:
                raise GraphValidationError("node failure route references unknown node")
        entrypoints = tuple(sorted(node.node_id for node in nodes.values() if node.entrypoint))
        completion = tuple(sorted(node.node_id for node in nodes.values() if node.completion_eligible))
        if not entrypoints or not completion:
            raise GraphValidationError("graph requires entrypoint and completion nodes")
        outgoing = {
            node_id: tuple(sorted((edge for edge in edges.values() if edge.from_node == node_id), key=lambda item: (item.route_priority, item.edge_id)))
            for node_id in nodes
        }
        control_outgoing = cls._control_topology(nodes, outgoing)
        cls._validate_route_groups(outgoing)
        cls._validate_join_groups(edges)
        cls._validate_reachability(nodes, control_outgoing, entrypoints, completion)
        cyclic = cls._cyclic_nodes(nodes, control_outgoing)
        for node_id in cyclic:
            if nodes[node_id].loop_budget_ref is None:
                raise GraphValidationError(f"cycle node {node_id} has no loop budget")
            if nodes[node_id].loop_budget_ref not in loop_budgets.budgets:
                raise GraphValidationError(f"cycle node {node_id} references unknown loop budget")
        result = object.__new__(GraphDefinition)
        for name, item in (
            ("schema_version", "1.0.0"), ("graph_id", graph_id), ("graph_version", graph_version),
            ("completion_policy_ref", completion_policy_ref), ("completion_policy", completion_policy),
            ("registry_pins", registry_pins), ("resource_pins", resource_pins),
            ("trust_policy", trust),
            ("condition_roots", roots), ("nodes", MappingProxyType(dict(nodes))),
            ("edges", MappingProxyType(dict(edges))), ("digest", digest),
            ("entrypoints", entrypoints), ("completion_nodes", completion),
            ("cyclic_nodes", tuple(sorted(cyclic))), ("_outgoing", MappingProxyType(outgoing)),
            ("_control_outgoing", MappingProxyType(control_outgoing)),
            ("_route_programs", MappingProxyType(route_programs)),
        ):
            object.__setattr__(result, name, item)
        return result

    @classmethod
    def create(
        cls,
        candidate_without_digest: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
        completion_policies: CompletionPolicyRegistry,
        loop_budgets: LoopBudgetRegistry,
        operation_path: tuple[int, ...] = (),
    ) -> dict[str, object]:
        """Create and semantically verify one graph through its registered projection."""

        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(predicates) is not PredicateRegistry
            or type(error_rules) is not ErrorRuleRegistry
            or type(context) is not WorkContext
            or type(completion_policies) is not CompletionPolicyRegistry
            or type(loop_budgets) is not LoopBudgetRegistry
        ):
            raise GraphValidationError("graph creation requires exact attested contract inputs")
        registry_pins = cls._registry_pins(
            candidate_without_digest.get("registry_pins"),
            cls._actual_registry_pins(
                schema_registry, predicates, error_rules, completion_policies, loop_budgets,
            ),
        )
        resource_pins = cls._resource_pins(
            candidate_without_digest.get("resource_pins"), context,
        )
        cls._validate_projection(schema_registry)

        def validate_source(candidate: object, operation_path: tuple[int, ...]) -> None:
            if schema_registry.validate(
                GRAPH_SCHEMA, candidate, context, operation_path=operation_path,
            ):
                raise GraphValidationError("graph source schema validation failed")

        def validate_input(candidate: object, operation_path: tuple[int, ...]) -> None:
            if schema_registry.validate(
                GRAPH_DIGEST_INPUT_SCHEMA, candidate, context, operation_path=operation_path,
            ):
                raise GraphValidationError("graph digest-input schema validation failed")

        complete = create_self_digest_charged(
            candidate_without_digest,
            GRAPH_DIGEST_PROJECTION,
            context,
            validate_input=validate_input,
            validate_source=validate_source,
            operation_path=operation_path,
        )
        cls._from_verified_record(
            complete,
            schema_registry=schema_registry,
            predicates=predicates,
            error_rules=error_rules,
            context=context,
            completion_policies=completion_policies,
            loop_budgets=loop_budgets,
            registry_pins=registry_pins,
            resource_pins=resource_pins,
        )
        return complete

    @staticmethod
    def _actual_registry_pins(
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        completion_policies: CompletionPolicyRegistry,
        loop_budgets: LoopBudgetRegistry,
    ) -> Mapping[str, tuple[str, str]]:
        return {
            "schema": (schema_registry.registry_id, schema_registry.registry_digest),
            "predicate": (predicates.registry_id, predicates.registry_digest),
            "error_rule": (error_rules.registry_id, error_rules.registry_digest),
            "completion_policy": (
                completion_policies.registry_id, completion_policies.registry_digest,
            ),
            "loop_budget": (loop_budgets.registry_id, loop_budgets.registry_digest),
        }

    @staticmethod
    def _validate_projection(schema_registry: ClosedSchemaRegistry) -> None:
        try:
            validate_projection_schema_pair(
                schema_registry.resource(GRAPH_SCHEMA).schema,
                schema_registry.resource(GRAPH_DIGEST_INPUT_SCHEMA).schema,
                GRAPH_DIGEST_PROJECTION,
            )
        except ValueError as error:
            raise GraphValidationError("graph digest projection is not registered exactly") from error

    @staticmethod
    def _registry_pins(
        value: object,
        actual: Mapping[str, tuple[str, str]],
    ) -> Mapping[str, object]:
        record = _exact_mapping(value, REGISTRY_PIN_NAMES, "registry pins")
        normalized: dict[str, object] = {}
        for name in sorted(REGISTRY_PIN_NAMES):
            pin = _exact_mapping(
                record[name], frozenset({"registry_id", "registry_digest"}), f"{name} registry pin",
            )
            registry_id = _identifier(pin["registry_id"], f"{name} registry ID")
            registry_digest = pin["registry_digest"]
            if type(registry_digest) is not str or SEMANTIC_DIGEST.fullmatch(registry_digest) is None:
                raise GraphValidationError(f"invalid {name} registry digest")
            expected_id, expected_digest = actual[name]
            if registry_id != expected_id or not hmac.compare_digest(registry_digest, expected_digest):
                raise GraphValidationError(f"{name} registry pin mismatch")
            normalized[name] = {
                "registry_id": registry_id,
                "registry_digest": registry_digest,
            }
        frozen = freeze(normalized)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("registry pins must freeze to an object")
        return frozen

    @staticmethod
    def _resource_pins(value: object, context: WorkContext) -> Mapping[str, object]:
        record = _exact_mapping(value, RESOURCE_PIN_NAMES, "resource pins")
        expected = {
            "resource_profile": (
                "profile_id", context.profile.profile_id, context.profile.body_digest,
            ),
            "cost_schedule": (
                "schedule_id", context.schedule.schedule_id, context.schedule.body_digest,
            ),
        }
        normalized: dict[str, object] = {}
        for name in sorted(RESOURCE_PIN_NAMES):
            id_field, actual_id, actual_digest = expected[name]
            pin = _exact_mapping(
                record[name], frozenset({id_field, "body_digest"}), f"{name} pin",
            )
            resource_id = _identifier(pin[id_field], f"{name} ID")
            body_digest = pin["body_digest"]
            if type(body_digest) is not str or SEMANTIC_DIGEST.fullmatch(body_digest) is None:
                raise GraphValidationError(f"invalid {name} body digest")
            if resource_id != actual_id or not hmac.compare_digest(body_digest, actual_digest):
                raise GraphValidationError(f"{name} pin mismatch")
            normalized[name] = {id_field: resource_id, "body_digest": body_digest}
        frozen = freeze(normalized)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("resource pins must freeze to an object")
        return frozen

    def _require_context(self, context: WorkContext) -> None:
        if type(context) is not WorkContext:
            raise GraphValidationError("graph operation requires an exact work context")
        self._resource_pins(self.resource_pins, context)

    @staticmethod
    def _roots(value: object) -> tuple[RootPathType, ...]:
        if not isinstance(value, list):
            raise GraphValidationError("condition roots must be a list")
        roots: list[RootPathType] = []
        for raw in value:
            record = _exact_mapping(raw, frozenset({"root", "tokens", "value_type"}), "condition root")
            root = _identifier(record["root"], "condition root")
            tokens = record["tokens"]
            if not isinstance(tokens, list) or any(type(token) not in (str, int) or type(token) is bool for token in tokens):
                raise GraphValidationError("invalid condition root tokens")
            roots.append(RootPathType(root, tuple(tokens), _identifier(record["value_type"], "root value type")))
        identities = [(root.root, root.tokens) for root in roots]
        if len(identities) != len(set(identities)):
            raise GraphValidationError("duplicate condition root")
        return tuple(roots)

    @staticmethod
    def _nodes(value: object) -> dict[str, NodeDefinition]:
        if not isinstance(value, list) or not value:
            raise GraphValidationError("nodes must be a non-empty list")
        nodes: dict[str, NodeDefinition] = {}
        for raw in value:
            record = _exact_mapping(raw, NODE_FIELDS, "node")
            node_id = _identifier(record["node_id"], "node ID")
            if node_id in nodes:
                raise GraphValidationError("duplicate node ID")
            kind = _identifier(record["node_kind"], "node kind")
            if kind not in NODE_KINDS:
                raise GraphValidationError("unknown node kind")
            if type(record["entrypoint"]) is not bool or type(record["completion_eligible"]) is not bool:
                raise GraphValidationError("node entrypoint/completion flags must be booleans")
            failure = record["failure_routes"]
            if not isinstance(failure, Mapping) or any(type(key) is not str or type(item) is not str for key, item in failure.items()):
                raise GraphValidationError("invalid node failure routes")
            loop = record["loop_budget_ref"]
            if loop is not None:
                loop = _identifier(loop, "loop budget")
            nodes[node_id] = NodeDefinition(
                node_id, kind, _identifier(record["input_schema_ref"], "input schema"),
                _identifier(record["output_schema_ref"], "output schema"),
                _identifier(record["executor_capability"], "executor capability"),
                _identifier(record["authority_requirement"], "authority requirement"),
                _identifier(record["side_effect_class"], "side-effect class"),
                _identifier(record["review_policy_ref"], "review policy"), loop,
                _identifier(record["timeout_policy_ref"], "timeout policy"),
                _string_tuple(record["artifact_contract_refs"], "artifact contract ref"),
                MappingProxyType(dict(failure)), _string_tuple(record["invalidation_tags"], "invalidation tag"),
                record["entrypoint"], record["completion_eligible"],  # type: ignore[arg-type]
            )
        return nodes

    @staticmethod
    def _path(value: object, label: str) -> tuple[str | int, ...]:
        if not isinstance(value, list) or any(type(item) not in (str, int) or type(item) is bool or (type(item) is int and item < 0) for item in value):
            raise GraphValidationError(f"invalid {label}")
        return tuple(value)

    @classmethod
    def _edges(
        cls,
        value: object,
        nodes: Mapping[str, NodeDefinition],
        trust: TrustPolicy,
        roots: tuple[RootPathType, ...],
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
        schema_registry: ClosedSchemaRegistry,
    ) -> tuple[dict[str, EdgeDefinition], dict[str, GEELProgram | None]]:
        if not isinstance(value, list):
            raise GraphValidationError("edges must be a list")
        edges: dict[str, EdgeDefinition] = {}
        programs: dict[str, GEELProgram | None] = {}
        for raw in value:
            record = _exact_mapping(raw, EDGE_FIELDS, "edge")
            edge_id = _identifier(record["edge_id"], "edge ID")
            if edge_id in edges:
                raise GraphValidationError("duplicate edge ID")
            source = _identifier(record["from_node"], "edge source")
            target = _identifier(record["to_node"], "edge target")
            if source not in nodes or target not in nodes:
                raise GraphValidationError("edge references unknown node")
            target_schema = _identifier(record["target_input_schema_ref"], "target input schema")
            if target_schema != nodes[target].input_schema_ref:
                raise GraphValidationError("edge target schema is incompatible")
            raw_mappings = record["input_mapping"]
            if not isinstance(raw_mappings, list) or not raw_mappings:
                raise GraphValidationError("edge input mapping is empty")
            mappings: list[InputMapping] = []
            for raw_mapping in raw_mappings:
                mapping = _exact_mapping(raw_mapping, frozenset({"source_path", "target_path"}), "input mapping")
                mappings.append(InputMapping(cls._path(mapping["source_path"], "source path"), cls._path(mapping["target_path"], "target path")))
            targets = [item.target_path for item in mappings]
            if len(targets) != len(set(targets)):
                raise GraphValidationError("duplicate input mapping target")
            for index, left in enumerate(targets):
                for right in targets[index + 1:]:
                    shared = min(len(left), len(right))
                    if left[:shared] == right[:shared]:
                        raise GraphValidationError("overlapping input mapping targets")
            source_schema = nodes[source].output_schema_ref
            for mapping in mappings:
                source_location = cls._schema_location(
                    schema_registry, source_schema, mapping.source_path,
                )
                target_location = cls._schema_location(
                    schema_registry, target_schema, mapping.target_path,
                )
                if (
                    cls._single_schema_type(source_location) is None
                    or cls._single_schema_type(target_location) is None
                    or freeze(source_location) != freeze(target_location)
                ):
                    raise GraphValidationError("edge source/target schema mapping is incompatible")
            condition = record["route_condition"]
            frozen_condition = freeze(condition)
            if not isinstance(frozen_condition, FrozenMap):
                raise GraphValidationError("route condition must be an object")
            program: GEELProgram | None = None
            program = GEELProgram.load(condition, StaticRootRegistry(roots), predicates, error_rules, context)
            if program.result_type != "boolean":
                raise GraphValidationError("route condition must return boolean")
            priority = record["route_priority"]
            if type(priority) is not int or priority < 0:
                raise GraphValidationError("route priority must be a nonnegative integer")
            required_trust = _identifier(record["required_trust"], "required trust")
            if required_trust not in trust.levels:
                raise GraphValidationError("edge requires unknown trust")
            invalidation = _identifier(record["invalidation_rule"], "invalidation rule")
            if invalidation not in INVALIDATION_RULES:
                raise GraphValidationError("unknown invalidation rule")
            failure_route = record["failure_route"]
            if failure_route is not None:
                failure_route = _identifier(failure_route, "failure route")
                if failure_route not in nodes:
                    raise GraphValidationError("failure route references unknown node")
            edges[edge_id] = EdgeDefinition(
                edge_id, source, target, tuple(mappings), target_schema, frozen_condition, priority,
                required_trust, _string_tuple(record["evidence_requirements"], "evidence requirement"),
                JoinPolicy.from_dict(record["join_policy"], predicates, error_rules, context),
                invalidation, failure_route,
            )
            programs[edge_id] = program
        return edges, programs

    @staticmethod
    def _schema_location(
        registry: ClosedSchemaRegistry,
        schema_id: str,
        path: tuple[str | int, ...],
    ) -> object:
        current: object = registry.resource(schema_id).schema
        current_id = schema_id
        seen: set[tuple[str, str]] = set()

        def dereference(value: object, active_id: str) -> tuple[object, str]:
            while isinstance(value, Mapping) and "$ref" in value:
                if set(value) != {"$ref"}:
                    raise GraphValidationError(
                        "schema mapping reference with sibling assertions is not assignable"
                    )
                reference = value["$ref"]
                if type(reference) is not str:
                    raise GraphValidationError("schema mapping contains invalid reference")
                identity = (active_id, reference)
                if identity in seen:
                    raise GraphValidationError("schema mapping reference cycle")
                seen.add(identity)
                try:
                    value, active_id = registry.resolve(active_id, reference)
                except ValueError as error:
                    raise GraphValidationError("schema mapping reference is unresolved") from error
            return value, active_id

        current, current_id = dereference(current, current_id)
        for token in path:
            if not isinstance(current, Mapping):
                raise GraphValidationError("schema mapping path traverses a scalar")
            if type(token) is str:
                properties = current.get("properties")
                if not isinstance(properties, Mapping) or token not in properties:
                    raise GraphValidationError("schema mapping path is undeclared")
                current = properties[token]
            else:
                prefix = current.get("prefixItems")
                if type(prefix) in (list, tuple) and token < len(prefix):
                    current = prefix[token]
                elif "items" in current:
                    current = current["items"]
                else:
                    raise GraphValidationError("schema mapping array path is undeclared")
            current, current_id = dereference(current, current_id)
        return current

    @staticmethod
    def _single_schema_type(schema: object) -> str | None:
        """Return the one provable JSON type for an exact-assignability fragment."""

        if not isinstance(schema, Mapping):
            return None
        declared = schema.get("type")
        if type(declared) is str:
            return declared
        if "const" in schema:
            value = schema["const"]
            if value is None:
                return "null"
            if type(value) is bool:
                return "boolean"
            if type(value) is int:
                return "integer"
            if type(value) is str:
                return "string"
            if type(value) in (list, tuple):
                return "array"
            if isinstance(value, Mapping):
                return "object"
        enum = schema.get("enum")
        if type(enum) in (list, tuple) and enum:
            types = {GraphDefinition._single_schema_type({"const": item}) for item in enum}
            if len(types) == 1:
                return next(iter(types))
        return None

    @staticmethod
    def _validate_route_groups(outgoing: Mapping[str, tuple[EdgeDefinition, ...]]) -> None:
        for edges in outgoing.values():
            signatures: set[tuple[str, int, str]] = set()
            for edge in edges:
                signature = (
                    edge.to_node,
                    edge.route_priority,
                    canonical_bytes(edge.route_condition).decode("utf-8"),
                )
                if signature in signatures:
                    raise GraphValidationError("ambiguous route group")
                signatures.add(signature)

    @staticmethod
    def _validate_join_groups(edges: Mapping[str, EdgeDefinition]) -> None:
        by_target: dict[str, list[EdgeDefinition]] = {}
        for edge in edges.values():
            by_target.setdefault(edge.to_node, []).append(edge)
        for inbound in by_target.values():
            policies = {(edge.join_policy.kind, edge.join_policy.quorum) for edge in inbound}
            if len(policies) != 1:
                raise GraphValidationError("inconsistent join policy for target")
            kind, quorum = next(iter(policies))
            if kind == "quorum" and (quorum is None or quorum > len(inbound)):
                raise GraphValidationError("join quorum exceeds inbound edges")

    @staticmethod
    def _control_topology(
        nodes: Mapping[str, NodeDefinition],
        outgoing: Mapping[str, tuple[EdgeDefinition, ...]],
    ) -> dict[str, tuple[str, ...]]:
        """Include normal, node-failure, and edge-failure transitions in topology checks."""

        topology: dict[str, tuple[str, ...]] = {}
        for node_id, node in nodes.items():
            targets = {edge.to_node for edge in outgoing[node_id]}
            targets.update(node.failure_routes.values())
            targets.update(
                edge.failure_route
                for edge in outgoing[node_id]
                if edge.failure_route is not None
            )
            topology[node_id] = tuple(sorted(targets))
        return topology

    @staticmethod
    def _validate_reachability(
        nodes: Mapping[str, NodeDefinition],
        control_outgoing: Mapping[str, tuple[str, ...]],
        entrypoints: tuple[str, ...],
        completion: tuple[str, ...],
    ) -> None:
        reachable = set(entrypoints)
        pending = list(entrypoints)
        while pending:
            current = pending.pop()
            for target in control_outgoing[current]:
                if target not in reachable:
                    reachable.add(target)
                    pending.append(target)
        missing = sorted(set(nodes) - reachable)
        if missing:
            raise GraphValidationError(f"unreachable nodes: {','.join(missing)}")
        reverse: dict[str, set[str]] = {node_id: set() for node_id in nodes}
        for source, targets in control_outgoing.items():
            for target in targets:
                reverse[target].add(source)
        can_complete = set(completion)
        pending = list(completion)
        while pending:
            current = pending.pop()
            for parent in reverse[current]:
                if parent not in can_complete:
                    can_complete.add(parent)
                    pending.append(parent)
        dead = sorted(set(nodes) - can_complete)
        if dead:
            raise GraphValidationError(f"dead-end nodes: {','.join(dead)}")

    @staticmethod
    def _cyclic_nodes(
        nodes: Mapping[str, NodeDefinition],
        control_outgoing: Mapping[str, tuple[str, ...]],
    ) -> set[str]:
        index = 0
        stack: list[str] = []
        on_stack: set[str] = set()
        indices: dict[str, int] = {}
        low: dict[str, int] = {}
        cyclic: set[str] = set()

        def visit(node_id: str) -> None:
            nonlocal index
            indices[node_id] = index
            low[node_id] = index
            index += 1
            stack.append(node_id)
            on_stack.add(node_id)
            for target in control_outgoing[node_id]:
                if target not in indices:
                    visit(target)
                    low[node_id] = min(low[node_id], low[target])
                elif target in on_stack:
                    low[node_id] = min(low[node_id], indices[target])
            if low[node_id] == indices[node_id]:
                component: list[str] = []
                while True:
                    item = stack.pop()
                    on_stack.remove(item)
                    component.append(item)
                    if item == node_id:
                        break
                if len(component) > 1 or node_id in control_outgoing[node_id]:
                    cyclic.update(component)

        for node_id in sorted(nodes):
            if node_id not in indices:
                visit(node_id)
        return cyclic

    def outgoing(self, node_id: str) -> tuple[EdgeDefinition, ...]:
        try:
            return self._outgoing[node_id]
        except KeyError as error:
            raise GraphValidationError("unknown node") from error

    def invalidation_dependency(
        self,
        binding_tags: Sequence[str],
    ) -> tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        """Resolve one TargetBinding tag to its exact typed-edge downstream closure."""
        if (
            type(binding_tags) not in (list, tuple)
            or not binding_tags
            or any(type(item) is not str or not item for item in binding_tags)
            or len(binding_tags) != len(set(binding_tags))
        ):
            raise GraphValidationError("TargetBinding invalidation tags are malformed")
        tags = set(binding_tags)
        matches = sorted(
            node.node_id
            for node in self.nodes.values()
            if tags.intersection(node.invalidation_tags)
        )
        if not matches:
            raise GraphValidationError("TargetBinding has no graph invalidation dependency")
        if len(matches) != 1:
            raise GraphValidationError("TargetBinding graph invalidation dependency is ambiguous")
        root = matches[0]
        nodes = {root}
        edge_ids: set[str] = set()
        pending = [root]
        while pending:
            source = pending.pop()
            for edge in self.outgoing(source):
                edge_ids.add(edge.edge_id)
                if edge.to_node not in nodes:
                    nodes.add(edge.to_node)
                    pending.append(edge.to_node)
        matched_tags = tuple(sorted(tags.intersection(self.nodes[root].invalidation_tags)))
        return root, tuple(sorted(nodes)), tuple(sorted(edge_ids)), matched_tags

    def failure_target(
        self,
        node_id: str,
        error_code: str,
        *,
        edge_id: str | None = None,
    ) -> str | None:
        """Resolve an edge-specific fallback first, then the node's exact error route."""

        if type(error_code) is not str or not error_code:
            raise GraphValidationError("invalid failure error code")
        try:
            node = self.nodes[node_id]
        except KeyError as error:
            raise GraphValidationError("unknown node") from error
        if edge_id is not None:
            if type(edge_id) is not str or not edge_id:
                raise GraphValidationError("invalid failure edge ID")
            try:
                edge = self.edges[edge_id]
            except KeyError as error:
                raise GraphValidationError("unknown failure edge") from error
            if edge.from_node != node_id:
                raise GraphValidationError("failure edge does not leave node")
            if edge.failure_route is not None:
                return edge.failure_route
        return node.failure_routes.get(error_code)

    def route(
        self,
        node_id: str,
        roots: Mapping[str, object],
        *,
        trust_by_edge: Mapping[str, str],
        evidence_by_edge: Mapping[str, Sequence[str]],
        context: WorkContext,
    ) -> tuple[EdgeDefinition, ...]:
        """Select at most one matching edge per target, defaulting closed."""

        if (
            not isinstance(roots, Mapping)
            or not isinstance(trust_by_edge, Mapping)
            or not isinstance(evidence_by_edge, Mapping)
            or type(context) is not WorkContext
        ):
            raise GraphValidationError("invalid route context")
        self._require_context(context)
        declared = {edge.edge_id for edge in self.outgoing(node_id)}
        if set(trust_by_edge) - declared or set(evidence_by_edge) - declared:
            raise GraphValidationError("route inputs reference an unknown edge")
        for values in evidence_by_edge.values():
            if (
                type(values) not in (list, tuple)
                or any(type(item) is not str or not item for item in values)
                or len(values) != len(set(values))
            ):
                raise GraphValidationError("invalid route evidence refs")
        matches: dict[str, list[EdgeDefinition]] = {}
        for edge in self.outgoing(node_id):
            current_trust = trust_by_edge.get(edge.edge_id)
            if current_trust is None or not self.trust_policy.satisfies(current_trust, edge.required_trust):
                continue
            evidence = evidence_by_edge.get(edge.edge_id)
            if evidence is None or not set(edge.evidence_requirements).issubset(evidence):
                continue
            program = self._route_programs[edge.edge_id]
            if program is None:
                matched = edge.route_condition["value"] is True
            else:
                result = program.evaluate(
                    roots, context, operation_path=context.child_path(()),
                )
                if result.get("status") != "ok" or type(result.get("value")) is not bool:
                    raise GraphValidationError(f"route evaluation failed closed: {edge.edge_id}")
                matched = result["value"]
            if matched:
                matches.setdefault(edge.to_node, []).append(edge)
        selected: list[EdgeDefinition] = []
        for target in sorted(matches):
            candidates = sorted(matches[target], key=lambda item: (item.route_priority, item.edge_id))
            best_priority = candidates[0].route_priority
            best = [item for item in candidates if item.route_priority == best_priority]
            if len(best) != 1:
                raise GraphValidationError(f"ambiguous runtime route to {target}")
            selected.append(best[0])
        return tuple(selected)

    def join_ready(
        self,
        target_node: str,
        passed_by_edge: Mapping[str, bool],
        context: WorkContext,
    ) -> bool:
        self._require_context(context)
        inbound = tuple(sorted((edge for edge in self.edges.values() if edge.to_node == target_node), key=lambda item: item.edge_id))
        if target_node not in self.nodes:
            raise GraphValidationError("unknown join target")
        if not inbound:
            return target_node in self.entrypoints
        if set(passed_by_edge) - {edge.edge_id for edge in inbound}:
            raise GraphValidationError("join result contains unknown edge")
        policy = inbound[0].join_policy
        values = tuple(passed_by_edge.get(edge.edge_id, False) for edge in inbound)
        return policy.satisfied(values, len(inbound), context)

    def completion_ready(self, passed_node_ids: Sequence[str], context: WorkContext) -> bool:
        self._require_context(context)
        if (
            type(passed_node_ids) not in (list, tuple)
            or any(type(item) is not str for item in passed_node_ids)
            or len(passed_node_ids) != len(set(passed_node_ids))
            or set(passed_node_ids) - set(self.nodes)
        ):
            raise GraphValidationError("completion input contains duplicate or unknown node")
        return self.completion_policy.satisfied(passed_node_ids, self.completion_nodes, context)
