"""GEEL v1 bounded AST loader and deterministic eager evaluator."""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.canonical import MAX_SAFE_INTEGER, canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.errors import ContractError, ErrorDetail, error_result
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry
from graph_engineering.core.contracts.immutable import FrozenMap, code_fingerprint, freeze
from graph_engineering.core.contracts.resources import WorkContext, bounded_measure, build_result_record, compare_charge


GEEL_SCHEMA_ID = "urn:gew:schema:geel-expression:1.0.0"
GEEL_CONTRACT_TYPE = "urn:gew:contract:geel-expression"
GEEL_PROJECTION_ID = "urn:gew:digest-projection:identity:1.0.0"
OPS = frozenset({
    "literal", "path", "all", "any", "not", "eq", "ne", "lt", "lte", "gt", "gte",
    "contains", "in", "length", "exists", "is_type", "predicate",
})
BINARY_OPS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte"})
JSON_TYPE_NAMES = frozenset({"null", "boolean", "integer", "string", "array", "object"})


def _json_type(value: object) -> str:
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
    return "invalid"


def _equal(left: object, right: object) -> bool:
    if _json_type(left) != _json_type(right):
        return False
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(_equal(left[key], right[key]) for key in left)
    if type(left) in (list, tuple) and type(right) in (list, tuple):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _error(
    code: str,
    phase: str,
    rule_id: str,
    source_id: str,
    *,
    evaluation_path: tuple[str | int, ...] = (),
    instance_path: tuple[str | int, ...] = (),
    definition_path: tuple[str | int, ...] = (),
) -> ContractError:
    return ContractError(ErrorDetail(
        code=code,
        phase=phase,
        rule_id=rule_id,
        source_id=source_id,
        instance_path=instance_path,
        definition_path=definition_path,
        evaluation_path=evaluation_path,
    ))


@dataclass(frozen=True, slots=True)
class RootPathType:
    root: str
    tokens: tuple[str | int, ...]
    value_type: str


class StaticRootRegistry:
    """Closed static root/path type declarations supplied by Graph validation."""

    __slots__ = ("_paths", "_roots")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("StaticRootRegistry is final")

    def __init__(self, declarations: Sequence[RootPathType]) -> None:
        paths: dict[tuple[str, tuple[str | int, ...]], str] = {}
        for declaration in declarations:
            if declaration.value_type not in JSON_TYPE_NAMES:
                raise ValueError("unknown static root value type")
            key = (declaration.root, declaration.tokens)
            if key in paths:
                raise ValueError("duplicate static root path")
            paths[key] = declaration.value_type
        object.__setattr__(self, "_paths", MappingProxyType(paths))
        object.__setattr__(self, "_roots", frozenset(root for root, _ in paths))

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("StaticRootRegistry is immutable after construction")

    def type_at(self, root: str, tokens: tuple[str | int, ...]) -> str:
        if root not in self._roots:
            raise _error("E_PATH_MISSING", "static", "path/root", GEEL_SCHEMA_ID, definition_path=("root",))
        try:
            return self._paths[(root, tokens)]
        except KeyError as error:
            raise _error("E_PATH_MISSING", "static", "path/undeclared", GEEL_SCHEMA_ID, definition_path=("tokens",)) from error


@dataclass(frozen=True, slots=True, init=False)
class PredicateSpec:
    predicate_id: str
    version: str
    argument_types: tuple[str, ...]
    result_type: str
    multipliers: Mapping[str, int]
    implementation_id: str
    implementation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("PredicateSpec must be loaded from the closed registry")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("PredicateSpec is final")

def _string_starts_with(arguments: tuple[object, ...]) -> object:
    left, prefix = arguments
    if type(left) is not str or type(prefix) is not str:
        raise ValueError("invalid built-in predicate input")
    return left.startswith(prefix)


_PREDICATE_CONTRACT_TYPE = "urn:gew:contract:predicate-registry"
_PREDICATE_SCHEMA_ID = "urn:gew:schema:predicate-registry:1.0.0"
_PREDICATE_PROJECTION_ID = "urn:gew:digest-projection:predicate-registry:1.0.0"
def _implementation_digest(implementation: Callable[[tuple[object, ...]], object]) -> str:
    return "sha256-raw-v1:" + hashlib.sha256(inspect.getsource(implementation).encode("utf-8")).hexdigest()


_STRING_STARTS_WITH_IDENTITY = (
    "urn:gew:predicate:string-starts-with",
    "1.0.0",
    "builtin:string-starts-with:v1",
)
_BUILTIN_IDENTITIES = frozenset({_STRING_STARTS_WITH_IDENTITY})


@dataclass(frozen=True, slots=True, init=False)
class PredicateRegistry:
    """Digest-locked closed registry mapped only to product built-ins."""

    registry_id: str
    registry_digest: str
    _values: Mapping[tuple[str, str], PredicateSpec]
    _implementation: tuple[
        tuple[str, str, str],
        str,
        object,
        str,
        Mapping[str, object],
        type,
    ]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("PredicateRegistry must be loaded from a manifest")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("PredicateRegistry is final")

    @classmethod
    def create_manifest(cls, registry_id: str, predicates: list[dict[str, object]]) -> dict[str, object]:
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:predicate-registry:"):
            raise ValueError("invalid predicate registry ID")
        keys: list[tuple[str, str]] = []
        for record in predicates:
            if set(record) != {
                "predicate_id", "version", "argument_types", "result_type", "multipliers",
                "implementation_id", "implementation_digest", "capabilities",
            }:
                raise ValueError("predicate manifest record is not exact")
            key = (record["predicate_id"], record["version"])
            if type(key[0]) is not str or type(key[1]) is not str:
                raise ValueError("predicate identity is invalid")
            keys.append(key)  # type: ignore[arg-type]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise ValueError("predicate manifest identities must be sorted and unique")
        manifest: dict[str, object] = {
            "schema_version": "1.0.0",
            "registry_id": registry_id,
            "predicates": predicates,
        }
        manifest["registry_digest"] = semantic_digest(
            manifest,
            contract_type=_PREDICATE_CONTRACT_TYPE,
            projection_id=_PREDICATE_PROJECTION_ID,
            schema_id=_PREDICATE_SCHEMA_ID,
        )
        return manifest

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> PredicateRegistry:
        if set(value) != {"schema_version", "registry_id", "predicates", "registry_digest"} or value.get("schema_version") != "1.0.0":
            raise ValueError("predicate registry manifest is not exact")
        registry_id = value.get("registry_id")
        predicates = value.get("predicates")
        registry_digest = value.get("registry_digest")
        if type(registry_id) is not str or not isinstance(predicates, list) or type(registry_digest) is not str:
            raise ValueError("predicate registry fields are invalid")
        expected = PredicateRegistry.create_manifest(registry_id, predicates)
        if expected["registry_digest"] != registry_digest:
            raise ValueError("predicate registry digest mismatch")
        records = {(record["predicate_id"], record["version"], record["implementation_id"]): record for record in predicates}
        if set(records) != _BUILTIN_IDENTITIES:
            raise ValueError("predicate registry must equal the closed product built-in set")
        specifications: dict[tuple[str, str], PredicateSpec] = {}
        binding: tuple[
            tuple[str, str, str],
            str,
            object,
            str,
            Mapping[str, object],
            type,
        ] | None = None
        for builtin_key in sorted(_BUILTIN_IDENTITIES):
            record = records[builtin_key]
            source_implementation = _string_starts_with
            try:
                implementation_digest = _implementation_digest(source_implementation)
            except (OSError, TypeError) as error:
                raise ValueError("predicate implementation attestation mismatch") from error
            closure = inspect.getclosurevars(source_implementation)
            if closure.globals or closure.nonlocals:
                raise ValueError("predicate implementation dependency closure is not self-contained")
            isolated_builtins = MappingProxyType({
                "ValueError": ValueError,
                "str": str,
                "type": type,
            })
            if record["capabilities"] != [] or record["implementation_digest"] != implementation_digest:
                raise ValueError("predicate implementation or capability binding mismatch")
            argument_types = record["argument_types"]
            multipliers = record["multipliers"]
            if not isinstance(argument_types, list) or not isinstance(multipliers, Mapping):
                raise ValueError("predicate signature or multipliers are invalid")
            frozen_multipliers = freeze(multipliers)
            if not isinstance(frozen_multipliers, FrozenMap):
                raise AssertionError("predicate multipliers must freeze to a map")
            specification = object.__new__(PredicateSpec)
            object.__setattr__(specification, "predicate_id", builtin_key[0])
            object.__setattr__(specification, "version", builtin_key[1])
            object.__setattr__(specification, "argument_types", tuple(argument_types))
            object.__setattr__(specification, "result_type", record["result_type"])
            object.__setattr__(specification, "multipliers", frozen_multipliers)
            object.__setattr__(specification, "implementation_id", builtin_key[2])
            object.__setattr__(specification, "implementation_digest", record["implementation_digest"])
            specifications[(builtin_key[0], builtin_key[1])] = specification
            binding = (
                builtin_key,
                implementation_digest,
                source_implementation.__code__,
                code_fingerprint(source_implementation.__code__),
                isolated_builtins,
                type(source_implementation),
            )
        if binding is None:
            raise AssertionError("closed predicate implementation binding is missing")
        result = object.__new__(PredicateRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", registry_digest)
        object.__setattr__(result, "_values", MappingProxyType(dict(specifications)))
        object.__setattr__(result, "_implementation", binding)
        return result

    def resolve(self, predicate_id: str, version: str) -> PredicateSpec:
        try:
            specification = self._values[(predicate_id, version)]
        except KeyError as error:
            raise _error("E_OPERATOR", "registry", "predicate/unknown", predicate_id) from error
        identity = (specification.predicate_id, specification.version, specification.implementation_id)
        bound_identity, bound_digest, bound_code, bound_code_fingerprint, isolated_builtins, function_type = self._implementation
        if (
            type(specification) is not PredicateSpec
            or identity != bound_identity
            or specification.implementation_digest != bound_digest
            or code_fingerprint(bound_code) != bound_code_fingerprint
            or function_type.__name__ != "function"
            or set(isolated_builtins) != {"ValueError", "str", "type"}
        ):
            raise ValueError("predicate specification attestation mismatch")
        return specification


@dataclass(frozen=True, slots=True)
class _Value:
    value: object | None = None
    error: ErrorDetail | None = None


def _shape(node: object, profile_limit: int, depth_limit: int) -> int:
    count = 0

    def visit(current: object, path: tuple[str | int, ...], depth: int) -> None:
        nonlocal count
        if depth > depth_limit:
            raise _error("E_LIMIT", "limit", "limit/ast_depth", GEEL_SCHEMA_ID, definition_path=path)
        count += 1
        if count > profile_limit:
            raise _error("E_LIMIT", "limit", "limit/ast_nodes", GEEL_SCHEMA_ID, definition_path=path)
        if not isinstance(current, Mapping) or type(current.get("op")) is not str:
            raise _error("E_SCHEMA", "schema", "schema/geel-node", GEEL_SCHEMA_ID, definition_path=path)
        op = current["op"]
        expected: set[str] | None = None
        children: list[tuple[object, str | int]] = []
        if op == "literal":
            expected = {"op", "value"}
            if _json_type(current.get("value")) not in {"null", "boolean", "integer", "string"}:
                raise _error("E_SCHEMA", "schema", "schema/literal", GEEL_SCHEMA_ID, definition_path=path)
        elif op in {"path", "exists"}:
            expected = {"op", "root", "tokens"}
            tokens = current.get("tokens")
            if type(current.get("root")) is not str or not isinstance(tokens, list) or any(type(token) not in (str, int) or (type(token) is int and token < 0) for token in tokens):
                raise _error("E_SCHEMA", "schema", "schema/path", GEEL_SCHEMA_ID, definition_path=path)
        elif op in {"all", "any"}:
            expected = {"op", "args"}
            args = current.get("args")
            if not isinstance(args, list) or not args:
                raise _error("E_SCHEMA", "schema", "schema/minItems", GEEL_SCHEMA_ID, definition_path=(*path, "args"))
            children = [(child, index) for index, child in enumerate(args)]
        elif op == "not":
            expected = {"op", "arg"}
            children = [(current.get("arg"), "arg")]
        elif op in BINARY_OPS:
            expected = {"op", "left", "right"}
            children = [(current.get("left"), "left"), (current.get("right"), "right")]
        elif op == "contains":
            expected = {"op", "container", "value"}
            children = [(current.get("container"), "container"), (current.get("value"), "value")]
        elif op == "in":
            expected = {"op", "value", "container"}
            children = [(current.get("value"), "value"), (current.get("container"), "container")]
        elif op == "length":
            expected = {"op", "value"}
            children = [(current.get("value"), "value")]
        elif op == "is_type":
            expected = {"op", "value", "expected"}
            if current.get("expected") not in JSON_TYPE_NAMES:
                raise _error("E_SCHEMA", "schema", "schema/is-type", GEEL_SCHEMA_ID, definition_path=path)
            children = [(current.get("value"), "value")]
        elif op == "predicate":
            expected = {"op", "predicate_id", "version", "args"}
            args = current.get("args")
            if type(current.get("predicate_id")) is not str or type(current.get("version")) is not str or not isinstance(args, list):
                raise _error("E_SCHEMA", "schema", "schema/predicate", GEEL_SCHEMA_ID, definition_path=path)
            children = [(child, index) for index, child in enumerate(args)]
        if expected is not None and set(current) != expected:
            raise _error("E_SCHEMA", "schema", "schema/exact-properties", GEEL_SCHEMA_ID, definition_path=path)
        for child, token in children:
            visit(child, (*path, token), depth + 1)

    visit(node, (), 1)
    return count


def _resolve_operators(node: Mapping[str, object], predicates: PredicateRegistry) -> None:
    op = node["op"]
    if op not in OPS:
        raise _error("E_OPERATOR", "registry", "operator/unknown", GEEL_SCHEMA_ID)
    if op == "predicate":
        predicates.resolve(node["predicate_id"], node["version"])  # type: ignore[arg-type]
    for child in _children(node):
        _resolve_operators(child, predicates)


def _children(node: Mapping[str, object]) -> list[Mapping[str, object]]:
    op = node["op"]
    raw: list[object]
    if op in {"all", "any", "predicate"}:
        raw = list(node["args"])  # type: ignore[arg-type]
    elif op == "not":
        raw = [node["arg"]]
    elif op in BINARY_OPS:
        raw = [node["left"], node["right"]]
    elif op == "contains":
        raw = [node["container"], node["value"]]
    elif op == "in":
        raw = [node["value"], node["container"]]
    elif op in {"length", "is_type"}:
        raw = [node["value"]]
    else:
        raw = []
    return [child for child in raw if isinstance(child, Mapping)]


def _static_type(node: Mapping[str, object], roots: StaticRootRegistry, predicates: PredicateRegistry, path_limit: int) -> str:
    op = node["op"]
    children = _children(node)
    child_types = [_static_type(child, roots, predicates, path_limit) for child in children]
    if op == "literal":
        return _json_type(node["value"])
    if op in {"path", "exists"}:
        tokens = tuple(node["tokens"])  # type: ignore[arg-type]
        if len(tokens) > path_limit:
            raise _error("E_LIMIT", "limit", "limit/path_tokens", GEEL_SCHEMA_ID)
        path_type = roots.type_at(node["root"], tokens)  # type: ignore[arg-type]
        return "boolean" if op == "exists" else path_type
    if op in {"all", "any", "not"}:
        if any(value != "boolean" for value in child_types):
            raise _error("E_TYPE", "static", "type/boolean-operand", GEEL_SCHEMA_ID)
        return "boolean"
    if op in {"eq", "ne"}:
        if child_types[0] != child_types[1]:
            raise _error("E_TYPE", "static", "type/equality-operands", GEEL_SCHEMA_ID)
        return "boolean"
    if op in {"lt", "lte", "gt", "gte"}:
        if child_types[0] != child_types[1] or child_types[0] not in {"integer", "string"}:
            raise _error("E_TYPE", "static", "type/order-operands", GEEL_SCHEMA_ID)
        return "boolean"
    if op in {"contains", "in"}:
        container_index = 0 if op == "contains" else 1
        if child_types[container_index] != "array":
            raise _error("E_TYPE", "static", "type/membership-container", GEEL_SCHEMA_ID)
        return "boolean"
    if op == "length":
        if child_types[0] not in {"string", "array", "object"}:
            raise _error("E_TYPE", "static", "type/length-value", GEEL_SCHEMA_ID)
        return "integer"
    if op == "is_type":
        return "boolean"
    if op == "predicate":
        specification = predicates.resolve(node["predicate_id"], node["version"])  # type: ignore[arg-type]
        if tuple(child_types) != specification.argument_types:
            raise _error("E_TYPE", "static", "type/predicate-arguments", specification.predicate_id)
        return specification.result_type
    raise _error("E_OPERATOR", "registry", "operator/unknown", GEEL_SCHEMA_ID)


class GEELProgram:
    """Validated, digest-identified GEEL expression."""

    __slots__ = ("expression", "result_type", "predicates", "error_rules", "digest", "_sealed")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("GEELProgram must be created by GEELProgram.load")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("GEELProgram is final")

    @staticmethod
    def _create(
        expression: Mapping[str, object],
        result_type: str,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
    ) -> GEELProgram:
        frozen_expression = freeze(expression)
        if not isinstance(frozen_expression, FrozenMap):
            raise AssertionError("GEEL expression must freeze to an object")
        result = object.__new__(GEELProgram)
        object.__setattr__(result, "expression", frozen_expression)
        object.__setattr__(result, "result_type", result_type)
        object.__setattr__(result, "predicates", predicates)
        object.__setattr__(result, "error_rules", error_rules)
        object.__setattr__(result, "digest", semantic_digest(frozen_expression, contract_type=GEEL_CONTRACT_TYPE, projection_id=GEEL_PROJECTION_ID, schema_id=GEEL_SCHEMA_ID))
        object.__setattr__(result, "_sealed", True)
        return result

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("GEELProgram is immutable after load")

    @classmethod
    def load(
        cls,
        expression: Mapping[str, object],
        roots: StaticRootRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> GEELProgram:
        if type(roots) is not StaticRootRegistry:
            raise TypeError("GEEL load requires the exact static root registry")
        if type(predicates) is not PredicateRegistry:
            raise TypeError("GEEL load requires the exact predicate registry")
        if type(error_rules) is not ErrorRuleRegistry:
            raise TypeError("GEEL load requires the exact error rule registry")
        try:
            _shape(expression, context.profile.limits["ast_nodes"], context.profile.limits["ast_depth"])
            _resolve_operators(expression, predicates)
            result_type = _static_type(expression, roots, predicates, context.profile.limits["path_tokens"])
            if result_type != "boolean":
                raise _error("E_TYPE", "static", "type/root-result", GEEL_SCHEMA_ID)
            return GEELProgram._create(expression, result_type, predicates, error_rules)
        except ContractError as error:
            error_rules.require(error.detail)
            raise

    def evaluate(
        self,
        roots: Mapping[str, object],
        context: WorkContext,
        *,
        operation_path: tuple[int, ...] = (),
    ) -> dict[str, object]:
        try:
            outcome = self._evaluate_node(
                self.expression, roots, context, operation_path, (),
            )
            if outcome.error is not None:
                self.error_rules.require(outcome.error)
            fields = (
                (("error", outcome.error.as_dict()), ("schema_version", "1.0.0"), ("status", "error"))
                if outcome.error is not None
                else (("schema_version", "1.0.0"), ("status", "ok"), ("value", outcome.value))
            )
            return build_result_record(
                fields, context, source_id=self.digest, parent_path=operation_path,
            )
        except ContractError as error:
            self.error_rules.require(error.detail)
            return error_result(error.detail)

    def _evaluate_node(
        self,
        node: Mapping[str, object],
        roots: Mapping[str, object],
        context: WorkContext,
        operation_path: tuple[int, ...],
        evaluation_path: tuple[str | int, ...],
    ) -> _Value:
        context.emit("geel.node", 1, operation_path=operation_path, source_id=self.digest, evaluation_path=evaluation_path)
        op = node["op"]
        if op == "literal":
            return _Value(node["value"])
        if op in {"path", "exists"}:
            return self._evaluate_path(node, roots, context, operation_path, evaluation_path, exists=op == "exists")
        raw_children = _children(node)
        values: list[_Value] = []
        for index, child in enumerate(raw_children):
            context.emit("geel.operand", 1, operation_path=operation_path, source_id=self.digest, evaluation_path=evaluation_path)
            child_path = context.child_path(operation_path)
            values.append(self._evaluate_node(child, roots, context, child_path, (*evaluation_path, index)))
        first_error = next((value.error for value in values if value.error is not None), None)
        if first_error is not None:
            return _Value(error=first_error)
        operands = [value.value for value in values]
        if op in {"all", "any"}:
            if any(type(value) is not bool for value in operands):
                return _Value(error=_error("E_TYPE", "runtime", "type/boolean-operand", self.digest, evaluation_path=evaluation_path).detail)
            return _Value(all(operands) if op == "all" else any(operands))
        if op == "not":
            if type(operands[0]) is not bool:
                return _Value(error=_error("E_TYPE", "runtime", "type/boolean-operand", self.digest, evaluation_path=evaluation_path).detail)
            return _Value(not operands[0])
        if op in BINARY_OPS:
            return self._evaluate_binary(op, operands[0], operands[1], context, operation_path, evaluation_path)
        if op in {"contains", "in"}:
            container = operands[0] if op == "contains" else operands[1]
            sought = operands[1] if op == "contains" else operands[0]
            if type(container) not in (list, tuple):
                return _Value(error=_error("E_TYPE", "runtime", "type/membership-container", self.digest, evaluation_path=evaluation_path).detail)
            matches: list[bool] = []
            for index, item in enumerate(container):
                context.emit("geel.membership_item", 1, operation_path=operation_path, source_id=self.digest, evaluation_path=evaluation_path)
                compare_path = context.child_path(operation_path)
                compare_charge(item, sought, context, operation_path=compare_path, source_id=self.digest, evaluation_path=(*evaluation_path, index))
                matches.append(_equal(item, sought))
            return _Value(any(matches))
        if op == "length":
            value = operands[0]
            if type(value) is str or type(value) in (list, tuple) or isinstance(value, Mapping):
                return _Value(len(value))
            return _Value(error=_error("E_TYPE", "runtime", "type/length-value", self.digest, evaluation_path=evaluation_path).detail)
        if op == "is_type":
            return _Value(_json_type(operands[0]) == node["expected"])
        if op == "predicate":
            return self._evaluate_predicate(node, tuple(operands), context, operation_path, evaluation_path)
        return _Value(error=_error("E_OPERATOR", "registry", "operator/unknown", self.digest, evaluation_path=evaluation_path).detail)

    def _evaluate_path(
        self,
        node: Mapping[str, object],
        roots: Mapping[str, object],
        context: WorkContext,
        operation_path: tuple[int, ...],
        evaluation_path: tuple[str | int, ...],
        *,
        exists: bool,
    ) -> _Value:
        root = node["root"]
        if root not in roots:
            detail = _error("E_PATH_MISSING", "runtime", "path/root-missing", self.digest, evaluation_path=evaluation_path).detail
            return _Value(False) if exists else _Value(error=detail)
        current = roots[root]
        traversed: list[str | int] = []
        for token in node["tokens"]:  # type: ignore[union-attr]
            context.emit("geel.path_token", 1, operation_path=operation_path, source_id=self.digest, evaluation_path=evaluation_path)
            if type(token) is str and isinstance(current, Mapping):
                if token not in current:
                    detail = _error("E_PATH_MISSING", "runtime", "path/member-missing", self.digest, evaluation_path=evaluation_path, instance_path=tuple(traversed)).detail
                    return _Value(False) if exists else _Value(error=detail)
                current = current[token]
            elif type(token) is int and type(current) in (list, tuple):
                if token >= len(current):
                    detail = _error("E_PATH_MISSING", "runtime", "path/index-missing", self.digest, evaluation_path=evaluation_path, instance_path=tuple(traversed)).detail
                    return _Value(False) if exists else _Value(error=detail)
                current = current[token]
            else:
                detail = _error("E_PATH_TYPE", "runtime", "path/container-type", self.digest, evaluation_path=evaluation_path, instance_path=tuple(traversed)).detail
                return _Value(error=detail)
            traversed.append(token)
        return _Value(True if exists else current)

    def _evaluate_binary(
        self,
        op: str,
        left: object,
        right: object,
        context: WorkContext,
        operation_path: tuple[int, ...],
        evaluation_path: tuple[str | int, ...],
    ) -> _Value:
        compare_path = context.child_path(operation_path)
        compare_charge(left, right, context, operation_path=compare_path, source_id=self.digest, evaluation_path=evaluation_path)
        if _json_type(left) != _json_type(right):
            return _Value(error=_error("E_TYPE", "runtime", "type/binary-operands", self.digest, evaluation_path=evaluation_path).detail)
        if op == "eq":
            return _Value(_equal(left, right))
        if op == "ne":
            return _Value(not _equal(left, right))
        if _json_type(left) not in {"integer", "string"}:
            return _Value(error=_error("E_TYPE", "runtime", "type/order-operands", self.digest, evaluation_path=evaluation_path).detail)
        operations = {"lt": left < right, "lte": left <= right, "gt": left > right, "gte": left >= right}  # type: ignore[operator]
        return _Value(operations[op])

    def _evaluate_predicate(
        self,
        node: Mapping[str, object],
        arguments: tuple[object, ...],
        context: WorkContext,
        operation_path: tuple[int, ...],
        evaluation_path: tuple[str | int, ...],
    ) -> _Value:
        specification = self.predicates.resolve(node["predicate_id"], node["version"])  # type: ignore[arg-type]
        if tuple(_json_type(value) for value in arguments) != specification.argument_types:
            return _Value(error=_error("E_TYPE", "runtime", "type/predicate-arguments", specification.predicate_id, evaluation_path=evaluation_path).detail)
        bound_identity, bound_digest, bound_code, bound_code_fingerprint, isolated_builtins, function_type = self.predicates._implementation
        identity = (specification.predicate_id, specification.version, specification.implementation_id)
        if (
            identity != bound_identity
            or specification.implementation_digest != bound_digest
            or code_fingerprint(bound_code) != bound_code_fingerprint
            or function_type.__name__ != "function"
            or set(isolated_builtins) != {"ValueError", "str", "type"}
        ):
            raise ValueError("predicate implementation attestation mismatch")
        implementation = function_type(bound_code, {"__builtins__": isolated_builtins})
        executable_path = context.child_path(operation_path)
        aggregate = bounded_measure(list(arguments), context, source_id=specification.predicate_id, operation_path=executable_path)
        for event_id, count in (
            ("executable.base", 1),
            ("executable.input_node", aggregate.nodes),
            ("executable.input_scalar", aggregate.string_scalars),
            ("executable.input_byte", aggregate.canonical_bytes),
        ):
            context.emit(event_id, count, operation_path=executable_path, multiplier=specification.multipliers[event_id], source_id=specification.predicate_id, evaluation_path=evaluation_path)
        try:
            result = implementation(arguments)
        except Exception:
            return _Value(error=_error("E_PREDICATE", "runtime", "predicate/declared-error", specification.predicate_id, evaluation_path=evaluation_path).detail)
        if _json_type(result) != specification.result_type:
            return _Value(error=_error("E_PREDICATE", "runtime", "predicate/result-type", specification.predicate_id, evaluation_path=evaluation_path).detail)
        return _Value(result)
