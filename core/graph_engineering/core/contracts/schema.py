"""GEW Schema Profile v1 linter and deterministic instance evaluator."""

from __future__ import annotations

import base64
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import MAX_SAFE_INTEGER, MIN_SAFE_INTEGER, canonical_bytes
from graph_engineering.core.contracts.formats import allowed_formats, validate_format
from graph_engineering.core.contracts.resources import WorkContext, compare_charge


SCHEMA_ID = re.compile(r"urn:gew:schema:[a-z][a-z0-9]*(?:-[a-z0-9]+)*:(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\Z")
ALLOWED_KEYWORDS = frozenset({
    "$schema", "$id", "$defs", "$ref", "$comment",
    "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "dependentSchemas",
    "prefixItems", "items", "contains", "properties", "additionalProperties",
    "type", "enum", "const", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "minContains", "maxContains",
    "minProperties", "maxProperties", "required", "dependentRequired",
    "unevaluatedProperties", "unevaluatedItems",
    "title", "description", "deprecated", "readOnly", "writeOnly", "format", "pattern",
})
ALLOWED_PATTERNS = frozenset({
    r"^sha256-jcs-v1:[0-9a-f]{64}$",
    r"^sha256:[0-9a-f]{64}$",
    r"^profile-coverage-execution:sha256:[0-9a-f]{64}$",
    r"^evidence-bytes-sha256:[0-9a-f]{64}$",
    r"^task:wp08-coverage:gew-(?:pro|psc)-[a-z0-9-]+-[pr]$",
    r"^[0-9a-f]{64}$",
    r"^[0-9a-f]{40,64}$",
})
JSON_TYPES = frozenset({"null", "boolean", "integer", "string", "array", "object"})
ANNOTATIONS = frozenset({"title", "description", "deprecated", "readOnly", "writeOnly", "$comment"})


@dataclass(frozen=True, slots=True)
class SchemaViolation:
    rule_id: str
    source_id: str
    instance_path: tuple[str | int, ...]
    definition_path: tuple[str | int, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "code": "E_SCHEMA",
            "definition_path": list(self.definition_path),
            "evaluation_path": [],
            "instance_path": list(self.instance_path),
            "phase": "schema",
            "rule_id": self.rule_id,
            "source_id": self.source_id,
        }


@dataclass(frozen=True, slots=True)
class SchemaProfilePolicy:
    """Installed values for the frozen schema profile."""

    profile_id: str
    schema_version: str
    dialect_id: str

    def __post_init__(self) -> None:
        if type(self.profile_id) is not str or not self.profile_id.startswith("urn:gew:schema-profile:"):
            raise ValueError("invalid schema profile ID")
        if type(self.schema_version) is not str or type(self.dialect_id) is not str:
            raise ValueError("invalid schema profile values")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SchemaProfilePolicy:
        if set(value) != {"profile_id", "schema_version", "dialect_id"}:
            raise ValueError("SchemaProfilePolicy properties are not exact")
        profile_id = value["profile_id"]
        schema_version = value["schema_version"]
        dialect_id = value["dialect_id"]
        if type(profile_id) is not str or not profile_id.startswith("urn:gew:schema-profile:"):
            raise ValueError("invalid schema profile ID")
        if type(schema_version) is not str or type(dialect_id) is not str:
            raise ValueError("invalid schema profile values")
        return cls(profile_id, schema_version, dialect_id)


class SchemaProfileError(ValueError):
    def __init__(self, rule_id: str, definition_path: tuple[str | int, ...]) -> None:
        super().__init__(f"{rule_id} at {list(definition_path)}")
        self.rule_id = rule_id
        self.definition_path = definition_path


Resolver = Callable[[str, str], tuple[object, str]]


def _fail(rule_id: str, path: tuple[str | int, ...]) -> None:
    raise SchemaProfileError(rule_id, path)


def _schema_children(schema: Mapping[str, object], path: tuple[str | int, ...]) -> list[tuple[object, tuple[str | int, ...]]]:
    children: list[tuple[object, tuple[str | int, ...]]] = []
    for keyword in ("$defs", "properties", "dependentSchemas"):
        value = schema.get(keyword)
        if isinstance(value, Mapping):
            children.extend((child, (*path, keyword, key)) for key, child in value.items())
    for keyword in ("additionalProperties", "unevaluatedProperties", "unevaluatedItems", "items", "contains", "not", "if", "then", "else"):
        if keyword in schema:
            children.append((schema[keyword], (*path, keyword)))
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        value = schema.get(keyword)
        if isinstance(value, list):
            children.extend((child, (*path, keyword, index)) for index, child in enumerate(value))
    return children


def _validate_schema_node(schema: object, path: tuple[str | int, ...], policy: SchemaProfilePolicy, *, root: bool) -> None:
    if type(schema) is bool:
        return
    if not isinstance(schema, Mapping) or any(type(key) is not str for key in schema):
        _fail("profile/schema-object", path)
    unknown = set(schema) - ALLOWED_KEYWORDS
    if unknown:
        _fail("profile/unknown-keyword", (*path, sorted(unknown)[0]))
    if not root and "$id" in schema:
        _fail("profile/nested-id", (*path, "$id"))
    if "$schema" in schema and schema["$schema"] != policy.dialect_id:
        _fail("profile/dialect", (*path, "$schema"))
    if "$ref" in schema and type(schema["$ref"]) is not str:
        _fail("profile/ref-type", (*path, "$ref"))
    value_type = schema.get("type")
    if value_type is not None:
        values = [value_type] if type(value_type) is str else value_type
        if not isinstance(values, list) or not values or any(type(item) is not str or item not in JSON_TYPES for item in values) or len(values) != len(set(values)):
            _fail("profile/type", (*path, "type"))
    if schema.get("format") not in (None, *allowed_formats()):
        _fail("profile/format", (*path, "format"))
    if schema.get("pattern") not in (None, *ALLOWED_PATTERNS):
        _fail("profile/pattern", (*path, "pattern"))
    for keyword in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "minItems", "maxItems", "minContains", "maxContains", "minProperties", "maxProperties"):
        if keyword in schema:
            value = schema[keyword]
            lower = MIN_SAFE_INTEGER if keyword in {"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"} else 0
            if type(value) is not int or not lower <= value <= MAX_SAFE_INTEGER:
                _fail("profile/integer-bound", (*path, keyword))
    if value_type == "array" and "maxItems" not in schema:
        _fail("profile/array-bound", path)
    if value_type == "array" and not ({"items", "prefixItems"} & set(schema)):
        _fail("profile/array-items", path)
    for keyword in ("required",):
        if keyword in schema:
            value = schema[keyword]
            if not isinstance(value, list) or any(type(item) is not str for item in value) or len(value) != len(set(value)):
                _fail("profile/string-array", (*path, keyword))
    if "dependentRequired" in schema:
        value = schema["dependentRequired"]
        if not isinstance(value, Mapping):
            _fail("profile/dependent-required", (*path, "dependentRequired"))
        for key, members in value.items():
            if type(key) is not str or not isinstance(members, list) or any(type(item) is not str for item in members) or len(members) != len(set(members)):
                _fail("profile/dependent-required", (*path, "dependentRequired", str(key)))
    for keyword in ("$defs", "properties", "dependentSchemas"):
        if keyword in schema and (not isinstance(schema[keyword], Mapping) or any(type(key) is not str for key in schema[keyword])):
            _fail("profile/schema-map", (*path, keyword))
    for keyword in ("allOf", "anyOf", "oneOf", "prefixItems"):
        if keyword in schema and (not isinstance(schema[keyword], list) or not schema[keyword]):
            _fail("profile/schema-array", (*path, keyword))
    for child, child_path in _schema_children(schema, path):
        _validate_schema_node(child, child_path, policy, root=False)


def validate_schema_profile(schema: object, policy: SchemaProfilePolicy) -> str:
    """Validate a product schema against the frozen GEW Schema Profile v1."""

    if not isinstance(schema, Mapping):
        _fail("profile/root-object", ())
    if schema.get("$schema") != policy.dialect_id:
        _fail("profile/root-dialect", ("$schema",))
    schema_id = schema.get("$id")
    if type(schema_id) is not str or (match := SCHEMA_ID.fullmatch(schema_id)) is None:
        _fail("profile/root-id", ("$id",))
    if schema.get("type") != "object":
        _fail("profile/root-type", ("type",))
    properties = schema.get("properties")
    required = schema.get("required")
    if not isinstance(properties, Mapping) or "schema_version" not in properties:
        _fail("profile/schema-version-property", ("properties",))
    version_schema = properties["schema_version"]
    if not isinstance(version_schema, Mapping) or version_schema.get("const") != match.group("version"):
        _fail("profile/schema-version-const", ("properties", "schema_version"))
    if not isinstance(required, list) or "schema_version" not in required:
        _fail("profile/schema-version-required", ("required",))
    if schema.get("unevaluatedProperties") is not False:
        _fail("profile/root-closed", ("unevaluatedProperties",))
    _validate_schema_node(schema, (), policy, root=True)
    return schema_id


def _type_name(value: object) -> str:
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


def _json_equal(left: object, right: object) -> bool:
    if _type_name(left) != _type_name(right):
        return False
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        return set(left) == set(right) and all(_json_equal(left[key], right[key]) for key in left)
    if type(left) in (list, tuple) and type(right) in (list, tuple):
        return len(left) == len(right) and all(_json_equal(a, b) for a, b in zip(left, right, strict=True))
    return left == right


def _violation(rule: str, source_id: str, instance_path: tuple[str | int, ...], definition_path: tuple[str | int, ...]) -> SchemaViolation:
    return SchemaViolation(f"schema/{rule}", source_id, instance_path, definition_path)


def _successful_annotations(
    schema: object,
    instance: object,
    *,
    source_id: str,
    instance_path: tuple[str | int, ...],
    definition_path: tuple[str | int, ...],
    resolver: Resolver | None,
) -> tuple[set[str], set[int]]:
    """Collect Draft 2020-12 evaluated annotations from successful subschemas."""

    if not isinstance(schema, Mapping):
        return set(), set()
    properties: set[str] = set()
    items: set[int] = set()
    declared = schema.get("properties")
    if isinstance(instance, Mapping) and isinstance(declared, Mapping):
        properties.update(set(instance) & set(declared))
    if isinstance(instance, Mapping) and "additionalProperties" in schema and isinstance(declared, Mapping):
        properties.update(set(instance) - set(declared))
    prefix = schema.get("prefixItems")
    if type(instance) in (list, tuple) and type(prefix) in (list, tuple):
        items.update(range(min(len(instance), len(prefix))))
    if type(instance) in (list, tuple) and "items" in schema:
        start = len(prefix) if type(prefix) in (list, tuple) else 0
        items.update(range(start, len(instance)))

    def merge_if_success(child: object, child_definition: tuple[str | int, ...]) -> None:
        failures = _evaluate(
            child,
            instance,
            source_id=source_id,
            instance_path=instance_path,
            definition_path=child_definition,
            resolver=resolver,
        )
        if not failures:
            child_properties, child_items = _successful_annotations(
                child,
                instance,
                source_id=source_id,
                instance_path=instance_path,
                definition_path=child_definition,
                resolver=resolver,
            )
            properties.update(child_properties)
            items.update(child_items)

    if "$ref" in schema and resolver is not None:
        target, target_source = resolver(source_id, schema["$ref"])  # type: ignore[arg-type]
        if not _evaluate(target, instance, source_id=target_source, instance_path=instance_path, definition_path=(), resolver=resolver):
            target_properties, target_items = _successful_annotations(
                target,
                instance,
                source_id=target_source,
                instance_path=instance_path,
                definition_path=(),
                resolver=resolver,
            )
            properties.update(target_properties)
            items.update(target_items)
    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if type(branches) in (list, tuple):
            for index, child in enumerate(branches):
                merge_if_success(child, (*definition_path, keyword, index))
    dependent = schema.get("dependentSchemas")
    if isinstance(instance, Mapping) and isinstance(dependent, Mapping):
        for trigger, child in dependent.items():
            if trigger in instance:
                merge_if_success(child, (*definition_path, "dependentSchemas", trigger))
    if "if" in schema:
        condition = _evaluate(schema["if"], instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, "if"), resolver=resolver)
        branch = "then" if not condition else "else"
        if branch in schema:
            merge_if_success(schema[branch], (*definition_path, branch))
    if type(instance) in (list, tuple) and "contains" in schema:
        for index, item in enumerate(instance):
            if not _evaluate(schema["contains"], item, source_id=source_id, instance_path=(*instance_path, index), definition_path=(*definition_path, "contains"), resolver=resolver):
                items.add(index)
    return properties, items


def _charge_schema(
    schema: object,
    instance: object,
    *,
    source_id: str,
    resolver: Resolver | None,
    context: WorkContext,
    operation_path: tuple[int, ...],
) -> None:
    """Emit the frozen recursive schema work model before each operation."""

    context.emit("schema.instance_visit", 1, operation_path=operation_path, source_id=source_id)
    if not isinstance(schema, Mapping):
        return
    for keyword in sorted(schema, key=lambda value: value.encode("utf-8")):
        context.emit("schema.keyword", 1, operation_path=operation_path, source_id=source_id)
        if keyword == "$ref":
            context.emit("schema.ref", 1, operation_path=operation_path, source_id=source_id)
            if resolver is not None:
                target, target_source = resolver(source_id, schema[keyword])  # type: ignore[arg-type]
                _charge_schema(
                    target,
                    instance,
                    source_id=target_source,
                    resolver=resolver,
                    context=context,
                    operation_path=context.child_path(operation_path),
                )
        elif keyword == "format" and type(instance) is str:
            context.emit("schema.format", 1, operation_path=operation_path, source_id=source_id)
            format_path = context.child_path(operation_path)
            for _ in instance:
                context.emit("format.scalar", 1, operation_path=format_path, source_id=source_id)
            if schema[keyword] == "gew-opaque-ref" and validate_format("gew-opaque-ref", instance):
                padding = "=" * ((4 - len(instance) % 4) % 4)
                for _ in base64.urlsafe_b64decode(instance + padding):
                    context.emit("format.decoded_byte", 1, operation_path=format_path, source_id=source_id)
        elif keyword in {"properties", "additionalProperties", "unevaluatedProperties", "dependentSchemas"} and isinstance(instance, Mapping):
            declared = schema.get("properties")
            for name in sorted(instance, key=lambda value: value.encode("utf-16-be")):
                context.emit("schema.property", 1, operation_path=operation_path, source_id=source_id)
                child: object | None = None
                if keyword == "properties" and isinstance(schema[keyword], Mapping):
                    child = schema[keyword].get(name)
                elif keyword == "additionalProperties" and (not isinstance(declared, Mapping) or name not in declared):
                    child = schema[keyword]
                elif keyword == "unevaluatedProperties":
                    child = schema[keyword] if schema[keyword] is not False else None
                elif keyword == "dependentSchemas" and isinstance(schema[keyword], Mapping) and name in schema[keyword]:
                    child = schema[keyword][name]
                if child is not None:
                    _charge_schema(
                        child,
                        instance if keyword == "dependentSchemas" else instance[name],
                        source_id=source_id,
                        resolver=resolver,
                        context=context,
                        operation_path=context.child_path(operation_path),
                    )
        elif keyword in {"prefixItems", "items", "contains", "unevaluatedItems"} and type(instance) in (list, tuple):
            prefix = schema.get("prefixItems")
            for index, item in enumerate(instance):
                context.emit("schema.item", 1, operation_path=operation_path, source_id=source_id)
                child = None
                if keyword == "prefixItems" and type(schema[keyword]) in (list, tuple) and index < len(schema[keyword]):
                    child = schema[keyword][index]
                elif keyword == "items" and (type(prefix) not in (list, tuple) or index >= len(prefix)):
                    child = schema[keyword]
                elif keyword == "contains":
                    child = schema[keyword]
                elif keyword == "unevaluatedItems" and schema[keyword] is not False:
                    child = schema[keyword]
                if child is not None:
                    _charge_schema(
                        child,
                        item,
                        source_id=source_id,
                        resolver=resolver,
                        context=context,
                        operation_path=context.child_path(operation_path),
                    )
        elif keyword in {"allOf", "anyOf", "oneOf"} and type(schema[keyword]) in (list, tuple):
            acquired = 0
            try:
                for child in schema[keyword]:
                    context.emit("schema.branch", 1, operation_path=operation_path, source_id=source_id)
                    _charge_schema(
                        child,
                        instance,
                        source_id=source_id,
                        resolver=resolver,
                        context=context,
                        operation_path=context.child_path(operation_path),
                    )
                    context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
                    acquired += 1
            finally:
                context.release_temporary(acquired)
        elif keyword in {"not", "if", "then", "else"}:
            context.emit("schema.branch", 1, operation_path=operation_path, source_id=source_id)
            _charge_schema(
                schema[keyword],
                instance,
                source_id=source_id,
                resolver=resolver,
                context=context,
                operation_path=context.child_path(operation_path),
            )
        elif keyword == "uniqueItems" and schema[keyword] is True and type(instance) in (list, tuple):
            for left in range(len(instance)):
                for right in range(left + 1, len(instance)):
                    context.emit("unique.pair", 1, operation_path=operation_path, source_id=source_id)
                    compare_charge(
                        instance[left],
                        instance[right],
                        context,
                        operation_path=context.child_path(operation_path),
                        source_id=source_id,
                    )


def _evaluate(
    schema: object,
    instance: object,
    *,
    source_id: str,
    instance_path: tuple[str | int, ...],
    definition_path: tuple[str | int, ...],
    resolver: Resolver | None,
) -> list[SchemaViolation]:
    if schema is True:
        return []
    if schema is False:
        return [_violation("false-schema", source_id, instance_path, definition_path)]
    if not isinstance(schema, Mapping):
        return [_violation("schema-object", source_id, instance_path, definition_path)]
    failures: list[SchemaViolation] = []
    if "$ref" in schema:
        if resolver is None:
            return [_violation("$ref", source_id, instance_path, (*definition_path, "$ref"))]
        target, target_source = resolver(source_id, schema["$ref"])  # type: ignore[arg-type]
        failures.extend(_evaluate(target, instance, source_id=target_source, instance_path=instance_path, definition_path=(), resolver=resolver))
    expected = schema.get("type")
    if expected is not None:
        allowed = {expected} if type(expected) is str else set(expected)  # type: ignore[arg-type]
        if _type_name(instance) not in allowed:
            failures.append(_violation("type", source_id, instance_path, (*definition_path, "type")))
            return failures
    if "enum" in schema and (type(schema["enum"]) not in (list, tuple) or not any(_json_equal(instance, candidate) for candidate in schema["enum"])):
        failures.append(_violation("enum", source_id, instance_path, (*definition_path, "enum")))
    if "const" in schema and not _json_equal(instance, schema["const"]):
        failures.append(_violation("const", source_id, instance_path, (*definition_path, "const")))
    if type(instance) is int:
        checks = {
            "minimum": lambda bound: instance >= bound,
            "maximum": lambda bound: instance <= bound,
            "exclusiveMinimum": lambda bound: instance > bound,
            "exclusiveMaximum": lambda bound: instance < bound,
        }
        for keyword, check in checks.items():
            if keyword in schema and not check(schema[keyword]):  # type: ignore[arg-type]
                failures.append(_violation(keyword, source_id, instance_path, (*definition_path, keyword)))
    if type(instance) is str:
        for keyword, valid in (
            ("minLength", lambda bound: len(instance) >= bound),
            ("maxLength", lambda bound: len(instance) <= bound),
        ):
            if keyword in schema and not valid(schema[keyword]):  # type: ignore[arg-type]
                failures.append(_violation(keyword, source_id, instance_path, (*definition_path, keyword)))
        if "format" in schema and not validate_format(schema["format"], instance):  # type: ignore[arg-type]
            failures.append(_violation(f"format/{schema['format']}", source_id, instance_path, (*definition_path, "format")))
        if "pattern" in schema and re.fullmatch(str(schema["pattern"]), instance) is None:
            failures.append(_violation("pattern", source_id, instance_path, (*definition_path, "pattern")))
    if isinstance(instance, Mapping):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        for name in required if type(required) in (list, tuple) else []:
            if name not in instance:
                failures.append(_violation("required", source_id, instance_path, (*definition_path, "required")))
        evaluated, _ = _successful_annotations(
            schema,
            instance,
            source_id=source_id,
            instance_path=instance_path,
            definition_path=definition_path,
            resolver=resolver,
        )
        if isinstance(properties, Mapping):
            for name in sorted(set(instance) & set(properties), key=lambda item: item.encode("utf-8")):
                evaluated.add(name)
                failures.extend(_evaluate(properties[name], instance[name], source_id=source_id, instance_path=(*instance_path, name), definition_path=(*definition_path, "properties", name), resolver=resolver))
        additional = schema.get("additionalProperties")
        for name in sorted(set(instance) - set(properties) if isinstance(properties, Mapping) else set(instance), key=lambda item: item.encode("utf-8")):
            if additional is not None:
                evaluated.add(name)
                failures.extend(_evaluate(additional, instance[name], source_id=source_id, instance_path=(*instance_path, name), definition_path=(*definition_path, "additionalProperties"), resolver=resolver))
        if "unevaluatedProperties" in schema:
            unevaluated_schema = schema["unevaluatedProperties"]
            for name in sorted(set(instance) - evaluated, key=lambda item: item.encode("utf-8")):
                if unevaluated_schema is False:
                    failures.append(_violation("unevaluatedProperties", source_id, (*instance_path, name), (*definition_path, "unevaluatedProperties")))
                else:
                    failures.extend(_evaluate(unevaluated_schema, instance[name], source_id=source_id, instance_path=(*instance_path, name), definition_path=(*definition_path, "unevaluatedProperties"), resolver=resolver))
        for keyword, valid in (
            ("minProperties", lambda bound: len(instance) >= bound),
            ("maxProperties", lambda bound: len(instance) <= bound),
        ):
            if keyword in schema and not valid(schema[keyword]):  # type: ignore[arg-type]
                failures.append(_violation(keyword, source_id, instance_path, (*definition_path, keyword)))
        dependent_required = schema.get("dependentRequired")
        if isinstance(dependent_required, Mapping):
            for trigger, names in dependent_required.items():
                if trigger in instance and type(names) in (list, tuple) and any(name not in instance for name in names):
                    failures.append(_violation("dependentRequired", source_id, instance_path, (*definition_path, "dependentRequired", trigger)))
        dependent_schemas = schema.get("dependentSchemas")
        if isinstance(dependent_schemas, Mapping):
            for trigger, child in dependent_schemas.items():
                if trigger in instance:
                    failures.extend(_evaluate(child, instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, "dependentSchemas", trigger), resolver=resolver))
    if type(instance) in (list, tuple):
        prefix = schema.get("prefixItems", [])
        _, evaluated_indexes = _successful_annotations(
            schema,
            instance,
            source_id=source_id,
            instance_path=instance_path,
            definition_path=definition_path,
            resolver=resolver,
        )
        if type(prefix) in (list, tuple):
            for index, child in enumerate(prefix[:len(instance)]):
                evaluated_indexes.add(index)
                failures.extend(_evaluate(child, instance[index], source_id=source_id, instance_path=(*instance_path, index), definition_path=(*definition_path, "prefixItems", index), resolver=resolver))
        if "items" in schema:
            start = len(prefix) if type(prefix) in (list, tuple) else 0
            for index in range(start, len(instance)):
                evaluated_indexes.add(index)
                failures.extend(_evaluate(schema["items"], instance[index], source_id=source_id, instance_path=(*instance_path, index), definition_path=(*definition_path, "items"), resolver=resolver))
        if "unevaluatedItems" in schema:
            unevaluated_schema = schema["unevaluatedItems"]
            for index in sorted(set(range(len(instance))) - evaluated_indexes):
                if unevaluated_schema is False:
                    failures.append(_violation("unevaluatedItems", source_id, (*instance_path, index), (*definition_path, "unevaluatedItems")))
                else:
                    failures.extend(_evaluate(unevaluated_schema, instance[index], source_id=source_id, instance_path=(*instance_path, index), definition_path=(*definition_path, "unevaluatedItems"), resolver=resolver))
        for keyword, valid in (
            ("minItems", lambda bound: len(instance) >= bound),
            ("maxItems", lambda bound: len(instance) <= bound),
        ):
            if keyword in schema and not valid(schema[keyword]):  # type: ignore[arg-type]
                failures.append(_violation(keyword, source_id, instance_path, (*definition_path, keyword)))
        if schema.get("uniqueItems") is True:
            if any(_json_equal(instance[left], instance[right]) for left in range(len(instance)) for right in range(left + 1, len(instance))):
                failures.append(_violation("uniqueItems", source_id, instance_path, (*definition_path, "uniqueItems")))
        if "contains" in schema:
            matched = sum(not _evaluate(schema["contains"], item, source_id=source_id, instance_path=(*instance_path, index), definition_path=(*definition_path, "contains"), resolver=resolver) for index, item in enumerate(instance))
            minimum = schema.get("minContains", 1)
            maximum = schema.get("maxContains")
            if matched < minimum or (type(maximum) is int and matched > maximum):
                failures.append(_violation("contains", source_id, instance_path, (*definition_path, "contains")))
    for keyword in ("allOf", "anyOf", "oneOf"):
        branches = schema.get(keyword)
        if type(branches) in (list, tuple):
            results = [
                _evaluate(child, instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, keyword, index), resolver=resolver)
                for index, child in enumerate(branches)
            ]
            matches = sum(not result for result in results)
            valid = matches == len(results) if keyword == "allOf" else matches >= 1 if keyword == "anyOf" else matches == 1
            if not valid:
                failures.append(_violation(keyword, source_id, instance_path, (*definition_path, keyword)))
    if "not" in schema and not _evaluate(schema["not"], instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, "not"), resolver=resolver):
        failures.append(_violation("not", source_id, instance_path, (*definition_path, "not")))
    if "if" in schema:
        condition = _evaluate(schema["if"], instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, "if"), resolver=resolver)
        branch = "then" if not condition else "else"
        if branch in schema:
            failures.extend(_evaluate(schema[branch], instance, source_id=source_id, instance_path=instance_path, definition_path=(*definition_path, branch), resolver=resolver))
    return failures


def validate_instance(
    schema: object,
    instance: object,
    *,
    source_id: str,
    resolver: Resolver | None = None,
    context: WorkContext | None = None,
    operation_path: tuple[int, ...] = (),
) -> list[SchemaViolation]:
    """Return all normalized validation failures for one instance."""

    if context is not None:
        _charge_schema(
            schema,
            instance,
            source_id=source_id,
            resolver=resolver,
            context=context,
            operation_path=operation_path,
        )
    failures = _evaluate(schema, instance, source_id=source_id, instance_path=(), definition_path=(), resolver=resolver)
    return sorted(
        set(failures),
        key=lambda failure: (
            canonical_bytes(list(failure.instance_path)),
            failure.rule_id.encode("utf-8"),
            canonical_bytes(list(failure.definition_path)),
            failure.source_id.encode("utf-8"),
        ),
    )
