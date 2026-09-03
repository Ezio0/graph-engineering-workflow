"""Digest-locked, offline-only closed schema registry."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.contracts.errors import ContractError, ErrorDetail
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.resources import ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SCHEMA_ID, SchemaProfilePolicy, validate_instance, validate_schema_profile
from graph_engineering.core.contracts.strict_json import parse_json


POINTER_ESCAPE = re.compile(r"~(?:0|1)")
REGISTRY_CONTRACT = "urn:gew:contract:schema-registry"
REGISTRY_SCHEMA = "urn:gew:schema:schema-registry:1.0.0"
REGISTRY_PROJECTION = "urn:gew:digest-projection:schema-registry:1.0.0"
def _split_reference(current_id: str, reference: str) -> tuple[str, str]:
    if reference.startswith("#"):
        return current_id, reference[1:]
    schema_id, separator, fragment = reference.partition("#")
    if SCHEMA_ID.fullmatch(schema_id) is None:
        raise ValueError(f"remote, relative, or unknown ref scheme: {reference}")
    return schema_id, fragment if separator else ""


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if pointer == "":
        return ()
    if not pointer.startswith("/"):
        raise ValueError("only JSON Pointer fragments are supported")
    tokens: list[str] = []
    for encoded in pointer[1:].split("/"):
        remainder = POINTER_ESCAPE.sub("", encoded)
        if "~" in remainder:
            raise ValueError("invalid JSON Pointer escape")
        tokens.append(encoded.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _resolve_pointer(document: object, pointer: str) -> object:
    current = document
    for token in _pointer_tokens(pointer):
        if isinstance(current, Mapping):
            if token not in current:
                raise ValueError(f"unknown JSON Pointer member: {token}")
            current = current[token]
        elif type(current) in (list, tuple):
            if not token.isascii() or not token.isdigit() or (token.startswith("0") and token != "0"):
                raise ValueError("invalid JSON Pointer array index")
            index = int(token)
            if index >= len(current):
                raise ValueError("JSON Pointer array index is out of bounds")
            current = current[index]
        else:
            raise ValueError("JSON Pointer traverses a scalar")
    return current


def _iter_schemas(value: object, path: tuple[str | int, ...] = ()) -> Iterator[tuple[tuple[str | int, ...], Mapping[str, object]]]:
    if not isinstance(value, Mapping):
        return
    yield path, value
    map_keywords = frozenset({"$defs", "properties", "dependentSchemas"})
    scalar_keywords = frozenset({"additionalProperties", "unevaluatedProperties", "unevaluatedItems", "items", "contains", "not", "if", "then", "else"})
    array_keywords = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
    for keyword in sorted(value, key=lambda item: item.encode("utf-16-be")):
        children = value[keyword]
        if keyword in map_keywords and isinstance(children, Mapping):
            for key in sorted(children, key=lambda item: item.encode("utf-16-be")):
                yield from _iter_schemas(children[key], (*path, keyword, key))
        elif keyword in scalar_keywords:
            yield from _iter_schemas(children, (*path, keyword))
        elif keyword in array_keywords and type(children) in (list, tuple):
            for index, child in enumerate(children):
                yield from _iter_schemas(child, (*path, keyword, index))


def _walk_schemas(value: object, path: tuple[str | int, ...] = ()) -> list[tuple[tuple[str | int, ...], Mapping[str, object]]]:
    return list(_iter_schemas(value, path))


def _path_pointer(path: tuple[str | int, ...]) -> str:
    return "" if not path else "/" + "/".join(str(token).replace("~", "~0").replace("/", "~1") for token in path)


@dataclass(frozen=True, slots=True, init=False)
class SchemaResource:
    schema_id: str
    raw_body: bytes
    body_digest: str
    schema: Mapping[str, object]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SchemaResource must be created by ClosedSchemaRegistry.build")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SchemaResource is final")


@dataclass(frozen=True, slots=True, init=False)
class ClosedSchemaRegistry:
    """Registry with no retrieve callback, filesystem, or network capability."""

    registry_id: str
    registry_digest: str
    _resources: Mapping[str, SchemaResource]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ClosedSchemaRegistry must be built from attested resources")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("ClosedSchemaRegistry is final")

    @classmethod
    def build(
        cls,
        manifest: Mapping[str, object],
        bodies: Mapping[str, bytes],
        profile: ResourceProfile,
        schema_policy: SchemaProfilePolicy,
        context: WorkContext | None = None,
    ) -> ClosedSchemaRegistry:
        expected_keys = {"schema_version", "registry_id", "resources", "registry_digest"}
        if set(manifest) != expected_keys or manifest.get("schema_version") != "1.0.0":
            raise ValueError("registry manifest shape is not exact")
        registry_id = manifest.get("registry_id")
        records = manifest.get("resources")
        expected_digest = manifest.get("registry_digest")
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:schema-registry:") or not isinstance(records, list) or type(expected_digest) is not str:
            raise ValueError("registry manifest fields are invalid")
        unsigned = dict(manifest)
        del unsigned["registry_digest"]
        actual_digest = semantic_digest(unsigned, contract_type=REGISTRY_CONTRACT, projection_id=REGISTRY_PROJECTION, schema_id=REGISTRY_SCHEMA)
        if actual_digest != expected_digest:
            raise ValueError("registry manifest digest mismatch")
        def check_limit(limit_id: str, count: int) -> None:
            if context is not None:
                context.check_limit(limit_id, count, source_id=registry_id)
            elif count > profile.limits[limit_id]:
                raise ContractError(ErrorDetail(
                    code="E_LIMIT",
                    phase="limit",
                    rule_id=f"limit/{limit_id}",
                    source_id=registry_id,
                ))

        check_limit("registry_resources", len(records))
        record_ids = [record.get("schema_id") for record in records if isinstance(record, Mapping)]
        if record_ids != sorted(record_ids, key=lambda item: str(item).encode("utf-8")):
            raise ValueError("registry resources must be in schema ID order")
        manifest_ids = frozenset(record_ids)
        resources: dict[str, SchemaResource] = {}
        graph: dict[tuple[str, str], set[tuple[str, str]]] = {}
        schema_location_count = 0
        for record in records:
            if not isinstance(record, Mapping) or set(record) != {"schema_id", "body_digest"}:
                raise ValueError("registry resource record is not exact")
            schema_id = record.get("schema_id")
            body_digest = record.get("body_digest")
            if type(schema_id) is not str or SCHEMA_ID.fullmatch(schema_id) is None or type(body_digest) is not str:
                raise ValueError("registry resource identity is invalid")
            if schema_id in resources or schema_id not in bodies:
                raise ValueError("duplicate or missing registry resource")
            raw = bytes(bodies[schema_id])
            check_limit("schema_bytes", len(raw))
            path = context.child_path(()) if context is not None else ()
            if context is not None:
                context.emit("registry.resource", 1, operation_path=path, source_id=registry_id)
                context.emit("registry.schema_byte", len(raw), operation_path=path, source_id=registry_id)
            parsed = parse_json(
                raw,
                context=context,
                source_id=registry_id if context is not None else None,
                operation_path=context.child_path(path) if context is not None else path,
            )
            if not isinstance(parsed, Mapping):
                raise ValueError("schema body must be an object")
            for definition_path, schema in _iter_schemas(parsed):
                schema_location_count += 1
                check_limit("schema_locations", schema_location_count)
                if context is not None:
                    context.emit("registry.schema_location", 1, operation_path=path, source_id=registry_id)
                source = (schema_id, _path_pointer(definition_path))
                graph.setdefault(source, set())
                reference = schema.get("$ref")
                if reference is None:
                    continue
                if type(reference) is not str:
                    raise ValueError("schema ref must be a string")
                target_id, pointer = _split_reference(schema_id, reference)
                if target_id not in manifest_ids:
                    raise ValueError("unregistered schema ref target")
                pointer_tokens = _pointer_tokens(pointer)
                if context is not None:
                    context.emit("registry.ref_edge", 1, operation_path=path, source_id=registry_id)
                    for _ in pointer_tokens:
                        context.emit("registry.pointer_token", 1, operation_path=path, source_id=registry_id)
                graph[source].add((target_id, pointer))
            parsed_id = validate_schema_profile(parsed, schema_policy)
            if parsed_id != schema_id:
                raise ValueError("schema body ID does not match registry")
            frozen_schema = freeze(parsed)
            if not isinstance(frozen_schema, FrozenMap):
                raise AssertionError("schema must freeze to an object")
            if context is not None:
                context.emit("registry.digest_compare", 1, operation_path=path, source_id=registry_id)
            if raw_digest(raw) != body_digest:
                raise ValueError("registry schema body digest or size mismatch")
            resource = object.__new__(SchemaResource)
            object.__setattr__(resource, "schema_id", schema_id)
            object.__setattr__(resource, "raw_body", raw)
            object.__setattr__(resource, "body_digest", body_digest)
            object.__setattr__(resource, "schema", frozen_schema)
            resources[schema_id] = resource
        if set(resources) != set(bodies):
            raise ValueError("undeclared registry body")
        registry = object.__new__(ClosedSchemaRegistry)
        object.__setattr__(registry, "registry_id", registry_id)
        object.__setattr__(registry, "registry_digest", expected_digest)
        object.__setattr__(registry, "_resources", MappingProxyType(dict(resources)))
        registry._validate_references(profile, context, graph)
        return registry

    @staticmethod
    def create_manifest(registry_id: str, bodies: Mapping[str, bytes]) -> dict[str, object]:
        resources = [
            {"schema_id": schema_id, "body_digest": raw_digest(bytes(bodies[schema_id]))}
            for schema_id in sorted(bodies, key=lambda item: item.encode("utf-8"))
        ]
        unsigned: dict[str, object] = {"schema_version": "1.0.0", "registry_id": registry_id, "resources": resources}
        unsigned["registry_digest"] = semantic_digest(unsigned, contract_type=REGISTRY_CONTRACT, projection_id=REGISTRY_PROJECTION, schema_id=REGISTRY_SCHEMA)
        return unsigned

    def _validate_references(
        self,
        profile: ResourceProfile,
        context: WorkContext | None,
        graph: Mapping[tuple[str, str], set[tuple[str, str]]],
    ) -> None:
        def check_limit(limit_id: str, count: int) -> None:
            if context is not None:
                context.check_limit(limit_id, count, source_id=self.registry_id)
            elif count > profile.limits[limit_id]:
                raise ContractError(ErrorDetail(
                    code="E_LIMIT", phase="limit", rule_id=f"limit/{limit_id}", source_id=self.registry_id,
                ))

        visiting: set[tuple[str, str]] = set()
        visited: set[tuple[str, str]] = set()

        def visit(node: tuple[str, str], depth: int) -> None:
            check_limit("registry_ref_depth", depth)
            if node in visiting:
                raise ValueError("cyclic schema reference")
            if node in visited:
                return
            visiting.add(node)
            target = _resolve_pointer(self._resources[node[0]].schema, node[1])
            dependencies: set[tuple[str, str]] = set(graph.get(node, set()))
            for _, nested in _walk_schemas(target):
                reference = nested.get("$ref")
                if type(reference) is str:
                    dependencies.add(_split_reference(node[0], reference))
            for dependency in dependencies:
                visit(dependency, depth + 1)
            visiting.remove(node)
            visited.add(node)

        for node in graph:
            visit(node, 0)

    def resolve(self, current_id: str, reference: str) -> tuple[object, str]:
        target_id, pointer = _split_reference(current_id, reference)
        if target_id not in self._resources:
            raise ValueError("unregistered schema reference")
        return _resolve_pointer(self._resources[target_id].schema, pointer), target_id

    def validate(
        self,
        schema_id: str,
        instance: object,
        context: WorkContext,
        *,
        operation_path: tuple[int, ...] = (),
    ) -> list[object]:
        if schema_id not in self._resources:
            raise ValueError("unknown schema ID")
        return validate_instance(
            self._resources[schema_id].schema,
            instance,
            source_id=schema_id,
            resolver=self.resolve,
            context=context,
            operation_path=operation_path,
        )

    def resource(self, schema_id: str) -> SchemaResource:
        try:
            return self._resources[schema_id]
        except KeyError as error:
            raise ValueError("unknown schema ID") from error
