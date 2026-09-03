"""Exact, directional contract compatibility declarations."""

from __future__ import annotations

import hashlib
import hmac
import inspect
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.canonical import canonicalize
from graph_engineering.core.contracts.digest import semantic_digest, semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, code_fingerprint, freeze
from graph_engineering.core.contracts.resources import WorkContext, bounded_measure, build_result_record


CONTRACT_TYPE = "urn:gew:contract:compatibility-matrix"
SCHEMA_ID = "urn:gew:schema:compatibility-matrix:1.0.0"
PROJECTION_ID = "urn:gew:digest-projection:compatibility-matrix:1.0.0"


@dataclass(frozen=True, slots=True, init=False)
class CompatibilityMatrix:
    """Directional exact reader-to-writer contract compatibility map."""

    matrix_id: str
    matrix_digest: str
    readers: Mapping[str, frozenset[str]]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("CompatibilityMatrix must be loaded from a manifest")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CompatibilityMatrix is final")

    @classmethod
    def create_manifest(cls, matrix_id: str, rows: list[dict[str, object]]) -> dict[str, object]:
        if type(matrix_id) is not str or not matrix_id.startswith("urn:gew:compatibility-matrix:"):
            raise ValueError("invalid compatibility matrix ID")
        reader_ids: list[str] = []
        for row in rows:
            if set(row) != {"reader_id", "accepted_writer_ids"}:
                raise ValueError("compatibility row properties are not exact")
            reader_id = row["reader_id"]
            writers = row["accepted_writer_ids"]
            if type(reader_id) is not str or not isinstance(writers, list) or any(type(writer) is not str for writer in writers):
                raise ValueError("compatibility row fields are invalid")
            if writers != sorted(writers) or len(writers) != len(set(writers)):
                raise ValueError("accepted writer IDs must be sorted and unique")
            reader_ids.append(reader_id)
        if reader_ids != sorted(reader_ids) or len(reader_ids) != len(set(reader_ids)):
            raise ValueError("reader IDs must be sorted and unique")
        manifest: dict[str, object] = {"schema_version": "1.0.0", "matrix_id": matrix_id, "rows": rows}
        manifest["matrix_digest"] = semantic_digest(manifest, contract_type=CONTRACT_TYPE, projection_id=PROJECTION_ID, schema_id=SCHEMA_ID)
        return manifest

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> CompatibilityMatrix:
        if set(value) != {"schema_version", "matrix_id", "rows", "matrix_digest"} or value.get("schema_version") != "1.0.0":
            raise ValueError("compatibility matrix properties are not exact")
        matrix_id = value.get("matrix_id")
        rows = value.get("rows")
        matrix_digest = value.get("matrix_digest")
        if type(matrix_id) is not str or not isinstance(rows, list) or type(matrix_digest) is not str:
            raise ValueError("compatibility matrix fields are invalid")
        expected = CompatibilityMatrix.create_manifest(matrix_id, rows)
        if expected["matrix_digest"] != matrix_digest:
            raise ValueError("compatibility matrix digest mismatch")
        readers = FrozenMap.from_dict({
            row["reader_id"]: frozenset(row["accepted_writer_ids"]) for row in rows  # type: ignore[misc]
        })
        result = object.__new__(CompatibilityMatrix)
        object.__setattr__(result, "matrix_id", matrix_id)
        object.__setattr__(result, "matrix_digest", matrix_digest)
        object.__setattr__(result, "readers", readers)
        return result

    def require(self, reader_id: str, writer_id: str) -> None:
        if reader_id not in self.readers or writer_id not in self.readers[reader_id]:
            raise ValueError(f"incompatible exact contract pair: {reader_id} <- {writer_id}")


MIGRATION_CONTRACT_TYPE = "urn:gew:contract:migration-registry"
MIGRATION_SCHEMA_ID = "urn:gew:schema:migration-registry:1.0.0"
MIGRATION_PROJECTION_ID = "urn:gew:digest-projection:migration-registry:1.0.0"
IDENTITY_PROJECTION_ID = "urn:gew:digest-projection:identity:1.0.0"
EXECUTABLE_EVENTS = (
    "executable.base",
    "executable.input_node",
    "executable.input_scalar",
    "executable.input_byte",
)


def _upgrade_contract_stack_1_0_0_to_1_0_1(value: object) -> object:
    if not hasattr(value, "items") or not hasattr(value, "get") or value.get("schema_version") != "1.0.0":  # type: ignore[union-attr]
        raise ValueError("migration input does not match its exact source contract")

    def clone(current: object) -> object:
        if current is None or type(current) in (bool, int, str):
            return current
        if type(current) in (list, tuple):
            return [clone(item) for item in current]
        if hasattr(current, "items"):
            entries = current.items()  # type: ignore[union-attr]
            if any(type(key) is not str for key, _ in entries):
                raise ValueError("migration input contains a non-string object key")
            return {key: clone(item) for key, item in current.items()}  # type: ignore[union-attr]
        raise ValueError("migration input contains a non-JSON value")

    result = clone(value)
    if type(result) is not dict:
        raise AssertionError("migration object clone changed its root type")
    result["schema_version"] = "1.0.1"
    return result


def _code_digest(implementation: Callable[[object], object]) -> str:
    return "sha256-raw-v1:" + hashlib.sha256(inspect.getsource(implementation).encode("utf-8")).hexdigest()


_CONTRACT_STACK_UPGRADE_IDENTITY = (
    "urn:gew:migration:contract-stack-1-0-0-to-1-0-1",
    "1.0.0",
    "builtin:contract-stack-1-0-0-to-1-0-1:v1",
)
_MIGRATION_BUILTIN_IDENTITIES = frozenset({_CONTRACT_STACK_UPGRADE_IDENTITY})


@dataclass(frozen=True, slots=True, init=False)
class MigrationSpec:
    transform_id: str
    version: str
    source_contract_id: str
    target_contract_id: str
    input_schema_id: str
    output_schema_id: str
    multipliers: Mapping[str, int]
    implementation_id: str
    implementation_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("MigrationSpec must be loaded from the closed registry")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("MigrationSpec is final")


def _all_paths(
    specifications: Sequence[MigrationSpec],
    source_contract_id: str,
    target_contract_id: str,
) -> list[tuple[MigrationSpec, ...]]:
    adjacency: dict[str, list[MigrationSpec]] = {}
    for specification in specifications:
        adjacency.setdefault(specification.source_contract_id, []).append(specification)
    paths: list[tuple[MigrationSpec, ...]] = []

    def visit(current: str, path: tuple[MigrationSpec, ...], seen: frozenset[str]) -> None:
        if current == target_contract_id:
            paths.append(path)
            return
        for specification in sorted(adjacency.get(current, []), key=lambda item: (item.transform_id, item.version)):
            if specification.target_contract_id in seen:
                raise ValueError("migration registry contains a cycle")
            visit(
                specification.target_contract_id,
                (*path, specification),
                seen | {specification.target_contract_id},
            )

    visit(source_contract_id, (), frozenset({source_contract_id}))
    return paths


@dataclass(frozen=True, slots=True, init=False)
class MigrationRegistry:
    """Digest-locked, pure built-in transform registry with unique paths."""

    registry_id: str
    registry_digest: str
    _specifications: tuple[MigrationSpec, ...]
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
        raise TypeError("MigrationRegistry must be loaded from a manifest")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("MigrationRegistry is final")

    @classmethod
    def create_manifest(cls, registry_id: str, transforms: list[dict[str, object]]) -> dict[str, object]:
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:migration-registry:"):
            raise ValueError("invalid migration registry ID")
        identities: list[tuple[str, str]] = []
        expected_fields = {
            "transform_id", "version", "source_contract_id", "target_contract_id",
            "input_schema_id", "output_schema_id", "multipliers", "implementation_id",
            "implementation_digest", "capabilities",
        }
        for record in transforms:
            if set(record) != expected_fields:
                raise ValueError("migration record is not exact")
            identity = (record["transform_id"], record["version"])
            if type(identity[0]) is not str or type(identity[1]) is not str:
                raise ValueError("migration identity is invalid")
            identities.append(identity)  # type: ignore[arg-type]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise ValueError("migration identities must be sorted and unique")
        manifest: dict[str, object] = {
            "schema_version": "1.0.0",
            "registry_id": registry_id,
            "transforms": transforms,
        }
        manifest["registry_digest"] = semantic_digest(
            manifest,
            contract_type=MIGRATION_CONTRACT_TYPE,
            projection_id=MIGRATION_PROJECTION_ID,
            schema_id=MIGRATION_SCHEMA_ID,
        )
        return manifest

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> MigrationRegistry:
        if set(value) != {"schema_version", "registry_id", "transforms", "registry_digest"} or value.get("schema_version") != "1.0.0":
            raise ValueError("migration registry is not exact")
        registry_id = value.get("registry_id")
        transforms = value.get("transforms")
        registry_digest = value.get("registry_digest")
        if type(registry_id) is not str or not isinstance(transforms, list) or type(registry_digest) is not str:
            raise ValueError("migration registry fields are invalid")
        if MigrationRegistry.create_manifest(registry_id, transforms)["registry_digest"] != registry_digest:
            raise ValueError("migration registry digest mismatch")
        records = {(item["transform_id"], item["version"], item["implementation_id"]): item for item in transforms}
        if set(records) != _MIGRATION_BUILTIN_IDENTITIES:
            raise ValueError("migration registry must equal the closed product built-in set")
        specifications: list[MigrationSpec] = []
        binding: tuple[
            tuple[str, str, str],
            str,
            object,
            str,
            Mapping[str, object],
            type,
        ] | None = None
        for builtin_key in sorted(_MIGRATION_BUILTIN_IDENTITIES):
            record = records[builtin_key]
            multipliers = record["multipliers"]
            source_implementation = _upgrade_contract_stack_1_0_0_to_1_0_1
            try:
                implementation_digest = _code_digest(source_implementation)
            except (OSError, TypeError) as error:
                raise ValueError("migration implementation attestation mismatch") from error
            closure = inspect.getclosurevars(source_implementation)
            if (
                record["capabilities"] != []
                or record["implementation_digest"] != implementation_digest
                or closure.globals
                or closure.nonlocals
                or not isinstance(multipliers, Mapping)
                or set(multipliers) != set(EXECUTABLE_EVENTS)
                or any(type(item) is not int or item < 1 for item in multipliers.values())
            ):
                raise ValueError("migration implementation, capability, or cost binding mismatch")
            isolated_builtins = MappingProxyType({
                "AssertionError": AssertionError,
                "ValueError": ValueError,
                "any": any,
                "bool": bool,
                "dict": dict,
                "hasattr": hasattr,
                "int": int,
                "list": list,
                "str": str,
                "tuple": tuple,
                "type": type,
            })
            frozen_multipliers = freeze(multipliers)
            if not isinstance(frozen_multipliers, FrozenMap):
                raise AssertionError("migration multipliers must freeze to a map")
            specification = object.__new__(MigrationSpec)
            object.__setattr__(specification, "transform_id", builtin_key[0])
            object.__setattr__(specification, "version", builtin_key[1])
            object.__setattr__(specification, "source_contract_id", record["source_contract_id"])
            object.__setattr__(specification, "target_contract_id", record["target_contract_id"])
            object.__setattr__(specification, "input_schema_id", record["input_schema_id"])
            object.__setattr__(specification, "output_schema_id", record["output_schema_id"])
            object.__setattr__(specification, "multipliers", frozen_multipliers)
            object.__setattr__(specification, "implementation_id", builtin_key[2])
            object.__setattr__(specification, "implementation_digest", record["implementation_digest"])
            specifications.append(specification)
            binding = (
                builtin_key,
                implementation_digest,
                source_implementation.__code__,
                code_fingerprint(source_implementation.__code__),
                isolated_builtins,
                type(source_implementation),
            )
        if binding is None:
            raise AssertionError("closed migration implementation binding is missing")
        result = object.__new__(MigrationRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", registry_digest)
        object.__setattr__(result, "_specifications", tuple(specifications))
        object.__setattr__(result, "_implementation", binding)
        result._validate_unique_paths()
        return result

    def _validate_unique_paths(self) -> None:
        contracts = {
            item.source_contract_id for item in self._specifications
        } | {
            item.target_contract_id for item in self._specifications
        }
        for source in contracts:
            for target in contracts:
                if source != target and len(_all_paths(self._specifications, source, target)) > 1:
                    raise ValueError(f"ambiguous migration path: {source} -> {target}")

    def resolve_unique_path(self, source_contract_id: str, target_contract_id: str) -> tuple[MigrationSpec, ...]:
        paths = _all_paths(self._specifications, source_contract_id, target_contract_id)
        if len(paths) != 1 or not paths[0]:
            raise ValueError(f"migration path must be unique, found {len(paths)}")
        path = paths[0]
        bound_identity, bound_digest, bound_code, bound_code_fingerprint, isolated_builtins, function_type = self._implementation
        for specification in path:
            identity = (specification.transform_id, specification.version, specification.implementation_id)
            attestation_failures = [
                name for name, failed in (
                    ("specification-type", type(specification) is not MigrationSpec),
                    ("identity", identity != bound_identity),
                    ("source-digest", specification.implementation_digest != bound_digest),
                    ("code-fingerprint", code_fingerprint(bound_code) != bound_code_fingerprint),
                    ("function-type", function_type.__name__ != "function"),
                    ("builtins", set(isolated_builtins) != {
                        "AssertionError", "ValueError", "any", "bool", "dict", "hasattr",
                        "int", "list", "str", "tuple", "type",
                    }),
                ) if failed
            ]
            if attestation_failures:
                raise ValueError(f"migration specification attestation mismatch: {','.join(attestation_failures)}")
        return path

    def migrate(
        self,
        value: object,
        *,
        source_contract_id: str,
        target_contract_id: str,
        expected_source_digest: str,
        expected_schema_registry_id: str,
        expected_schema_registry_digest: str,
        actor_id: str,
        transaction_id: str,
        schema_registry: object,
        context: WorkContext,
    ) -> dict[str, object]:
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry

        if type(schema_registry) is not ClosedSchemaRegistry:
            raise TypeError("migration requires the closed schema registry")
        if (
            type(expected_source_digest) is not str
            or type(expected_schema_registry_id) is not str
            or type(expected_schema_registry_digest) is not str
            or type(actor_id) is not str
            or type(transaction_id) is not str
        ):
            raise TypeError("migration identity and expected digest fields must be strings")
        if (
            not hmac.compare_digest(expected_schema_registry_id, schema_registry.registry_id)
            or not hmac.compare_digest(expected_schema_registry_digest, schema_registry.registry_digest)
        ):
            raise ValueError("migration schema registry identity or digest mismatch")
        path = self.resolve_unique_path(source_contract_id, target_contract_id)
        current = freeze(value)
        steps: list[dict[str, object]] = []
        if schema_registry.validate(path[0].input_schema_id, current, context):
            raise ValueError("migration source schema validation failed")
        source_digest = semantic_digest_charged(
            current,
            context,
            contract_type=source_contract_id,
            projection_id=IDENTITY_PROJECTION_ID,
            schema_id=path[0].input_schema_id,
        )
        if not hmac.compare_digest(expected_source_digest, source_digest):
            raise ValueError("migration source digest mismatch")
        for index, specification in enumerate(path):
            candidate = current
            if schema_registry.validate(specification.input_schema_id, candidate, context):
                raise ValueError("migration input schema validation failed")
            bound_identity, bound_digest, bound_code, bound_code_fingerprint, isolated_builtins, function_type = self._implementation
            identity = (specification.transform_id, specification.version, specification.implementation_id)
            if (
                identity != bound_identity
                or specification.implementation_digest != bound_digest
                or code_fingerprint(bound_code) != bound_code_fingerprint
                or function_type.__name__ != "function"
                or set(isolated_builtins) != {
                    "AssertionError", "ValueError", "any", "bool", "dict", "hasattr",
                    "int", "list", "str", "tuple", "type",
                }
            ):
                raise ValueError("migration implementation attestation mismatch")
            implementation = function_type(bound_code, {"__builtins__": isolated_builtins})
            operation_path = context.child_path(())
            aggregate = bounded_measure(candidate, context, source_id=specification.transform_id, operation_path=operation_path)
            for event_id, count in zip(
                EXECUTABLE_EVENTS,
                (1, aggregate.nodes, aggregate.string_scalars, aggregate.canonical_bytes),
                strict=True,
            ):
                context.emit(
                    event_id,
                    count,
                    operation_path=operation_path,
                    multiplier=specification.multipliers[event_id],
                    source_id=specification.transform_id,
                )
            output = implementation(candidate)
            if schema_registry.validate(specification.output_schema_id, output, context):
                raise ValueError("migration output schema validation failed")
            current = freeze(output)
            step_digest = semantic_digest_charged(
                current,
                context,
                contract_type=specification.target_contract_id,
                projection_id=IDENTITY_PROJECTION_ID,
                schema_id=specification.output_schema_id,
            )
            steps.append({
                "implementation_digest": specification.implementation_digest,
                "index": index,
                "output_digest": step_digest,
                "transform_id": specification.transform_id,
                "version": specification.version,
            })
        target_digest = steps[-1]["output_digest"]
        provenance = {
            "actor_id": actor_id,
            "registry_digest": self.registry_digest,
            "registry_id": self.registry_id,
            "result": "migrated",
            "schema_version": "1.0.0",
            "source_contract_id": source_contract_id,
            "source_digest": source_digest,
            "steps": steps,
            "target_contract_id": target_contract_id,
            "target_digest": target_digest,
            "transaction_id": transaction_id,
        }
        output_path = context.child_path(())
        output_canonical = canonicalize(
            output,
            context,
            source_id=target_contract_id,
            operation_path=output_path,
        ).decode("utf-8")
        provenance_path = context.child_path(())
        provenance_canonical = canonicalize(
            provenance,
            context,
            source_id=self.registry_id,
            operation_path=provenance_path,
        ).decode("utf-8")
        return build_result_record((
            ("output", output),
            ("output_canonical", output_canonical),
            ("provenance", provenance),
            ("provenance_canonical", provenance_canonical),
        ), context, source_id=self.registry_id)
