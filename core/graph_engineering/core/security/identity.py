"""Canonical task/runtime/project/target security bindings."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    exact_mapping,
    require_canonical_strings,
    require_digest,
    require_id,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import SecurityRuntimeManifest


BINDING_SCHEMA_ID = "urn:gew:schema:security-binding:1.0.0"
BINDING_CONTRACT_ID = "urn:gew:contract:security-binding"
_FIELDS = {
    "schema_version",
    "task_id",
    "owner_id",
    "runtime_kind",
    "runtime_lineage_id",
    "scope_id",
    "scope_digest",
    "baselines",
    "snapshot_digest",
    "targets",
    "binding_digest",
}


class BindingMismatchError(ValueError):
    """A task security binding is invalid or no longer current."""


@dataclass(frozen=True, slots=True, init=False)
class TargetBinding:
    target_id: str
    target_kind: str
    canonical_identity: str
    target_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("TargetBinding is emitted only by SecurityBinding")


@dataclass(frozen=True, slots=True, init=False)
class SecurityBinding:
    task_id: str
    owner_id: str
    runtime_kind: str
    runtime_lineage_id: str
    scope_id: str
    scope_digest: str
    baselines: Mapping[str, object]
    snapshot_digest: str
    targets: Mapping[str, TargetBinding]
    binding_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SecurityBinding must be loaded from validated data")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SecurityBinding is final")

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return unsigned_digest(
            value,
            digest_field="binding_digest",
            contract_type=BINDING_CONTRACT_ID,
            schema_id=BINDING_SCHEMA_ID,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        allowed_runtime_kinds: tuple[str, ...] | None = None,
    ) -> SecurityBinding:
        del cls, value, schema_registry, context, allowed_runtime_kinds
        raise BindingMismatchError(
            "security bindings are issued only from current durable task state",
        )

    @classmethod
    def _from_attested_dict(
        cls,
        value: Mapping[str, object],
        *,
        runtime: SecurityRuntimeManifest,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        issuer: object,
    ) -> SecurityBinding:
        if (
            type(runtime) is not SecurityRuntimeManifest
            or issuer is not runtime._issuer
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise BindingMismatchError("security binding requires an application-issued context")
        if schema_registry.validate(BINDING_SCHEMA_ID, value, context):
            raise BindingMismatchError("security binding schema validation failed")
        try:
            exact_mapping(value, _FIELDS, "security binding")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("security binding schema version is invalid")
            task_id = require_id(value.get("task_id"), "task ID")
            owner_id = require_id(value.get("owner_id"), "owner ID")
            runtime_kind = require_id(value.get("runtime_kind"), "runtime kind")
            lineage = require_id(value.get("runtime_lineage_id"), "runtime lineage")
            scope_id = require_id(value.get("scope_id"), "scope ID")
            scope_digest = require_digest(value.get("scope_digest"), "scope digest")
            snapshot_digest = require_digest(value.get("snapshot_digest"), "snapshot digest")
            expected_digest = require_digest(value.get("binding_digest"), "binding digest")
            if runtime_kind not in runtime.allowed_runtime_kinds:
                raise ValueError("runtime kind is not approved")
            raw_baselines = value.get("baselines")
            if not isinstance(raw_baselines, Mapping) or not raw_baselines:
                raise ValueError("baseline bindings are invalid")
            if list(raw_baselines) != sorted(raw_baselines):
                raise ValueError("baseline bindings are not canonical")
            baselines = {
                require_id(key, "baseline kind"): require_digest(item, "baseline digest")
                for key, item in raw_baselines.items()
            }
            raw_targets = value.get("targets")
            if type(raw_targets) is not list or not raw_targets:
                raise ValueError("target bindings are invalid")
            target_ids = [item.get("target_id") for item in raw_targets if isinstance(item, Mapping)]
            if target_ids != sorted(set(target_ids)):
                raise ValueError("target bindings are not canonical")
            targets: dict[str, TargetBinding] = {}
            for raw in raw_targets:
                exact_mapping(raw, {"target_id", "target_kind", "canonical_identity", "target_digest"}, "target binding")
                target = object.__new__(TargetBinding)
                target_id = require_id(raw.get("target_id"), "target ID")
                for name, item in (
                    ("target_id", target_id),
                    ("target_kind", require_id(raw.get("target_kind"), "target kind")),
                    ("canonical_identity", require_id(raw.get("canonical_identity"), "canonical identity")),
                    ("target_digest", require_digest(raw.get("target_digest"), "target digest")),
                ):
                    object.__setattr__(target, name, item)
                targets[target_id] = target
            actual_digest = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "binding_digest"},
                context,
                contract_type=BINDING_CONTRACT_ID,
                projection_id=IDENTITY_PROJECTION,
                schema_id=BINDING_SCHEMA_ID,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected_digest, actual_digest):
                raise ValueError("security binding digest mismatch")
        except (TypeError, ValueError) as error:
            raise BindingMismatchError(str(error)) from error
        frozen_baselines = freeze(baselines)
        if not isinstance(frozen_baselines, FrozenMap):
            raise AssertionError("baseline map did not freeze")
        result = object.__new__(SecurityBinding)
        for name, item in (
            ("task_id", task_id),
            ("owner_id", owner_id),
            ("runtime_kind", runtime_kind),
            ("runtime_lineage_id", lineage),
            ("scope_id", scope_id),
            ("scope_digest", scope_digest),
            ("baselines", frozen_baselines),
            ("snapshot_digest", snapshot_digest),
            ("targets", MappingProxyType(dict(targets))),
            ("binding_digest", expected_digest),
        ):
            object.__setattr__(result, name, item)
        return result

    def target_digest(self, target_id: str) -> str:
        try:
            return self.targets[target_id].target_digest
        except KeyError as error:
            raise BindingMismatchError("unknown target binding") from error

    def require_current(self, current: SecurityBinding) -> None:
        if type(current) is not SecurityBinding or not hmac.compare_digest(
            self.binding_digest,
            current.binding_digest,
        ):
            raise BindingMismatchError("security binding is no longer current")
