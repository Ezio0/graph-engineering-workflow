"""Canonical ProjectScope contracts and deterministic change classification."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest, semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import require_digest, require_id


PROJECT_SCOPE_SCHEMA_ID = "urn:gew:schema:project-scope:1.0.0"
PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID = "urn:gew:schema:project-scope-digest-input:1.0.0"
PROJECT_SCOPE_CONTRACT_ID = "urn:gew:contract:project-scope"
PROJECT_SCOPE_PROJECTION_ID = "urn:gew:projection:project-scope:scope-digest:1.0.0"


class ProjectScopeError(ValueError):
    """A ProjectScope or scope transition is not canonical and trustworthy."""


def _sorted_ids(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise ProjectScopeError(f"{label} must be an array")
    items = tuple(require_id(item, label) for item in value)
    if tuple(sorted(set(items))) != items:
        raise ProjectScopeError(f"{label} must be canonical, unique, and sorted")
    return items


def _ordered_records(
    value: object,
    identity: str,
    label: str,
    *,
    nonempty: bool = False,
) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list or any(not isinstance(item, Mapping) for item in value):
        raise ProjectScopeError(f"{label} must be an object array")
    records = tuple(value)
    identifiers = tuple(require_id(item.get(identity), f"{label} identity") for item in records)
    if (nonempty and not identifiers) or tuple(sorted(set(identifiers))) != identifiers:
        raise ProjectScopeError(f"{label} identities must be canonical, unique, and sorted")
    return records


def _project(value: Mapping[str, object]) -> dict[str, object]:
    repositories = [
        {
            key: raw[key]
            for key in (
                "binding_id", "mode", "vcs", "canonical_identity", "planned_target_id",
                "allowed_path_boundary", "default_branch_ref", "command_refs",
            )
        }
        for raw in value["repositories"]  # type: ignore[index]
    ]
    environments = [
        {
            key: raw[key]
            for key in (
                "binding_id", "kind", "canonical_identity", "service_ids", "sensitivity",
                "operation_classes", "target_state_validator_ref",
            )
        }
        for raw in value["environments"]  # type: ignore[index]
    ]
    return {
        "schema_version": value["schema_version"],
        "scope_id": value["scope_id"],
        "version": value["version"],
        "mode": value["mode"],
        "repositories": repositories,
        "services": value["services"],
        "environments": environments,
        "target_bindings": value["target_bindings"],
        "discovery_digest": value["discovery_digest"],
    }


@dataclass(frozen=True, slots=True, init=False)
class RepositoryBinding:
    binding_id: str
    mode: str
    locator_ref: str
    canonical_identity: str | None
    planned_target_id: str | None
    realized_git_identity: str | None
    allowed_path_boundary: str
    default_branch_ref: str
    command_refs: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RepositoryBinding is emitted only by ProjectScope")


@dataclass(frozen=True, slots=True, init=False)
class ScopeTargetBinding:
    target_id: str
    acceptance_id: str
    repository_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    environment_ids: tuple[str, ...]
    resource_ids: tuple[str, ...]
    required_final_state: str
    verification_contract_ref: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ScopeTargetBinding is emitted only by ProjectScope")


@dataclass(frozen=True, slots=True, init=False)
class ProjectScope:
    scope_id: str
    version: int
    repositories: Mapping[str, RepositoryBinding]
    services: Mapping[str, Mapping[str, object]]
    environments: Mapping[str, Mapping[str, object]]
    target_bindings: Mapping[str, ScopeTargetBinding]
    discovery_digest: str
    metadata_revision: int
    scope_digest: str
    _source: Mapping[str, object]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ProjectScope must be loaded from validated data")

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return semantic_digest(
            _project(value),
            contract_type=PROJECT_SCOPE_CONTRACT_ID,
            projection_id=PROJECT_SCOPE_PROJECTION_ID,
            schema_id=PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> ProjectScope:
        if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
            raise ProjectScopeError("ProjectScope requires attested contracts and work context")
        if not isinstance(value, Mapping):
            raise ProjectScopeError("ProjectScope must be an object")
        if schema_registry.validate(PROJECT_SCOPE_SCHEMA_ID, value, context):
            raise ProjectScopeError("ProjectScope source schema validation failed")
        projected = _project(value)
        if schema_registry.validate(PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID, projected, context):
            raise ProjectScopeError("ProjectScope digest projection schema validation failed")
        try:
            scope_id = require_id(value.get("scope_id"), "scope ID")
            version = value.get("version")
            metadata_revision = value.get("metadata_revision")
            if type(version) is not int or version < 1 or type(metadata_revision) is not int or metadata_revision < 1:
                raise ProjectScopeError("ProjectScope revisions are invalid")
            discovery_digest = require_digest(value.get("discovery_digest"), "discovery digest")
            expected_digest = require_digest(value.get("scope_digest"), "scope digest")
            repository_records = _ordered_records(value.get("repositories"), "binding_id", "repositories")
            service_records = _ordered_records(value.get("services"), "binding_id", "services")
            environment_records = _ordered_records(value.get("environments"), "binding_id", "environments")
            target_records = _ordered_records(
                value.get("target_bindings"), "target_id", "target bindings", nonempty=True,
            )

            repositories: dict[str, RepositoryBinding] = {}
            canonical_targets: set[str] = set()
            for raw in repository_records:
                binding_id = require_id(raw.get("binding_id"), "repository binding ID")
                mode = raw.get("mode")
                canonical = raw.get("canonical_identity")
                planned = raw.get("planned_target_id")
                realized = raw.get("realized_git_identity")
                if mode == "attach_existing":
                    canonical = require_id(canonical, "existing Git identity")
                    if planned is not None or realized != canonical:
                        raise ProjectScopeError("existing repository identity tuple is invalid")
                    unique_identity = canonical
                elif mode == "create_new":
                    planned = require_id(planned, "planned target ID")
                    if canonical is not None or realized is not None and type(realized) is not str:
                        raise ProjectScopeError("new repository identity tuple is invalid")
                    unique_identity = realized or planned
                else:
                    raise ProjectScopeError("repository mode is invalid")
                if unique_identity in canonical_targets:
                    raise ProjectScopeError("duplicate canonical repository target")
                canonical_targets.add(unique_identity)
                binding = object.__new__(RepositoryBinding)
                fields = (
                    ("binding_id", binding_id), ("mode", mode),
                    ("locator_ref", require_id(raw.get("locator_ref"), "repository locator ref")),
                    ("canonical_identity", canonical), ("planned_target_id", planned),
                    ("realized_git_identity", realized),
                    ("allowed_path_boundary", require_id(raw.get("allowed_path_boundary"), "allowed path boundary")),
                    ("default_branch_ref", require_id(raw.get("default_branch_ref"), "default branch ref")),
                    ("command_refs", _sorted_ids(raw.get("command_refs"), "repository command refs")),
                )
                for name, item in fields:
                    object.__setattr__(binding, name, item)
                repositories[binding_id] = binding

            repository_ids = set(repositories)
            services: dict[str, Mapping[str, object]] = {}
            for raw in service_records:
                binding_id = require_id(raw.get("binding_id"), "service binding ID")
                if raw.get("repository_id") not in repository_ids:
                    raise ProjectScopeError("service references an unknown repository")
                for field in ("component_refs", "capability_refs", "dependency_refs"):
                    _sorted_ids(raw.get(field), f"service {field}")
                frozen = freeze(dict(raw))
                if not isinstance(frozen, FrozenMap):
                    raise AssertionError("service binding did not freeze")
                services[binding_id] = frozen
            service_ids = set(services)
            for raw in service_records:
                if set(raw["dependency_refs"]) - service_ids:  # type: ignore[arg-type]
                    raise ProjectScopeError("service dependency is unknown")

            environments: dict[str, Mapping[str, object]] = {}
            environment_identities: set[str] = set()
            for raw in environment_records:
                binding_id = require_id(raw.get("binding_id"), "environment binding ID")
                identity = require_id(raw.get("canonical_identity"), "environment canonical identity")
                if identity in environment_identities:
                    raise ProjectScopeError("duplicate canonical environment target")
                environment_identities.add(identity)
                if set(_sorted_ids(raw.get("service_ids"), "environment service refs")) - service_ids:
                    raise ProjectScopeError("environment references an unknown service")
                _sorted_ids(raw.get("operation_classes"), "environment operation classes")
                frozen = freeze(dict(raw))
                if not isinstance(frozen, FrozenMap):
                    raise AssertionError("environment binding did not freeze")
                environments[binding_id] = frozen
            environment_ids = set(environments)

            targets: dict[str, ScopeTargetBinding] = {}
            for raw in target_records:
                repository_refs = _sorted_ids(raw.get("repository_ids"), "target repository refs")
                service_refs = _sorted_ids(raw.get("service_ids"), "target service refs")
                environment_refs = _sorted_ids(raw.get("environment_ids"), "target environment refs")
                resource_refs = _sorted_ids(raw.get("resource_ids"), "target resource refs")
                if not any((repository_refs, service_refs, environment_refs, resource_refs)):
                    raise ProjectScopeError("target binding has no concrete target")
                if set(repository_refs) - repository_ids or set(service_refs) - service_ids or set(environment_refs) - environment_ids:
                    raise ProjectScopeError("target binding references an unknown binding")
                target = object.__new__(ScopeTargetBinding)
                fields = (
                    ("target_id", require_id(raw.get("target_id"), "target ID")),
                    ("acceptance_id", require_id(raw.get("acceptance_id"), "acceptance ID")),
                    ("repository_ids", repository_refs), ("service_ids", service_refs),
                    ("environment_ids", environment_refs), ("resource_ids", resource_refs),
                    ("required_final_state", require_id(raw.get("required_final_state"), "required final state")),
                    ("verification_contract_ref", require_id(raw.get("verification_contract_ref"), "verification contract ref")),
                )
                for name, item in fields:
                    object.__setattr__(target, name, item)
                targets[target.target_id] = target
            actual_digest = semantic_digest_charged(
                projected,
                context,
                contract_type=PROJECT_SCOPE_CONTRACT_ID,
                projection_id=PROJECT_SCOPE_PROJECTION_ID,
                schema_id=PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(actual_digest, expected_digest):
                raise ProjectScopeError("ProjectScope digest mismatch")
        except (KeyError, TypeError, ValueError) as error:
            if isinstance(error, ProjectScopeError):
                raise
            raise ProjectScopeError(str(error)) from error
        frozen_source = freeze(dict(value))
        if not isinstance(frozen_source, FrozenMap):
            raise AssertionError("ProjectScope source did not freeze")
        result = object.__new__(ProjectScope)
        fields = (
            ("scope_id", scope_id), ("version", version),
            ("repositories", MappingProxyType(dict(repositories))),
            ("services", MappingProxyType(dict(services))),
            ("environments", MappingProxyType(dict(environments))),
            ("target_bindings", MappingProxyType(dict(targets))),
            ("discovery_digest", discovery_digest), ("metadata_revision", metadata_revision),
            ("scope_digest", expected_digest), ("_source", frozen_source),
        )
        for name, item in fields:
            object.__setattr__(result, name, item)
        return result

    def require_realization(self, repository_id: str, actual_git_identity: str) -> None:
        repository_id = require_id(repository_id, "repository binding ID")
        actual_git_identity = require_id(actual_git_identity, "actual Git identity")
        try:
            binding = self.repositories[repository_id]
        except KeyError as error:
            raise ProjectScopeError("unknown repository binding") from error
        expected = binding.canonical_identity if binding.mode == "attach_existing" else binding.realized_git_identity
        if expected is None or not hmac.compare_digest(expected, actual_git_identity):
            raise ProjectScopeError("actual Git identity does not match the approved target")

    def to_dict(self) -> dict[str, object]:
        """Return the exact validated source without exposing mutable internal state."""

        value = thaw(self._source)
        if not isinstance(value, dict):
            raise AssertionError("ProjectScope source did not thaw to an object")
        return value


@dataclass(frozen=True, slots=True)
class ScopeChange:
    change_class: str
    changed_binding_ids: tuple[str, ...]
    invalidated_target_ids: tuple[str, ...]
    requires_reapproval: bool
    requires_authority_expansion: bool


def classify_scope_change(current: ProjectScope, candidate: ProjectScope) -> ScopeChange:
    if type(current) is not ProjectScope or type(candidate) is not ProjectScope:
        raise ProjectScopeError("scope change requires exact ProjectScope values")
    if current.scope_id != candidate.scope_id:
        raise ProjectScopeError("scope identity cannot change")
    before_projection = _project(current._source)
    after_projection = _project(candidate._source)
    if current.scope_digest == candidate.scope_digest:
        if current.version != candidate.version or candidate.metadata_revision <= current.metadata_revision:
            raise ProjectScopeError("metadata-only update must advance only metadata revision")
        return ScopeChange("metadata-only", (), (), False, False)
    if candidate.version != current.version + 1:
        raise ProjectScopeError("semantic scope change must advance version exactly once")
    changed: set[str] = set()
    added = False
    for group in ("repositories", "services", "environments", "target_bindings"):
        identity = "target_id" if group == "target_bindings" else "binding_id"
        before = {item[identity]: item for item in before_projection[group]}
        after = {item[identity]: item for item in after_projection[group]}
        changed.update(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        added = added or bool(after.keys() - before.keys())
    invalidated: list[str] = []
    for target_id in sorted(current.target_bindings.keys() | candidate.target_bindings.keys()):
        target = current.target_bindings.get(target_id) or candidate.target_bindings[target_id]
        refs = target.repository_ids + target.service_ids + target.environment_ids
        if target_id in changed or any(ref in changed for ref in refs):
            invalidated.append(target_id)
    change_class = "authority-expansion" if added else "semantic"
    return ScopeChange(
        change_class,
        tuple(sorted(changed)),
        tuple(invalidated),
        True,
        added,
    )
