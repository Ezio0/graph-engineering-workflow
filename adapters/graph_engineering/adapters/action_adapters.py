"""Factory-attested dispatch boundary for closed concrete action adapters."""

from __future__ import annotations

import copy
import hashlib
import hmac
import importlib
import json
import os
import pathlib
import stat
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.action_adapters import (
    ActionAdapterContractError,
    ActionAdapterRegistry,
    ActionAdapterRegistryEntry,
    ActionInvocation,
    ConcreteActionPolicy,
)
from graph_engineering.core.actions import (
    ActionAdapterInstallationAttestation,
    ActionPolicy,
)
from graph_engineering.core.contracts.digest import semantic_digest


class ActionAdapterRejection(ValueError):
    """A concrete adapter dispatch was rejected before its port was called."""


@dataclass(frozen=True, slots=True)
class ActionAdapterPorts:
    invoke: Callable[[ActionInvocation, dict[str, object]], Mapping[str, object]]

    def __post_init__(self) -> None:
        if not callable(self.invoke):
            raise ActionAdapterRejection("concrete action invocation port is missing")


_FACTORY_SEAL = object()
_ATTESTED_ACTION_ADAPTERS: dict[int, tuple[object, object]] = {}

_IMPLEMENTATION_MODULES = MappingProxyType({
    "builtin:connector-unavailable-v1": "graph_engineering.adapters.connector_unavailable",
    "builtin:git-native-v1": "graph_engineering.adapters.git_native",
    "builtin:project-command-v1": "graph_engineering.adapters.command_native",
    "builtin:secret-provider-v1": "graph_engineering.adapters.command_native",
    "builtin:target-query-v1": "graph_engineering.adapters.git_native",
})
_extension_build_tables = (
    "tool.gew.build.offline-wheel-policy",
    "tool.gew.build.package-parser-requirement",
    "tool.gew.profile.category-execution-policy",
    "tool.gew.profile.coverage-execution-plan",
    "tool.gew.profile.real-e2e-bindings",
    "tool.gew.profile.dependency-advisory",
    "tool.gew.profile.migration-rehearsal",
    "tool.gew.profile.performance-benchmark",
)
_extension_dependencies = ("cryptography==50.0.0", "packaging==26.3")
_extension_imports = ("cryptography", "packaging")


def _remove_toml_table(body: bytes, table: str) -> bytes:
    marker = b"\n[" + table.encode("ascii") + b"]\n"
    if body.count(marker) != 1:
        raise ActionAdapterRejection("built-in action adapter build projection is not exact")
    start = body.index(marker)
    end = body.find(b"\n[", start + len(marker))
    if end < 0:
        end = len(body)
    return body[:start] + body[end:]


def _project_owned_toml_list_members(
    body: bytes,
    table: str,
    key: str,
    values: list[str],
    owned: tuple[str, ...],
) -> bytes:
    header = b"[" + table.encode("ascii") + b"]\n"
    if body.count(header) != 1:
        raise ActionAdapterRejection("built-in action adapter build projection is not exact")
    start = body.index(header) + len(header)
    end = body.find(b"\n[", start)
    if end < 0:
        end = len(body)
    prefix = key.encode("ascii") + b" = "
    lines = body[start:end].splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if (
        len(matches) != 1
        or len(values) != len(set(values))
        or any(values.count(member) != 1 for member in owned)
        or tuple(value for value in values if value in owned) != owned
    ):
        raise ActionAdapterRejection("built-in action adapter build projection is not exact")
    canonical = json.dumps(values, ensure_ascii=False).encode("utf-8")
    if lines[matches[0]] != prefix + canonical + b"\n":
        raise ActionAdapterRejection("built-in action adapter build projection is not exact")
    retained = [value for value in values if value not in owned]
    lines[matches[0]] = (
        prefix + json.dumps(retained, ensure_ascii=False).encode("utf-8") + b"\n"
    )
    return body[:start] + b"".join(lines) + body[end:]


def _action_build_manifest_digest(body: bytes) -> str:
    """Bind action code to its manifest while excluding exact WP-08-only fields."""

    try:
        manifest = tomllib.loads(body.decode("utf-8", errors="strict"))
        project = manifest["project"]
        architecture = manifest["tool"]["gew"]["architecture"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ActionAdapterRejection(
            "built-in action adapter build manifest is malformed"
        ) from error
    if (
        type(project) is not dict
        or type(project.get("dependencies")) is not list
        or any(type(item) is not str for item in project["dependencies"])
        or type(architecture) is not dict
        or type(architecture.get("declared-external-imports")) is not list
        or any(
            type(item) is not str
            for item in architecture["declared-external-imports"]
        )
    ):
        raise ActionAdapterRejection(
            "built-in action adapter extension build boundary is not exact"
        )
    projected = _project_owned_toml_list_members(
        body,
        "project",
        "dependencies",
        project["dependencies"],
        _extension_dependencies,
    )
    projected = _project_owned_toml_list_members(
        projected,
        "tool.gew.architecture",
        "declared-external-imports",
        architecture["declared-external-imports"],
        _extension_imports,
    )
    for table in _extension_build_tables:
        projected = _remove_toml_table(projected, table)
    return hashlib.sha256(projected).hexdigest()


def builtin_implementation_digest(implementation_ref: str) -> str:
    """Mechanically bind a built-in ref to its exact module and build-source bytes."""

    try:
        module_name = _IMPLEMENTATION_MODULES[implementation_ref]
    except KeyError as error:
        raise ActionAdapterRejection("action adapter implementation is not built in") from error
    module = importlib.import_module(module_name)
    origin = getattr(module, "__file__", None)
    if type(origin) is not str:
        raise ActionAdapterRejection("built-in action adapter source origin is unavailable")
    from graph_engineering import _validated_archive_resource
    module_resource = module_name.replace(".", "/") + ".py"
    archived_source = _validated_archive_resource(module_resource)
    archived_manifest = _validated_archive_resource("graph_engineering/pyproject.toml")
    if archived_source is not None or archived_manifest is not None:
        loader = getattr(module, "__loader__", None)
        get_data = getattr(loader, "get_data", None)
        if (
            archived_source is None
            or archived_manifest is None
            or not callable(get_data)
        ):
            raise ActionAdapterRejection(
                "built-in action adapter archive binding is incomplete"
            )
        try:
            loaded_source = get_data(origin)
        except OSError as error:
            raise ActionAdapterRejection(
                "built-in action adapter archive origin is unavailable"
            ) from error
        if type(loaded_source) is not bytes or not hmac.compare_digest(
            hashlib.sha256(loaded_source).digest(),
            hashlib.sha256(archived_source).digest(),
        ):
            raise ActionAdapterRejection(
                "built-in action adapter archive origin changed"
            )
        source_digest = hashlib.sha256(archived_source).hexdigest()
        build_digest = _action_build_manifest_digest(archived_manifest)
    else:
        source = pathlib.Path(origin).resolve(strict=True)
        metadata = os.lstat(source)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ActionAdapterRejection("built-in action adapter source origin is unsafe")
        source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        project_manifest = next(
            (parent / "pyproject.toml" for parent in tuple(source.parents)[:8]
             if (parent / "pyproject.toml").is_file()),
            None,
        )
        if project_manifest is None:
            raise ActionAdapterRejection("built-in action adapter build manifest is unavailable")
        build_digest = _action_build_manifest_digest(project_manifest.read_bytes())
    return semantic_digest(
        {
            "schema_version": "1.0.0",
            "implementation_ref": implementation_ref,
            "module_name": module_name,
            "module_source_sha256": source_digest,
            "build_manifest_sha256": build_digest,
        },
        contract_type="urn:gew:contract:action-adapter-implementation-provenance",
        projection_id="urn:gew:digest-projection:identity:1.0.0",
        schema_id="urn:gew:schema:action-adapter-implementation-provenance:1.0.0",
    )


class BoundActionAdapter:
    """One immutable registry entry bound to one product-owned invocation port."""

    __slots__ = ("_descriptor", "_policy", "_ports")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("concrete action adapters are created only by ActionAdapterFactory")

    @property
    def descriptor(self) -> ActionAdapterRegistryEntry:
        return self._descriptor

    def dispatch(
        self,
        invocation_document: Mapping[str, object],
        *,
        expected: ActionInvocation,
        payload: dict[str, object],
    ) -> dict[str, object]:
        ActionAdapterFactory.require_attested(self)
        if type(expected) is not ActionInvocation:
            raise ActionAdapterRejection("durable expected invocation is missing or forged")
        try:
            candidate = ActionInvocation.from_dict(invocation_document)
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("action invocation contract rejected") from error
        if candidate != expected:
            raise ActionAdapterRejection("action invocation differs from the durable expected binding")
        if (
            candidate.adapter_id != self._descriptor.adapter_id
            or candidate.adapter_id not in self._policy.allowed_adapter_ids
            or candidate.operation_id not in self._descriptor.operation_ids
            or candidate.operation_id not in self._policy.allowed_operation_ids
        ):
            raise ActionAdapterRejection("action adapter or operation is not in the exact policy closure")
        try:
            payload_digest = ActionInvocation.payload_digest_for(payload)
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("action payload contract rejected") from error
        if not hmac.compare_digest(payload_digest, candidate.payload_digest):
            raise ActionAdapterRejection("action payload differs from the authorized invocation")
        raw = self._ports.invoke(candidate, copy.deepcopy(payload))
        if type(raw) is not dict or set(raw) != {"result", "result_digest"}:
            raise ActionAdapterRejection("action adapter result is not exact")
        if raw["result"] not in {"succeeded", "failed", "unknown", "blocked"}:
            raise ActionAdapterRejection("action adapter result class is invalid")
        from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST
        if type(raw["result_digest"]) is not str or SEMANTIC_DIGEST.fullmatch(raw["result_digest"]) is None:
            raise ActionAdapterRejection("action adapter result digest is invalid")
        return copy.deepcopy(raw)


class ActionAdapterFactory:
    """The sole production issuer for adapters in the exact installed registry."""

    __slots__ = (
        "_policy", "_registry", "_configuration_digests", "_installation_attestation",
    )

    def __init__(
        self,
        policy: ConcreteActionPolicy,
        registry: ActionAdapterRegistry,
        *,
        installation_attestation: ActionAdapterInstallationAttestation,
        configuration_digests: Mapping[str, str] | None = None,
    ) -> None:
        if type(policy) is not ConcreteActionPolicy or type(registry) is not ActionAdapterRegistry:
            raise ActionAdapterRejection("concrete action policy or registry is missing or forged")
        if policy.registry_id != registry.registry_id or not hmac.compare_digest(
            policy.registry_digest, registry.registry_digest
        ):
            raise ActionAdapterRejection("concrete action policy registry binding changed")
        if (
            type(installation_attestation) is not ActionAdapterInstallationAttestation
            or installation_attestation.concrete_policy_id != policy.policy_id
            or not hmac.compare_digest(
                installation_attestation.concrete_policy_digest, policy.policy_digest,
            )
            or installation_attestation.registry_id != registry.registry_id
            or not hmac.compare_digest(
                installation_attestation.registry_digest, registry.registry_digest,
            )
            or type(installation_attestation._issuer) is not ActionPolicy
        ):
            raise ActionAdapterRejection("concrete action authority is not installation-attested")
        for entry in registry.entries:
            if not hmac.compare_digest(
                entry.implementation_digest,
                builtin_implementation_digest(entry.implementation_ref),
            ):
                raise ActionAdapterRejection(
                    "action adapter implementation provenance differs from installation registry"
                )
        self._policy = policy
        self._registry = registry
        self._installation_attestation = installation_attestation
        pins = {} if configuration_digests is None else dict(configuration_digests)
        allowed = {
            "command-registry", "command-runtime-policy", "git-adapter-configuration",
            "secret-provider-registry", "connector-registry",
        }
        from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST
        if (
            not set(pins).issubset(allowed)
            or any(
                type(name) is not str
                or type(value) is not str
                or SEMANTIC_DIGEST.fullmatch(value) is None
                for name, value in pins.items()
            )
        ):
            raise ActionAdapterRejection("action adapter installation configuration pins are invalid")
        self._configuration_digests = MappingProxyType(pins)

    def _require_configuration(
        self,
        kind: str,
        document: Mapping[str, object],
        field: str,
    ) -> None:
        expected = self._configuration_digests.get(kind)
        candidate = document.get(field)
        if (
            expected is None
            or type(candidate) is not str
            or not hmac.compare_digest(expected, candidate)
        ):
            raise ActionAdapterRejection("action adapter configuration is not installation-pinned")

    def issue(self, adapter_id: str, ports: ActionAdapterPorts) -> BoundActionAdapter:
        if type(ports) is not ActionAdapterPorts:
            raise ActionAdapterRejection("concrete action ports are missing or forged")
        if adapter_id not in self._policy.allowed_adapter_ids:
            raise ActionAdapterRejection("concrete action adapter is not policy enabled")
        try:
            descriptor = self._registry.entry(adapter_id)
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("concrete action adapter is not installed") from error
        adapter = object.__new__(BoundActionAdapter)
        adapter._descriptor = descriptor
        adapter._policy = self._policy
        adapter._ports = ports
        _ATTESTED_ACTION_ADAPTERS[id(adapter)] = (adapter, _FACTORY_SEAL)
        return adapter

    def issue_git_native(self, configuration: Mapping[str, object]) -> object:
        self._require_configuration(
            "git-adapter-configuration", configuration, "configuration_digest",
        )
        try:
            descriptor = self._registry.entry("git-native-v1")
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("native Git adapter is not installed") from error
        if (
            descriptor.adapter_kind != "git"
            or descriptor.implementation_ref != "builtin:git-native-v1"
            or descriptor.adapter_id not in self._policy.allowed_adapter_ids
        ):
            raise ActionAdapterRejection("native Git adapter registry binding changed")
        from graph_engineering.adapters.git_native import GitNativeAdapter
        adapter = GitNativeAdapter._issue(
            configuration,
            descriptor=descriptor,
            registry_digest=self._registry.registry_digest,
        )
        _ATTESTED_ACTION_ADAPTERS[id(adapter)] = (adapter, _FACTORY_SEAL)
        return adapter

    def issue_secret_provider(self, registry: Mapping[str, object], ports: object) -> object:
        self._require_configuration("secret-provider-registry", registry, "registry_digest")
        try:
            descriptor = self._registry.entry("secret-provider-v1")
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("secret provider adapter is not installed") from error
        if descriptor.adapter_id not in self._policy.allowed_adapter_ids:
            raise ActionAdapterRejection("secret provider adapter is not policy enabled")
        from graph_engineering.adapters.command_native import BoundSecretProvider, SecretProviderPorts
        if type(ports) is not SecretProviderPorts:
            raise ActionAdapterRejection("secret provider ports are missing or forged")
        provider = BoundSecretProvider._issue(registry, ports, descriptor=descriptor)
        _ATTESTED_ACTION_ADAPTERS[id(provider)] = (provider, _FACTORY_SEAL)
        return provider

    def issue_project_command(
        self,
        registry: Mapping[str, object],
        runtime_policy: Mapping[str, object],
        *,
        provider: object,
    ) -> object:
        self._require_configuration("command-registry", registry, "registry_digest")
        self._require_configuration("command-runtime-policy", runtime_policy, "policy_digest")
        try:
            descriptor = self._registry.entry("project-command-v1")
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("project command adapter is not installed") from error
        if descriptor.adapter_id not in self._policy.allowed_adapter_ids:
            raise ActionAdapterRejection("project command adapter is not policy enabled")
        from graph_engineering.adapters.command_native import StructuredCommandLauncher
        launcher = StructuredCommandLauncher._issue(
            registry,
            runtime_policy,
            provider,
            descriptor=descriptor,
        )
        _ATTESTED_ACTION_ADAPTERS[id(launcher)] = (launcher, _FACTORY_SEAL)
        return launcher

    def issue_unavailable_connector(
        self,
        registry: Mapping[str, object],
        connector_id: str,
    ) -> object:
        self._require_configuration("connector-registry", registry, "registry_digest")
        try:
            descriptor = self._registry.entry("connector-unavailable-v1")
        except ActionAdapterContractError as error:
            raise ActionAdapterRejection("unavailable connector adapter is not installed") from error
        if descriptor.adapter_id not in self._policy.allowed_adapter_ids:
            raise ActionAdapterRejection("unavailable connector adapter is not policy enabled")
        from graph_engineering.adapters.connector_unavailable import UnavailableConnectorAdapter
        adapter = UnavailableConnectorAdapter._issue(
            dict(registry),
            connector_id,
            descriptor=descriptor,
        )
        _ATTESTED_ACTION_ADAPTERS[id(adapter)] = (adapter, _FACTORY_SEAL)
        return adapter

    @staticmethod
    def require_attested(adapter: object) -> object:
        issued = _ATTESTED_ACTION_ADAPTERS.get(id(adapter))
        if issued is None or issued[0] is not adapter or issued[1] is not _FACTORY_SEAL:
            raise ActionAdapterRejection("concrete action adapter is not factory-attested")
        return issued[0]

    def require_binding(
        self,
        policy: ConcreteActionPolicy,
        registry: ActionAdapterRegistry,
        action_policy: ActionPolicy,
    ) -> None:
        if (
            self._policy is not policy
            or self._registry is not registry
            or type(action_policy) is not ActionPolicy
            or dict(action_policy.concrete_action_authority) != {
                "policy_id": self._installation_attestation.concrete_policy_id,
                "policy_digest": self._installation_attestation.concrete_policy_digest,
                "registry_id": self._installation_attestation.registry_id,
                "registry_digest": self._installation_attestation.registry_digest,
                "schema_registry_id": self._installation_attestation.schema_registry_id,
                "schema_registry_digest": self._installation_attestation.schema_registry_digest,
            }
        ):
            raise ActionAdapterRejection("action adapter factory policy/registry binding changed")
