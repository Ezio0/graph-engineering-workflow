"""Factory-issued ephemeral secret resolution and structured local command launcher."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import time
import urllib.parse
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.action_adapters import (
    ActionAdapterRegistryEntry,
    ActionInvocation,
)
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.security.privacy import SecretMaterial, SecretReference


IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
_ID = re.compile(r"[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*")
_HEX = re.compile(r"[0-9a-f]{64}")
_ENVIRONMENT = re.compile(r"[A-Z][A-Z0-9_]*")
_FACTORY_SEAL = object()
_ATTESTED_SECRET_PROVIDERS: dict[int, tuple[object, object]] = {}
_issued_launchers: dict[int, tuple[object, object]] = {}


class StructuredCommandRejection(ValueError):
    """The command or secret request failed closed without exposing material."""


def _record(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise StructuredCommandRejection(f"{label} record is not exact")
    return value


def _identity(value: object, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise StructuredCommandRejection(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise StructuredCommandRejection(f"{label} is invalid")
    return value


def _semantic(name: str, value: Mapping[str, object]) -> str:
    return semantic_digest(
        value,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=IDENTITY_PROJECTION,
        schema_id=f"urn:gew:schema:{name}:1.0.0",
    )


def _self_digest(value: Mapping[str, object], field: str, name: str) -> str:
    expected = _digest(value[field], field)
    actual = _semantic(name, {key: item for key, item in value.items() if key != field})
    if not hmac.compare_digest(expected, actual):
        raise StructuredCommandRejection(f"{name} digest mismatch")
    return expected


def _reference_key(reference: SecretReference) -> tuple[str, str, str]:
    return reference.provider_id, reference.key_ref, reference.version_ref


@dataclass(frozen=True, slots=True)
class SecretProviderRegistryEntry:
    provider_id: str
    adapter_id: str
    implementation_ref: str
    allowed_references: tuple[SecretReference, ...]


@dataclass(frozen=True, slots=True)
class SecretProviderRegistry:
    schema_version: str
    registry_id: str
    entries: tuple[SecretProviderRegistryEntry, ...]
    registry_digest: str

    FIELDS = frozenset({"schema_version", "registry_id", "entries", "registry_digest"})

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "secret-provider-registry",
            {key: item for key, item in value.items() if key != "registry_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> SecretProviderRegistry:
        row = _record(value, cls.FIELDS, "secret provider registry")
        raw_entries = row["entries"]
        if row["schema_version"] != "1.0.0" or type(raw_entries) is not list or not raw_entries:
            raise StructuredCommandRejection("secret provider registry value is invalid")
        entries: list[SecretProviderRegistryEntry] = []
        for raw in raw_entries:
            item = _record(
                raw,
                frozenset({"provider_id", "adapter_id", "implementation_ref", "allowed_references"}),
                "secret provider registry entry",
            )
            raw_references = item["allowed_references"]
            if type(raw_references) is not list or not raw_references:
                raise StructuredCommandRejection("secret provider reference closure is empty")
            references = tuple(SecretReference.from_dict(reference) for reference in raw_references)
            keys = tuple(_reference_key(reference) for reference in references)
            if keys != tuple(sorted(set(keys))):
                raise StructuredCommandRejection("secret provider references are not canonical")
            entries.append(SecretProviderRegistryEntry(
                _identity(item["provider_id"], "secret provider ID"),
                _identity(item["adapter_id"], "secret provider adapter ID"),
                _identity(item["implementation_ref"], "secret provider implementation ref"),
                references,
            ))
        provider_ids = tuple(entry.provider_id for entry in entries)
        if provider_ids != tuple(sorted(set(provider_ids))):
            raise StructuredCommandRejection("secret provider entries are not canonical")
        return cls(
            "1.0.0",
            _identity(row["registry_id"], "secret provider registry ID"),
            tuple(entries),
            _self_digest(row, "registry_digest", "secret-provider-registry"),
        )

    def entry(self, provider_id: str) -> SecretProviderRegistryEntry:
        matches = tuple(entry for entry in self.entries if entry.provider_id == provider_id)
        if len(matches) != 1:
            raise StructuredCommandRejection("secret provider is not installed")
        return matches[0]


@dataclass(frozen=True, slots=True)
class SecretProviderPorts:
    resolve: Callable[[SecretReference], bytes]

    def __post_init__(self) -> None:
        if not callable(self.resolve):
            raise StructuredCommandRejection("secret provider port is missing")


class _SecretResolutionPermit:
    __slots__ = ("owner", "live")

    def __init__(self, owner: object) -> None:
        self.owner = owner
        self.live = True


class BoundSecretProvider:
    """Closed provider whose value-producing method is accessible only to a live launch."""

    __slots__ = ("_entry", "_ports")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("secret providers are created only by ActionAdapterFactory")

    @classmethod
    def _issue(
        cls,
        registry_document: Mapping[str, object],
        ports: SecretProviderPorts,
        *,
        descriptor: ActionAdapterRegistryEntry,
    ) -> BoundSecretProvider:
        registry = SecretProviderRegistry.from_dict(registry_document)
        if type(ports) is not SecretProviderPorts or type(descriptor) is not ActionAdapterRegistryEntry:
            raise StructuredCommandRejection("secret provider factory binding is invalid")
        entries = tuple(entry for entry in registry.entries if entry.adapter_id == descriptor.adapter_id)
        if (
            descriptor.adapter_kind != "secret-provider"
            or descriptor.implementation_ref != "builtin:secret-provider-v1"
            or len(entries) != 1
        ):
            raise StructuredCommandRejection("secret provider registry binding changed")
        provider = object.__new__(cls)
        provider._entry = entries[0]
        provider._ports = ports
        _ATTESTED_SECRET_PROVIDERS[id(provider)] = (provider, _FACTORY_SEAL)
        return provider

    @staticmethod
    def require_attested(provider: object) -> BoundSecretProvider:
        issued = _ATTESTED_SECRET_PROVIDERS.get(id(provider))
        if issued is None or issued[0] is not provider or issued[1] is not _FACTORY_SEAL:
            raise StructuredCommandRejection("secret provider is not factory-attested")
        return provider  # type: ignore[return-value]

    def _resolve(self, reference: SecretReference, permit: _SecretResolutionPermit) -> SecretMaterial:
        BoundSecretProvider.require_attested(self)
        if (
            type(reference) is not SecretReference
            or type(permit) is not _SecretResolutionPermit
            or permit.owner is not self
            or permit.live is not True
            or _reference_key(reference) not in tuple(
                _reference_key(candidate) for candidate in self._entry.allowed_references
            )
        ):
            raise StructuredCommandRejection("secret reference is not approved for this session")
        try:
            value = self._ports.resolve(reference)
            return SecretMaterial.from_provider(value, reference=reference)
        except BaseException as error:
            raise StructuredCommandRejection("secret provider resolution failed") from error

    def __repr__(self) -> str:
        return f"<BoundSecretProvider provider_id={self._entry.provider_id!r}>"


@dataclass(frozen=True, slots=True)
class CommandRegistryEntry:
    command_id: str
    adapter_id: str
    executable: str
    executable_sha256: str
    allowed_root: str
    cwd_relative: str
    argv_prefix: tuple[str, ...]
    parameter_order: tuple[str, ...]
    parameter_values: Mapping[str, tuple[str, ...]]
    static_environment: Mapping[str, str]
    secret_environment: Mapping[str, SecretReference]
    side_effect_class: str
    idempotency_class: str


@dataclass(frozen=True, slots=True)
class CommandRegistry:
    schema_version: str
    registry_id: str
    entries: tuple[CommandRegistryEntry, ...]
    registry_digest: str

    FIELDS = frozenset({"schema_version", "registry_id", "entries", "registry_digest"})

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "command-registry",
            {key: item for key, item in value.items() if key != "registry_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> CommandRegistry:
        row = _record(value, cls.FIELDS, "command registry")
        raw_entries = row["entries"]
        if row["schema_version"] != "1.0.0" or type(raw_entries) is not list or not raw_entries:
            raise StructuredCommandRejection("command registry value is invalid")
        entries: list[CommandRegistryEntry] = []
        entry_fields = frozenset({
            "command_id", "adapter_id", "executable", "executable_sha256", "allowed_root",
            "cwd_relative", "argv_prefix", "parameter_order", "parameter_values",
            "static_environment", "secret_environment", "side_effect_class",
            "idempotency_class",
        })
        for raw in raw_entries:
            item = _record(raw, entry_fields, "command registry entry")
            executable = item["executable"]
            executable_sha256 = item["executable_sha256"]
            allowed_root = item["allowed_root"]
            cwd_relative = item["cwd_relative"]
            argv_prefix = item["argv_prefix"]
            parameter_order = item["parameter_order"]
            parameter_values = item["parameter_values"]
            static_environment = item["static_environment"]
            secret_environment = item["secret_environment"]
            if (
                type(executable) is not str
                or not pathlib.PurePath(executable).is_absolute()
                or type(executable_sha256) is not str
                or _HEX.fullmatch(executable_sha256) is None
                or type(allowed_root) is not str
                or not pathlib.PurePath(allowed_root).is_absolute()
                or type(cwd_relative) is not str
                or not cwd_relative
                or type(argv_prefix) is not list
                or not argv_prefix
                or any(type(argument) is not str or not argument or "\x00" in argument for argument in argv_prefix)
                or type(parameter_order) is not list
                or not parameter_order
                or type(parameter_values) is not dict
                or type(static_environment) is not dict
                or type(secret_environment) is not dict
            ):
                raise StructuredCommandRejection("command registry entry value is invalid")
            cwd = pathlib.PurePosixPath(cwd_relative)
            if cwd.is_absolute() or any(part in {"", ".", ".."} for part in cwd_relative.split("/")):
                raise StructuredCommandRejection("command working directory escapes its allowed root")
            parameters = tuple(_identity(name, "command parameter") for name in parameter_order)
            if parameters != tuple(sorted(set(parameters))) or set(parameter_values) != set(parameters):
                raise StructuredCommandRejection("command parameter closure is not exact")
            frozen_values: dict[str, tuple[str, ...]] = {}
            for name in parameters:
                values = parameter_values[name]
                if type(values) is not list or not values or any(
                    type(candidate) is not str or not candidate or "\x00" in candidate for candidate in values
                ):
                    raise StructuredCommandRejection("command parameter values are invalid")
                frozen = tuple(values)
                if frozen != tuple(sorted(set(frozen))):
                    raise StructuredCommandRejection("command parameter values are not canonical")
                frozen_values[name] = frozen
            static: dict[str, str] = {}
            for name, candidate in static_environment.items():
                if (
                    type(name) is not str
                    or _ENVIRONMENT.fullmatch(name) is None
                    or type(candidate) is not str
                    or "\x00" in candidate
                ):
                    raise StructuredCommandRejection("static command environment is invalid")
                static[name] = candidate
            secret: dict[str, SecretReference] = {}
            for name, candidate in secret_environment.items():
                if type(name) is not str or _ENVIRONMENT.fullmatch(name) is None:
                    raise StructuredCommandRejection("secret command environment is invalid")
                secret[name] = SecretReference.from_dict(candidate)
            if set(static) & set(secret):
                raise StructuredCommandRejection("command environment names overlap")
            entries.append(CommandRegistryEntry(
                _identity(item["command_id"], "command ID"),
                _identity(item["adapter_id"], "command adapter ID"),
                executable,
                executable_sha256,
                allowed_root,
                cwd.as_posix(),
                tuple(argv_prefix),
                parameters,
                MappingProxyType(frozen_values),
                MappingProxyType(static),
                MappingProxyType(secret),
                _identity(item["side_effect_class"], "command side-effect class"),
                _identity(item["idempotency_class"], "command idempotency class"),
            ))
        command_ids = tuple(entry.command_id for entry in entries)
        if command_ids != tuple(sorted(set(command_ids))):
            raise StructuredCommandRejection("command registry entries are not canonical")
        return cls(
            "1.0.0",
            _identity(row["registry_id"], "command registry ID"),
            tuple(entries),
            _self_digest(row, "registry_digest", "command-registry"),
        )


@dataclass(frozen=True, slots=True)
class CommandRuntimePolicy:
    schema_version: str
    policy_id: str
    launcher_mode: str
    max_parameters: int
    max_parameter_bytes: int
    max_output_bytes: int
    read_chunk_bytes: int
    timeout_ms: int
    poll_interval_ms: int
    termination_grace_ms: int
    termination_force_wait_ms: int
    output_field_allowlist: tuple[str, ...]
    secret_encodings: tuple[str, ...]
    policy_digest: str

    FIELDS = frozenset({
        "schema_version", "policy_id", "launcher_mode", "max_parameters",
        "max_parameter_bytes", "max_output_bytes", "read_chunk_bytes", "timeout_ms",
        "poll_interval_ms", "termination_grace_ms", "termination_force_wait_ms",
        "output_field_allowlist", "secret_encodings", "policy_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "command-runtime-policy",
            {key: item for key, item in value.items() if key != "policy_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> CommandRuntimePolicy:
        row = _record(value, cls.FIELDS, "command runtime policy")
        integer_fields = (
            "max_parameters", "max_parameter_bytes", "max_output_bytes", "read_chunk_bytes",
            "timeout_ms", "poll_interval_ms", "termination_grace_ms",
            "termination_force_wait_ms",
        )
        integers = tuple(row[name] for name in integer_fields)
        fields = row["output_field_allowlist"]
        encodings = row["secret_encodings"]
        if (
            row["schema_version"] != "1.0.0"
            or row["launcher_mode"] != "structured-argv-shell-false"
            or any(type(item) is not int or item <= 0 for item in integers)
            or row["read_chunk_bytes"] > row["max_output_bytes"]
            or type(fields) is not list
            or not fields
            or type(encodings) is not list
            or not encodings
        ):
            raise StructuredCommandRejection("command runtime policy value is invalid")
        output_fields = tuple(_identity(item, "output field") for item in fields)
        encoding_values = tuple(_identity(item, "secret encoding") for item in encodings)
        if (
            output_fields != tuple(sorted(set(output_fields)))
            or encoding_values != tuple(sorted(set(encoding_values)))
            or not set(encoding_values).issubset({
                "raw", "base64", "hex", "json", "sha256", "url",
            })
        ):
            raise StructuredCommandRejection("command runtime policy closure is invalid")
        return cls(
            "1.0.0",
            _identity(row["policy_id"], "command runtime policy ID"),
            row["launcher_mode"],
            *integers,
            output_fields,
            encoding_values,
            _self_digest(row, "policy_digest", "command-runtime-policy"),
        )


@dataclass(frozen=True, slots=True)
class CommandExecutionRequest:
    schema_version: str
    request_id: str
    command_id: str
    parameters: Mapping[str, str]
    secret_references: tuple[SecretReference, ...]
    request_digest: str

    FIELDS = frozenset({
        "schema_version", "request_id", "command_id", "parameters",
        "secret_references", "request_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _semantic(
            "command-execution-request",
            {key: item for key, item in value.items() if key != "request_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> CommandExecutionRequest:
        row = _record(value, cls.FIELDS, "command execution request")
        parameters = row["parameters"]
        references = row["secret_references"]
        if (
            row["schema_version"] != "1.0.0"
            or type(parameters) is not dict
            or type(references) is not list
        ):
            raise StructuredCommandRejection("command execution request value is invalid")
        frozen_parameters: dict[str, str] = {}
        for name, candidate in parameters.items():
            if (
                type(name) is not str
                or _ID.fullmatch(name) is None
                or type(candidate) is not str
                or not candidate
                or "\x00" in candidate
            ):
                raise StructuredCommandRejection("command execution parameter is invalid")
            frozen_parameters[name] = candidate
        parsed_references = tuple(SecretReference.from_dict(reference) for reference in references)
        keys = tuple(_reference_key(reference) for reference in parsed_references)
        if keys != tuple(sorted(set(keys))):
            raise StructuredCommandRejection("command secret references are not canonical")
        return cls(
            "1.0.0",
            _identity(row["request_id"], "command request ID"),
            _identity(row["command_id"], "command ID"),
            MappingProxyType(frozen_parameters),
            parsed_references,
            _self_digest(row, "request_digest", "command-execution-request"),
        )


@dataclass(frozen=True, slots=True)
class CommandExecutionResult:
    schema_version: str
    request_id: str
    request_digest: str
    command_id: str
    invocation_digest: str
    outcome: str
    failure_class: str | None
    reconciliation_required: bool
    exit_code: int | None
    output: Mapping[str, object]
    result_digest: str

    @classmethod
    def create(
        cls,
        *,
        request: CommandExecutionRequest,
        invocation: ActionInvocation,
        outcome: str,
        failure_class: str | None,
        reconciliation_required: bool,
        exit_code: int | None,
        output: Mapping[str, object],
    ) -> CommandExecutionResult:
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "request_id": request.request_id,
            "request_digest": request.request_digest,
            "command_id": request.command_id,
            "invocation_digest": invocation.invocation_digest,
            "outcome": outcome,
            "failure_class": failure_class,
            "reconciliation_required": reconciliation_required,
            "exit_code": exit_code,
            "output": copy.deepcopy(dict(output)),
        }
        body["result_digest"] = _semantic("command-execution-result", body)
        return cls(
            "1.0.0", request.request_id, request.request_digest, request.command_id,
            invocation.invocation_digest, outcome, failure_class, reconciliation_required,
            exit_code, MappingProxyType(copy.deepcopy(dict(output))), body["result_digest"],  # type: ignore[arg-type]
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "request_digest": self.request_digest,
            "command_id": self.command_id,
            "invocation_digest": self.invocation_digest,
            "outcome": self.outcome,
            "failure_class": self.failure_class,
            "reconciliation_required": self.reconciliation_required,
            "exit_code": self.exit_code,
            "output": copy.deepcopy(dict(self.output)),
            "result_digest": self.result_digest,
        }


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_cwd(entry: CommandRegistryEntry) -> tuple[int, int, tuple[int, int], str]:
    try:
        root_named = os.lstat(entry.allowed_root)
        if stat.S_ISLNK(root_named.st_mode) or not stat.S_ISDIR(root_named.st_mode):
            raise StructuredCommandRejection("command allowed root is unsafe")
        root_descriptor = os.open(entry.allowed_root, _directory_flags())
        descriptor = os.dup(root_descriptor)
        try:
            for part in pathlib.PurePosixPath(entry.cwd_relative).parts:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            path = os.path.join(entry.allowed_root, entry.cwd_relative)
            named = os.lstat(path)
            if (
                stat.S_ISLNK(named.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
            ):
                raise StructuredCommandRejection("command working directory identity changed")
            return root_descriptor, descriptor, (metadata.st_dev, metadata.st_ino), path
        except BaseException:
            os.close(descriptor)
            os.close(root_descriptor)
            raise
    except (FileNotFoundError, NotADirectoryError, OSError) as error:
        raise StructuredCommandRejection("command working directory is unavailable") from error


def _secret_variants(materials: tuple[SecretMaterial, ...], encodings: tuple[str, ...]) -> tuple[bytes, ...]:
    variants: set[bytes] = set()
    for material in materials:
        raw = material.reveal()
        # Semantic values and their digest are never safe output, regardless
        # of optional transport encodings selected by installation policy.
        variants.add(raw)
        variants.add(hashlib.sha256(raw).hexdigest().encode("ascii"))
        if "base64" in encodings:
            variants.add(base64.b64encode(raw))
        if "hex" in encodings:
            variants.add(raw.hex().encode("ascii"))
        if "url" in encodings:
            variants.add(urllib.parse.quote_from_bytes(raw, safe="").encode("ascii"))
        if "json" in encodings:
            try:
                semantic = raw.decode("utf-8", errors="strict")
            except UnicodeError:
                pass
            else:
                for ensure_ascii in (False, True):
                    serialized = json.dumps(semantic, ensure_ascii=ensure_ascii).encode("utf-8")
                    variants.add(serialized)
                    variants.add(serialized[1:-1])
    return tuple(sorted(variant for variant in variants if variant))


def _semantic_contains_secret(value: object, variants: tuple[bytes, ...]) -> bool:
    """Scan parsed output without copying it into a result or log record."""

    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is str:
            encoded = item.encode("utf-8")
            if any(variant in encoded for variant in variants):
                return True
        elif type(item) is dict:
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    return False


class StructuredCommandLauncher:
    __slots__ = (
        "_entry", "_policy", "_registry_digest", "_policy_digest", "_provider",
        "_executable_descriptor", "_executable_identity",
        "_root_descriptor", "_cwd_descriptor", "_cwd_identity", "_cwd_path", "_launch_count",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("structured command launchers are created only by ActionAdapterFactory")

    @classmethod
    def _issue(
        cls,
        registry_document: Mapping[str, object],
        policy_document: Mapping[str, object],
        provider: object,
        *,
        descriptor: ActionAdapterRegistryEntry,
    ) -> StructuredCommandLauncher:
        registry = CommandRegistry.from_dict(registry_document)
        policy = CommandRuntimePolicy.from_dict(policy_document)
        bound_provider = BoundSecretProvider.require_attested(provider)
        entries = tuple(entry for entry in registry.entries if entry.adapter_id == descriptor.adapter_id)
        if (
            descriptor.adapter_kind != "project-command"
            or descriptor.implementation_ref != "builtin:project-command-v1"
            or len(entries) != 1
        ):
            raise StructuredCommandRejection("project command registry binding changed")
        entry = entries[0]
        if len(entry.parameter_order) > policy.max_parameters:
            raise StructuredCommandRejection("command parameter count exceeds configured policy")
        try:
            named = os.lstat(entry.executable)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            executable_descriptor = os.open(entry.executable, flags)
            metadata = os.fstat(executable_descriptor)
            if (
                stat.S_ISLNK(named.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise StructuredCommandRejection("configured command executable is unsafe")
            with os.fdopen(os.dup(executable_descriptor), "rb", closefd=True) as stream:
                actual = hashlib.sha256(stream.read()).hexdigest()
            if not hmac.compare_digest(actual, entry.executable_sha256):
                raise StructuredCommandRejection("configured command executable digest changed")
            root_descriptor, cwd_descriptor, cwd_identity, cwd_path = _open_cwd(entry)
        except BaseException:
            if "executable_descriptor" in locals():
                os.close(executable_descriptor)
            raise
        launcher = object.__new__(cls)
        launcher._entry = entry
        launcher._policy = policy
        launcher._registry_digest = registry.registry_digest
        launcher._policy_digest = policy.policy_digest
        launcher._provider = bound_provider
        launcher._executable_descriptor = executable_descriptor
        launcher._executable_identity = (metadata.st_dev, metadata.st_ino, metadata.st_size)
        launcher._root_descriptor = root_descriptor
        launcher._cwd_descriptor = cwd_descriptor
        launcher._cwd_identity = cwd_identity
        launcher._cwd_path = cwd_path
        launcher._launch_count = 0
        _issued_launchers[id(launcher)] = (launcher, _FACTORY_SEAL)
        return launcher

    @staticmethod
    def require_attested(launcher: object) -> StructuredCommandLauncher:
        issued = _issued_launchers.get(id(launcher))
        if issued is None or issued[0] is not launcher or issued[1] is not _FACTORY_SEAL:
            raise StructuredCommandRejection("command launcher is not factory-attested")
        return launcher  # type: ignore[return-value]

    @property
    def launch_count(self) -> int:
        return self._launch_count

    @property
    def command_registry_digest(self) -> str:
        StructuredCommandLauncher.require_attested(self)
        return self._registry_digest

    @property
    def command_runtime_policy_digest(self) -> str:
        StructuredCommandLauncher.require_attested(self)
        return self._policy_digest

    @property
    def executable_raw_sha256(self) -> str:
        StructuredCommandLauncher.require_attested(self)
        self._verify_locations()
        return self._entry.executable_sha256

    @property
    def command_id(self) -> str:
        StructuredCommandLauncher.require_attested(self)
        return self._entry.command_id

    def _verify_locations(self) -> None:
        executable = os.fstat(self._executable_descriptor)
        executable_named = os.lstat(self._entry.executable)
        cwd = os.fstat(self._cwd_descriptor)
        cwd_named = os.lstat(self._cwd_path)
        if (
            (executable.st_dev, executable.st_ino, executable.st_size) != self._executable_identity
            or (executable_named.st_dev, executable_named.st_ino, executable_named.st_size)
            != self._executable_identity
            or (cwd.st_dev, cwd.st_ino) != self._cwd_identity
            or (cwd_named.st_dev, cwd_named.st_ino) != self._cwd_identity
        ):
            raise StructuredCommandRejection("command executable or working directory identity changed")

    def _failure(
        self,
        request: CommandExecutionRequest,
        invocation: ActionInvocation,
        failure_class: str,
        *,
        outcome: str = "unknown",
        reconciliation_required: bool = True,
    ) -> CommandExecutionResult:
        return CommandExecutionResult.create(
            request=request,
            invocation=invocation,
            outcome=outcome,
            failure_class=failure_class,
            reconciliation_required=reconciliation_required,
            exit_code=None,
            output={},
        )

    def _collect(
        self,
        process: subprocess.Popen[bytes],
        cancelled: Callable[[], bool],
    ) -> tuple[bytes, bytes, str | None]:
        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        chunks: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        total = 0
        start = time.monotonic()
        failure: str | None = None
        termination_started: float | None = None
        forced = False

        def terminate_group() -> None:
            nonlocal termination_started
            if termination_started is not None:
                return
            termination_started = time.monotonic()
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

        def force_group() -> None:
            nonlocal forced
            if forced:
                return
            forced = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            while selector.get_map():
                elapsed_ms = int((time.monotonic() - start) * 1000)
                if elapsed_ms >= self._policy.timeout_ms:
                    failure = "timeout"
                    terminate_group()
                elif cancelled():
                    failure = "cancelled-after-launch"
                    terminate_group()
                if (
                    termination_started is not None
                    and not forced
                    and (time.monotonic() - termination_started) * 1000
                    >= self._policy.termination_grace_ms
                ):
                    force_group()
                timeout = self._policy.poll_interval_ms / 1000
                for key, _ in selector.select(timeout):
                    chunk = os.read(key.fd, self._policy.read_chunk_bytes)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > self._policy.max_output_bytes:
                        failure = "output-bound"
                        terminate_group()
                    else:
                        chunks[key.data].append(chunk)
                if failure is not None and forced and process.poll() is not None:
                    for key in tuple(selector.get_map().values()):
                        selector.unregister(key.fileobj)
            try:
                process.wait(timeout=self._policy.termination_force_wait_ms / 1000)
            except subprocess.TimeoutExpired:
                force_group()
                process.wait(timeout=self._policy.termination_force_wait_ms / 1000)
        finally:
            selector.close()
            if process.poll() is None:
                force_group()
                try:
                    process.wait(timeout=self._policy.termination_force_wait_ms / 1000)
                except subprocess.TimeoutExpired as error:
                    raise StructuredCommandRejection(
                        "command process group could not be reaped within policy bound"
                    ) from error
            process.stdout.close()
            process.stderr.close()
        return b"".join(chunks["stdout"]), b"".join(chunks["stderr"]), failure

    def execute(
        self,
        invocation_document: Mapping[str, object],
        *,
        expected: ActionInvocation,
        request_document: Mapping[str, object],
        cancelled: Callable[[], bool] = lambda: False,
    ) -> CommandExecutionResult:
        StructuredCommandLauncher.require_attested(self)
        if type(expected) is not ActionInvocation or not callable(cancelled):
            raise StructuredCommandRejection("structured command expected authority is missing")
        try:
            candidate = ActionInvocation.from_dict(invocation_document)
        except ValueError as error:
            raise StructuredCommandRejection("structured command invocation rejected") from error
        if candidate != expected:
            raise StructuredCommandRejection("structured command invocation binding changed")
        request = CommandExecutionRequest.from_dict(request_document)
        if (
            candidate.adapter_id != self._entry.adapter_id
            or candidate.operation_id != "project.run"
            or candidate.idempotency_class != self._entry.idempotency_class
            or not hmac.compare_digest(
                candidate.payload_digest, ActionInvocation.payload_digest_for(request_document)
            )
            or request.command_id != self._entry.command_id
            or tuple(sorted(request.parameters)) != self._entry.parameter_order
            or len(request.parameters) > self._policy.max_parameters
        ):
            raise StructuredCommandRejection("structured command request is not exactly authorized")
        for name in self._entry.parameter_order:
            value = request.parameters[name]
            if (
                len(value.encode("utf-8")) > self._policy.max_parameter_bytes
                or value not in self._entry.parameter_values[name]
            ):
                raise StructuredCommandRejection("structured command parameter is not allowed")
        expected_references = tuple(
            sorted((_reference_key(reference) for reference in self._entry.secret_environment.values()))
        )
        actual_references = tuple(_reference_key(reference) for reference in request.secret_references)
        if actual_references != expected_references:
            raise StructuredCommandRejection("structured command secret reference closure changed")
        self._verify_locations()
        if cancelled():
            return self._failure(
                request,
                candidate,
                "cancelled-before-launch",
                outcome="cancelled",
                reconciliation_required=False,
            )
        permit = _SecretResolutionPermit(self._provider)
        materials: list[SecretMaterial] = []
        try:
            material_by_key: dict[tuple[str, str, str], SecretMaterial] = {}
            for reference in request.secret_references:
                material = self._provider._resolve(reference, permit)
                materials.append(material)
                material_by_key[_reference_key(reference)] = material
            environment = dict(self._entry.static_environment)
            for name, reference in self._entry.secret_environment.items():
                try:
                    value = material_by_key[_reference_key(reference)].reveal().decode("utf-8", errors="strict")
                except (KeyError, UnicodeError) as error:
                    raise StructuredCommandRejection("secret cannot be injected into structured environment") from error
                if not value or "\x00" in value:
                    raise StructuredCommandRejection("secret cannot be injected into structured environment")
                environment[name] = value
            arguments = (
                self._entry.executable,
                *self._entry.argv_prefix,
                *(request.parameters[name] for name in self._entry.parameter_order),
            )
            self._launch_count += 1
            process = subprocess.Popen(
                arguments,
                cwd=self._cwd_path,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )
            stdout, stderr, failure = self._collect(process, cancelled)
            self._verify_locations()
            variants = _secret_variants(tuple(materials), self._policy.secret_encodings)
            if any(variant and (variant in stdout or variant in stderr) for variant in variants):
                return self._failure(request, candidate, "secret-leakage")
            if failure is not None:
                return self._failure(request, candidate, failure)
            try:
                decoded = stdout.decode("utf-8", errors="strict")
                error_text = stderr.decode("utf-8", errors="strict")
                output = json.loads(decoded)
            except (UnicodeError, json.JSONDecodeError):
                return self._failure(request, candidate, "malformed-output")
            if (
                type(output) is not dict
                or any(type(key) is not str or key not in self._policy.output_field_allowlist for key in output)
                or any(type(value) not in (str, bool, int) for value in output.values())
                or error_text
            ):
                return self._failure(request, candidate, "malformed-output")
            if _semantic_contains_secret(output, variants):
                return self._failure(request, candidate, "secret-leakage")
            if process.returncode != 0:
                return self._failure(request, candidate, "nonzero-exit")
            return CommandExecutionResult.create(
                request=request,
                invocation=candidate,
                outcome="succeeded",
                failure_class=None,
                reconciliation_required=False,
                exit_code=process.returncode,
                output=output,
            )
        finally:
            permit.live = False
            for material in materials:
                material.destroy()

    def close(self) -> None:
        for attribute in ("_cwd_descriptor", "_root_descriptor", "_executable_descriptor"):
            descriptor = getattr(self, attribute, -1)
            if type(descriptor) is int and descriptor >= 0:
                setattr(self, attribute, -1)
                os.close(descriptor)

    def __del__(self) -> None:
        for attribute in ("_cwd_descriptor", "_root_descriptor", "_executable_descriptor"):
            descriptor = getattr(self, attribute, -1)
            if type(descriptor) is int and descriptor >= 0:
                setattr(self, attribute, -1)
                try:
                    os.close(descriptor)
                except OSError:
                    pass
