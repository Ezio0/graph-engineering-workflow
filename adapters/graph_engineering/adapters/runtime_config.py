"""Production runtime identity, lineage, capability, and configuration boundary."""

from __future__ import annotations

import json
import os
import pathlib
import stat
from collections.abc import Mapping

from graph_engineering.adapters.runtime_locator import VerifiedExecutable
from graph_engineering.core.runtime import (
    CapabilitySet,
    OwnerIdentity,
    RuntimeCompatibilityRequest,
    RuntimeIdentity,
    RuntimeLineage,
    RuntimeResourceGuard,
    RuntimeResourcePolicy,
    SkillHandshakeRequest,
    runtime_record_digest,
)
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext


class RuntimeAdapterRejection(RuntimeError):
    """Non-disclosing rejection at the configured runtime boundary."""


CONFIGURATION_FIELDS = frozenset({
    "schema_version", "cell_id", "runtime_kind", "adapter_id", "adapter_version",
    "runtime_version", "protocol_version", "runtime_instance_id", "skill_id",
    "skill_version", "release_id", "release_manifest_digest", "core_version",
    "repository_contract_version", "repository_bundle_version", "schema_registry_digest",
    "graph_contract_version", "profile_contract_version", "overlay_contract_version",
    "action_protocol_version", "data_root_ref", "capabilities", "channel_kind",
    "owner_bindings", "allowed_channels",
    "runtime_resource_policy_digest",
    "runtime_local_port_policy_digest",
    "configuration_digest",
})
RUNTIME_INPUT_FIELDS = frozenset({
    "user_id", "channel_kind", "channel_ref", "thread_ref", "session_id",
})
CAPABILITY_FIELDS = frozenset({
    "schema_version", "release_id", "release_manifest_digest", "core_version",
    "cli_protocol_version", "runtime_kind", "adapter_id", "adapter_version", "skill_id",
    "skill_version", "repository_contract_version", "repository_bundle_version",
    "schema_registry_digest", "graph_contract_version", "profile_contract_version",
    "overlay_contract_version", "action_protocol_version", "capabilities",
    "canonical_executable", "package_origin", "data_root_ref", "compatibility",
    "capability_digest",
})
def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or "\x00" in value:
        raise RuntimeAdapterRejection(f"runtime adapter {label} is invalid")
    return value


def load_runtime_configuration(path: pathlib.Path, guard: RuntimeResourceGuard) -> object:
    """Read one owner-only bounded configuration without following a final symlink."""

    location = pathlib.Path(path)
    if location.is_symlink():
        raise RuntimeAdapterRejection("runtime configuration symlink is forbidden")
    if not location.is_absolute() or str(location.resolve(strict=True)) != str(location):
        raise RuntimeAdapterRejection("runtime configuration path is not absolute and canonical")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(location, flags)
    except OSError as error:
        raise RuntimeAdapterRejection("runtime configuration cannot be opened safely") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_uid != os.geteuid() or before.st_mode & 0o077
        ):
            raise RuntimeAdapterRejection("runtime configuration owner or mode is unsafe")
        try:
            guard.validate_bytes(before.st_size, source_id="runtime-configuration")
        except Exception as error:
            raise RuntimeAdapterRejection("runtime configuration exceeds the bounded policy") from error
        payload = os.read(descriptor, guard.policy.max_record_bytes + 1)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ):
            raise RuntimeAdapterRejection("runtime configuration changed during verification")
    finally:
        os.close(descriptor)
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeAdapterRejection("runtime configuration is not valid JSON") from error


def load_runtime_resource_guard(
    policy_path: pathlib.Path,
    profile_path: pathlib.Path,
    schedule_path: pathlib.Path,
) -> RuntimeResourceGuard:
    """Load the configured ADR-0003 roots and their runtime-specific bound policy."""

    try:
        profile = ResourceProfile.from_dict(json.loads(profile_path.read_bytes()))
        schedule = CostSchedule.from_dict(json.loads(schedule_path.read_bytes()))
        policy_document = json.loads(policy_path.read_bytes())
        policy = RuntimeResourcePolicy.from_dict(policy_document)
        guard = RuntimeResourceGuard(policy, WorkContext(profile, schedule))
        guard.validate(policy_document, source_id="runtime-resource-policy")
        guard.validate(profile.to_dict(), source_id="runtime-resource-profile")
        guard.validate(schedule.to_dict(), source_id="runtime-cost-schedule")
        return guard
    except Exception as error:
        raise RuntimeAdapterRejection("runtime resource configuration is invalid") from error


class ConfiguredRuntimeHandshake:
    """Validated production boundary without deterministic invocation behavior."""

    __slots__ = ("_config", "_executable", "_guard")

    def __init__(
        self, config: dict[str, object], executable: VerifiedExecutable,
        guard: RuntimeResourceGuard,
    ) -> None:
        self._config = config
        self._executable = executable
        self._guard = guard

    @classmethod
    def from_dict(
        cls, value: object, executable: VerifiedExecutable, guard: RuntimeResourceGuard,
    ) -> ConfiguredRuntimeHandshake:
        if type(guard) is not RuntimeResourceGuard:
            raise RuntimeAdapterRejection("runtime resource guard is missing or forged")
        try:
            value = guard.validate(value, source_id="runtime-configuration-record")
        except Exception as error:
            raise RuntimeAdapterRejection("runtime configuration exceeds the bounded policy") from error
        if not isinstance(value, Mapping) or set(value) != CONFIGURATION_FIELDS:
            raise RuntimeAdapterRejection("runtime adapter configuration is not exact")
        if type(executable) is not VerifiedExecutable:
            raise RuntimeAdapterRejection("verified executable binding is missing")
        try:
            executable.require_verified()
        except Exception as error:
            raise RuntimeAdapterRejection("verified executable binding is missing or forged") from error
        config = dict(value)
        expected_configuration_digest = config.get("configuration_digest")
        actual_configuration_digest = runtime_record_digest(
            "runtime-configuration",
            {key: item for key, item in config.items() if key != "configuration_digest"},
        )
        if expected_configuration_digest != actual_configuration_digest:
            raise RuntimeAdapterRejection("runtime configuration digest is invalid")
        for field in CONFIGURATION_FIELDS - {"owner_bindings", "allowed_channels", "capabilities"}:
            _text(config[field], field)
        bindings = config["owner_bindings"]
        if not isinstance(bindings, Mapping) or not bindings:
            raise RuntimeAdapterRejection("runtime adapter owner bindings are invalid")
        canonical_bindings = {
            _text(key, "user ID"): _text(owner, "owner ID") for key, owner in bindings.items()
        }
        if len(set(canonical_bindings.values())) != len(canonical_bindings):
            raise RuntimeAdapterRejection("runtime owner pairing must be one-to-one without aliases")
        allowed = config["allowed_channels"]
        capabilities = config["capabilities"]
        if (
            not isinstance(allowed, list) or not allowed or allowed != sorted(set(allowed))
            or not isinstance(capabilities, list) or not capabilities
            or capabilities != sorted(set(capabilities))
        ):
            raise RuntimeAdapterRejection("runtime adapter channels or capabilities are not canonical")
        config["owner_bindings"] = canonical_bindings
        config["allowed_channels"] = tuple(_text(item, "channel ref") for item in allowed)
        config["capabilities"] = tuple(_text(item, "capability") for item in capabilities)
        if (
            config["release_manifest_digest"] != executable.release_manifest_digest
            or config["core_version"] != executable.expected_core_version
            or config["runtime_resource_policy_digest"] != guard.policy.policy_digest
        ):
            raise RuntimeAdapterRejection(
                "runtime locator release, core, or resource policy binding is incompatible"
            )
        return cls(config, executable, guard)

    def verify_skill_request(self, request: SkillHandshakeRequest) -> None:
        if type(request) is not SkillHandshakeRequest:
            raise RuntimeAdapterRejection("independent Skill handshake request is missing")
        expected = (
            self._config["skill_id"], self._config["skill_version"],
            self._config["protocol_version"], self._config["runtime_kind"],
            self._config["configuration_digest"],
        )
        actual = (
            request.skill_id, request.skill_version, request.protocol_version,
            request.runtime_kind, request.runtime_configuration_digest,
        )
        if actual != expected:
            raise RuntimeAdapterRejection("independent Skill handshake is incompatible")

    def identity(self) -> RuntimeIdentity:
        body = {
            "schema_version": self._config["schema_version"],
            "runtime_kind": self._config["runtime_kind"],
            "adapter_id": self._config["adapter_id"],
            "adapter_version": self._config["adapter_version"],
            "runtime_version": self._config["runtime_version"],
            "protocol_version": self._config["protocol_version"],
            "runtime_instance_id": self._config["runtime_instance_id"],
        }
        return RuntimeIdentity.from_dict({
            **body, "identity_digest": runtime_record_digest("identity", body),
        })

    def _input(self, raw_input: Mapping[str, object]) -> dict[str, str]:
        try:
            raw_input = self._guard.validate(raw_input, source_id="runtime-owner-input")  # type: ignore[assignment]
        except Exception as error:
            raise RuntimeAdapterRejection("runtime input is not authorized") from error
        if not isinstance(raw_input, Mapping) or set(raw_input) != RUNTIME_INPUT_FIELDS:
            raise RuntimeAdapterRejection("runtime input is not authorized")
        record = {key: _text(raw_input[key], key) for key in RUNTIME_INPUT_FIELDS}
        if (
            record["channel_kind"] != self._config["channel_kind"]
            or record["channel_ref"] not in self._config["allowed_channels"]
            or record["user_id"] not in self._config["owner_bindings"]
        ):
            raise RuntimeAdapterRejection("runtime input is not authorized")
        return record

    def resolve_owner(self, raw_input: Mapping[str, object]) -> OwnerIdentity:
        record = self._input(raw_input)
        body = {
            "schema_version": "1.0",
            "owner_id": self._config["owner_bindings"][record["user_id"]],
            "runtime_kind": self._config["runtime_kind"],
            "runtime_instance_id": self._config["runtime_instance_id"],
            "identity_source_ref": f"pairing:{self._config['cell_id']}:{record['user_id']}",
        }
        return OwnerIdentity.from_dict({
            **body, "proof_digest": runtime_record_digest("owner-identity", body),
        })

    def resolve_lineage(self, raw_input: Mapping[str, object]) -> RuntimeLineage:
        record = self._input(raw_input)
        body = {
            "schema_version": "1.0", "runtime_kind": self._config["runtime_kind"],
            "runtime_instance_id": self._config["runtime_instance_id"],
            "session_id": record["session_id"], "channel_kind": record["channel_kind"],
            "channel_ref": record["channel_ref"], "thread_ref": record["thread_ref"],
            "owner_id": self._config["owner_bindings"][record["user_id"]],
            "identity_source_ref": f"pairing:{self._config['cell_id']}:{record['user_id']}",
            "lineage_id": (
                f"lineage:{self._config['cell_id']}:{record['user_id']}:"
                f"{record['channel_ref']}:{record['thread_ref']}"
            ),
        }
        return RuntimeLineage.from_dict({
            **body, "proof_digest": runtime_record_digest("lineage", body),
        })

    def discover_capabilities(self, request: RuntimeCompatibilityRequest) -> CapabilitySet:
        del request
        body = {
            "schema_version": self._config["schema_version"],
            "release_id": self._config["release_id"],
            "release_manifest_digest": self._config["release_manifest_digest"],
            "core_version": self._config["core_version"],
            "cli_protocol_version": self._config["protocol_version"],
            "runtime_kind": self._config["runtime_kind"], "adapter_id": self._config["adapter_id"],
            "adapter_version": self._config["adapter_version"], "skill_id": self._config["skill_id"],
            "skill_version": self._config["skill_version"],
            "repository_contract_version": self._config["repository_contract_version"],
            "repository_bundle_version": self._config["repository_bundle_version"],
            "schema_registry_digest": self._config["schema_registry_digest"],
            "graph_contract_version": self._config["graph_contract_version"],
            "profile_contract_version": self._config["profile_contract_version"],
            "overlay_contract_version": self._config["overlay_contract_version"],
            "action_protocol_version": self._config["action_protocol_version"],
            "capabilities": self._config["capabilities"],
            "canonical_executable": self._executable.executable,
            "package_origin": self._executable.package_origin,
            "data_root_ref": self._config["data_root_ref"], "compatibility": "compatible",
        }
        return CapabilitySet.from_dict({
            **body, "capability_digest": runtime_record_digest("capabilities", body),
        })
