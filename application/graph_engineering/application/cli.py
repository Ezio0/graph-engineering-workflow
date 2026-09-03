"""Command-line entry point for the installed distribution."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from graph_engineering.adapters.runtime_config import (
    ConfiguredRuntimeHandshake,
    load_runtime_configuration,
    load_runtime_resource_guard,
)
from graph_engineering.adapters.runtime_locator import ExecutableLocator, RunningDistributionProbe
from graph_engineering.core.runtime import (
    RuntimeCompatibilityRequest,
    SkillHandshakeRequest,
    runtime_record_digest,
)
from graph_engineering.core.version import installed_version
from graph_engineering.application.owner_turns import OwnerTurnRequest
from graph_engineering.adapters.owner_turn_local import LocalOwnerTurnRuntime

__all__ = ["installed_version", "main"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="graph-engineering")
    subcommands = parser.add_subparsers(dest="command")
    capabilities = subcommands.add_parser("capabilities")
    capabilities.add_argument("--format", choices=("json",), required=True)
    capabilities.add_argument("--locator", type=pathlib.Path, required=True)
    capabilities.add_argument("--runtime-config", type=pathlib.Path, required=True)
    capabilities.add_argument("--runtime-resource-policy", type=pathlib.Path, required=True)
    capabilities.add_argument("--resource-profile", type=pathlib.Path, required=True)
    capabilities.add_argument("--cost-schedule", type=pathlib.Path, required=True)
    capabilities.add_argument("--skill-request", type=pathlib.Path, required=True)
    owner = subcommands.add_parser("owner-flow")
    owner.add_argument("--format", choices=("json",), required=True)
    for name in (
        "locator", "runtime-config", "runtime-resource-policy", "resource-profile",
        "cost-schedule", "skill-request", "runtime-input", "repository-policy",
        "migration-policy", "runtime-port-policy", "schema-profile", "schema-manifest", "schema-root",
        "repository-root", "control-root", "request",
    ):
        owner.add_argument(f"--{name}", type=pathlib.Path, required=True)
    return parser


def _compatibility(configuration: dict[str, object]) -> RuntimeCompatibilityRequest:
    request_body = {
        "schema_version": configuration["schema_version"],
        "runtime_kind": configuration["runtime_kind"],
        "runtime_version": configuration["runtime_version"],
        "adapter_version": configuration["adapter_version"],
        "skill_id": configuration["skill_id"],
        "skill_version": configuration["skill_version"],
        "protocol_version": configuration["protocol_version"],
        "release_manifest_digest": configuration["release_manifest_digest"],
        "core_version": configuration["core_version"],
        "repository_contract_version": configuration["repository_contract_version"],
        "repository_bundle_version": configuration["repository_bundle_version"],
        "schema_registry_digest": configuration["schema_registry_digest"],
        "graph_contract_version": configuration["graph_contract_version"],
        "profile_contract_version": configuration["profile_contract_version"],
        "overlay_contract_version": configuration["overlay_contract_version"],
        "action_protocol_version": configuration["action_protocol_version"],
        "required_capabilities": configuration["capabilities"],
    }
    return RuntimeCompatibilityRequest.from_dict({
        **request_body,
        "request_digest": runtime_record_digest("compatibility-request", request_body),
    })


def _owner_rejection() -> int:
    body = {"schema_version": "1.0", "status": "rejected", "exit_code": 4}
    print(json.dumps({
        **body, "result_digest": runtime_record_digest("owner-turn-rejection", body),
    }, sort_keys=True, separators=(",", ":")))
    return 4


def main(argv: list[str] | None = None) -> int:
    """Run the stable, daemon-free installed command-line surface."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--version"]:
        print(installed_version())
        return 0
    parsed = _parser().parse_args(arguments)
    if parsed.command == "capabilities":
        guard = load_runtime_resource_guard(
            parsed.runtime_resource_policy, parsed.resource_profile, parsed.cost_schedule,
        )
        running = RunningDistributionProbe().probe("graph-engineering-workflow")
        executable = ExecutableLocator(guard, running).resolve(parsed.locator)
        configuration = load_runtime_configuration(parsed.runtime_config, guard)
        skill_request_document = load_runtime_configuration(parsed.skill_request, guard)
        if not isinstance(configuration, dict):
            raise ValueError("runtime configuration is not an object")
        adapter = ConfiguredRuntimeHandshake.from_dict(configuration, executable, guard)
        skill_request = SkillHandshakeRequest.from_dict(skill_request_document)
        adapter.verify_skill_request(skill_request)
        request = _compatibility(configuration)
        result = adapter.discover_capabilities(request)
        print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    elif parsed.command == "owner-flow":
        try:
            guard = load_runtime_resource_guard(
                parsed.runtime_resource_policy, parsed.resource_profile, parsed.cost_schedule,
            )
            running = RunningDistributionProbe().probe("graph-engineering-workflow")
            executable = ExecutableLocator(guard, running).resolve(parsed.locator)
            configuration = load_runtime_configuration(parsed.runtime_config, guard)
            skill_document = load_runtime_configuration(parsed.skill_request, guard)
            raw_input = load_runtime_configuration(parsed.runtime_input, guard)
            request_document = load_runtime_configuration(parsed.request, guard)
            local_port_policy = load_runtime_configuration(parsed.runtime_port_policy, guard)
            if not all(isinstance(item, dict) for item in (
                configuration, skill_document, raw_input, request_document, local_port_policy,
            )):
                raise ValueError("owner-flow input is not an object")
            handshake = ConfiguredRuntimeHandshake.from_dict(configuration, executable, guard)
            handshake.verify_skill_request(SkillHandshakeRequest.from_dict(skill_document))
            request = OwnerTurnRequest.from_dict(request_document)
            owner = handshake.resolve_owner(raw_input)
            lineage = handshake.resolve_lineage(raw_input)
            request.require_binding(owner.owner_id, lineage.runtime_kind, lineage.lineage_id)
            with LocalOwnerTurnRuntime(
                configuration=configuration, executable=executable, guard=guard,
                compatibility=_compatibility(configuration), raw_input=raw_input,
                repository_root=parsed.repository_root, control_root=parsed.control_root,
                repository_policy_path=parsed.repository_policy,
                migration_policy_path=parsed.migration_policy,
                local_port_policy=local_port_policy,
                schema_profile_path=parsed.schema_profile,
                schema_manifest_path=parsed.schema_manifest,
                schema_root=parsed.schema_root,
            ) as runtime:
                result = runtime.application.execute(request)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return int(result["exit_code"])
        except Exception:
            return _owner_rejection()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
