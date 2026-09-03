from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.application.runtime import (  # noqa: E402
    RuntimeMutationGateway,
    RuntimeSession,
    RuntimeSessionError,
)
from graph_engineering.core.runtime import (  # noqa: E402
    AgentRequest,
    AgentResult,
    CapabilitySet,
    DeliveryPresentation,
    HumanDecision,
    HumanDecisionRequest,
    OwnerIdentity,
    ReviewerRequest,
    ReviewerResult,
    RuntimeCompatibilityRequest,
    RuntimeContractError,
    RuntimeIdentity,
    RuntimeLineage,
    ToolRequest,
    ToolResult,
    runtime_record_digest,
)
from graph_engineering.adapters.runtime_locator import (  # noqa: E402
    ExecutableLocator,
    ExecutableLocatorError,
)
from tests.support.runtime_adapter_authority import attest_test_adapter  # noqa: E402
from tests.support.runtime_resources import runtime_resource_guard  # noqa: E402
from tests.support.runtime_distribution import running_distribution  # noqa: E402


DIGEST = "sha256-jcs-v1:" + "1" * 64
RAW_DIGEST = "sha256-raw-v1:" + "2" * 64


def signed(kind: str, field: str, body: dict[str, object]) -> dict[str, object]:
    return {**body, field: runtime_record_digest(kind, body)}


def runtime_identity(kind: str = "codex") -> RuntimeIdentity:
    body = {
        "schema_version": "1.0",
        "runtime_kind": kind,
        "adapter_id": f"adapter:{kind}:fixture-v1",
        "adapter_version": "1.0.0",
        "runtime_version": "fixture-1.0.0",
        "protocol_version": "1.0.0",
        "runtime_instance_id": f"runtime:{kind}:fixture",
    }
    return RuntimeIdentity.from_dict(signed("identity", "identity_digest", body))


def owner(owner_id: str = "owner-fixture") -> OwnerIdentity:
    body = {
        "schema_version": "1.0", "owner_id": owner_id,
        "runtime_kind": "codex", "runtime_instance_id": "runtime:codex:fixture",
        "identity_source_ref": "fixture:owner-proof",
    }
    return OwnerIdentity.from_dict(signed("owner-identity", "proof_digest", body))


def lineage(kind: str = "codex", value: str = "lineage-fixture") -> RuntimeLineage:
    body = {
        "schema_version": "1.0", "runtime_kind": kind,
        "runtime_instance_id": f"runtime:{kind}:fixture", "session_id": "session-fixture",
        "channel_kind": "native" if kind == "codex" else "telegram",
        "channel_ref": "channel-fixture", "thread_ref": "thread-fixture",
        "owner_id": "owner-fixture", "identity_source_ref": "fixture:owner-proof",
        "lineage_id": value,
    }
    return RuntimeLineage.from_dict(signed("lineage", "proof_digest", body))


def request(kind: str = "codex") -> RuntimeCompatibilityRequest:
    body = {
        "schema_version": "1.0", "runtime_kind": kind,
        "runtime_version": "fixture-1.0.0", "adapter_version": "1.0.0",
        "skill_id": f"skill:{kind}:graph-engineering", "skill_version": "1.0.0",
        "protocol_version": "1.0.0",
        "release_manifest_digest": DIGEST, "core_version": "0.1.0",
        "repository_contract_version": "1.0.0", "repository_bundle_version": "1.0.0",
        "schema_registry_digest": DIGEST, "graph_contract_version": "1.0.0",
        "profile_contract_version": "1.0.0", "overlay_contract_version": "1.0.0",
        "action_protocol_version": "1.0.0",
        "required_capabilities": [
            "agent.invoke", "human.request", "presentation.deliver", "reviewer.invoke",
        ],
    }
    return RuntimeCompatibilityRequest.from_dict(
        signed("compatibility-request", "request_digest", body)
    )


def capabilities(kind: str = "codex") -> CapabilitySet:
    body = {
        "schema_version": "1.0", "release_id": "release:fixture-v1",
        "release_manifest_digest": DIGEST, "core_version": "0.1.0",
        "cli_protocol_version": "1.0.0", "runtime_kind": kind,
        "adapter_id": f"adapter:{kind}:fixture-v1", "adapter_version": "1.0.0",
        "skill_id": f"skill:{kind}:graph-engineering", "skill_version": "1.0.0",
        "repository_contract_version": "1.0.0", "repository_bundle_version": "1.0.0",
        "schema_registry_digest": DIGEST, "graph_contract_version": "1.0.0",
        "profile_contract_version": "1.0.0", "overlay_contract_version": "1.0.0",
        "action_protocol_version": "1.0.0",
        "capabilities": [
            "agent.invoke", "human.request", "presentation.deliver", "reviewer.invoke",
            "tool.invoke",
        ],
        "canonical_executable": "/fixture/graph-engineering",
        "package_origin": "/fixture/tool-environment",
        "data_root_ref": "data-root:fixture", "compatibility": "compatible",
    }
    return CapabilitySet.from_dict(signed("capabilities", "capability_digest", body))


class FixtureAdapter:
    def identity(self):
        return runtime_identity()

    def resolve_owner(self, raw_input):
        return owner(raw_input["owner_id"])

    def resolve_lineage(self, raw_input):
        return lineage(value=raw_input["lineage_id"])

    def discover_capabilities(self, compatibility_request):
        del compatibility_request
        return capabilities()

    def invoke_agent(self, runtime_request):
        body = {
            "schema_version": "1.0", "request_id": runtime_request.request_id,
            "task_id": runtime_request.task_id, "status": "succeeded",
            "candidate_ref": "candidate:fixture",
        }
        return AgentResult.from_dict(signed("agent-result", "result_digest", body))

    def invoke_reviewer(self, runtime_request, independence):
        del independence
        body = {
            "schema_version": "1.0", "request_id": runtime_request.request_id,
            "task_id": runtime_request.task_id, "reviewer_id": "reviewer-fixture",
            "verdict": "PASS", "finding_refs": [],
        }
        return ReviewerResult.from_dict(signed("reviewer-result", "result_digest", body))

    def invoke_tool(self, runtime_request):
        body = {
            "schema_version": "1.0", "request_id": runtime_request.request_id,
            "task_id": runtime_request.task_id, "status": "succeeded",
            "receipt_ref": "receipt:fixture",
        }
        return ToolResult.from_dict(signed("tool-result", "result_digest", body))

    def request_human(self, decision_request):
        body = {
            "schema_version": "1.0", "request_id": decision_request.request_id,
            "task_id": decision_request.task_id, "owner_id": "owner-fixture",
            "status": "approved",
            "decision_ref": "decision:fixture",
        }
        return HumanDecision.from_dict(signed("human-decision", "decision_digest", body))

    def present(self, presentation):
        return presentation.receipt(("delivery:fixture:1",))


def fixture_adapter(adapter_type=FixtureAdapter):
    return attest_test_adapter(adapter_type())


class WP07RuntimeContractTests(unittest.TestCase):
    def test_gew_rt_001_runtime_identity_is_exact_immutable_and_digest_bound(self) -> None:
        identity = runtime_identity()
        self.assertEqual((identity.runtime_kind, identity.adapter_version), ("codex", "1.0.0"))
        with self.assertRaises((AttributeError, TypeError)):
            identity.runtime_kind = "hermes"  # type: ignore[misc]
        value = identity.to_dict()
        value["extra"] = True
        with self.assertRaisesRegex(RuntimeContractError, "exact"):
            RuntimeIdentity.from_dict(value)

    def test_gew_rt_002_owner_and_lineage_proofs_bind_one_runtime_instance(self) -> None:
        self.assertEqual(owner().runtime_instance_id, lineage().runtime_instance_id)
        mismatched = owner().to_dict()
        mismatched["runtime_instance_id"] = "runtime:codex:other"
        mismatched["proof_digest"] = runtime_record_digest(
            "owner-identity", {key: value for key, value in mismatched.items() if key != "proof_digest"},
        )
        session = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        with self.assertRaisesRegex(RuntimeSessionError, "runtime instance"):
            session.require_owner_lineage(OwnerIdentity.from_dict(mismatched), lineage())

    def test_gew_rt_003_capability_handshake_is_exact_and_compatible(self) -> None:
        session = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        self.assertEqual(session.capabilities.compatibility, "compatible")
        self.assertEqual(RuntimeMutationGateway.invoke(
            session, session.proof, lambda runtime: runtime.runtime_kind,
            occurred_at="2026-08-15T00:00:00Z", lease_ttl_ns=100,
        ), "codex")

    def test_gew_rt_004_capability_missing_or_version_mismatch_rejects_session(self) -> None:
        for field, value in (
            ("capabilities", ["agent.invoke"]),
            ("adapter_version", "2.0.0"),
            ("schema_registry_digest", "sha256-jcs-v1:" + "9" * 64),
            ("repository_contract_version", "2.0.0"),
            ("action_protocol_version", "2.0.0"),
            ("compatibility", "incompatible"),
        ):
            class Changed(FixtureAdapter):
                def discover_capabilities(self, compatibility_request):
                    del compatibility_request
                    document = capabilities().to_dict()
                    document[field] = value
                    document["capability_digest"] = runtime_record_digest(
                        "capabilities", {
                            key: item for key, item in document.items() if key != "capability_digest"
                        },
                    )
                    return CapabilitySet.from_dict(document)

            with self.subTest(field=field), self.assertRaisesRegex(
                RuntimeSessionError, "compatib|capabil|version",
            ):
                RuntimeSession.establish(
                    fixture_adapter(Changed), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
                    request(),
                )

    def test_gew_rt_005_runtime_adapter_protocol_requires_every_port(self) -> None:
        session = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        self.assertEqual(session.capabilities.adapter_id, "adapter:codex:fixture-v1")
        with self.assertRaisesRegex(RuntimeSessionError, "adapter contract|factory-attested"):
            RuntimeSession.establish(
                object(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
                request(),
            )

    def test_gew_rt_006_agent_and_reviewer_results_are_request_and_identity_bound(self) -> None:
        active = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        agent_body = {
            "schema_version": "1.0", "request_id": "agent-request-1", "task_id": "task-1",
            "run_id": "run-1", "node_id": "node-1", "input_ref": "input:1",
            "input_digest": DIGEST,
        }
        agent = AgentRequest.from_dict(signed("agent-request", "request_digest", agent_body))
        reviewer_body = {
            "schema_version": "1.0", "request_id": "review-request-1", "task_id": "task-1",
            "run_id": "run-1", "candidate_ref": "candidate:fixture",
            "candidate_digest": DIGEST, "author_id": "author-fixture",
        }
        reviewer = ReviewerRequest.from_dict(
            signed("reviewer-request", "request_digest", reviewer_body)
        )
        self.assertEqual(active.invoke_agent(agent).request_id, agent.request_id)
        result = active.invoke_reviewer(reviewer, None)
        self.assertNotEqual(result.reviewer_id.casefold(), reviewer.author_id.casefold())

    def test_gew_rt_007_tool_and_human_ports_preserve_prepared_refs_and_pending(self) -> None:
        tool_body = {
            "schema_version": "1.0", "request_id": "tool-request-1", "task_id": "task-1",
            "prepared_action_ref": "prepared:1", "prepared_action_digest": DIGEST,
        }
        tool = ToolRequest.from_dict(signed("tool-request", "request_digest", tool_body))
        decision_body = {
            "schema_version": "1.0", "request_id": "human-request-1", "task_id": "task-1",
            "owner_id": "owner-fixture", "decision_kind": "prd-approval",
            "decision_payload_ref": "decision-payload:1", "decision_payload_digest": DIGEST,
        }
        decision = HumanDecisionRequest.from_dict(
            signed("human-decision-request", "request_digest", decision_body)
        )
        active = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        self.assertEqual(active.invoke_tool(tool).request_id, tool.request_id)
        self.assertEqual(active.request_human(decision).owner_id, "owner-fixture")

    def test_gew_rt_008_presentation_segments_bind_one_delivery_receipt(self) -> None:
        body = {
            "schema_version": "1.0", "presentation_id": "presentation-1", "task_id": "task-1",
            "kind": "result", "segments": ["first", "second"], "content_digest": DIGEST,
        }
        presentation = DeliveryPresentation.from_dict(
            signed("delivery-presentation", "presentation_digest", body)
        )
        receipt = FixtureAdapter().present(presentation)
        self.assertEqual(receipt.presentation_id, presentation.presentation_id)
        self.assertEqual(receipt.delivery_refs, ("delivery:fixture:1",))

    def test_gew_rt_009_canonical_executable_locator_rejects_symlink_mode_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            executable = root / "graph-engineering"
            executable.write_bytes(b"#!/bin/sh\nexit 0\n")
            executable.chmod(0o700)
            origin = root
            locator = root / "locator.json"
            locator.write_text(json.dumps({
                "schema_version": "1.0", "executable": str(executable.resolve()),
                "package_origin": str(origin.resolve()), "executable_digest": RAW_DIGEST,
                "release_manifest_digest": DIGEST, "expected_core_version": "0.1.0",
                "distribution_name": "graph-engineering-workflow",
                "distribution_version": "0.1.0",
                "distribution_origin": str(origin.resolve()),
            }))
            actual = "sha256-raw-v1:" + __import__("hashlib").sha256(executable.read_bytes()).hexdigest()
            document = json.loads(locator.read_text())
            document["executable_digest"] = actual
            locator.write_text(json.dumps(document))
            locator.chmod(0o600)
            running = running_distribution(
                str(executable.resolve()), str(origin.resolve()), str(origin.resolve())
            )
            resolved = ExecutableLocator(runtime_resource_guard(), running).resolve(locator)
            self.assertEqual(resolved.executable, str(executable.resolve()))
            linked = root / "linked-locator.json"
            os.symlink(locator, linked)
            with self.assertRaisesRegex(ExecutableLocatorError, "symlink"):
                ExecutableLocator(runtime_resource_guard(), running).resolve(linked)
            locator.chmod(0o644)
            with self.assertRaisesRegex(ExecutableLocatorError, "mode"):
                ExecutableLocator(runtime_resource_guard(), running).resolve(locator)

    def test_gew_rt_010_session_rejects_cross_runtime_owner_or_lineage(self) -> None:
        session = RuntimeSession.establish(
            fixture_adapter(), {"owner_id": "owner-fixture", "lineage_id": "lineage-fixture"},
            request(),
        )
        with self.assertRaisesRegex(RuntimeSessionError, "runtime|owner|lineage"):
            session.require_owner_lineage(owner("owner-other"), lineage())
        with self.assertRaisesRegex(RuntimeSessionError, "runtime|owner|lineage"):
            session.require_owner_lineage(owner(), lineage(value="lineage-other"))


if __name__ == "__main__":
    unittest.main()
