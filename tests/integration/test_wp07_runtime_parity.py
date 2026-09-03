from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from tests.support.wp07_runtime_adapter import (  # noqa: E402
    ConfiguredRuntimeAdapter,
    RuntimeAdapterRejection,
)
from graph_engineering.application.runtime import (  # noqa: E402
    RuntimeMutationGateway,
    RuntimeQueryGateway,
    RuntimeSession,
    RuntimeSessionError,
)
from graph_engineering.application.tasks import TaskApplication  # noqa: E402
from graph_engineering.core.graph.state import TaskCommand  # noqa: E402
from graph_engineering.core.runtime import (  # noqa: E402
    AgentRequest,
    DeliveryPresentation,
    HumanDecisionRequest,
    ReviewerRequest,
    RuntimeCompatibilityRequest,
    runtime_record_digest,
)
from graph_engineering.adapters.runtime_locator import VerifiedExecutable  # noqa: E402
from graph_engineering.adapters.runtime_adapters import (  # noqa: E402
    RuntimeAdapterFactory,
    RuntimeInvocationPorts,
)
from tests.integration.test_wp04_application import SCHEMAS, WORK  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.runtime_locator import verified_executable  # noqa: E402
from tests.support.runtime_adapter_authority import reviewer_attestation  # noqa: E402
from tests.support.runtime_resources import runtime_resource_guard  # noqa: E402


DIGEST = "sha256-jcs-v1:" + "1" * 64
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "wp07-runtime-adapters.json").read_text())


def signed(kind: str, field: str, body: dict[str, object]) -> dict[str, object]:
    return {**body, field: runtime_record_digest(kind, body)}


def adapter_document(cell: dict[str, object]) -> dict[str, object]:
    document = {**FIXTURE["shared"], **cell, "schema_version": FIXTURE["schema_version"]}
    document["configuration_digest"] = runtime_record_digest(
        "runtime-configuration", document
    )
    return document


def resign_configuration(document: dict[str, object]) -> dict[str, object]:
    document["configuration_digest"] = runtime_record_digest(
        "runtime-configuration",
        {key: value for key, value in document.items() if key != "configuration_digest"},
    )
    return document


def executable() -> VerifiedExecutable:
    return verified_executable(
        "/fixture/graph-engineering", "/fixture/tool-environment",
        "sha256-raw-v1:" + "2" * 64, DIGEST, "0.1.0",
    )


def raw_input(cell: dict[str, object], *, user: str | None = None) -> dict[str, object]:
    channel = cell["allowed_channels"][0]
    default_user = next(iter(cell["owner_bindings"]))
    return {
        "user_id": default_user if user is None else user,
        "channel_kind": cell["channel_kind"],
        "channel_ref": channel,
        "thread_ref": f"thread:{cell['cell_id']}",
        "session_id": f"session:{cell['cell_id']}",
    }


def compatibility(cell: dict[str, object]) -> RuntimeCompatibilityRequest:
    shared = FIXTURE["shared"]
    body = {
        "schema_version": "1.0",
        "runtime_kind": cell["runtime_kind"],
        "runtime_version": shared["runtime_version"],
        "adapter_version": shared["adapter_version"],
        "skill_id": cell["skill_id"],
        "skill_version": shared["skill_version"],
        "protocol_version": shared["protocol_version"],
        "release_manifest_digest": shared["release_manifest_digest"],
        "core_version": shared["core_version"],
        "repository_contract_version": shared["repository_contract_version"],
        "repository_bundle_version": shared["repository_bundle_version"],
        "schema_registry_digest": shared["schema_registry_digest"],
        "graph_contract_version": shared["graph_contract_version"],
        "profile_contract_version": shared["profile_contract_version"],
        "overlay_contract_version": shared["overlay_contract_version"],
        "action_protocol_version": shared["action_protocol_version"],
        "required_capabilities": [
            "agent.invoke", "human.request", "presentation.deliver", "reviewer.invoke",
        ],
    }
    return RuntimeCompatibilityRequest.from_dict(
        signed("compatibility-request", "request_digest", body)
    )


def production_adapter_for_test(cell: dict[str, object], document: dict[str, object] | None = None):
    configured = adapter_document(cell) if document is None else document
    fixture = ConfiguredRuntimeAdapter.from_dict(configured, executable())
    ports = RuntimeInvocationPorts(
        lambda task_id, owner, lineage: {
            "task_id": task_id, "owner_id": owner.owner_id,
            "runtime_kind": lineage.runtime_kind,
            "runtime_lineage_id": lineage.lineage_id,
        },
        lambda request, owner, lineage, capabilities: reviewer_attestation(
            request, owner, lineage, capabilities,
            reviewer_id=f"reviewer:{cell['adapter_id']}",
            source_ref=f"reviewer-source:{cell['cell_id']}",
        ),
        lambda value, _owner, _lineage: fixture.invoke_agent(value),
        lambda value, independence, _owner, _lineage: fixture.invoke_reviewer(
            value, {"author_id": independence["author_id"]}
        ),
        lambda value, _owner, _lineage: fixture.invoke_tool(value),
        lambda value, _owner, _lineage: fixture.request_human(value),
        lambda presentation, _owner, lineage: presentation.receipt(tuple(
            f"delivery:{lineage.channel_kind}:{lineage.channel_ref}:"
            f"{presentation.presentation_id}:{index}"
            for index, _segment in enumerate(presentation.segments, start=1)
        )),
    )
    factory = RuntimeAdapterFactory(runtime_resource_guard())
    adapter = (
        factory.codex(configured, executable(), ports)
        if cell["runtime_kind"] == "codex"
        else factory.hermes(configured, executable(), ports)
    )
    return adapter


def session(cell: dict[str, object]) -> RuntimeSession:
    return RuntimeSession.establish(
        production_adapter_for_test(cell), raw_input(cell), compatibility(cell)
    )


class WP07RuntimeParityTests(unittest.TestCase):
    def test_gew_rt_011_all_runtime_channel_cells_share_exact_handshake(self) -> None:
        for cell in FIXTURE["cells"]:
            with self.subTest(cell=cell["cell_id"]):
                active = session(cell)
                self.assertEqual(active.capabilities.runtime_kind, cell["runtime_kind"])
                self.assertEqual(active.capabilities.canonical_executable, executable().executable)

    def test_gew_rt_012_owner_pairing_allowlist_and_lineage_are_channel_exact(self) -> None:
        for cell in FIXTURE["cells"]:
            active = session(cell)
            with self.subTest(cell=cell["cell_id"]):
                self.assertIn(cell["cell_id"], active.proof.lineage_id)
                with self.assertRaisesRegex(RuntimeAdapterRejection, "not authorized"):
                    RuntimeSession.establish(
                        production_adapter_for_test(cell),
                        raw_input(cell, user="unauthorized-user"), compatibility(cell),
                    )

    def test_gew_rt_013_adapter_session_is_required_for_repository_create(self) -> None:
        cell = FIXTURE["cells"][0]
        active = session(cell)
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(repository, repository, leases, schema_registry=SCHEMAS, context=WORK)
            identity = {
                "task_id": "task-runtime-1", "owner_id": "owner-fixture",
                "runtime_kind": cell["runtime_kind"], "runtime_lineage_id": active.proof.lineage_id,
            }
            receipt = RuntimeMutationGateway.create(
                active, active.proof, identity,
                lambda runtime: application.execute(
                    "task-runtime-1", TaskCommand("create", 0, {"identity": identity}), runtime,
                ),
                occurred_at="2026-08-15T00:00:00Z", lease_ttl_ns=100,
            )
            self.assertEqual(receipt.task_revision, 1)

    def test_gew_rt_014_human_approval_and_result_ports_preserve_exact_binding(self) -> None:
        for cell in FIXTURE["cells"]:
            active = session(cell)
            decision_body = {
                "schema_version": "1.0", "request_id": f"approve:{cell['cell_id']}",
                "task_id": f"task:{cell['cell_id']}", "owner_id": "owner-fixture",
                "decision_kind": "prd-approval", "decision_payload_ref": "artifact:prd-v1",
                "decision_payload_digest": DIGEST,
            }
            decision = HumanDecisionRequest.from_dict(
                signed("human-decision-request", "request_digest", decision_body)
            )
            result = active.request_human(decision)
            presentation_body = {
                "schema_version": "1.0", "presentation_id": f"result:{cell['cell_id']}",
                "task_id": decision.task_id, "kind": "result", "segments": ["result"],
                "content_digest": DIGEST,
            }
            presentation = DeliveryPresentation.from_dict(
                signed("delivery-presentation", "presentation_digest", presentation_body)
            )
            with self.subTest(cell=cell["cell_id"]):
                self.assertEqual((result.owner_id, result.request_id), ("owner-fixture", decision.request_id))
                self.assertEqual(active.present(presentation).task_id, decision.task_id)

    def test_gew_rt_015_cross_runtime_continuation_is_nondisclosing_and_zero_write(self) -> None:
        codex, telegram = FIXTURE["cells"][:2]
        initial = session(codex)
        foreign = session(telegram)
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(repository, repository, leases, schema_registry=SCHEMAS, context=WORK)
            identity = {
                "task_id": "task-private", "owner_id": "owner-fixture", "runtime_kind": "codex",
                "runtime_lineage_id": initial.proof.lineage_id,
            }
            RuntimeMutationGateway.create(
                initial, initial.proof, identity,
                lambda runtime: application.execute(
                    "task-private", TaskCommand("create", 0, {"identity": identity}), runtime,
                ), occurred_at="2026-08-15T00:00:00Z", lease_ttl_ns=100,
            )
            before = (
                RuntimeQueryGateway.show(
                    initial, initial.proof, application, "task-private"
                ).repository_revision,
                repository.replay("task-private"),
            )
            called = False

            def forbidden(_runtime):
                nonlocal called
                called = True

            with self.assertRaisesRegex(RuntimeSessionError, "not authorized") as rejected:
                RuntimeMutationGateway.status(
                    foreign, foreign.proof, application, "task-private",
                )
            self.assertEqual(str(rejected.exception), "runtime continuation is not authorized")
            self.assertFalse(called)
            self.assertEqual(
                (
                    RuntimeQueryGateway.show(
                        initial, initial.proof, application, "task-private"
                    ).repository_revision,
                    repository.replay("task-private"),
                ),
                before,
            )
            self.assertEqual(
                RuntimeMutationGateway.status(
                    initial, initial.proof, application, "task-private",
                ).task_id,
                "task-private",
            )

    def test_gew_rt_016_runtime_close_stops_and_same_runtime_session_recovers(self) -> None:
        cell = FIXTURE["cells"][0]
        stopped = session(cell)
        proof = stopped.proof
        stopped.close()
        with self.assertRaisesRegex(RuntimeSessionError, "expired"):
            RuntimeMutationGateway.invoke(stopped, proof, lambda _runtime: None)
        recovered = session(cell)
        self.assertNotEqual(recovered.proof.session_id, proof.session_id)
        self.assertEqual(recovered.proof.lineage_id, proof.lineage_id)

    def test_gew_rt_017_reviewer_identity_is_independent_in_every_cell(self) -> None:
        for cell in FIXTURE["cells"]:
            active = session(cell)
            reviewer_body = {
                "schema_version": "1.0", "request_id": f"review:{cell['cell_id']}",
                "task_id": f"task:{cell['cell_id']}", "run_id": "run:review",
                "candidate_ref": "candidate:1", "candidate_digest": DIGEST,
                "author_id": "author:fixture",
            }
            request = ReviewerRequest.from_dict(
                signed("reviewer-request", "request_digest", reviewer_body)
            )
            result = active.invoke_reviewer(request, None)
            with self.subTest(cell=cell["cell_id"]):
                self.assertNotEqual(result.reviewer_id, request.author_id)

    def test_gew_rt_018_hermes_long_message_receipts_are_channel_separate_and_ordered(self) -> None:
        receipts = []
        for cell in FIXTURE["cells"][1:]:
            active = session(cell)
            presentation_body = {
                "schema_version": "1.0", "presentation_id": f"long:{cell['cell_id']}",
                "task_id": f"task:{cell['cell_id']}", "kind": "result",
                "segments": ["segment-z", "segment-a"], "content_digest": DIGEST,
            }
            presentation = DeliveryPresentation.from_dict(
                signed("delivery-presentation", "presentation_digest", presentation_body)
            )
            receipt = active.present(presentation)
            receipts.append(receipt)
            self.assertEqual(len(receipt.delivery_refs), 2)
        self.assertNotEqual(receipts[0].delivery_refs, receipts[1].delivery_refs)

    def test_gew_rt_019_resume_renegotiates_capabilities_before_mutation(self) -> None:
        cell = FIXTURE["cells"][0]
        document = adapter_document(cell)
        document["capabilities"] = ["agent.invoke"]
        resign_configuration(document)
        called = False
        with self.assertRaisesRegex(RuntimeSessionError, "capability"):
            RuntimeSession.establish(
                production_adapter_for_test(cell, document), raw_input(cell), compatibility(cell)
            )
        self.assertFalse(called)

    def test_gew_rt_020_fixture_adapters_exit_without_daemon_or_background_work(self) -> None:
        before = {thread.ident for thread in threading.enumerate()}
        for cell in FIXTURE["cells"]:
            active = session(cell)
            active.close()
        after = {thread.ident for thread in threading.enumerate()}
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
