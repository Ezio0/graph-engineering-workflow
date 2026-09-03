from __future__ import annotations

import multiprocessing
import pathlib
import sys
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
    RuntimeSession,
    RuntimeSessionError,
    RuntimeSessionProof,
)
from graph_engineering.application.tasks import (  # noqa: E402
    RuntimeContext,
    TaskApplication,
    _ISSUED_RUNTIME_CONTEXTS,
)
from graph_engineering.core.graph.state import TaskCommand  # noqa: E402
from graph_engineering.core.runtime import (  # noqa: E402
    AgentRequest,
    DeliveryPresentation,
    HumanDecisionRequest,
    ReviewerRequest,
    RuntimeContractError,
    ToolRequest,
    runtime_record_digest,
)
from tests.integration.test_wp04_application import SCHEMAS, WORK  # noqa: E402
from tests.integration.test_wp07_runtime_parity import (  # noqa: E402
    DIGEST,
    FIXTURE,
    adapter_document,
    compatibility,
    executable,
    raw_input,
    session,
    signed,
)
from tests.support.wp03_repository import repository_stack  # noqa: E402
from tests.support.runtime_locator import verified_executable  # noqa: E402
from tests.support.runtime_adapter_authority import attest_test_adapter  # noqa: E402


def _fork_check(active, proof, connection) -> None:
    try:
        active.require_current(proof)
    except RuntimeSessionError as error:
        connection.send(str(error))
    else:
        connection.send("accepted")
    finally:
        connection.close()


class WP07RuntimeHardeningTests(unittest.TestCase):
    def test_gew_rt_021_every_runtime_envelope_self_digest_rejects_substitution(self) -> None:
        cell = FIXTURE["cells"][0]
        active = session(cell)
        adapter = ConfiguredRuntimeAdapter.from_dict(adapter_document(cell), executable())
        adapter.resolve_lineage(raw_input(cell))
        agent_body = {
            "schema_version": "1.0", "request_id": "agent:1", "task_id": "task:1",
            "run_id": "run:1", "node_id": "node:1", "input_ref": "input:1",
            "input_digest": DIGEST,
        }
        agent = AgentRequest.from_dict(signed("agent-request", "request_digest", agent_body))
        reviewer_body = {
            "schema_version": "1.0", "request_id": "review:1", "task_id": "task:1",
            "run_id": "run:1", "candidate_ref": "candidate:1", "candidate_digest": DIGEST,
            "author_id": "author:1",
        }
        reviewer = ReviewerRequest.from_dict(
            signed("reviewer-request", "request_digest", reviewer_body)
        )
        tool_body = {
            "schema_version": "1.0", "request_id": "tool:1", "task_id": "task:1",
            "prepared_action_ref": "prepared:1", "prepared_action_digest": DIGEST,
        }
        tool = ToolRequest.from_dict(signed("tool-request", "request_digest", tool_body))
        human_body = {
            "schema_version": "1.0", "request_id": "human:1", "task_id": "task:1",
            "owner_id": "owner-fixture", "decision_kind": "approval",
            "decision_payload_ref": "payload:1", "decision_payload_digest": DIGEST,
        }
        human = HumanDecisionRequest.from_dict(
            signed("human-decision-request", "request_digest", human_body)
        )
        presentation_body = {
            "schema_version": "1.0", "presentation_id": "presentation:1", "task_id": "task:1",
            "kind": "result", "segments": ["segment-z", "segment-a"], "content_digest": DIGEST,
        }
        presentation = DeliveryPresentation.from_dict(
            signed("delivery-presentation", "presentation_digest", presentation_body)
        )
        records = (
            (adapter.identity(), "adapter_id", "adapter:changed"),
            (adapter.resolve_owner(raw_input(cell)), "owner_id", "owner-changed"),
            (adapter.resolve_lineage(raw_input(cell)), "thread_ref", "thread:changed"),
            (compatibility(cell), "skill_id", "skill:changed"),
            (active.capabilities, "release_id", "release:changed"),
            (agent, "node_id", "node:changed"),
            (active.invoke_agent(agent), "candidate_ref", "candidate:changed"),
            (reviewer, "candidate_ref", "candidate:changed"),
            (active.invoke_reviewer(reviewer, None), "reviewer_id", "reviewer:changed"),
            (tool, "prepared_action_ref", "prepared:changed"),
            (active.invoke_tool(tool), "receipt_ref", "receipt:changed"),
            (human, "decision_payload_ref", "payload:changed"),
            (active.request_human(human), "decision_ref", "decision:changed"),
            (presentation, "kind", "status"),
            (active.present(presentation), "status", "pending"),
        )
        for record, field, replacement in records:
            document = record.to_dict()
            document[field] = replacement
            with self.subTest(record=type(record).__name__), self.assertRaisesRegex(
                RuntimeContractError, "canonical projection",
            ):
                type(record).from_dict(document)

    def test_gew_rt_022_direct_context_forged_proof_and_closed_context_are_zero_write(self) -> None:
        cell = FIXTURE["cells"][0]
        active = session(cell)
        with self.assertRaisesRegex(TypeError, "issued"):
            RuntimeContext("owner", "codex", "lineage", "actor", "now", 1)
        forged = RuntimeSessionProof(
            active.proof.session_id, active.proof.runtime_instance_id,
            active.proof.owner_id, active.proof.lineage_id,
        )
        with self.assertRaisesRegex(RuntimeSessionError, "forged"):
            RuntimeMutationGateway.invoke(active, forged, lambda _runtime: None)
        contexts = []
        RuntimeMutationGateway.invoke(
            active, active.proof, lambda runtime: contexts.append(runtime),
            occurred_at="2026-08-15T00:00:00Z", lease_ttl_ns=100,
        )
        context = contexts[0]
        active.close()
        with repository_stack() as (_root, _factory, _locks, _objects, repository, leases):
            application = TaskApplication(repository, repository, leases, schema_registry=SCHEMAS, context=WORK)
            identity = {
                "task_id": "task-closed", "owner_id": "owner-fixture", "runtime_kind": "codex",
                "runtime_lineage_id": forged.lineage_id,
            }
            with self.assertRaisesRegex(Exception, "expired"):
                application.execute(
                    "task-closed", TaskCommand("create", 0, {"identity": identity}), context,
                )
            self.assertEqual(repository.query_catalog({}), ())

    def test_gew_rt_022a_callback_context_is_one_use_and_exception_safe(self) -> None:
        active = session(FIXTURE["cells"][0])
        baseline = len(_ISSUED_RUNTIME_CONTEXTS)
        contexts = []
        RuntimeMutationGateway.invoke(
            active, active.proof, lambda runtime: contexts.append(runtime),
        )
        with self.assertRaisesRegex(Exception, "expired"):
            contexts[0].require_issued()
        self.assertEqual(len(_ISSUED_RUNTIME_CONTEXTS), baseline)

        def fail(runtime):
            contexts.append(runtime)
            raise LookupError("fixture failure")

        with self.assertRaisesRegex(LookupError, "fixture failure"):
            RuntimeMutationGateway.invoke(active, active.proof, fail)
        with self.assertRaisesRegex(Exception, "expired"):
            contexts[-1].require_issued()
        self.assertEqual(len(_ISSUED_RUNTIME_CONTEXTS), baseline)

    def test_gew_rt_023_session_proof_is_thread_and_fork_bound(self) -> None:
        active = session(FIXTURE["cells"][0])
        failures: list[str] = []

        def thread_check() -> None:
            try:
                active.require_current(active.proof)
            except RuntimeSessionError as error:
                failures.append(str(error))

        thread = threading.Thread(target=thread_check)
        thread.start()
        thread.join()
        self.assertEqual(len(failures), 1)
        if "fork" not in multiprocessing.get_all_start_methods():
            self.skipTest("fork context unavailable")
        parent, child = multiprocessing.get_context("fork").Pipe(duplex=False)
        process = multiprocessing.get_context("fork").Process(
            target=_fork_check, args=(active, active.proof, child),
        )
        process.start()
        child.close()
        result = parent.recv()
        process.join(10)
        self.assertEqual(process.exitcode, 0)
        self.assertIn("expired", result)

    def test_gew_rt_024_same_author_reviewer_is_rejected_before_result(self) -> None:
        cell = FIXTURE["cells"][0]
        active = session(cell)
        reviewer_id = f"reviewer:{cell['adapter_id']}"
        body = {
            "schema_version": "1.0", "request_id": "review:same", "task_id": "task:1",
            "run_id": "run:1", "candidate_ref": "candidate:1", "candidate_digest": DIGEST,
            "author_id": reviewer_id,
        }
        request = ReviewerRequest.from_dict(signed("reviewer-request", "request_digest", body))
        with self.assertRaisesRegex(RuntimeSessionError, "independence"):
            active.invoke_reviewer(request, None)

    def test_gew_rt_025_locator_release_and_core_tuple_cannot_be_substituted(self) -> None:
        cell = FIXTURE["cells"][0]
        document = adapter_document(cell)
        mismatched = verified_executable(
            executable().executable, executable().package_origin,
            executable().executable_digest, "sha256-jcs-v1:" + "9" * 64,
            executable().expected_core_version,
        )
        with self.assertRaisesRegex(RuntimeAdapterRejection, "release|core"):
            ConfiguredRuntimeAdapter.from_dict(document, mismatched)

    def test_gew_rt_025a_resigned_adapter_result_binding_is_rejected(self) -> None:
        cell = FIXTURE["cells"][0]

        def rebound(record, field, value, kind, digest_field):
            document = record.to_dict()
            document[field] = value
            document[digest_field] = runtime_record_digest(
                kind, {key: item for key, item in document.items() if key != digest_field},
            )
            return type(record).from_dict(document)

        class ReboundResults(ConfiguredRuntimeAdapter):
            def invoke_agent(self, request):
                return rebound(
                    super().invoke_agent(request), "task_id", "task:foreign",
                    "agent-result", "result_digest",
                )

            def invoke_reviewer(self, request, independence):
                return rebound(
                    super().invoke_reviewer(request, independence), "task_id", "task:foreign",
                    "reviewer-result", "result_digest",
                )

            def invoke_tool(self, request):
                return rebound(
                    super().invoke_tool(request), "request_id", "tool:foreign",
                    "tool-result", "result_digest",
                )

            def request_human(self, request):
                return rebound(
                    super().request_human(request), "owner_id", "owner-foreign",
                    "human-decision", "decision_digest",
                )

            def present(self, presentation):
                return rebound(
                    super().present(presentation), "task_id", "task:foreign",
                    "delivery-receipt", "receipt_digest",
                )

        adapter = attest_test_adapter(
            ReboundResults.from_dict(adapter_document(cell), executable())
        )
        active = RuntimeSession.establish(adapter, raw_input(cell), compatibility(cell))
        agent_body = {
            "schema_version": "1.0", "request_id": "agent:binding", "task_id": "task:1",
            "run_id": "run:1", "node_id": "node:1", "input_ref": "input:1",
            "input_digest": DIGEST,
        }
        agent = AgentRequest.from_dict(signed("agent-request", "request_digest", agent_body))
        reviewer_body = {
            "schema_version": "1.0", "request_id": "review:binding", "task_id": "task:1",
            "run_id": "run:1", "candidate_ref": "candidate:1", "candidate_digest": DIGEST,
            "author_id": "author:1",
        }
        reviewer = ReviewerRequest.from_dict(
            signed("reviewer-request", "request_digest", reviewer_body)
        )
        tool_body = {
            "schema_version": "1.0", "request_id": "tool:binding", "task_id": "task:1",
            "prepared_action_ref": "prepared:1", "prepared_action_digest": DIGEST,
        }
        tool = ToolRequest.from_dict(signed("tool-request", "request_digest", tool_body))
        human_body = {
            "schema_version": "1.0", "request_id": "human:binding", "task_id": "task:1",
            "owner_id": "owner-fixture", "decision_kind": "approval",
            "decision_payload_ref": "payload:1", "decision_payload_digest": DIGEST,
        }
        human = HumanDecisionRequest.from_dict(
            signed("human-decision-request", "request_digest", human_body)
        )
        presentation_body = {
            "schema_version": "1.0", "presentation_id": "presentation:binding",
            "task_id": "task:1", "kind": "result", "segments": ["result"],
            "content_digest": DIGEST,
        }
        presentation = DeliveryPresentation.from_dict(
            signed("delivery-presentation", "presentation_digest", presentation_body)
        )
        calls = (
            lambda: active.invoke_agent(agent),
            lambda: active.invoke_reviewer(reviewer, None),
            lambda: active.invoke_tool(tool), lambda: active.request_human(human),
            lambda: active.present(presentation),
        )
        for call in calls:
            with self.subTest(call=call), self.assertRaisesRegex(RuntimeSessionError, "binding"):
                call()

    def test_gew_rt_032_production_has_one_context_issuer_and_no_test_bootstrap_dependency(self) -> None:
        production = tuple(
            path for root_name in ("core", "application", "storage", "adapters")
            for path in (ROOT / root_name).rglob("*.py")
        )
        registry_users = {
            path.relative_to(ROOT).as_posix()
            for path in production if "_ISSUED_RUNTIME_CONTEXTS" in path.read_text()
        }
        self.assertEqual(registry_users, {
            "application/graph_engineering/application/runtime.py",
            "application/graph_engineering/application/tasks.py",
        })
        self.assertFalse(any("_issue_runtime_context" in path.read_text() for path in production))
        self.assertFalse(any("tests.support" in path.read_text() for path in production))


if __name__ == "__main__":
    unittest.main()
