"""Deterministic invocation behavior used only by isolated WP-07 fixtures."""

from __future__ import annotations

from collections.abc import Mapping

from graph_engineering.adapters.runtime_config import (
    ConfiguredRuntimeHandshake,
    RuntimeAdapterRejection,
)
from graph_engineering.core.runtime import (
    AgentRequest,
    AgentResult,
    DeliveryPresentation,
    DeliveryReceipt,
    HumanDecision,
    HumanDecisionRequest,
    ReviewerRequest,
    ReviewerResult,
    ToolRequest,
    ToolResult,
    runtime_record_digest,
)


class ConfiguredRuntimeAdapter(ConfiguredRuntimeHandshake):
    @classmethod
    def from_dict(cls, value, executable, guard=None):
        if guard is None:
            from tests.support.runtime_resources import runtime_resource_guard
            guard = runtime_resource_guard()
        return super().from_dict(value, executable, guard)

    def invoke_agent(self, request: AgentRequest) -> AgentResult:
        body = {
            "schema_version": "1.0", "request_id": request.request_id,
            "task_id": request.task_id, "status": "succeeded",
            "candidate_ref": f"candidate:{request.run_id}",
        }
        return AgentResult.from_dict({
            **body, "result_digest": runtime_record_digest("agent-result", body),
        })

    def invoke_reviewer(
        self, request: ReviewerRequest, independence: Mapping[str, object],
    ) -> ReviewerResult:
        reviewer_id = f"reviewer:{self._config['adapter_id']}"
        if independence.get("author_id") != request.author_id or reviewer_id == request.author_id:
            raise RuntimeAdapterRejection("reviewer independence is not authorized")
        body: dict[str, object] = {
            "schema_version": "1.0", "request_id": request.request_id,
            "task_id": request.task_id, "reviewer_id": reviewer_id,
            "verdict": "PASS", "finding_refs": [],
        }
        return ReviewerResult.from_dict({
            **body, "result_digest": runtime_record_digest("reviewer-result", body),
        })

    def invoke_tool(self, request: ToolRequest) -> ToolResult:
        body = {
            "schema_version": "1.0", "request_id": request.request_id,
            "task_id": request.task_id, "status": "succeeded",
            "receipt_ref": f"receipt:{request.request_id}",
        }
        return ToolResult.from_dict({
            **body, "result_digest": runtime_record_digest("tool-result", body),
        })

    def request_human(self, request: HumanDecisionRequest) -> HumanDecision:
        if request.owner_id not in self._config["owner_bindings"].values():
            raise RuntimeAdapterRejection("human decision input is not authorized")
        body = {
            "schema_version": "1.0", "request_id": request.request_id,
            "task_id": request.task_id, "owner_id": request.owner_id,
            "status": "approved", "decision_ref": f"decision:{request.request_id}",
        }
        return HumanDecision.from_dict({
            **body, "decision_digest": runtime_record_digest("human-decision", body),
        })

    def present(self, presentation: DeliveryPresentation) -> DeliveryReceipt:
        refs = tuple(
            f"delivery:{self._config['channel_kind']}:{self._config['allowed_channels'][0]}:"
            f"{presentation.presentation_id}:{index}"
            for index, _segment in enumerate(presentation.segments, start=1)
        )
        return presentation.receipt(refs)
