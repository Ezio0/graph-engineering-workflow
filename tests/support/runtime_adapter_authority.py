"""Exact test-only issuer for runtime adapter doubles.

Production code cannot import this module.  Tests use it when exercising the
platform-neutral session contract without a configured production adapter.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.adapters.runtime_adapters import (
    _ATTESTED_RUNTIME_ADAPTERS,
    _FACTORY_SEAL,
)
from graph_engineering.core.runtime import (
    CapabilitySet,
    OwnerIdentity,
    ReviewerIndependenceAttestation,
    ReviewerRequest,
    RuntimeLineage,
    runtime_record_digest,
)


def reviewer_attestation(
    request: ReviewerRequest,
    owner: OwnerIdentity,
    lineage: RuntimeLineage,
    capabilities: CapabilitySet,
    *,
    reviewer_id: str,
    source_ref: str,
) -> ReviewerIndependenceAttestation:
    body = {
        "schema_version": "1.0", "request_id": request.request_id,
        "task_id": request.task_id, "run_id": request.run_id,
        "candidate_ref": request.candidate_ref,
        "candidate_digest": request.candidate_digest,
        "request_digest": request.request_digest,
        "author_id": request.author_id,
        "reviewer_id": reviewer_id, "runtime_kind": lineage.runtime_kind,
        "runtime_instance_id": lineage.runtime_instance_id,
        "owner_id": owner.owner_id, "runtime_lineage_id": lineage.lineage_id,
        "session_ref": lineage.session_id,
        "capability_digest": capabilities.capability_digest,
        "source_ref": source_ref,
    }
    return ReviewerIndependenceAttestation.from_dict({
        **body,
        "attestation_digest": runtime_record_digest(
            "reviewer-independence-attestation", body
        ),
    })


@dataclass(frozen=True, slots=True)
class _BoundTestPorts:
    delegate: object
    owner: OwnerIdentity
    lineage: RuntimeLineage

    def authorize_task(self, task_id: str):
        return {
            "task_id": task_id, "owner_id": self.owner.owner_id,
            "runtime_kind": self.lineage.runtime_kind,
            "runtime_lineage_id": self.lineage.lineage_id,
        }

    def attest_reviewer(self, request, capabilities):
        return reviewer_attestation(
            request, self.owner, self.lineage, capabilities,
            reviewer_id="reviewer-fixture", source_ref="reviewer-source:test-fixture",
        )

    def invoke_agent(self, request):
        return self.delegate.invoke_agent(request)

    def invoke_reviewer(self, request, independence: Mapping[str, object]):
        return self.delegate.invoke_reviewer(
            request, {"author_id": independence["author_id"]}
        )

    def invoke_tool(self, request):
        return self.delegate.invoke_tool(request)

    def request_human(self, request):
        return self.delegate.request_human(request)

    def present(self, presentation):
        return self.delegate.present(presentation)


class _TestAttestedAdapter:
    __slots__ = ("_delegate", "_guard")

    def __init__(self, delegate: object) -> None:
        self._delegate = delegate
        from tests.support.runtime_resources import runtime_resource_guard
        self._guard = runtime_resource_guard()

    @property
    def resource_guard(self):
        return self._guard

    def identity(self):
        return self._delegate.identity()

    def resolve_owner(self, raw_input):
        return self._delegate.resolve_owner(raw_input)

    def resolve_lineage(self, raw_input):
        return self._delegate.resolve_lineage(raw_input)

    def discover_capabilities(self, request):
        return self._delegate.discover_capabilities(request)

    def bind_session(self, owner: OwnerIdentity, lineage: RuntimeLineage):
        return _BoundTestPorts(self._delegate, owner, lineage)


def attest_test_adapter(delegate: object) -> object:
    """Issue one exact adapter double through the test-only authority."""

    adapter = _TestAttestedAdapter(delegate)
    _ATTESTED_RUNTIME_ADAPTERS[id(adapter)] = (adapter, _FACTORY_SEAL)  # type: ignore[assignment]
    return adapter
