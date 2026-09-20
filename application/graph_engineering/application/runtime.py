"""Runtime session establishment and bounded application authority."""

from __future__ import annotations

import os
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.application.tasks import (
    RuntimeContext,
    _ISSUED_RUNTIME_CONTEXTS,
)
from graph_engineering.adapters.runtime_adapters import RuntimeAdapterFactory
from graph_engineering.core.runtime import (
    AgentRequest,
    AgentResult,
    CapabilitySet,
    DeliveryPresentation,
    DeliveryReceipt,
    HumanDecision,
    HumanDecisionRequest,
    OwnerIdentity,
    ReviewerRequest,
    ReviewerIndependenceAttestation,
    ReviewerResult,
    RuntimeAdapter,
    RuntimeCompatibilityRequest,
    RuntimeIdentity,
    RuntimeLineage,
    ToolRequest,
    ToolResult,
)


class RuntimeSessionError(RuntimeError):
    """Fail-closed rejection of an invalid or expired runtime session."""


_ADAPTER_METHODS = (
    "identity",
    "resolve_owner",
    "resolve_lineage",
    "discover_capabilities",
    "bind_session",
)
_ISSUED: dict[int, tuple[object, int, int]] = {}


@dataclass(frozen=True, slots=True)
class RuntimeSessionProof:
    """Opaque audit handle; validity still requires its issuing live session."""

    session_id: str
    runtime_instance_id: str
    owner_id: str
    lineage_id: str


class RuntimeSession:
    """Factory-issued, PID/thread-bound scope around one adapter handshake."""

    __slots__ = (
        "_adapter",
        "_identity",
        "_owner",
        "_lineage",
        "_capabilities",
        "_compatibility_request",
        "_guard",
        "_port_session",
        "_proof",
        "_secret",
        "_closed",
    )

    def __new__(cls, *args: object, **kwargs: object) -> RuntimeSession:
        del args, kwargs
        raise TypeError("runtime sessions are established only by the application")

    @classmethod
    def establish(
        cls,
        adapter: RuntimeAdapter,
        raw_input: Mapping[str, object],
        compatibility_request: RuntimeCompatibilityRequest,
    ) -> RuntimeSession:
        try:
            adapter = RuntimeAdapterFactory.require_attested(adapter)
        except Exception as error:
            raise RuntimeSessionError("runtime adapter is not factory-attested") from error
        if any(not callable(getattr(adapter, name, None)) for name in _ADAPTER_METHODS):
            raise RuntimeSessionError("runtime adapter contract is incomplete")
        identity = adapter.identity()
        owner = adapter.resolve_owner(raw_input)
        lineage = adapter.resolve_lineage(raw_input)
        capabilities = adapter.discover_capabilities(compatibility_request)
        if type(identity) is not RuntimeIdentity:
            raise RuntimeSessionError("runtime adapter contract returned an invalid identity")
        if type(owner) is not OwnerIdentity or type(lineage) is not RuntimeLineage:
            raise RuntimeSessionError("runtime adapter contract returned an invalid owner or lineage")
        if type(capabilities) is not CapabilitySet:
            raise RuntimeSessionError("runtime adapter contract returned invalid capabilities")
        cls._validate_handshake(identity, owner, lineage, capabilities, compatibility_request)

        session = object.__new__(cls)
        session._adapter = adapter
        session._guard = adapter.resource_guard
        for label, record in (
            ("runtime-identity", identity), ("runtime-owner", owner),
            ("runtime-lineage", lineage), ("runtime-capabilities", capabilities),
            ("runtime-compatibility", compatibility_request),
        ):
            session._guard.validate(record.to_dict(), source_id=label)
        session._identity = identity
        session._owner = owner
        session._lineage = lineage
        session._capabilities = capabilities
        session._compatibility_request = compatibility_request
        session._port_session = adapter.bind_session(owner, lineage)
        session._secret = object()
        session._proof = RuntimeSessionProof(
            session_id=secrets.token_hex(16),
            runtime_instance_id=identity.runtime_instance_id,
            owner_id=owner.owner_id,
            lineage_id=lineage.lineage_id,
        )
        session._closed = False
        _ISSUED[id(session)] = (session._secret, os.getpid(), threading.get_ident())
        return session

    @staticmethod
    def _validate_handshake(
        identity: RuntimeIdentity,
        owner: OwnerIdentity,
        lineage: RuntimeLineage,
        capabilities: CapabilitySet,
        request: RuntimeCompatibilityRequest,
    ) -> None:
        runtime_tuple = (identity.runtime_kind, identity.runtime_instance_id)
        if (owner.runtime_kind, owner.runtime_instance_id) != runtime_tuple:
            raise RuntimeSessionError("owner runtime instance does not match adapter identity")
        if (lineage.runtime_kind, lineage.runtime_instance_id) != runtime_tuple:
            raise RuntimeSessionError("lineage runtime instance does not match adapter identity")
        if (
            lineage.owner_id != owner.owner_id
            or lineage.identity_source_ref != owner.identity_source_ref
        ):
            raise RuntimeSessionError("lineage owner identity source does not match the session")
        if request.runtime_kind != identity.runtime_kind or request.runtime_version != identity.runtime_version:
            raise RuntimeSessionError("runtime version compatibility failed")
        if request.adapter_version != identity.adapter_version:
            raise RuntimeSessionError("adapter version compatibility failed")
        if request.protocol_version != identity.protocol_version:
            raise RuntimeSessionError("runtime protocol version compatibility failed")
        expected = (
            identity.runtime_kind,
            identity.adapter_id,
            identity.adapter_version,
            request.skill_id,
            request.skill_version,
            request.protocol_version,
            request.release_manifest_digest,
            request.core_version,
            request.repository_contract_version,
            request.repository_bundle_version,
            request.schema_registry_digest,
            request.graph_contract_version,
            request.profile_contract_version,
            request.overlay_contract_version,
            request.action_protocol_version,
        )
        actual = (
            capabilities.runtime_kind,
            capabilities.adapter_id,
            capabilities.adapter_version,
            capabilities.skill_id,
            capabilities.skill_version,
            capabilities.cli_protocol_version,
            capabilities.release_manifest_digest,
            capabilities.core_version,
            capabilities.repository_contract_version,
            capabilities.repository_bundle_version,
            capabilities.schema_registry_digest,
            capabilities.graph_contract_version,
            capabilities.profile_contract_version,
            capabilities.overlay_contract_version,
            capabilities.action_protocol_version,
        )
        if actual != expected or capabilities.compatibility != "compatible":
            raise RuntimeSessionError("capability compatibility tuple is incompatible")
        if not set(request.required_capabilities).issubset(capabilities.capabilities):
            raise RuntimeSessionError("required runtime capability is missing")

    @property
    def capabilities(self) -> CapabilitySet:
        self.require_current()
        return self._capabilities

    @property
    def proof(self) -> RuntimeSessionProof:
        self.require_current()
        return self._proof

    def require_current(self, proof: RuntimeSessionProof | None = None) -> None:
        issued = _ISSUED.get(id(self))
        if (
            self._closed
            or issued is None
            or issued[0] is not self._secret
            or issued[1] != os.getpid()
            or issued[2] != threading.get_ident()
        ):
            raise RuntimeSessionError("runtime session is missing, foreign, or expired")
        if proof is not None and proof is not self._proof:
            raise RuntimeSessionError("runtime session proof is missing or forged")

    def require_owner_lineage(self, owner: OwnerIdentity, lineage: RuntimeLineage) -> None:
        self.require_current()
        if owner != self._owner:
            raise RuntimeSessionError("runtime instance or owner identity does not match the session")
        if lineage != self._lineage:
            raise RuntimeSessionError("runtime lineage does not match the session")

    def invoke_agent(self, request: AgentRequest) -> AgentResult:
        self.require_current()
        self._guard.validate(request.to_dict(), source_id="runtime-agent-request")
        self._authorize_invocation("agent.invoke", request.task_id)
        result = self._port_session.invoke_agent(request)
        self._guard.validate(result.to_dict(), source_id="runtime-agent-result")
        if (
            type(result) is not AgentResult
            or result.request_id != request.request_id or result.task_id != request.task_id
        ):
            raise RuntimeSessionError("agent result binding is invalid")
        return result

    def invoke_reviewer(
        self, request: ReviewerRequest, independence: ReviewerIndependenceAttestation | None,
    ) -> ReviewerResult:
        self.require_current()
        self._guard.validate(request.to_dict(), source_id="runtime-reviewer-request")
        self._authorize_invocation("reviewer.invoke", request.task_id)
        try:
            issued = self._port_session.attest_reviewer(request, self._capabilities)
        except Exception as error:
            raise RuntimeSessionError("reviewer independence attestation is invalid") from error
        self._validate_reviewer_independence(request, issued)
        if independence is not None and independence != issued:
            raise RuntimeSessionError("reviewer independence attestation is substituted")
        result = self._port_session.invoke_reviewer(request, issued.to_dict())
        self._guard.validate(result.to_dict(), source_id="runtime-reviewer-result")
        if (
            type(result) is not ReviewerResult
            or result.request_id != request.request_id or result.task_id != request.task_id
            or result.reviewer_id.casefold() == request.author_id.casefold()
        ):
            raise RuntimeSessionError("reviewer result binding or independence is invalid")
        return result

    def invoke_tool(self, request: ToolRequest) -> ToolResult:
        self.require_current()
        self._guard.validate(request.to_dict(), source_id="runtime-tool-request")
        self._authorize_invocation("tool.invoke", request.task_id)
        result = self._port_session.invoke_tool(request)
        self._guard.validate(result.to_dict(), source_id="runtime-tool-result")
        if (
            type(result) is not ToolResult
            or result.request_id != request.request_id or result.task_id != request.task_id
        ):
            raise RuntimeSessionError("tool result binding is invalid")
        return result

    def request_human(self, request: HumanDecisionRequest) -> HumanDecision:
        self.require_current()
        self._guard.validate(request.to_dict(), source_id="runtime-human-request")
        self._authorize_invocation("human.request", request.task_id)
        if request.owner_id != self._owner.owner_id:
            raise RuntimeSessionError("human decision owner binding is invalid")
        result = self._port_session.request_human(request)
        self._guard.validate(result.to_dict(), source_id="runtime-human-result")
        if (
            type(result) is not HumanDecision
            or result.request_id != request.request_id or result.task_id != request.task_id
            or result.owner_id != request.owner_id
        ):
            raise RuntimeSessionError("human decision result binding is invalid")
        return result

    def present(self, presentation: DeliveryPresentation) -> DeliveryReceipt:
        self.require_current()
        self._guard.validate(
            presentation.to_dict(), source_id="runtime-presentation",
            segments=len(presentation.segments),
        )
        self._authorize_invocation("presentation.deliver", presentation.task_id)
        result = self._port_session.present(presentation)
        self._guard.validate(result.to_dict(), source_id="runtime-delivery-receipt")
        if (
            type(result) is not DeliveryReceipt
            or result.presentation_id != presentation.presentation_id
            or result.task_id != presentation.task_id
        ):
            raise RuntimeSessionError("delivery receipt binding is invalid")
        return result

    def _authorize_invocation(self, capability: str, task_id: str) -> None:
        current = self._adapter.discover_capabilities(self._compatibility_request)
        if type(current) is not CapabilitySet:
            raise RuntimeSessionError("runtime invocation is not authorized")
        self._guard.validate(current.to_dict(), source_id="runtime-capability-refresh")
        self._validate_handshake(
            self._identity, self._owner, self._lineage, current,
            self._compatibility_request,
        )
        if capability not in current.capabilities:
            raise RuntimeSessionError("runtime invocation capability is not authorized")
        expected = {
            "task_id": task_id,
            "owner_id": self._owner.owner_id,
            "runtime_kind": self._identity.runtime_kind,
            "runtime_lineage_id": self._lineage.lineage_id,
        }
        try:
            actual = self._port_session.authorize_task(task_id)
        except Exception as error:
            raise RuntimeSessionError("runtime task is not authorized") from error
        if not isinstance(actual, Mapping) or dict(actual) != expected:
            raise RuntimeSessionError("runtime task is not authorized")
        self._capabilities = current

    def _validate_reviewer_independence(
        self,
        request: ReviewerRequest,
        attestation: ReviewerIndependenceAttestation,
    ) -> None:
        if type(attestation) is not ReviewerIndependenceAttestation:
            raise RuntimeSessionError("reviewer independence attestation is invalid")
        expected = (
            request.request_id,
            request.task_id,
            request.run_id,
            request.candidate_ref,
            request.candidate_digest,
            request.request_digest,
            request.author_id,
            self._identity.runtime_kind,
            self._identity.runtime_instance_id,
            self._owner.owner_id,
            self._lineage.lineage_id,
            self._lineage.session_id,
            self._capabilities.capability_digest,
        )
        actual = (
            attestation.request_id,
            attestation.task_id,
            attestation.run_id,
            attestation.candidate_ref,
            attestation.candidate_digest,
            attestation.request_digest,
            attestation.author_id,
            attestation.runtime_kind,
            attestation.runtime_instance_id,
            attestation.owner_id,
            attestation.runtime_lineage_id,
            attestation.session_ref,
            attestation.capability_digest,
        )
        if actual != expected or attestation.author_id.casefold() == attestation.reviewer_id.casefold():
            raise RuntimeSessionError("reviewer independence attestation is invalid")

    def _issue_context(self, occurred_at: str, lease_ttl_ns: int) -> RuntimeContext:
        self.require_current()
        runtime = object.__new__(RuntimeContext)
        for field, value in (
            ("owner_id", self._owner.owner_id),
            ("runtime_kind", self._identity.runtime_kind),
            ("runtime_lineage_id", self._lineage.lineage_id),
            ("actor_id", self._identity.adapter_id),
            ("occurred_at", occurred_at),
            ("lease_ttl_ns", lease_ttl_ns),
        ):
            object.__setattr__(runtime, field, value)
        runtime._validate()
        _ISSUED_RUNTIME_CONTEXTS[id(runtime)] = (
            runtime, os.getpid(), threading.get_ident(), self.require_current,
        )
        return runtime

    def bind_release_namespace(self, *, action_coordinator: object, namespace_path: object) -> object:
        """Bind host configuration, never an evidence-supplied recovery path."""

        self.require_current()
        from graph_engineering.application.release_operations import _issue_retained_namespace

        return _issue_retained_namespace(self, action_coordinator, namespace_path)

    def close(self) -> None:
        self.require_current()
        self._closed = True
        _ISSUED.pop(id(self), None)

    def __enter__(self) -> RuntimeSession:
        self.require_current()
        return self

    def __exit__(self, *exc: object) -> None:
        del exc
        self.close()


class RuntimeMutationGateway:
    """The sole bridge from a live adapter session to a mutation callback."""

    __slots__ = ()

    @staticmethod
    def invoke(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        operation: object,
        *,
        occurred_at: str = "runtime-turn",
        lease_ttl_ns: int = 1,
    ) -> object:
        session.require_current(proof)
        if not callable(operation):
            raise RuntimeSessionError("runtime mutation operation is invalid")
        runtime = session._issue_context(occurred_at, lease_ttl_ns)
        try:
            return operation(runtime)
        finally:
            issued = _ISSUED_RUNTIME_CONTEXTS.get(id(runtime))
            if issued is not None and issued[0] is runtime:
                del _ISSUED_RUNTIME_CONTEXTS[id(runtime)]

    @staticmethod
    def create(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        identity: Mapping[str, object],
        operation: object,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        session.require_current(proof)
        expected = {
            "task_id": identity.get("task_id"),
            "owner_id": proof.owner_id,
            "runtime_kind": session._identity.runtime_kind,
            "runtime_lineage_id": proof.lineage_id,
        }
        if dict(identity) != expected:
            raise RuntimeSessionError("runtime continuation is not authorized")
        return RuntimeMutationGateway.invoke(
            session, proof, operation,
            occurred_at=occurred_at, lease_ttl_ns=lease_ttl_ns,
        )

    @staticmethod
    def task(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        application: object,
        task_id: str,
        operation: object,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        session.require_current(proof)
        runtime = session._issue_context(occurred_at, lease_ttl_ns)
        try:
            view = application.runtime_show(task_id, runtime)  # type: ignore[attr-defined]
            identity = view.snapshot.identity
            if (
                identity.get("owner_id") != proof.owner_id
                or identity.get("runtime_kind") != session._identity.runtime_kind
                or identity.get("runtime_lineage_id") != proof.lineage_id
            ):
                raise RuntimeSessionError("runtime continuation is not authorized")
            return operation(runtime)
        except RuntimeSessionError:
            raise
        except Exception as error:
            raise RuntimeSessionError("runtime continuation is not authorized") from error
        finally:
            issued = _ISSUED_RUNTIME_CONTEXTS.get(id(runtime))
            if issued is not None and issued[0] is runtime:
                del _ISSUED_RUNTIME_CONTEXTS[id(runtime)]

    @staticmethod
    def status(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        application: object,
        task_id: str,
    ) -> object:
        """Return status only after the same non-disclosing task binding gate."""

        return RuntimeMutationGateway.task(
            session, proof, application, task_id,
            lambda runtime: application.runtime_show(task_id, runtime),  # type: ignore[attr-defined]
            occurred_at="runtime-status", lease_ttl_ns=1,
        )


class RuntimeQueryGateway:
    """Live-session facade for non-disclosing task and catalog reads."""

    __slots__ = ()

    @staticmethod
    def _invoke(session: RuntimeSession, proof: RuntimeSessionProof, operation: object) -> object:
        session.require_current(proof)
        if not callable(operation):
            raise RuntimeSessionError("runtime query is not authorized")
        runtime = session._issue_context("runtime-query", 1)
        try:
            return operation(runtime)
        except Exception as error:
            raise RuntimeSessionError("runtime query is not authorized") from error
        finally:
            issued = _ISSUED_RUNTIME_CONTEXTS.get(id(runtime))
            if issued is not None and issued[0] is runtime:
                del _ISSUED_RUNTIME_CONTEXTS[id(runtime)]

    @staticmethod
    def show(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        application: object,
        task_id: str,
    ) -> object:
        return RuntimeQueryGateway._invoke(
            session, proof,
            lambda runtime: application.runtime_show(task_id, runtime),  # type: ignore[attr-defined]
        )

    @staticmethod
    def search(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        application: object,
        filters: Mapping[str, object] | None = None,
    ) -> object:
        return RuntimeQueryGateway._invoke(
            session, proof,
            lambda runtime: application.runtime_search(filters, runtime),  # type: ignore[attr-defined]
        )

    @staticmethod
    def list(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        application: object,
    ) -> object:
        return RuntimeQueryGateway.search(session, proof, application)
