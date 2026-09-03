"""Production Codex/Hermes adapters with injected runtime invocation ports."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from graph_engineering.adapters.runtime_config import (
    ConfiguredRuntimeHandshake,
    RuntimeAdapterRejection,
)
from graph_engineering.adapters.runtime_locator import VerifiedExecutable
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
    RuntimeCompatibilityRequest,
    RuntimeIdentity,
    RuntimeLineage,
    RuntimeResourceGuard,
    ToolRequest,
    ToolResult,
)


@dataclass(frozen=True, slots=True)
class RuntimeInvocationPorts:
    authorize_task: Callable[[str, OwnerIdentity, RuntimeLineage], Mapping[str, object] | None]
    attest_reviewer: Callable[
        [ReviewerRequest, OwnerIdentity, RuntimeLineage, CapabilitySet],
        ReviewerIndependenceAttestation,
    ]
    invoke_agent: Callable[[AgentRequest, OwnerIdentity, RuntimeLineage], AgentResult]
    invoke_reviewer: Callable[
        [ReviewerRequest, Mapping[str, object], OwnerIdentity, RuntimeLineage], ReviewerResult
    ]
    invoke_tool: Callable[[ToolRequest, OwnerIdentity, RuntimeLineage], ToolResult]
    request_human: Callable[[HumanDecisionRequest, OwnerIdentity, RuntimeLineage], HumanDecision]
    present: Callable[[DeliveryPresentation, OwnerIdentity, RuntimeLineage], DeliveryReceipt]

    def __post_init__(self) -> None:
        if any(not callable(value) for value in (
            self.authorize_task, self.attest_reviewer,
            self.invoke_agent, self.invoke_reviewer, self.invoke_tool,
            self.request_human, self.present,
        )):
            raise RuntimeAdapterRejection("runtime invocation port is missing")


_FACTORY_SEAL = object()
_ATTESTED_RUNTIME_ADAPTERS: dict[int, tuple["BoundRuntimeAdapter", object]] = {}


@dataclass(frozen=True, slots=True)
class BoundRuntimePortSession:
    ports: RuntimeInvocationPorts
    owner: OwnerIdentity
    lineage: RuntimeLineage

    def authorize_task(self, task_id: str) -> Mapping[str, object] | None:
        return self.ports.authorize_task(task_id, self.owner, self.lineage)

    def attest_reviewer(
        self, request: ReviewerRequest, capabilities: CapabilitySet,
    ) -> ReviewerIndependenceAttestation:
        return self.ports.attest_reviewer(request, self.owner, self.lineage, capabilities)

    def invoke_agent(self, request: AgentRequest) -> AgentResult:
        return self.ports.invoke_agent(request, self.owner, self.lineage)

    def invoke_reviewer(
        self, request: ReviewerRequest, independence: Mapping[str, object],
    ) -> ReviewerResult:
        return self.ports.invoke_reviewer(request, independence, self.owner, self.lineage)

    def invoke_tool(self, request: ToolRequest) -> ToolResult:
        return self.ports.invoke_tool(request, self.owner, self.lineage)

    def request_human(self, request: HumanDecisionRequest) -> HumanDecision:
        return self.ports.request_human(request, self.owner, self.lineage)

    def present(self, presentation: DeliveryPresentation) -> DeliveryReceipt:
        return self.ports.present(presentation, self.owner, self.lineage)


class BoundRuntimeAdapter:
    """Compose the production handshake with runtime-owned invocation ports."""

    __slots__ = ("_handshake", "_ports", "_guard")

    runtime_kind: str | None = None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("runtime adapters are created only by RuntimeAdapterFactory")

    def identity(self) -> RuntimeIdentity:
        return self._handshake.identity()

    def resolve_owner(self, raw_input: Mapping[str, object]) -> OwnerIdentity:
        return self._handshake.resolve_owner(raw_input)

    def resolve_lineage(self, raw_input: Mapping[str, object]) -> RuntimeLineage:
        return self._handshake.resolve_lineage(raw_input)

    def discover_capabilities(self, request: RuntimeCompatibilityRequest) -> CapabilitySet:
        return self._handshake.discover_capabilities(request)

    @property
    def resource_guard(self) -> RuntimeResourceGuard:
        return self._guard

    def bind_session(
        self, owner: OwnerIdentity, lineage: RuntimeLineage,
    ) -> BoundRuntimePortSession:
        if (
            owner.runtime_kind != self.identity().runtime_kind
            or owner.runtime_instance_id != self.identity().runtime_instance_id
            or lineage.owner_id != owner.owner_id
            or lineage.identity_source_ref != owner.identity_source_ref
        ):
            raise RuntimeAdapterRejection("runtime session port binding is invalid")
        return BoundRuntimePortSession(self._ports, owner, lineage)

    def invoke_agent(self, request: AgentRequest) -> AgentResult:
        del request
        raise RuntimeAdapterRejection("runtime invocation requires an immutable bound session")

    def invoke_reviewer(
        self, request: ReviewerRequest, independence: Mapping[str, object],
    ) -> ReviewerResult:
        del request, independence
        raise RuntimeAdapterRejection("runtime invocation requires an immutable bound session")

    def invoke_tool(self, request: ToolRequest) -> ToolResult:
        del request
        raise RuntimeAdapterRejection("runtime invocation requires an immutable bound session")

    def request_human(self, request: HumanDecisionRequest) -> HumanDecision:
        del request
        raise RuntimeAdapterRejection("runtime invocation requires an immutable bound session")

    def present(self, presentation: DeliveryPresentation) -> DeliveryReceipt:
        del presentation
        raise RuntimeAdapterRejection("runtime invocation requires an immutable bound session")


class CodexRuntimeAdapter(BoundRuntimeAdapter):
    runtime_kind = "codex"


class HermesRuntimeAdapter(BoundRuntimeAdapter):
    runtime_kind = "hermes"


class RuntimeAdapterFactory:
    """The sole production issuer for registry-attested runtime adapters."""

    __slots__ = ("_guard",)

    def __init__(self, guard: RuntimeResourceGuard) -> None:
        if type(guard) is not RuntimeResourceGuard:
            raise RuntimeAdapterRejection("runtime resource guard is missing or forged")
        self._guard = guard

    def _create(
        self,
        adapter_type: type[BoundRuntimeAdapter],
        value: object,
        executable: VerifiedExecutable,
        ports: RuntimeInvocationPorts,
    ) -> BoundRuntimeAdapter:
        handshake = ConfiguredRuntimeHandshake.from_dict(value, executable, self._guard)
        adapter = object.__new__(adapter_type)
        identity = handshake.identity()
        if adapter_type.runtime_kind is not None and identity.runtime_kind != adapter_type.runtime_kind:
            raise RuntimeAdapterRejection("runtime adapter kind does not match its factory")
        adapter._handshake = handshake
        adapter._ports = ports
        adapter._guard = self._guard
        _ATTESTED_RUNTIME_ADAPTERS[id(adapter)] = (adapter, _FACTORY_SEAL)
        return adapter

    def codex(
        self, value: object, executable: VerifiedExecutable, ports: RuntimeInvocationPorts,
    ) -> CodexRuntimeAdapter:
        return self._create(CodexRuntimeAdapter, value, executable, ports)  # type: ignore[return-value]

    def hermes(
        self, value: object, executable: VerifiedExecutable, ports: RuntimeInvocationPorts,
    ) -> HermesRuntimeAdapter:
        return self._create(HermesRuntimeAdapter, value, executable, ports)  # type: ignore[return-value]

    @staticmethod
    def require_attested(adapter: object) -> BoundRuntimeAdapter:
        issued = _ATTESTED_RUNTIME_ADAPTERS.get(id(adapter))
        if issued is None or issued[0] is not adapter or issued[1] is not _FACTORY_SEAL:
            raise RuntimeAdapterRejection("runtime adapter is not factory-attested")
        return issued[0]
