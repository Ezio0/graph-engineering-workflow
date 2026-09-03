"""Platform-neutral runtime adapter records and ports."""

from __future__ import annotations

import re
import hmac
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from typing import Protocol

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import freeze, thaw
from graph_engineering.core.contracts.resources import WorkContext, bounded_measure


class RuntimeContractError(ValueError):
    """Stable rejection for an invalid runtime adapter record."""


_VERSION = re.compile(
    r"(?:[0-9]+\.[0-9]+(?:\.[0-9]+)?|fixture-[0-9]+\.[0-9]+\.[0-9]+)"
)


def _record(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise RuntimeContractError(f"{label} record is not exact")
    return value


def _identity(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or not value.isascii() or "\x00" in value:
        raise RuntimeContractError(f"{label} is invalid")
    return value


def _version(value: object, label: str) -> str:
    result = _identity(value, label)
    if _VERSION.fullmatch(result) is None:
        raise RuntimeContractError(f"{label} is not a supported version identity")
    return result


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise RuntimeContractError(f"{label} is invalid")
    return value


def runtime_record_digest(record_type: str, body: Mapping[str, object]) -> str:
    """Compute the normative exact projection for a runtime envelope."""

    kind = _identity(record_type, "runtime record type")
    return semantic_digest(
        body,
        contract_type=f"runtime-{kind}",
        projection_id=f"urn:gew:projection:runtime-{kind}:1.0.0",
        schema_id=f"urn:gew:schema:runtime-{kind}:1.0.0",
    )


def _self_digest(row: Mapping[str, object], field: str, kind: str) -> str:
    expected = _digest(row[field], field)
    body = {key: value for key, value in row.items() if key != field}
    actual = runtime_record_digest(kind, body)
    if not hmac.compare_digest(expected, actual):
        raise RuntimeContractError(f"{field} does not match the exact canonical projection")
    return expected


def _strings(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise RuntimeContractError(f"{label} is not an array")
    result = tuple(_identity(item, label) for item in value)
    if len(result) != len(set(result)) or list(result) != sorted(result):
        raise RuntimeContractError(f"{label} is not canonical")
    if nonempty and not result:
        raise RuntimeContractError(f"{label} is empty")
    return result


def _ordered_strings(value: object, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise RuntimeContractError(f"{label} is not an array")
    result = tuple(_identity(item, label) for item in value)
    if len(result) != len(set(result)):
        raise RuntimeContractError(f"{label} contains a duplicate")
    if nonempty and not result:
        raise RuntimeContractError(f"{label} is empty")
    return result


class _Record:
    def to_dict(self) -> dict[str, object]:
        value = asdict(self)  # type: ignore[arg-type]
        for name, item in tuple(value.items()):
            if isinstance(item, tuple):
                value[name] = list(item)
        return value


@dataclass(frozen=True, slots=True)
class RuntimeResourcePolicy(_Record):
    schema_version: str; policy_id: str; resource_profile_digest: str
    cost_schedule_digest: str; max_record_bytes: int; max_executable_bytes: int
    max_string_chars: int; max_segments: int; max_items: int; max_depth: int
    policy_digest: str

    @classmethod
    def from_dict(cls, value: object) -> RuntimeResourcePolicy:
        row = _record(value, frozenset(cls.__dataclass_fields__), "runtime resource policy")
        names = (
            "max_record_bytes", "max_executable_bytes", "max_string_chars",
            "max_segments", "max_items", "max_depth",
        )
        integers = {name: row[name] for name in names}
        if any(type(item) is not int or item < 1 for item in integers.values()):
            raise RuntimeContractError("runtime resource policy bounds are invalid")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["policy_id"], "policy ID"),
            _digest(row["resource_profile_digest"], "resource profile digest"),
            _digest(row["cost_schedule_digest"], "cost schedule digest"),
            *(integers[name] for name in names),
            _self_digest(row, "policy_digest", "resource-policy"),
        )


class RuntimeResourceGuard:
    """Charge and bound each runtime ingress before digesting or copying it."""

    __slots__ = ("policy", "context")

    def __init__(self, policy: RuntimeResourcePolicy, context: WorkContext) -> None:
        if type(policy) is not RuntimeResourcePolicy or type(context) is not WorkContext:
            raise RuntimeContractError("runtime resource guard configuration is invalid")
        if (
            policy.resource_profile_digest != context.profile.body_digest
            or policy.cost_schedule_digest != context.schedule.body_digest
        ):
            raise RuntimeContractError("runtime resource policy WorkContext binding is invalid")
        self.policy = policy
        self.context = context

    def validate(self, value: object, *, source_id: str, segments: int | None = None) -> object:
        def depth(current: object, level: int) -> int:
            if level > self.policy.max_depth:
                raise RuntimeContractError("runtime resource policy bound exceeded")
            if isinstance(current, Mapping):
                return max((depth(child, level + 1) for child in current.values()), default=level)
            if isinstance(current, (list, tuple)):
                return max((depth(child, level + 1) for child in current), default=level)
            return level

        depth(value, 1)
        measurement = bounded_measure(
            value, self.context, source_id=source_id,
            operation_path=self.context.child_path(()),
        )
        if (
            measurement.canonical_bytes > self.policy.max_record_bytes
            or measurement.string_scalars > self.policy.max_string_chars
            or measurement.items > self.policy.max_items
            or (segments is not None and segments > self.policy.max_segments)
        ):
            raise RuntimeContractError("runtime resource policy bound exceeded")
        self.context.emit(
            "digest.input_byte", measurement.canonical_bytes,
            operation_path=self.context.child_path(()), source_id=source_id,
        )
        return thaw(freeze(value))

    def validate_bytes(self, size: int, *, source_id: str, executable: bool = False) -> None:
        maximum = self.policy.max_executable_bytes if executable else self.policy.max_record_bytes
        if type(size) is not int or size < 0 or size > maximum:
            raise RuntimeContractError("runtime byte resource policy bound exceeded")
        self.context.check_limit("raw_document_bytes", size, source_id=source_id)
        self.context.emit("digest.input_byte", size, source_id=source_id)


@dataclass(frozen=True, slots=True)
class RuntimeIdentity(_Record):
    schema_version: str
    runtime_kind: str
    adapter_id: str
    adapter_version: str
    runtime_version: str
    protocol_version: str
    runtime_instance_id: str
    identity_digest: str

    @classmethod
    def from_dict(cls, value: object) -> RuntimeIdentity:
        row = _record(value, frozenset(cls.__dataclass_fields__), "runtime identity")
        return cls(
            _version(row["schema_version"], "schema version"), _identity(row["runtime_kind"], "runtime kind"),
            _identity(row["adapter_id"], "adapter ID"), _version(row["adapter_version"], "adapter version"),
            _version(row["runtime_version"], "runtime version"), _version(row["protocol_version"], "protocol version"),
            _identity(row["runtime_instance_id"], "runtime instance ID"), _self_digest(row, "identity_digest", "identity"),
        )


@dataclass(frozen=True, slots=True)
class OwnerIdentity(_Record):
    schema_version: str; owner_id: str; runtime_kind: str; runtime_instance_id: str
    identity_source_ref: str; proof_digest: str

    @classmethod
    def from_dict(cls, value: object) -> OwnerIdentity:
        row = _record(value, frozenset(cls.__dataclass_fields__), "owner identity")
        return cls(
            _version(row["schema_version"], "schema version"), _identity(row["owner_id"], "owner ID"),
            _identity(row["runtime_kind"], "runtime kind"), _identity(row["runtime_instance_id"], "runtime instance ID"),
            _identity(row["identity_source_ref"], "identity source ref"), _self_digest(row, "proof_digest", "owner-identity"),
        )


@dataclass(frozen=True, slots=True)
class RuntimeLineage(_Record):
    schema_version: str; runtime_kind: str; runtime_instance_id: str; session_id: str
    channel_kind: str; channel_ref: str; thread_ref: str; owner_id: str
    identity_source_ref: str; lineage_id: str; proof_digest: str

    @classmethod
    def from_dict(cls, value: object) -> RuntimeLineage:
        row = _record(value, frozenset(cls.__dataclass_fields__), "runtime lineage")
        values = []
        for name in cls.__dataclass_fields__:
            values.append(
                _version(row[name], name) if name == "schema_version"
                else _self_digest(row, name, "lineage") if name == "proof_digest"
                else _identity(row[name], name)
            )
        return cls(*values)


@dataclass(frozen=True, slots=True)
class RuntimeCompatibilityRequest(_Record):
    schema_version: str; runtime_kind: str; runtime_version: str; adapter_version: str
    skill_id: str; skill_version: str; protocol_version: str; release_manifest_digest: str
    core_version: str; repository_contract_version: str; repository_bundle_version: str
    schema_registry_digest: str; graph_contract_version: str; profile_contract_version: str
    overlay_contract_version: str; action_protocol_version: str
    required_capabilities: tuple[str, ...]; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> RuntimeCompatibilityRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "compatibility request")
        return cls(
            _version(row["schema_version"], "schema version"), _identity(row["runtime_kind"], "runtime kind"),
            _version(row["runtime_version"], "runtime version"), _version(row["adapter_version"], "adapter version"),
            _identity(row["skill_id"], "Skill ID"), _version(row["skill_version"], "Skill version"),
            _version(row["protocol_version"], "protocol version"),
            _digest(row["release_manifest_digest"], "release manifest digest"),
            _version(row["core_version"], "core version"),
            _version(row["repository_contract_version"], "repository contract version"),
            _version(row["repository_bundle_version"], "repository bundle version"),
            _digest(row["schema_registry_digest"], "schema registry digest"),
            _version(row["graph_contract_version"], "graph contract version"),
            _version(row["profile_contract_version"], "profile contract version"),
            _version(row["overlay_contract_version"], "overlay contract version"),
            _version(row["action_protocol_version"], "action protocol version"),
            _strings(row["required_capabilities"], "required capabilities", nonempty=True),
            _self_digest(row, "request_digest", "compatibility-request"),
        )


@dataclass(frozen=True, slots=True)
class SkillHandshakeRequest(_Record):
    schema_version: str; skill_id: str; skill_version: str; protocol_version: str
    runtime_kind: str; runtime_configuration_digest: str; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> SkillHandshakeRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "Skill handshake request")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["skill_id"], "Skill ID"),
            _version(row["skill_version"], "Skill version"),
            _version(row["protocol_version"], "protocol version"),
            _identity(row["runtime_kind"], "runtime kind"),
            _digest(row["runtime_configuration_digest"], "runtime configuration digest"),
            _self_digest(row, "request_digest", "skill-handshake-request"),
        )


@dataclass(frozen=True, slots=True)
class CapabilitySet(_Record):
    schema_version: str; release_id: str; release_manifest_digest: str; core_version: str
    cli_protocol_version: str; runtime_kind: str; adapter_id: str; adapter_version: str
    skill_id: str; skill_version: str; repository_contract_version: str; repository_bundle_version: str
    schema_registry_digest: str; graph_contract_version: str; profile_contract_version: str
    overlay_contract_version: str; action_protocol_version: str; capabilities: tuple[str, ...]
    canonical_executable: str; package_origin: str; data_root_ref: str; compatibility: str
    capability_digest: str

    @classmethod
    def from_dict(cls, value: object) -> CapabilitySet:
        row = _record(value, frozenset(cls.__dataclass_fields__), "capability set")
        compatibility = _identity(row["compatibility"], "compatibility")
        if compatibility not in {"compatible", "incompatible", "diagnostic-only"}:
            raise RuntimeContractError("compatibility verdict is unknown")
        versions = {
            name: _version(row[name], name)
            for name in (
                "schema_version", "core_version", "cli_protocol_version", "adapter_version", "skill_version",
                "repository_contract_version", "repository_bundle_version", "graph_contract_version",
                "profile_contract_version", "overlay_contract_version", "action_protocol_version",
            )
        }
        return cls(
            versions["schema_version"], _identity(row["release_id"], "release ID"),
            _digest(row["release_manifest_digest"], "release manifest digest"), versions["core_version"],
            versions["cli_protocol_version"], _identity(row["runtime_kind"], "runtime kind"),
            _identity(row["adapter_id"], "adapter ID"), versions["adapter_version"],
            _identity(row["skill_id"], "Skill ID"), versions["skill_version"],
            versions["repository_contract_version"], versions["repository_bundle_version"],
            _digest(row["schema_registry_digest"], "schema registry digest"), versions["graph_contract_version"],
            versions["profile_contract_version"], versions["overlay_contract_version"],
            versions["action_protocol_version"], _strings(row["capabilities"], "capabilities", nonempty=True),
            _identity(row["canonical_executable"], "canonical executable"),
            _identity(row["package_origin"], "package origin"), _identity(row["data_root_ref"], "data root ref"),
            compatibility, _self_digest(row, "capability_digest", "capabilities"),
        )


def _simple_values(cls: type, value: object, label: str, digest_fields: set[str]) -> list[str]:
    row = _record(value, frozenset(cls.__dataclass_fields__), label)  # type: ignore[attr-defined]
    return [
        _version(row[name], name) if name == "schema_version"
        else _digest(row[name], name) if name in digest_fields
        else _identity(row[name], name)
        for name in cls.__dataclass_fields__  # type: ignore[attr-defined]
    ]


@dataclass(frozen=True, slots=True)
class AgentRequest(_Record):
    schema_version: str; request_id: str; task_id: str; run_id: str; node_id: str; input_ref: str
    input_digest: str; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> AgentRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "agent request")
        values = _simple_values(cls, value, "agent request", {"input_digest", "request_digest"})
        values[-1] = _self_digest(row, "request_digest", "agent-request")
        return cls(*values)


@dataclass(frozen=True, slots=True)
class AgentResult(_Record):
    schema_version: str; request_id: str; task_id: str; status: str; candidate_ref: str; result_digest: str

    @classmethod
    def from_dict(cls, value: object) -> AgentResult:
        row = _record(value, frozenset(cls.__dataclass_fields__), "agent result")
        values = _simple_values(cls, value, "agent result", {"result_digest"})
        values[-1] = _self_digest(row, "result_digest", "agent-result")
        result = cls(*values)
        if result.status not in {"succeeded", "failed", "blocked"}:
            raise RuntimeContractError("agent result status is unknown")
        return result


@dataclass(frozen=True, slots=True)
class ReviewerRequest(_Record):
    schema_version: str; request_id: str; task_id: str; run_id: str; candidate_ref: str
    candidate_digest: str; author_id: str; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ReviewerRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "reviewer request")
        values = _simple_values(cls, value, "reviewer request", {"candidate_digest", "request_digest"})
        values[-1] = _self_digest(row, "request_digest", "reviewer-request")
        return cls(*values)


@dataclass(frozen=True, slots=True)
class ReviewerIndependenceAttestation(_Record):
    schema_version: str; request_id: str; task_id: str; run_id: str
    candidate_ref: str; candidate_digest: str; request_digest: str
    author_id: str; reviewer_id: str; runtime_kind: str
    runtime_instance_id: str; owner_id: str; runtime_lineage_id: str; session_ref: str
    capability_digest: str; source_ref: str; attestation_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ReviewerIndependenceAttestation:
        row = _record(value, frozenset(cls.__dataclass_fields__), "reviewer independence attestation")
        values = _simple_values(
            cls, value, "reviewer independence attestation",
            {
                "candidate_digest", "request_digest", "capability_digest",
                "attestation_digest",
            },
        )
        values[-1] = _self_digest(
            row, "attestation_digest", "reviewer-independence-attestation"
        )
        result = cls(*values)
        if result.author_id.casefold() == result.reviewer_id.casefold():
            raise RuntimeContractError("reviewer independence identities are not distinct")
        return result


@dataclass(frozen=True, slots=True)
class ReviewerResult(_Record):
    schema_version: str; request_id: str; task_id: str; reviewer_id: str; verdict: str
    finding_refs: tuple[str, ...]; result_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ReviewerResult:
        row = _record(value, frozenset(cls.__dataclass_fields__), "reviewer result")
        verdict = _identity(row["verdict"], "verdict")
        if verdict not in {"PASS", "REVISE", "ESCALATE", "BLOCKED"}:
            raise RuntimeContractError("review verdict is unknown")
        return cls(
            _version(row["schema_version"], "schema version"), _identity(row["request_id"], "request ID"),
            _identity(row["task_id"], "task ID"), _identity(row["reviewer_id"], "reviewer ID"),
            verdict, _strings(row["finding_refs"], "finding refs"),
            _self_digest(row, "result_digest", "reviewer-result"),
        )


@dataclass(frozen=True, slots=True)
class ToolRequest(_Record):
    schema_version: str; request_id: str; task_id: str; prepared_action_ref: str
    prepared_action_digest: str; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ToolRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "tool request")
        values = _simple_values(cls, value, "tool request", {"prepared_action_digest", "request_digest"})
        values[-1] = _self_digest(row, "request_digest", "tool-request")
        return cls(*values)


@dataclass(frozen=True, slots=True)
class ToolResult(_Record):
    schema_version: str; request_id: str; task_id: str; status: str; receipt_ref: str; result_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ToolResult:
        row = _record(value, frozenset(cls.__dataclass_fields__), "tool result")
        values = _simple_values(cls, value, "tool result", {"result_digest"})
        values[-1] = _self_digest(row, "result_digest", "tool-result")
        return cls(*values)


@dataclass(frozen=True, slots=True)
class HumanDecisionRequest(_Record):
    schema_version: str; request_id: str; task_id: str; owner_id: str; decision_kind: str
    decision_payload_ref: str; decision_payload_digest: str; request_digest: str

    @classmethod
    def from_dict(cls, value: object) -> HumanDecisionRequest:
        row = _record(value, frozenset(cls.__dataclass_fields__), "human decision request")
        values = _simple_values(
            cls, value, "human decision request", {"decision_payload_digest", "request_digest"},
        )
        values[-1] = _self_digest(row, "request_digest", "human-decision-request")
        return cls(*values)


@dataclass(frozen=True, slots=True)
class HumanDecision(_Record):
    schema_version: str; request_id: str; task_id: str; owner_id: str; status: str
    decision_ref: str; decision_digest: str

    @classmethod
    def from_dict(cls, value: object) -> HumanDecision:
        row = _record(value, frozenset(cls.__dataclass_fields__), "human decision")
        values = _simple_values(cls, value, "human decision", {"decision_digest"})
        values[-1] = _self_digest(row, "decision_digest", "human-decision")
        result = cls(*values)
        if result.status not in {"approved", "rejected", "pending"}:
            raise RuntimeContractError("human decision status is unknown")
        return result


@dataclass(frozen=True, slots=True)
class DeliveryReceipt(_Record):
    schema_version: str; presentation_id: str; task_id: str; delivery_refs: tuple[str, ...]
    status: str; receipt_digest: str

    @classmethod
    def from_dict(cls, value: object) -> DeliveryReceipt:
        row = _record(value, frozenset(cls.__dataclass_fields__), "delivery receipt")
        status = _identity(row["status"], "delivery status")
        if status not in {"delivered", "failed", "pending"}:
            raise RuntimeContractError("delivery status is unknown")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["presentation_id"], "presentation ID"),
            _identity(row["task_id"], "task ID"),
            _ordered_strings(row["delivery_refs"], "delivery refs", nonempty=True),
            status, _self_digest(row, "receipt_digest", "delivery-receipt"),
        )


@dataclass(frozen=True, slots=True)
class DeliveryPresentation(_Record):
    schema_version: str; presentation_id: str; task_id: str; kind: str; segments: tuple[str, ...]
    content_digest: str; presentation_digest: str

    @classmethod
    def from_dict(cls, value: object) -> DeliveryPresentation:
        row = _record(value, frozenset(cls.__dataclass_fields__), "delivery presentation")
        return cls(
            _version(row["schema_version"], "schema version"), _identity(row["presentation_id"], "presentation ID"),
            _identity(row["task_id"], "task ID"), _identity(row["kind"], "presentation kind"),
            _ordered_strings(row["segments"], "presentation segments", nonempty=True),
            _digest(row["content_digest"], "content digest"),
            _self_digest(row, "presentation_digest", "delivery-presentation"),
        )

    def receipt(self, delivery_refs: Sequence[str]) -> DeliveryReceipt:
        body = {
            "schema_version": "1.0", "presentation_id": self.presentation_id,
            "task_id": self.task_id,
            "delivery_refs": list(delivery_refs), "status": "delivered",
        }
        return DeliveryReceipt.from_dict({
            **body, "receipt_digest": runtime_record_digest("delivery-receipt", body),
        })


class RuntimeAdapter(Protocol):
    def identity(self) -> RuntimeIdentity: ...
    def resolve_owner(self, raw_input: Mapping[str, object]) -> OwnerIdentity: ...
    def resolve_lineage(self, raw_input: Mapping[str, object]) -> RuntimeLineage: ...
    def discover_capabilities(self, request: RuntimeCompatibilityRequest) -> CapabilitySet: ...
    def invoke_agent(self, request: AgentRequest) -> AgentResult: ...
    def invoke_reviewer(self, request: ReviewerRequest, independence: Mapping[str, object]) -> ReviewerResult: ...
    def invoke_tool(self, request: ToolRequest) -> ToolResult: ...
    def request_human(self, request: HumanDecisionRequest) -> HumanDecision: ...
    def present(self, presentation: DeliveryPresentation) -> DeliveryReceipt: ...
