"""Deterministic authority and prepared-action contracts."""

from __future__ import annotations

import copy
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.contracts.immutable import freeze
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    exact_mapping,
    parse_timestamp,
    require_canonical_strings,
    require_digest,
    require_id,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import SecurityRuntimeManifest


class ActionContractError(ValueError):
    """An action contract is malformed, stale, or digest-inconsistent."""


class ActionGateError(ValueError):
    """Stable deterministic rejection emitted before an action tool call."""

    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


class ExecuteGateDecisionTable:
    """Frozen precedence oracle shared by the execute gate and mutation tests."""

    PRECEDENCE = (
        "GEW-AUT-PRECONDITION-CHANGED",
        "GEW-AUT-PRECONDITION-UNVERIFIABLE",
        "GEW-AUT-IDEMPOTENCY-KEY-CHANGED",
        "GEW-AUT-IDEMPOTENCY-CLASS-CHANGED",
        "GEW-AUT-IDEMPOTENCY-DUPLICATE",
        "GEW-AUT-IDEMPOTENCY-UNKNOWN",
        "GEW-AUT-ROLLBACK-MISSING",
        "GEW-AUT-ROLLBACK-CHANGED",
        "GEW-AUT-VERIFY-MISSING",
        "GEW-AUT-VERIFY-CHANGED",
        "GEW-AUT-TARGET-EVIDENCE-STALE",
    )

    @classmethod
    def first(cls, codes: object) -> str | None:
        if type(codes) not in {set, frozenset}:
            raise ActionGateError("GEW-AUT-DECISION-INPUT-INVALID", "decision codes must be an exact set")
        values = codes
        unknown = values.difference(cls.PRECEDENCE)  # type: ignore[union-attr]
        if unknown:
            raise ActionGateError("GEW-AUT-DECISION-INPUT-INVALID", "decision code is not frozen")
        return next((code for code in cls.PRECEDENCE if code in values), None)  # type: ignore[operator]

    @classmethod
    def reject(cls, codes: set[str], detail: str) -> None:
        code = cls.first(codes)
        if code is not None:
            raise ActionGateError(code, detail)


@dataclass(frozen=True, slots=True, init=False)
class ActionAdapterInstallationAttestation:
    """Opaque installation-issued trust anchor for the concrete adapter closure."""

    runtime_manifest_digest: str
    concrete_policy_id: str
    concrete_policy_digest: str
    registry_id: str
    registry_digest: str
    schema_registry_id: str
    schema_registry_digest: str
    _issuer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("action adapter installation attestations are installation-issued")


@dataclass(frozen=True, slots=True, init=False)
class ActionPolicy:
    policy_id: str
    real_external_actions_enabled: bool
    separately_authorized_action_kinds: tuple[str, ...]
    enabled_adapter_capabilities: tuple[str, ...]
    required_gate_capabilities: tuple[str, ...]
    unknown_routes: tuple[str, ...]
    concrete_action_authority: Mapping[str, str]
    policy_digest: str
    _schemas: ClosedSchemaRegistry
    _context: WorkContext
    _runtime_issuer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ActionPolicy must be loaded from the installed security runtime")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> ActionPolicy:
        if schema_registry.validate("urn:gew:schema:action-policy:1.0.0", value, context):
            raise ActionContractError("action policy schema validation failed")
        try:
            exact_mapping(value, {
                "schema_version", "policy_id", "real_external_actions_enabled",
                "separately_authorized_action_kinds", "enabled_adapter_capabilities",
                "required_gate_capabilities", "unknown_routes", "concrete_action_authority",
                "policy_digest",
            }, "action policy")
            external_actions_enabled = value.get("real_external_actions_enabled")
            if value.get("schema_version") != "1.0.0" or type(external_actions_enabled) is not bool:
                raise ValueError("action policy version or external-action boundary is invalid")
            policy_id = require_id(value.get("policy_id"), "action policy ID")
            expected = require_digest(value.get("policy_digest"), "action policy digest")
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "policy_digest"}, context,
                contract_type="urn:gew:contract:action-policy", projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:action-policy:1.0.0", operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected, actual):
                raise ValueError("action policy digest mismatch")
            runtime.require_policy("action", policy_id, expected)
            authority = exact_mapping(
                value.get("concrete_action_authority"),
                {
                    "policy_id", "policy_digest", "registry_id", "registry_digest",
                    "schema_registry_id", "schema_registry_digest",
                },
                "concrete action authority",
            )
            concrete_authority = MappingProxyType({
                "policy_id": require_id(authority.get("policy_id"), "concrete action policy ID"),
                "policy_digest": require_digest(authority.get("policy_digest"), "concrete action policy digest"),
                "registry_id": require_id(authority.get("registry_id"), "action adapter registry ID"),
                "registry_digest": require_digest(authority.get("registry_digest"), "action adapter registry digest"),
                "schema_registry_id": require_id(authority.get("schema_registry_id"), "action adapter schema registry ID"),
                "schema_registry_digest": require_digest(authority.get("schema_registry_digest"), "action adapter schema registry digest"),
            })
            result = object.__new__(cls)
            for name, item in (
                ("policy_id", policy_id),
                ("real_external_actions_enabled", external_actions_enabled),
                ("separately_authorized_action_kinds", require_canonical_strings(value.get("separately_authorized_action_kinds"), "separate action kinds", ids=True)),
                ("enabled_adapter_capabilities", require_canonical_strings(value.get("enabled_adapter_capabilities"), "enabled adapter capabilities", ids=True)),
                ("required_gate_capabilities", require_canonical_strings(value.get("required_gate_capabilities"), "required gate capabilities", ids=True)),
                ("unknown_routes", require_canonical_strings(value.get("unknown_routes"), "unknown routes", ids=True)),
                ("concrete_action_authority", concrete_authority),
                ("policy_digest", expected),
                ("_schemas", schema_registry),
                ("_context", context),
                ("_runtime_issuer", runtime._issuer),
            ):
                object.__setattr__(result, name, item)
            required = {"commit", "push", "merge", "deploy", "release", "external-communication"}
            if not required.issubset(result.separately_authorized_action_kinds):
                raise ValueError("irreversible action classes are not separately configured")
            return result
        except (TypeError, ValueError) as error:
            raise ActionContractError(str(error)) from error

    def issue_action_adapter_installation(
        self,
        *,
        concrete_policy_id: str,
        concrete_policy_digest: str,
        registry_id: str,
        registry_digest: str,
        schema_registry_id: str,
        schema_registry_digest: str,
        runtime: SecurityRuntimeManifest,
    ) -> ActionAdapterInstallationAttestation:
        """Mint an opaque concrete-adapter authority from the installed policy pins."""

        candidate = {
            "policy_id": concrete_policy_id,
            "policy_digest": concrete_policy_digest,
            "registry_id": registry_id,
            "registry_digest": registry_digest,
            "schema_registry_id": schema_registry_id,
            "schema_registry_digest": schema_registry_digest,
        }
        if (
            type(runtime) is not SecurityRuntimeManifest
            or runtime._issuer is not self._runtime_issuer
            or dict(self.concrete_action_authority) != candidate
        ):
            raise ActionContractError("concrete action authority differs from installation pins")
        result = object.__new__(ActionAdapterInstallationAttestation)
        for name, item in (
            ("runtime_manifest_digest", runtime.manifest_digest),
            ("concrete_policy_id", concrete_policy_id),
            ("concrete_policy_digest", concrete_policy_digest),
            ("registry_id", registry_id),
            ("registry_digest", registry_digest),
            ("schema_registry_id", schema_registry_id),
            ("schema_registry_digest", schema_registry_digest),
            ("_issuer", self),
        ):
            object.__setattr__(result, name, item)
        return result

    def load_prepared(self, value: Mapping[str, object]) -> PreparedAction:
        if self._schemas.validate("urn:gew:schema:prepared-action:1.0.0", value, self._context):
            raise ActionContractError("prepared action schema validation failed")
        return PreparedAction.from_dict(value, context=self._context)

    def load_authority(self, value: Mapping[str, object]) -> AuthorityEnvelope:
        if self._schemas.validate("urn:gew:schema:authority-envelope:1.0.0", value, self._context):
            raise ActionContractError("authority envelope schema validation failed")
        return AuthorityEnvelope.from_dict(value, context=self._context)


def _digest(value: Mapping[str, object], field: str, name: str) -> str:
    return unsigned_digest(
        value,
        digest_field=field,
        contract_type=f"urn:gew:contract:{name}",
        schema_id=f"urn:gew:schema:{name}:1.0.0",
    )


def _digest_charged(
    value: Mapping[str, object],
    field: str,
    name: str,
    context: WorkContext,
) -> str:
    return semantic_digest_charged(
        {key: item for key, item in value.items() if key != field},
        context,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=IDENTITY_PROJECTION,
        schema_id=f"urn:gew:schema:{name}:1.0.0",
        operation_path=context.child_path(()),
    )


def _frozen_mapping(value: object, label: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be an exact object")
    frozen = freeze(copy.deepcopy(value))
    return MappingProxyType(dict(frozen.items()))  # type: ignore[union-attr]


@dataclass(frozen=True, slots=True)
class IntentBaseline:
    task_id: str
    baseline_digest: str
    approved_by: str
    approved_at: str
    record_digest: str

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _digest(value, "record_digest", "intent-baseline")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> IntentBaseline:
        try:
            exact_mapping(value, {"schema_version", "task_id", "baseline_digest", "approved_by", "approved_at", "record_digest"}, "intent baseline")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("intent baseline version is invalid")
            result = cls(
                require_id(value.get("task_id"), "task ID"),
                require_digest(value.get("baseline_digest"), "baseline digest"),
                require_id(value.get("approved_by"), "approver ID"),
                str(value.get("approved_at")),
                require_digest(value.get("record_digest"), "record digest"),
            )
            parse_timestamp(result.approved_at, "approval time")
            if not hmac.compare_digest(result.record_digest, cls.digest_document(value)):
                raise ValueError("intent baseline digest mismatch")
            return result
        except (TypeError, ValueError) as error:
            raise ActionContractError(str(error)) from error


@dataclass(frozen=True, slots=True)
class PreparedAction:
    action_id: str
    task_id: str
    action_kind: str
    target_id: str
    target_digest: str
    resources: tuple[str, ...]
    payload: Mapping[str, object]
    payload_digest: str
    precondition: Mapping[str, object]
    expected_postcondition: Mapping[str, object]
    idempotency_class: str
    idempotency_key: str
    verification_plan: Mapping[str, object]
    rollback_plan: Mapping[str, object]
    required_capabilities: tuple[str, ...]
    baseline_digest: str
    snapshot_digest: str
    prepared_action_digest: str

    FIELDS = frozenset({
        "schema_version", "action_id", "task_id", "action_kind", "target_id", "target_digest",
        "resources", "payload", "payload_digest", "precondition", "expected_postcondition",
        "idempotency_class", "idempotency_key", "verification_plan", "rollback_plan",
        "required_capabilities", "baseline_digest", "snapshot_digest", "prepared_action_digest",
    })

    @staticmethod
    def payload_digest_for(
        payload: Mapping[str, object],
        context: WorkContext,
    ) -> str:
        return semantic_digest_charged(
            payload,
            context,
            contract_type="urn:gew:contract:redacted-payload",
            projection_id=IDENTITY_PROJECTION,
            schema_id="urn:gew:schema:redacted-payload:1.0.0",
            operation_path=context.child_path(()),
        )

    @staticmethod
    def digest_document(
        value: Mapping[str, object],
        context: WorkContext,
    ) -> str:
        return _digest_charged(value, "prepared_action_digest", "prepared-action", context)

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        context: WorkContext,
    ) -> PreparedAction:
        try:
            exact_mapping(value, set(cls.FIELDS), "prepared action")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("prepared action version is invalid")
            payload = _frozen_mapping(value.get("payload"), "action payload")
            payload_digest = require_digest(value.get("payload_digest"), "payload digest")
            if not hmac.compare_digest(payload_digest, cls.payload_digest_for(payload, context)):
                raise ValueError("payload digest mismatch")
            idempotency = value.get("idempotency_class")
            if idempotency not in {"idempotent", "non-idempotent"}:
                raise ValueError("idempotency class is invalid")
            result = cls(
                require_id(value.get("action_id"), "action ID"),
                require_id(value.get("task_id"), "task ID"),
                require_id(value.get("action_kind"), "action kind"),
                require_id(value.get("target_id"), "target ID"),
                require_digest(value.get("target_digest"), "target digest"),
                require_canonical_strings(value.get("resources"), "resources", ids=True),
                payload,
                payload_digest,
                _frozen_mapping(value.get("precondition"), "precondition"),
                _frozen_mapping(value.get("expected_postcondition"), "postcondition"),
                str(idempotency),
                require_id(value.get("idempotency_key"), "idempotency key"),
                _frozen_mapping(value.get("verification_plan"), "verification plan"),
                _frozen_mapping(value.get("rollback_plan"), "rollback plan"),
                require_canonical_strings(value.get("required_capabilities"), "required capabilities", ids=True),
                require_digest(value.get("baseline_digest"), "baseline digest"),
                require_digest(value.get("snapshot_digest"), "snapshot digest"),
                require_digest(value.get("prepared_action_digest"), "prepared action digest"),
            )
            if not result.verification_plan or not result.rollback_plan:
                raise ValueError("verification and rollback plans are required")
            if not hmac.compare_digest(result.prepared_action_digest, cls.digest_document(value, context)):
                raise ValueError("prepared action digest mismatch")
            return result
        except (TypeError, ValueError) as error:
            raise ActionContractError(str(error)) from error


@dataclass(frozen=True, slots=True)
class AuthorityEnvelope:
    authority_id: str
    task_id: str
    owner_id: str
    runtime_kind: str
    runtime_lineage_id: str
    authorized_action_kind: str
    authorized_resources: tuple[str, ...]
    prepared_action_digest: str
    baseline_digest: str
    snapshot_digest: str
    issued_at: str
    expires_at: str
    status: str
    authority_digest: str

    FIELDS = frozenset({
        "schema_version", "authority_id", "task_id", "owner_id", "runtime_kind",
        "runtime_lineage_id", "authorized_action_kind", "authorized_resources",
        "prepared_action_digest", "baseline_digest", "snapshot_digest", "issued_at",
        "expires_at", "status", "authority_digest",
    })

    @staticmethod
    def digest_document(
        value: Mapping[str, object],
        context: WorkContext,
    ) -> str:
        return _digest_charged(value, "authority_digest", "authority-envelope", context)

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        context: WorkContext,
    ) -> AuthorityEnvelope:
        try:
            exact_mapping(value, set(cls.FIELDS), "authority envelope")
            if value.get("schema_version") != "1.0.0" or value.get("status") not in {"active", "revoked", "expired", "superseded"}:
                raise ValueError("authority version or status is invalid")
            result = cls(
                require_id(value.get("authority_id"), "authority ID"),
                require_id(value.get("task_id"), "task ID"),
                require_id(value.get("owner_id"), "owner ID"),
                require_id(value.get("runtime_kind"), "runtime kind"),
                require_id(value.get("runtime_lineage_id"), "runtime lineage"),
                require_id(value.get("authorized_action_kind"), "authorized action kind"),
                require_canonical_strings(value.get("authorized_resources"), "authorized resources", ids=True),
                require_digest(value.get("prepared_action_digest"), "prepared action digest"),
                require_digest(value.get("baseline_digest"), "baseline digest"),
                require_digest(value.get("snapshot_digest"), "snapshot digest"),
                str(value.get("issued_at")), str(value.get("expires_at")), str(value.get("status")),
                require_digest(value.get("authority_digest"), "authority digest"),
            )
            if parse_timestamp(result.issued_at, "authority issued time") >= parse_timestamp(result.expires_at, "authority expiry"):
                raise ValueError("authority expiry is not after issuance")
            if not hmac.compare_digest(result.authority_digest, cls.digest_document(value, context)):
                raise ValueError("authority digest mismatch")
            return result
        except (TypeError, ValueError) as error:
            raise ActionContractError(str(error)) from error


@dataclass(frozen=True, slots=True)
class ActionJournalRecord:
    action_id: str
    task_id: str
    state: str
    revision: int
    prepared: PreparedAction
    authority: AuthorityEnvelope | None
    receipt: Mapping[str, object] | None
    reconciliation: Mapping[str, object] | None
