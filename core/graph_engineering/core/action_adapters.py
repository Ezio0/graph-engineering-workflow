"""Platform-neutral contracts for concrete local action adapters."""

from __future__ import annotations

import hmac
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest


IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
_ID = re.compile(r"[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


class ActionAdapterContractError(ValueError):
    """A concrete action adapter record is malformed or digest-inconsistent."""


def _record(value: object, fields: frozenset[str], label: str) -> Mapping[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise ActionAdapterContractError(f"{label} record is not exact")
    return value


def _identity(value: object, label: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ActionAdapterContractError(f"{label} is invalid")
    return value


def _version(value: object, label: str) -> str:
    if type(value) is not str or _VERSION.fullmatch(value) is None:
        raise ActionAdapterContractError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise ActionAdapterContractError(f"{label} is invalid")
    return value


def _identities(value: object, label: str, *, sorted_values: bool = True) -> tuple[str, ...]:
    if type(value) is not list or not value:
        raise ActionAdapterContractError(f"{label} must be a non-empty array")
    result = tuple(_identity(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ActionAdapterContractError(f"{label} contains a duplicate")
    if sorted_values and result != tuple(sorted(result)):
        raise ActionAdapterContractError(f"{label} is not canonical")
    return result


def _record_digest(name: str, body: Mapping[str, object]) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=IDENTITY_PROJECTION,
        schema_id=f"urn:gew:schema:{name}:1.0.0",
    )


def _self_digest(value: Mapping[str, object], field: str, name: str) -> str:
    expected = _digest(value[field], field)
    actual = _record_digest(name, {key: item for key, item in value.items() if key != field})
    if not hmac.compare_digest(expected, actual):
        raise ActionAdapterContractError(f"{name} digest mismatch")
    return expected


@dataclass(frozen=True, slots=True)
class ActionAdapterRegistryEntry:
    adapter_id: str
    adapter_kind: str
    adapter_version: str
    capabilities: tuple[str, ...]
    operation_ids: tuple[str, ...]
    implementation_ref: str
    implementation_digest: str

    FIELDS = frozenset({
        "adapter_id", "adapter_kind", "adapter_version", "capabilities",
        "operation_ids", "implementation_ref", "implementation_digest",
    })

    @classmethod
    def from_dict(cls, value: object) -> ActionAdapterRegistryEntry:
        row = _record(value, cls.FIELDS, "action adapter registry entry")
        return cls(
            _identity(row["adapter_id"], "adapter ID"),
            _identity(row["adapter_kind"], "adapter kind"),
            _version(row["adapter_version"], "adapter version"),
            _identities(row["capabilities"], "adapter capabilities"),
            _identities(row["operation_ids"], "adapter operations"),
            _identity(row["implementation_ref"], "implementation ref"),
            _digest(row["implementation_digest"], "implementation digest"),
        )


@dataclass(frozen=True, slots=True)
class ActionAdapterRegistry:
    schema_version: str
    registry_id: str
    protocol_version: str
    entries: tuple[ActionAdapterRegistryEntry, ...]
    registry_digest: str

    FIELDS = frozenset({
        "schema_version", "registry_id", "protocol_version", "entries", "registry_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "action-adapter-registry",
            {key: item for key, item in value.items() if key != "registry_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> ActionAdapterRegistry:
        row = _record(value, cls.FIELDS, "action adapter registry")
        raw_entries = row["entries"]
        if type(raw_entries) is not list or not raw_entries:
            raise ActionAdapterContractError("action adapter registry entries are invalid")
        entries = tuple(ActionAdapterRegistryEntry.from_dict(item) for item in raw_entries)
        adapter_ids = tuple(entry.adapter_id for entry in entries)
        adapter_kinds = tuple(entry.adapter_kind for entry in entries)
        operations = tuple(operation for entry in entries for operation in entry.operation_ids)
        if len(set(adapter_ids)) != len(adapter_ids):
            raise ActionAdapterContractError("action adapter ID is not unique")
        if len(set(adapter_kinds)) != len(adapter_kinds):
            raise ActionAdapterContractError("action adapter kind is not unique")
        if len(set(operations)) != len(operations):
            raise ActionAdapterContractError("action operation is not uniquely owned")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["registry_id"], "registry ID"),
            _version(row["protocol_version"], "protocol version"),
            entries,
            _self_digest(row, "registry_digest", "action-adapter-registry"),
        )

    def entry(self, adapter_id: str) -> ActionAdapterRegistryEntry:
        matches = tuple(entry for entry in self.entries if entry.adapter_id == adapter_id)
        if len(matches) != 1:
            raise ActionAdapterContractError("action adapter is not in the closed registry")
        return matches[0]


@dataclass(frozen=True, slots=True)
class ConcreteActionPolicy:
    schema_version: str
    policy_id: str
    protocol_version: str
    registry_id: str
    registry_digest: str
    real_local_actions_enabled: bool
    allowed_adapter_ids: tuple[str, ...]
    allowed_operation_ids: tuple[str, ...]
    required_invocation_bindings: tuple[str, ...]
    secret_handling: str
    launcher_mode: str
    policy_digest: str

    FIELDS = frozenset({
        "schema_version", "policy_id", "protocol_version", "registry_id",
        "registry_digest", "real_local_actions_enabled", "allowed_adapter_ids",
        "allowed_operation_ids", "required_invocation_bindings", "secret_handling",
        "launcher_mode", "policy_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "concrete-action-policy",
            {key: item for key, item in value.items() if key != "policy_digest"},
        )

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        registry: ActionAdapterRegistry,
    ) -> ConcreteActionPolicy:
        row = _record(value, cls.FIELDS, "concrete action policy")
        if type(registry) is not ActionAdapterRegistry:
            raise ActionAdapterContractError("concrete action registry is missing or forged")
        enabled = row["real_local_actions_enabled"]
        if type(enabled) is not bool or enabled is not True:
            raise ActionAdapterContractError("concrete local actions are not enabled by policy")
        result = cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["policy_id"], "policy ID"),
            _version(row["protocol_version"], "protocol version"),
            _identity(row["registry_id"], "registry ID"),
            _digest(row["registry_digest"], "registry digest"),
            enabled,
            _identities(row["allowed_adapter_ids"], "allowed adapter IDs"),
            _identities(row["allowed_operation_ids"], "allowed operation IDs"),
            _identities(row["required_invocation_bindings"], "required invocation bindings"),
            _identity(row["secret_handling"], "secret handling"),
            _identity(row["launcher_mode"], "launcher mode"),
            _self_digest(row, "policy_digest", "concrete-action-policy"),
        )
        if result.registry_id != registry.registry_id or not hmac.compare_digest(
            result.registry_digest, registry.registry_digest
        ):
            raise ActionAdapterContractError("concrete action policy registry binding changed")
        registered_adapters = tuple(sorted(entry.adapter_id for entry in registry.entries))
        registered_operations = tuple(sorted(
            operation for entry in registry.entries for operation in entry.operation_ids
        ))
        if result.allowed_adapter_ids != registered_adapters:
            raise ActionAdapterContractError("concrete action policy adapter closure is not exact")
        if result.allowed_operation_ids != registered_operations:
            raise ActionAdapterContractError("concrete action policy operation closure is not exact")
        return result


def _fencing_tuple(value: object) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list or not value:
        raise ActionAdapterContractError("fencing tokens must be a non-empty array")
    result: list[Mapping[str, object]] = []
    for item in value:
        row = _record(item, frozenset({"resource_id", "token"}), "fencing token")
        token = row["token"]
        if type(token) is not int or token <= 0:
            raise ActionAdapterContractError("fencing token is invalid")
        result.append(MappingProxyType({
            "resource_id": _identity(row["resource_id"], "fence resource ID"),
            "token": token,
        }))
    return tuple(result)


def _validate_resources_and_fences(
    resources_value: object,
    fences_value: object,
) -> tuple[tuple[str, ...], tuple[Mapping[str, object], ...]]:
    resources = _identities(resources_value, "action resources")
    fences = _fencing_tuple(fences_value)
    if tuple(item["resource_id"] for item in fences) != resources:
        raise ActionAdapterContractError("fencing tokens do not exactly cover ordered resources")
    return resources, fences


@dataclass(frozen=True, slots=True)
class ActionInvocation:
    schema_version: str
    invocation_id: str
    task_id: str
    action_id: str
    prepared_action_digest: str
    authority_digest: str
    adapter_id: str
    operation_id: str
    target_id: str
    target_digest: str
    resources: tuple[str, ...]
    lease_id: str
    fencing_tokens: tuple[Mapping[str, object], ...]
    idempotency_class: str
    idempotency_key: str
    payload_digest: str
    disclosure_plan_digest: str
    invocation_digest: str

    FIELDS = frozenset({
        "schema_version", "invocation_id", "task_id", "action_id",
        "prepared_action_digest", "authority_digest", "adapter_id", "operation_id",
        "target_id", "target_digest", "resources", "lease_id", "fencing_tokens",
        "idempotency_class", "idempotency_key", "payload_digest",
        "disclosure_plan_digest", "invocation_digest",
    })

    @staticmethod
    def payload_digest_for(payload: Mapping[str, object]) -> str:
        if type(payload) is not dict:
            raise ActionAdapterContractError("action payload must be an exact object")
        return semantic_digest(
            payload,
            contract_type="urn:gew:contract:redacted-payload",
            projection_id=IDENTITY_PROJECTION,
            schema_id="urn:gew:schema:redacted-payload:1.0.0",
        )

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "action-invocation",
            {key: item for key, item in value.items() if key != "invocation_digest"},
        )

    @staticmethod
    def binding_fields() -> tuple[str, ...]:
        return (
            "invocation_id", "task_id", "action_id", "prepared_action_digest",
            "authority_digest", "adapter_id", "operation_id", "target_id",
            "target_digest", "lease_id", "idempotency_class", "idempotency_key", "payload_digest",
            "disclosure_plan_digest", "invocation_digest",
        )

    @classmethod
    def from_dict(cls, value: object) -> ActionInvocation:
        row = _record(value, cls.FIELDS, "action invocation")
        resources, fences = _validate_resources_and_fences(row["resources"], row["fencing_tokens"])
        idempotency = row["idempotency_class"]
        if idempotency not in {"idempotent", "non-idempotent"}:
            raise ActionAdapterContractError("action invocation idempotency class is invalid")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["invocation_id"], "invocation ID"),
            _identity(row["task_id"], "task ID"),
            _identity(row["action_id"], "action ID"),
            _digest(row["prepared_action_digest"], "prepared action digest"),
            _digest(row["authority_digest"], "authority digest"),
            _identity(row["adapter_id"], "adapter ID"),
            _identity(row["operation_id"], "operation ID"),
            _identity(row["target_id"], "target ID"),
            _digest(row["target_digest"], "target digest"),
            resources,
            _identity(row["lease_id"], "lease ID"),
            fences,
            str(idempotency),
            _identity(row["idempotency_key"], "idempotency key"),
            _digest(row["payload_digest"], "payload digest"),
            _digest(row["disclosure_plan_digest"], "disclosure plan digest"),
            _self_digest(row, "invocation_digest", "action-invocation"),
        )


_INVOCATION_BINDING_FIELDS = (
    "invocation_id", "invocation_digest", "task_id", "action_id",
    "prepared_action_digest", "authority_digest", "adapter_id", "operation_id",
    "target_id", "target_digest", "resources", "lease_id", "fencing_tokens",
    "idempotency_class", "idempotency_key",
)


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    schema_version: str
    receipt_id: str
    invocation_id: str
    invocation_digest: str
    task_id: str
    action_id: str
    prepared_action_digest: str
    authority_digest: str
    adapter_id: str
    operation_id: str
    target_id: str
    target_digest: str
    resources: tuple[str, ...]
    lease_id: str
    fencing_tokens: tuple[Mapping[str, object], ...]
    idempotency_class: str
    idempotency_key: str
    result: str
    result_digest: str
    receipt_source: str
    receipt_digest: str

    FIELDS = frozenset({
        "schema_version", "receipt_id", "invocation_id", "invocation_digest", "task_id",
        "action_id", "prepared_action_digest", "authority_digest", "adapter_id",
        "operation_id", "target_id", "target_digest", "resources", "lease_id", "fencing_tokens",
        "idempotency_class", "idempotency_key", "result", "result_digest",
        "receipt_source", "receipt_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "action-receipt",
            {key: item for key, item in value.items() if key != "receipt_digest"},
        )

    @staticmethod
    def invocation_binding_fields() -> tuple[str, ...]:
        return _INVOCATION_BINDING_FIELDS

    @classmethod
    def from_dict(cls, value: object) -> ActionReceipt:
        row = _record(value, cls.FIELDS, "action receipt")
        resources, fences = _validate_resources_and_fences(row["resources"], row["fencing_tokens"])
        idempotency = row["idempotency_class"]
        if idempotency not in {"idempotent", "non-idempotent"}:
            raise ActionAdapterContractError("action receipt idempotency class is invalid")
        result = row["result"]
        if result not in {"succeeded", "failed", "unknown", "blocked"}:
            raise ActionAdapterContractError("action receipt result is invalid")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["receipt_id"], "receipt ID"),
            _identity(row["invocation_id"], "invocation ID"),
            _digest(row["invocation_digest"], "invocation digest"),
            _identity(row["task_id"], "task ID"),
            _identity(row["action_id"], "action ID"),
            _digest(row["prepared_action_digest"], "prepared action digest"),
            _digest(row["authority_digest"], "authority digest"),
            _identity(row["adapter_id"], "adapter ID"),
            _identity(row["operation_id"], "operation ID"),
            _identity(row["target_id"], "target ID"),
            _digest(row["target_digest"], "target digest"),
            resources,
            _identity(row["lease_id"], "lease ID"),
            fences,
            str(idempotency),
            _identity(row["idempotency_key"], "idempotency key"),
            str(result),
            _digest(row["result_digest"], "result digest"),
            _identity(row["receipt_source"], "receipt source"),
            _self_digest(row, "receipt_digest", "action-receipt"),
        )

    def require_invocation(self, invocation: ActionInvocation) -> None:
        if type(invocation) is not ActionInvocation:
            raise ActionAdapterContractError("action invocation binding is missing or forged")
        if any(getattr(self, field) != getattr(invocation, field) for field in _INVOCATION_BINDING_FIELDS):
            raise ActionAdapterContractError("action receipt invocation binding changed")


_RECEIPT_BINDING_FIELDS = (
    "receipt_id", "receipt_digest", "invocation_id", "invocation_digest", "task_id",
    "action_id", "prepared_action_digest", "authority_digest", "adapter_id", "operation_id",
    "target_id", "target_digest", "resources", "lease_id", "fencing_tokens",
)


@dataclass(frozen=True, slots=True)
class TargetObservation:
    schema_version: str
    observation_id: str
    receipt_id: str
    receipt_digest: str
    invocation_id: str
    invocation_digest: str
    task_id: str
    action_id: str
    prepared_action_digest: str
    authority_digest: str
    adapter_id: str
    operation_id: str
    target_id: str
    target_digest: str
    resources: tuple[str, ...]
    lease_id: str
    fencing_tokens: tuple[Mapping[str, object], ...]
    fresh: bool
    observation_revision: int
    observed_state_digest: str
    observation_digest: str

    FIELDS = frozenset({
        "schema_version", "observation_id", "receipt_id", "receipt_digest",
        "invocation_id", "invocation_digest", "task_id", "action_id",
        "prepared_action_digest", "authority_digest", "adapter_id", "operation_id",
        "target_id", "target_digest", "resources", "lease_id", "fencing_tokens", "fresh",
        "observation_revision", "observed_state_digest", "observation_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "target-observation",
            {key: item for key, item in value.items() if key != "observation_digest"},
        )

    @staticmethod
    def receipt_binding_fields() -> tuple[str, ...]:
        return _RECEIPT_BINDING_FIELDS

    @classmethod
    def from_dict(cls, value: object) -> TargetObservation:
        row = _record(value, cls.FIELDS, "target observation")
        resources, fences = _validate_resources_and_fences(row["resources"], row["fencing_tokens"])
        if row["fresh"] is not True:
            raise ActionAdapterContractError("target observation is not fresh")
        revision = row["observation_revision"]
        if type(revision) is not int or revision <= 0:
            raise ActionAdapterContractError("target observation revision is invalid")
        return cls(
            _version(row["schema_version"], "schema version"),
            _identity(row["observation_id"], "observation ID"),
            _identity(row["receipt_id"], "receipt ID"),
            _digest(row["receipt_digest"], "receipt digest"),
            _identity(row["invocation_id"], "invocation ID"),
            _digest(row["invocation_digest"], "invocation digest"),
            _identity(row["task_id"], "task ID"),
            _identity(row["action_id"], "action ID"),
            _digest(row["prepared_action_digest"], "prepared action digest"),
            _digest(row["authority_digest"], "authority digest"),
            _identity(row["adapter_id"], "adapter ID"),
            _identity(row["operation_id"], "operation ID"),
            _identity(row["target_id"], "target ID"),
            _digest(row["target_digest"], "target digest"),
            resources,
            _identity(row["lease_id"], "lease ID"),
            fences,
            True,
            revision,
            _digest(row["observed_state_digest"], "observed state digest"),
            _self_digest(row, "observation_digest", "target-observation"),
        )

    def require_receipt(self, receipt: ActionReceipt) -> None:
        if type(receipt) is not ActionReceipt:
            raise ActionAdapterContractError("action receipt binding is missing or forged")
        if any(getattr(self, field) != getattr(receipt, field) for field in _RECEIPT_BINDING_FIELDS):
            raise ActionAdapterContractError("target observation receipt binding changed")


@dataclass(frozen=True, slots=True)
class ConnectorRegistryEntry:
    connector_id: str
    adapter_id: str
    status: str
    declared_capabilities: tuple[str, ...]
    reason_code: str
    retryable: bool


@dataclass(frozen=True, slots=True)
class ConnectorRegistry:
    schema_version: str
    registry_id: str
    entries: tuple[ConnectorRegistryEntry, ...]
    registry_digest: str

    FIELDS = frozenset({"schema_version", "registry_id", "entries", "registry_digest"})

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "connector-registry",
            {key: item for key, item in value.items() if key != "registry_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> ConnectorRegistry:
        row = _record(value, cls.FIELDS, "connector registry")
        raw_entries = row["entries"]
        if row["schema_version"] != "1.0.0" or type(raw_entries) is not list or not raw_entries:
            raise ActionAdapterContractError("connector registry value is invalid")
        entries: list[ConnectorRegistryEntry] = []
        fields = frozenset({
            "connector_id", "adapter_id", "status", "declared_capabilities",
            "reason_code", "retryable",
        })
        for raw in raw_entries:
            item = _record(raw, fields, "connector registry entry")
            if item["status"] != "unavailable" or item["retryable"] is not False:
                raise ActionAdapterContractError("v1 connector registry must fail stably unavailable")
            entries.append(ConnectorRegistryEntry(
                _identity(item["connector_id"], "connector ID"),
                _identity(item["adapter_id"], "connector adapter ID"),
                "unavailable",
                _identities(item["declared_capabilities"], "connector capabilities"),
                _identity(item["reason_code"], "connector reason code"),
                False,
            ))
        connector_ids = tuple(entry.connector_id for entry in entries)
        if connector_ids != tuple(sorted(set(connector_ids))):
            raise ActionAdapterContractError("connector registry entries are not canonical")
        return cls(
            "1.0.0",
            _identity(row["registry_id"], "connector registry ID"),
            tuple(entries),
            _self_digest(row, "registry_digest", "connector-registry"),
        )

    def entry(self, connector_id: str) -> ConnectorRegistryEntry:
        matches = tuple(entry for entry in self.entries if entry.connector_id == connector_id)
        if len(matches) != 1:
            raise ActionAdapterContractError("connector is not in the closed registry")
        return matches[0]


@dataclass(frozen=True, slots=True)
class ConnectorCapabilityMismatch:
    schema_version: str
    task_id: str
    action_id: str
    connector_id: str
    adapter_id: str
    capability: str
    status: str
    reason_code: str
    retryable: bool
    registry_digest: str
    mismatch_digest: str

    FIELDS = frozenset({
        "schema_version", "task_id", "action_id", "connector_id", "adapter_id",
        "capability", "status", "reason_code", "retryable", "registry_digest",
        "mismatch_digest",
    })

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return _record_digest(
            "connector-capability-mismatch",
            {key: item for key, item in value.items() if key != "mismatch_digest"},
        )

    @classmethod
    def from_dict(cls, value: object) -> ConnectorCapabilityMismatch:
        row = _record(value, cls.FIELDS, "connector capability mismatch")
        if (
            row["schema_version"] != "1.0.0"
            or row["status"] != "unavailable"
            or row["retryable"] is not False
        ):
            raise ActionAdapterContractError("connector capability mismatch value is invalid")
        return cls(
            "1.0.0",
            _identity(row["task_id"], "connector mismatch task ID"),
            _identity(row["action_id"], "connector mismatch action ID"),
            _identity(row["connector_id"], "connector mismatch connector ID"),
            _identity(row["adapter_id"], "connector mismatch adapter ID"),
            _identity(row["capability"], "connector mismatch capability"),
            "unavailable",
            _identity(row["reason_code"], "connector mismatch reason code"),
            False,
            _digest(row["registry_digest"], "connector registry digest"),
            _self_digest(row, "mismatch_digest", "connector-capability-mismatch"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "action_id": self.action_id,
            "connector_id": self.connector_id,
            "adapter_id": self.adapter_id,
            "capability": self.capability,
            "status": self.status,
            "reason_code": self.reason_code,
            "retryable": self.retryable,
            "registry_digest": self.registry_digest,
            "mismatch_digest": self.mismatch_digest,
        }
