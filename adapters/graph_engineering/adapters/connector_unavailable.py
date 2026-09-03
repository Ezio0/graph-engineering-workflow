"""Stable no-network connector mismatch for unavailable v1 integrations."""

from __future__ import annotations

from graph_engineering.core.action_adapters import (
    ActionAdapterRegistryEntry,
    ConnectorCapabilityMismatch,
    ConnectorRegistry,
)


_FACTORY_SEAL = object()
_issued_connectors: dict[int, tuple[object, object]] = {}


class ConnectorUnavailable(RuntimeError):
    def __init__(self, mismatch: ConnectorCapabilityMismatch) -> None:
        super().__init__("connector capability is stably unavailable")
        self.mismatch = mismatch


class UnavailableConnectorAdapter:
    __slots__ = ("_entry", "_registry_digest", "_call_count")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("unavailable connectors are created only by ActionAdapterFactory")

    @classmethod
    def _issue(
        cls,
        registry_document: dict[str, object],
        connector_id: str,
        *,
        descriptor: ActionAdapterRegistryEntry,
    ) -> UnavailableConnectorAdapter:
        registry = ConnectorRegistry.from_dict(registry_document)
        entry = registry.entry(connector_id)
        if (
            type(descriptor) is not ActionAdapterRegistryEntry
            or descriptor.adapter_kind != "connector"
            or descriptor.implementation_ref != "builtin:connector-unavailable-v1"
            or entry.adapter_id != descriptor.adapter_id
        ):
            raise ValueError("unavailable connector factory binding changed")
        adapter = object.__new__(cls)
        adapter._entry = entry
        adapter._registry_digest = registry.registry_digest
        adapter._call_count = 0
        _issued_connectors[id(adapter)] = (adapter, _FACTORY_SEAL)
        return adapter

    @staticmethod
    def require_attested(adapter: object) -> UnavailableConnectorAdapter:
        issued = _issued_connectors.get(id(adapter))
        if issued is None or issued[0] is not adapter or issued[1] is not _FACTORY_SEAL:
            raise ValueError("unavailable connector is not factory-attested")
        return adapter  # type: ignore[return-value]

    @property
    def call_count(self) -> int:
        return self._call_count

    def require_capability(
        self,
        *,
        task_id: str,
        action_id: str,
        capability: str,
    ) -> None:
        from graph_engineering.adapters.action_adapters import ActionAdapterRejection

        self.require_attested(self)
        if capability not in self._entry.declared_capabilities:
            raise ActionAdapterRejection("connector capability is not declared")
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "action_id": action_id,
            "connector_id": self._entry.connector_id,
            "adapter_id": self._entry.adapter_id,
            "capability": capability,
            "status": self._entry.status,
            "reason_code": self._entry.reason_code,
            "retryable": self._entry.retryable,
            "registry_digest": self._registry_digest,
        }
        body["mismatch_digest"] = ConnectorCapabilityMismatch.digest_document(body)
        raise ConnectorUnavailable(ConnectorCapabilityMismatch.from_dict(body))
