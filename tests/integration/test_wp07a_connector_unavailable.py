from __future__ import annotations

import copy
import json
import pathlib
import unittest

from graph_engineering.adapters.action_adapters import ActionAdapterFactory, ActionAdapterRejection
from graph_engineering.adapters.connector_unavailable import ConnectorUnavailable
from graph_engineering.core.action_adapters import (
    ActionAdapterRegistry,
    ConcreteActionPolicy,
    ConnectorCapabilityMismatch,
    ConnectorRegistry,
)
from tests.support.wp07a_actions import installed_action_adapter_attestation


ROOT = pathlib.Path(__file__).resolve().parents[2]


def registry_document() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "registry_id": "connector-registry-default",
        "entries": [{
            "connector_id": "remote-project-host",
            "adapter_id": "connector-unavailable-v1",
            "status": "unavailable",
            "declared_capabilities": ["remote-read", "remote-write"],
            "reason_code": "connector-not-installed",
            "retryable": False,
        }],
    }
    body["registry_digest"] = ConnectorRegistry.digest_document(body)
    return body


def factory(document: dict[str, object]) -> ActionAdapterFactory:
    adapter_registry = ActionAdapterRegistry.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
    ))
    policy = ConcreteActionPolicy.from_dict(
        json.loads((ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()),
        registry=adapter_registry,
    )
    return ActionAdapterFactory(
        policy,
        adapter_registry,
        installation_attestation=installed_action_adapter_attestation(),
        configuration_digests={"connector-registry": document["registry_digest"]},  # type: ignore[dict-item]
    )


class WP07AUnavailableConnectorTests(unittest.TestCase):
    def test_gew_act_009_unavailable_connector_returns_stable_self_digested_mismatch_without_port(self) -> None:
        document = registry_document()
        adapter = factory(document).issue_unavailable_connector(document, "remote-project-host")
        for capability in ("remote-read", "remote-write"):
            with self.subTest(capability=capability), self.assertRaises(ConnectorUnavailable) as raised:
                adapter.require_capability(
                    task_id="task-wp07a",
                    action_id="action-wp07a",
                    capability=capability,
                )
            mismatch = raised.exception.mismatch
            self.assertIsInstance(mismatch, ConnectorCapabilityMismatch)
            self.assertEqual(mismatch.capability, capability)
            self.assertEqual(mismatch.reason_code, "connector-not-installed")
            self.assertFalse(mismatch.retryable)
            self.assertEqual(
                ConnectorCapabilityMismatch.from_dict(mismatch.to_dict()),
                mismatch,
            )
        self.assertEqual(adapter.call_count, 0)

    def test_gew_act_009a_unknown_capability_and_re_signed_unpinned_registry_fail_closed(self) -> None:
        document = registry_document()
        action_factory = factory(document)
        adapter = action_factory.issue_unavailable_connector(document, "remote-project-host")
        with self.assertRaises(ActionAdapterRejection):
            adapter.require_capability(
                task_id="task-wp07a",
                action_id="action-wp07a",
                capability="foreign-capability",
            )
        changed = copy.deepcopy(document)
        changed["entries"][0]["reason_code"] = "foreign-reason"  # type: ignore[index]
        changed["registry_digest"] = ConnectorRegistry.digest_document(changed)
        with self.assertRaises(ActionAdapterRejection):
            action_factory.issue_unavailable_connector(changed, "remote-project-host")
        self.assertEqual(adapter.call_count, 0)


if __name__ == "__main__":
    unittest.main()
