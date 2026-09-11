from __future__ import annotations

import copy
import json
import pathlib
import unittest

from graph_engineering.adapters.action_adapters import (
    ActionAdapterFactory,
    ActionAdapterPorts,
    ActionAdapterRejection,
    _action_build_manifest_digest,
    builtin_implementation_digest,
)
from graph_engineering.core.action_adapters import (
    ActionAdapterRegistry,
    ActionInvocation,
    ConcreteActionPolicy,
)
from tests.contract.test_wp07a_action_contracts import digest, invocation_document
from tests.support.wp07a_actions import installed_action_adapter_attestation


ROOT = pathlib.Path(__file__).resolve().parents[2]


class _CounterPort:
    def __init__(self) -> None:
        self.calls = 0
        self.writes = 0

    def invoke(self, invocation: ActionInvocation, payload: dict[str, object]) -> dict[str, object]:
        del invocation, payload
        self.calls += 1
        self.writes += 1
        return {"result": "succeeded", "result_digest": digest("result")}


def factory() -> tuple[ActionAdapterFactory, _CounterPort]:
    registry = ActionAdapterRegistry.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
    ))
    policy = ConcreteActionPolicy.from_dict(
        json.loads((ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()),
        registry=registry,
    )
    counter = _CounterPort()
    return ActionAdapterFactory(
        policy,
        registry,
        installation_attestation=installed_action_adapter_attestation(),
    ), counter


class WP07AActionContractSecurityTests(unittest.TestCase):
    def test_gew_act_001a_only_factory_attested_closed_adapter_can_dispatch(self) -> None:
        issuer, counter = factory()
        adapter = issuer.issue("git-native-v1", ActionAdapterPorts(invoke=counter.invoke))
        self.assertIs(ActionAdapterFactory.require_attested(adapter), adapter)
        with self.assertRaises(ActionAdapterRejection):
            ActionAdapterFactory.require_attested(object())

    def test_gew_act_001b_installation_anchor_rejects_re_signed_registry_and_provenance_substitutions(self) -> None:
        manifest = (ROOT / "pyproject.toml").read_bytes()
        baseline = _action_build_manifest_digest(manifest)
        self.assertEqual(
            baseline,
            "29a9c70362f54779b52266701de1147813b9c8a42ecae42253dd4ffe3c1fa577",
        )
        registry_document = json.loads(
            (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
        )
        policy_document = json.loads(
            (ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()
        )
        registry = ActionAdapterRegistry.from_dict(registry_document)
        for entry in registry.entries:
            with self.subTest(
                provenance=entry.implementation_ref,
                historical_identity=entry.implementation_ref,
            ):
                self.assertEqual(
                    entry.implementation_digest,
                    builtin_implementation_digest(entry.implementation_ref),
                )
                self.assertGreater(len(set(entry.implementation_digest.removeprefix("sha256-jcs-v1:"))), 8)

        dependency_line = (
            b'dependencies = ["cryptography==50.0.0", "packaging==26.3"]'
        )
        dependency_added = manifest.replace(
            dependency_line,
            b'dependencies = ["cryptography==50.0.0", "packaging==26.3", "other==1.0"]',
        )
        dependency_replaced = dependency_added.replace(b"other==1.0", b"other==2.0")
        dependency_removed = dependency_added.replace(b', "other==1.0"', b"")
        self.assertNotEqual(_action_build_manifest_digest(dependency_added), baseline)
        self.assertNotEqual(
            _action_build_manifest_digest(dependency_replaced),
            _action_build_manifest_digest(dependency_added),
        )
        self.assertNotEqual(
            _action_build_manifest_digest(dependency_removed),
            _action_build_manifest_digest(dependency_added),
        )

        import_line = b'declared-external-imports = ["cryptography", "packaging"]'
        import_added = manifest.replace(
            import_line,
            b'declared-external-imports = ["cryptography", "packaging", "otherlib"]',
        )
        import_replaced = import_added.replace(b"otherlib", b"anotherlib")
        import_removed = import_added.replace(b', "otherlib"', b"")
        self.assertNotEqual(_action_build_manifest_digest(import_added), baseline)
        self.assertNotEqual(
            _action_build_manifest_digest(import_replaced),
            _action_build_manifest_digest(import_added),
        )
        self.assertNotEqual(
            _action_build_manifest_digest(import_removed),
            _action_build_manifest_digest(import_added),
        )

        for old, new in (
            (b"cryptography==50.0.0", b"cryptography==49.0.0"),
            (b"packaging==26.3", b"packaging-next==26.3"),
            (b'"cryptography", "packaging"', b'"cryptography2", "packaging"'),
            (b'"cryptography", "packaging"', b'"cryptography", "packaging2"'),
        ):
            with self.subTest(unexpected_wp08_member=new):
                with self.assertRaises(ActionAdapterRejection):
                    _action_build_manifest_digest(manifest.replace(old, new))

        build_mapping_changed = manifest.replace(
            b'"core/graph_engineering/core" = "graph_engineering.core"',
            b'"core/graph_engineering/core" = "graph_engineering.core.changed"',
        )
        entrypoint_changed = manifest.replace(
            b'graph-engineering = "graph_engineering.cli:main"',
            b'graph-engineering = "graph_engineering.cli:changed"',
        )
        self.assertNotEqual(_action_build_manifest_digest(build_mapping_changed), baseline)
        self.assertNotEqual(_action_build_manifest_digest(entrypoint_changed), baseline)

        for field in ("implementation_digest", "capabilities", "operation_ids"):
            with self.subTest(field=field):
                changed_registry = copy.deepcopy(registry_document)
                entry = changed_registry["entries"][0]
                if field == "implementation_digest":
                    entry[field] = digest("foreign-implementation")
                else:
                    substitution = "foreign-operation" if field == "operation_ids" else "foreign-capability"
                    entry[field] = sorted([*entry[field], substitution])
                changed_registry["registry_digest"] = ActionAdapterRegistry.digest_document(
                    changed_registry
                )
                foreign_registry = ActionAdapterRegistry.from_dict(changed_registry)
                changed_policy = copy.deepcopy(policy_document)
                changed_policy["registry_digest"] = foreign_registry.registry_digest
                if field == "operation_ids":
                    changed_policy["allowed_operation_ids"] = sorted([
                        *changed_policy["allowed_operation_ids"],
                        "foreign-operation",
                    ])
                changed_policy["policy_digest"] = ConcreteActionPolicy.digest_document(changed_policy)
                foreign_policy = ConcreteActionPolicy.from_dict(
                    changed_policy,
                    registry=foreign_registry,
                )
                with self.assertRaisesRegex(ActionAdapterRejection, "installation-attested"):
                    ActionAdapterFactory(
                        foreign_policy,
                        foreign_registry,
                        installation_attestation=installed_action_adapter_attestation(),
                    )

    def test_gew_act_002a_all_re_signed_binding_and_fence_substitutions_are_zero_call_zero_write(self) -> None:
        issuer, counter = factory()
        adapter = issuer.issue("git-native-v1", ActionAdapterPorts(invoke=counter.invoke))
        expected = ActionInvocation.from_dict(invocation_document())

        substitutions = list(ActionInvocation.binding_fields()) + [
            "resources-missing", "fences-missing", "fences-extra", "fences-reordered",
        ]
        for mutation in substitutions:
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(invocation_document())
                if mutation == "resources-missing":
                    assert isinstance(changed["resources"], list)
                    changed["resources"].pop()
                elif mutation.startswith("fences-"):
                    fences = changed["fencing_tokens"]
                    assert isinstance(fences, list)
                    if mutation == "fences-missing":
                        fences.pop()
                    elif mutation == "fences-extra":
                        fences.append({"resource_id": "target:other", "token": 1})
                    else:
                        fences.reverse()
                elif mutation != "invocation_digest":
                    changed[mutation] = digest(mutation) if mutation.endswith("_digest") else "substituted"
                changed["invocation_digest"] = ActionInvocation.digest_document(changed)
                if mutation == "invocation_digest":
                    changed["invocation_digest"] = digest(mutation)
                with self.assertRaises(ActionAdapterRejection):
                    adapter.dispatch(changed, expected=expected, payload={"operation": "noop"})
        self.assertEqual((counter.calls, counter.writes), (0, 0))

    def test_gew_act_003a_valid_dispatch_calls_the_exact_attested_port_once(self) -> None:
        issuer, counter = factory()
        adapter = issuer.issue("git-native-v1", ActionAdapterPorts(invoke=counter.invoke))
        expected = ActionInvocation.from_dict(invocation_document())
        result = adapter.dispatch(invocation_document(), expected=expected, payload={"operation": "noop"})
        self.assertEqual(result["result"], "succeeded")
        self.assertEqual((counter.calls, counter.writes), (1, 1))


if __name__ == "__main__":
    unittest.main()
