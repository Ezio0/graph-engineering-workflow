"""WP-08A deterministic data extension materialization (GEW-EXT-017..019)."""

from __future__ import annotations

import json
import unittest

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from tests.integration.test_wp08a_extension_activation import (
    _activate,
    _activation_request,
    _environment,
    _install,
    _points,
)
from tests.support.wp08a_extension_bundle import DIGEST, valid_bundle


INVARIANT_BODY: dict[str, object] = {
    "schema_version": "1.0.0",
    "invariant_set_id": "gew-core-invariants-v1",
    "invariant_ids": [
        "authority-monotonicity",
        "built-in-identity-integrity",
        "canonical-digest-integrity",
        "completion-truth",
        "lease-fence-claim-safety",
    ],
    "allowed_security_effects": ["constrain-only"],
}


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


INVARIANT_DIGEST = _digest(INVARIANT_BODY, "extension-core-invariant-set")


def _record(
    kind: str,
    identity: str,
    body: dict[str, object],
    *,
    dependencies: list[dict[str, str]] | None = None,
    security_effect: str = "constrain-only",
) -> dict[str, object]:
    source: dict[str, object] = {
        "schema_version": "1.0.0",
        "data_kind": kind,
        "identity_id": identity,
        "data_version": "1.0.0",
        "dependencies": sorted(dependencies or [], key=canonical_bytes),
        "core_invariant_set_digest": INVARIANT_DIGEST,
        "security_effect": security_effect,
        "body": body,
    }
    return {**source, "record_digest": _digest(source, f"extension-data-{kind}")}


def _records() -> list[dict[str, object]]:
    node = _record(
        "node",
        "extension.node",
        {
            "node_semantics": "declarative-only",
            "input_schema_id": "urn:gew:schema:input-example:1.0.0",
            "output_schema_id": "urn:gew:schema:output-example:1.0.0",
            "invalidation_tags": ["implementation"],
        },
    )
    template = _record(
        "template",
        "extension.template",
        {
            "template_schema_id": "urn:gew:schema:template-example:1.0.0",
            "template_text": "deterministic fixture",
        },
    )
    policy = _record(
        "policy",
        "extension.policy",
        {"policy_effect": "constrain-only", "rule_ids": ["rule.require-review"]},
        dependencies=[{"kind": "node", "id": "extension.node"}],
    )
    edge = _record(
        "edge",
        "extension.edge",
        {
            "source_id": "extension.node",
            "target_id": "extension.node",
            "edge_type": "typed-data",
            "condition_ref": None,
            "invalidation_mode": "descendants",
        },
        dependencies=[{"kind": "node", "id": "extension.node"}],
    )
    return [node, edge, policy, template]


class ExtensionDataMaterializationTests(unittest.TestCase):
    def test_gew_ext_017_four_data_kinds_decode_and_materialize_exact_closed_registry(self) -> None:
        records = _records()
        points = _points(*((str(item["data_kind"]), str(item["identity_id"])) for item in records))
        with _environment(points=points, data_records=records) as environment:
            receipt = _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.data.1"
                ),
            )
            self.assertEqual(receipt.categories, ("edge", "node", "policy", "template"))
            registry = environment.activation.snapshot().data_registry
            self.assertEqual(
                [(item["kind"], item["id"]) for item in registry["entries"]],
                [("edge", "extension.edge"), ("node", "extension.node"),
                 ("policy", "extension.policy"), ("template", "extension.template")],
            )
            self.assertEqual(
                registry["resolution_order"],
                [
                    next(item["record_digest"] for item in records if item["identity_id"] == identity)
                    for identity in (
                        "extension.node", "extension.edge", "extension.policy",
                        "extension.template",
                    )
                ],
            )
            self.assertEqual(registry["activation_id"], receipt.activation_id)

        malformed = _record(
            "template", "extension.malformed",
            {
                "template_schema_id": "urn:gew:schema:template-example:1.0.0",
                "template_text": "malformed fixture",
            },
        )
        malformed["unexpected"] = "self-consistent-but-not-closed"
        malformed.pop("record_digest")
        malformed["record_digest"] = _digest(
            {key: value for key, value in malformed.items() if key != "record_digest"},
            "extension-data-template",
        )
        with _environment(
            points=_points(("template", "extension.malformed")),
            data_records=[malformed],
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_DATA_RECORD"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.malformed"
                    ),
                )
            self.assertEqual(
                (environment.activation.snapshot().activations,
                 environment.activation.snapshot().data_registry),
                ((), None),
            )

    def test_gew_ext_018_dependency_missing_cycle_and_registry_conflict_roll_back_atomically(self) -> None:
        missing = _record(
            "policy", "extension.policy",
            {"policy_effect": "constrain-only", "rule_ids": ["rule.one"]},
            dependencies=[{"kind": "node", "id": "extension.missing"}],
        )
        with _environment(
            points=_points(("policy", "extension.policy")), data_records=[missing]
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_DEPENDENCY"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.missing"
                    ),
                )
            snapshot = environment.activation.snapshot()
            self.assertEqual((snapshot.activations, snapshot.data_registry), ((), None))

        dangling_edge = _record(
            "edge", "extension.dangling-edge",
            {
                "source_id": "core.task-runner",
                "target_id": "extension.missing-target",
                "edge_type": "typed-data",
                "condition_ref": None,
                "invalidation_mode": "descendants",
            },
            dependencies=[{"kind": "node", "id": "core.task-runner"}],
        )
        with _environment(
            points=_points(("edge", "extension.dangling-edge")),
            data_records=[dangling_edge],
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_DEPENDENCY"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.dangling-edge"
                    ),
                )
            self.assertIsNone(environment.activation.snapshot().data_registry)

        left = _record(
            "policy", "extension.left",
            {"policy_effect": "constrain-only", "rule_ids": ["rule.left"]},
            dependencies=[{"kind": "policy", "id": "extension.right"}],
        )
        right = _record(
            "policy", "extension.right",
            {"policy_effect": "constrain-only", "rule_ids": ["rule.right"]},
            dependencies=[{"kind": "policy", "id": "extension.left"}],
        )
        with _environment(
            points=_points(
                ("policy", "extension.left"), ("policy", "extension.right")
            ),
            data_records=[left, right],
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_DEPENDENCY"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.cycle"
                    ),
                )
            self.assertIsNone(environment.activation.snapshot().data_registry)

        shared = _record(
            "node", "extension.shared",
            {
                "node_semantics": "declarative-only",
                "input_schema_id": "urn:gew:schema:input-example:1.0.0",
                "output_schema_id": "urn:gew:schema:output-example:1.0.0",
                "invalidation_tags": [],
            },
        )
        with _environment(
            points=_points(("node", "extension.shared")), data_records=[shared],
            extension_id="extension.one",
        ) as environment:
            _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.shared.one"
                ),
            )
            second = _install(
                environment,
                valid_bundle(
                    extension_id="extension.two",
                    extension_points=_points(("node", "extension.shared")),
                    exported_identities=_points(("node", "extension.shared")),
                    data_records=[shared],
                )[0],
            )
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_REGISTRY_CONFLICT"):
                _activate(
                    environment,
                    _activation_request(environment, second, "activation.shared.two"),
                )
            snapshot = environment.activation.snapshot()
            self.assertEqual(len(snapshot.activations), 1)
            self.assertEqual(snapshot.data_registry["extension_id"], "extension.one")

    def test_gew_ext_019_invariant_or_builtin_override_rejects_and_restart_rematerializes_bytes(self) -> None:
        weakened = _record(
            "policy", "extension.policy",
            {"policy_effect": "allow", "rule_ids": ["rule.weaken"]},
            security_effect="allow",
        )
        with _environment(
            points=_points(("policy", "extension.policy")), data_records=[weakened]
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_CORE_INVARIANT"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.weaken"
                    ),
                )
            self.assertIsNone(environment.activation.snapshot().data_registry)

        built_in = _record(
            "node", "core.task-runner",
            {
                "node_semantics": "declarative-only",
                "input_schema_id": "urn:gew:schema:input-example:1.0.0",
                "output_schema_id": "urn:gew:schema:output-example:1.0.0",
                "invalidation_tags": [],
            },
        )
        with _environment(
            points=_points(("node", "core.task-runner")), data_records=[built_in]
        ) as environment:
            with self.assertRaisesRegex(ValueError, "E_EXTENSION_BUILTIN_IDENTITY"):
                _activate(
                    environment,
                    _activation_request(
                        environment, environment.initial_receipt, "activation.built-in"
                    ),
                )
            self.assertIsNone(environment.activation.snapshot().data_registry)

        records = _records()
        points = _points(*((str(item["data_kind"]), str(item["identity_id"])) for item in records))
        with _environment(points=points, data_records=records) as environment:
            _activate(
                environment,
                _activation_request(
                    environment, environment.initial_receipt, "activation.restart"
                ),
            )
            before = environment.activation.snapshot().data_registry
            restarted = environment.restart_activation()
            self.assertEqual(restarted.snapshot().data_registry, before)

            root = environment.installer._test_content_path(environment.initial_receipt)
            member = next(root.glob("payload/data/*.json"))
            member.chmod(0o600)
            original = json.loads(member.read_text())
            original["identity_id"] = "core.task-runner"
            member.write_text(json.dumps(original, sort_keys=True, separators=(",", ":")))
            member.chmod(0o400)
            with self.assertRaisesRegex(ValueError, "content|digest|registry"):
                environment.restart_activation()


if __name__ == "__main__":
    unittest.main()
