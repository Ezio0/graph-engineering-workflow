"""Final table-driven trust reducer closure for WP08A-QR-R1-001."""

from __future__ import annotations

import copy
import unittest

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.extensions import (
    ExtensionTrustOperation,
    ExtensionTrustPolicyReducer,
    extension_capability_set_digest,
)
from tests.support.wp08a_extension_bundle import DIGEST, trust_policy_chain


def _digest(body: dict[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _operation(
    current_digest: str,
    kind: str,
    target: str,
    old: dict[str, object] | None,
    new: dict[str, object],
) -> ExtensionTrustOperation:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "operation_id": f"operation.{kind}",
        "operation_kind": kind,
        "expected_policy_digest": current_digest,
        "target_identity": target,
        "expected_old": old,
        "new_value": new,
    }
    body["operation_digest"] = _digest(body, "extension-trust-operation")
    return ExtensionTrustOperation.from_dict(body)


class ExtensionTrustReducerFinalTests(unittest.TestCase):
    def test_wp08a_qr_r1_001_all_twelve_transitions_and_rejections_are_exact(self) -> None:
        genesis, current = trust_policy_chain("installation.reducer-final")
        reducer = ExtensionTrustPolicyReducer.issue(genesis)
        cases = _transition_cases(current)
        next_generation = current.generation + 1
        self.assertEqual(tuple(item[0] for item in cases), reducer.OPERATION_KINDS)
        for kind, target, old, new, invalid_new in cases:
            with self.subTest(kind=kind):
                operation = _operation(current.policy_digest, kind, target, old, new)
                reduced = reducer.reduce(current, (operation,))
                self.assertEqual(reduced.generation, next_generation)
                with self.assertRaises(ValueError):
                    invalid = _operation(current.policy_digest, kind, target, old, invalid_new)
                    reducer.reduce(current, (invalid,))
        retire = next(item for item in cases if item[0] == "retire-key")
        revoke = next(item for item in cases if item[0] == "apply-local-revocation")
        duplicated_sequence = tuple(sorted((
            _operation(current.policy_digest, retire[0], retire[1], retire[2], retire[3]),
            _operation(current.policy_digest, revoke[0], revoke[1], revoke[2], revoke[3]),
        ), key=lambda item: item.operation_digest))
        with self.assertRaisesRegex(ValueError, "sequence"):
            reducer.reduce(current, duplicated_sequence)


def _transition_cases(current):  # type: ignore[no-untyped-def]
        body = current.to_dict()
        key = copy.deepcopy(body["trust_keys"][0])
        production = copy.deepcopy(body["production_policies"][0])
        source = copy.deepcopy(body["source_rules"][0])
        namespace = copy.deepcopy(body["namespace_rules"][0])
        extension_kind = copy.deepcopy(body["extension_kind_rules"][0])
        ceiling = copy.deepcopy(body["capability_ceilings"][0])
        floor = copy.deepcopy(body["compatibility_floors"][0])
        next_generation = current.generation + 1
        next_sequence = current.revocation_high_water + 1

        added_key = copy.deepcopy(key)
        added_key.update(key_id="publisher.key.2", added_generation=next_generation)
        retired_key = copy.deepcopy(key)
        retired_key.update(status="retired", revocation_sequence=next_sequence)
        rotated_key = copy.deepcopy(key)
        rotated_key.update(
            ed25519_public_key="A" * 43,
            added_generation=next_generation,
            revocation_sequence=current.revocation_high_water,
        )
        added_policy = copy.deepcopy(production)
        added_policy.update(
            policy_id="production.policy.2",
            policy_digest="sha256-jcs-v1:" + "b" * 64,
            added_generation=next_generation,
        )
        retired_policy = copy.deepcopy(production)
        retired_policy["status"] = "retired"
        changed_source = copy.deepcopy(source)
        changed_source["allowed_source_ids"] = sorted(
            [*changed_source["allowed_source_ids"], "source.second"]
        )
        changed_namespace = copy.deepcopy(namespace)
        changed_namespace["allowed_extension_kinds"] = sorted(
            [*changed_namespace["allowed_extension_kinds"], "template"]
        )
        changed_kind = copy.deepcopy(extension_kind)
        changed_kind["data_allowed"] = not changed_kind["data_allowed"]
        changed_ceiling = copy.deepcopy(ceiling)
        changed_ceiling["capability_ids"] = sorted(
            [*changed_ceiling["capability_ids"], "capability.second"]
        )
        changed_ceiling["capability_set_digest"] = extension_capability_set_digest(
            changed_ceiling["subject_kind"],
            changed_ceiling["subject_id"],
            changed_ceiling["capability_ids"],
        )
        changed_floor = copy.deepcopy(floor)
        changed_floor["compatibility_policy_digest"] = "sha256-jcs-v1:" + "d" * 64
        local_revocation = {
            "target_kind": "extension",
            "target_identity_digest": "sha256-jcs-v1:" + "e" * 64,
            "input_kind": "owner-revocation",
            "input_digest": DIGEST,
            "reason_code": "security.denied",
            "local_sequence": next_sequence,
            "effective_generation": next_generation,
            "owner_decision_digest": DIGEST,
        }
        publisher_revocation = {
            **local_revocation,
            "target_identity_digest": "sha256-jcs-v1:" + "f" * 64,
            "input_kind": "publisher-revocation",
        }
        cases = (
            ("add-key", "publisher.example/publisher.key.2", None, added_key),
            ("retire-key", f"{key['publisher_id']}/{key['key_id']}", key, retired_key),
            ("rotate-key", f"{key['publisher_id']}/{key['key_id']}", key, rotated_key),
            ("register-production-policy", "production.policy.2", None, added_policy),
            ("retire-production-policy", str(production["policy_id"]), production, retired_policy),
            ("set-source-rule", str(source["source_type"]), source, changed_source),
            (
                "set-namespace-rule",
                f"{namespace['publisher_id']}/{namespace['namespace_prefix']}",
                namespace,
                changed_namespace,
            ),
            (
                "set-extension-kind-rule", str(extension_kind["extension_kind"]),
                extension_kind, changed_kind,
            ),
            (
                "set-capability-ceiling",
                f"{ceiling['subject_kind']}/{ceiling['subject_id']}", ceiling, changed_ceiling,
            ),
            (
                "set-compatibility-floor", str(floor["component_kind"]), floor, changed_floor,
            ),
            (
                "apply-local-revocation",
                f"extension/{local_revocation['target_identity_digest']}",
                None,
                local_revocation,
            ),
            (
                "apply-publisher-revocation",
                f"extension/{publisher_revocation['target_identity_digest']}",
                None,
                publisher_revocation,
            ),
        )
        result = []
        for kind, target, old, new in cases:
            invalid_new = copy.deepcopy(new)
            if kind in {"add-key", "rotate-key"}:
                invalid_new["added_generation"] = current.generation
            elif kind == "retire-key":
                invalid_new["revocation_sequence"] = current.revocation_high_water
            elif kind == "register-production-policy":
                invalid_new["added_generation"] = current.generation
            elif kind == "retire-production-policy":
                invalid_new["status"] = "active"
            elif kind.startswith("set-"):
                assert old is not None
                invalid_new = copy.deepcopy(old)
            else:
                invalid_new["local_sequence"] = current.revocation_high_water
            result.append((kind, target, old, new, invalid_new))
        return tuple(result)


if __name__ == "__main__":
    unittest.main()
