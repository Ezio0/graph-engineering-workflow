from __future__ import annotations

import copy
import json
import unittest

from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.schema import SchemaProfilePolicy, validate_schema_profile
from graph_engineering.core.security.disclosure import DisclosureError, DisclosurePolicy
from graph_engineering.core.security.evidence import EvidenceError, EvidencePolicyRegistry
from graph_engineering.core.security.inputs import InputSafetyError, InputSafetyPolicy
from graph_engineering.core.security.privacy import RedactionError, RedactionPolicy
from graph_engineering.core.security.retention import RetentionError, RetentionPolicyRegistry
from tests.support.wp05a_security import (
    ROOT,
    SECURITY_SCHEMA_NAMES,
    disclosure_policy_document,
    evidence_policy_document,
    input_policy_document,
    load_json,
    redaction_policy_document,
    retention_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
)


class WP05ASecurityContractTests(unittest.TestCase):
    def test_security_schema_registry_is_closed_profile_valid_and_digest_locked(self) -> None:
        policy = SchemaProfilePolicy.from_dict(load_json(
            ROOT / "config" / "contracts" / "schema-profile-v1.json"
        ))
        bodies: dict[str, bytes] = {}
        for name in SECURITY_SCHEMA_NAMES:
            path = ROOT / "config" / "contracts" / "schemas" / name
            value = json.loads(path.read_text())
            schema_id = validate_schema_profile(value, policy)
            bodies[schema_id] = path.read_bytes()
        manifest = load_json(
            ROOT / "config" / "contracts" / "security-schema-registry-v1.json"
        )
        self.assertEqual(
            manifest,
            ClosedSchemaRegistry.create_manifest(
                "urn:gew:schema-registry:security-foundation:1.0.0",
                bodies,
            ),
        )
        self.assertEqual(
            security_schema_registry().registry_digest,
            "sha256-jcs-v1:5af3f2ba14d440f50e6194d9ea1aa9bc510e6573a0f19e7a8d564fdf9f0fd9b4",
        )

    def test_all_policy_documents_are_schema_and_digest_bound(self) -> None:
        cases = (
            (InputSafetyPolicy, input_policy_document(), InputSafetyError),
            (RedactionPolicy, redaction_policy_document(), RedactionError),
            (DisclosurePolicy, disclosure_policy_document(), DisclosureError),
            (EvidencePolicyRegistry, evidence_policy_document(), EvidenceError),
            (RetentionPolicyRegistry, retention_policy_document(), RetentionError),
        )
        for loader, document, error_type in cases:
            with self.subTest(loader=loader.__name__):
                context = security_context()
                schemas = security_schema_registry(context)
                runtime = security_runtime(context, schemas)
                loaded = loader.from_dict(document, schema_registry=schemas, context=context, runtime=runtime)
                self.assertIs(type(loaded), loader)
                with self.assertRaises(TypeError):
                    loader()
                changed = copy.deepcopy(document)
                numeric_fields = [
                    key for key, value in changed.items()
                    if type(value) is int
                ]
                if numeric_fields:
                    changed[numeric_fields[0]] += 1
                else:
                    sequence_field = next(
                        key for key, value in changed.items()
                        if type(value) is list
                    )
                    changed[sequence_field] = list(reversed(changed[sequence_field]))
                with self.assertRaises((error_type, ValueError)):
                    loader.from_dict(changed, schema_registry=schemas, context=context, runtime=runtime)

    def test_registry_body_or_manifest_tamper_is_rejected(self) -> None:
        context = security_context()
        manifest = load_json(
            ROOT / "config" / "contracts" / "security-schema-registry-v1.json"
        )
        bodies: dict[str, bytes] = {}
        for name in SECURITY_SCHEMA_NAMES:
            path = ROOT / "config" / "contracts" / "schemas" / name
            schema_id = load_json(path)["$id"]
            bodies[str(schema_id)] = path.read_bytes()
        first_id = sorted(bodies)[0]
        changed_bodies = dict(bodies)
        changed_bodies[first_id] = bodies[first_id] + b" "
        profile = load_json(ROOT / "config" / "contracts" / "resource-profile-v1.json")
        schema_policy = SchemaProfilePolicy.from_dict(load_json(
            ROOT / "config" / "contracts" / "schema-profile-v1.json"
        ))
        from graph_engineering.core.contracts.resources import ResourceProfile

        with self.assertRaises(ValueError):
            ClosedSchemaRegistry.build(
                manifest,
                changed_bodies,
                ResourceProfile.from_dict(profile),
                schema_policy,
                context,
            )
        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["resources"][0]["body_digest"] = "sha256-raw-v1:" + "0" * 64
        with self.assertRaises(ValueError):
            ClosedSchemaRegistry.build(
                changed_manifest,
                bodies,
                ResourceProfile.from_dict(profile),
                schema_policy,
                context,
            )


if __name__ == "__main__":
    unittest.main()
