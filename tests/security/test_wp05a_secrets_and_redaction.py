from __future__ import annotations

import unittest

from graph_engineering.core.security.privacy import (
    LeakageIncident,
    RedactionError,
    RedactionPolicy,
    Redactor,
    SecretMaterial,
    SecretReference,
    classify_sensitivity,
)
from tests.support.wp05a_security import (
    digest_value,
    redaction_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
)


class SecretAndRedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)
        self.policy = RedactionPolicy.from_dict(
            redaction_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )

    def test_secret_reference_contains_no_value_and_material_repr_is_safe(self) -> None:
        reference = SecretReference.from_dict({
            "schema_version": "1.0.0",
            "provider_id": "provider-local",
            "key_ref": "secret-project-token",
            "version_ref": "current",
        })
        material = SecretMaterial.from_provider(b"top-secret-value", reference=reference)
        self.assertNotIn("top-secret-value", repr(material))
        self.assertNotIn("top-secret-value", str(material))
        self.assertEqual(material.reference, reference)
        self.assertEqual(material.reveal(), b"top-secret-value")
        self.assertNotIn("value", reference.as_dict())
        self.assertEqual(classify_sensitivity(None), "confidential")
        self.assertEqual(classify_sensitivity("unknown"), "confidential")
        self.assertEqual(classify_sensitivity("secret"), "secret")
        with self.assertRaises(TypeError):
            SecretReference()

    def test_redactor_keeps_only_allowlisted_fields_and_applies_transforms(self) -> None:
        result = Redactor.redact(
            {
                "summary": "build passed",
                "token": "ordinary-token-shaped-text",
                "nested": {"email": "owner@example.invalid", "source": "private source"},
                "ignored": "drop me",
            },
            field_allowlist=("/nested/email", "/summary", "/token"),
            transforms={"/nested/email": "mask", "/token": "drop"},
            secret_materials=(),
            policy=self.policy,
            context=self.context,
        )
        self.assertEqual(result.as_dict(), {
            "nested": {"email": "[REDACTED]"},
            "summary": "build passed",
        })
        self.assertEqual(result.applied_transforms, ("/nested/email:mask", "/token:drop"))
        self.assertNotIn("ignored", result.canonical_text())

    def test_secret_value_anywhere_in_output_is_blocked_without_echo(self) -> None:
        reference = SecretReference.from_dict({
            "schema_version": "1.0.0",
            "provider_id": "provider-local",
            "key_ref": "secret-project-token",
            "version_ref": "current",
        })
        secret = SecretMaterial.from_provider(b"fixture-secret-value", reference=reference)
        with self.assertRaises(RedactionError) as raised:
            Redactor.redact(
                {"summary": "prefix fixture-secret-value suffix"},
                field_allowlist=("/summary",),
                transforms={},
                secret_materials=(secret,),
                policy=self.policy,
                context=self.context,
            )
        self.assertNotIn("fixture-secret-value", str(raised.exception))

    def test_incident_is_factory_only_digest_bound_and_never_contains_content(self) -> None:
        incident = LeakageIncident.create(
            incident_id="incident-wp05a",
            source_ref="object-output",
            suspect_digest=digest_value("suspect"),
            detector_ids=("known-secret",),
            occurred_at="2026-08-14T00:00:00Z",
        )
        self.assertEqual(incident.status, "quarantined")
        self.assertNotIn("content", incident.as_dict())
        with self.assertRaises(TypeError):
            LeakageIncident()

    def test_invalid_json_pointer_unknown_transform_and_unlisted_transform_reject(self) -> None:
        for allowlist, transforms in (
            (("summary",), {}),
            (("/summary",), {"/summary": "unknown"}),
            (("/summary",), {"/other": "mask"}),
        ):
            with self.subTest(allowlist=allowlist, transforms=transforms), self.assertRaises(RedactionError):
                Redactor.redact(
                    {"summary": "ok", "other": "value"},
                    field_allowlist=allowlist,
                    transforms=transforms,
                    secret_materials=(),
                    policy=self.policy,
                    context=self.context,
                )

    def test_deep_selected_payload_fails_with_deterministic_resource_error(self) -> None:
        value: object = "leaf"
        for _ in range(1400):
            value = {"nested": value}
        with self.assertRaises(RedactionError) as raised:
            Redactor.redact(
                {"value": value},
                field_allowlist=("/value",),
                transforms={},
                secret_materials=(),
                policy=self.policy,
                context=self.context,
            )
        self.assertNotIsInstance(raised.exception.__cause__, RecursionError)


if __name__ == "__main__":
    unittest.main()
