from __future__ import annotations

import copy
import unittest

from graph_engineering.core.security._common import unsigned_digest
from graph_engineering.core.security.attestation import (
    DisclosureJournalAttestation,
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TaskSecurityContext,
    require_runtime_context,
)
from graph_engineering.core.security.disclosure import DisclosurePolicy
from graph_engineering.core.security.evidence import EvidencePolicyRegistry
from graph_engineering.core.security.inputs import InputSafetyPolicy
from graph_engineering.core.security.privacy import RedactionPolicy
from graph_engineering.core.security.retention import RetentionEngine, RetentionPolicyRegistry
from tests.support.wp05a_security import (
    ROOT,
    SECURITY_RUNTIME_DIGEST,
    SECURITY_RUNTIME_ID,
    disclosure_policy_document,
    evidence_policy_document,
    input_policy_document,
    load_json,
    redaction_policy_document,
    retention_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
    task_security_context,
)


class WP05AR2AttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)

    def test_runtime_manifest_self_recomputation_cannot_replace_installed_pin(self) -> None:
        changed = load_json(ROOT / "config" / "security" / "security-runtime-v1.json")
        changed["allowed_runtime_kinds"] = ["codex", "hermes", "openclaw"]
        changed["manifest_digest"] = SecurityRuntimeManifest.digest_document(changed)
        with self.assertRaises(SecurityAttestationError):
            SecurityRuntimeManifest.from_dict(
                changed,
                expected_manifest_id=SECURITY_RUNTIME_ID,
                expected_manifest_digest=SECURITY_RUNTIME_DIGEST,
                schema_registry=self.schemas,
                context=self.context,
            )

    def test_every_policy_recomputed_by_caller_is_rejected_by_runtime_pin(self) -> None:
        cases = [
            (
                InputSafetyPolicy,
                input_policy_document(),
                "policy_digest",
                "urn:gew:contract:input-safety-policy",
                "urn:gew:schema:input-safety-policy:1.0.0",
                lambda value: value.__setitem__("max_arguments", value["max_arguments"] + 1),
            ),
            (
                RedactionPolicy,
                redaction_policy_document(),
                "policy_digest",
                "urn:gew:contract:redaction-policy",
                "urn:gew:schema:redaction-policy:1.0.0",
                lambda value: value.__setitem__("mask_marker", "[CHANGED]"),
            ),
            (
                DisclosurePolicy,
                disclosure_policy_document(),
                "policy_digest",
                "urn:gew:contract:disclosure-policy",
                "urn:gew:schema:disclosure-policy:1.0.0",
                lambda value: value["rules"][0].__setitem__("authority_required", False),
            ),
            (
                EvidencePolicyRegistry,
                evidence_policy_document(),
                "registry_digest",
                "urn:gew:contract:evidence-policy-registry",
                "urn:gew:schema:evidence-policy-registry:1.0.0",
                lambda value: value["policies"][0].__setitem__(
                    "maximum_freshness_seconds",
                    value["policies"][0]["maximum_freshness_seconds"] + 1,
                ),
            ),
            (
                RetentionPolicyRegistry,
                retention_policy_document(),
                "registry_digest",
                "urn:gew:contract:retention-policy-registry",
                "urn:gew:schema:retention-policy-registry:1.0.0",
                lambda value: value["policies"][0].__setitem__(
                    "max_age_seconds",
                    value["policies"][0]["max_age_seconds"] + 1,
                ),
            ),
        ]
        for loader, source, digest_field, contract_type, schema_id, mutate in cases:
            changed = copy.deepcopy(source)
            mutate(changed)
            changed[digest_field] = unsigned_digest(
                changed,
                digest_field=digest_field,
                contract_type=contract_type,
                schema_id=schema_id,
            )
            with self.subTest(loader=loader.__name__), self.assertRaises(ValueError):
                loader.from_dict(
                    changed,
                    runtime=self.runtime,
                    schema_registry=self.schemas,
                    context=self.context,
                )

    def test_task_and_journal_attestations_are_factory_only_and_runtime_scoped(self) -> None:
        with self.assertRaises(TypeError):
            TaskSecurityContext()
        with self.assertRaises(TypeError):
            DisclosureJournalAttestation()
        task_context = task_security_context(self.context, self.schemas, self.runtime)
        second_runtime = security_runtime(self.context, self.schemas)
        with self.assertRaises(SecurityAttestationError):
            require_runtime_context(second_runtime, task_context)

    def test_retention_engine_has_no_raw_hold_or_classification_api(self) -> None:
        registry = RetentionPolicyRegistry.from_dict(
            retention_policy_document(),
            runtime=self.runtime,
            schema_registry=self.schemas,
            context=self.context,
        )
        with self.assertRaises(TypeError):
            RetentionEngine.evaluate(
                registry=registry,
                category="tool-raw-output",
                sensitivity="public",
                legal_hold=False,
                rollback_dependency=False,
                unresolved_action=False,
            )


if __name__ == "__main__":
    unittest.main()
