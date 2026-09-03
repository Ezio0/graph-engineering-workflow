from __future__ import annotations

import copy
import unittest

from graph_engineering.core.security.disclosure import (
    DataDisclosurePlan,
    DisclosureError,
    DisclosurePolicy,
    DisclosureReceipt,
)
from graph_engineering.core.security.evidence import (
    EvidenceError,
    EvidencePolicyRegistry,
    EvidenceRecord,
    EvidenceValidator,
)
from graph_engineering.core.security.privacy import LeakageIncident, RedactionPolicy, Redactor
from tests.support.wp05a_security import (
    disclosure_plan_document,
    disclosure_journal_attestation,
    disclosure_policy_document,
    disclosure_receipt_document,
    evidence_document,
    evidence_policy_document,
    redaction_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
    task_security_context,
)


class DisclosureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)
        self.task_context = task_security_context(self.context, self.schemas, self.runtime)
        self.policy = DisclosurePolicy.from_dict(
            disclosure_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )
        redaction_policy = RedactionPolicy.from_dict(
            redaction_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )
        self.redacted = Redactor.redact(
            {"summary": "tests passed", "source": "private body"},
            field_allowlist=("/source", "/summary"),
            transforms={"/source": "mask"},
            secret_materials=(),
            policy=redaction_policy,
            context=self.context,
        )
        self.expected_snapshot_digest = disclosure_plan_document(
            self.redacted.payload_digest, external=True,
        )["snapshot_digest"]
        self.expected_action_digest = disclosure_plan_document(
            self.redacted.payload_digest, external=True,
        )["prepared_action_digest"]
        expected_plan = disclosure_plan_document(self.redacted.payload_digest, external=True)
        self.expected_data_refs = {
            item["ref_id"]: {"digest": item["digest"], "sensitivity": item["sensitivity"]}
            for item in expected_plan["data_refs"]
        }

    def load(self, value: dict[str, object], *, authority: str | None = None) -> DataDisclosurePlan:
        return DataDisclosurePlan.from_dict(
            value,
            policy=self.policy,
            runtime=self.runtime,
            task_context=self.task_context,
            redacted_payload=self.redacted,
            schema_registry=self.schemas,
            context=self.context,
        )

    def test_external_disclosure_binds_destination_payload_authority_and_receipt(self) -> None:
        value = disclosure_plan_document(self.redacted.payload_digest, external=True)
        plan = self.load(value, authority=value["authority_digest"])
        self.assertTrue(plan.receipt_required)
        receipt_value = disclosure_receipt_document(
            receipt_id="receipt-wp05a",
            plan=plan,
            occurred_at="2026-08-14T00:01:00Z",
            result="delivered",
            target_receipt_digest=value["payload_digest"],
        )
        journal = disclosure_journal_attestation(
            receipt_value,
            runtime=self.runtime,
            context=self.context,
        )
        receipt = DisclosureReceipt.from_dict(
            receipt_value,
            plan=plan,
            runtime=self.runtime,
            task_context=self.task_context,
            journal_attestation=journal,
            schema_registry=self.schemas,
            context=self.context,
        )
        self.assertEqual(receipt.plan_digest, plan.plan_digest)
        with self.assertRaises(DisclosureError):
            DisclosureReceipt.document(
                receipt_id="forged",
                plan=plan,
                occurred_at="2026-08-14T00:02:00Z",
                result="delivered",
                target_receipt_digest=value["payload_digest"],
            )

    def test_undeclared_destination_overclassification_missing_redaction_and_authority_reject(self) -> None:
        base = disclosure_plan_document(self.redacted.payload_digest, external=True)
        cases: list[tuple[str, dict[str, object], str | None]] = []
        changed = copy.deepcopy(base)
        changed["destination"]["kind"] = "unknown-connector"
        cases.append(("destination", changed, base["authority_digest"]))
        changed = copy.deepcopy(base)
        changed["maximum_sensitivity"] = "secret"
        cases.append(("classification", changed, base["authority_digest"]))
        changed = copy.deepcopy(base)
        changed["redaction_transforms"] = []
        cases.append(("redaction", changed, base["authority_digest"]))
        changed = copy.deepcopy(base)
        changed["authority_digest"] = None
        cases.append(("authority", changed, None))
        changed = copy.deepcopy(base)
        changed["payload_digest"] = "sha256-jcs-v1:" + "0" * 64
        cases.append(("payload", changed, base["authority_digest"]))
        changed = copy.deepcopy(base)
        changed["snapshot_digest"] = "sha256-jcs-v1:" + "1" * 64
        cases.append(("snapshot", changed, base["authority_digest"]))
        changed = copy.deepcopy(base)
        changed["prepared_action_digest"] = "sha256-jcs-v1:" + "2" * 64
        cases.append(("prepared-action", changed, base["authority_digest"]))
        for name, value, authority in cases:
            value["plan_digest"] = DataDisclosurePlan.digest_document(value)
            with self.subTest(name=name), self.assertRaises(DisclosureError):
                self.load(value, authority=authority)

    def test_concrete_destination_identity_cannot_be_substituted(self) -> None:
        value = disclosure_plan_document(self.redacted.payload_digest, external=True)
        value["destination"]["identity_ref"] = "attacker-endpoint"
        value["plan_digest"] = DataDisclosurePlan.digest_document(value)
        with self.assertRaises(DisclosureError):
            self.load(value, authority=value["authority_digest"])

    def test_owner_session_disclosure_still_minimizes_but_needs_no_action_authority(self) -> None:
        value = disclosure_plan_document(self.redacted.payload_digest, external=False)
        plan = self.load(value, authority=None)
        self.assertEqual(plan.destination["trust_boundary"], "owner-session")
        self.assertIsNone(plan.authority_digest)


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)
        self.policy_registry = EvidencePolicyRegistry.from_dict(
            evidence_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )
        self.expected = evidence_document()

    def validate(self, value: dict[str, object], *, now: str = "2026-08-14T00:30:00Z") -> EvidenceRecord:
        task_context = task_security_context(
            self.context,
            self.schemas,
            self.runtime,
            current_time=now,
        )
        return EvidenceValidator.load(
            value,
            runtime=self.runtime,
            task_context=task_context,
            policy_registry=self.policy_registry,
            schema_registry=self.schemas,
            context=self.context,
        )

    def test_fresh_independent_redacted_evidence_is_accepted(self) -> None:
        record = self.validate(evidence_document())
        self.assertEqual(record.trust, "independently-reviewed")
        self.assertEqual(record.status, "valid")
        with self.assertRaises(TypeError):
            EvidenceRecord()

    def test_leakage_incident_quarantines_and_revokes_evidence_trust(self) -> None:
        record = self.validate(evidence_document())
        incident = LeakageIncident.create(
            incident_id="incident-evidence",
            source_ref="object-evidence",
            suspect_digest=record.body["content_digest"],
            detector_ids=("known-secret",),
            occurred_at="2026-08-14T00:31:00Z",
        )
        quarantined = EvidenceRecord.quarantine(record, incident, context=self.context)
        self.assertEqual(quarantined.status, "quarantined")
        self.assertEqual(quarantined.trust, "untrusted")
        with self.assertRaises(EvidenceError):
            self.validate(quarantined.as_dict())

    def test_stale_wrong_binding_self_review_unredacted_and_digest_tamper_reject(self) -> None:
        base = evidence_document()
        cases: list[tuple[str, dict[str, object], str]] = []
        cases.append(("stale", copy.deepcopy(base), "2026-08-15T00:00:00Z"))
        changed = copy.deepcopy(base)
        changed["task_id"] = "task-other"
        cases.append(("task", changed, "2026-08-14T00:30:00Z"))
        changed = copy.deepcopy(base)
        changed["producer_id"] = "author-wp05a"
        cases.append(("self-review", changed, "2026-08-14T00:30:00Z"))
        changed = copy.deepcopy(base)
        changed["redaction"]["status"] = "none"
        cases.append(("redaction", changed, "2026-08-14T00:30:00Z"))
        changed = copy.deepcopy(base)
        changed["content_digest"] = "sha256-jcs-v1:" + "f" * 64
        cases.append(("digest", changed, "2026-08-14T00:30:00Z"))
        changed = copy.deepcopy(base)
        changed["fresh_until"] = "2026-08-14T02:00:00Z"
        cases.append(("freshness-policy", changed, "2026-08-14T00:30:00Z"))
        for name, value, now in cases:
            value["record_digest"] = EvidenceRecord.digest_document(value)
            with self.subTest(name=name), self.assertRaises(EvidenceError):
                self.validate(value, now=now)

    def test_caller_cannot_self_attest_producer_classification_or_redaction(self) -> None:
        forged = evidence_document()
        forged["producer_id"] = "attacker-producer"
        forged["sensitivity"] = "public"
        forged["redaction"] = {"status": "not-required", "transforms": []}
        forged["trust"] = "independently-reviewed"
        forged["record_digest"] = EvidenceRecord.digest_document(forged)
        with self.assertRaises(EvidenceError):
            self.validate(forged)


if __name__ == "__main__":
    unittest.main()
