from __future__ import annotations

import inspect
import sqlite3
import unittest

import graph_engineering.core.security.attestation as attestation_module
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.core.security._common import unsigned_digest
from graph_engineering.core.security.attestation import (
    SecurityAttestationError,
    SecurityRuntimeManifest,
)
from graph_engineering.storage.errors import RepositoryIntegrityError
from tests.support.wp05a_security import (
    ROOT,
    SECURITY_RUNTIME_DIGEST,
    SECURITY_RUNTIME_ID,
    digest_value,
    durable_security_issuer,
    load_json,
    security_context,
    security_schema_registry,
)


class WP05AR3DurableIssuanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)

    def test_core_has_no_raw_attestation_issuer_and_runtime_pin_is_not_caller_selected(self) -> None:
        self.assertFalse(hasattr(attestation_module, "_issue_task_security_context"))
        self.assertFalse(hasattr(attestation_module, "_issue_disclosure_journal_attestation"))
        with self.assertRaises(SecurityAttestationError):
            SecurityRuntimeManifest.from_dict(
                load_json(ROOT / "config" / "security" / "security-runtime-v1.json"),
                expected_manifest_id=SECURITY_RUNTIME_ID,
                expected_manifest_digest=SECURITY_RUNTIME_DIGEST,
                schema_registry=self.schemas,
                context=self.context,
            )

    def test_production_issuer_accepts_only_durable_record_identities(self) -> None:
        task_parameters = tuple(inspect.signature(SecurityContextIssuer.issue_task_context).parameters)
        journal_parameters = tuple(
            inspect.signature(SecurityContextIssuer.issue_disclosure_attestation).parameters
        )
        self.assertEqual(task_parameters, ("self", "task_id"))
        self.assertEqual(journal_parameters, ("self", "receipt_id"))
        with durable_security_issuer(self.context, self.schemas) as (issuer, _factory):
            task_context = issuer.issue_task_context("task-wp05a")
            self.assertEqual(task_context.binding.owner_id, "owner-wp05a")
            self.assertEqual(task_context.binding.snapshot_digest, digest_value("snapshot"))
            with self.assertRaises(TypeError):
                issuer.issue_task_context(  # type: ignore[call-arg]
                    "task-wp05a",
                    destinations={"attacker": {}},
                )

    def test_state_row_tamper_fails_before_attestation_is_issued(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, factory):
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE task_security_states SET state_json=? WHERE task_id=?",
                        ('{"forged":true}', "task-wp05a"),
                    )
            with self.assertRaises(RepositoryIntegrityError):
                issuer.issue_task_context("task-wp05a")

    def test_installed_runtime_row_is_single_write_immutable(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (_issuer, factory):
            for statement in (
                "UPDATE security_runtime_installation SET manifest_id='attacker' WHERE singleton=1",
                "DELETE FROM security_runtime_installation WHERE singleton=1",
            ):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                    with factory._for_maintenance().open("application") as connection:
                        with connection.transaction():
                            connection.execute(statement)

    def test_disclosure_attestation_requires_a_delivered_durable_journal_entry(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, _factory):
            with self.assertRaises(RepositoryIntegrityError):
                issuer.issue_disclosure_attestation("receipt-wp05a")

        receipt: dict[str, object] = {
            "schema_version": "1.0.0",
            "receipt_id": "receipt-wp05a",
            "plan_digest": digest_value("disclosure-plan"),
            "payload_digest": digest_value("disclosure-payload"),
            "destination_identity_ref": "connector-fixture",
            "occurred_at": "2026-08-14T00:01:00Z",
            "result": "delivered",
            "target_receipt_digest": digest_value("target-receipt"),
        }
        receipt["receipt_digest"] = unsigned_digest(
            receipt,
            digest_field="receipt_digest",
            contract_type="urn:gew:contract:disclosure-receipt",
            schema_id="urn:gew:schema:disclosure-receipt:1.0.0",
        )
        with durable_security_issuer(
            self.context,
            self.schemas,
            journal_receipt=receipt,
        ) as (issuer, _factory):
            journal = issuer.issue_disclosure_attestation("receipt-wp05a")
            self.assertEqual(dict(journal.receipt), receipt)
            self.assertEqual(journal.prepared_action_digest, digest_value("prepared-action"))
            with self.assertRaises((TypeError, RepositoryIntegrityError)):
                issuer.issue_disclosure_attestation(receipt)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
