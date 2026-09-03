from __future__ import annotations

import unittest

from graph_engineering.core.contracts.errors import ContractError
from graph_engineering.storage.errors import RepositoryIntegrityError
from tests.support.wp05a_security import (
    digest_value,
    durable_security_issuer,
    security_context,
    security_schema_registry,
)


def _deep_document() -> str:
    return "[" * 1400 + "0" + "]" * 1400


class WP05AR4BoundedDurableParsingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)

    def _assert_bounded_failure(self, operation: object, source_id: str) -> None:
        if not callable(operation):
            raise AssertionError("test operation must be callable")
        before = len(self.context.trace)
        with self.assertRaises(RepositoryIntegrityError) as caught:
            operation()
        self.assertNotIsInstance(caught.exception.__cause__, RecursionError)
        self.assertIsInstance(caught.exception.__cause__, ContractError)
        cause = caught.exception.__cause__
        assert isinstance(cause, ContractError)
        self.assertEqual(cause.detail.source_id, source_id)
        self.assertEqual(cause.detail.code, "E_LIMIT")
        events = self.context.trace[before:]
        self.assertTrue(events)
        self.assertTrue(any(event.get("event_id") == "parse.token" for event in events))

    def test_deep_installed_runtime_fails_inside_resource_boundary(self) -> None:
        with self.assertRaises(RepositoryIntegrityError) as caught:
            with durable_security_issuer(
                self.context,
                self.schemas,
                runtime_json=_deep_document(),
            ):
                self.fail("issuer must not be created from an over-depth runtime")
        self.assertNotIsInstance(caught.exception.__cause__, RecursionError)
        self.assertIsInstance(caught.exception.__cause__, ContractError)
        cause = caught.exception.__cause__
        assert isinstance(cause, ContractError)
        self.assertEqual(cause.detail.source_id, "security-runtime-installation")
        self.assertEqual(cause.detail.code, "E_LIMIT")
        self.assertTrue(any(event.get("event_id") == "parse.token" for event in self.context.trace))

    def test_deep_task_state_fails_inside_resource_boundary(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, factory):
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE task_security_states SET state_json=? WHERE task_id=?",
                        (_deep_document(), "task-wp05a"),
                    )
            self._assert_bounded_failure(
                lambda: issuer.issue_task_context("task-wp05a"),
                "task-security-state:task-wp05a",
            )

    def test_deep_disclosure_journal_fails_inside_resource_boundary(self) -> None:
        receipt_id = "receipt-wp05a"
        receipt = {
            "schema_version": "1.0.0",
            "receipt_id": receipt_id,
            "plan_digest": digest_value("disclosure-plan"),
            "payload_digest": digest_value("disclosure-payload"),
            "destination_identity_ref": "connector-fixture",
            "occurred_at": "2026-08-14T00:01:00Z",
            "result": "delivered",
            "target_receipt_digest": digest_value("target-receipt"),
            "receipt_digest": digest_value("receipt"),
        }
        with durable_security_issuer(
            self.context,
            self.schemas,
            journal_receipt=receipt,
        ) as (issuer, factory):
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "UPDATE disclosure_journal SET entry_json=? WHERE receipt_id=?",
                        (_deep_document(), receipt_id),
                    )
            self._assert_bounded_failure(
                lambda: issuer.issue_disclosure_attestation(receipt_id),
                f"disclosure-journal:{receipt_id}",
            )


if __name__ == "__main__":
    unittest.main()
