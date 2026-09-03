from __future__ import annotations

import copy
import unittest

from graph_engineering.core.security.extensions import (
    ExtensionError,
    ExtensionGate,
)
from graph_engineering.core.security.retention import (
    RetentionEngine,
    RetentionError,
    RetentionPolicyRegistry,
)
from graph_engineering.storage.errors import RepositoryConflictError
from tests.support.wp05a_security import (
    digest_value,
    durable_security_issuer,
    retention_policy_document,
    security_context,
    security_runtime,
    security_schema_registry,
    task_security_context,
    task_security_state_document,
    write_durable_task_security_state,
)


class RetentionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = security_context()
        self.schemas = security_schema_registry(self.context)
        self.runtime = security_runtime(self.context, self.schemas)
        self.registry = RetentionPolicyRegistry.from_dict(
            retention_policy_document(),
            schema_registry=self.schemas,
            context=self.context,
            runtime=self.runtime,
        )

    def test_raw_tool_output_is_purged_after_extraction_with_tombstone(self) -> None:
        decision = RetentionEngine.evaluate(
            runtime=self.runtime,
            task_context=task_security_context(self.context, self.schemas, self.runtime),
            registry=self.registry,
            subject_ref="object-tool-output",
            trigger="extracted",
        )
        self.assertEqual(decision.action, "purge")
        self.assertTrue(decision.tombstone_required)

    def test_holds_and_unresolved_actions_block_purge(self) -> None:
        for field in ("legal_hold", "rollback_dependency", "unresolved_action"):
            overrides = {"category": "evidence-body", "created_at": "2026-08-01T00:00:00Z", field: True}
            decision = RetentionEngine.evaluate(
                runtime=self.runtime,
                task_context=task_security_context(
                    self.context,
                    self.schemas,
                    self.runtime,
                    current_time="2026-08-14T00:00:00Z",
                    retention_overrides=overrides,
                ),
                registry=self.registry,
                subject_ref="object-tool-output",
                trigger="archive",
            )
            with self.subTest(field=field):
                self.assertEqual(decision.action, "blocked")

    def test_secret_body_persistence_and_unknown_category_fail_closed(self) -> None:
        with self.assertRaises(RetentionError):
            RetentionEngine.evaluate(
                runtime=self.runtime,
                task_context=task_security_context(
                    self.context,
                    self.schemas,
                    self.runtime,
                    current_time="2026-08-14T00:00:01Z",
                    retention_overrides={"sensitivity": "secret"},
                ),
                registry=self.registry,
                subject_ref="object-tool-output",
                trigger="write",
            )
        with self.assertRaises(RetentionError):
            self.registry.resolve("unknown")

    def test_purge_decision_must_be_revalidated_against_current_hold_snapshot(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, factory):
            original = issuer.issue_task_context("task-wp05a")
            registry = RetentionPolicyRegistry.from_dict(
                retention_policy_document(),
                schema_registry=self.schemas,
                context=self.context,
                runtime=issuer.runtime,
            )
            decision = RetentionEngine.evaluate(
                runtime=issuer.runtime,
                task_context=original,
                registry=registry,
                subject_ref="object-tool-output",
                trigger="extracted",
            )
            changed = task_security_state_document(
                retention_overrides={"legal_hold": True, "revision": 2},
            )
            write_durable_task_security_state(factory, changed)
            with self.assertRaises(RepositoryConflictError):
                issuer.authorize_purge("task-wp05a", decision)

    def test_current_purge_is_consumed_exactly_once(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, _factory):
            current = issuer.issue_task_context("task-wp05a")
            registry = RetentionPolicyRegistry.from_dict(
                retention_policy_document(),
                schema_registry=self.schemas,
                context=self.context,
                runtime=issuer.runtime,
            )
            decision = RetentionEngine.evaluate(
                runtime=issuer.runtime,
                task_context=current,
                registry=registry,
                subject_ref="object-tool-output",
                trigger="extracted",
            )
            authorization = issuer.authorize_purge("task-wp05a", decision)
            self.assertEqual(authorization.security_state_digest, current.state_digest)
            with self.assertRaises(RepositoryConflictError):
                issuer.authorize_purge("task-wp05a", decision)

    def test_current_unresolved_claim_is_read_from_repository(self) -> None:
        with durable_security_issuer(self.context, self.schemas) as (issuer, factory):
            current = issuer.issue_task_context("task-wp05a")
            registry = RetentionPolicyRegistry.from_dict(
                retention_policy_document(),
                schema_registry=self.schemas,
                context=self.context,
                runtime=issuer.runtime,
            )
            decision = RetentionEngine.evaluate(
                runtime=issuer.runtime,
                task_context=current,
                registry=registry,
                subject_ref="object-tool-output",
                trigger="extracted",
            )
            with factory._for_maintenance().open("application") as connection:
                with connection.transaction():
                    connection.execute(
                        "INSERT INTO leases(lease_id,request_digest,task_id,run_id,operation_id,"
                        "issued_at,expires_at,heartbeat_revision,state) "
                        "VALUES(?,?,?,?,?,?,?,?,'live')",
                        (
                            "lease-retention",
                            digest_value("lease-request"),
                            "task-wp05a",
                            "run-retention",
                            "operation-retention",
                            1,
                            2,
                            0,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO claims(claim_id,action_id,task_id,lease_id,"
                        "started_event_digest,state,outcome_digest) "
                        "VALUES(?,?,?,?,?,'unresolved',NULL)",
                        (
                            "claim-retention",
                            "action-retention",
                            "task-wp05a",
                            "lease-retention",
                            digest_value("started-event"),
                        ),
                    )
            with self.assertRaises(RepositoryConflictError):
                issuer.authorize_purge("task-wp05a", decision)


class ExtensionGateTests(unittest.TestCase):
    def test_builtin_data_descriptor_can_pass_but_non_builtin_executable_is_rejected(self) -> None:
        built_in = {
            "schema_version": "1.0.0",
            "extension_id": "builtin-validator",
            "extension_version": "1.0.0",
            "extension_kind": "validator",
            "source_kind": "built-in",
            "executable": False,
            "capabilities": [],
            "side_effects": [],
            "package_digest": digest_value("builtin-extension"),
        }
        approved = ExtensionGate.validate(
            built_in,
            approved_builtins={"builtin-validator": built_in["package_digest"]},
        )
        self.assertEqual(approved.extension_id, "builtin-validator")
        cases = []
        executable = copy.deepcopy(built_in)
        executable["extension_id"] = "third-party-exec"
        executable["source_kind"] = "third-party"
        executable["executable"] = True
        cases.append(executable)
        unknown_builtin = copy.deepcopy(built_in)
        unknown_builtin["extension_id"] = "unknown-builtin"
        cases.append(unknown_builtin)
        callable_injection = copy.deepcopy(built_in)
        callable_injection["implementation"] = lambda: True
        cases.append(callable_injection)
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ExtensionError):
                ExtensionGate.validate(
                    value,
                    approved_builtins={"builtin-validator": built_in["package_digest"]},
                )


if __name__ == "__main__":
    unittest.main()
