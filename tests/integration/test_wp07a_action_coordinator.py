from __future__ import annotations

import hashlib
import copy
import dataclasses
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from graph_engineering.adapters.action_adapters import ActionAdapterFactory
from graph_engineering.adapters.git_native import GitAdapterConfiguration, GitTargetPlan
from graph_engineering.application.actions import ActionCoordinator
from graph_engineering.core.action_adapters import ActionAdapterRegistry, ConcreteActionPolicy
from graph_engineering.core.actions import PreparedAction
from graph_engineering.core.security.disclosure import DataDisclosurePlan, DisclosurePolicy
from graph_engineering.core.security.privacy import RedactionPolicy, Redactor
from tests.integration.test_wp07a_git_readonly import mutation_payload, raw_git
from tests.support.wp05_actions import (
    action_stack,
    authority_document,
    digest,
    prepared_document,
)
from tests.support.wp05a_security import (
    disclosure_policy_document,
    redaction_policy_document,
)
from tests.support.wp07a_actions import installed_action_adapter_attestation


ROOT = pathlib.Path(__file__).resolve().parents[2]


def coordinator_target_plan(root: pathlib.Path) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "plan_id": "git-plan-wp07a-coordinator",
        "target_id": "target-project",
        "target_digest": digest("target"),
        "allowed_root": os.fspath(root),
        "relative_path": "project",
    }
    body["plan_digest"] = GitTargetPlan.digest_document(body)
    return body


def concrete_factory(
    git_configuration_document: dict[str, object],
) -> tuple[ActionAdapterFactory, ConcreteActionPolicy, ActionAdapterRegistry]:
    registry = ActionAdapterRegistry.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
    ))
    policy = ConcreteActionPolicy.from_dict(
        json.loads((ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()),
        registry=registry,
    )
    return ActionAdapterFactory(
        policy,
        registry,
        installation_attestation=installed_action_adapter_attestation(),
        configuration_digests={
            "git-adapter-configuration": git_configuration_document["configuration_digest"],
        },
    ), policy, registry  # type: ignore[arg-type]


def git_configuration(executable: pathlib.Path) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "configuration_id": "git-native-coordinator-test",
        "adapter_id": "git-native-v1",
        "executable": os.fspath(executable),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "max_output_bytes": 65536,
        "timeout_seconds": 10,
    }
    body["configuration_digest"] = GitAdapterConfiguration.digest_document(body)
    return body


def disclosure(fixture, issuer, prepared: PreparedAction) -> DataDisclosurePlan:
    disclosure_policy = DisclosurePolicy.from_dict(
        disclosure_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=issuer.runtime,
    )
    redaction_policy = RedactionPolicy.from_dict(
        redaction_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=issuer.runtime,
    )
    allowlist = tuple(f"/{key}" for key in sorted(prepared.payload))
    redacted = Redactor.redact(
        dict(prepared.payload), field_allowlist=allowlist, transforms={}, secret_materials=(),
        policy=redaction_policy, context=fixture.context,
    )
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "disclosure_id": "disclosure-wp07a-git",
        "destination": {
            "identity_ref": "owner-wp05", "kind": "owner", "trust_boundary": "owner-session",
        },
        "purpose": "owner-update",
        "data_refs": [{
            "ref_id": "action-payload", "digest": digest("payload-source"),
            "sensitivity": "internal",
        }],
        "maximum_sensitivity": "internal",
        "field_allowlist": list(allowlist),
        "redaction_transforms": [],
        "retention_class": "evidence-body",
        "authority_digest": None,
        "prepared_action_digest": prepared.prepared_action_digest,
        "snapshot_digest": prepared.snapshot_digest,
        "payload_digest": redacted.payload_digest,
        "receipt_required": False,
    }
    value["plan_digest"] = DataDisclosurePlan.digest_document(value)
    return DataDisclosurePlan.from_dict(
        value,
        policy=disclosure_policy,
        runtime=issuer.runtime,
        task_context=issuer.issue_task_context(prepared.task_id),
        redacted_payload=redacted,
        schema_registry=fixture.schemas,
        context=fixture.context,
    )


class WP07AConcreteActionCoordinatorTests(unittest.TestCase):
    def test_gew_act_008_real_git_path_persists_typed_records_and_reconciles_before_completion(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        git_config = git_configuration(executable)
        action_factory, concrete_policy, concrete_registry = concrete_factory(git_config)
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-coordinator-") as directory, action_stack(
            concrete_action_authority=(action_factory, concrete_policy, concrete_registry),
        ) as fixture:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            for message in ("first", "second"):
                subprocess.run(
                    (
                        os.fspath(executable), "-C", os.fspath(repository),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "--quiet", "--allow-empty", "-m", message,
                    ),
                    shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                if message == "first":
                    first_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            second_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            subprocess.run(
                (os.fspath(executable), "-C", os.fspath(repository), "reset", "--quiet", "--hard", first_oid),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            adapter = action_factory.issue_git_native(git_config)
            target = GitTargetPlan.from_dict(coordinator_target_plan(root))
            before = adapter.observe(coordinator_target_plan(root), expected=target)
            coordinator = fixture.coordinator
            raw_coordinator = fixture.raw_coordinator
            issuer = fixture.issuer
            value = prepared_document()
            payload = mutation_payload(
                target,
                ref_name=before.head_ref,
                expected_old_oid=first_oid,
                new_oid=second_oid,
            )
            value.update({
                "payload": payload,
                "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
                "precondition": {"head_oid": first_oid, "head_ref": before.head_ref},
                "expected_postcondition": {"head_oid": second_oid, "head_ref": before.head_ref},
                "required_capabilities": ["fresh-target-query", "native-precondition"],
            })
            value["prepared_action_digest"] = PreparedAction.digest_document(value, fixture.context)
            prepared = coordinator.prepare(value)
            coordinator.authorize(authority_document(prepared))
            stale_tokens = tuple(
                (resource, token + 1 if index == 0 else token)
                for index, (resource, token) in enumerate(fixture.action_lease.fencing_tokens)
            )
            stale_lease = dataclasses.replace(
                fixture.action_lease,
                fencing_tokens=stale_tokens,
            )
            queries_before_stale = adapter.query_count
            with self.assertRaisesRegex(ValueError, "action authority rejected"):
                raw_coordinator.execute_concrete_git(
                    prepared.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=stale_lease,
                    adapter=adapter,
                    target_plan_document=coordinator_target_plan(root),
                    expected_target=target,
                    disclosure_plan=disclosure(fixture, issuer, prepared),
                )
            self.assertEqual(adapter.query_count, queries_before_stale)
            self.assertEqual(adapter.mutation_count, 0)
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "authorized")
            outcome = raw_coordinator.execute_concrete_git(
                prepared.action_id,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                lease=fixture.action_lease,
                adapter=adapter,
                target_plan_document=coordinator_target_plan(root),
                expected_target=target,
                disclosure_plan=disclosure(fixture, issuer, prepared),
            )
            self.assertEqual(outcome.state, "reconciled")
            self.assertEqual(raw_git(executable, repository, "rev-parse", before.head_ref), second_oid)
            self.assertEqual(adapter.mutation_count, 1)
            self.assertEqual(adapter.query_count, 4)
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "reconciled")
            with fixture.repository._factory.open("doctor") as connection:
                records = tuple(connection.execute(
                    "SELECT record_type FROM concrete_action_records WHERE action_id=? ORDER BY record_type",
                    (prepared.action_id,),
                ))
                claim = connection.execute(
                    "SELECT state FROM claims WHERE action_id=?", (prepared.action_id,),
                ).fetchone()
            self.assertEqual(records, (("invocation",), ("observation",), ("receipt",)))
            self.assertEqual(claim, ("reconciled_effect_verified",))

    def test_gew_act_008a_re_signed_registry_substitution_cannot_enter_real_coordinator(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        git_config = git_configuration(executable)
        action_factory, concrete_policy, concrete_registry = concrete_factory(git_config)
        adapter = action_factory.issue_git_native(git_config)
        registry_document = json.loads(
            (ROOT / "config" / "contracts" / "action-adapter-registry-v1.json").read_text()
        )
        changed_registry = copy.deepcopy(registry_document)
        changed_registry["entries"][0]["implementation_digest"] = digest("foreign-implementation")
        changed_registry["registry_digest"] = ActionAdapterRegistry.digest_document(changed_registry)
        foreign_registry = ActionAdapterRegistry.from_dict(changed_registry)
        policy_document = json.loads(
            (ROOT / "config" / "actions" / "concrete-action-policy-v1.json").read_text()
        )
        changed_policy = copy.deepcopy(policy_document)
        changed_policy["registry_digest"] = foreign_registry.registry_digest
        changed_policy["policy_digest"] = ConcreteActionPolicy.digest_document(changed_policy)
        foreign_policy = ConcreteActionPolicy.from_dict(changed_policy, registry=foreign_registry)
        with action_stack(
            concrete_action_authority=(action_factory, concrete_policy, concrete_registry),
        ) as fixture:
            with self.assertRaisesRegex(ValueError, "concrete adapter authority"):
                ActionCoordinator(
                    journal=fixture.journal._journal,
                    repository=fixture.repository,
                    leases=fixture.leases,
                    locks=fixture.locks,
                    objects=fixture.objects,
                    security_issuer=fixture.issuer,
                    action_policy=fixture.raw_coordinator._policy,
                    installation_scope=fixture.repository.command_scope,
                    action_adapter_factory=action_factory,
                    concrete_action_policy=foreign_policy,
                    concrete_action_registry=foreign_registry,
                )
        self.assertEqual(adapter.mutation_count, 0)

    def test_gew_act_008b_crash_after_started_commit_retries_without_native_replay(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        git_config = git_configuration(executable)
        action_factory, concrete_policy, concrete_registry = concrete_factory(git_config)
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-coordinator-crash-") as directory, action_stack(
            concrete_action_authority=(action_factory, concrete_policy, concrete_registry),
        ) as fixture:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            for message in ("first", "second"):
                subprocess.run(
                    (
                        os.fspath(executable), "-C", os.fspath(repository),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "--quiet", "--allow-empty", "-m", message,
                    ),
                    shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                if message == "first":
                    first_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            second_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            subprocess.run(
                (os.fspath(executable), "-C", os.fspath(repository), "reset", "--quiet", "--hard", first_oid),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            adapter = action_factory.issue_git_native(git_config)
            target_document = coordinator_target_plan(root)
            target = GitTargetPlan.from_dict(target_document)
            before = adapter.observe(target_document, expected=target)
            payload = mutation_payload(
                target,
                ref_name=before.head_ref,
                expected_old_oid=first_oid,
                new_oid=second_oid,
            )
            value = prepared_document()
            value.update({
                "action_id": "action-wp07a-crash",
                "idempotency_key": "idempotency-wp07a-crash",
                "payload": payload,
                "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
                "precondition": {"head_oid": first_oid, "head_ref": before.head_ref},
                "expected_postcondition": {"head_oid": second_oid, "head_ref": before.head_ref},
                "required_capabilities": ["fresh-target-query", "native-precondition"],
            })
            value["prepared_action_digest"] = PreparedAction.digest_document(value, fixture.context)
            prepared = fixture.coordinator.prepare(value)
            fixture.coordinator.authorize(authority_document(prepared))

            def crash(step: str) -> None:
                if step == "concrete.after-start-commit":
                    raise RuntimeError("fixture crash after committed start")

            fixture.raw_coordinator._fault = crash
            arguments = {
                "owner_id": "owner-wp05",
                "runtime_kind": "codex",
                "runtime_lineage_id": "lineage-wp05",
                "lease": fixture.action_lease,
                "adapter": adapter,
                "target_plan_document": target_document,
                "expected_target": target,
                "disclosure_plan": disclosure(fixture, fixture.issuer, prepared),
            }
            with self.assertRaisesRegex(RuntimeError, "committed start"):
                fixture.raw_coordinator.execute_concrete_git(prepared.action_id, **arguments)
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "executing")
            self.assertEqual(adapter.mutation_count, 0)
            self.assertEqual(raw_git(executable, repository, "rev-parse", before.head_ref), first_oid)
            events_before_retry = fixture.repository.replay(prepared.task_id)
            fixture.raw_coordinator._fault = lambda _step: None
            retry = fixture.raw_coordinator.execute_concrete_git(prepared.action_id, **arguments)
            self.assertEqual((retry.state, retry.route), (
                "executing", "manual-target-reconciliation",
            ))
            self.assertEqual(fixture.repository.replay(prepared.task_id), events_before_retry)
            self.assertEqual(adapter.mutation_count, 0)
            self.assertEqual(adapter.query_count, 3)
            with fixture.repository._factory.open("doctor") as connection:
                claim = connection.execute(
                    "SELECT state FROM claims WHERE action_id=?", (prepared.action_id,),
                ).fetchone()
                records = tuple(connection.execute(
                    "SELECT record_type FROM concrete_action_records WHERE action_id=?",
                    (prepared.action_id,),
                ))
            self.assertEqual(claim, ("unresolved",))
            self.assertEqual(records, (("invocation",),))

    def test_gew_act_008c_after_receipt_drift_cannot_consume_the_claim(self) -> None:
        executable_name = shutil.which("git")
        self.assertIsNotNone(executable_name)
        executable = pathlib.Path(executable_name).resolve()
        git_config = git_configuration(executable)
        action_factory, concrete_policy, concrete_registry = concrete_factory(git_config)
        with tempfile.TemporaryDirectory(prefix="gew-wp07a-coordinator-drift-") as directory, action_stack(
            concrete_action_authority=(action_factory, concrete_policy, concrete_registry),
        ) as fixture:
            root = pathlib.Path(directory)
            repository = root / "project"
            subprocess.run(
                (os.fspath(executable), "init", "--quiet", os.fspath(repository)),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            for message in ("first", "second"):
                subprocess.run(
                    (
                        os.fspath(executable), "-C", os.fspath(repository),
                        "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                        "commit", "--quiet", "--allow-empty", "-m", message,
                    ),
                    shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                )
                if message == "first":
                    first_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            second_oid = raw_git(executable, repository, "rev-parse", "HEAD")
            subprocess.run(
                (os.fspath(executable), "-C", os.fspath(repository), "reset", "--quiet", "--hard", first_oid),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            adapter = action_factory.issue_git_native(git_config)
            target_document = coordinator_target_plan(root)
            target = GitTargetPlan.from_dict(target_document)
            before = adapter.observe(target_document, expected=target)
            payload = mutation_payload(
                target,
                ref_name=before.head_ref,
                expected_old_oid=first_oid,
                new_oid=second_oid,
            )
            value = prepared_document()
            value.update({
                "action_id": "action-wp07a-drift",
                "idempotency_key": "idempotency-wp07a-drift",
                "payload": payload,
                "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
                "precondition": {"head_oid": first_oid, "head_ref": before.head_ref},
                "expected_postcondition": {"head_oid": second_oid, "head_ref": before.head_ref},
                "required_capabilities": ["fresh-target-query", "native-precondition"],
            })
            value["prepared_action_digest"] = PreparedAction.digest_document(value, fixture.context)
            prepared = fixture.coordinator.prepare(value)
            fixture.coordinator.authorize(authority_document(prepared))

            def drift(step: str) -> None:
                if step == "concrete.after-receipt-commit":
                    subprocess.run(
                        (
                            os.fspath(executable), "-C", os.fspath(repository),
                            "update-ref", before.head_ref, first_oid, second_oid,
                        ),
                        shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=10,
                    )
                    raise RuntimeError("fixture crash after receipt and target drift")

            fixture.raw_coordinator._fault = drift
            arguments = {
                "owner_id": "owner-wp05",
                "runtime_kind": "codex",
                "runtime_lineage_id": "lineage-wp05",
                "lease": fixture.action_lease,
                "adapter": adapter,
                "target_plan_document": target_document,
                "expected_target": target,
                "disclosure_plan": disclosure(fixture, fixture.issuer, prepared),
            }
            with self.assertRaisesRegex(RuntimeError, "receipt and target drift"):
                fixture.raw_coordinator.execute_concrete_git(prepared.action_id, **arguments)
            self.assertEqual((adapter.mutation_count, adapter.query_count), (1, 3))
            fixture.raw_coordinator._fault = lambda _step: None
            outcome = fixture.raw_coordinator.execute_concrete_git(prepared.action_id, **arguments)
            self.assertEqual((outcome.state, outcome.route), (
                "succeeded", "manual-target-reconciliation",
            ))
            self.assertEqual(raw_git(executable, repository, "rev-parse", before.head_ref), first_oid)
            self.assertEqual((adapter.mutation_count, adapter.query_count), (1, 4))
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "succeeded")
            with fixture.repository._factory.open("doctor") as connection:
                claim = connection.execute(
                    "SELECT state FROM claims WHERE action_id=?", (prepared.action_id,),
                ).fetchone()
                records = tuple(connection.execute(
                    "SELECT record_type FROM concrete_action_records WHERE action_id=? "
                    "ORDER BY record_type",
                    (prepared.action_id,),
                ))
            self.assertEqual(claim, ("unresolved",))
            self.assertEqual(records, (("invocation",), ("receipt",)))

            queries_before_rejections = adapter.query_count
            events_before_rejections = fixture.repository.replay(prepared.task_id)
            stale_tokens = tuple(
                (resource, token + (1 if index == 0 else 0))
                for index, (resource, token) in enumerate(fixture.action_lease.fencing_tokens)
            )
            missing_task_lease = dataclasses.replace(
                fixture.action_lease,
                resources=("target:project",),
                fencing_tokens=(fixture.action_lease.fencing_tokens[0],),
            )
            foreign_disclosure = copy.copy(arguments["disclosure_plan"])
            object.__setattr__(
                foreign_disclosure,
                "prepared_action_digest",
                digest("foreign-prepared"),
            )
            rejected = (
                (prepared.action_id, {**arguments, "owner_id": "owner-foreign"}),
                (prepared.action_id, {**arguments, "runtime_kind": "hermes"}),
                (prepared.action_id, {**arguments, "runtime_lineage_id": "lineage-foreign"}),
                (prepared.action_id, {**arguments, "lease": missing_task_lease}),
                (prepared.action_id, {**arguments, "lease": dataclasses.replace(
                    fixture.action_lease, fencing_tokens=stale_tokens,
                )}),
                (prepared.action_id, {**arguments, "expected_target": dataclasses.replace(
                    target, target_digest=digest("foreign-target"),
                )}),
                (prepared.action_id, {**arguments, "disclosure_plan": foreign_disclosure}),
                ("action-missing", arguments),
            )
            for rejected_action_id, rejected_arguments in rejected:
                with self.subTest(rejected_action_id=rejected_action_id), self.assertRaisesRegex(
                    ValueError, "^concrete Git action authority rejected$",
                ):
                    fixture.raw_coordinator.execute_concrete_git(
                        rejected_action_id, **rejected_arguments,
                    )
            self.assertEqual(adapter.query_count, queries_before_rejections)
            self.assertEqual(adapter.mutation_count, 1)
            self.assertEqual(fixture.repository.replay(prepared.task_id), events_before_rejections)

            subprocess.run(
                (
                    os.fspath(executable), "-C", os.fspath(repository),
                    "update-ref", before.head_ref, second_oid, first_oid,
                ),
                shell=False, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
            )
            recovered = fixture.raw_coordinator.execute_concrete_git(prepared.action_id, **arguments)
            self.assertEqual((recovered.state, recovered.route), (
                "reconciled", "reconciled-effect-verified",
            ))
            self.assertEqual((adapter.mutation_count, adapter.query_count), (1, 5))
            self.assertEqual(fixture.journal.load(prepared.action_id).state, "reconciled")


if __name__ == "__main__":
    unittest.main()
