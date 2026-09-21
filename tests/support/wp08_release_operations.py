from __future__ import annotations

import base64

from graph_engineering.core.actions import PreparedAction
from graph_engineering.core.contracts.immutable import thaw
from graph_engineering.core.release_operations import ReleaseArtifactManifest
from graph_engineering.core.security.disclosure import DataDisclosurePlan, DisclosurePolicy
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.privacy import RedactionPolicy, Redactor
from graph_engineering.storage.codec import (
    canonical_json,
    parse_canonical_json,
    semantic_record_digest,
)
from tests.support.wp05_actions import ActionFixture, digest, prepared_document
from tests.support.wp05a_security import (
    disclosure_policy_document,
    redaction_policy_document,
)


def artifact_bytes() -> tuple[bytes, bytes]:
    return b"artifact-a\n", b"artifact-b\n"


def retarget_security_binding(fixture: ActionFixture, *, target_digest: str) -> None:
    command_factory = fixture.coordinator._factory
    with command_factory.open("application") as connection:
        with connection.transaction():
            row = connection.execute(
                "SELECT state_json FROM task_security_states WHERE task_id=?",
                (fixture.task_id,),
            ).fetchone()
            if row is None:
                raise AssertionError("release fixture task security state is missing")
            state = parse_canonical_json(row[0])
            if type(state) is not dict or type(state.get("binding")) is not dict:
                raise AssertionError("release fixture task security state is invalid")
            binding = state["binding"]
            targets = binding.get("targets")
            if type(targets) is not list or len(targets) != 1 or type(targets[0]) is not dict:
                raise AssertionError("release fixture target binding is invalid")
            targets[0]["target_digest"] = target_digest
            binding["binding_digest"] = SecurityBinding.digest_document(binding)
            state_digest = semantic_record_digest({
                "contract": "task-security-state-v1",
                "value": state,
            })
            connection.execute(
                "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                (canonical_json(state), state_digest, fixture.task_id),
            )


def release_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    candidate: ReleaseArtifactManifest,
    candidate_bytes: bytes,
) -> dict[str, object]:
    value = prepared_document(context=fixture.context)
    value["task_id"] = fixture.task_id
    value["resources"] = ["target:project", "task:" + fixture.task_id]
    payload = {
        "operation_id": "local-release-simulator.apply",
        "expected_generation": 0,
        "artifact_manifest": candidate.to_dict(),
        "artifact_bytes_base64": base64.b64encode(candidate_bytes).decode("ascii"),
    }
    value.update({
        "action_kind": "deploy",
        "target_digest": target_digest,
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": None,
        },
        "expected_postcondition": {
            "generation": 1,
            "active_artifact_digest": candidate.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": baseline.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_restore_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    baseline_bytes: bytes,
    candidate: ReleaseArtifactManifest,
    original_claim_id: str,
    original_receipt_digest: str,
) -> dict[str, object]:
    value = prepared_document(context=fixture.context)
    value["task_id"] = fixture.task_id
    value["resources"] = ["target:project", "task:" + fixture.task_id]
    payload = {
        "operation_id": "local-release-simulator.restore",
        "expected_generation": 1,
        "artifact_manifest": baseline.to_dict(),
        "artifact_bytes_base64": base64.b64encode(baseline_bytes).decode("ascii"),
        "original_claim_id": original_claim_id,
        "original_receipt_digest": original_receipt_digest,
    }
    value.update({
        "action_id": "action-wp05-release-restore",
        "action_kind": "rollback",
        "target_digest": target_digest,
        "snapshot_digest": fixture.current_task_snapshot_digest(),
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 1,
            "active_artifact_digest": candidate.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "expected_postcondition": {
            "generation": 2,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": baseline.manifest_digest,
        },
        "idempotency_key": "idempotency-wp05-release-restore",
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": candidate.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_partial_restore_prepared_document(
    fixture: ActionFixture,
    *,
    target_digest: str,
    baseline: ReleaseArtifactManifest,
    baseline_bytes: bytes,
    candidate: ReleaseArtifactManifest,
    original_claim_id: str,
    original_receipt_digest: str,
) -> dict[str, object]:
    """Prepare exact same-claim cleanup for staged-B/active-A unknown state."""

    value = prepared_document(context=fixture.context)
    value["task_id"] = fixture.task_id
    value["resources"] = ["target:project", "task:" + fixture.task_id]
    payload = {
        "operation_id": "local-release-simulator.restore",
        "expected_generation": 0,
        "artifact_manifest": baseline.to_dict(),
        "artifact_bytes_base64": base64.b64encode(baseline_bytes).decode("ascii"),
        "original_claim_id": original_claim_id,
        "original_receipt_digest": original_receipt_digest,
    }
    value.update({
        "action_id": "action-wp05-release-partial-restore",
        "action_kind": "rollback",
        "target_digest": target_digest,
        "snapshot_digest": fixture.current_task_snapshot_digest(),
        "payload": payload,
        "payload_digest": PreparedAction.payload_digest_for(payload, fixture.context),
        "precondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": candidate.manifest_digest,
        },
        "expected_postcondition": {
            "generation": 0,
            "active_artifact_digest": baseline.manifest_digest,
            "staged_artifact_digest": None,
        },
        "idempotency_key": "idempotency-wp05-release-partial-restore",
        "required_capabilities": [
            "deterministic-fake-target-v1",
            "fresh-target-query",
            "local-release-simulator-v1",
        ],
        "verification_plan": {
            "capability": "fresh-target-query",
            "predicate": "exact-release-state",
        },
        "rollback_plan": {
            "capability": "fake-compensation",
            "artifact_manifest_digest": candidate.manifest_digest,
        },
    })
    value["prepared_action_digest"] = PreparedAction.digest_document(
        value, fixture.context,
    )
    return value


def release_disclosure_plan(
    fixture: ActionFixture,
    prepared: PreparedAction,
) -> DataDisclosurePlan:
    runtime = fixture.issuer.runtime
    policy = DisclosurePolicy.from_dict(
        disclosure_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=runtime,
    )
    redaction_policy = RedactionPolicy.from_dict(
        redaction_policy_document(), schema_registry=fixture.schemas,
        context=fixture.context, runtime=runtime,
    )
    allowlist = tuple(f"/{key}" for key in sorted(prepared.payload))
    redacted = Redactor.redact(
        dict(prepared.payload), field_allowlist=allowlist, transforms={},
        secret_materials=(), policy=redaction_policy, context=fixture.context,
    )
    if redacted.as_dict() != thaw(prepared.payload):
        raise AssertionError("release payload disclosure projection changed")
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "disclosure_id": "disclosure-wp08-release",
        "destination": {
            "identity_ref": "owner-wp05", "kind": "owner",
            "trust_boundary": "owner-session",
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
        value, policy=policy, runtime=runtime,
        task_context=fixture.issuer.issue_task_context(prepared.task_id),
        redacted_payload=redacted, schema_registry=fixture.schemas,
        context=fixture.context,
    )


def release_mandatory_runtime(*, column: str, task_id: str, accepted: bool):
    """Own one distinct task and retained local release action stack."""
    from tests.integration.test_wp08_release_operations import WP08RetainedReleaseSessionTests

    return WP08RetainedReleaseSessionTests()._same_task_assessment(
        cold=True, partial=column in {"recovery", "rollback"}, column=column,
        accepted=accepted, task_id=task_id,
    )


class PrivateReleaseCoverageRoot:
    """Preserve files while closing every producing and consuming source port."""

    def __init__(self):
        import pathlib
        import tempfile
        self._temporary = tempfile.TemporaryDirectory(prefix="gew-private-release-coverage-")
        self.path = pathlib.Path(self._temporary.name).resolve()
        self._producer = self._stack = self._reader = None
        self._resources = None
        self.closed_phases = 0

    def produce(self, **arguments):
        import tempfile
        from contextlib import contextmanager
        from unittest import mock
        original = tempfile.TemporaryDirectory
        preserved = set()

        @contextmanager
        def directories(*args, **kwargs):
            selected = {"gew-wp03-": "repository-fixture",
                "gew-retained-assessment-": "retained-namespace"}.get(kwargs.get("prefix"))
            if selected is None or selected in preserved:
                with original(*args, **{**kwargs, "dir": self.path}) as path:
                    yield path
            else:
                preserved.add(selected)
                path = self.path / selected
                path.mkdir(mode=0o700)
                yield str(path)

        self._producer = release_mandatory_runtime(**arguments)
        with mock.patch.object(tempfile, "TemporaryDirectory", directories):
            values = self._producer.__enter__()
        action = values[1]
        self.paths = {"repository": action.repository._factory._root,
            "installation_control": action.factory._test_installation_control_root,
            "namespace": action.retained_namespace._record()[4].path}
        self._remember_resources(action.repository.command_scope, action.objects,
            action.coordinator._locks, action.retained_namespace)
        return values

    def _remember_resources(self, scope, objects, locks, namespace):
        directories = []
        for directory in (objects._objects_directory, objects._staging_directory,
                locks._lock_directory, locks._resource_directory):
            while directory is not None:
                if directory not in directories:
                    directories.append(directory)
                directory = directory._parent
        self._resources = (scope, tuple(directories), namespace._record()[4])

    def _assert_closed(self):
        import os
        if self._resources is None:
            return
        scope, directories, native = self._resources
        if scope._connections or native._active or not native._closed:
            raise AssertionError("release source connection or lease remained open")
        for directory in directories:
            if not directory._closed:
                raise AssertionError("release source directory remained open")
            try:
                os.fstat(directory._descriptor)
            except OSError:
                pass
            else:
                raise AssertionError("release source descriptor remained open")
        self._resources = None
        self.closed_phases += 1

    def seal_producer(self, reader):
        self._reader = reader
        reader.quiesce(reader)
        self._producer.__exit__(None, None, None)
        self._producer = None
        self._assert_closed()

    def open(self):
        from contextlib import ExitStack
        from unittest import mock
        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.core.actions import ActionPolicy
        from graph_engineering.core.profile_execution import CategoryExecutionPolicy
        from graph_engineering.storage.actions import ActionJournalRepository
        from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.storage.locks import LockedFileRegistry
        from graph_engineering.storage.migration import InstallationMigrationRepository
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.security import SecurityStateRepository
        from tests.contract.test_wp02_graph import graph_schemas, work_context
        from tests.support.wp03_repository import policy as repository_policy, mount_observation
        from tests.support.wp05a_security import security_context, security_schema_registry
        from tests.support.wp07a_actions import action_adapter_schema_registry
        from tests.support import wp08_category_execution as category
        from tests.integration.test_wp08_release_operations import WP08RetainedReleaseSessionTests

        if self._stack is not None or self._producer is not None:
            raise AssertionError("release private source is already open")
        self._stack = stack = ExitStack()
        try:
            stack.enter_context(mock.patch.object(RepositoryDoctor, "_mount_observation", side_effect=mount_observation))
            maintenance = ConnectionFactory._attach_existing_for_maintenance(
                self.paths["repository"], repository_policy(), "repository-test-v1")
            locks = LockedFileRegistry(maintenance); stack.callback(locks.close)
            maintenance_objects = ObjectRepository(maintenance, locks); stack.callback(maintenance_objects.close)
            manager = InstallationMigrationRepository.attach_command_plane(maintenance, locks, maintenance_objects,
                control_root=self.paths["installation_control"],
                policy_document=category.load_json(category.ROOT / "config/contracts/migration-storage-policy-v1.json"))
            stack.callback(manager.close)
            scope = stack.enter_context(manager.command_scope())
            factory = maintenance.bind_command_scope(scope)
            objects = ObjectRepository(factory, locks); stack.callback(objects.close)
            leases = ResourceLeaseRepository(factory, locks)
            context = security_context()
            schemas = security_schema_registry(context)
            journal = ActionJournalRepository(factory, schema_registry=schemas, context=context)
            repository = TaskRepository(factory, locks, objects, action_journal=journal,
                concrete_action_schemas=action_adapter_schema_registry(context),
                concrete_action_context=context, command_scope=scope)
            issuer = SecurityContextIssuer(SecurityStateRepository(factory), schema_registry=schemas, context=context)
            action_policy = ActionPolicy.from_dict(category.load_json(category.ROOT / "config/actions/action-policy-v1.json"),
                schema_registry=schemas, context=context, runtime=issuer.runtime)
            coordinator = ActionCoordinator(journal=journal, repository=repository, leases=leases, locks=locks,
                objects=objects, security_issuer=issuer, action_policy=action_policy, installation_scope=scope)
            app = TaskApplication(repository, repository, leases, schema_registry=graph_schemas(),
                context=work_context(), materialization_objects=objects)
            runtime = stack.enter_context(WP08RetainedReleaseSessionTests()._runtime())
            runtime_context = runtime._issue_context("2026-09-21T00:00:00Z", 10**15)
            namespace = stack.enter_context(runtime.bind_release_namespace(
                action_coordinator=coordinator, namespace_path=self.paths["namespace"]))
            policy = CategoryExecutionPolicy.from_installation(
                profile_document=category.profile_document("release-operations"),
                support_matrix_document=category.load_json(category.SUPPORT_MATRIX_PATH),
                materialization_record=category.materialized_profile("release-operations").record)
            release = ReleaseOperationsRegistryFactory.from_installation()
            if release._issued or coordinator._issued_outcomes:
                raise AssertionError("release reader invented live issuance")
            self._remember_resources(scope, objects, locks, namespace)
            self._reader._bind_read_ports(app=app, runtime=runtime_context, objects=objects,
                coordinator=coordinator, namespace=namespace, factory=release, policy=policy)
            return self._reader.open()
        except BaseException:
            self.close_handle(self._reader)
            raise

    def refresh(self):
        self.close_handle(self._reader)
        return self.open()

    def close_handle(self, handle):
        if handle is not self._reader:
            raise AssertionError("release private close handle is foreign")
        try:
            if self._reader is not None:
                self._reader.quiesce(handle)
        finally:
            if self._stack is not None:
                stack, self._stack = self._stack, None
                stack.close()
            self._assert_closed()

    def terminate(self, action):
        try:
            if self._stack is not None:
                self.close_handle(self._reader)
            if self._reader is not None:
                self._reader.terminate(action)
            if self._producer is not None:
                self._producer.__exit__(None, None, None)
                self._producer = None
        finally:
            self._temporary.cleanup()

    def __exit__(self, *_):
        self.terminate("revoke")
