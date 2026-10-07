"""Local installed-runtime composition for the owner-turn application use case."""

from __future__ import annotations

import json
import pathlib
from contextlib import contextmanager
from collections.abc import Mapping, Iterator
from typing import NoReturn
from typing import cast

from graph_engineering.adapters.runtime_adapters import RuntimeAdapterFactory, RuntimeInvocationPorts
from graph_engineering.adapters.runtime_config import ConfiguredRuntimeHandshake
from graph_engineering.adapters.runtime_locator import VerifiedExecutable
from graph_engineering.application.owner_turns import OwnerTurnApplication
from graph_engineering.application.runtime import RuntimeSession
from graph_engineering.application.tasks import TaskApplication
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
from graph_engineering.core.contracts.schema import SchemaProfilePolicy
from graph_engineering.core.project import (
    PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID,
    PROJECT_SCOPE_SCHEMA_ID,
    ProjectScope,
)
from graph_engineering.core.runtime import (
    DeliveryReceipt,
    DeliveryPresentation,
    HumanDecision,
    HumanDecisionRequest,
    OwnerIdentity,
    RuntimeCompatibilityRequest,
    RuntimeLineage,
    RuntimeResourceGuard,
    runtime_record_digest,
)
from graph_engineering.storage.connection import ConnectionFactory
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.migration import InstallationMigrationRepository
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.policy import RepositoryPolicy
from graph_engineering.storage.repository import TaskRepository


class LocalOwnerTurnRuntime:
    """Build fresh command-scoped dependencies for each installed owner operation."""

    def __init__(
        self,
        *,
        configuration: Mapping[str, object],
        executable: VerifiedExecutable,
        guard: RuntimeResourceGuard,
        compatibility: RuntimeCompatibilityRequest,
        raw_input: Mapping[str, object],
        repository_root: pathlib.Path,
        control_root: pathlib.Path,
        repository_policy_path: pathlib.Path,
        migration_policy_path: pathlib.Path,
        local_port_policy: Mapping[str, object],
        schema_profile_path: pathlib.Path,
        schema_manifest_path: pathlib.Path,
        schema_root: pathlib.Path,
    ) -> None:
        port_fields = {
            "schema_version", "human_status", "decision_ref_prefix",
            "presentation_status", "delivery_ref_prefix", "policy_digest",
        }
        if not isinstance(local_port_policy, Mapping) or set(local_port_policy) != port_fields:
            raise RuntimeError("local runtime port policy is not exact")
        port_body = {
            key: value for key, value in local_port_policy.items() if key != "policy_digest"
        }
        if local_port_policy["policy_digest"] != runtime_record_digest(
            "local-runtime-port-policy", port_body,
        ):
            raise RuntimeError("local runtime port policy digest is invalid")
        if (
            configuration.get("runtime_local_port_policy_digest")
            != local_port_policy["policy_digest"]
        ):
            raise RuntimeError("runtime configuration does not bind the local port policy")
        for name in port_fields - {"policy_digest"}:
            if (
                type(local_port_policy[name]) is not str
                or not local_port_policy[name]
                or local_port_policy[name] != local_port_policy[name].strip()
                or "\x00" in local_port_policy[name]
            ):
                raise RuntimeError("local runtime port policy value is invalid")
        human_status = cast(str, local_port_policy["human_status"])
        decision_ref_prefix = cast(str, local_port_policy["decision_ref_prefix"])
        presentation_status = cast(str, local_port_policy["presentation_status"])
        delivery_ref_prefix = cast(str, local_port_policy["delivery_ref_prefix"])
        if human_status not in {"approved", "rejected", "pending"} or presentation_status not in {
            "delivered", "failed", "pending",
        }:
            raise RuntimeError("local runtime port policy status is invalid")
        profile = guard.context.profile
        schedule = guard.context.schedule
        schema_policy = SchemaProfilePolicy.from_dict(json.loads(schema_profile_path.read_text()))
        manifest = json.loads(schema_manifest_path.read_text())
        resources = manifest.get("resources")
        if not isinstance(resources, list):
            raise RuntimeError("graph schema manifest resources are invalid")
        available = {
            document["$id"]: path.read_bytes()
            for path in schema_root.glob("*.json")
            for document in (json.loads(path.read_text()),)
            if isinstance(document, Mapping) and type(document.get("$id")) is str
        }
        bodies = {}
        for resource in resources:
            if not isinstance(resource, Mapping) or type(resource.get("schema_id")) is not str:
                raise RuntimeError("graph schema manifest resource is invalid")
            schema_id = resource["schema_id"]
            if schema_id not in available:
                raise RuntimeError("graph schema body is missing or ambiguous")
            bodies[schema_id] = available[schema_id]
        schemas = ClosedSchemaRegistry.build(manifest, bodies, profile, schema_policy)
        scope_bodies = {
            schema_id: available[schema_id]
            for schema_id in (PROJECT_SCOPE_SCHEMA_ID, PROJECT_SCOPE_DIGEST_INPUT_SCHEMA_ID)
        }
        scope_manifest = ClosedSchemaRegistry.create_manifest(
            "urn:gew:schema-registry:project-scope:1.0.0", scope_bodies,
        )
        scope_schemas = ClosedSchemaRegistry.build(
            scope_manifest, scope_bodies, profile, schema_policy,
        )
        repository_policy = RepositoryPolicy.from_dict(json.loads(repository_policy_path.read_text()))
        migration_policy = json.loads(migration_policy_path.read_text())
        repository_id = "repository-owner-turn-" + str(configuration["runtime_instance_id"])
        repository_exists = repository_root.exists()
        control_exists = control_root.exists()
        if repository_exists != control_exists:
            raise RuntimeError("local owner-turn installation is incomplete")
        factory = (
            ConnectionFactory._attach_existing_for_maintenance(
                repository_root, repository_policy, repository_id,
            )
            if repository_exists
            else ConnectionFactory.initialize(
                repository_root, repository_policy, repository_id,
            )
        )
        locks = LockedFileRegistry(factory)
        maintenance = factory._for_maintenance()
        maintenance_objects = ObjectRepository(maintenance, locks)
        manager_factory = (
            InstallationMigrationRepository.attach_command_plane
            if repository_exists else InstallationMigrationRepository.initialize
        )
        manager = manager_factory(
            maintenance, locks, maintenance_objects, control_root=control_root,
            policy_document=migration_policy,
        )
        active_tasks = []

        @contextmanager
        def task_provider() -> Iterator[TaskApplication]:
            with manager.command_scope() as scope:
                _manifest, current = manager._current_factory(scope._control_token())
                bound_factory = current.bind_command_scope(scope)
                owns_locks = bound_factory.data_root != locks._root
                current_locks = LockedFileRegistry(bound_factory) if owns_locks else locks
                objects = ObjectRepository(bound_factory, current_locks)
                try:
                    leases = ResourceLeaseRepository(bound_factory, current_locks)
                    repository = TaskRepository(bound_factory, current_locks, objects, command_scope=scope)
                    tasks = TaskApplication(repository, repository, leases, schema_registry=schemas,
                        context=WorkContext(profile, schedule))
                    active_tasks.append(tasks)
                    yield tasks
                finally:
                    active_tasks.clear()
                    objects.close()
                    if owns_locks:
                        current_locks.close()

        def authorize(
            task_id: str, owner: OwnerIdentity, lineage: RuntimeLineage,
        ) -> Mapping[str, object] | None:
            try:
                if active_tasks:
                    loaded = active_tasks[0]._repository.load(task_id)
                else:
                    with task_provider() as current_tasks:
                        loaded = current_tasks._repository.load(task_id)
                identity = loaded["domain"]["identity"]
            except Exception:
                return None
            expected = {
                "task_id": task_id, "owner_id": owner.owner_id,
                "runtime_kind": lineage.runtime_kind,
                "runtime_lineage_id": lineage.lineage_id,
            }
            return expected if all(identity.get(key) == value for key, value in expected.items()) else None

        def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
            raise RuntimeError("external runtime port is not configured for local owner turns")

        def pending_human(
            request: HumanDecisionRequest, _owner: OwnerIdentity, _lineage: RuntimeLineage,
        ) -> HumanDecision:
            body = {
                "schema_version": "1.0", "request_id": request.request_id,
                "task_id": request.task_id, "owner_id": request.owner_id,
                "status": human_status,
                "decision_ref": decision_ref_prefix + request.request_digest,
            }
            return HumanDecision.from_dict({
                **body, "decision_digest": runtime_record_digest("human-decision", body),
            })

        def pending_presentation(
            presentation: DeliveryPresentation, _owner: OwnerIdentity, lineage: RuntimeLineage,
        ) -> DeliveryReceipt:
            body = {
                "schema_version": "1.0", "presentation_id": presentation.presentation_id,
                "task_id": presentation.task_id,
                "delivery_refs": [
                    f"{delivery_ref_prefix}"
                    f"{lineage.channel_kind}:{lineage.channel_ref}:"
                    f"{presentation.presentation_id}:{index}"
                    for index, _segment in enumerate(presentation.segments, start=1)
                ],
                "status": presentation_status,
            }
            return DeliveryReceipt.from_dict({
                **body, "receipt_digest": runtime_record_digest("delivery-receipt", body),
            })

        ports = RuntimeInvocationPorts(
            authorize, unavailable, unavailable, unavailable, unavailable,
            pending_human, pending_presentation,
        )
        adapter_factory = RuntimeAdapterFactory(guard)
        handshake = ConfiguredRuntimeHandshake.from_dict(configuration, executable, guard)
        kind = handshake.identity().runtime_kind
        adapter = (
            adapter_factory.codex(configuration, executable, ports)
            if kind == "codex"
            else adapter_factory.hermes(configuration, executable, ports)
        )

        def session_factory() -> RuntimeSession:
            return RuntimeSession.establish(adapter, raw_input, compatibility)

        def scope_loader(value: Mapping[str, object]) -> ProjectScope:
            return ProjectScope.from_dict(
                value, schema_registry=scope_schemas, context=WorkContext(profile, schedule)
            )

        from graph_engineering.application.action_authority import ActionAuthorizationApplication
        from graph_engineering import _installation_owned_resources
        security_manifest = json.loads(_installation_owned_resources((
            "config/contracts/security-schema-registry-v1.json",))[0])
        security_bodies = {resource["schema_id"]: available[resource["schema_id"]]
                           for resource in security_manifest["resources"]}
        security_schemas = ClosedSchemaRegistry.build(security_manifest, security_bodies, profile, schema_policy)
        action_authority = ActionAuthorizationApplication(manager, schema_registry=security_schemas,
            context=WorkContext(profile, schedule))
        self.application = OwnerTurnApplication(None, scope_loader, session_factory,
            task_provider=task_provider, action_authority=action_authority)
        self._resources = (manager, maintenance_objects, locks)

    def close(self) -> None:
        manager, maintenance_objects, locks = self._resources
        manager.close()
        maintenance_objects.close()
        locks.close()

    def __enter__(self) -> LocalOwnerTurnRuntime:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
