"""Fresh private ADR-0008 scenario-truth fixtures for production tests."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import pathlib
import stat
import tempfile
import threading
from collections.abc import Callable, Mapping
from contextlib import ExitStack
from dataclasses import dataclass
from unittest import mock

from graph_engineering.application.scenario_truth import ScenarioTruthRegistryFactory
from graph_engineering.core.contracts.canonical import (
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
)
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.profile_coverage import (
    BindingLifecycleError,
    RuntimeBindingReopenPort,
    profile_coverage_digest,
)
from graph_engineering.core.scenario_truth import ScenarioTruthError


@dataclass(frozen=True, slots=True, eq=False)
class _PrivateBindingSnapshot:
    root_identity: tuple[str, int, int, int]
    projection: FrozenMap
    projection_digest: str


def _canonical_runtime_projection(value: object) -> object:
    """Preserve host integers exactly inside the GEW I-JSON profile."""

    if type(value) is int and not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        return {"integer_decimal": str(value)}
    if isinstance(value, Mapping):
        return {
            str(key): _canonical_runtime_projection(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_canonical_runtime_projection(item) for item in value]
    return value


def _stable_runtime_projection(value: FrozenMap) -> FrozenMap:
    """Exclude the one permitted phase output from the sealed state baseline."""

    projected = dict(value)
    authority = projected.get("authority")
    if isinstance(authority, Mapping):
        stable_authority = dict(authority)
        stable_authority.pop("observation_digests", None)
        stable_authority.pop("observation_object_identities", None)
        projected["authority"] = stable_authority
    target = projected.get("target_state")
    if isinstance(target, Mapping):
        stable_target = dict(target)
        stable_target.pop("query_count", None)
        projected["target_state"] = stable_target
    return freeze(projected)


class PrivateBindingReopenPort(RuntimeBindingReopenPort):
    """Test-runtime adapter for one same-root, process-local binding."""

    __process_lock = threading.RLock()
    __active_handles = 0
    __active_reopened: PrivateBindingReopenPort | None = None
    __maximum_active_reopened = 0

    def __init__(
        self,
        *,
        private_root: pathlib.Path,
        opened_handle: object,
        close_handle: Callable[[object], None],
        reopen_handle: Callable[[], object],
        project_current: Callable[[object], Mapping[str, object]],
        terminate_root: Callable[[str], None],
    ) -> None:
        if (
            not isinstance(private_root, pathlib.Path)
            or opened_handle is None
            or not callable(close_handle)
            or not callable(reopen_handle)
            or not callable(project_current)
            or not callable(terminate_root)
        ):
            raise BindingLifecycleError("private binding reopen adapter is malformed")
        try:
            supplied_metadata = os.lstat(private_root)
            resolved_root = private_root.resolve(strict=True)
        except OSError as error:
            raise BindingLifecycleError(
                "private binding root is unavailable"
            ) from error
        if stat.S_ISLNK(supplied_metadata.st_mode):
            raise BindingLifecycleError("private binding root identity is unsafe")
        self.__root = resolved_root
        self.__root_identity = self._read_root_identity()
        self.__close_handle = close_handle
        self.__reopen_handle = reopen_handle
        self.__project_current = project_current
        self.__terminate_root = terminate_root
        self.__capability: object | None = None
        self.__lifecycle: object | None = None
        self.__handle: object | None = opened_handle
        self.__snapshot: _PrivateBindingSnapshot | None = None
        self.__reopened = False
        self.__terminal = False
        with self.__process_lock:
            type(self).__active_handles += 1

    @classmethod
    def active_handle_count(cls) -> int:
        with cls.__process_lock:
            return cls.__active_handles

    @classmethod
    def active_reopened_binding_count(cls) -> int:
        with cls.__process_lock:
            return int(cls.__active_reopened is not None)

    @classmethod
    def maximum_active_reopened_binding_count(cls) -> int:
        with cls.__process_lock:
            return cls.__maximum_active_reopened

    def _read_root_identity(self) -> tuple[str, int, int, int]:
        try:
            metadata = os.lstat(self.__root)
            resolved = self.__root.resolve(strict=True)
        except OSError as error:
            raise BindingLifecycleError(
                "private binding root is unavailable"
            ) from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != os.getuid()
        ):
            raise BindingLifecycleError("private binding root identity is unsafe")
        return (
            os.fspath(resolved),
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_uid),
        )

    def _require_authority(
        self,
        lifecycle: object,
        capability: object,
    ) -> None:
        if self.__terminal:
            raise BindingLifecycleError("private binding reopen adapter is terminal")
        if self.__capability is None:
            self.__capability = capability
            self.__lifecycle = lifecycle
        if (
            self.__capability is not capability
            or self.__lifecycle is not lifecycle
        ):
            raise BindingLifecycleError("private binding reopen authority is foreign")

    def _projection(self, handle: object) -> tuple[FrozenMap, str]:
        try:
            projection = freeze(
                _canonical_runtime_projection(self.__project_current(handle))
            )
        except Exception as error:
            raise BindingLifecycleError(
                "private binding current projection is unavailable"
            ) from error
        if not isinstance(projection, FrozenMap):
            raise BindingLifecycleError(
                "private binding current projection is not an object"
            )
        digest = profile_coverage_digest(
            projection,
            contract="process-local-binding-runtime-projection",
            schema="process-local-binding-runtime-projection",
        )
        return projection, digest

    def _release_live_handle(self, handle: object) -> None:
        try:
            self.__close_handle(handle)
        finally:
            with self.__process_lock:
                if self.__handle is handle:
                    self.__handle = None
                    type(self).__active_handles -= 1
                if type(self).__active_reopened is self:
                    type(self).__active_reopened = None
                self.__reopened = False

    def seal_current(
        self,
        lifecycle: object,
        handle: object,
        capability: object,
    ) -> tuple[object, str]:
        self._require_authority(lifecycle, capability)
        if handle is not self.__handle:
            raise BindingLifecycleError("private binding live handle is foreign")
        root_identity = self._read_root_identity()
        if root_identity != self.__root_identity:
            raise BindingLifecycleError("private binding root identity changed")
        projection, projection_digest = self._projection(handle)
        prior = self.__snapshot
        if (
            prior is not None
            and self.__reopened
            and _stable_runtime_projection(projection)
            != _stable_runtime_projection(prior.projection)
        ):
            raise BindingLifecycleError(
                "private binding stable state changed during lifecycle phase"
            )
        snapshot = _PrivateBindingSnapshot(
            root_identity=root_identity,
            projection=projection,
            projection_digest=projection_digest,
        )
        self.__snapshot = snapshot
        return snapshot, projection_digest

    def quiesce(
        self,
        lifecycle: object,
        handle: object,
        capability: object,
    ) -> None:
        self._require_authority(lifecycle, capability)
        if handle is not self.__handle:
            raise BindingLifecycleError("private binding quiesce handle is foreign")
        self._release_live_handle(handle)

    def reopen(
        self,
        lifecycle: object,
        sealed_snapshot: object,
        purpose: str,
        capability: object,
    ) -> object:
        self._require_authority(lifecycle, capability)
        if (
            type(sealed_snapshot) is not _PrivateBindingSnapshot
            or sealed_snapshot is not self.__snapshot
            or purpose not in {"issue", "use", "precommit", "gate"}
            or self.__handle is not None
        ):
            raise BindingLifecycleError("private binding reopen request is stale")
        if self._read_root_identity() != sealed_snapshot.root_identity:
            raise BindingLifecycleError("private binding reopen root changed")
        with self.__process_lock:
            if type(self).__active_reopened is not None:
                raise BindingLifecycleError(
                    "another private binding is already reopened"
                )
            type(self).__active_reopened = self
            type(self).__maximum_active_reopened = max(
                type(self).__maximum_active_reopened, 1,
            )
        handle: object | None = None
        try:
            handle = self.__reopen_handle()
            if handle is None:
                raise BindingLifecycleError("private binding reopen returned no handle")
            with self.__process_lock:
                self.__handle = handle
                self.__reopened = True
                type(self).__active_handles += 1
            projection, projection_digest = self._projection(handle)
            if (
                projection != sealed_snapshot.projection
                or not hmac.compare_digest(
                    projection_digest, sealed_snapshot.projection_digest,
                )
            ):
                raise BindingLifecycleError(
                    "private binding sealed projection changed"
                )
            return handle
        except Exception:
            if handle is not None:
                self._release_live_handle(handle)
            else:
                with self.__process_lock:
                    if type(self).__active_reopened is self:
                        type(self).__active_reopened = None
            raise

    def terminate(
        self,
        lifecycle: object,
        handle: object | None,
        terminal_action: str,
        capability: object,
    ) -> None:
        self._require_authority(lifecycle, capability)
        if terminal_action not in {"finalize", "revoke"}:
            raise BindingLifecycleError("private binding terminal action is invalid")
        if handle is not None:
            if handle is not self.__handle:
                raise BindingLifecycleError(
                    "private binding terminal handle is foreign"
                )
            self._release_live_handle(handle)
        elif self.__handle is not None:
            raise BindingLifecycleError("private binding live handle was omitted")
        self.__terminate_root(terminal_action)
        self.__snapshot = None
        self.__terminal = True


def issue_quiescent_binding(
    *,
    binding_identity: Mapping[str, object],
    close_handle: Callable[[object], None],
    opened_handle: object,
    private_root: pathlib.Path,
    project_current: Callable[[object], Mapping[str, object]],
    reopen_handle: Callable[[], object],
    terminate_root: Callable[[str], None],
) -> object:
    """Issue and immediately quiesce one isolated binding runtime."""

    from graph_engineering.application.profile_coverage import (
        ProfileCoverageBindingLifecycle,
    )

    binding_digest = profile_coverage_digest(
        freeze(binding_identity),
        contract="process-local-binding-identity",
        schema="process-local-binding-identity",
    )
    port = PrivateBindingReopenPort(
        private_root=private_root,
        opened_handle=opened_handle,
        close_handle=close_handle,
        reopen_handle=reopen_handle,
        project_current=project_current,
        terminate_root=terminate_root,
    )
    return ProfileCoverageBindingLifecycle._issue(
        port=port,
        binding_digest=binding_digest,
        opened_handle=opened_handle,
    )


class PrivateCategoryRepositoryRoot:
    """Retain one private repository's bytes while reopening live handles."""

    def __init__(self, profile_id: str, *, manual_time: object | None = None) -> None:
        from tests.support import wp08_category_execution as category

        if profile_id not in category.PROFILE_IDS:
            raise AssertionError("private category repository Profile is unknown")
        self.profile_id = profile_id
        self.__temporary = tempfile.TemporaryDirectory(
            prefix="gew-e1-private-binding-"
        )
        self.root = pathlib.Path(self.__temporary.name).resolve(strict=True)
        self.repository_root = self.root / "repository"
        self.action_root = self.root / "action"
        self.command_root = self.root / "command"
        self.action_root.mkdir(mode=0o700)
        self.command_root.mkdir(mode=0o700)
        self.__repository_id = (
            "repository-e1-"
            + hashlib.sha256(os.fspath(self.root).encode("utf-8")).hexdigest()
        )
        if manual_time is None:
            from tests.support.wp03_repository import ManualTime

            manual_time = ManualTime()
        if not callable(manual_time):
            raise AssertionError("private category repository clock is invalid")
        self.__manual_time = manual_time
        self.__first_open = True
        self.__live: object | None = None
        self.__terminated = False
        self.__active_repository_root: pathlib.Path | None = None
        self.__active_repository_id: str | None = None

    @staticmethod
    def _identity(path: pathlib.Path) -> tuple[int, int, int, int]:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BindingLifecycleError("private binding directory changed")
        return (
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_uid),
            stat.S_IMODE(metadata.st_mode),
        )

    def identity_projection(self) -> dict[str, object]:
        repository_root = (
            self.repository_root
            if self.__active_repository_root is None
            else self.__active_repository_root
        )
        return {
            "action_root_identity": list(self._identity(self.action_root)),
            "command_root_identity": list(self._identity(self.command_root)),
            "repository_root_identity": list(
                self._identity(repository_root)
            ),
            "runtime_root_identity": list(self._identity(self.root)),
        }

    def open(self) -> object:
        """Open a full command-scoped repository handle on the same root."""

        if self.__terminated or self.__live is not None:
            raise BindingLifecycleError("private category repository cannot reopen")
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.storage.connection import (
            ConnectionFactory,
            RepositoryDoctor,
        )
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.storage.locks import LockedFileRegistry
        from graph_engineering.storage.migration import (
            InstallationMigrationRepository,
        )
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository
        from tests.contract.test_wp02_graph import graph_schemas, work_context
        from tests.support import wp03_repository
        from tests.support import wp08_category_execution as category
        from tests.support.runtime import runtime_context

        stack = ExitStack()
        try:
            stack.enter_context(mock.patch.object(
                RepositoryDoctor,
                "_mount_observation",
                side_effect=wp03_repository.mount_observation,
            ))
            stack.enter_context(mock.patch(
                "graph_engineering.storage.clock.time.time_ns",
                side_effect=self.__manual_time,
            ))
            repository_policy = wp03_repository.policy()
            if self.__first_open:
                factory = ConnectionFactory.initialize(
                    self.repository_root,
                    repository_policy,
                    self.__repository_id,
                )
            else:
                factory = ConnectionFactory._attach_existing_for_maintenance(
                    self.repository_root,
                    repository_policy,
                    self.__repository_id,
                )
            control_factory = factory
            control_locks = LockedFileRegistry(control_factory)
            stack.callback(control_locks.close)
            maintenance_objects = ObjectRepository(
                control_factory._for_maintenance(), control_locks,
            )
            stack.callback(maintenance_objects.close)
            control_root = self.root / "installation-control"
            migration_policy = category.load_json(
                category.ROOT
                / "config/contracts/migration-storage-policy-v1.json"
            )
            if self.__first_open:
                manager = InstallationMigrationRepository.initialize(
                    control_factory._for_maintenance(),
                    control_locks,
                    maintenance_objects,
                    control_root=control_root,
                    policy_document=migration_policy,
                )
            else:
                manager = InstallationMigrationRepository.attach_command_plane(
                    control_factory,
                    control_locks,
                    maintenance_objects,
                    control_root=control_root,
                    policy_document=migration_policy,
                )
            stack.callback(manager.close)
            scope = manager.command_scope()
            scope.__enter__()
            stack.callback(
                lambda: (
                    None
                    if getattr(scope, "_closed", False)
                    else scope.__exit__(None, None, None)
                )
            )
            locks = control_locks
            active_root = self.__active_repository_root
            if active_root is not None:
                if (
                    scope.repository_root != active_root
                    or scope.context.repository_id != self.__active_repository_id
                ):
                    raise BindingLifecycleError(
                        "private category active repository binding changed"
                    )
                factory = ConnectionFactory._attach_existing_for_maintenance(
                    active_root,
                    repository_policy,
                    self.__active_repository_id,
                )
                locks = LockedFileRegistry(factory)
                stack.callback(locks.close)
            bound_factory = factory.bind_command_scope(scope)
            objects = ObjectRepository(bound_factory, locks)
            stack.callback(objects.close)
            leases = ResourceLeaseRepository(bound_factory, locks)
            repository = TaskRepository(
                bound_factory,
                locks,
                objects,
                command_scope=scope,
            )
            factory._test_installation_control_root = control_root
            factory._test_migration_policy = migration_policy
            factory._test_installation_scope = scope
            factory._test_installation_manager = manager
            schemas = graph_schemas()
            context = work_context()
            task_application = TaskApplication(
                repository,
                repository,
                leases,
                schema_registry=schemas,
                context=context,
                materialization_objects=objects,
            )
            runtime = runtime_context(
                f"owner:{self.profile_id}",
                "codex",
                f"lineage:{self.profile_id}",
                f"actor:{self.profile_id}",
                "2026-08-24T00:00:00Z",
                10**12,
            )
            shared = category.SharedProductionCategoryRuntime(
                profile_id=self.profile_id,
                stack=stack,
                factory=factory,
                objects=objects,
                repository=repository,
                leases=leases,
                schemas=schemas,
                context=context,
                application=task_application,
                runtime=runtime,
            )
            self.__first_open = False
            self.__live = shared
            return shared
        except BaseException:
            stack.close()
            raise

    def adopt_active_repository(
        self,
        current: object,
        replacement: object,
        repository: object,
    ) -> None:
        """Switch the live handle to one already-migrated current repository."""

        if current is not self.__live or replacement is None:
            raise BindingLifecycleError("private category live handle is foreign")
        factory = getattr(repository, "_factory", None)
        command_scope = getattr(repository, "_command_scope", None)
        data_root = pathlib.Path(getattr(factory, "data_root", ""))
        repository_id = getattr(factory, "repository_id", None)
        manager = getattr(command_scope, "_manager", None)
        if (
            not data_root.is_absolute()
            or type(repository_id) is not str
            or not repository_id
            or manager is None
            or command_scope.repository_root != data_root
            or manager._current_manifest().repository_id != repository_id
            or manager._resolve_locator(manager._current_manifest()) != data_root
        ):
            raise BindingLifecycleError(
                "private category activated repository is foreign"
            )
        self.__active_repository_root = data_root.resolve(strict=True)
        self.__active_repository_id = repository_id
        self.__live = replacement

    def close_handle(self, shared: object) -> None:
        if shared is not self.__live:
            raise BindingLifecycleError("private category repository handle is foreign")
        close = getattr(shared, "close", None)
        if not callable(close):
            raise BindingLifecycleError("private category repository cannot close")
        try:
            close()
        finally:
            self.__live = None

    def terminate(self, action: str) -> None:
        if action not in {"finalize", "revoke"} or self.__live is not None:
            raise BindingLifecycleError("private category repository cannot terminate")
        self.__terminated = True
        self.__temporary.cleanup()


class PrivateActionRepositoryRoot:
    """Retain and reattach the exact rollback Action repository bytes."""

    def __init__(self) -> None:
        import datetime
        from tests.support.wp03_repository import ManualTime

        epoch = datetime.datetime(
            2026, 8, 14, 0, 30, tzinfo=datetime.timezone.utc,
        )
        self.manual_time = ManualTime(
            int(epoch.timestamp() * 1_000_000_000)
        )
        self.__repository = PrivateCategoryRepositoryRoot(
            "new-feature", manual_time=self.manual_time,
        )
        self.__seeded = False
        self.__concrete: bool | None = None
        self.__concrete_authority: tuple[object, object, object] | None = None
        self.__live: tuple[object, object] | None = None

    @property
    def root(self) -> pathlib.Path:
        return self.__repository.root

    def identity_projection(self) -> dict[str, object]:
        return self.__repository.identity_projection()

    def _seed(self, shared: object, *, concrete: bool) -> None:
        from graph_engineering.core.actions import PreparedAction
        from graph_engineering.core.security.identity import SecurityBinding
        from graph_engineering.storage.codec import canonical_json
        from graph_engineering.storage.ports import CommitBatch
        from graph_engineering.storage.repository import make_event
        from tests.support import wp05_actions
        from tests.support.wp05a_security import (
            binding_document,
            task_security_state_document,
            write_durable_task_security_state,
        )

        leases = shared.leases
        repository = shared.repository
        factory = shared.repository._factory
        initial_lease = leases.acquire_many(
            lease_id="lease-create-wp05",
            task_id="task-wp05",
            run_id="run-create-wp05",
            operation_id="create",
            resources=("task:task-wp05",),
            ttl_ns=10**15,
        )
        event = make_event(
            task_id="task-wp05",
            sequence=1,
            event_id="task-wp05-created",
            event_type="task.created",
            occurred_at="2026-08-14T00:00:00Z",
            actor={"kind": "runtime", "id": "lineage-wp05"},
            expected_task_revision=0,
            baseline_digests=[],
            payload={"task_id": "task-wp05"},
            previous_event_digest=None,
        )
        repository.commit(CommitBatch(
            "transaction-create-wp05",
            "task-wp05",
            0,
            (event,),
            {"task_id": "task-wp05", "revision": 1, "state": "ready"},
            {},
            {
                "lease_id": initial_lease.lease_id,
                "resource_id": "task:task-wp05",
                "fencing_token": dict(initial_lease.fencing_tokens)[
                    "task:task-wp05"
                ],
            },
        ))
        leases.release(initial_lease.lease_id)
        runtime_name = (
            "security-runtime-local-actions-v1.json"
            if concrete else "security-runtime-v1.json"
        )
        manifest = json.loads((
            wp05_actions.ROOT / "config/security" / runtime_name
        ).read_text())
        registry = manifest["schema_registry"]
        with factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO security_runtime_installation("
                    "singleton,manifest_json,manifest_id,manifest_digest,"
                    "schema_registry_id,schema_registry_digest) "
                    "VALUES(1,?,?,?,?,?)",
                    (
                        canonical_json(manifest),
                        manifest["manifest_id"],
                        manifest["manifest_digest"],
                        registry["registry_id"],
                        registry["registry_digest"],
                    ),
                )
        binding = binding_document()
        binding.update({
            "task_id": "task-wp05",
            "owner_id": "owner-wp05",
            "runtime_lineage_id": "lineage-wp05",
            "baselines": {"intent": wp05_actions.digest("intent")},
            "snapshot_digest": wp05_actions.digest("snapshot"),
            "targets": [{
                "target_id": "target-project",
                "target_kind": "project",
                "canonical_identity": "project-main",
                "target_digest": wp05_actions.digest("target"),
            }],
        })
        binding["binding_digest"] = SecurityBinding.digest_document(binding)
        document_context = wp05_actions.security_context()
        prepared = PreparedAction.from_dict(
            wp05_actions.prepared_document(context=document_context),
            context=document_context,
        )
        compensation = PreparedAction.from_dict(
            wp05_actions.compensation_prepared_document(context=document_context),
            context=document_context,
        )
        destinations = {
            "owner-wp05": {
                "kind": "owner",
                "trust_boundary": "owner-session",
                "target_digest": wp05_actions.digest("owner-session"),
                "prepared_action_digest": prepared.prepared_action_digest,
            },
        }
        state = task_security_state_document(
            binding=binding, destinations=destinations,
        )
        state["authority_digests"] = sorted((
            wp05_actions.authority_document(prepared)["authority_digest"],
            wp05_actions.authority_document(compensation)["authority_digest"],
        ))
        state["data_refs"] = {
            "action-payload": {
                "digest": wp05_actions.digest("payload-source"),
                "sensitivity": "internal",
                "retention_class": "evidence-body",
            },
        }
        write_durable_task_security_state(factory, state)

    def open(
        self,
        *,
        concrete_action_authority: tuple[object, object, object] | None = None,
    ) -> object:
        if self.__live is not None:
            raise BindingLifecycleError("private action repository is already open")
        concrete = concrete_action_authority is not None
        if self.__concrete is not None and self.__concrete is not concrete:
            raise BindingLifecycleError(
                "private action repository authority mode changed"
            )
        if concrete and self.__concrete_authority is not None and any(
            current is not expected
            for current, expected in zip(
                concrete_action_authority, self.__concrete_authority,
                strict=True,
            )
        ):
            raise BindingLifecycleError(
                "private action repository concrete authority changed"
            )
        import dataclasses

        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.core.actions import ActionPolicy
        from graph_engineering.storage.actions import ActionJournalRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.security import SecurityStateRepository
        from tests.support import wp05_actions
        from tests.support.wp05a_security import (
            security_context,
            security_schema_registry,
        )
        from tests.support.wp07a_actions import action_adapter_schema_registry

        shared = self.__repository.open()
        try:
            if not self.__seeded:
                self._seed(shared, concrete=concrete)
                self.__seeded = True
                self.__concrete = concrete
                self.__concrete_authority = concrete_action_authority
            context = security_context()
            schemas = security_schema_registry(context)
            command_factory = shared.repository._factory
            issuer = SecurityContextIssuer(
                SecurityStateRepository(command_factory),
                schema_registry=schemas,
                context=context,
            )
            journal = ActionJournalRepository(
                command_factory, schema_registry=schemas, context=context,
            )
            action_lease = shared.leases.acquire_many(
                lease_id="lease-action-wp05",
                task_id="task-wp05",
                run_id="run-action-wp05",
                operation_id="action",
                resources=("target:project", "task:task-wp05"),
                ttl_ns=10**15,
            )
            policy_name = (
                "action-policy-local-actions-v1.json"
                if concrete_action_authority is not None
                else "action-policy-v1.json"
            )
            policy = ActionPolicy.from_dict(
                json.loads((
                    wp05_actions.ROOT / "config/actions" / policy_name
                ).read_text()),
                schema_registry=schemas,
                context=context,
                runtime=issuer.runtime,
            )
            repository = TaskRepository(
                command_factory,
                shared.repository._locks,
                shared.objects,
                action_journal=journal,
                concrete_action_schemas=action_adapter_schema_registry(context),
                concrete_action_context=context,
                command_scope=shared.repository.command_scope,
            )
            concrete_kwargs = (
                {}
                if concrete_action_authority is None
                else {
                    "action_adapter_factory": concrete_action_authority[0],
                    "concrete_action_policy": concrete_action_authority[1],
                    "concrete_action_registry": concrete_action_authority[2],
                }
            )
            raw_coordinator = ActionCoordinator(
                journal=journal,
                repository=repository,
                leases=shared.leases,
                locks=shared.repository._locks,
                objects=shared.objects,
                security_issuer=issuer,
                action_policy=policy,
                installation_scope=repository.command_scope,
                **concrete_kwargs,
            )
            fixture = wp05_actions.ActionFixture(
                wp05_actions.TestOnlyTrustedCoordinator(
                    raw_coordinator, command_factory,
                ),
                raw_coordinator,
                repository,
                shared.objects,
                shared.repository._locks,
                wp05_actions.JournalFixture(journal, command_factory),
                shared.leases,
                action_lease,
                dataclasses.replace(action_lease, lease_id="wrong-lease"),
                context,
                schemas,
                issuer,
                self.manual_time,
                command_factory,
            )
            self.__live = (fixture, shared)
            return fixture
        except BaseException:
            self.__repository.close_handle(shared)
            raise

    def close_handle(self, fixture: object) -> None:
        if self.__live is None or self.__live[0] is not fixture:
            raise BindingLifecycleError("private action repository handle is foreign")
        shared = self.__live[1]
        try:
            self.__repository.close_handle(shared)
        finally:
            self.__live = None

    def terminate(self, action: str) -> None:
        if self.__live is not None:
            raise BindingLifecycleError("private action repository is still open")
        self.__repository.terminate(action)


def bind_private_rollback_action(
    probe: object,
    target: object,
    action_root: PrivateActionRepositoryRoot,
) -> tuple[object, dict[str, object], object]:
    """Prepare the standard rollback authority on one retained action root."""

    action = action_root.open()
    coordinator, context = bind_rollback_action_fixture(probe, target, action)
    return coordinator, context, action


def bind_rollback_action_fixture(
    probe: object,
    target: object,
    action: object,
) -> tuple[object, dict[str, object]]:
    """Prepare rollback on one already-open private Action handle."""

    from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
    from graph_engineering.core.actions import PreparedAction
    from tests.support import wp05_actions

    document_context = wp05_actions.security_context()
    prepared_document = wp05_actions.compensation_prepared_document(context=document_context)
    prepared_document["snapshot_digest"] = action.current_task_snapshot_digest()
    prepared_document["prepared_action_digest"] = PreparedAction.digest_document(
        prepared_document, context=document_context,
    )
    parsed = PreparedAction.from_dict(
        prepared_document, context=document_context,
    )
    authority = wp05_actions.authority_document(parsed)
    action.coordinator.prepare(prepared_document)
    action.coordinator.authorize(authority)

    class LinkedRollbackTarget(DeterministicFakeTarget):
        def invoke(self, **kwargs):  # type: ignore[no-untyped-def]
            result = super().invoke(**kwargs)
            target.apply_rollback()
            return result

    action_target = LinkedRollbackTarget(
        target_id=parsed.target_id,
        target_digest=parsed.target_digest,
        resource_id="target:project",
        initial_state={"version": 2},
    )
    probe.bind_rollback_audit(action, action_target, target)
    return action.raw_coordinator, {
        "prepared_document": prepared_document,
        "authority_document": authority,
        "lease": action.action_lease,
        "target": action_target,
        "observer": action_target.observer_port(),
        "disclosure_plan": wp05_actions.disclosure_plan(action, parsed),
        "owner_id": "owner-wp05",
        "runtime_kind": "codex",
        "runtime_lineage_id": "lineage-wp05",
    }


@dataclass(slots=True)
class ScenarioTruthCoverageContext:
    registry_factory: ScenarioTruthRegistryFactory
    temporary_root: tempfile.TemporaryDirectory[str]
    observer: object
    evidence: object

    def close(self) -> None:
        self.registry_factory.close()
        self.temporary_root.cleanup()


@dataclass(slots=True)
class ScenarioTruthRejectionContext:
    registry_factory: ScenarioTruthRegistryFactory
    temporary_roots: list[tempfile.TemporaryDirectory[str]]
    task_id: str
    test_id: str
    oracle_digest: str
    evidence: object

    @property
    def receipts(self) -> tuple:
        return self.evidence.receipts

    @receipts.setter
    def receipts(self, value: object) -> None:
        # Adversarial test hook: this cannot alter the issuer's frozen issuance.
        object.__setattr__(self.evidence, "receipts", value)

    def close(self) -> None:
        self.registry_factory.close()
        for temporary_root in reversed(self.temporary_roots):
            temporary_root.cleanup()
        self.temporary_roots.clear()


def _current_binding(
    application: object,
    target: object,
    candidate: dict[str, object],
    *,
    scenario_id: str | None,
) -> dict[str, object]:
    from graph_engineering.application.profile_execution import _category_selector

    selector = _category_selector(candidate)
    _issued, current = application._authoritative_candidate(selector, target)
    task_id = str(current["task_id"])
    if scenario_id is None:
        scenario_id = (
            str(current["scenario_id"])
            .removeprefix(
                "GEW-PSC-" + str(current["profile_id"]).upper() + "-"
            )
            .removesuffix("-P")
            .lower()
        )
    return {
        "task_id": task_id,
        "task_revision": current["task_revision"],
        "snapshot_digest": current["snapshot_digest"],
        "invalidation_epoch": current["invalidation_epoch"],
        "profile_id": current["profile_id"],
        "profile_version": current["profile_version"],
        "scenario_id": scenario_id,
        "graph_ref_pins": dict(current["digest_pins"]),
        "branch_id": "branch:" + task_id,
        "ref_id": "ref:" + task_id,
    }


def observe_current_candidate(
    application: object,
    target: object,
    candidate: dict[str, object],
    registry_factory: ScenarioTruthRegistryFactory,
) -> ScenarioTruthCoverageContext:
    """Execute one config-owned scenario before category assessment commits it."""

    temporary_root = tempfile.TemporaryDirectory(prefix="gew-scenario-truth-")
    binding = _current_binding(
        application, target, candidate, scenario_id=None,
    )
    observer = registry_factory.observation_factory(
        registry_factory.registry(),
        binding=binding,
        private_root=temporary_root.name,
    )
    baseline = (observer.capture_baseline()
                if "execution_contract" in observer._fixture_row else None)
    evidence = observer.execute(observer.request(), baseline_receipt=baseline)
    return ScenarioTruthCoverageContext(
        registry_factory, temporary_root, observer, evidence,
    )


def reject_current_candidate(
    application: object,
    target: object,
    candidate: dict[str, object],
    current_candidate: dict[str, object],
    registry_factory: ScenarioTruthRegistryFactory,
    *,
    scenario_id: str,
    test_id: str,
    oracle_digest: str,
) -> ScenarioTruthRejectionContext:
    """Run the exact multi-target rejection matrix in fresh private roots."""

    binding = _current_binding(
        application, target, current_candidate, scenario_id=scenario_id,
    )
    if candidate.get("task_id") != binding["task_id"]:
        raise AssertionError("scenario rejection task binding is foreign")
    # A rejection has no committed assessment. Its no-handle receipt issuer is
    # owned until terminal coverage cleanup, not by the category reopen stack.
    registry_factory.registry()
    rejection_factory = ScenarioTruthRegistryFactory.from_installation()
    if rejection_factory.installation_pins != registry_factory.installation_pins:
        rejection_factory.close()
        raise ScenarioTruthError("scenario rejection installation changed")
    registry_factory = rejection_factory
    task_id = str(binding["task_id"])
    roots: list[tempfile.TemporaryDirectory[str]] = []
    receipts: list[object] = []

    def missing_role(request: dict[str, object], observer: object) -> None:
        del observer
        del request["targets"][0]["role_id"]

    def extra_role(request: dict[str, object], observer: object) -> None:
        del observer
        extra = copy.deepcopy(request["targets"][0])
        extra["role_id"] = str(extra["role_id"]) + "-extra"
        extra["path_id"] = "targets/extra.state"
        request["targets"].append(extra)

    def aliased_role(request: dict[str, object], observer: object) -> None:
        del observer
        request["targets"][1]["role_id"] = request["targets"][0]["role_id"]

    def one_target_only(request: dict[str, object], observer: object) -> None:
        del observer
        request["targets"].pop()

    def cross_branch(request: dict[str, object], observer: object) -> None:
        del observer
        request["branch_id"] = "branch:foreign:" + task_id

    def partial_success(request: dict[str, object], observer: object) -> None:
        del observer
        request["targets"][1]["apply"] = False

    def stale_target(request: dict[str, object], observer: object) -> None:
        path = pathlib.Path(observer._root) / request["targets"][0]["path_id"]
        path.write_bytes(path.read_bytes() + b"stale")

    def wrong_rollback(request: dict[str, object], observer: object) -> None:
        del observer
        request["rollback_or_compensation"]["expected_state_id"] = "foreign"

    def refactor_contract(request: dict[str, object]) -> dict[str, object]:
        value = request["refactor_contract"]
        if type(value) is not dict:
            raise AssertionError("refactor rejection contract is malformed")
        return value

    def behavior_case_addition(request: dict[str, object], observer: object) -> None:
        del observer
        contract = refactor_contract(request)
        added = copy.deepcopy(contract["behavior_cases"][0])
        added["case_id"] += "-added"
        contract["behavior_cases"].append(added)

    def behavior_case_omission(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["behavior_cases"].pop()

    def behavior_case_reorder(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["behavior_cases"].reverse()

    def behavior_delta(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["behavior_cases"][0]["output_digest"] = (
            "sha256-jcs-v1:" + "f" * 64
        )

    def expected_vector_alias(request: dict[str, object], observer: object) -> None:
        del observer
        contract = refactor_contract(request)
        contract["behavior_cases"][1] = copy.deepcopy(contract["behavior_cases"][0])

    def caller_behavior_equivalent(request: dict[str, object], observer: object) -> None:
        del observer
        request["behavior_equivalent"] = True

    def architecture_missing_edge(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["required_edges"].pop()

    def architecture_forbidden_edge(request: dict[str, object], observer: object) -> None:
        del observer
        contract = refactor_contract(request)
        contract["required_edges"] = copy.deepcopy(contract["forbidden_edges"])

    def architecture_path_alias(request: dict[str, object], observer: object) -> None:
        del observer
        edge = refactor_contract(request)["required_edges"][0]
        edge["to_path_id"] = edge["from_path_id"]

    def architecture_count_only(request: dict[str, object], observer: object) -> None:
        del observer
        request["architecture_edge_count"] = 1

    def architecture_set_only(request: dict[str, object], observer: object) -> None:
        del observer
        request["architecture_nodes"] = ["layers/core", "layers/domain"]

    def behavior_gate_skip(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["gate_ids"].pop(0)

    def environment_drift(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["environment_id"] += "-foreign"

    def hardcoded_threshold(request: dict[str, object], observer: object) -> None:
        del observer
        target = refactor_contract(request)["nonfunctional_target"]
        target["threshold"] -= 1

    def threshold_float(request: dict[str, object], observer: object) -> None:
        del observer
        target = refactor_contract(request)["nonfunctional_target"]
        target["threshold"] = float(target["threshold"])

    def threshold_bool(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["nonfunctional_target"]["threshold"] = True

    def metric_miss(request: dict[str, object], observer: object) -> None:
        del observer
        refactor_contract(request)["nonfunctional_target"]["metric_id"] += "-foreign"

    def caller_metric_pass(request: dict[str, object], observer: object) -> None:
        del observer
        request["metric_passed"] = True

    attacks = dict((
        ("missing-role", missing_role),
        ("extra-role", extra_role),
        ("aliased-role", aliased_role),
        ("one-target-only", one_target_only),
        ("cross-branch", cross_branch),
        ("partial-success", partial_success),
        ("stale-target", stale_target),
        ("wrong-rollback", wrong_rollback),
        ("behavior-case-addition", behavior_case_addition),
        ("behavior-case-omission", behavior_case_omission),
        ("behavior-case-reorder", behavior_case_reorder),
        ("behavior-delta", behavior_delta),
        ("expected-vector-alias", expected_vector_alias),
        ("caller-behavior-equivalent", caller_behavior_equivalent),
        ("architecture-missing-edge", architecture_missing_edge),
        ("architecture-forbidden-edge", architecture_forbidden_edge),
        ("architecture-path-alias", architecture_path_alias),
        ("architecture-count-only", architecture_count_only),
        ("architecture-set-only", architecture_set_only),
        ("behavior-gate-skip", behavior_gate_skip),
        ("environment-drift", environment_drift),
        ("hardcoded-threshold", hardcoded_threshold),
        ("threshold-float", threshold_float),
        ("threshold-bool", threshold_bool),
        ("metric-miss", metric_miss),
        ("caller-metric-pass", caller_metric_pass),
    ))
    try:
        for attack_id in registry_factory.rejection_attack_ids(binding["profile_id"], scenario_id):
            temporary_root = tempfile.TemporaryDirectory(
                prefix="gew-scenario-truth-rejection-"
            )
            roots.append(temporary_root)
            observer = registry_factory.observation_factory(
                registry_factory.registry(),
                binding=binding,
                private_root=temporary_root.name,
            )
            request = observer.request()
            baseline = (observer.capture_baseline()
                        if "execution_contract" in observer._fixture_row else None)
            if attack_id == "missing-baseline":
                baseline = None
            elif attack_id == "foreign-baseline":
                foreign_root = tempfile.TemporaryDirectory(prefix="gew-scenario-foreign-")
                roots.append(foreign_root)
                foreign = registry_factory.observation_factory(
                    registry_factory.registry(), binding=binding, private_root=foreign_root.name)
                baseline = foreign.capture_baseline()
            elif attack_id == "stale-control":
                path = observer._root / observer._fixture_row["execution_contract"]["controls"][0]["path_id"]
                path.write_bytes(path.read_bytes() + b"stale")
            elif attack_id == "wrong-environment":
                request["environment"]["classification"] = "production"
            elif attack_id == "gate-omission":
                request["ordered_gate_ids"].pop()
            elif attack_id == "gate-reorder":
                request["ordered_gate_ids"].reverse()
            else:
                attacks[attack_id](request, observer)
            receipt = observer.reject(attack_id, request, baseline_receipt=baseline)
            if (
                receipt.mutation_count != 0
                or not receipt.request_unchanged
                or not receipt.target_bytes_unchanged
            ):
                raise AssertionError(
                    f"scenario rejection attack changed state: {attack_id}"
                )
            receipts.append(receipt)
        evidence = registry_factory.bind_rejections(
            tuple(receipts), test_id=test_id, oracle_digest=oracle_digest,
        )
    except BaseException:
        registry_factory.close()
        for temporary_root in reversed(roots):
            temporary_root.cleanup()
        raise
    return ScenarioTruthRejectionContext(
        registry_factory=registry_factory,
        temporary_roots=roots,
        task_id=task_id,
        test_id=test_id,
        oracle_digest=oracle_digest,
        evidence=evidence,
    )
