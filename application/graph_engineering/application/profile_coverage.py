"""Production-backed WP-08 coverage observation and execution authority."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import threading
import weakref
from collections.abc import Mapping

from graph_engineering.application.profile_execution import (
    CategoryExecutionApplication,
)
from graph_engineering.application.tasks import RuntimeContext, TaskApplication
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.profile_execution import CategoryExecutionError
from graph_engineering.core.profile_coverage import (
    ProcessLocalBindingLifecycle,
    ProfileCoverageAuthorityRegistration,
    ProfileCoverageError,
    ProfileCoverageExecutionPlan,
    ProfileCoverageExecutionRecord,
    ProfileCoverageObservation,
    RuntimeBindingReopenPort,
    _register_profile_coverage_authority_type,
    profile_coverage_digest,
)
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository


_PIPE_BOOTSTRAP = r'''import base64,hashlib,json,sys
def canonical(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode("utf-8")
envelope=json.loads(sys.stdin.buffer.read())
if type(envelope) is not dict or set(envelope)!={"runner_source_b64","runner_raw_sha256","payload"}:
    raise RuntimeError("Profile coverage byte-pipe envelope is not exact")
runner=base64.b64decode(envelope["runner_source_b64"],validate=True)
if hashlib.sha256(runner).hexdigest()!=envelope["runner_raw_sha256"]:
    raise RuntimeError("Profile coverage oracle runner changed")
scope={"_GEW_PROFILE_COVERAGE_PAYLOAD":envelope["payload"]}
exec(compile(runner,"<profile-coverage-oracle>","exec",dont_inherit=True),scope,scope)
'''


def _raw_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _semantic(value: object, contract: str) -> str:
    return profile_coverage_digest(
        value,
        contract=contract,
        schema=contract,
    )


def _frozen_mapping(value: object, label: str) -> FrozenMap:
    frozen = freeze(value)
    if not isinstance(frozen, FrozenMap):
        raise ProfileCoverageError(f"{label} is not an exact object")
    return frozen


_RELEASE_READ_BINDINGS: dict[int, tuple[object, dict[str, object], int, int]] = {}


class _ReleaseCoverageReadBinding:
    """Process-local validation of an existing record, never execution authority."""

    __slots__ = ()

    def __new__(cls, *args: object, **kwargs: object) -> object:
        raise TypeError("release coverage readers are authority-issued")

    @classmethod
    def _issue(cls, authority: object, record: object, namespace: object) -> _ReleaseCoverageReadBinding:
        from graph_engineering.application.release_operations import (
            ReleaseOperationsRegistryFactory, RetainedReleaseNamespace,
        )
        if type(authority) is not ProfileCoverageAuthority:
            raise ProfileCoverageError("release reader has a foreign coverage authority")
        authority._require_record(record)
        factory = authority._category._oracle._release_operations_factory
        if (type(factory) is not ReleaseOperationsRegistryFactory
                or type(namespace) is not RetainedReleaseNamespace
                or record.profile_id != "release-operations" or record.selector_kind != "mandatory"):
            raise ProfileCoverageError("release reader selector or factory is foreign")
        sessions = [session for session in factory._issued_sessions.values()
            if session.recovery_binding is not None
            and session.recovery_binding.projection["task_id"] == record.task_id]
        if len(sessions) != 1:
            raise ProfileCoverageError("release reader session is not unique")
        session = sessions[0]
        coordinator = factory._session_coordinators[id(session)]
        namespace.require_current(coordinator)
        if (coordinator._repository is not authority._repository
                or coordinator._objects is not authority._objects):
            raise ProfileCoverageError("release reader ports are foreign")
        real = authority._category._facts._real_e2e_authority
        if record.column_id == "real-e2e":
            authority._require_real_e2e_current(authority._plan.binding(record.test_id), task_id=record.task_id)
            if real._session is not session or real._coordinator is not coordinator:
                raise ProfileCoverageError("release reader predecessor is foreign")
            action_id = real._journal.action_id
        else:
            evidence = [item for item in factory._issued.values()
                if item.projection["task_id"] == record.task_id
                and item.projection["column_id"] == record.column_id]
            if len(evidence) != 1:
                raise ProfileCoverageError("release reader evidence is not unique")
            factory.require_current(evidence[0])
            action_id = evidence[0].projection["deployment_observation"]["action_id"]
        raw = None if record.result == "EXPECTED_REJECTION" else authority._objects.get(
            record.assessment_object_digest, require_referenced=False)
        root = session._root
        tree_digest = root.tree_digest()
        authority._require_record(record)
        if root.tree_digest() != tree_digest:
            raise ProfileCoverageError("release target changed while sealing read contract")
        result = object.__new__(cls)
        context = {"authority": authority, "record": record, "factory": factory,
            "session": session, "coordinator": coordinator, "namespace": namespace,
            "binding": session.recovery_binding, "record_document": freeze(record.to_dict()),
            "assessment_bytes": raw, "action_id": action_id, "handle": None,
            "source_digest": None, "reopen_sources": None, "read_generation": 0, "expected_tree_digest": tree_digest, "pending_digests": ((real._journal.prepared.prepared_action_digest,
                real._journal.authority.authority_digest) if record.column_id == "real-e2e"
                and record.result == "EXPECTED_REJECTION" else None),
            "policy": authority._category._policy,
            "ports": (authority._tasks, authority._runtime, authority._objects, coordinator, namespace, factory, authority._category._policy)}
        _RELEASE_READ_BINDINGS[id(result)] = (result, context, os.getpid(), threading.get_ident())
        try:
            factory._cold_artifact_authority()
            session.close()
            result.open()
            return result
        except BaseException:
            result.terminate("revoke")
            raise

    def _context(self) -> dict[str, object]:
        row = _RELEASE_READ_BINDINGS.get(id(self))
        if row is None or row[0] is not self or row[2:] != (os.getpid(), threading.get_ident()):
            raise ProfileCoverageError("release coverage reader is closed or foreign")
        return row[1]

    def _bind_read_ports(self, *, app: object, runtime: object, objects: object, coordinator: object,
                         namespace: object, factory: object, policy: object) -> None:
        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory, RetainedReleaseNamespace
        from graph_engineering.core.profile_execution import CategoryExecutionPolicy
        context = self._context()
        if (context["handle"] is not None or type(app) is not TaskApplication
                or type(runtime) is not RuntimeContext or type(objects) is not ObjectRepository
                or type(coordinator) is not ActionCoordinator or type(namespace) is not RetainedReleaseNamespace
                or type(factory) is not ReleaseOperationsRegistryFactory or type(policy) is not CategoryExecutionPolicy
                or app._repository is not coordinator._repository or app._materialization_objects is not objects
                or coordinator._objects is not objects
                or namespace.repository_scope_digest != context["binding"].projection["repository_scope_digest"]
                or policy.materialization_graph_ref != context["policy"].materialization_graph_ref
                or policy.policy_digest != context["policy"].policy_digest):
            raise ProfileCoverageError("release reader reopened ports are foreign")
        namespace.require_current(coordinator)
        factory._cold_artifact_authority()
        if any(factory._bootstrap.get(key) != value for key, value in context["binding"].projection["installation_pins"].items()):
            raise ProfileCoverageError("release reader reopened installation changed")
        context["ports"] = (app, runtime, objects, coordinator, namespace, factory, policy)
        authority = context["authority"]
        authority._tasks, authority._runtime, authority._objects, authority._repository = app, runtime, objects, app._repository

    def open(self) -> _ReleaseCoverageReadBinding:
        from graph_engineering.application.release_operations import restore_current_release_assessment, _open_release_rejection_reader
        context = self._context()
        if context["handle"] is not None or not context["session"]._root.closed or context["ports"] is None:
            raise ProfileCoverageError("release reader is already open or has no reopened source ports")
        app, runtime, objects, coordinator, namespace, factory, policy = context["ports"]
        record = context["record"]
        try:
            if record.result == "COMPLETED":
                handle = restore_current_release_assessment(task_application=app,
                    runtime=runtime, policy=policy, release_factory=factory,
                    object_repository=objects, action_coordinator=coordinator,
                    retained_namespace=namespace, task_id=record.task_id)
            else:
                handle = _open_release_rejection_reader(app=app, runtime=runtime, policy=policy,
                    factory=factory, objects=objects, coordinator=coordinator, namespace=namespace,
                    task_id=record.task_id, target_id=context["binding"].projection["target_id"],
                    action_id=context["action_id"], expected_state_digest=record.after_state_digest,
                    pending_digests=context["pending_digests"], expected_tree_digest=context["expected_tree_digest"])
            context["handle"] = handle
            context["read_generation"] += 1
            self._check_captured_history()
            return self
        except BaseException:
            self.quiesce(self)
            raise

    def _bind_source_reopener(self, reopen_sources: object) -> None:
        context = self._context()
        if context["reopen_sources"] is not None or not callable(reopen_sources):
            raise ProfileCoverageError("release source reopener is foreign")
        context["reopen_sources"] = reopen_sources

    def require_current(self) -> None:
        context = self._context()
        context["authority"]._require_active()
        if context["handle"] is None:
            raise ProfileCoverageError("release reader has no open phase")
        reopen = context["reopen_sources"]
        if reopen is None:
            context["handle"].query()
        else:
            previous, generation = context["handle"], context["read_generation"]
            reopen()
            if context["handle"] is previous or context["read_generation"] != generation + 1:
                raise ProfileCoverageError("release source reopener did not complete a fresh read")
        self._check_captured_history()

    def _check_captured_history(self) -> None:
        context = self._context()
        authority, record = context["authority"], context["record"]
        authority._require_active()
        if (context["handle"] is None or not context["session"]._root.closed
                or freeze(record.to_dict()) != context["record_document"]):
            raise ProfileCoverageError("release reader record or lifetime changed")
        history = (context["handle"]._record()[1].history if record.result == "COMPLETED"
                   else context["handle"].history)
        if (history["coverage_state_digest"] != record.after_state_digest
                or record.result == "COMPLETED" and history["assessment_bytes"] != context["assessment_bytes"]):
            raise ProfileCoverageError("release reader assessment or source state changed")
        current = history["coverage_source_digest"]
        if context["source_digest"] is None:
            context["source_digest"] = current
        elif current != context["source_digest"]:
            raise ProfileCoverageError("release reader source/action/security/physical closure changed")

    def state_digest(self) -> str:
        self.require_current()
        return self._context()["record"].after_state_digest

    def completion_values(self, test_id: str) -> dict[str, object]:
        self.require_current()
        context = self._context()
        record = context["record"]
        if record.test_id != test_id or record.result != "COMPLETED":
            raise ProfileCoverageError("release reader completion selector is foreign")
        return {key: value for key, value in thaw(context["record_document"]).items()
            if key not in {"schema_version", "execution_digest", "execution_object_digest"}}

    def quiesce(self, handle: object) -> None:
        if handle is not self:
            raise ProfileCoverageError("release reader close handle is foreign")
        context = self._context()
        current, context["handle"] = context["handle"], None
        context["ports"] = None
        if current is not None:
            from graph_engineering.application.release_operations import _ReadOnlyReleaseAssessment, _COLD_ASSESSMENT_HANDLES
            if type(current) is not _ReadOnlyReleaseAssessment or id(current) in _COLD_ASSESSMENT_HANDLES:
                current.close()

    def terminate(self, action: str) -> None:
        if action not in {"revoke", "finalize"}:
            raise ProfileCoverageError("release reader terminal action is foreign")
        if id(self) not in _RELEASE_READ_BINDINGS:
            return
        try:
            self.quiesce(self)
        finally:
            _RELEASE_READ_BINDINGS.pop(id(self), None)

    def session_closed(self) -> bool:
        return self._context()["session"]._root.closed

    def active_readers(self) -> int:
        row = _RELEASE_READ_BINDINGS.get(id(self))
        return 0 if row is None else int(row[1]["handle"] is not None)


class ProfileCoverageBindingLifecycle:
    """Application-owned orchestration for one quiescent coverage binding."""

    __slots__ = ("__lifecycle", "__seal")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("coverage binding lifecycle is runtime-issued")

    def __copy__(self) -> object:
        raise TypeError("coverage binding lifecycle is not cloneable")

    def __deepcopy__(self, memo: object) -> object:
        del memo
        raise TypeError("coverage binding lifecycle is not cloneable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        raise TypeError("coverage binding lifecycle is not serializable")

    def __getstate__(self) -> object:
        raise TypeError("coverage binding lifecycle is not serializable")

    @classmethod
    def _issue(
        cls,
        *,
        port: RuntimeBindingReopenPort,
        binding_digest: str,
        opened_handle: object,
    ) -> ProfileCoverageBindingLifecycle:
        result = object.__new__(cls)
        lifecycle = ProcessLocalBindingLifecycle._issue(
            port=port,
            binding_digest=binding_digest,
            opened_handle=opened_handle,
            owner=result,
        )
        result.__lifecycle = lifecycle
        result.__seal = lifecycle.seal_and_quiesce(result)
        return result

    @property
    def state(self) -> str:
        return self.__lifecycle.state

    @property
    def generation(self) -> int:
        return self.__lifecycle.generation

    @property
    def expected_purpose(self) -> str | None:
        return self.__lifecycle.expected_purpose

    def _require_process_local_current(self) -> None:
        self.__lifecycle._require_owner(self)
        self.__lifecycle._require_current_seal(self.__seal)

    def run(self, purpose: object, phase: object) -> object:
        value, next_seal = self.__lifecycle.run_phase(
            self.__seal, purpose, phase, self,
        )
        self.__seal = next_seal
        return value

    def terminate(self, terminal_action: object) -> None:
        self.__lifecycle.terminate(self.__seal, terminal_action, self)
        self.__seal = None


class ProfileCoverageAuthority:
    """Issue current production coverage proofs under consumer-local identity."""

    def __init__(
        self,
        *,
        plan: ProfileCoverageExecutionPlan,
        category_application: CategoryExecutionApplication,
        task_application: TaskApplication,
        repository: TaskRepository,
        object_repository: ObjectRepository,
        runtime: RuntimeContext,
        dependency_security: tuple[object, object] | None = None,
        scenario_rejection_factory: object | None = None,
    ) -> None:
        if (
            type(plan) is not ProfileCoverageExecutionPlan
            or type(category_application) is not CategoryExecutionApplication
            or type(task_application) is not TaskApplication
            or type(repository) is not TaskRepository
            or type(object_repository) is not ObjectRepository
            or type(runtime) is not RuntimeContext
            or category_application._task_application is not task_application
            or category_application._repository is not repository
            or category_application._objects is not object_repository
            or category_application._runtime is not runtime
            or task_application._repository is not repository
            or task_application._materialization_objects is not object_repository
        ):
            raise ProfileCoverageError("production coverage authority inputs are foreign")
        from graph_engineering.application.dependency_security import (
            DependencyGraphAssessmentEvidence,
            DependencyGraphAssessmentFactory,
            DependencySecurityObservation,
            DependencySecurityObservationFactory,
        )

        profile_id = category_application._policy.profile_id
        performance_factory: object | None = None
        performance_registry_authority: object | None = None
        if profile_id == "dependency-security":
            dependency_observation_authority = (
                type(dependency_security) is tuple
                and len(dependency_security) == 2
                and type(dependency_security[0])
                is DependencySecurityObservationFactory
                and type(dependency_security[1]) is DependencySecurityObservation
                and dependency_security[0]._category is category_application
                and dependency_security[1]._authority is dependency_security[0]
            )
            dependency_assessment_authority = (
                type(dependency_security) is tuple
                and len(dependency_security) == 2
                and type(dependency_security[0])
                is DependencyGraphAssessmentFactory
                and type(dependency_security[1]) is DependencyGraphAssessmentEvidence
                and dependency_security[0]._repository is repository
                and dependency_security[1]._authority is dependency_security[0]
            )
            if (
                not dependency_observation_authority
                and not dependency_assessment_authority
            ):
                raise ProfileCoverageError(
                    "dependency security coverage authority is unavailable"
                )
        elif dependency_security is not None:
            raise ProfileCoverageError(
                "dependency security coverage authority is cross-profile"
            )
        if profile_id == "performance":
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkError,
                PerformanceBenchmarkRegistryFactory,
            )

            performance_factory = (
                category_application._oracle._performance_registry_factory
            )
            performance_registry_authority = (
                category_application._oracle._performance_registry_authority
            )
            try:
                if type(performance_factory) is not PerformanceBenchmarkRegistryFactory:
                    raise PerformanceBenchmarkError(
                        "performance coverage factory is unavailable"
                    )
                performance_factory.require_current(
                    performance_registry_authority
                )
            except PerformanceBenchmarkError as error:
                raise ProfileCoverageError(
                    "performance coverage installation authority is unavailable"
                ) from error
        plan.isolated_runner_bytes()
        self._plan = plan
        self._category = category_application
        self._tasks = task_application
        self._repository = repository
        self._objects = object_repository
        self._runtime = runtime
        self._dependency_security = dependency_security
        # R has no committed category assessment from which restart could
        # restore this issuer. Retain its process-local identity (no open runtime
        # handles) for full receipt/installation/target rereads at every phase.
        category_scenario_factory = category_application._oracle._scenario_truth_factory
        if scenario_rejection_factory is not None:
            from graph_engineering.application.scenario_truth import ScenarioTruthRegistryFactory
            if (type(scenario_rejection_factory) is not ScenarioTruthRegistryFactory
                    or type(category_scenario_factory) is not ScenarioTruthRegistryFactory):
                raise ProfileCoverageError("scenario rejection issuer is foreign")
            scenario_rejection_factory.registry()
            category_scenario_factory.registry()
            if scenario_rejection_factory.installation_pins != category_scenario_factory.installation_pins:
                raise ProfileCoverageError("scenario rejection installation is foreign")
        self.__scenario_rejection_factory = (
            category_scenario_factory if scenario_rejection_factory is None
            else scenario_rejection_factory
        )
        self.__scenario_rejections: dict[int, object] = {}
        self.__issued: dict[
            int,
            tuple[
                ProfileCoverageExecutionRecord,
                FrozenMap,
                str,
                str,
                object,
                FrozenMap | None,
            ],
        ] = {}
        self.__observations: dict[
            int,
            tuple[
                ProfileCoverageObservation,
                ProfileCoverageExecutionRecord,
                FrozenMap,
                str,
                object,
            ],
        ] = {}
        self.__lifecycle_lock = threading.RLock()
        self.__lifecycle_state = "active"
        self.__revoke_capabilities: dict[int, tuple[object, object]] = {}
        self.__revoked_capabilities: dict[
            int,
            tuple[object, weakref.ReferenceType[object], bool],
        ] = {}
        self._performance_registry_factory = performance_factory
        self._performance_registry_authority = performance_registry_authority
        self._performance_registration = None
        self._performance_rejection_binding = None
        self._binding_lifecycle: ProfileCoverageBindingLifecycle | None = None
        self.__release_reader: _ReleaseCoverageReadBinding | None = None
        if performance_factory is not None:
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkError,
            )

            try:
                task_id = category_application._facts._coverage_task_identity()
                matching = tuple(
                    binding
                    for binding in plan.bindings.values()
                    if binding["task_id"] == task_id
                )
                if (
                    len(matching) == 1
                    and matching[0]["expected_result"] == "EXPECTED_REJECTION"
                    and matching[0]["selector_kind"] == "scenario"
                ):
                    self._performance_rejection_binding = matching[0]
                else:
                    self._performance_registration = (
                        performance_factory._issue_profile_coverage_registration(
                            authority=self,
                            application=category_application,
                            task_application=task_application,
                            repository=repository,
                            object_repository=object_repository,
                            runtime=runtime,
                            plan=plan,
                            registry_authority=performance_registry_authority,
                        )
                    )
            except PerformanceBenchmarkError as error:
                raise ProfileCoverageError(
                    "performance coverage authority registration failed"
                ) from error
        self._coverage_registration = ProfileCoverageAuthorityRegistration._issue(
            self, plan,
        )

    def _bind_binding_lifecycle(
        self,
        lifecycle: ProfileCoverageBindingLifecycle,
    ) -> None:
        if (
            type(lifecycle) is not ProfileCoverageBindingLifecycle
            or self._binding_lifecycle is not None
            or lifecycle.state != "QUIESCED"
        ):
            raise ProfileCoverageError("coverage binding lifecycle is foreign")
        lifecycle._require_process_local_current()
        self._binding_lifecycle = lifecycle

    def _seal_release_reader(self, record: object, namespace: object) -> _ReleaseCoverageReadBinding:
        if self.__release_reader is not None:
            raise ProfileCoverageError("release reader is already sealed")
        reader = _ReleaseCoverageReadBinding._issue(self, record, namespace)
        self.__release_reader = reader
        return reader

    def _run_binding_phase(self, purpose: str, phase: object) -> object:
        lifecycle = self._binding_lifecycle
        if lifecycle is None:
            if not callable(phase):
                raise ProfileCoverageError("coverage binding phase is unavailable")
            return phase()
        return lifecycle.run(purpose, lambda _handle: phase())

    def _quiesce_dependency_security(
        self, authority: tuple[object, object],
    ) -> None:
        """Release the live generic dependency tuple after its runtime seals it."""

        self._require_active()
        from graph_engineering.application.dependency_security import (
            DependencySecurityObservation,
            DependencySecurityObservationFactory,
        )

        if (
            authority is not self._dependency_security
            or type(authority) is not tuple
            or len(authority) != 2
            or type(authority[0]) is not DependencySecurityObservationFactory
            or type(authority[1]) is not DependencySecurityObservation
            or authority[1]._authority is not authority[0]
            or authority[1]._projection.get("schema_version")
            not in {"1.0.0", "1.1.0"}
        ):
            raise ProfileCoverageError(
                "dependency security quiesce authority is foreign"
            )
        authority[0].require_current(authority[1])
        self._dependency_security = None

    def _rebind_binding_runtime(
        self,
        *,
        category_application: CategoryExecutionApplication,
        task_application: TaskApplication,
        repository: TaskRepository,
        object_repository: ObjectRepository,
        runtime: RuntimeContext,
        dependency_security: tuple[object, object] | None = None,
    ) -> None:
        old_category = self._category
        if (
            type(category_application) is not CategoryExecutionApplication
            or type(task_application) is not TaskApplication
            or type(repository) is not TaskRepository
            or type(object_repository) is not ObjectRepository
            or type(runtime) is not RuntimeContext
            or category_application._task_application is not task_application
            or category_application._repository is not repository
            or category_application._objects is not object_repository
            or category_application._runtime is not runtime
            or task_application._repository is not repository
            or task_application._materialization_objects is not object_repository
            or old_category is None
            or category_application._policy is not old_category._policy
            or category_application._facts._coverage_task_identity()
            != old_category._facts._coverage_task_identity()
        ):
            raise ProfileCoverageError("coverage binding runtime is foreign")
        profile_id = category_application._policy.profile_id
        if profile_id == "dependency-security":
            from graph_engineering.application.dependency_security import (
                DependencyGraphAssessmentEvidence,
                DependencyGraphAssessmentFactory,
                DependencySecurityObservation,
                DependencySecurityObservationFactory,
            )

            generic_current = (
                type(dependency_security) is tuple
                and len(dependency_security) == 2
                and type(dependency_security[0])
                is DependencySecurityObservationFactory
                and type(dependency_security[1]) is DependencySecurityObservation
                and dependency_security[0]._category is category_application
                and dependency_security[1]._authority is dependency_security[0]
                and dependency_security[0].require_current(dependency_security[1])
                is dependency_security[1]
            )
            graph_current = (
                type(dependency_security) is tuple
                and len(dependency_security) == 2
                and type(dependency_security[0]) is DependencyGraphAssessmentFactory
                and type(dependency_security[1]) is DependencyGraphAssessmentEvidence
                and dependency_security[0]._repository is repository
                and dependency_security[1]._authority is dependency_security[0]
                and dependency_security[0].require_current(dependency_security[1])
                is dependency_security[1]
            )
            if not generic_current and not graph_current:
                raise ProfileCoverageError(
                    "restarted dependency security authority is unavailable"
                )
        elif dependency_security is not None:
            raise ProfileCoverageError(
                "restarted dependency security authority is cross-profile"
            )
        performance_factory = self._performance_registry_factory
        performance_authority = self._performance_registry_authority
        performance_registration = self._performance_registration
        if performance_factory is not None:
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkError,
                PerformanceBenchmarkRegistryFactory,
            )

            restarted_factory = (
                category_application._oracle._performance_registry_factory
            )
            restarted_authority = (
                category_application._oracle._performance_registry_authority
            )
            try:
                if type(restarted_factory) is not PerformanceBenchmarkRegistryFactory:
                    raise PerformanceBenchmarkError(
                        "restarted performance coverage factory is unavailable"
                    )
                restarted_factory.require_current(restarted_authority)
                if performance_registration is None:
                    if self._performance_rejection_binding is None:
                        raise PerformanceBenchmarkError(
                            "restarted performance rejection binding is unavailable"
                        )
                    restarted_registration = None
                else:
                    task_id = category_application._facts._coverage_task_identity()
                    current_bindings = tuple(
                        binding
                        for binding in self._plan.bindings.values()
                        if binding["task_id"] == task_id
                    )
                    if (
                        len(current_bindings) == 1
                        and current_bindings[0]["expected_result"]
                        == "EXPECTED_REJECTION"
                    ):
                        performance_factory._rehydrate_quiescent_profile_coverage_rejection(
                            performance_registration,
                            self,
                            restarted_factory,
                            restarted_authority,
                        )
                    restarted_registration = (
                        restarted_factory._issue_profile_coverage_registration(
                            authority=self,
                            application=category_application,
                            task_application=task_application,
                            repository=repository,
                            object_repository=object_repository,
                            runtime=runtime,
                            plan=self._plan,
                            registry_authority=restarted_authority,
                        )
                    )
            except PerformanceBenchmarkError as error:
                close = getattr(restarted_factory, "close", None)
                if callable(close):
                    close()
                raise ProfileCoverageError(
                    "restarted performance coverage authority is unavailable"
                ) from error
            performance_factory = restarted_factory
            performance_authority = restarted_authority
            performance_registration = restarted_registration
        self._category = category_application
        self._tasks = task_application
        self._repository = repository
        self._objects = object_repository
        self._runtime = runtime
        self._dependency_security = dependency_security
        self._performance_registry_factory = performance_factory
        self._performance_registry_authority = performance_authority
        self._performance_registration = performance_registration

    def _binding_lifecycle_projection(
        self,
        record: ProfileCoverageExecutionRecord,
    ) -> dict[str, object]:
        import graph_engineering

        issued = self._require_record(record)
        try:
            archive_resources = graph_engineering._validate_distribution_identity()
            provenance, plan, oracles, runner = (
                graph_engineering._profile_coverage_installation_resources()
            )
        except Exception as error:
            raise ProfileCoverageError(
                "coverage binding installation closure is stale"
            ) from error
        installed_members = (provenance, plan, *oracles, runner)
        observation_digests = sorted(
            item[0].observation_digest
            for item in self.__observations.values()
            if item[1] is issued
        )
        return {
            "archive_members": (
                []
                if archive_resources is None
                else [
                    [name, hashlib.sha256(body).hexdigest(), len(body)]
                    for name, body in archive_resources
                ]
            ),
            "execution_digest": issued.execution_digest,
            "execution_object_digest": issued.execution_object_digest,
            "execution_object_identity": str(id(issued)),
            "installation_members": [
                [hashlib.sha256(body).hexdigest(), len(body)]
                for body in installed_members
            ],
            "observation_digests": observation_digests,
            "observation_object_identities": sorted(
                str(id(item[0]))
                for item in self.__observations.values()
                if item[1] is issued
            ),
            "plan_digest": self._plan.plan_digest,
            "task_state": (self._state_document(issued.task_id) if self.__release_reader is None
                else {"source_state_digest": issued.after_state_digest}),
        }

    def _require_active(self) -> None:
        lifecycle_lock = getattr(
            self, "_ProfileCoverageAuthority__lifecycle_lock", None,
        )
        if lifecycle_lock is None:
            raise ProfileCoverageError(
                "production coverage authority is cloned or unissued"
            )
        with lifecycle_lock:
            if getattr(
                self, "_ProfileCoverageAuthority__lifecycle_state", None,
            ) != "active":
                raise ProfileCoverageError(
                    "production coverage authority is closed"
                )
        performance_factory = getattr(
            self, "_performance_registry_factory", None,
        )
        performance_registration = getattr(
            self, "_performance_registration", None,
        )
        performance_rejection_binding = getattr(
            self, "_performance_rejection_binding", None,
        )
        if (
            performance_factory is not None
            or performance_registration is not None
            or performance_rejection_binding is not None
        ):
            from graph_engineering.application.performance_benchmark import (
                PerformanceBenchmarkError,
                PerformanceBenchmarkRegistryFactory,
            )

            try:
                if type(performance_factory) is not PerformanceBenchmarkRegistryFactory:
                    raise PerformanceBenchmarkError(
                        "performance coverage factory changed"
                    )
                if performance_registration is not None:
                    performance_factory._require_profile_coverage_registration(
                        performance_registration, self,
                    )
                else:
                    performance_factory.require_current(
                        self._performance_registry_authority,
                    )
                    task_id = self._category._facts._coverage_task_identity()
                    current = tuple(
                        binding
                        for binding in self._plan.bindings.values()
                        if binding["task_id"] == task_id
                    )
                    if (
                        len(current) != 1
                        or current[0] is not performance_rejection_binding
                        or current[0]["profile_id"] != "performance"
                        or current[0]["expected_result"] != "EXPECTED_REJECTION"
                        or current[0]["selector_kind"] != "scenario"
                    ):
                        raise PerformanceBenchmarkError(
                            "performance rejection binding changed"
                        )
            except PerformanceBenchmarkError as error:
                raise ProfileCoverageError(
                    "performance coverage authority is foreign or stale"
                ) from error

    def _register_factory_capability(
        self,
        registration: object,
        factory: object,
        capability: object,
    ) -> None:
        from graph_engineering.core.profiles import CoverageRecordFactory

        with self.__lifecycle_lock:
            lifecycle = self._binding_lifecycle
            if lifecycle is None:
                self._require_active()
            elif (
                type(lifecycle) is not ProfileCoverageBindingLifecycle
                or self.__lifecycle_state != "active"
                or lifecycle.state != "QUIESCED"
                or lifecycle.generation != 1
                or lifecycle.expected_purpose != "use"
            ):
                raise ProfileCoverageError(
                    "production coverage lifecycle is not ready for record use"
                )
            if lifecycle is not None:
                lifecycle._require_process_local_current()
            if (
                registration is not self._coverage_registration
                or type(factory) is not CoverageRecordFactory
                or type(capability) is not object
                or id(capability) in self.__revoke_capabilities
                or id(capability) in self.__revoked_capabilities
            ):
                raise ProfileCoverageError(
                    "production coverage lifecycle capability is foreign"
                )
            self.__revoke_capabilities[id(capability)] = (
                capability,
                factory,
            )

    def _revoke_from_factory(
        self,
        registration: object,
        factory: object,
        capability: object,
        terminal_action: str,
    ) -> bool:
        with self.__lifecycle_lock:
            revoked = self.__revoked_capabilities.get(id(capability))
            if revoked is not None:
                if (
                    registration is not self._coverage_registration
                    or revoked[0] is not capability
                    or revoked[1]() is not factory
                ):
                    raise ProfileCoverageError(
                        "production coverage lifecycle capability is foreign"
                    )
                return revoked[2]
            binding = self.__revoke_capabilities.get(id(capability))
            if (
                registration is not self._coverage_registration
                or binding is None
                or binding[0] is not capability
                or binding[1] is not factory
                or terminal_action not in {"finalize", "revoke"}
            ):
                raise ProfileCoverageError(
                    "production coverage lifecycle capability is foreign"
                )
            del self.__revoke_capabilities[id(capability)]
            if self.__revoke_capabilities:
                self.__revoked_capabilities[id(capability)] = (
                    capability,
                    weakref.ref(factory),
                    False,
                )
                return False
            if self.__lifecycle_state != "active":
                raise ProfileCoverageError(
                    "production coverage authority is closing"
                )
            self.__lifecycle_state = "closing"
            try:
                lifecycle = self._binding_lifecycle
                if (
                    lifecycle is not None
                    and lifecycle.state != "PERMANENTLY_CLOSED"
                ):
                    lifecycle.terminate(terminal_action)
                self.__observations.clear()
                self.__issued.clear()
                self.__scenario_rejections.clear()
                self.__scenario_rejection_factory = None
                if self.__release_reader is not None:
                    self.__release_reader.terminate(terminal_action)
                    self.__release_reader = None
                self._category = None
                self._tasks = None
                self._repository = None
                self._objects = None
                self._runtime = None
                self._dependency_security = None
                self._plan = None
                self._binding_lifecycle = None
            finally:
                self.__lifecycle_state = "closed"
            self.__revoked_capabilities[id(capability)] = (
                capability,
                weakref.ref(factory),
                True,
            )
            return True

    def _state_document(self, task_id: str) -> dict[str, object]:
        self._require_active()
        dependency_observation = self._require_dependency_security_current(
            task_id=task_id,
        )
        try:
            view = self._tasks.runtime_show(task_id, self._runtime)
            events = self._repository.replay(task_id)
            references = self._repository.referenced_objects(task_id)
        except Exception as error:
            raise ProfileCoverageError(
                "production coverage task state is unavailable"
            ) from error
        document = {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "snapshot": view.snapshot.to_dict(),
            "runner": thaw(freeze(view.runner_state)),
            "events": list(events),
            "object_references": [
                {"digest": digest, "bytes_sha256": _raw_sha256(body)}
                for digest, body in references
            ],
        }
        if dependency_observation is not None:
            document["dependency_security_observation_digest"] = (
                dependency_observation.observation_digest
            )
        return document

    def _require_dependency_security_current(
        self,
        *,
        task_id: str,
        precommit: bool = False,
        restart: bool = False,
    ) -> object | None:
        self._require_active()
        if self._category._policy.profile_id != "dependency-security":
            return None
        authority = self._dependency_security
        if type(authority) is not tuple or len(authority) != 2:
            raise ProfileCoverageError(
                "dependency security coverage authority is unavailable"
            )
        factory, observation = authority
        if getattr(observation, "task_id", None) != task_id:
            raise ProfileCoverageError(
                "dependency security coverage task identity is foreign"
            )
        try:
            if precommit:
                return factory.precommit(observation)
            if restart:
                return factory.restart(observation)
            return factory.require_current(observation)
        except Exception as error:
            raise ProfileCoverageError(
                "dependency security observation is stale or foreign"
            ) from error

    @staticmethod
    def _pins(graph_ref: object) -> dict[str, object]:
        if not isinstance(graph_ref, Mapping):
            raise ProfileCoverageError("production coverage GraphRef is absent")
        fields = {
            "base_graph_digest": graph_ref.get("graph_digest"),
            "profile_digest": graph_ref.get("profile_digest"),
            "overlay_digest": graph_ref.get("overlay_digest"),
            "project_config_digest": graph_ref.get("project_config_digest"),
            "support_matrix_digest": graph_ref.get("support_matrix_digest"),
            "materialization_digest": graph_ref.get("materialization_digest"),
        }
        if any(
            type(value) is not str or not value.startswith("sha256-jcs-v1:")
            for value in fields.values()
        ):
            raise ProfileCoverageError("production coverage GraphRef pins are invalid")
        return fields

    def _binding(self, test_id: str, disposition: str) -> FrozenMap:
        self._require_active()
        self._plan.isolated_runner_bytes()
        binding = self._plan.binding(test_id)
        if binding["disposition"] != disposition:
            raise ProfileCoverageError("coverage execution disposition is wrong")
        return binding

    def _require_real_e2e_current(
        self,
        binding: Mapping[str, object],
        *,
        task_id: str,
    ) -> None:
        self._require_active()
        if (
            binding.get("column_id") != "real-e2e"
            or binding.get("execution_kind") != "real-target"
        ):
            return
        authority = self._category._facts._real_e2e_authority
        if self.__release_reader is not None:
            self.__release_reader.require_current()
            return
        try:
            from graph_engineering.application.profile_execution import _require_real_category_authority
            _require_real_category_authority(authority, str(binding["profile_id"]))
            authority.require_current(
                expected_task_id=task_id,
                require_success=binding.get("disposition") == "P",
            )
        except ValueError as error:
            raise ProfileCoverageError(str(error)) from error

    @staticmethod
    def _record_digests(values: Mapping[str, object]) -> tuple[str, str, FrozenMap]:
        body = {"schema_version": "1.0.0", **dict(values)}
        projection = _frozen_mapping(body, "coverage execution projection")
        execution_digest = _semantic(
            body,
            "profile-coverage-execution-record",
        )
        document = {**body, "execution_digest": execution_digest}
        execution_object_digest = "sha256:" + _raw_sha256(canonical_bytes(document))
        return execution_digest, execution_object_digest, projection

    def _issue_record(
        self,
        values: Mapping[str, object],
        *,
        request_projection: object | None = None,
        rejection_evidence: object | None = None,
    ) -> ProfileCoverageExecutionRecord:
        self._require_active()
        self._require_dependency_security_current(
            task_id=str(values.get("task_id", "")),
            precommit=True,
        )
        expected_fields = {
            name
            for name in ProfileCoverageExecutionRecord.__dataclass_fields__
            if not name.startswith("_")
            and name not in {"execution_digest", "execution_object_digest"}
        }
        if set(values) != expected_fields:
            raise ProfileCoverageError("coverage execution projection is not exact")
        execution_digest, execution_object_digest, projection = (
            self._record_digests(values)
        )
        frozen_request = (
            None
            if request_projection is None
            else _frozen_mapping(
                request_projection, "coverage rejection request projection",
            )
        )
        capability = object()
        result = object.__new__(ProfileCoverageExecutionRecord)
        for field, value in (
            *((name, value) for name, value in values.items()),
            ("execution_digest", execution_digest),
            ("execution_object_digest", execution_object_digest),
            ("_authority", self),
            ("_capability", capability),
        ):
            if field == "materialization_pins":
                value = _frozen_mapping(value, "coverage materialization pins")
            object.__setattr__(result, field, value)
        self._require_active()
        if values["result"] == "EXPECTED_REJECTION":
            current_rejection_digest = self._scenario_rejection_digest(
                str(values["test_id"]), rejection_evidence,
            )
            if current_rejection_digest != values["typed_evidence_object_digest"]:
                raise ProfileCoverageError("scenario rejection changed before issuance")
        self.__issued[id(result)] = (
            result,
            projection,
            execution_digest,
            execution_object_digest,
            capability,
            frozen_request,
        )
        if rejection_evidence is not None:
            self.__scenario_rejections[id(result)] = rejection_evidence
        return result

    def _completion_values(
        self,
        test_id: str,
        *,
        task_id: str,
        expected_profile_id: str,
    ) -> dict[str, object]:
        self._require_active()
        binding = self._binding(test_id, "P")
        if binding["profile_id"] != expected_profile_id:
            raise ProfileCoverageError("coverage completion Profile is foreign")
        if task_id != binding["task_id"]:
            raise ProfileCoverageError("coverage completion task identity is foreign")
        if self.__release_reader is not None:
            return self.__release_reader.completion_values(test_id)
        self._require_real_e2e_current(binding, task_id=task_id)
        try:
            assessment = self._category.current_assessment(
                task_id,
                expected_profile_id=expected_profile_id,
            )
            view = self._tasks.runtime_show(task_id, self._runtime)
        except Exception as error:
            raise ProfileCoverageError(
                "current production category assessment is unavailable"
            ) from error
        if assessment is None:
            raise ProfileCoverageError("current production assessment is absent")
        snapshot = view.snapshot
        if (
            assessment.profile_id != binding["profile_id"]
            or assessment.column_id != binding["column_id"]
            or snapshot.graph_ref.get("profile_id") != binding["profile_id"]
            or snapshot.graph_ref.get("overlay_id") != binding["overlay_id"]
            or (
                binding["selector_kind"] == "scenario"
                and assessment.scenario_id
                != binding["category_boundary_case_id"]
            )
        ):
            raise ProfileCoverageError(
                "coverage completion plan selector is stale or foreign"
            )
        dependency_graph_scenario = (
            assessment.profile_id == "dependency-security"
            and assessment.scenario_id in {
                "GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P",
                "GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P",
            }
        )
        if dependency_graph_scenario:
            from graph_engineering.application.dependency_security import (
                DependencyGraphAssessmentEvidence,
                DependencySecurityObservation,
            )

            projection = getattr(assessment, "dependency_graph_projection", None)
            if (
                assessment.schema_version != "1.2.0"
                or not isinstance(projection, FrozenMap)
                or assessment.migration_rehearsal_projection is not None
                or assessment.performance_evidence_projection is not None
            ):
                raise ProfileCoverageError(
                    "dependency graph category projection is absent or foreign"
                )
            projection_body = thaw(projection)
            dependency_evidence = self._require_dependency_security_current(
                task_id=task_id,
            )
            evidence_projection = getattr(
                dependency_evidence, "_projection", None,
            )
            if (
                type(projection_body) is not dict
                or projection_body.get("task_id") != assessment.task_id
                or projection_body.get("task_revision") != assessment.task_revision
                or projection_body.get("snapshot_digest")
                != assessment.snapshot_digest
                or projection_body.get("invalidation_epoch")
                != assessment.invalidation_epoch
                or projection_body.get("graph_ref_pins")
                != thaw(assessment.materialization_pins)
                or projection_body.get("observation")
                != (
                    dependency_evidence.to_dict()
                    if type(dependency_evidence) is DependencySecurityObservation
                    else projection_body.get("observation")
                )
                or (
                    isinstance(evidence_projection, FrozenMap)
                    and type(dependency_evidence) is DependencyGraphAssessmentEvidence
                    and evidence_projection != projection
                )
            ):
                raise ProfileCoverageError(
                    "dependency graph category projection binding changed"
                )
        elif getattr(assessment, "dependency_graph_projection", None) is not None:
            raise ProfileCoverageError(
                "dependency graph category projection crossed selector boundary"
            )
        scenario_projection = getattr(assessment, "scenario_truth_projection", None)
        if scenario_projection is not None:
            if (
                assessment.schema_version != "1.3.0"
                or binding["selector_kind"] != "scenario"
                or not isinstance(scenario_projection, FrozenMap)
                or assessment.performance_evidence_projection is not None
                or assessment.migration_rehearsal_projection is not None
                or assessment.dependency_graph_projection is not None
            ):
                raise ProfileCoverageError(
                    "scenario truth category projection is absent or foreign"
                )
            projection_body = thaw(scenario_projection)
            expected_boundary_case = (
                "GEW-PSC-" + str(projection_body.get("profile_id", "")).upper()
                + "-" + str(projection_body.get("scenario_id", "")).upper() + "-P"
            )
            if (
                projection_body.get("task_id") != assessment.task_id
                or projection_body.get("task_revision") != assessment.task_revision
                or projection_body.get("snapshot_digest") != assessment.snapshot_digest
                or projection_body.get("invalidation_epoch")
                != assessment.invalidation_epoch
                or projection_body.get("profile_id") != assessment.profile_id
                or expected_boundary_case != assessment.scenario_id
                or projection_body.get("graph_ref_pins")
                != thaw(assessment.materialization_pins)
            ):
                raise ProfileCoverageError(
                    "scenario truth category projection binding changed"
                )
        elif assessment.schema_version == "1.3.0":
            raise ProfileCoverageError("scenario truth projection is missing")
        release_projection = getattr(assessment, "release_operations_projection", None)
        if assessment.profile_id == "release-operations" or release_projection is not None or assessment.schema_version == "1.4.0":
            if (
                assessment.schema_version != "1.4.0"
                or assessment.profile_id != "release-operations"
                or binding["selector_kind"] != "mandatory"
                or not isinstance(release_projection, FrozenMap)
                or any(getattr(assessment, field) is not None for field in (
                    "performance_evidence_projection", "migration_rehearsal_projection",
                    "dependency_graph_projection", "scenario_truth_projection"))
            ):
                raise ProfileCoverageError("release category projection is absent or foreign")
            projection_body = thaw(release_projection)
            if (
                any(projection_body.get(field) != getattr(assessment, field) for field in (
                    "task_id", "task_revision", "snapshot_digest", "invalidation_epoch",
                    "column_id", "scenario_id"))
                or projection_body.get("graph_ref_pins") != thaw(assessment.materialization_pins)
            ):
                raise ProfileCoverageError("release category projection binding changed")
        reference = {
            "evidence_id": assessment.assessment_digest,
            "evidence_type": "category-completion-assessment",
            "source_ref": assessment.object_digest,
            "digest": assessment.assessment_digest,
            "trust": "factory-attested",
        }
        references = [item.to_dict() for item in snapshot.evidence]
        if references.count(reference) != 1:
            raise ProfileCoverageError("category assessment reference is not unique/current")
        try:
            assessment_bytes = self._objects.get(
                assessment.object_digest,
                require_referenced=False,
            )
            evidence = self._category._facts.require_assessment_evidence(assessment)
            referenced = self._repository.referenced_objects(task_id)
        except Exception as error:
            raise ProfileCoverageError(
                "category assessment or typed evidence is unavailable"
            ) from error
        if assessment_bytes != assessment.to_bytes():
            raise ProfileCoverageError("category assessment object bytes changed")
        evidence_bytes = canonical_bytes(evidence)
        oracle = self._plan.oracle_for(test_id)
        evidence_facts = evidence.get("facts")
        if (
            evidence.get("evidence_kind") != oracle["evidence_kind"]
            or evidence.get("outcome") != oracle["required_outcome"]
            or type(evidence_facts) is not dict
            or tuple(sorted(evidence_facts)) != tuple(oracle["required_fact_ids"])
        ):
            raise ProfileCoverageError(
                "typed category evidence does not match the installed oracle"
            )
        matching_evidence = tuple(
            digest for digest, body in referenced if body == evidence_bytes
        )
        if len(matching_evidence) != 1:
            raise ProfileCoverageError("typed category evidence is not uniquely referenced")
        pins = self._pins(snapshot.graph_ref)
        if pins != thaw(assessment.materialization_pins):
            raise ProfileCoverageError("category assessment GraphRef pins changed")
        state = self._state_document(task_id)
        state_digest = _semantic(state, "profile-coverage-task-state")
        reference_digest = _semantic(
            {"schema_version": "1.0.0", **reference},
            "profile-coverage-assessment-reference",
        )
        runtime = self._plan.runtime_binding
        return {
            "test_id": test_id,
            "result": str(binding["expected_result"]),
            "request_digest": assessment.request_digest,
            "profile_id": assessment.profile_id,
            "profile_version": assessment.profile_version,
            "column_id": assessment.column_id,
            "selector_kind": str(binding["selector_kind"]),
            "scenario_id": binding["scenario_id"],
            "category_boundary_case_id": binding["category_boundary_case_id"],
            "plan_selector_digest": str(binding["selector_digest"]),
            "profile_digest": assessment.profile_digest,
            "overlay_id": assessment.overlay_id,
            "overlay_version": str(snapshot.graph_ref["overlay_version"]),
            "overlay_digest": str(snapshot.graph_ref["overlay_digest"]),
            "task_id": task_id,
            "task_revision": snapshot.task_revision,
            "snapshot_digest": snapshot.snapshot_digest,
            "invalidation_epoch": snapshot.invalidation_epoch,
            "materialization_pins": pins,
            "assessment_digest": assessment.assessment_digest,
            "assessment_object_digest": assessment.object_digest,
            "assessment_reference_digest": reference_digest,
            "column_evidence_digest": assessment.column_evidence_digest,
            "typed_evidence_object_digest": matching_evidence[0],
            "matrix_digest": self._plan.support_matrix_digest,
            "plan_digest": self._plan.plan_digest,
            "oracle_id": str(oracle["oracle_id"]),
            "oracle_digest": str(oracle["oracle_digest"]),
            "runtime_kind": str(runtime["runtime_kind"]),
            "runtime_lineage_id": str(runtime["runtime_lineage_id"]),
            "runtime_digest": str(runtime["runtime_digest"]),
            "execution_kind": str(binding["execution_kind"]),
            "before_state_digest": assessment.snapshot_digest,
            "after_state_digest": state_digest,
            "rejection_error_type": None,
            "rejection_error_message": None,
            "isolated_oracle_digest": str(oracle["oracle_digest"]),
        }

    def observe_completion(
        self,
        test_id: str,
        *,
        task_id: str,
        expected_profile_id: str,
    ) -> ProfileCoverageExecutionRecord:
        self._require_active()
        values = self._completion_values(
            test_id,
            task_id=task_id,
            expected_profile_id=expected_profile_id,
        )
        return self._issue_record(values)

    def _isolated_rejection_oracle(
        self,
        *,
        test_id: str,
        result: str,
        error_type: str,
        error_message: str,
        before_state: dict[str, object],
        after_state: dict[str, object],
        before_candidate: object,
        after_candidate: object,
    ) -> str:
        self._require_active()
        runner = self._plan.isolated_runner_bytes()
        oracle = self._plan.oracle_for(test_id)
        payload = {
            "schema_version": "1.0.0",
            "test_id": test_id,
            "result": result,
            "expected_result": oracle["reject_result"],
            "error_type": error_type,
            "expected_error_type": oracle["reject_error_type"],
            "error_message": error_message,
            "expected_error_message": oracle["reject_error_message"],
            "before_state": before_state,
            "after_state": after_state,
            "before_candidate": before_candidate,
            "after_candidate": after_candidate,
            "oracle_id": oracle["oracle_id"],
            "oracle_digest": oracle["oracle_digest"],
            "plan_digest": self._plan.plan_digest,
        }
        envelope = {
            "runner_source_b64": base64.b64encode(runner).decode("ascii"),
            "runner_raw_sha256": _raw_sha256(runner),
            "payload": payload,
        }
        command = [sys.executable, "-I", "-c", _PIPE_BOOTSTRAP]
        completed = subprocess.run(
            command,
            input=canonical_bytes(envelope),
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0 or completed.stderr:
            raise ProfileCoverageError("isolated rejection oracle failed closed")
        try:
            observed = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProfileCoverageError("isolated rejection oracle output is malformed") from error
        body = {
            "schema_version": "1.0.0",
            "test_id": test_id,
            "result": result,
            "zero_state_change": True,
            "unchanged_input": True,
            "oracle_id": oracle["oracle_id"],
            "oracle_digest": oracle["oracle_digest"],
            "plan_digest": self._plan.plan_digest,
        }
        expected = {
            **body,
            "oracle_result_digest": _raw_sha256(canonical_bytes(body)),
        }
        if observed != expected:
            raise ProfileCoverageError("isolated rejection oracle result changed")
        return "sha256:" + str(observed["oracle_result_digest"])

    def _scenario_rejection_digest(self, test_id: str, evidence: object) -> str | None:
        from graph_engineering.core.scenario_truth import ScenarioTruthError

        binding = self._binding(test_id, "R")
        factory = self.__scenario_rejection_factory
        try:
            if factory is None and binding["selector_kind"] == "scenario":
                from graph_engineering.application.scenario_truth import ScenarioTruthRegistryFactory
                installed = ScenarioTruthRegistryFactory.from_installation()
                try:
                    if installed.rejection_attack_ids(binding["profile_id"], binding["scenario_id"]):
                        raise ScenarioTruthError("required scenario rejection issuer is absent")
                finally:
                    installed.close()
            required = (
                factory is not None and binding["selector_kind"] == "scenario"
                and factory.rejection_attack_ids(binding["profile_id"], binding["scenario_id"])
            )
            if not required:
                if evidence is not None:
                    raise ScenarioTruthError("scenario rejection evidence crossed selector boundary")
                return None
            task_id = str(binding["task_id"])
            snapshot = self._tasks.runtime_show(task_id, self._runtime).snapshot
            current = {
                "task_id": task_id, "task_revision": snapshot.task_revision,
                "snapshot_digest": snapshot.snapshot_digest,
                "invalidation_epoch": snapshot.invalidation_epoch,
                "profile_id": str(snapshot.graph_ref["profile_id"]),
                "profile_version": str(snapshot.graph_ref["profile_version"]),
                "scenario_id": binding["scenario_id"],
                "graph_ref_pins": self._pins(snapshot.graph_ref),
                "branch_id": "branch:" + task_id, "ref_id": "ref:" + task_id,
            }
            return factory.require_rejections(
                evidence, binding=current, test_id=test_id,
                oracle_digest=str(self._plan.oracle_for(test_id)["oracle_digest"]),
            )
        except ScenarioTruthError as error:
            raise ProfileCoverageError("scenario rejection evidence failed closed") from error

    def execute_rejection(
        self,
        test_id: str,
        *,
        candidate: object,
        observer: object,
        scenario_rejection_evidence: object | None = None,
    ) -> ProfileCoverageExecutionRecord:
        self._require_active()
        binding = self._binding(test_id, "R")
        rejection_evidence_digest = self._scenario_rejection_digest(
            test_id, scenario_rejection_evidence,
        )
        if type(candidate) is not dict:
            raise ProfileCoverageError("coverage rejection candidate is not exact")
        candidate_before = copy.deepcopy(candidate)
        request_digest = _semantic(
            candidate_before,
            "profile-coverage-request",
        )
        if (
            candidate_before.get("column_id") != binding["column_id"]
            or not hmac.compare_digest(
                request_digest, str(binding["request_digest"]),
            )
        ):
            raise ProfileCoverageError(
                "coverage rejection request is not the installed plan request"
            )
        task_id = candidate.get("task_id")
        if type(task_id) is not str:
            raise ProfileCoverageError("coverage rejection task ID is invalid")
        if task_id != binding["task_id"]:
            raise ProfileCoverageError("coverage rejection task identity is foreign")
        self._require_real_e2e_current(binding, task_id=task_id)
        before_state = self._state_document(task_id)
        performance_message = None
        if self._performance_rejection_binding is binding:
            try:
                performance_message = (
                    self._performance_registry_factory
                    ._profile_coverage_rejection_message(
                        self._performance_registry_authority,
                        self._plan.oracle_for(test_id),
                    )
                )
            except Exception as error:
                from graph_engineering.application.performance_benchmark import (
                    PerformanceBenchmarkError,
                )

                if not isinstance(error, PerformanceBenchmarkError):
                    raise
                raise ProfileCoverageError(
                    "performance coverage rejection proof failed closed"
                ) from error
        if performance_message is None:
            try:
                self._category.assess_and_commit(candidate, observer=observer)
            except CategoryExecutionError as error:
                rejection = error
            else:
                raise ProfileCoverageError(
                    "coverage rejection command unexpectedly committed"
                )
        else:
            rejection = CategoryExecutionError(performance_message)
        after_state = self._state_document(task_id)
        if candidate != candidate_before or after_state != before_state:
            raise ProfileCoverageError("coverage rejection changed input or durable task state")
        error_type = type(rejection).__name__
        error_message = str(rejection)
        result = str(binding["expected_result"])
        oracle_result_digest = self._isolated_rejection_oracle(
            test_id=test_id,
            result=result,
            error_type=error_type,
            error_message=error_message,
            before_state=before_state,
            after_state=after_state,
            before_candidate=candidate_before,
            after_candidate=candidate,
        )
        snapshot = self._tasks.runtime_show(task_id, self._runtime).snapshot
        if snapshot.graph_ref.get("profile_id") != binding["profile_id"]:
            raise ProfileCoverageError("coverage rejection Profile selector is foreign")
        pins = self._pins(snapshot.graph_ref)
        runtime = self._plan.runtime_binding
        oracle = self._plan.oracle_for(test_id)
        self._require_real_e2e_current(binding, task_id=task_id)
        values = {
            "test_id": test_id,
            "result": result,
            "request_digest": request_digest,
            "profile_id": str(snapshot.graph_ref["profile_id"]),
            "profile_version": str(snapshot.graph_ref["profile_version"]),
            "column_id": str(binding["column_id"]),
            "selector_kind": str(binding["selector_kind"]),
            "scenario_id": binding["scenario_id"],
            "category_boundary_case_id": binding["category_boundary_case_id"],
            "plan_selector_digest": str(binding["selector_digest"]),
            "profile_digest": str(snapshot.graph_ref["profile_digest"]),
            "overlay_id": str(snapshot.graph_ref["overlay_id"]),
            "overlay_version": str(snapshot.graph_ref["overlay_version"]),
            "overlay_digest": str(snapshot.graph_ref["overlay_digest"]),
            "task_id": task_id,
            "task_revision": snapshot.task_revision,
            "snapshot_digest": snapshot.snapshot_digest,
            "invalidation_epoch": snapshot.invalidation_epoch,
            "materialization_pins": pins,
            "assessment_digest": None,
            "assessment_object_digest": None,
            "assessment_reference_digest": None,
            "column_evidence_digest": None,
            "typed_evidence_object_digest": rejection_evidence_digest,
            "matrix_digest": self._plan.support_matrix_digest,
            "plan_digest": self._plan.plan_digest,
            "oracle_id": str(oracle["oracle_id"]),
            "oracle_digest": str(oracle["oracle_digest"]),
            "runtime_kind": str(runtime["runtime_kind"]),
            "runtime_lineage_id": str(runtime["runtime_lineage_id"]),
            "runtime_digest": str(runtime["runtime_digest"]),
            "execution_kind": str(binding["execution_kind"]),
            "before_state_digest": _semantic(
                before_state, "profile-coverage-task-state"
            ),
            "after_state_digest": _semantic(
                after_state, "profile-coverage-task-state"
            ),
            "rejection_error_type": error_type,
            "rejection_error_message": error_message,
            "isolated_oracle_digest": oracle_result_digest,
        }
        return self._issue_record(
            values,
            request_projection=candidate_before,
            rejection_evidence=scenario_rejection_evidence,
        )

    def _require_record(
        self,
        record: object,
    ) -> ProfileCoverageExecutionRecord:
        self._require_active()
        if (
            type(record) is not ProfileCoverageExecutionRecord
            or record._authority is not self
        ):
            raise ProfileCoverageError("coverage execution record is cloned or foreign")
        issued = self.__issued.get(id(record))
        if issued is None or issued[0] is not record:
            raise ProfileCoverageError("coverage execution record is cloned or foreign")
        (
            _original,
            original_projection,
            original_execution_digest,
            original_object_digest,
            capability,
            request_projection,
        ) = issued
        values = {
            name: getattr(record, name)
            for name in record.__dataclass_fields__
            if not name.startswith("_")
            and name not in {"execution_digest", "execution_object_digest"}
        }
        current_projection = _frozen_mapping(
            {"schema_version": "1.0.0", **values},
            "coverage execution projection",
        )
        if (
            record._capability is not capability
            or current_projection != original_projection
            or not hmac.compare_digest(
                record.execution_digest, original_execution_digest,
            )
            or not hmac.compare_digest(
                record.execution_object_digest, original_object_digest,
            )
        ):
            raise ProfileCoverageError(
                "coverage execution immutable issuance changed"
            )
        if record.result == "COMPLETED":
            current = self._completion_values(
                record.test_id,
                task_id=record.task_id,
                expected_profile_id=record.profile_id,
            )
            expected_execution, expected_object, expected_projection = (
                self._record_digests(current)
            )
            if (
                expected_projection != original_projection
                or not hmac.compare_digest(
                    expected_execution, record.execution_digest,
                )
                or not hmac.compare_digest(
                    expected_object, record.execution_object_digest,
                )
            ):
                raise ProfileCoverageError("coverage completion record is stale")
        elif record.result == "EXPECTED_REJECTION":
            rejection_evidence_digest = self._scenario_rejection_digest(
                record.test_id, self.__scenario_rejections.get(id(record)),
            )
            if rejection_evidence_digest != record.typed_evidence_object_digest:
                raise ProfileCoverageError("scenario rejection evidence digest changed")
            if request_projection is None:
                raise ProfileCoverageError(
                    "coverage rejection request projection is absent"
                )
            binding = self._binding(record.test_id, "R")
            if self.__release_reader is None:
                self._require_real_e2e_current(binding, task_id=record.task_id)
            request = thaw(request_projection)
            request_digest = _semantic(request, "profile-coverage-request")
            if self.__release_reader is None:
                current_state = self._state_document(record.task_id)
                current_digest = _semantic(current_state, "profile-coverage-task-state")
            else:
                current_digest = self.__release_reader.state_digest()
                current_state = {"source_state_digest": current_digest}
            oracle_digest = self._isolated_rejection_oracle(
                test_id=record.test_id,
                result=record.result,
                error_type=str(record.rejection_error_type),
                error_message=str(record.rejection_error_message),
                before_state=current_state,
                after_state=current_state,
                before_candidate=request,
                after_candidate=request,
            )
            if (
                request.get("column_id") != binding["column_id"]
                or request.get("task_id") != binding["task_id"]
                or record.task_id != binding["task_id"]
                or not hmac.compare_digest(
                    request_digest, str(binding["request_digest"]),
                )
                or record.profile_id != binding["profile_id"]
                or record.column_id != binding["column_id"]
                or record.selector_kind != binding["selector_kind"]
                or record.scenario_id != binding["scenario_id"]
                or record.category_boundary_case_id
                != binding["category_boundary_case_id"]
                or record.overlay_id != binding["overlay_id"]
                or not hmac.compare_digest(
                    record.plan_selector_digest, str(binding["selector_digest"]),
                )
                or not hmac.compare_digest(current_digest, record.before_state_digest)
                or not hmac.compare_digest(current_digest, record.after_state_digest)
                or not hmac.compare_digest(
                    oracle_digest, record.isolated_oracle_digest,
                )
            ):
                raise ProfileCoverageError("coverage rejection record is stale")
        else:
            raise ProfileCoverageError("coverage execution result is invalid")
        execution_digest, object_digest, projection = self._record_digests(values)
        if (
            projection != original_projection
            or not hmac.compare_digest(
                execution_digest, record.execution_digest,
            )
            or not hmac.compare_digest(
                object_digest, record.execution_object_digest,
            )
        ):
            raise ProfileCoverageError("coverage execution record digest changed")
        return record

    def observe(
        self,
        record: object,
    ) -> ProfileCoverageObservation:
        return self._run_binding_phase(
            "issue", lambda: self._observe_live(record),
        )  # type: ignore[return-value]

    def _observe_live(
        self,
        record: object,
    ) -> ProfileCoverageObservation:
        self._require_active()
        issued = self._require_record(record)
        binding = self._plan.binding(issued.test_id)
        profile_version = issued.profile_version
        fixture_id = f"profile:{issued.profile_id}:{profile_version}"
        values = {
            "test_id": issued.test_id,
            "matrix_digest": issued.matrix_digest,
            "profile_id": issued.profile_id,
            "profile_version": profile_version,
            "column_id": issued.column_id,
            "selector_kind": issued.selector_kind,
            "scenario_id": issued.scenario_id,
            "category_boundary_case_id": issued.category_boundary_case_id,
            "plan_digest": issued.plan_digest,
            "plan_selector_digest": issued.plan_selector_digest,
            "profile_digest": issued.profile_digest,
            "overlay_id": issued.overlay_id,
            "overlay_version": issued.overlay_version,
            "overlay_digest": issued.overlay_digest,
            "runtime_kind": issued.runtime_kind,
            "runtime_lineage_id": issued.runtime_lineage_id,
            "runtime_digest": issued.runtime_digest,
            "fixture_id": fixture_id,
            "oracle_id": issued.oracle_id,
            "evidence_type": "coverage-record",
            "owner_gate": "WP-08",
            "evidence_ref": (
                "profile-coverage-execution:" + issued.execution_object_digest
            ),
            "evidence_digest": issued.execution_object_digest,
            "execution_kind": str(binding["execution_kind"]),
            "execution_digest": issued.execution_digest,
        }
        observation_digest = _semantic(
            {"schema_version": "1.0.0", **values},
            "profile-coverage-observation",
        )
        projection = _frozen_mapping(
            {"schema_version": "1.0.0", **values},
            "coverage observation projection",
        )
        capability = object()
        observation = object.__new__(ProfileCoverageObservation)
        for field, value in (
            *((name, value) for name, value in values.items()),
            ("observation_digest", observation_digest),
            ("_authority", self),
            ("_capability", capability),
        ):
            object.__setattr__(observation, field, value)
        self._require_active()
        self.__observations[id(observation)] = (
            observation,
            issued,
            projection,
            observation_digest,
            capability,
        )
        return observation

    def _require_observation(
        self,
        observation: object,
    ) -> ProfileCoverageObservation:
        return self._require_observation_for_phase(observation, "use")

    def _require_observation_for_phase(
        self,
        observation: object,
        purpose: str,
    ) -> ProfileCoverageObservation:
        return self._run_binding_phase(
            purpose, lambda: self._require_observation_live(observation),
        )  # type: ignore[return-value]

    def _require_observation_live(
        self,
        observation: object,
    ) -> ProfileCoverageObservation:
        self._require_active()
        if (
            type(observation) is not ProfileCoverageObservation
            or observation._authority is not self
        ):
            raise ProfileCoverageError("coverage observation is cloned or foreign")
        issued = self.__observations.get(id(observation))
        if issued is None or issued[0] is not observation:
            raise ProfileCoverageError("coverage observation is not consumer-issued")
        record = self._require_record(issued[1])
        values = {
            name: getattr(observation, name)
            for name in observation.__dataclass_fields__
            if not name.startswith("_") and name != "observation_digest"
        }
        projection = _frozen_mapping(
            {"schema_version": "1.0.0", **values},
            "coverage observation projection",
        )
        expected = _semantic(
            {"schema_version": "1.0.0", **values},
            "profile-coverage-observation",
        )
        if (
            observation._capability is not issued[4]
            or projection != issued[2]
            or not hmac.compare_digest(
                observation.observation_digest, issued[3],
            )
            or not hmac.compare_digest(observation.observation_digest, expected)
            or not hmac.compare_digest(
                observation.execution_digest,
                record.execution_digest,
            )
            or observation.evidence_digest != record.execution_object_digest
            or observation.evidence_ref
            != "profile-coverage-execution:" + record.execution_object_digest
            or observation.profile_id != record.profile_id
            or observation.column_id != record.column_id
            or observation.selector_kind != record.selector_kind
            or observation.scenario_id != record.scenario_id
            or observation.category_boundary_case_id
            != record.category_boundary_case_id
            or observation.plan_digest != record.plan_digest
            or observation.plan_selector_digest != record.plan_selector_digest
        ):
            raise ProfileCoverageError("coverage observation binding changed")
        return observation


_register_profile_coverage_authority_type(ProfileCoverageAuthority)


__all__ = ["ProfileCoverageAuthority", "ProfileCoverageBindingLifecycle"]
