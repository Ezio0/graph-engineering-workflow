"""Factory-attested disposable local real-E2E predecessor authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.adapters.action_adapters import ActionAdapterFactory
from graph_engineering.adapters.command_native import (
    CommandExecutionRequest,
    CommandExecutionResult,
    StructuredCommandLauncher,
)
from graph_engineering.adapters.git_native import (
    GitIdentityObservation,
    GitNativeAdapter,
    GitTargetPlan,
)
from graph_engineering.application.actions import ActionCoordinator
from graph_engineering.application.tasks import RuntimeContext, TaskApplication
from graph_engineering.core.action_adapters import ActionInvocation
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.graph.state import TaskSnapshot
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.repository import TaskRepository


class ProfileRealE2EError(ValueError):
    """A disposable local real-E2E authority check failed closed."""


def _semantic(value: object, contract: str) -> str:
    return semantic_digest(
        value,
        contract_type=f"urn:gew:contract:{contract}",
        projection_id=f"urn:gew:digest-projection:{contract}:1.0.0",
        schema_id=f"urn:gew:schema:{contract}:1.0.0",
    )


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ProfileRealE2EError(f"{label} contains a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProfileRealE2EError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise ProfileRealE2EError(f"{label} is not a JSON object")
    return value


def _load_registry() -> dict[str, object]:
    from graph_engineering import (
        DistributionIdentityError,
        _profile_real_e2e_installation_resource,
    )

    try:
        provenance, body = _profile_real_e2e_installation_resource()
        document = _strict_json(body, "Profile real-E2E binding registry")
        bootstrap = tomllib.loads(provenance.decode("utf-8", errors="strict"))[
            "tool"
        ]["gew"]["profile"]["real-e2e-bindings"]
    except (
        DistributionIdentityError,
        KeyError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise ProfileRealE2EError(
            "Profile real-E2E installation binding is unavailable"
        ) from error
    expected_bootstrap = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource",
    }
    expected_document = {
        "schema_version", "registry_id", "profiles",
        "toolchain_id", "adapter_id", "operation_id", "command_id",
        "evidence_kind", "required_outcome", "required_fact_ids",
        "registry_digest",
    }
    if (
        type(bootstrap) is not dict
        or set(bootstrap) != expected_bootstrap
        or set(document) != expected_document
        or document["schema_version"] != "1.0.0"
        or bootstrap["registry-id"] != document["registry_id"]
        or bootstrap["registry-raw-sha256"] != hashlib.sha256(body).hexdigest()
    ):
        raise ProfileRealE2EError("Profile real-E2E bootstrap binding changed")
    claimed = document["registry_digest"]
    calculated = _semantic(
        {key: value for key, value in document.items() if key != "registry_digest"},
        "profile-real-e2e-binding-registry",
    )
    if (
        type(claimed) is not str
        or not hmac.compare_digest(claimed, calculated)
        or bootstrap["registry-digest"] != claimed
        or document["adapter_id"] != "git-native-v1"
        or document["operation_id"] != "git.update-ref"
        or type(document["profiles"]) is not list
        or not document["profiles"]
        or type(document["required_fact_ids"]) is not list
        or document["required_fact_ids"] != sorted(set(document["required_fact_ids"]))
    ):
        raise ProfileRealE2EError("Profile real-E2E registry is stale or incoherent")
    profile_ids: list[str] = []
    predecessor_keys: list[tuple[str, str]] = []
    for profile in document["profiles"]:
        if type(profile) is not dict or set(profile) != {
            "profile_id", "profile_version", "bindings",
        }:
            raise ProfileRealE2EError("Profile real-E2E Profile binding is not exact")
        profile_id = profile["profile_id"]
        if type(profile_id) is not str or not profile_id:
            raise ProfileRealE2EError("Profile real-E2E Profile ID is invalid")
        profile_ids.append(profile_id)
        bindings = profile["bindings"]
        if (
            profile["profile_version"] != "1.0.0"
            or type(bindings) is not list
            or len(bindings) != 2
        ):
            raise ProfileRealE2EError("Profile real-E2E Profile binding is stale")
        dispositions: list[str] = []
        for binding in bindings:
            fields = {
                "disposition", "test_id", "predecessor_id", "result",
                "journal_state", "claim_state", "reconcile_route",
                "mutation_delta", "command_required", "reject_error_message",
            }
            if type(binding) is not dict or set(binding) != fields:
                raise ProfileRealE2EError("Profile real-E2E binding is not exact")
            disposition = binding["disposition"]
            predecessor_id = binding["predecessor_id"]
            if (
                type(disposition) is not str
                or type(predecessor_id) is not str
                or binding["test_id"]
                != f"GEW-PRO-{profile_id.upper()}-REAL-E2E-{disposition}"
            ):
                raise ProfileRealE2EError("Profile real-E2E binding identity changed")
            dispositions.append(disposition)
            predecessor_keys.append((profile_id, predecessor_id))
        if dispositions != ["P", "R"]:
            raise ProfileRealE2EError("Profile real-E2E bindings are not canonical")
    if (
        profile_ids != sorted(set(profile_ids))
        or len(predecessor_keys) != len(set(predecessor_keys))
    ):
        raise ProfileRealE2EError("Profile real-E2E Profiles are not canonical")
    return document


@dataclass(frozen=True, slots=True, init=False, eq=False)
class ProfileRealE2EPredecessorRecord:
    body: Mapping[str, object]
    record_digest: str
    _authority: object
    _capability: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Profile real-E2E predecessor records are factory-issued")

    def to_dict(self) -> dict[str, object]:
        value = thaw(self.body)
        if type(value) is not dict:
            raise ProfileRealE2EError("Profile real-E2E record body is malformed")
        return value

    def to_bytes(self) -> bytes:
        return canonical_bytes(self.body)


@dataclass(frozen=True, slots=True, init=False, eq=False)
class ProfileRealE2EObserver:
    is_test_double = False
    is_read_only_observer = True
    execution_kind = "authoritative-real-e2e-observer"

    target_id: str
    resource_id: str
    expected_state: Mapping[str, object]
    rollback_state: Mapping[str, object]
    _authority: object
    _capability: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Profile real-E2E observers are factory-issued")

    def observe(self) -> dict[str, object]:
        authority = self._authority
        if type(authority) is not ProfileRealE2EAuthority:
            raise ProfileRealE2EError("Profile real-E2E observer authority is foreign")
        return authority.observe(self)

    @classmethod
    def require_issued(cls, value: object) -> ProfileRealE2EAuthority:
        if type(value) is not cls or type(value._authority) is not ProfileRealE2EAuthority:
            raise ProfileRealE2EError("Profile real-E2E observer is cloned or foreign")
        value._authority.require_observer(value)
        return value._authority


class ProfileRealE2EAuthority:
    """Bind one current local Git/action/command execution to one category task."""

    _PINS = (
        "base_graph_digest", "profile_digest", "overlay_digest",
        "project_config_digest", "support_matrix_digest",
        "materialization_digest",
    )
    _CURRENT_OBSERVATION_FIELDS = (
        "schema_version", "plan_id", "plan_digest", "target_id",
        "target_digest", "worktree_path", "worktree_device",
        "worktree_inode", "common_dir_path", "common_dir_device",
        "common_dir_inode", "head_ref", "head_oid", "fresh",
    )

    @classmethod
    def _same_current_observation(
        cls, current: GitIdentityObservation, expected: Mapping[str, object],
    ) -> bool:
        current_document = current.to_dict()
        try:
            reparsed = GitIdentityObservation.from_dict(current_document)
        except Exception:
            return False
        return reparsed == current and all(
            current_document.get(field) == expected.get(field)
            for field in cls._CURRENT_OBSERVATION_FIELDS
        )

    def __init__(
        self,
        *,
        coordinator: ActionCoordinator,
        action_repository: TaskRepository,
        adapter: GitNativeAdapter,
        target_plan_document: dict[str, object],
        expected_target: GitTargetPlan,
        launcher: StructuredCommandLauncher,
        profile_id: str,
        predecessor_id: str,
    ) -> None:
        registry = _load_registry()
        profiles = tuple(
            profile for profile in registry["profiles"]
            if isinstance(profile, dict) and profile.get("profile_id") == profile_id
        )
        matches = tuple(
            binding for binding in profiles[0]["bindings"]
            if isinstance(binding, dict) and binding.get("predecessor_id") == predecessor_id
        ) if len(profiles) == 1 and isinstance(profiles[0].get("bindings"), list) else ()
        if (
            type(coordinator) is not ActionCoordinator
            or type(action_repository) is not TaskRepository
            or coordinator._repository is not action_repository
            or type(adapter) is not GitNativeAdapter
            or ActionAdapterFactory.require_attested(adapter) is not adapter
            or type(expected_target) is not GitTargetPlan
            or type(target_plan_document) is not dict
            or GitTargetPlan.from_dict(target_plan_document) != expected_target
            or type(launcher) is not StructuredCommandLauncher
            or len(profiles) != 1
            or len(matches) != 1
        ):
            raise ProfileRealE2EError("Profile real-E2E authority inputs are foreign")
        before = adapter.observe(target_plan_document, expected=expected_target)
        if type(before) is not GitIdentityObservation:
            raise ProfileRealE2EError("Profile real-E2E initial target is unavailable")
        frozen_registry = freeze(registry)
        frozen_profile = freeze(profiles[0])
        frozen_binding = freeze(matches[0])
        if (
            not isinstance(frozen_registry, FrozenMap)
            or not isinstance(frozen_profile, FrozenMap)
            or not isinstance(frozen_binding, FrozenMap)
        ):
            raise ProfileRealE2EError(
                "Profile real-E2E installation projection did not freeze"
            )
        self._registry = frozen_registry
        self._profile = frozen_profile
        self._binding = frozen_binding
        self._coordinator = coordinator
        self._action_repository = action_repository
        self._adapter = adapter
        self._target_plan_document = dict(target_plan_document)
        self._expected_target = expected_target
        self._launcher = launcher
        self._before = before
        self._mutation_baseline = adapter.mutation_count
        self._adapter_phase_mutation_baseline = adapter.mutation_count
        self._cumulative_mutation_count = 0
        self._launcher_phase_launch_baseline = launcher.launch_count
        self._cumulative_launch_count = 0
        self._action_id: str | None = None
        self._execution: dict[str, object] | None = None
        self._record: ProfileRealE2EPredecessorRecord | None = None
        self._record_object_digest: str | None = None
        self._task_application: TaskApplication | None = None
        self._task_repository: TaskRepository | None = None
        self._objects: ObjectRepository | None = None
        self._runtime: RuntimeContext | None = None
        self.__records: dict[int, ProfileRealE2EPredecessorRecord] = {}
        self.__observers: dict[int, ProfileRealE2EObserver] = {}

    def _require_installation_current(self) -> None:
        """Reload and compare the complete installation-owned registry."""

        current = _load_registry()
        profiles = tuple(
            profile for profile in current["profiles"]
            if (
                isinstance(profile, dict)
                and profile.get("profile_id") == self.profile_id
            )
        )
        matches = tuple(
            binding for binding in profiles[0]["bindings"]
            if (
                isinstance(binding, dict)
                and binding.get("predecessor_id") == self.predecessor_id
            )
        ) if len(profiles) == 1 and isinstance(profiles[0].get("bindings"), list) else ()
        current_registry = freeze(current)
        current_profile = None if len(profiles) != 1 else freeze(profiles[0])
        current_binding = None if len(matches) != 1 else freeze(matches[0])
        if (
            not isinstance(current_registry, FrozenMap)
            or not isinstance(current_profile, FrozenMap)
            or not isinstance(current_binding, FrozenMap)
            or current_registry != self._registry
            or current_profile != self._profile
            or current_binding != self._binding
        ):
            raise ProfileRealE2EError(
                "Profile real-E2E installation registry changed after issuance"
            )
        record = self._record
        if record is None:
            return
        body = record.body
        expected = {
            "registry_id": self._registry["registry_id"],
            "registry_digest": self._registry["registry_digest"],
            "profile_id": self._profile["profile_id"],
            "profile_version": self._profile["profile_version"],
            "test_id": self._binding["test_id"],
            "predecessor_id": self._binding["predecessor_id"],
            "toolchain_id": self._registry["toolchain_id"],
            "adapter_id": self._registry["adapter_id"],
            "operation_id": self._registry["operation_id"],
            "command_id": self._registry["command_id"],
            "result": self._binding["result"],
            "journal_state": self._binding["journal_state"],
            "claim_state": self._binding["claim_state"],
            "reconcile_route": self._binding["reconcile_route"],
            "mutation_delta": self._binding["mutation_delta"],
        }
        if (
            any(body.get(field) != value for field, value in expected.items())
            or (body.get("command_result") is not None)
            is not self._binding["command_required"]
        ):
            raise ProfileRealE2EError(
                "Profile real-E2E predecessor installation projection changed"
            )

    @property
    def disposition(self) -> str:
        return str(self._binding["disposition"])

    @property
    def profile_id(self) -> str:
        return str(self._profile["profile_id"])

    @property
    def predecessor_id(self) -> str:
        return str(self._binding["predecessor_id"])

    def _fresh(self) -> GitIdentityObservation:
        value = self._adapter.observe(
            self._target_plan_document, expected=self._expected_target,
        )
        if type(value) is not GitIdentityObservation:
            raise ProfileRealE2EError("Profile real-E2E target observation is invalid")
        return value

    def _action_audit(self, action_id: str) -> dict[str, object]:
        try:
            audit = self._action_repository.concrete_action_audit(action_id)
        except Exception as error:
            raise ProfileRealE2EError(
                "Profile real-E2E durable action evidence is unavailable"
            ) from error
        if type(audit) is not dict:
            raise ProfileRealE2EError("Profile real-E2E action audit is malformed")
        return audit

    def capture_success(
        self,
        *,
        action_id: str,
        action_outcome: object,
        command_request: dict[str, object],
        command_invocation: dict[str, object],
        expected_invocation: ActionInvocation,
    ) -> None:
        if self.disposition != "P" or self._execution is not None:
            raise ProfileRealE2EError("Profile real-E2E execution was already captured")
        from graph_engineering.application.actions import ActionOutcome

        if (
            type(action_outcome) is not ActionOutcome
            or action_outcome.action_id != action_id
            or action_outcome.state != "reconciled"
            or action_outcome.route != self._binding["reconcile_route"]
            or type(expected_invocation) is not ActionInvocation
            or type(command_request) is not dict
            or type(command_invocation) is not dict
        ):
            raise ProfileRealE2EError("Profile real-E2E action result is not approved")
        result = self._launcher.execute(
            command_invocation,
            expected=expected_invocation,
            request_document=command_request,
        )
        if (
            type(result) is not CommandExecutionResult
            or result.outcome != "succeeded"
            or result.failure_class is not None
            or result.reconciliation_required is not False
            or result.output.get("accepted") is not True
        ):
            raise ProfileRealE2EError("Profile real-E2E verifier did not pass")
        audit = self._action_audit(action_id)
        after = self._fresh()
        records = audit.get("records")
        if (
            audit.get("journal_state") != self._binding["journal_state"]
            or audit.get("claim_state") != self._binding["claim_state"]
            or type(records) is not dict
            or set(records) != {"invocation", "receipt", "observation"}
            or self._adapter.mutation_count - self._mutation_baseline
            != self._binding["mutation_delta"]
            or after.head_oid != result.output.get("head_oid")
        ):
            raise ProfileRealE2EError("Profile real-E2E action evidence is incomplete")
        request = CommandExecutionRequest.from_dict(command_request)
        if (
            request.request_digest != result.request_digest
            or expected_invocation.invocation_digest != result.invocation_digest
        ):
            raise ProfileRealE2EError("Profile real-E2E command binding changed")
        self._action_id = action_id
        self._execution = {
            "result": "COMPLETED",
            "journal_state": audit["journal_state"],
            "claim_state": audit["claim_state"],
            "reconcile_route": action_outcome.route,
            "records": records,
            "command_result": result.as_dict(),
            "before": self._before.to_dict(),
            "after": after.to_dict(),
            "mutation_delta": self._adapter.mutation_count - self._mutation_baseline,
        }
        self._cumulative_mutation_count = int(self._execution["mutation_delta"])
        self._adapter_phase_mutation_baseline = self._adapter.mutation_count
        self._cumulative_launch_count = self._launcher.launch_count
        self._launcher_phase_launch_baseline = self._launcher.launch_count

    def capture_stale_rejection(self, *, action_id: str) -> None:
        if self.disposition != "R" or self._execution is not None:
            raise ProfileRealE2EError("Profile real-E2E rejection was already captured")
        audit = self._action_audit(action_id)
        after = self._fresh()
        prepared = self._coordinator._journal.load(action_id).prepared
        expected_oid = prepared.precondition.get("head_oid")
        records = audit.get("records")
        if (
            audit.get("journal_state") != self._binding["journal_state"]
            or audit.get("claim_state") is not None
            or records != {}
            or self._adapter.mutation_count - self._mutation_baseline != 0
            or expected_oid == after.head_oid
        ):
            raise ProfileRealE2EError("stale expected-ref rejection was not zero-mutation")
        self._action_id = action_id
        self._execution = {
            "result": "EXPECTED_REJECTION",
            "journal_state": audit["journal_state"],
            "claim_state": None,
            "reconcile_route": self._binding["reconcile_route"],
            "records": {},
            "command_result": None,
            "before": self._before.to_dict(),
            "after": after.to_dict(),
            "mutation_delta": 0,
        }
        self._cumulative_mutation_count = 0
        self._adapter_phase_mutation_baseline = self._adapter.mutation_count
        self._cumulative_launch_count = self._launcher.launch_count
        self._launcher_phase_launch_baseline = self._launcher.launch_count

    def reattach_current(
        self,
        *,
        coordinator: ActionCoordinator,
        action_repository: TaskRepository,
        adapter: GitNativeAdapter,
        launcher: StructuredCommandLauncher,
        task_application: TaskApplication,
        task_repository: TaskRepository,
        objects: ObjectRepository,
        runtime: RuntimeContext,
    ) -> None:
        """Atomically attach fresh handles to the exact retained root state."""

        record = self._record
        self._require_installation_current()
        self._require_record_identity(record)  # type: ignore[arg-type]
        if (
            type(coordinator) is not ActionCoordinator
            or type(action_repository) is not TaskRepository
            or coordinator._repository is not action_repository
            or type(adapter) is not GitNativeAdapter
            or ActionAdapterFactory.require_attested(adapter) is not adapter
            or type(launcher) is not StructuredCommandLauncher
            or StructuredCommandLauncher.require_attested(launcher) is not launcher
            or type(task_application) is not TaskApplication
            or type(task_repository) is not TaskRepository
            or task_application._repository is not task_repository
            or type(objects) is not ObjectRepository
            or task_application._materialization_objects is not objects
            or type(runtime) is not RuntimeContext
            or record is None
            or self._execution is None
            or self._record_object_digest is None
            or adapter.mutation_count != 0
            or launcher.launch_count != 0
        ):
            raise ProfileRealE2EError(
                "Profile real-E2E reopened authority inputs are foreign"
            )
        runtime.require_issued()
        task_id = str(record.body["task_id"])
        try:
            snapshot = task_application.runtime_show(task_id, runtime).snapshot
            references = task_repository.referenced_objects(task_id)
            body = record.to_bytes()
            audit = action_repository.concrete_action_audit(
                str(record.body["action_id"])
            )
            current = adapter.observe(
                self._target_plan_document, expected=self._expected_target,
            )
        except Exception as error:
            raise ProfileRealE2EError(
                "Profile real-E2E retained root could not be reopened"
            ) from error
        graph_ref = snapshot.graph_ref
        current_pins = {
            "base_graph_digest": graph_ref.get("graph_digest"),
            "profile_digest": graph_ref.get("profile_digest"),
            "overlay_digest": graph_ref.get("overlay_digest"),
            "project_config_digest": graph_ref.get("project_config_digest"),
            "support_matrix_digest": graph_ref.get("support_matrix_digest"),
            "materialization_digest": graph_ref.get("materialization_digest"),
        }
        if (
            snapshot.task_revision not in {
                record.body["task_revision"], int(record.body["task_revision"]) + 1,
            }
            or snapshot.invalidation_epoch != record.body["invalidation_epoch"]
            or current_pins != thaw(record.body["materialization_pins"])
            or objects.get(
                self._record_object_digest, require_referenced=False,
            ) != body
            or tuple(item for item in references if item == (
                self._record_object_digest, body,
            )) != ((self._record_object_digest, body),)
            or audit.get("journal_state") != record.body["journal_state"]
            or audit.get("claim_state") != record.body["claim_state"]
            or audit.get("records") != self._execution["records"]
            or not self._same_current_observation(
                current, self._execution["after"],
            )
            or self._cumulative_mutation_count != record.body["mutation_delta"]
            or self._cumulative_launch_count
            != int(bool(self._binding["command_required"]))
        ):
            raise ProfileRealE2EError(
                "Profile real-E2E retained root is stale or substituted"
            )
        self._coordinator = coordinator
        self._action_repository = action_repository
        self._adapter = adapter
        self._launcher = launcher
        self._task_application = task_application
        self._task_repository = task_repository
        self._objects = objects
        self._runtime = runtime
        self._adapter_phase_mutation_baseline = adapter.mutation_count
        self._launcher_phase_launch_baseline = launcher.launch_count

    def stage_task(self, snapshot: TaskSnapshot) -> ProfileRealE2EPredecessorRecord:
        self._require_installation_current()
        if (
            type(snapshot) is not TaskSnapshot
            or self._execution is None
            or self._action_id is None
            or self._record is not None
            or not snapshot.graph_ref
            or snapshot.lifecycle != "completing"
        ):
            raise ProfileRealE2EError("Profile real-E2E task projection is unavailable")
        graph_ref = snapshot.graph_ref
        pins = {
            "base_graph_digest": graph_ref["graph_digest"],
            "profile_digest": graph_ref["profile_digest"],
            "overlay_digest": graph_ref["overlay_digest"],
            "project_config_digest": graph_ref["project_config_digest"],
            "support_matrix_digest": graph_ref["support_matrix_digest"],
            "materialization_digest": graph_ref["materialization_digest"],
        }
        records = self._execution["records"]
        assert isinstance(records, dict)
        command = self._execution["command_result"]
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "record_kind": "profile-real-e2e-predecessor-v1",
            "registry_id": self._registry["registry_id"],
            "registry_digest": self._registry["registry_digest"],
            "test_id": self._binding["test_id"],
            "predecessor_id": self.predecessor_id,
            "profile_id": self._profile["profile_id"],
            "profile_version": self._profile["profile_version"],
            "task_id": snapshot.identity["task_id"],
            "task_revision": snapshot.task_revision,
            "snapshot_digest": snapshot.snapshot_digest,
            "invalidation_epoch": snapshot.invalidation_epoch,
            "materialization_pins": pins,
            "toolchain_id": self._registry["toolchain_id"],
            "adapter_id": self._registry["adapter_id"],
            "operation_id": self._registry["operation_id"],
            "command_id": self._registry["command_id"],
            "action_id": self._action_id,
            "prepared_action_digest": self._coordinator._journal.load(
                self._action_id
            ).prepared.prepared_action_digest,
            "invocation_digest": (
                None if not records else records["invocation"]["invocation_digest"]
            ),
            "receipt_digest": (
                None if not records else records["receipt"]["receipt_digest"]
            ),
            "action_observation_digest": (
                None if not records else records["observation"]["observation_digest"]
            ),
            "journal_state": self._execution["journal_state"],
            "claim_state": self._execution["claim_state"],
            "reconcile_route": self._execution["reconcile_route"],
            "command_result_digest": (
                None if command is None else command["result_digest"]
            ),
            "command_result": command,
            "before_observation": self._execution["before"],
            "after_observation": self._execution["after"],
            "before_oid": self._execution["before"]["head_oid"],
            "after_oid": self._execution["after"]["head_oid"],
            "mutation_delta": self._execution["mutation_delta"],
            "result": self._execution["result"],
        }
        body["record_digest"] = _semantic(body, "profile-real-e2e-predecessor-record")
        capability = object()
        record = object.__new__(ProfileRealE2EPredecessorRecord)
        frozen_body = freeze(body)
        if not isinstance(frozen_body, FrozenMap):
            raise ProfileRealE2EError("Profile real-E2E record did not freeze")
        object.__setattr__(record, "body", frozen_body)
        object.__setattr__(record, "record_digest", body["record_digest"])
        object.__setattr__(record, "_authority", self)
        object.__setattr__(record, "_capability", capability)
        self.__records[id(record)] = record
        self._record = record
        return record

    def evidence_facts(
        self, record: ProfileRealE2EPredecessorRecord,
    ) -> dict[str, object]:
        self._require_record_identity(record)
        self._require_installation_current()
        body = record.body
        before = body["before_observation"]
        after = body["after_observation"]
        return {
            "predecessor-record-digest": record.record_digest,
            "predecessor-result": body["result"],
            "target-after-digest": after["observation_digest"],
            "target-before-digest": before["observation_digest"],
            "toolchain-id": body["toolchain_id"],
        }

    def issue_observer(self) -> ProfileRealE2EObserver:
        self._require_installation_current()
        if self._execution is None:
            raise ProfileRealE2EError("Profile real-E2E execution is not captured")
        after = self._execution["after"]
        assert isinstance(after, dict)
        command = self._execution["command_result"]
        desired_oid = (
            command["output"]["head_oid"]
            if isinstance(command, dict)
            else self._coordinator._journal.load(self._action_id).prepared.expected_postcondition[
                "head_oid"
            ]
        )
        expected_state = {
            "head_oid": desired_oid,
            "head_ref": after["head_ref"],
            "verifier_result_digest": (
                None if command is None else command["result_digest"]
            ),
        }
        observer = object.__new__(ProfileRealE2EObserver)
        capability = object()
        for name, value in (
            ("target_id", self._expected_target.target_id),
            ("resource_id", "target:project"),
            ("expected_state", expected_state),
            ("rollback_state", expected_state),
            ("_authority", self),
            ("_capability", capability),
        ):
            object.__setattr__(observer, name, value)
        self.__observers[id(observer)] = observer
        return observer

    def activate(
        self,
        *,
        task_application: TaskApplication,
        repository: TaskRepository,
        objects: ObjectRepository,
        runtime: RuntimeContext,
        object_digest: str,
    ) -> None:
        self._require_installation_current()
        if (
            self._record is None
            or type(task_application) is not TaskApplication
            or type(repository) is not TaskRepository
            or type(objects) is not ObjectRepository
            or type(runtime) is not RuntimeContext
            or task_application._repository is not repository
            or task_application._materialization_objects is not objects
        ):
            raise ProfileRealE2EError("Profile real-E2E task authority is foreign")
        body = self._record.to_bytes()
        if objects.digest(body) != object_digest:
            raise ProfileRealE2EError("Profile real-E2E object digest changed")
        references = repository.referenced_objects(str(self._record.body["task_id"]))
        if tuple(item for item in references if item == (object_digest, body)) != (
            (object_digest, body),
        ):
            raise ProfileRealE2EError("Profile real-E2E record is not uniquely referenced")
        self._task_application = task_application
        self._task_repository = repository
        self._objects = objects
        self._runtime = runtime
        self._record_object_digest = object_digest
        self.require_current(expected_task_id=str(self._record.body["task_id"]))

    def _require_record_identity(
        self, record: ProfileRealE2EPredecessorRecord,
    ) -> None:
        if (
            type(record) is not ProfileRealE2EPredecessorRecord
            or record._authority is not self
            or self.__records.get(id(record)) is not record
            or self._record is not record
            or record.body.get("record_digest") != record.record_digest
            or not hmac.compare_digest(
                record.record_digest,
                _semantic(
                    {key: value for key, value in record.body.items() if key != "record_digest"},
                    "profile-real-e2e-predecessor-record",
                ),
            )
        ):
            raise ProfileRealE2EError("Profile real-E2E predecessor is cloned or changed")

    def require_observer(self, observer: ProfileRealE2EObserver) -> None:
        self._require_observer_identity(observer)
        self.require_current(expected_task_id=None)

    def require_installation_current(self) -> None:
        """Revalidate installation bytes without entering repository locks."""

        record = self._record
        self._require_record_identity(record)  # type: ignore[arg-type]
        self._require_installation_current()

    def _require_observer_identity(self, observer: ProfileRealE2EObserver) -> None:
        if (
            type(observer) is not ProfileRealE2EObserver
            or observer._authority is not self
            or self.__observers.get(id(observer)) is not observer
        ):
            raise ProfileRealE2EError("Profile real-E2E observer is cloned or foreign")

    def require_current(
        self,
        *,
        expected_task_id: str | None,
        require_success: bool = False,
    ) -> ProfileRealE2EPredecessorRecord:
        self._require_installation_current()
        record = self._record
        self._require_record_identity(record)  # type: ignore[arg-type]
        if any(
            value is None
            for value in (
                self._task_application, self._task_repository, self._objects,
                self._runtime, self._record_object_digest,
            )
        ):
            raise ProfileRealE2EError("Profile real-E2E record is not activated")
        assert record is not None
        task_id = str(record.body["task_id"])
        if expected_task_id is not None and task_id != expected_task_id:
            raise ProfileRealE2EError("Profile real-E2E task binding is foreign")
        view = self._task_application.runtime_show(task_id, self._runtime)
        snapshot = view.snapshot
        graph_ref = snapshot.graph_ref
        pins = record.body["materialization_pins"]
        current_pins = {
            "base_graph_digest": graph_ref.get("graph_digest"),
            "profile_digest": graph_ref.get("profile_digest"),
            "overlay_digest": graph_ref.get("overlay_digest"),
            "project_config_digest": graph_ref.get("project_config_digest"),
            "support_matrix_digest": graph_ref.get("support_matrix_digest"),
            "materialization_digest": graph_ref.get("materialization_digest"),
        }
        references = self._task_repository.referenced_objects(task_id)
        body = record.to_bytes()
        audit = self._action_audit(str(record.body["action_id"]))
        current = self._fresh()
        if (
            snapshot.task_revision not in {
                record.body["task_revision"], int(record.body["task_revision"]) + 1,
            }
            or snapshot.invalidation_epoch != record.body["invalidation_epoch"]
            or current_pins != thaw(pins)
            or self._objects.get(
                self._record_object_digest, require_referenced=False,
            ) != body
            or tuple(item for item in references if item == (
                self._record_object_digest, body,
            )) != ((self._record_object_digest, body),)
            or audit.get("journal_state") != record.body["journal_state"]
            or audit.get("claim_state") != record.body["claim_state"]
            or audit.get("records") != self._execution["records"]
            or not self._same_current_observation(
                current, record.body["after_observation"],
            )
            or self._adapter.mutation_count
            != self._adapter_phase_mutation_baseline
            or self._launcher.launch_count != self._launcher_phase_launch_baseline
            or self._cumulative_mutation_count != record.body["mutation_delta"]
            or self._cumulative_launch_count
            != int(bool(self._binding["command_required"]))
        ):
            raise ProfileRealE2EError("Profile real-E2E predecessor is stale or substituted")
        if require_success and record.body["result"] != "COMPLETED":
            raise ProfileRealE2EError(str(self._binding["reject_error_message"]))
        self._require_installation_current()
        return record

    def observe(self, observer: ProfileRealE2EObserver) -> dict[str, object]:
        self._require_observer_identity(observer)
        self.require_installation_current()
        record = self._record
        assert record is not None
        current = self._fresh()
        state = {
            "head_oid": current.head_oid,
            "head_ref": current.head_ref,
            "verifier_result_digest": record.body["command_result_digest"],
        }
        metadata = __import__("os").stat(current.worktree_path, follow_symlinks=False)
        result = {
            "schema_version": "1.0.0",
            "execution_kind": observer.execution_kind,
            "target_id": observer.target_id,
            "resource_id": observer.resource_id,
            "fresh": True,
            "observation_revision": current.observation_revision,
            "file_identity": [metadata.st_dev, metadata.st_ino],
            "state": state,
            "state_bytes_sha256": hashlib.sha256(canonical_bytes(state)).hexdigest(),
        }
        self.require_installation_current()
        return result


__all__ = [
    "ProfileRealE2EAuthority",
    "ProfileRealE2EError",
    "ProfileRealE2EObserver",
    "ProfileRealE2EPredecessorRecord",
]
