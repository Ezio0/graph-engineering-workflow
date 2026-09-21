"""Installed authority and evidence factory for ADR-0009 release operations."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import os
import pathlib
import threading
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from weakref import WeakKeyDictionary, WeakSet

from graph_engineering.adapters.local_release_simulator import (
    LocalReleaseSimulatorSession,
    _LocalReleaseSimulatorFactory,
    _RetainedNamespace,
    _RetainedReadOnlyHandle,
    _retained_members,
)
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.schema import validate_instance
from graph_engineering.core.release_operations import (
    RELEASE_OPERATIONS_SCHEMA_IDS,
    ReleaseArtifactManifest,
    ReleaseOperationsError,
    ReleaseOperationsRegistry,
    ReleaseRecoveryBinding,
)


_INSTALLED_RELEASE_FACTORIES: WeakSet[object] = WeakSet()
_COLD_ARTIFACT_INPUTS: WeakKeyDictionary[object, dict[str, bytes]] = WeakKeyDictionary()
_COLD_ARTIFACT_AUTHORITIES: WeakKeyDictionary[object, tuple] = WeakKeyDictionary()
_COLD_INSTALLATION_PLANS: WeakKeyDictionary[object, object] = WeakKeyDictionary()
_COLD_CURRENTNESS_INPUTS: WeakKeyDictionary[object, tuple] = WeakKeyDictionary()
_COLD_CATEGORY_DOCUMENTS: WeakKeyDictionary[object, object] = WeakKeyDictionary()

_RETAINED_NAMESPACES: dict[int, tuple[object, object, object, object, object, object, int, int]] = {}


@dataclass(frozen=True, slots=True, init=False)
class RetainedReleaseNamespace:
    """Runtime-issued namespace authority, never reconstructed from binding data."""

    repository_scope_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        raise TypeError("retained release namespace requires a live runtime issuer")

    def _record(self) -> tuple:
        row = _RETAINED_NAMESPACES.get(id(self))
        if row is None or row[0] is not self or row[-2:] != (os.getpid(), threading.get_ident()):
            raise ReleaseOperationsError("retained release namespace is missing, closed or foreign")
        return row

    def require_current(self, coordinator: object) -> _RetainedNamespace:
        _authority, runtime, expected, scope, native, repository_identity, _pid, _thread = self._record()
        if coordinator is not expected:
            raise ReleaseOperationsError("retained release coordinator is foreign")
        runtime.require_current()
        if coordinator._retained_scope() is not scope:
            raise ReleaseOperationsError("retained release installation scope changed")
        with _RetainedNamespace(scope.repository_root) as repository:
            if repository.identity != repository_identity:
                raise ReleaseOperationsError("retained release repository physical identity changed")
        native._require_current()
        return native

    def close(self) -> None:
        row = self._record()
        row[4].close()
        del _RETAINED_NAMESPACES[id(self)]

    def __enter__(self) -> "RetainedReleaseNamespace":
        self.require_current(self._record()[2])
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _issue_retained_namespace(runtime: object, coordinator: object, path: object) -> RetainedReleaseNamespace:
    from graph_engineering.application.runtime import RuntimeSession
    from graph_engineering.application.actions import ActionCoordinator

    if type(runtime) is not RuntimeSession or type(coordinator) is not ActionCoordinator or not isinstance(path, pathlib.Path):
        raise ReleaseOperationsError("retained release runtime configuration is not exact")
    runtime.require_current()
    scope = coordinator._retained_scope(require_idle=True)
    with _RetainedNamespace(scope.repository_root) as repository:
        identity = dict(repository.identity)
    native = _RetainedNamespace(path)
    try:
        if native.identity == identity:
            raise ReleaseOperationsError("retained namespace cannot be the repository root")
        result = object.__new__(RetainedReleaseNamespace)
        digest = _semantic({"installation_id": scope.installation_id, "repository_id": scope.repository_id,
            "repository_locator_digest": scope.repository_locator_digest, "physical_identity": identity}, "release-repository-scope")
        object.__setattr__(result, "repository_scope_digest", digest)
        _RETAINED_NAMESPACES[id(result)] = (result, runtime, coordinator, scope, native, identity, os.getpid(), threading.get_ident())
        return result
    except BaseException:
        native.close()
        raise


_COLD_ASSESSMENT_HANDLES: dict[int, tuple] = {}


class _ReadOnlyReleaseAssessment:
    """An exact runtime-local reader; historical data cannot issue live evidence."""

    __slots__ = ()

    def __new__(cls, *args, **kwargs):
        raise TypeError("cold assessment handles are factory-issued")

    def _record(self):
        row = _COLD_ASSESSMENT_HANDLES.get(id(self))
        if (row is None or row[0] is not self
                or row[-2:] != (os.getpid(), threading.get_ident())):
            raise ReleaseOperationsError("cold assessment handle is missing, closed or foreign")
        return row

    def query(self) -> Mapping[str, object]:
        return self._record()[1].query()

    def close(self) -> None:
        row = self._record()
        try:
            row[1].close()
        finally:
            _COLD_ASSESSMENT_HANDLES.pop(id(self), None)

    def __copy__(self):
        raise TypeError("cold assessment handles cannot be copied")

    def __deepcopy__(self, memo):
        raise TypeError("cold assessment handles cannot be copied")

    def __reduce_ex__(self, protocol):
        raise TypeError("cold assessment handles cannot be serialized")


def _cold_read_equal(left, right, context, budget, depth=0):
    """Compare the closed JSON/raw-byte capture without serializing raw bodies."""
    context.check_limit("parse_depth", depth, source_id="cold-closure-comparison")
    with budget.reserve(context, units=4, byte_count=0, source_id="cold-closure-comparison"):
        if isinstance(left, Mapping) and isinstance(right, Mapping):
            return len(left) == len(right) and all(
                key in right and _cold_read_equal(value, right[key], context, budget, depth + 1)
                for key, value in left.items())
        if type(left) in (list, tuple) and type(right) in (list, tuple):
            return len(left) == len(right) and all(
                _cold_read_equal(a, b, context, budget, depth + 1) for a, b in zip(left, right))
        if type(left) is bytes and type(right) is bytes:
            context.emit("digest.input_byte", len(left) + len(right),
                         source_id="cold-closure-comparison", operation_path=())
        return type(left) is type(right) and type(left) in (str, bytes, int, bool, type(None)) and left == right


class _ColdReleaseReadScope:
    """Private complete read lifetime, including configuration and both closures."""

    def __init__(self, app, runtime, policy, factory, objects, coordinator, namespace, task_id):
        from graph_engineering.storage.repository import _RecoveryReadBudget

        self.app, self.runtime, self.policy, self.factory = app, runtime, policy, factory
        self.objects, self.coordinator, self.namespace, self.task_id = objects, coordinator, namespace, task_id
        self.repository = app._repository
        self.command_scope = self.repository.command_scope
        self.native = namespace._record()[4]
        self.context = _COLD_ARTIFACT_AUTHORITIES[factory][2]
        self.budget = _RecoveryReadBudget((self.context, app._context, coordinator._policy._context,
            coordinator._journal._context, coordinator._issuer._context),
            task_id=task_id, command_scope=self.command_scope)
        self.ports = (app, self.repository, objects, coordinator, coordinator._journal,
            coordinator._issuer, coordinator._issuer._repository, factory, self.native)
        self.configuration = self.history = self.lease = self.names = self.epoch = None
        self.revision, self.closed, self.handle_id = 0, False, None
        self.identities = None

    def _configuration(self, records):
        from dataclasses import fields
        from graph_engineering.adapters.action_adapters import ActionAdapterFactory
        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.application.runtime import RuntimeSession, RuntimeSessionProof
        from graph_engineering.application.security import SecurityContextIssuer
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.application.tasks import RuntimeContext
        from graph_engineering.core.action_adapters import (
            ActionAdapterRegistry, ActionAdapterRegistryEntry, ConcreteActionPolicy,
        )
        from graph_engineering.core.actions import ActionPolicy, ActionAdapterInstallationAttestation
        from graph_engineering.core.migration import RepositoryCommandContext
        from graph_engineering.core.profile_execution import CategoryExecutionPolicy
        from graph_engineering.core.profiles import MaterializationRecord, _MaterializationRecordIssuer
        from graph_engineering.core.runtime import RuntimeIdentity, OwnerIdentity, RuntimeLineage, CapabilitySet
        from graph_engineering.core.security.attestation import SecurityRuntimeManifest
        from graph_engineering.storage.actions import ActionJournalRepository
        from graph_engineering.storage.connection import BoundDirectory, ConnectionFactory, FilesystemCapability
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.storage.locks import LockedFileRegistry
        from graph_engineering.storage.migration import (
            InstallationCommandScope, InstallationMigrationRepository, MigrationStoragePolicy,
        )
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.policy import RepositoryPolicy
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.security import SecurityStateRepository

        if self.identities is None:
            raise ReleaseOperationsError("cold configuration identity snapshot is absent")

        # The factory reserves the fixed table/tuple/path-cache headers before
        # entering here. Variable payloads are admitted by the same identity DFS
        # as all installation roots, so shared schemas and contexts count once.
        for kind in (RuntimeSessionProof, RuntimeContext, ActionPolicy, ActionAdapterInstallationAttestation,
                     ActionAdapterRegistry, ActionAdapterRegistryEntry, ConcreteActionPolicy,
                     RepositoryCommandContext, CategoryExecutionPolicy, MaterializationRecord,
                     RuntimeIdentity, OwnerIdentity, RuntimeLineage, CapabilitySet,
                     SecurityRuntimeManifest, MigrationStoragePolicy, RepositoryPolicy, FilesystemCapability):
            records[kind] = tuple(field.name for field in fields(kind))
        records[_MaterializationRecordIssuer] = ("_MaterializationRecordIssuer__issued",)
        records[ActionAdapterFactory] = ("_policy", "_registry", "_configuration_digests", "_installation_attestation")
        records[BoundDirectory] = ("_identity", "_parent", "_name", "_path")
        records[pathlib.PosixPath] = ("_raw_paths",)
        # These exact ports are retained only as identity anchors. Their read
        # configuration is enumerated below and in the identity snapshot; no
        # executable callback or unrelated mutable runtime state is traversed.
        for kind in (TaskApplication, TaskRepository, ObjectRepository, ActionCoordinator,
                     ActionJournalRepository, SecurityContextIssuer, SecurityStateRepository,
                     ResourceLeaseRepository, LockedFileRegistry, InstallationCommandScope,
                     InstallationMigrationRepository, ConnectionFactory, RuntimeSession,
                     RetainedReleaseNamespace, _RetainedNamespace):
            records[kind] = ()
        action, issuer, scope = self.coordinator, self.coordinator._issuer, self.command_scope
        runtime_session = self.namespace._record()[1]
        ports = (self.repository, self.objects, action._journal, action._leases, issuer._repository, action._locks)
        connections = tuple(port._factory for port in ports)
        paths = (scope._root, scope._manager._control, self.native.path,
                 self.objects._objects, self.objects._staging,
                 action._locks._root, action._locks._lock_root, action._locks._resource_root,
                 *(connection._root for connection in connections),
                 *(connection._database for connection in connections))
        path_caches = tuple(tuple(getattr(path, field, None) for field in (
            "_raw_paths", "_drv", "_root", "_tail_cached", "_str", "_str_normcase_cached",
            "_parts_normcase_cached")) for path in paths)
        return (self.task_id, self.policy, self.runtime, self.app._schemas, self.app._context,
                action._policy, action._journal._schemas, action._journal._context,
                issuer._schemas, issuer._context, issuer._runtime,
                action._concrete_action_policy, action._concrete_action_registry, action._action_adapter_factory,
                scope._context, scope._manager._policy, self.namespace.repository_scope_digest,
                self.namespace._record()[5], self.native.identity, self.native._path_text, paths, path_caches,
                runtime_session._proof, runtime_session._identity, runtime_session._owner,
                runtime_session._lineage, runtime_session._capabilities,
                tuple((connection._policy, connection._capability, connection._repository_id,
                       connection._directory_identities) for connection in connections),
                self.objects._policy, action._locks._policy,
                self.objects._objects_directory, action._locks._lock_directory,
                action._locks._resource_directory, self.identities)

    def _participant_identities(self):
        from graph_engineering import _SourceInstallationReadPlan, _WheelInstallationReadPlan

        action, scope = self.coordinator, self.command_scope
        namespace = self.namespace._record()
        session, adapter = namespace[1], action._action_adapter_factory
        connections = tuple(port._factory for port in (
            self.repository, self.objects, action._journal, action._leases,
            action._issuer._repository, action._locks))
        directories = (self.objects._objects_directory, action._locks._lock_directory,
                       action._locks._resource_directory)
        plan = _COLD_INSTALLATION_PLANS.get(self.factory)
        currentness = _COLD_CURRENTNESS_INPUTS.get(self.factory)
        # Inspect replaceable containers before expanding them into a fixed
        # table. In particular, a changed tuple must not allocate its contents
        # under the fixed control allowance merely to reject them afterward.
        if (type(currentness) is not tuple or len(currentness) != 2
                or type(plan) not in (_SourceInstallationReadPlan, _WheelInstallationReadPlan)):
            raise ReleaseOperationsError("cold read participants or installed configuration changed")
        roots = (
            self.policy, self.runtime, self.task_id, self.repository._objects,
            self.app._repository, self.app._materialization_objects, self.app._schemas, self.app._context,
            action._repository, action._objects, action._policy, action._journal, action._journal._schemas,
            action._journal._context, action._issuer, action._issuer._repository, action._issuer._schemas,
            action._issuer._context, action._issuer._runtime, action._leases, action._locks,
            action._concrete_action_policy, action._concrete_action_registry, action._action_adapter_factory,
            self.repository.command_scope, scope._context, scope._manager,
            scope._manager._policy, scope._root, scope._manager._control,
            self.factory._bootstrap, self.factory._schemas, self.factory._registry,
            _COLD_ARTIFACT_AUTHORITIES.get(self.factory), plan, currentness, *currentness,
            _COLD_ARTIFACT_INPUTS.get(self.factory), _COLD_CATEGORY_DOCUMENTS.get(self.factory),
            namespace, namespace[4], namespace[5], self.namespace.repository_scope_digest,
            self.native.identity, self.native.path, self.native._path_text,
            session, session._proof, session._identity, session._owner, session._lineage, session._capabilities,
            self.objects._policy, self.objects._objects, self.objects._staging,
            action._locks._policy, action._locks._root, action._locks._lock_root, action._locks._resource_root,
            *(getattr(adapter, name, None) for name in (
                "_policy", "_registry", "_configuration_digests", "_installation_attestation")),
            *(value for connection in connections for value in (
                connection, connection._policy, connection._capability, connection._repository_id,
                connection._directory_identities, connection._root, connection._database)),
            *(value for directory in directories for value in (
                directory, directory._identity, directory._parent, directory._name, directory._path)),
            *(value for context in self.budget.contexts for value in (context.profile, context.schedule)),
            *(getattr(plan, name) for name in (
                ("_source_path", "_control_path", "source_identity", "control_identity", "files", "key", "attestation")
                if type(plan) is _SourceInstallationReadPlan else
                ("_root_path", "archive", "root_identity", "module_origin", "names", "discovery", "members"))),
        )
        # Compare root identities before traversing any replaceable mapping.
        # For a retained reader, reject an expanded map by length before any
        # member snapshot can be allocated. Values below are immutable leaves.
        if self.identities is not None and (len(roots) != len(self.identities[0]) or any(
                value is not expected for value, expected in zip(roots, self.identities[0]))):
            raise ReleaseOperationsError("cold read participants or installed configuration changed")
        maps = (self.factory._schemas, currentness[0], _COLD_ARTIFACT_INPUTS[self.factory],
                namespace[5], self.native.identity,
                *(connection._directory_identities for connection in connections))
        if self.identities is None:
            pairs = sum(len(mapping) for mapping in maps)
            # Snapshot references alias installed data and will join the same
            # configuration adoption. Charge their headers and slots during
            # construction, without copying payloads or allocating ID integers.
            with self.budget.reserve(self.context, units=32 + len(roots) + 8 * len(maps) + 4 * pairs,
                                     byte_count=0,
                                     source_id="cold-configuration-identities") as retained:
                self.identities = (roots, tuple((mapping, tuple(mapping.items())) for mapping in maps))
                retained.transfer(self.identities)
        else:
            for mapping, (identity, members) in zip(maps, self.identities[1]):
                if mapping is not identity or len(mapping) != len(members) or any(
                        key is not old_key or value is not old_value
                        for (key, value), (old_key, old_value) in zip(mapping.items(), members)):
                    raise ReleaseOperationsError("cold read participants or installed configuration changed")

    def _current(self):
        self.budget._require_active()
        if self.closed:
            raise ReleaseOperationsError("cold read participants or installed configuration changed")
        self._participant_identities()
        self.runtime.require_issued()
        if (self.namespace.require_current(self.coordinator) is not self.native
                or self.coordinator._retained_scope(require_idle=True) is not self.command_scope):
            raise ReleaseOperationsError("cold read repository or retained namespace changed")
        session = self.namespace._record()[1]
        if (self.runtime.owner_id, self.runtime.runtime_kind, self.runtime.runtime_lineage_id) != (
                session.proof.owner_id, session.capabilities.runtime_kind, session.proof.lineage_id):
            raise ReleaseOperationsError("cold read runtime and namespace owner differ")

    def _require_category_current(self):
        from graph_engineering.core.contracts.canonical import canonical_byte_length

        installed = _COLD_CATEGORY_DOCUMENTS[self.factory]
        if (installed.get("policy_digest") != self.policy.policy_digest
                or len(installed) != len(self.policy._policy_body) + 1
                or any(key not in installed or not _cold_read_equal(value, installed[key], self.context, self.budget)
                       for key, value in self.policy._policy_body.items())):
            raise ReleaseOperationsError("cold category installation policy changed")
        # These immutable documents are already adopted. Validate one digest at
        # a time with shallow projections, without thaw/freeze copies of the
        # entire installed category and support matrices.
        for document, field, expected, name in (
                (self.policy._policy_body, None, self.policy.policy_digest, "category-execution-policy"),
                (self.policy._profile_document, "digest", self.policy.profile_digest, "profile-definition"),
                (self.policy._support_matrix_document, "digest", self.policy.support_matrix_digest, "support-matrix-definition")):
            size = canonical_byte_length(document) + 512
            with self.budget.reserve(self.context, units=4 * size, byte_count=4 * size,
                                     source_id="cold-category-currentness"):
                if field is not None and document.get(field) != expected:
                    raise ReleaseOperationsError("cold category document digest pin changed")
                value = {key: item for key, item in document.items() if key != field}
                actual = semantic_digest(value, contract_type="urn:gew:contract:" + name,
                    projection_id="urn:gew:digest-projection:" + name + ":1.0.0",
                    schema_id="urn:gew:schema:" + name + "-input:1.0.0")
                self.context.emit("digest.input_byte", size, source_id="cold-category-currentness", operation_path=())
                if actual != expected:
                    raise ReleaseOperationsError("cold category document self digest changed")
                value = None
        size = canonical_byte_length(self.policy.materialization_graph_ref) + canonical_byte_length(
            self.policy.materialization_output) + 512
        with self.budget.reserve(self.context, units=8 * size, byte_count=4 * size,
                                 source_id="cold-materialization-currentness"):
            self.policy.materialization_record.require_issued()

    def _select_locator(self, capture):
        from graph_engineering.storage.repository import _recovery_json
        from graph_engineering.application.profile_execution import _COLD_RELEASE_COLUMN_IDS

        with _recovery_json(capture["assessment_body"], self.context, self.budget,
                            source_id="cold-assessment-selector") as value:
            projection = value.get("release_operations_projection")
            target = projection.get("current_target") if type(projection) is dict else None
            if (value.get("schema_version") != "1.4.0" or value.get("profile_id") != "release-operations"
                    or type(value.get("column_id")) is not str
                    or value.get("column_id") not in _COLD_RELEASE_COLUMN_IDS
                    or value.get("column_id") not in self.policy.column_ids or value.get("status") != "PASS"
                    or value.get("task_id") != self.task_id or type(target) is not dict
                    or projection.get("column_id") != value.get("column_id")
                    or type(target.get("target_id")) is not str or not target["target_id"]
                    or value.get("assessment_digest") != capture["assessment_ref"]["digest"]):
                raise ReleaseOperationsError("cold assessment selector is unsupported or malformed")
            # Return an alias into the already owned raw locator only after
            # separately retaining its parsed string.
            from graph_engineering.storage.repository import _recovery_adopt
            return _recovery_adopt(target["target_id"], self.context, self.budget,
                                   record_fields={}, source_id="cold-target-selector")

    def _read_locator(self):
        return self.repository.read_category_recovery_sources(self.task_id, phase="locator")

    def start(self) -> None:
        from types import MappingProxyType
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.storage.repository import _recovery_clear_exception_frames
        import secrets

        locator = target_id = None
        try:
            with self.budget.bind(ports=self.ports):
                # Fixed control/path transient allowance is retained for the
                # handle lifetime; every variable input is separately admitted.
                with self.budget.reserve(self.context, units=8192, byte_count=8192,
                                         source_id="cold-operation-control") as control:
                    self._participant_identities()
                    # Adoption includes this same snapshot's actual references,
                    # preserving their lifetime and charging every aliased graph.
                    # It cannot establish a new baseline after a replacement.
                    self.configuration = self.factory._adopt_cold_configuration(self.budget, _operation=self)
                    self.budget.release_projection(self.identities)
                    self.epoch = secrets.token_hex(16)
                    control.transfer(self)
                self._current()
                self.factory.require_installed_authority()
                self._require_category_current()
                locator = self._read_locator()
                target_id = self._select_locator(locator)
                self.coordinator._require_retained_idle()
                self.lease = self.native._open_cold_marker(self.task_id, target_id, self.context, self.budget)
                binding = self.lease._cold_binding.projection
                size = canonical_byte_length(self.factory._registry.fixture(binding["fixture_id"]))
                with self.budget.reserve(self.context, units=8 * size, byte_count=4 * size,
                                         source_id="cold-installed-member-selection") as members:
                    names = _retained_members(self.factory._registry.fixture(binding["fixture_id"]))
                    self.lease._admit_cold_members({name: 0o600 for role, name in names.items() if role != "identity"})
                    self.names = MappingProxyType(names)
                    members.transfer(self)
                transfer = [locator]
                locator = None
                # Transfer the sole retained locator into refresh so it can be
                # retired after its first complete capture has been joined.
                self._refresh(locator=transfer.pop())
                self.budget.release_projection(target_id); target_id = None
        except BaseException as error:
            _recovery_clear_exception_frames(error)
            self.close()
            raise
        finally:
            locator = target_id = binding = names = self = None

    def _capture(self):
        from types import MappingProxyType
        from graph_engineering.application.profile_execution import _validate_cold_category_sources
        from graph_engineering.storage.repository import _recovery_json, _recovery_clear_exception_frames

        parts: dict[str, object] | None = None
        result = security = None
        try:
            with self.budget.reserve(self.context, units=64, byte_count=0,
                                     source_id="cold-capture-control") as frame:
                parts = {}
                frame.transfer(parts)
                self._current()
                parts["capture"] = self.repository.read_category_recovery_sources(self.task_id, phase="sources")
                with _recovery_json(parts["capture"]["assessment_body"], self.context, self.budget,
                                    source_id="cold-action-selector") as assessment:
                    from graph_engineering.storage.repository import _recovery_adopt
                    action_id = assessment["release_operations_projection"]["deployment_observation"]["action_id"]
                    action_id = _recovery_adopt(action_id, self.context, self.budget,
                        record_fields={}, source_id="cold-action-id")
                assessment = None
                try:
                    parts["action"] = self.coordinator._read_completed_action_provenance_bounded(self.task_id, action_id)
                finally:
                    self.budget.release_projection(action_id)
                    action_id = None
                security = self.coordinator._issuer.read_task_state(self.task_id)
                parts["security"] = (security.state, security.state_digest, security.runtime_manifest_digest)
                self.budget.move_projection(security, parts["security"]); security = None
                if any(authority["security_state_digest"] != parts["security"][1]
                       or authority["runtime_manifest_digest"] != parts["security"][2]
                       for authority in parts["action"]["authorities"]):
                    raise ReleaseOperationsError("cold action authority and current security capture differ")
                parts["physical"] = self.lease._capture_cold_members()
                self.factory.require_installed_authority()
                self._require_category_current()
                binding = self.lease._cold_binding
                owner = parts["security"][0]["binding"]
                self._validate_binding(owner)
                contracts, schemas, context = _COLD_ARTIFACT_AUTHORITIES[self.factory]
                parts["sources"] = _validate_cold_category_sources(
                    capture=parts["capture"], task_application=self.app, runtime=self.runtime,
                    policy=self.policy, contracts=contracts, schemas=schemas, context=context,
                    action_target={"task_id":self.task_id, "target_id":binding.projection["target_id"],
                        "target_digest":binding.target_digest()},
                    action_baselines=owner["baselines"], action_provenance=parts["action"])
                self._validate_release(parts)
                self._current()
                for value in parts.values():
                    self.budget.move_projection(value, parts)
                result = MappingProxyType(parts)
                self.budget.move_projection(parts, result)
                return result
        except BaseException as error:
            if parts is not None:
                while parts:
                    _key, value = parts.popitem()
                    if id(value) in self.budget._projections:
                        self.budget.release_projection(value)
                    value = None
                if id(parts) in self.budget._projections:
                    self.budget.release_projection(parts)
            _recovery_clear_exception_frames(error)
            raise
        finally:
            self = parts = result = security = assessment = action_id = binding = owner = None
            contracts = schemas = context = value = None

    def _validate_binding(self, owner):
        value = self.lease._cold_binding.projection
        if (value["task_id"] != self.task_id
                or value["repository_scope_digest"] != self.namespace.repository_scope_digest
                or any(self.factory._bootstrap.get(key) != expected
                       for key, expected in value["installation_pins"].items())
                or (owner["task_id"], owner["owner_id"], owner["runtime_kind"], owner["runtime_lineage_id"]) != (
                    self.task_id, self.runtime.owner_id, self.runtime.runtime_kind, self.runtime.runtime_lineage_id)):
            raise ReleaseOperationsError("cold root installation or current owner binding changed")
        matches = [target for target in owner["targets"] if target["target_id"] == value["target_id"]]
        if len(matches) != 1 or matches[0]["target_digest"] != self.lease._cold_binding.target_digest():
            raise ReleaseOperationsError("cold root current security target changed")

    def _validate_release(self, parts):
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.storage.repository import _recovery_clear_exception_frames

        try:
            size = (len(parts["capture"]["assessment_body"])
                    + sum(len(raw[0]) for raw in parts["physical"].values())
                    + canonical_byte_length(self.factory._registry.fixture_registry))
            action_size = canonical_byte_length(parts["action"])
            with self.budget.reserve(self.context, units=8 * size + 2 * action_size,
                                     byte_count=4 * size + 2 * action_size,
                                     source_id="cold-release-validation"):
                _validate_cold_release_projection(self, parts)
        except BaseException as error:
            _recovery_clear_exception_frames(error)
            raise
        finally:
            self = parts = None

    def _refresh(self, *, locator=None):
        from types import MappingProxyType
        from graph_engineering.storage.repository import (
            _recovery_adopt, _recovery_clear_exception_frames, _recovery_record_digest,
        )

        def action_identity(action: Mapping[str, object]) -> tuple[object, ...]:
            # source_digest binds every durable action field. Authority rows
            # are already joined to that journal and these current issuers.
            return (action["task_id"], action["action_id"], action["completion"],
                action["provenance"]["source_digest"], tuple(
                    (authority["action_id"], authority["security_state_digest"], authority["runtime_manifest_digest"])
                    for authority in action["authorities"]))

        captures: list[object] | None = None
        history = source = None
        try:
            with self.budget.reserve(self.context, units=96, byte_count=0,
                                     source_id="cold-complete-captures"):
                captures = []
                try:
                    captures.append(self._capture())
                    if locator is not None and any(not _cold_read_equal(
                            locator[key], captures[0]["capture"][key], self.context, self.budget)
                            for key in ("task", "assessment_ref", "assessment_body")):
                        raise ReleaseOperationsError("cold locator changed after root admission")
                    if locator is not None:
                        self.budget.release_projection(locator)
                        locator = None
                    captures.append(self._capture())
                    if not _cold_read_equal(captures[0], captures[1], self.context, self.budget):
                        raise ReleaseOperationsError("cold complete source or physical closure changed")
                    source = captures[1]
                    references_digest = _recovery_record_digest(
                        {"contract": "cold-category-references-v1", "value": source["capture"]["references"]},
                        self.context, self.budget, source_id="cold-reference-identity")
                    security_identity = source["security"][1:]
                    coverage_identity = _coverage_capture_identity(self, source)
                    if self.history is None:
                        # Double capture equality is complete; retire the first
                        # source before deriving the retained coverage digest.
                        self.budget.release_projection(captures.pop(0))
                        # A separate admission covers only what this reader
                        # retains after both complete captures are discarded.
                        history = MappingProxyType({
                            "coverage_state_digest": _coverage_captured_state_digest(self, source["capture"]),
                            "coverage_source_digest": coverage_identity,
                            "assessment_bytes": source["capture"]["assessment_body"],
                            "assessment": source["sources"]["assessment"],
                            "source_projection": source["sources"],
                            "task": source["capture"]["task"],
                            "references_digest": references_digest,
                            "security_identity": security_identity,
                            "action_identity": action_identity(source["action"]),
                        })
                        self.history = _recovery_adopt(history, self.context, self.budget,
                            record_fields={}, source_id="cold-assessment-history")
                    elif any(not _cold_read_equal(left, right, self.context, self.budget) for left, right in (
                            (self.history["coverage_source_digest"], coverage_identity),
                            (self.history["assessment_bytes"], source["capture"]["assessment_body"]),
                            (self.history["task"], source["capture"]["task"]),
                            (self.history["references_digest"], references_digest),
                            (self.history["source_projection"], source["sources"]),
                            (self.history["security_identity"], security_identity),
                            (self.history["action_identity"], action_identity(source["action"])) )):
                        raise ReleaseOperationsError("cold assessment sources changed since issuance")
                    self.revision += 1
                finally:
                    source = history = None
                    while captures:
                        self.budget.release_projection(captures.pop())
        except BaseException as error:
            _recovery_clear_exception_frames(error)
            raise
        finally:
            if locator is not None:
                self.budget.release_projection(locator)
                locator = None
            self = captures = history = source = locator = references_digest = security_identity = None

    def query(self) -> Mapping[str, object]:
        from types import MappingProxyType
        from graph_engineering.storage.repository import _recovery_clear_exception_frames

        try:
            if self.closed:
                raise ReleaseOperationsError("cold assessment handle is closed")
            with self.budget.bind(ports=self.ports):
                self._refresh()
                return MappingProxyType({"assessment_bytes": self.history["assessment_bytes"],
                    "assessment": self.history["assessment"], "source_projection": self.history["source_projection"],
                    "observation_epoch": self.epoch, "observation_revision": self.revision})
        except BaseException as error:
            self.close()
            _recovery_clear_exception_frames(error)
            raise
        finally:
            self = None

    def close(self) -> None:
        if self.closed:
            return
        self.budget._require_owner()
        if self.budget._active:
            raise ReleaseOperationsError("cold read cannot close while an operation is active")
        try:
            if self.lease is not None:
                self.lease.close()
        finally:
            self.closed = True
            self.lease = self.history = self.configuration = self.names = self.identities = self.epoch = None
            self.ports = ()
            self.app = self.runtime = self.policy = self.factory = self.objects = self.coordinator = None
            self.namespace = self.repository = self.command_scope = self.native = self.context = self.task_id = None
            if self.handle_id is not None:
                _COLD_ASSESSMENT_HANDLES.pop(self.handle_id, None)
            self.budget.close()


def restore_current_release_assessment(*, task_application: object, runtime: object, policy: object, release_factory: ReleaseOperationsRegistryFactory,
                                      object_repository: object, action_coordinator: object, retained_namespace: RetainedReleaseNamespace, task_id: str) -> _ReadOnlyReleaseAssessment:
    """Restore current historical data with no live evidence or mutation authority."""
    from graph_engineering.application.actions import ActionCoordinator
    from graph_engineering.application.tasks import TaskApplication, RuntimeContext
    from graph_engineering.core.profile_execution import CategoryExecutionPolicy
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository, _recovery_clear_exception_frames

    scope = handle = None
    try:
        if (type(task_application) is not TaskApplication or type(runtime) is not RuntimeContext
                or type(policy) is not CategoryExecutionPolicy or type(release_factory) is not ReleaseOperationsRegistryFactory
                or release_factory not in _INSTALLED_RELEASE_FACTORIES
                or release_factory not in _COLD_ARTIFACT_AUTHORITIES
                or type(object_repository) is not ObjectRepository or type(action_coordinator) is not ActionCoordinator
                or type(retained_namespace) is not RetainedReleaseNamespace or type(task_id) is not str or not task_id
                or type(task_application._repository) is not TaskRepository
                or task_application._repository is not action_coordinator._repository
                or task_application._materialization_objects is not object_repository
                or action_coordinator._objects is not object_repository
                or task_application._repository._objects is not object_repository):
            raise ReleaseOperationsError("cold assessment requires exact current installed participants")
        scope = _ColdReleaseReadScope(task_application, runtime, policy, release_factory,
            object_repository, action_coordinator, retained_namespace, task_id)
        scope.start()
        handle = object.__new__(_ReadOnlyReleaseAssessment)
        scope.handle_id = id(handle)
        _COLD_ASSESSMENT_HANDLES[id(handle)] = (handle, scope, os.getpid(), threading.get_ident())
        return handle
    except BaseException as error:
        if scope is not None:
            scope.close()
        _recovery_clear_exception_frames(error)
        raise
    finally:
        task_application = runtime = policy = release_factory = object_repository = None
        action_coordinator = retained_namespace = scope = handle = None
        task_id: str | None = None


def _coverage_captured_state_digest(scope, capture):
    from graph_engineering.core.contracts.canonical import canonical_byte_length
    from graph_engineering.core.profile_coverage import profile_coverage_digest
    size = canonical_byte_length(capture["snapshot"]) + canonical_byte_length(capture["events"]) + 512 * len(capture["references"]) + 1024
    # Semantic replay was already validated by the owner. Alias its immutable
    # inputs rather than reconstructing another complete TaskView.
    with scope.budget.reserve(scope.context, units=6 * size, byte_count=4 * size, source_id="coverage-captured-state"):
        body = {"schema_version": "1.0.0", "task_id": scope.task_id,
            "snapshot": capture["snapshot"]["domain"], "runner": capture["snapshot"]["runner"],
            "events": [row["event"] for row in capture["events"]],
            "object_references": [{"digest": ref, "bytes_sha256": hashlib.sha256(raw).hexdigest()}
                for ref, raw in capture["objects"]]}
        scope.context.emit("digest.input_byte", sum(len(raw) for _ref, raw in capture["objects"]) + size,
            source_id="coverage-captured-state", operation_path=())
        return profile_coverage_digest(body, contract="profile-coverage-task-state", schema="profile-coverage-task-state")


def _coverage_capture_identity(scope, source):
    from graph_engineering.storage.repository import _recovery_record_digest
    with scope.budget.reserve(scope.context, units=1024 + 512 * len(source["physical"]),
            byte_count=1024 + 512 * len(source["physical"]), source_id="coverage-source-fingerprint"):
        physical = {}
        for name, (raw, metadata) in source["physical"].items():
            scope.context.emit("digest.input_byte", len(raw), source_id="coverage-source-fingerprint", operation_path=())
            physical[name] = {"raw_sha256": hashlib.sha256(raw).hexdigest(), "metadata": tuple(str(value) for value in metadata)}
        return _recovery_record_digest({"contract": "release-coverage-source-v1",
            "task": source["capture"]["task"], "references": source["capture"]["references"],
            "security": source["security"][1:], "action": (source["action"]["provenance"]["source_digest"]
                if "provenance" in source["action"] else source["action"]), "physical": physical},
            scope.context, scope.budget, source_id="coverage-source-fingerprint")


class _RejectedReleaseReadScope(_ColdReleaseReadScope):
    """Bounded historical validation for an existing opaque R execution only."""

    def _configuration(self, records):
        return (super()._configuration(records), self.target_id, self.action_id,
            self.expected_state_digest, self.pending_digests, self.expected_tree_digest)

    def _read_locator(self):
        from graph_engineering.storage.repository import _recovery_adopt
        return _recovery_adopt({"task_id": self.task_id, "target_id": self.target_id},
            self.context, self.budget, record_fields={}, source_id="rejected-release-locator")

    def _select_locator(self, capture):
        from graph_engineering.storage.repository import _recovery_adopt
        if capture != {"task_id": self.task_id, "target_id": self.target_id}:
            raise ReleaseOperationsError("rejected release locator changed")
        return _recovery_adopt(self.target_id, self.context, self.budget,
            record_fields={}, source_id="rejected-release-target")

    def _capture(self):
        from types import MappingProxyType
        from graph_engineering.storage.repository import _recovery_json, _recovery_clear_exception_frames
        parts: dict[str, object] | None = None
        security = result = None
        try:
            with self.budget.reserve(self.context, units=64, byte_count=0,
                    source_id="rejected-capture-control") as frame:
                parts = {}
                frame.transfer(parts)
                self._current()
                parts["capture"] = self.repository._read_release_rejection_sources(self.task_id)
                with self.app._cold_task_view(parts["capture"], policy=self.policy, runtime=self.runtime):
                    pass
                if _coverage_captured_state_digest(self, parts["capture"]) != self.expected_state_digest:
                    raise ReleaseOperationsError("rejected release source changed")
                security = self.coordinator._issuer.read_task_state(self.task_id)
                parts["security"] = (security.state, security.state_digest, security.runtime_manifest_digest)
                self.budget.move_projection(security, parts["security"])
                if self.pending_digests is None:
                    parts["action"] = self.coordinator._read_completed_action_provenance_bounded(self.task_id, self.action_id)
                    if any(item["security_state_digest"] != parts["security"][1]
                            or item["runtime_manifest_digest"] != parts["security"][2]
                            for item in parts["action"]["authorities"]):
                        raise ReleaseOperationsError("rejected release action security differs")
                else:
                    parts["action"] = self.repository._read_release_rejected_action_source(self.task_id, self.action_id)
                    row = parts["action"]["journal"][0]
                    if (row[5], row[7]) != self.pending_digests:
                        raise ReleaseOperationsError("rejected predecessor identity changed")
                    with _recovery_json(row[4], self.context, self.budget, source_id="rejected-prepared") as prepared, \
                            _recovery_json(row[6], self.context, self.budget, source_id="rejected-authority") as authority:
                        from graph_engineering.core.contracts.canonical import canonical_byte_length
                        size = canonical_byte_length(prepared) + canonical_byte_length(authority)
                        with self.budget.reserve(self.context, units=12 * size, byte_count=8 * size,
                                source_id="rejected-action-validation"):
                            p = self.coordinator._policy.load_prepared(prepared)
                            a = self.coordinator._policy.load_authority(authority)
                            owner = security.state["binding"]
                            if (p.action_id != self.action_id or p.task_id != self.task_id
                                    or a.prepared_action_digest != p.prepared_action_digest
                                    or a.task_id != self.task_id or a.authority_digest not in security.state["authority_digests"]
                                    or (a.owner_id, a.runtime_kind, a.runtime_lineage_id) !=
                                       (self.runtime.owner_id, self.runtime.runtime_kind, self.runtime.runtime_lineage_id)
                                    or p.baseline_digest != owner["baselines"].get("intent")
                                    or p.target_digest != self.lease._cold_binding.target_digest()):
                                raise ReleaseOperationsError("rejected action authority differs from current owner")
                            p = a = owner = None
                        prepared = authority = None
                parts["physical"] = self.lease._capture_cold_members()
                from graph_engineering.core.contracts.canonical import canonical_bytes
                import stat
                with self.budget.reserve(self.context, units=1024 + 512 * len(parts["physical"]),
                        byte_count=1024 + 512 * len(parts["physical"]), source_id="rejected-tree-identity"):
                    rows = [(name, stat.S_IMODE(metadata[2]), hashlib.sha256(raw).hexdigest())
                        for name, (raw, metadata) in sorted(parts["physical"].items())]
                    self.context.emit("digest.input_byte", sum(len(raw[0]) for raw in parts["physical"].values()),
                        source_id="rejected-tree-identity", operation_path=())
                    if hashlib.sha256(canonical_bytes(rows)).hexdigest() != self.expected_tree_digest:
                        raise ReleaseOperationsError("rejected release physical state differs from issued execution")
                    rows = None
                self._validate_binding(parts["security"][0]["binding"])
                self.factory.require_installed_authority()
                self._require_category_current()
                self._current()
                for value in parts.values():
                    self.budget.move_projection(value, parts)
                result = MappingProxyType(parts)
                self.budget.move_projection(parts, result)
                return result
        except BaseException as error:
            if parts is not None:
                while parts:
                    _key, value = parts.popitem()
                    if id(value) in self.budget._projections:
                        self.budget.release_projection(value)
                    value = None
                if id(parts) in self.budget._projections:
                    self.budget.release_projection(parts)
            _recovery_clear_exception_frames(error)
            raise
        finally:
            self = parts = security = result = value = row = prepared = authority = p = a = owner = None

    def _refresh(self, *, locator=None):
        from graph_engineering.storage.repository import _recovery_adopt
        first = second = None
        try:
            if locator is not None:
                self.budget.release_projection(locator)
                locator = None
            first = self._capture()
            second = self._capture()
            if not _cold_read_equal(first, second, self.context, self.budget):
                raise ReleaseOperationsError("rejected release closure changed between captures")
            identity = _coverage_capture_identity(self, second)
            if self.history is None:
                self.history = _recovery_adopt({"coverage_state_digest": self.expected_state_digest,
                    "coverage_source_digest": identity}, self.context, self.budget,
                    record_fields={}, source_id="rejected-release-history")
            elif identity != self.history["coverage_source_digest"]:
                raise ReleaseOperationsError("rejected release closure changed since issuance")
            self.revision += 1
        finally:
            for capture in (second, first):
                if capture is not None:
                    self.budget.release_projection(capture)

    def query(self) -> Mapping[str, object]:
        try:
            with self.budget.bind(ports=self.ports):
                self._refresh()
                return dict(self.history)
        except BaseException:
            self.close()
            raise


def _open_release_rejection_reader(*, app, runtime, policy, factory, objects, coordinator,
        namespace, task_id, target_id, action_id, expected_state_digest, pending_digests, expected_tree_digest):
    factory._cold_artifact_authority()
    scope = _RejectedReleaseReadScope(app, runtime, policy, factory, objects, coordinator, namespace, task_id)
    scope.target_id, scope.action_id = target_id, action_id
    scope.expected_state_digest, scope.pending_digests = expected_state_digest, pending_digests
    scope.expected_tree_digest = expected_tree_digest
    try:
        scope.start()
        return scope
    except BaseException:
        scope.close()
        raise


def _validate_cold_release_projection(scope, parts):
    """Pure joins of owned physical, category, action and current security facts."""
    from graph_engineering.core.contracts.strict_json import parse_json
    from graph_engineering.core.release_operations import evaluate_health

    factory, registry = scope.factory, scope.factory._registry
    context, budget = scope.context, scope.budget
    same = lambda a, b: _cold_read_equal(a, b, context, budget)
    assessment = thaw(parts["sources"]["assessment"])
    projection = assessment["release_operations_projection"]
    if type(projection) is not dict or set(projection) != set(_PROJECTION_FIELDS):
        raise ReleaseOperationsError("cold release projection is not exact")
    factory._validate_document("urn:gew:schema:release-operations-observation:1.0.0", projection)
    if projection["observation_digest"] != _semantic(
            {key: value for key, value in projection.items() if key != "observation_digest"},
            "release-operations-observation"):
        raise ReleaseOperationsError("cold release projection digest changed")
    factory._require_nested_projection(projection)
    binding = scope.lease._cold_binding.projection
    fixture = registry.fixture(binding["fixture_id"])
    if any(not same(projection[field], assessment[field]) for field in (
            "task_id", "task_revision", "snapshot_digest", "invalidation_epoch", "profile_id",
            "profile_version", "column_id", "scenario_id")):
        raise ReleaseOperationsError("cold release and assessment identities differ")
    if (not same(projection["graph_ref_pins"], assessment["materialization_pins"])
            or not same(projection["installation_pins"], binding["installation_pins"])
            or projection["evidence_kind"] != registry.policy["artifact_policy"]["allowed_evidence_kind"]):
        raise ReleaseOperationsError("cold release graph or installation binding changed")

    physical = parts["physical"]
    names = scope.names
    def body(role: str) -> bytes:
        if names[role] not in physical:
            raise ReleaseOperationsError("cold release required physical member is absent")
        return physical[names[role]][0]
    def document(role: str) -> object:
        return parse_json(body(role), context=context, source_id="cold-physical-" + role)
    def manifest(value: Mapping[str, object], raw: bytes) -> ReleaseArtifactManifest:
        parsed = ReleaseArtifactManifest.from_dict(value)
        vector = registry.fixture_artifact(binding["fixture_id"], parsed.artifact_id)
        record_digest = _semantic({"schema_version":"1.0.0", "fixture_id":binding["fixture_id"],
            "artifact":dict(vector)}, "release-fixture-artifact-record")
        source_digest = _semantic({"schema_version":"1.0.0", "fixture_id":binding["fixture_id"],
            "fixture_registry_id":factory._bootstrap["fixture_registry_id"],
            "fixture_registry_digest":factory._bootstrap["fixture_registry_digest"]}, "release-fixture-source-manifest")
        build_digest = _semantic({"schema_version":"1.0.0",
            "attestation_kind":"installed-deterministic-release-fixture",
            "fixture_registry_digest":factory._bootstrap["fixture_registry_digest"],
            "artifact_record_digest":record_digest, "source_manifest_digest":source_digest,
            "protected_closure_digest":factory._bootstrap["protected_closure_digest"]}, "release-fixture-build-attestation")
        if (type(raw) is not bytes or len(raw) != parsed.size or _raw(raw) != parsed.raw_sha256
                or base64.b64encode(raw).decode("ascii") != vector["artifact_base64"]
                or parsed.artifact_version != vector["artifact_version"]
                or parsed.artifact_path != "artifacts/" + parsed.artifact_id + ".bin"
                or parsed.distribution_name != vector["distribution_name"]
                or parsed.distribution_version != vector["distribution_version"]
                or parsed.record_digest != record_digest or parsed.source_manifest_digest != source_digest
                or parsed.build_attestation_digest != build_digest
                or parsed.protected_closure_digest != factory._bootstrap["protected_closure_digest"]):
            raise ReleaseOperationsError("cold release artifact bytes or installed provenance changed")
        return parsed

    state = document("state")
    active = manifest(document("active"), body("active_artifact"))
    state_fields = ("schema_version", "generation", "active_artifact_digest", "staged_artifact_digest")
    if (type(state) is not dict or tuple(state) != state_fields or state["schema_version"] != "1.0.0"
            or type(state["generation"]) is not int or state["generation"] < 0
            or state["generation"] > registry.policy["deployment_policy"]["generation_limit"]
            or state["active_artifact_digest"] != active.manifest_digest):
        raise ReleaseOperationsError("cold release state pointer or generation changed")
    staged = names["stage"] in physical
    if staged != (names["stage_artifact"] in physical):
        raise ReleaseOperationsError("cold release staged manifest and bytes differ")
    if staged:
        stage = manifest(document("stage"), body("stage_artifact"))
        if state["staged_artifact_digest"] != stage.manifest_digest:
            raise ReleaseOperationsError("cold release staged pointer changed")
    elif state["staged_artifact_digest"] is not None:
        raise ReleaseOperationsError("cold release staged pointer is dangling")
    current_state = {key: state[key] for key in state_fields[1:]}
    current_target = projection["current_target"]
    target_contract = parts["sources"]["target"]
    if (set(current_target) != {"target_id", "target_digest", "resource_id", "fresh", "observation_revision", "state"}
            or any(current_target[key] != binding[key] for key in ("target_id", "resource_id"))
            or current_target["target_digest"] != scope.lease._cold_binding.target_digest()
            or current_target["fresh"] is not True or type(current_target["observation_revision"]) is not int
            or current_target["observation_revision"] < 1 or not same(current_target["state"], current_state)
            or target_contract["target_id"] != binding["target_id"] or target_contract["resource_id"] != binding["resource_id"]
            or not same(target_contract["rollback_state" if assessment["column_id"] == "rollback" else "expected_state"], state)):
        raise ReleaseOperationsError("cold release current physical target differs from committed contract")

    action = parts["action"]
    provenance = action["provenance"]
    journals = {journal["action_id"]: journal for journal in provenance["journals"]}
    deployment, rollback = projection["deployment_observation"], projection["rollback_observation"]
    original = journals[deployment["action_id"]]
    prepared = original["prepared"]
    recovery = provenance["recovery"]
    partial = recovery is not None
    if assessment["column_id"] in {"recovery", "rollback"} and not partial:
        raise ReleaseOperationsError("cold release action column requires completed compensation")
    if (action["action_id"] != deployment["action_id"] or projection["claim_id"] != provenance["claim"]["claim_id"]
            or projection["receipt_digest"] != deployment["receipt_digest"]
            or prepared["action_kind"] != "deploy"
            or prepared["payload"]["operation_id"] != registry.operation_roles["apply"]
            or not same(prepared["payload"]["artifact_manifest"], projection["artifact_manifest"])):
        raise ReleaseOperationsError("cold release original deployment action changed")
    candidate = manifest(projection["artifact_manifest"],
        base64.b64decode(prepared["payload"]["artifact_bytes_base64"], validate=True))
    baseline_vector = registry.fixture_artifact(binding["fixture_id"], fixture["expected_rollback_artifact_id"])
    baseline_digest = prepared["precondition"]["active_artifact_digest"]
    baseline_bytes = base64.b64decode(baseline_vector["artifact_base64"], validate=True)
    baseline_record = _semantic({"schema_version":"1.0.0", "fixture_id":binding["fixture_id"],
        "artifact":dict(baseline_vector)}, "release-fixture-artifact-record")
    baseline_source = _semantic({"schema_version":"1.0.0", "fixture_id":binding["fixture_id"],
        "fixture_registry_id":factory._bootstrap["fixture_registry_id"],
        "fixture_registry_digest":factory._bootstrap["fixture_registry_digest"]}, "release-fixture-source-manifest")
    expected_baseline = {"schema_version":"1.0.0", "artifact_id":baseline_vector["artifact_id"],
        "artifact_version":baseline_vector["artifact_version"],
        "artifact_path":"artifacts/" + baseline_vector["artifact_id"] + ".bin",
        "raw_sha256":_raw(baseline_bytes), "size":len(baseline_bytes),
        "distribution_name":baseline_vector["distribution_name"], "distribution_version":baseline_vector["distribution_version"],
        "record_digest":baseline_record, "source_manifest_digest":baseline_source,
        "build_attestation_digest":_semantic({"schema_version":"1.0.0",
            "attestation_kind":"installed-deterministic-release-fixture",
            "fixture_registry_digest":factory._bootstrap["fixture_registry_digest"],
            "artifact_record_digest":baseline_record, "source_manifest_digest":baseline_source,
            "protected_closure_digest":factory._bootstrap["protected_closure_digest"]}, "release-fixture-build-attestation"),
        "protected_closure_digest":factory._bootstrap["protected_closure_digest"]}
    expected_baseline["provenance_digest"] = _semantic(expected_baseline, "release-artifact-provenance")
    if baseline_digest != _semantic(expected_baseline, "release-artifact-manifest"):
        raise ReleaseOperationsError("cold release original baseline is not the installed artifact")
    before = {"generation":0, "active_artifact_digest":baseline_digest, "staged_artifact_digest":None}
    staged_state = {**before, "staged_artifact_digest":candidate.manifest_digest}
    applied = {"generation":1, "active_artifact_digest":candidate.manifest_digest,
               "staged_artifact_digest":candidate.manifest_digest}
    if (candidate.artifact_id == baseline_vector["artifact_id"] or not same(prepared["precondition"], before)
            or not same(prepared["expected_postcondition"], applied)):
        raise ReleaseOperationsError("cold release baseline or apply postcondition changed")
    if partial:
        if rollback is None or rollback["action_id"] != recovery["compensation_action_id"]:
            raise ReleaseOperationsError("cold release compensation observation is absent or foreign")
        restore = journals[rollback["action_id"]]
        restored = restore["prepared"]
        payload = restored["payload"]
        baseline = manifest(payload["artifact_manifest"], base64.b64decode(payload["artifact_bytes_base64"], validate=True))
        if (baseline.artifact_id != baseline_vector["artifact_id"] or baseline.manifest_digest != baseline_digest
                or restored["action_kind"] != "rollback" or payload["operation_id"] != registry.operation_roles["restore"]
                or payload["original_claim_id"] != deployment["claim_id"]
                or payload["original_receipt_digest"] != deployment["receipt_digest"]
                or not same(restored["precondition"], staged_state) or not same(restored["expected_postcondition"], before)
                or action["completion"] != "compensation_reconciled" or not same(current_state, before)
                or projection["owner_route"] != registry.policy["rollback_policy"]["owner_route"]):
            raise ReleaseOperationsError("cold release partial compensation chain changed")
    elif (rollback is not None or action["completion"] != "reconciled_effect_verified"
          or not same(current_state, applied) or projection["owner_route"] != "reconciled-effect-verified"):
        raise ReleaseOperationsError("cold release normal completed action changed")
    scenarios = [row for row in registry.policy["scenarios"]
        if projection["scenario_id"] == "GEW-PSC-RELEASE-OPERATIONS-" + row["scenario_id"].upper() + "-P"]
    if (len(scenarios) != 1 or (scenarios[0]["scenario_id"] == "partial-deploy") is not partial
            or projection["outcome"] != scenarios[0]["success_outcome"]):
        raise ReleaseOperationsError("cold release scenario outcome changed")

    def state_digest(value: Mapping[str, object], name: str="release-local-target-state") -> str:
        return _semantic({"schema_version":"1.0.0", **dict(value)}, name)
    def phase(role: str, value: Mapping[str, object]) -> dict[str, object]:
        return {"phase_id":registry.phase_roles[role], "generation":value["generation"],
                "state_digest":state_digest(value, "local-release-simulator-result")}
    base_phases = [phase("baseline", before), phase("staged", staged_state)]
    for observation, journal, prior, after, route, expected_phases in (
            (deployment, original, before, staged_state if partial else applied,
             "manual-reconciliation" if partial else "reconciled-effect-verified",
             base_phases if partial else [*base_phases, phase("active", applied)]),
            *(([(rollback, restore, staged_state, before, "compensation-reconciled",
                  [*base_phases, phase("restored", before)])]) if partial else [])):
        payload = journal["prepared"]["payload"]
        if (observation["claim_id"] != provenance["claim"]["claim_id"]
                or observation["prepared_action_digest"] != journal["prepared_digest"]
                or observation["authority_digest"] != journal["authority_digest"]
                or observation["receipt_digest"] != journal["receipt"]["receipt_digest"]
                or observation["expected_generation"] != payload["expected_generation"]
                or type(observation["expected_generation"]) is not int
                or observation["current_generation"] != after["generation"]
                or type(observation["current_generation"]) is not int
                or observation["artifact_manifest_digest"] != payload["artifact_manifest"]["manifest_digest"]
                or observation["before_target_digest"] != state_digest(prior)
                or observation["after_target_digest"] != state_digest(after)
                or observation["reconciliation_state"] != route
                or journal["prepared"]["target_id"] != binding["target_id"]
                or journal["prepared"]["target_digest"] != scope.lease._cold_binding.target_digest()
                or tuple(journal["prepared"]["resources"]) != tuple(sorted(("task:" + scope.task_id, binding["resource_id"])))
                or not same(observation["phase_transitions"], expected_phases)):
            raise ReleaseOperationsError("cold release deployment phase or durable action binding changed")
        if partial:
            if observation["fault_point"] not in (registry.fault_roles["after_stage_durable"], registry.fault_roles["before_active_switch"]):
                raise ReleaseOperationsError("cold release partial fault history changed")
        elif observation["fault_point"] is not None:
            raise ReleaseOperationsError("cold release normal fault history changed")
    terminal = rollback if partial else deployment
    roles = registry.predicate_roles
    values = {roles["artifact_current"]:state["active_artifact_digest"] == terminal["artifact_manifest_digest"],
              roles["generation_current"]:state["generation"] == terminal["current_generation"]}
    values[roles["service_ready"]] = all(values.values())
    results, outcome = evaluate_health(registry, values)
    health = {"schema_version":"1.0.0", "task_id":scope.task_id, "target_id":binding["target_id"],
        "generation":state["generation"], "policy_digest":registry.policy["registry_digest"],
        "active_artifact_digest":state["active_artifact_digest"], "state_raw_sha256":_raw(body("state")),
        "predicate_results":list(results), "outcome":outcome}
    health["observation_digest"] = _semantic(health, "release-health-observation")
    if not same(health, projection["health_observation"]) or outcome != registry.health_outcomes["healthy"]:
        raise ReleaseOperationsError("cold release physical health changed")


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ReleaseOperationsError(f"{label} has a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseOperationsError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise ReleaseOperationsError(f"{label} root is not an object")
    return value


def _raw(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _semantic(value: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        freeze(value),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


_BOOTSTRAP_FIELDS = (
    "schema_version", "bootstrap_id", "policy_registry_id",
    "policy_registry_digest", "policy_registry_raw_sha256", "fixture_registry_id",
    "fixture_registry_digest", "fixture_registry_raw_sha256",
    "profile_schema_registry_id", "profile_schema_registry_digest",
    "profile_schema_registry_raw_sha256", "schema_vectors",
    "action_authority_pins", "source_authority_pins", "package_authority_pins",
    "protected_resources", "protected_closure_digest", "bootstrap_digest",
)


def _verify_bootstrap(
    bootstrap: Mapping[str, object],
    *,
    policy_bytes: bytes,
    fixture_bytes: bytes,
    profile_schema_registry_bytes: bytes,
    package_provenance_bytes: bytes,
    schema_bodies: Mapping[str, bytes],
    protected_resources: Mapping[str, bytes],
) -> None:
    if type(bootstrap) is not dict or tuple(bootstrap) != _BOOTSTRAP_FIELDS:
        raise ReleaseOperationsError("release bootstrap fields/order are not exact")
    policy = _strict_json(policy_bytes, "release policy registry")
    fixture = _strict_json(fixture_bytes, "release fixture registry")
    profile = _strict_json(profile_schema_registry_bytes, "Profile schema registry")
    if (
        bootstrap["schema_version"] != "1.0.0"
        or bootstrap["policy_registry_id"] != policy.get("registry_id")
        or bootstrap["policy_registry_digest"] != policy.get("registry_digest")
        or bootstrap["policy_registry_raw_sha256"] != _raw(policy_bytes)
        or bootstrap["fixture_registry_id"] != fixture.get("registry_id")
        or bootstrap["fixture_registry_digest"] != fixture.get("registry_digest")
        or bootstrap["fixture_registry_raw_sha256"] != _raw(fixture_bytes)
        or bootstrap["profile_schema_registry_id"] != profile.get("registry_id")
        or bootstrap["profile_schema_registry_digest"] != profile.get("registry_digest")
        or bootstrap["profile_schema_registry_raw_sha256"]
        != _raw(profile_schema_registry_bytes)
    ):
        raise ReleaseOperationsError("release bootstrap registry pins changed")
    vectors = bootstrap["schema_vectors"]
    if type(vectors) is not list or tuple(
        row.get("schema_id") for row in vectors if type(row) is dict
    ) != RELEASE_OPERATIONS_SCHEMA_IDS:
        raise ReleaseOperationsError("release bootstrap schema closure changed")
    for row in vectors:
        if type(row) is not dict or tuple(row) != ("schema_id", "raw_sha256"):
            raise ReleaseOperationsError("release bootstrap schema vector is not exact")
        body = schema_bodies.get(str(row["schema_id"]))
        if body is None or row["raw_sha256"] != _raw(body):
            raise ReleaseOperationsError("release bootstrap schema bytes changed")
    resources = bootstrap["protected_resources"]
    expected_paths = tuple(sorted(protected_resources))
    if type(resources) is not list or tuple(
        row.get("path") for row in resources if type(row) is dict
    ) != expected_paths:
        raise ReleaseOperationsError("release protected resource closure changed")
    closure_rows: list[dict[str, object]] = []
    for row in resources:
        if type(row) is not dict or tuple(row) != ("path", "raw_sha256"):
            raise ReleaseOperationsError("release protected resource is not exact")
        body = protected_resources.get(str(row["path"]))
        if body is None or row["raw_sha256"] != _raw(body):
            raise ReleaseOperationsError("release protected resource bytes changed")
        closure_rows.append(dict(row))
    closure = _semantic(
        {"schema_version": "1.0.0", "resources": closure_rows},
        "release-operations-protected-closure",
    )
    if bootstrap["protected_closure_digest"] != closure:
        raise ReleaseOperationsError("release protected closure changed")
    action_pins = bootstrap["action_authority_pins"]
    action_expected = {
        "adapter_registry_digest": (
            "config/contracts/action-adapter-registry-v1.json", "registry_digest",
        ),
        "concrete_policy_digest": (
            "config/actions/concrete-action-policy-v1.json", "policy_digest",
        ),
        "default_action_policy_digest": (
            "config/actions/action-policy-v1.json", "policy_digest",
        ),
        "local_action_policy_digest": (
            "config/actions/action-policy-local-actions-v1.json", "policy_digest",
        ),
        "default_runtime_digest": (
            "config/security/security-runtime-v1.json", "manifest_digest",
        ),
        "local_runtime_digest": (
            "config/security/security-runtime-local-actions-v1.json", "manifest_digest",
        ),
    }
    expected_action_fields = {
        field for key in action_expected for field in (key, key.removesuffix("_digest") + "_raw_sha256")
    }
    if type(action_pins) is not dict or set(action_pins) != expected_action_fields:
        raise ReleaseOperationsError("release action authority pins are not exact")
    for digest_field, (path, document_field) in action_expected.items():
        resource = protected_resources.get(path)
        if resource is None:
            raise ReleaseOperationsError("release action authority resource is absent")
        document = _strict_json(resource, path)
        raw_field = digest_field.removesuffix("_digest") + "_raw_sha256"
        if (
            action_pins[digest_field] != document.get(document_field)
            or action_pins[raw_field] != _raw(resource)
        ):
            raise ReleaseOperationsError("release action authority pin changed")
    source_pins = bootstrap["source_authority_pins"]
    if type(source_pins) is not dict or tuple(source_pins) != (
        "policy_id", "source_file_count", "source_issuer_raw_sha256",
    ):
        raise ReleaseOperationsError("release source authority pins are not exact")
    from graph_engineering import _SOURCE_FILES

    source_issuer = protected_resources.get(
        "core/graph_engineering/core/source_checkout.py"
    )
    if (
        source_pins["policy_id"] != "source-checkout-attestation-v1"
        or source_pins["source_file_count"] != len(_SOURCE_FILES)
        or source_issuer is None
        or source_pins["source_issuer_raw_sha256"] != _raw(source_issuer)
    ):
        raise ReleaseOperationsError("release source authority pin changed")
    package_pins = bootstrap["package_authority_pins"]
    if type(package_pins) is not dict or tuple(package_pins) != (
        "build_backend_raw_sha256", "distribution_name", "distribution_version",
    ):
        raise ReleaseOperationsError("release package authority pins are not exact")
    try:
        provenance = tomllib.loads(package_provenance_bytes.decode("utf-8", errors="strict"))
        project = provenance["project"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseOperationsError("release package provenance is malformed") from error
    build_backend = protected_resources.get("scripts/build_backend.py")
    if (
        type(project) is not dict
        or package_pins["distribution_name"] != project.get("name")
        or package_pins["distribution_version"] != project.get("version")
        or build_backend is None
        or package_pins["build_backend_raw_sha256"] != _raw(build_backend)
    ):
        raise ReleaseOperationsError("release package authority pin changed")
    unsigned = copy.deepcopy(dict(bootstrap))
    expected = unsigned.pop("bootstrap_digest", None)
    if (
        type(expected) is not str or SEMANTIC_DIGEST.fullmatch(expected) is None
        or not hmac.compare_digest(
            expected, _semantic(unsigned, "release-operations-installation-bootstrap")
        )
    ):
        raise ReleaseOperationsError("release bootstrap digest changed")


_PROJECTION_FIELDS = (
    "schema_version", "evidence_kind", "task_id", "task_revision",
    "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
    "graph_ref_pins", "installation_pins",
    "artifact_manifest", "artifact_manifest_digest",
    "deployment_observation", "deployment_observation_digest",
    "health_observation", "health_observation_digest",
    "rollback_observation", "rollback_observation_digest",
    "current_target", "current_target_digest", "claim_id", "receipt_digest", "owner_route",
    "column_id", "scenario_id", "outcome", "observation_digest",
)

_GRAPH_PIN_FIELDS = frozenset({
    "base_graph_digest", "profile_digest", "overlay_digest",
    "project_config_digest", "support_matrix_digest", "materialization_digest",
})


@dataclass(frozen=True, slots=True, init=False)
class ReleaseOperationsEvidence:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


@dataclass(frozen=True, slots=True, init=False)
class ReleaseDeploymentObservation:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


@dataclass(frozen=True, slots=True, init=False)
class ReleaseHealthObservation:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


def _release_category_predecessor(binding, installation, journal, claim_state, before, after, disposition):
    """Pure private record shared by live issuance and captured cold validation."""
    body = {"schema_version": "1.0.0", "record_kind": "release-category-predecessor-v1",
        **dict(binding), "installation_pins": dict(installation),
        "toolchain_id": "authoritative-local-release-simulator",
        "action_id": journal["action_id"], "prepared_action_digest": journal["prepared_digest"],
        "authority_digest": journal["authority_digest"], "journal_state": journal["state"],
        "claim_state": claim_state, "receipt_digest": None if journal["receipt"] is None else journal["receipt"]["receipt_digest"],
        "before_state": dict(before), "after_state": dict(after),
        "mutation_delta": int(disposition == "P"),
        "result": "COMPLETED" if disposition == "P" else "EXPECTED_REJECTION"}
    body["record_digest"] = _semantic(body, "release-category-predecessor")
    return body


def _release_category_facts(body):
    return {"predecessor-record-digest": body["record_digest"],
        "predecessor-result": body["result"], "toolchain-id": body["toolchain_id"],
        "target-before-digest": _semantic(body["before_state"], "release-local-target-state"),
        "target-after-digest": _semantic(body["after_state"], "release-local-target-state")}


@dataclass(frozen=True, slots=True, init=False, eq=False)
class _ReleaseCategoryRecord:
    body: FrozenMap
    _authority: object

    def __init__(self, *args, **kwargs):
        raise TypeError("release category records are factory-issued")

    def to_dict(self) -> dict[str, object]:
        return thaw(self.body)

    def to_bytes(self) -> bytes:
        from graph_engineering.core.contracts.canonical import canonical_bytes
        return canonical_bytes(self.body)


class _ReleaseCategoryObserver:
    is_test_double = False
    is_read_only_observer = True
    execution_kind = "authoritative-real-e2e-observer"

    def __init__(self, *args, **kwargs):
        raise TypeError("release category observers are factory-issued")

    @classmethod
    def require_issued(cls, observer: object) -> _ReleaseCategoryAuthority:
        if (type(observer) is not cls or type(observer._authority) is not _ReleaseCategoryAuthority
                or observer._authority._observer is not observer
                or observer._authority._factory._category_observers.get(id(observer))
                    != (observer._authority, observer)):
            raise ReleaseOperationsError("release category observer is cloned or foreign")
        observer._authority._require_execution()
        authority = observer._authority
        session = authority._session
        if (observer.target_id != session.target.target_id
                or observer.target_digest != session.target.target_digest
                or observer.resource_id != session.target.resource_id
                or freeze(observer.expected_state) != authority._execution["after_state"]
                or freeze(observer.rollback_state) != authority._execution["after_state"]):
            raise ReleaseOperationsError("release category observer target binding changed")
        return observer._authority

    def observe(self) -> dict[str, object]:
        from graph_engineering.core.contracts.canonical import canonical_bytes

        authority = self.require_issued(self)
        root = authority._session._root
        state = root.state()
        metadata = os.stat(root._root_path / root.names["state"], follow_symlinks=False)
        self._revision += 1
        return {"schema_version": "1.0.0", "execution_kind": self.execution_kind,
            "target_id": self.target_id, "resource_id": self.resource_id, "fresh": True,
            "observation_revision": self._revision, "file_identity": [metadata.st_dev, metadata.st_ino],
            "state": state, "state_bytes_sha256": hashlib.sha256(canonical_bytes(state)).hexdigest()}

    def close(self) -> None:
        pass


class _ReleaseCategoryAuthority:
    """Private proof of one actual local simulator execute-gate attempt."""

    def __init__(self, *args, **kwargs):
        raise TypeError("release category execution authority is factory-issued")

    @property
    def disposition(self) -> str:
        return self._execution["disposition"]

    @property
    def profile_id(self) -> str:
        return "release-operations"

    def _require_execution(self):
        from graph_engineering.storage.errors import RepositoryConflictError

        factory, session, coordinator = self._factory, self._session, self._coordinator
        factory.require_installed_authority()
        issuance = factory._category_executions.get(id(self))
        if (issuance is None or issuance[0] is not self
                or any(actual is not expected for actual, expected in zip(issuance[1:],
                    (session, coordinator, self._journal, self._claim,
                     self._outcome, self._deployment, self._security, self._execution)))
                or factory._issued_sessions.get(id(session)) is not session
                or factory._session_coordinators.get(id(session)) is not coordinator
                or freeze(self._execution) != self._execution_seal):
            raise ReleaseOperationsError("release category execution capability changed")
        session._root._require_open()
        security = coordinator._issuer.read_task_state(self._journal.task_id)
        stable = lambda state: {key: (freeze({name: value for name, value in item.items()
            if name not in {"snapshot_digest", "binding_digest"}}) if key == "binding" else item)
            for key, item in state.items() if key not in {"task_revision", "task_snapshot_digest"}}
        checks = {
            "journal": coordinator._journal.load(self._journal.action_id) == self._journal,
            "security": stable(security.state) == stable(self._security.state),
            "runtime": security.runtime_manifest_digest == self._security.runtime_manifest_digest,
            "mutation": session._root.mutation_count == self._execution["mutation_delta"],
            "apply": session.target.apply_count == self._execution["mutation_delta"],
            "target": freeze(session._root.state()) == self._execution["after_state"],
        }
        if not all(checks.values()):
            raise ReleaseOperationsError("release category currentness changed: "
                + ",".join(key for key, passed in checks.items() if not passed))
        coordinator._issuer.runtime.require_policy(
            "action", coordinator._policy.policy_id, coordinator._policy.policy_digest)
        if coordinator._policy._runtime_issuer is not coordinator._issuer.runtime._issuer:
            raise ReleaseOperationsError("release category action security issuer changed")
        if self.disposition == "P":
            coordinator.require_issued_outcome(self._outcome)
            if freeze(coordinator._leases.load_claim(self._outcome.claim_id)) != self._claim:
                raise ReleaseOperationsError("release category terminal claim changed")
        else:
            try:
                coordinator._leases.load_claim("claim:" + self._journal.action_id)
            except RepositoryConflictError:
                pass
            else:
                raise ReleaseOperationsError("rejected release category action acquired a claim")

    def issue_observer(self) -> _ReleaseCategoryObserver:
        self._require_execution()
        if self._observer is not None:
            raise ReleaseOperationsError("release category observer already issued")
        observer = object.__new__(_ReleaseCategoryObserver)
        observer._authority = self
        observer._revision = 0
        observer.target_id = self._session.target.target_id
        observer.target_digest = self._session.target.target_digest
        observer.resource_id = self._session.target.resource_id
        observer.expected_state = thaw(self._execution["after_state"])
        observer.rollback_state = thaw(self._execution["after_state"])
        self._observer = observer
        self._factory._category_observers[id(observer)] = (self, observer)
        return observer

    def stage_task(self, snapshot: object) -> _ReleaseCategoryRecord:
        from graph_engineering.core.graph.state import TaskSnapshot

        self._require_execution()
        if (type(snapshot) is not TaskSnapshot or self._record is not None
                or snapshot.lifecycle != "completing" or not snapshot.graph_ref
                or snapshot.identity["task_id"] != self._journal.task_id):
            raise ReleaseOperationsError("release category task binding is invalid")
        graph = snapshot.graph_ref
        if graph.get("profile_id") != self.profile_id:
            raise ReleaseOperationsError("release category task profile is foreign")
        pins = {key: graph["graph_digest" if key == "base_graph_digest" else key]
                for key in _GRAPH_PIN_FIELDS}
        binding = {"task_id": self._journal.task_id, "task_revision": snapshot.task_revision,
            "snapshot_digest": snapshot.snapshot_digest, "invalidation_epoch": snapshot.invalidation_epoch,
            "profile_id": self.profile_id, "profile_version": "1.0.0", "materialization_pins": pins}
        installation = {key: self._factory._bootstrap[key] for key in (
            "bootstrap_id", "bootstrap_digest", "policy_registry_digest", "fixture_registry_digest",
            "profile_schema_registry_digest", "protected_closure_digest")}
        journal = {"action_id": self._journal.action_id,
            "prepared_digest": self._journal.prepared.prepared_action_digest,
            "authority_digest": self._journal.authority.authority_digest,
            "state": self._journal.state, "receipt": self._journal.receipt}
        body = _release_category_predecessor(binding, installation, journal,
            None if self._claim is None else self._claim["state"],
            self._execution["before_state"], self._execution["after_state"], self.disposition)
        record = object.__new__(_ReleaseCategoryRecord)
        object.__setattr__(record, "body", freeze(body))
        object.__setattr__(record, "_authority", self)
        self._record = record
        self._record_seal = record.body
        self._factory._category_records[id(record)] = (self, record, record.body)
        return record

    def require_installation_current(self) -> None:
        self._require_execution()
        record = self._record
        issuance = self._factory._category_records.get(id(record))
        if (type(record) is not _ReleaseCategoryRecord or record._authority is not self
                or issuance is None or issuance[0] is not self or issuance[1] is not record
                or issuance[2] is not record.body
                or record.body != self._record_seal
                or record.body["record_digest"] != _semantic(
                    {key: value for key, value in record.body.items() if key != "record_digest"},
                    "release-category-predecessor")):
            raise ReleaseOperationsError("release category predecessor is missing, cloned or changed")

    def evidence_facts(self, record: object) -> dict[str, object]:
        self.require_installation_current()
        if record is not self._record:
            raise ReleaseOperationsError("release category predecessor is foreign")
        return _release_category_facts(record.body)

    def activate(self, *, task_application: object, repository: object, objects: object,
                 runtime: object, object_digest: str) -> None:
        from graph_engineering.application.tasks import TaskApplication, RuntimeContext
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.objects import ObjectRepository

        self.require_installation_current()
        if (self._task_binding is not None or type(task_application) is not TaskApplication
                or type(runtime) is not RuntimeContext or type(repository) is not TaskRepository
                or type(objects) is not ObjectRepository or repository is not self._coordinator._repository
                or objects is not self._coordinator._objects or task_application._repository is not repository
                or task_application._materialization_objects is not objects
                or objects.digest(self._record.to_bytes()) != object_digest):
            raise ReleaseOperationsError("release category task ports are foreign")
        self._task_binding = (task_application, repository, objects, runtime, object_digest)
        try:
            self.require_current(expected_task_id=self._journal.task_id)
        except BaseException:
            self._task_binding = None
            raise

    def require_current(self, *, expected_task_id: str | None,
                        require_success: bool=False) -> _ReleaseCategoryRecord:
        self.require_installation_current()
        if self._task_binding is None or expected_task_id not in (None, self._journal.task_id):
            raise ReleaseOperationsError("release category task authority is absent or foreign")
        app, repository, objects, runtime, ref = self._task_binding
        body = self._record.body
        view = app.runtime_show(self._journal.task_id, runtime)
        snapshot = view.snapshot
        graph = snapshot.graph_ref
        pins = {key: graph.get("graph_digest" if key == "base_graph_digest" else key)
                for key in _GRAPH_PIN_FIELDS}
        raw = self._record.to_bytes()
        if (snapshot.task_revision not in (body["task_revision"], body["task_revision"] + 1)
                or snapshot.invalidation_epoch != body["invalidation_epoch"]
                or freeze(pins) != body["materialization_pins"]
                or objects.get(ref, require_referenced=False) != raw
                or tuple(item for item in repository.referenced_objects(self._journal.task_id)
                         if item == (ref, raw)) != ((ref, raw),)):
            raise ReleaseOperationsError("release category predecessor task source changed")
        if snapshot.task_revision == body["task_revision"]:
            if snapshot.lifecycle != "completing" or snapshot.snapshot_digest != body["snapshot_digest"]:
                raise ReleaseOperationsError("release category predecessor snapshot changed")
        else:
            from graph_engineering.application.profile_execution import (
                CategoryAssessmentResolver, _strict_json, _value_digest,
            )
            if snapshot.lifecycle != "completed" or self.disposition != "P":
                raise ReleaseOperationsError("release category predecessor advanced by an unrelated transition")
            resolved = CategoryAssessmentResolver(repository, objects,
                task_application=app, runtime=runtime).current_body(self._journal.task_id)
            if resolved is None:
                raise ReleaseOperationsError("release category assessment transition is absent")
            assessment = _strict_json(resolved[1])
            event = repository.replay(self._journal.task_id)[-1]
            if (assessment.get("schema_version") != "1.4.0" or assessment.get("column_id") != "real-e2e"
                    or assessment.get("status") != "PASS"
                    or any(assessment.get(key) != body[key] for key in (
                        "task_id", "profile_id", "task_revision", "snapshot_digest", "invalidation_epoch"))
                    or assessment["assessment_digest"] != _value_digest(
                        {key: value for key, value in assessment.items() if key != "assessment_digest"},
                        "category-completion-assessment")
                    or event.get("event_type") != "task.category_assessed"
                    or event.get("payload", {}).get("evidence_ref", {}).get("source_ref")
                        != resolved[0]["assessment_object_digest"]
                    or assessment["release_operations_projection"]["deployment_observation"]["action_id"]
                        != self._journal.action_id):
                raise ReleaseOperationsError("release category assessment transition does not consume predecessor snapshot")
        if require_success and self.disposition != "P":
            raise ReleaseOperationsError("release real E2E predecessor rejected before mutation")
        return self._record


class ReleaseOperationsRegistryFactory:
    """Validate installation bytes and issue factory-local release capabilities."""

    def __init__(
        self,
        registry: ReleaseOperationsRegistry,
        bootstrap: Mapping[str, object],
        *,
        schema_documents: Mapping[str, Mapping[str, object]],
        currentness_check: Callable[[], None],
    ) -> None:
        if type(registry) is not ReleaseOperationsRegistry or not callable(currentness_check):
            raise ReleaseOperationsError("release factory authority is invalid")
        self._registry = registry
        frozen = freeze(bootstrap)
        if not isinstance(frozen, FrozenMap):
            raise ReleaseOperationsError("release bootstrap did not freeze")
        self._bootstrap = frozen
        if set(schema_documents) != set(RELEASE_OPERATIONS_SCHEMA_IDS):
            raise ReleaseOperationsError("release schema authority is incomplete")
        self._schemas = {
            schema_id: freeze(document)
            for schema_id, document in schema_documents.items()
        }
        self._currentness_check = currentness_check
        self._issued: dict[int, ReleaseOperationsEvidence] = {}
        self._issued_manifests: dict[int, ReleaseArtifactManifest] = {}
        self._issued_artifact_bytes: dict[int, bytes] = {}
        self._issued_sessions: dict[int, LocalReleaseSimulatorSession] = {}
        self._session_coordinators: dict[int, object] = {}
        self._issued_deployments: dict[int, ReleaseDeploymentObservation] = {}
        self._deployment_sessions: dict[int, LocalReleaseSimulatorSession] = {}
        self._deployment_outcomes: dict[int, object] = {}
        self._evidence_bindings: dict[
            int, tuple[
                LocalReleaseSimulatorSession, ReleaseDeploymentObservation,
                ReleaseDeploymentObservation | None,
            ]
        ] = {}
        self._issued_health: dict[int, ReleaseHealthObservation] = {}
        self._category_executions: dict[int, tuple] = {}
        self._category_records: dict[int, tuple] = {}
        self._category_observers: dict[int, tuple] = {}
        self._health_bindings: dict[
            int, tuple[LocalReleaseSimulatorSession, ReleaseDeploymentObservation]
        ] = {}
        self._currentness_check()

    def _execute_category_action(self, *, action_coordinator, session, action_id, **arguments):
        """Execute once and seal measured P or an exact pre-claim rejection."""
        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.core.actions import ActionGateError
        from graph_engineering.storage.errors import RepositoryConflictError

        self.require_installed_authority()
        if (type(action_coordinator) is not ActionCoordinator
                or type(session) is not LocalReleaseSimulatorSession
                or self._issued_sessions.get(id(session)) is not session
                or self._session_coordinators.get(id(session)) is not action_coordinator
                or set(arguments) != {"owner_id", "runtime_kind", "runtime_lineage_id", "lease", "disclosure_plan"}
                or session._root.mutation_count != 0 or session.target.apply_count != 0
                or session._release_snapshot()["last_execution"] is not None):
            raise ReleaseOperationsError("release category execution inputs are foreign or already used")
        record = action_coordinator._journal.load(action_id)
        security = action_coordinator._issuer.read_task_state(record.task_id)
        before = session._root.state()
        if (record.state != "authorized" or record.authority is None
                or record.prepared.action_kind != "deploy"
                or record.prepared.target_id != session.target.target_id
                or record.prepared.target_digest != session.target.target_digest
                or record.prepared.payload["operation_id"] != self._registry.operation_roles["apply"]):
            raise ReleaseOperationsError("release category action is not an authorized apply")
        outcome, deployment = None, None
        rejection = None
        try:
            outcome = action_coordinator.execute(action_id, target=session.target,
                observer=session.observer, **arguments)
        except ActionGateError as error:
            if error.code != "GEW-AUT-PRECONDITION-CHANGED":
                raise
            rejection = error.code
        after = session._root.state()
        terminal = action_coordinator._journal.load(action_id)
        if rejection is not None:
            condition = record.prepared.precondition
            current = {key: value for key, value in before.items() if key != "schema_version"}
            stale_generation = (set(condition) == set(current)
                and type(condition.get("generation")) is int
                and type(record.prepared.payload["expected_generation"]) is int
                and 0 <= condition["generation"] < self._registry.policy["deployment_policy"]["generation_limit"]
                and condition["generation"] != current["generation"]
                and condition["generation"] == record.prepared.payload["expected_generation"]
                and all(condition[key] == current[key] for key in current if key != "generation"))
            if not stale_generation:
                raise ReleaseOperationsError("release real E2E rejection is not an exact stale-generation request")
            if (terminal != record or after != before or session._root.mutation_count != 0
                    or session.target.apply_count != 0
                    or session._release_snapshot()["last_execution"] is not None
                    or dict(record.prepared.precondition) == {key: value for key, value in before.items() if key != "schema_version"}):
                raise ReleaseOperationsError("release rejection did not occur before mutation")
            try:
                action_coordinator._leases.load_claim("claim:" + action_id)
            except RepositoryConflictError:
                claim = None
            else:
                raise ReleaseOperationsError("release rejection unexpectedly acquired a claim")
        else:
            if (outcome is None or outcome.route != "reconciled-effect-verified"
                    or session._root.mutation_count != 1 or session.target.apply_count != 1):
                raise ReleaseOperationsError("release category success is not one reconciled mutation")
            deployment = self.issue_deployment_observation(action_coordinator=action_coordinator,
                session=session, outcome=outcome)
            health = self.issue_health_observation(session=session, terminal_observation=deployment)
            if health.to_dict()["outcome"] != self._registry.health_outcomes["healthy"]:
                raise ReleaseOperationsError("release category apply is unhealthy")
            claim = freeze(action_coordinator._leases.load_claim(outcome.claim_id))
        authority = object.__new__(_ReleaseCategoryAuthority)
        authority._factory, authority._session, authority._coordinator = self, session, action_coordinator
        authority._journal, authority._claim, authority._outcome = terminal, claim, outcome
        authority._deployment = deployment
        authority._security = security
        authority._execution = freeze({"disposition": "P" if rejection is None else "R",
            "before_state": before, "after_state": after, "mutation_delta": session._root.mutation_count,
            "rejection_code": rejection})
        authority._execution_seal = authority._execution
        authority._observer = None
        authority._record = None
        authority._record_seal = None
        authority._task_binding = None
        self._category_executions[id(authority)] = (authority, session, action_coordinator,
            terminal, claim, outcome, deployment, security, authority._execution)
        try:
            authority._require_execution()
        except BaseException:
            self._category_executions.pop(id(authority), None)
            raise
        return authority

    def _resolve_schema(
        self, current_id: str, reference: str,
    ) -> tuple[object, str]:
        if reference.startswith("#"):
            target_id, pointer = current_id, reference[1:]
        else:
            target_id, separator, pointer = reference.partition("#")
            if not separator:
                pointer = ""
        target = self._schemas.get(target_id)
        if target is None:
            raise ReleaseOperationsError("release schema reference is not installed")
        current: object = target
        if pointer:
            if not pointer.startswith("/"):
                raise ReleaseOperationsError("release schema pointer is invalid")
            for encoded in pointer[1:].split("/"):
                token = encoded.replace("~1", "/").replace("~0", "~")
                if not isinstance(current, Mapping) or token not in current:
                    raise ReleaseOperationsError("release schema pointer is unresolved")
                current = current[token]
        return current, target_id

    def _validate_document(self, schema_id: str, document: object) -> None:
        schema = self._schemas.get(schema_id)
        if schema is None:
            raise ReleaseOperationsError("release schema is not installed")
        try:
            failures = validate_instance(
                schema,
                document,
                source_id=schema_id,
                resolver=self._resolve_schema,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ReleaseOperationsError("release schema validation failed") from error
        if failures:
            raise ReleaseOperationsError(
                f"release document violates {schema_id}: {failures[0].rule_id}"
            )

    @classmethod
    def from_documents(
        cls,
        *,
        policy_bytes: bytes,
        fixture_bytes: bytes,
        bootstrap_bytes: bytes,
        profile_schema_registry_bytes: bytes,
        package_provenance_bytes: bytes,
        schema_bodies: Mapping[str, bytes],
        protected_resources: Mapping[str, bytes],
        current_resource_reader: Callable[[], Mapping[str, bytes]] | None = None,
    ) -> "ReleaseOperationsRegistryFactory":
        if any(type(body) is not bytes for body in (
            policy_bytes, fixture_bytes, bootstrap_bytes, profile_schema_registry_bytes,
            package_provenance_bytes,
        )):
            raise ReleaseOperationsError("release installation bodies are not exact bytes")
        policy = _strict_json(policy_bytes, "release policy registry")
        fixture = _strict_json(fixture_bytes, "release fixture registry")
        bootstrap = _strict_json(bootstrap_bytes, "release installation bootstrap")
        schemas = dict(schema_bodies)
        protected = dict(protected_resources)
        _verify_bootstrap(
            bootstrap,
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            profile_schema_registry_bytes=profile_schema_registry_bytes,
            package_provenance_bytes=package_provenance_bytes,
            schema_bodies=schemas,
            protected_resources=protected,
        )
        initial = {
            "policy": policy_bytes,
            "fixture": fixture_bytes,
            "bootstrap": bootstrap_bytes,
            "profile-schema-registry": profile_schema_registry_bytes,
            "package-provenance": package_provenance_bytes,
            **{f"schema:{key}": value for key, value in schemas.items()},
            **{f"protected:{key}": value for key, value in protected.items()},
        }
        expected = {key: _raw(value) for key, value in initial.items()}
        # Installed factories reread current resources; only validation-only
        # document factories need to retain their original raw input bodies.
        if current_resource_reader is not None:
            initial = None

        def current() -> None:
            if current_resource_reader is None:
                observed = initial
            else:
                observed = dict(current_resource_reader())
            if set(observed) != set(expected) or any(
                type(observed[key]) is not bytes or _raw(observed[key]) != digest
                for key, digest in expected.items()
            ):
                raise ReleaseOperationsError("release installation currentness changed")

        factory = cls(
            ReleaseOperationsRegistry.from_dicts(policy, fixture),
            bootstrap,
            schema_documents={
                schema_id: _strict_json(body, f"release schema {schema_id}")
                for schema_id, body in schemas.items()
            },
            currentness_check=current,
        )
        _COLD_CURRENTNESS_INPUTS[factory] = (expected,)
        return factory

    @classmethod
    def from_installation(cls) -> "ReleaseOperationsRegistryFactory":
        if cls is not ReleaseOperationsRegistryFactory:
            raise ReleaseOperationsError("release installation factory type is foreign")
        from graph_engineering import (
            DistributionIdentityError,
            _release_operations_installation_resources,
            _release_operations_read_plan,
        )

        try:
            resources = _release_operations_installation_resources()
            provenance_bytes, policy_bytes, fixture_bytes, bootstrap_bytes, profile_bytes = (
                resources[:5]
            )
            schema_bodies = resources[5:5 + len(RELEASE_OPERATIONS_SCHEMA_IDS)]
            bootstrap = _strict_json(bootstrap_bytes, "release installation bootstrap")
            protected_count = len(bootstrap.get("protected_resources", ()))
            protected_bodies = resources[5 + len(RELEASE_OPERATIONS_SCHEMA_IDS):]
            provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
            project = provenance["project"]
            pin = provenance["tool"]["gew"]["profile"]["release-operations"]
        except (
            DistributionIdentityError, KeyError, TypeError, UnicodeError,
            tomllib.TOMLDecodeError,
        ) as error:
            raise ReleaseOperationsError(
                "release installation bootstrap is unavailable"
            ) from error
        expected_pin_fields = {
            "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
            "bootstrap-source", "bootstrap-resource", "policy-source",
            "policy-resource", "fixture-source", "fixture-resource",
            "profile-schema-registry-source", "profile-schema-registry-resource",
            "schema-sources", "schema-resources", "protected-sources",
            "protected-resources", "distribution-name", "distribution-version",
        }
        if type(pin) is not dict or set(pin) != expected_pin_fields:
            raise ReleaseOperationsError("release independent installation pin is not exact")
        if (
            len(schema_bodies) != len(RELEASE_OPERATIONS_SCHEMA_IDS)
            or len(protected_bodies) != protected_count
            or pin["bootstrap-id"] != bootstrap.get("bootstrap_id")
            or pin["bootstrap-digest"] != bootstrap.get("bootstrap_digest")
            or not hmac.compare_digest(
                _raw(bootstrap_bytes), str(pin["bootstrap-raw-sha256"]),
            )
        ):
            raise ReleaseOperationsError("release installation pin changed")
        if (
            type(project) is not dict
            or pin["distribution-name"] != project.get("name")
            or pin["distribution-version"] != project.get("version")
            or pin["distribution-name"]
            != bootstrap.get("package_authority_pins", {}).get("distribution_name")
            or pin["distribution-version"]
            != bootstrap.get("package_authority_pins", {}).get("distribution_version")
        ):
            raise ReleaseOperationsError("release independent installation pin changed")
        schema_documents = {
            str(document["$id"]): body
            for body in schema_bodies
            for document in (_strict_json(body, "release schema"),)
        }
        protected_paths = tuple(
            str(row["path"])
            for row in bootstrap["protected_resources"]
            if type(row) is dict and "path" in row
        )
        if len(protected_paths) != protected_count:
            raise ReleaseOperationsError("release protected closure is malformed")
        protected = dict(zip(protected_paths, protected_bodies, strict=True))

        def read_current() -> Mapping[str, bytes]:
            try:
                current = _release_operations_installation_resources()
            except (DistributionIdentityError, OSError) as error:
                raise ReleaseOperationsError(
                    "release installation closure is unavailable"
                ) from error
            current_schema_bodies = current[5:5 + len(RELEASE_OPERATIONS_SCHEMA_IDS)]
            current_protected = current[5 + len(RELEASE_OPERATIONS_SCHEMA_IDS):]
            return {
                "policy": current[1],
                "fixture": current[2],
                "bootstrap": current[3],
                "profile-schema-registry": current[4],
                "package-provenance": current[0],
                **{
                    f"schema:{schema_id}": body
                    for schema_id, body in zip(
                        RELEASE_OPERATIONS_SCHEMA_IDS,
                        current_schema_bodies,
                        strict=True,
                    )
                },
                **{
                    f"protected:{path}": body
                    for path, body in zip(
                        protected_paths, current_protected, strict=True,
                    )
                },
            }

        factory = cls.from_documents(
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            bootstrap_bytes=bootstrap_bytes,
            profile_schema_registry_bytes=profile_bytes,
            package_provenance_bytes=provenance_bytes,
            schema_bodies=schema_documents,
            protected_resources=protected,
            current_resource_reader=read_current,
        )
        _INSTALLED_RELEASE_FACTORIES.add(factory)
        cold_names = (
            "artifact-contracts-v1.json", "artifact-schema-registry-v1.json",
            "cost-schedule-v1.json", "resource-profile-v1.json", "schema-profile-v1.json",
            "schemas/artifact-contract-registry-1.0.0.json", "schemas/artifact-lifecycle-event-1.0.0.json",
            "schemas/artifact-record-1.0.0.json", "schemas/logical-body-manifest-1.0.0.json",
        )
        _COLD_ARTIFACT_INPUTS[factory] = {
            "config/contracts/" + name: protected["config/contracts/" + name] for name in cold_names
        }
        from graph_engineering import _category_policy_installation_resources
        from graph_engineering.core.profile_execution import _policy_document_from_installation_resources

        category_resources = _category_policy_installation_resources()
        if category_resources[0] != provenance_bytes:
            raise ReleaseOperationsError("cold category and release installation inputs differ")
        _COLD_CATEGORY_DOCUMENTS[factory] = freeze(
            _policy_document_from_installation_resources(category_resources))
        # All parsing and schema construction precedes entry into a cold read.
        # The operation adopts these exact caches before any source lookup.
        factory._cold_artifact_authority()
        _COLD_INSTALLATION_PLANS[factory] = _release_operations_read_plan(
            resources, category_resources=category_resources)
        if _COLD_INSTALLATION_PLANS[factory] is None:
            from graph_engineering import _release_operations_wheel_read_plan
            from graph_engineering.storage.repository import _RecoveryReadBudget

            context = factory._cold_artifact_authority()[2]
            owner = _RecoveryReadBudget((context,))
            try:
                _COLD_INSTALLATION_PLANS[factory] = _release_operations_wheel_read_plan(
                    resources, context, owner, category_resources=category_resources)
            finally:
                owner.close()
        _COLD_CURRENTNESS_INPUTS[factory] = (*_COLD_CURRENTNESS_INPUTS[factory], protected_paths)
        return factory

    def _cold_artifact_authority(self) -> tuple:
        """Resolve cold validation authority only from the installed closure."""
        from contextlib import ExitStack

        from graph_engineering.core.artifacts.contracts import ArtifactContractRegistry
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
        from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy
        from graph_engineering.core.contracts.strict_json import parse_json
        from graph_engineering.storage.repository import _recovery_scope

        self.require_installed_authority()
        if self not in _COLD_ARTIFACT_INPUTS:
            raise ReleaseOperationsError("cold artifact installed authority is absent")
        cached = _COLD_ARTIFACT_AUTHORITIES.get(self)
        if cached is not None:
            return cached
        resources = _COLD_ARTIFACT_INPUTS[self]
        prefix = "config/contracts/"
        try:
            profile = ResourceProfile.from_dict(_strict_json(
                resources[prefix + "resource-profile-v1.json"], "installed resource profile",
            ))
            schedule = CostSchedule.from_dict(_strict_json(
                resources[prefix + "cost-schedule-v1.json"], "installed cost schedule",
            ))
            context = WorkContext(profile, schedule)
            with _recovery_scope(context) as budget, ExitStack() as stack:
                def document(name: str) -> dict:
                    body = resources[prefix + name]
                    stack.enter_context(budget.reserve(
                        context, units=6 * len(body), byte_count=4 * len(body),
                        source_id="cold-artifact-authority:" + name,
                    ))
                    return parse_json(body, context=context, source_id=prefix + name)

                policy = SchemaProfilePolicy.from_dict(document("schema-profile-v1.json"))
                manifest = document("artifact-schema-registry-v1.json")
                contracts_document = document("artifact-contracts-v1.json")
                names = ("artifact-contract-registry", "artifact-lifecycle-event",
                         "artifact-record", "logical-body-manifest")
                bodies = {
                    "urn:gew:schema:" + name + ":1.0.0":
                    resources[prefix + "schemas/" + name + "-1.0.0.json"]
                    for name in names
                }
                size = sum(len(body) for body in bodies.values())
                stack.enter_context(budget.reserve(
                    context, units=12 * size, byte_count=4 * size,
                    source_id="cold-artifact-schema-construction",
                ))
                schemas = ClosedSchemaRegistry.build(manifest, bodies, profile, policy, context)
                contracts = ArtifactContractRegistry.from_dict(
                    contracts_document, schema_registry=schemas, context=context,
                    expected_registry_id=contracts_document["registry_id"],
                    expected_registry_digest=contracts_document["registry_digest"],
                )
        except (KeyError, TypeError, ValueError) as error:
            raise ReleaseOperationsError("cold artifact installation is invalid") from error
        result = (contracts, schemas, context)
        _COLD_ARTIFACT_AUTHORITIES[self] = result
        return result

    def _adopt_cold_configuration(self, budget, *, _operation=None):
        """Admit every retained installation cache into the active read owner."""
        from graph_engineering import _SourceInstallationReadPlan, _WheelInstallationReadPlan
        from graph_engineering.core.artifacts.contracts import ArtifactContract, ArtifactContractRegistry
        from graph_engineering.core.contracts.registry import ClosedSchemaRegistry, SchemaResource
        from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext
        from graph_engineering.storage.repository import (
            _RecoveryReadBudget, _recovery_adopt, _recovery_clear_exception_frames,
        )

        authority = plan = context = records = roots = None
        try:
            if (type(self) is not ReleaseOperationsRegistryFactory or self not in _INSTALLED_RELEASE_FACTORIES
                    or type(budget) is not _RecoveryReadBudget or self not in budget._ports):
                raise ReleaseOperationsError("cold configuration owner or factory is foreign")
            budget._require_active()
            authority = _COLD_ARTIFACT_AUTHORITIES.get(self)
            plan = _COLD_INSTALLATION_PLANS.get(self)
            if (authority is None or plan is None
                    or not any(authority[2] is context for context in budget.contexts)):
                raise ReleaseOperationsError("cold configuration context or plan is absent")
            context = authority[2]
            # Exact fixed scratch: types8 + map19 + dynamic field tuples47 +
            # fixed field tuples11 + roots8 + iteration setup7. Field names
            # alias installed code declarations; no payload text is copied.
            wheel_plan = type(plan) is _WheelInstallationReadPlan
            with budget.reserve(context, units=101 + (10 if wheel_plan else 0)
                                + (2048 if _operation is not None else 0), byte_count=0,
                                source_id="cold-configuration-table"):
                try:
                    records = {kind: tuple(kind.__dataclass_fields__) for kind in (
                        ArtifactContract, ArtifactContractRegistry, ClosedSchemaRegistry,
                        SchemaResource, CostSchedule, ResourceProfile, ReleaseOperationsRegistry,
                    )}
                    records[WorkContext] = ("profile", "schedule")
                    records[_SourceInstallationReadPlan] = (
                        "_source_path", "_control_path", "source_identity", "control_identity",
                        "files", "key", "attestation",
                    )
                    if wheel_plan:
                        records[_WheelInstallationReadPlan] = (
                            "_root_path", "archive", "root_identity", "module_origin", "names", "discovery", "members",
                        )
                    roots = (self._bootstrap, self._schemas, self._registry,
                             _COLD_CURRENTNESS_INPUTS[self], _COLD_ARTIFACT_INPUTS[self],
                             authority, plan, _COLD_CATEGORY_DOCUMENTS[self])
                    if _operation is not None:
                        if type(_operation) not in (_ColdReleaseReadScope, _RejectedReleaseReadScope) or _operation.factory is not self:
                            raise ReleaseOperationsError("cold operation configuration is foreign")
                        roots = (*roots, _operation._configuration(records))
                    return _recovery_adopt(roots, context, budget, record_fields=records,
                                           source_id="cold-installed-configuration")
                except BaseException as error:
                    _recovery_clear_exception_frames(error)
                    raise
                finally:
                    roots = records = authority = plan = self = None
        except BaseException as error:
            _recovery_clear_exception_frames(error)
            raise
        finally:
            self = authority = plan = context = records = roots = budget = _operation = None

    def registry(self) -> ReleaseOperationsRegistry:
        from graph_engineering.storage.repository import _RECOVERY_INSTALLATION_CONTEXT

        if (self in _INSTALLED_RELEASE_FACTORIES or getattr(self, "_recovery_read_budget", None) is not None
                or _RECOVERY_INSTALLATION_CONTEXT.get() is not None):
            self.require_installed_authority()
        else:
            self._currentness_check()
        return self._registry

    def require_installed_authority(self) -> None:
        """Require the opaque authority granted only by ``from_installation``."""

        if (
            type(self) is not ReleaseOperationsRegistryFactory
            or self not in _INSTALLED_RELEASE_FACTORIES
        ):
            raise ReleaseOperationsError("release installed authority is absent")
        from graph_engineering.storage.repository import _RECOVERY_INSTALLATION_CONTEXT

        budget = getattr(self, "_recovery_read_budget", None)
        authority = _COLD_ARTIFACT_AUTHORITIES.get(self)
        inherited = None if authority is None else getattr(authority[2], "_recovery_read_budget", None)
        if budget is None and (_RECOVERY_INSTALLATION_CONTEXT.get() is not None or inherited is not None):
            raise ReleaseOperationsError("cold release installation factory is not bound")
        if budget is None:
            self._currentness_check()
        else:
            from graph_engineering import DistributionIdentityError
            from graph_engineering.storage.repository import _RecoveryReadBudget

            if type(budget) is not _RecoveryReadBudget or self not in budget._ports:
                raise ReleaseOperationsError("cold release installation owner is foreign")
            budget._require_active()
            plan = _COLD_INSTALLATION_PLANS.get(self)
            if (plan is None or authority is None
                    or not any(authority[2] is context for context in budget.contexts)):
                raise ReleaseOperationsError("cold release installation read plan is unavailable")
            try:
                plan.require_current(authority[2], budget)
            except (DistributionIdentityError, OSError) as error:
                raise ReleaseOperationsError("release installation currentness changed") from error

    def issue_artifact_manifest(
        self,
        *,
        fixture_id: str,
        artifact_id: str,
    ) -> ReleaseArtifactManifest:
        """Issue only artifact bytes owned by the installed fixture registry."""

        self.require_installed_authority()
        vector = self._registry.fixture_artifact(fixture_id, artifact_id)
        encoded = vector["artifact_base64"]
        if type(encoded) is not str or not encoded.isascii():
            raise ReleaseOperationsError("release fixture artifact bytes are invalid")
        try:
            artifact_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ReleaseOperationsError(
                "release fixture artifact bytes are invalid"
            ) from error
        if not artifact_bytes or base64.b64encode(artifact_bytes).decode("ascii") != encoded:
            raise ReleaseOperationsError("release fixture artifact bytes are not canonical")
        artifact_record = {
            "schema_version": "1.0.0",
            "fixture_id": fixture_id,
            "artifact": dict(vector),
        }
        record_digest = _semantic(artifact_record, "release-fixture-artifact-record")
        source_manifest_digest = _semantic(
            {
                "schema_version": "1.0.0",
                "fixture_id": fixture_id,
                "fixture_registry_id": self._bootstrap["fixture_registry_id"],
                "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            },
            "release-fixture-source-manifest",
        )
        build_attestation_digest = _semantic({
            "schema_version": "1.0.0",
            "attestation_kind": "installed-deterministic-release-fixture",
            "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            "artifact_record_digest": record_digest,
            "source_manifest_digest": source_manifest_digest,
            "protected_closure_digest": self._bootstrap["protected_closure_digest"],
        }, "release-fixture-build-attestation")
        manifest = ReleaseArtifactManifest._issue(
            artifact_id=artifact_id,
            artifact_version=str(vector["artifact_version"]),
            artifact_bytes=artifact_bytes,
            distribution_name=str(vector["distribution_name"]),
            distribution_version=str(vector["distribution_version"]),
            record_digest=record_digest,
            source_manifest_digest=source_manifest_digest,
            build_attestation_digest=build_attestation_digest,
            protected_closure_digest=str(self._bootstrap["protected_closure_digest"]),
        )
        self._validate_document(
            "urn:gew:schema:release-artifact-manifest:1.0.0",
            manifest.to_dict(),
        )
        self._issued_manifests[id(manifest)] = manifest
        self._issued_artifact_bytes[id(manifest)] = artifact_bytes
        return manifest

    def artifact_bytes(self, manifest: ReleaseArtifactManifest) -> bytes:
        """Return bytes for an exact factory-issued fixture artifact."""

        self.require_installed_authority()
        if self._issued_manifests.get(id(manifest)) is not manifest:
            raise ReleaseOperationsError("release artifact authority is foreign")
        body = self._issued_artifact_bytes.get(id(manifest))
        if type(body) is not bytes:
            raise ReleaseOperationsError("release artifact bytes are unavailable")
        return body

    def issue_simulator(
        self,
        *,
        action_coordinator: object,
        task_id: str,
        fixture_id: str,
        target_id: str,
        resource_id: str,
        baseline_manifest: ReleaseArtifactManifest,
        authorized_artifacts: tuple[ReleaseArtifactManifest, ...],
        fault_hook: Callable[[str], None] = lambda _step: None,
        retained_namespace: RetainedReleaseNamespace | None = None,
    ) -> LocalReleaseSimulatorSession:
        from graph_engineering.application.actions import ActionCoordinator

        self.require_installed_authority()
        if type(action_coordinator) is not ActionCoordinator:
            raise ReleaseOperationsError("release simulator coordinator is missing or forged")
        if retained_namespace is not None:
            if type(retained_namespace) is not RetainedReleaseNamespace:
                raise ReleaseOperationsError("release retained namespace authority is not exact")
            retained_namespace.require_current(action_coordinator)
            action_coordinator._retained_scope(require_idle=True)
        if any(
            self._issued_manifests.get(id(manifest)) is not manifest
            for manifest in authorized_artifacts
        ):
            raise ReleaseOperationsError("release simulator artifact authority is foreign")
        if self._issued_manifests.get(id(baseline_manifest)) is not baseline_manifest:
            raise ReleaseOperationsError("release simulator baseline authority is foreign")
        if baseline_manifest not in authorized_artifacts:
            raise ReleaseOperationsError("release simulator baseline is not authorized")
        baseline_artifact_bytes = self.artifact_bytes(baseline_manifest)
        exact_authorized = tuple(
            (manifest, self.artifact_bytes(manifest))
            for manifest in authorized_artifacts
        )
        lease = binding = None
        current = self._currentness_check
        max_read_bytes = None
        try:
            if retained_namespace is not None:
                native = retained_namespace.require_current(action_coordinator)
                names = _retained_members(self._registry.fixture(fixture_id))
                lease = native.create(task_id, target_id, members={
                    name: 0o600 for role, name in names.items() if role != "identity"})
                # The root gate is already held before the first repository read.
                security = action_coordinator._issuer.read_task_state(task_id).state["binding"]
                runtime = retained_namespace._record()[1]
                if (security["owner_id"], security["runtime_kind"], security["runtime_lineage_id"]) != (
                    runtime.proof.owner_id, runtime.capabilities.runtime_kind, runtime.proof.lineage_id):
                    raise ReleaseOperationsError("retained release runtime does not own the task")
                value = {"schema_version": "1.0.0", "binding_kind": "retained-local-release-root",
                    "task_id": task_id, "fixture_id": fixture_id, "target_id": target_id, "resource_id": resource_id,
                    "repository_scope_digest": retained_namespace.repository_scope_digest, **lease.binding_parts(),
                    "installation_pins": {k: self._bootstrap[k] for k in (
                        "bootstrap_id", "bootstrap_digest", "policy_registry_digest", "fixture_registry_digest",
                        "profile_schema_registry_digest", "protected_closure_digest")}}
                value["binding_digest"] = _semantic(value, "release-recovery-binding")
                binding = ReleaseRecoveryBinding.from_dict(value)
                max_read_bytes = action_coordinator._policy._context.profile.limits["raw_document_bytes"]
                def current() -> None:
                    self._currentness_check()
                    retained_namespace.require_current(action_coordinator)
            session = _LocalReleaseSimulatorFactory(
                self._registry, currentness_check=current,
                durable_execution_gate=action_coordinator.issue_durable_execution_gate(), issuer=self,
            ).create(task_id=task_id, fixture_id=fixture_id, target_id=target_id, resource_id=resource_id,
                baseline_manifest=baseline_manifest, baseline_artifact_bytes=baseline_artifact_bytes,
                authorized_artifacts=exact_authorized, fault_hook=fault_hook,
                retained_lease=lease, recovery_binding=binding, max_read_bytes=max_read_bytes,
                retained_close_check=action_coordinator._require_retained_idle)
            if lease is not None:
                action_coordinator._register_retained_target(task_id, session)
        except BaseException:
            if lease is not None:
                lease.close()
            raise
        self._issued_sessions[id(session)] = session
        self._session_coordinators[id(session)] = action_coordinator
        return session

    def _open_retained_storage_query(
        self, *, action_coordinator: object,
        retained_namespace: RetainedReleaseNamespace,
        binding: ReleaseRecoveryBinding,
    ) -> _RetainedReadOnlyHandle:
        """Open raw storage queries under current runtime read authority.

        This internal prerequisite does not resolve an assessment or validate
        its action history. It cannot issue recovery evidence or a mutation
        capability, including for an uncommitted retained root.
        """
        from graph_engineering.application.actions import ActionCoordinator

        self.require_installed_authority()
        if (
            type(action_coordinator) is not ActionCoordinator
            or type(retained_namespace) is not RetainedReleaseNamespace
            or type(binding) is not ReleaseRecoveryBinding
        ):
            raise ReleaseOperationsError("retained query authority is missing or foreign")
        native = retained_namespace.require_current(action_coordinator)
        action_coordinator._retained_scope(require_idle=True)
        value = binding.to_dict()
        if (
            value["repository_scope_digest"] != retained_namespace.repository_scope_digest
            or value["installation_pins"] != {k: self._bootstrap[k] for k in value["installation_pins"]}
        ):
            raise ReleaseOperationsError("retained query binding is foreign or stale")
        names = _retained_members(self._registry.fixture(value["fixture_id"]))
        security_snapshot = None

        def current() -> None:
            nonlocal security_snapshot
            self.require_installed_authority()
            retained_namespace.require_current(action_coordinator)
            action_coordinator._retained_scope(require_idle=True)
            # The handle already owns the root gate. This public read manages
            # and releases its own repository locks; no outer token is held.
            security = action_coordinator._issuer.read_task_state(value["task_id"])
            owner = security.state["binding"]
            runtime = retained_namespace._record()[1]
            if (owner["task_id"], owner["owner_id"], owner["runtime_kind"], owner["runtime_lineage_id"]) != (
                value["task_id"], runtime.proof.owner_id, runtime.capabilities.runtime_kind, runtime.proof.lineage_id
            ):
                raise ReleaseOperationsError("retained query runtime does not own the task")
            targets = [target for target in owner["targets"] if target["target_id"] == value["target_id"]]
            if len(targets) != 1 or targets[0]["target_digest"] != binding.target_digest():
                raise ReleaseOperationsError("retained query target binding changed")
            if security_snapshot is not None and security != security_snapshot:
                raise ReleaseOperationsError("retained query security state changed")
            self.require_installed_authority()
            retained_namespace.require_current(action_coordinator)
            action_coordinator._require_retained_idle()
            security_snapshot = security

        handle = native.open_readonly_handle(binding,
            members={name: 0o600 for role, name in names.items() if role != "identity"},
            context=action_coordinator._policy._context, currentness_check=current,
            entry_check=action_coordinator._require_retained_idle)
        try:
            handle.query()
            return handle
        except BaseException:
            handle.close()
            raise

    def destroy_retained_simulator(
        self, *, action_coordinator: object,
        retained_namespace: RetainedReleaseNamespace,
        session: LocalReleaseSimulatorSession,
    ) -> None:
        """Explicit owner cleanup of an original quiesced session, not recovery.

        The original factory/session registration is required. A serialized
        binding or a freshly opened directory never grants this authority.
        """
        from graph_engineering.application.actions import ActionCoordinator

        self.require_installed_authority()
        if (
            type(action_coordinator) is not ActionCoordinator
            or type(retained_namespace) is not RetainedReleaseNamespace
            or type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._session_coordinators.get(id(session)) is not action_coordinator
        ):
            raise ReleaseOperationsError("retained destruction authority is foreign")
        native = retained_namespace.require_current(action_coordinator)
        action_coordinator._retained_scope(require_idle=True)
        root = session._root
        if root._retained_lease is None or not root.closed or not root._retained_lease._closed:
            raise ReleaseOperationsError("retained destruction requires a quiesced original session")
        binding = root._recovery_binding
        value = binding.to_dict()
        if (
            value["repository_scope_digest"] != retained_namespace.repository_scope_digest
            or value["installation_pins"] != {k: self._bootstrap[k] for k in value["installation_pins"]}
            or action_coordinator._retained_targets.get((value["task_id"], value["target_id"])) is not session
        ):
            raise ReleaseOperationsError("retained destruction binding is foreign or stale")
        names = _retained_members(self._registry.fixture(value["fixture_id"]))
        context = action_coordinator._policy._context
        with native.open_readonly(binding,
                members={name: 0o600 for role, name in names.items() if role != "identity"},
                context=context) as lease:
            security = action_coordinator._issuer.read_task_state(value["task_id"])
            current = security.state["binding"]
            runtime = retained_namespace._record()[1]
            if (current["task_id"], current["owner_id"], current["runtime_kind"], current["runtime_lineage_id"]) != (
                value["task_id"], runtime.proof.owner_id, runtime.capabilities.runtime_kind, runtime.proof.lineage_id
            ):
                raise ReleaseOperationsError("retained destruction runtime does not own the task")
            targets = [target for target in current["targets"] if target["target_id"] == value["target_id"]]
            if len(targets) != 1 or targets[0]["target_digest"] != binding.target_digest():
                raise ReleaseOperationsError("retained destruction target binding changed")
            if action_coordinator._issuer.read_task_state(value["task_id"]) != security:
                raise ReleaseOperationsError("retained destruction security state changed")
            self.require_installed_authority()
            retained_namespace.require_current(action_coordinator)
            action_coordinator._require_retained_idle()
            lease._destroy_owned_root(binding, context)

    def issue_deployment_observation(
        self,
        *,
        action_coordinator: object,
        session: LocalReleaseSimulatorSession,
        outcome: object,
    ) -> ReleaseDeploymentObservation:
        from graph_engineering.application.actions import ActionCoordinator, ActionOutcome
        from graph_engineering.core.actions import ActionJournalRecord

        self.require_installed_authority()
        if (
            type(action_coordinator) is not ActionCoordinator
            or type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._session_coordinators.get(id(session)) is not action_coordinator
            or type(outcome) is not ActionOutcome
        ):
            raise ReleaseOperationsError("release deployment authority is foreign")
        try:
            if session._root._retained_lease is not None:
                session._root._require_open()
            outcome = action_coordinator.require_issued_outcome(outcome)
        except ValueError as error:
            raise ReleaseOperationsError(
                "release deployment outcome is not coordinator-issued/current"
            ) from error
        snapshot = session._release_snapshot()
        execution = snapshot["last_execution"]
        if type(execution) is not dict:
            raise ReleaseOperationsError("release deployment has no simulator execution")
        record_action_id = outcome.action_id
        if outcome.route == "compensation-reconciled":
            if execution.get("operation_id") != self._registry.operation_roles["restore"]:
                raise ReleaseOperationsError(
                    "release compensation observation is not a restore"
                )
            record_action_id = str(execution.get("action_id"))
        record = action_coordinator._journal.load(record_action_id)
        if (
            type(record) is not ActionJournalRecord
            or record.receipt is None
            or record.authority is None
            or outcome.route not in {
                "manual-reconciliation", "reconciled-effect-verified",
                "compensation-reconciled",
            }
            or outcome.claim_id != record.receipt.get("claim_id")
            or outcome.receipt_digest != record.receipt.get("receipt_digest")
            or record.prepared.target_id != session.target.target_id
            or record.prepared.target_digest != session.target.target_digest
            or (
                outcome.route == "manual-reconciliation"
                and record.state not in {"executing", "unknown"}
            )
            or (
                outcome.route == "reconciled-effect-verified"
                and record.state != "reconciled"
            )
            or (
                outcome.route == "compensation-reconciled"
                and record.state != "reconciled"
            )
        ):
            raise ReleaseOperationsError("release deployment journal binding changed")
        payload = thaw(record.prepared.payload)
        if (
            type(payload) is not dict
            or execution.get("action_id") != record.action_id
            or execution.get("claim_id") != outcome.claim_id
            or execution.get("prepared_action_digest")
            != record.prepared.prepared_action_digest
            or execution.get("artifact_manifest_digest")
            != payload.get("artifact_manifest", {}).get("manifest_digest")
        ):
            raise ReleaseOperationsError("release deployment simulator binding changed")
        before_state = execution["before_state"]
        after_state = execution["after_state"]
        if type(before_state) is not dict or type(after_state) is not dict:
            raise ReleaseOperationsError("release deployment states are invalid")
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "action_id": record.action_id,
            "claim_id": outcome.claim_id,
            "prepared_action_digest": record.prepared.prepared_action_digest,
            "authority_digest": record.authority.authority_digest,
            "receipt_digest": outcome.receipt_digest,
            "expected_generation": execution["expected_generation"],
            "current_generation": after_state["generation"],
            "artifact_manifest_digest": execution["artifact_manifest_digest"],
            "phase_transitions": snapshot["phase_transitions"],
            "fault_point": snapshot["fault_point"],
            "reconciliation_state": outcome.route,
            "before_target_digest": _semantic(
                before_state, "release-local-target-state",
            ),
            "after_target_digest": _semantic(
                after_state, "release-local-target-state",
            ),
        }
        body["observation_digest"] = _semantic(
            body, "release-deployment-observation",
        )
        self._validate_document(
            "urn:gew:schema:release-deployment-observation:1.0.0", body,
        )
        issued = object.__new__(ReleaseDeploymentObservation)
        object.__setattr__(issued, "projection", freeze(body))
        object.__setattr__(issued, "_factory", self)
        self._issued_deployments[id(issued)] = issued
        self._deployment_sessions[id(issued)] = session
        self._deployment_outcomes[id(issued)] = outcome
        operation_id = execution["operation_id"]
        apply_id = self._registry.operation_roles["apply"]
        if operation_id == apply_id and outcome.route in {
            "reconciled-effect-verified", "manual-reconciliation",
        }:
            session._root.bind_original_action(
                claim_id=outcome.claim_id,
                receipt_digest=str(outcome.receipt_digest),
                applied_artifact_digest=str(execution["artifact_manifest_digest"]),
                before_state=before_state,
                after_state=after_state,
            )
        return issued

    def issue_health_observation(
        self,
        *,
        session: LocalReleaseSimulatorSession,
        terminal_observation: ReleaseDeploymentObservation,
    ) -> ReleaseHealthObservation:
        self.require_installed_authority()
        if (
            type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._issued_deployments.get(id(terminal_observation))
            is not terminal_observation
            or self._deployment_sessions.get(id(terminal_observation)) is not session
        ):
            raise ReleaseOperationsError("release health authority is foreign")
        terminal = terminal_observation.to_dict()
        body = session.health_observer.observe(
            expected_generation=terminal["current_generation"],
            expected_artifact_digest=terminal["artifact_manifest_digest"],
        )
        expected = body.pop("observation_digest", None)
        if (
            type(expected) is not str
            or not hmac.compare_digest(
                expected, _semantic(body, "release-health-observation")
            )
        ):
            raise ReleaseOperationsError("release health observation digest changed")
        body["observation_digest"] = expected
        self._validate_document(
            "urn:gew:schema:release-health-observation:1.0.0", body,
        )
        issued = object.__new__(ReleaseHealthObservation)
        object.__setattr__(issued, "projection", freeze(body))
        object.__setattr__(issued, "_factory", self)
        self._issued_health[id(issued)] = issued
        self._health_bindings[id(issued)] = (session, terminal_observation)
        return issued

    def issue_evidence(
        self,
        *,
        task_id: str,
        task_revision: int,
        snapshot_digest: str,
        invalidation_epoch: int,
        graph_ref_pins: Mapping[str, object],
        artifact_manifest: ReleaseArtifactManifest,
        deployment_observation: ReleaseDeploymentObservation,
        health_observation: ReleaseHealthObservation,
        rollback_observation: ReleaseDeploymentObservation | None,
        session: LocalReleaseSimulatorSession,
        owner_route: str,
        column_id: str,
        scenario_id: str,
        outcome: str,
    ) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if (
            self._issued_manifests.get(id(artifact_manifest)) is not artifact_manifest
            or self._issued_deployments.get(id(deployment_observation))
            is not deployment_observation
            or self._issued_health.get(id(health_observation)) is not health_observation
            or (
                rollback_observation is not None
                and self._issued_deployments.get(id(rollback_observation))
                is not rollback_observation
            )
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._deployment_sessions.get(id(deployment_observation)) is not session
            or (
                rollback_observation is not None
                and self._deployment_sessions.get(id(rollback_observation)) is not session
            )
            or self._health_bindings.get(id(health_observation))
            != (
                session,
                rollback_observation
                if rollback_observation is not None
                else deployment_observation,
            )
        ):
            raise ReleaseOperationsError("release evidence component authority is foreign")
        deployment = deployment_observation.to_dict()
        health = health_observation.to_dict()
        rollback = (
            None if rollback_observation is None else rollback_observation.to_dict()
        )
        current_target = session.observer.observe()
        scenario_matches = tuple(
            row for row in self._registry.policy["scenarios"]
            if scenario_id == (
                "GEW-PSC-RELEASE-OPERATIONS-"
                + str(row["scenario_id"]).upper()
                + "-P"
            )
        )
        if len(scenario_matches) != 1:
            raise ReleaseOperationsError(
                "release evidence scenario is not a configured positive case"
            )
        scenario = scenario_matches[0]
        partial = scenario["scenario_id"] == "partial-deploy"
        if column_id in {"recovery", "rollback"} and not partial:
            raise ReleaseOperationsError("release action column requires completed compensation")
        terminal = rollback if rollback is not None else deployment
        if (
            health["outcome"] != self._registry.health_outcomes["healthy"]
            or outcome != scenario["success_outcome"]
            or deployment["artifact_manifest_digest"]
            != artifact_manifest.manifest_digest
            or (
                partial
                and (
                    deployment["reconciliation_state"] != "manual-reconciliation"
                    or rollback is None
                    or rollback["reconciliation_state"]
                    != "compensation-reconciled"
                    or owner_route
                    != self._registry.policy["rollback_policy"]["owner_route"]
                )
            )
            or (
                not partial
                and (
                    deployment["reconciliation_state"]
                    != "reconciled-effect-verified"
                    or rollback is not None
                    or owner_route != deployment["reconciliation_state"]
                )
            )
        ):
            raise ReleaseOperationsError(
                "release evidence scenario/health/rollback semantics changed"
            )
        if (
            health["task_id"] != task_id
            or current_target.get("target_id") != health["target_id"]
            or current_target.get("state", {}).get("generation") != health["generation"]
            or current_target.get("state", {}).get("active_artifact_digest")
            != health["active_artifact_digest"]
            or health["active_artifact_digest"]
            != terminal["artifact_manifest_digest"]
            or _semantic(
                {
                    "schema_version": "1.0.0",
                    **current_target.get("state", {}),
                },
                "release-local-target-state",
            ) != terminal["after_target_digest"]
            or (
                rollback is not None
                and rollback["action_id"] == deployment["action_id"]
            )
        ):
            raise ReleaseOperationsError("release evidence components do not bind")
        current_target_digest = _semantic(
            current_target, "release-current-target-observation",
        )
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "evidence_kind": self._registry.policy[
                "artifact_policy"
            ]["allowed_evidence_kind"],
            "task_id": task_id,
            "task_revision": task_revision,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": invalidation_epoch,
            "profile_id": "release-operations",
            "profile_version": "1.0.0",
            "graph_ref_pins": copy.deepcopy(dict(graph_ref_pins)),
            "installation_pins": {
                "bootstrap_id": self._bootstrap["bootstrap_id"],
                "bootstrap_digest": self._bootstrap["bootstrap_digest"],
                "policy_registry_digest": self._bootstrap["policy_registry_digest"],
                "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
                "profile_schema_registry_digest": self._bootstrap[
                    "profile_schema_registry_digest"
                ],
                "protected_closure_digest": self._bootstrap[
                    "protected_closure_digest"
                ],
            },
            "artifact_manifest": artifact_manifest.to_dict(),
            "artifact_manifest_digest": artifact_manifest.manifest_digest,
            "deployment_observation": deployment,
            "deployment_observation_digest": deployment["observation_digest"],
            "health_observation": health,
            "health_observation_digest": health["observation_digest"],
            "rollback_observation": rollback,
            "rollback_observation_digest": (
                None if rollback is None else rollback["observation_digest"]
            ),
            "current_target": current_target,
            "current_target_digest": current_target_digest,
            "claim_id": deployment["claim_id"],
            "receipt_digest": deployment["receipt_digest"],
            "owner_route": owner_route,
            "column_id": column_id,
            "scenario_id": scenario_id,
            "outcome": outcome,
        }
        for field in (
            "snapshot_digest", "artifact_manifest_digest",
            "deployment_observation_digest", "health_observation_digest",
            "current_target_digest", "receipt_digest",
        ):
            if type(body[field]) is not str or SEMANTIC_DIGEST.fullmatch(body[field]) is None:
                raise ReleaseOperationsError(f"release {field} is invalid")
        if (
            type(task_id) is not str or not task_id
            or type(task_revision) is not int or task_revision < 1
            or type(invalidation_epoch) is not int or invalidation_epoch < 0
            or type(graph_ref_pins) is not dict
            or set(graph_ref_pins) != _GRAPH_PIN_FIELDS
            or any(
                type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None
                for value in graph_ref_pins.values()
            )
            or type(body["claim_id"]) is not str
            or not str(body["claim_id"]).startswith("claim:")
            or any(
                type(item) is not str or not item
                for item in (owner_route, column_id, scenario_id, outcome)
            )
        ):
            raise ReleaseOperationsError("release evidence binding is invalid")
        body["observation_digest"] = _semantic(body, "release-operations-observation")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", body,
        )
        binding = (session, deployment_observation, rollback_observation)
        self._require_live_projection(body, binding)
        evidence = object.__new__(ReleaseOperationsEvidence)
        object.__setattr__(evidence, "projection", freeze(body))
        object.__setattr__(evidence, "_factory", self)
        self._issued[id(evidence)] = evidence
        self._evidence_bindings[id(evidence)] = binding
        return evidence

    def _require_live_projection(
        self,
        projection: Mapping[str, object],
        binding: tuple[
            LocalReleaseSimulatorSession, ReleaseDeploymentObservation,
            ReleaseDeploymentObservation | None,
        ],
    ) -> None:
        """Revalidate process-local authority without replaying an action."""

        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.core.actions import ActionJournalRecord

        session, deployment, rollback = binding
        coordinator = self._session_coordinators.get(id(session))
        observations = (deployment,) if rollback is None else (deployment, rollback)
        if (
            type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or type(coordinator) is not ActionCoordinator
            or any(
                self._issued_deployments.get(id(item)) is not item
                or self._deployment_sessions.get(id(item)) is not session
                for item in observations
            )
        ):
            raise ReleaseOperationsError("release live authority is missing or foreign")
        terminal = rollback if rollback is not None else deployment
        try:
            if session._root._retained_lease is not None:
                session._root._require_open()
            # A compensated manual observation is history, not a live outcome.
            coordinator.require_issued_outcome(self._deployment_outcomes.get(id(terminal)))
            for item in observations:
                value = item.to_dict()
                record = coordinator._journal.load(value["action_id"])
                expected_state = (
                    "compensated" if item is deployment and rollback is not None
                    else "reconciled"
                )
                if (
                    type(record) is not ActionJournalRecord
                    or record.state != expected_state
                    or record.authority is None
                    or record.receipt is None
                    or record.prepared.prepared_action_digest != value["prepared_action_digest"]
                    or record.authority.authority_digest != value["authority_digest"]
                    or record.receipt.get("receipt_digest") != value["receipt_digest"]
                    or record.receipt.get("claim_id") != value["claim_id"]
                    or record.prepared.target_id != session.target.target_id
                    or record.prepared.target_digest != session.target.target_digest
                ):
                    raise ReleaseOperationsError("release live journal/receipt changed")
            terminal_body = terminal.to_dict()
            health = session.health_observer.observe(
                expected_generation=terminal_body["current_generation"],
                expected_artifact_digest=terminal_body["artifact_manifest_digest"],
            )
            current = session.observer.observe()
        except (ValueError, OSError) as error:
            raise ReleaseOperationsError("release live authority is no longer current") from error
        previous = projection["current_target"]
        if (
            health != projection["health_observation"]
            or {key: value for key, value in current.items() if key != "observation_revision"}
            != {key: value for key, value in previous.items() if key != "observation_revision"}
            or current["observation_revision"] <= previous["observation_revision"]
        ):
            raise ReleaseOperationsError("release live target/health changed")

    def require_current(self, evidence: object) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if (
            type(evidence) is not ReleaseOperationsEvidence
            or evidence._factory is not self
            or self._issued.get(id(evidence)) is not evidence
        ):
            raise ReleaseOperationsError("release evidence is missing, cloned, or foreign")
        projection = evidence.to_dict()
        if set(projection) != set(_PROJECTION_FIELDS):
            raise ReleaseOperationsError("release evidence projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", projection,
        )
        expected = projection.pop("observation_digest")
        self._require_nested_projection(projection)
        if not hmac.compare_digest(
            str(expected), _semantic(projection, "release-operations-observation")
        ):
            raise ReleaseOperationsError("release evidence changed")
        binding = self._evidence_bindings.get(id(evidence))
        if binding is None:
            raise ReleaseOperationsError("release evidence has no live authority binding")
        self._require_live_projection(projection, binding)
        return evidence

    def _require_nested_projection(self, projection: Mapping[str, object]) -> None:
        manifest = ReleaseArtifactManifest.from_dict(projection["artifact_manifest"])
        deployment = projection["deployment_observation"]
        health = projection["health_observation"]
        rollback = projection["rollback_observation"]
        current_target = projection["current_target"]
        if any(type(value) is not dict for value in (deployment, health, current_target)):
            raise ReleaseOperationsError("release nested projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-artifact-manifest:1.0.0",
            projection["artifact_manifest"],
        )
        self._validate_document(
            "urn:gew:schema:release-deployment-observation:1.0.0", deployment,
        )
        self._validate_document(
            "urn:gew:schema:release-health-observation:1.0.0", health,
        )
        for value, name, digest_field in (
            (deployment, "release-deployment-observation", "deployment_observation_digest"),
            (health, "release-health-observation", "health_observation_digest"),
            (current_target, "release-current-target-observation", "current_target_digest"),
        ):
            body = copy.deepcopy(value)
            embedded = body.pop("observation_digest", None) if name != "release-current-target-observation" else None
            calculated = _semantic(body if embedded is not None else value, name)
            expected = projection[digest_field]
            if embedded is not None and embedded != expected:
                raise ReleaseOperationsError("release nested observation binding changed")
            if not hmac.compare_digest(str(expected), calculated):
                raise ReleaseOperationsError("release nested observation digest changed")
        if manifest.manifest_digest != projection["artifact_manifest_digest"]:
            raise ReleaseOperationsError("release nested manifest digest changed")
        if rollback is None:
            if projection["rollback_observation_digest"] is not None:
                raise ReleaseOperationsError("release rollback absence changed")
        else:
            if type(rollback) is not dict:
                raise ReleaseOperationsError("release rollback projection is not exact")
            self._validate_document(
                "urn:gew:schema:release-deployment-observation:1.0.0", rollback,
            )
            body = copy.deepcopy(rollback)
            embedded = body.pop("observation_digest", None)
            expected = projection["rollback_observation_digest"]
            if (
                embedded != expected
                or type(expected) is not str
                or not hmac.compare_digest(
                    expected, _semantic(body, "release-deployment-observation")
                )
            ):
                raise ReleaseOperationsError("release rollback observation changed")

    def projection(self, evidence: object) -> FrozenMap:
        return self.require_current(evidence).projection

    def restore_projection(self, projection: Mapping[str, object]) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if type(projection) is not dict or set(projection) != set(_PROJECTION_FIELDS):
            raise ReleaseOperationsError("stored release projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", projection,
        )
        body = copy.deepcopy(dict(projection))
        expected = body.pop("observation_digest", None)
        if (
            type(expected) is not str
            or not hmac.compare_digest(
                expected, _semantic(body, "release-operations-observation")
            )
        ):
            raise ReleaseOperationsError("stored release projection changed")
        self._require_nested_projection(body)
        expected_installation = {
            "bootstrap_id": self._bootstrap["bootstrap_id"],
            "bootstrap_digest": self._bootstrap["bootstrap_digest"],
            "policy_registry_digest": self._bootstrap["policy_registry_digest"],
            "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            "profile_schema_registry_digest": self._bootstrap[
                "profile_schema_registry_digest"
            ],
            "protected_closure_digest": self._bootstrap[
                "protected_closure_digest"
            ],
        }
        if body.get("installation_pins") != expected_installation:
            raise ReleaseOperationsError("stored release installation pins changed")
        owned = [evidence for evidence in self._issued.values()
            if evidence.projection == freeze(projection)]
        if len(owned) == 1:
            return self.require_current(owned[0])
        raise ReleaseOperationsError(
            "stored release projection requires live target/journal revalidation"
        )
