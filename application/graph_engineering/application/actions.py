"""Application-owned prepare/authorize/execute/reconcile protocol."""

from __future__ import annotations

import datetime
import hmac
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Protocol
from weakref import WeakKeyDictionary

from graph_engineering.core.actions import (
    ActionGateError,
    ActionPolicy,
    AuthorityEnvelope,
    ExecuteGateDecisionTable,
    PreparedAction,
)
from graph_engineering.core.security._common import parse_timestamp, require_id
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.security.disclosure import DataDisclosurePlan
from graph_engineering.application.security import SecurityContextIssuer
from graph_engineering.application.tasks import action_task_snapshot
from graph_engineering.storage.actions import ActionJournalRepository
from graph_engineering.storage.codec import canonical_json, semantic_record_digest
from graph_engineering.storage.errors import RepositoryConflictError
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.ports import CommitBatch, LeaseGrant
from graph_engineering.storage.repository import TaskRepository, make_event


class ActionTargetPort(Protocol):
    is_test_double: bool
    target_id: str
    target_digest: str
    resource_id: str
    capabilities: tuple[str, ...]

    def invoke(self, *, payload: dict[str, object], fencing_token: int, started_was_durable: bool) -> dict[str, object]: ...


class ActionObserverPort(Protocol):
    is_test_double: bool
    is_read_only_observer: bool
    target_id: str
    target_digest: str
    resource_id: str
    capabilities: tuple[str, ...]

    def observe(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True, init=False)
class ActionOutcome:
    action_id: str
    state: str
    route: str
    claim_id: str
    receipt_digest: str | None


class _DurableExecutionGate:
    """Target-visible one-shot consume facet with no arming capability."""

    __slots__ = ("__weakref__",)

    def consume(
        self,
        *,
        payload: dict[str, object],
        fencing_token: int,
        started_was_durable: bool,
    ) -> MappingProxyType[str, object]:
        registry = _DURABLE_EXECUTION_GATE_REGISTRIES.get(self)
        if registry is None:
            raise ValueError("durable execution gate is not coordinator-issued")
        return registry.consume(
            self,
            payload=payload,
            fencing_token=fencing_token,
            started_was_durable=started_was_durable,
        )


class _DurableExecutionGateRegistry:
    """Coordinator-owned arming state, never handed to an action target."""

    def __init__(self) -> None:
        self._issued: dict[int, _DurableExecutionGate] = {}
        self._bindings: dict[int, MappingProxyType[str, object]] = {}
        self._consumed: set[int] = set()

    def issue(self) -> _DurableExecutionGate:
        gate = _DurableExecutionGate()
        self._issued[id(gate)] = gate
        _DURABLE_EXECUTION_GATE_REGISTRIES[gate] = self
        return gate

    def arm(
        self,
        gate: _DurableExecutionGate,
        *,
        action_id: str,
        claim_id: str,
        prepared_action_digest: str,
        payload: dict[str, object],
        fencing_token: int,
    ) -> None:
        key = id(gate)
        if self._issued.get(key) is not gate or key in self._bindings:
            raise ValueError("durable execution gate authority or lifecycle changed")
        if (
            type(action_id) is not str or not action_id
            or type(claim_id) is not str or not claim_id.startswith("claim:")
            or type(prepared_action_digest) is not str
            or type(payload) is not dict
            or type(fencing_token) is not int or fencing_token <= 0
        ):
            raise ValueError("durable execution gate binding is invalid")
        exact_payload = thaw(payload)
        if type(exact_payload) is not dict:
            raise ValueError("durable execution gate payload did not thaw exactly")
        self._bindings[key] = MappingProxyType({
            "action_id": action_id,
            "claim_id": claim_id,
            "prepared_action_digest": prepared_action_digest,
            "payload": exact_payload,
            "fencing_token": fencing_token,
        })
        self._consumed.discard(key)

    def consume(
        self,
        gate: _DurableExecutionGate,
        *,
        payload: dict[str, object],
        fencing_token: int,
        started_was_durable: bool,
    ) -> MappingProxyType[str, object]:
        key = id(gate)
        binding = self._bindings.get(key)
        if (
            self._issued.get(key) is not gate
            or binding is None or key in self._consumed
            or started_was_durable is not True
            or type(payload) is not dict
            or payload != binding["payload"]
            or type(fencing_token) is not int
            or fencing_token != binding["fencing_token"]
        ):
            raise ValueError("durable execution gate is absent, consumed, or mismatched")
        self._consumed.add(key)
        return binding

    def disarm(self, gate: _DurableExecutionGate) -> None:
        key = id(gate)
        if self._issued.get(key) is not gate:
            raise ValueError("durable execution gate authority changed")
        self._bindings.pop(key, None)
        self._consumed.discard(key)


_DURABLE_EXECUTION_GATE_REGISTRIES: WeakKeyDictionary[
    _DurableExecutionGate, _DurableExecutionGateRegistry
] = WeakKeyDictionary()


class ActionCoordinator:
    """The only application path that may cross the action call boundary."""

    def __init__(
        self,
        *,
        journal: ActionJournalRepository,
        repository: TaskRepository,
        leases: ResourceLeaseRepository,
        locks: LockedFileRegistry,
        objects: ObjectRepository,
        security_issuer: SecurityContextIssuer,
        action_policy: ActionPolicy,
        installation_scope: object,
        action_adapter_factory: object | None = None,
        concrete_action_policy: object | None = None,
        concrete_action_registry: object | None = None,
        fault_hook: Callable[[str], None] = lambda _step: None,
    ) -> None:
        if not all((
            type(journal) is ActionJournalRepository,
            type(repository) is TaskRepository,
            type(leases) is ResourceLeaseRepository,
            type(locks) is LockedFileRegistry,
            type(objects) is ObjectRepository,
            type(security_issuer) is SecurityContextIssuer,
        )):
            raise ValueError("action coordinator requires exact durable dependencies")
        if type(action_policy) is not ActionPolicy:
            raise ValueError("action coordinator policy is missing or forged")
        if action_policy.real_external_actions_enabled:
            from graph_engineering.adapters.action_adapters import ActionAdapterFactory
            from graph_engineering.core.action_adapters import ActionAdapterRegistry, ConcreteActionPolicy
            if (
                type(action_adapter_factory) is not ActionAdapterFactory
                or type(concrete_action_policy) is not ConcreteActionPolicy
                or type(concrete_action_registry) is not ActionAdapterRegistry
            ):
                raise ValueError("real action coordinator requires exact concrete adapter authority")
            try:
                action_adapter_factory.require_binding(
                    concrete_action_policy,
                    concrete_action_registry,
                    action_policy,
                )
            except ValueError as error:
                raise ValueError("real action coordinator concrete adapter authority changed") from error
        elif any(item is not None for item in (
            action_adapter_factory, concrete_action_policy, concrete_action_registry,
        )):
            raise ValueError("disabled real action policy cannot receive concrete adapter authority")
        self._journal = journal
        self._repository = repository
        self._leases = leases
        self._locks = locks
        self._objects = objects
        self._issuer = security_issuer
        self._policy = action_policy
        self._action_adapter_factory = action_adapter_factory
        self._concrete_action_policy = concrete_action_policy
        self._concrete_action_registry = concrete_action_registry
        self._fault = fault_hook
        self._durable_execution_gates = _DurableExecutionGateRegistry()
        self._issued_outcomes: dict[int, ActionOutcome] = {}
        self._retained_targets: dict[tuple[str, str], object] = {}
        self._retained_actions: dict[str, object] = {}
        self._retained_prepared: dict[str, object] = {}
        from graph_engineering.storage.migration import InstallationCommandScope
        if type(installation_scope) is not InstallationCommandScope:
            raise ValueError("action installation command scope is missing or forged")
        installation_scope.require_current()
        if not repository.command_context_bound or repository.command_scope is not installation_scope:
            raise ValueError("action repository is not bound to the installation command scope")
        self._installation_validator: Callable[[], None] = installation_scope.require_current

    def _require_installation_context(self) -> None:
        self._installation_validator()

    def _retained_scope(self, *, require_idle: bool = False) -> object:
        """Check existing ports/lock state without changing storage lock APIs."""

        self._require_installation_context()
        scope = self._repository.command_scope
        for port in (self._repository, self._journal, self._leases, self._objects, self._issuer._repository):
            factory = port._factory
            if factory._command_scope is not scope or factory.data_root != scope.repository_root:
                raise ValueError("retained release repository scope differs across ports")
        self._locks._check()
        if self._locks._root != scope.repository_root:
            raise ValueError("retained release repository lock scope differs")
        if require_idle:
            self._require_retained_idle()
        return scope

    def _require_retained_idle(self) -> None:
        # Cleanup must still work after runtime revocation; it only checks order.
        with LockedFileRegistry._ACTIVE_GUARD:
            registries = tuple(LockedFileRegistry._ACTIVE_ROOTS.values())
        held = False
        for registry in registries:
            with registry._registry_guard:
                held = held or bool(registry._thread_tokens.get(threading.get_ident()))
        if held or self._repository.command_scope._connections:
            raise ValueError("retained release repository token or connection is held")

    def _register_retained_target(self, task_id: str, session: object) -> None:
        from graph_engineering.adapters.local_release_simulator import LocalReleaseSimulatorSession

        if type(session) is not LocalReleaseSimulatorSession or session.recovery_binding is None:
            raise ValueError("retained release session is not exact")
        self._retained_scope(require_idle=True)
        session._root._require_open()
        key = (task_id, session.target.target_id)
        if key in self._retained_targets:
            raise ValueError("retained release target is already registered")
        self._retained_targets[key] = session

    def _require_retained_action(self, action_id: str, *, target: object | None = None,
                                 observer: object | None = None) -> None:
        session = self._retained_actions.get(action_id)
        if session is not None:
            self._retained_scope(require_idle=True)
            session._root._require_open()
            if target is not None and target is not session.target:
                raise ValueError("retained release action target is foreign")
            if observer is not None and observer is not session.observer:
                raise ValueError("retained release action observer is foreign")
        from graph_engineering.adapters.local_release_simulator import LocalReleaseObserver, LocalReleaseTarget

        if type(target) is LocalReleaseTarget and target._root._retained_lease is not None:
            if session is None or target is not session.target:
                raise ValueError("retained release action has no live coordinator binding")
        if type(observer) is LocalReleaseObserver and observer._root._retained_lease is not None:
            if session is None or observer is not session.observer:
                raise ValueError("retained release observer has no live coordinator binding")

    def issue_durable_execution_gate(self) -> object:
        """Issue an opaque gate that only this coordinator can arm after start commit."""

        self._require_installation_context()
        return self._durable_execution_gates.issue()

    def _issue_outcome(
        self,
        action_id: str,
        state: str,
        route: str,
        claim_id: str,
        receipt_digest: str | None,
    ) -> ActionOutcome:
        outcome = object.__new__(ActionOutcome)
        object.__setattr__(outcome, "action_id", action_id)
        object.__setattr__(outcome, "state", state)
        object.__setattr__(outcome, "route", route)
        object.__setattr__(outcome, "claim_id", claim_id)
        object.__setattr__(outcome, "receipt_digest", receipt_digest)
        self._issued_outcomes[id(outcome)] = outcome
        return outcome

    def require_issued_outcome(self, outcome: object) -> ActionOutcome:
        """Rebind an outcome to current durable journal, claim, and receipt state."""

        self._require_installation_context()
        if (
            type(outcome) is not ActionOutcome
            or self._issued_outcomes.get(id(outcome)) is not outcome
        ):
            raise ValueError("action outcome is missing, forged, or foreign")
        record = self._journal.load(outcome.action_id)
        claim = self._leases.load_claim(outcome.claim_id)
        expected_states = {
            "manual-reconciliation": {"executing", "unknown"},
            "manual-target-reconciliation": {"succeeded"},
            "reconciled-effect-verified": {"reconciled"},
            "reconciled-no-effect": {"reconciled"},
            "compensation-reconciled": {"compensated"},
        }
        if (
            outcome.claim_id != f"claim:{outcome.action_id}"
            or outcome.route not in expected_states
            or record.state not in expected_states[outcome.route]
            or claim.get("action_id") != outcome.action_id
        ):
            raise ValueError("action outcome no longer matches durable state")
        if outcome.route == "compensation-reconciled":
            attempt = self._leases.recovery_attempt(outcome.claim_id)
            receipt = None if attempt is None else attempt.get("receipt")
            expected_receipt = (
                receipt.get("receipt_digest") if isinstance(receipt, dict) else None
            )
        else:
            expected_receipt = (
                record.receipt.get("receipt_digest")
                if isinstance(record.receipt, dict) else None
            )
        if outcome.receipt_digest != expected_receipt:
            raise ValueError("action outcome receipt no longer matches durable state")
        unresolved = outcome.route in {
            "manual-reconciliation", "manual-target-reconciliation",
        }
        if (claim.get("state") == "unresolved") is not unresolved:
            raise ValueError("action outcome claim no longer matches durable state")
        return outcome

    def _read_action_authority(self, *, task_id: str, action_id: str) -> FrozenMap:
        """Read terminal prepared/authority facts, without issuing a capability.

        This is only the authorization input to a future recovery resolver.
        It does not prove claim, receipt, compensation or assessment completion.
        The resolver must separately own current runtime/root read authority.
        Historical execution expiry is not a reason to renew or execute here.
        """
        require_id(task_id, "read-only action task ID")
        require_id(action_id, "read-only action ID")
        self._retained_scope(require_idle=True)

        def read() -> FrozenMap:
            self._retained_scope(require_idle=True)
            record = self._journal.load(action_id)
            if (
                record.action_id != action_id or record.task_id != task_id
                or record.state not in {"reconciled", "compensated"}
                or record.authority is None
            ):
                raise ValueError("read-only action is not a terminal authorized record")
            prepared_document = thaw(freeze(self._journal.prepared_document(record.prepared)))
            authority_document = self._journal.authority_document(record.authority)
            prepared = self._policy.load_prepared(prepared_document)
            authority = self._policy.load_authority(authority_document)
            if (
                prepared.action_id != action_id or prepared.task_id != task_id
                or authority.task_id != task_id or authority.status != "active"
                or prepared.action_kind not in self._policy.separately_authorized_action_kinds
                or authority.prepared_action_digest != prepared.prepared_action_digest
                or authority.authorized_action_kind != prepared.action_kind
                or authority.authorized_resources != prepared.resources
                or authority.baseline_digest != prepared.baseline_digest
                or authority.snapshot_digest != prepared.snapshot_digest
                or self._journal.find_prepared(prepared.prepared_action_digest) != record
            ):
                raise ValueError("read-only authority does not bind the exact prepared action")

            security = self._issuer.read_task_state(task_id)
            self._issuer.runtime.require_policy("action", self._policy.policy_id, self._policy.policy_digest)
            if self._policy._runtime_issuer is not self._issuer.runtime._issuer:
                raise ValueError("read-only action policy has a foreign security issuer")
            if self._policy.real_external_actions_enabled:
                self._action_adapter_factory.require_binding(
                    self._concrete_action_policy, self._concrete_action_registry, self._policy)
            owner = security.state["binding"]
            targets = [target for target in owner["targets"] if target["target_id"] == prepared.target_id]
            if (
                owner["task_id"] != task_id
                or authority.owner_id != owner["owner_id"]
                or authority.runtime_kind != owner["runtime_kind"]
                or authority.runtime_lineage_id != owner["runtime_lineage_id"]
                or prepared.baseline_digest != owner["baselines"].get("intent")
                or authority.authority_digest not in security.state["authority_digests"]
                or len(targets) != 1 or targets[0]["target_digest"] != prepared.target_digest
            ):
                raise ValueError("read-only action authority is revoked or foreign to the current task")
            self._retained_scope(require_idle=True)
            result = freeze({
                "task_id": task_id, "action_id": action_id,
                "journal_state": record.state, "journal_revision": record.revision,
                "prepared": prepared_document, "authority": authority_document,
                "security_state_digest": security.state_digest,
                "runtime_manifest_digest": security.runtime_manifest_digest,
            })
            assert type(result) is FrozenMap
            return result

        first, current = read(), read()
        if first != current:
            raise ValueError("read-only action authority changed during query")
        return current


    def _read_completed_action_provenance(self, *, task_id: str, action_id: str) -> FrozenMap:
        """Read completion facts under current authority, without issuing a gate."""
        require_id(task_id, "read-only action task ID")
        require_id(action_id, "read-only action ID")
        self._retained_scope(require_idle=True)
        if any(getattr(port, "_recovery_read_budget", None) is not None for port in
                (self, self._repository, self._objects, self._journal, self._issuer, self._issuer._repository,
                 self._policy._context, self._journal._context, self._issuer._context)):
            return self._read_completed_action_provenance_bounded(task_id, action_id)

        def read() -> FrozenMap:
            provenance = self._repository.read_action_provenance(task_id, action_id)
            authorities = []
            for journal in provenance["journals"]:
                authority = self._read_action_authority(task_id=task_id, action_id=journal["action_id"])
                if (authority["journal_state"] != journal["state"]
                        or authority["journal_revision"] != journal["revision"]
                        or authority["prepared"] != journal["prepared"]
                        or authority["authority"] != journal["authority"]
                        or authority["prepared"]["prepared_action_digest"] != journal["prepared_digest"]
                        or authority["authority"]["authority_digest"] != journal["authority_digest"]):
                    raise ValueError("completed action authority differs from captured provenance")
                authorities.append(authority)
            completion = self._validate_completed_action_provenance(provenance, action_id)
            self._retained_scope(require_idle=True)
            return freeze({"task_id": task_id, "action_id": action_id, "completion": completion,
                           "provenance": provenance, "authorities": authorities})

        first, current = read(), read()
        if first != current:
            raise ValueError("completed action provenance changed during query")
        return current

    def _read_captured_action_authority(self, task_id, journal, budget):
        """Validate internally captured journals without a second legacy query."""
        from contextlib import ExitStack
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.storage.repository import _recovery_freeze

        context = self._policy._context
        size = canonical_byte_length(journal)
        with ExitStack() as stack:
            stack.enter_context(budget.reserve(context, units=12 * size, byte_count=4 * size,
                source_id="captured-action-authority"))
            value = thaw(journal)
            if (value["task_id"] != task_id or value["state"] not in {"reconciled", "compensated"}
                    or type(value["authority"]) is not dict):
                raise ValueError("read-only action is not a terminal authorized record")
            prepared = self._policy.load_prepared(value["prepared"])
            authority = self._policy.load_authority(value["authority"])
            if (prepared.action_id != value["action_id"] or prepared.task_id != task_id
                    or authority.task_id != task_id or authority.status != "active"
                    or prepared.action_kind not in self._policy.separately_authorized_action_kinds
                    or authority.prepared_action_digest != prepared.prepared_action_digest
                    or authority.authorized_action_kind != prepared.action_kind
                    or authority.authorized_resources != prepared.resources
                    or authority.baseline_digest != prepared.baseline_digest
                    or authority.snapshot_digest != prepared.snapshot_digest
                    or value["prepared_digest"] != prepared.prepared_action_digest
                    or value["authority_digest"] != authority.authority_digest):
                raise ValueError("read-only authority does not bind the exact prepared action")
            security = self._issuer.read_task_state(task_id)
            stack.callback(budget.release_projection, security)
            self._issuer.runtime.require_policy("action", self._policy.policy_id, self._policy.policy_digest)
            if self._policy._runtime_issuer is not self._issuer.runtime._issuer:
                raise ValueError("read-only action policy has a foreign security issuer")
            if self._policy.real_external_actions_enabled:
                self._action_adapter_factory.require_binding(
                    self._concrete_action_policy, self._concrete_action_registry, self._policy)
            owner = security.state["binding"]
            targets = [target for target in owner["targets"] if target["target_id"] == prepared.target_id]
            if (owner["task_id"] != task_id or authority.owner_id != owner["owner_id"]
                    or authority.runtime_kind != owner["runtime_kind"]
                    or authority.runtime_lineage_id != owner["runtime_lineage_id"]
                    or prepared.baseline_digest != owner["baselines"].get("intent")
                    or authority.authority_digest not in security.state["authority_digests"]
                    or len(targets) != 1 or targets[0]["target_digest"] != prepared.target_digest):
                raise ValueError("read-only action authority is revoked or foreign to the current task")
            return _recovery_freeze({"task_id": task_id, "action_id": prepared.action_id,
                "journal_state": value["state"], "journal_revision": value["revision"],
                "prepared": value["prepared"], "authority": value["authority"],
                "security_state_digest": security.state_digest,
                "runtime_manifest_digest": security.runtime_manifest_digest},
                context, budget, source_id="captured-action-authority")

    def _read_completed_action_provenance_bounded(self, task_id, action_id):
        from contextlib import ExitStack
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.storage.repository import _RecoveryReadBudget, _recovery_freeze, _recovery_equal

        context = self._policy._context
        budget = getattr(context, "_recovery_read_budget", None)
        if (type(budget) is not _RecoveryReadBudget or budget.task_id != task_id
                or budget.command_scope is not self._repository.command_scope
                or any(getattr(port, "_recovery_read_budget", None) is not budget
                       for port in (self, self._repository, self._objects, self._journal,
                                    self._issuer, self._issuer._repository, self._policy._context,
                                    self._journal._context, self._issuer._context))):
            raise ValueError("completed action has no exact recovery owner")
        budget._require_active()

        def read() -> FrozenMap:
            self._retained_scope(require_idle=True)
            with ExitStack() as stack:
                provenance = self._repository.read_action_provenance(task_id, action_id)
                stack.callback(budget.release_projection, provenance)
                authorities = []
                for journal in provenance["journals"]:
                    authority = self._read_captured_action_authority(task_id, journal, budget)
                    stack.callback(budget.release_projection, authority)
                    authorities.append(authority)
                size = canonical_byte_length(provenance)
                # The bounded validator walks the immutable capture directly.
                # Its index/selector slots and one narrow digest buffer stay
                # below this whole-document bound; no mutable full copy exists.
                with budget.reserve(context, units=4 * size, byte_count=2 * size,
                        source_id="completed-action-validation"):
                    completion = self._validate_completed_action_provenance(
                        provenance, action_id, _budget=budget, _context=context)
                self._retained_scope(require_idle=True)
                return _recovery_freeze({"task_id": task_id, "action_id": action_id,
                    "completion": completion, "provenance": provenance, "authorities": authorities},
                    context, budget, source_id="completed-action-result")

        first, current = read(), None
        try:
            current = read()
            if not _recovery_equal(first, current, context, budget):
                raise ValueError("completed action provenance changed during query")
            return current
        except BaseException:
            if current is not None:
                budget.release_projection(current)
            raise
        finally:
            budget.release_projection(first)

    @staticmethod
    def _validate_completed_action_provenance(provenance: FrozenMap, action_id: str,
                                             *, _budget=None, _context=None) -> str:
        """Join persisted facts; every successful branch has an exact history."""
        from graph_engineering.storage.codec import require_jcs_digest

        value = thaw(provenance) if _budget is None else provenance
        task_id = value["task"]["task_id"]
        journals = {journal["action_id"]: journal for journal in value["journals"]}
        original = journals[action_id]
        prepared, authority = original["prepared"], original["authority"]
        claim, recovery = value["claim"], value["recovery"]
        claim_id = "claim:" + action_id
        events = value["events"]
        by_transaction = {}
        for entry in events:
            by_transaction.setdefault(entry["transaction_id"], []).append(entry)
        target_resources = [resource for resource in prepared["resources"] if resource != "task:" + task_id]
        if (len(target_resources) != 1 or claim["claim_id"] != claim_id or claim["revision"] != 2
                or claim["resources"] != prepared["resources"]
                or set(claim["fencing_tokens"]) != set(prepared["resources"])
                or "task:" + task_id not in prepared["resources"]):
            raise ValueError("completed action original claim resources differ")
        target_resource = target_resources[0]
        used = set()

        def same(left: object, right: object) -> bool:
            # JSON booleans and numbers are distinct even though True == 1 in Python.
            if _budget is not None:
                from graph_engineering.storage.repository import _recovery_equal
                return _recovery_equal(left, right, _context, _budget)
            return canonical_json(left) == canonical_json(right)

        def one(kind: str, identifiers: Mapping[str, object], *, required: bool=True) -> Mapping[str, object] | None:
            matches = [entry for entry in events if entry["event"]["event_type"] == kind
                       and any(entry["event"]["payload"].get(key) == item for key, item in identifiers.items())]
            if not matches and not required:
                return None
            if len(matches) != 1:
                raise ValueError("completed action event is missing or ambiguous")
            entry = matches[0]
            if len(by_transaction[entry["transaction_id"]]) != 1:
                raise ValueError("completed action transaction is not a single event")
            used.add(entry["event"]["event_digest"])
            return entry

        def event_matches(entry: Mapping[str, object], payload: Mapping[str, object], baseline: str, actor: Mapping[str, object]) -> None:
            event = entry["event"]
            if (not same(event["payload"], payload) or not same(event["baseline_digests"], [baseline])
                    or not same(event["actor"], actor)):
                raise ValueError("completed action event payload or authority binding differs")

        started = one("action.execution_started", {"action_id": action_id})
        start_payload = {
            "action_id": action_id, "authority_digest": authority["authority_digest"],
            "prepared_action_digest": prepared["prepared_action_digest"],
            "snapshot_digest": prepared["snapshot_digest"], "lease_id": claim["lease_id"],
            "fencing_tokens": claim["fencing_tokens"],
            "disclosure_plan_digest": started["event"]["payload"].get("disclosure_plan_digest"),
        }
        require_jcs_digest(start_payload["disclosure_plan_digest"])
        event_matches(started, start_payload, prepared["baseline_digest"],
                      {"kind": "runtime", "id": authority["runtime_lineage_id"]})
        if claim["started_event_digest"] != started["event"]["event_digest"]:
            raise ValueError("completed action claim start digest differs")

        def receipt_object(receipt: Mapping[str, object], entry: Mapping[str, object]) -> None:
            matches = [item for item in value["receipt_objects"]
                       if item["digest"] == receipt["raw_receipt_object_digest"]]
            refs = [item for item in value["references"]
                    if item["digest"] == receipt["raw_receipt_object_digest"]]
            if len(matches) != 1 or len(refs) != 1:
                raise ValueError("completed action receipt object/reference is ambiguous")
            reference_events = by_transaction.get(refs[0]["transaction_id"], [])
            if (not reference_events or reference_events[0]["transaction_revision"] > entry["transaction_revision"]):
                raise ValueError("completed action receipt reference is foreign or from the future")
            body = matches[0]["document"]
            required = {"schema_version", "contract", "receipt_source", "result"}
            if (type(body) not in (dict, FrozenMap) or set(body) not in (required, required | {"effect"})
                    or body["schema_version"] != "1.0.0" or body["contract"] != "bounded-redacted-fake-receipt-v1"
                    or body["receipt_source"] not in {"tool-return", "post-crash-target-query"}
                    or body["result"] not in {"succeeded", "failed", "unknown"}
                    or body["result"] != receipt["result"]
                    or ("effect" in body and body["effect"] not in {"applied", "none"})
                    or receipt["raw_result_digest"] != semantic_record_digest({
                        "contract": "bounded-redacted-fake-receipt-v1", "value": body})
                    or ("receipt_source" in receipt and receipt["receipt_source"] != body["receipt_source"])):
                raise ValueError("completed action bounded receipt body differs")

        normal_receipt = one("action.receipt_recorded", {"action_id": action_id, "claim_id": claim_id},
                             required=original["receipt"] is not None)
        if original["receipt"] is None:
            if normal_receipt is not None:
                raise ValueError("completed action historical receipt is missing")
        else:
            receipt = original["receipt"]
            expected = {
                "task_id": task_id, "action_id": action_id, "claim_id": claim_id,
                "started_event_digest": claim["started_event_digest"],
                "prepared_action_digest": prepared["prepared_action_digest"],
                "authority_digest": authority["authority_digest"], "payload_digest": prepared["payload_digest"],
                "target_id": prepared["target_id"], "fencing_token": claim["fencing_tokens"][target_resource],
            }
            if not same({key: receipt.get(key) for key in expected}, expected):
                raise ValueError("completed action historical receipt binding differs")
            event_matches(normal_receipt, {
                "action_id": action_id, "claim_id": claim_id, "receipt_digest": receipt["receipt_digest"],
                "raw_receipt_object_digest": receipt["raw_receipt_object_digest"],
            }, prepared["baseline_digest"], {"kind": "deterministic", "id": "action-receipt-recorder"})
            if normal_receipt["event"]["sequence"] <= started["event"]["sequence"]:
                raise ValueError("completed action receipt precedes start")
            receipt_object(receipt, normal_receipt)

        observation = original["reconciliation"]
        if (type(observation) not in (dict, FrozenMap) or observation["target_id"] != prepared["target_id"]
                or observation["target_digest"] != prepared["target_digest"]
                or observation["resource_id"] != target_resource):
            raise ValueError("completed action observation is foreign")
        if recovery is None:
            if (original["state"] != "reconciled" or claim["state"] != "reconciled_effect_verified"
                    or len(journals) != 1 or normal_receipt is None
                    or not same(observation["state"], prepared["expected_postcondition"])
                    or set(observation) != {"target_id", "target_digest", "resource_id", "fresh",
                                            "observation_revision", "state"}):
                raise ValueError("completed action is not normally reconciled")
            reconciled = one("action.reconciled_effect_verified", {"action_id": action_id, "claim_id": claim_id})
            event_matches(reconciled, {"action_id": action_id, "claim_id": claim_id},
                          prepared["baseline_digest"], {"kind": "deterministic", "id": "action-reconciler"})
            if reconciled["event"]["sequence"] <= normal_receipt["event"]["sequence"]:
                raise ValueError("completed action reconciliation precedes receipt")
        else:
            restore = journals[recovery["compensation_action_id"]]
            restored, restore_authority = restore["prepared"], restore["authority"]
            if (original["state"] != "compensated" or claim["state"] != "compensation_reconciled"
                    or recovery["state"] != "reconciled" or recovery["revision"] != 3
                    or recovery["protocol_version"] != "1.0.0" or restore["state"] != "reconciled"
                    or restored["action_kind"] != "rollback" or len(journals) != 2
                    or restored["target_id"] != prepared["target_id"]
                    or restored["target_digest"] != prepared["target_digest"]
                    or restored["resources"] != prepared["resources"]
                    or not same(restored["expected_postcondition"], prepared["precondition"])
                    or not same(observation["state"], restored["expected_postcondition"])
                    or not same(restore["reconciliation"], observation)):
                raise ValueError("completed compensation state or rollback postcondition differs")
            binding = {
                "claim_id": claim_id, "task_id": task_id, "original_action_id": action_id,
                "original_started_event_digest": claim["started_event_digest"],
                "compensation_action_id": restored["action_id"],
                "compensation_authority_digest": restore_authority["authority_digest"],
                "compensation_prepared_digest": restored["prepared_action_digest"],
                "lease_id": claim["lease_id"], "resources": claim["resources"],
                "fencing_tokens": claim["fencing_tokens"], "target_id": restored["target_id"],
                "target_digest": restored["target_digest"], "baseline_digest": restored["baseline_digest"],
                "snapshot_digest": restored["snapshot_digest"],
            }
            if not same({key: recovery.get(key) for key in binding}, binding):
                raise ValueError("completed compensation attempt binding differs")
            expected_attempt_id = ResourceLeaseRepository.compensation_attempt_id(
                {**claim, "revision": claim["revision"] - 1},
                compensation_action_id=restored["action_id"],
                compensation_authority_digest=restore_authority["authority_digest"],
                compensation_prepared_digest=restored["prepared_action_digest"])
            if recovery["attempt_id"] != expected_attempt_id:
                raise ValueError("completed compensation attempt identity differs")
            require_jcs_digest(recovery["disclosure_plan_digest"])
            identifiers = {"attempt_id": recovery["attempt_id"], "claim_id": claim_id,
                           "compensation_action_id": restored["action_id"]}
            restore_started = one("action.compensation_execution_started", identifiers)
            event_matches(restore_started, {
                **binding, "attempt_id": recovery["attempt_id"],
                "disclosure_plan_digest": recovery["disclosure_plan_digest"],
            }, restored["baseline_digest"], {"kind": "runtime", "id": restore_authority["runtime_lineage_id"]})
            if recovery["start_event_digest"] != restore_started["event"]["event_digest"]:
                raise ValueError("completed compensation start digest differs")
            receipt = restore["receipt"]
            if (type(receipt) not in (dict, FrozenMap) or receipt["result"] != "succeeded"
                    or not same(receipt, recovery["receipt"]) or receipt["receipt_digest"] != recovery["receipt_digest"]
                    or receipt["raw_receipt_object_digest"] != recovery["receipt_object_digest"]):
                raise ValueError("completed compensation receipt index differs")
            expected_receipt = {
                "protocol_version": "1.0.0", "attempt_id": recovery["attempt_id"], "claim_id": claim_id,
                "task_id": task_id, "original_action_id": action_id, "compensation_action_id": restored["action_id"],
                "start_event_digest": recovery["start_event_digest"], "authority_digest": restore_authority["authority_digest"],
                "prepared_action_digest": restored["prepared_action_digest"], "target_id": restored["target_id"],
                "target_digest": restored["target_digest"], "lease_id": claim["lease_id"],
                "resources": claim["resources"], "fencing_tokens": claim["fencing_tokens"],
            }
            if not same({key: receipt.get(key) for key in expected_receipt}, expected_receipt):
                raise ValueError("completed compensation receipt identity differs")
            receipt_event = one("action.compensation_receipt_recorded", identifiers)
            event_matches(receipt_event, {
                **identifiers, "start_event_digest": recovery["start_event_digest"], "task_id": task_id,
                "receipt_digest": receipt["receipt_digest"], "raw_receipt_object_digest": receipt["raw_receipt_object_digest"],
                "receipt_source": receipt["receipt_source"], "target_id": restored["target_id"],
                "target_digest": restored["target_digest"], "lease_id": claim["lease_id"],
                "resources": claim["resources"], "fencing_tokens": claim["fencing_tokens"], "result": receipt["result"],
            }, restored["baseline_digest"], {"kind": "deterministic", "id": "compensation-receipt-recorder"})
            if recovery["receipt_event_digest"] != receipt_event["event"]["event_digest"]:
                raise ValueError("completed compensation receipt event differs")
            receipt_object(receipt, receipt_event)
            if observation.get("bound_receipt_digest") != receipt["receipt_digest"]:
                raise ValueError("completed compensation observation is not receipt-bound")
            reconciled = one("action.compensation_reconciled", identifiers)
            event_matches(reconciled, {
                **identifiers, "start_event_digest": recovery["start_event_digest"],
                "receipt_event_digest": recovery["receipt_event_digest"], "receipt_digest": receipt["receipt_digest"],
                "fresh_observation_digest": observation["observation_digest"],
                "fresh_observation_revision": observation["observation_revision"],
                "verified_outcome": "compensation_reconciled",
            }, prepared["baseline_digest"], {"kind": "deterministic", "id": "compensation-reconciler"})
            ordered = [started["event"]["sequence"]]
            if normal_receipt is not None:
                ordered.append(normal_receipt["event"]["sequence"])
            ordered += [entry["event"]["sequence"] for entry in (restore_started, receipt_event, reconciled)]
            if any(left >= right for left, right in zip(ordered, ordered[1:])):
                raise ValueError("completed compensation history is out of order")

        if claim["outcome_digest"] != semantic_record_digest({
                "contract": "claim-outcome-v1", "state": claim["state"], "value": observation}):
            raise ValueError("completed action claim outcome digest differs")
        related_ids = {"action_id": set(journals), "original_action_id": {action_id},
                       "compensation_action_id": set(journals), "claim_id": {claim_id}}
        if recovery is not None:
            related_ids["attempt_id"] = {recovery["attempt_id"]}
        related = {entry["event"]["event_digest"] for entry in events
                   if entry["event"]["event_type"].startswith("action.")
                   and any(type(entry["event"]["payload"].get(key)) is str
                           and entry["event"]["payload"].get(key) in identifiers
                           for key, identifiers in related_ids.items())}
        if related != used:
            raise ValueError("completed action history has unexpected or unresolved events")
        return claim["state"]


    def _publish_bounded_receipt_object(
        self,
        raw: dict[str, object],
        *,
        result: str,
        receipt_source: str,
    ) -> tuple[str, str]:
        if type(raw) is not dict or result not in {"succeeded", "failed", "unknown"}:
            raise ValueError("fake receipt result is invalid")
        value: dict[str, object] = {
            "schema_version": "1.0.0",
            "contract": "bounded-redacted-fake-receipt-v1",
            "receipt_source": receipt_source,
            "result": result,
        }
        effect = raw.get("effect")
        if effect in {"applied", "none"}:
            value["effect"] = effect
        body = canonical_json(value).encode("utf-8")
        digest = self._objects.digest(body)
        self._fault("receipt-object.before-durable")
        self._objects.put_verified(body, digest)
        self._fault("receipt-object.after-durable")
        return digest, semantic_record_digest({
            "contract": "bounded-redacted-fake-receipt-v1", "value": value,
        })

    @staticmethod
    def _typed_receipt_document(receipt: object) -> dict[str, object]:
        from graph_engineering.core.action_adapters import ActionReceipt

        if type(receipt) is not ActionReceipt:
            raise ValueError("concrete action receipt is missing or forged")
        return {
            "schema_version": receipt.schema_version,
            "receipt_id": receipt.receipt_id,
            "invocation_id": receipt.invocation_id,
            "invocation_digest": receipt.invocation_digest,
            "task_id": receipt.task_id,
            "action_id": receipt.action_id,
            "prepared_action_digest": receipt.prepared_action_digest,
            "authority_digest": receipt.authority_digest,
            "adapter_id": receipt.adapter_id,
            "operation_id": receipt.operation_id,
            "target_id": receipt.target_id,
            "target_digest": receipt.target_digest,
            "resources": list(receipt.resources),
            "lease_id": receipt.lease_id,
            "fencing_tokens": [dict(item) for item in receipt.fencing_tokens],
            "idempotency_class": receipt.idempotency_class,
            "idempotency_key": receipt.idempotency_key,
            "result": receipt.result,
            "result_digest": receipt.result_digest,
            "receipt_source": receipt.receipt_source,
            "receipt_digest": receipt.receipt_digest,
        }

    @staticmethod
    def _typed_observation_document(observation: object) -> dict[str, object]:
        from graph_engineering.core.action_adapters import TargetObservation

        if type(observation) is not TargetObservation:
            raise ValueError("concrete target observation is missing or forged")
        return {
            "schema_version": observation.schema_version,
            "observation_id": observation.observation_id,
            "receipt_id": observation.receipt_id,
            "receipt_digest": observation.receipt_digest,
            "invocation_id": observation.invocation_id,
            "invocation_digest": observation.invocation_digest,
            "task_id": observation.task_id,
            "action_id": observation.action_id,
            "prepared_action_digest": observation.prepared_action_digest,
            "authority_digest": observation.authority_digest,
            "adapter_id": observation.adapter_id,
            "operation_id": observation.operation_id,
            "target_id": observation.target_id,
            "target_digest": observation.target_digest,
            "resources": list(observation.resources),
            "lease_id": observation.lease_id,
            "fencing_tokens": [dict(item) for item in observation.fencing_tokens],
            "fresh": observation.fresh,
            "observation_revision": observation.observation_revision,
            "observed_state_digest": observation.observed_state_digest,
            "observation_digest": observation.observation_digest,
        }

    def _publish_concrete_receipt_object(
        self,
        receipt: object,
        observation: object,
    ) -> str:
        from graph_engineering.adapters.git_native import GitIdentityObservation

        if type(observation) is not GitIdentityObservation:
            raise ValueError("concrete Git observation is missing or forged")
        value = {
            "schema_version": "1.0.0",
            "contract": "concrete-action-receipt-v1",
            "receipt": self._typed_receipt_document(receipt),
            "observation": observation.to_dict(),
        }
        body = canonical_json(value).encode("utf-8")
        digest = self._objects.digest(body)
        self._fault("concrete.receipt-object.before-durable")
        self._objects.put_verified(body, digest)
        self._fault("concrete.receipt-object.after-durable")
        return digest

    def prepare(self, value: dict[str, object]) -> PreparedAction:
        if self._installation_validator is not None:
            self._installation_validator()
        prepared = self._policy.load_prepared(value)
        if prepared.action_kind not in self._policy.separately_authorized_action_kinds:
            raise ValueError("action kind has no separately configured authority class")
        retained = self._retained_targets.get((prepared.task_id, prepared.target_id))
        if retained is not None:
            self._retained_scope(require_idle=True)
            retained._root._require_open()
            if prepared.target_digest != retained.target.target_digest:
                raise ValueError("retained release prepared target digest differs")
            previous = self._retained_actions.get(prepared.action_id)
            if previous is not None and previous is not retained:
                raise ValueError("retained release action identity was reused")
        self._journal.record_prepared(prepared)
        if retained is not None:
            self._retained_actions[prepared.action_id] = retained
            self._retained_prepared[prepared.prepared_action_digest] = retained
        return prepared

    def authorize(self, value: dict[str, object]) -> AuthorityEnvelope:
        if self._installation_validator is not None:
            self._installation_validator()
        authority = self._policy.load_authority(value)
        retained = self._retained_prepared.get(authority.prepared_action_digest)
        if retained is not None:
            self._retained_scope(require_idle=True)
            retained._root._require_open()
        prepared_record = self._journal.find_prepared(authority.prepared_action_digest)
        prepared = prepared_record.prepared
        if (
            prepared_record.state != "authorized"
            or
            authority.authorized_action_kind != prepared.action_kind
            or authority.authorized_resources != prepared.resources
            or authority.baseline_digest != prepared.baseline_digest
            or authority.snapshot_digest != prepared.snapshot_digest
        ):
            raise ValueError("authority does not exactly bind prepared action semantics")
        task_context = self._issuer.issue_task_context(prepared.task_id)
        if (
            authority.owner_id != task_context.binding.owner_id
            or authority.runtime_kind != task_context.binding.runtime_kind
            or authority.runtime_lineage_id != task_context.binding.runtime_lineage_id
            or prepared.baseline_digest != task_context.binding.baselines.get("intent")
            or prepared.snapshot_digest != task_context.binding.snapshot_digest
            or authority.baseline_digest != task_context.binding.baselines.get("intent")
            or authority.snapshot_digest != task_context.binding.snapshot_digest
        ):
            raise ValueError("authority identity/baseline/snapshot is not bound to the current durable task")
        if authority.authority_digest not in task_context.authority_digests:
            raise ValueError("authority is not present in current durable task authority state")
        self._journal.record_authorized(authority)
        return authority

    def revoke(self, action_id: str, authority_id: str, *, session: object = None,
               request_id: str | None = None, expected_generation: int | None = None) -> dict[str, object]:
        from graph_engineering.application.action_authority import ActionAuthorizationApplication
        from graph_engineering.application.runtime import RuntimeSession
        from graph_engineering.core.action_authority import ActionAuthorityError
        from graph_engineering.storage.action_authority import ActionAuthorityLedger, installed_policy
        if (type(session) is not RuntimeSession or type(request_id) is not str
                or type(expected_generation) is not int or not 0 <= expected_generation <= 2**53-1):
            raise ActionAuthorityError('identity_mismatch')
        scope=self._retained_scope(require_idle=True)
        factory=self._journal._factory
        service=ActionAuthorizationApplication(scope._manager,
            schema_registry=self._journal._schemas,context=self._journal._context)
        ledger=ActionAuthorityLedger(factory,installed_policy())
        with factory.open('application') as connection:
            with connection.transaction():
                record=self._journal._load(connection,action_id)
                if record.authority is None or record.authority.authority_id!=authority_id:
                    raise ActionAuthorityError('stale_binding')
                request=service._request(dict(schema_version='1.0.0',request_id=request_id,
                    task_id=record.task_id,action_id=action_id),preconditions=False)
                return service._revoke_locked(connection,session,request,expected_generation,
                    ledger,self._journal,self._issuer)

    @staticmethod
    def _lease_assertion(lease: LeaseGrant, task_id: str) -> dict[str, object]:
        token = dict(lease.fencing_tokens).get(f"task:{task_id}")
        if type(token) is not int:
            raise ValueError("combined action lease lacks the task resource fence")
        return {"lease_id": lease.lease_id, "resource_id": f"task:{task_id}", "fencing_token": token}

    @staticmethod
    def _fresh_observation_binding(
        observed: object,
        *,
        target_id: str,
        target_digest: str,
        resource_id: str,
    ) -> bool:
        return bool(
            type(observed) is dict
            and observed.get("fresh") is True
            and observed.get("target_id") == target_id
            and observed.get("target_digest") == target_digest
            and observed.get("resource_id") == resource_id
            and type(observed.get("observation_revision")) is int
            and observed.get("observation_revision", 0) > 0
        )

    def _validate_gate(
        self,
        record: object,
        *,
        owner_id: str,
        runtime_kind: str,
        runtime_lineage_id: str,
        lease: LeaseGrant,
        target: ActionTargetPort,
        observer: ActionObserverPort,
        disclosure_plan: DataDisclosurePlan,
        candidate_action: dict[str, object] | None,
    ) -> tuple[object, dict[str, object]]:
        from graph_engineering.core.actions import ActionJournalRecord
        exact_codes: set[str] = set()
        if type(record) is not ActionJournalRecord or record.authority is None:
            raise ValueError("action is not currently authorized")
        if record.state != "authorized":
            state = getattr(record, "state", "missing")
            if state == "unknown":
                exact_codes.add("GEW-AUT-IDEMPOTENCY-UNKNOWN")
            elif state in {"executing", "succeeded", "failed", "reconciled", "compensated"}:
                exact_codes.add("GEW-AUT-IDEMPOTENCY-DUPLICATE")
            else:
                raise ValueError("action is not currently authorized")
        prepared, authority = record.prepared, record.authority
        if candidate_action is not None:
            if candidate_action.get("idempotency_key") != prepared.idempotency_key:
                exact_codes.add("GEW-AUT-IDEMPOTENCY-KEY-CHANGED")
            if candidate_action.get("idempotency_class") != prepared.idempotency_class:
                exact_codes.add("GEW-AUT-IDEMPOTENCY-CLASS-CHANGED")
            if "rollback_plan" not in candidate_action or not candidate_action.get("rollback_plan"):
                exact_codes.add("GEW-AUT-ROLLBACK-MISSING")
                exact_codes.add("GEW-AUT-ROLLBACK-CHANGED")
            elif candidate_action.get("rollback_plan") != thaw(prepared.rollback_plan):
                exact_codes.add("GEW-AUT-ROLLBACK-CHANGED")
            if "verification_plan" not in candidate_action or not candidate_action.get("verification_plan"):
                exact_codes.add("GEW-AUT-VERIFY-MISSING")
                exact_codes.add("GEW-AUT-VERIFY-CHANGED")
            elif candidate_action.get("verification_plan") != thaw(prepared.verification_plan):
                exact_codes.add("GEW-AUT-VERIFY-CHANGED")
        if exact_codes.intersection({
            "GEW-AUT-IDEMPOTENCY-DUPLICATE", "GEW-AUT-IDEMPOTENCY-UNKNOWN",
        }):
            try:
                replay_observed = observer.observe()
            except (LookupError, OSError, RuntimeError, ValueError):
                exact_codes.add("GEW-AUT-PRECONDITION-UNVERIFIABLE")
            else:
                if replay_observed.get("fresh") is not True:
                    exact_codes.add("GEW-AUT-TARGET-EVIDENCE-STALE")
                if (
                    replay_observed.get("target_id") != prepared.target_id
                    or replay_observed.get("target_digest") != prepared.target_digest
                    or replay_observed.get("resource_id") != observer.resource_id
                    or type(replay_observed.get("observation_revision")) is not int
                    or replay_observed.get("observation_revision", 0) <= 0
                ):
                    exact_codes.add("GEW-AUT-PRECONDITION-UNVERIFIABLE")
                if replay_observed.get("state") != dict(prepared.precondition):
                    exact_codes.add("GEW-AUT-PRECONDITION-CHANGED")
            ExecuteGateDecisionTable.reject(
                exact_codes,
                "execute gate journal history/candidate mutation rejected",
            )
        task_context = self._issuer.issue_task_context(prepared.task_id)
        binding = task_context.binding
        if (binding.owner_id, binding.runtime_kind, binding.runtime_lineage_id) != (owner_id, runtime_kind, runtime_lineage_id):
            raise ValueError("Owner/runtime/lineage binding mismatch")
        if authority.status != "active" or authority.owner_id != owner_id or authority.runtime_kind != runtime_kind or authority.runtime_lineage_id != runtime_lineage_id:
            raise ValueError("authority identity, status, or runtime binding mismatch")
        if authority.authority_digest not in task_context.authority_digests:
            raise ValueError("authority is not current in durable task authority state")
        if authority.authorized_action_kind != prepared.action_kind or authority.authorized_resources != prepared.resources:
            raise ValueError("authority action/resource class mismatch")
        if not hmac.compare_digest(authority.prepared_action_digest, prepared.prepared_action_digest):
            raise ValueError("prepared action digest changed after authority")
        if (
            binding.baselines.get("intent") != prepared.baseline_digest
            or binding.snapshot_digest != prepared.snapshot_digest
            or authority.baseline_digest != prepared.baseline_digest
            or authority.snapshot_digest != prepared.snapshot_digest
        ):
            raise ValueError("baseline or snapshot binding mismatch")
        if parse_timestamp(task_context.current_time, "current repository time") >= parse_timestamp(authority.expires_at, "authority expiry"):
            raise ValueError("authority expired")
        bound_target = binding.targets.get(prepared.target_id)
        if bound_target is None or target.target_id != prepared.target_id or target.target_digest != prepared.target_digest or bound_target.target_digest != prepared.target_digest:
            raise ValueError("target identity or digest mismatch")
        if target.resource_id not in prepared.resources or tuple(sorted(lease.resources)) != prepared.resources:
            raise ValueError("combined lease does not exactly cover prepared resources")
        fences = dict(lease.fencing_tokens)
        if set(fences) != set(prepared.resources) or any(
            not self._leases.validate_fence(lease_id=lease.lease_id, resource_id=resource, fencing_token=fences[resource])
            for resource in prepared.resources
        ):
            raise ValueError("lease or fencing token is stale")
        enabled = self._policy.enabled_adapter_capabilities
        if target.is_test_double is not True or any(capability not in target.capabilities for capability in prepared.required_capabilities):
            raise ValueError("adapter capability is missing or not a deterministic fake")
        if not any(capability in target.capabilities for capability in enabled):
            raise ValueError("adapter capability is not enabled by policy")
        if not prepared.rollback_plan or not prepared.verification_plan:
            raise ValueError("rollback or verification plan is unavailable")
        if (
            type(disclosure_plan) is not DataDisclosurePlan
            or disclosure_plan.prepared_action_digest != prepared.prepared_action_digest
            or disclosure_plan.snapshot_digest != prepared.snapshot_digest
            or disclosure_plan.payload_digest != prepared.payload_digest
        ):
            raise ValueError("disclosure plan binding mismatch")
        if (
            observer is target
            or observer.is_test_double is not True
            or observer.is_read_only_observer is not True
            or observer.target_id != target.target_id
            or observer.target_digest != target.target_digest
            or observer.resource_id != target.resource_id
            or "fresh-target-query" not in observer.capabilities
        ):
            raise ValueError("fresh target evidence requires a separate read-only observer capability")
        try:
            observed = observer.observe()
        except (LookupError, OSError, RuntimeError, ValueError) as error:
            observed = {}
            exact_codes.add("GEW-AUT-PRECONDITION-UNVERIFIABLE")
            observation_error = error
        else:
            observation_error = None
            if observed.get("fresh") is not True:
                exact_codes.add("GEW-AUT-TARGET-EVIDENCE-STALE")
            if (
                observed.get("target_id") != prepared.target_id
                or observed.get("target_digest") != prepared.target_digest
                or observed.get("resource_id") != observer.resource_id
                or type(observed.get("observation_revision")) is not int
                or observed.get("observation_revision", 0) <= 0
            ):
                exact_codes.add("GEW-AUT-PRECONDITION-UNVERIFIABLE")
            if observed.get("state") != dict(prepared.precondition):
                exact_codes.add("GEW-AUT-PRECONDITION-CHANGED")
        try:
            ExecuteGateDecisionTable.reject(exact_codes, "execute gate exact mutation rejected")
        except ActionGateError as gate_error:
            if observation_error is not None:
                raise gate_error from observation_error
            raise
        if candidate_action is not None:
            candidate = self._policy.load_prepared(candidate_action)
            if not hmac.compare_digest(candidate.prepared_action_digest, prepared.prepared_action_digest):
                raise ValueError("current action body digest differs from authorized prepared record")
        return task_context, observed

    def execute(
        self,
        action_id: str,
        *,
        owner_id: str,
        runtime_kind: str,
        runtime_lineage_id: str,
        lease: LeaseGrant,
        target: ActionTargetPort,
        observer: ActionObserverPort,
        disclosure_plan: DataDisclosurePlan,
        candidate_action: dict[str, object] | None = None,
    ) -> ActionOutcome:
        self._require_retained_action(action_id, target=target, observer=observer)
        if self._installation_validator is not None:
            self._installation_validator()
        installation = self._locks.acquire_installation("shared")
        resource_locks = None
        try:
            resource_locks = self._locks.acquire_resources(tuple(sorted(lease.resources)))
            record = self._journal.load(action_id)
            context, _observed = self._validate_gate(
                record, owner_id=owner_id, runtime_kind=runtime_kind,
                runtime_lineage_id=runtime_lineage_id, lease=lease, target=target,
                observer=observer,
                disclosure_plan=disclosure_plan,
                candidate_action=candidate_action,
            )
            prepared, authority = record.prepared, record.authority
            assert authority is not None
            claim_id = f"claim:{action_id}"
            head = self._journal.current_task_head(prepared.task_id)
            event = make_event(
                task_id=prepared.task_id, sequence=head.sequence + 1, event_id=f"{action_id}:started",
                event_type="action.execution_started", occurred_at=context.current_time,
                actor={"kind": "runtime", "id": runtime_lineage_id}, expected_task_revision=head.revision,
                baseline_digests=[prepared.baseline_digest],
                payload={
                    "action_id": action_id, "authority_digest": authority.authority_digest,
                    "prepared_action_digest": prepared.prepared_action_digest,
                    "snapshot_digest": prepared.snapshot_digest, "lease_id": lease.lease_id,
                    "fencing_tokens": dict(lease.fencing_tokens), "disclosure_plan_digest": disclosure_plan.plan_digest,
                }, previous_event_digest=head.head_digest,
            )
            claim = self._leases.claim_action(
                claim_id=claim_id, action_id=action_id, task_id=prepared.task_id, lease=lease,
                started_event_digest=event["event_digest"],
            )
            snapshot = action_task_snapshot(
                head.snapshot, task_id=prepared.task_id, revision=head.revision,
                action_state="executing",
            )
            self._repository.commit(CommitBatch(
                transaction_id=f"{action_id}:start", task_id=prepared.task_id,
                expected_task_revision=head.revision, events=(event,), snapshot=snapshot,
                catalog_delta={}, lease_assertion=self._lease_assertion(lease, prepared.task_id),
                claim_delta=claim, action_journal_delta=self._journal.start_delta(record),
            ))
            fence = dict(lease.fencing_tokens)[target.resource_id]
            execution_gate = getattr(target, "_durable_execution_gate", None)
            try:
                if self._installation_validator is not None:
                    self._installation_validator()
                if execution_gate is not None:
                    if type(execution_gate) is not _DurableExecutionGate:
                        raise ValueError("action target durable execution gate is foreign")
                    self._durable_execution_gates.arm(
                        execution_gate,
                        action_id=action_id,
                        claim_id=claim_id,
                        prepared_action_digest=prepared.prepared_action_digest,
                        payload=dict(prepared.payload),
                        fencing_token=fence,
                    )
                try:
                    raw = target.invoke(
                        payload=dict(prepared.payload),
                        fencing_token=fence,
                        started_was_durable=True,
                    )
                finally:
                    if execution_gate is not None:
                        self._durable_execution_gates.disarm(execution_gate)
                state = "succeeded" if raw.get("result") == "succeeded" else "failed"
            except TimeoutError as error:
                raw = {"result": "unknown", "error_type": type(error).__name__}
                state = "unknown"
            receipt_object_digest, raw_result_digest = self._publish_bounded_receipt_object(
                raw, result=state, receipt_source="tool-return",
            )
            receipt = {
                "action_id": action_id, "task_id": prepared.task_id, "claim_id": claim_id,
                "started_event_digest": event["event_digest"],
                "prepared_action_digest": prepared.prepared_action_digest,
                "authority_digest": authority.authority_digest, "payload_digest": prepared.payload_digest,
                "target_id": prepared.target_id, "fencing_token": fence, "result": state,
                "raw_result_digest": raw_result_digest,
                "raw_receipt_object_digest": receipt_object_digest,
            }
            receipt["receipt_digest"] = semantic_record_digest({"contract": "action-receipt-v1", "value": receipt})
            executing_record = self._journal.load(action_id)
            receipt_head = self._journal.current_task_head(prepared.task_id)
            receipt_event = make_event(
                task_id=prepared.task_id,
                sequence=receipt_head.sequence + 1,
                event_id=f"{action_id}:receipt",
                event_type="action.receipt_recorded",
                occurred_at=self._journal.current_time(),
                actor={"kind": "deterministic", "id": "action-receipt-recorder"},
                expected_task_revision=receipt_head.revision,
                baseline_digests=[prepared.baseline_digest],
                payload={
                    "action_id": action_id,
                    "claim_id": claim_id,
                    "receipt_digest": receipt["receipt_digest"],
                    "raw_receipt_object_digest": receipt_object_digest,
                },
                previous_event_digest=receipt_head.head_digest,
            )
            receipt_snapshot = action_task_snapshot(
                receipt_head.snapshot, task_id=prepared.task_id, revision=receipt_head.revision,
                action_state=state,
            )
            self._repository.commit(CommitBatch(
                transaction_id=f"{action_id}:receipt",
                task_id=prepared.task_id,
                expected_task_revision=receipt_head.revision,
                events=(receipt_event,),
                snapshot=receipt_snapshot,
                catalog_delta={},
                object_digests=(receipt_object_digest,),
                lease_assertion=self._lease_assertion(lease, prepared.task_id),
                action_journal_delta=self._journal.receipt_delta(
                    executing_record,
                    state=state,
                    receipt=receipt,
                    receipt_event_digest=receipt_event["event_digest"],
                ),
            ))
            if state != "succeeded":
                return self._issue_outcome(action_id, state, "manual-reconciliation", claim_id, receipt["receipt_digest"])
            try:
                observed = observer.observe()
            except (LookupError, OSError, RuntimeError, ValueError):
                observed = {}
            if (
                not self._fresh_observation_binding(
                    observed,
                    target_id=prepared.target_id,
                    target_digest=prepared.target_digest,
                    resource_id=target.resource_id,
                )
                or observed.get("state") != dict(prepared.expected_postcondition)
            ):
                return self._issue_outcome(action_id, "succeeded", "manual-target-reconciliation", claim_id, receipt["receipt_digest"])
            return self._finish_reconciliation(action_id, lease=lease, outcome="reconciled_effect_verified", body=observed)
        finally:
            if resource_locks is not None:
                self._locks.release(resource_locks)
            self._locks.release(installation)

    def _finish_reconciliation(
        self,
        action_id: str,
        *,
        lease: LeaseGrant,
        outcome: str,
        body: dict[str, object],
        compensated: bool = False,
        concrete_observation: object | None = None,
    ) -> ActionOutcome:
        record = self._journal.load(action_id)
        claim_id = f"claim:{action_id}"
        head = self._journal.current_task_head(record.task_id)
        event_type = {
            "reconciled_effect_verified": "action.reconciled_effect_verified",
            "reconciled_no_effect": "action.reconciled_no_effect",
            "compensation_reconciled": "action.compensation_reconciled",
        }[outcome]
        event = make_event(
            task_id=record.task_id, sequence=head.sequence + 1, event_id=f"{action_id}:{outcome}",
            event_type=event_type, occurred_at=self._journal.current_time(),
            actor={"kind": "deterministic", "id": "action-reconciler"}, expected_task_revision=head.revision,
            baseline_digests=[record.prepared.baseline_digest], payload={"claim_id": claim_id, "action_id": action_id},
            previous_event_digest=head.head_digest,
        )
        delta = self._leases.reconcile_claim(claim_id, outcome, body, event["event_digest"])
        snapshot = action_task_snapshot(
            head.snapshot, task_id=record.task_id, revision=head.revision,
            action_state="compensated" if compensated else "reconciled",
        )
        self._repository.commit(CommitBatch(
            transaction_id=f"{action_id}:{outcome}", task_id=record.task_id,
            expected_task_revision=head.revision, events=(event,), snapshot=snapshot,
            catalog_delta={}, lease_assertion=self._lease_assertion(lease, record.task_id),
            claim_reconciliation_delta=delta,
            action_journal_delta=self._journal.reconcile_delta(record, body, compensated=compensated),
            concrete_action_delta=None if concrete_observation is None else {
                "operation": "observation",
                "record": self._typed_observation_document(concrete_observation),
            },
        ))
        route = "compensation-reconciled" if compensated else outcome.replace("_", "-")
        receipt_digest = None if record.receipt is None else record.receipt.get("receipt_digest")
        return self._issue_outcome(action_id, "compensated" if compensated else "reconciled", route, claim_id, receipt_digest if isinstance(receipt_digest, str) else None)

    def execute_concrete_git(
        self,
        action_id: str,
        *,
        owner_id: str,
        runtime_kind: str,
        runtime_lineage_id: str,
        lease: LeaseGrant,
        adapter: object,
        target_plan_document: dict[str, object],
        expected_target: object,
        disclosure_plan: DataDisclosurePlan,
    ) -> ActionOutcome:
        """Run one authorized built-in Git CAS through the durable action protocol."""

        if action_id in self._retained_actions:
            raise ValueError("retained release actions cannot use the concrete Git route")

        from graph_engineering.adapters.action_adapters import ActionAdapterFactory
        from graph_engineering.adapters.git_native import (
            GitIdentityObservation,
            GitNativeAdapter,
            GitRefMutationPlan,
            GitTargetPlan,
        )
        from graph_engineering.core.action_adapters import (
            ActionInvocation,
            ActionReceipt,
            TargetObservation,
        )

        self._require_installation_context()
        if (
            self._policy.real_external_actions_enabled is not True
            or self._action_adapter_factory is None
            or type(adapter) is not GitNativeAdapter
            or ActionAdapterFactory.require_attested(adapter) is not adapter
            or type(expected_target) is not GitTargetPlan
            or type(disclosure_plan) is not DataDisclosurePlan
        ):
            raise ValueError("real Git action authority is disabled or not factory-attested")
        installation = self._locks.acquire_installation("shared")
        resource_locks = None
        try:
            resource_locks = self._locks.acquire_resources(tuple(sorted(lease.resources)))
            task_resources = tuple(
                resource for resource in lease.resources if resource.startswith("task:")
            )
            if len(task_resources) != 1 or len(task_resources[0]) <= len("task:"):
                raise ValueError("concrete Git action authority rejected")
            asserted_task_id = task_resources[0][len("task:"):]
            pre_context = self._issuer.issue_task_context(asserted_task_id)
            pre_binding = pre_context.binding
            pre_target = pre_binding.targets.get(expected_target.target_id)
            expected_resources = tuple(lease.resources)
            non_task_resources = tuple(
                resource for resource in expected_resources
                if resource != f"task:{asserted_task_id}"
            )
            if (
                (pre_binding.owner_id, pre_binding.runtime_kind, pre_binding.runtime_lineage_id)
                != (owner_id, runtime_kind, runtime_lineage_id)
                or pre_target is None
                or pre_target.target_digest != expected_target.target_digest
                or expected_resources != tuple(sorted(expected_resources))
                or expected_resources.count(f"task:{asserted_task_id}") != 1
                or len(non_task_resources) != 1
                or tuple(resource for resource, _token in lease.fencing_tokens)
                != expected_resources
                or any(
                    not self._leases.validate_fence(
                        lease_id=lease.lease_id,
                        resource_id=resource,
                        fencing_token=dict(lease.fencing_tokens)[resource],
                    )
                    for resource in expected_resources
                )
            ):
                raise ValueError("concrete Git action authority rejected")
            try:
                record = self._journal.load(action_id)
            except (LookupError, RepositoryConflictError, ValueError) as error:
                raise ValueError("concrete Git action authority rejected") from error
            if record.state not in {
                "authorized", "executing", "succeeded", "failed", "unknown", "reconciled",
            } or record.authority is None:
                raise ValueError("concrete Git action authority rejected")
            prepared, authority = record.prepared, record.authority
            context = self._issuer.issue_task_context(prepared.task_id)
            binding = context.binding
            if (
                (binding.owner_id, binding.runtime_kind, binding.runtime_lineage_id)
                != (owner_id, runtime_kind, runtime_lineage_id)
                or (authority.owner_id, authority.runtime_kind, authority.runtime_lineage_id)
                != (owner_id, runtime_kind, runtime_lineage_id)
                or authority.status != "active"
                or authority.authority_digest not in context.authority_digests
                or authority.prepared_action_digest != prepared.prepared_action_digest
                or authority.authorized_action_kind != prepared.action_kind
                or authority.authorized_resources != prepared.resources
                or binding.baselines.get("intent") != prepared.baseline_digest
                or (
                    record.state == "authorized"
                    and binding.snapshot_digest != prepared.snapshot_digest
                )
                or parse_timestamp(context.current_time, "current repository time")
                >= parse_timestamp(authority.expires_at, "authority expiry")
            ):
                raise ValueError("concrete Git action identity/authority/baseline gate rejected")
            bound_target = binding.targets.get(prepared.target_id)
            if (
                bound_target is None
                or bound_target.target_digest != prepared.target_digest
                or expected_target.target_id != prepared.target_id
                or expected_target.target_digest != prepared.target_digest
                or tuple(lease.resources) != prepared.resources
                or tuple(resource for resource, _token in lease.fencing_tokens)
                != prepared.resources
                or any(
                    not self._leases.validate_fence(
                        lease_id=lease.lease_id,
                        resource_id=resource,
                        fencing_token=dict(lease.fencing_tokens)[resource],
                    )
                    for resource in prepared.resources
                )
                or disclosure_plan.prepared_action_digest != prepared.prepared_action_digest
                or disclosure_plan.snapshot_digest != prepared.snapshot_digest
                or disclosure_plan.payload_digest != prepared.payload_digest
                or not set(prepared.required_capabilities).issubset(
                    set(self._policy.enabled_adapter_capabilities)
                )
            ):
                raise ValueError("concrete Git action authority rejected")
            target = GitTargetPlan.from_dict(target_plan_document)
            if target != expected_target:
                raise ValueError("concrete Git target plan differs from approved target")
            non_task_resources = tuple(
                resource for resource in prepared.resources
                if resource != f"task:{prepared.task_id}"
            )
            if len(non_task_resources) != 1:
                raise ValueError("concrete Git action requires one exact target resource")
            target_resource = non_task_resources[0]
            claim_id = f"claim:{action_id}"
            if record.state != "authorized":
                receipt_digest = (
                    None if record.receipt is None else record.receipt.get("receipt_digest")
                )
                if record.state == "reconciled":
                    return self._issue_outcome(
                        action_id,
                        "reconciled",
                        "reconciled-effect-verified",
                        claim_id,
                        receipt_digest if isinstance(receipt_digest, str) else None,
                    )
                records = self._repository.concrete_action_records(action_id)
                invocation_value = records.get("invocation")
                if invocation_value is None:
                    raise ValueError("concrete Git recovery invocation is not durable")
                invocation = ActionInvocation.from_dict(invocation_value)
                if (
                    invocation.task_id != prepared.task_id
                    or invocation.action_id != prepared.action_id
                    or invocation.prepared_action_digest != prepared.prepared_action_digest
                    or invocation.authority_digest != authority.authority_digest
                    or invocation.target_id != prepared.target_id
                    or invocation.target_digest != prepared.target_digest
                    or invocation.resources != prepared.resources
                    or invocation.lease_id != lease.lease_id
                    or tuple(
                        (item["resource_id"], item["token"])
                        for item in invocation.fencing_tokens
                    ) != lease.fencing_tokens
                ):
                    raise ValueError("concrete Git recovery invocation binding changed")
                try:
                    fresh_recovery = adapter.observe(target_plan_document, expected=target)
                except (LookupError, OSError, RuntimeError, ValueError):
                    return self._issue_outcome(
                        action_id,
                        record.state,
                        "manual-target-reconciliation",
                        claim_id,
                        receipt_digest if isinstance(receipt_digest, str) else None,
                    )
                recovery_state = {
                    "head_oid": fresh_recovery.head_oid,
                    "head_ref": fresh_recovery.head_ref,
                }
                receipt_value = records.get("receipt")
                if (
                    record.state != "succeeded"
                    or receipt_value is None
                    or recovery_state != dict(prepared.expected_postcondition)
                ):
                    return self._issue_outcome(
                        action_id,
                        record.state,
                        "manual-target-reconciliation",
                        claim_id,
                        receipt_digest if isinstance(receipt_digest, str) else None,
                    )
                typed_receipt = ActionReceipt.from_dict(receipt_value)
                typed_receipt.require_invocation(invocation)
                typed_observation_body: dict[str, object] = {
                    "schema_version": "1.0.0",
                    "observation_id": f"observation-{action_id}",
                    "receipt_id": typed_receipt.receipt_id,
                    "receipt_digest": typed_receipt.receipt_digest,
                    "invocation_id": typed_receipt.invocation_id,
                    "invocation_digest": typed_receipt.invocation_digest,
                    "task_id": typed_receipt.task_id,
                    "action_id": typed_receipt.action_id,
                    "prepared_action_digest": typed_receipt.prepared_action_digest,
                    "authority_digest": typed_receipt.authority_digest,
                    "adapter_id": typed_receipt.adapter_id,
                    "operation_id": typed_receipt.operation_id,
                    "target_id": typed_receipt.target_id,
                    "target_digest": typed_receipt.target_digest,
                    "resources": list(typed_receipt.resources),
                    "lease_id": typed_receipt.lease_id,
                    "fencing_tokens": [dict(item) for item in typed_receipt.fencing_tokens],
                    "fresh": True,
                    "observation_revision": fresh_recovery.observation_revision,
                    "observed_state_digest": fresh_recovery.observation_digest,
                }
                typed_observation_body["observation_digest"] = (
                    TargetObservation.digest_document(typed_observation_body)
                )
                typed_observation = TargetObservation.from_dict(typed_observation_body)
                typed_observation.require_receipt(typed_receipt)
                return self._finish_reconciliation(
                    action_id,
                    lease=lease,
                    outcome="reconciled_effect_verified",
                    body={
                        "target_id": prepared.target_id,
                        "target_digest": prepared.target_digest,
                        "resource_id": target_resource,
                        "fresh": True,
                        "observation_revision": fresh_recovery.observation_revision,
                        "state": recovery_state,
                    },
                    concrete_observation=typed_observation,
                )
            before = adapter.observe(target_plan_document, expected=target)
            if type(before) is not GitIdentityObservation or dict(prepared.precondition) != {
                "head_oid": before.head_oid,
                "head_ref": before.head_ref,
            }:
                raise ValueError("concrete Git native precondition changed")
            payload = dict(prepared.payload)
            if payload != {
                "target_plan_id": target.plan_id,
                "target_plan_digest": target.plan_digest,
                "ref_name": before.head_ref,
                "expected_old_oid": before.head_oid,
                "new_oid": dict(prepared.expected_postcondition).get("head_oid"),
            }:
                raise ValueError("concrete Git prepared payload is not the exact native mutation")
            invocation_body: dict[str, object] = {
                "schema_version": "1.0.0",
                "invocation_id": f"invocation-{action_id}",
                "task_id": prepared.task_id,
                "action_id": action_id,
                "prepared_action_digest": prepared.prepared_action_digest,
                "authority_digest": authority.authority_digest,
                "adapter_id": "git-native-v1",
                "operation_id": "git.update-ref",
                "target_id": prepared.target_id,
                "target_digest": prepared.target_digest,
                "resources": list(prepared.resources),
                "lease_id": lease.lease_id,
                "fencing_tokens": [
                    {"resource_id": resource, "token": dict(lease.fencing_tokens)[resource]}
                    for resource in prepared.resources
                ],
                "idempotency_class": prepared.idempotency_class,
                "idempotency_key": prepared.idempotency_key,
                "payload_digest": prepared.payload_digest,
                "disclosure_plan_digest": disclosure_plan.plan_digest,
            }
            invocation_body["invocation_digest"] = ActionInvocation.digest_document(invocation_body)
            invocation = ActionInvocation.from_dict(invocation_body)
            plan_body: dict[str, object] = {
                "schema_version": "1.0.0",
                "plan_id": f"git-plan-{action_id}",
                "target_plan_id": target.plan_id,
                "target_plan_digest": target.plan_digest,
                "task_id": invocation.task_id,
                "action_id": invocation.action_id,
                "prepared_action_digest": invocation.prepared_action_digest,
                "authority_digest": invocation.authority_digest,
                "invocation_id": invocation.invocation_id,
                "invocation_digest": invocation.invocation_digest,
                "target_id": invocation.target_id,
                "target_digest": invocation.target_digest,
                "resources": list(invocation.resources),
                "lease_id": invocation.lease_id,
                "fencing_tokens": [dict(item) for item in invocation.fencing_tokens],
                "idempotency_key": invocation.idempotency_key,
                "ref_name": payload["ref_name"],
                "expected_old_oid": payload["expected_old_oid"],
                "new_oid": payload["new_oid"],
            }
            plan_body["plan_digest"] = GitRefMutationPlan.digest_document(plan_body)
            GitRefMutationPlan.from_dict(plan_body).require_invocation(invocation)
            head = self._journal.current_task_head(prepared.task_id)
            event = make_event(
                task_id=prepared.task_id,
                sequence=head.sequence + 1,
                event_id=f"{action_id}:started",
                event_type="action.execution_started",
                occurred_at=context.current_time,
                actor={"kind": "runtime", "id": runtime_lineage_id},
                expected_task_revision=head.revision,
                baseline_digests=[prepared.baseline_digest],
                payload={
                    "action_id": action_id,
                    "authority_digest": authority.authority_digest,
                    "prepared_action_digest": prepared.prepared_action_digest,
                    "snapshot_digest": prepared.snapshot_digest,
                    "lease_id": lease.lease_id,
                    "fencing_tokens": dict(lease.fencing_tokens),
                    "disclosure_plan_digest": disclosure_plan.plan_digest,
                    "invocation_digest": invocation.invocation_digest,
                },
                previous_event_digest=head.head_digest,
            )
            claim = self._leases.claim_action(
                claim_id=claim_id,
                action_id=action_id,
                task_id=prepared.task_id,
                lease=lease,
                started_event_digest=event["event_digest"],
            )
            snapshot = action_task_snapshot(
                head.snapshot, task_id=prepared.task_id, revision=head.revision,
                action_state="executing",
            )
            self._repository.commit(CommitBatch(
                transaction_id=f"{action_id}:start",
                task_id=prepared.task_id,
                expected_task_revision=head.revision,
                events=(event,),
                snapshot=snapshot,
                catalog_delta={},
                lease_assertion=self._lease_assertion(lease, prepared.task_id),
                claim_delta=claim,
                action_journal_delta=self._journal.start_delta(record),
                concrete_action_delta={"operation": "invocation", "record": invocation_body},
            ))
            self._fault("concrete.after-start-commit")
            self._installation_validator()
            typed_receipt, git_observation = adapter.update_ref(
                invocation_body,
                expected=invocation,
                target_plan_document=target_plan_document,
                expected_target=target,
                mutation_plan_document=plan_body,
                before=before,
            )
            self._fault("concrete.after-call")
            receipt_object_digest = self._publish_concrete_receipt_object(
                typed_receipt,
                git_observation,
            )
            legacy_receipt: dict[str, object] = {
                "action_id": action_id,
                "task_id": prepared.task_id,
                "claim_id": claim_id,
                "started_event_digest": event["event_digest"],
                "prepared_action_digest": prepared.prepared_action_digest,
                "authority_digest": authority.authority_digest,
                "payload_digest": prepared.payload_digest,
                "target_id": prepared.target_id,
                "fencing_token": dict(lease.fencing_tokens)[target_resource],
                "result": typed_receipt.result,
                "raw_result_digest": typed_receipt.receipt_digest,
                "raw_receipt_object_digest": receipt_object_digest,
            }
            legacy_receipt["receipt_digest"] = semantic_record_digest({
                "contract": "action-receipt-v1",
                "value": legacy_receipt,
            })
            executing_record = self._journal.load(action_id)
            receipt_head = self._journal.current_task_head(prepared.task_id)
            receipt_event = make_event(
                task_id=prepared.task_id,
                sequence=receipt_head.sequence + 1,
                event_id=f"{action_id}:receipt",
                event_type="action.receipt_recorded",
                occurred_at=self._journal.current_time(),
                actor={"kind": "deterministic", "id": "action-receipt-recorder"},
                expected_task_revision=receipt_head.revision,
                baseline_digests=[prepared.baseline_digest],
                payload={
                    "action_id": action_id,
                    "claim_id": claim_id,
                    "receipt_digest": legacy_receipt["receipt_digest"],
                    "raw_receipt_object_digest": receipt_object_digest,
                },
                previous_event_digest=receipt_head.head_digest,
            )
            receipt_snapshot = action_task_snapshot(
                receipt_head.snapshot, task_id=prepared.task_id, revision=receipt_head.revision,
                action_state="succeeded",
            )
            self._repository.commit(CommitBatch(
                transaction_id=f"{action_id}:receipt",
                task_id=prepared.task_id,
                expected_task_revision=receipt_head.revision,
                events=(receipt_event,),
                snapshot=receipt_snapshot,
                catalog_delta={},
                object_digests=(receipt_object_digest,),
                lease_assertion=self._lease_assertion(lease, prepared.task_id),
                action_journal_delta=self._journal.receipt_delta(
                    executing_record,
                    state="succeeded",
                    receipt=legacy_receipt,
                    receipt_event_digest=receipt_event["event_digest"],
                ),
                concrete_action_delta={
                    "operation": "receipt",
                    "record": self._typed_receipt_document(typed_receipt),
                },
            ))
            self._fault("concrete.after-receipt-commit")
            try:
                fresh_git_observation = adapter.observe(
                    target_plan_document,
                    expected=target,
                )
            except (LookupError, OSError, RuntimeError, ValueError):
                return self._issue_outcome(
                    action_id,
                    "succeeded",
                    "manual-target-reconciliation",
                    claim_id,
                    legacy_receipt["receipt_digest"],  # type: ignore[arg-type]
                )
            identity_fields = (
                "worktree_path", "worktree_device", "worktree_inode",
                "common_dir_path", "common_dir_device", "common_dir_inode",
                "head_ref",
            )
            if (
                type(fresh_git_observation) is not GitIdentityObservation
                or fresh_git_observation.observation_revision
                <= git_observation.observation_revision
                or any(
                    getattr(fresh_git_observation, field) != getattr(git_observation, field)
                    for field in identity_fields
                )
            ):
                return self._issue_outcome(
                    action_id,
                    "succeeded",
                    "manual-target-reconciliation",
                    claim_id,
                    legacy_receipt["receipt_digest"],  # type: ignore[arg-type]
                )
            observed_state = {
                "head_oid": fresh_git_observation.head_oid,
                "head_ref": fresh_git_observation.head_ref,
            }
            if observed_state != dict(prepared.expected_postcondition):
                return self._issue_outcome(
                    action_id,
                    "succeeded",
                    "manual-target-reconciliation",
                    claim_id,
                    legacy_receipt["receipt_digest"],  # type: ignore[arg-type]
                )
            typed_observation_body: dict[str, object] = {
                "schema_version": "1.0.0",
                "observation_id": f"observation-{action_id}",
                "receipt_id": typed_receipt.receipt_id,
                "receipt_digest": typed_receipt.receipt_digest,
                "invocation_id": typed_receipt.invocation_id,
                "invocation_digest": typed_receipt.invocation_digest,
                "task_id": typed_receipt.task_id,
                "action_id": typed_receipt.action_id,
                "prepared_action_digest": typed_receipt.prepared_action_digest,
                "authority_digest": typed_receipt.authority_digest,
                "adapter_id": typed_receipt.adapter_id,
                "operation_id": typed_receipt.operation_id,
                "target_id": typed_receipt.target_id,
                "target_digest": typed_receipt.target_digest,
                "resources": list(typed_receipt.resources),
                "lease_id": typed_receipt.lease_id,
                "fencing_tokens": [dict(item) for item in typed_receipt.fencing_tokens],
                "fresh": True,
                "observation_revision": fresh_git_observation.observation_revision,
                "observed_state_digest": fresh_git_observation.observation_digest,
            }
            typed_observation_body["observation_digest"] = TargetObservation.digest_document(
                typed_observation_body
            )
            typed_observation = TargetObservation.from_dict(typed_observation_body)
            typed_observation.require_receipt(typed_receipt)
            reconciliation_body = {
                "target_id": prepared.target_id,
                "target_digest": prepared.target_digest,
                "resource_id": target_resource,
                "fresh": True,
                "observation_revision": fresh_git_observation.observation_revision,
                "state": observed_state,
            }
            return self._finish_reconciliation(
                action_id,
                lease=lease,
                outcome="reconciled_effect_verified",
                body=reconciliation_body,
                concrete_observation=typed_observation,
            )
        finally:
            if resource_locks is not None:
                self._locks.release(resource_locks)
            self._locks.release(installation)

    def reconcile_unknown(self, action_id: str, *, lease: LeaseGrant, observer: ActionObserverPort) -> ActionOutcome:
        self._require_retained_action(action_id, observer=observer)
        if self._installation_validator is not None:
            self._installation_validator()
        installation = self._locks.acquire_installation("shared")
        resource_locks = None
        try:
            resource_locks = self._locks.acquire_resources(tuple(sorted(lease.resources)))
            record = self._journal.load(action_id)
            if record.state not in {"executing", "succeeded", "failed", "unknown"}:
                raise ValueError("only unresolved started actions use recovery reconciliation")
            if (
                observer.target_id != record.prepared.target_id
                or observer.target_digest != record.prepared.target_digest
                or observer.resource_id not in record.prepared.resources
                or set(lease.resources) != set(record.prepared.resources)
            ):
                raise ValueError("recovery observer or lease is not bound to the unresolved action")
            if observer.is_read_only_observer is not True or observer.is_test_double is not True:
                raise ValueError("reconciliation requires an independent read-only fake observer")
            try:
                observed = observer.observe()
            except (LookupError, OSError, RuntimeError, ValueError):
                observed = {}
            if not self._fresh_observation_binding(
                observed,
                target_id=record.prepared.target_id,
                target_digest=record.prepared.target_digest,
                resource_id=observer.resource_id,
            ):
                return self._issue_outcome(action_id, "unknown", "manual-reconciliation", f"claim:{action_id}", None)
            if observed.get("state") == dict(record.prepared.expected_postcondition):
                return self._finish_reconciliation(action_id, lease=lease, outcome="reconciled_effect_verified", body=observed)
            if observed.get("state") == dict(record.prepared.precondition):
                return self._finish_reconciliation(action_id, lease=lease, outcome="reconciled_no_effect", body=observed)
            return self._issue_outcome(action_id, "unknown", "manual-reconciliation", f"claim:{action_id}", None)
        finally:
            if resource_locks is not None:
                self._locks.release(resource_locks)
            self._locks.release(installation)

    def compensate_unknown(
        self,
        action_id: str,
        *,
        compensation_action_id: str,
        recovery_lease: LeaseGrant,
        owner_id: str,
        runtime_kind: str,
        runtime_lineage_id: str,
        target: ActionTargetPort,
        observer: ActionObserverPort,
        disclosure_plan: DataDisclosurePlan,
    ) -> ActionOutcome:
        """Recover an expired-lease claim through its one durable compensation attempt."""
        self._require_retained_action(action_id, target=target, observer=observer)
        self._require_retained_action(compensation_action_id, target=target, observer=observer)
        if self._installation_validator is not None:
            self._installation_validator()
        claim_id = f"claim:{action_id}"
        installation = self._locks.acquire_installation("shared")
        resource_locks = None
        try:
            resource_locks = self._locks.acquire_resources(tuple(sorted(recovery_lease.resources)))
            original = self._journal.load(action_id)
            compensation = self._journal.load(compensation_action_id)
            claim = self._leases.load_claim(claim_id)
            committed_attempt = self._leases.recovery_attempt(claim_id)
            if (
                committed_attempt is not None
                and committed_attempt["state"] == "reconciled"
                and committed_attempt["original_action_id"] == action_id
                and committed_attempt["compensation_action_id"] == compensation_action_id
                and original.state == "compensated"
                and compensation.state == "reconciled"
            ):
                committed_receipt = committed_attempt["receipt"]
                committed_digest = (
                    committed_receipt.get("receipt_digest")
                    if isinstance(committed_receipt, dict) else None
                )
                return self._issue_outcome(
                    action_id, "compensated", "compensation-reconciled", claim_id,
                    committed_digest if isinstance(committed_digest, str) else None,
                )
            if original.state not in {"executing", "unknown"} or claim["state"] != "unresolved":
                raise ValueError("compensation requires one exact unresolved original action")
            authority = compensation.authority
            if (
                authority is None
                or compensation.state not in {"authorized", "executing", "succeeded"}
                or compensation.action_id == original.action_id
                or compensation.prepared.action_kind != "rollback"
                or compensation.prepared.target_id != original.prepared.target_id
                or compensation.prepared.target_digest != original.prepared.target_digest
                or compensation.prepared.resources != original.prepared.resources
                or dict(compensation.prepared.expected_postcondition) != dict(original.prepared.precondition)
                or claim["action_id"] != action_id
                or claim["task_id"] != original.task_id
                or claim["lease_id"] != recovery_lease.lease_id
                or tuple(claim["resources"]) != recovery_lease.resources
                or claim["fencing_tokens"] != dict(recovery_lease.fencing_tokens)
            ):
                raise ValueError("compensation is not exactly bound to the original claim")
            attempt_id = self._leases.compensation_attempt_id(
                claim,
                compensation_action_id=compensation_action_id,
                compensation_authority_digest=authority.authority_digest,
                compensation_prepared_digest=compensation.prepared.prepared_action_digest,
            )
            attempt = self._leases.recovery_attempt(claim_id)
            context = self._issuer.issue_task_context(original.task_id)
            if (
                authority.authority_digest not in context.authority_digests
                or authority.status != "active"
                or authority.authorized_action_kind != "rollback"
                or authority.authorized_resources != compensation.prepared.resources
                or authority.prepared_action_digest != compensation.prepared.prepared_action_digest
                or authority.baseline_digest != compensation.prepared.baseline_digest
                or authority.snapshot_digest != compensation.prepared.snapshot_digest
                or compensation.prepared.baseline_digest != context.binding.baselines.get("intent")
                or (attempt is None and compensation.prepared.snapshot_digest != context.binding.snapshot_digest)
                or (authority.owner_id, authority.runtime_kind, authority.runtime_lineage_id)
                != (owner_id, runtime_kind, runtime_lineage_id)
                or parse_timestamp(context.current_time, "current repository time")
                >= parse_timestamp(authority.expires_at, "compensation authority expiry")
                or target.is_test_double is not True
                or target.target_id != compensation.prepared.target_id
                or target.target_digest != compensation.prepared.target_digest
                or target.resource_id not in compensation.prepared.resources
                or "fake-compensation" not in target.capabilities
                or any(
                    capability not in target.capabilities
                    for capability in compensation.prepared.required_capabilities
                    if capability != "fresh-target-query"
                )
                or not any(
                    capability in target.capabilities
                    for capability in self._policy.enabled_adapter_capabilities
                )
                or observer is target
                or observer.is_test_double is not True
                or observer.is_read_only_observer is not True
                or observer.target_id != target.target_id
                or observer.target_digest != target.target_digest
                or observer.resource_id != target.resource_id
                or "fresh-target-query" not in observer.capabilities
                or disclosure_plan.prepared_action_digest != compensation.prepared.prepared_action_digest
                or disclosure_plan.payload_digest != compensation.prepared.payload_digest
                or disclosure_plan.snapshot_digest != compensation.prepared.snapshot_digest
            ):
                raise ValueError("current rollback authority/target/disclosure binding is invalid")
            if attempt is None:
                try:
                    compensation_precondition = observer.observe()
                except (LookupError, OSError, RuntimeError, ValueError) as error:
                    raise ValueError("rollback precondition is unverifiable") from error
                if (
                    compensation_precondition.get("fresh") is not True
                    or compensation_precondition.get("target_id") != compensation.prepared.target_id
                    or compensation_precondition.get("target_digest") != compensation.prepared.target_digest
                    or compensation_precondition.get("resource_id") != target.resource_id
                    or type(compensation_precondition.get("observation_revision")) is not int
                    or compensation_precondition.get("observation_revision", 0) <= 0
                    or compensation_precondition.get("state") != dict(compensation.prepared.precondition)
                ):
                    raise ValueError("rollback precondition changed or target evidence is stale")
                if compensation.state != "authorized":
                    raise ValueError("fresh compensation start requires one authorized action")
                head = self._journal.current_task_head(original.task_id)
                start_event = make_event(
                    task_id=original.task_id,
                    sequence=head.sequence + 1,
                    event_id=f"{attempt_id}:start",
                    event_type="action.compensation_execution_started",
                    occurred_at=context.current_time,
                    actor={"kind": "runtime", "id": runtime_lineage_id},
                    expected_task_revision=head.revision,
                    baseline_digests=[compensation.prepared.baseline_digest],
                    payload={
                        "attempt_id": attempt_id, "claim_id": claim_id,
                        "original_action_id": action_id,
                        "original_started_event_digest": claim["started_event_digest"],
                        "compensation_action_id": compensation_action_id,
                        "compensation_authority_digest": authority.authority_digest,
                        "compensation_prepared_digest": compensation.prepared.prepared_action_digest,
                        "task_id": original.task_id, "lease_id": recovery_lease.lease_id,
                        "resources": list(recovery_lease.resources),
                        "fencing_tokens": dict(recovery_lease.fencing_tokens),
                        "target_id": compensation.prepared.target_id,
                        "target_digest": compensation.prepared.target_digest,
                        "baseline_digest": compensation.prepared.baseline_digest,
                        "snapshot_digest": compensation.prepared.snapshot_digest,
                        "disclosure_plan_digest": disclosure_plan.plan_digest,
                    },
                    previous_event_digest=head.head_digest,
                )
                snapshot = action_task_snapshot(
                    head.snapshot, task_id=original.task_id, revision=head.revision,
                    action_state="compensation-executing",
                )
                self._repository.commit(CommitBatch(
                    transaction_id=f"{attempt_id}:start", task_id=original.task_id,
                    expected_task_revision=head.revision, events=(start_event,), snapshot=snapshot,
                    catalog_delta={}, lease_assertion=self._lease_assertion(recovery_lease, original.task_id),
                    claim_compensation_delta=self._leases.start_claim_compensation(
                        claim, attempt_id=attempt_id,
                        compensation_action_id=compensation_action_id,
                        compensation_authority_digest=authority.authority_digest,
                        compensation_prepared_digest=compensation.prepared.prepared_action_digest,
                        start_event_digest=start_event["event_digest"],
                        target_id=compensation.prepared.target_id,
                        target_digest=compensation.prepared.target_digest,
                        baseline_digest=compensation.prepared.baseline_digest,
                        snapshot_digest=compensation.prepared.snapshot_digest,
                        disclosure_plan_digest=disclosure_plan.plan_digest,
                    ),
                    action_journal_delta=self._journal.compensation_start_delta(compensation),
                ))
                attempt = self._leases.recovery_attempt(claim_id)
                assert attempt is not None
                fence = dict(recovery_lease.fencing_tokens)[target.resource_id]
                execution_gate = getattr(target, "_durable_execution_gate", None)
                try:
                    if self._installation_validator is not None:
                        self._installation_validator()
                    if execution_gate is not None:
                        if type(execution_gate) is not _DurableExecutionGate:
                            raise ValueError(
                                "compensation target durable execution gate is foreign"
                            )
                        self._durable_execution_gates.arm(
                            execution_gate,
                            action_id=compensation.action_id,
                            claim_id=claim_id,
                            prepared_action_digest=(
                                compensation.prepared.prepared_action_digest
                            ),
                            payload=dict(compensation.prepared.payload),
                            fencing_token=fence,
                        )
                    try:
                        raw = target.invoke(
                            payload=dict(compensation.prepared.payload),
                            fencing_token=fence,
                            started_was_durable=True,
                        )
                    finally:
                        if execution_gate is not None:
                            self._durable_execution_gates.disarm(execution_gate)
                    receipt_state = "succeeded" if raw.get("result") == "succeeded" else "failed"
                    receipt_source = "tool-return"
                except TimeoutError as error:
                    raw = {"result": "unknown", "error_type": type(error).__name__}
                    receipt_state = "unknown"
                    receipt_source = "tool-return"
            else:
                if (
                    attempt["attempt_id"] != attempt_id
                    or attempt["compensation_action_id"] != compensation_action_id
                    or attempt["state"] not in {"started", "receipt_recorded", "reconciled"}
                ):
                    raise ValueError("committed recovery attempt binding changed")
                if attempt["state"] == "reconciled":
                    receipt = attempt["receipt"]
                    digest = receipt.get("receipt_digest") if isinstance(receipt, dict) else None
                    return self._issue_outcome(action_id, "compensated", "compensation-reconciled", claim_id, digest if isinstance(digest, str) else None)
                if attempt["state"] == "started":
                    observed_after_crash = observer.observe()
                    raw = {
                        "result": "succeeded"
                        if observed_after_crash.get("state") == dict(compensation.prepared.expected_postcondition)
                        else "unknown",
                        "recovered_by": "fresh-target-query",
                    }
                    receipt_state = str(raw["result"])
                    receipt_source = "post-crash-target-query"
                else:
                    receipt_state = "recorded"
                    receipt_source = "durable-receipt"
                    raw = {}

            if attempt["state"] == "started":
                receipt_object_digest, raw_result_digest = self._publish_bounded_receipt_object(
                    raw, result=receipt_state, receipt_source=receipt_source,
                )
                receipt = {
                    "protocol_version": "1.0.0",
                    "attempt_id": attempt_id,
                    "claim_id": claim_id,
                    "task_id": original.task_id,
                    "original_action_id": action_id,
                    "compensation_action_id": compensation_action_id,
                    "start_event_digest": attempt["start_event_digest"],
                    "authority_digest": authority.authority_digest,
                    "prepared_action_digest": compensation.prepared.prepared_action_digest,
                    "target_id": compensation.prepared.target_id,
                    "target_digest": compensation.prepared.target_digest,
                    "lease_id": recovery_lease.lease_id,
                    "resources": list(recovery_lease.resources),
                    "fencing_tokens": dict(recovery_lease.fencing_tokens),
                    "receipt_source": receipt_source,
                    "result": receipt_state,
                    "raw_result_digest": raw_result_digest,
                    "raw_receipt_object_digest": receipt_object_digest,
                }
                receipt["receipt_digest"] = semantic_record_digest({
                    "contract": "claim-compensation-receipt-v1", "value": receipt,
                })
                receipt_head = self._journal.current_task_head(original.task_id)
                receipt_event = make_event(
                    task_id=original.task_id, sequence=receipt_head.sequence + 1,
                    event_id=f"{attempt_id}:receipt", event_type="action.compensation_receipt_recorded",
                    occurred_at=self._journal.current_time(),
                    actor={"kind": "deterministic", "id": "compensation-receipt-recorder"},
                    expected_task_revision=receipt_head.revision,
                    baseline_digests=[compensation.prepared.baseline_digest],
                    payload={
                        "attempt_id": attempt_id,
                        "start_event_digest": attempt["start_event_digest"],
                        "claim_id": claim_id,
                        "compensation_action_id": compensation_action_id,
                        "task_id": original.task_id,
                        "receipt_digest": receipt["receipt_digest"],
                        "raw_receipt_object_digest": receipt_object_digest,
                        "receipt_source": receipt_source,
                        "target_id": compensation.prepared.target_id,
                        "target_digest": compensation.prepared.target_digest,
                        "lease_id": recovery_lease.lease_id,
                        "resources": list(recovery_lease.resources),
                        "fencing_tokens": dict(recovery_lease.fencing_tokens),
                        "result": receipt_state,
                    }, previous_event_digest=receipt_head.head_digest,
                )
                receipt_snapshot = action_task_snapshot(
                    receipt_head.snapshot, task_id=original.task_id, revision=receipt_head.revision,
                    action_state=f"compensation-{receipt_state}",
                )
                executing_compensation = self._journal.load(compensation_action_id)
                self._repository.commit(CommitBatch(
                    transaction_id=f"{attempt_id}:receipt", task_id=original.task_id,
                    expected_task_revision=receipt_head.revision, events=(receipt_event,),
                    snapshot=receipt_snapshot, catalog_delta={},
                    object_digests=(receipt_object_digest,),
                    lease_assertion=self._lease_assertion(recovery_lease, original.task_id),
                    claim_compensation_delta=self._leases.record_compensation_receipt(
                        claim, attempt=attempt, receipt_event_digest=receipt_event["event_digest"],
                        receipt=receipt,
                    ),
                    action_journal_delta=self._journal.compensation_receipt_delta(
                        executing_compensation, state=receipt_state, receipt=receipt,
                    ),
                ))
                attempt = self._leases.recovery_attempt(claim_id)
                assert attempt is not None
            receipt = attempt["receipt"]
            receipt_digest = receipt.get("receipt_digest") if isinstance(receipt, dict) else None
            if not isinstance(receipt, dict) or receipt.get("result") != "succeeded":
                return self._issue_outcome(action_id, "unknown", "manual-reconciliation", claim_id, receipt_digest if isinstance(receipt_digest, str) else None)
            observed = observer.observe()
            observed = dict(observed)
            observed["bound_receipt_digest"] = receipt_digest
            observed["observation_digest"] = semantic_record_digest({
                "contract": "fresh-target-observation-v1",
                "value": {
                    key: value for key, value in observed.items()
                    if key not in {"bound_receipt_digest", "observation_digest"}
                },
            })
            if (
                observed.get("fresh") is not True
                or type(observed.get("observation_revision")) is not int
                or observed.get("observation_revision", 0) <= 0
                or observed.get("target_id") != original.prepared.target_id
                or observed.get("target_digest") != original.prepared.target_digest
                or observed.get("resource_id") != target.resource_id
                or observed.get("state") != dict(original.prepared.precondition)
            ):
                return self._issue_outcome(action_id, "unknown", "manual-reconciliation", claim_id, receipt_digest if isinstance(receipt_digest, str) else None)
            reconcile_head = self._journal.current_task_head(original.task_id)
            reconcile_event = make_event(
                task_id=original.task_id, sequence=reconcile_head.sequence + 1,
                event_id=f"{attempt_id}:reconcile", event_type="action.compensation_reconciled",
                occurred_at=self._journal.current_time(),
                actor={"kind": "deterministic", "id": "compensation-reconciler"},
                expected_task_revision=reconcile_head.revision,
                baseline_digests=[original.prepared.baseline_digest],
                payload={
                    "attempt_id": attempt_id, "claim_id": claim_id,
                    "compensation_action_id": compensation_action_id,
                    "start_event_digest": attempt["start_event_digest"],
                    "receipt_event_digest": attempt["receipt_event_digest"],
                    "receipt_digest": receipt_digest,
                    "fresh_observation_digest": observed["observation_digest"],
                    "fresh_observation_revision": observed.get("observation_revision"),
                    "verified_outcome": "compensation_reconciled",
                }, previous_event_digest=reconcile_head.head_digest,
            )
            reconcile_snapshot = action_task_snapshot(
                reconcile_head.snapshot, task_id=original.task_id, revision=reconcile_head.revision,
                action_state="compensated",
            )
            current_original = self._journal.load(action_id)
            current_compensation = self._journal.load(compensation_action_id)
            self._repository.commit(CommitBatch(
                transaction_id=f"{attempt_id}:reconcile", task_id=original.task_id,
                expected_task_revision=reconcile_head.revision, events=(reconcile_event,),
                snapshot=reconcile_snapshot, catalog_delta={},
                lease_assertion=self._lease_assertion(recovery_lease, original.task_id),
                claim_compensation_delta=self._leases.reconcile_claim_compensation(
                    claim, attempt=attempt, reconciled_event_digest=reconcile_event["event_digest"],
                    fresh_observation=observed,
                ),
                action_journal_delta=self._journal.compensation_reconcile_delta(
                    current_original, current_compensation, observed,
                ),
            ))
            return self._issue_outcome(
                action_id, "compensated", "compensation-reconciled", claim_id,
                receipt_digest if isinstance(receipt_digest, str) else None,
            )
        finally:
            if resource_locks is not None:
                self._locks.release(resource_locks)
            self._locks.release(installation)
