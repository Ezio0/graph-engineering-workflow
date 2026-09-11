"""Deterministic WP-08 category-execution acceptance fixtures.

The doubles in this module deliberately expose no production authority.  They
only make repository mutations and local-target observations measurable while
the production Slice 3 factory/reducer/application boundary is developed.
"""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import pathlib
import tempfile
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Callable, Iterator


ROOT = pathlib.Path(__file__).resolve().parents[2]
CATEGORY_POLICY_PATH = ROOT / "config/profiles/category-execution-policy-v1.json"
CATEGORY_POLICY_REGISTRY_PATH = (
    ROOT / "config/profiles/category-execution-policy-registry-v1.json"
)
PROFILE_ROOT = ROOT / "config/profiles/definitions"
SUPPORT_MATRIX_PATH = ROOT / "config/profiles/support-matrix-v1.json"

PROFILE_IDS = (
    "new-feature",
    "bug-fix",
    "hotfix",
    "refactor-debt",
    "migration",
    "dependency-security",
    "performance",
    "release-operations",
    "incident-response",
)
COLUMNS = (
    "normal",
    "boundary",
    "revise",
    "authority",
    "drift",
    "invalidation",
    "recovery",
    "artifacts",
    "review",
    "target",
    "rollback",
)
REQUIRED_SCHEMA_IDS = (
    "urn:gew:schema:category-execution-policy-input:1.0.0",
    "urn:gew:schema:category-execution-policy:1.0.0",
    "urn:gew:schema:category-execution-state-input:1.0.0",
    "urn:gew:schema:category-execution-state:1.0.0",
    "urn:gew:schema:category-completion-assessment-input:1.0.0",
    "urn:gew:schema:category-completion-assessment:1.0.0",
    "urn:gew:schema:category-target-observation-input:1.0.0",
    "urn:gew:schema:category-target-observation:1.0.0",
    "urn:gew:schema:category-rollback-assessment-input:1.0.0",
    "urn:gew:schema:category-rollback-assessment:1.0.0",
)


class MissingCategoryExecutionContract(AssertionError):
    """The production Slice 3 public contract does not exist yet."""


@dataclass(frozen=True, slots=True)
class Slice3API:
    CategoryExecutionPolicy: type
    CategoryExecutionState: type
    CategoryExecutionEvent: type
    CategoryExecutionReducer: type
    CategoryCompletionOracle: type
    CategoryCompletionAssessment: type
    CategoryTargetObservation: type
    CategoryTargetObservationAuthority: type
    TargetObservationFence: type
    CategoryRollbackBridge: type
    CategoryAssessmentResolver: type
    CategoryExecutionApplication: type
    CategoryExecutionError: type[Exception]


def load_slice3_api() -> Slice3API:
    """Resolve the closed production surface without a test fallback."""

    missing: list[str] = []
    if not CATEGORY_POLICY_PATH.is_file():
        missing.append("config/profiles/category-execution-policy-v1.json")
    installed_schema_ids = frozenset(profile_schema_ids())
    missing.extend(
        schema_id for schema_id in REQUIRED_SCHEMA_IDS
        if schema_id not in installed_schema_ids
    )
    try:
        core = importlib.import_module("graph_engineering.core.profile_execution")
    except ModuleNotFoundError:
        core = None
        missing.append("graph_engineering.core.profile_execution")
    try:
        application = importlib.import_module(
            "graph_engineering.application.profile_execution"
        )
    except ModuleNotFoundError:
        application = None
        missing.append("graph_engineering.application.profile_execution")
    core_names = (
        "CategoryExecutionPolicy",
        "CategoryExecutionState",
        "CategoryExecutionEvent",
        "CategoryExecutionReducer",
        "CategoryCompletionAssessment",
        "CategoryTargetObservation",
        "CategoryExecutionError",
    )
    application_names = (
        "CategoryCompletionOracle",
        "CategoryTargetObservationAuthority",
        "CategoryRollbackBridge",
        "CategoryAssessmentResolver",
        "CategoryExecutionApplication",
        "TargetObservationFence",
    )
    for name in core_names:
        if core is None or not isinstance(getattr(core, name, None), type):
            missing.append(name)
    for name in application_names:
        if application is None or not isinstance(getattr(application, name, None), type):
            missing.append(name)
    if missing:
        raise MissingCategoryExecutionContract(
            "WP-08 Slice 3 production contract is absent: " + ", ".join(missing)
        )
    error_type = getattr(core, "CategoryExecutionError")
    if not issubclass(error_type, Exception):
        raise MissingCategoryExecutionContract(
            "CategoryExecutionError is not an exception type"
        )
    return Slice3API(
        **{name: getattr(core, name) for name in core_names},
        **{name: getattr(application, name) for name in application_names},
    )


def load_json(path: pathlib.Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise AssertionError(f"fixture is not an object: {path.name}")
    return value


def load_json_bytes(body: bytes) -> dict[str, object]:
    value = json.loads(body)
    if type(value) is not dict:
        raise AssertionError("fixture bytes are not an object")
    return value


def profile_document(profile_id: str) -> dict[str, object]:
    if profile_id not in PROFILE_IDS:
        raise AssertionError("unknown WP-08 Profile fixture")
    return load_json(PROFILE_ROOT / f"{profile_id}-v1.json")


def category_policy_document() -> dict[str, object]:
    if not CATEGORY_POLICY_PATH.is_file():
        raise MissingCategoryExecutionContract(
            "config/profiles/category-execution-policy-v1.json is absent"
        )
    return load_json(CATEGORY_POLICY_PATH)


def resign_category_policy(document: dict[str, object]) -> None:
    from graph_engineering.core.contracts.digest import semantic_digest

    body = copy.deepcopy(document)
    body.pop("policy_digest", None)
    document["policy_digest"] = semantic_digest(
        body,
        contract_type="urn:gew:contract:category-execution-policy",
        projection_id="urn:gew:digest-projection:category-execution-policy:1.0.0",
        schema_id="urn:gew:schema:category-execution-policy-input:1.0.0",
    )


def profile_schema_ids() -> tuple[str, ...]:
    manifest = load_json(ROOT / "config/contracts/profile-schema-registry-v1.json")
    resources = manifest.get("resources")
    if type(resources) is not list:
        raise AssertionError("Profile schema registry fixture is invalid")
    return tuple(
        str(item["schema_id"])
        for item in resources
        if type(item) is dict and type(item.get("schema_id")) is str
    )


def assert_frozen_policy_and_schema_contract() -> None:
    """Mechanical R1-006/007 probe for installation pins and typed schemas."""

    if not CATEGORY_POLICY_REGISTRY_PATH.is_file():
        raise AssertionError("installation-pinned category policy registry is absent")
    registry = load_json(CATEGORY_POLICY_REGISTRY_PATH)
    if set(registry) != {
        "schema_version", "registry_id", "policy_id", "policy_digest",
        "policy_path", "policy_raw_sha256", "registry_digest",
    }:
        raise AssertionError("category policy registry is not exact")
    policy = category_policy_document()
    transitions = policy.get("transition_rules")
    if type(transitions) is not list or any(
        type(item) is not dict
        or set(item) != {
            "column_id", "from_state", "event_type", "to_state",
            "evidence_kind", "required_outcome", "required_fact_ids",
            "owner_route",
        }
        for item in transitions
    ):
        raise AssertionError("category column evidence/outcome policy is absent")
    outcomes = [item["required_outcome"] for item in transitions]
    if len(outcomes) != len(set(outcomes)):
        raise AssertionError("category outcomes are not column-specific")
    schema_root = ROOT / "config/contracts/schemas"
    for schema_id in REQUIRED_SCHEMA_IDS:
        name = schema_id.removeprefix("urn:gew:schema:").removesuffix(":1.0.0")
        schema = load_json(schema_root / f"{name}-1.0.0.json")
        properties = schema.get("properties")
        if (
            schema.get("unevaluatedProperties") is not False
            or type(properties) is not dict
            or any(definition == {} for definition in properties.values())
        ):
            raise AssertionError(f"category schema is not typed and closed: {schema_id}")


def assert_digest_schema_patterns() -> None:
    """Require exact lowercase semantic/raw digest patterns in all ten schemas."""

    schema_root = ROOT / "config/contracts/schemas"
    for schema_id in REQUIRED_SCHEMA_IDS:
        name = schema_id.removeprefix("urn:gew:schema:").removesuffix(":1.0.0")
        schema = load_json(schema_root / f"{name}-1.0.0.json")
        definitions = schema.get("$defs")
        if (
            type(definitions) is not dict
            or definitions.get("digest", {}).get("pattern")
            != r"^sha256-jcs-v1:[0-9a-f]{64}$"
            or definitions.get("raw", {}).get("pattern")
            != r"^[0-9a-f]{64}$"
        ):
            raise AssertionError(f"category digest schema is open: {schema_id}")


def category_schema_registry():  # type: ignore[no-untyped-def]
    from graph_engineering.core.contracts.resources import (
        CostSchedule,
        ResourceProfile,
        WorkContext,
    )
    from graph_engineering.core.contracts.schema import SchemaProfilePolicy
    from graph_engineering.core.profiles import build_profile_schema_registry

    manifest = load_json(ROOT / "config/contracts/profile-schema-registry-v1.json")
    schema_root = ROOT / "config/contracts/schemas"
    bodies = {
        item["schema_id"]: (
            schema_root
            / (
                str(item["schema_id"])
                .removeprefix("urn:gew:schema:")
                .replace(":", "-")
                + ".json"
            )
        ).read_bytes()
        for item in manifest["resources"]
    }
    profile = ResourceProfile.from_dict(load_json(
        ROOT / "config/contracts/resource-profile-v1.json"
    ))
    schedule = CostSchedule.from_dict(load_json(
        ROOT / "config/contracts/cost-schedule-v1.json"
    ))
    policy = SchemaProfilePolicy.from_dict(load_json(
        ROOT / "config/contracts/schema-profile-v1.json"
    ))
    return build_profile_schema_registry(manifest, bodies, profile, policy), WorkContext(
        profile, schedule
    )


def digest(label: str) -> str:
    return "sha256-jcs-v1:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def internal_digest(value: object, name: str) -> str:
    from graph_engineering.core.contracts.canonical import canonical_bytes

    framed = b"GEW-INTERNAL-DIGEST-V1\x00" + name.encode("ascii") + b"\x00"
    return "sha256-jcs-v1:" + hashlib.sha256(framed + canonical_bytes(value)).hexdigest()


class RecordingCategoryRepository:
    """Instance-scoped durable-port double with atomic staged commits."""

    def __init__(
        self,
        durable: dict[str, object] | None = None,
        *,
        profile_id: str | None = None,
        column_id: str | None = None,
    ) -> None:
        if durable is not None:
            self._durable = durable
            return
        category_facts = (
            None
            if profile_id is None or column_id is None
            else candidate_facts_document(profile_id, column_id)
        )
        graph_ref = None
        if type(category_facts) is dict:
            pins = category_facts["digest_pins"]
            assert isinstance(pins, dict)
            graph_ref = {
                "schema_version": "1.0.0",
                "graph_id": f"slice3-{profile_id}",
                "graph_version": "1.0.0",
                "graph_digest": pins["base_graph_digest"],
                "profile_id": profile_id,
                "profile_version": "1.0.0",
                "profile_digest": pins["profile_digest"],
                "overlay_id": category_facts["overlay_id"],
                "overlay_version": "1.0.0",
                "overlay_digest": pins["overlay_digest"],
                "project_config_digest": pins["project_config_digest"],
                "support_matrix_digest": pins["support_matrix_digest"],
                "materialization_digest": pins["materialization_digest"],
            }
        self._durable = {
            "events": [],
            "snapshots": [],
            "objects": {},
            "object_references": [],
            "current": None,
            "transactions": {},
            "task_authority": (
                None
                if profile_id is None
                else {
                    "task_id": f"task:{profile_id}:local",
                    "task_revision": 1,
                    "snapshot_digest": digest(f"snapshot:{profile_id}:1"),
                    "invalidation_epoch": 0,
                    "graph_ref": graph_ref,
                }
            ),
            "category_facts": category_facts,
            "category_evidence": (
                None
                if profile_id is None or column_id is None
                else column_evidence_document(
                    category_facts, column_id
                )
            ),
        }
        self._observer: object | None = None

    def signature(self) -> dict[str, object]:
        return copy.deepcopy(self._durable)

    def restart(self) -> RecordingCategoryRepository:
        restarted = RecordingCategoryRepository(self._durable)
        restarted._observer = self._observer
        return restarted

    def resolve_task_snapshot(self, task_id: str) -> object:
        value = self._durable["task_authority"]
        if type(value) is not dict or value.get("task_id") != task_id:
            raise ValueError("current task snapshot authority is unavailable")
        return copy.deepcopy(value)

    def resolve_category_execution_facts(self, task_id: str) -> object:
        value = self._durable.get("category_facts")
        if type(value) is not dict or value.get("task_id") != task_id:
            raise ValueError("durable category execution facts are unavailable")
        return copy.deepcopy(value)

    def replace_category_facts(self, value: object) -> None:
        self._durable["category_facts"] = copy.deepcopy(value)

    def replace_task_authority(self, value: object) -> None:
        self._durable["task_authority"] = copy.deepcopy(value)

    def resolve_category_evidence(self, task_id: str, column_id: str) -> object:
        value = self._durable.get("category_evidence")
        if (
            type(value) is not dict
            or value.get("task_id") != task_id
            or value.get("column_id") != column_id
        ):
            raise ValueError("durable category evidence is unavailable")
        return copy.deepcopy(value)

    def replace_category_evidence(self, value: object) -> None:
        self._durable["category_evidence"] = copy.deepcopy(value)

    def bind_target_observer(self, observer: object) -> None:
        self._observer = observer

    def require_target_observer(self, observer: object) -> None:
        if observer is not self._observer:
            raise ValueError("target observer capability is foreign")

    def current(self) -> object:
        return copy.deepcopy(self._durable["current"])

    def get(self, object_digest: str, *, require_referenced: bool = True) -> bytes:
        objects = self._durable["objects"]
        references = self._durable["object_references"]
        if type(objects) is not dict or type(references) is not list:
            raise AssertionError("recording repository was corrupted")
        if require_referenced and object_digest not in references:
            raise ValueError("category assessment object is not referenced")
        body = objects.get(object_digest)
        if type(body) is not bytes:
            raise ValueError("category assessment object is absent")
        return bytes(body)

    def commit_category_assessment(
        self,
        *,
        transaction_id: str,
        event: dict[str, object],
        snapshot: dict[str, object],
        object_digest: str,
        object_body: bytes,
        expected_revision: int,
    ) -> dict[str, object]:
        transactions = self._durable["transactions"]
        events = self._durable["events"]
        snapshots = self._durable["snapshots"]
        objects = self._durable["objects"]
        references = self._durable["object_references"]
        if not all((
            type(transactions) is dict,
            type(events) is list,
            type(snapshots) is list,
            type(objects) is dict,
            type(references) is list,
        )):
            raise AssertionError("recording repository was corrupted")
        existing = transactions.get(transaction_id)
        if existing is not None:
            return copy.deepcopy(existing)
        if len(events) != expected_revision:
            raise ValueError("category assessment revision conflict")
        staged = copy.deepcopy(self._durable)
        staged_objects = staged["objects"]
        staged_events = staged["events"]
        staged_snapshots = staged["snapshots"]
        staged_references = staged["object_references"]
        staged_transactions = staged["transactions"]
        assert isinstance(staged_objects, dict)
        assert isinstance(staged_events, list)
        assert isinstance(staged_snapshots, list)
        assert isinstance(staged_references, list)
        assert isinstance(staged_transactions, dict)
        existing_body = staged_objects.get(object_digest)
        if existing_body is not None and existing_body != object_body:
            raise ValueError("category assessment object digest collision")
        staged_objects[object_digest] = bytes(object_body)
        staged_events.append(copy.deepcopy(event))
        staged_snapshots.append(copy.deepcopy(snapshot))
        if object_digest not in staged_references:
            staged_references.append(object_digest)
        receipt = {
            "transaction_id": transaction_id,
            "revision": len(staged_events),
            "object_digest": object_digest,
        }
        staged["current"] = copy.deepcopy(snapshot)
        staged_transactions[transaction_id] = copy.deepcopy(receipt)
        self._durable.clear()
        self._durable.update(staged)
        return receipt


class ProductionCategoryProbe:
    """Test-only observability/tamper probe; never supplies production authority."""

    def __init__(
        self,
        *,
        stack: ExitStack,
        factory: object,
        repository: object,
        objects: object,
        task_application: object,
        runtime: object,
        task_id: str,
        baseline_event_count: int,
        baseline_object_digests: tuple[str, ...],
        evidence_by_column: dict[str, tuple[str, dict[str, object]]],
        source_by_kind: dict[str, tuple[str, dict[str, object]]],
    ) -> None:
        self._stack = stack
        self.factory = factory
        self.repository = repository
        self.objects = objects
        self.task_application = task_application
        self.runtime = runtime
        self.task_id = task_id
        self._baseline_event_count = baseline_event_count
        self._baseline_object_digests = baseline_object_digests
        self._evidence_by_column = evidence_by_column
        self._source_by_kind = source_by_kind
        self._rollback_action: object | None = None
        self._rollback_action_target: object | None = None
        self._rollback_local_target: object | None = None

    def close(self) -> None:
        stack = self.__dict__.get("_stack")
        if stack is None:
            return
        try:
            stack.close()
        finally:
            # ExitStack.close() releases the resources, but the probe itself
            # is deliberately retained by coverage diagnostics.  Drop every
            # closed repository/application/real-E2E reference immediately;
            # a second close remains a no-op.
            self.__dict__.clear()
            self._stack = None

    def signature(self) -> dict[str, object]:
        from graph_engineering.storage.codec import parse_canonical_json

        with self.factory.open("application") as connection:
            row = connection.execute(
                "SELECT revision,snapshot_json FROM tasks WHERE task_id=?",
                (self.task_id,),
            ).fetchone()
            events = connection.execute(
                "SELECT body_json FROM events WHERE task_id=? ORDER BY sequence",
                (self.task_id,),
            ).fetchall()
            refs = connection.execute(
                "SELECT digest FROM object_references WHERE task_id=? ORDER BY digest",
                (self.task_id,),
            ).fetchall()
        if row is None:
            raise AssertionError("production category task disappeared")
        wrapper = parse_canonical_json(row[1])
        if type(wrapper) is not dict:
            raise AssertionError("production category task wrapper is malformed")
        domain = wrapper.get("domain")
        evidence = domain.get("evidence", []) if type(domain) is dict else []
        new_refs = [
            item[0] for item in refs if item[0] not in self._baseline_object_digests
        ]
        assessment_refs = [
            item for item in evidence
            if type(item) is dict
            and item.get("evidence_type") == "category-completion-assessment"
        ] if type(evidence) is list else []
        current = None
        if assessment_refs:
            reference = assessment_refs[0]
            current = {
                "task_id": self.task_id,
                "evidence": copy.deepcopy(evidence),
                "assessment_digest": reference.get("evidence_id"),
                "assessment_object_digest": reference.get("source_ref"),
                "repository_revision": row[0],
            }
        return {
            "events": [item[0] for item in events[self._baseline_event_count:]],
            "snapshots": [] if current is None else [copy.deepcopy(wrapper)],
            "objects": list(new_refs),
            "object_references": list(new_refs),
            "current": current,
            "task_wrapper": copy.deepcopy(wrapper),
        }

    def restart_authorities(self):  # type: ignore[no-untyped-def]
        from graph_engineering.application.tasks import TaskApplication

        application = TaskApplication(
            self.repository,
            self.repository,
            self.task_application._leases,
            schema_registry=self.task_application._schemas,
            context=self.task_application._context,
            materialization_objects=self.objects,
        )
        return application, self.runtime

    def resolve_category_evidence(
        self, task_id: str, column_id: str
    ) -> dict[str, object]:
        if task_id != self.task_id or column_id not in self._evidence_by_column:
            raise ValueError("category evidence fixture is unavailable")
        return copy.deepcopy(self._evidence_by_column[column_id][1])

    def _delete_ref(self, object_digest: str) -> None:
        with self.factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "DELETE FROM object_references WHERE task_id=? AND digest=?",
                    (self.task_id, object_digest),
                )

    def _insert_ref(self, object_digest: str) -> None:
        with self.factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "INSERT INTO object_references(task_id,digest,ref_kind,transaction_id) "
                    "VALUES(?,?,'task','test-only-category-tamper')",
                    (self.task_id, object_digest),
                )

    def replace_category_evidence_for(
        self, column_id: str, value: object
    ) -> None:
        from graph_engineering.core.contracts.canonical import canonical_bytes

        if column_id not in self._evidence_by_column:
            raise AssertionError("replacement category evidence column is unknown")
        if value is None:
            digest_value, _record = self._evidence_by_column[column_id]
            self._delete_ref(digest_value)
            return
        if type(value) is not dict:
            raise AssertionError("replacement category evidence is malformed")
        old_digest, _old = self._evidence_by_column[column_id]
        body = canonical_bytes(value)
        new_digest = self.objects.digest(body)
        self.objects.put_verified(body, new_digest)
        self._delete_ref(old_digest)
        self._insert_ref(new_digest)
        self._evidence_by_column[column_id] = (new_digest, copy.deepcopy(value))

    def replace_category_evidence(self, value: object) -> None:
        if value is None:
            for column_id in tuple(self._evidence_by_column):
                self.replace_category_evidence_for(column_id, None)
            return
        if type(value) is not dict or type(value.get("column_id")) is not str:
            raise AssertionError("replacement category evidence is malformed")
        self.replace_category_evidence_for(value["column_id"], value)

    def resolve_category_source(self, kind: str) -> dict[str, object]:
        if kind not in self._source_by_kind:
            raise ValueError("category source fixture is unavailable")
        return copy.deepcopy(self._source_by_kind[kind][1])

    def replace_category_source(self, kind: str, value: dict[str, object]) -> None:
        from graph_engineering.core.contracts.canonical import canonical_bytes

        if kind not in self._source_by_kind or type(value) is not dict:
            raise AssertionError("replacement category source is malformed")
        old_digest, _old = self._source_by_kind[kind]
        body = canonical_bytes(value)
        new_digest = self.objects.digest(body)
        self.objects.put_verified(body, new_digest)
        self._delete_ref(old_digest)
        self._insert_ref(new_digest)
        self._source_by_kind[kind] = (new_digest, copy.deepcopy(value))

    def bind_rollback_evidence(self, bridge: object) -> None:
        """Bind the fixture's expected result to the exact prepared rollback action."""

        from graph_engineering.application.profile_execution import CategoryRollbackBridge

        if type(bridge) is not CategoryRollbackBridge:
            raise AssertionError("rollback evidence bridge is not production authority")
        context = bridge._CategoryRollbackBridge__action_context
        if not isinstance(context, dict):
            raise AssertionError("rollback evidence action was not prepared")
        prepared = context.get("prepared")
        action_id = getattr(prepared, "action_id", None)
        if type(action_id) is not str:
            raise AssertionError("rollback evidence action ID is unavailable")
        evidence = self.resolve_category_evidence(self.task_id, "rollback")
        evidence["facts"] = {
            "action-id": action_id,
            "action-status": "reconciled",
            "claim-status": "reconciled_effect_verified",
        }
        resign_column_evidence(evidence)
        self.replace_category_evidence_for("rollback", evidence)
        self._baseline_object_digests = tuple(
            item[0] for item in self.repository.referenced_objects(self.task_id)
        )

    def bind_rollback_audit(
        self, action: object, action_target: object, local_target: object,
    ) -> None:
        if self._rollback_action is not None:
            raise AssertionError("rollback audit authority is already bound")
        self._rollback_action = action
        self._rollback_action_target = action_target
        self._rollback_local_target = local_target

    def rollback_signature(self) -> dict[str, object]:
        """Return the complete deterministic coordinator and target baseline."""

        action = self._rollback_action
        action_target = self._rollback_action_target
        local_target = self._rollback_local_target
        journal = getattr(action, "journal", None)
        factory = getattr(journal, "_factory", None)
        if factory is None or action_target is None or local_target is None:
            raise AssertionError("rollback audit authority is unavailable")
        tables: dict[str, list[tuple[object, ...]]] = {}
        with factory.open("application") as connection:
            names = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            for row in names:
                name = row[0]
                if type(name) is not str or not name.replace("_", "").isalnum():
                    raise AssertionError("rollback audit table identity is unsafe")
                tables[name] = [
                    tuple(item) for item in connection.execute(
                        f'SELECT * FROM "{name}" ORDER BY rowid'
                    ).fetchall()
                ]
        return {
            "tables": tables,
            "action_target_state": copy.deepcopy(action_target._state),
            "action_target_calls": action_target.call_count,
            "local_target_bytes": local_target.path.read_bytes(),
            "local_target_revision": local_target._revision,
            "local_target_mutations": local_target.mutation_count,
        }

    def replace_category_facts(self, value: object) -> None:
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json

        with self.factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT snapshot_json FROM tasks WHERE task_id=?", (self.task_id,),
                ).fetchone()
                wrapper = parse_canonical_json(row[0])
                if not isinstance(wrapper, dict) or not isinstance(wrapper.get("runner"), dict):
                    raise AssertionError("task runner fixture is malformed")
                wrapper["runner"]["node_outputs"] = {}  # type: ignore[index]
                connection.execute(
                    "UPDATE tasks SET snapshot_json=? WHERE task_id=?",
                    (canonical_json(wrapper), self.task_id),
                )

    def replace_task_authority(self, value: object) -> None:
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json

        with self.factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT snapshot_json FROM tasks WHERE task_id=?", (self.task_id,),
                ).fetchone()
                wrapper = parse_canonical_json(row[0])
                if not isinstance(wrapper, dict) or not isinstance(wrapper.get("domain"), dict):
                    raise AssertionError("task domain fixture is malformed")
                domain = wrapper["domain"]
                if isinstance(value, dict):
                    domain["task_revision"] = value.get("task_revision", domain["task_revision"])
                    domain["invalidation_epoch"] = value.get(
                        "invalidation_epoch", domain["invalidation_epoch"]
                    )
                connection.execute(
                    "UPDATE tasks SET snapshot_json=? WHERE task_id=?",
                    (canonical_json(wrapper), self.task_id),
                )


def _durable_record(kind: str, values: dict[str, object]) -> dict[str, object]:
    record = {"schema_version": "1.0.0", "record_kind": kind, **values}
    record["record_digest"] = internal_digest(record, kind)
    return record


@dataclass(slots=True)
class SharedProductionCategoryRuntime:
    """One per-Profile test fixture repository with independent task rows."""

    profile_id: str
    stack: ExitStack
    factory: object
    objects: object
    repository: object
    leases: object
    schemas: object
    context: object
    application: object
    runtime: object
    dependency_security_context: object | None = None

    def close(self) -> None:
        stack = self.stack
        try:
            dependency_context = self.dependency_security_context
            close_dependency = getattr(dependency_context, "close", None)
            if callable(close_dependency):
                close_dependency()
            stack.close()
        finally:
            # Closing an ExitStack releases its resources, but the fixture
            # object would otherwise retain the full repository/application
            # graph until method teardown.  Replace those closed references
            # immediately so coverage-batch cleanup stays bounded.
            object.__setattr__(self, "stack", ExitStack())
            object.__setattr__(self, "factory", None)
            object.__setattr__(self, "objects", None)
            object.__setattr__(self, "repository", None)
            object.__setattr__(self, "leases", None)
            object.__setattr__(self, "schemas", None)
            object.__setattr__(self, "context", None)
            object.__setattr__(self, "application", None)
            object.__setattr__(self, "runtime", None)
            object.__setattr__(self, "dependency_security_context", None)


def shared_production_category_runtime(
    profile_id: str,
) -> SharedProductionCategoryRuntime:
    """Build a test-only per-Profile repository fixture for coverage bindings."""

    if profile_id not in PROFILE_IDS:
        raise AssertionError("shared Profile runtime identity is unknown")
    from graph_engineering.application.tasks import TaskApplication
    from tests.contract.test_wp02_graph import graph_schemas, work_context
    from tests.support.runtime import runtime_context
    from tests.support.wp03_repository import repository_stack

    stack = ExitStack()
    try:
        _root, factory, _locks, objects, repository, leases = stack.enter_context(
            repository_stack()
        )
        schemas = graph_schemas()
        context = work_context()
        application = TaskApplication(
            repository,
            repository,
            leases,
            schema_registry=schemas,
            context=context,
            materialization_objects=objects,
        )
        runtime = runtime_context(
            f"owner:{profile_id}", "codex", f"lineage:{profile_id}",
            f"actor:{profile_id}", "2026-08-24T00:00:00Z", 10**12,
        )
        return SharedProductionCategoryRuntime(
            profile_id=profile_id,
            stack=stack,
            factory=factory,
            objects=objects,
            repository=repository,
            leases=leases,
            schemas=schemas,
            context=context,
            application=application,
            runtime=runtime,
        )
    except BaseException:
        stack.close()
        raise


def production_category_runtime(
    profile_id: str,
    column: str,
    *,
    target: DisposableLocalTarget,
    scenario_id: str | None = None,
    real_e2e_authority: object | None = None,
    task_id: str | None = None,
    shared_runtime: SharedProductionCategoryRuntime | None = None,
):  # type: ignore[no-untyped-def]
    """Build the exact production TaskApplication/TaskRepository authority chain."""

    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.graph.state import DomainEvent, TaskCommand, apply_events
    from tests.contract.test_wp02_graph import graph_schemas, loop_budgets, work_context
    from tests.support.runtime import runtime_context
    from tests.support.wp03_repository import repository_stack
    from tests.unit.test_wp06_project_scope import load as load_scope, scope_document

    stack = ExitStack()
    try:
        if shared_runtime is None:
            _root, factory, _locks, objects, repository, leases = stack.enter_context(
                repository_stack()
            )
            schemas = graph_schemas()
            context = work_context()
            application = TaskApplication(
                repository,
                repository,
                leases,
                schema_registry=schemas,
                context=context,
                materialization_objects=objects,
            )
            runtime = runtime_context(
                f"owner:{profile_id}", "codex", f"lineage:{profile_id}",
                f"actor:{profile_id}", "2026-08-24T00:00:00Z", 10**12,
            )
        else:
            if shared_runtime.profile_id != profile_id:
                raise AssertionError("shared Profile runtime is foreign")
            factory = shared_runtime.factory
            objects = shared_runtime.objects
            repository = shared_runtime.repository
            leases = shared_runtime.leases
            schemas = shared_runtime.schemas
            context = shared_runtime.context
            application = shared_runtime.application
            runtime = shared_runtime.runtime
        task_id = f"task:{profile_id}:local" if task_id is None else task_id
        if type(task_id) is not str or not task_id:
            raise AssertionError("category fixture task identity is invalid")
        identity = {
            "task_id": task_id,
            "owner_id": runtime.owner_id,
            "runtime_kind": runtime.runtime_kind,
            "runtime_lineage_id": runtime.runtime_lineage_id,
        }
        scope = load_scope(scope_document())
        scope_ref = lambda status: {  # noqa: E731
            "scope_id": scope.scope_id,
            "version": scope.version,
            "digest": scope.scope_digest,
            "status": status,
        }
        materialized = materialized_profile(profile_id)
        materialization_ref = application.preauthorize_materialization(
            materialized.record
        )
        application.execute(
            task_id, TaskCommand("create", 0, {"identity": identity}), runtime,
        )
        application.execute_scope(
            task_id,
            TaskCommand("bind_project_scope", 1, {
                "project_scope_ref": scope_ref("drafted"),
            }),
            scope,
            runtime,
        )
        application.execute(
            task_id,
            TaskCommand("request_prd_approval", 2, {
                "prd_candidate_ref": f"artifact:prd:{profile_id}",
            }),
            runtime,
        )
        application.execute(
            task_id,
            TaskCommand("approve_prd", 3, {
                "project_scope_ref": scope_ref("frozen"),
                "owner_decision_ref": f"decision:{profile_id}:approved",
                "baseline_refs": ({
                    "kind": "intent", "version": 1,
                    "digest": digest(f"intent:{profile_id}"),
                    "approved_by": runtime.owner_id,
                    "approved_at": "2026-08-24T00:00:00Z",
                },),
                "graph_ref": dict(materialized.graph_ref()),
                "authority_refs": ("authority:category-current",),
            }),
            runtime,
            materialization_reference=materialization_ref,
        )
        application.execute(
            task_id,
            TaskCommand("run", 5, {
                "compatibility_evidence_ref": "evidence:wp08-category-compatible",
                "lease_plan_ref": "lease-plan:none-v1",
            }),
            runtime,
        )
        view = application.runtime_show(task_id, runtime)
        current = candidate_facts_document(
            profile_id, column, scenario_id=scenario_id,
        )
        current["task_id"] = task_id
        runner = copy.deepcopy(dict(view.runner_state))
        required_nodes = tuple(current["required_node_ids"])
        outputs: dict[str, dict[str, object]] = {}
        reviews: list[dict[str, object]] = []
        for index, node_id in enumerate(required_nodes):
            body_digest = digest(f"runner-body:{profile_id}:{node_id}:2")
            output = {
                "node_id": node_id,
                "run_id": f"run:{profile_id}:{node_id}",
                "attempt": 2,
                "body_digest": body_digest,
                "author_id": f"author:{profile_id}:{node_id}",
                "trust": "independently_reviewed",
                "evidence_refs": [],
                "verdict": "PASS",
                "reviewer_id": f"reviewer:{profile_id}:{node_id}",
                "route_roots": {},
            }
            outputs[node_id] = output
            if index == len(required_nodes) - 1:
                reviews.append({
                    "node_id": node_id,
                    "run_id": output["run_id"],
                    "attempt": 1,
                    "body_digest": digest(f"runner-body:{profile_id}:{node_id}:1"),
                    "reviewer_id": output["reviewer_id"],
                    "verdict": "REVISE",
                    "finding_ids": [],
                    "findings": [],
                })
            reviews.append({
                "node_id": node_id,
                "run_id": output["run_id"],
                "attempt": 2,
                "body_digest": body_digest,
                "reviewer_id": output["reviewer_id"],
                "verdict": "PASS",
                "finding_ids": [],
                "findings": [],
            })
        runner["node_outputs"] = outputs
        runner["review_history"] = reviews
        event = DomainEvent(
            view.snapshot.last_event_seq + 1,
            view.snapshot.task_revision,
            "task.completion_started",
            {},
        )
        next_snapshot = apply_events(
            view.snapshot, (event,), schema_registry=schemas, context=context,
        )
        current["task_revision"] = next_snapshot.task_revision
        current["snapshot_digest"] = next_snapshot.snapshot_digest
        current["invalidation_epoch"] = next_snapshot.invalidation_epoch

        records: list[dict[str, object]] = []
        target_record = _durable_record("category-target-contract-v1", {
            "task_id": task_id,
            "profile_id": profile_id,
            "target_id": target.target_id,
            "resource_id": target.resource_id,
            "expected_state": target.expected_state,
            "rollback_state": target.rollback_state,
        })
        records.append(target_record)
        artifact_records: list[dict[str, object]] = []
        for contract_id in current["required_artifact_contract_ids"]:
            artifact_record = _durable_record("category-artifact-record-v1", {
                "task_id": task_id,
                "artifact_id": f"artifact:{profile_id}:{contract_id}",
                "contract_id": contract_id,
                "body_digest": digest(f"artifact-body:{profile_id}:{contract_id}"),
                "author_id": f"author:{profile_id}:{contract_id}",
                "reviewer_id": f"reviewer:{profile_id}:{contract_id}",
                "status": "accepted-for-category",
            })
            artifact_records.append(artifact_record)
            records.append(artifact_record)
        current_review = reviews[-1]
        previous_review = reviews[-2]
        common_source = {
            "task_id": task_id,
            "profile_id": profile_id,
            "task_revision": current["task_revision"],
            "snapshot_digest": current["snapshot_digest"],
            "invalidation_epoch": current["invalidation_epoch"],
        }
        revision_record = _durable_record("category-revision-record-v1", {
            **common_source,
            "budget_remaining": 1,
            "current_body_digest": current_review["body_digest"],
            "previous_body_digest": previous_review["body_digest"],
            "owner_route": "owner-revision",
        })
        drift_record = _durable_record("category-drift-record-v1", {
            **common_source,
            "target_id": target.target_id,
            "target_digest": internal_digest(
                target.expected_state, "category-target-state"
            ),
            "status": "resolved",
        })
        recovery_record = _durable_record("category-recovery-record-v1", {
            **common_source,
            "recovery_id": f"recovery:{task_id}",
            "status": "recovered",
        })
        records.extend((revision_record, drift_record, recovery_record))
        durable_sources: dict[str, object] = {
            "runner_outputs": outputs,
            "current_review": current_review,
            "revision": revision_record,
            "drift": drift_record,
            "recovery": recovery_record,
            "artifact_records": artifact_records,
            "target_record": target_record,
            "review_author_id": outputs[str(current_review["node_id"])]["author_id"],
        }
        real_e2e_record = None
        if real_e2e_authority is not None:
            from graph_engineering.application.profile_real_e2e import (
                ProfileRealE2EAuthority,
                ProfileRealE2EObserver,
            )

            if (
                type(real_e2e_authority) is not ProfileRealE2EAuthority
                or type(target) is not ProfileRealE2EObserver
                or target._authority is not real_e2e_authority
            ):
                raise AssertionError("real-E2E fixture authority is foreign")
            real_e2e_record = real_e2e_authority.stage_task(next_snapshot)
            records.append(real_e2e_record.to_dict())
            durable_sources["real_e2e_facts"] = real_e2e_authority.evidence_facts(
                real_e2e_record
            )
        evidence_by_column: dict[str, tuple[str, dict[str, object]]] = {}
        source_by_kind: dict[str, tuple[str, dict[str, object]]] = {}
        evidence_columns = COLUMNS + (
            ("real-e2e",) if real_e2e_authority is not None else ()
        )
        for column_id in evidence_columns:
            evidence = column_evidence_document(
                current, column_id, durable_sources=durable_sources
            )
            records.append(evidence)
        object_digests: list[str] = []
        for record in records:
            body = canonical_bytes(record)
            object_digest = objects.digest(body)
            objects.put_verified(body, object_digest)
            object_digests.append(object_digest)
            if record.get("record_kind") == "category-column-evidence-v1":
                evidence_by_column[str(record["column_id"])] = (
                    object_digest, copy.deepcopy(record)
                )
            elif record.get("record_kind") in {
                "category-revision-record-v1",
                "category-drift-record-v1",
                "category-recovery-record-v1",
            }:
                source_by_kind[str(record["record_kind"])] = (
                    object_digest, copy.deepcopy(record)
                )
        runner_port = application.create_runner(
            objects,
            loop_budgets(schemas=schemas, context=context),
            context=context,
            materialization=materialized,
        )
        channel = runner_port._ApplicationRunner__transition_channel
        channel.commit(
            task_id,
            view.snapshot.snapshot_digest,
            (event,),
            runner,
            runtime,
            operation_id=f"category-fixture-ready:{task_id}:{column}",
            object_digests=tuple(sorted(object_digests)),
        )
        if real_e2e_record is not None:
            real_e2e_body = canonical_bytes(real_e2e_record.to_dict())
            real_e2e_digest = objects.digest(real_e2e_body)
            real_e2e_authority.activate(
                task_application=application,
                repository=repository,
                objects=objects,
                runtime=runtime,
                object_digest=real_e2e_digest,
            )
        baseline_events = len(repository.replay(task_id))
        baseline_objects = tuple(
            item[0] for item in repository.referenced_objects(task_id)
        )
        probe = ProductionCategoryProbe(
            stack=stack,
            factory=repository._factory,
            repository=repository,
            objects=objects,
            task_application=application,
            runtime=runtime,
            task_id=task_id,
            baseline_event_count=baseline_events,
            baseline_object_digests=baseline_objects,
            evidence_by_column=evidence_by_column,
            source_by_kind=source_by_kind,
        )
        if type(target) is DisposableLocalTarget:
            target._category_probe = probe
        return application, repository, objects, runtime, probe
    except BaseException:
        stack.close()
        raise


class DisposableLocalTarget:
    """Read-only local fixture observer with deterministic replacement hooks."""

    is_test_double = True
    is_read_only_observer = True
    execution_kind = "deterministic-disposable-local"

    def __init__(self, profile_id: str) -> None:
        self._temporary = tempfile.TemporaryDirectory(
            prefix=f"gew-wp08-s3-{profile_id}-"
        )
        self.root = pathlib.Path(self._temporary.name).resolve(strict=True)
        self.path = self.root / "target.json"
        self.target_id = f"target:{profile_id}:local"
        self.resource_id = f"resource:{profile_id}:local"
        self._revision = 0
        self.query_count = 0
        self.mutation_count = 0
        self.expected_state = {"generation": 2, "profile_id": profile_id}
        self.rollback_state = {"generation": 1, "profile_id": profile_id}
        self._write(self.expected_state)
        self.replace_after_observation = False
        self.force_observation_revision: int | None = None

    def _write(self, state: dict[str, object]) -> None:
        body = json.dumps(
            state, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        temporary = self.root / ".target.next"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            os.write(descriptor, body)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, self.path)
        self._revision += 1

    def observe(self) -> dict[str, object]:
        descriptor = os.open(
            self.path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            metadata = os.fstat(descriptor)
            body = bytearray()
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                body.extend(chunk)
            rebound = os.stat(self.path, follow_symlinks=False)
            if (metadata.st_dev, metadata.st_ino) != (rebound.st_dev, rebound.st_ino):
                raise ValueError("local target changed during observation")
        finally:
            os.close(descriptor)
        self.query_count += 1
        result = {
            "schema_version": "1.0.0",
            "execution_kind": self.execution_kind,
            "target_id": self.target_id,
            "resource_id": self.resource_id,
            "fresh": True,
            "observation_revision": (
                self.query_count
                if self.force_observation_revision is None
                else self.force_observation_revision
            ),
            "file_identity": [metadata.st_dev, metadata.st_ino],
            "state": json.loads(bytes(body)),
            "state_bytes_sha256": hashlib.sha256(body).hexdigest(),
        }
        if self.replace_after_observation:
            self.replace_after_observation = False
            self._write({"generation": 999, "profile_id": "substituted"})
        return result

    def apply_expected(self) -> None:
        self._write(self.expected_state)
        self.mutation_count += 1

    def apply_rollback(self) -> None:
        self._write(self.rollback_state)
        self.mutation_count += 1

    def close(self) -> None:
        probe = getattr(self, "_category_probe", None)
        if probe is not None:
            self._category_probe = None
            probe.close()
        self._temporary.cleanup()


class RecordingRollbackCoordinator:
    """Deterministic local bridge for the existing ActionCoordinator protocol."""

    is_test_double = True
    is_action_coordinator_bridge = True

    def __init__(self, target: DisposableLocalTarget) -> None:
        self._target = target
        self.outcome = "reconciled-effect-verified"
        self.calls: list[str] = []

    def coordinate_rollback(self, request: object) -> dict[str, object]:
        if type(request) is not dict:
            raise ValueError("rollback request is invalid")
        self.calls.extend(("prepare", "authorize", "execute-or-reconcile"))
        if self.outcome == "reconciled-effect-verified":
            self._target.apply_rollback()
        return {
            "prepared_status": "prepared",
            "authorized_status": "authorized",
            "outcome": self.outcome,
            "claim_status": (
                "resolved"
                if self.outcome == "reconciled-effect-verified"
                else "unresolved"
            ),
        }


def action_rollback_binding(
    probe: ProductionCategoryProbe,
    target: DisposableLocalTarget,
) -> tuple[object, dict[str, object]]:
    """Return exact production ActionCoordinator inputs over a linked fake port."""

    from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
    from graph_engineering.core.actions import PreparedAction
    from tests.support.wp05_actions import (
        action_stack,
        authority_document,
        compensation_prepared_document,
        disclosure_plan,
        security_context,
    )

    action = probe._stack.enter_context(action_stack())
    document_context = security_context()
    prepared_document = compensation_prepared_document(context=document_context)
    parsed = PreparedAction.from_dict(
        prepared_document, context=document_context,
    )
    authority = authority_document(parsed)
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
        "disclosure_plan": disclosure_plan(action, parsed),
        "owner_id": "owner-wp05",
        "runtime_kind": "codex",
        "runtime_lineage_id": "lineage-wp05",
    }


def column_evidence_document(
    candidate: object,
    column_id: str,
    *,
    durable_sources: dict[str, object] | None = None,
) -> dict[str, object]:
    if type(candidate) is not dict:
        raise AssertionError("category evidence candidate is missing")
    evidence_kinds = {
        "normal": "runner-execution",
        "boundary": "scenario-membership",
        "revise": "revision-lineage",
        "authority": "authority-decision",
        "drift": "drift-assessment",
        "invalidation": "invalidation-record",
        "recovery": "recovery-record",
        "artifacts": "artifact-records",
        "review": "independent-review",
        "target": "target-observation",
        "rollback": "action-rollback",
        "real-e2e": "real-toolchain-execution",
    }
    review = candidate["review"]
    target = candidate["target"]
    artifacts = candidate["current_artifact_contract_ids"]
    assert isinstance(review, dict)
    assert isinstance(target, dict)
    assert isinstance(artifacts, list)
    facts_by_column: dict[str, dict[str, object]] = {
        "normal": {"runner-output-digest": digest(f"runner:{candidate['task_id']}")},
        "boundary": {"scenario-id": candidate["scenario_id"]},
        "revise": {
            "budget-remaining": 1,
            "current-body-digest": review["body_digest"],
            "owner-route": "owner-revision",
            "previous-body-digest": review["previous_body_digest"],
        },
        "authority": {
            "authority-ref": candidate["authority_refs"][0],
            "authority-status": "current",
        },
        "drift": {
            "drift-status": "resolved",
            "target-digest": digest(f"target:{candidate['task_id']}"),
        },
        "invalidation": {
            "invalidation-epoch": candidate["invalidation_epoch"],
            "invalidation-status": "current",
        },
        "recovery": {
            "recovery-id": f"recovery:{candidate['task_id']}",
            "recovery-status": "recovered",
        },
        "artifacts": {
            "artifact-record-digests": [
                digest(f"artifact-record:{item}") for item in artifacts
            ],
        },
        "review": {
            "author-id": review["author_id"],
            "review-record-digest": digest(f"review:{candidate['task_id']}"),
            "reviewer-id": review["reviewer_id"],
        },
        "target": {
            "expected-state-digest": digest(json.dumps(
                target["expected_state"], sort_keys=True, separators=(",", ":")
            )),
            "target-id": target["target_id"],
        },
        "rollback": {
            "action-id": f"rollback:{candidate['task_id']}",
            "action-status": "prepared-authorized",
            "claim-status": "ready",
        },
        "real-e2e": {},
    }
    if durable_sources is not None:
        runner_outputs = durable_sources["runner_outputs"]
        current_review = durable_sources["current_review"]
        revision = durable_sources["revision"]
        drift = durable_sources["drift"]
        recovery = durable_sources["recovery"]
        artifact_records = durable_sources["artifact_records"]
        target_record = durable_sources["target_record"]
        if not all((
            isinstance(runner_outputs, dict),
            isinstance(current_review, dict),
            isinstance(revision, dict),
            isinstance(drift, dict),
            isinstance(recovery, dict),
            isinstance(artifact_records, list),
            isinstance(target_record, dict),
        )):
            raise AssertionError("durable category source fixture is malformed")
        facts_by_column.update({
            "normal": {
                "runner-output-digest": internal_digest(
                    runner_outputs, "category-runner-outputs"
                ),
            },
            "revise": {
                "budget-remaining": revision["budget_remaining"],
                "current-body-digest": revision["current_body_digest"],
                "owner-route": revision["owner_route"],
                "previous-body-digest": revision["previous_body_digest"],
            },
            "drift": {
                "drift-status": drift["status"],
                "target-digest": drift["target_digest"],
            },
            "recovery": {
                "recovery-id": recovery["recovery_id"],
                "recovery-status": recovery["status"],
            },
            "artifacts": {
                "artifact-record-digests": sorted(
                    item["record_digest"] for item in artifact_records
                ),
            },
            "review": {
                "author-id": durable_sources["review_author_id"],
                "review-record-digest": internal_digest(
                    current_review, "category-runner-review"
                ),
                "reviewer-id": current_review["reviewer_id"],
            },
            "target": {
                "expected-state-digest": internal_digest(
                    target_record["expected_state"], "category-target-state"
                ),
                "target-id": target_record["target_id"],
            },
        })
        rollback_facts = durable_sources.get("rollback_facts")
        if isinstance(rollback_facts, dict):
            facts_by_column["rollback"] = copy.deepcopy(rollback_facts)
        real_e2e_facts = durable_sources.get("real_e2e_facts")
        if isinstance(real_e2e_facts, dict):
            facts_by_column["real-e2e"] = copy.deepcopy(real_e2e_facts)
    facts = facts_by_column.get(column_id, {})
    policy = category_policy_document()
    transitions = policy.get("transition_rules")
    if type(transitions) is not list:
        raise AssertionError("category transition fixtures are unavailable")
    try:
        outcome = next(
            item["required_outcome"] for item in transitions
            if type(item) is dict and item.get("column_id") == column_id
        )
    except StopIteration as error:
        raise AssertionError("category column outcome is unavailable") from error
    record = {
        "schema_version": "1.0.0",
        "record_kind": "category-column-evidence-v1",
        "task_id": candidate["task_id"],
        "task_revision": candidate["task_revision"],
        "snapshot_digest": candidate["snapshot_digest"],
        "invalidation_epoch": candidate["invalidation_epoch"],
        "profile_id": candidate["profile_id"],
        "column_id": column_id,
        "evidence_kind": evidence_kinds.get(column_id, "authoritative-real-e2e"),
        "outcome": outcome,
        "facts": facts,
    }
    record["record_digest"] = internal_digest(
        record, "category-column-evidence-v1"
    )
    return record


def resign_column_evidence(record: dict[str, object]) -> None:
    """Recompute the internal record digest for an adversarial durable replacement."""

    body = {key: value for key, value in record.items() if key != "record_digest"}
    record["record_digest"] = internal_digest(
        body, "category-column-evidence-v1"
    )


def resign_durable_record(record: dict[str, object]) -> None:
    """Re-sign one exact internal durable-source record for adversarial probes."""

    kind = record.get("record_kind")
    if type(kind) is not str:
        raise AssertionError("durable source record kind is missing")
    body = {key: value for key, value in record.items() if key != "record_digest"}
    record["record_digest"] = internal_digest(body, kind)


def selector_request_digest(selector: dict[str, object]) -> str:
    """Return the canonical digest of the exact public category selector."""

    return internal_digest(selector, "category-assessment-selector")


def materialized_profile(profile_id: str):  # type: ignore[no-untyped-def]
    """Build one factory-issued installed full-planned materialization fixture."""

    from graph_engineering.core import profiles as api
    from tests.unit import test_wp08_profile_contracts as slice1

    approved = slice1._approved_registry()
    coverage = slice1._coverage_policy()
    semantic = slice1._semantic_policy()
    profile = api.ProfileDefinition.from_dict(
        profile_document(profile_id),
        approved_profiles=approved,
        coverage_policy=coverage,
        semantic_policy=semantic,
    )
    overlay = api.RiskOverlayDefinition.from_dict(
        load_json(ROOT / "config/profiles/risk-overlays/full-planned-v1.json"),
        approved_profiles=approved,
        coverage_policy=coverage,
    )
    matrix = api.SupportMatrixDefinition.from_dict(
        load_json(SUPPORT_MATRIX_PATH),
        approved_profiles=approved,
        coverage_policy=coverage,
    )
    return api.ProfileMaterializer.materialize(
        base_graph_document={
            "graph_id": f"slice3-{profile_id}",
            "graph_version": "1.0.0",
            "graph_digest": digest(f"slice3-base:{profile_id}"),
            "node_ids": list(profile.required_node_ids),
            "edge_ids": list(profile.required_edge_ids),
        },
        profile=profile,
        overlay=overlay,
        project_config={},
        approved_profiles=approved,
        support_matrix=matrix,
        semantic_policy=semantic,
    )


def candidate_facts_document(
    profile_id: str,
    column: str,
    *,
    scenario_id: str | None = None,
) -> dict[str, object]:
    profile = profile_document(profile_id)
    materialized = materialized_profile(profile_id)
    scenario_ids = profile.get("category_boundary_case_ids")
    if type(scenario_ids) is not list or not scenario_ids:
        raise AssertionError("Profile category-boundary fixture is empty")
    positive_scenarios = tuple(
        item for item in scenario_ids
        if type(item) is str and item.endswith("-P")
    )
    if not positive_scenarios:
        raise AssertionError("Profile category-boundary PASS fixture is empty")
    scenario = positive_scenarios[0] if scenario_id is None else scenario_id
    if scenario not in positive_scenarios:
        raise AssertionError("Profile category-boundary fixture is not approved")
    rollback = profile.get("rollback_contract")
    if type(rollback) is not dict:
        raise AssertionError("Profile rollback fixture is malformed")
    return {
        "schema_version": "1.0.0",
        "request_id": f"wp08-s3:{profile_id}:{column}",
        "task_id": f"task:{profile_id}:local",
        "task_revision": 1,
        "snapshot_digest": digest(f"snapshot:{profile_id}:1"),
        "invalidation_epoch": 0,
        "profile_id": profile_id,
        "profile_version": profile["version"],
        "profile_digest": profile["digest"],
        "overlay_id": materialized.overlay_id,
        "materialization_digest": materialized.digest_pins[
            "materialization_digest"
        ],
        "digest_pins": {
            "base_graph_digest": materialized.digest_pins["base_graph_digest"],
            "profile_digest": materialized.digest_pins["profile_digest"],
            "overlay_digest": materialized.digest_pins["overlay_digest"],
            "project_config_digest": materialized.digest_pins[
                "project_config_digest"
            ],
            "support_matrix_digest": materialized.digest_pins[
                "support_matrix_digest"
            ],
            "materialization_digest": materialized.digest_pins[
                "materialization_digest"
            ],
        },
        "column_id": column,
        "scenario_id": scenario,
        "execution_kind": "deterministic-disposable-local",
        "authority_refs": ["authority:category-current"],
        "required_node_ids": copy.deepcopy(profile["required_node_ids"]),
        "passed_node_ids": copy.deepcopy(profile["required_node_ids"]),
        "required_artifact_contract_ids": copy.deepcopy(
            profile["artifact_contract_ids"]
        ),
        "current_artifact_contract_ids": copy.deepcopy(
            profile["artifact_contract_ids"]
        ),
        "required_validator_ids": copy.deepcopy(profile["validator_ids"]),
        "passed_validator_ids": copy.deepcopy(profile["validator_ids"]),
        "required_completion_predicate_ids": copy.deepcopy(
            profile["completion_predicate_ids"]
        ),
        "passed_completion_predicate_ids": copy.deepcopy(
            profile["completion_predicate_ids"]
        ),
        "runner_outputs": {
            "node_ids": list(materialized.node_ids),
            "edge_ids": list(materialized.edge_ids),
            "artifact_contract_ids": list(materialized.artifact_contract_ids),
            "validator_ids": list(materialized.validator_ids),
            "completion_predicate_ids": list(
                materialized.completion_predicate_ids
            ),
            "required_invariant_ids": list(materialized.required_invariant_ids),
            "budget_limits": dict(materialized.budget_limits),
        },
        "review": {
            "author_id": f"author:{profile_id}",
            "reviewer_id": f"reviewer:{profile_id}",
            "trust": "independently-reviewed",
            "verdict": "PASS",
            "body_digest": digest(f"body:{profile_id}:2"),
            "previous_body_digest": digest(f"body:{profile_id}:1"),
        },
        "target": {
            "target_id": f"target:{profile_id}:local",
            "resource_id": f"resource:{profile_id}:local",
            "expected_state": {
                "generation": 1 if column == "rollback" else 2,
                "profile_id": profile_id,
            },
        },
        "rollback": {
            "logical_action_kind": rollback["eligible_action_kinds"][0],
            "action_protocol_kind": "rollback",
            "authority_requirement": rollback["authority_requirement"],
            "compensation_graph_ref": rollback["compensation_graph_ref"],
            "precondition_ids": copy.deepcopy(rollback["precondition_ids"]),
            "verification_ids": copy.deepcopy(rollback["verification_ids"]),
        },
        "unresolved_refs": [],
    }


def candidate_document(profile_id: str, column: str) -> dict[str, object]:
    """Return only the public selector surface; no completion truth is caller-owned."""

    profile = profile_document(profile_id)
    scenarios = profile.get("category_boundary_case_ids")
    if type(scenarios) is not list:
        raise AssertionError("Profile category boundary scenarios are malformed")
    scenario = next(
        (item for item in scenarios if type(item) is str and item.endswith("-P")),
        None,
    )
    if scenario is None:
        raise AssertionError("Profile category boundary PASS scenario is absent")
    return {
        "schema_version": "1.0.0",
        "request_id": f"wp08-s3:{profile_id}:{column}",
        "task_id": f"task:{profile_id}:local",
        "column_id": column,
        "scenario_id": scenario,
        "target_id": f"target:{profile_id}:local",
    }


def coherent_resign(candidate: dict[str, object], label: str) -> None:
    candidate["profile_digest"] = digest(f"coherent-resign:{label}")


def reject_mutations(
    candidate: dict[str, object], target: DisposableLocalTarget
) -> Iterator[tuple[str, Callable[[dict[str, object]], None]]]:
    yield "forged-target-ids", lambda value: value.__setitem__(
        "target_id", "target:forged"
    )
    yield "stale-snapshot", lambda value: value.__setitem__(
        "snapshot_digest", digest("stale-snapshot")
    )
    yield "foreign-authority", lambda value: value.__setitem__(
        "authority_refs", ["authority:foreign"]
    )
    yield "clone-observation", lambda value: value.__setitem__(
        "target_observation_override", target.observe()
    )
    yield "coherent-profile-resign", lambda value: coherent_resign(
        value, "profile-body"
    )
    yield "target-post-observation-replacement", lambda value: setattr(
        target, "replace_after_observation", True
    )


def assert_local_real_e2e_rejected_input(profile_id: str) -> dict[str, object]:
    candidate = candidate_document(profile_id, "real-e2e")
    candidate["claimed_test_id"] = (
        f"GEW-PRO-{profile_id.upper()}-REAL-E2E-P"
    )
    candidate["execution_kind"] = "deterministic-disposable-local"
    return candidate
