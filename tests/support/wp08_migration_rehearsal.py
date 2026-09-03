"""ADR-0002 revision 6 Migration rehearsal Slice-A contract probes."""

from __future__ import annotations

import importlib
import copy
import json
import pathlib
import tempfile
from contextlib import contextmanager
from collections.abc import Callable
from dataclasses import dataclass
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "config/migration/migration-rehearsal-registry-v1.json"
FIXTURE_PATH = ROOT / "config/migration/migration-rehearsal-fixture-v1.json"
TRANSFORM_PATH = ROOT / "config/migration/migration-rehearsal-transform-manifest-v1.json"
BOOTSTRAP_PATH = (
    ROOT / "config/migration/migration-rehearsal-installation-bootstrap-v1.json"
)

MIGRATION_REHEARSAL_SCHEMA_IDS = tuple(sorted({
    f"urn:gew:schema:{stem}{suffix}:{version}"
    for stem, version in (
        ("migration-rehearsal-fixture-manifest", "1.0.0"),
        ("migration-rehearsal-transform-manifest", "1.0.0"),
        ("migration-rehearsal-registry", "1.0.0"),
        ("migration-rehearsal-installation-bootstrap", "1.0.0"),
        ("migration-step-observation", "1.0.0"),
        ("migration-crash-recovery-observation", "1.0.0"),
        ("migration-rehearsal-observation", "1.0.0"),
    )
    for suffix in ("", "-input")
} | {
    "urn:gew:schema:category-completion-assessment-input:1.2.0",
    "urn:gew:schema:category-completion-assessment:1.2.0",
}))


class MissingMigrationRehearsalContract(AssertionError):
    """The production Migration rehearsal Slice-A surface is absent."""


@dataclass(frozen=True, slots=True)
class SliceAAPI:
    MigrationRehearsalError: type[Exception]
    MigrationRehearsalRegistryData: type
    MigrationRehearsalObservation: type
    parse_migration_rehearsal_registry: Callable[..., object]
    MigrationRehearsalFactory: type
    MigrationRehearsalAuthority: type
    MigrationRehearsalObservationAuthority: type


@dataclass(slots=True)
class _RehearsalFixture:
    api: SliceAAPI
    factory: object
    authority: object
    observation: object
    category_application: object
    task_id: str
    forward_id: str
    backward_id: str
    crashes: dict[str, str]
    manager: object
    repository: object
    stale_repository: object
    completed: object
    probe: object
    target: object
    temporary: tempfile.TemporaryDirectory[str]

    def close(self) -> None:
        self.completed.close()
        self.target._category_probe = None
        self.probe.close()
        self.target.close()
        self.temporary.cleanup()


def load_slice_a_api() -> SliceAAPI:
    missing: list[str] = []
    try:
        core = importlib.import_module("graph_engineering.core.migration_rehearsal")
    except ModuleNotFoundError:
        core = None
        missing.append("graph_engineering.core.migration_rehearsal")
    try:
        application = importlib.import_module(
            "graph_engineering.application.migration_rehearsal"
        )
    except ModuleNotFoundError:
        application = None
        missing.append("graph_engineering.application.migration_rehearsal")
    core_names = (
        "MigrationRehearsalError",
        "MigrationRehearsalRegistryData",
        "MigrationRehearsalObservation",
        "parse_migration_rehearsal_registry",
    )
    application_names = (
        "MigrationRehearsalFactory",
        "MigrationRehearsalAuthority",
        "MigrationRehearsalObservationAuthority",
    )
    for name in core_names:
        if core is None or not hasattr(core, name):
            missing.append(name)
    for name in application_names:
        if application is None or not hasattr(application, name):
            missing.append(name)
    if missing:
        raise MissingMigrationRehearsalContract(
            "ADR-0002 revision 6 production contract is absent: "
            + ", ".join(missing)
        )
    return SliceAAPI(
        **{name: getattr(core, name) for name in core_names},
        **{name: getattr(application, name) for name in application_names},
    )


@contextmanager
def _rehearsal_fixture(
    *,
    task_id: str = "task:migration:rehearsal-slice-a",
    scenario_boundary_case_id: str | None = None,
    selector: dict[str, object] | None = None,
) -> object:
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.core.contracts.immutable import thaw
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from tests.support.wp08_category_execution import (
        DisposableLocalTarget,
        action_rollback_binding,
        candidate_document,
        load_json,
        load_slice3_api,
        materialized_profile,
        profile_document,
        production_category_runtime,
        SUPPORT_MATRIX_PATH,
    )

    api = load_slice_a_api()
    target = DisposableLocalTarget("migration")
    application = repository = objects = runtime = probe = None
    current_scope = current_objects = None
    temporary = tempfile.TemporaryDirectory(prefix="gew-wp08-migration-rehearsal-")
    completed = None
    try:
        application, repository, objects, runtime, probe = production_category_runtime(
            "migration", "boundary", target=target,
            task_id=task_id,
            scenario_id=scenario_boundary_case_id,
        )
        category_api = load_slice3_api()
        materialized = materialized_profile("migration")
        policy = category_api.CategoryExecutionPolicy.from_installation(
            profile_document=profile_document("migration"),
            support_matrix_document=load_json(SUPPORT_MATRIX_PATH),
            materialization_record=materialized.record,
        )
        target_authority = category_api.CategoryTargetObservationAuthority(policy)
        rollback_coordinator, rollback_context = action_rollback_binding(probe, target)
        rollback = category_api.CategoryRollbackBridge(policy, rollback_coordinator)
        rollback.prepare_action(**rollback_context)
        probe.bind_rollback_evidence(rollback)
        manager = repository._command_scope._manager
        factory = api.MigrationRehearsalFactory.from_installation(
            manager, repository,
        )
        factory.bind_task(
            factory.authority, task_id,
        )
        category_application = category_api.CategoryExecutionApplication(
            repository=repository,
            object_repository=objects,
            policy=policy,
            reducer=category_api.CategoryExecutionReducer(policy),
            completion_oracle=category_api.CategoryCompletionOracle(
                policy=policy,
                target_authority=target_authority,
                migration_rehearsal_factory=factory,
                migration_rehearsal_authority=factory.authority,
            ),
            rollback_bridge=rollback,
            assessment_resolver=category_api.CategoryAssessmentResolver(
                repository, objects, task_application=application, runtime=runtime,
            ),
            task_application=application,
            runtime=runtime,
            target_observer=target,
        )
        category_application.bind_current_sources(probe.task_id)
        repository._command_scope.__exit__(None, None, None)
        root = pathlib.Path(temporary.name)
        factory.execute(
            factory.authority,
            task_id=task_id,
            private_root=root,
        )
        completed = factory._completed
        assert completed is not None
        current_scope = manager.command_scope()
        current_scope.__enter__()
        current_connection_factory = completed.imported.factory.bind_command_scope(
            current_scope
        )
        current_objects = ObjectRepository(
            current_connection_factory, completed.imported.locks,
        )
        current_repository = TaskRepository(
            current_connection_factory,
            completed.imported.locks,
            current_objects,
            command_scope=current_scope,
        )
        current_task_application = TaskApplication(
            current_repository,
            current_repository,
            ResourceLeaseRepository(
                completed.imported.factory, completed.imported.locks,
            ),
            schema_registry=application._schemas,
            context=application._context,
            materialization_objects=current_objects,
        )
        current_factory = api.MigrationRehearsalFactory.from_installation(
            manager, current_repository,
        )
        current_factory._rehydrate_executions(factory)
        previous_category_application = category_application
        current_snapshot_before = copy.deepcopy(
            current_repository.load(task_id)
        )
        current_references_before = tuple(
            current_repository.referenced_objects(task_id)
        )
        category_application = category_api.CategoryExecutionApplication(
            repository=current_repository,
            object_repository=current_objects,
            policy=policy,
            reducer=category_api.CategoryExecutionReducer(policy),
            completion_oracle=category_api.CategoryCompletionOracle(
                policy=policy,
                target_authority=category_api.CategoryTargetObservationAuthority(
                    policy
                ),
                migration_rehearsal_factory=current_factory,
                migration_rehearsal_authority=current_factory.authority,
            ),
            rollback_bridge=rollback,
            assessment_resolver=category_api.CategoryAssessmentResolver(
                current_repository,
                current_objects,
                task_application=current_task_application,
                runtime=runtime,
            ),
            task_application=current_task_application,
            runtime=runtime,
            target_observer=target,
        )
        category_application.bind_current_sources(task_id)
        if (
            category_application is previous_category_application
            or current_repository.load(task_id) != current_snapshot_before
            or tuple(current_repository.referenced_objects(task_id))
            != current_references_before
        ):
            raise AssertionError(
                "migration consumer-local handoff changed durable task state"
            )
        current_observation = current_factory.observe(
            current_factory.authority,
            task_id=task_id,
        )
        selected = (
            candidate_document("migration", "boundary")
            if selector is None else copy.deepcopy(selector)
        )
        selected["task_id"] = task_id
        receipt = category_application.assess_and_commit(
            selected,
            observer=target,
            migration_rehearsal_evidence=current_observation,
        )
        if receipt.idempotent_replay:
            raise AssertionError("migration assessment unexpectedly replayed")
        crashes = {
            "activation.after_active_manifest": "migration-rehearsal-crash-new",
            "migration.after_state.compatible": "migration-rehearsal-crash-old",
        }
        observation = current_factory.restart(
            current_factory.authority,
            category_application,
            task_id=task_id,
        )
        probe.factory = current_connection_factory
        probe.repository = current_repository
        probe.objects = current_objects
        probe.task_application = current_task_application
        fixture = _RehearsalFixture(
            api, current_factory, current_factory.authority, observation,
            category_application,
            task_id,
            "migration-rehearsal-forward", "migration-rehearsal-backward", crashes,
            manager, current_repository, repository, completed, probe, target, temporary,
        )
        case_document = thaw(observation.observation.document)
        assert type(case_document) is dict
        yield fixture, case_document
    finally:
        if current_objects is not None:
            try:
                current_objects.close()
            except Exception:
                pass
        if current_scope is not None:
            try:
                current_scope.__exit__(None, None, None)
            except Exception:
                pass
        if completed is not None:
            try:
                completed.close()
            except Exception:
                pass
        if probe is not None:
            try:
                target._category_probe = None
                probe.close()
            except Exception:
                pass
        try:
            target.close()
        except Exception:
            pass
        temporary.cleanup()
def assert_migration_rehearsal_schema_instances(
    case: object,
    registry: object,
    context_factory: Callable[[], object],
) -> None:
    for path, schema_id in (
        (FIXTURE_PATH, "urn:gew:schema:migration-rehearsal-fixture-manifest:1.0.0"),
        (TRANSFORM_PATH, "urn:gew:schema:migration-rehearsal-transform-manifest:1.0.0"),
        (REGISTRY_PATH, "urn:gew:schema:migration-rehearsal-registry:1.0.0"),
        (BOOTSTRAP_PATH, "urn:gew:schema:migration-rehearsal-installation-bootstrap:1.0.0"),
    ):
        case.assertTrue(path.is_file(), path)
        document = json.loads(path.read_bytes())
        registry.validate(schema_id, document, context_factory())


def assert_migration_rehearsal_slice_a_positive(case: object) -> None:
    api = load_slice_a_api()
    parsed = api.parse_migration_rehearsal_registry(json.loads(REGISTRY_PATH.read_bytes()))
    case.assertIs(type(parsed), api.MigrationRehearsalRegistryData)
    with _rehearsal_fixture() as payload:
        fixture, document = payload
        case.assertIs(
            fixture.factory.require_current(fixture.observation), fixture.observation,
        )
        case.assertIs(fixture.factory.precommit(fixture.observation), fixture.observation)
        restarted = fixture.factory.restart(
            fixture.authority, fixture.category_application, fixture.task_id,
        )
        case.assertEqual(restarted.observation.document, fixture.observation.observation.document)
        case.assertEqual(
            [item["outcome"] for item in document["crash_recoveries"]],
            ["new-active", "old-active"],
        )
        case.assertGreater(
            document["forward_step"]["target_generation"],
            document["forward_step"]["source_generation"],
        )
        case.assertGreater(
            document["backward_step"]["target_activation_epoch"],
            document["backward_step"]["source_activation_epoch"],
        )


def assert_migration_rehearsal_slice_a_rejections(case: object) -> None:
    api = load_slice_a_api()
    with case.assertRaises(api.MigrationRehearsalError):
        api.parse_migration_rehearsal_registry({})
    registry = json.loads(REGISTRY_PATH.read_bytes())
    for mutation in (
        lambda value: value.__setitem__("crash_cut_ids", list(reversed(value["crash_cut_ids"]))),
        lambda value: value.__setitem__("registry_digest", "sha256-jcs-v1:" + "f" * 64),
        lambda value: value.__setitem__("unknown", True),
    ):
        candidate = copy.deepcopy(registry)
        mutation(candidate)
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            api.parse_migration_rehearsal_registry(candidate)
    with _rehearsal_fixture() as payload:
        fixture, document = payload
        for foreign in (
            object.__new__(api.MigrationRehearsalAuthority),
            copy.copy(fixture.authority),
        ):
            with case.assertRaises((api.MigrationRehearsalError, TypeError)):
                fixture.factory.require_authority_current(foreign)
        with case.assertRaises(TypeError):
            copy.deepcopy(fixture.authority)
        for foreign in (
            object.__new__(api.MigrationRehearsalObservationAuthority),
            copy.copy(fixture.observation),
        ):
            with case.assertRaises((api.MigrationRehearsalError, TypeError)):
                fixture.factory.require_current(foreign)
        with case.assertRaises(TypeError):
            copy.deepcopy(fixture.observation)
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            api.MigrationRehearsalFactory.from_installation(
                fixture.manager, fixture.stale_repository,
            )
        changed = copy.deepcopy(document)
        changed["task_binding"]["invalidation_epoch"] += 1
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            fixture.factory.restart(fixture.authority, changed)
        original_history = fixture.manager._migration_history

        def altered_history(
            _manager: object, migration_id: str, repository_factory: object,
        ):
            rows = list(original_history(migration_id, repository_factory))
            rows[-1] = copy.deepcopy(rows[-1])
            rows[-1]["migration"]["revision"] += 1
            return tuple(rows)

        with mock.patch.object(
            type(fixture.manager), "_migration_history", altered_history,
        ), case.assertRaises(api.MigrationRehearsalError):
            fixture.factory.require_current(fixture.observation)


def assert_migration_rehearsal_slice_a_r1_contracts(case: object) -> None:
    """Exact reviewer attacks for WP08-MIG-SLICEA-R1-001..004."""

    api = load_slice_a_api()
    with _rehearsal_fixture() as payload:
        fixture, document = payload

        # R1-001: a completed ledger identity cannot be relabelled as both
        # direction-specific transforms, even when the resulting document is
        # coherently self-digested by the production factory.
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            fixture.factory.observe(
                fixture.authority,
                task_id=fixture.task_id,
                forward_migration_id=fixture.forward_id,
                backward_migration_id=fixture.forward_id,
                crash_migration_ids=fixture.crashes,
            )
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            fixture.factory.observe(
                fixture.authority,
                task_id=fixture.task_id,
                forward_migration_id=fixture.backward_id,
                backward_migration_id=fixture.forward_id,
                crash_migration_ids=fixture.crashes,
            )

        # R1-002: the selected values still match the protected expectation
        # fixture, but their truth must be independently derived from exact
        # source-export, forward-import/readback, and backward-import/readback
        # row artifacts.  A match alone is not production evidence.
        expected_rows = json.loads(FIXTURE_PATH.read_bytes())["rows"]
        case.assertEqual(
            [
                {
                    name: item[name]
                    for name in (
                        "row_id", "field_id", "source_value", "forward_value",
                        "backward_value", "disposition", "owner_route", "row_digest",
                    )
                }
                for item in document["partial_data"]
            ],
            expected_rows,
        )
        row_execution = document.get("row_execution")
        case.assertIs(type(row_execution), dict)
        case.assertEqual(
            set(row_execution),
            {
                "schema_version", "task_id", "source_artifact",
                "forward_artifact", "backward_artifact", "execution_digest",
            },
        )
        case.assertEqual(row_execution["task_id"], fixture.task_id)
        artifact_specs = (
            ("source_artifact", "source-export", None, None),
            (
                "forward_artifact", "forward-readback", fixture.forward_id,
                document["forward_step"]["history_digest"],
            ),
            (
                "backward_artifact", "backward-readback", fixture.backward_id,
                document["backward_step"]["history_digest"],
            ),
        )
        for name, stage, migration_id, history_digest in artifact_specs:
            artifact = row_execution[name]
            case.assertIs(type(artifact), dict)
            case.assertEqual(artifact["stage"], stage)
            case.assertEqual(artifact["migration_id"], migration_id)
            case.assertEqual(artifact["history_digest"], history_digest)
            case.assertEqual(
                [row["row_id"] for row in artifact["rows"]],
                sorted(row["row_id"] for row in artifact["rows"]),
            )
        for item in document["partial_data"]:
            case.assertEqual(item["row_execution_digest"], row_execution["execution_digest"])
            for stage in ("source", "forward", "backward"):
                rows = row_execution[f"{stage}_artifact"]["rows"]
                derived = next(row for row in rows if row["row_id"] == item["row_id"])
                case.assertEqual(item[f"{stage}_row_digest"], derived["row_digest"])

        from graph_engineering.core.contracts.digest import semantic_digest
        from graph_engineering.core.contracts.immutable import freeze, thaw

        def resign(candidate: dict[str, object]) -> None:
            for artifact_name in (
                "source_artifact", "forward_artifact", "backward_artifact",
            ):
                artifact = candidate[artifact_name]
                assert type(artifact) is dict
                rows = artifact["rows"]
                assert type(rows) is list
                for row in rows:
                    assert type(row) is dict
                    row_body = copy.deepcopy(row)
                    row_body.pop("row_digest", None)
                    row["row_digest"] = semantic_digest(
                        row_body,
                        contract_type=(
                            "urn:gew:contract:migration-rehearsal-row-artifact-row"
                        ),
                        projection_id=(
                            "urn:gew:digest-projection:"
                            "migration-rehearsal-row-artifact-row:1.0.0"
                        ),
                        schema_id=(
                            "urn:gew:schema:"
                            "migration-rehearsal-row-artifact-row-input:1.0.0"
                        ),
                    )
                artifact_body = copy.deepcopy(artifact)
                artifact_body.pop("artifact_digest", None)
                artifact["artifact_digest"] = semantic_digest(
                    artifact_body,
                    contract_type="urn:gew:contract:migration-rehearsal-row-artifact",
                    projection_id=(
                        "urn:gew:digest-projection:migration-rehearsal-row-artifact:1.0.0"
                    ),
                    schema_id=(
                        "urn:gew:schema:migration-rehearsal-row-artifact-input:1.0.0"
                    ),
                )
            body = copy.deepcopy(candidate)
            body.pop("execution_digest", None)
            candidate["execution_digest"] = semantic_digest(
                body,
                contract_type="urn:gew:contract:migration-rehearsal-row-execution",
                projection_id=(
                    "urn:gew:digest-projection:migration-rehearsal-row-execution:1.0.0"
                ),
                schema_id=(
                    "urn:gew:schema:migration-rehearsal-row-execution-input:1.0.0"
                ),
            )

        issued = getattr(fixture.factory, "_row_execution", None)
        case.assertIsNotNone(issued)
        before = {
            "task": fixture.repository.load(fixture.task_id),
            "target": fixture.target.path.read_bytes(),
            "target_queries": fixture.target.query_count,
            "target_mutations": fixture.target.mutation_count,
            "replay_count": fixture.factory._replay_count,
        }

        def omit(candidate: dict[str, object]) -> None:
            candidate["forward_artifact"]["rows"].pop()

        def duplicate(candidate: dict[str, object]) -> None:
            rows = candidate["forward_artifact"]["rows"]
            rows.append(copy.deepcopy(rows[-1]))

        def reorder(candidate: dict[str, object]) -> None:
            candidate["forward_artifact"]["rows"].reverse()

        def alias(candidate: dict[str, object]) -> None:
            rows = candidate["forward_artifact"]["rows"]
            rows[1]["row_id"] = rows[0]["row_id"]

        def silent_drop(candidate: dict[str, object]) -> None:
            row = candidate["forward_artifact"]["rows"][0]
            row["present"] = False
            row["value"] = None

        def caller_default(candidate: dict[str, object]) -> None:
            candidate["forward_artifact"]["rows"][0]["value"] = "caller-default"

        def unknown_owner_route(candidate: dict[str, object]) -> None:
            candidate["forward_artifact"]["rows"][1]["owner_route"] = "unknown-owner"

        original = fixture.factory._row_execution
        try:
            for label, mutation in (
                ("omission", omit),
                ("duplicate", duplicate),
                ("reorder", reorder),
                ("alias", alias),
                ("silent-drop", silent_drop),
                ("caller-default", caller_default),
                ("unknown-owner-route", unknown_owner_route),
            ):
                with case.subTest(migration_partial_data_attack=label):
                    candidate = thaw(original)
                    case.assertIs(type(candidate), dict)
                    mutation(candidate)
                    resign(candidate)
                    fixture.factory._row_execution = freeze(candidate)
                    with case.assertRaises(api.MigrationRehearsalError):
                        fixture.factory.require_current(fixture.observation)
                    case.assertEqual(fixture.repository.load(fixture.task_id), before["task"])
                    case.assertEqual(fixture.target.path.read_bytes(), before["target"])
                    case.assertEqual(fixture.target.query_count, before["target_queries"])
                    case.assertEqual(fixture.target.mutation_count, before["target_mutations"])
                    case.assertEqual(fixture.factory._replay_count, before["replay_count"])
        finally:
            fixture.factory._row_execution = original

        # R1-003: restart may resolve only the task-current uniquely referenced
        # assessment CAS.  A caller-supplied (even canonical) document is not
        # restart authority.
        with case.assertRaises((api.MigrationRehearsalError, TypeError)):
            fixture.factory.restart(fixture.authority, copy.deepcopy(document))

        # R1-004: a caller-projected crash label plus an omitted ledger is not
        # production crash-cut authority, even when the terminal row remains.
        original_history = fixture.manager._migration_history

        def omitted_crash_ledger(
            _manager: object, migration_id: str, repository_factory: object,
        ):
            rows = original_history(migration_id, repository_factory)
            if migration_id == fixture.crashes["activation.after_active_manifest"]:
                return (rows[0], rows[-1])
            return rows

        with mock.patch.object(
            type(fixture.manager), "_migration_history", omitted_crash_ledger,
        ), case.assertRaises(api.MigrationRehearsalError):
            fixture.factory.require_current(fixture.observation)
