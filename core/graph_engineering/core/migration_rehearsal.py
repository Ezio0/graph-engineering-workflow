"""Closed, self-digested records for WP-08 migration rehearsal authority."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from .contracts.digest import SEMANTIC_DIGEST, semantic_digest
from .contracts.immutable import FrozenMap, freeze, thaw


SAFE_INTEGER = 9_007_199_254_740_991
MIGRATION_REHEARSAL_SCHEMA_IDS = tuple(sorted({
    f"urn:gew:schema:{stem}{suffix}:1.0.0"
    for stem in (
        "migration-rehearsal-fixture-manifest",
        "migration-rehearsal-transform-manifest",
        "migration-rehearsal-registry",
        "migration-rehearsal-installation-bootstrap",
        "migration-step-observation",
        "migration-crash-recovery-observation",
        "migration-rehearsal-observation",
    )
    for suffix in ("", "-input")
} | {
    "urn:gew:schema:category-completion-assessment-input:1.2.0",
    "urn:gew:schema:category-completion-assessment:1.2.0",
}))


class MigrationRehearsalError(ValueError):
    """A migration rehearsal record or authority failed closed."""


def _mapping(value: object, fields: tuple[str, ...], label: str) -> Mapping[str, object]:
    if type(value) is not dict or tuple(value) != tuple(sorted(fields)):
        raise MigrationRehearsalError(f"{label} fields/order are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise MigrationRehearsalError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= SAFE_INTEGER:
        raise MigrationRehearsalError(f"{label} is not an exact safe integer")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if SEMANTIC_DIGEST.fullmatch(result) is None:
        raise MigrationRehearsalError(f"{label} is not a semantic digest")
    return result


def _raw(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(item not in "0123456789abcdef" for item in result):
        raise MigrationRehearsalError(f"{label} is not a raw SHA-256")
    return result


def _self_digest(value: Mapping[str, object], name: str, field: str) -> str:
    expected = _digest(value.get(field), field)
    body = thaw(freeze(value))
    if type(body) is not dict:
        raise AssertionError("migration rehearsal record did not thaw")
    del body[field]
    actual = semantic_digest(
        freeze(body),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise MigrationRehearsalError(f"{name} self digest changed")
    return expected


@dataclass(frozen=True, slots=True)
class MigrationRehearsalRegistryData:
    registry_id: str
    fixture_manifest_id: str
    fixture_manifest_digest: str
    transform_manifest_id: str
    transform_manifest_digest: str
    compatibility_policy_id: str
    crash_cut_ids: tuple[str, ...]
    registry_digest: str
    document: FrozenMap


_REGISTRY_FIELDS = (
    "schema_version", "registry_id", "fixture_manifest_id",
    "fixture_manifest_digest", "transform_manifest_id",
    "transform_manifest_digest", "compatibility_policy_id",
    "crash_cut_ids", "registry_digest",
)


def parse_migration_rehearsal_registry(value: object) -> MigrationRehearsalRegistryData:
    document = _mapping(value, _REGISTRY_FIELDS, "migration rehearsal registry")
    if document["schema_version"] != "1.0.0":
        raise MigrationRehearsalError("migration rehearsal registry version changed")
    cuts = document["crash_cut_ids"]
    if type(cuts) is not list or not cuts:
        raise MigrationRehearsalError("migration rehearsal crash cuts are absent")
    cut_ids = tuple(_text(item, "crash cut ID") for item in cuts)
    if cut_ids != tuple(sorted(set(cut_ids))):
        raise MigrationRehearsalError("migration rehearsal crash cuts are not canonical")
    digest = _self_digest(document, "migration-rehearsal-registry", "registry_digest")
    return MigrationRehearsalRegistryData(
        _text(document["registry_id"], "migration rehearsal registry ID"),
        _text(document["fixture_manifest_id"], "fixture manifest ID"),
        _digest(document["fixture_manifest_digest"], "fixture manifest digest"),
        _text(document["transform_manifest_id"], "transform manifest ID"),
        _digest(document["transform_manifest_digest"], "transform manifest digest"),
        _text(document["compatibility_policy_id"], "compatibility policy ID"),
        cut_ids,
        digest,
        freeze(document),
    )


_OBSERVATION_FIELDS = (
    "schema_version", "observation_id", "task_binding", "installation_projection",
    "forward_step", "backward_step", "row_execution", "partial_data",
    "crash_recoveries", "current_manifest", "lifecycle_projection", "fresh_target",
    "observation_digest",
)


_STEP_FIELDS = (
    "schema_version", "step_id", "step_kind", "migration_id",
    "transform_projection", "source_manifest_digest", "target_manifest_digest",
    "source_repository_id", "target_repository_id", "source_generation",
    "target_generation", "source_activation_epoch", "target_activation_epoch",
    "ledger", "history_digest", "bundle_projection", "candidate_projection",
    "integrity_projection", "compatibility_projection", "step_digest",
)
_CRASH_FIELDS = (
    "schema_version", "crash_cut_id", "migration_id", "outcome",
    "observed_manifest_digest", "generation", "activation_epoch", "repository_id",
    "cut_provenance", "ledger", "source_manifest", "recovered_manifest",
    "bundle_projection", "candidate_projection", "history_digest", "recovery_digest",
)
_PARTIAL_FIELDS = (
    "backward_integrity_digest", "backward_value", "case_id", "disposition",
    "disposition_digest", "field_id", "forward_integrity_digest", "forward_value",
    "owner_route", "row_digest", "row_id", "source_value", "source_row_digest",
    "forward_row_digest", "backward_row_digest", "row_execution_digest",
)
_ROW_EXECUTION_FIELDS = (
    "schema_version", "task_id", "source_artifact", "forward_artifact",
    "backward_artifact", "execution_digest",
)
_ROW_ARTIFACT_FIELDS = (
    "schema_version", "artifact_id", "stage", "migration_id", "transform_digest",
    "history_digest", "rows", "artifact_digest",
)
_ROW_ARTIFACT_ROW_FIELDS = (
    "row_id", "field_id", "present", "value", "status", "owner_route",
    "row_digest",
)


def _history(
    value: object, migration_id: str, *, terminal: tuple[str, ...], label: str,
) -> list[dict[str, object]]:
    if type(value) is not list or not value:
        raise MigrationRehearsalError(f"{label} is absent")
    rows: list[dict[str, object]] = []
    for revision, item in enumerate(value, 1):
        if type(item) is not dict or type(item.get("migration")) is not dict:
            raise MigrationRehearsalError(f"{label} row is malformed")
        migration = item["migration"]
        if (
            migration.get("migration_id") != migration_id
            or migration.get("revision") != revision
            or type(migration.get("state")) is not str
        ):
            raise MigrationRehearsalError(f"{label} identity is not consecutive")
        rows.append(item)
    if rows[-1]["migration"]["state"] not in terminal:
        raise MigrationRehearsalError(f"{label} terminal state changed")
    return rows


def _step(value: object, expected_kind: str) -> Mapping[str, object]:
    step = _mapping(value, _STEP_FIELDS, f"migration {expected_kind} step")
    if step["schema_version"] != "1.0.0" or step["step_kind"] != expected_kind:
        raise MigrationRehearsalError("migration step kind changed")
    migration_id = _text(step["migration_id"], "migration step execution ID")
    transform = _mapping(
        step["transform_projection"],
        (
            "compatibility_digest", "direction", "implementation_digest",
            "implementation_id", "input_projection_digest", "migration_id",
            "output_projection_digest", "row_rules", "source_contract_id",
            "source_digest", "target_contract_id", "transform_digest", "transform_id",
        ),
        "migration transform projection",
    )
    if transform["direction"] != expected_kind or transform["migration_id"] != migration_id:
        raise MigrationRehearsalError("migration transform lineage changed")
    for name in (
        "compatibility_digest", "implementation_digest", "input_projection_digest",
        "output_projection_digest", "source_digest", "transform_digest",
    ):
        _digest(transform[name], f"migration transform {name}")
    ledger = _history(
        step["ledger"], migration_id, terminal=("completed",),
        label=f"migration {expected_kind} ledger",
    )
    source = ledger[0].get("source_manifest")
    active = ledger[-1].get("active_manifest")
    if (
        type(source) is not dict or type(active) is not dict
        or step["source_manifest_digest"] != source.get("manifest_digest")
        or step["target_manifest_digest"] != active.get("manifest_digest")
        or step["source_repository_id"] != source.get("repository_id")
        or step["target_repository_id"] != active.get("repository_id")
        or step["source_generation"] != source.get("generation")
        or step["target_generation"] != active.get("generation")
        or step["source_activation_epoch"] != source.get("activation_epoch")
        or step["target_activation_epoch"] != active.get("activation_epoch")
        or step["target_generation"] <= step["source_generation"]
        or step["target_activation_epoch"] <= step["source_activation_epoch"]
        or step["bundle_projection"] != ledger[-1].get("bundle")
        or step["candidate_projection"] != ledger[-1].get("candidate")
    ):
        raise MigrationRehearsalError("migration step source/target evidence changed")
    expected_history = semantic_digest(
        {"history": ledger},
        contract_type="urn:gew:contract:migration-rehearsal-execution-history",
        projection_id=(
            "urn:gew:digest-projection:migration-rehearsal-execution-history:1.0.0"
        ),
        schema_id="urn:gew:schema:migration-step-observation-input:1.0.0",
    )
    if step["history_digest"] != expected_history:
        raise MigrationRehearsalError("migration step ledger digest changed")
    integrity = _mapping(
        step["integrity_projection"],
        (
            "bundle_digest", "snapshot_digest", "source_repository_digest",
            "candidate_records_digest", "candidate_repository_digest", "result",
            "integrity_digest",
        ),
        "migration integrity projection",
    )
    if integrity["result"] != "verified":
        raise MigrationRehearsalError("migration integrity result changed")
    _self_digest(integrity, "migration-rehearsal-integrity", "integrity_digest")
    compatibility = _mapping(
        step["compatibility_projection"],
        (
            "compatibility_policy_id", "source_contract_id", "target_contract_id",
            "compatibility_digest", "result",
        ),
        "migration compatibility projection",
    )
    if (
        compatibility["result"] != "compatible"
        or compatibility["compatibility_digest"] != transform["compatibility_digest"]
        or compatibility["source_contract_id"] != transform["source_contract_id"]
        or compatibility["target_contract_id"] != transform["target_contract_id"]
    ):
        raise MigrationRehearsalError("migration compatibility evidence changed")
    _self_digest(step, "migration-step-observation", "step_digest")
    return step


def _crash(value: object) -> Mapping[str, object]:
    crash = _mapping(value, _CRASH_FIELDS, "migration crash recovery")
    if crash["schema_version"] != "1.0.0":
        raise MigrationRehearsalError("migration crash recovery version changed")
    migration_id = _text(crash["migration_id"], "migration crash execution ID")
    ledger = _history(
        crash["ledger"], migration_id,
        terminal=("recovered_old_active", "recovered_rolled_back", "recovered_new_active"),
        label="migration crash ledger",
    )
    provenance = _mapping(
        crash["cut_provenance"],
        (
            "case_digest", "cut_id", "expected_outcome", "migration_id",
            "required_states", "terminal_states",
        ),
        "migration crash cut provenance",
    )
    states = tuple(item["migration"]["state"] for item in ledger)
    if (
        provenance["cut_id"] != crash["crash_cut_id"]
        or provenance["migration_id"] != migration_id
        or tuple(provenance["required_states"]) != states[:-1]
        or states[-1] not in tuple(provenance["terminal_states"])
        or provenance["expected_outcome"] != crash["outcome"]
        or crash["source_manifest"] != ledger[0].get("source_manifest")
        or crash["recovered_manifest"] != ledger[-1].get("recovered_manifest")
        or crash["bundle_projection"] != ledger[-1].get("bundle")
        or crash["candidate_projection"] != ledger[-1].get("candidate")
    ):
        raise MigrationRehearsalError("migration crash cut evidence changed")
    expected_history = semantic_digest(
        {"history": ledger},
        contract_type="urn:gew:contract:migration-rehearsal-execution-history",
        projection_id=(
            "urn:gew:digest-projection:migration-rehearsal-execution-history:1.0.0"
        ),
        schema_id="urn:gew:schema:migration-step-observation-input:1.0.0",
    )
    if crash["history_digest"] != expected_history:
        raise MigrationRehearsalError("migration crash ledger digest changed")
    _self_digest(crash, "migration-crash-recovery-observation", "recovery_digest")
    return crash


def _row_artifact(
    value: object, *, stage: str, task_id: str,
) -> Mapping[str, object]:
    artifact = _mapping(value, _ROW_ARTIFACT_FIELDS, "migration row artifact")
    if (
        artifact["schema_version"] != "1.0.0"
        or artifact["stage"] != stage
        or artifact["artifact_id"] != f"migration-row-artifact:{task_id}:{stage}"
    ):
        raise MigrationRehearsalError("migration row artifact identity changed")
    rows = artifact["rows"]
    if type(rows) is not list or len(rows) != 4:
        raise MigrationRehearsalError("migration row artifact closure is incomplete")
    row_ids: list[str] = []
    field_ids: list[str] = []
    for value_row in rows:
        row = _mapping(
            value_row, _ROW_ARTIFACT_ROW_FIELDS, "migration row artifact row",
        )
        row_ids.append(_text(row["row_id"], "migration row artifact row ID"))
        field_ids.append(_text(row["field_id"], "migration row artifact field ID"))
        if type(row["present"]) is not bool or (
            row["present"] and type(row["value"]) is not str
        ) or (not row["present"] and row["value"] is not None):
            raise MigrationRehearsalError("migration row artifact presence changed")
        if row["present"]:
            _text(row["value"], "migration row artifact value")
        status = _text(row["status"], "migration row artifact status")
        route = _text(row["owner_route"], "migration row artifact owner route")
        if (
            status not in {"exported", "applied", "rejected"}
            or status in {"exported", "rejected"} and route != "none"
        ):
            raise MigrationRehearsalError("migration row artifact result changed")
        _self_digest(
            row, "migration-rehearsal-row-artifact-row", "row_digest",
        )
    if (
        tuple(row_ids) != tuple(sorted(set(row_ids)))
        or tuple(field_ids) != tuple(sorted(set(field_ids)))
    ):
        raise MigrationRehearsalError("migration row artifact rows are not canonical")
    _self_digest(
        artifact, "migration-rehearsal-row-artifact", "artifact_digest",
    )
    return artifact


def _row_execution(
    value: object,
    *,
    task_id: str,
    forward: Mapping[str, object],
    backward: Mapping[str, object],
) -> Mapping[str, object]:
    execution = _mapping(value, _ROW_EXECUTION_FIELDS, "migration row execution")
    if execution["schema_version"] != "1.0.0" or execution["task_id"] != task_id:
        raise MigrationRehearsalError("migration row execution identity changed")
    source = _row_artifact(
        execution["source_artifact"], stage="source-export", task_id=task_id,
    )
    forward_artifact = _row_artifact(
        execution["forward_artifact"], stage="forward-readback", task_id=task_id,
    )
    backward_artifact = _row_artifact(
        execution["backward_artifact"], stage="backward-readback", task_id=task_id,
    )
    if (
        source["migration_id"] is not None
        or source["transform_digest"] is not None
        or source["history_digest"] is not None
        or forward_artifact["migration_id"] != forward["migration_id"]
        or forward_artifact["transform_digest"]
        != forward["transform_projection"]["transform_digest"]
        or forward_artifact["history_digest"] != forward["history_digest"]
        or backward_artifact["migration_id"] != backward["migration_id"]
        or backward_artifact["transform_digest"]
        != backward["transform_projection"]["transform_digest"]
        or backward_artifact["history_digest"] != backward["history_digest"]
    ):
        raise MigrationRehearsalError("migration row execution history changed")
    source_rows = source["rows"]
    forward_rows = forward_artifact["rows"]
    backward_rows = backward_artifact["rows"]
    for source_row, forward_row, backward_row in zip(
        source_rows, forward_rows, backward_rows, strict=True,
    ):
        if (
            source_row["row_id"] != forward_row["row_id"]
            or source_row["row_id"] != backward_row["row_id"]
            or source_row["field_id"] != forward_row["field_id"]
            or source_row["field_id"] != backward_row["field_id"]
        ):
            raise MigrationRehearsalError("migration row execution lineage changed")
    _self_digest(
        execution, "migration-rehearsal-row-execution", "execution_digest",
    )
    return execution


@dataclass(frozen=True, slots=True)
class MigrationRehearsalObservation:
    observation_id: str
    task_id: str
    task_revision: int
    snapshot_digest: str
    invalidation_epoch: int
    registry_digest: str
    bootstrap_digest: str
    fixture_manifest_digest: str
    transform_manifest_digest: str
    current_manifest_digest: str
    document: FrozenMap
    observation_digest: str

    @classmethod
    def from_document(cls, value: object) -> MigrationRehearsalObservation:
        document = _mapping(value, _OBSERVATION_FIELDS, "migration rehearsal observation")
        if document["schema_version"] != "1.0.0":
            raise MigrationRehearsalError("migration rehearsal observation version changed")
        task = _mapping(
            document["task_binding"],
            (
                "task_id", "task_revision", "snapshot_digest", "invalidation_epoch",
                "graph_ref_pins",
            ),
            "migration rehearsal task binding",
        )
        installation = _mapping(
            document["installation_projection"],
            (
                "build_backend_raw_sha256", "bootstrap_digest", "distribution_root",
                "distribution_version", "fixture_manifest_digest", "installation_id",
                "installation_mode", "profile_schema_registry_digest",
                "protected_closure_digest", "record_raw_sha256", "registry_digest",
                "schema_raw_sha256", "source_attestation_digest",
                "source_attestation_policy_id", "transform_manifest_digest",
            ),
            "migration rehearsal installation projection",
        )
        current = _mapping(
            document["current_manifest"],
            (
                "installation_id", "generation", "activation_epoch", "repository_id",
                "repository_digest", "repository_locator_ref", "manifest_digest",
                "repository_locator_digest", "release_id", "contract_id", "mode",
                "previous_manifest_digest", "fencing_high_water", "restore_gap_digest",
            ),
            "migration rehearsal current manifest",
        )
        forward = _step(document["forward_step"], "forward")
        backward = _step(document["backward_step"], "backward")
        if (
            forward["migration_id"] == backward["migration_id"]
            or forward["target_manifest_digest"] != backward["source_manifest_digest"]
            or backward["target_generation"] <= forward["target_generation"]
            or backward["target_activation_epoch"] <= forward["target_activation_epoch"]
            or current["manifest_digest"] != backward["target_manifest_digest"]
            or current["mode"] != "active"
            or current["restore_gap_digest"] is not None
        ):
            raise MigrationRehearsalError("migration A-B-A lineage changed")
        row_execution = _row_execution(
            document["row_execution"],
            task_id=_text(task["task_id"], "migration rehearsal task ID"),
            forward=forward,
            backward=backward,
        )
        source_rows = row_execution["source_artifact"]["rows"]
        forward_rows = row_execution["forward_artifact"]["rows"]
        backward_rows = row_execution["backward_artifact"]["rows"]
        partial = document["partial_data"]
        if type(partial) is not list or len(partial) != 4:
            raise MigrationRehearsalError("migration partial-data closure is incomplete")
        case_ids: list[str] = []
        row_ids: list[str] = []
        dispositions: list[str] = []
        for item, source_row, forward_row, backward_row in zip(
            partial, source_rows, forward_rows, backward_rows, strict=True,
        ):
            row = _mapping(item, _PARTIAL_FIELDS, "migration partial-data observation")
            case_ids.append(_text(row["case_id"], "migration partial-data case ID"))
            row_ids.append(_text(row["row_id"], "migration partial-data row ID"))
            disposition = _text(row["disposition"], "migration partial-data disposition")
            if disposition not in {"preserved", "defaulted", "rejected", "owner-route"}:
                raise MigrationRehearsalError("migration partial-data disposition changed")
            dispositions.append(disposition)
            route = _text(row["owner_route"], "migration partial-data owner route")
            if (disposition == "owner-route") != (route != "none"):
                raise MigrationRehearsalError("migration partial-data owner route changed")
            if (
                row["forward_integrity_digest"]
                != forward["integrity_projection"]["integrity_digest"]
                or row["backward_integrity_digest"]
                != backward["integrity_projection"]["integrity_digest"]
                or row["row_execution_digest"] != row_execution["execution_digest"]
                or row["source_row_digest"] != source_row["row_digest"]
                or row["forward_row_digest"] != forward_row["row_digest"]
                or row["backward_row_digest"] != backward_row["row_digest"]
                or row["row_id"] != source_row["row_id"]
                or row["row_id"] != forward_row["row_id"]
                or row["row_id"] != backward_row["row_id"]
            ):
                raise MigrationRehearsalError("migration partial-data integrity changed")
            _self_digest(
                row,
                "migration-rehearsal-partial-data-observation",
                "disposition_digest",
            )
        if (
            tuple(case_ids) != tuple(sorted(set(case_ids)))
            or tuple(row_ids) != tuple(sorted(set(row_ids)))
            or set(dispositions) != {"preserved", "defaulted", "rejected", "owner-route"}
        ):
            raise MigrationRehearsalError("migration partial-data observations changed")
        crashes = document["crash_recoveries"]
        if type(crashes) is not list or len(crashes) < 2:
            raise MigrationRehearsalError("migration crash recovery closure is incomplete")
        parsed_crashes = tuple(_crash(item) for item in crashes)
        cut_ids = tuple(item["crash_cut_id"] for item in parsed_crashes)
        if cut_ids != tuple(sorted(set(cut_ids))):
            raise MigrationRehearsalError("migration crash recoveries are not canonical")
        lifecycle = _mapping(
            document["lifecycle_projection"],
            (
                "live_leases", "unresolved_claims", "action_states",
                "compensable_action_refs", "fencing_high_water",
                "security_state_digest", "retention_plan_ref",
                "rollback_clearance_ref", "assertion",
            ),
            "migration lifecycle projection",
        )
        if lifecycle["live_leases"] or lifecycle["unresolved_claims"]:
            raise MigrationRehearsalError("migration lifecycle is not quiescent")
        target = _mapping(
            document["fresh_target"],
            (
                "repository_root", "repository_device", "repository_inode",
                "manifest_digest", "repository_digest", "task_snapshot_digest",
                "fresh", "target_digest",
            ),
            "migration fresh target",
        )
        if (
            target["fresh"] is not True
            or target["manifest_digest"] != current["manifest_digest"]
            or target["repository_digest"] != current["repository_digest"]
            or target["task_snapshot_digest"] != task["snapshot_digest"]
        ):
            raise MigrationRehearsalError("migration fresh target changed")
        _self_digest(target, "migration-rehearsal-fresh-target", "target_digest")
        digest = _self_digest(
            document, "migration-rehearsal-observation", "observation_digest",
        )
        for field in (
            "build_backend_raw_sha256", "record_raw_sha256",
            "source_attestation_digest",
        ):
            _raw(installation[field], f"migration {field}")
        for field in (
            "distribution_root", "distribution_version", "installation_mode",
            "source_attestation_policy_id",
        ):
            _text(installation[field], f"migration {field}")
        _digest(
            installation["protected_closure_digest"],
            "migration protected closure digest",
        )
        return cls(
            _text(document["observation_id"], "migration rehearsal observation ID"),
            _text(task["task_id"], "migration rehearsal task ID"),
            _integer(task["task_revision"], "migration rehearsal task revision", minimum=1),
            _digest(task["snapshot_digest"], "migration rehearsal snapshot digest"),
            _integer(task["invalidation_epoch"], "migration invalidation epoch"),
            _digest(installation["registry_digest"], "migration registry digest"),
            _digest(installation["bootstrap_digest"], "migration bootstrap digest"),
            _digest(installation["fixture_manifest_digest"], "migration fixture digest"),
            _digest(installation["transform_manifest_digest"], "migration transform digest"),
            _digest(current["manifest_digest"], "migration current manifest digest"),
            freeze(document),
            digest,
        )

    def to_dict(self) -> dict[str, object]:
        value = thaw(self.document)
        if type(value) is not dict:
            raise AssertionError("migration rehearsal observation did not thaw")
        return value


__all__ = [
    "MIGRATION_REHEARSAL_SCHEMA_IDS",
    "MigrationRehearsalError",
    "MigrationRehearsalObservation",
    "MigrationRehearsalRegistryData",
    "parse_migration_rehearsal_registry",
]
