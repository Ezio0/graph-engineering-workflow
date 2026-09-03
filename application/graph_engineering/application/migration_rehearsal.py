"""Consumer-local WP-08 migration rehearsal observation authority."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import pathlib
import stat
import tomllib
from collections.abc import Mapping

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.migration_rehearsal import (
    MIGRATION_REHEARSAL_SCHEMA_IDS,
    MigrationRehearsalError,
    MigrationRehearsalObservation,
    MigrationRehearsalRegistryData,
    parse_migration_rehearsal_registry,
)


def _strict_json(value: bytes, label: str) -> dict[str, object]:
    if type(value) is not bytes:
        raise MigrationRehearsalError(f"{label} bytes are invalid")
    try:
        parsed = json.loads(value)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise MigrationRehearsalError(f"{label} is invalid JSON") from error
    if type(parsed) is not dict:
        raise MigrationRehearsalError(f"{label} is not an object")
    return parsed


def _raw(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _self_digest(document: Mapping[str, object], name: str, field: str) -> str:
    expected = document.get(field)
    if type(expected) is not str:
        raise MigrationRehearsalError(f"{name} digest is invalid")
    body = copy.deepcopy(dict(document))
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


def _exact_mapping(
    value: object, fields: frozenset[str], label: str,
) -> dict[str, object]:
    if type(value) is not dict or set(value) != fields:
        raise MigrationRehearsalError(f"{label} fields are not exact")
    return value


def _text(value: object, label: str) -> str:
    if (
        type(value) is not str or not value or value != value.strip()
        or not value.isascii() or "\x00" in value
    ):
        raise MigrationRehearsalError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    result = _text(value, label)
    if (
        not result.startswith("sha256-jcs-v1:") or len(result) != 78
        or any(item not in "0123456789abcdef" for item in result[14:])
    ):
        raise MigrationRehearsalError(f"{label} is invalid")
    return result


def _child_digest(
    value: Mapping[str, object], name: str, field: str,
) -> str:
    return _self_digest(value, name, field)


def _validate_fixture(document: dict[str, object]) -> dict[str, object]:
    _exact_mapping(document, frozenset({
        "schema_version", "fixture_manifest_id", "source_contract_id",
        "target_contract_id", "source_rows", "rows", "partial_data_cases",
        "crash_cases", "fixture_manifest_digest",
    }), "migration rehearsal fixture")
    if document["schema_version"] != "1.0.0":
        raise MigrationRehearsalError("migration rehearsal fixture version changed")
    for name in (
        "fixture_manifest_id", "source_contract_id", "target_contract_id",
    ):
        _text(document[name], f"migration fixture {name}")
    source_rows = document["source_rows"]
    if type(source_rows) is not list or len(source_rows) != 4:
        raise MigrationRehearsalError("migration fixture source rows are incomplete")
    source_row_ids: list[str] = []
    source_field_ids: list[str] = []
    for item in source_rows:
        source = _exact_mapping(item, frozenset({
            "row_id", "field_id", "present", "value", "row_digest",
        }), "migration fixture source row")
        source_row_ids.append(_text(source["row_id"], "migration source row ID"))
        source_field_ids.append(_text(source["field_id"], "migration source field ID"))
        present = source["present"]
        value = source["value"]
        if type(present) is not bool or (
            present and type(value) is not str
        ) or (not present and value is not None):
            raise MigrationRehearsalError("migration fixture source presence changed")
        if present:
            _text(value, "migration fixture source value")
        _child_digest(
            source, "migration-rehearsal-source-row", "row_digest",
        )
    if (
        tuple(source_row_ids) != tuple(sorted(set(source_row_ids)))
        or tuple(source_field_ids) != tuple(sorted(set(source_field_ids)))
    ):
        raise MigrationRehearsalError("migration fixture source rows are not canonical")
    rows = document["rows"]
    if type(rows) is not list or len(rows) != 4:
        raise MigrationRehearsalError("migration fixture rows are incomplete")
    row_ids: list[str] = []
    field_ids: list[str] = []
    dispositions: list[str] = []
    for item in rows:
        row = _exact_mapping(item, frozenset({
            "row_id", "field_id", "source_value", "forward_value",
            "backward_value", "disposition", "owner_route", "row_digest",
        }), "migration fixture row")
        row_ids.append(_text(row["row_id"], "migration fixture row ID"))
        field_ids.append(_text(row["field_id"], "migration fixture field ID"))
        for name in ("source_value", "forward_value", "backward_value"):
            _text(row[name], f"migration fixture {name}")
        disposition = _text(row["disposition"], "migration fixture disposition")
        if disposition not in {"preserved", "defaulted", "rejected", "owner-route"}:
            raise MigrationRehearsalError("migration fixture disposition changed")
        dispositions.append(disposition)
        route = _text(row["owner_route"], "migration fixture owner route")
        if (disposition == "owner-route") != (route != "none"):
            raise MigrationRehearsalError("migration fixture owner route is unauthorized")
        _child_digest(row, "migration-rehearsal-fixture-row", "row_digest")
    if (
        tuple(row_ids) != tuple(sorted(set(row_ids)))
        or tuple(field_ids) != tuple(sorted(set(field_ids)))
        or set(dispositions) != {"preserved", "defaulted", "rejected", "owner-route"}
        or tuple(row_ids) != tuple(source_row_ids)
        or tuple(field_ids) != tuple(source_field_ids)
    ):
        raise MigrationRehearsalError("migration fixture row closure changed")
    cases = document["partial_data_cases"]
    if type(cases) is not list or len(cases) != len(rows):
        raise MigrationRehearsalError("migration partial-data cases are incomplete")
    case_ids: list[str] = []
    for item, row in zip(cases, rows, strict=True):
        case = _exact_mapping(item, frozenset({
            "case_id", "row_id", "field_id", "expected_disposition",
            "owner_route", "case_digest",
        }), "migration partial-data case")
        case_ids.append(_text(case["case_id"], "migration partial-data case ID"))
        if (
            case["row_id"] != row["row_id"]
            or case["field_id"] != row["field_id"]
            or case["expected_disposition"] != row["disposition"]
            or case["owner_route"] != row["owner_route"]
        ):
            raise MigrationRehearsalError("migration partial-data fixture is not row-derived")
        _child_digest(case, "migration-rehearsal-partial-data-case", "case_digest")
    if tuple(case_ids) != tuple(sorted(set(case_ids))):
        raise MigrationRehearsalError("migration partial-data cases are not canonical")
    crashes = document["crash_cases"]
    if type(crashes) is not list or len(crashes) < 2:
        raise MigrationRehearsalError("migration crash cases are incomplete")
    cut_ids: list[str] = []
    migration_ids: list[str] = []
    for item in crashes:
        crash = _exact_mapping(item, frozenset({
            "cut_id", "migration_id", "expected_outcome", "required_states",
            "terminal_states", "case_digest",
        }), "migration crash case")
        cut_ids.append(_text(crash["cut_id"], "migration crash cut ID"))
        migration_ids.append(_text(crash["migration_id"], "migration crash migration ID"))
        if crash["expected_outcome"] not in {"old-active", "new-active"}:
            raise MigrationRehearsalError("migration crash outcome changed")
        for name in ("required_states", "terminal_states"):
            values = crash[name]
            if (
                type(values) is not list or not values
                or tuple(values) != tuple(dict.fromkeys(values))
                or any(type(value) is not str or not value for value in values)
            ):
                raise MigrationRehearsalError("migration crash ledger policy changed")
        _child_digest(crash, "migration-rehearsal-crash-case", "case_digest")
    if (
        tuple(cut_ids) != tuple(sorted(set(cut_ids)))
        or len(set(migration_ids)) != len(migration_ids)
    ):
        raise MigrationRehearsalError("migration crash cases are not canonical")
    _self_digest(
        document, "migration-rehearsal-fixture-manifest", "fixture_manifest_digest",
    )
    return document


def _validate_transform(document: dict[str, object]) -> dict[str, object]:
    _exact_mapping(document, frozenset({
        "schema_version", "manifest_id", "transforms", "manifest_digest",
    }), "migration transform manifest")
    if document["schema_version"] != "1.0.0":
        raise MigrationRehearsalError("migration transform manifest version changed")
    _text(document["manifest_id"], "migration transform manifest ID")
    transforms = document["transforms"]
    if type(transforms) is not list or len(transforms) != 2:
        raise MigrationRehearsalError("migration transform paths are incomplete")
    ids: list[str] = []
    directions: list[str] = []
    migrations: list[str] = []
    for item in transforms:
        row = _exact_mapping(item, frozenset({
            "transform_id", "migration_id", "direction", "implementation_id",
            "implementation_digest", "source_digest", "source_contract_id",
            "target_contract_id", "input_projection_digest",
            "output_projection_digest", "compatibility_digest",
            "row_rules", "transform_digest",
        }), "migration transform row")
        ids.append(_text(row["transform_id"], "migration transform ID"))
        migrations.append(_text(row["migration_id"], "migration execution ID"))
        direction = _text(row["direction"], "migration transform direction")
        if direction not in {"backward", "forward"}:
            raise MigrationRehearsalError("migration transform direction changed")
        directions.append(direction)
        for name in ("implementation_id", "source_contract_id", "target_contract_id"):
            _text(row[name], f"migration transform {name}")
        for name in (
            "implementation_digest", "source_digest", "input_projection_digest",
            "output_projection_digest", "compatibility_digest",
        ):
            _digest(row[name], f"migration transform {name}")
        rules = row["row_rules"]
        if type(rules) is not list or len(rules) != 4:
            raise MigrationRehearsalError("migration transform row rules are incomplete")
        rule_ids: list[str] = []
        rule_fields: list[str] = []
        for item_rule in rules:
            rule = _exact_mapping(item_rule, frozenset({
                "row_id", "field_id", "input_present", "input_value",
                "output_present", "output_value", "action", "owner_route",
                "rule_digest",
            }), "migration transform row rule")
            rule_ids.append(_text(rule["row_id"], "migration transform row ID"))
            rule_fields.append(_text(rule["field_id"], "migration transform field ID"))
            for prefix in ("input", "output"):
                present = rule[f"{prefix}_present"]
                value = rule[f"{prefix}_value"]
                if type(present) is not bool or (
                    present and type(value) is not str
                ) or (not present and value is not None):
                    raise MigrationRehearsalError(
                        "migration transform row presence changed"
                    )
                if present:
                    _text(value, f"migration transform {prefix} value")
            action = _text(rule["action"], "migration transform row action")
            if action not in {"apply", "reject"}:
                raise MigrationRehearsalError("migration transform action changed")
            route = _text(rule["owner_route"], "migration transform owner route")
            if action == "reject" and route != "none":
                raise MigrationRehearsalError("rejected transform has an owner route")
            _child_digest(
                rule, "migration-rehearsal-transform-row-rule", "rule_digest",
            )
        if (
            tuple(rule_ids) != tuple(sorted(set(rule_ids)))
            or tuple(rule_fields) != tuple(sorted(set(rule_fields)))
        ):
            raise MigrationRehearsalError("migration transform row rules are not canonical")
        _child_digest(row, "migration-rehearsal-transform", "transform_digest")
    if (
        tuple(ids) != tuple(sorted(set(ids)))
        or len(set(migrations)) != 2
        or set(directions) != {"backward", "forward"}
    ):
        raise MigrationRehearsalError("migration transform closure changed")
    _self_digest(
        document, "migration-rehearsal-transform-manifest", "manifest_digest",
    )
    return document


def _canonical_document_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True,
    ).encode("ascii") + b"\n"


def _write_owner_only_document(
    path: pathlib.Path, value: Mapping[str, object],
) -> dict[str, object]:
    body = _canonical_document_bytes(value)
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(body)
        offset = 0
        while offset < len(body):
            offset += os.write(descriptor, view[offset:])
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    return dict(sorted({
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "path": path.as_posix(),
        "raw_sha256": _raw(body),
    }.items()))


def _read_owner_only_document(
    binding: Mapping[str, object], label: str,
) -> dict[str, object]:
    if set(binding) != {"device", "inode", "path", "raw_sha256"}:
        raise MigrationRehearsalError(f"{label} file binding is not exact")
    path_value = binding.get("path")
    if type(path_value) is not str:
        raise MigrationRehearsalError(f"{label} file path is invalid")
    path = pathlib.Path(path_value)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        body = b"".join(chunks)
        rebound = path.lstat()
    finally:
        os.close(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino)
        != (binding.get("device"), binding.get("inode"))
        or (rebound.st_dev, rebound.st_ino) != (metadata.st_dev, metadata.st_ino)
        or _raw(body) != binding.get("raw_sha256")
    ):
        raise MigrationRehearsalError(f"{label} file changed")
    document = _strict_json(body, label)
    if _canonical_document_bytes(document) != body:
        raise MigrationRehearsalError(f"{label} bytes are not canonical")
    return document


def _installation_projection() -> tuple[
    MigrationRehearsalRegistryData, FrozenMap, FrozenMap, FrozenMap, FrozenMap,
]:
    try:
        from graph_engineering import _migration_rehearsal_installation_resources

        resources = _migration_rehearsal_installation_resources()
    except Exception as error:
        raise MigrationRehearsalError(
            "migration rehearsal installation resources are unavailable"
        ) from error
    if type(resources) is not tuple or len(resources) < 20:
        raise MigrationRehearsalError("migration rehearsal installation closure is incomplete")
    provenance, registry_raw, fixture_raw, transform_raw, bootstrap_raw, schemas_raw, *tail = (
        resources[0], resources[1], resources[2], resources[3], resources[4],
        resources[5], *resources[6:],
    )
    try:
        provenance_document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        project = provenance_document["project"]
        pin = provenance_document["tool"]["gew"]["profile"]["migration-rehearsal"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise MigrationRehearsalError(
            "migration rehearsal independent pin is unavailable"
        ) from error
    if type(project) is not dict or type(pin) is not dict:
        raise MigrationRehearsalError("migration rehearsal provenance is invalid")
    registry_document = _strict_json(registry_raw, "migration rehearsal registry")
    fixture = _validate_fixture(
        _strict_json(fixture_raw, "migration rehearsal fixture")
    )
    transform = _validate_transform(
        _strict_json(transform_raw, "migration rehearsal transform manifest")
    )
    bootstrap = _strict_json(bootstrap_raw, "migration rehearsal bootstrap")
    schema_registry = _strict_json(schemas_raw, "Profile schema registry")
    registry = parse_migration_rehearsal_registry(registry_document)
    fixture_digest = _self_digest(
        fixture, "migration-rehearsal-fixture-manifest", "fixture_manifest_digest",
    )
    transform_digest = _self_digest(
        transform, "migration-rehearsal-transform-manifest", "manifest_digest",
    )
    bootstrap_digest = _self_digest(
        bootstrap, "migration-rehearsal-installation-bootstrap", "bootstrap_digest",
    )
    protected = pin.get("protected-resources")
    normalized_protected = [
        {
            "raw_sha256": item["raw-sha256"],
            "resource": item["resource"],
            "source": item["source"],
        }
        for item in protected
    ] if type(protected) is list and all(type(item) is dict for item in protected) else []
    protected_bodies = resources[22:]
    closure_digest = semantic_digest(
        {"resources": normalized_protected},
        contract_type="urn:gew:contract:migration-rehearsal-protected-resource-closure",
        projection_id=(
            "urn:gew:digest-projection:migration-rehearsal-protected-resource-closure:1.0.0"
        ),
        schema_id=(
            "urn:gew:schema:migration-rehearsal-protected-resource-closure-input:1.0.0"
        ),
    )
    if (
        not normalized_protected
        or tuple(item["source"] for item in normalized_protected)
        != tuple(sorted({item["source"] for item in normalized_protected}))
        or len(protected_bodies) != len(normalized_protected)
        or any(
            _raw(body) != vector["raw_sha256"]
            for vector, body in zip(normalized_protected, protected_bodies, strict=True)
        )
        or bootstrap.get("protected_resources") != normalized_protected
        or bootstrap.get("protected_closure_digest") != closure_digest
        or pin.get("protected-closure-digest") != closure_digest
    ):
        raise MigrationRehearsalError("migration rehearsal protected closure changed")
    try:
        from graph_engineering import _migration_rehearsal_installation_identity

        installed = dict(_migration_rehearsal_installation_identity(provenance))
    except Exception as error:
        raise MigrationRehearsalError(
            "migration rehearsal distribution identity is unavailable"
        ) from error
    if (
        registry.fixture_manifest_id != fixture.get("fixture_manifest_id")
        or registry.fixture_manifest_digest != fixture_digest
        or registry.transform_manifest_id != transform.get("manifest_id")
        or registry.transform_manifest_digest != transform_digest
        or bootstrap.get("bootstrap_id") != "urn:gew:migration-rehearsal-bootstrap:v1"
        or bootstrap.get("registry_id") != registry.registry_id
        or bootstrap.get("registry_digest") != registry.registry_digest
        or bootstrap.get("registry_raw_sha256") != _raw(registry_raw)
        or bootstrap.get("fixture_manifest_id") != registry.fixture_manifest_id
        or bootstrap.get("fixture_manifest_digest") != fixture_digest
        or bootstrap.get("fixture_raw_sha256") != _raw(fixture_raw)
        or bootstrap.get("transform_manifest_id") != registry.transform_manifest_id
        or bootstrap.get("transform_manifest_digest") != transform_digest
        or bootstrap.get("transform_raw_sha256") != _raw(transform_raw)
        or bootstrap.get("profile_schema_registry_id") != schema_registry.get("registry_id")
        or bootstrap.get("profile_schema_registry_digest") != schema_registry.get("registry_digest")
        or bootstrap.get("profile_schema_registry_raw_sha256") != _raw(schemas_raw)
        or bootstrap.get("distribution_name") != project.get("name")
        or bootstrap.get("distribution_version") != project.get("version")
        or bootstrap.get("source_attestation_policy_id")
        != pin.get("source-attestation-policy-id")
        or bootstrap.get("build_backend_raw_sha256")
        != pin.get("build-backend-raw-sha256")
        or bootstrap.get("build_backend_source") != pin.get("build-backend-source")
        or bootstrap.get("build_backend_resource") != pin.get("build-backend-resource")
        or bootstrap.get("network_mode") != "offline-only"
        or bootstrap.get("activation_status") != "rehearsal-only-wp10-blocked"
    ):
        raise MigrationRehearsalError("migration rehearsal bootstrap identity changed")
    schema_resources = bootstrap.get("schema_resources")
    if type(schema_resources) is not list or len(schema_resources) != 16:
        raise MigrationRehearsalError("migration rehearsal schema closure is incomplete")
    schema_bodies = resources[6:22]
    identities: list[str] = []
    raw_digests: list[str] = []
    registered = {
        item.get("schema_id"): item.get("body_digest")
        for item in schema_registry.get("resources", [])
        if type(item) is dict
    }
    for vector, body in zip(schema_resources, schema_bodies, strict=True):
        if type(vector) is not dict or set(vector) != {"schema_id", "raw_sha256"}:
            raise MigrationRehearsalError("migration rehearsal schema pin is not exact")
        schema = _strict_json(body, "migration rehearsal schema")
        schema_id = vector["schema_id"]
        raw = _raw(body)
        if (
            type(schema_id) is not str
            or schema.get("$id") != schema_id
            or vector["raw_sha256"] != raw
            or registered.get(schema_id) != "sha256-raw-v1:" + raw
        ):
            raise MigrationRehearsalError("migration rehearsal schema bytes changed")
        identities.append(schema_id)
        raw_digests.append(raw)
    if tuple(identities) != MIGRATION_REHEARSAL_SCHEMA_IDS:
        raise MigrationRehearsalError("migration rehearsal schema identities are not exact")
    projection = freeze({
        "build_backend_raw_sha256": bootstrap.get("build_backend_raw_sha256"),
        "installation_id": bootstrap.get("installation_id"),
        "distribution_root": installed["distribution_root"],
        "distribution_version": installed["distribution_version"],
        "installation_mode": installed["installation_mode"],
        "record_raw_sha256": installed["record_raw_sha256"],
        "source_attestation_digest": installed["source_attestation_digest"],
        "source_attestation_policy_id": bootstrap.get("source_attestation_policy_id"),
        "registry_digest": registry.registry_digest,
        "bootstrap_digest": bootstrap_digest,
        "fixture_manifest_digest": fixture_digest,
        "transform_manifest_digest": transform_digest,
        "profile_schema_registry_digest": schema_registry.get("registry_digest"),
        "protected_closure_digest": closure_digest,
        "schema_raw_sha256": raw_digests,
    })
    return registry, freeze(fixture), freeze(transform), freeze(bootstrap), projection


class MigrationRehearsalAuthority:
    """Opaque current installation authority issued by one factory."""

    __slots__ = ("registry_digest", "bootstrap_digest", "_factory")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("migration rehearsal authorities are factory-issued")


class MigrationRehearsalObservationAuthority:
    """Opaque task-bound observation authority."""

    __slots__ = ("observation", "_factory")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("migration rehearsal observations are factory-issued")


class MigrationRehearsalFactory:
    """Derive current rehearsal truth from one installed migration repository."""

    __slots__ = (
        "_manager", "_repository", "_registry", "_fixture", "_transform",
        "_bootstrap", "_projection", "_issued", "_observations", "_executions",
        "_task_bindings", "_row_execution", "_row_execution_paths", "_completed",
        "_replay_count", "authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("migration rehearsal factories are installation-issued")

    @classmethod
    def from_installation(
        cls, manager: object, repository: object,
    ) -> MigrationRehearsalFactory:
        from graph_engineering.storage.migration import (
            InstallationMigrationRepository,
            MigrationRepositoryError,
        )
        from graph_engineering.storage.repository import TaskRepository

        if (
            cls is not MigrationRehearsalFactory
            or type(manager) is not InstallationMigrationRepository
            or type(repository) is not TaskRepository
        ):
            raise MigrationRehearsalError("migration rehearsal installation is foreign")
        registry, fixture, transform, bootstrap, projection = _installation_projection()
        scope = repository._command_scope
        if scope is None or getattr(scope, "_manager", None) is not manager:
            raise MigrationRehearsalError("migration rehearsal repository scope is foreign")
        try:
            scope.require_current()
        except MigrationRepositoryError as error:
            raise MigrationRehearsalError(
                "migration rehearsal repository scope is stale"
            ) from error
        if pathlib.Path(repository._factory.data_root) != scope.repository_root:
            raise MigrationRehearsalError("migration rehearsal repository is not current")
        factory = object.__new__(MigrationRehearsalFactory)
        factory._manager = manager
        factory._repository = repository
        factory._registry = registry
        factory._fixture = fixture
        factory._transform = transform
        factory._bootstrap = bootstrap
        factory._projection = projection
        factory._issued = {}
        factory._observations = {}
        factory._executions = {}
        factory._task_bindings = {}
        factory._row_execution = None
        factory._row_execution_paths = None
        factory._completed = None
        factory._replay_count = 0
        authority = object.__new__(MigrationRehearsalAuthority)
        authority.registry_digest = registry.registry_digest
        authority.bootstrap_digest = str(projection["bootstrap_digest"])
        authority._factory = factory
        factory.authority = authority
        factory._issued[id(authority)] = authority
        return factory

    def bind_task(self, authority: object, task_id: str) -> None:
        """Capture one factory-owned current task projection before migration."""

        self.require_authority_current(authority)
        task_id = _text(task_id, "migration rehearsal task ID")
        if task_id in self._task_bindings:
            raise MigrationRehearsalError("migration rehearsal task is already bound")
        self._task_bindings[task_id] = freeze(
            self._task_binding(self._repository.load(task_id), task_id)
        )

    def _current_context(self) -> dict[str, object]:
        from graph_engineering.storage.migration import (
            InstallationCommandScope,
            MigrationRepositoryError,
        )

        scope = self._repository._command_scope
        if (
            type(scope) is not InstallationCommandScope
            or getattr(scope, "_manager", None) is not self._manager
        ):
            raise MigrationRehearsalError("migration rehearsal repository scope is foreign")
        try:
            scope.require_current()
        except MigrationRepositoryError:
            with self._manager.command_scope() as current_scope:
                return self._context_from_scope(current_scope)
        return self._context_from_scope(scope)

    def _context_from_scope(self, scope: object) -> dict[str, object]:
        if pathlib.Path(self._repository._factory.data_root) != scope.repository_root:
            raise MigrationRehearsalError("migration rehearsal repository became stale")
        context = scope.context
        manifest = self._manager._current_manifest()
        return dict(sorted({
                "installation_id": context.installation_id,
                "generation": context.generation,
                "activation_epoch": context.activation_epoch,
                "repository_id": context.repository_id,
                "repository_digest": manifest.repository_digest,
                "repository_locator_ref": manifest.repository_locator_ref,
                "manifest_digest": context.manifest_digest,
                "repository_locator_digest": context.repository_locator_digest,
                "release_id": manifest.release_id,
                "contract_id": manifest.contract_id,
                "mode": manifest.mode,
                "previous_manifest_digest": manifest.previous_manifest_digest,
                "fencing_high_water": [list(item) for item in manifest.fencing_high_water],
                "restore_gap_digest": manifest.restore_gap_digest,
        }.items()))

    def _transform_for_direction(self, direction: str) -> dict[str, object]:
        matches = tuple(
            thaw(item) for item in self._transform["transforms"]
            if item["direction"] == direction
        )
        if len(matches) != 1 or type(matches[0]) is not dict:
            raise MigrationRehearsalError("migration transform direction is not unique")
        return matches[0]

    @staticmethod
    def _row_artifact_row(
        *,
        row_id: object,
        field_id: object,
        present: object,
        value: object,
        status: object,
        owner_route: object,
    ) -> dict[str, object]:
        row_id = _text(row_id, "migration row artifact row ID")
        field_id = _text(field_id, "migration row artifact field ID")
        if type(present) is not bool or (
            present and type(value) is not str
        ) or (not present and value is not None):
            raise MigrationRehearsalError("migration row artifact presence is invalid")
        if present:
            _text(value, "migration row artifact value")
        status = _text(status, "migration row artifact status")
        if status not in {"exported", "applied", "rejected"}:
            raise MigrationRehearsalError("migration row artifact status changed")
        owner_route = _text(owner_route, "migration row artifact owner route")
        if status in {"exported", "rejected"} and owner_route != "none":
            raise MigrationRehearsalError("migration row artifact route is unauthorized")
        body = {
            "field_id": field_id,
            "owner_route": owner_route,
            "present": present,
            "row_id": row_id,
            "status": status,
            "value": value,
        }
        body["row_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-row-artifact-row",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-row-artifact-row:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:migration-rehearsal-row-artifact-row-input:1.0.0"
            ),
        )
        return dict(sorted(body.items()))

    @staticmethod
    def _row_artifact(
        *,
        task_id: str,
        stage: str,
        migration_id: str | None,
        transform_digest: str | None,
        history_digest: str | None,
        rows: list[dict[str, object]],
    ) -> dict[str, object]:
        body = {
            "schema_version": "1.0.0",
            "artifact_id": f"migration-row-artifact:{task_id}:{stage}",
            "stage": stage,
            "migration_id": migration_id,
            "transform_digest": transform_digest,
            "history_digest": history_digest,
            "rows": rows,
        }
        body["artifact_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-row-artifact",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-row-artifact:1.0.0"
            ),
            schema_id="urn:gew:schema:migration-rehearsal-row-artifact-input:1.0.0",
        )
        return dict(sorted(body.items()))

    def _source_row_artifact(self, task_id: str) -> dict[str, object]:
        rows: list[dict[str, object]] = []
        for frozen_row in self._fixture["source_rows"]:
            row = thaw(frozen_row)
            if type(row) is not dict:
                raise MigrationRehearsalError("migration source row did not thaw")
            rows.append(self._row_artifact_row(
                row_id=row["row_id"],
                field_id=row["field_id"],
                present=row["present"],
                value=row["value"],
                status="exported",
                owner_route="none",
            ))
        return self._row_artifact(
            task_id=task_id,
            stage="source-export",
            migration_id=None,
            transform_digest=None,
            history_digest=None,
            rows=rows,
        )

    def _transformed_row_artifact(
        self,
        *,
        task_id: str,
        source: Mapping[str, object],
        direction: str,
        stage: str,
        history_digest: str,
    ) -> dict[str, object]:
        transform = self._transform_for_direction(direction)
        input_rows = source.get("rows")
        rules = transform.get("row_rules")
        if type(input_rows) is not list or type(rules) is not list:
            raise MigrationRehearsalError("migration row transform input is absent")
        if len(input_rows) != len(rules):
            raise MigrationRehearsalError("migration row transform input is incomplete")
        output: list[dict[str, object]] = []
        for input_row, frozen_rule in zip(input_rows, rules, strict=True):
            rule = thaw(frozen_rule)
            if type(input_row) is not dict or type(rule) is not dict:
                raise MigrationRehearsalError("migration row transform evidence is malformed")
            if (
                input_row.get("row_id") != rule.get("row_id")
                or input_row.get("field_id") != rule.get("field_id")
                or input_row.get("present") is not rule.get("input_present")
                or input_row.get("value") != rule.get("input_value")
            ):
                raise MigrationRehearsalError("migration row transform input changed")
            action = rule.get("action")
            output.append(self._row_artifact_row(
                row_id=rule["row_id"],
                field_id=rule["field_id"],
                present=rule["output_present"],
                value=rule["output_value"],
                status="applied" if action == "apply" else "rejected",
                owner_route=rule["owner_route"],
            ))
        return self._row_artifact(
            task_id=task_id,
            stage=stage,
            migration_id=str(transform["migration_id"]),
            transform_digest=str(transform["transform_digest"]),
            history_digest=history_digest,
            rows=output,
        )

    @staticmethod
    def _parse_row_artifact(
        value: object, *, stage: str, task_id: str,
    ) -> dict[str, object]:
        artifact = _exact_mapping(value, frozenset({
            "schema_version", "artifact_id", "stage", "migration_id",
            "transform_digest", "history_digest", "rows", "artifact_digest",
        }), "migration row artifact")
        if (
            artifact["schema_version"] != "1.0.0"
            or artifact["stage"] != stage
            or artifact["artifact_id"] != f"migration-row-artifact:{task_id}:{stage}"
        ):
            raise MigrationRehearsalError("migration row artifact identity changed")
        rows = artifact["rows"]
        if type(rows) is not list or len(rows) != 4:
            raise MigrationRehearsalError("migration row artifact rows are incomplete")
        row_ids: list[str] = []
        field_ids: list[str] = []
        for item in rows:
            row = _exact_mapping(item, frozenset({
                "row_id", "field_id", "present", "value", "status",
                "owner_route", "row_digest",
            }), "migration row artifact row")
            expected = MigrationRehearsalFactory._row_artifact_row(
                row_id=row["row_id"],
                field_id=row["field_id"],
                present=row["present"],
                value=row["value"],
                status=row["status"],
                owner_route=row["owner_route"],
            )
            if expected != row:
                raise MigrationRehearsalError("migration row artifact row digest changed")
            row_ids.append(str(row["row_id"]))
            field_ids.append(str(row["field_id"]))
        if (
            tuple(row_ids) != tuple(sorted(set(row_ids)))
            or tuple(field_ids) != tuple(sorted(set(field_ids)))
        ):
            raise MigrationRehearsalError("migration row artifact rows are not canonical")
        expected_artifact = copy.deepcopy(artifact)
        expected_digest = expected_artifact.pop("artifact_digest")
        actual_digest = semantic_digest(
            expected_artifact,
            contract_type="urn:gew:contract:migration-rehearsal-row-artifact",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-row-artifact:1.0.0"
            ),
            schema_id="urn:gew:schema:migration-rehearsal-row-artifact-input:1.0.0",
        )
        if type(expected_digest) is not str or not hmac.compare_digest(
            expected_digest, actual_digest,
        ):
            raise MigrationRehearsalError("migration row artifact digest changed")
        return artifact

    @staticmethod
    def _row_value(row: Mapping[str, object]) -> str:
        return str(row["value"]) if row["present"] else "omitted"

    def _derive_partial_rows(
        self, execution: Mapping[str, object],
    ) -> list[dict[str, object]]:
        source = self._parse_row_artifact(
            execution.get("source_artifact"),
            stage="source-export", task_id=str(execution.get("task_id")),
        )
        forward = self._parse_row_artifact(
            execution.get("forward_artifact"),
            stage="forward-readback", task_id=str(execution.get("task_id")),
        )
        backward = self._parse_row_artifact(
            execution.get("backward_artifact"),
            stage="backward-readback", task_id=str(execution.get("task_id")),
        )
        derived: list[dict[str, object]] = []
        for source_row, forward_row, backward_row in zip(
            source["rows"], forward["rows"], backward["rows"], strict=True,
        ):
            if (
                source_row["row_id"] != forward_row["row_id"]
                or source_row["row_id"] != backward_row["row_id"]
                or source_row["field_id"] != forward_row["field_id"]
                or source_row["field_id"] != backward_row["field_id"]
            ):
                raise MigrationRehearsalError("migration row execution lineage changed")
            route = forward_row["owner_route"]
            if (
                forward_row["status"] == "rejected"
                and backward_row["status"] == "rejected"
                and forward_row["present"] is source_row["present"]
                and backward_row["present"] is source_row["present"]
                and forward_row["value"] == source_row["value"]
                and backward_row["value"] == source_row["value"]
                and route == "none" and backward_row["owner_route"] == "none"
            ):
                disposition = "rejected"
            elif (
                route != "none" and backward_row["owner_route"] == route
                and forward_row["status"] == "applied"
                and backward_row["status"] == "applied"
                and backward_row["present"] is source_row["present"]
                and backward_row["value"] == source_row["value"]
            ):
                disposition = "owner-route"
            elif (
                source_row["present"] is False
                and forward_row["present"] is True
                and backward_row["present"] is False
                and forward_row["status"] == "applied"
                and backward_row["status"] == "applied"
                and route == "none" and backward_row["owner_route"] == "none"
            ):
                disposition = "defaulted"
            elif (
                source_row["present"] is True
                and forward_row["status"] == "applied"
                and backward_row["status"] == "applied"
                and backward_row["present"] is True
                and backward_row["value"] == source_row["value"]
                and route == "none" and backward_row["owner_route"] == "none"
            ):
                disposition = "preserved"
            else:
                raise MigrationRehearsalError(
                    "migration row disposition is not execution-derived"
                )
            result = {
                "row_id": source_row["row_id"],
                "field_id": source_row["field_id"],
                "source_value": self._row_value(source_row),
                "forward_value": self._row_value(forward_row),
                "backward_value": self._row_value(backward_row),
                "disposition": disposition,
                "owner_route": route if disposition == "owner-route" else "none",
            }
            result["row_digest"] = semantic_digest(
                result,
                contract_type="urn:gew:contract:migration-rehearsal-fixture-row",
                projection_id=(
                    "urn:gew:digest-projection:migration-rehearsal-fixture-row:1.0.0"
                ),
                schema_id=(
                    "urn:gew:schema:migration-rehearsal-fixture-row-input:1.0.0"
                ),
            )
            derived.append(dict(sorted(result.items())))
        expected = [thaw(item) for item in self._fixture["rows"]]
        if derived != expected:
            raise MigrationRehearsalError(
                "migration row execution does not match protected expectations"
            )
        return derived

    def _validate_row_execution(
        self, value: object, *, task_id: str,
    ) -> dict[str, object]:
        execution = _exact_mapping(value, frozenset({
            "schema_version", "task_id", "source_artifact", "forward_artifact",
            "backward_artifact", "execution_digest",
        }), "migration row execution")
        if execution["schema_version"] != "1.0.0" or execution["task_id"] != task_id:
            raise MigrationRehearsalError("migration row execution identity changed")
        source = self._parse_row_artifact(
            execution["source_artifact"], stage="source-export", task_id=task_id,
        )
        forward_execution = self._execution(
            str(self._transform_for_direction("forward")["migration_id"])
        )
        backward_execution = self._execution(
            str(self._transform_for_direction("backward")["migration_id"])
        )
        forward = self._parse_row_artifact(
            execution["forward_artifact"], stage="forward-readback", task_id=task_id,
        )
        backward = self._parse_row_artifact(
            execution["backward_artifact"], stage="backward-readback", task_id=task_id,
        )
        expected_source = self._source_row_artifact(task_id)
        expected_forward = self._transformed_row_artifact(
            task_id=task_id,
            source=source,
            direction="forward",
            stage="forward-readback",
            history_digest=str(forward_execution["history_digest"]),
        )
        expected_backward = self._transformed_row_artifact(
            task_id=task_id,
            source=forward,
            direction="backward",
            stage="backward-readback",
            history_digest=str(backward_execution["history_digest"]),
        )
        if source != expected_source or forward != expected_forward or backward != expected_backward:
            raise MigrationRehearsalError("migration row execution artifacts changed")
        self._derive_partial_rows(execution)
        body = copy.deepcopy(execution)
        expected_digest = body.pop("execution_digest")
        actual_digest = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-row-execution",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-row-execution:1.0.0"
            ),
            schema_id="urn:gew:schema:migration-rehearsal-row-execution-input:1.0.0",
        )
        if type(expected_digest) is not str or not hmac.compare_digest(
            expected_digest, actual_digest,
        ):
            raise MigrationRehearsalError("migration row execution digest changed")
        return execution

    def _require_row_execution_current(self, *, task_id: str) -> dict[str, object]:
        if self._row_execution is None:
            raise MigrationRehearsalError("migration row execution is absent")
        value = thaw(self._row_execution)
        if type(value) is not dict:
            raise MigrationRehearsalError("migration row execution did not thaw")
        current = self._validate_row_execution(value, task_id=task_id)
        if self._row_execution_paths is not None:
            bindings = thaw(self._row_execution_paths)
            if type(bindings) is not dict or set(bindings) != {
                "source_artifact", "forward_artifact", "backward_artifact",
            }:
                raise MigrationRehearsalError("migration row file bindings changed")
            for name in sorted(bindings):
                observed = _read_owner_only_document(
                    bindings[name], f"migration {name.replace('_', ' ')}",
                )
                if observed != current[name]:
                    raise MigrationRehearsalError("migration row artifact file changed")
        return current

    def _adopt_row_execution(self, source: object) -> None:
        if (
            type(source) is not MigrationRehearsalFactory
            or source is self
            or source._manager is not self._manager
            or source._projection != self._projection
            or self._row_execution is not None
        ):
            raise MigrationRehearsalError("migration row execution source is foreign")
        task_ids = tuple(source._task_bindings)
        if len(task_ids) != 1:
            raise MigrationRehearsalError("migration row execution task is not unique")
        value = thaw(source._row_execution)
        if type(value) is not dict:
            raise MigrationRehearsalError("migration row execution source is absent")
        paths = thaw(source._row_execution_paths)
        if type(paths) is not dict or set(paths) != {
            "source_artifact", "forward_artifact", "backward_artifact",
        }:
            raise MigrationRehearsalError("migration row file source is absent")
        for name in sorted(paths):
            if _read_owner_only_document(
                paths[name], f"migration {name.replace('_', ' ')}",
            ) != value[name]:
                raise MigrationRehearsalError("migration row file source changed")
        current = self._validate_row_execution(value, task_id=task_ids[0])
        self._row_execution = freeze(current)
        self._row_execution_paths = freeze(paths)

    def _set_row_execution(
        self,
        *,
        task_id: str,
        source: dict[str, object],
        forward: dict[str, object],
        backward: dict[str, object],
        paths: dict[str, object] | None,
    ) -> None:
        body = {
            "schema_version": "1.0.0",
            "task_id": task_id,
            "source_artifact": source,
            "forward_artifact": forward,
            "backward_artifact": backward,
        }
        body["execution_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-row-execution",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-row-execution:1.0.0"
            ),
            schema_id="urn:gew:schema:migration-rehearsal-row-execution-input:1.0.0",
        )
        self._row_execution = freeze(dict(sorted(body.items())))
        self._row_execution_paths = None if paths is None else freeze(paths)
        self._require_row_execution_current(task_id=task_id)

    def _crash_case(self, cut_id: str) -> dict[str, object]:
        matches = tuple(
            thaw(item) for item in self._fixture["crash_cases"]
            if item["cut_id"] == cut_id
        )
        if len(matches) != 1 or type(matches[0]) is not dict:
            raise MigrationRehearsalError("migration crash cut is not config-owned")
        return matches[0]

    @staticmethod
    def _history_states(history: object) -> tuple[str, ...]:
        if type(history) is not tuple or not history:
            raise MigrationRehearsalError("migration ledger is absent")
        states: list[str] = []
        for revision, row in enumerate(history, 1):
            if type(row) is not dict or type(row.get("migration")) is not dict:
                raise MigrationRehearsalError("migration ledger row is malformed")
            migration = row["migration"]
            if (
                migration.get("revision") != revision
                or type(migration.get("state")) is not str
            ):
                raise MigrationRehearsalError("migration ledger is not consecutive")
            states.append(migration["state"])
        return tuple(states)

    def _current_migration_history(
        self, migration_id: str,
    ) -> tuple[dict[str, object], ...]:
        """Read through the exact command scope when this factory already holds it."""

        scope = self._repository._command_scope
        if scope is not None:
            try:
                scope.require_current()
            except Exception:
                pass
            else:
                return self._manager._migration_history(
                    migration_id, self._repository._factory,
                )
        return self._manager.migration_history(migration_id)

    def _record_execution(
        self,
        *,
        migration_id: str,
        direction: str | None,
        cut_id: str | None,
    ) -> None:
        if migration_id in self._executions:
            raise MigrationRehearsalError("migration execution identity was reused")
        history = self._current_migration_history(migration_id)
        states = self._history_states(history)
        if direction is not None:
            transform = self._transform_for_direction(direction)
            expected = (
                "requested", "upgrade_locked", "quiescence_verified", "exported",
                "imported_isolated", "replayed", "compatible",
                "activation_prepared", "verifying_reference",
                "post_switch_verified", "active", "completed",
            )
            if (
                transform["migration_id"] != migration_id
                or states != expected
            ):
                raise MigrationRehearsalError(
                    "migration execution does not bind the configured transform"
                )
            policy = transform
        else:
            if cut_id is None:
                raise MigrationRehearsalError("migration crash provenance is absent")
            crash = self._crash_case(cut_id)
            required = tuple(crash["required_states"])
            terminals = tuple(crash["terminal_states"])
            if (
                crash["migration_id"] != migration_id
                or states[:-1] != required
                or states[-1] not in terminals
            ):
                raise MigrationRehearsalError(
                    "migration crash ledger does not bind the configured cut"
                )
            policy = crash
        self._executions[migration_id] = freeze({
            "migration_id": migration_id,
            "direction": direction,
            "cut_id": cut_id,
            "policy": policy,
            "history": list(history),
            "history_digest": semantic_digest(
                {"history": history},
                contract_type="urn:gew:contract:migration-rehearsal-execution-history",
                projection_id=(
                    "urn:gew:digest-projection:migration-rehearsal-execution-history:1.0.0"
                ),
                schema_id="urn:gew:schema:migration-step-observation-input:1.0.0",
            ),
        })

    def _rehydrate_executions(self, source_factory: object | None = None) -> None:
        """Rebuild the consumer-local execution ledger without replay."""

        if self._executions:
            raise MigrationRehearsalError("migration execution ledger is already issued")
        forward = self._transform_for_direction("forward")
        self._record_execution(
            migration_id=str(forward["migration_id"]), direction="forward", cut_id=None,
        )
        for frozen_case in self._fixture["crash_cases"]:
            crash = thaw(frozen_case)
            if type(crash) is not dict:
                raise MigrationRehearsalError("migration crash case did not thaw")
            self._record_execution(
                migration_id=str(crash["migration_id"]),
                direction=None,
                cut_id=str(crash["cut_id"]),
            )
        backward = self._transform_for_direction("backward")
        self._record_execution(
            migration_id=str(backward["migration_id"]), direction="backward", cut_id=None,
        )
        self._replay_count = 0
        self._validate_lineage()
        if source_factory is not None:
            self._adopt_row_execution(source_factory)

    def _rehydrate_executions_from_projection(self, projection: object) -> None:
        """Rebuild execution truth only from one referenced assessment projection."""

        fields = {
            "schema_version", "evidence_kind", "task_id", "task_revision",
            "snapshot_digest", "invalidation_epoch", "profile_id",
            "graph_ref_pins", "observation", "projection_digest",
        }
        if type(projection) is not dict or set(projection) != fields:
            raise MigrationRehearsalError(
                "migration restart assessment projection is not exact"
            )
        expected = projection["projection_digest"]
        body = copy.deepcopy(projection)
        del body["projection_digest"]
        if (
            projection["schema_version"] != "1.0.0"
            or projection["evidence_kind"] != "migration-rehearsal-evidence-v1"
            or projection["profile_id"] != "migration"
            or type(expected) is not str
            or not hmac.compare_digest(
                expected,
                semantic_digest(
                    body,
                    contract_type=(
                        "urn:gew:contract:migration-rehearsal-assessment-projection"
                    ),
                    projection_id=(
                        "urn:gew:digest-projection:"
                        "migration-rehearsal-assessment-projection:1.0.0"
                    ),
                    schema_id=(
                        "urn:gew:schema:category-completion-assessment-input:1.2.0"
                    ),
                ),
            )
        ):
            raise MigrationRehearsalError(
                "migration restart assessment projection changed"
            )
        observation = projection["observation"]
        if type(observation) is not dict:
            raise MigrationRehearsalError(
                "migration restart observation projection is malformed"
            )
        self._rehydrate_executions()
        current = self._validate_row_execution(
            observation.get("row_execution"),
            task_id=_text(projection["task_id"], "migration rehearsal task ID"),
        )
        self._row_execution = freeze(current)
        self._row_execution_paths = None

    def execute(
        self,
        authority: object,
        *,
        task_id: str,
        private_root: pathlib.Path,
    ) -> None:
        """Run the complete config-owned rehearsal once inside a private root."""

        self.require_authority_current(authority)
        _text(task_id, "migration rehearsal task ID")
        if not isinstance(private_root, pathlib.Path) or not private_root.is_absolute():
            raise MigrationRehearsalError("migration rehearsal root is invalid")
        metadata = private_root.lstat()
        if (
            private_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or self._executions or self._completed is not None
        ):
            raise MigrationRehearsalError("migration rehearsal root is not fresh owner-only")
        # Prove the task existed under this factory before any installation
        # mutation; the original repository scope is intentionally closed
        # before the installation-wide rehearsal begins.
        if task_id not in self._task_bindings:
            raise MigrationRehearsalError("migration rehearsal task was not factory-bound")
        source_artifact = self._source_row_artifact(task_id)
        artifact_paths: dict[str, object] = {
            "source_artifact": _write_owner_only_document(
                private_root / "migration-rehearsal-source-export.json",
                source_artifact,
            ),
        }

        def migrate(
            migration_id: str, *, cut_id: str | None = None,
        ) -> object | None:
            calls = 0

            def fault(point: str) -> None:
                nonlocal calls
                if point == cut_id and calls == 0:
                    calls += 1
                    raise RuntimeError(f"migration-rehearsal-cut:{cut_id}")

            previous_fault = self._manager._fault
            self._manager._fault = fault if cut_id is not None else previous_fault
            try:
                result = self._manager.migrate(
                    migration_id=migration_id,
                    export_id=f"export:{migration_id}",
                    bundle_destination=private_root / f"{migration_id}-bundle",
                    candidate_destination=private_root / f"{migration_id}-candidate",
                    candidate_repository_id=f"repository:{migration_id}",
                    release_id=f"release:{migration_id}",
                    contract_id=self._manager._policy.repository_contract_id,
                )
            except RuntimeError as error:
                if cut_id is None or str(error) != f"migration-rehearsal-cut:{cut_id}":
                    raise
                self._manager._fault = previous_fault
                self._manager.recover_migration(migration_id)
                return None
            finally:
                self._manager._fault = previous_fault
            return result

        # Crash-cut rehearsals are completed before the linked A->B->A path,
        # so they cannot splice an unrelated manifest into the forward/backward
        # lineage that the observation attests.
        for frozen_case in self._fixture["crash_cases"]:
            crash = thaw(frozen_case)
            if type(crash) is not dict:
                raise MigrationRehearsalError("migration crash case did not thaw")
            result = migrate(str(crash["migration_id"]), cut_id=str(crash["cut_id"]))
            if result is not None:
                result.close()
                raise MigrationRehearsalError("migration crash cut was not consumed")
            self._record_execution(
                migration_id=str(crash["migration_id"]),
                direction=None,
                cut_id=str(crash["cut_id"]),
            )
        forward = self._transform_for_direction("forward")
        first = migrate(str(forward["migration_id"]))
        if first is None:
            raise MigrationRehearsalError("forward migration did not complete")
        self._record_execution(
            migration_id=str(forward["migration_id"]), direction="forward", cut_id=None,
        )
        forward_execution = self._execution(str(forward["migration_id"]))
        forward_artifact = self._transformed_row_artifact(
            task_id=task_id,
            source=source_artifact,
            direction="forward",
            stage="forward-readback",
            history_digest=str(forward_execution["history_digest"]),
        )
        artifact_paths["forward_artifact"] = _write_owner_only_document(
            private_root / "migration-rehearsal-forward-readback.json",
            forward_artifact,
        )
        first.close()
        backward = self._transform_for_direction("backward")
        completed = migrate(str(backward["migration_id"]))
        if completed is None:
            raise MigrationRehearsalError("backward migration did not complete")
        self._record_execution(
            migration_id=str(backward["migration_id"]), direction="backward", cut_id=None,
        )
        backward_execution = self._execution(str(backward["migration_id"]))
        backward_artifact = self._transformed_row_artifact(
            task_id=task_id,
            source=forward_artifact,
            direction="backward",
            stage="backward-readback",
            history_digest=str(backward_execution["history_digest"]),
        )
        artifact_paths["backward_artifact"] = _write_owner_only_document(
            private_root / "migration-rehearsal-backward-readback.json",
            backward_artifact,
        )
        self._repository = completed.imported.repository
        self._completed = completed
        self._validate_lineage()
        self._set_row_execution(
            task_id=task_id,
            source=source_artifact,
            forward=forward_artifact,
            backward=backward_artifact,
            paths=artifact_paths,
        )

    def _execution(self, migration_id: str) -> dict[str, object]:
        issued = self._executions.get(migration_id)
        if issued is None:
            raise MigrationRehearsalError("migration execution was not factory-issued")
        value = thaw(issued)
        if type(value) is not dict or type(value.get("history")) is not list:
            raise MigrationRehearsalError("migration execution ledger is invalid")
        current = self._current_migration_history(migration_id)
        self._history_states(current)
        if freeze(value["history"]) != freeze(list(current)):
            raise MigrationRehearsalError("migration execution ledger changed")
        return value

    def _validate_lineage(self) -> None:
        forward = self._execution(
            str(self._transform_for_direction("forward")["migration_id"])
        )
        backward = self._execution(
            str(self._transform_for_direction("backward")["migration_id"])
        )
        forward_history = forward["history"]
        backward_history = backward["history"]
        assert type(forward_history) is list and type(backward_history) is list
        forward_active = forward_history[-1]["active_manifest"]
        backward_source = backward_history[0]["source_manifest"]
        backward_active = backward_history[-1]["active_manifest"]
        if (
            forward["migration_id"] == backward["migration_id"]
            or forward_active != backward_source
            or backward_active["generation"] <= forward_active["generation"]
            or backward_active["activation_epoch"] <= forward_active["activation_epoch"]
            or backward_active["fencing_high_water"] < forward_active["fencing_high_water"]
        ):
            raise MigrationRehearsalError("migration A-B-A lineage is not exact and monotonic")

    def require_authority_current(self, value: object) -> MigrationRehearsalAuthority:
        if (
            type(value) is not MigrationRehearsalAuthority
            or getattr(value, "_factory", None) is not self
            or self._issued.get(id(value)) is not value
        ):
            raise MigrationRehearsalError("migration rehearsal authority is foreign")
        registry, fixture, transform, bootstrap, projection = _installation_projection()
        if (
            registry != self._registry or fixture != self._fixture
            or transform != self._transform or bootstrap != self._bootstrap
            or projection != self._projection
            or value.registry_digest != registry.registry_digest
            or value.bootstrap_digest != projection["bootstrap_digest"]
        ):
            raise MigrationRehearsalError("migration rehearsal installation changed")
        self._current_context()
        return value

    @staticmethod
    def _task_binding(snapshot: object, task_id: str) -> dict[str, object]:
        if type(snapshot) is not dict or set(snapshot) != {"task_id", "revision", "domain", "runner"}:
            raise MigrationRehearsalError("migration task snapshot wrapper is not exact")
        domain = snapshot["domain"]
        if type(domain) is not dict or snapshot["task_id"] != task_id:
            raise MigrationRehearsalError("migration task snapshot is foreign")
        graph_ref = domain.get("graph_ref")
        if type(graph_ref) is not dict:
            raise MigrationRehearsalError("migration task GraphRef is absent")
        pins = {
            "base_graph_digest": graph_ref.get("graph_digest"),
            "profile_digest": graph_ref.get("profile_digest"),
            "overlay_digest": graph_ref.get("overlay_digest"),
            "project_config_digest": graph_ref.get("project_config_digest"),
            "support_matrix_digest": graph_ref.get("support_matrix_digest"),
            "materialization_digest": graph_ref.get("materialization_digest"),
        }
        if any(type(value) is not str for value in pins.values()):
            raise MigrationRehearsalError("migration task GraphRef pins are incomplete")
        revision = domain.get("task_revision")
        digest = domain.get("snapshot_digest")
        epoch = domain.get("invalidation_epoch")
        if type(revision) is not int or revision < 1 or type(digest) is not str or type(epoch) is not int:
            raise MigrationRehearsalError("migration task currentness is invalid")
        return dict(sorted({
            "task_id": task_id,
            "task_revision": revision,
            "snapshot_digest": digest,
            "invalidation_epoch": epoch,
            "graph_ref_pins": dict(sorted(pins.items())),
        }.items()))

    @staticmethod
    def _manifest_from_history(record: object, field: str) -> dict[str, object]:
        if type(record) is not dict or type(record.get(field)) is not dict:
            raise MigrationRehearsalError("migration history manifest is absent")
        return copy.deepcopy(record[field])

    def _step(self, migration_id: str, expected_kind: str) -> dict[str, object]:
        execution = self._execution(migration_id)
        history = execution["history"]
        if (
            type(history) is not list
            or execution["direction"] != expected_kind
            or execution["cut_id"] is not None
            or history[-1]["migration"]["state"] != "completed"
        ):
            raise MigrationRehearsalError("migration rehearsal step is not completed")
        source = self._manifest_from_history(history[0], "source_manifest")
        active = self._manifest_from_history(history[-1], "active_manifest")
        if (
            type(source.get("generation")) is not int
            or type(active.get("generation")) is not int
            or active["generation"] <= source["generation"]
            or type(source.get("activation_epoch")) is not int
            or type(active.get("activation_epoch")) is not int
            or active["activation_epoch"] <= source["activation_epoch"]
        ):
            raise MigrationRehearsalError("migration rehearsal generation is not monotonic")
        transform = self._transform_for_direction(expected_kind)
        if transform["migration_id"] != migration_id:
            raise MigrationRehearsalError("migration transform execution ID changed")
        bundle = copy.deepcopy(history[-1]["bundle"])
        candidate = copy.deepcopy(history[-1]["candidate"])
        if type(bundle) is not dict or type(candidate) is not dict:
            raise MigrationRehearsalError("migration bundle or candidate evidence is absent")
        integrity = {
            "bundle_digest": bundle["bundle_digest"],
            "snapshot_digest": bundle["snapshot_digest"],
            "source_repository_digest": bundle["source_repository_digest"],
            "candidate_records_digest": candidate["candidate_records_digest"],
            "candidate_repository_digest": candidate["repository_digest"],
            "result": "verified",
        }
        integrity["integrity_digest"] = semantic_digest(
            integrity,
            contract_type="urn:gew:contract:migration-rehearsal-integrity",
            projection_id="urn:gew:digest-projection:migration-rehearsal-integrity:1.0.0",
            schema_id="urn:gew:schema:migration-rehearsal-integrity-input:1.0.0",
        )
        integrity = dict(sorted(integrity.items()))
        compatibility = dict(sorted({
            "compatibility_policy_id": self._registry.compatibility_policy_id,
            "source_contract_id": transform["source_contract_id"],
            "target_contract_id": transform["target_contract_id"],
            "compatibility_digest": transform["compatibility_digest"],
            "result": "compatible",
        }.items()))
        body = {
            "schema_version": "1.0.0",
            "step_id": f"step:{migration_id}",
            "step_kind": expected_kind,
            "migration_id": migration_id,
            "transform_projection": transform,
            "source_manifest_digest": source["manifest_digest"],
            "target_manifest_digest": active["manifest_digest"],
            "source_repository_id": source["repository_id"],
            "target_repository_id": active["repository_id"],
            "source_generation": source["generation"],
            "target_generation": active["generation"],
            "source_activation_epoch": source["activation_epoch"],
            "target_activation_epoch": active["activation_epoch"],
            "ledger": copy.deepcopy(history),
            "history_digest": execution["history_digest"],
            "bundle_projection": bundle,
            "candidate_projection": candidate,
            "integrity_projection": integrity,
            "compatibility_projection": compatibility,
        }
        body["step_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-step-observation",
            projection_id="urn:gew:digest-projection:migration-step-observation:1.0.0",
            schema_id="urn:gew:schema:migration-step-observation-input:1.0.0",
        )
        return dict(sorted(body.items()))

    def _crash_recovery(self, cut_id: str, migration_id: str) -> dict[str, object]:
        execution = self._execution(migration_id)
        history = execution["history"]
        if (
            type(history) is not list
            or execution["cut_id"] != cut_id
            or execution["direction"] is not None
        ):
            raise MigrationRehearsalError("migration crash execution is foreign")
        terminal = history[-1]
        state = terminal["migration"]["state"]
        outcomes = {
            "recovered_old_active": "old-active",
            "recovered_rolled_back": "old-active",
            "recovered_new_active": "new-active",
        }
        outcome = outcomes.get(state)
        manifest = terminal.get("recovered_manifest")
        crash = self._crash_case(cut_id)
        expected = crash["expected_outcome"]
        if (
            crash["migration_id"] != migration_id
            or outcome is None or outcome != expected or type(manifest) is not dict
            or manifest.get("mode") != "active"
        ):
            raise MigrationRehearsalError("migration crash recovery is not old-or-new")
        source_manifest = copy.deepcopy(history[0]["source_manifest"])
        bundle = copy.deepcopy(terminal.get("bundle"))
        candidate = copy.deepcopy(terminal.get("candidate"))
        if outcome == "old-active" and manifest != source_manifest:
            raise MigrationRehearsalError("migration crash old target is not exact")
        if outcome == "new-active" and (
            type(candidate) is not dict
            or manifest.get("repository_id") != candidate.get("repository_id")
        ):
            raise MigrationRehearsalError("migration crash new target is not exact")
        body = {
            "schema_version": "1.0.0",
            "crash_cut_id": cut_id,
            "migration_id": migration_id,
            "outcome": outcome,
            "observed_manifest_digest": manifest["manifest_digest"],
            "generation": manifest["generation"],
            "activation_epoch": manifest["activation_epoch"],
            "repository_id": manifest["repository_id"],
            "cut_provenance": crash,
            "ledger": copy.deepcopy(history),
            "source_manifest": source_manifest,
            "recovered_manifest": copy.deepcopy(manifest),
            "bundle_projection": bundle,
            "candidate_projection": candidate,
            "history_digest": execution["history_digest"],
        }
        body["recovery_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-crash-recovery-observation",
            projection_id=(
                "urn:gew:digest-projection:migration-crash-recovery-observation:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:migration-crash-recovery-observation-input:1.0.0"
            ),
        )
        return dict(sorted(body.items()))

    def _document(
        self,
        *,
        task_id: str,
    ) -> dict[str, object]:
        if type(task_id) is not str:
            raise MigrationRehearsalError("migration rehearsal selector is not exact")
        self._validate_lineage()
        task = self._task_binding(self._repository.load(task_id), task_id)
        current = self._current_context()
        forward_transform = self._transform_for_direction("forward")
        backward_transform = self._transform_for_direction("backward")
        forward_migration_id = str(forward_transform["migration_id"])
        backward_migration_id = str(backward_transform["migration_id"])
        forward_step = self._step(forward_migration_id, "forward")
        backward_step = self._step(backward_migration_id, "backward")
        row_execution = self._require_row_execution_current(task_id=task_id)
        derived_rows = self._derive_partial_rows(row_execution)
        partial: list[dict[str, object]] = []
        cases = tuple(self._fixture["partial_data_cases"])
        source_rows = row_execution["source_artifact"]["rows"]
        forward_rows = row_execution["forward_artifact"]["rows"]
        backward_rows = row_execution["backward_artifact"]["rows"]
        for frozen_case, row, source_row, forward_row, backward_row in zip(
            cases, derived_rows, source_rows, forward_rows, backward_rows, strict=True,
        ):
            case = thaw(frozen_case)
            if type(case) is not dict or type(row) is not dict:
                raise MigrationRehearsalError("migration partial-data evidence did not thaw")
            if (
                case["row_id"] != row["row_id"]
                or case["field_id"] != row["field_id"]
                or case["expected_disposition"] != row["disposition"]
                or case["owner_route"] != row["owner_route"]
            ):
                raise MigrationRehearsalError("migration partial-data evidence changed")
            evidence = {
                "case_id": case["case_id"],
                "row_id": row["row_id"],
                "field_id": row["field_id"],
                "source_value": row["source_value"],
                "forward_value": row["forward_value"],
                "backward_value": row["backward_value"],
                "disposition": row["disposition"],
                "owner_route": row["owner_route"],
                "row_digest": row["row_digest"],
                "forward_integrity_digest": forward_step["integrity_projection"]["integrity_digest"],
                "backward_integrity_digest": backward_step["integrity_projection"]["integrity_digest"],
                "source_row_digest": source_row["row_digest"],
                "forward_row_digest": forward_row["row_digest"],
                "backward_row_digest": backward_row["row_digest"],
                "row_execution_digest": row_execution["execution_digest"],
            }
            evidence["disposition_digest"] = semantic_digest(
                evidence,
                contract_type="urn:gew:contract:migration-rehearsal-partial-data-observation",
                projection_id=(
                    "urn:gew:digest-projection:migration-rehearsal-partial-data-observation:1.0.0"
                ),
                schema_id=(
                    "urn:gew:schema:migration-rehearsal-partial-data-observation-input:1.0.0"
                ),
            )
            partial.append(dict(sorted(evidence.items())))
        if tuple(item["case_id"] for item in partial) != tuple(sorted({item["case_id"] for item in partial})):
            raise MigrationRehearsalError("migration partial-data observations are not canonical")
        crash = [
            self._crash_recovery(
                cut_id, str(self._crash_case(cut_id)["migration_id"])
            ) for cut_id in self._registry.crash_cut_ids
        ]
        lifecycle = dict(sorted(
            self._repository.lifecycle_facts(task_id).items()
        ))
        root = pathlib.Path(self._repository._factory.data_root)
        metadata = root.lstat()
        target = {
            "repository_root": root.as_posix(),
            "repository_device": metadata.st_dev,
            "repository_inode": metadata.st_ino,
            "manifest_digest": current["manifest_digest"],
            "repository_digest": current["repository_digest"],
            "task_snapshot_digest": task["snapshot_digest"],
            "fresh": True,
        }
        target["target_digest"] = semantic_digest(
            target,
            contract_type="urn:gew:contract:migration-rehearsal-fresh-target",
            projection_id="urn:gew:digest-projection:migration-rehearsal-fresh-target:1.0.0",
            schema_id="urn:gew:schema:migration-rehearsal-fresh-target-input:1.0.0",
        )
        target = dict(sorted(target.items()))
        body = {
            "schema_version": "1.0.0",
            "observation_id": f"migration-rehearsal:{task_id}",
            "task_binding": task,
            "installation_projection": dict(
                sorted(thaw(self._projection).items())
            ),
            "forward_step": forward_step,
            "backward_step": backward_step,
            "row_execution": row_execution,
            "partial_data": partial,
            "crash_recoveries": crash,
            "current_manifest": current,
            "lifecycle_projection": lifecycle,
            "fresh_target": target,
        }
        body["observation_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-observation",
            projection_id="urn:gew:digest-projection:migration-rehearsal-observation:1.0.0",
            schema_id="urn:gew:schema:migration-rehearsal-observation-input:1.0.0",
        )
        return dict(sorted(body.items()))

    def observe(
        self,
        authority: object,
        *,
        task_id: str,
    ) -> MigrationRehearsalObservationAuthority:
        self.require_authority_current(authority)
        document = self._document(task_id=task_id)
        parsed = MigrationRehearsalObservation.from_document(document)
        issued = object.__new__(MigrationRehearsalObservationAuthority)
        issued.observation = parsed
        issued._factory = self
        self._observations[id(issued)] = (issued, task_id, False)
        return issued

    def _require_committed_document_current(
        self, document: Mapping[str, object], task_id: str,
    ) -> None:
        """Revalidate an immutable precommit projection after task completion."""

        stored = thaw(freeze(document))
        if type(stored) is not dict or type(stored.get("task_binding")) is not dict:
            raise MigrationRehearsalError("migration committed projection is malformed")
        old_task = stored["task_binding"]
        current_snapshot = self._repository.load(task_id)
        current_task = self._task_binding(current_snapshot, task_id)
        current_domain = current_snapshot.get("domain")
        if (
            current_task["task_revision"] != old_task.get("task_revision", -1) + 1
            or current_task["invalidation_epoch"] != old_task.get("invalidation_epoch")
            or current_task["graph_ref_pins"] != old_task.get("graph_ref_pins")
            or type(current_domain) is not dict
            or current_domain.get("lifecycle") != "completed"
        ):
            raise MigrationRehearsalError("migration committed task binding changed")
        rebuilt = self._document(task_id=task_id)
        for field in (
            "installation_projection", "forward_step", "backward_step",
            "row_execution", "partial_data", "crash_recoveries", "current_manifest",
        ):
            if freeze(rebuilt[field]) != freeze(stored.get(field)):
                raise MigrationRehearsalError(
                    f"migration committed {field} evidence changed"
                )
        old_target = stored.get("fresh_target")
        new_target = rebuilt.get("fresh_target")
        if type(old_target) is not dict or type(new_target) is not dict:
            raise MigrationRehearsalError("migration committed target is malformed")
        stable_target_fields = {
            "repository_root", "repository_device", "repository_inode",
            "manifest_digest", "repository_digest", "fresh",
        }
        if any(old_target.get(name) != new_target.get(name) for name in stable_target_fields):
            raise MigrationRehearsalError("migration committed target changed")

    def require_current(
        self, value: object,
    ) -> MigrationRehearsalObservationAuthority:
        if (
            type(value) is not MigrationRehearsalObservationAuthority
            or getattr(value, "_factory", None) is not self
        ):
            raise MigrationRehearsalError("migration rehearsal observation is foreign")
        binding = self._observations.get(id(value))
        if binding is None or binding[0] is not value:
            raise MigrationRehearsalError("migration rehearsal observation is unissued")
        self.require_authority_current(self.authority)
        if binding[2]:
            self._require_committed_document_current(
                value.observation.to_dict(), binding[1],
            )
        else:
            rebuilt = self._document(task_id=binding[1])
            if freeze(rebuilt) != value.observation.document:
                raise MigrationRehearsalError("migration rehearsal observation became stale")
        return value

    def projection(self, value: object) -> FrozenMap:
        """Return the closed task evidence projection for category assessment."""

        current = self.require_current(value)
        observation = current.observation.to_dict()
        body = {
            "schema_version": "1.0.0",
            "evidence_kind": "migration-rehearsal-evidence-v1",
            "task_id": current.observation.task_id,
            "task_revision": current.observation.task_revision,
            "snapshot_digest": current.observation.snapshot_digest,
            "invalidation_epoch": current.observation.invalidation_epoch,
            "profile_id": "migration",
            "graph_ref_pins": observation["task_binding"]["graph_ref_pins"],
            "observation": observation,
        }
        body["projection_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:migration-rehearsal-assessment-projection",
            projection_id=(
                "urn:gew:digest-projection:migration-rehearsal-assessment-projection:1.0.0"
            ),
            schema_id="urn:gew:schema:category-completion-assessment-input:1.2.0",
        )
        result = freeze(body)
        if not isinstance(result, FrozenMap):
            raise AssertionError("migration assessment projection did not freeze")
        return result

    def rehydrate_projection(
        self, authority: object, projection: object,
    ) -> MigrationRehearsalObservationAuthority:
        """Reissue only from assessment-CAS bytes already resolved by the consumer."""

        self.require_authority_current(authority)
        if type(projection) is not dict or set(projection) != {
            "schema_version", "evidence_kind", "task_id", "task_revision",
            "snapshot_digest", "invalidation_epoch", "profile_id",
            "graph_ref_pins", "observation", "projection_digest",
        }:
            raise MigrationRehearsalError("migration assessment projection is not exact")
        expected = projection["projection_digest"]
        body = copy.deepcopy(projection)
        del body["projection_digest"]
        if (
            projection["schema_version"] != "1.0.0"
            or projection["evidence_kind"] != "migration-rehearsal-evidence-v1"
            or projection["profile_id"] != "migration"
            or type(expected) is not str
            or not hmac.compare_digest(
                expected,
                semantic_digest(
                    body,
                    contract_type=(
                        "urn:gew:contract:migration-rehearsal-assessment-projection"
                    ),
                    projection_id=(
                        "urn:gew:digest-projection:"
                        "migration-rehearsal-assessment-projection:1.0.0"
                    ),
                    schema_id=(
                        "urn:gew:schema:category-completion-assessment-input:1.2.0"
                    ),
                ),
            )
        ):
            raise MigrationRehearsalError("migration assessment projection digest changed")
        if not self._executions:
            self._rehydrate_executions()
        document = projection["observation"]
        if type(document) is not dict:
            raise MigrationRehearsalError("migration assessment observation is malformed")
        projected_row_execution = document.get("row_execution")
        if self._row_execution is None:
            current_rows = self._validate_row_execution(
                projected_row_execution, task_id=str(projection["task_id"]),
            )
            self._row_execution = freeze(current_rows)
            self._row_execution_paths = None
        elif freeze(self._require_row_execution_current(
            task_id=str(projection["task_id"]),
        )) != freeze(projected_row_execution):
            raise MigrationRehearsalError(
                "migration assessment row execution changed"
            )
        parsed = MigrationRehearsalObservation.from_document(document)
        rebuilt = object.__new__(MigrationRehearsalObservationAuthority)
        rebuilt.observation = parsed
        rebuilt._factory = self
        self._observations[id(rebuilt)] = (
            rebuilt, str(projection["task_id"]), True,
        )
        if (
            rebuilt.observation.task_revision != projection["task_revision"]
            or rebuilt.observation.snapshot_digest != projection["snapshot_digest"]
            or rebuilt.observation.invalidation_epoch != projection["invalidation_epoch"]
            or freeze(
                rebuilt.observation.to_dict()["task_binding"]["graph_ref_pins"]
            ) != freeze(projection["graph_ref_pins"])
            or rebuilt.observation.to_dict() != projection["observation"]
        ):
            self._observations.pop(id(rebuilt), None)
            raise MigrationRehearsalError("migration assessment projection became stale")
        self._require_committed_document_current(document, str(projection["task_id"]))
        if self.projection(rebuilt) != freeze(projection):
            self._observations.pop(id(rebuilt), None)
            raise MigrationRehearsalError("migration assessment projection changed")
        return rebuilt

    def precommit(self, value: object) -> MigrationRehearsalObservationAuthority:
        """Final read-only validation immediately before a caller transaction commits."""

        return self.require_current(value)

    def restart(
        self, authority: object, application: object, task_id: str,
    ) -> MigrationRehearsalObservationAuthority:
        """Resolve the current referenced assessment CAS; caller documents are denied."""

        from graph_engineering.application.profile_execution import (
            CategoryExecutionApplication,
        )

        self.require_authority_current(authority)
        if type(application) is not CategoryExecutionApplication:
            raise MigrationRehearsalError("migration restart consumer is foreign")
        assessment = application.current_assessment(
            task_id, expected_profile_id="migration",
        )
        if assessment is None or assessment.migration_rehearsal_projection is None:
            raise MigrationRehearsalError("migration current assessment is absent")
        projection = thaw(assessment.migration_rehearsal_projection)
        if type(projection) is not dict:
            raise MigrationRehearsalError("migration current assessment is malformed")
        before = self._replay_count
        restarted = self.rehydrate_projection(authority, projection)
        if self._replay_count != before:
            raise MigrationRehearsalError("migration restart replayed execution")
        return restarted


__all__ = [
    "MigrationRehearsalAuthority",
    "MigrationRehearsalFactory",
    "MigrationRehearsalObservationAuthority",
]
