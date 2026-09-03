"""Stable-control data-only activation, task-pin, and diagnostic ledger."""

from __future__ import annotations

import hmac
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from graph_engineering.application.tasks import RuntimeContext
from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.extension_activation import (
    ExtensionActivationError,
    ExtensionActivationManifest,
    ExtensionActivationPolicy,
    ExtensionActivationRequest,
    ExtensionActiveSetPointer,
    ExtensionActiveSetRequest,
    ExtensionBuiltInRegistry,
    ExtensionTaskPinRequest,
    activation_resource_binding_digest,
)
from graph_engineering.core.extension_data import (
    ExtensionCoreInvariantSet,
    ExtensionDataError,
    ExtensionDataRecord,
)
from graph_engineering.core.security.extensions import (
    ExtensionPackageManifest,
    ExtensionTrustPolicy,
)

from .codec import canonical_json, parse_canonical_json
from .extension_bundle import (
    BoundedExtensionBundle,
    ExtensionBundleError,
    verify_extension_bundle,
)
from .extension_install import (
    ExtensionBundleInstaller,
    ExtensionIngestReceipt,
    _INGEST_SCHEMA,
    _ingest_records,
)
from .extensions import ExtensionTrustRepository, ExtensionTrustSnapshot


_SCHEMA = """
CREATE TABLE IF NOT EXISTS extension_activation_ledger (
    record_sequence INTEGER PRIMARY KEY,
    activation_id TEXT NOT NULL UNIQUE,
    extension_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_task_pins (
    record_sequence INTEGER PRIMARY KEY,
    pin_id TEXT NOT NULL UNIQUE,
    task_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_diagnostics (
    record_sequence INTEGER PRIMARY KEY,
    diagnostic_id TEXT NOT NULL UNIQUE,
    code TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_data_registries (
    generation INTEGER PRIMARY KEY CHECK(generation > 0),
    activation_id TEXT NOT NULL UNIQUE,
    registry_digest TEXT NOT NULL UNIQUE,
    registry_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_activation_manifests (
    generation INTEGER PRIMARY KEY CHECK(generation > 0),
    transition_id TEXT NOT NULL UNIQUE,
    manifest_digest TEXT NOT NULL UNIQUE,
    manifest_json TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS extension_active_set_pointer (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    generation INTEGER NOT NULL CHECK(generation > 0),
    manifest_digest TEXT NOT NULL UNIQUE,
    pointer_digest TEXT NOT NULL UNIQUE,
    pointer_json TEXT NOT NULL
) STRICT;
CREATE TRIGGER IF NOT EXISTS extension_activation_no_update BEFORE UPDATE ON extension_activation_ledger
BEGIN SELECT RAISE(ABORT, 'extension activation ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_activation_no_delete BEFORE DELETE ON extension_activation_ledger
BEGIN SELECT RAISE(ABORT, 'extension activation ledger is append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_pin_no_update BEFORE UPDATE ON extension_task_pins
BEGIN SELECT RAISE(ABORT, 'extension task pins are immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_pin_no_delete BEFORE DELETE ON extension_task_pins
BEGIN SELECT RAISE(ABORT, 'extension task pins are immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_diagnostic_no_update BEFORE UPDATE ON extension_diagnostics
BEGIN SELECT RAISE(ABORT, 'extension diagnostics are append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_diagnostic_no_delete BEFORE DELETE ON extension_diagnostics
BEGIN SELECT RAISE(ABORT, 'extension diagnostics are append-only'); END;
CREATE TRIGGER IF NOT EXISTS extension_data_registry_no_update BEFORE UPDATE ON extension_data_registries
BEGIN SELECT RAISE(ABORT, 'extension data registries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_data_registry_no_delete BEFORE DELETE ON extension_data_registries
BEGIN SELECT RAISE(ABORT, 'extension data registries are immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_activation_manifest_no_update BEFORE UPDATE ON extension_activation_manifests
BEGIN SELECT RAISE(ABORT, 'extension activation manifests are immutable'); END;
CREATE TRIGGER IF NOT EXISTS extension_activation_manifest_no_delete BEFORE DELETE ON extension_activation_manifests
BEGIN SELECT RAISE(ABORT, 'extension activation manifests are immutable'); END;
"""


def _no_fault(_point: str) -> None:
    return


@dataclass(frozen=True, slots=True)
class ExtensionActivationReceipt:
    activation_id: str
    extension_id: str
    extension_version: str
    categories: tuple[str, ...]
    record_digest: str
    local_status: str
    formal_release_status: str


@dataclass(frozen=True, slots=True)
class ExtensionTaskPinReceipt:
    pin_id: str
    task_id: str
    record_digest: str
    activation_record_digests: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExtensionActiveSetReceipt:
    generation: int
    transition_kind: str
    manifest_digest: str
    pointer_digest: str


@dataclass(frozen=True, slots=True)
class ExtensionActivationSnapshot:
    activations: tuple[Mapping[str, object], ...]
    task_pins: tuple[Mapping[str, object], ...]
    diagnostics: tuple[Mapping[str, object], ...]
    data_registry: Mapping[str, object] | None
    activation_manifests: tuple[Mapping[str, object], ...]
    active_manifest: Mapping[str, object] | None
    active_pointer: Mapping[str, object] | None


_ISSUED: dict[int, object] = {}
_ISSUED_PIN_AUTHORITIES: dict[int, object] = {}

_CHAIN_FIELDS = {
    "extension_activation_ledger": {
        "schema_version", "record_sequence", "previous_record_digest", "activation_id",
        "installation_id", "request_digest", "ingest_record_digest", "extension_id",
        "extension_version", "package_identity_digest", "manifest_digest", "archive_raw_digest",
        "categories", "trust_policy_digest", "trust_head_digest", "revocation_high_water",
        "activation_policy_digest", "built_in_registry_digest",
        "activation_resource_binding_digest",
        "data_registry_digest", "core_invariant_set_digest",
        "owner_decision_digest", "owner_authority_digest", "conflict_override_digest",
        "activated_at", "local_status", "formal_release_status", "executable_status",
        "record_digest",
    },
    "extension_task_pins": {
        "schema_version", "record_sequence", "previous_record_digest", "pin_id", "task_id",
        "installation_id", "request_digest", "packages", "trust_policy_digest",
        "trust_head_digest", "revocation_high_water", "graph_digest",
        "active_generation", "active_manifest_digest", "contract_registry_digest",
        "capability_profile_digest", "owner_id", "runtime_kind",
        "runtime_lineage_id", "owner_decision_digest", "owner_authority_digest", "pinned_at",
        "record_digest",
    },
    "extension_diagnostics": {
        "schema_version", "record_sequence", "previous_record_digest", "diagnostic_id", "code",
        "subject_digest", "observed_at", "record_digest",
    },
}

_DATA_REGISTRY_FIELDS = {
    "schema_version", "generation", "previous_registry_digest", "activation_id",
    "extension_id", "package_identity_digest", "content_root_ref", "content_root_digest",
    "core_invariant_set_digest", "entries", "resolution_order", "registry_digest",
}


def _record_digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _load_chain(
    connection: sqlite3.Connection,
    table: str,
    maximum: int,
) -> tuple[Mapping[str, object], ...]:
    rows = connection.execute(
        f"SELECT record_sequence,record_digest,record_json FROM {table} ORDER BY record_sequence"
    ).fetchall()
    if len(rows) > maximum:
        raise ExtensionActivationError("extension durable ledger exceeds configured bound")
    records: list[Mapping[str, object]] = []
    previous: str | None = None
    name = {
        "extension_activation_ledger": "extension-activation-record",
        "extension_task_pins": "extension-task-pin-record",
        "extension_diagnostics": "extension-diagnostic-record",
    }[table]
    for expected, (sequence, stored, encoded) in enumerate(rows, 1):
        value = parse_canonical_json(str(encoded))
        if (
            not isinstance(value, Mapping)
            or set(value) != _CHAIN_FIELDS[table]
            or value.get("record_sequence") != expected
        ):
            raise ExtensionActivationError("extension durable ledger sequence is invalid")
        body = dict(value)
        claimed = body.pop("record_digest", None)
        actual = _record_digest(body, name)
        if (
            sequence != expected
            or body.get("previous_record_digest") != previous
            or type(claimed) is not str
            or not hmac.compare_digest(claimed, actual)
            or not hmac.compare_digest(str(stored), actual)
        ):
            raise ExtensionActivationError("extension durable ledger chain is invalid")
        previous = actual
        records.append(value)
    return tuple(records)


def _load_data_registries(
    connection: sqlite3.Connection,
    maximum: int,
) -> tuple[Mapping[str, object], ...]:
    rows = connection.execute(
        "SELECT generation,registry_digest,registry_json FROM extension_data_registries "
        "ORDER BY generation"
    ).fetchall()
    if len(rows) > maximum:
        raise ExtensionActivationError("extension data registry exceeds configured bound")
    result: list[Mapping[str, object]] = []
    previous: str | None = None
    for expected, (generation, stored, encoded) in enumerate(rows, 1):
        value = parse_canonical_json(str(encoded))
        if (
            not isinstance(value, Mapping)
            or set(value) != _DATA_REGISTRY_FIELDS
            or value.get("generation") != expected
            or generation != expected
        ):
            raise ExtensionActivationError("extension data registry generation is invalid")
        body = dict(value)
        claimed = body.pop("registry_digest", None)
        actual = _record_digest(body, "extension-data-registry")
        if (
            body.get("previous_registry_digest") != previous
            or type(claimed) is not str
            or not hmac.compare_digest(claimed, actual)
            or not hmac.compare_digest(str(stored), actual)
        ):
            raise ExtensionActivationError("extension data registry chain is invalid")
        entries = body.get("entries")
        order = body.get("resolution_order")
        if type(entries) is not list or type(order) is not list:
            raise ExtensionActivationError("extension data registry body is invalid")
        identities: list[tuple[str, str]] = []
        digests: set[str] = set()
        for entry in entries:
            if not isinstance(entry, Mapping) or set(entry) != {
                "kind", "id", "record_digest", "record", "extension_id",
                "extension_version", "package_identity_digest", "ingest_record_digest",
                "content_root_ref", "content_root_digest",
            }:
                raise ExtensionActivationError("extension data registry entry is not exact")
            record = ExtensionDataRecord.from_dict(entry["record"])
            if (
                (record.kind, record.identity_id) != (entry["kind"], entry["id"])
                or record.record_digest != entry["record_digest"]
            ):
                raise ExtensionActivationError("extension data registry entry binding is invalid")
            identities.append((record.kind, record.identity_id))
            digests.add(record.record_digest)
        if identities != sorted(set(identities)) or set(order) != digests or len(order) != len(digests):
            raise ExtensionActivationError("extension data registry resolution is invalid")
        previous = actual
        result.append(value)
    return tuple(result)


def _load_activation_manifests(
    connection: sqlite3.Connection,
    maximum: int,
) -> tuple[Mapping[str, object], ...]:
    rows = connection.execute(
        "SELECT generation,transition_id,manifest_digest,manifest_json "
        "FROM extension_activation_manifests ORDER BY generation"
    ).fetchall()
    if len(rows) > maximum:
        raise ExtensionActivationError("extension activation manifest chain exceeds bound")
    result: list[Mapping[str, object]] = []
    previous: str | None = None
    for expected, (generation, transition_id, stored_digest, encoded) in enumerate(rows, 1):
        value = parse_canonical_json(str(encoded))
        manifest = ExtensionActivationManifest.from_dict(value)
        body = manifest.to_dict()
        if (
            generation != expected
            or body["generation"] != expected
            or body["transition_id"] != transition_id
            or body["previous_manifest_digest"] != previous
            or body["manifest_digest"] != stored_digest
        ):
            raise ExtensionActivationError("extension activation manifest chain is invalid")
        previous = str(body["manifest_digest"])
        result.append(body)
    return tuple(result)


def _load_active_pointer(connection: sqlite3.Connection) -> Mapping[str, object] | None:
    rows = connection.execute(
        "SELECT generation,manifest_digest,pointer_digest,pointer_json "
        "FROM extension_active_set_pointer WHERE singleton=1"
    ).fetchall()
    if not rows:
        return None
    if len(rows) != 1:
        raise ExtensionActivationError("extension active-set pointer is duplicated")
    generation, manifest_digest, pointer_digest, encoded = rows[0]
    pointer = ExtensionActiveSetPointer.from_dict(parse_canonical_json(str(encoded))).to_dict()
    if (
        pointer["generation"] != generation
        or pointer["manifest_digest"] != manifest_digest
        or pointer["pointer_digest"] != pointer_digest
    ):
        raise ExtensionActivationError("extension active-set pointer binding is invalid")
    return pointer


def _pointer_document(
    manifest: Mapping[str, object],
    previous_pointer_digest: str | None,
) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "generation": manifest["generation"],
        "manifest_digest": manifest["manifest_digest"],
        "previous_pointer_digest": previous_pointer_digest,
        "transition_id": manifest["transition_id"],
        "updated_at": manifest["activated_at"],
    }
    return {**body, "pointer_digest": _record_digest(body, "extension-active-set-pointer")}


class ExtensionActivationRepository:
    """Installation-scoped local data activation; never loads executable bytes."""

    __slots__ = (
        "_trust", "_installer", "_policy", "_builtins", "_invariants",
        "_resource_binding_digest", "_fault",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension activation repositories are factory-issued")

    @classmethod
    def create(
        cls,
        trust: ExtensionTrustRepository,
        installer: ExtensionBundleInstaller,
        *,
        policy_document: object,
        built_in_registry_document: object,
        core_invariant_document: object,
        fault_hook: Callable[[str], None] = _no_fault,
    ) -> ExtensionActivationRepository:
        if (
            type(trust) is not ExtensionTrustRepository
            or ExtensionBundleInstaller.require_attested(installer) is not installer
            or installer._repository is not trust
            or not callable(fault_hook)
        ):
            raise TypeError("extension activation trust authority is invalid")
        result = object.__new__(cls)
        result._trust = trust
        result._installer = installer
        result._policy = ExtensionActivationPolicy.from_dict(policy_document)
        result._builtins = ExtensionBuiltInRegistry.from_dict(built_in_registry_document)
        result._invariants = ExtensionCoreInvariantSet.from_dict(core_invariant_document)
        result._fault = fault_hook
        result._resource_binding_digest = activation_resource_binding_digest(
            result._policy, result._builtins, result._invariants
        )
        token = trust._manager._control_lock.acquire("exclusive")
        try:
            connection = trust._connect()
            try:
                connection.executescript(_INGEST_SCHEMA + _SCHEMA)
                manifest = trust._manager._current_manifest()
                current = trust._load(
                    connection, expected_installation_id=manifest.installation_id
                )
                if (
                    current.policy.to_dict()["resource_policy_digest"]
                    != result._resource_binding_digest
                ):
                    raise ExtensionActivationError(
                        "extension activation resources are not installation-authorized"
                    )
                result._snapshot(connection)
                result._verify_materialized_registry(connection)
            finally:
                connection.close()
        finally:
            trust._manager._control_lock.release(token)
        _ISSUED[id(result)] = result
        return result

    @classmethod
    def require_attested(cls, value: object) -> ExtensionActivationRepository:
        if type(value) is not cls or _ISSUED.get(id(value)) is not value:
            raise TypeError("extension activation repository is not factory-issued")
        return value

    @staticmethod
    def fault_schedule() -> tuple[str, ...]:
        return (
            "extension-activation.after-data-registry",
            "extension-activation.after-manifest",
            "extension-activation.after-pointer-cas",
            "extension-activation.after-commit",
        )

    @staticmethod
    def post_publish_fault_schedule() -> tuple[str, ...]:
        return (
            "extension-activation.after-publish-durability",
            "extension-activation.before-restoration-publication",
            "extension-activation.after-restoration-durability",
            "extension-activation.after-restoration-reread",
        )

    @staticmethod
    def task_pin_policy() -> dict[str, object]:
        return {
            "preserve": (
                "unrelated-activation", "side-by-side-update", "key-addition",
                "capability-ceiling-expansion",
            ),
            "block": (
                "matching-key-tightening", "matching-production-policy-tightening",
                "matching-source-tightening", "matching-namespace-tightening",
                "matching-kind-tightening", "matching-revocation",
                "capability-ceiling-contraction", "resource-policy-change",
                "compatibility-floor",
            ),
            "upgrade": "explicit-owner-rebase-new-generation",
        }

    @staticmethod
    def _runtime_bound(body: Mapping[str, object], runtime: RuntimeContext) -> None:
        runtime.require_issued()
        if (
            body.get("owner_id") != runtime.owner_id
            or body.get("runtime_kind") != runtime.runtime_kind
            or body.get("runtime_lineage_id") != runtime.runtime_lineage_id
        ):
            raise ExtensionActivationError("extension management is unavailable")

    def _snapshot(self, connection: sqlite3.Connection) -> ExtensionActivationSnapshot:
        registries = _load_data_registries(
            connection, self._policy.maximum_activations
        )
        manifests = _load_activation_manifests(
            connection, self._policy.maximum_activations
        )
        pointer = _load_active_pointer(connection)
        if len(registries) != len(manifests):
            raise ExtensionActivationError("extension activation manifest has orphan state")
        previous_pointer: str | None = None
        expected_pointer: Mapping[str, object] | None = None
        installation_id = self._trust._manager._current_manifest().installation_id
        for registry, manifest in zip(registries, manifests, strict=True):
            if (
                registry["generation"] != manifest["generation"]
                or registry["activation_id"] != manifest["transition_id"]
                or registry["registry_digest"] != manifest["data_registry_digest"]
                or manifest["installation_id"] != installation_id
            ):
                raise ExtensionActivationError("extension activation manifest registry binding is invalid")
            expected_pointer = _pointer_document(manifest, previous_pointer)
            previous_pointer = str(expected_pointer["pointer_digest"])
        if (
            (not manifests and pointer is not None)
            or (manifests and pointer != expected_pointer)
        ):
            raise ExtensionActivationError("extension active-set pointer is stale or invalid")
        return ExtensionActivationSnapshot(
            _load_chain(connection, "extension_activation_ledger", self._policy.maximum_activations),
            _load_chain(connection, "extension_task_pins", self._policy.maximum_task_pins),
            _load_chain(connection, "extension_diagnostics", self._policy.maximum_diagnostics),
            None if not registries else registries[-1],
            manifests,
            None if not manifests else manifests[-1],
            pointer,
        )

    @staticmethod
    def _receipt_from_ingest(ingest: Mapping[str, object]) -> ExtensionIngestReceipt:
        return ExtensionIngestReceipt(
            str(ingest["ingest_id"]), str(ingest["request_digest"]),
            int(ingest["record_sequence"]), str(ingest["archive_raw_digest"]),
            str(ingest["manifest_digest"]), str(ingest["package_identity_digest"]),
            str(ingest["trust_policy_digest"]), str(ingest["trust_head_digest"]),
            str(ingest["content_root_ref"]), str(ingest["content_root_digest"]),
            str(ingest["record_digest"]),
        )

    def _decode_records(
        self,
        ingest: Mapping[str, object],
        package: Mapping[str, object],
    ) -> tuple[ExtensionDataRecord, ...]:
        members = self._installer._load_installed_members_under_lock(
            self._receipt_from_ingest(ingest)
        )
        records: list[ExtensionDataRecord] = []
        for name, encoded in members.items():
            if not name.startswith("payload/data/"):
                continue
            try:
                document = parse_canonical_json(encoded.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as error:
                raise ExtensionActivationError("E_EXTENSION_DATA_RECORD") from error
            if canonical_json(document).encode() != encoded:
                raise ExtensionActivationError("E_EXTENSION_DATA_RECORD")
            try:
                record = ExtensionDataRecord.from_dict(document)
            except ExtensionDataError as error:
                code = (
                    "E_EXTENSION_CORE_INVARIANT"
                    if "security" in str(error) or "invariant" in str(error)
                    else "E_EXTENSION_DATA_RECORD"
                )
                raise ExtensionActivationError(code) from error
            expected_name = (
                "payload/data/"
                + record.record_digest.removeprefix("sha256-jcs-v1:")
                + ".json"
            )
            if name != expected_name:
                raise ExtensionActivationError("E_EXTENSION_DATA_RECORD")
            records.append(record)
        records.sort(key=lambda item: (item.kind, item.identity_id))
        declared = {
            (str(item["kind"]), str(item["id"])): str(item["contract_digest"])
            for item in package["extension_points"]
        }
        observed = {
            (item.kind, item.identity_id): item.record_digest for item in records
        }
        if len(declared) != len(package["extension_points"]) or observed != declared:
            raise ExtensionActivationError("E_EXTENSION_DATA_RECORD")
        for record in records:
            body = record.to_dict()
            if (
                body["core_invariant_set_digest"] != self._invariants.invariant_set_digest
                or body["security_effect"] not in self._invariants.allowed_security_effects
                or (
                    record.kind == "policy"
                    and body["body"]["policy_effect"] != "constrain-only"  # type: ignore[index]
                )
                or (record.kind, record.identity_id) in self._builtins.protected_identities
            ):
                raise ExtensionActivationError("E_EXTENSION_CORE_INVARIANT")
        return tuple(records)

    def _verify_materialized_registry(self, connection: sqlite3.Connection) -> None:
        registries = _load_data_registries(
            connection, self._policy.maximum_activations
        )
        if not registries:
            return
        activations = _load_chain(
            connection, "extension_activation_ledger", self._policy.maximum_activations
        )
        by_activation = {str(item["activation_id"]): item for item in activations}
        manifests = _load_activation_manifests(
            connection, self._policy.maximum_activations
        )
        for registry, manifest in zip(registries, manifests, strict=True):
            if manifest["transition_kind"] in {"activate", "supersede"}:
                activation = by_activation.get(str(registry["activation_id"]))
                if (
                    activation is None
                    or activation["data_registry_digest"] != registry["registry_digest"]
                    or activation["core_invariant_set_digest"]
                    != registry["core_invariant_set_digest"]
                ):
                    raise ExtensionActivationError(
                        "extension data registry activation binding drifted"
                    )
        latest = registries[-1]
        if latest["core_invariant_set_digest"] != self._invariants.invariant_set_digest:
            raise ExtensionActivationError("extension data registry invariant binding drifted")
        entries = latest["entries"]
        if not isinstance(entries, list) or latest["resolution_order"] != self._resolution_order(entries):
            raise ExtensionActivationError("extension data registry resolution drifted")
        ingests = _ingest_records(connection, self._trust._policy.max_ledger_records)
        by_digest = {str(item["record_digest"]): item for item in ingests}
        grouped: dict[str, list[Mapping[str, object]]] = {}
        for entry in latest["entries"]:  # type: ignore[index]
            assert isinstance(entry, Mapping)
            grouped.setdefault(str(entry["ingest_record_digest"]), []).append(entry)
        for digest, group_entries in grouped.items():
            ingest = by_digest.get(digest)
            if ingest is None:
                raise ExtensionActivationError("extension data registry ingest is missing")
            row = connection.execute(
                "SELECT manifest_json FROM extension_ingest_packages WHERE ingest_id=?",
                (ingest["ingest_id"],),
            ).fetchone()
            if row is None:
                raise ExtensionActivationError("extension data registry manifest is missing")
            package = parse_canonical_json(str(row[0]))
            if not isinstance(package, Mapping):
                raise ExtensionActivationError("extension data registry manifest is invalid")
            decoded = self._decode_records(ingest, package)
            expected = {
                (str(entry["kind"]), str(entry["id"])): entry["record"]
                for entry in group_entries
            }
            actual = {(item.kind, item.identity_id): item.to_dict() for item in decoded}
            if actual != expected:
                raise ExtensionActivationError("extension data registry bytes drifted")
        active_manifest = manifests[-1]
        active_packages = active_manifest["active_packages"]
        assert isinstance(active_packages, list)
        entries_by_extension: dict[str, list[Mapping[str, object]]] = {}
        for entry in entries:
            assert isinstance(entry, Mapping)
            entries_by_extension.setdefault(str(entry["extension_id"]), []).append(entry)
        if set(entries_by_extension) != {
            str(item["extension_id"]) for item in active_packages
        }:
            raise ExtensionActivationError("extension active package registry binding drifted")
        by_ingest_digest = {
            str(item["record_digest"]): item for item in ingests
        }
        for package_binding in active_packages:
            activation = next(
                (
                    item
                    for item in activations
                    if item["record_digest"]
                    == package_binding["activation_record_digest"]
                ),
                None,
            )
            ingest = by_ingest_digest.get(str(package_binding["ingest_record_digest"]))
            if (
                activation is None
                or ingest is None
                or activation["extension_id"] != package_binding["extension_id"]
                or activation["extension_version"] != package_binding["extension_version"]
                or activation["package_identity_digest"]
                != package_binding["package_identity_digest"]
                or activation["manifest_digest"]
                != package_binding["package_manifest_digest"]
                or ingest["content_root_ref"] != package_binding["content_root_ref"]
                or ingest["content_root_digest"] != package_binding["content_root_digest"]
                or any(
                    entry["ingest_record_digest"] != ingest["record_digest"]
                    or entry["content_root_ref"] != ingest["content_root_ref"]
                    or entry["content_root_digest"] != ingest["content_root_digest"]
                    for entry in entries_by_extension[str(package_binding["extension_id"])]
                )
            ):
                raise ExtensionActivationError("extension active package binding drifted")

    @staticmethod
    def _require_active_cas(
        body: Mapping[str, object], snapshot: ExtensionActivationSnapshot
    ) -> None:
        manifest = snapshot.active_manifest
        generation = 0 if manifest is None else manifest["generation"]
        digest = None if manifest is None else manifest["manifest_digest"]
        if (
            body.get("expected_active_generation") != generation
            or body.get("expected_active_manifest_digest") != digest
        ):
            raise ExtensionActivationError("extension active-set CAS is stale")

    @staticmethod
    def _active_package(
        activation: Mapping[str, object],
        ingest: Mapping[str, object],
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "extension_id": activation["extension_id"],
            "extension_version": activation["extension_version"],
            "activation_record_digest": activation["record_digest"],
            "ingest_record_digest": activation["ingest_record_digest"],
            "package_identity_digest": activation["package_identity_digest"],
            "package_manifest_digest": activation["manifest_digest"],
            "content_root_ref": ingest["content_root_ref"],
            "content_root_digest": ingest["content_root_digest"],
        }
        return {
            **body,
            "package_binding_digest": _record_digest(
                body, "extension-active-package-binding"
            ),
        }

    def _write_manifest_and_pointer(
        self,
        connection: sqlite3.Connection,
        *,
        transition_id: str,
        transition_kind: str,
        installation_id: str,
        trust: ExtensionTrustSnapshot,
        registry_digest: str,
        active_packages: list[Mapping[str, object]],
        tombstones: list[Mapping[str, object]],
        owner_decision_digest: object,
        owner_authority_digest: object,
        activated_at: str,
    ) -> ExtensionActiveSetReceipt:
        histories = _load_activation_manifests(
            connection, self._policy.maximum_activations
        )
        previous = None if not histories else histories[-1]
        active_packages.sort(key=lambda item: canonical_bytes(item["extension_id"]))
        tombstones.sort(key=canonical_bytes)
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "generation": len(histories) + 1,
            "previous_manifest_digest": (
                None if previous is None else previous["manifest_digest"]
            ),
            "transition_id": transition_id,
            "transition_kind": transition_kind,
            "installation_id": installation_id,
            "trust_policy_digest": trust.policy.policy_digest,
            "trust_head_digest": trust.head.head_digest,
            "revocation_high_water": trust.policy.revocation_high_water,
            "data_registry_digest": registry_digest,
            "active_packages": active_packages,
            "tombstones": tombstones,
            "owner_decision_digest": owner_decision_digest,
            "owner_authority_digest": owner_authority_digest,
            "activated_at": activated_at,
        }
        digest = _record_digest(body, "extension-activation-manifest")
        manifest = ExtensionActivationManifest.from_dict(
            {**body, "manifest_digest": digest}
        ).to_dict()
        connection.execute(
            "INSERT INTO extension_activation_manifests"
            "(generation,transition_id,manifest_digest,manifest_json) VALUES(?,?,?,?)",
            (
                body["generation"], transition_id, digest,
                canonical_json(manifest),
            ),
        )
        self._fault("extension-activation.after-manifest")
        previous_pointer = _load_active_pointer(connection)
        pointer = _pointer_document(
            manifest,
            None if previous_pointer is None else str(previous_pointer["pointer_digest"]),
        )
        ExtensionActiveSetPointer.from_dict(pointer)
        if previous_pointer is None:
            connection.execute(
                "INSERT INTO extension_active_set_pointer"
                "(singleton,generation,manifest_digest,pointer_digest,pointer_json) "
                "VALUES(1,?,?,?,?)",
                (
                    pointer["generation"], pointer["manifest_digest"],
                    pointer["pointer_digest"], canonical_json(pointer),
                ),
            )
        else:
            cursor = connection.execute(
                "UPDATE extension_active_set_pointer SET generation=?,manifest_digest=?,"
                "pointer_digest=?,pointer_json=? WHERE singleton=1 AND generation=? "
                "AND manifest_digest=? AND pointer_digest=?",
                (
                    pointer["generation"], pointer["manifest_digest"],
                    pointer["pointer_digest"], canonical_json(pointer),
                    previous_pointer["generation"], previous_pointer["manifest_digest"],
                    previous_pointer["pointer_digest"],
                ),
            )
            if cursor.rowcount != 1:
                raise ExtensionActivationError("extension active-set pointer CAS failed")
        self._fault("extension-activation.after-pointer-cas")
        return ExtensionActiveSetReceipt(
            int(pointer["generation"]), transition_kind, digest,
            str(pointer["pointer_digest"]),
        )

    def _restore_published_active_set(
        self,
        connection: sqlite3.Connection,
        *,
        previous: ExtensionActivationSnapshot,
        failed_receipt: ExtensionActiveSetReceipt,
        installation_id: str,
        trust: ExtensionTrustSnapshot,
        owner_decision_digest: object,
        owner_authority_digest: object,
        activated_at: str,
    ) -> ExtensionActiveSetReceipt:
        current = self._snapshot(connection)
        if (
            current.active_manifest is None
            or current.active_manifest["manifest_digest"] != failed_receipt.manifest_digest
        ):
            raise ExtensionActivationError(
                "extension post-publish restoration base is divergent"
            )
        registries = _load_data_registries(
            connection, self._policy.maximum_activations
        )
        published_registry = registries[-1]
        old_registry = previous.data_registry
        transition_id = (
            f"{current.active_manifest['transition_id']}.postverify-restore"
        )
        registry_body: dict[str, object] = {
            "schema_version": "1.0.0",
            "generation": len(registries) + 1,
            "previous_registry_digest": published_registry["registry_digest"],
            "activation_id": transition_id,
            "extension_id": published_registry["extension_id"],
            "package_identity_digest": published_registry["package_identity_digest"],
            "content_root_ref": published_registry["content_root_ref"],
            "content_root_digest": published_registry["content_root_digest"],
            "core_invariant_set_digest": self._invariants.invariant_set_digest,
            "entries": [] if old_registry is None else old_registry["entries"],
            "resolution_order": (
                [] if old_registry is None else old_registry["resolution_order"]
            ),
        }
        registry_digest = _record_digest(
            registry_body, "extension-data-registry"
        )
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "INSERT INTO extension_data_registries"
                "(generation,activation_id,registry_digest,registry_json) VALUES(?,?,?,?)",
                (
                    registry_body["generation"],
                    transition_id,
                    registry_digest,
                    canonical_json({**registry_body, "registry_digest": registry_digest}),
                ),
            )
            receipt = self._write_manifest_and_pointer(
                connection,
                transition_id=transition_id,
                transition_kind="rollback",
                installation_id=installation_id,
                trust=trust,
                registry_digest=registry_digest,
                active_packages=(
                    []
                    if previous.active_manifest is None
                    else list(previous.active_manifest["active_packages"])
                ),
                tombstones=(
                    []
                    if previous.active_manifest is None
                    else list(previous.active_manifest["tombstones"])
                ),
                owner_decision_digest=owner_decision_digest,
                owner_authority_digest=owner_authority_digest,
                activated_at=activated_at,
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        self._fault("extension-activation.after-restoration-durability")
        restored = self._snapshot(connection)
        self._verify_materialized_registry(connection)
        expected_packages = (
            []
            if previous.active_manifest is None
            else previous.active_manifest["active_packages"]
        )
        if (
            restored.active_manifest is None
            or restored.active_manifest["active_packages"] != expected_packages
        ):
            raise ExtensionActivationError(
                "extension post-publish restoration is incomplete"
            )
        self._fault("extension-activation.after-restoration-reread")
        return receipt

    def _post_publish_verify_or_restore(
        self,
        connection: sqlite3.Connection,
        *,
        previous: ExtensionActivationSnapshot,
        receipt: ExtensionActiveSetReceipt,
        installation_id: str,
        trust: ExtensionTrustSnapshot,
        owner_decision_digest: object,
        owner_authority_digest: object,
        activated_at: str,
    ) -> ExtensionActivationSnapshot:
        fault: BaseException | None = None
        observed: ExtensionActivationSnapshot | None = None
        try:
            self._fault("extension-activation.after-publish-durability")
            observed = self._snapshot(connection)
            self._verify_materialized_registry(connection)
            if (
                observed.active_manifest is None
                or observed.active_manifest["manifest_digest"] != receipt.manifest_digest
                or observed.active_pointer is None
                or observed.active_pointer["pointer_digest"] != receipt.pointer_digest
            ):
                raise ExtensionActivationError(
                    "extension post-publish doctor binding failed"
                )
        except BaseException as error:
            fault = error
        if fault is not None:
            self._fault("extension-activation.before-restoration-publication")
            self._restore_published_active_set(
                connection,
                previous=previous,
                failed_receipt=receipt,
                installation_id=installation_id,
                trust=trust,
                owner_decision_digest=owner_decision_digest,
                owner_authority_digest=owner_authority_digest,
                activated_at=activated_at,
            )
            raise fault
        assert observed is not None
        return observed

    def _resolution_order(self, entries: list[object]) -> list[str]:
        by_identity: dict[tuple[str, str], Mapping[str, object]] = {}
        for item in entries:
            if not isinstance(item, Mapping):
                raise ExtensionActivationError("extension data registry entry is invalid")
            identity = (str(item["kind"]), str(item["id"]))
            if identity in by_identity:
                raise ExtensionActivationError("E_EXTENSION_REGISTRY_CONFLICT")
            by_identity[identity] = item
        indegree = {identity: 0 for identity in by_identity}
        consumers: dict[tuple[str, str], set[tuple[str, str]]] = {
            identity: set() for identity in by_identity
        }
        for identity, entry in by_identity.items():
            record = ExtensionDataRecord.from_dict(entry["record"])
            if record.kind == "edge":
                document = record.to_dict()
                edge_body = document["body"]
                assert isinstance(edge_body, Mapping)
                expected_dependencies = tuple(sorted({
                    ("node", str(edge_body["source_id"])),
                    ("node", str(edge_body["target_id"])),
                }))
                if record.dependencies != expected_dependencies:
                    raise ExtensionActivationError("E_EXTENSION_DEPENDENCY")
            for dependency in record.dependencies:
                if dependency in self._builtins.protected_identities:
                    continue
                if dependency not in by_identity:
                    raise ExtensionActivationError("E_EXTENSION_DEPENDENCY")
                indegree[identity] += 1
                consumers[dependency].add(identity)
        ready = sorted(identity for identity, degree in indegree.items() if degree == 0)
        order: list[str] = []
        while ready:
            identity = ready.pop(0)
            order.append(str(by_identity[identity]["record_digest"]))
            for consumer in sorted(consumers[identity]):
                indegree[consumer] -= 1
                if indegree[consumer] == 0:
                    ready.append(consumer)
                    ready.sort()
        if len(order) != len(entries):
            raise ExtensionActivationError("E_EXTENSION_DEPENDENCY")
        return order

    def _candidate_data_registry(
        self,
        connection: sqlite3.Connection,
        *,
        activation_id: str,
        ingest: Mapping[str, object],
        package: Mapping[str, object],
        records: tuple[ExtensionDataRecord, ...],
        replace_extension: bool,
    ) -> tuple[dict[str, object], str]:
        histories = _load_data_registries(
            connection, self._policy.maximum_activations
        )
        previous = None if not histories else histories[-1]
        existing = [] if previous is None else list(previous["entries"])
        if replace_extension:
            existing = [
                item for item in existing if item["extension_id"] != package["extension_id"]
            ]
        additions = [
            {
                "kind": record.kind,
                "id": record.identity_id,
                "record_digest": record.record_digest,
                "record": record.to_dict(),
                "extension_id": package["extension_id"],
                "extension_version": package["extension_version"],
                "package_identity_digest": package["package_identity_digest"],
                "ingest_record_digest": ingest["record_digest"],
                "content_root_ref": ingest["content_root_ref"],
                "content_root_digest": ingest["content_root_digest"],
            }
            for record in records
        ]
        entries = [*existing, *additions]
        entries.sort(key=lambda item: (item["kind"], item["id"]))
        identities = [(str(item["kind"]), str(item["id"])) for item in entries]
        if identities != sorted(set(identities)) or any(
            identity in self._builtins.protected_identities for identity in identities
        ):
            raise ExtensionActivationError("E_EXTENSION_REGISTRY_CONFLICT")
        order = self._resolution_order(entries)
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "generation": len(histories) + 1,
            "previous_registry_digest": None if previous is None else previous["registry_digest"],
            "activation_id": activation_id,
            "extension_id": package["extension_id"],
            "package_identity_digest": package["package_identity_digest"],
            "content_root_ref": ingest["content_root_ref"],
            "content_root_digest": ingest["content_root_digest"],
            "core_invariant_set_digest": self._invariants.invariant_set_digest,
            "entries": entries,
            "resolution_order": order,
        }
        digest = _record_digest(body, "extension-data-registry")
        return body, digest

    def snapshot(self) -> ExtensionActivationSnapshot:
        self.require_attested(self)
        token = self._trust._manager._control_lock.acquire("exclusive")
        try:
            connection = self._trust._connect()
            try:
                return self._snapshot(connection)
            finally:
                connection.close()
        finally:
            self._trust._manager._control_lock.release(token)


    @property
    def capability_profile_digest(self) -> str:
        return _record_digest(
            {
                "schema_version": "1.0.0",
                "activation_policy_digest": self._policy.policy_digest,
                "available_capabilities": list(self._policy.available_capabilities),
            },
            "extension-capability-profile",
        )

    def doctor(self) -> ExtensionActivationSnapshot:
        self.require_attested(self)
        token = self._trust._manager._control_lock.acquire("exclusive")
        try:
            connection = self._trust._connect()
            try:
                connection.executescript(_INGEST_SCHEMA + _SCHEMA)
                snapshot = self._snapshot(connection)
                self._verify_materialized_registry(connection)
                return snapshot
            finally:
                connection.close()
        finally:
            self._trust._manager._control_lock.release(token)

    def _diagnostic(
        self,
        connection: sqlite3.Connection,
        *,
        code: str,
        subject_digest: str,
        observed_at: str,
    ) -> None:
        records = _load_chain(
            connection, "extension_diagnostics", self._policy.maximum_diagnostics
        )
        sequence = len(records) + 1
        previous = None if not records else records[-1]["record_digest"]
        body: dict[str, object] = {
            "schema_version": "1.0.0", "record_sequence": sequence,
            "previous_record_digest": previous,
            "diagnostic_id": f"extension-diagnostic.{sequence}", "code": code,
            "subject_digest": subject_digest, "observed_at": observed_at,
        }
        digest = _record_digest(body, "extension-diagnostic-record")
        connection.execute(
            "INSERT INTO extension_diagnostics"
            "(record_sequence,diagnostic_id,code,record_digest,record_json) VALUES(?,?,?,?,?)",
            (sequence, body["diagnostic_id"], code, digest, canonical_json({**body, "record_digest": digest})),
        )

    def _trust_snapshot(self, connection: sqlite3.Connection, installation_id: object):
        manifest = self._trust._manager._current_manifest()
        if installation_id != manifest.installation_id:
            raise ExtensionActivationError("extension installation binding mismatch")
        return self._trust._load(connection, expected_installation_id=manifest.installation_id)

    @staticmethod
    def _require_trust(body: Mapping[str, object], snapshot: object) -> None:
        if (
            body.get("expected_trust_head_digest") != snapshot.head.head_digest
            or body.get("expected_trust_policy_digest") != snapshot.policy.policy_digest
            or body.get("expected_revocation_high_water") != snapshot.policy.revocation_high_water
        ):
            raise ExtensionActivationError("extension trust tuple is stale")

    def _current_eligibility_code(
        self,
        connection: sqlite3.Connection,
        *,
        trust: ExtensionTrustSnapshot,
        ingest: Mapping[str, object],
        package: Mapping[str, object],
        observed_at: str,
        activation: Mapping[str, object] | None,
    ) -> str | None:
        """Re-evaluate one immutable installed package against current authority."""

        try:
            manifest = ExtensionPackageManifest.from_dict(package)
        except (TypeError, ValueError):
            return "E_EXTENSION_CURRENT_TRUST"
        if (
            manifest.package_identity_digest != ingest.get("package_identity_digest")
            or package.get("manifest_digest") != ingest.get("manifest_digest")
            or package.get("source_attestation_digest")
            != ingest.get("source_attestation_digest")
            or package.get("build_attestation_digest")
            != ingest.get("build_attestation_digest")
            or ingest.get("activation_status")
            != "data-only-installed-executable-denied"
        ):
            return "E_EXTENSION_CURRENT_TRUST"

        subjects = {
            str(ingest.get("record_digest")),
            str(ingest.get("package_identity_digest")),
            str(ingest.get("manifest_digest")),
            str(ingest.get("source_attestation_digest")),
            str(ingest.get("build_attestation_digest")),
            str(ingest.get("publisher_signature_digest")),
            str(ingest.get("production_policy_digest")),
        }
        if activation is not None:
            subjects.add(str(activation.get("record_digest")))
        revoked = {
            str(item["target_identity_digest"])
            for item in trust.policy.to_dict()["revocations"]
        }
        if subjects & revoked:
            return "E_EXTENSION_REVOKED"

        identities = [
            (str(item["kind"]), str(item["id"]))
            for field in ("extension_points", "exported_identities")
            for item in package[field]
        ]
        identities.extend(
            ("schema", str(item))
            for field in ("input_schema_ids", "output_schema_ids")
            for item in package[field]
        )
        categories = {
            str(item["kind"]) for item in package["extension_points"]
        }
        if package["package_class"] != "data-only" or package["executable_contract"] is not None:
            return "E_EXTENSION_EXECUTABLE_CONTRACT_GATE"
        if not categories or not categories.issubset(self._policy.allowed_data_categories):
            return "E_EXTENSION_DATA_CATEGORY"
        if any(identity in self._builtins.protected_identities for identity in identities):
            return "E_EXTENSION_BUILTIN_IDENTITY"
        if any(
            package["compatibility"][field] not in accepted
            for field, accepted in self._policy.accepted_compatibility.items()
        ):
            return "E_EXTENSION_COMPATIBILITY"
        requested = {
            str(item["capability_id"])
            for item in package["requested_capabilities"]
        }
        if not requested.issubset(self._policy.available_capabilities):
            return "E_EXTENSION_CAPABILITY_INTERSECTION"
        if trust.policy.to_dict()["resource_policy_digest"] != self._resource_binding_digest:
            return "E_EXTENSION_CURRENT_TRUST"
        if activation is not None and (
            activation.get("ingest_record_digest") != ingest.get("record_digest")
            or activation.get("package_identity_digest")
            != ingest.get("package_identity_digest")
            or activation.get("manifest_digest") != ingest.get("manifest_digest")
            or activation.get("archive_raw_digest") != ingest.get("archive_raw_digest")
            or activation.get("activation_policy_digest") != self._policy.policy_digest
            or activation.get("built_in_registry_digest") != self._builtins.registry_digest
            or activation.get("core_invariant_set_digest")
            != self._invariants.invariant_set_digest
            or activation.get("activation_resource_binding_digest")
            != self._resource_binding_digest
            or activation.get("local_status") != self._policy.local_activation_status
            or activation.get("formal_release_status") != self._policy.formal_release_status
            or activation.get("executable_status") != self._policy.executable_status
        ):
            return "E_EXTENSION_CURRENT_TRUST"

        try:
            members = self._installer._load_installed_members_under_lock(
                self._receipt_from_ingest(ingest)
            )
            source = parse_canonical_json(
                members["META-INF/source-attestation.json"].decode("utf-8")
            )
            if not isinstance(source, Mapping):
                return "E_EXTENSION_CURRENT_TRUST"
            production_policy = self._trust._production_policy(
                connection,
                policy_id=str(source["production_policy_id"]),
                policy_digest=str(source["production_policy_digest"]),
            )
            data_mode = self._installer._reader._policy.data_member_mode
            verified = verify_extension_bundle(
                BoundedExtensionBundle(
                    str(ingest["archive_raw_digest"]),
                    members,
                    {name: data_mode for name in members},
                ),
                trust.policy,
                self._installer._verifier,
                verified_at=observed_at,
                production_policy=production_policy,
            )
        except ExtensionBundleError as error:
            if "E_EXTENSION_REVOKED" in str(error):
                return "E_EXTENSION_REVOKED"
            if "E_EXTENSION_EXECUTABLE_CONTRACT_GATE" in str(error):
                return "E_EXTENSION_EXECUTABLE_CONTRACT_GATE"
            return "E_EXTENSION_CURRENT_TRUST"
        except Exception:
            return "E_EXTENSION_CURRENT_TRUST"
        if (
            verified.archive_raw_digest != ingest.get("archive_raw_digest")
            or verified.manifest.to_dict() != dict(package)
            or verified.manifest.package_identity_digest
            != ingest.get("package_identity_digest")
            or verified.source_attestation.attestation_digest
            != ingest.get("source_attestation_digest")
            or verified.build_attestation.attestation_digest
            != ingest.get("build_attestation_digest")
            or verified.publisher_signature.signature_record_digest
            != ingest.get("publisher_signature_digest")
            or production_policy.policy_digest != ingest.get("production_policy_digest")
            or verified.trust_policy_digest != trust.policy.policy_digest
        ):
            return "E_EXTENSION_CURRENT_TRUST"
        return None

    def activate(
        self,
        request: ExtensionActivationRequest,
        runtime: RuntimeContext,
    ) -> ExtensionActivationReceipt:
        self.require_attested(self)
        if type(request) is not ExtensionActivationRequest or type(runtime) is not RuntimeContext:
            raise TypeError("extension activation inputs are invalid")
        body = request.to_dict()
        self._runtime_bound(body, runtime)
        high_water = body.get("expected_revocation_high_water")
        if type(high_water) is not int or high_water < 0:
            raise ExtensionActivationError("extension activation high-water is invalid")
        token = self._trust._manager._control_lock.acquire("exclusive")
        try:
            connection = self._trust._connect()
            try:
                connection.executescript(_INGEST_SCHEMA + _SCHEMA)
                connection.execute("BEGIN IMMEDIATE")
                try:
                    trust = self._trust_snapshot(connection, body.get("installation_id"))
                    self._require_trust(body, trust)
                    active_snapshot = self._snapshot(connection)
                    self._require_active_cas(body, active_snapshot)
                    ingests = _ingest_records(connection, self._trust._policy.max_ledger_records)
                    matches = [item for item in ingests if item["record_digest"] == body["ingest_record_digest"]]
                    if len(matches) != 1:
                        raise ExtensionActivationError("extension ingest record is missing")
                    ingest = matches[0]
                    row = connection.execute(
                        "SELECT record_digest,manifest_json,content_root_ref,content_root_digest "
                        "FROM extension_ingest_packages WHERE ingest_id=?",
                        (ingest["ingest_id"],),
                    ).fetchone()
                    if (
                        row is None
                        or row[0] != ingest["record_digest"]
                        or row[2] != ingest["content_root_ref"]
                        or row[3] != ingest["content_root_digest"]
                    ):
                        raise ExtensionActivationError("extension ingest package binding is missing")
                    document = parse_canonical_json(str(row[1]))
                    if not isinstance(document, Mapping):
                        raise ExtensionActivationError("extension package manifest is invalid")
                    manifest = ExtensionPackageManifest.from_dict(document)
                    package = manifest.to_dict()
                    categories = tuple(sorted({str(item["kind"]) for item in package["extension_points"]}))
                    code = self._current_eligibility_code(
                        connection,
                        trust=trust,
                        ingest=ingest,
                        package=package,
                        observed_at=runtime.occurred_at,
                        activation=None,
                    )
                    activations = _load_chain(
                        connection, "extension_activation_ledger", self._policy.maximum_activations
                    )
                    conflicts = [
                        item for item in activations
                        if item["extension_id"] == package["extension_id"]
                        and item["package_identity_digest"] != manifest.package_identity_digest
                    ]
                    if code is None and conflicts:
                        override_body = {
                            "schema_version": "1.0.0",
                            "activation_id": body["activation_id"],
                            "candidate_ingest_record_digest": ingest["record_digest"],
                            "existing_activation_record_digests": sorted(
                                str(item["record_digest"]) for item in conflicts
                            ),
                            "owner_decision_digest": body["owner_decision_digest"],
                        }
                        expected_override = _record_digest(override_body, "extension-conflict-override")
                        if body.get("conflict_override_digest") != expected_override:
                            code = "E_EXTENSION_UPDATE_CONFLICT"
                    if code is not None:
                        self._diagnostic(
                            connection, code=code, subject_digest=request.request_digest,
                            observed_at=runtime.occurred_at,
                        )
                        connection.commit()
                        raise ExtensionActivationError(code)
                    records = self._decode_records(ingest, package)
                    registry_body, registry_digest = self._candidate_data_registry(
                        connection,
                        activation_id=str(body["activation_id"]),
                        ingest=ingest,
                        package=package,
                        records=records,
                        replace_extension=bool(conflicts),
                    )
                    sequence = len(activations) + 1
                    previous = None if not activations else activations[-1]["record_digest"]
                    record_body: dict[str, object] = {
                        "schema_version": "1.0.0", "record_sequence": sequence,
                        "previous_record_digest": previous, "activation_id": body["activation_id"],
                        "installation_id": body["installation_id"], "request_digest": request.request_digest,
                        "ingest_record_digest": ingest["record_digest"],
                        "extension_id": package["extension_id"],
                        "extension_version": package["extension_version"],
                        "package_identity_digest": manifest.package_identity_digest,
                        "manifest_digest": package["manifest_digest"],
                        "archive_raw_digest": ingest["archive_raw_digest"], "categories": list(categories),
                        "trust_policy_digest": trust.policy.policy_digest,
                        "trust_head_digest": trust.head.head_digest,
                        "revocation_high_water": trust.policy.revocation_high_water,
                        "activation_policy_digest": self._policy.policy_digest,
                        "built_in_registry_digest": self._builtins.registry_digest,
                        "activation_resource_binding_digest": self._resource_binding_digest,
                        "data_registry_digest": registry_digest,
                        "core_invariant_set_digest": self._invariants.invariant_set_digest,
                        "owner_decision_digest": body["owner_decision_digest"],
                        "owner_authority_digest": body["owner_authority_digest"],
                        "conflict_override_digest": body["conflict_override_digest"],
                        "activated_at": runtime.occurred_at,
                        "local_status": self._policy.local_activation_status,
                        "formal_release_status": self._policy.formal_release_status,
                        "executable_status": self._policy.executable_status,
                    }
                    digest = _record_digest(record_body, "extension-activation-record")
                    connection.execute(
                        "INSERT INTO extension_activation_ledger"
                        "(record_sequence,activation_id,extension_id,record_digest,record_json) VALUES(?,?,?,?,?)",
                        (sequence, body["activation_id"], package["extension_id"], digest, canonical_json({**record_body, "record_digest": digest})),
                    )
                    connection.execute(
                        "INSERT INTO extension_data_registries"
                        "(generation,activation_id,registry_digest,registry_json) VALUES(?,?,?,?)",
                        (
                            registry_body["generation"], body["activation_id"], registry_digest,
                            canonical_json({**registry_body, "registry_digest": registry_digest}),
                        ),
                    )
                    self._fault("extension-activation.after-data-registry")
                    previous_packages = (
                        []
                        if active_snapshot.active_manifest is None
                        else list(active_snapshot.active_manifest["active_packages"])
                    )
                    previous_packages = [
                        item
                        for item in previous_packages
                        if item["extension_id"] != package["extension_id"]
                    ]
                    previous_packages.append(
                        self._active_package(
                            {**record_body, "record_digest": digest}, ingest
                        )
                    )
                    tombstones = (
                        []
                        if active_snapshot.active_manifest is None
                        else list(active_snapshot.active_manifest["tombstones"])
                    )
                    active_set_receipt = self._write_manifest_and_pointer(
                        connection,
                        transition_id=str(body["activation_id"]),
                        transition_kind=(
                            "supersede"
                            if any(
                                item["extension_id"] == package["extension_id"]
                                for item in (
                                    []
                                    if active_snapshot.active_manifest is None
                                    else active_snapshot.active_manifest["active_packages"]
                                )
                            )
                            else "activate"
                        ),
                        installation_id=str(body["installation_id"]),
                        trust=trust,
                        registry_digest=registry_digest,
                        active_packages=previous_packages,
                        tombstones=tombstones,
                        owner_decision_digest=body["owner_decision_digest"],
                        owner_authority_digest=body["owner_authority_digest"],
                        activated_at=runtime.occurred_at,
                    )
                    connection.commit()
                    self._fault("extension-activation.after-commit")
                    self._post_publish_verify_or_restore(
                        connection,
                        previous=active_snapshot,
                        receipt=active_set_receipt,
                        installation_id=str(body["installation_id"]),
                        trust=trust,
                        owner_decision_digest=body["owner_decision_digest"],
                        owner_authority_digest=body["owner_authority_digest"],
                        activated_at=runtime.occurred_at,
                    )
                except ExtensionActivationError:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                except BaseException:
                    connection.rollback()
                    raise
            finally:
                connection.close()
            return ExtensionActivationReceipt(
                str(body["activation_id"]), str(package["extension_id"]),
                str(package["extension_version"]), categories, digest,
                self._policy.local_activation_status, self._policy.formal_release_status,
            )
        finally:
            self._trust._manager._control_lock.release(token)

    def transition_active_set(
        self,
        request: ExtensionActiveSetRequest,
        runtime: RuntimeContext,
    ) -> ExtensionActiveSetReceipt:
        self.require_attested(self)
        if type(request) is not ExtensionActiveSetRequest or type(runtime) is not RuntimeContext:
            raise TypeError("extension active-set inputs are invalid")
        body = request.to_dict()
        self._runtime_bound(body, runtime)
        token = self._trust._manager._control_lock.acquire("exclusive")
        try:
            connection = self._trust._connect()
            try:
                connection.executescript(_INGEST_SCHEMA + _SCHEMA)
                connection.execute("BEGIN IMMEDIATE")
                try:
                    trust = self._trust_snapshot(connection, body.get("installation_id"))
                    self._require_trust(body, trust)
                    snapshot = self._snapshot(connection)
                    self._require_active_cas(body, snapshot)
                    if snapshot.active_manifest is None:
                        raise ExtensionActivationError("extension active-set target is missing")
                    current_packages = list(snapshot.active_manifest["active_packages"])
                    selected_current = [
                        item
                        for item in current_packages
                        if item["extension_id"] == body["extension_id"]
                    ]
                    if len(selected_current) != 1:
                        raise ExtensionActivationError("extension active-set target is missing")
                    activations = _load_chain(
                        connection,
                        "extension_activation_ledger",
                        self._policy.maximum_activations,
                    )
                    by_digest = {str(item["record_digest"]): item for item in activations}
                    if body["transition_kind"] == "rollback":
                        target = by_digest.get(str(body["target_activation_record_digest"]))
                        if (
                            target is None
                            or target["extension_id"] != body["extension_id"]
                            or target["record_digest"]
                            == selected_current[0]["activation_record_digest"]
                        ):
                            raise ExtensionActivationError("extension rollback target is invalid")
                    else:
                        target = by_digest.get(
                            str(selected_current[0]["activation_record_digest"])
                        )
                        if target is None:
                            raise ExtensionActivationError("extension removal target is invalid")
                    ingests = _ingest_records(
                        connection, self._trust._policy.max_ledger_records
                    )
                    ingest_matches = [
                        item
                        for item in ingests
                        if item["record_digest"] == target["ingest_record_digest"]
                    ]
                    if len(ingest_matches) != 1:
                        raise ExtensionActivationError("extension transition ingest is missing")
                    ingest = ingest_matches[0]
                    row = connection.execute(
                        "SELECT manifest_json FROM extension_ingest_packages WHERE ingest_id=?",
                        (ingest["ingest_id"],),
                    ).fetchone()
                    if row is None:
                        raise ExtensionActivationError("extension transition package is missing")
                    package = parse_canonical_json(str(row[0]))
                    if not isinstance(package, Mapping):
                        raise ExtensionActivationError("extension transition package is invalid")
                    ExtensionPackageManifest.from_dict(package)
                    if body["transition_kind"] == "rollback":
                        code = self._current_eligibility_code(
                            connection,
                            trust=trust,
                            ingest=ingest,
                            package=package,
                            observed_at=runtime.occurred_at,
                            activation=target,
                        )
                        if code is not None:
                            raise ExtensionActivationError(code)
                    records = (
                        self._decode_records(ingest, package)
                        if body["transition_kind"] == "rollback"
                        else ()
                    )
                    registry_body, registry_digest = self._candidate_data_registry(
                        connection,
                        activation_id=str(body["transition_id"]),
                        ingest=ingest,
                        package=package,
                        records=records,
                        replace_extension=True,
                    )
                    connection.execute(
                        "INSERT INTO extension_data_registries"
                        "(generation,activation_id,registry_digest,registry_json) VALUES(?,?,?,?)",
                        (
                            registry_body["generation"], body["transition_id"], registry_digest,
                            canonical_json({**registry_body, "registry_digest": registry_digest}),
                        ),
                    )
                    self._fault("extension-activation.after-data-registry")
                    next_packages = [
                        item
                        for item in current_packages
                        if item["extension_id"] != body["extension_id"]
                    ]
                    tombstones = list(snapshot.active_manifest["tombstones"])
                    if body["transition_kind"] == "rollback":
                        next_packages.append(self._active_package(target, ingest))
                    else:
                        tombstone_body: dict[str, object] = {
                            "schema_version": "1.0.0",
                            "extension_id": body["extension_id"],
                            "removed_activation_record_digest": target["record_digest"],
                            "transition_id": body["transition_id"],
                            "reason_code": body["reason_code"],
                        }
                        tombstones.append(
                            {
                                **tombstone_body,
                                "tombstone_digest": _record_digest(
                                    tombstone_body, "extension-activation-tombstone"
                                ),
                            }
                        )
                    receipt = self._write_manifest_and_pointer(
                        connection,
                        transition_id=str(body["transition_id"]),
                        transition_kind=str(body["transition_kind"]),
                        installation_id=str(body["installation_id"]),
                        trust=trust,
                        registry_digest=registry_digest,
                        active_packages=next_packages,
                        tombstones=tombstones,
                        owner_decision_digest=body["owner_decision_digest"],
                        owner_authority_digest=body["owner_authority_digest"],
                        activated_at=runtime.occurred_at,
                    )
                    connection.commit()
                    self._fault("extension-activation.after-commit")
                    self._post_publish_verify_or_restore(
                        connection,
                        previous=snapshot,
                        receipt=receipt,
                        installation_id=str(body["installation_id"]),
                        trust=trust,
                        owner_decision_digest=body["owner_decision_digest"],
                        owner_authority_digest=body["owner_authority_digest"],
                        activated_at=runtime.occurred_at,
                    )
                    return receipt
                except ExtensionActivationError:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
                except BaseException:
                    if connection.in_transaction:
                        connection.rollback()
                    raise
            finally:
                connection.close()
        finally:
            self._trust._manager._control_lock.release(token)

    def pin_task(
        self,
        request: ExtensionTaskPinRequest,
        runtime: RuntimeContext,
    ) -> ExtensionTaskPinReceipt:
        self.require_attested(self)
        if type(request) is not ExtensionTaskPinRequest or type(runtime) is not RuntimeContext:
            raise TypeError("extension task pin inputs are invalid")
        body = request.to_dict()
        self._runtime_bound(body, runtime)
        token = self._trust._manager._control_lock.acquire("exclusive")
        try:
            connection = self._trust._connect()
            try:
                connection.executescript(_INGEST_SCHEMA + _SCHEMA)
                connection.execute("BEGIN IMMEDIATE")
                trust = self._trust_snapshot(connection, body.get("installation_id"))
                self._require_trust(body, trust)
                activations = _load_chain(
                    connection, "extension_activation_ledger", self._policy.maximum_activations
                )
                requested = tuple(body["activation_record_digests"])
                selected = [item for item in activations if item["record_digest"] in requested]
                active_snapshot = self._snapshot(connection)
                if (
                    active_snapshot.active_manifest is None
                    or body["expected_active_generation"]
                    != active_snapshot.active_manifest["generation"]
                    or body["expected_active_manifest_digest"]
                    != active_snapshot.active_manifest["manifest_digest"]
                    or active_snapshot.data_registry is None
                    or body["expected_contract_registry_digest"]
                    != active_snapshot.data_registry["registry_digest"]
                    or body["expected_capability_profile_digest"]
                    != self.capability_profile_digest
                ):
                    raise ExtensionActivationError("extension task pin active-set tuple is stale")
                active_digests = {
                    str(item["activation_record_digest"])
                    for item in (
                        []
                        if active_snapshot.active_manifest is None
                        else active_snapshot.active_manifest["active_packages"]
                    )
                }
                if len(selected) != len(requested) or not set(requested).issubset(active_digests):
                    self._diagnostic(
                        connection, code="E_EXTENSION_TASK_PIN_MISSING", subject_digest=request.request_digest,
                        observed_at=runtime.occurred_at,
                    )
                    connection.commit()
                    raise ExtensionActivationError("E_EXTENSION_TASK_PIN_MISSING")
                revoked = {
                    str(item["target_identity_digest"])
                    for item in trust.policy.to_dict()["revocations"]
                }
                if any(
                    item["package_identity_digest"] in revoked
                    or item["manifest_digest"] in revoked
                    or item["record_digest"] in revoked
                    for item in selected
                ):
                    self._diagnostic(
                        connection, code="E_EXTENSION_TASK_PIN_REVOKED", subject_digest=request.request_digest,
                        observed_at=runtime.occurred_at,
                    )
                    connection.commit()
                    raise ExtensionActivationError("E_EXTENSION_TASK_PIN_REVOKED")
                pins = _load_chain(connection, "extension_task_pins", self._policy.maximum_task_pins)
                sequence = len(pins) + 1
                previous = None if not pins else pins[-1]["record_digest"]
                packages = [
                    {
                        field: item[field]
                        for field in (
                            "activation_id", "record_digest", "extension_id", "extension_version",
                            "package_identity_digest", "manifest_digest", "archive_raw_digest",
                            "trust_policy_digest", "revocation_high_water",
                        )
                    }
                    for item in selected
                ]
                packages.sort(key=canonical_bytes)
                record_body: dict[str, object] = {
                    "schema_version": "1.0.0", "record_sequence": sequence,
                    "previous_record_digest": previous, "pin_id": body["pin_id"],
                    "task_id": body["task_id"], "installation_id": body["installation_id"],
                    "request_digest": request.request_digest, "packages": packages,
                    "trust_policy_digest": trust.policy.policy_digest,
                    "trust_head_digest": trust.head.head_digest,
                    "revocation_high_water": trust.policy.revocation_high_water,
                    "graph_digest": body["graph_digest"],
                    "active_generation": active_snapshot.active_manifest["generation"],
                    "active_manifest_digest": active_snapshot.active_manifest["manifest_digest"],
                    "contract_registry_digest": active_snapshot.data_registry["registry_digest"],
                    "capability_profile_digest": self.capability_profile_digest,
                    "owner_id": runtime.owner_id, "runtime_kind": runtime.runtime_kind,
                    "runtime_lineage_id": runtime.runtime_lineage_id,
                    "owner_decision_digest": body["owner_decision_digest"],
                    "owner_authority_digest": body["owner_authority_digest"],
                    "pinned_at": runtime.occurred_at,
                }
                digest = _record_digest(record_body, "extension-task-pin-record")
                connection.execute(
                    "INSERT INTO extension_task_pins"
                    "(record_sequence,pin_id,task_id,record_digest,record_json) VALUES(?,?,?,?,?)",
                    (sequence, body["pin_id"], body["task_id"], digest, canonical_json({**record_body, "record_digest": digest})),
                )
                connection.commit()
            except ExtensionActivationError:
                if connection.in_transaction:
                    connection.rollback()
                raise
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()
            return ExtensionTaskPinReceipt(
                str(body["pin_id"]), str(body["task_id"]), digest, requested
            )
        finally:
            self._trust._manager._control_lock.release(token)


class ExtensionTaskPinAuthority:
    """Read-only task-pin verifier bound to one live installation command scope."""

    __slots__ = ("_activation", "_scope")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension task pin authorities are factory-issued")

    @classmethod
    def create(
        cls,
        activation: ExtensionActivationRepository,
        command_scope: object,
    ) -> ExtensionTaskPinAuthority:
        from .migration import InstallationCommandScope

        if (
            ExtensionActivationRepository.require_attested(activation) is not activation
            or type(command_scope) is not InstallationCommandScope
        ):
            raise TypeError("extension task pin authority inputs are invalid")
        command_scope.require_current()
        if activation._trust._manager is not command_scope._manager:
            raise TypeError("extension task pin authority installation differs")
        result = object.__new__(cls)
        result._activation = activation
        result._scope = command_scope
        _ISSUED_PIN_AUTHORITIES[id(result)] = result
        return result

    @classmethod
    def require_attested(cls, value: object) -> ExtensionTaskPinAuthority:
        if type(value) is not cls or _ISSUED_PIN_AUTHORITIES.get(id(value)) is not value:
            raise TypeError("extension task pin authority is missing or forged")
        value._scope.require_current()
        return value

    @staticmethod
    def _historical_policy(
        connection: sqlite3.Connection, policy_digest: str,
    ) -> ExtensionTrustPolicy:
        previous: ExtensionTrustPolicy | None = None
        found: ExtensionTrustPolicy | None = None
        for (encoded,) in connection.execute(
            "SELECT policy_json FROM trust_policies ORDER BY generation"
        ):
            document = parse_canonical_json(str(encoded))
            policy = ExtensionTrustPolicy.from_dict(document, previous=previous)
            if policy.policy_digest == policy_digest:
                found = policy
            previous = policy
        if found is None:
            raise ExtensionActivationError("extension task is unavailable")
        return found

    @staticmethod
    def _records(
        policy: Mapping[str, object], field: str,
    ) -> dict[str, Mapping[str, object]]:
        from graph_engineering.core.security.extensions import ExtensionTrustPolicyReducer

        return {
            ExtensionTrustPolicyReducer._identity(field, item): item
            for item in policy[field]
            if isinstance(item, Mapping)
        }

    @staticmethod
    def _capability_relation(
        previous: tuple[str, ...], current: tuple[str, ...],
    ) -> str:
        if previous != tuple(sorted(set(previous))) or current != tuple(sorted(set(current))):
            raise ExtensionActivationError("extension task is unavailable")
        old = set(previous)
        new = set(current)
        if old == new:
            return "equal"
        if old.issubset(new):
            return "expansion"
        if new.issubset(old):
            return "contraction"
        return "incomparable"

    def _has_relevant_security_tightening(
        self,
        pinned: ExtensionTrustPolicy,
        current: ExtensionTrustPolicy,
        package: Mapping[str, object],
        ingest: Mapping[str, object],
    ) -> bool:
        """Compare only dimensions that authorized this immutable package."""

        members = self._activation._installer._load_installed_members_under_lock(
            self._activation._receipt_from_ingest(ingest)
        )
        try:
            source = parse_canonical_json(
                members["META-INF/source-attestation.json"].decode("utf-8")
            )
            build = parse_canonical_json(
                members["META-INF/build-attestation.json"].decode("utf-8")
            )
            signature = parse_canonical_json(
                members["META-INF/publisher-signature.json"].decode("utf-8")
            )
        except (KeyError, UnicodeDecodeError, ValueError) as error:
            raise ExtensionActivationError("extension task is unavailable") from error
        if not all(isinstance(item, Mapping) for item in (source, build, signature)):
            raise ExtensionActivationError("extension task is unavailable")

        old = pinned.to_dict()
        new = current.to_dict()
        relevant_keys = {
            f"{signature['publisher_id']}/{signature['publisher_key_id']}",
            f"{source['attestor_id']}/{source['attestor_key_id']}",
            f"{build['builder_id']}/{build['builder_key_id']}",
        }
        old_keys = self._records(old, "trust_keys")
        new_keys = self._records(new, "trust_keys")
        set_fields = (
            "roles", "source_classes", "namespaces", "extension_kinds",
            "allowed_production_policy_digests",
        )
        for identity in relevant_keys:
            before = old_keys.get(identity)
            after = new_keys.get(identity)
            if before is None:
                continue
            if after is None or after.get("status") != "active":
                return True
            if (
                any(
                    not set(before[field]).issubset(after[field])
                    for field in set_fields
                )
            ):
                return True

        old_production = self._records(old, "production_policies")
        new_production = self._records(new, "production_policies")
        policy_id = str(source["production_policy_id"])
        before_production = old_production.get(policy_id)
        after_production = new_production.get(policy_id)
        if before_production is not None and (
            after_production is None
            or after_production.get("status") != "active"
            or after_production.get("policy_digest")
            != before_production.get("policy_digest")
        ):
            return True

        source_type = str(source["source_type"])
        old_source = self._records(old, "source_rules").get(source_type)
        new_source = self._records(new, "source_rules").get(source_type)
        if old_source is not None and (
            new_source is None
            or source["source_id"] not in new_source["allowed_source_ids"]
            or not set(new_source["required_material_kinds"]).issubset(
                old_source["required_material_kinds"]
            )
            or new_source["rule_mode"] != old_source["rule_mode"]
        ):
            return True

        publisher = str(package["publisher_id"])
        extension_id = str(package["extension_id"])
        extension_kind = str(package["package_class"])
        old_namespaces = [
            item for item in old["namespace_rules"]
            if item["publisher_id"] == publisher
            and extension_id.startswith(str(item["namespace_prefix"]))
        ]
        new_namespaces = [
            item for item in new["namespace_rules"]
            if item["publisher_id"] == publisher
            and extension_id.startswith(str(item["namespace_prefix"]))
            and extension_kind in item["allowed_extension_kinds"]
        ]
        if old_namespaces and not new_namespaces:
            return True

        old_kind = self._records(old, "extension_kind_rules").get(extension_kind)
        new_kind = self._records(new, "extension_kind_rules").get(extension_kind)
        if old_kind is not None and (
            new_kind is None
            or (old_kind["data_allowed"] and not new_kind["data_allowed"])
            or (old_kind["executable_allowed"] and not new_kind["executable_allowed"])
            or not set(new_kind["required_isolation_profiles"]).issubset(
                old_kind["required_isolation_profiles"]
            )
        ):
            return True

        old_ceiling = self._records(old, "capability_ceilings").get(
            f"publisher/{publisher}"
        )
        new_ceiling = self._records(new, "capability_ceilings").get(
            f"publisher/{publisher}"
        )
        if old_ceiling is None:
            return False
        if new_ceiling is None:
            return True
        relation = self._capability_relation(
            tuple(str(item) for item in old_ceiling["capability_ids"]),
            tuple(str(item) for item in new_ceiling["capability_ids"]),
        )
        return relation in {"contraction", "incomparable"}

    def load(self, pin_digest: str, *, require_current: bool = True) -> dict[str, object]:
        self.require_attested(self)
        connection = self._activation._trust._connect()
        try:
            connection.executescript(_INGEST_SCHEMA + _SCHEMA)
            pins = _load_chain(
                connection,
                "extension_task_pins",
                self._activation._policy.maximum_task_pins,
            )
            matches = [item for item in pins if item["record_digest"] == pin_digest]
            if len(matches) != 1:
                raise ExtensionActivationError("extension task is unavailable")
            result = dict(matches[0])
            if require_current:
                self._activation._snapshot(connection)
                self._activation._verify_materialized_registry(connection)
                trust = self._activation._trust_snapshot(
                    connection, result["installation_id"]
                )
                selected = {
                    str(item["record_digest"]) for item in result["packages"]
                }
                revoked = {
                    str(item["target_identity_digest"])
                    for item in trust.policy.to_dict()["revocations"]
                }
                activations = _load_chain(
                    connection, "extension_activation_ledger",
                    self._activation._policy.maximum_activations,
                )
                by_activation = {str(item["record_digest"]): item for item in activations}
                ingests = _ingest_records(
                    connection, self._activation._trust._policy.max_ledger_records
                )
                by_ingest = {str(item["record_digest"]): item for item in ingests}
                registries = {
                    str(item["registry_digest"])
                    for item in _load_data_registries(
                        connection, self._activation._policy.maximum_activations
                    )
                }
                blocked = result["contract_registry_digest"] not in registries
                floors = trust.policy.to_dict()["compatibility_floors"]
                for package_pin in result["packages"]:
                    activation = by_activation.get(str(package_pin["record_digest"]))
                    if activation is None or any(
                        package_pin[field] != activation[field]
                        for field in (
                            "activation_id", "record_digest", "extension_id",
                            "extension_version", "package_identity_digest", "manifest_digest",
                            "archive_raw_digest", "trust_policy_digest", "revocation_high_water",
                        )
                    ):
                        blocked = True
                        continue
                    ingest = by_ingest.get(str(activation["ingest_record_digest"]))
                    if ingest is None:
                        blocked = True
                        continue
                    row = connection.execute(
                        "SELECT manifest_json FROM extension_ingest_packages WHERE ingest_id=?",
                        (ingest["ingest_id"],),
                    ).fetchone()
                    if row is None:
                        blocked = True
                        continue
                    manifest_document = parse_canonical_json(str(row[0]))
                    if not isinstance(manifest_document, Mapping):
                        blocked = True
                        continue
                    package = ExtensionPackageManifest.from_dict(manifest_document).to_dict()
                    pinned_policy = self._historical_policy(
                        connection, str(activation["trust_policy_digest"])
                    )
                    if self._has_relevant_security_tightening(
                        pinned_policy, trust.policy, package, ingest
                    ):
                        blocked = True
                    subjects = {
                        str(activation["record_digest"]), str(ingest["record_digest"]),
                        str(ingest["source_attestation_digest"]),
                        str(ingest["build_attestation_digest"]),
                        str(ingest["publisher_signature_digest"]),
                        str(ingest["production_policy_digest"]),
                        str(package["package_identity_digest"]), str(package["manifest_digest"]),
                    }
                    if subjects & revoked:
                        blocked = True
                    if (
                        activation["activation_resource_binding_digest"]
                        != self._activation._resource_binding_digest
                        or trust.policy.to_dict()["resource_policy_digest"]
                        != self._activation._resource_binding_digest
                    ):
                        blocked = True
                    requested = {
                        str(item["capability_id"])
                        for item in package["requested_capabilities"]
                    }
                    if not requested.issubset(self._activation._policy.available_capabilities):
                        blocked = True
                    for component, declaration in package["compatibility"].items():
                        floor_digest = _record_digest(
                            {
                                "schema_version": "1.0.0",
                                "component_kind": component,
                                "accepted_declarations": [declaration],
                            },
                            "extension-compatibility-floor",
                        )
                        if sum(
                            1 for item in floors
                            if item["component_kind"] == component
                            and item["compatibility_policy_digest"] == floor_digest
                        ) != 1:
                            blocked = True
                if blocked or len(selected) != len(result["packages"]):
                    raise ExtensionActivationError("extension task is unavailable")
            self._scope.require_current()
            return result
        except ExtensionActivationError:
            raise
        except Exception as error:
            raise ExtensionActivationError("extension task is unavailable") from error
        finally:
            connection.close()
