"""Validated logical-body extraction and independent invalidation."""

from __future__ import annotations

import hmac
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import (
    RAW_DIGEST,
    SEMANTIC_DIGEST,
    semantic_digest_charged,
)
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.contracts.immutable import freeze, thaw


LOGICAL_BODY_MANIFEST_SCHEMA = "urn:gew:schema:logical-body-manifest:1.0.0"
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"


class LogicalBodyManifestError(ValueError):
    """Invalid logical body selector, digest, or dependency graph."""


@dataclass(frozen=True, slots=True, init=False)
class LogicalBodyEntry:
    artifact_id: str
    start: int
    end: int
    extracted_body_digest: str
    entry_digest: str
    shared_section_id: str | None
    dependencies: tuple[str, ...]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("LogicalBodyEntry must be loaded from a validated manifest")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("LogicalBodyEntry is final")


@dataclass(frozen=True, slots=True, init=False)
class LogicalBodyManifest:
    manifest_id: str
    mode: str
    physical_body_digest: str
    manifest_digest: str
    entries: Mapping[str, LogicalBodyEntry]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("LogicalBodyManifest must be loaded from validated configuration")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("LogicalBodyManifest is final")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        physical_body: bytes,
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> LogicalBodyManifest:
        if (
            type(physical_body) is not bytes
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise LogicalBodyManifestError("manifest requires exact bytes, registry, and context")
        try:
            snapshot = thaw(freeze(value))
        except (TypeError, ValueError) as error:
            raise LogicalBodyManifestError("manifest must be exact JSON") from error
        if not isinstance(snapshot, dict):
            raise LogicalBodyManifestError("manifest must be an object")
        value = snapshot
        root_path = context.child_path(())
        context.check_limit(
            "raw_document_bytes",
            len(physical_body),
            source_id=LOGICAL_BODY_MANIFEST_SCHEMA,
        )
        schema_path = context.child_path(root_path)
        if schema_registry.validate(
            LOGICAL_BODY_MANIFEST_SCHEMA,
            value,
            context,
            operation_path=schema_path,
        ):
            raise LogicalBodyManifestError("logical body manifest schema validation failed")
        fields = {
            "schema_version",
            "manifest_id",
            "mode",
            "physical_body_digest",
            "entries",
            "manifest_digest",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise LogicalBodyManifestError("logical body manifest properties are not exact")
        manifest_id = value.get("manifest_id")
        mode = value.get("mode")
        physical_digest = value.get("physical_body_digest")
        expected_digest = value.get("manifest_digest")
        raw_entries = value.get("entries")
        if (
            type(manifest_id) is not str
            or not manifest_id.startswith("urn:gew:logical-body-manifest:")
            or mode not in {"full", "compact", "emergency"}
            or type(physical_digest) is not str
            or RAW_DIGEST.fullmatch(physical_digest) is None
            or type(expected_digest) is not str
            or SEMANTIC_DIGEST.fullmatch(expected_digest) is None
            or type(raw_entries) is not list
            or not raw_entries
        ):
            raise LogicalBodyManifestError("logical body manifest identity is invalid")
        physical_digest_path = context.child_path(root_path)
        if not hmac.compare_digest(
            physical_digest,
            _raw_digest_charged(
                physical_body,
                context,
                operation_path=physical_digest_path,
                source_id=LOGICAL_BODY_MANIFEST_SCHEMA,
            ),
        ):
            raise LogicalBodyManifestError("physical body digest mismatch")
        entries: list[LogicalBodyEntry] = []
        for raw in raw_entries:
            if not isinstance(raw, Mapping) or set(raw) != {
                "artifact_id",
                "selector",
                "extracted_body_digest",
                "entry_digest",
                "shared_section_id",
                "dependencies",
            }:
                raise LogicalBodyManifestError("logical body entry is not exact")
            artifact_id = raw.get("artifact_id")
            selector = raw.get("selector")
            extracted_digest = raw.get("extracted_body_digest")
            expected_entry_digest = raw.get("entry_digest")
            shared = raw.get("shared_section_id")
            dependencies = raw.get("dependencies")
            if (
                type(artifact_id) is not str
                or not artifact_id
                or not isinstance(selector, Mapping)
                or set(selector) != {"start", "end"}
                or type(selector.get("start")) is not int
                or type(selector.get("end")) is not int
                or type(extracted_digest) is not str
                or RAW_DIGEST.fullmatch(extracted_digest) is None
                or type(expected_entry_digest) is not str
                or SEMANTIC_DIGEST.fullmatch(expected_entry_digest) is None
                or (shared is not None and (type(shared) is not str or not shared))
                or type(dependencies) is not list
                or any(type(item) is not str or not item for item in dependencies)
                or dependencies != sorted(set(dependencies))
            ):
                raise LogicalBodyManifestError("logical body entry fields are invalid")
            start = selector["start"]
            end = selector["end"]
            if start < 0 or end <= start or end > len(physical_body):
                raise LogicalBodyManifestError("logical body selector is out of bounds")
            context.check_limit(
                "result_bytes",
                end - start,
                source_id=LOGICAL_BODY_MANIFEST_SCHEMA,
            )
            extracted_path = context.child_path(root_path)
            if not hmac.compare_digest(
                extracted_digest,
                _raw_digest_charged(
                    memoryview(physical_body)[start:end],
                    context,
                    operation_path=extracted_path,
                    source_id=LOGICAL_BODY_MANIFEST_SCHEMA,
                ),
            ):
                raise LogicalBodyManifestError("extracted logical body digest mismatch")
            unsigned_entry = dict(raw)
            del unsigned_entry["entry_digest"]
            actual_entry_digest = semantic_digest_charged(
                unsigned_entry,
                context,
                contract_type="urn:gew:contract:logical-body-entry",
                projection_id=IDENTITY_PROJECTION,
                schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
                operation_path=context.child_path(root_path),
            )
            if not hmac.compare_digest(expected_entry_digest, actual_entry_digest):
                raise LogicalBodyManifestError("logical body entry digest mismatch")
            entry = object.__new__(LogicalBodyEntry)
            for name, item in (
                ("artifact_id", artifact_id),
                ("start", start),
                ("end", end),
                ("extracted_body_digest", extracted_digest),
                ("entry_digest", expected_entry_digest),
                ("shared_section_id", shared),
                ("dependencies", tuple(dependencies)),
            ):
                object.__setattr__(entry, name, item)
            entries.append(entry)
        identities = tuple(entry.artifact_id for entry in entries)
        if identities != tuple(sorted(set(identities))):
            raise LogicalBodyManifestError("logical body entries must be sorted and unique")
        known = set(identities)
        for entry in entries:
            if entry.artifact_id in entry.dependencies or not set(entry.dependencies).issubset(known):
                raise LogicalBodyManifestError("logical body dependency is cyclic or unknown")
        for index, left in enumerate(entries):
            for right in entries[index + 1:]:
                overlaps = left.start < right.end and right.start < left.end
                shared_exactly = (
                    left.start == right.start
                    and left.end == right.end
                    and left.shared_section_id is not None
                    and left.shared_section_id == right.shared_section_id
                )
                if overlaps and not shared_exactly:
                    raise LogicalBodyManifestError("logical body selectors overlap ambiguously")
        visiting: set[str] = set()
        visited: set[str] = set()
        by_id = {entry.artifact_id: entry for entry in entries}

        def visit(artifact_id: str) -> None:
            if artifact_id in visiting:
                raise LogicalBodyManifestError("logical body dependency cycle")
            if artifact_id in visited:
                return
            visiting.add(artifact_id)
            for dependency in by_id[artifact_id].dependencies:
                visit(dependency)
            visiting.remove(artifact_id)
            visited.add(artifact_id)

        for artifact_id in identities:
            visit(artifact_id)
        unsigned = dict(value)
        del unsigned["manifest_digest"]
        actual_digest = semantic_digest_charged(
            unsigned,
            context,
            contract_type="urn:gew:contract:logical-body-manifest",
            projection_id=IDENTITY_PROJECTION,
            schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
            operation_path=context.child_path(root_path),
        )
        if not hmac.compare_digest(expected_digest, actual_digest):
            raise LogicalBodyManifestError("logical body manifest digest mismatch")
        result = object.__new__(LogicalBodyManifest)
        object.__setattr__(result, "manifest_id", manifest_id)
        object.__setattr__(result, "mode", mode)
        object.__setattr__(result, "physical_body_digest", physical_digest)
        object.__setattr__(result, "manifest_digest", expected_digest)
        object.__setattr__(result, "entries", MappingProxyType(by_id))
        return result

    def extracted_digest(self, artifact_id: str) -> str:
        try:
            return self.entries[artifact_id].extracted_body_digest
        except KeyError as error:
            raise LogicalBodyManifestError("unknown logical artifact") from error

    def entry_digest(self, artifact_id: str) -> str:
        try:
            return self.entries[artifact_id].entry_digest
        except KeyError as error:
            raise LogicalBodyManifestError("unknown logical artifact") from error

    def semantic_body_digest(
        self,
        artifact_id: str,
        semantic_fields: Mapping[str, str],
        context: WorkContext,
    ) -> str:
        """Bind one logical identity to its bytes and semantic claims."""

        if (
            type(context) is not WorkContext
            or not isinstance(semantic_fields, Mapping)
            or any(type(key) is not str or type(item) is not str for key, item in semantic_fields.items())
        ):
            raise LogicalBodyManifestError("logical body digest requires an attested context")
        extracted = self.extracted_digest(artifact_id)
        return semantic_digest_charged(
            {
                "artifact_id": artifact_id,
                "extracted_body_digest": extracted,
                "semantic_fields": dict(semantic_fields),
            },
            context,
            contract_type="urn:gew:contract:logical-artifact-body",
            projection_id=IDENTITY_PROJECTION,
            schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
            operation_path=context.child_path(()),
        )

    def invalidated_by(self, previous: LogicalBodyManifest) -> tuple[str, ...]:
        if (
            type(previous) is not LogicalBodyManifest
            or self.manifest_id != previous.manifest_id
            or self.mode != previous.mode
            or set(previous.entries) != set(self.entries)
        ):
            raise LogicalBodyManifestError("logical body manifests are not comparable")
        changed = {
            artifact_id for artifact_id, entry in self.entries.items()
            if previous.entries[artifact_id].entry_digest != entry.entry_digest
        }
        pending = list(changed)
        while pending:
            source = pending.pop()
            for artifact_id, entry in self.entries.items():
                if source in entry.dependencies and artifact_id not in changed:
                    changed.add(artifact_id)
                    pending.append(artifact_id)
        return tuple(sorted(changed))


def _raw_digest_charged(
    body: bytes | memoryview,
    context: WorkContext,
    *,
    operation_path: tuple[int, ...],
    source_id: str,
) -> str:
    view = memoryview(body)
    context.acquire_temporary(1, source_id=source_id, operation_path=operation_path)
    try:
        for _ in view:
            context.emit(
                "digest.input_byte",
                1,
                operation_path=operation_path,
                source_id=source_id,
            )
        return "sha256-raw-v1:" + hashlib.sha256(view).hexdigest()
    finally:
        context.release_temporary(1)
