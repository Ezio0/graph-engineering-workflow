from __future__ import annotations

import copy
import pathlib
import sys
import unittest
from collections.abc import Mapping


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT))

from graph_engineering.core.artifacts import (  # noqa: E402
    ArtifactValidator,
    LogicalBodyManifest,
    LogicalBodyManifestError,
)
from graph_engineering.core.artifacts.manifest import LOGICAL_BODY_MANIFEST_SCHEMA  # noqa: E402
from graph_engineering.core.contracts.canonical import canonical_bytes  # noqa: E402
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.resources import ResourceProfile, WorkContext  # noqa: E402
from tests.support.wp04a_artifacts import (  # noqa: E402
    IDENTITY_PROJECTION,
    artifact_record,
    contract_registry,
    golden_semantics,
    schema_registry,
    work_context,
)
from tests.unit.test_wp04a_artifacts import resign  # noqa: E402


def manifest_value(
    physical: bytes,
    entries: list[dict[str, object]],
    *,
    mode: str = "compact",
    manifest_id: str = "urn:gew:logical-body-manifest:merged:1",
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": "1.0.0",
        "manifest_id": manifest_id,
        "mode": mode,
        "physical_body_digest": raw_digest(physical),
        "entries": entries,
    }
    value["manifest_digest"] = semantic_digest(
        value,
        contract_type="urn:gew:contract:logical-body-manifest",
        projection_id=IDENTITY_PROJECTION,
        schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
    )
    return value


def entry(
    artifact_id: str,
    physical: bytes,
    start: int,
    end: int,
    *,
    shared: str | None = None,
    dependencies: tuple[str, ...] = (),
) -> dict[str, object]:
    value: dict[str, object] = {
        "artifact_id": artifact_id,
        "selector": {"start": start, "end": end},
        "extracted_body_digest": raw_digest(physical[start:end]),
        "shared_section_id": shared,
        "dependencies": list(dependencies),
    }
    value["entry_digest"] = semantic_digest(
        value,
        contract_type="urn:gew:contract:logical-body-entry",
        projection_id=IDENTITY_PROJECTION,
        schema_id=LOGICAL_BODY_MANIFEST_SCHEMA,
    )
    return value


class LogicalBodyManifestTests(unittest.TestCase):
    def load(
        self,
        physical: bytes,
        entries: list[dict[str, object]],
        *,
        mode: str = "compact",
        context=None,
        schemas=None,
    ) -> LogicalBodyManifest:
        current_context = work_context() if context is None else context
        current_schemas = schema_registry(current_context) if schemas is None else schemas
        return LogicalBodyManifest.from_dict(
            manifest_value(physical, entries, mode=mode),
            physical,
            schema_registry=current_schemas,
            context=current_context,
        )

    def test_gew_art_merged_manifest_gold(self) -> None:
        physical = b"alpha-body|beta-body"
        entries = [
            entry("artifact-alpha-v1", physical, 0, 10),
            entry("artifact-beta-v1", physical, 11, len(physical)),
        ]
        for mode in ("full", "compact", "emergency"):
            with self.subTest(mode=mode):
                loaded = self.load(physical, entries, mode=mode)
                self.assertEqual((loaded.mode, tuple(loaded.entries)), (mode, ("artifact-alpha-v1", "artifact-beta-v1")))

    def test_gew_art_merged_selector_missing(self) -> None:
        physical = b"alpha"
        value = entry("artifact-alpha-v1", physical, 0, 5)
        del value["selector"]
        with self.assertRaises(LogicalBodyManifestError):
            self.load(physical, [value])

    def test_gew_art_merged_selector_ambiguous(self) -> None:
        physical = b"alpha"
        entries = [
            entry("artifact-alpha-v1", physical, 0, 5),
            entry("artifact-alpha-v1", physical, 0, 5, shared="shared-1"),
        ]
        with self.assertRaises(LogicalBodyManifestError):
            self.load(physical, entries)

    def test_gew_art_merged_selector_out_of_bounds(self) -> None:
        physical = b"alpha"
        value = entry("artifact-alpha-v1", physical, 0, 5)
        value["selector"]["end"] = 6
        with self.assertRaises(LogicalBodyManifestError):
            self.load(physical, [value])

    def test_gew_art_merged_overlap(self) -> None:
        physical = b"alpha-beta"
        entries = [
            entry("artifact-alpha-v1", physical, 0, 7),
            entry("artifact-beta-v1", physical, 5, 10),
        ]
        with self.assertRaisesRegex(LogicalBodyManifestError, "overlap"):
            self.load(physical, entries)

    def test_gew_art_merged_extracted_digest(self) -> None:
        physical = b"alpha"
        value = entry("artifact-alpha-v1", physical, 0, 5)
        value["extracted_body_digest"] = "sha256-raw-v1:" + "0" * 64
        with self.assertRaisesRegex(LogicalBodyManifestError, "extracted"):
            self.load(physical, [value])

    def test_manifest_raw_result_temporary_and_budget_boundaries_fail_closed(
        self,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        physical = b"bounded-body"
        entries = [entry("artifact-alpha-v1", physical, 0, len(physical))]
        base = work_context()
        schemas = schema_registry(base)

        raw_profile = base.profile.to_dict()
        raw_profile["profile_id"] = "urn:gew:resource-profile:wp04a-raw-limit"
        raw_profile["limits"]["raw_document_bytes"] = len(physical) - 1
        raw_context = WorkContext(ResourceProfile.from_dict(raw_profile), base.schedule)
        with self.assertRaises(ContractError):
            self.load(physical, entries, context=raw_context, schemas=schemas)
        self.assertEqual(raw_context.trace, [])
        if mutation_reporter is not None:
            mutation_reporter.add("raw-byte-limit-rejected-before-charge")

        result_profile = base.profile.to_dict()
        result_profile["profile_id"] = "urn:gew:resource-profile:wp04a-result-limit"
        result_profile["limits"]["result_bytes"] = len(physical) - 1
        result_context = WorkContext(ResourceProfile.from_dict(result_profile), base.schedule)
        with self.assertRaises(ContractError):
            self.load(physical, entries, context=result_context, schemas=schemas)
        if mutation_reporter is not None:
            mutation_reporter.add("result-byte-limit-rejected")

        temporary_context = WorkContext(base.profile, base.schedule)
        temporary_context.acquire_temporary(
            base.profile.limits["temporary_units"],
            source_id=LOGICAL_BODY_MANIFEST_SCHEMA,
            operation_path=(),
        )
        try:
            with self.assertRaises(ContractError):
                self.load(physical, entries, context=temporary_context, schemas=schemas)
        finally:
            temporary_context.release_temporary(base.profile.limits["temporary_units"])
        if mutation_reporter is not None:
            mutation_reporter.add("temporary-unit-limit-rejected")

        measured = WorkContext(base.profile, base.schedule)
        self.load(physical, entries, context=measured, schemas=schemas)
        spent = base.profile.work_budget - measured.balance
        exact = WorkContext(base.profile, base.schedule, initial_balance=spent)
        self.load(physical, entries, context=exact, schemas=schemas)
        self.assertEqual(exact.balance, 0)
        if mutation_reporter is not None:
            mutation_reporter.add("exact-budget-accepted")
        insufficient = WorkContext(base.profile, base.schedule, initial_balance=spent - 1)
        with self.assertRaises(ContractError):
            self.load(physical, entries, context=insufficient, schemas=schemas)
        self.assertEqual(insufficient.trace[-1]["status"], "rejected")
        if mutation_reporter is not None:
            mutation_reporter.add("insufficient-budget-rejected")

    def test_gew_art_merged_independent_invalidation(self) -> None:
        previous_body = b"alpha|beta|gamma"
        current_body = b"alpHa|beta|gamma"
        previous_entries = [
            entry("artifact-alpha-v1", previous_body, 0, 5),
            entry("artifact-beta-v1", previous_body, 6, 10),
            entry("artifact-gamma-v1", previous_body, 11, 16, dependencies=("artifact-alpha-v1",)),
        ]
        current_entries = [
            entry("artifact-alpha-v1", current_body, 0, 5),
            entry("artifact-beta-v1", current_body, 6, 10),
            entry("artifact-gamma-v1", current_body, 11, 16, dependencies=("artifact-alpha-v1",)),
        ]
        previous = self.load(previous_body, previous_entries)
        current = self.load(current_body, current_entries)
        self.assertEqual(
            current.invalidated_by(previous),
            ("artifact-alpha-v1", "artifact-gamma-v1"),
        )

    def test_gew_art_merged_shared_invalidation(self) -> None:
        previous_body = b"shared-body"
        current_body = b"shared-Body"
        previous_entries = [
            entry("artifact-alpha-v1", previous_body, 0, 11, shared="shared-1"),
            entry("artifact-beta-v1", previous_body, 0, 11, shared="shared-1"),
        ]
        current_entries = [
            entry("artifact-alpha-v1", current_body, 0, 11, shared="shared-1"),
            entry("artifact-beta-v1", current_body, 0, 11, shared="shared-1"),
        ]
        previous = self.load(previous_body, previous_entries)
        current = self.load(current_body, current_entries)
        self.assertEqual(
            current.invalidated_by(previous),
            ("artifact-alpha-v1", "artifact-beta-v1"),
        )

    def test_manifest_binding_fields_and_unselected_gap_invalidate_minimally(
        self,
        mutation_reporter: set[str] | None = None,
    ) -> None:
        context = work_context()
        schemas = schema_registry(context)
        contracts = contract_registry(schemas, context)
        semantics = golden_semantics()
        impact_body = canonical_bytes(dict(semantics["impact"]))
        plan_body = canonical_bytes(dict(semantics["plan"]))
        previous_body = impact_body + b"|" + plan_body
        current_body = impact_body + b"!" + plan_body
        previous_entries = [
            entry("artifact-impact-v1", previous_body, 0, len(impact_body)),
            entry("artifact-plan-v1", previous_body, len(impact_body) + 1, len(previous_body)),
        ]
        current_entries = [
            entry("artifact-impact-v1", current_body, 0, len(impact_body)),
            entry("artifact-plan-v1", current_body, len(impact_body) + 1, len(current_body)),
        ]
        previous = self.load(previous_body, previous_entries, context=context, schemas=schemas)
        current = self.load(current_body, current_entries, context=context, schemas=schemas)
        self.assertEqual(current.invalidated_by(previous), ())
        record, validation = artifact_record("impact", contracts, previous, semantics["impact"])
        validation["schema_registry"] = schemas
        validation["manifest"] = current
        self.assertEqual(
            ArtifactValidator.validate(record, context=context, **validation).status,
            "PASS",
        )
        if mutation_reporter is not None:
            mutation_reporter.add("unselected-gap-change-preserves-record")

        repeated = b"alphaalpha"
        selector_before = self.load(
            repeated,
            [entry("artifact-alpha-v1", repeated, 0, 5)],
        )
        selector_after = self.load(
            repeated,
            [entry("artifact-alpha-v1", repeated, 5, 10)],
        )
        self.assertEqual(selector_after.invalidated_by(selector_before), ("artifact-alpha-v1",))
        if mutation_reporter is not None:
            mutation_reporter.add("selector-change-invalidates")

        dependency_before = self.load(
            b"alpha|beta",
            [
                entry("artifact-alpha-v1", b"alpha|beta", 0, 5),
                entry("artifact-beta-v1", b"alpha|beta", 6, 10),
            ],
        )
        dependency_after = self.load(
            b"alpha|beta",
            [
                entry("artifact-alpha-v1", b"alpha|beta", 0, 5, dependencies=("artifact-beta-v1",)),
                entry("artifact-beta-v1", b"alpha|beta", 6, 10),
            ],
        )
        self.assertEqual(dependency_after.invalidated_by(dependency_before), ("artifact-alpha-v1",))
        if mutation_reporter is not None:
            mutation_reporter.add("dependency-change-invalidates")

        other_id = LogicalBodyManifest.from_dict(
            manifest_value(current_body, current_entries, manifest_id="urn:gew:logical-body-manifest:other:1"),
            current_body,
            schema_registry=schemas,
            context=context,
        )
        other_mode = self.load(current_body, current_entries, mode="emergency", context=context, schemas=schemas)
        for incomparable in (other_id, other_mode):
            with self.subTest(incomparable=(incomparable.manifest_id, incomparable.mode)):
                with self.assertRaisesRegex(LogicalBodyManifestError, "not comparable"):
                    incomparable.invalidated_by(previous)
                if mutation_reporter is not None:
                    mutation_reporter.add(
                        "manifest-id-change-incomparable"
                        if incomparable is other_id
                        else "mode-change-incomparable"
                    )

    def test_gew_art_merged_review_binding(self) -> None:
        context = work_context()
        schemas = schema_registry(context)
        contracts = contract_registry(schemas, context)
        semantics = golden_semantics()
        first = canonical_bytes(dict(semantics["impact"]))
        second = canonical_bytes(dict(semantics["plan"]))
        physical = first + b"\n" + second
        entries = [
            entry("artifact-impact-v1", physical, 0, len(first)),
            entry("artifact-plan-v1", physical, len(first) + 1, len(physical)),
        ]
        manifest = self.load(physical, entries, context=context, schemas=schemas)
        impact, impact_validation = artifact_record("impact", contracts, manifest, semantics["impact"])
        plan, plan_validation = artifact_record("plan", contracts, manifest, semantics["plan"])
        for record, validation in ((impact, impact_validation), (plan, plan_validation)):
            validation["schema_registry"] = schemas
            self.assertEqual(
                ArtifactValidator.validate(record, context=context, **validation).status,
                "PASS",
            )
        swapped = copy.deepcopy(impact)
        swapped["review_records"][0]["body_digest"] = plan["body_digest"]
        resign(swapped)
        impact_validation["schema_registry"] = schemas
        self.assertIn(
            "review",
            ArtifactValidator.validate(
                swapped,
                context=context,
                **impact_validation,
            ).failures,
        )


if __name__ == "__main__":
    unittest.main()
