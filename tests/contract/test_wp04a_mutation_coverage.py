from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT))

from tests.contract import test_wp04a_manifests as manifest_tests  # noqa: E402
from tests.unit import test_wp04a_artifacts as artifact_tests  # noqa: E402


REQUIRED_MUTATIONS = frozenset({
    "accepted-predecessor-revision-rejected",
    "actor-case-alias-rejected",
    "actor-leading-whitespace-rejected",
    "actor-unicode-normalization-alias-rejected",
    "author-reviewer-equality-rejected",
    "caller-mappings-snapshotted-once",
    "cross-baseline-input-swap-rejected",
    "dependency-change-invalidates",
    "digest-bound-lifecycle-event-accepted",
    "direct-lifecycle-event-construction-rejected",
    "direct-validation-record-construction-rejected",
    "exact-budget-accepted",
    "insufficient-budget-rejected",
    "invalidated-predecessor-revision-accepted",
    "lifecycle-record-status-mismatch-rejected",
    "invented-target-rejected",
    "manifest-id-change-incomparable",
    "mode-change-incomparable",
    "multi-baseline-accepted",
    "multi-input-accepted",
    "multi-input-missing-edge-rejected",
    "multi-requirement-accepted",
    "multi-requirement-missing-edge-rejected",
    "multi-target-accepted",
    "multi-target-missing-edge-rejected",
    "raw-byte-limit-rejected-before-charge",
    "result-byte-limit-rejected",
    "selector-change-invalidates",
    "temporary-unit-limit-rejected",
    "unselected-gap-change-preserves-record",
})


def coverage_findings(manifest: dict[str, object], executed: set[str]) -> list[str]:
    probes = manifest.get("probes")
    if not isinstance(probes, list):
        return ["PROBES_MISSING"]
    declared = [
        subcase
        for probe in probes
        if isinstance(probe, dict) and isinstance(probe.get("subcases"), list)
        for subcase in probe["subcases"]
    ]
    if any(type(item) is not str or not item for item in declared):
        return ["SUBCASE_ID_INVALID"]
    if len(declared) != len(set(declared)):
        return ["SUBCASE_ID_DUPLICATE"]
    return [] if set(declared) == executed else ["DECLARED_EXECUTION_MISMATCH"]


class WP04AMutationCoverageTests(unittest.TestCase):
    def test_declared_mutations_are_executable_and_fail_closed(self) -> None:
        manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-04a-mutations.json").read_text()
        )
        self.assertEqual(set(manifest), {"schema_version", "probes"})
        self.assertEqual(manifest["schema_version"], "1.0")
        probes = manifest["probes"]
        self.assertIsInstance(probes, list)
        probe_ids = [probe["probe_id"] for probe in probes]
        self.assertEqual(
            probe_ids,
            [
                "ingress-snapshot",
                "identity-independence",
                "reference-trace-closure",
                "lifecycle-evidence",
                "manifest-resource-boundaries",
                "manifest-minimal-invalidation",
            ],
        )
        declared = [subcase for probe in probes for subcase in probe["subcases"]]
        self.assertEqual(frozenset(declared), REQUIRED_MUTATIONS)
        self.assertEqual(len(declared), len(REQUIRED_MUTATIONS))

        artifact_probe = artifact_tests.WP04AArtifactMatrixTests()
        manifest_probe = manifest_tests.LogicalBodyManifestTests()
        executed: set[str] = set()
        for probe in probes:
            probe_id = probe["probe_id"]
            if probe_id == "ingress-snapshot":
                artifact_probe.test_ingress_mappings_are_snapshotted_once_before_validation(executed)
            elif probe_id == "identity-independence":
                artifact_probe.run_case("prd", "REVIEW", executed)
            elif probe_id == "reference-trace-closure":
                artifact_probe.run_case("prd", "INPUTS", executed)
                artifact_probe.run_case("prd", "TRACE", executed)
            elif probe_id == "lifecycle-evidence":
                artifact_probe.test_lifecycle_transition_emits_digest_bound_audit_event(executed)
                artifact_probe.test_revision_requires_closed_predecessor_and_binds_changed_body(executed)
            elif probe_id == "manifest-resource-boundaries":
                manifest_probe.test_manifest_raw_result_temporary_and_budget_boundaries_fail_closed(executed)
            elif probe_id == "manifest-minimal-invalidation":
                manifest_probe.test_manifest_binding_fields_and_unselected_gap_invalidate_minimally(executed)
            else:
                self.fail(f"unhandled mutation probe: {probe_id}")
        self.assertEqual(coverage_findings(manifest, executed), [])
        self.assertEqual(executed, REQUIRED_MUTATIONS)

        unimplemented = copy.deepcopy(manifest)
        unimplemented["probes"][0]["subcases"].append("unimplemented-sentinel")
        self.assertEqual(
            coverage_findings(unimplemented, executed),
            ["DECLARED_EXECUTION_MISMATCH"],
        )
