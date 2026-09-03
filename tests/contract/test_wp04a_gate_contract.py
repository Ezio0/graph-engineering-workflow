from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ARTIFACT_TYPES = (
    "candidate-review", "completion-record", "impact", "implementation", "plan",
    "positioning", "prd", "tech-spec", "test-plan", "verification",
)
CASE_CODES = (
    "DIGEST", "EXIT", "FINDINGS", "GOLD", "INPUTS",
    "INVALIDATE", "REVIEW", "SEMANTICS", "STATUS", "TRACE",
)
REQUIRED = {
    f"GEW-ART-{artifact_type}-{case_code}"
    for artifact_type in ARTIFACT_TYPES
    for case_code in CASE_CODES
} | {
    "GEW-ART-MERGED-MANIFEST-GOLD",
    "GEW-ART-MERGED-SELECTOR-MISSING",
    "GEW-ART-MERGED-SELECTOR-AMBIGUOUS",
    "GEW-ART-MERGED-SELECTOR-OUT-OF-BOUNDS",
    "GEW-ART-MERGED-OVERLAP",
    "GEW-ART-MERGED-EXTRACTED-DIGEST",
    "GEW-ART-MERGED-INDEPENDENT-INVALIDATION",
    "GEW-ART-MERGED-SHARED-INVALIDATION",
    "GEW-ART-MERGED-REVIEW-BINDING",
    "GEW-ART-CONTRACT-REGISTRY-P",
    "GEW-ART-CONTRACT-REGISTRY-R",
    "GEW-ART-SCHEMA-P",
    "GEW-ART-SCHEMA-REQUIRED-R",
    "GEW-ART-DEPENDENCY-P",
    "GEW-ART-LIFECYCLE-P",
    "GEW-ART-COVERAGE-P",
    "GEW-ART-MUTATION-COVERAGE-R",
    "GEW-WP-04A-EXIT-P",
    "GEW-WP-04A-EXIT-R",
    "GEW-WP-04A-DEPENDENCY-R",
}


def validate(manifest: dict[str, object]) -> list[str]:
    bindings = manifest.get("test_bindings")
    if not isinstance(bindings, list):
        return ["BINDINGS_MISSING"]
    ids = [item.get("test_id") for item in bindings if isinstance(item, dict)]
    qualified = [item.get("qualified_test") for item in bindings if isinstance(item, dict)]
    findings = []
    if set(ids) != REQUIRED:
        findings.append("TEST_ID_SET_MISMATCH")
    if len(ids) != len(set(ids)) or len(qualified) != len(set(qualified)) or any(not item for item in qualified):
        findings.append("BINDING_NOT_ONE_TO_ONE")
    return findings


class WP04AGateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-04a-gate.json").read_text()
        )

    def test_gate_has_exact_required_bindings(self) -> None:
        self.assertEqual(validate(self.manifest), [])
        self.assertEqual(len(REQUIRED), 120)

    def test_missing_or_duplicate_binding_is_rejected(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["test_bindings"].pop()
        self.assertIn("TEST_ID_SET_MISMATCH", validate(missing))
        duplicate = copy.deepcopy(self.manifest)
        duplicate["test_bindings"][0]["qualified_test"] = duplicate["test_bindings"][1]["qualified_test"]
        self.assertIn("BINDING_NOT_ONE_TO_ONE", validate(duplicate))


if __name__ == "__main__":
    unittest.main()
