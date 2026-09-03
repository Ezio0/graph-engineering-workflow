from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIRED = {
    "GEW-RUN-FINDING-STATE-P",
    "GEW-RUN-COMMAND-TRANSACTION-P",
    "GEW-RUN-LINEAGE-R",
    "GEW-RUN-RESUME-P",
    "GEW-RUN-DURABLE-REVIEW-RESUME-P",
    "GEW-RUN-NO-PROGRESS-R",
    "GEW-RUN-PASS-NO-PROGRESS-R",
    "GEW-RUN-PROGRESS-P",
    "GEW-RUN-INTERNAL-AUTHORITY-R",
    "GEW-RUN-AUTHORITY-STALE-R",
    "GEW-RUN-AUTHORITY-TASK-R",
    "GEW-RUN-AUTHORITY-SCOPE-R",
    "GEW-RUN-AUTHORITY-EVENT-R",
    "GEW-RUN-AUTHORITY-ONE-USE-R",
    "GEW-RUN-GRAPH-BINDING-R",
    "GEW-RUN-FAILURE-ROUTE-P",
    "GEW-RUN-COMPLETION-R",
    "GEW-WP-04-EXIT-P",
    "GEW-WP-04-EXIT-R",
    "GEW-WP-04-DEPENDENCY-R",
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


class WP04GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-04-gate.json").read_text()
        )

    def test_gate_has_exact_required_bindings_and_dependencies(self) -> None:
        self.assertEqual(validate(self.manifest), [])
        self.assertEqual(
            [(item["work_package"], item["revision"]) for item in self.manifest["dependencies"]],
            [("WP-02", 4), ("WP-03", 8), ("WP-04A", 5)],
        )

    def test_missing_or_duplicate_binding_is_rejected(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["test_bindings"].pop()
        self.assertIn("TEST_ID_SET_MISMATCH", validate(missing))
        duplicate = copy.deepcopy(self.manifest)
        duplicate["test_bindings"][0]["qualified_test"] = duplicate["test_bindings"][1]["qualified_test"]
        self.assertIn("BINDING_NOT_ONE_TO_ONE", validate(duplicate))


if __name__ == "__main__":
    unittest.main()
