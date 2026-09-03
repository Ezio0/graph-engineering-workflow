from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIRED = {
    f"GEW-{family}-{case}-{outcome}"
    for family, cases in (
        ("GRA", ("001", "002", "003", "004", "005", "006")),
        ("RED", ("001", "002", "003", "004")),
        ("RUN", ("001", "002")),
    )
    for case in cases
    for outcome in ("P", "R")
} | {
    "GEW-REQ-FR06-P", "GEW-REQ-FR06-R", "GEW-WP-02-SCHEMA-P", "GEW-WP-02-SCHEMA-R",
    "GEW-WP-02-EXIT-P", "GEW-WP-02-EXIT-R", "GEW-WP-02-DEPENDENCY-R",
}


def validate(manifest: dict[str, object]) -> list[str]:
    bindings = manifest.get("test_bindings")
    if not isinstance(bindings, list):
        return ["BINDINGS_MISSING"]
    ids = [binding.get("test_id") for binding in bindings if isinstance(binding, dict)]
    qualified = [binding.get("qualified_test") for binding in bindings if isinstance(binding, dict)]
    findings: list[str] = []
    if set(ids) != REQUIRED:
        findings.append("TEST_ID_SET_MISMATCH")
    if len(ids) != len(set(ids)) or len(qualified) != len(set(qualified)) or any(not item for item in qualified):
        findings.append("BINDING_NOT_ONE_TO_ONE")
    return findings


class WP02GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((ROOT / "config" / "verification" / "wp-02-gate.json").read_text())

    def test_gate_has_exact_required_bindings(self) -> None:
        self.assertEqual(validate(self.manifest), [])

    def test_missing_or_duplicate_binding_is_rejected(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["test_bindings"].pop()
        self.assertIn("TEST_ID_SET_MISMATCH", validate(missing))
        duplicate = copy.deepcopy(self.manifest)
        duplicate["test_bindings"][0]["qualified_test"] = duplicate["test_bindings"][1]["qualified_test"]
        self.assertIn("BINDING_NOT_ONE_TO_ONE", validate(duplicate))


if __name__ == "__main__":
    unittest.main()
