from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIRED = {
    f"GEW-ADR3-{suffix}-{outcome}"
    for suffix in ("SCHEMA", "REF", "JCS", "DIGEST", "MODEL", "GEEL", "BUDGET", "EXEC", "VERSION")
    for outcome in ("P", "R")
} | {
    "GEW-ADR3-SCHEMA-FROZEN-R", "GEW-REQ-FR12-P", "GEW-REQ-FR12-R",
    "GEW-WP-01-EXIT-P", "GEW-WP-01-EXIT-R",
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
    if len(ids) != len(set(ids)) or len(qualified) != len(set(qualified)) or any(not value for value in qualified):
        findings.append("BINDING_NOT_ONE_TO_ONE")
    return findings


class WP01GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads((ROOT / "config" / "verification" / "wp-01-gate.json").read_text())

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
