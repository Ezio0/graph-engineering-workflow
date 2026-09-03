from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
REQUIRED = {
    "GEW-ADR2-CONNECTION-P", "GEW-ADR2-CONNECTION-R", "GEW-ADR2-DOCTOR-P",
    "GEW-REP-001-P", "GEW-REP-001-R",
    "GEW-ADR2-TRANSACTION-P", "GEW-ADR2-TRANSACTION-R", "GEW-REP-061-P", "GEW-REP-061-R",
    "GEW-REQ-FR03-P", "GEW-ADR2-OBJECT-P", "GEW-ADR2-OBJECT-R",
    "GEW-ADR2-OBJECT-MUTATION-R", "GEW-ADR2-OBJECT-ANCESTOR-R",
    "GEW-ADR2-OBJECT-PUBLICATION-R",
    "GEW-ADR2-OBJECT-DEDUP-R",
    "GEW-ADR2-OBJECT-CLEANUP-ISOLATION-R",
    "GEW-ADR2-OBJECT-LOCK-COMPOSITION-P",
    "GEW-DUR-OBJECT-FILE-P",
    "GEW-DUR-GC-PURGE-R", "GEW-ADR2-LEASE-P", "GEW-ADR2-LEASE-R", "GEW-ADR2-CLOCK-R",
    "GEW-ADR2-CLAIM-P",
    "GEW-ADR2-CLAIM-R", "GEW-REP-CHAIN-R",
    "GEW-ADR2-LOCK-P", "GEW-ADR2-LOCK-R", "GEW-ADR2-LOCK-SEQUENCE-R",
    "GEW-ADR2-LOCK-ANCESTOR-R",
    "GEW-LOC-001-P", "GEW-LOC-001-R",
    "GEW-DUR-SCHEDULE-R", "GEW-DUR-MATRIX-P", "GEW-WP-03-EXIT-P", "GEW-WP-03-EXIT-R",
    "GEW-WP-03-DEPENDENCY-R",
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


class WP03GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-03-gate.json").read_text()
        )

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
