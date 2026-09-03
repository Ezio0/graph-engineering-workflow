from __future__ import annotations

import copy
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MATRIX_IDS = {
    *(f"GEW-SEC-{number:03d}" for number in range(1, 121)),
    *(f"GEW-PRI-{number:03d}" for number in range(1, 81)),
}
EXTRA_IDS = {
    "GEW-WP-05A-SCHEMA-P", "GEW-WP-05A-POLICY-R", "GEW-WP-05A-REGISTRY-R",
    "GEW-WP-05A-IDENTITY-P", "GEW-WP-05A-IDENTITY-R", "GEW-WP-05A-PATH-R",
    "GEW-WP-05A-COMMAND-R", "GEW-WP-05A-PROMPT-R", "GEW-WP-05A-SECRET-P",
    "GEW-WP-05A-REDACTION-P", "GEW-WP-05A-REDACTION-R", "GEW-WP-05A-INCIDENT-P",
    "GEW-WP-05A-DISCLOSURE-P", "GEW-WP-05A-DISCLOSURE-R", "GEW-WP-05A-EVIDENCE-P",
    "GEW-WP-05A-EVIDENCE-R", "GEW-WP-05A-QUARANTINE-P", "GEW-WP-05A-RETENTION-P",
    "GEW-WP-05A-RETENTION-R", "GEW-WP-05A-EXTENSION-R", "GEW-WP-05A-PERMISSION-P",
    "GEW-WP-05A-OBJECT-QUARANTINE-P", "GEW-WP-05A-EXIT-P", "GEW-WP-05A-EXIT-R",
    "GEW-WP-05A-DEPENDENCY-R",
    "GEW-WP-05A-R1-001-RUNTIME-R", "GEW-WP-05A-R1-001-POLICY-R",
    "GEW-WP-05A-R1-002-EVIDENCE-R", "GEW-WP-05A-R1-003-DESTINATION-R",
    "GEW-WP-05A-R1-004-STATE-R", "GEW-WP-05A-R1-004-REVALIDATE-R",
    "GEW-WP-05A-R1-005-RESOURCE-R",
    "GEW-WP-05A-R2-001-RAW-ISSUER-R", "GEW-WP-05A-R2-001-DURABLE-IDENTITY-P",
    "GEW-WP-05A-R2-001-INSTALLED-R",
    "GEW-WP-05A-R2-001-INSTALL-PIN-R", "GEW-WP-05A-R2-001-STATE-TAMPER-R",
    "GEW-WP-05A-R2-002-JOURNAL-R", "GEW-WP-05A-R2-003-ONE-USE-R",
    "GEW-WP-05A-R2-003-CLAIM-R",
    "GEW-WP-05A-R3-001-RUNTIME-DEPTH-R", "GEW-WP-05A-R3-001-STATE-DEPTH-R",
    "GEW-WP-05A-R3-001-JOURNAL-DEPTH-R",
}
REQUIRED = MATRIX_IDS | EXTRA_IDS


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
    dependencies = manifest.get("dependencies")
    if not isinstance(dependencies, list) or [item.get("work_package") for item in dependencies] != ["WP-01", "WP-03"]:
        findings.append("DEPENDENCY_SET_MISMATCH")
    return findings


class WP05AGateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-05a-gate.json").read_text()
        )

    def test_gate_has_exact_security_privacy_bindings_and_dependencies(self) -> None:
        self.assertEqual(validate(self.manifest), [])
        self.assertEqual(len(MATRIX_IDS), 200)
        self.assertEqual(len(REQUIRED), 243)

    def test_missing_duplicate_or_dependency_change_is_rejected(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["test_bindings"].pop()
        self.assertIn("TEST_ID_SET_MISMATCH", validate(missing))
        duplicate = copy.deepcopy(self.manifest)
        duplicate["test_bindings"][0]["qualified_test"] = duplicate["test_bindings"][1]["qualified_test"]
        self.assertIn("BINDING_NOT_ONE_TO_ONE", validate(duplicate))
        dependency = copy.deepcopy(self.manifest)
        dependency["dependencies"].pop()
        self.assertIn("DEPENDENCY_SET_MISMATCH", validate(dependency))


if __name__ == "__main__":
    unittest.main()
