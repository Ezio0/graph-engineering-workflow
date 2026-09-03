from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
import source_manifest  # noqa: E402


EXPECTED_DEPENDENCIES = [("WP-05", 2), ("WP-06", 3), ("WP-07", 3), ("WP-07A", 6)]


def validate(gate: dict[str, object]) -> list[str]:
    findings: list[str] = []
    dependencies = gate.get("dependencies")
    if (
        not isinstance(dependencies, list)
        or [(item.get("work_package"), item.get("revision")) for item in dependencies]
        != EXPECTED_DEPENDENCIES
    ):
        findings.append("DEPENDENCY_SET_MISMATCH")
    try:
        stable = evidence_utils.wp08a_test_bindings(gate)
    except ValueError:
        findings.append("STABLE_BINDING_MISMATCH")
    else:
        if (
            len(stable) != 32
            or [item["test_id"] for item in stable]
            != [f"GEW-EXT-{number:03d}" for number in range(1, 33)]
            or len({item["qualified_test"] for item in stable}) != 32
        ):
            findings.append("STABLE_BINDING_MISMATCH")
    try:
        supplemental = evidence_utils.wp08a_supplemental_test_bindings(gate)
    except ValueError:
        findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    else:
        if len(supplemental) != 12 or len({item["qualified_test"] for item in supplemental}) != 12:
            findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    try:
        remedies = evidence_utils.wp08a_reviewer_remedy_test_bindings(gate)
    except ValueError:
        findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    else:
        if (
            len(remedies) != 20
            or {item["finding_id"] for item in remedies}
            != {
                "WP08A-QR-R1-001", "WP08A-QR-R1-002", "WP08A-QR-R1-003",
                "WP08A-QR-R1-004", "WP08A-QR-R1-005", "WP08A-QR-R1-006",
                "WP08A-QR-R1-007", "WP08A-QR-R3-008",
                "WP08A-CODE-R4-009",
            }
        ):
            findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    evidence = gate.get("evidence_test_bindings")
    if (
        not isinstance(evidence, list) or len(evidence) != 3
        or {item.get("test_id") for item in evidence if isinstance(item, dict)}
        != {"GEW-WP-08A-EXIT-P", "GEW-WP-08A-EXIT-R", "GEW-WP-08A-DEPENDENCY-R"}
    ):
        findings.append("EVIDENCE_BINDING_MISMATCH")
    sources = gate.get("source_paths")
    if (
        not isinstance(sources, list) or sources != sorted(sources)
        or len(sources) != 150 or len(sources) != len(set(sources))
        or gate.get("newly_targeted_file_count") != 123
        or gate.get("changed_targeted_file_count") != 27
        or gate.get("source_path_count") != 150
    ):
        findings.append("SOURCE_SET_MISMATCH")
    try:
        evidence_utils.wp08a_runtime(gate)
    except ValueError:
        findings.append("RUNTIME_PIN_MISMATCH")
    try:
        evidence_utils.wp08a_runtime_dependencies(gate)
    except ValueError:
        findings.append("RUNTIME_DEPENDENCY_MISMATCH")
    try:
        evidence_utils.wp08a_external_action_boundary(gate)
    except ValueError:
        findings.append("EXTERNAL_ACTION_BOUNDARY_MISMATCH")
    try:
        evidence_utils.wp08a_candidate_identities(gate)
    except ValueError:
        findings.append("CANDIDATE_IDENTITY_MISMATCH")
    try:
        evidence_utils.wp08a_governing_documents(gate)
    except ValueError:
        findings.append("GOVERNING_DOCUMENT_SET_MISMATCH")
    try:
        evidence_utils.wp08a_source_records(gate, source_manifest.create_manifest())
    except ValueError:
        findings.append("SOURCE_TARGETING_MISMATCH")
    commands = gate.get("commands")
    if (
        not isinstance(commands, list) or len(commands) != 6
        or [item.get("id") for item in commands if isinstance(item, dict)] != [
            "GEW-WP-08A-LINT-P", "GEW-WP-08A-TYPE-P",
            "GEW-WP-08A-ARCHITECTURE-P", "GEW-WP-08A-TEST-P",
            "GEW-WP-08A-BUILD-P", "GEW-WP-08A-REPRODUCIBILITY-P",
        ]
        or any("--" in arg for item in commands if isinstance(item, dict) for arg in item.get("argv", []))
    ):
        findings.append("COMMAND_SET_MISMATCH")
    if (
        gate.get("minimum_passed_test_count") != 911
        or gate.get("expected_test_execution_count") != 915
    ):
        findings.append("TEST_COUNT_MISMATCH")
    return findings


class WP08AGateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = json.loads((ROOT / "config/verification/wp-08a-gate.json").read_text())

    def test_gate_has_exact_extension_dependency_source_and_boundary_contract(self) -> None:
        self.assertEqual(validate(self.gate), [])
        runtime = evidence_utils.wp08a_runtime(self.gate)
        self.assertEqual(len(runtime["inputs"]), 32)
        self.assertEqual(runtime["schema_count"], 76)
        self.assertEqual(runtime["runtime_source_count"], 20)
        self.assertEqual(runtime["configuration_count"], 12)
        boundary = evidence_utils.wp08a_external_action_boundary(self.gate)
        self.assertEqual(boundary["trust_plane"], "offline-only")
        self.assertEqual(boundary["data_only_extension_status"], "local-data-only-active")
        self.assertIn("blocked", boundary["non_builtin_executable_status"])
        self.assertIn("wp10", boundary["formal_release_status"])

    def test_binding_runtime_boundary_dependency_source_and_command_mutations_are_rejected(self) -> None:
        mutations: list[tuple[dict[str, object], str]] = []
        stable = copy.deepcopy(self.gate)
        stable["binding_groups"][-1]["end"] = 31
        mutations.append((stable, "STABLE_BINDING_MISMATCH"))
        supplemental = copy.deepcopy(self.gate)
        supplemental["supplemental_test_bindings"].pop()
        mutations.append((supplemental, "SUPPLEMENTAL_BINDING_MISMATCH"))
        remedy = copy.deepcopy(self.gate)
        remedy["reviewer_remedy_bindings"][0]["qualified_tests"].pop()
        mutations.append((remedy, "REVIEWER_REMEDY_BINDING_MISMATCH"))
        runtime = copy.deepcopy(self.gate)
        runtime["runtime_pins"][0]["sha256"] = "0" * 64
        mutations.append((runtime, "RUNTIME_PIN_MISMATCH"))
        runtime_dependency = copy.deepcopy(self.gate)
        runtime_dependency["dependency_boundary"]["formal_release_status"] = "active"
        mutations.append((runtime_dependency, "RUNTIME_DEPENDENCY_MISMATCH"))
        boundary = copy.deepcopy(self.gate)
        boundary["external_action_boundary"]["network_enabled"] = True
        mutations.append((boundary, "EXTERNAL_ACTION_BOUNDARY_MISMATCH"))
        identity = copy.deepcopy(self.gate)
        identity["designated_reviewer_id"] = identity["candidate_author_id"]
        mutations.append((identity, "CANDIDATE_IDENTITY_MISMATCH"))
        dependency = copy.deepcopy(self.gate)
        dependency["dependencies"].pop()
        mutations.append((dependency, "DEPENDENCY_SET_MISMATCH"))
        source = copy.deepcopy(self.gate)
        source["source_paths"].append(source["source_paths"][0])
        mutations.append((source, "SOURCE_SET_MISMATCH"))
        commands = copy.deepcopy(self.gate)
        commands["commands"][3]["argv"].append("--filtered")
        mutations.append((commands, "COMMAND_SET_MISMATCH"))
        count = copy.deepcopy(self.gate)
        count["expected_test_execution_count"] = 914
        mutations.append((count, "TEST_COUNT_MISMATCH"))
        for candidate, finding in mutations:
            with self.subTest(finding=finding):
                self.assertIn(finding, validate(candidate))


if __name__ == "__main__":
    unittest.main()
