from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
EXPECTED_DEPENDENCIES = [("WP-05", 2), ("WP-06", 3), ("WP-07", 3)]


def frozen_source_manifest() -> dict[str, object]:
    return json.loads(
        (ROOT / ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07a-source-manifest-r6.json")
        .read_text()
    )


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
        stable = evidence_utils.wp07a_test_bindings(gate)
    except ValueError:
        findings.append("STABLE_BINDING_MISMATCH")
    else:
        if (
            len(stable) != 10
            or [item["test_id"] for item in stable]
            != [f"GEW-ACT-{number:03d}" for number in range(1, 11)]
            or len({item["qualified_test"] for item in stable}) != 10
        ):
            findings.append("STABLE_BINDING_MISMATCH")
    try:
        supplemental = evidence_utils.wp07a_supplemental_test_bindings(gate)
    except ValueError:
        findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    else:
        if len(supplemental) != 28 or len({item["qualified_test"] for item in supplemental}) != 28:
            findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    try:
        remedies = evidence_utils.wp07a_reviewer_remedy_test_bindings(gate)
    except ValueError:
        findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    else:
        if (
            len(remedies) != 12
            or {item["finding_id"] for item in remedies}
            != {f"WP07A-CODE-R1-{number:03d}" for number in range(1, 6)}
        ):
            findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    e2e = gate.get("real_e2e_test_bindings")
    if (
        not isinstance(e2e, list) or len(e2e) != 2
        or {item.get("test_id") for item in e2e if isinstance(item, dict)}
        != {"GEW-WP-07A-REAL-E2E-P", "GEW-WP-07A-ZERO-SIDE-EFFECT-R"}
    ):
        findings.append("REAL_E2E_BINDING_MISMATCH")
    evidence = gate.get("evidence_test_bindings")
    if (
        not isinstance(evidence, list) or len(evidence) != 3
        or {item.get("test_id") for item in evidence if isinstance(item, dict)}
        != {"GEW-WP-07A-EXIT-P", "GEW-WP-07A-EXIT-R", "GEW-WP-07A-DEPENDENCY-R"}
    ):
        findings.append("EVIDENCE_BINDING_MISMATCH")
    sources = gate.get("source_paths")
    if (
        not isinstance(sources, list) or sources != sorted(sources)
        or len(sources) != 69 or len(sources) != len(set(sources))
    ):
        findings.append("SOURCE_SET_MISMATCH")
    try:
        evidence_utils.wp07a_frozen_runtime(gate)
    except ValueError:
        findings.append("RUNTIME_PIN_MISMATCH")
    try:
        evidence_utils.wp07a_external_action_boundary(gate)
    except ValueError:
        findings.append("EXTERNAL_ACTION_BOUNDARY_MISMATCH")
    try:
        evidence_utils.wp07a_candidate_identities(gate)
    except ValueError:
        findings.append("CANDIDATE_IDENTITY_MISMATCH")
    try:
        evidence_utils.wp07a_frozen_governing_documents(gate)
    except ValueError:
        findings.append("GOVERNING_DOCUMENT_SET_MISMATCH")
    try:
        evidence_utils.wp07a_source_records(gate, frozen_source_manifest())
    except ValueError:
        findings.append("SOURCE_TARGETING_MISMATCH")
    commands = gate.get("commands")
    if (
        not isinstance(commands, list) or len(commands) != 6
        or [item.get("id") for item in commands if isinstance(item, dict)] != [
            "GEW-WP-07A-LINT-P", "GEW-WP-07A-TYPE-P",
            "GEW-WP-07A-ARCHITECTURE-P", "GEW-WP-07A-TEST-P",
            "GEW-WP-07A-BUILD-P", "GEW-WP-07A-REPRODUCIBILITY-P",
        ]
        or any("--" in arg for item in commands if isinstance(item, dict) for arg in item.get("argv", []))
    ):
        findings.append("COMMAND_SET_MISMATCH")
    if (
        gate.get("minimum_passed_test_count") != 843
        or gate.get("expected_test_execution_count") != 847
    ):
        findings.append("TEST_COUNT_MISMATCH")
    return findings


class WP07AGateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = json.loads((ROOT / "config/verification/wp-07a-gate.json").read_text())

    def test_gate_has_exact_action_runtime_dependency_source_and_boundary_contract(self) -> None:
        self.assertEqual(validate(self.gate), [])
        current = {record["path"] for record in frozen_source_manifest()["files"]}
        predecessor = json.loads((ROOT / ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07-source-manifest-r3.json").read_text())
        old = {record["path"] for record in predecessor["files"]}
        evidence_infra = {
            "config/verification/wp-07a-gate.json",
            "scripts/collect_wp07a_evidence.py",
            "scripts/run_wp07a_gate.py",
            "scripts/verify_wp07a_evidence.py",
            "tests/contract/test_wp07a_evidence_contract.py",
            "tests/contract/test_wp07a_gate_contract.py",
        }
        newly_targeted = current - old - evidence_infra
        self.assertEqual(len(newly_targeted), self.gate["newly_targeted_file_count"])
        self.assertEqual(self.gate["newly_targeted_file_count"], 40)
        self.assertTrue(newly_targeted.issubset(set(self.gate["source_paths"])))
        runtime = evidence_utils.wp07a_frozen_runtime(self.gate)
        self.assertEqual(len(runtime["inputs"]), 33)
        self.assertEqual(runtime["schema_count"], 16)
        self.assertEqual(len(runtime["adapter_ids"]), 5)
        self.assertTrue(runtime["command_registry_closed"])
        self.assertTrue(runtime["secret_provider_registry_closed"])

    def test_binding_runtime_boundary_dependency_source_and_command_mutations_are_rejected(self) -> None:
        mutations: list[tuple[dict[str, object], str]] = []
        stable = copy.deepcopy(self.gate)
        stable["binding_groups"][-1]["end"] = 9
        mutations.append((stable, "STABLE_BINDING_MISMATCH"))
        supplemental = copy.deepcopy(self.gate)
        supplemental["supplemental_test_bindings"].pop()
        mutations.append((supplemental, "SUPPLEMENTAL_BINDING_MISMATCH"))
        remedy = copy.deepcopy(self.gate)
        remedy["reviewer_remedy_bindings"][1]["qualified_tests"].pop()
        mutations.append((remedy, "REVIEWER_REMEDY_BINDING_MISMATCH"))
        e2e = copy.deepcopy(self.gate)
        e2e["real_e2e_test_bindings"].pop()
        mutations.append((e2e, "REAL_E2E_BINDING_MISMATCH"))
        runtime = copy.deepcopy(self.gate)
        runtime["runtime_pins"][0]["sha256"] = "0" * 64
        mutations.append((runtime, "RUNTIME_PIN_MISMATCH"))
        boundary = copy.deepcopy(self.gate)
        boundary["external_action_boundary"]["network_enabled"] = True
        mutations.append((boundary, "EXTERNAL_ACTION_BOUNDARY_MISMATCH"))
        identity = copy.deepcopy(self.gate)
        identity["designated_reviewer_id"] = "codex:/root/wp06_reviewer_r2"
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
        count["expected_test_execution_count"] = 841
        mutations.append((count, "TEST_COUNT_MISMATCH"))
        for candidate, finding in mutations:
            with self.subTest(finding=finding):
                self.assertIn(finding, validate(candidate))


if __name__ == "__main__":
    unittest.main()
