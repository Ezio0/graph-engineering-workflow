from __future__ import annotations

import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
import source_manifest  # noqa: E402


EXPECTED_DEPENDENCIES = [("WP-05", 2), ("WP-06", 3)]
EXPECTED_EVIDENCE_IDS = {
    "GEW-WP-07-EXIT-P", "GEW-WP-07-EXIT-R", "GEW-WP-07-DEPENDENCY-R",
}


def validate(gate: dict[str, object]) -> list[str]:
    findings: list[str] = []
    dependencies = gate.get("dependencies")
    if (
        not isinstance(dependencies, list)
        or [(item.get("work_package"), item.get("revision")) for item in dependencies]
        != EXPECTED_DEPENDENCIES
    ):
        findings.append("DEPENDENCY_SET_MISMATCH")
    evidence_bindings = gate.get("evidence_test_bindings")
    if not isinstance(evidence_bindings, list):
        findings.append("EVIDENCE_BINDING_MISMATCH")
    else:
        ids = [item.get("test_id") for item in evidence_bindings if isinstance(item, dict)]
        qualified = [item.get("qualified_test") for item in evidence_bindings if isinstance(item, dict)]
        if (
            set(ids) != EXPECTED_EVIDENCE_IDS
            or len(ids) != len(set(ids))
            or len(qualified) != len(set(qualified))
            or any(not item for item in qualified)
        ):
            findings.append("EVIDENCE_BINDING_MISMATCH")
    try:
        stable = evidence_utils.wp07_frozen_test_bindings(gate)
    except ValueError:
        findings.append("STABLE_BINDING_MISMATCH")
    else:
        if (
            len(stable) != 45
            or [item["test_id"] for item in stable]
            != [f"GEW-RT-{number:03d}" for number in range(1, 46)]
            or len({item["qualified_test"] for item in stable}) != 45
        ):
            findings.append("STABLE_BINDING_MISMATCH")
    try:
        supplemental = evidence_utils.wp07_supplemental_test_bindings(gate)
    except ValueError:
        findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    else:
        if [item["test_id"] for item in supplemental] != [
            "GEW-RT-022A", "GEW-RT-025A", "GEW-RT-044A",
        ]:
            findings.append("SUPPLEMENTAL_BINDING_MISMATCH")
    try:
        skills = evidence_utils.wp07_required_skill_test_bindings(gate)
    except ValueError:
        findings.append("SKILL_BINDING_MISMATCH")
    else:
        if [item["test_id"] for item in skills] != [
            "GEW-WP-07-SKILL-QUICK-P", "GEW-WP-07-ISOLATED-WHEEL-P",
            "GEW-WP-07-ISOLATED-FULL-FLOW-P",
        ]:
            findings.append("SKILL_BINDING_MISMATCH")
    try:
        remedies = evidence_utils.wp07_reviewer_remedy_test_bindings(gate)
    except ValueError:
        findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    else:
        if (
            len(remedies) != 15
            or {item["finding_id"] for item in remedies}
            != {f"WP07-CODE-R1-{number:03d}" for number in range(1, 9)}
            or len({item["qualified_test"] for item in remedies}) != 15
        ):
            findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    sources = gate.get("source_paths")
    if (
        not isinstance(sources, list) or sources != sorted(sources)
        or len(sources) != len(set(sources)) or len(sources) != 42
    ):
        findings.append("SOURCE_SET_MISMATCH")
    commands = gate.get("commands")
    if (
        not isinstance(commands, list) or len(commands) != 6
        or [item.get("id") for item in commands if isinstance(item, dict)] != [
            "GEW-WP-07-LINT-P", "GEW-WP-07-TYPE-P", "GEW-WP-07-ARCHITECTURE-P",
            "GEW-WP-07-TEST-P", "GEW-WP-07-BUILD-P", "GEW-WP-07-REPRODUCIBILITY-P",
        ]
        or any("--" in arg for item in commands if isinstance(item, dict) for arg in item.get("argv", []))
    ):
        findings.append("COMMAND_SET_MISMATCH")
    if (
        gate.get("minimum_passed_test_count") != 800
        or gate.get("expected_test_execution_count") != 804
    ):
        findings.append("TEST_COUNT_MISMATCH")
    try:
        evidence_utils.wp07_frozen_governing_documents(gate)
    except ValueError:
        findings.append("GOVERNING_DOCUMENT_SET_MISMATCH")
    try:
        evidence_utils.wp07_frozen_runtime(gate)
    except ValueError:
        findings.append("RUNTIME_PIN_MISMATCH")
    try:
        evidence_utils.wp07_source_records(gate, source_manifest.create_manifest())
    except ValueError:
        findings.append("SOURCE_TARGETING_MISMATCH")
    return findings


class WP07GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = json.loads(
            (ROOT / "config" / "verification" / "wp-07-gate.json").read_text()
        )

    def test_gate_has_exact_runtime_skill_remedy_dependency_and_source_contract(self) -> None:
        self.assertEqual(validate(self.gate), [])
        runtime = evidence_utils.wp07_frozen_runtime(self.gate)
        self.assertEqual(runtime["fixture"]["cell_ids"], [
            "codex-native", "hermes-telegram", "hermes-discord",
        ])
        self.assertEqual(len(runtime["skill_assets"]), 4)
        self.assertEqual(len(runtime["configuration_contract"]["configuration_fields"]), 28)
        self.assertEqual(len(runtime["configuration_contract"]["runtime_input_fields"]), 5)
        self.assertEqual(len(runtime["configuration_contract"]["capability_fields"]), 23)
        self.assertEqual(
            runtime["runtime_resource_policy"]["policy_id"],
            "urn:gew:runtime-resource-policy:default:1.0.0",
        )
        self.assertEqual(
            runtime["runtime_local_port_policy"]["policy_digest"],
            "sha256-jcs-v1:e6a529519a011ca5fb7cabe81cd8697c961f937b3488e770d79cb58a742b440f",
        )

    def test_all_binding_dependency_source_document_runtime_and_command_mutations_are_rejected(self) -> None:
        mutations = []
        stable = copy.deepcopy(self.gate)
        stable["binding_groups"][-1]["end"] = 44
        mutations.append((stable, "STABLE_BINDING_MISMATCH"))
        supplemental = copy.deepcopy(self.gate)
        supplemental["supplemental_test_bindings"].pop()
        mutations.append((supplemental, "SUPPLEMENTAL_BINDING_MISMATCH"))
        skill = copy.deepcopy(self.gate)
        skill["required_skill_test_bindings"].pop()
        mutations.append((skill, "SKILL_BINDING_MISMATCH"))
        per_turn_remedy = copy.deepcopy(self.gate)
        per_turn_remedy["reviewer_remedy_bindings"][0]["qualified_tests"].pop()
        mutations.append((per_turn_remedy, "REVIEWER_REMEDY_BINDING_MISMATCH"))
        attestation_remedy = copy.deepcopy(self.gate)
        attestation_remedy["reviewer_remedy_bindings"][5]["qualified_tests"].pop()
        mutations.append((attestation_remedy, "REVIEWER_REMEDY_BINDING_MISMATCH"))
        dependency = copy.deepcopy(self.gate)
        dependency["dependencies"].pop()
        mutations.append((dependency, "DEPENDENCY_SET_MISMATCH"))
        source = copy.deepcopy(self.gate)
        source["source_paths"].append(source["source_paths"][0])
        mutations.append((source, "SOURCE_SET_MISMATCH"))
        governing = copy.deepcopy(self.gate)
        governing["governing_document_digests"][8]["sha256"] = "0" * 64
        mutations.append((governing, "GOVERNING_DOCUMENT_SET_MISMATCH"))
        runtime = copy.deepcopy(self.gate)
        runtime["runtime_pins"]["runtime_resource_policy"]["max_depth"] = 63
        mutations.append((runtime, "RUNTIME_PIN_MISMATCH"))
        local_ports = copy.deepcopy(self.gate)
        local_ports["runtime_pins"]["runtime_local_port_policy"]["human_status"] = "succeeded"
        mutations.append((local_ports, "RUNTIME_PIN_MISMATCH"))
        commands = copy.deepcopy(self.gate)
        commands["commands"][3]["argv"].append("--filtered")
        mutations.append((commands, "COMMAND_SET_MISMATCH"))
        for candidate, finding in mutations:
            with self.subTest(finding=finding):
                self.assertIn(finding, validate(candidate))

        prefix = ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-07"
        frozen_paths = tuple(
            f"{prefix}-{kind}-r3.json"
            for kind in ("source-manifest", "command-evidence", "exit", "review-verdict")
        )
        with tempfile.TemporaryDirectory(prefix="gew-wp07-frozen-") as directory:
            frozen_root = pathlib.Path(directory)
            for relative in frozen_paths:
                target = frozen_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            coordinated_gate = copy.deepcopy(self.gate)
            command_path = frozen_root / frozen_paths[1]
            exit_path = frozen_root / frozen_paths[2]
            verdict_path = frozen_root / frozen_paths[3]
            command = json.loads(command_path.read_text(encoding="utf-8"))
            exit_record = json.loads(exit_path.read_text(encoding="utf-8"))
            verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            command["governing_documents"][0]["sha256"] = "0" * 64
            coordinated_gate["governing_document_digests"][0]["sha256"] = "0" * 64
            command_digest = evidence_utils.digest(evidence_utils.canonical_bytes(command))
            documents_digest = evidence_utils.governing_documents_digest(
                command["governing_documents"]
            )
            exit_record["command_evidence_digest"] = command_digest
            exit_record["governing_documents_digest"] = documents_digest
            verdict["command_evidence_digest"] = command_digest
            verdict["governing_documents_digest"] = documents_digest
            verdict["candidate_exit_digest"] = evidence_utils.digest(
                evidence_utils.canonical_bytes(exit_record)
            )
            command_path.write_text(json.dumps(command), encoding="utf-8")
            exit_path.write_text(json.dumps(exit_record), encoding="utf-8")
            verdict_path.write_text(json.dumps(verdict), encoding="utf-8")
            with self.assertRaises(ValueError):
                evidence_utils.wp07_frozen_governing_documents(
                    coordinated_gate,
                    root=frozen_root,
                )


if __name__ == "__main__":
    unittest.main()
