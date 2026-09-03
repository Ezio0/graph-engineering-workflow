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


EXPECTED_DEPENDENCIES = [("WP-03", 8), ("WP-04", 3), ("WP-05A", 4), ("WP-05", 2)]
EXPECTED_EVIDENCE_IDS = {
    "GEW-WP-06-EXIT-P", "GEW-WP-06-EXIT-R", "GEW-WP-06-DEPENDENCY-R",
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
        bindings = evidence_utils.wp06_frozen_test_bindings(gate)
    except ValueError:
        findings.append("STABLE_BINDING_MISMATCH")
    else:
        ids = [item["test_id"] for item in bindings]
        qualified = [item["qualified_test"] for item in bindings]
        if (
            len(bindings) != 68
            or ids[:46] != [f"GEW-MIG-{number:03d}" for number in range(1, 47)]
            or ids[46:] != [f"GEW-LIF-{number:03d}" for number in range(1, 23)]
            or len(qualified) != len(set(qualified))
        ):
            findings.append("STABLE_BINDING_MISMATCH")
    try:
        remedy_bindings = evidence_utils.wp06_reviewer_remedy_test_bindings(gate)
    except ValueError:
        findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    else:
        if (
            len(remedy_bindings) != 7
            or {item["finding_id"] for item in remedy_bindings}
            != {
                "WP06-CODE-R1-001", "WP06-CODE-R1-002", "WP06-CODE-R1-006",
                "WP06-CODE-R1-007", "WP06-CODE-R1-008",
            }
            or len({item["qualified_test"] for item in remedy_bindings}) != 7
        ):
            findings.append("REVIEWER_REMEDY_BINDING_MISMATCH")
    sources = gate.get("source_paths")
    if (
        not isinstance(sources, list)
        or sources != sorted(sources)
        or len(sources) != len(set(sources))
        or not sources
    ):
        findings.append("SOURCE_SET_MISMATCH")
    try:
        evidence_utils.wp06_frozen_governing_documents(gate)
    except ValueError:
        findings.append("GOVERNING_DOCUMENT_SET_MISMATCH")
    try:
        evidence_utils.wp06_frozen_runtime(gate)
    except ValueError:
        findings.append("RUNTIME_PIN_MISMATCH")
    return findings


class WP06GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gate = json.loads(
            (ROOT / "config" / "verification" / "wp-06-gate.json").read_text()
        )

    def test_gate_has_exact_migration_lifecycle_runtime_and_dependencies(self) -> None:
        self.assertEqual(validate(self.gate), [])
        bindings = evidence_utils.wp06_frozen_test_bindings(self.gate)
        self.assertEqual(len(bindings), 68)
        self.assertEqual(sum(item["test_id"].startswith("GEW-MIG-") for item in bindings), 46)
        self.assertEqual(sum(item["test_id"].startswith("GEW-LIF-") for item in bindings), 22)
        runtime = evidence_utils.wp06_frozen_runtime(self.gate)
        self.assertEqual(runtime["migration_schedule_id"], "wp06-migration-fault-schedule-v2")
        self.assertEqual(
            runtime["migration_schedule_sha256"],
            "20b7095ec76b46b4fe392521f274942dcdeab7d8da33576eb7dbdaf219b9ef17",
        )
        self.assertEqual(len(runtime["migration_points"]), 51)
        self.assertEqual(len(runtime["process_crash_points"]), 31)
        self.assertEqual(len(runtime["concurrency_scenarios"]), 4)
        self.assertNotIn(
            "config/contracts/migration-fault-schedule-v1.json",
            [item["path"] for item in runtime["inputs"]],
        )

    def test_binding_dependency_source_document_and_runtime_mutations_are_rejected(self) -> None:
        binding = copy.deepcopy(self.gate)
        binding["binding_groups"][0]["end"] = 9
        self.assertIn("STABLE_BINDING_MISMATCH", validate(binding))
        dependency = copy.deepcopy(self.gate)
        dependency["dependencies"].pop()
        self.assertIn("DEPENDENCY_SET_MISMATCH", validate(dependency))
        source = copy.deepcopy(self.gate)
        source["source_paths"].append(source["source_paths"][0])
        self.assertIn("SOURCE_SET_MISMATCH", validate(source))
        governing = copy.deepcopy(self.gate)
        governing["governing_document_digests"][0]["sha256"] = "0" * 64
        self.assertIn("GOVERNING_DOCUMENT_SET_MISMATCH", validate(governing))
        runtime = copy.deepcopy(self.gate)
        runtime["runtime_pins"]["migration_fault_schedule"]["point_count"] = 50
        self.assertIn("RUNTIME_PIN_MISMATCH", validate(runtime))
        remedy = copy.deepcopy(self.gate)
        remedy["reviewer_remedy_bindings"][2]["qualified_tests"] = []
        self.assertIn("REVIEWER_REMEDY_BINDING_MISMATCH", validate(remedy))

        prefix = ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-06"
        frozen_paths = tuple(
            f"{prefix}-{kind}-r3.json"
            for kind in ("source-manifest", "command-evidence", "exit", "review-verdict")
        )
        with tempfile.TemporaryDirectory(prefix="gew-wp06-frozen-") as directory:
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
                evidence_utils.wp06_frozen_governing_documents(
                    coordinated_gate,
                    root=frozen_root,
                )


if __name__ == "__main__":
    unittest.main()
