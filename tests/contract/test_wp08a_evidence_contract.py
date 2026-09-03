from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import platform
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
import source_manifest  # noqa: E402
import verify_wp08a_evidence  # noqa: E402


class WP08AEvidenceContractTests(unittest.TestCase):
    def valid(self) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config/verification/wp-08a-gate.json").read_text())
        stable = evidence_utils.wp08a_test_bindings(gate)
        supplemental = evidence_utils.wp08a_supplemental_test_bindings(gate)
        remedies = evidence_utils.wp08a_reviewer_remedy_test_bindings(gate)
        evidence_bindings = gate["evidence_test_bindings"]
        qualified = {
            binding["qualified_test"]
            for binding in stable + supplemental + remedies + evidence_bindings
        }
        index = 0
        while len(qualified) < gate["expected_test_execution_count"]:
            qualified.add(f"test_wp08a_evidence_fixture.FillerTests.test_pass_{index:04d}")
            index += 1
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-08A-TEST-P":
                outcome["tests"] = [
                    {"id": test_id, "status": "PASS"} for test_id in sorted(qualified)
                ]
                outcome["test_count"] = len(qualified)
                outcome["suite_count"] = 6
            commands.append({
                "test_id": command["id"],
                "argv": evidence_utils.expand_argv(command),
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        documents = evidence_utils.wp08a_governing_documents(gate)
        self.runtime = evidence_utils.wp08a_runtime(gate)
        self.runtime_dependencies = evidence_utils.wp08a_runtime_dependencies(gate)
        self.boundary = evidence_utils.wp08a_external_action_boundary(gate)
        self.identities = evidence_utils.wp08a_candidate_identities(gate)
        self.dependencies = [
            {
                "work_package": package, "revision": revision,
                "source_manifest_path": f"records/{package}-source.json",
                "source_manifest_digest": str(item) * 64,
                "command_evidence_path": f"records/{package}-commands.json",
                "command_evidence_digest": str(item + 1) * 64,
                "verdict_path": f"records/{package}-verdict.json",
                "verdict_digest": str(item + 2) * 64,
                "exit_path": f"records/{package}-exit.json",
                "exit_digest": str(item + 3) * 64,
                "reviewer_id": f"codex:/dependency-reviewer-{item}",
            }
            for item, (package, revision) in enumerate(
                (("WP-05", 2), ("WP-06", 3), ("WP-07", 3), ("WP-07A", 6)), start=1,
            )
        ]
        self.sources = evidence_utils.wp08a_source_records(gate, source)
        evidence: dict[str, object] = {
            "schema_version": "1.0", "status": "PASS",
            "source_manifest_digest": source["manifest_digest"],
            "wp08a_sources": self.sources,
            "interpreter": {
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "wp08a_runtime": self.runtime,
            "wp08a_runtime_dependencies": self.runtime_dependencies,
            "external_action_boundary": self.boundary,
            "candidate_identities": self.identities,
            "dependency_verdicts": self.dependencies,
            "commands": commands,
            "governing_documents": documents,
            "stable_test_bindings": stable,
            "supplemental_test_bindings": supplemental,
            "reviewer_remedy_test_bindings": remedies,
            "evidence_test_bindings": evidence_bindings,
            "passed_test_count": len(qualified),
            "test_execution_count": len(qualified),
            "wheel": {"filename": "unused", "sha256": "unused"},
            "real_external_actions_enabled": False,
        }
        exit_record: dict[str, object] = {
            "schema_version": "1.0", "artifact": "wp-08a", "status": "CANDIDATE",
            "author_id": self.identities["author_id"],
            "reviewer_id": self.identities["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp08a_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
            "wp08a_runtime_digest": verify_wp08a_evidence.canonical_digest(self.runtime),
            "wp08a_runtime_dependencies_digest": verify_wp08a_evidence.canonical_digest(
                self.runtime_dependencies
            ),
            "wp08a_sources_digest": verify_wp08a_evidence.canonical_digest(self.sources),
            "external_action_boundary_digest": verify_wp08a_evidence.canonical_digest(self.boundary),
            "dependency_verdicts_digest": verify_wp08a_evidence.canonical_digest(self.dependencies),
            "real_external_actions_enabled": False,
            "test_ids": ["GEW-WP-08A-EXIT-P", "GEW-WP-08A-EXIT-R"],
        }
        verdict: dict[str, object] = {
            "schema_version": "1.0", "artifact": "wp-08a", "verdict": "PASS",
            "scope_changed": False, "change_kinds": [],
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp08a_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp08a_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "wp08a_runtime_digest": exit_record["wp08a_runtime_digest"],
            "wp08a_runtime_dependencies_digest": exit_record["wp08a_runtime_dependencies_digest"],
            "wp08a_sources_digest": exit_record["wp08a_sources_digest"],
            "external_action_boundary_digest": exit_record["external_action_boundary_digest"],
            "dependency_verdicts_digest": exit_record["dependency_verdicts_digest"],
            "finding_dispositions": [{"finding_id": "WP08A-QR-R1-001", "status": "closed"}],
            "findings": [],
        }
        return source, evidence, exit_record, verdict

    def validate(self, *values: object) -> list[str]:
        with mock.patch.object(
            evidence_utils, "dependency_verdicts", return_value=self.dependencies,
        ):
            return verify_wp08a_evidence.validate(*values)  # type: ignore[arg-type]

    def test_valid_candidate_binding_passes(self) -> None:
        self.assertEqual(self.validate(*self.valid()), [])

    def test_source_command_runtime_dependency_boundary_document_and_review_mutations_fail(self) -> None:
        source, evidence, exit_record, verdict = self.valid()
        mutations = []
        changed_source = copy.deepcopy(source)
        changed_source["files"][0]["sha256"] = "0" * 64
        mutations.append((changed_source, evidence, exit_record, verdict, "SOURCE_MANIFEST_MISMATCH"))
        changed_command = copy.deepcopy(evidence)
        changed_command["commands"][0]["outcome"] = {"status": "PASS", "fabricated": True}
        mutations.append((source, changed_command, exit_record, verdict, "COMMAND_RECORD_MISMATCH"))
        changed_runtime = copy.deepcopy(evidence)
        changed_runtime["wp08a_runtime"]["schema_registry_id"] = "attacker"
        mutations.append((source, changed_runtime, exit_record, verdict, "WP08A_RUNTIME_MISMATCH"))
        changed_runtime_dependency = copy.deepcopy(evidence)
        changed_runtime_dependency["wp08a_runtime_dependencies"]["formal_release_status"] = "active"
        mutations.append((
            source, changed_runtime_dependency, exit_record, verdict,
            "WP08A_RUNTIME_DEPENDENCY_MISMATCH",
        ))
        changed_boundary = copy.deepcopy(evidence)
        changed_boundary["external_action_boundary"]["network_enabled"] = True
        mutations.append((
            source, changed_boundary, exit_record, verdict, "EXTERNAL_ACTION_BOUNDARY_MISMATCH",
        ))
        changed_sources = copy.deepcopy(evidence)
        changed_sources["wp08a_sources"].pop()
        mutations.append((source, changed_sources, exit_record, verdict, "WP08A_SOURCE_BINDING_MISMATCH"))
        changed_documents = copy.deepcopy(evidence)
        changed_documents["governing_documents"][11]["sha256"] = "0" * 64
        mutations.append((source, changed_documents, exit_record, verdict, "GOVERNING_DOCUMENT_MISMATCH"))
        changed_dependencies = copy.deepcopy(evidence)
        changed_dependencies["dependency_verdicts"] = []
        mutations.append((source, changed_dependencies, exit_record, verdict, "DEPENDENCY_VERDICT_MISMATCH"))
        missing_boundary_test = copy.deepcopy(evidence)
        tests = missing_boundary_test["commands"][3]["outcome"]["tests"]
        missing_boundary_test["commands"][3]["outcome"]["tests"] = [
            item for item in tests if "test_gew_ext_032_" not in item["id"]
        ]
        missing_boundary_test["commands"][3]["outcome_sha256"] = evidence_utils.digest(
            evidence_utils.canonical_bytes(missing_boundary_test["commands"][3]["outcome"])
        )
        mutations.append((source, missing_boundary_test, exit_record, verdict, "TEST_BINDING_MISMATCH"))
        changed_verdict = copy.deepcopy(verdict)
        changed_verdict["candidate_exit_digest"] = "0" * 64
        mutations.append((source, evidence, exit_record, changed_verdict, "REVIEW_VERDICT_MISMATCH"))
        for source_value, evidence_value, exit_value, verdict_value, finding in mutations:
            with self.subTest(finding=finding):
                self.assertIn(
                    finding,
                    self.validate(source_value, evidence_value, exit_value, verdict_value),
                )

    def test_prerequisites_require_exact_pass_candidates(self) -> None:
        gate = json.loads((ROOT / "config/verification/wp-08a-gate.json").read_text())
        actual = evidence_utils.dependency_verdicts(gate)
        self.assertEqual(
            [(item["work_package"], item["revision"]) for item in actual],
            [("WP-05", 2), ("WP-06", 3), ("WP-07", 3), ("WP-07A", 6)],
        )
        changed = copy.deepcopy(gate)
        changed["dependencies"][3]["source_manifest_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            evidence_utils.dependency_verdicts(changed)


if __name__ == "__main__":
    unittest.main()
