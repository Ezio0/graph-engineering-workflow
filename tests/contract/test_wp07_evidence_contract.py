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
import verify_wp07_evidence  # noqa: E402


class WP07EvidenceContractTests(unittest.TestCase):
    def valid(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-07-gate.json").read_text())
        stable = evidence_utils.wp07_frozen_test_bindings(gate)
        supplemental = evidence_utils.wp07_supplemental_test_bindings(gate)
        skills = evidence_utils.wp07_required_skill_test_bindings(gate)
        remedies = evidence_utils.wp07_reviewer_remedy_test_bindings(gate)
        evidence_bindings = gate["evidence_test_bindings"]
        qualified = {
            binding["qualified_test"]
            for binding in stable + supplemental + skills + remedies + evidence_bindings
        }
        index = 0
        while len(qualified) < gate["expected_test_execution_count"]:
            qualified.add(f"test_wp07_evidence_fixture.FillerTests.test_pass_{index:04d}")
            index += 1
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-07-TEST-P":
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
        documents = evidence_utils.wp07_frozen_governing_documents(gate)
        self.runtime = evidence_utils.wp07_frozen_runtime(gate)
        self.dependencies = [
            {
                "work_package": work_package,
                "revision": revision,
                "source_manifest_path": f"records/{work_package}-source.json",
                "source_manifest_digest": str(index) * 64,
                "command_evidence_path": f"records/{work_package}-commands.json",
                "command_evidence_digest": str(index + 1) * 64,
                "verdict_path": f"records/{work_package}-verdict.json",
                "verdict_digest": str(index + 2) * 64,
                "exit_path": f"records/{work_package}-exit.json",
                "exit_digest": str(index + 3) * 64,
                "reviewer_id": f"codex:/dependency-reviewer-{index}",
            }
            for index, (work_package, revision) in enumerate(
                (("WP-05", 2), ("WP-06", 3)), start=1,
            )
        ]
        self.sources = evidence_utils.wp07_source_records(gate, source)
        evidence = {
            "schema_version": "1.0",
            "status": "PASS",
            "source_manifest_digest": source["manifest_digest"],
            "wp07_sources": self.sources,
            "interpreter": {
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "wp07_runtime": self.runtime,
            "dependency_verdicts": self.dependencies,
            "commands": commands,
            "governing_documents": documents,
            "stable_test_bindings": stable,
            "supplemental_test_bindings": supplemental,
            "required_skill_test_bindings": skills,
            "reviewer_remedy_test_bindings": remedies,
            "evidence_test_bindings": evidence_bindings,
            "passed_test_count": len(qualified),
            "test_execution_count": len(qualified),
            "wheel": {"filename": "unused", "sha256": "unused"},
            "real_external_actions_enabled": False,
        }
        exit_record = {
            "schema_version": "1.0",
            "artifact": "wp-07",
            "status": "CANDIDATE",
            "author_id": "codex:/root/wp07_evidence_author_r1",
            "reviewer_id": "codex:/root/wp07_reviewer_r2",
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp07_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
            "wp07_runtime_digest": verify_wp07_evidence.canonical_digest(self.runtime),
            "wp07_sources_digest": verify_wp07_evidence.canonical_digest(self.sources),
            "dependency_verdicts_digest": verify_wp07_evidence.canonical_digest(self.dependencies),
            "real_external_actions_enabled": False,
            "test_ids": ["GEW-WP-07-EXIT-P", "GEW-WP-07-EXIT-R"],
        }
        verdict = {
            "schema_version": "1.0",
            "artifact": "wp-07",
            "verdict": "PASS",
            "scope_changed": False,
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp07_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp07_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "wp07_runtime_digest": exit_record["wp07_runtime_digest"],
            "wp07_sources_digest": exit_record["wp07_sources_digest"],
            "dependency_verdicts_digest": exit_record["dependency_verdicts_digest"],
            "finding_dispositions": [
                {"finding_id": f"WP07-CODE-R1-{number:03d}", "status": "closed"}
                for number in range(1, 9)
            ],
            "findings": [],
        }
        return source, evidence, exit_record, verdict

    def validate(self, *values: object) -> list[str]:
        with (
            mock.patch.object(
                evidence_utils,
                "wp07_frozen_runtime",
                return_value=self.runtime,
            ),
            mock.patch.object(evidence_utils, "dependency_verdicts", return_value=self.dependencies),
        ):
            return verify_wp07_evidence.validate(*values)  # type: ignore[arg-type]

    def test_valid_candidate_binding_passes(self) -> None:
        self.assertEqual(self.validate(*self.valid()), [])

    def test_source_command_runtime_document_dependency_binding_and_review_mutations_fail(self) -> None:
        source, evidence, exit_record, verdict = self.valid()
        changed_source = copy.deepcopy(source)
        changed_source["files"][0]["sha256"] = "0" * 64
        self.assertIn(
            "SOURCE_MANIFEST_MISMATCH",
            self.validate(changed_source, evidence, exit_record, verdict),
        )
        changed_command = copy.deepcopy(evidence)
        changed_command["commands"][0]["outcome"] = {"status": "PASS", "fabricated": True}
        self.assertIn(
            "COMMAND_RECORD_MISMATCH",
            self.validate(source, changed_command, exit_record, verdict),
        )
        changed_runtime = copy.deepcopy(evidence)
        changed_runtime["wp07_runtime"]["runtime_resource_policy"]["policy_id"] = "attacker"
        self.assertIn(
            "WP07_RUNTIME_MISMATCH",
            self.validate(source, changed_runtime, exit_record, verdict),
        )
        changed_sources = copy.deepcopy(evidence)
        changed_sources["wp07_sources"].pop()
        self.assertIn(
            "WP07_SOURCE_BINDING_MISMATCH",
            self.validate(source, changed_sources, exit_record, verdict),
        )
        changed_documents = copy.deepcopy(evidence)
        changed_documents["governing_documents"][8]["sha256"] = "0" * 64
        self.assertIn(
            "GOVERNING_DOCUMENT_MISMATCH",
            self.validate(source, changed_documents, exit_record, verdict),
        )
        changed_dependencies = copy.deepcopy(evidence)
        changed_dependencies["dependency_verdicts"] = []
        self.assertIn(
            "DEPENDENCY_VERDICT_MISMATCH",
            self.validate(source, changed_dependencies, exit_record, verdict),
        )
        for field in (
            "stable_test_bindings", "supplemental_test_bindings",
            "required_skill_test_bindings", "reviewer_remedy_test_bindings",
            "evidence_test_bindings",
        ):
            changed_binding = copy.deepcopy(evidence)
            changed_binding[field].pop()
            with self.subTest(field=field):
                self.assertIn(
                    "TEST_BINDING_MISMATCH",
                    self.validate(source, changed_binding, exit_record, verdict),
                )
        changed_count = copy.deepcopy(evidence)
        changed_count["passed_test_count"] -= 1
        self.assertIn(
            "TEST_BINDING_MISMATCH",
            self.validate(source, changed_count, exit_record, verdict),
        )
        missing_full_flow = copy.deepcopy(evidence)
        tests = missing_full_flow["commands"][3]["outcome"]["tests"]
        missing_full_flow["commands"][3]["outcome"]["tests"] = [
            item for item in tests if "test_gew_rt_043_" not in item["id"]
        ]
        missing_full_flow["commands"][3]["outcome_sha256"] = evidence_utils.digest(
            evidence_utils.canonical_bytes(missing_full_flow["commands"][3]["outcome"])
        )
        self.assertIn(
            "TEST_BINDING_MISMATCH",
            self.validate(source, missing_full_flow, exit_record, verdict),
        )
        missing_resigned_substitution = copy.deepcopy(evidence)
        tests = missing_resigned_substitution["commands"][3]["outcome"]["tests"]
        missing_resigned_substitution["commands"][3]["outcome"]["tests"] = [
            item for item in tests if "test_gew_rt_044a_" not in item["id"]
        ]
        missing_resigned_substitution["commands"][3]["outcome_sha256"] = evidence_utils.digest(
            evidence_utils.canonical_bytes(
                missing_resigned_substitution["commands"][3]["outcome"]
            )
        )
        self.assertIn(
            "TEST_BINDING_MISMATCH",
            self.validate(source, missing_resigned_substitution, exit_record, verdict),
        )
        changed_verdict = copy.deepcopy(verdict)
        changed_verdict["candidate_exit_digest"] = "0" * 64
        self.assertIn(
            "REVIEW_VERDICT_MISMATCH",
            self.validate(source, evidence, exit_record, changed_verdict),
        )

    def test_prerequisites_require_exact_pass_candidates(self) -> None:
        gate = json.loads((ROOT / "config" / "verification" / "wp-07-gate.json").read_text())
        actual = evidence_utils.dependency_verdicts(gate)
        self.assertEqual(
            [(item["work_package"], item["revision"]) for item in actual],
            [("WP-05", 2), ("WP-06", 3)],
        )
        changed = copy.deepcopy(gate)
        changed["dependencies"][1]["source_manifest_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            evidence_utils.dependency_verdicts(changed)


if __name__ == "__main__":
    unittest.main()
