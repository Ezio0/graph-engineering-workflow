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
import verify_wp06_evidence  # noqa: E402


class WP06EvidenceContractTests(unittest.TestCase):
    def valid(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-06-gate.json").read_text())
        stable_bindings = evidence_utils.wp06_frozen_test_bindings(gate)
        remedy_bindings = evidence_utils.wp06_reviewer_remedy_test_bindings(gate)
        qualified = sorted(
            binding["qualified_test"]
            for binding in stable_bindings + gate["evidence_test_bindings"] + remedy_bindings
        )
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-06-TEST-P":
                outcome["tests"] = [{"id": test_id, "status": "PASS"} for test_id in qualified]
            commands.append({
                "test_id": command["id"],
                "argv": evidence_utils.expand_argv(command),
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        documents = evidence_utils.wp06_frozen_governing_documents(gate)
        self.runtime = evidence_utils.wp06_frozen_runtime(gate)
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
                (("WP-03", 8), ("WP-04", 3), ("WP-05A", 4), ("WP-05", 2)), start=1,
            )
        ]
        self.sources = evidence_utils.wp06_source_records(gate, source)
        evidence = {
            "schema_version": "1.0",
            "status": "PASS",
            "source_manifest_digest": source["manifest_digest"],
            "wp06_sources": self.sources,
            "interpreter": {
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "wp06_runtime": self.runtime,
            "dependency_verdicts": self.dependencies,
            "commands": commands,
            "governing_documents": documents,
            "stable_test_bindings": stable_bindings,
            "evidence_test_bindings": gate["evidence_test_bindings"],
            "reviewer_remedy_test_bindings": remedy_bindings,
            "wheel": {"filename": "unused", "sha256": "unused"},
            "real_external_actions_enabled": False,
        }
        exit_record = {
            "schema_version": "1.0",
            "artifact": "wp-06",
            "status": "CANDIDATE",
            "author_id": "codex:/root/wp06_evidence_author_r1",
            "reviewer_id": "codex:/root/wp06_reviewer_r1",
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp06_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
            "wp06_runtime_digest": verify_wp06_evidence.canonical_digest(self.runtime),
            "wp06_sources_digest": verify_wp06_evidence.canonical_digest(self.sources),
            "dependency_verdicts_digest": verify_wp06_evidence.canonical_digest(self.dependencies),
            "real_external_actions_enabled": False,
            "test_ids": ["GEW-WP-06-EXIT-P", "GEW-WP-06-EXIT-R"],
        }
        verdict = {
            "schema_version": "1.0",
            "artifact": "wp-06",
            "verdict": "PASS",
            "scope_changed": False,
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp06_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp06_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "wp06_runtime_digest": exit_record["wp06_runtime_digest"],
            "wp06_sources_digest": exit_record["wp06_sources_digest"],
            "dependency_verdicts_digest": exit_record["dependency_verdicts_digest"],
            "finding_dispositions": [],
            "findings": [],
        }
        return source, evidence, exit_record, verdict

    def validate(self, *values: object) -> list[str]:
        with (
            mock.patch.object(
                evidence_utils,
                "wp06_frozen_runtime",
                return_value=self.runtime,
            ),
            mock.patch.object(evidence_utils, "dependency_verdicts", return_value=self.dependencies),
        ):
            return verify_wp06_evidence.validate(*values)  # type: ignore[arg-type]

    def test_valid_candidate_binding_passes(self) -> None:
        self.assertEqual(self.validate(*self.valid()), [])

    def test_source_command_runtime_document_dependency_and_review_mutations_fail(self) -> None:
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
        changed_runtime["wp06_runtime"]["migration_schedule_id"] = "attacker"
        self.assertIn(
            "WP06_RUNTIME_MISMATCH",
            self.validate(source, changed_runtime, exit_record, verdict),
        )
        changed_sources = copy.deepcopy(evidence)
        changed_sources["wp06_sources"].pop()
        self.assertIn(
            "WP06_SOURCE_BINDING_MISMATCH",
            self.validate(source, changed_sources, exit_record, verdict),
        )
        changed_documents = copy.deepcopy(evidence)
        changed_documents["governing_documents"][0]["sha256"] = "0" * 64
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
        changed_remedy = copy.deepcopy(evidence)
        changed_remedy["reviewer_remedy_test_bindings"].pop()
        self.assertIn(
            "TEST_BINDING_MISMATCH",
            self.validate(source, changed_remedy, exit_record, verdict),
        )
        changed_verdict = copy.deepcopy(verdict)
        changed_verdict["candidate_exit_digest"] = "0" * 64
        self.assertIn(
            "REVIEW_VERDICT_MISMATCH",
            self.validate(source, evidence, exit_record, changed_verdict),
        )

    def test_prerequisites_require_exact_pass_candidates(self) -> None:
        gate = json.loads((ROOT / "config" / "verification" / "wp-06-gate.json").read_text())
        actual = evidence_utils.dependency_verdicts(gate)
        self.assertEqual(
            [(item["work_package"], item["revision"]) for item in actual],
            [("WP-03", 8), ("WP-04", 3), ("WP-05A", 4), ("WP-05", 2)],
        )
        changed = copy.deepcopy(gate)
        changed["dependencies"][3]["source_manifest_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            evidence_utils.dependency_verdicts(changed)


if __name__ == "__main__":
    unittest.main()
