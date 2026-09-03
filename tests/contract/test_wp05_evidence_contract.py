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
import verify_wp05_evidence  # noqa: E402


class WP05EvidenceContractTests(unittest.TestCase):
    def valid(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-05-gate.json").read_text())
        exact_gate_bindings = evidence_utils.wp05_exact_gate_test_bindings(gate)
        qualified = sorted(
            binding["qualified_test"]
            for binding in gate["test_bindings"] + exact_gate_bindings
        )
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-05-TEST-P":
                outcome["tests"] = [{"id": test_id, "status": "PASS"} for test_id in qualified]
            commands.append({
                "test_id": command["id"],
                "argv": evidence_utils.expand_argv(command),
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        documents = evidence_utils.wp05_frozen_governing_documents(gate)
        self.architecture_review_digest = next(
            record["sha256"] for record in documents
            if record["path"] == verify_wp05_evidence.ARCHITECTURE_REVIEW_PATH
        )
        self.runtime = evidence_utils.wp05_frozen_action_runtime(gate)
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
                (("WP-03", 8), ("WP-04", 3), ("WP-05A", 4)), start=1,
            )
        ]
        self.action_sources = evidence_utils.wp05_action_source_records(gate, source)
        evidence = {
            "schema_version": "1.0",
            "status": "PASS",
            "source_manifest_digest": source["manifest_digest"],
            "action_sources": self.action_sources,
            "interpreter": {
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "action_runtime": self.runtime,
            "dependency_verdicts": self.dependencies,
            "commands": commands,
            "governing_documents": documents,
            "test_bindings": gate["test_bindings"],
            "exact_gate_test_bindings": exact_gate_bindings,
            "wheel": {"filename": "unused", "sha256": "unused"},
            "real_external_actions_enabled": False,
        }
        exit_record = {
            "schema_version": "1.0",
            "artifact": "wp-05",
            "status": "CANDIDATE",
            "author_id": "codex:/root/wp05_author_r1",
            "reviewer_id": "codex:/root/wp05_code_reviewer_r1",
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp05_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
            "architecture_review_digest": self.architecture_review_digest,
            "action_runtime_digest": verify_wp05_evidence.canonical_digest(self.runtime),
            "action_sources_digest": verify_wp05_evidence.canonical_digest(self.action_sources),
            "dependency_verdicts_digest": verify_wp05_evidence.canonical_digest(self.dependencies),
            "real_external_actions_enabled": False,
            "test_ids": ["GEW-WP-05-EXIT-P", "GEW-WP-05-EXIT-R"],
        }
        verdict = {
            "schema_version": "1.0",
            "artifact": "wp-05",
            "verdict": "PASS",
            "scope_changed": False,
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp05_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp05_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "architecture_review_digest": self.architecture_review_digest,
            "action_runtime_digest": exit_record["action_runtime_digest"],
            "action_sources_digest": exit_record["action_sources_digest"],
            "dependency_verdicts_digest": exit_record["dependency_verdicts_digest"],
            "finding_dispositions": [],
            "findings": [],
        }
        return source, evidence, exit_record, verdict

    def validate(self, *values: object) -> list[str]:
        with (
            mock.patch.object(
                evidence_utils,
                "wp05_frozen_action_runtime",
                return_value=self.runtime,
            ),
            mock.patch.object(evidence_utils, "dependency_verdicts", return_value=self.dependencies),
        ):
            return verify_wp05_evidence.validate(*values)  # type: ignore[arg-type]

    def test_valid_candidate_binding_passes(self) -> None:
        self.assertEqual(self.validate(*self.valid()), [])

    def test_source_command_runtime_document_and_review_mutations_fail(self) -> None:
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
        changed_runtime["action_runtime"]["recovery_schedule_id"] = "attacker"
        self.assertIn(
            "ACTION_RUNTIME_MISMATCH",
            self.validate(source, changed_runtime, exit_record, verdict),
        )
        changed_sources = copy.deepcopy(evidence)
        changed_sources["action_sources"].pop()
        self.assertIn(
            "ACTION_SOURCE_BINDING_MISMATCH",
            self.validate(source, changed_sources, exit_record, verdict),
        )
        changed_documents = copy.deepcopy(evidence["governing_documents"])
        changed_documents[0]["sha256"] = "0" * 64
        evidence_documents = copy.deepcopy(evidence)
        evidence_documents["governing_documents"] = changed_documents
        self.assertIn(
            "GOVERNING_DOCUMENT_MISMATCH",
            self.validate(source, evidence_documents, exit_record, verdict),
        )
        changed_dependencies = copy.deepcopy(evidence)
        changed_dependencies["dependency_verdicts"] = []
        self.assertIn(
            "DEPENDENCY_VERDICT_MISMATCH",
            self.validate(source, changed_dependencies, exit_record, verdict),
        )
        changed_verdict = copy.deepcopy(verdict)
        changed_verdict["candidate_exit_digest"] = "0" * 64
        self.assertIn(
            "REVIEW_VERDICT_MISMATCH",
            self.validate(source, evidence, exit_record, changed_verdict),
        )

    def test_prerequisites_require_exact_pass_candidates(self) -> None:
        gate = json.loads((ROOT / "config" / "verification" / "wp-05-gate.json").read_text())
        actual = evidence_utils.dependency_verdicts(gate)
        self.assertEqual(
            [(item["work_package"], item["revision"]) for item in actual],
            [("WP-03", 8), ("WP-04", 3), ("WP-05A", 4)],
        )
        changed = copy.deepcopy(gate)
        changed["dependencies"][2]["source_manifest_digest"] = "0" * 64
        with self.assertRaises(ValueError):
            evidence_utils.dependency_verdicts(changed)


if __name__ == "__main__":
    unittest.main()
