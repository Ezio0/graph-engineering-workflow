from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
import source_manifest  # noqa: E402
import verify_wp01_evidence  # noqa: E402


class WP01EvidenceContractTests(unittest.TestCase):
    def valid(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-01-gate.json").read_text())
        qualified = sorted(binding["qualified_test"] for binding in gate["test_bindings"])
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-01-TEST-P":
                outcome["tests"] = [{"id": test_id, "status": "PASS"} for test_id in qualified]
            commands.append({
                "test_id": command["id"],
                "argv": [sys.executable if value == "{python}" else value for value in command["argv"]],
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        node = pathlib.Path(shutil.which("node") or "").resolve()
        reference = ROOT / "tests" / "support" / "wp01_reference.mjs"
        evidence = {
            "schema_version": "1.0",
            "status": "PASS",
            "source_manifest_digest": source["manifest_digest"],
            "interpreter": {
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
            },
            "reference_runtime": {
                "kind": "node",
                "executable": str(node),
                "executable_sha256": hashlib.sha256(node.read_bytes()).hexdigest(),
                "version": subprocess.run([str(node), "--version"], check=True, capture_output=True, text=True).stdout.strip(),
                "implementation": "tests/support/wp01_reference.mjs",
                "implementation_sha256": hashlib.sha256(reference.read_bytes()).hexdigest(),
            },
            "commands": commands,
            "governing_documents": evidence_utils.governing_documents(),
            "test_bindings": gate["test_bindings"],
            "wheel": {"filename": "unused", "sha256": "unused"},
        }
        exit_record = {
            "author_id": "codex:/root",
            "reviewer_id": "codex:/reviewer",
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp01_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(
                evidence["governing_documents"]
            ),
            "test_ids": ["GEW-WP-01-EXIT-P", "GEW-WP-01-EXIT-R"],
        }
        self.assertEqual(evidence["test_bindings"], gate["test_bindings"])
        return source, evidence, exit_record

    def test_valid_candidate_binding_passes(self) -> None:
        self.assertEqual(verify_wp01_evidence.validate(*self.valid()), [])

    def test_source_command_runtime_binding_and_independence_mutations_fail(self) -> None:
        source, evidence, exit_record = self.valid()
        changed_source = copy.deepcopy(source)
        changed_source["files"][0]["sha256"] = "0" * 64
        self.assertIn("SOURCE_MANIFEST_MISMATCH", verify_wp01_evidence.validate(changed_source, evidence, exit_record))
        changed_command = copy.deepcopy(evidence)
        changed_command["commands"][0]["outcome"] = {"status": "PASS", "fabricated": True}
        self.assertIn("COMMAND_RECORD_MISMATCH", verify_wp01_evidence.validate(source, changed_command, exit_record))
        changed_node = copy.deepcopy(evidence)
        changed_node["reference_runtime"]["implementation_sha256"] = "0" * 64
        self.assertIn("REFERENCE_RUNTIME_MISMATCH", verify_wp01_evidence.validate(source, changed_node, exit_record))
        changed_documents = copy.deepcopy(evidence["governing_documents"])
        changed_documents[0]["sha256"] = "0" * 64
        with mock.patch.object(evidence_utils, "governing_documents", return_value=changed_documents):
            self.assertIn(
                "GOVERNING_DOCUMENT_MISMATCH",
                verify_wp01_evidence.validate(source, evidence, exit_record),
            )
        changed_document_evidence = copy.deepcopy(evidence)
        changed_document_evidence["governing_documents"][1]["size"] += 1
        self.assertIn(
            "GOVERNING_DOCUMENT_MISMATCH",
            verify_wp01_evidence.validate(source, changed_document_evidence, exit_record),
        )
        same_actor = copy.deepcopy(exit_record)
        same_actor["reviewer_id"] = str(same_actor["author_id"]).upper()
        self.assertIn("REVIEWER_NOT_INDEPENDENT", verify_wp01_evidence.validate(source, evidence, same_actor))
        changed_exit = copy.deepcopy(exit_record)
        changed_exit["command_evidence_digest"] = evidence_utils.digest(b"wrong")
        self.assertIn("EXIT_BINDING_MISMATCH", verify_wp01_evidence.validate(source, evidence, changed_exit))
        changed_governing_exit = copy.deepcopy(exit_record)
        changed_governing_exit["governing_documents_digest"] = "0" * 64
        self.assertIn("EXIT_BINDING_MISMATCH", verify_wp01_evidence.validate(source, evidence, changed_governing_exit))

    def test_reviewer_verdict_binds_governing_documents(self) -> None:
        source, evidence, exit_record = self.valid()
        verdict = {
            "verdict": "PASS",
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp01_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp01_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "finding_dispositions": [],
            "findings": [],
        }
        self.assertEqual(verify_wp01_evidence.validate(source, evidence, exit_record, verdict), [])
        stale = copy.deepcopy(verdict)
        stale["governing_documents_digest"] = "0" * 64
        self.assertIn(
            "REVIEW_VERDICT_MISMATCH",
            verify_wp01_evidence.validate(source, evidence, exit_record, stale),
        )


if __name__ == "__main__":
    unittest.main()
