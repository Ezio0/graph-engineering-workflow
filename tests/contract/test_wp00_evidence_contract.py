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

import source_manifest  # noqa: E402
import evidence_utils  # noqa: E402
import verify_evidence  # noqa: E402


class EvidenceContractTests(unittest.TestCase):
    def _valid(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
        all_required_tests = sorted(
            set(evidence_utils.REQUIRED_REJECT_TESTS.values())
            | set(evidence_utils.REQUIRED_EXIT_TESTS.values())
        )
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-00-TEST-P":
                outcome["tests"] = [
                    {"id": test_id, "status": "PASS"} for test_id in all_required_tests
                ]
            commands.append({
                "test_id": command["id"],
                "argv": [
                    sys.executable if value == "{python}" else value
                    for value in command["argv"]
                ],
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        evidence = {
            "source_manifest_digest": source["manifest_digest"],
            "commands": commands,
            "reject_tests": [
                {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
                for test_id, qualified_test in sorted(evidence_utils.REQUIRED_REJECT_TESTS.items())
            ],
            "exit_tests": [
                {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
                for test_id, qualified_test in sorted(evidence_utils.REQUIRED_EXIT_TESTS.items())
            ],
            "interpreter": {
                "version": platform.python_version(),
                "implementation": platform.python_implementation(),
                "platform": platform.platform(),
                "executable": sys.executable,
                "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
            },
            "wheel": {"filename": "unused", "sha256": "unused"},
        }
        exit_record = {
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_evidence._canonical_digest(evidence),
            "author_id": "author",
            "reviewer_id": "reviewer",
            "test_ids": ["GEW-WP-00-EXIT-P", "GEW-WP-00-EXIT-R"],
        }
        return source, evidence, exit_record

    def test_valid_binding_and_independence_pass(self) -> None:
        self.assertEqual(verify_evidence.validate(*self._valid()), [])

    def test_source_command_interpreter_and_reviewer_mutations_fail(self) -> None:
        source, evidence, exit_record = self._valid()
        changed_source = copy.deepcopy(source)
        changed_source["files"][0]["sha256"] = "0" * 64
        self.assertIn("SOURCE_MANIFEST_MISMATCH", verify_evidence.validate(changed_source, evidence, exit_record))
        changed_commands = copy.deepcopy(evidence)
        changed_commands["commands"].pop()
        self.assertIn("COMMAND_RECORD_MISMATCH", verify_evidence.validate(source, changed_commands, exit_record))
        changed_argv = copy.deepcopy(evidence)
        changed_argv["commands"][0]["argv"] = [sys.executable, "wrong.py"]
        self.assertIn("COMMAND_RECORD_MISMATCH", verify_evidence.validate(source, changed_argv, exit_record))
        fabricated = copy.deepcopy(evidence)
        fabricated["commands"][0]["outcome"] = {"status": "PASS", "fabricated": True}
        fabricated["commands"][0]["outcome_sha256"] = evidence_utils.digest(
            evidence_utils.canonical_bytes(fabricated["commands"][0]["outcome"])
        )
        fabricated_exit = copy.deepcopy(exit_record)
        fabricated_exit["command_evidence_digest"] = verify_evidence._canonical_digest(fabricated)
        with mock.patch.object(evidence_utils, "command_records", return_value=evidence["commands"]):
            self.assertIn(
                "COMMAND_REPLAY_MISMATCH",
                verify_evidence.validate(source, fabricated, fabricated_exit, rerun_commands=True),
            )
        changed_interpreter = copy.deepcopy(evidence)
        changed_interpreter["interpreter"]["version"] = "0"
        self.assertIn("INTERPRETER_MISMATCH", verify_evidence.validate(source, changed_interpreter, exit_record))
        same_actor = copy.deepcopy(exit_record)
        same_actor["reviewer_id"] = same_actor["author_id"]
        self.assertIn("REVIEWER_NOT_INDEPENDENT", verify_evidence.validate(source, evidence, same_actor))
        case_actor = copy.deepcopy(exit_record)
        case_actor["reviewer_id"] = str(case_actor["author_id"]).upper()
        self.assertIn("REVIEWER_NOT_INDEPENDENT", verify_evidence.validate(source, evidence, case_actor))
        padded_actor = copy.deepcopy(exit_record)
        padded_actor["reviewer_id"] = f" {padded_actor['reviewer_id']} "
        self.assertIn("REVIEWER_NOT_INDEPENDENT", verify_evidence.validate(source, evidence, padded_actor))

    def test_reviewer_verdict_must_bind_the_exact_candidate(self) -> None:
        source, evidence, exit_record = self._valid()
        verdict = {
            "verdict": "PASS",
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_evidence._canonical_digest(evidence),
            "candidate_exit_digest": verify_evidence._canonical_digest(exit_record),
        }
        self.assertEqual(verify_evidence.validate(source, evidence, exit_record, verdict), [])
        stale = copy.deepcopy(verdict)
        stale["candidate_exit_digest"] = "0" * 64
        self.assertIn("REVIEW_VERDICT_MISMATCH", verify_evidence.validate(source, evidence, exit_record, stale))


if __name__ == "__main__":
    unittest.main()
