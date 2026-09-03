from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import platform
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402
import source_manifest  # noqa: E402
import verify_wp02_evidence  # noqa: E402


class WP02EvidenceContractTests(unittest.TestCase):
    def valid(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        source = source_manifest.create_manifest()
        gate = json.loads((ROOT / "config" / "verification" / "wp-02-gate.json").read_text())
        qualified = sorted(binding["qualified_test"] for binding in gate["test_bindings"])
        commands = []
        for command in gate["commands"]:
            outcome: dict[str, object] = {"status": "PASS"}
            if command["id"] == "GEW-WP-02-TEST-P":
                outcome["tests"] = [{"id": test_id, "status": "PASS"} for test_id in qualified]
            commands.append({
                "test_id": command["id"],
                "argv": evidence_utils.expand_argv(command),
                "exit_code": 0,
                "outcome": outcome,
                "outcome_sha256": evidence_utils.digest(evidence_utils.canonical_bytes(outcome)),
                "stderr_sha256": evidence_utils.digest(b""),
            })
        documents = evidence_utils.governing_documents(paths=evidence_utils.WP02_GOVERNING_DOCUMENT_PATHS)
        self.reference_runtime = evidence_utils.reference_runtime()
        self.dependency_verdicts = [{
            "work_package": "WP-01",
            "revision": 18,
            "source_manifest_path": ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-01-source-manifest-r18.json",
            "source_manifest_digest": "0" * 64,
            "command_evidence_path": ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-01-command-evidence-r18.json",
            "command_evidence_digest": "3" * 64,
            "verdict_path": ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-01-review-verdict-r18.json",
            "verdict_digest": "1" * 64,
            "exit_path": ".workflow/delivery/GEW-IMPLEMENTATION-V1/wp-01-exit-r18.json",
            "exit_digest": "2" * 64,
            "reviewer_id": "codex:/dependency-reviewer",
        }]
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
            "reference_runtime": self.reference_runtime,
            "dependency_verdicts": self.dependency_verdicts,
            "commands": commands,
            "governing_documents": documents,
            "test_bindings": gate["test_bindings"],
            "wheel": {"filename": "unused", "sha256": "unused"},
        }
        exit_record = {
            "author_id": "codex:/root",
            "reviewer_id": "codex:/reviewer",
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp02_evidence.canonical_digest(evidence),
            "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
            "reference_runtime_digest": verify_wp02_evidence.canonical_digest(
                self.reference_runtime,
            ),
            "dependency_verdicts_digest": verify_wp02_evidence.canonical_digest(
                self.dependency_verdicts,
            ),
            "test_ids": ["GEW-WP-02-EXIT-P", "GEW-WP-02-EXIT-R"],
        }
        return source, evidence, exit_record

    def validate(self, *args: object) -> list[str]:
        with (
            mock.patch.object(
                evidence_utils, "reference_runtime", return_value=self.reference_runtime,
            ),
            mock.patch.object(
                evidence_utils, "dependency_verdicts", return_value=self.dependency_verdicts,
            ),
        ):
            return verify_wp02_evidence.validate(*args)  # type: ignore[arg-type]

    def test_valid_candidate_binding_passes(self) -> None:
        values = self.valid()
        self.assertEqual(self.validate(*values), [])

    def test_source_command_document_and_review_mutations_fail(self) -> None:
        source, evidence, exit_record = self.valid()
        changed_source = copy.deepcopy(source)
        changed_source["files"][0]["sha256"] = "0" * 64
        self.assertIn("SOURCE_MANIFEST_MISMATCH", self.validate(changed_source, evidence, exit_record))
        changed_command = copy.deepcopy(evidence)
        changed_command["commands"][0]["outcome"] = {"status": "PASS", "fabricated": True}
        self.assertIn("COMMAND_RECORD_MISMATCH", self.validate(source, changed_command, exit_record))
        changed_documents = copy.deepcopy(evidence["governing_documents"])
        changed_documents[0]["sha256"] = "0" * 64
        with mock.patch.object(evidence_utils, "governing_documents", return_value=changed_documents):
            self.assertIn("GOVERNING_DOCUMENT_MISMATCH", self.validate(source, evidence, exit_record))
        same_actor = copy.deepcopy(exit_record)
        same_actor["reviewer_id"] = str(same_actor["author_id"]).upper()
        self.assertIn("REVIEWER_NOT_INDEPENDENT", self.validate(source, evidence, same_actor))
        changed_runtime = copy.deepcopy(evidence)
        changed_runtime["reference_runtime"]["version"] = "v0.0.0"
        self.assertIn(
            "REFERENCE_RUNTIME_MISMATCH",
            self.validate(source, changed_runtime, exit_record),
        )
        missing_dependency = copy.deepcopy(evidence)
        missing_dependency["dependency_verdicts"] = []
        self.assertIn(
            "DEPENDENCY_VERDICT_MISMATCH",
            self.validate(source, missing_dependency, exit_record),
        )
        verdict = {
            "verdict": "PASS",
            "reviewer_id": exit_record["reviewer_id"],
            "source_manifest_digest": source["manifest_digest"],
            "command_evidence_digest": verify_wp02_evidence.canonical_digest(evidence),
            "candidate_exit_digest": verify_wp02_evidence.canonical_digest(exit_record),
            "governing_documents_digest": exit_record["governing_documents_digest"],
            "finding_dispositions": [],
            "findings": [],
        }
        stale = copy.deepcopy(verdict)
        stale["candidate_exit_digest"] = "0" * 64
        self.assertIn(
            "REVIEW_VERDICT_MISMATCH",
            self.validate(source, evidence, exit_record, stale),
        )

    def test_dependency_verdict_requires_exact_pass_candidate_binding(self) -> None:
        source_manifest = {"schema_version": "1.0", "files": []}
        source_digest = evidence_utils.digest(
            evidence_utils.canonical_bytes(source_manifest)
        )
        source_manifest["manifest_digest"] = source_digest
        command_evidence = {
            "schema_version": "1.0",
            "status": "PASS",
            "source_manifest_digest": source_digest,
            "commands": [],
        }
        command_digest = evidence_utils.digest(
            evidence_utils.canonical_bytes(command_evidence)
        )
        exit_record = {
            "artifact": "wp-01",
            "author_id": "codex:/author",
            "reviewer_id": "codex:/reviewer",
            "source_manifest_digest": source_digest,
            "command_evidence_digest": command_digest,
            "governing_documents_digest": "d" * 64,
        }
        verdict = {
            "artifact": "wp-01",
            "verdict": "PASS",
            "reviewer_id": "codex:/reviewer",
            "source_manifest_digest": source_digest,
            "command_evidence_digest": command_digest,
            "candidate_exit_digest": evidence_utils.digest(
                evidence_utils.canonical_bytes(exit_record)
            ),
            "governing_documents_digest": "d" * 64,
            "finding_dispositions": [{"id": "finding", "status": "closed"}],
            "findings": [],
        }
        gate = {"dependencies": [{
            "work_package": "WP-01",
            "revision": 18,
            "source_manifest_path": "records/source.json",
            "source_manifest_digest": source_digest,
            "command_evidence_path": "records/commands.json",
            "verdict_path": "records/verdict.json",
            "exit_path": "records/exit.json",
        }]}
        with tempfile.TemporaryDirectory(prefix="gew-dependency-verdict-") as directory:
            root = pathlib.Path(directory)
            records = root / "records"
            records.mkdir()
            source_path = records / "source.json"
            source_path.write_text(json.dumps(source_manifest))
            command_path = records / "commands.json"
            command_path.write_text(json.dumps(command_evidence))
            (records / "exit.json").write_text(json.dumps(exit_record))
            verdict_path = records / "verdict.json"
            verdict_path.write_text(json.dumps(verdict))
            self.assertEqual(
                evidence_utils.dependency_verdicts(gate, root=root)[0][
                    "work_package"
                ],
                "WP-01",
            )
            for name, mutate in (
                ("revise", lambda value: value.update({"verdict": "REVISE"})),
                ("stale", lambda value: value.update({"candidate_exit_digest": "0" * 64})),
                ("source", lambda value: value.update({"source_manifest_digest": "b" * 64})),
            ):
                changed = copy.deepcopy(verdict)
                mutate(changed)
                verdict_path.write_text(json.dumps(changed))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    evidence_utils.dependency_verdicts(gate, root=root)
            verdict_path.write_text(json.dumps(verdict))
            changed_command = copy.deepcopy(command_evidence)
            changed_command["commands"] = [{"fabricated": True}]
            command_path.write_text(json.dumps(changed_command))
            with self.assertRaises(ValueError):
                evidence_utils.dependency_verdicts(gate, root=root)
            command_path.write_text(json.dumps(command_evidence))
            changed_source = copy.deepcopy(source_manifest)
            changed_source["files"] = [{"path": "rogue", "sha256": "0" * 64, "size": 0}]
            source_path.write_text(json.dumps(changed_source))
            with self.assertRaises(ValueError):
                evidence_utils.dependency_verdicts(gate, root=root)
            source_path.write_text(json.dumps(source_manifest))
            verdict_path.unlink()
            with self.assertRaises(ValueError):
                evidence_utils.dependency_verdicts(gate, root=root)


if __name__ == "__main__":
    unittest.main()
