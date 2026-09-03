from __future__ import annotations

import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import evidence_utils  # noqa: E402


RECOVERY_IDS = {
    "GEW-ACT-RECOVERY-CLAIM-LIVE-P",
    "GEW-ACT-RECOVERY-CLAIM-EXPIRED-P",
    "GEW-ACT-RECOVERY-CLAIM-EXACT-R",
    "GEW-ACT-RECOVERY-AUTHORITY-R",
    "GEW-ACT-RECOVERY-COMPENSATION-ONLY-R",
    "GEW-ACT-RECOVERY-NO-NEW-LEASE-CLAIM-R",
    "GEW-ACT-RECOVERY-LOCK-SPAN-P",
    "GEW-ACT-RECOVERY-VERIFY-P",
    "GEW-ACT-RECOVERY-VERIFY-R",
    "GEW-ACT-RECOVERY-NO-REPLAY-R",
    "GEW-ACT-RECOVERY-ATTEMPT-ID-P",
    "GEW-ACT-RECOVERY-ATTEMPT-ID-R",
    "GEW-ACT-RECOVERY-START-REPLAY-R",
    "GEW-ACT-RECOVERY-RECEIPT-BINDING-R",
    "GEW-ACT-RECOVERY-CONCURRENCY-R",
    "GEW-ACT-RECOVERY-CLAIM-FREEZE-P",
}
EXTRA_IDS = {
    "GEW-WP-05-ACTION-CONTRACT-P",
    "GEW-WP-05-IRREVERSIBLE-AUTHORITY-R",
    "GEW-ACT-DIRECT-BYPASS-R",
    "GEW-ACT-PREPARE-AUTHORIZE-EXECUTE-RECONCILE-P",
    "WP05-CODE-R1-002-NORMAL-RECEIPT-OBJECT-P",
    "GEW-ACT-NONIDEMPOTENT-TIMEOUT-R",
    "GEW-ACT-CRASH-AFTER-EFFECT-R",
    "GEW-ACT-FAILURE-BEFORE-EFFECT-P",
    "GEW-ACT-TARGET-MISMATCH-R",
    "GEW-ACT-POST-CALL-OBSERVATION-BINDING-R",
    "GEW-ACT-RECONCILE-OBSERVATION-BINDING-R",
    "GEW-ACT-SUCCEEDED-UNRESOLVED-RECONCILE-P",
    "GEW-ACT-COMPENSATION-STALE-SNAPSHOT-R",
    "GEW-ACT-AUTHORITY-MEMBERSHIP-R",
    "GEW-ACT-DURABLE-BODY-BOUNDS-R",
    "GEW-AUT-001-100",
    "GEW-ACT-RECOVERY-START-EVENT-EXACT-R",
    "GEW-ACT-RECOVERY-RECONCILE-EVENT-EXACT-R",
    "WP05-CODE-R1-001-OBSERVATION-RESOURCE-R",
    "WP05-CODE-R1-001-ROLLBACK-STATE-R",
    "WP05-CODE-R1-002-COMPENSATION-RECEIPT-OBJECT-P",
    "WP05-CODE-R1-002-PROCESS-SIGKILL-V2-P",
    "WP05-CODE-R1-002-DOUBLE-CALL-ORACLE-R",
    "GEW-WP-05-EXIT-P",
    "GEW-WP-05-EXIT-R",
    "GEW-WP-05-DEPENDENCY-R",
}
REQUIRED = RECOVERY_IDS | EXTRA_IDS


def validate(manifest: dict[str, object]) -> list[str]:
    findings: list[str] = []
    bindings = manifest.get("test_bindings")
    if not isinstance(bindings, list):
        return ["BINDINGS_MISSING"]
    ids = [item.get("test_id") for item in bindings if isinstance(item, dict)]
    qualified = [item.get("qualified_test") for item in bindings if isinstance(item, dict)]
    if set(ids) != REQUIRED:
        findings.append("TEST_ID_SET_MISMATCH")
    if len(ids) != len(set(ids)) or len(qualified) != len(set(qualified)) or any(not item for item in qualified):
        findings.append("BINDING_NOT_ONE_TO_ONE")
    dependencies = manifest.get("dependencies")
    if (
        not isinstance(dependencies, list)
        or [(item.get("work_package"), item.get("revision")) for item in dependencies] != [
            ("WP-03", 8), ("WP-04", 3), ("WP-05A", 4),
        ]
    ):
        findings.append("DEPENDENCY_SET_MISMATCH")
    if manifest.get("recovery_schedule") != {
        "path": "config/contracts/action-recovery-fault-schedule-v2.json",
        "schedule_id": "wp05-action-recovery-fault-schedule-v2",
        "sha256": "20ebd22292b94d909205761d19a9e3889491d26fa11dc739950f0f9fd500a88d",
        "point_count": 13,
    }:
        findings.append("RECOVERY_SCHEDULE_PIN_MISMATCH")
    source_paths = manifest.get("action_source_paths")
    if (
        not isinstance(source_paths, list)
        or source_paths != sorted(source_paths)
        or len(source_paths) != len(set(source_paths))
        or not source_paths
    ):
        findings.append("ACTION_SOURCE_SET_MISMATCH")
    try:
        evidence_utils.wp05_frozen_governing_documents(manifest)
    except ValueError:
        findings.append("GOVERNING_DOCUMENT_SET_MISMATCH")
    try:
        exact = evidence_utils.wp05_exact_gate_test_bindings(manifest)
    except ValueError:
        findings.append("EXACT_GATE_BINDING_MISMATCH")
    else:
        exact_ids = [item["test_id"] for item in exact]
        exact_tests = [item["qualified_test"] for item in exact]
        if (
            len(exact) != 67
            or len(exact_ids) != len(set(exact_ids))
            or len(exact_tests) != len(set(exact_tests))
            or sum(item.startswith("GEW-AUT-COMBINED-MUTATION:") for item in exact_ids) != 55
        ):
            findings.append("EXACT_GATE_BINDING_MISMATCH")
    return findings


class WP05GateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(
            (ROOT / "config" / "verification" / "wp-05-gate.json").read_text()
        )

    def test_gate_has_exact_action_recovery_bindings_and_dependencies(self) -> None:
        self.assertEqual(validate(self.manifest), [])
        self.assertEqual(len(RECOVERY_IDS), 16)
        self.assertEqual(len(REQUIRED), 42)
        bindings = {
            item["test_id"]: item["qualified_test"] for item in self.manifest["test_bindings"]
        }
        self.assertEqual(
            bindings["GEW-ACT-RECOVERY-RECEIPT-BINDING-R"],
            "test_wp05_recovery_claim.WP05RecoveryClaimTests."
            "test_gew_act_recovery_receipt_binding_r",
        )
        runtime = evidence_utils.wp05_frozen_action_runtime(self.manifest)
        self.assertEqual(runtime["recovery_schedule_id"], "wp05-action-recovery-fault-schedule-v2")
        self.assertEqual(
            runtime["recovery_schedule_sha256"],
            "20ebd22292b94d909205761d19a9e3889491d26fa11dc739950f0f9fd500a88d",
        )
        self.assertEqual(len(runtime["recovery_points"]), 13)
        self.assertTrue(evidence_utils.valid_digest(runtime["recovery_schedule_sha256"]))
        self.assertNotIn(
            "config/contracts/action-recovery-fault-schedule-v1.json",
            [item["path"] for item in runtime["inputs"]],
        )

    def test_missing_duplicate_dependency_or_source_change_is_rejected(self) -> None:
        missing = copy.deepcopy(self.manifest)
        missing["test_bindings"].pop()
        self.assertIn("TEST_ID_SET_MISMATCH", validate(missing))
        duplicate = copy.deepcopy(self.manifest)
        duplicate["test_bindings"][0]["qualified_test"] = duplicate["test_bindings"][1]["qualified_test"]
        self.assertIn("BINDING_NOT_ONE_TO_ONE", validate(duplicate))
        dependency = copy.deepcopy(self.manifest)
        dependency["dependencies"].pop()
        self.assertIn("DEPENDENCY_SET_MISMATCH", validate(dependency))
        source = copy.deepcopy(self.manifest)
        source["action_source_paths"].append(source["action_source_paths"][0])
        self.assertIn("ACTION_SOURCE_SET_MISMATCH", validate(source))
        governing = copy.deepcopy(self.manifest)
        governing["governing_document_digests"][0]["sha256"] = "0" * 64
        self.assertIn("GOVERNING_DOCUMENT_SET_MISMATCH", validate(governing))
        schedule = copy.deepcopy(self.manifest)
        schedule["recovery_schedule"]["point_count"] = 11
        self.assertIn("RECOVERY_SCHEDULE_PIN_MISMATCH", validate(schedule))

        frozen_paths = (
            evidence_utils.WP05_FROZEN_SOURCE_MANIFEST_PATH,
            evidence_utils.WP05_FROZEN_COMMAND_EVIDENCE_PATH,
            evidence_utils.WP05_FROZEN_EXIT_PATH,
            evidence_utils.WP05_FROZEN_VERDICT_PATH,
        )
        for mutation in (
            "source-extra-field",
            "exit-extra-field",
            "exit-author",
            "command-exit-redigestion",
            "gate-document-command-exit-redigestion",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="gew-wp05-frozen-"
            ) as directory:
                frozen_root = pathlib.Path(directory)
                for relative in frozen_paths:
                    source_path = ROOT / relative
                    target_path = frozen_root / relative
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_path, target_path)
                frozen_gate = copy.deepcopy(self.manifest)
                command_path = frozen_root / evidence_utils.WP05_FROZEN_COMMAND_EVIDENCE_PATH
                exit_path = frozen_root / evidence_utils.WP05_FROZEN_EXIT_PATH
                source_path = frozen_root / evidence_utils.WP05_FROZEN_SOURCE_MANIFEST_PATH
                command = json.loads(command_path.read_text(encoding="utf-8"))
                exit_record = json.loads(exit_path.read_text(encoding="utf-8"))
                if mutation == "source-extra-field":
                    source_record = json.loads(source_path.read_text(encoding="utf-8"))
                    source_record["fabricated"] = True
                    source_path.write_text(json.dumps(source_record), encoding="utf-8")
                elif mutation == "exit-extra-field":
                    exit_record["fabricated"] = True
                elif mutation == "exit-author":
                    exit_record["author_id"] = "codex:/attacker"
                elif mutation == "command-exit-redigestion":
                    command["wheel"]["filename"] = "attacker.whl"
                    command_path.write_text(json.dumps(command), encoding="utf-8")
                    exit_record["command_evidence_digest"] = evidence_utils.digest(
                        evidence_utils.canonical_bytes(command)
                    )
                else:
                    command["governing_documents"][0]["sha256"] = "0" * 64
                    frozen_gate["governing_document_digests"][0]["sha256"] = "0" * 64
                    command_path.write_text(json.dumps(command), encoding="utf-8")
                    exit_record["command_evidence_digest"] = evidence_utils.digest(
                        evidence_utils.canonical_bytes(command)
                    )
                    exit_record["governing_documents_digest"] = (
                        evidence_utils.governing_documents_digest(
                            command["governing_documents"]
                        )
                    )
                exit_path.write_text(json.dumps(exit_record), encoding="utf-8")
                with self.assertRaises(ValueError):
                    evidence_utils.wp05_frozen_governing_documents(
                        frozen_gate,
                        root=frozen_root,
                    )

        command_path = ROOT / evidence_utils.WP05_FROZEN_COMMAND_EVIDENCE_PATH
        original_read_text = pathlib.Path.read_text
        command_reads = 0

        def substitute_second_command_read(
            path: pathlib.Path,
            *args: object,
            **kwargs: object,
        ) -> str:
            nonlocal command_reads
            body = original_read_text(path, *args, **kwargs)  # type: ignore[arg-type]
            if path == command_path:
                command_reads += 1
                if command_reads > 1:
                    changed = json.loads(body)
                    changed["action_runtime"]["kind"] = "attacker-runtime"
                    return json.dumps(changed)
            return body

        with mock.patch.object(
            pathlib.Path,
            "read_text",
            autospec=True,
            side_effect=substitute_second_command_read,
        ):
            runtime = evidence_utils.wp05_frozen_action_runtime(self.manifest)
        self.assertNotEqual(runtime.get("kind"), "attacker-runtime")
        self.assertEqual(command_reads, 1)


if __name__ == "__main__":
    unittest.main()
