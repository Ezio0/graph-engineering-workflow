"""Validate digest binding and independence fields for WP-00 evidence."""

from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import sys
import tempfile

import build_backend
import evidence_utils
import source_manifest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _canonical_digest(value: object) -> str:
    return evidence_utils.digest(evidence_utils.canonical_bytes(value))


def _valid_actor(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip() and value.isascii()


def validate(
    expected_source: dict[str, object],
    command_evidence: dict[str, object],
    exit_record: dict[str, object],
    reviewer_verdict: dict[str, object] | None = None,
    *,
    rebuild: bool = False,
    rerun_commands: bool = False,
) -> list[str]:
    findings: list[str] = []
    if source_manifest.verify(expected_source):
        findings.append("SOURCE_MANIFEST_MISMATCH")
    if command_evidence.get("source_manifest_digest") != expected_source.get("manifest_digest"):
        findings.append("COMMAND_SOURCE_BINDING_MISMATCH")
    gate = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
    expected_positive = [command["id"] for command in gate["commands"]]
    expected_commands = [
        (
            command["id"],
            [sys.executable if value == "{python}" else value for value in command["argv"]],
        )
        for command in gate["commands"]
    ]
    commands = command_evidence.get("commands")
    actual_commands = [] if not isinstance(commands, list) else [
        (record.get("test_id"), record.get("argv")) for record in commands
    ]
    digest_fields_valid = isinstance(commands, list) and all(
        evidence_utils.valid_digest(record.get(field))
        for record in commands
        for field in ("outcome_sha256", "stderr_sha256")
    )
    outcome_fields_valid = isinstance(commands, list) and all(
        isinstance(record.get("outcome"), dict)
        and record["outcome"].get("status") == "PASS"  # type: ignore[union-attr]
        and record.get("outcome_sha256") == evidence_utils.digest(evidence_utils.canonical_bytes(record["outcome"]))
        for record in commands
    )
    if (
        not isinstance(commands, list)
        or [record.get("test_id") for record in commands] != expected_positive
        or actual_commands != expected_commands
        or any(record.get("exit_code") != 0 for record in commands)
        or not digest_fields_valid
        or not outcome_fields_valid
    ):
        findings.append("COMMAND_RECORD_MISMATCH")
    if rerun_commands and isinstance(commands, list):
        replayed = evidence_utils.command_records(gate["commands"])
        if replayed != commands:
            findings.append("COMMAND_REPLAY_MISMATCH")
    reject_records = command_evidence.get("reject_tests")
    expected_rejects = [
        {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
        for test_id, qualified_test in sorted(evidence_utils.REQUIRED_REJECT_TESTS.items())
    ]
    exit_records = command_evidence.get("exit_tests")
    expected_exits = [
        {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
        for test_id, qualified_test in sorted(evidence_utils.REQUIRED_EXIT_TESTS.items())
    ]
    passed_tests = evidence_utils.passed_test_ids(commands) if isinstance(commands, list) else set()
    required_qualified = set(evidence_utils.REQUIRED_REJECT_TESTS.values()) | set(evidence_utils.REQUIRED_EXIT_TESTS.values())
    if reject_records != expected_rejects or exit_records != expected_exits or not required_qualified.issubset(passed_tests):
        findings.append("REJECT_TEST_RECORD_MISMATCH")
    interpreter = command_evidence.get("interpreter")
    if (
        not isinstance(interpreter, dict)
        or interpreter.get("version") != platform.python_version()
        or interpreter.get("implementation") != platform.python_implementation()
        or interpreter.get("platform") != platform.platform()
        or pathlib.Path(str(interpreter.get("executable", ""))).resolve() != pathlib.Path(sys.executable).resolve()
        or interpreter.get("executable_sha256") != hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest()
    ):
        findings.append("INTERPRETER_MISMATCH")
    if (
        not evidence_utils.valid_digest(expected_source.get("manifest_digest"))
        or not evidence_utils.valid_digest(command_evidence.get("source_manifest_digest"))
        or exit_record.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or exit_record.get("command_evidence_digest") != _canonical_digest(command_evidence)
    ):
        findings.append("EXIT_BINDING_MISMATCH")
    author_id = exit_record.get("author_id")
    reviewer_id = exit_record.get("reviewer_id")
    if not _valid_actor(author_id) or not _valid_actor(reviewer_id) or str(author_id).casefold() == str(reviewer_id).casefold():
        findings.append("REVIEWER_NOT_INDEPENDENT")
    if exit_record.get("test_ids") != ["GEW-WP-00-EXIT-P", "GEW-WP-00-EXIT-R"]:
        findings.append("EXIT_TEST_IDS_MISMATCH")
    if reviewer_verdict is not None:
        if (
            reviewer_verdict.get("verdict") != "PASS"
            or not _valid_actor(reviewer_verdict.get("reviewer_id"))
            or str(reviewer_verdict.get("reviewer_id")).casefold() != str(reviewer_id).casefold()
            or reviewer_verdict.get("source_manifest_digest") != expected_source.get("manifest_digest")
            or reviewer_verdict.get("command_evidence_digest") != _canonical_digest(command_evidence)
            or reviewer_verdict.get("candidate_exit_digest") != _canonical_digest(exit_record)
        ):
            findings.append("REVIEW_VERDICT_MISMATCH")
    if rebuild:
        with tempfile.TemporaryDirectory(prefix="gew-evidence-rebuild-") as directory:
            filename = build_backend.build_wheel(directory)
            digest = hashlib.sha256((pathlib.Path(directory) / filename).read_bytes()).hexdigest()
        if command_evidence.get("wheel") != {"filename": filename, "sha256": digest}:
            findings.append("WHEEL_EVIDENCE_STALE")
    return findings


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) not in (3, 4):
        raise SystemExit("usage: verify_evidence.py SOURCE COMMANDS EXIT [VERDICT]")
    documents = [json.loads(pathlib.Path(path).read_text(encoding="utf-8")) for path in arguments]
    findings = validate(
        documents[0],
        documents[1],
        documents[2],
        documents[3] if len(documents) == 4 else None,
        rebuild=True,
        rerun_commands=True,
    )
    print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
