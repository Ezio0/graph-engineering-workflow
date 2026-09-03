"""Verify the complete digest-bound WP-04 candidate and independent review."""

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


def canonical_digest(value: object) -> str:
    return evidence_utils.digest(evidence_utils.canonical_bytes(value))


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
    documents = evidence_utils.governing_documents(
        paths=evidence_utils.WP04_GOVERNING_DOCUMENT_PATHS,
    )
    documents_digest = evidence_utils.governing_documents_digest(documents)
    if command_evidence.get("governing_documents") != documents:
        findings.append("GOVERNING_DOCUMENT_MISMATCH")
    gate = json.loads((ROOT / "config" / "verification" / "wp-04-gate.json").read_text())
    expected_commands = [
        (command["id"], evidence_utils.expand_argv(command)) for command in gate["commands"]
    ]
    commands = command_evidence.get("commands")
    actual_commands = [] if not isinstance(commands, list) else [
        (record.get("test_id"), record.get("argv")) for record in commands
    ]
    if (
        not isinstance(commands, list)
        or actual_commands != expected_commands
        or any(record.get("exit_code") != 0 for record in commands)
        or any(
            not isinstance(record.get("outcome"), dict)
            or record["outcome"].get("status") != "PASS"
            for record in commands
        )
        or any(record.get("outcome_sha256") != canonical_digest(record["outcome"]) for record in commands)
        or any(not evidence_utils.valid_digest(record.get("stderr_sha256")) for record in commands)
    ):
        findings.append("COMMAND_RECORD_MISMATCH")
    if rerun_commands and isinstance(commands, list):
        if evidence_utils.command_records(gate["commands"]) != commands:
            findings.append("COMMAND_REPLAY_MISMATCH")
    passed = evidence_utils.passed_test_ids(commands) if isinstance(commands, list) else set()
    bindings = command_evidence.get("test_bindings")
    if bindings != gate["test_bindings"] or any(
        binding["qualified_test"] not in passed for binding in gate["test_bindings"]
    ):
        findings.append("TEST_BINDING_MISMATCH")
    interpreter = command_evidence.get("interpreter")
    if (
        not isinstance(interpreter, dict)
        or interpreter.get("version") != platform.python_version()
        or interpreter.get("implementation") != platform.python_implementation()
        or interpreter.get("platform") != platform.platform()
        or pathlib.Path(str(interpreter.get("executable", ""))).resolve()
        != pathlib.Path(sys.executable).resolve()
        or interpreter.get("executable_sha256")
        != hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest()
    ):
        findings.append("INTERPRETER_MISMATCH")
    try:
        runtime = evidence_utils.artifact_runtime()
    except ValueError:
        runtime = None
    if command_evidence.get("artifact_runtime") != runtime:
        findings.append("ARTIFACT_RUNTIME_MISMATCH")
    try:
        dependencies = evidence_utils.dependency_verdicts(gate)
    except ValueError:
        dependencies = None
    if command_evidence.get("dependency_verdicts") != dependencies:
        findings.append("DEPENDENCY_VERDICT_MISMATCH")
    if (
        exit_record.get("schema_version") != "1.0"
        or exit_record.get("artifact") != "wp-04"
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or exit_record.get("command_evidence_digest") != canonical_digest(command_evidence)
        or exit_record.get("governing_documents_digest") != documents_digest
        or exit_record.get("artifact_runtime_digest") != canonical_digest(runtime)
        or exit_record.get("dependency_verdicts_digest") != canonical_digest(dependencies)
    ):
        findings.append("EXIT_BINDING_MISMATCH")
    author = exit_record.get("author_id")
    reviewer = exit_record.get("reviewer_id")
    if (
        not evidence_utils.valid_actor(author)
        or not evidence_utils.valid_actor(reviewer)
        or str(author).casefold() == str(reviewer).casefold()
    ):
        findings.append("REVIEWER_NOT_INDEPENDENT")
    if exit_record.get("test_ids") != ["GEW-WP-04-EXIT-P", "GEW-WP-04-EXIT-R"]:
        findings.append("EXIT_TEST_IDS_MISMATCH")
    if reviewer_verdict is not None and (
        reviewer_verdict.get("schema_version") != "1.0"
        or reviewer_verdict.get("artifact") != "wp-04"
        or reviewer_verdict.get("verdict") != "PASS"
        or not evidence_utils.valid_actor(reviewer_verdict.get("reviewer_id"))
        or str(reviewer_verdict.get("reviewer_id")).casefold() != str(reviewer).casefold()
        or reviewer_verdict.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or reviewer_verdict.get("command_evidence_digest") != canonical_digest(command_evidence)
        or reviewer_verdict.get("candidate_exit_digest") != canonical_digest(exit_record)
        or reviewer_verdict.get("governing_documents_digest") != documents_digest
        or reviewer_verdict.get("finding_dispositions") is None
        or reviewer_verdict.get("findings") != []
    ):
        findings.append("REVIEW_VERDICT_MISMATCH")
    if rebuild:
        with tempfile.TemporaryDirectory(prefix="gew-wp04-evidence-") as directory:
            filename = build_backend.build_wheel(directory)
            digest = hashlib.sha256((pathlib.Path(directory) / filename).read_bytes()).hexdigest()
        if command_evidence.get("wheel") != {"filename": filename, "sha256": digest}:
            findings.append("WHEEL_EVIDENCE_STALE")
    return findings


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) not in (3, 4):
        raise SystemExit("usage: verify_wp04_evidence.py SOURCE COMMANDS EXIT [VERDICT]")
    documents = [json.loads(pathlib.Path(path).read_text()) for path in arguments]
    findings = validate(
        documents[0], documents[1], documents[2],
        documents[3] if len(documents) == 4 else None,
        rebuild=True,
        rerun_commands=True,
    )
    print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
