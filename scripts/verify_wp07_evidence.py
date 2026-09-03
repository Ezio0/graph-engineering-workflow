"""Verify the complete digest-bound WP-07 candidate and independent review."""

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
    try:
        source_findings = source_manifest.verify(expected_source)
    except (OSError, ValueError, KeyError, TypeError):
        source_findings = ["SOURCE_MANIFEST_MISMATCH"]
    if source_findings:
        findings.append("SOURCE_MANIFEST_MISMATCH")
    if (
        command_evidence.get("schema_version") != "1.0"
        or command_evidence.get("status") != "PASS"
        or command_evidence.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or command_evidence.get("real_external_actions_enabled") is not False
    ):
        findings.append("COMMAND_SOURCE_BINDING_MISMATCH")

    gate = json.loads((ROOT / "config" / "verification" / "wp-07-gate.json").read_text())
    try:
        sources = evidence_utils.wp07_source_records(gate, expected_source)
    except ValueError:
        sources = None
    if command_evidence.get("wp07_sources") != sources:
        findings.append("WP07_SOURCE_BINDING_MISMATCH")
    try:
        documents = evidence_utils.wp07_frozen_governing_documents(gate)
    except ValueError:
        documents = []
    documents_digest = evidence_utils.governing_documents_digest(documents)
    if command_evidence.get("governing_documents") != documents:
        findings.append("GOVERNING_DOCUMENT_MISMATCH")

    expected_commands = [
        (command["id"], evidence_utils.expand_argv(command)) for command in gate["commands"]
    ]
    commands = command_evidence.get("commands")
    actual_commands = [] if not isinstance(commands, list) else [
        (record.get("test_id"), record.get("argv"))
        for record in commands if isinstance(record, dict)
    ]
    command_records_valid = isinstance(commands, list) and all(
        isinstance(record, dict)
        and record.get("exit_code") == 0
        and isinstance(record.get("outcome"), dict)
        and record["outcome"].get("status") == "PASS"
        and record.get("outcome_sha256") == canonical_digest(record["outcome"])
        and evidence_utils.valid_digest(record.get("stderr_sha256"))
        for record in commands
    )
    if not command_records_valid or actual_commands != expected_commands:
        findings.append("COMMAND_RECORD_MISMATCH")
    if rerun_commands and isinstance(commands, list):
        if evidence_utils.command_records(gate["commands"]) != commands:
            findings.append("COMMAND_REPLAY_MISMATCH")

    try:
        stable_bindings = evidence_utils.wp07_frozen_test_bindings(gate)
        supplemental_bindings = evidence_utils.wp07_supplemental_test_bindings(gate)
        skill_bindings = evidence_utils.wp07_required_skill_test_bindings(gate)
        remedy_bindings = evidence_utils.wp07_reviewer_remedy_test_bindings(gate)
    except ValueError:
        stable_bindings = []
        supplemental_bindings = []
        skill_bindings = []
        remedy_bindings = []
    evidence_bindings = gate.get("evidence_test_bindings")
    passed = evidence_utils.passed_test_ids(commands) if isinstance(commands, list) else set()
    execution_count = (
        evidence_utils.passed_test_execution_count(commands)
        if isinstance(commands, list) else 0
    )
    minimum = gate.get("minimum_passed_test_count")
    if (
        command_evidence.get("stable_test_bindings") != stable_bindings
        or command_evidence.get("supplemental_test_bindings") != supplemental_bindings
        or command_evidence.get("required_skill_test_bindings") != skill_bindings
        or command_evidence.get("reviewer_remedy_test_bindings") != remedy_bindings
        or command_evidence.get("evidence_test_bindings") != evidence_bindings
        or not isinstance(evidence_bindings, list)
        or type(minimum) is not int or minimum < 800
        or len(passed) < minimum
        or command_evidence.get("passed_test_count") != len(passed)
        or gate.get("expected_test_execution_count") != 804
        or execution_count != 804
        or command_evidence.get("test_execution_count") != execution_count
        or any(
            binding["qualified_test"] not in passed
            for binding in (
                stable_bindings + supplemental_bindings + skill_bindings
                + remedy_bindings + evidence_bindings
            )
        )
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
        runtime = evidence_utils.wp07_frozen_runtime(gate)
    except ValueError:
        runtime = None
    if command_evidence.get("wp07_runtime") != runtime:
        findings.append("WP07_RUNTIME_MISMATCH")
    try:
        dependencies = evidence_utils.dependency_verdicts(gate)
    except ValueError:
        dependencies = None
    if command_evidence.get("dependency_verdicts") != dependencies:
        findings.append("DEPENDENCY_VERDICT_MISMATCH")

    if (
        exit_record.get("schema_version") != "1.0"
        or exit_record.get("artifact") != "wp-07"
        or exit_record.get("status") != "CANDIDATE"
        or exit_record.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or exit_record.get("command_evidence_digest") != canonical_digest(command_evidence)
        or exit_record.get("governing_documents_digest") != documents_digest
        or exit_record.get("wp07_runtime_digest") != canonical_digest(runtime)
        or exit_record.get("wp07_sources_digest") != canonical_digest(sources)
        or exit_record.get("dependency_verdicts_digest") != canonical_digest(dependencies)
        or exit_record.get("real_external_actions_enabled") is not False
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
    if exit_record.get("test_ids") != ["GEW-WP-07-EXIT-P", "GEW-WP-07-EXIT-R"]:
        findings.append("EXIT_TEST_IDS_MISMATCH")

    if reviewer_verdict is not None and (
        reviewer_verdict.get("schema_version") != "1.0"
        or reviewer_verdict.get("artifact") != "wp-07"
        or reviewer_verdict.get("verdict") != "PASS"
        or reviewer_verdict.get("scope_changed") is not False
        or not evidence_utils.valid_actor(reviewer_verdict.get("reviewer_id"))
        or str(reviewer_verdict.get("reviewer_id")).casefold() != str(reviewer).casefold()
        or reviewer_verdict.get("source_manifest_digest") != expected_source.get("manifest_digest")
        or reviewer_verdict.get("command_evidence_digest") != canonical_digest(command_evidence)
        or reviewer_verdict.get("candidate_exit_digest") != canonical_digest(exit_record)
        or reviewer_verdict.get("governing_documents_digest") != documents_digest
        or reviewer_verdict.get("wp07_runtime_digest") != canonical_digest(runtime)
        or reviewer_verdict.get("wp07_sources_digest") != canonical_digest(sources)
        or reviewer_verdict.get("dependency_verdicts_digest") != canonical_digest(dependencies)
        or not isinstance(reviewer_verdict.get("finding_dispositions"), list)
        or any(
            not isinstance(item, dict) or item.get("status") != "closed"
            for item in reviewer_verdict.get("finding_dispositions", [])
        )
        or reviewer_verdict.get("findings") != []
    ):
        findings.append("REVIEW_VERDICT_MISMATCH")
    if rebuild:
        with tempfile.TemporaryDirectory(prefix="gew-wp07-evidence-") as directory:
            filename = build_backend.build_wheel(directory)
            wheel_digest = hashlib.sha256((pathlib.Path(directory) / filename).read_bytes()).hexdigest()
        if command_evidence.get("wheel") != {"filename": filename, "sha256": wheel_digest}:
            findings.append("WHEEL_EVIDENCE_STALE")
    return findings


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 4:
        raise SystemExit("usage: verify_wp07_evidence.py SOURCE COMMANDS EXIT VERDICT")
    documents = [json.loads(pathlib.Path(path).read_text()) for path in arguments]
    findings = validate(
        documents[0], documents[1], documents[2], documents[3],
        rebuild=True, rerun_commands=True,
    )
    print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
