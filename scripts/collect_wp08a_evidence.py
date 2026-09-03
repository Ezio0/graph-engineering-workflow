"""Collect source, command, and exit records for a WP-08A candidate without a verdict."""

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


def _output_path(value: str, kind: str) -> pathlib.PurePosixPath:
    path = pathlib.PurePosixPath(value)
    if (
        path.is_absolute() or path.suffix != ".json"
        or path.parts[:3] != (".workflow", "delivery", "GEW-IMPLEMENTATION-V1")
        or any(part in {"", ".", ".."} for part in path.parts)
        or kind not in path.name
    ):
        raise SystemExit(f"{kind} output must be a task-local JSON path")
    return path


def _write_new(path: pathlib.PurePosixPath, value: dict[str, object]) -> None:
    target = ROOT / path
    if target.exists() or target.is_symlink():
        raise SystemExit(f"refusing to overwrite historical evidence: {path}")
    target.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 6 or arguments[::2] != [
        "--source-output", "--command-output", "--exit-output",
    ]:
        raise SystemExit(
            "usage: collect_wp08a_evidence.py --source-output SOURCE "
            "--command-output COMMANDS --exit-output EXIT"
        )
    source_output = _output_path(arguments[1], "source-manifest")
    command_output = _output_path(arguments[3], "command-evidence")
    exit_output = _output_path(arguments[5], "exit")
    if len({source_output, command_output, exit_output}) != 3:
        raise SystemExit("evidence output paths must be distinct")

    gate = json.loads((ROOT / "config/verification/wp-08a-gate.json").read_text())
    manifest = source_manifest.create_manifest()
    records = evidence_utils.command_records(gate["commands"])
    if any(
        record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
        for record in records
    ):
        print(json.dumps({"status": "FAIL", "commands": records}, sort_keys=True))
        return 1
    if source_manifest.create_manifest() != manifest:
        print(json.dumps({"status": "FAIL", "finding": "SOURCE_CHANGED_DURING_COLLECTION"}))
        return 1

    stable = evidence_utils.wp08a_test_bindings(gate)
    supplemental = evidence_utils.wp08a_supplemental_test_bindings(gate)
    remedies = evidence_utils.wp08a_reviewer_remedy_test_bindings(gate)
    evidence_bindings = gate["evidence_test_bindings"]
    passed = evidence_utils.passed_test_ids(records)
    execution_count = evidence_utils.passed_test_execution_count(records)
    missing = sorted({
        binding["qualified_test"]
        for binding in stable + supplemental + remedies + evidence_bindings
        if binding["qualified_test"] not in passed
    })
    minimum = gate.get("minimum_passed_test_count")
    expected = gate.get("expected_test_execution_count")
    if (
        missing or type(minimum) is not int or len(passed) < minimum
        or type(expected) is not int or execution_count != expected
    ):
        print(json.dumps({
            "status": "FAIL", "missing_bound_tests": missing,
            "passed_test_count": len(passed), "minimum_passed_test_count": minimum,
            "test_execution_count": execution_count,
            "expected_test_execution_count": expected,
        }, sort_keys=True))
        return 1

    with tempfile.TemporaryDirectory(prefix="gew-wp08a-wheel-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel_digest = evidence_utils.digest((pathlib.Path(directory) / filename).read_bytes())
    dependencies = evidence_utils.dependency_verdicts(gate)
    runtime = evidence_utils.wp08a_runtime(gate)
    runtime_dependencies = evidence_utils.wp08a_runtime_dependencies(gate)
    boundary = evidence_utils.wp08a_external_action_boundary(gate)
    identities = evidence_utils.wp08a_candidate_identities(gate)
    documents = evidence_utils.wp08a_governing_documents(gate)
    sources = evidence_utils.wp08a_source_records(gate, manifest)
    evidence: dict[str, object] = {
        "schema_version": "1.0",
        "status": "PASS",
        "source_manifest_digest": manifest["manifest_digest"],
        "wp08a_sources": sources,
        "interpreter": {
            "executable": sys.executable,
            "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "wp08a_runtime": runtime,
        "wp08a_runtime_dependencies": runtime_dependencies,
        "external_action_boundary": boundary,
        "candidate_identities": identities,
        "dependency_verdicts": dependencies,
        "commands": records,
        "governing_documents": documents,
        "stable_test_bindings": stable,
        "supplemental_test_bindings": supplemental,
        "reviewer_remedy_test_bindings": remedies,
        "evidence_test_bindings": evidence_bindings,
        "passed_test_count": len(passed),
        "test_execution_count": execution_count,
        "wheel": {"filename": filename, "sha256": wheel_digest},
        "real_external_actions_enabled": False,
    }
    command_digest = evidence_utils.digest(evidence_utils.canonical_bytes(evidence))
    exit_record: dict[str, object] = {
        "schema_version": "1.0",
        "artifact": "wp-08a",
        "status": "CANDIDATE",
        "author_id": identities["author_id"],
        "reviewer_id": identities["reviewer_id"],
        "source_manifest_digest": manifest["manifest_digest"],
        "command_evidence_digest": command_digest,
        "governing_documents_digest": evidence_utils.governing_documents_digest(documents),
        "wp08a_runtime_digest": evidence_utils.digest(evidence_utils.canonical_bytes(runtime)),
        "wp08a_runtime_dependencies_digest": evidence_utils.digest(
            evidence_utils.canonical_bytes(runtime_dependencies)
        ),
        "wp08a_sources_digest": evidence_utils.digest(evidence_utils.canonical_bytes(sources)),
        "external_action_boundary_digest": evidence_utils.digest(
            evidence_utils.canonical_bytes(boundary)
        ),
        "dependency_verdicts_digest": evidence_utils.digest(
            evidence_utils.canonical_bytes(dependencies)
        ),
        "real_external_actions_enabled": False,
        "test_ids": ["GEW-WP-08A-EXIT-P", "GEW-WP-08A-EXIT-R"],
    }
    _write_new(source_output, manifest)
    _write_new(command_output, evidence)
    _write_new(exit_output, exit_record)
    print(json.dumps({
        "status": "PASS",
        "source_manifest_digest": manifest["manifest_digest"],
        "source_row_count": len(manifest["files"]),
        "wp08a_source_count": len(sources),
        "command_evidence_digest": command_digest,
        "candidate_exit_digest": evidence_utils.digest(
            evidence_utils.canonical_bytes(exit_record)
        ),
        "passed_test_count": len(passed),
        "test_execution_count": execution_count,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
