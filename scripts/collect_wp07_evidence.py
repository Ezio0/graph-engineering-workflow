"""Collect a digest-bound WP-07 runtime-adapter and Skill candidate."""

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


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: pathlib.PurePosixPath | None = None
    if arguments:
        if len(arguments) != 2 or arguments[0] != "--output":
            raise SystemExit("usage: collect_wp07_evidence.py [--output EVIDENCE]")
        output_path = pathlib.PurePosixPath(arguments[1])
        if (
            output_path.is_absolute()
            or output_path.suffix != ".json"
            or output_path.parts[:3] != (".workflow", "delivery", "GEW-IMPLEMENTATION-V1")
            or any(part in {"", ".", ".."} for part in output_path.parts)
        ):
            raise SystemExit("evidence output must be a task-local JSON path")
    gate = json.loads((ROOT / "config" / "verification" / "wp-07-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    if any(
        record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
        for record in records
    ):
        print(json.dumps({"status": "FAIL", "commands": records}, sort_keys=True))
        return 1
    stable_bindings = evidence_utils.wp07_test_bindings(gate)
    supplemental_bindings = evidence_utils.wp07_supplemental_test_bindings(gate)
    skill_bindings = evidence_utils.wp07_required_skill_test_bindings(gate)
    remedy_bindings = evidence_utils.wp07_reviewer_remedy_test_bindings(gate)
    evidence_bindings = gate["evidence_test_bindings"]
    all_bindings = (
        stable_bindings + supplemental_bindings + skill_bindings
        + remedy_bindings + evidence_bindings
    )
    passed = evidence_utils.passed_test_ids(records)
    execution_count = evidence_utils.passed_test_execution_count(records)
    missing = sorted({
        binding["qualified_test"] for binding in all_bindings
        if binding["qualified_test"] not in passed
    })
    minimum = gate.get("minimum_passed_test_count")
    if (
        missing or type(minimum) is not int or minimum < 800 or len(passed) < minimum
        or gate.get("expected_test_execution_count") != 804 or execution_count != 804
    ):
        print(json.dumps({
            "status": "FAIL",
            "missing_bound_tests": missing,
            "passed_test_count": len(passed),
            "minimum_passed_test_count": minimum,
            "test_execution_count": execution_count,
        }, sort_keys=True))
        return 1
    with tempfile.TemporaryDirectory(prefix="gew-wp07-wheel-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel_digest = evidence_utils.digest((pathlib.Path(directory) / filename).read_bytes())
    manifest = source_manifest.create_manifest()
    dependencies = evidence_utils.dependency_verdicts(gate)
    runtime = evidence_utils.wp07_runtime(gate)
    documents = evidence_utils.wp07_governing_documents(gate)
    sources = evidence_utils.wp07_source_records(gate, manifest)
    evidence = {
        "schema_version": "1.0",
        "status": "PASS",
        "source_manifest_digest": manifest["manifest_digest"],
        "wp07_sources": sources,
        "interpreter": {
            "executable": sys.executable,
            "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "wp07_runtime": runtime,
        "dependency_verdicts": dependencies,
        "commands": records,
        "governing_documents": documents,
        "stable_test_bindings": stable_bindings,
        "supplemental_test_bindings": supplemental_bindings,
        "required_skill_test_bindings": skill_bindings,
        "reviewer_remedy_test_bindings": remedy_bindings,
        "evidence_test_bindings": evidence_bindings,
        "passed_test_count": len(passed),
        "test_execution_count": execution_count,
        "wheel": {"filename": filename, "sha256": wheel_digest},
        "real_external_actions_enabled": False,
    }
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    if output_path is not None:
        (ROOT / output_path).write_text(encoded + "\n", encoding="utf-8")
        print(json.dumps({
            "status": "PASS",
            "source_manifest_digest": evidence["source_manifest_digest"],
            "command_evidence_digest": evidence_utils.digest(encoded.encode()),
            "passed_test_count": len(passed),
            "test_execution_count": execution_count,
        }, sort_keys=True))
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
