"""Run the complete WP-06 lifecycle and migration verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    gate = json.loads((ROOT / "config" / "verification" / "wp-06-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    passed = evidence_utils.passed_test_ids(records)
    failed = [
        record["test_id"] for record in records
        if record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
    ]
    try:
        stable_bindings = evidence_utils.wp06_test_bindings(gate)
        remedy_bindings = evidence_utils.wp06_reviewer_remedy_test_bindings(gate)
        bindings = stable_bindings + gate["evidence_test_bindings"] + remedy_bindings
        dependencies = evidence_utils.dependency_verdicts(gate)
        runtime = evidence_utils.wp06_runtime(gate)
        evidence_utils.wp06_governing_documents(gate)
    except (KeyError, TypeError, ValueError) as error:
        stable_bindings = []
        remedy_bindings = []
        bindings = []
        dependencies = []
        runtime = None
        failed.append(str(error))
    missing = sorted(
        binding["qualified_test"] for binding in bindings
        if binding["qualified_test"] not in passed
    )
    outcome = {
        "status": "PASS" if not failed and not missing else "FAIL",
        "failed_commands": failed,
        "missing_bound_tests": missing,
        "dependency_count": len(dependencies),
        "stable_test_binding_count": len(stable_bindings),
        "evidence_test_binding_count": len(gate.get("evidence_test_bindings", [])),
        "reviewer_remedy_binding_count": len(remedy_bindings),
        "migration_point_count": 0 if runtime is None else len(runtime["migration_points"]),
        "process_crash_point_count": 0 if runtime is None else len(runtime["process_crash_points"]),
        "concurrency_scenario_count": 0 if runtime is None else len(runtime["concurrency_scenarios"]),
        "runtime_digest": (
            evidence_utils.digest(evidence_utils.canonical_bytes(runtime))
            if runtime is not None else None
        ),
        "record_digests": [record["outcome_sha256"] for record in records],
    }
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
