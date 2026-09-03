"""Run the complete WP-07 runtime-adapter and Skill verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    gate = json.loads((ROOT / "config" / "verification" / "wp-07-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    passed = evidence_utils.passed_test_ids(records)
    execution_count = evidence_utils.passed_test_execution_count(records)
    failed = [
        record["test_id"] for record in records
        if record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
    ]
    try:
        stable_bindings = evidence_utils.wp07_test_bindings(gate)
        supplemental_bindings = evidence_utils.wp07_supplemental_test_bindings(gate)
        skill_bindings = evidence_utils.wp07_required_skill_test_bindings(gate)
        remedy_bindings = evidence_utils.wp07_reviewer_remedy_test_bindings(gate)
        evidence_bindings = gate["evidence_test_bindings"]
        bindings = (
            stable_bindings + supplemental_bindings + skill_bindings
            + remedy_bindings + evidence_bindings
        )
        dependencies = evidence_utils.dependency_verdicts(gate)
        runtime = evidence_utils.wp07_runtime(gate)
        evidence_utils.wp07_governing_documents(gate)
    except (KeyError, TypeError, ValueError) as error:
        stable_bindings = []
        supplemental_bindings = []
        skill_bindings = []
        remedy_bindings = []
        evidence_bindings = []
        bindings = []
        dependencies = []
        runtime = None
        failed.append(str(error))
    missing = sorted({
        binding["qualified_test"] for binding in bindings
        if binding["qualified_test"] not in passed
    })
    minimum = gate.get("minimum_passed_test_count")
    if type(minimum) is not int or minimum < 800 or len(passed) < minimum:
        failed.append("MINIMUM_PASSED_TEST_COUNT_MISMATCH")
    if gate.get("expected_test_execution_count") != 804 or execution_count != 804:
        failed.append("TEST_EXECUTION_COUNT_MISMATCH")
    outcome = {
        "status": "PASS" if not failed and not missing else "FAIL",
        "failed_commands": failed,
        "missing_bound_tests": missing,
        "passed_test_count": len(passed),
        "test_execution_count": execution_count,
        "dependency_count": len(dependencies),
        "stable_test_binding_count": len(stable_bindings),
        "supplemental_test_binding_count": len(supplemental_bindings),
        "required_skill_test_binding_count": len(skill_bindings),
        "reviewer_remedy_binding_count": len(remedy_bindings),
        "evidence_test_binding_count": len(evidence_bindings),
        "runtime_cell_count": 0 if runtime is None else len(runtime["fixture"]["cell_ids"]),
        "skill_asset_count": 0 if runtime is None else len(runtime["skill_assets"]),
        "capability_field_count": (
            0 if runtime is None
            else len(runtime["configuration_contract"]["capability_fields"])
        ),
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
