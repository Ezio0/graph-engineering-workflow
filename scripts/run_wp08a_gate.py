"""Run the complete WP-08A offline extension candidate verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    gate = json.loads((ROOT / "config/verification/wp-08a-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    passed = evidence_utils.passed_test_ids(records)
    execution_count = evidence_utils.passed_test_execution_count(records)
    failed = [
        record["test_id"] for record in records
        if record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
    ]
    try:
        stable = evidence_utils.wp08a_test_bindings(gate)
        supplemental = evidence_utils.wp08a_supplemental_test_bindings(gate)
        remedies = evidence_utils.wp08a_reviewer_remedy_test_bindings(gate)
        evidence = gate["evidence_test_bindings"]
        dependencies = evidence_utils.dependency_verdicts(gate)
        runtime = evidence_utils.wp08a_runtime(gate)
        runtime_dependencies = evidence_utils.wp08a_runtime_dependencies(gate)
        boundary = evidence_utils.wp08a_external_action_boundary(gate)
        evidence_utils.wp08a_candidate_identities(gate)
        evidence_utils.wp08a_governing_documents(gate)
    except (KeyError, TypeError, ValueError) as error:
        stable, supplemental, remedies, evidence, dependencies = [], [], [], [], []
        runtime, runtime_dependencies, boundary = None, None, None
        failed.append(str(error))
    bindings = stable + supplemental + remedies + evidence
    missing = sorted({
        binding["qualified_test"] for binding in bindings
        if binding["qualified_test"] not in passed
    })
    minimum = gate.get("minimum_passed_test_count")
    expected = gate.get("expected_test_execution_count")
    if type(minimum) is not int or len(passed) < minimum:
        failed.append("MINIMUM_PASSED_TEST_COUNT_MISMATCH")
    if type(expected) is not int or execution_count != expected:
        failed.append("TEST_EXECUTION_COUNT_MISMATCH")
    outcome = {
        "status": "PASS" if not failed and not missing else "FAIL",
        "failed_commands": failed,
        "missing_bound_tests": missing,
        "passed_test_count": len(passed),
        "test_execution_count": execution_count,
        "dependency_count": len(dependencies),
        "stable_test_binding_count": len(stable),
        "supplemental_test_binding_count": len(supplemental),
        "reviewer_remedy_binding_count": len(remedies),
        "evidence_test_binding_count": len(evidence),
        "runtime_input_count": 0 if runtime is None else len(runtime["inputs"]),
        "schema_count": 0 if runtime is None else runtime["schema_count"],
        "runtime_source_count": 0 if runtime is None else runtime["runtime_source_count"],
        "runtime_dependency_count": (
            0 if runtime_dependencies is None
            else len(runtime_dependencies["candidate_runtime_distributions"])
        ),
        "external_action_boundary": boundary,
        "runtime_digest": (
            None if runtime is None
            else evidence_utils.digest(evidence_utils.canonical_bytes(runtime))
        ),
        "runtime_dependencies_digest": (
            None if runtime_dependencies is None
            else evidence_utils.digest(evidence_utils.canonical_bytes(runtime_dependencies))
        ),
        "record_digests": [record["outcome_sha256"] for record in records],
    }
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
