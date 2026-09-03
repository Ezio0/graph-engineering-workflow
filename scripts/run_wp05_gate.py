"""Run the complete WP-05 authority, action, and recovery verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    gate = json.loads((ROOT / "config" / "verification" / "wp-05-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    passed = evidence_utils.passed_test_ids(records)
    bindings = gate["test_bindings"] + evidence_utils.wp05_exact_gate_test_bindings(gate)
    missing = sorted(
        binding["qualified_test"] for binding in bindings
        if binding["qualified_test"] not in passed
    )
    failed = [
        record["test_id"] for record in records
        if record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
    ]
    try:
        dependencies = evidence_utils.dependency_verdicts(gate)
        runtime = evidence_utils.action_runtime()
        evidence_utils.wp05_governing_documents(gate)
    except ValueError as error:
        dependencies = []
        runtime = None
        failed.append(str(error))
    outcome = {
        "status": "PASS" if not failed and not missing else "FAIL",
        "failed_commands": failed,
        "missing_bound_tests": missing,
        "dependency_count": len(dependencies),
        "exact_gate_binding_count": len(bindings) - len(gate["test_bindings"]),
        "action_runtime_digest": (
            evidence_utils.digest(evidence_utils.canonical_bytes(runtime))
            if runtime is not None else None
        ),
        "record_digests": [record["outcome_sha256"] for record in records],
    }
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
