"""Run the complete WP-04 Application Runner verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    gate = json.loads((ROOT / "config" / "verification" / "wp-04-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    passed = evidence_utils.passed_test_ids(records)
    missing = sorted(
        binding["qualified_test"] for binding in gate["test_bindings"]
        if binding["qualified_test"] not in passed
    )
    failed = [
        record["test_id"] for record in records
        if record["exit_code"] != 0 or record["outcome"].get("status") != "PASS"
    ]
    outcome = {
        "status": "PASS" if not failed and not missing else "FAIL",
        "failed_commands": failed,
        "missing_bound_tests": missing,
        "record_digests": [record["outcome_sha256"] for record in records],
    }
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 0 if outcome["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
