"""Run every command in the closed WP-01 verification manifest."""

from __future__ import annotations

import json
import pathlib
import sys

import evidence_utils


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = json.loads((ROOT / "config" / "verification" / "wp-01-gate.json").read_text(encoding="utf-8"))
    records = evidence_utils.command_records(manifest["commands"])
    passed = all(record["exit_code"] == 0 and record["outcome"].get("status") == "PASS" for record in records)  # type: ignore[union-attr]
    print(json.dumps({"status": "PASS" if passed else "FAIL", "records": records}, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
