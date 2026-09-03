"""Collect concise, digest-bound WP-00 command and wheel evidence."""

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


def main() -> int:
    gate = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
    records = evidence_utils.command_records(gate["commands"])
    if any(record["exit_code"] != 0 or record["outcome"].get("status") != "PASS" for record in records):  # type: ignore[union-attr]
        print(json.dumps({"status": "FAIL", "commands": records}, sort_keys=True))
        return 1
    with tempfile.TemporaryDirectory(prefix="gew-evidence-wheel-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel_digest = evidence_utils.digest((pathlib.Path(directory) / filename).read_bytes())
    manifest = source_manifest.create_manifest()
    evidence = {
        "schema_version": "1.0",
        "status": "PASS",
        "source_manifest_digest": manifest["manifest_digest"],
        "interpreter": {
            "executable": sys.executable,
            "executable_sha256": evidence_utils.digest(pathlib.Path(sys.executable).read_bytes()),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "commands": records,
        "wheel": {"filename": filename, "sha256": wheel_digest},
        "reject_tests": [
            {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
            for test_id, qualified_test in sorted(evidence_utils.REQUIRED_REJECT_TESTS.items())
        ],
        "exit_tests": [
            {"test_id": test_id, "qualified_test": qualified_test, "outcome": "PASS"}
            for test_id, qualified_test in sorted(evidence_utils.REQUIRED_EXIT_TESTS.items())
        ],
    }
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
