"""Validate the machine-readable WP-00 platform matrix."""

from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(document: dict[str, object]) -> list[str]:
    findings: list[str] = []
    cells = document.get("cells")
    if document.get("schema_version") != "1.0" or not isinstance(cells, list) or not cells:
        return ["INVALID_MATRIX_SHAPE"]
    identities: set[str] = set()
    systems: set[str] = set()
    for cell in cells:
        if not isinstance(cell, dict):
            findings.append("INVALID_CELL")
            continue
        required = ("id", "os", "architecture", "python", "required_suite")
        if any(not isinstance(cell.get(field), str) or not cell[field] for field in required):
            findings.append("INCOMPLETE_CELL")
            continue
        if cell["id"] in identities:
            findings.append("DUPLICATE_CELL")
        identities.add(cell["id"])
        systems.add(cell["os"])
    if systems != {"macos", "linux"}:
        findings.append("MISSING_REQUIRED_OS")
    return findings


def main() -> int:
    path = ROOT / "config" / "release-coverage" / "platform-matrix-v1.json"
    findings = validate(json.loads(path.read_text(encoding="utf-8")))
    print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
