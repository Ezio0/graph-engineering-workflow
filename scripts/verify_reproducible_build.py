"""Prove two dependency-free wheel builds are byte-identical."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import tempfile

import build_backend


def _digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gew-repro-check-") as directory:
        root = pathlib.Path(directory)
        first = root / "first"
        second = root / "second"
        first_name = build_backend.build_wheel(str(first))
        second_name = build_backend.build_wheel(str(second))
        first_digest = _digest(first / first_name)
        second_digest = _digest(second / second_name)
        passed = first_name == second_name and first_digest == second_digest
        print(json.dumps({"status": "PASS" if passed else "FAIL", "wheel": first_name, "sha256": first_digest}, sort_keys=True))
        return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
