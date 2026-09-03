"""Build and inspect a WP-00 wheel in an isolated temporary directory."""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import zipfile

import build_backend


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gew-build-check-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel = pathlib.Path(directory) / filename
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
        valid = all(member.startswith("graph_engineering/") or ".dist-info/" in member for member in members)
        print(json.dumps({"status": "PASS" if valid else "FAIL", "filename": filename, "member_count": len(members)}, sort_keys=True))
        return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
