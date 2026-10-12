"""Build and inspect a WP-00 wheel in an isolated temporary directory."""

from __future__ import annotations

import json
import base64
import csv
import hashlib
import io
import stat
import pathlib
import sys
import tempfile
import zipfile

import build_backend


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="gew-build-check-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel = pathlib.Path(directory) / filename
        direct = f"{build_backend._distribution_name()}-{build_backend._version()}.data/scripts/graph-engineering"
        dist_info = build_backend._dist_info()
        with zipfile.ZipFile(wheel) as archive:
            members = archive.namelist()
            valid = (len(members) == len(set(members)) and all(
                member.startswith("graph_engineering/") or member.startswith(dist_info + "/") or member == direct
                for member in members))
            if members.count(direct) != 1:
                valid = False
            else:
                body = archive.read(direct)
                mode = archive.getinfo(direct).external_attr >> 16
                expected_hash = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
                rows = list(csv.reader(io.StringIO(archive.read(dist_info + "/RECORD").decode())))
                valid = (valid and stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o755
                    and body.startswith(b"#!python\n") and rows.count([direct, expected_hash, str(len(body))]) == 1
                    and b"graph-engineering =" not in archive.read(dist_info + "/entry_points.txt"))
        print(json.dumps({"status": "PASS" if valid else "FAIL", "filename": filename, "member_count": len(members)}, sort_keys=True))
        return 0 if valid else 1


if __name__ == "__main__":
    sys.exit(main())
