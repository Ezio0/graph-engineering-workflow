"""Bounded local verifier used by the new-feature real-E2E command adapter."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys


def main(arguments: list[str]) -> int:
    if len(arguments) != 4:
        return 2
    artifact_relative, artifact_sha256, expected_oid, git_executable = arguments
    artifact_path = pathlib.Path(artifact_relative)
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        return 2
    completed = subprocess.run(
        (git_executable, "rev-parse", "HEAD"),
        shell=False,
        check=False,
        capture_output=True,
        timeout=5,
    )
    artifact = subprocess.run(
        (git_executable, "show", f"HEAD:{artifact_path.as_posix()}"),
        shell=False,
        check=False,
        capture_output=True,
        timeout=5,
    )
    try:
        head_oid = completed.stdout.decode("ascii", errors="strict").strip()
        body = artifact.stdout
    except (OSError, UnicodeError):
        return 2
    observed_sha256 = hashlib.sha256(body).hexdigest()
    accepted = (
        completed.returncode == 0
        and artifact.returncode == 0
        and head_oid == expected_oid
        and observed_sha256 == artifact_sha256
    )
    print(json.dumps({
        "accepted": accepted,
        "artifact_sha256": observed_sha256,
        "head_oid": head_oid,
    }, sort_keys=True, separators=(",", ":")))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
