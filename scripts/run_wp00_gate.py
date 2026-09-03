"""Run every command declared by the closed WP-00 verification manifest."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    manifest = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
    records: list[dict[str, object]] = []
    for command in manifest["commands"]:
        argv = [sys.executable if value == "{python}" else value for value in command["argv"]]
        result = subprocess.run(argv, cwd=ROOT, check=False, capture_output=True, text=True)
        records.append({
            "id": command["id"],
            "argv": argv,
            "exit_code": result.returncode,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
        })
        if result.returncode != 0:
            print(json.dumps({"status": "FAIL", "records": records}, sort_keys=True))
            return 1
    print(json.dumps({"status": "PASS", "records": records}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
