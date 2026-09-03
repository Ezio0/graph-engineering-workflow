"""Disposable offline correctness child for ADR-0007 contract tests."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] != "correct":
        return 2
    document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    payload = document["payload"]
    canonical = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
    ).encode("utf-8")
    result = {
        "correctness_digest": "sha256-jcs-v1:" + hashlib.sha256(canonical).hexdigest(),
    }
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

