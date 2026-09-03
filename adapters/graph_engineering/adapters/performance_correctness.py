"""Protected read-only child for ADR-0007 correctness observations."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def main() -> int:
    """Return only the canonical correctness digest of the installed fixture."""

    if len(sys.argv) != 3 or sys.argv[2] != "correct":
        return 2
    path = pathlib.Path(sys.argv[1])
    try:
        document = json.loads(path.read_bytes())
        if (
            type(document) is not dict
            or tuple(document) != ("fixture_digest", "fixture_id", "payload", "schema_version")
            or document["schema_version"] != "1.0.0"
        ):
            return 3
        payload = json.dumps(
            document["payload"], ensure_ascii=False, separators=(",", ":"), sort_keys=True,
        ).encode("utf-8")
    except (OSError, UnicodeError, json.JSONDecodeError):
        return 4
    result = {
        "correctness_digest": "sha256-jcs-v1:" + hashlib.sha256(payload).hexdigest(),
    }
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
