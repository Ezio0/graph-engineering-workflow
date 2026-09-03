"""Run the WP-01 independent-implementation conformance suite."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main() -> int:
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests" / "conformance"), pattern="test_wp01_cross_implementation.py")
    result = unittest.TestResult()
    suite.run(result)
    payload = {
        "status": "PASS" if result.wasSuccessful() else "FAIL",
        "test_count": result.testsRun,
        "failure_count": len(result.failures),
        "error_count": len(result.errors),
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
