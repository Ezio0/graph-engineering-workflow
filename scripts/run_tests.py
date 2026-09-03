"""Run the dependency-free local test suite under the selected interpreter."""

from __future__ import annotations

import json
import pathlib
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
import io
import os
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


for responsibility_root in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility_root))


class RecordingResult(unittest.TestResult):
    def __init__(self) -> None:
        super().__init__()
        self.outcomes: list[dict[str, str]] = []

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        super().addSuccess(test)
        self.outcomes.append({"id": test.id(), "status": "PASS"})

    def addFailure(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:
        super().addFailure(test, err)  # type: ignore[arg-type]
        self.outcomes.append({"id": test.id(), "status": "FAIL"})

    def addError(self, test: unittest.case.TestCase, err: tuple[type[BaseException], BaseException, object]) -> None:
        super().addError(test, err)  # type: ignore[arg-type]
        self.outcomes.append({"id": test.id(), "status": "ERROR"})

    def addSkip(self, test: unittest.case.TestCase, reason: str) -> None:
        super().addSkip(test, reason)
        self.outcomes.append({"id": test.id(), "status": "SKIP"})


def _run_suite() -> int:
    manifest = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    discovered: list[str] = []
    for suite_name in manifest["test_suites"]:
        directory = ROOT / "tests" / suite_name
        if not directory.is_dir():
            raise SystemExit(f"missing declared test suite: {suite_name}")
        discovered.append(suite_name)
        suite.addTests(loader.discover(str(directory), pattern="test_*.py"))
    if suite.countTestCases() == 0:
        raise SystemExit("no tests discovered")
    result = RecordingResult()
    with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
        suite.run(result)
    payload = {
        "status": "PASS" if result.wasSuccessful() else "FAIL",
        "suite_count": len(discovered),
        "test_count": result.testsRun,
        "tests": sorted(result.outcomes, key=lambda item: item["id"]),
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    sys.path.insert(0, str(ROOT))
    from tests.support.source_checkout_attestation import (
        CONTROL_ENVIRONMENT,
        CONTROL_OPTION,
        issue_source_checkout_attestation,
    )

    previous = os.environ.get(CONTROL_ENVIRONMENT)
    previous_option = sys._xoptions.get(CONTROL_OPTION)
    with tempfile.TemporaryDirectory(prefix="gew-source-test-control-") as directory:
        control_root = pathlib.Path(directory)
        issue_source_checkout_attestation(ROOT, control_root)
        control_root = control_root.resolve(strict=True)
        os.environ[CONTROL_ENVIRONMENT] = os.fspath(control_root)
        sys._xoptions[CONTROL_OPTION] = os.fspath(control_root)
        try:
            return _run_suite()
        finally:
            if previous_option is None:
                sys._xoptions.pop(CONTROL_OPTION, None)
            else:
                sys._xoptions[CONTROL_OPTION] = previous_option
            if previous is None:
                os.environ.pop(CONTROL_ENVIRONMENT, None)
            else:
                os.environ[CONTROL_ENVIRONMENT] = previous


if __name__ == "__main__":
    sys.exit(main())
