"""Run one named WP09/regression unittest in a fresh attested child process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]

_CHILD = r'''
import contextlib, json, os, pathlib, sys, unittest
root = pathlib.Path(sys.argv[1])
sys.path[:0] = [str(root)] + [str(root / x) for x in ("core", "application", "storage", "adapters")]
class Result(unittest.TestResult):
    def __init__(self):
        super().__init__(); self.outcomes = []
    def addSuccess(self, test):
        super().addSuccess(test); self.outcomes.append({"id":test.id(), "status":"PASS"})
    def addFailure(self, test, err):
        super().addFailure(test, err)
        frames = []
        trace = err[2]
        while trace is not None:
            path = pathlib.Path(trace.tb_frame.f_code.co_filename)
            if path.is_relative_to(root):
                frames.append({"file":str(path.relative_to(root)), "line":trace.tb_lineno})
            trace = trace.tb_next
        self.outcomes.append({"id":test.id(), "status":"FAIL", "frames":frames})
    def addError(self, test, err):
        super().addError(test, err)
        frames = []
        trace = err[2]
        while trace is not None:
            path = pathlib.Path(trace.tb_frame.f_code.co_filename)
            if path.is_relative_to(root):
                frames.append({"file":str(path.relative_to(root)), "line":trace.tb_lineno})
            trace = trace.tb_next
        self.outcomes.append({"id":test.id(), "status":"ERROR", "error_type":err[0].__name__, "frames":frames[-8:]})
    def addSkip(self, test, reason):
        super().addSkip(test, reason); self.outcomes.append({"id":test.id(), "status":"SKIP"})
    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.outcomes.append({"id":test.id(), "status":"FAIL", "error_type":err[0].__name__})
result = Result()
with open(os.devnull, 'w') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
    suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[2])
    count = suite.countTestCases()
    suite.run(result)
ok = count == 1 and result.testsRun == 1 and result.wasSuccessful() and not result.skipped and len(result.outcomes) == 1 and result.outcomes[0]["id"] == sys.argv[2]
print(json.dumps({"status":"PASS" if ok else "FAIL", "collected":count, "executed":result.testsRun, "outcomes":result.outcomes}, sort_keys=True))
sys.exit(0 if ok else 1)
'''


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--test', required=True)
    parser.add_argument('--timeout-seconds', type=int, required=True)
    args = parser.parse_args()
    parts = args.test.split('.')
    if len(parts) != 5 or parts[0] != 'tests' or any(not p.isidentifier() for p in parts):
        parser.error('one exact unittest method is required')
    if not 0 < args.timeout_seconds <= 290:
        parser.error('native timeout must not exceed approved 290 seconds')
    sys.path.insert(0, str(ROOT))
    from tests.support.source_checkout_attestation import (
        CONTROL_ENVIRONMENT, CONTROL_OPTION, issue_source_checkout_attestation,
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='gew-wp09-test-') as directory:
        root = Path(directory).resolve()
        control = root / 'control'
        issue_source_checkout_attestation(ROOT, control)
        child_env = dict(os.environ)
        child_env[CONTROL_ENVIRONMENT] = str(control)
        with (root/'stdout').open('wb') as out, (root/'stderr').open('wb') as err:
            process = subprocess.Popen(
                [sys.executable, '-B', '-X', f'{CONTROL_OPTION}={control}', '-c', _CHILD, str(ROOT), args.test],
                cwd=ROOT, env=child_env, stdout=out, stderr=err, start_new_session=True,
            )
            timed_out = False
            try:
                code = process.wait(timeout=args.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                code = process.wait()
        with (root/'stdout').open('rb') as stream:
            stdout = stream.read(65537)
        stderr_digest = hashlib.sha256()
        with (root/'stderr').open('rb') as stream:
            for chunk in iter(lambda: stream.read(65536), b''):
                stderr_digest.update(chunk)
        try:
            outcome = json.loads(stdout) if len(stdout) <= 65536 else None
        except (ValueError, UnicodeError):
            outcome = None
        passed = not timed_out and code == 0 and isinstance(outcome, dict) and outcome.get('status') == 'PASS'
        print(json.dumps({'status':'PASS' if passed else 'FAIL', 'selector':args.test,
            'exit_code':code, 'timed_out':timed_out, 'elapsed_seconds':time.monotonic()-started,
            'outcome':outcome, 'stderr_sha256':stderr_digest.hexdigest()}, sort_keys=True))
        return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
