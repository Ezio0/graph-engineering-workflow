"""Disposable child process used only by WP-07A structured-launcher tests."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.parse


def main() -> int:
    mode = sys.argv[1]
    secret = os.environ.get("WP07A_TOKEN", "")
    if mode == "clean":
        print(json.dumps({"secret_present": bool(secret), "summary": "ok"}, sort_keys=True))
        return 0
    if mode == "leak-raw":
        print(json.dumps({"summary": secret}, sort_keys=True))
        return 0
    if mode == "leak-base64":
        print(json.dumps({"summary": base64.b64encode(secret.encode()).decode()}, sort_keys=True))
        return 0
    if mode == "leak-hex":
        print(json.dumps({"summary": secret.encode().hex()}, sort_keys=True))
        return 0
    if mode == "leak-url":
        print(json.dumps({"summary": urllib.parse.quote(secret, safe="")}, sort_keys=True))
        return 0
    if mode == "leak-stderr":
        sys.stderr.write(secret)
        return 1
    if mode == "leak-json-escaped":
        print(json.dumps({"summary": json.dumps(secret, ensure_ascii=True)[1:-1]}, sort_keys=True))
        return 0
    if mode == "leak-sha256":
        print(json.dumps({"summary": hashlib.sha256(secret.encode()).hexdigest()}, sort_keys=True))
        return 0
    if mode == "oversized":
        print(json.dumps({"summary": "x" * 10000}, sort_keys=True))
        return 0
    if mode == "malformed":
        print("not-json")
        return 0
    if mode == "sleep":
        time.sleep(5)
        return 0
    if mode in {"descendant-timeout", "descendant-output"}:
        child = (
            "import pathlib,signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "time.sleep(0.75);"
            "pathlib.Path('descendant-survived').write_text('unsafe')"
        )
        subprocess.Popen(
            (sys.executable, "-c", child),
            stdin=subprocess.DEVNULL,
            stdout=sys.stdout,
            stderr=sys.stderr,
            shell=False,
            close_fds=True,
        )
        if mode == "descendant-output":
            sys.stdout.write("x" * 10000)
            sys.stdout.flush()
        time.sleep(5)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
