"""Collect deterministic WP-01 command, corpus, runtime, and wheel evidence."""

from __future__ import annotations

import hashlib
import json
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile

import build_backend
import evidence_utils
import source_manifest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    output_path: pathlib.PurePosixPath | None = None
    if arguments:
        if len(arguments) != 2 or arguments[0] != "--output":
            raise SystemExit("usage: collect_wp01_evidence.py [--output EVIDENCE]")
        output_path = pathlib.PurePosixPath(arguments[1])
        if (
            output_path.is_absolute()
            or output_path.suffix != ".json"
            or output_path.parts[:3] != (".workflow", "delivery", "GEW-IMPLEMENTATION-V1")
            or any(part in {"", ".", ".."} for part in output_path.parts)
        ):
            raise SystemExit("evidence output must be a task-local JSON path")
    gate = json.loads((ROOT / "config" / "verification" / "wp-01-gate.json").read_text(encoding="utf-8"))
    records = evidence_utils.command_records(gate["commands"])
    if any(record["exit_code"] != 0 or record["outcome"].get("status") != "PASS" for record in records):  # type: ignore[union-attr]
        print(json.dumps({"status": "FAIL", "commands": records}, sort_keys=True))
        return 1
    passed_tests = evidence_utils.passed_test_ids(records)
    missing = sorted(binding["qualified_test"] for binding in gate["test_bindings"] if binding["qualified_test"] not in passed_tests)
    if missing:
        print(json.dumps({"status": "FAIL", "missing_bound_tests": missing}, sort_keys=True))
        return 1
    node = shutil.which("node")
    if node is None:
        print(json.dumps({"status": "FAIL", "finding": "NODE_REFERENCE_MISSING"}, sort_keys=True))
        return 1
    node_path = pathlib.Path(node).resolve()
    node_version = subprocess.run([str(node_path), "--version"], check=True, capture_output=True, text=True).stdout.strip()
    with tempfile.TemporaryDirectory(prefix="gew-wp01-wheel-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel_digest = evidence_utils.digest((pathlib.Path(directory) / filename).read_bytes())
    manifest = source_manifest.create_manifest()
    evidence = {
        "schema_version": "1.0",
        "status": "PASS",
        "source_manifest_digest": manifest["manifest_digest"],
        "interpreter": {
            "executable": sys.executable,
            "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "reference_runtime": {
            "kind": "node",
            "executable": str(node_path),
            "executable_sha256": hashlib.sha256(node_path.read_bytes()).hexdigest(),
            "version": node_version,
            "implementation": "tests/support/wp01_reference.mjs",
            "implementation_sha256": hashlib.sha256((ROOT / "tests" / "support" / "wp01_reference.mjs").read_bytes()).hexdigest(),
        },
        "commands": records,
        "governing_documents": evidence_utils.governing_documents(),
        "test_bindings": gate["test_bindings"],
        "wheel": {"filename": filename, "sha256": wheel_digest},
    }
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":"))
    if output_path is not None:
        (ROOT / output_path).write_text(encoded + "\n", encoding="utf-8")
        print(json.dumps({
            "status": "PASS",
            "source_manifest_digest": evidence["source_manifest_digest"],
            "command_evidence_digest": evidence_utils.digest(encoded.encode()),
        }, sort_keys=True))
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    sys.exit(main())
