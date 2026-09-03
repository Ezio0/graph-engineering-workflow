"""Collect a digest-bound WP-02 Graph Kernel candidate."""

from __future__ import annotations

import hashlib
import json
import pathlib
import platform
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
            raise SystemExit("usage: collect_wp02_evidence.py [--output EVIDENCE]")
        output_path = pathlib.PurePosixPath(arguments[1])
        if (
            output_path.is_absolute()
            or output_path.suffix != ".json"
            or output_path.parts[:3] != (".workflow", "delivery", "GEW-IMPLEMENTATION-V1")
            or any(part in {"", ".", ".."} for part in output_path.parts)
        ):
            raise SystemExit("evidence output must be a task-local JSON path")
    gate = json.loads((ROOT / "config" / "verification" / "wp-02-gate.json").read_text())
    records = evidence_utils.command_records(gate["commands"])
    if any(record["exit_code"] != 0 or record["outcome"].get("status") != "PASS" for record in records):
        print(json.dumps({"status": "FAIL", "commands": records}, sort_keys=True))
        return 1
    passed = evidence_utils.passed_test_ids(records)
    missing = sorted(
        binding["qualified_test"] for binding in gate["test_bindings"]
        if binding["qualified_test"] not in passed
    )
    if missing:
        print(json.dumps({"status": "FAIL", "missing_bound_tests": missing}, sort_keys=True))
        return 1
    with tempfile.TemporaryDirectory(prefix="gew-wp02-wheel-") as directory:
        filename = build_backend.build_wheel(directory)
        wheel_digest = evidence_utils.digest((pathlib.Path(directory) / filename).read_bytes())
    manifest = source_manifest.create_manifest()
    dependencies = evidence_utils.dependency_verdicts(gate)
    reference_runtime = evidence_utils.reference_runtime()
    documents = evidence_utils.governing_documents(
        paths=evidence_utils.WP02_GOVERNING_DOCUMENT_PATHS,
    )
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
        "reference_runtime": reference_runtime,
        "dependency_verdicts": dependencies,
        "commands": records,
        "governing_documents": documents,
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
