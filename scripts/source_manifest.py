"""Create and verify a canonical, exact WP-00 source manifest."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET_SPEC = ROOT / "config" / "verification" / "wp-00-targets.json"


def _digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def create_manifest() -> dict[str, object]:
    specification = json.loads(TARGET_SPEC.read_text(encoding="utf-8"))
    declared = list(specification["files"])
    if declared != sorted(declared) or len(declared) != len(set(declared)):
        raise ValueError("target files must be sorted and unique")
    actual: set[str] = {"pyproject.toml", "uv.lock"}
    unexpected_nodes: list[str] = []
    for root_name in specification["owned_roots"]:
        root = ROOT / root_name
        for path in root.rglob("*"):
            if path.is_symlink():
                unexpected_nodes.append(path.relative_to(ROOT).as_posix())
            elif "__pycache__" in path.parts or (path.is_file() and path.suffix == ".pyc"):
                continue
            elif path.is_file():
                actual.add(path.relative_to(ROOT).as_posix())
    if unexpected_nodes:
        raise ValueError(json.dumps({"unexpected_nodes": sorted(unexpected_nodes)}, sort_keys=True))
    if actual != set(declared):
        raise ValueError(json.dumps({"missing": sorted(set(declared) - actual), "additional": sorted(actual - set(declared))}, sort_keys=True))
    files: list[dict[str, object]] = []
    for relative in declared:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"invalid target: {relative}")
        body = path.read_bytes()
        files.append({"path": relative, "sha256": _digest(body), "size": len(body)})
    payload: dict[str, object] = {"schema_version": "1.0", "files": files}
    payload["manifest_digest"] = _digest(_canonical(payload))
    return payload


def verify(expected: dict[str, object]) -> list[str]:
    current = create_manifest()
    return [] if expected == current else ["SOURCE_MANIFEST_MISMATCH"]


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if not arguments:
        print(json.dumps(create_manifest(), sort_keys=True, separators=(",", ":")))
        return 0
    if len(arguments) == 2 and arguments[0] == "--output":
        output = pathlib.PurePosixPath(arguments[1])
        if (
            output.is_absolute()
            or output.suffix != ".json"
            or output.parts[:3] != (".workflow", "delivery", "GEW-IMPLEMENTATION-V1")
            or any(part in {"", ".", ".."} for part in output.parts)
        ):
            raise SystemExit("source manifest output must be a task-local JSON path")
        value = create_manifest()
        (ROOT / output).write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        print(json.dumps({"status": "PASS", "manifest_digest": value["manifest_digest"]}, sort_keys=True))
        return 0
    if len(arguments) == 2 and arguments[0] == "--check":
        expected = json.loads(pathlib.Path(arguments[1]).read_text(encoding="utf-8"))
        findings = verify(expected)
        print(json.dumps({"status": "PASS" if not findings else "FAIL", "findings": findings}, sort_keys=True))
        return 0 if not findings else 1
    raise SystemExit("usage: source_manifest.py [--check MANIFEST | --output MANIFEST]")


if __name__ == "__main__":
    sys.exit(main())
