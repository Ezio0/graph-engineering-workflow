"""Verify the WP-00 dependency license policy and emit a minimal SBOM."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def _inputs() -> tuple[dict[str, object], dict[str, object]]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    policy = json.loads((ROOT / "config" / "supply-chain" / "license-policy-v1.json").read_text(encoding="utf-8"))
    return project, policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("license", "sbom"))
    arguments = parser.parse_args(argv)
    project, policy = _inputs()
    dependencies = project.get("dependencies", [])
    if dependencies != policy["runtime_dependencies"] or project["license"] != policy["project_license"]:
        print(json.dumps({"status": "FAIL", "code": "SUPPLY_CHAIN_POLICY_MISMATCH"}, sort_keys=True))
        return 1
    if arguments.mode == "license":
        result = {"status": "PASS", "project_license": project["license"], "runtime_dependency_count": len(dependencies)}
    else:
        result = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": {"component": {"type": "application", "name": project["name"], "version": project["version"]}},
            "components": [],
            "status": "PASS"
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
