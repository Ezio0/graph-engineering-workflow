from __future__ import annotations

import copy
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import verify_platform_matrix  # noqa: E402
import check_architecture  # noqa: E402
import check_sources  # noqa: E402


class SecurityMutationTests(unittest.TestCase):
    def test_platform_matrix_rejects_missing_linux_and_duplicate_cells(self) -> None:
        base = {"schema_version": "1.0", "cells": [{"id": "mac", "os": "macos", "architecture": "arm64", "python": ">=3.12", "required_suite": "full"}]}
        self.assertIn("MISSING_REQUIRED_OS", verify_platform_matrix.validate(base))
        duplicate = copy.deepcopy(base)
        duplicate["cells"].append(copy.deepcopy(duplicate["cells"][0]))
        self.assertIn("DUPLICATE_CELL", verify_platform_matrix.validate(duplicate))

    def test_architecture_scanner_rejects_forbidden_dependencies_and_data_values(self) -> None:
        architecture = {
            "core-forbidden-imports": ["graph_engineering.adapters"],
            "forbidden-runtime-import-prefixes": ["codex"],
            "declared-external-imports": [],
            "forbidden-environment-patterns": [r"/Users/", r"127\.0\.0\.1:[0-9]+"],
        }
        source = "import codex\nimport thirdparty\nimport os as operating\nfrom os import getenv as read_env\nimport subprocess as process\nfrom graph_engineering.adapters import x\nWEIGHT = 0.8\nTHRESHOLD = 7\nUSER_INTERESTS = ['graph']\nDATA = {'weight': 0.8, 'interests': ['graph']}\nSERVICE_URL = 'https://example.test:8443/api'\nPORT = 8443\nDB_DSN = 'sqlite:///tmp/example.db'\nPATH = '/Users/example/project'\nCOMMAND = ['tool', '--run']\nFIRST = operating.getenv('TOKEN')\nSECOND = read_env('TOKEN')\nRESULT = process.run(['tool', '--run'])\n"
        with tempfile.TemporaryDirectory(prefix="gew-architecture-mutation-") as directory:
            path = pathlib.Path(directory) / "bad.py"
            path.write_text(source, encoding="utf-8")
            codes = {finding["code"] for finding in check_architecture.inspect_python(path, "core", architecture)}
        self.assertTrue({"CORE_IMPORT_BOUNDARY", "VENDOR_RUNTIME_IMPORT", "UNDECLARED_EXTERNAL_IMPORT", "DATA_VALUE_IN_LOGIC", "ENVIRONMENT_VALUE_IN_LOGIC", "DIRECT_ENVIRONMENT_READ", "HARDCODED_COMMAND_IN_LOGIC"}.issubset(codes))

    def test_architecture_policy_cannot_be_weakened_and_config_access_passes(self) -> None:
        empty_policy = {
            "core-forbidden-imports": [],
            "forbidden-runtime-import-prefixes": [],
            "declared-external-imports": [],
            "forbidden-environment-patterns": [],
            "runtime-roots": [],
        }
        self.assertTrue(check_architecture.validate_policy(empty_policy))
        with tempfile.TemporaryDirectory(prefix="gew-policy-mutation-") as directory:
            bad = pathlib.Path(directory) / "bad.py"
            bad.write_text("from graph_engineering.adapters import adapter\n", encoding="utf-8")
            codes = {finding["code"] for finding in check_architecture.inspect_python(bad, "core", empty_policy)}
            self.assertIn("CORE_IMPORT_BOUNDARY", codes)

    def test_equivalent_values_from_configuration_ports_pass(self) -> None:
        architecture = {
            "core-forbidden-imports": [],
            "forbidden-runtime-import-prefixes": [],
            "declared-external-imports": [],
            "forbidden-environment-patterns": [],
            "runtime-roots": [],
        }
        with tempfile.TemporaryDirectory(prefix="gew-config-port-") as directory:
            configured = pathlib.Path(directory) / "configured.py"
            configured.write_text("WEIGHT = settings.weight\nTHRESHOLD = settings.threshold\n", encoding="utf-8")
            self.assertEqual(check_architecture.inspect_python(configured, "core", architecture), [])

    def test_type_gate_rejects_annotated_type_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-type-mutation-") as directory:
            path = pathlib.Path(directory) / "bad.py"
            path.write_text(
                "def make_text() -> str:\n"
                "    return 'wrong'\n"
                "COUNT: int = make_text()\n"
                "def result() -> int:\n"
                "    value = 'wrong'\n"
                "    return value\n",
                encoding="utf-8",
            )
            codes = {finding["code"] for finding in check_sources.inspect_path(path, "type")}
        self.assertEqual(codes, {"ANNOTATED_ASSIGNMENT_TYPE_MISMATCH", "RETURN_TYPE_MISMATCH"})


if __name__ == "__main__":
    unittest.main()
