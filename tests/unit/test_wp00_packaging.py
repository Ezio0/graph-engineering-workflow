from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]


class PackagingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_performance_installation_closure_matches_packaged_resources(self) -> None:
        from graph_engineering.application.performance_benchmark import (
            PerformanceBenchmarkRegistryFactory,
        )
        from scripts import build_backend

        # Initialize the real consumer before any workload is allowed to start.
        factory = PerformanceBenchmarkRegistryFactory.from_installation()
        authority = factory.registry()
        self.assertIs(factory.require_current(authority), authority)
        pin = self.pyproject["tool"]["gew"]["profile"]["performance-benchmark"]
        bootstrap = json.loads((ROOT / pin["bootstrap-source"]).read_text())
        resources = bootstrap["protected_resources"]
        self.assertEqual(len(resources), 38)
        self.assertEqual(resources, [
            {"source": row["source"], "resource": row["resource"],
             "raw_sha256": row["raw-sha256"]}
            for row in pin["protected-resources"]
        ])
        with tempfile.TemporaryDirectory(prefix="gew-performance-pin-wheel-") as directory:
            wheel = pathlib.Path(directory) / build_backend.build_wheel(directory)
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(archive.read(pin["bootstrap-resource"]),
                                 (ROOT / pin["bootstrap-source"]).read_bytes())
                for row in resources:
                    with self.subTest(source=row["source"]):
                        body = (ROOT / row["source"]).read_bytes()
                        self.assertEqual(hashlib.sha256(body).hexdigest(), row["raw_sha256"])
                        self.assertEqual(archive.read(row["resource"]), body)

    def test_performance_installation_rejects_source_drift_and_replaced_root(self) -> None:
        from tests.support.source_checkout_attestation import issue_source_checkout_attestation

        with tempfile.TemporaryDirectory(prefix="gew-performance-pin-attack-") as directory:
            temporary = pathlib.Path(directory).resolve()
            clone = temporary / "project"
            clone.mkdir()
            for name in ("core", "application", "storage", "adapters", "config", "scripts", "tests"):
                shutil.copytree(ROOT / name, clone / name,
                                ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copy2(ROOT / "pyproject.toml", clone / "pyproject.toml")
            control = temporary / "control"
            issue_source_checkout_attestation(clone, control)
            code = '''
import pathlib, shutil, sys
root = pathlib.Path.cwd()
sys.path[:0] = [str(root / name) for name in ("core", "application", "storage", "adapters")]
from graph_engineering import DistributionIdentityError
from graph_engineering.application.performance_benchmark import PerformanceBenchmarkRegistryFactory
from graph_engineering.core.performance_benchmark import PerformanceBenchmarkError
load = PerformanceBenchmarkRegistryFactory.from_installation
load()
victim = root / "application/graph_engineering/application/profile_coverage.py"
original = victim.read_bytes()
try:
    victim.write_bytes(original + b"\\n# unauthorized drift\\n")
    try:
        load()
    except PerformanceBenchmarkError as error:
        assert isinstance(error.__cause__, DistributionIdentityError)
        assert str(error.__cause__) == "source checkout attestation binding changed"
    else:
        raise AssertionError("changed source was accepted")
finally:
    victim.write_bytes(original)
load()
parked = root.with_name("original-project")
root.rename(parked)
try:
    shutil.copytree(parked, root)
    assert victim.read_bytes() == original
    try:
        load()
    except PerformanceBenchmarkError as error:
        assert isinstance(error.__cause__, DistributionIdentityError)
        assert str(error.__cause__) == "source checkout attestation binding changed"
    else:
        raise AssertionError("replacement installation root was accepted")
finally:
    if root.exists():
        shutil.rmtree(root)
    parked.rename(root)
load()
print("changed bytes and identical-content installation replacement rejected; restoration accepted")
'''
            environment = dict(os.environ)
            environment["GEW_INSTALLATION_CONTROL_ROOT"] = str(control)
            result = subprocess.run(
                [sys.executable, "-B", "-X", "gew_installation_control_root=" + str(control),
                 "-c", code], cwd=clone, env=environment, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_project_requires_supported_python_and_exact_approved_runtime_dependency(self) -> None:
        project = self.pyproject["project"]
        self.assertEqual(project["requires-python"], ">=3.12")
        self.assertEqual(
            project.get("dependencies", []),
            ["cryptography==50.0.0", "packaging==26.3"],
        )

    def test_console_script_uses_installed_distribution_namespace(self) -> None:
        self.assertEqual(
            self.pyproject["project"]["scripts"]["graph-engineering"],
            "graph_engineering.cli:main",
        )

    def test_responsibility_roots_map_to_one_namespace(self) -> None:
        expected = {
            "core/graph_engineering/core": "graph_engineering.core",
            "application/graph_engineering/application": "graph_engineering.application",
            "storage/graph_engineering/storage": "graph_engineering.storage",
            "adapters/graph_engineering/adapters": "graph_engineering.adapters",
        }
        self.assertEqual(self.pyproject["tool"]["gew"]["build"]["package-roots"], expected)
        for source, installed_package in expected.items():
            package_path = ROOT / source
            self.assertTrue((package_path / "__init__.py").is_file(), package_path)
            self.assertEqual(package_path.name, installed_package.rsplit(".", 1)[-1])

    def test_core_does_not_import_forbidden_layers(self) -> None:
        forbidden = (
            "graph_engineering.application",
            "graph_engineering.storage",
            "graph_engineering.adapters",
        )
        core_root = ROOT / "core" / "graph_engineering" / "core"
        for path in core_root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
                for name in names:
                    self.assertFalse(name.startswith(forbidden), f"{path}: {name}")

    def test_runtime_files_do_not_bind_reference_project(self) -> None:
        forbidden = "agent-engineering-workflow"
        for root_name in ("core", "application", "storage", "adapters", "config", "skills"):
            for path in (ROOT / root_name).rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    self.assertNotIn(forbidden, path.read_text(encoding="utf-8"))

    def test_source_manifest_closes_profile_oracle_input_generation_two(self) -> None:
        schema_path = "config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json"
        positive = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "source_manifest.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(positive.returncode, 0, positive.stderr)
        expected = json.loads(positive.stdout)
        rows = {item["path"]: item for item in expected["files"]}
        self.assertEqual(rows[schema_path]["sha256"], hashlib.sha256((ROOT / schema_path).read_bytes()).hexdigest())
        self.assertEqual(rows[schema_path]["size"], (ROOT / schema_path).stat().st_size)

        with tempfile.TemporaryDirectory(prefix="gew-source-manifest-attack-") as temp_dir:
            temp = pathlib.Path(temp_dir)
            clone = temp / "project"
            shutil.copytree(
                ROOT,
                clone,
                symlinks=True,
                ignore=shutil.ignore_patterns(".git", ".workflow", "__pycache__"),
            )
            expected_path = temp / "expected.json"
            expected_path.write_text(json.dumps(expected), encoding="utf-8")
            target_path = clone / "config" / "verification" / "wp-00-targets.json"
            original = json.loads(target_path.read_text(encoding="utf-8"))

            def rejected(value: dict[str, object]) -> subprocess.CompletedProcess[str]:
                target_path.write_text(json.dumps(value), encoding="utf-8")
                return subprocess.run(
                    [
                        sys.executable,
                        str(clone / "scripts" / "source_manifest.py"),
                        "--check",
                        str(expected_path),
                    ],
                    cwd=clone,
                    check=False,
                    capture_output=True,
                    text=True,
                )

            missing = json.loads(json.dumps(original))
            missing["files"].remove(schema_path)
            result = rejected(missing)
            self.assertNotEqual(result.returncode, 0)

            extra = json.loads(json.dumps(original))
            alias_path = "config/contracts/schemas/profile-coverage-oracle-input-1.1.1.json"
            extra["files"].append(alias_path)
            extra["files"].sort()
            result = rejected(extra)
            self.assertNotEqual(result.returncode, 0)

            (clone / alias_path).write_bytes((clone / schema_path).read_bytes())
            (clone / schema_path).unlink()
            alias = json.loads(json.dumps(original))
            alias["files"].remove(schema_path)
            alias["files"].append(alias_path)
            alias["files"].sort()
            result = rejected(alias)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)["findings"], ["SOURCE_MANIFEST_MISMATCH"])

    def test_build_backend_rejects_unowned_and_symlinked_package_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-build-attack-") as temp_dir:
            clone = pathlib.Path(temp_dir) / "project"
            shutil.copytree(ROOT, clone, symlinks=True, ignore=shutil.ignore_patterns(".git", ".workflow", "__pycache__"))
            rogue = clone / "core" / "rogue"
            rogue.mkdir()
            (rogue / "__init__.py").write_text("ROGUE = True\n", encoding="utf-8")
            valid = subprocess.run(
                [sys.executable, str(clone / "scripts" / "build_wheel.py"), str(clone / "dist")],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(valid.returncode, 0, valid.stderr)
            wheel = next((clone / "dist").glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                members = archive.namelist()
            self.assertEqual(len(members), len(set(members)))

            leak = clone / "core" / "graph_engineering" / "core" / "leak.txt"
            leak.symlink_to("/etc/hosts")
            rejected = subprocess.run(
                [sys.executable, str(clone / "scripts" / "build_wheel.py"), str(clone / "dist-bad")],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("symlink component is not a build input", rejected.stderr)

    def test_build_backend_rejects_internal_and_external_symlink_ancestors(self) -> None:
        build = self.pyproject["tool"]["gew"]["build"]
        sources = [*build["package-roots"], *build["owned-root-files"]]
        for source in sources:
            for location in ("internal", "external"):
                with self.subTest(source=source, location=location), tempfile.TemporaryDirectory(prefix="gew-build-ancestor-") as temp_dir:
                    temp = pathlib.Path(temp_dir)
                    clone = temp / "project"
                    shutil.copytree(ROOT, clone, symlinks=True, ignore=shutil.ignore_patterns(".git", ".workflow", "__pycache__"))
                    ancestor = (clone / source).parent
                    payload = (clone if location == "internal" else temp) / f"payload-{ancestor.parent.name}-{ancestor.name}"
                    ancestor.rename(payload)
                    ancestor.symlink_to(payload, target_is_directory=True)
                    result = subprocess.run(
                        [sys.executable, str(clone / "scripts" / "build_wheel.py"), str(clone / "dist")],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, source)
                    self.assertIn("symlink", result.stderr)
                    self.assertFalse(any((clone / "dist").glob("*.whl")))

    def test_build_backend_rejects_mapping_traversal(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-mapping-attack-") as temp_dir:
            clone = pathlib.Path(temp_dir) / "project"
            shutil.copytree(ROOT, clone, symlinks=True, ignore=shutil.ignore_patterns(".git", ".workflow", "__pycache__"))
            pyproject = clone / "pyproject.toml"
            text = pyproject.read_text(encoding="utf-8").replace(
                '"core/graph_engineering/core" = "graph_engineering.core"',
                '"../core/graph_engineering/core" = "graph_engineering.core"',
            )
            pyproject.write_text(text, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(clone / "scripts" / "build_wheel.py"), str(clone / "dist")],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("invalid package source", result.stderr)


if __name__ == "__main__":
    unittest.main()
