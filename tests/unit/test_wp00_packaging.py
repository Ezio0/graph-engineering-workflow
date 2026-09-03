from __future__ import annotations

import ast
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
