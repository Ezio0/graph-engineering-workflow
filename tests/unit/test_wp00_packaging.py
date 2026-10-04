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

class PreflightConfigurationReuseTests(unittest.TestCase):
    @staticmethod
    def _load_backend():
        import importlib.util
        spec = importlib.util.spec_from_file_location("gew_parse_reuse_test", ROOT / "scripts/build_backend.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _fixture(self):
        import contextlib

        @contextlib.contextmanager
        def fixture():
            module = self._load_backend()
            with tempfile.TemporaryDirectory(prefix="gew-config-parse-") as directory:
                module.PYPROJECT = pathlib.Path(directory) / "pyproject.toml"
                module.PYPROJECT.write_text('value = 1\n[nested]\nitems = [1, 2]\n')
                yield module
        return fixture()

    @staticmethod
    def _counts(module):
        import contextlib

        @contextlib.contextmanager
        def counted():
            counts = {"read": 0, "parse": 0}
            old = sys.getprofile()
            codes = {pathlib.Path.read_text.__code__: "read", module.tomllib.loads.__code__: "parse"}
            def trace(frame, event, arg):
                if event == "call" and frame.f_code in codes:
                    counts[codes[frame.f_code]] += 1
            sys.setprofile(trace)
            try:
                yield counts
            finally:
                sys.setprofile(old)
        return counted()

    def test_fresh_reads_exact_text_and_detached_toml_values(self):
        import datetime
        import math
        with self._fixture() as backend, self._counts(backend) as count:
            with backend._configuration_parse_operation():
                first = backend._configuration()
                first["nested"]["items"].append(9)
                self.assertEqual(backend._configuration()["nested"]["items"], [1, 2])
                self.assertEqual(count, {"read": 2, "parse": 1})
                original = backend.PYPROJECT.read_text()
                backend.PYPROJECT.write_text('value = 2\n')
                self.assertEqual(backend._configuration()["value"], 2)
                backend.PYPROJECT.write_text(original)
                self.assertEqual(backend._configuration()["value"], 1)
                self.assertEqual(count["parse"], 3)
                backend.PYPROJECT.write_text('date = 2026-09-30\ntime = 12:30:00\nx = nan\ny = inf\n')
                a, b = backend._configuration(), backend._configuration()
                self.assertEqual(a["date"], datetime.date(2026, 9, 30))
                self.assertEqual(b["time"], datetime.time(12, 30))
                self.assertTrue(math.isnan(b["x"]))
                self.assertTrue(math.isinf(b["y"]))
                self.assertIsNot(a, b)
                self.assertEqual(count["parse"], 4)
            backend._configuration()
            backend._configuration()
            self.assertEqual(count["parse"], 6)

    def test_warm_read_and_parse_failures_and_replaced_parser(self):
        from unittest import mock
        with self._fixture() as backend:
            with backend._configuration_parse_operation():
                backend._configuration()
                backend.PYPROJECT.write_text('value = [')
                with self.assertRaises(tomllib.TOMLDecodeError):
                    backend._configuration()
                with self.assertRaises(tomllib.TOMLDecodeError):
                    backend._configuration()
                backend.PYPROJECT.unlink()
                with self.assertRaises(FileNotFoundError):
                    backend._configuration()
                backend.PYPROJECT.write_text('value = 1\n')
                backend._configuration()
                with mock.patch.object(backend.tomllib, "loads", side_effect=[{"value": 2}, {"value": 3}]) as parser:
                    self.assertEqual(backend._configuration()["value"], 2)
                    self.assertEqual(backend._configuration()["value"], 3)
                    self.assertEqual(parser.call_count, 2)
                self.assertEqual(backend._configuration()["value"], 1)

    def test_nested_exception_cleanup_and_separate_operations(self):
        class Cancelled(BaseException):
            pass
        with self._fixture() as backend, self._counts(backend) as count:
            with backend._configuration_parse_operation():
                backend._configuration()
                try:
                    with backend._configuration_parse_operation():
                        backend._configuration()
                        backend._configuration()
                        raise Cancelled()
                except Cancelled:
                    pass
                backend._configuration()
                self.assertEqual(count["parse"], 2)
            with self.assertRaises(Cancelled):
                with backend._configuration_parse_operation():
                    backend._configuration()
                    raise Cancelled()
            with backend._configuration_parse_operation():
                backend._configuration()
                backend._configuration()
            self.assertEqual(count["parse"], 4)

    def test_copied_context_thread_and_fork_do_not_reuse_parent(self):
        import contextvars
        import threading
        with self._fixture() as backend:
            with backend._configuration_parse_operation():
                backend._configuration()
                results = []
                context = contextvars.copy_context()
                def worker():
                    with self._counts(backend) as counts:
                        backend._configuration()
                        backend._configuration()
                        results.append(dict(counts))
                thread = threading.Thread(target=context.run, args=(worker,))
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(results, [{"read": 2, "parse": 2}])
                if hasattr(os, "fork"):
                    read_fd, write_fd = os.pipe()
                    pid = os.fork()
                    if pid == 0:
                        os.close(read_fd)
                        try:
                            with self._counts(backend) as counts:
                                backend._configuration()
                                backend._configuration()
                            os.write(write_fd, json.dumps(counts).encode())
                            os._exit(0)
                        except BaseException:
                            os._exit(1)
                    os.close(write_fd)
                    try:
                        result = json.loads(os.read(read_fd, 1024))
                    finally:
                        os.close(read_fd)
                        _, status = os.waitpid(pid, 0)
                    self.assertEqual(status, 0)
                    self.assertEqual(result, {"read": 2, "parse": 2})

    def test_all_affected_installation_closures_match_real_wheel(self):
        from graph_engineering.application.migration_rehearsal import _installation_projection
        from graph_engineering.application.scenario_truth import ScenarioTruthRegistryFactory
        from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory
        from graph_engineering.application.performance_benchmark import PerformanceBenchmarkRegistryFactory
        from scripts import build_backend

        # Exercise real installation consumers before inspecting packaged bytes.
        self.assertEqual(_installation_projection(), _installation_projection())
        scenario = ScenarioTruthRegistryFactory.from_installation()
        scenario_authority = scenario.registry()
        self.assertIs(scenario.require_current(scenario_authority), scenario_authority)
        release = ReleaseOperationsRegistryFactory.from_installation()
        release.require_installed_authority()
        release.registry()
        performance = PerformanceBenchmarkRegistryFactory.from_installation()
        performance_authority = performance.registry()
        self.assertIs(performance.require_current(performance_authority), performance_authority)
        provenance = tomllib.loads((ROOT / "pyproject.toml").read_text())
        with tempfile.TemporaryDirectory(prefix="gew-parse-closure-wheel-") as directory:
            wheel = pathlib.Path(directory) / build_backend.build_wheel(directory)
            with zipfile.ZipFile(wheel) as archive:
                for family in ("migration-rehearsal", "performance-benchmark", "scenario-truth", "release-operations"):
                    with self.subTest(family=family):
                        pin = provenance["tool"]["gew"]["profile"][family]
                        raw = (ROOT / pin["bootstrap-source"]).read_bytes()
                        self.assertEqual(hashlib.sha256(raw).hexdigest(), pin["bootstrap-raw-sha256"])
                        self.assertEqual(archive.read(pin["bootstrap-resource"]), raw)
                        bootstrap = json.loads(raw)
                        self.assertEqual(bootstrap["bootstrap_digest"], pin["bootstrap-digest"])
                        for row in bootstrap["protected_resources"]:
                            source = row.get("source", row.get("path"))
                            body = (ROOT / source).read_bytes()
                            self.assertEqual(hashlib.sha256(body).hexdigest(), row["raw_sha256"])
                            if "resource" in row:
                                resource = row["resource"]
                            else:
                                sources = pin["protected-sources"]
                                resource = pin["protected-resources"][sources.index(source)]
                            self.assertEqual(archive.read(resource), body)
                installed = pathlib.Path(directory) / "installed"
                archive.extractall(installed)
            # Learning must load from the built wheel with no checkout path or
            # source attestation in the child interpreter. RECORD remains the
            # authority for every policy/schema read, including retained loaders.
            code = r'''
import pathlib, sys
installed = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(installed))
import graph_engineering
from graph_engineering.application.learning import LearningPolicyLoader
assert pathlib.Path(graph_engineering.__file__).is_relative_to(installed)
loader = LearningPolicyLoader.from_installation()
assert loader.limits['max_tasks'] == 32
assert loader.require_current() == loader.digest
resources = (
    'config/learning/learning-policy-v1.json',
    'config/contracts/schemas/learning-input-1.0.0.json',
)
for resource in resources:
    victim = installed / 'graph_engineering' / resource
    original = victim.read_bytes()
    for mode in ('changed', 'missing'):
        try:
            if mode == 'changed':
                victim.write_bytes(original + b' ')
            else:
                victim.unlink()
            try:
                loader.require_current()
            except graph_engineering.DistributionIdentityError:
                pass
            else:
                raise AssertionError('unbound learning resource accepted')
        finally:
            victim.write_bytes(original)
    assert loader.require_current() == loader.digest
'''
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c", code, str(installed)],
                cwd=directory, capture_output=True, timeout=60,
            )
            self.assertEqual(result.returncode, 0, "isolated wheel learning consumer failed")


class DependencyLocationReuseTests(unittest.TestCase):
    """Pure computation reuse must not confer resource/currentness authority."""

    def setUp(self):
        import graph_engineering as package
        self.package = package
        self.body = (ROOT / "pyproject.toml").read_bytes()

    def _calls(self, function, action):
        counts = []
        previous = sys.getprofile()
        def profile(frame, event, argument):
            if event == "call" and frame.f_code is function.__code__:
                counts.append(None)
        try:
            sys.setprofile(profile)
            action()
        finally:
            sys.setprofile(previous)
        return len(counts)

    def test_location_slots_reuse_only_within_phase_and_kind(self):
        p = self.package
        projectors = (
            (p._dependency_advisory_locations, p._parse_dependency_advisory_locations),
            (p._dependency_graph_locations, p._parse_dependency_graph_locations),
            (p._dependency_parser_requirement_location,
             p._parse_dependency_parser_requirement_location),
        )
        for public, pure in projectors:
            with self.subTest(projector=public.__name__):
                expected = public(self.body, location_kind="source")
                def action():
                    with p._dependency_location_operation() as operation:
                        for _ in range(3):
                            self.assertEqual(public(self.body, location_kind="source"), expected)
                        public(self.body, location_kind="resource")
                        public(self.body, location_kind="source")
                        self.assertEqual(len(operation.entries), 1)
                    self.assertEqual(operation.entries, {})
                    public(self.body, location_kind="source")
                self.assertEqual(self._calls(pure, action), 4)

    def test_location_failed_changed_and_reverted_input_reparses(self):
        p = self.package
        for slot in ("advisory", "graph", "parser"):
            pure = p._DEPENDENCY_LOCATION_PROJECTORS[slot]
            def action():
                with p._dependency_location_operation() as operation:
                    call = lambda body: p._reuse_dependency_location(slot, pure, body, "source")
                    value = call(self.body)
                    self.assertEqual(call(self.body + b"\n# changed\n"), value)
                    self.assertEqual(call(self.body), value)
                    with self.assertRaises(p.DistributionIdentityError):
                        call(b"[")
                    self.assertNotIn(slot, operation.entries)
                    self.assertEqual(call(self.body), value)
            self.assertEqual(self._calls(pure, action), 5)

    def test_location_parser_and_projector_substitution_cannot_hit(self):
        from unittest import mock
        p = self.package
        original = p.tomllib.loads
        with p._dependency_location_operation() as operation:
            p._dependency_advisory_locations(self.body, location_kind="source")
            with mock.patch.object(p.tomllib, "loads", wraps=original) as parser:
                for _ in range(2):
                    p._dependency_advisory_locations(self.body, location_kind="source")
                self.assertEqual(parser.call_count, 2)
                self.assertEqual(operation.entries, {})
            replacement = mock.Mock(return_value=["mutable"])
            with mock.patch.object(p, "_parse_dependency_advisory_locations", replacement):
                first = p._dependency_advisory_locations(self.body, location_kind="source")
                first.append("caller mutation")
                p._dependency_advisory_locations(self.body, location_kind="source")
                self.assertEqual(replacement.call_count, 2)
                self.assertEqual(operation.entries, {})

    def test_location_nested_thread_fork_and_baseexception_cleanup(self):
        import threading
        p = self.package
        def call():
            return p._dependency_graph_locations(self.body, location_kind="source")
        with p._dependency_location_operation() as outer:
            expected = call()
            class Cancel(BaseException):
                pass
            with self.assertRaises(Cancel):
                with p._dependency_location_operation() as inner:
                    self.assertEqual(inner.entries, {})
                    self.assertEqual(call(), expected)
                    raise Cancel()
            self.assertEqual(inner.entries, {})
            self.assertIs(p._dependency_location_local.current, outer)
            counts = []
            errors = []
            def foreign_thread():
                try:
                    p._dependency_location_local.current = outer
                    counts.append(self._calls(p._parse_dependency_graph_locations,
                                              lambda: (call(), call())))
                except BaseException as error:
                    errors.append(error)
                finally:
                    p._dependency_location_local.current = None
            thread = threading.Thread(target=foreign_thread)
            thread.start(); thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(counts, [2])
            if hasattr(os, "fork"):
                child = os.fork()
                if child == 0:
                    try:
                        count = self._calls(p._parse_dependency_graph_locations,
                                            lambda: (call(), call()))
                        os._exit(0 if count == 2 else 1)
                    except BaseException:
                        os._exit(2)
                self.assertEqual(os.waitpid(child, 0)[1], 0)
            self.assertEqual(call(), expected)
            self.assertEqual(len(outer.entries), 1)
        self.assertEqual(outer.entries, {})
        self.assertIsNone(p._dependency_location_local.current)

    def test_application_phase_owns_location_lifetime(self):
        from graph_engineering.application import dependency_security
        p = self.package
        with dependency_security._dependency_pure_operation():
            outer = p._dependency_location_local.current
            p._dependency_graph_locations(self.body, location_kind="source")
            with dependency_security._dependency_pure_operation():
                self.assertIsNot(p._dependency_location_local.current, outer)
            self.assertIs(p._dependency_location_local.current, outer)
        self.assertEqual(outer.entries, {})
        self.assertIsNone(p._dependency_location_local.current)
