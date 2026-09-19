from __future__ import annotations

import base64
import csv
import io
import json
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import tomllib
import unittest
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
RESPONSIBILITY_PACKAGES = ("core", "application", "storage", "adapters")


class InstalledWheelTests(unittest.TestCase):
    def test_installed_security_api_cannot_mint_attestations_from_raw_mappings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-security-wheel-") as temp_dir:
            temp = pathlib.Path(temp_dir)
            dist = temp / "dist"
            dist.mkdir()
            build = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_wheel.py"), str(dist)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = next(dist.glob("*.whl"))
            probe = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import inspect,json; "
                        "import graph_engineering.core.security.attestation as a; "
                        "from graph_engineering.application.security import SecurityContextIssuer; "
                        "rejected=False; "
                        "\ntry:\n a.SecurityRuntimeManifest.from_dict({},expected_manifest_id='x',"
                        "expected_manifest_digest='x',schema_registry=None,context=None)"
                        "\nexcept a.SecurityAttestationError:\n rejected=True\n"
                        "print(json.dumps({'raw_task':hasattr(a,'_issue_task_security_context'),"
                        "'raw_journal':hasattr(a,'_issue_disclosure_journal_attestation'),"
                        "'runtime_rejected':rejected,"
                        "'task_params':list(inspect.signature("
                        "SecurityContextIssuer.issue_task_context).parameters),"
                        "'journal_params':list(inspect.signature("
                        "SecurityContextIssuer.issue_disclosure_attestation).parameters)}))"
                    ),
                ],
                cwd=temp,
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PYTHONPATH": str(wheel)},
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            self.assertEqual(
                json.loads(probe.stdout),
                {
                    "raw_task": False,
                    "raw_journal": False,
                    "runtime_rejected": True,
                    "task_params": ["self", "task_id"],
                    "journal_params": ["self", "receipt_id"],
                },
            )

    def test_wheel_runs_inside_decoy_project_without_source_imports(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-wheel-test-") as temp_dir:
            temp = pathlib.Path(temp_dir)
            dist = temp / "dist"
            dist.mkdir()
            build = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_wheel.py"), str(dist)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = next(dist.glob("*.whl"))
            first_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
            second_dist = temp / "dist-second"
            second_dist.mkdir()
            second_build = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_wheel.py"), str(second_dist)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(second_build.returncode, 0, second_build.stderr)
            second_wheel = next(second_dist.glob("*.whl"))
            self.assertEqual(first_digest, hashlib.sha256(second_wheel.read_bytes()).hexdigest())

            with zipfile.ZipFile(wheel) as archive:
                members = archive.namelist()
            self.assertEqual(len(members), len(set(members)))
            names = set(members)
            self.assertTrue(
                all(name.startswith("graph_engineering/") or ".dist-info/" in name for name in names),
                sorted(names),
            )
            configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
            build_mapping = configuration["tool"]["gew"]["build"]
            expected_packages = set(build_mapping["owned-root-files"].values())
            expected_packages.add("graph_engineering/pyproject.toml")
            profile_configuration = configuration["tool"]["gew"]["profile"]
            category = profile_configuration["category-execution-policy"]
            coverage = profile_configuration["coverage-execution-plan"]
            migration = profile_configuration["migration-rehearsal"]
            performance = profile_configuration["performance-benchmark"]
            release = profile_configuration["release-operations"]
            protected_vectors = (
                tuple(sorted((
                    (category["registry-source"], category["registry-resource"]),
                    (category["policy-source"], category["policy-resource"]),
                ))),
                tuple(zip(
                    coverage["protected-sources"],
                    coverage["protected-resources"],
                    strict=True,
                )),
                tuple(
                    (item["source"], item["resource"])
                    for item in performance["protected-resources"]
                ),
                tuple(sorted((
                    (migration["registry-source"], migration["registry-resource"]),
                    (migration["fixture-source"], migration["fixture-resource"]),
                    (migration["transform-source"], migration["transform-resource"]),
                    (migration["bootstrap-source"], migration["bootstrap-resource"]),
                    (
                        migration["profile-schema-registry-source"],
                        migration["profile-schema-registry-resource"],
                    ),
                    (
                        migration["build-backend-source"],
                        migration["build-backend-resource"],
                    ),
                ))),
                tuple(
                    (item["source"], item["resource"])
                    for item in migration["protected-resources"]
                ),
                tuple(sorted(
                    (item["source"], item["resource"])
                    for item in migration["schema-vectors"]
                )),
                tuple(sorted((
                    (release["bootstrap-source"], release["bootstrap-resource"]),
                    (release["policy-source"], release["policy-resource"]),
                    (release["fixture-source"], release["fixture-resource"]),
                    (
                        release["profile-schema-registry-source"],
                        release["profile-schema-registry-resource"],
                    ),
                ))),
                tuple(zip(
                    release["protected-sources"],
                    release["protected-resources"],
                    strict=True,
                )),
                tuple(sorted(zip(
                    release["schema-sources"],
                    release["schema-resources"],
                    strict=True,
                ))),
            )
            protected_destinations: dict[str, str] = {}
            for protected in protected_vectors:
                sources = tuple(source for source, _destination in protected)
                destinations = tuple(destination for _source, destination in protected)
                self.assertEqual(sources, tuple(sorted(set(sources))))
                self.assertEqual(len(destinations), len(set(destinations)))
                for source, destination in protected:
                    previous = protected_destinations.setdefault(destination, source)
                    self.assertEqual(previous, source)
            expected_packages.update(sorted(protected_destinations))
            for source, destination in build_mapping["package-roots"].items():
                source_root = ROOT / source
                destination_root = pathlib.PurePosixPath(destination.replace(".", "/"))
                expected_packages.update(
                    (destination_root / path.relative_to(source_root).as_posix()).as_posix()
                    for path in source_root.rglob("*.py")
                    if "__pycache__" not in path.parts
                )
            self.assertEqual({name for name in names if name.startswith("graph_engineering/")}, expected_packages)
            for package in RESPONSIBILITY_PACKAGES:
                self.assertIn(f"graph_engineering/{package}/__init__.py", names)
                self.assertNotIn(f"{package}/__init__.py", names)

            schema_source = ROOT / "config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json"
            schema_resource = "graph_engineering/config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json"
            schema_body = schema_source.read_bytes()
            with zipfile.ZipFile(wheel) as archive:
                self.assertEqual(archive.read(schema_resource), schema_body)
                record_name = next(name for name in names if name.endswith(".dist-info/RECORD"))
                record = {
                    row[0]: (row[1], row[2])
                    for row in csv.reader(io.StringIO(archive.read(record_name).decode("utf-8")))
                }
            expected_hash = "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(schema_body).digest()
            ).decode("ascii").rstrip("=")
            self.assertEqual(record[schema_resource], (expected_hash, str(len(schema_body))))

            venv = temp / "venv"
            subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True)
            python = venv / "bin" / "python"
            install = subprocess.run(
                [str(python), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)],
                check=False,
                capture_output=True,
                text=True,
                env={**os.environ, "PIP_CONFIG_FILE": os.devnull},
            )
            self.assertEqual(install.returncode, 0, install.stderr)

            unpacked = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "import hashlib,importlib.resources,json; "
                        "body=importlib.resources.files('graph_engineering').joinpath("
                        "'config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json').read_bytes(); "
                        "print(json.dumps({'sha256':hashlib.sha256(body).hexdigest(),'size':len(body)}))"
                    ),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(unpacked.returncode, 0, unpacked.stderr)
            self.assertEqual(
                json.loads(unpacked.stdout),
                {"sha256": hashlib.sha256(schema_body).hexdigest(), "size": len(schema_body)},
            )

            entry_point = subprocess.run(
                [str(venv / "bin" / "graph-engineering"), "--version"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(entry_point.returncode, 0, entry_point.stderr)
            self.assertEqual(entry_point.stdout.strip(), "0.1.0")

            decoy = temp / "decoy"
            decoy.mkdir()
            for package in RESPONSIBILITY_PACKAGES:
                package_dir = decoy / package
                package_dir.mkdir()
                (package_dir / "__init__.py").write_text("RAISED = True\n", encoding="utf-8")

            probe = subprocess.run(
                [
                    str(python),
                    "-c",
                    (
                        "import json, pathlib, graph_engineering.cli as c; "
                        "print(json.dumps({'file': str(pathlib.Path(c.__file__).resolve()), "
                        "'version': c.installed_version()}))"
                    ),
                ],
                cwd=decoy,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            payload = json.loads(probe.stdout)
            self.assertIn(str(venv), payload["file"])
            self.assertNotIn(str(ROOT), payload["file"])
            self.assertEqual(payload["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
