from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "application", "storage", "adapters"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.adapters.runtime_locator import ExecutableLocatorError  # noqa: E402
from graph_engineering.adapters.runtime_locator import RunningDistributionProbe  # noqa: E402
from graph_engineering.adapters.runtime_config import (  # noqa: E402
    CAPABILITY_FIELDS,
    RuntimeAdapterRejection,
)
from graph_engineering.application.cli import main  # noqa: E402
from graph_engineering.core.runtime import runtime_record_digest  # noqa: E402
from tests.integration.test_wp07_runtime_parity import FIXTURE, adapter_document  # noqa: E402
from tests.support.runtime_distribution import running_distribution  # noqa: E402
from tests.unit.test_wp06_project_scope import scope_document  # noqa: E402
from tests.integration.test_wp04_application import TaskApplicationIntegrationTests  # noqa: E402


class WP07SkillCliTests(unittest.TestCase):
    @staticmethod
    def _main(locator: pathlib.Path, arguments: list[str]) -> int:
        document = json.loads(locator.read_text())
        running = running_distribution(
            document["executable"], document["package_origin"],
            document["distribution_origin"],
            distribution_name=document["distribution_name"],
            distribution_version=document["distribution_version"],
        )
        with mock.patch.object(RunningDistributionProbe, "probe", return_value=running):
            return main(arguments)

    @staticmethod
    def _resource_arguments(root: pathlib.Path) -> list[str]:
        return [
            "--runtime-resource-policy", str((root / "runtime-resource-policy-v1.json").resolve()),
            "--resource-profile", str((root / "resource-profile-v1.json").resolve()),
            "--cost-schedule", str((root / "cost-schedule-v1.json").resolve()),
            "--skill-request", str((root / "skill-request.json").resolve()),
        ]

    def _installation(self, root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
        origin = root / "tool-environment"
        origin.mkdir(mode=0o700)
        executable = origin / "graph-engineering"
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
        locator = root / "locator.json"
        locator.write_text(json.dumps({
            "schema_version": "1.0",
            "executable": str(executable.resolve()),
            "package_origin": str(origin.resolve()),
            "executable_digest": "sha256-raw-v1:" + hashlib.sha256(executable.read_bytes()).hexdigest(),
            "release_manifest_digest": FIXTURE["shared"]["release_manifest_digest"],
            "expected_core_version": FIXTURE["shared"]["core_version"],
            "distribution_name": "graph-engineering-workflow",
            "distribution_version": "0.1.0",
            "distribution_origin": str(origin.resolve()),
        }))
        locator.chmod(0o600)
        config = root / "runtime.json"
        configuration = adapter_document(FIXTURE["cells"][0])
        config.write_text(json.dumps(configuration))
        config.chmod(0o600)
        skill_body = {
            "schema_version": "1.0", "skill_id": configuration["skill_id"],
            "skill_version": configuration["skill_version"],
            "protocol_version": configuration["protocol_version"],
            "runtime_kind": configuration["runtime_kind"],
            "runtime_configuration_digest": configuration["configuration_digest"],
        }
        skill_request = root / "skill-request.json"
        skill_request.write_text(json.dumps({
            **skill_body,
            "request_digest": runtime_record_digest("skill-handshake-request", skill_body),
        }))
        skill_request.chmod(0o600)
        for name in (
            "runtime-resource-policy-v1.json", "resource-profile-v1.json",
            "cost-schedule-v1.json",
        ):
            shutil.copyfile(ROOT / "config/contracts" / name, root / name)
        return locator.resolve(), config.resolve()

    def test_gew_rt_026_codex_and_hermes_skills_are_thin_and_structurally_valid(self) -> None:
        for name in ("graph-engineering-codex", "graph-engineering-hermes"):
            skill = ROOT / "skills" / name / "SKILL.md"
            agent = ROOT / "skills" / name / "agents" / "openai.yaml"
            with self.subTest(skill=name):
                self.assertTrue(skill.is_file())
                self.assertTrue(agent.is_file())
                text = skill.read_text()
                self.assertLessEqual(len(text.splitlines()), 60)
                self.assertNotIn("```", text)
                self.assertFalse((skill.parent / "scripts").exists())

    def test_gew_rt_027_capabilities_cli_uses_locator_and_emits_exact_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            locator, config = self._installation(pathlib.Path(temporary))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = self._main(locator, [
                    "capabilities", "--format", "json", "--locator", str(locator),
                    "--runtime-config", str(config),
                    *self._resource_arguments(config.parent),
                ])
            document = json.loads(output.getvalue())
            self.assertEqual(status, 0)
            self.assertEqual(
                document["canonical_executable"],
                json.loads(locator.read_text())["executable"],
            )
            self.assertEqual(document["compatibility"], "compatible")
            self.assertEqual(set(document), CAPABILITY_FIELDS)
            self.assertEqual(document["capability_digest"], runtime_record_digest(
                "capabilities", {
                    key: value for key, value in document.items() if key != "capability_digest"
                },
            ))

    def test_gew_rt_028_unsafe_locator_rejects_before_capability_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            locator, config = self._installation(pathlib.Path(temporary))
            locator.chmod(0o644)
            output = io.StringIO()
            with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                ExecutableLocatorError, "mode",
            ):
                self._main(locator, [
                    "capabilities", "--format", "json", "--locator", str(locator),
                    "--runtime-config", str(config),
                    *self._resource_arguments(config.parent),
                ])
            self.assertEqual(output.getvalue(), "")
            locator.chmod(0o600)
            config.chmod(0o644)
            with contextlib.redirect_stdout(output), self.assertRaisesRegex(
                RuntimeAdapterRejection, "owner|mode",
            ):
                self._main(locator, [
                    "capabilities", "--format", "json", "--locator", str(locator),
                    "--runtime-config", str(config),
                    *self._resource_arguments(config.parent),
                ])
            self.assertEqual(output.getvalue(), "")

    def test_gew_rt_029_skills_require_canonical_executable_and_contain_no_engine_logic(self) -> None:
        forbidden = (
            "def ", "class ", "sha256", "sqlite", "reduce(", "apply_events",
            "decide_command", "completion predicate", "transfer token",
        )
        for skill in sorted((ROOT / "skills").glob("graph-engineering-*/SKILL.md")):
            text = skill.read_text().casefold()
            with self.subTest(skill=skill.parent.name):
                self.assertIn("canonical executable", text)
                self.assertIn("capabilities", text)
                self.assertFalse(any(token in text for token in forbidden))
                self.assertNotIn("agent-engineering-workflow", text)
        owner_turn_source = (
            ROOT / "application/graph_engineering/application/owner_turns.py"
        ).read_text()
        for fixture_constant in (
            "artifact:prd-candidate", "evidence:runtime-compatible",
            "lease-plan:none", "1_000_000_000",
        ):
            self.assertNotIn(fixture_constant, owner_turn_source)

    def test_gew_rt_030_cli_and_skills_create_no_daemon_or_remote_state(self) -> None:
        before = {thread.ident for thread in threading.enumerate()}
        with tempfile.TemporaryDirectory() as temporary:
            locator, config = self._installation(pathlib.Path(temporary))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(self._main(locator, [
                    "capabilities", "--format", "json", "--locator", str(locator),
                    "--runtime-config", str(config),
                    *self._resource_arguments(config.parent),
                ]), 0)
        self.assertEqual({thread.ident for thread in threading.enumerate()}, before)
        self.assertNotIn("daemon", os.environ)

    def test_gew_rt_031_isolated_prerelease_wheel_and_skill_fixture_uses_exact_origin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            distribution = root / "dist"
            distribution.mkdir()
            build = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_wheel.py"), str(distribution)],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = next(distribution.glob("*.whl"))
            with zipfile.ZipFile(wheel) as archive:
                names = set(archive.namelist())
            self.assertFalse(any("runtime_fixture" in name or name.startswith("tests/") for name in names))

            environment = root / "tool-environment"
            compatible_python = shutil.which("python3.14") or shutil.which("python3.13") or sys.executable
            subprocess.run([compatible_python, "-m", "venv", str(environment)], check=True)
            install = subprocess.run(
                [str(environment / "bin" / "python"), "-m", "pip", "install",
                 "--no-deps", "--no-index", str(wheel)],
                check=False, capture_output=True, text=True,
                env={**os.environ, "PIP_CONFIG_FILE": os.devnull},
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            canonical = environment / "bin" / "graph-engineering"
            canonical.chmod(0o700)
            environment.chmod(0o700)
            locator = root / "locator.json"
            locator.write_text(json.dumps({
                "schema_version": "1.0", "executable": str(canonical.resolve()),
                "package_origin": str(environment.resolve()),
                "executable_digest": "sha256-raw-v1:" + hashlib.sha256(canonical.read_bytes()).hexdigest(),
                "release_manifest_digest": FIXTURE["shared"]["release_manifest_digest"],
                "expected_core_version": FIXTURE["shared"]["core_version"],
                "distribution_name": "graph-engineering-workflow",
                "distribution_version": "0.1.0",
                "distribution_origin": str(next(environment.glob("lib/python*/site-packages")).resolve()),
            }))
            locator.chmod(0o600)
            runtime_config = root / "runtime.json"
            configuration = adapter_document(FIXTURE["cells"][0])
            runtime_config.write_text(json.dumps(configuration))
            runtime_config.chmod(0o600)
            skill_body = {
                "schema_version": "1.0", "skill_id": configuration["skill_id"],
                "skill_version": configuration["skill_version"],
                "protocol_version": configuration["protocol_version"],
                "runtime_kind": configuration["runtime_kind"],
                "runtime_configuration_digest": configuration["configuration_digest"],
            }
            skill_request = root / "skill-request.json"
            skill_request.write_text(json.dumps({
                **skill_body,
                "request_digest": runtime_record_digest("skill-handshake-request", skill_body),
            }))
            skill_request.chmod(0o600)
            for name in (
                "runtime-resource-policy-v1.json", "resource-profile-v1.json",
                "cost-schedule-v1.json",
            ):
                shutil.copyfile(ROOT / "config/contracts" / name, root / name)
            skill_fixture = root / "skills"
            for name in ("graph-engineering-codex", "graph-engineering-hermes"):
                shutil.copytree(ROOT / "skills" / name, skill_fixture / name)

            decoy = root / "decoy"
            decoy.mkdir()
            decoy_bin = decoy / "bin"
            decoy_bin.mkdir()
            shadow = decoy_bin / "graph-engineering"
            shadow.write_text("#!/bin/sh\nexit 99\n")
            shadow.chmod(0o700)
            for responsibility in ("core", "application", "storage", "adapters"):
                package = decoy / responsibility
                package.mkdir()
                (package / "__init__.py").write_text("raise RuntimeError('source shadow used')\n")
            result = subprocess.run(
                [str(canonical), "capabilities", "--format", "json", "--locator", str(locator.resolve()),
                 "--runtime-config", str(runtime_config.resolve()),
                 *self._resource_arguments(root)],
                cwd=decoy, check=False, capture_output=True, text=True,
                env={**os.environ, "PATH": str(decoy_bin), "PYTHONPATH": ""},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.assertEqual(document["canonical_executable"], str(canonical.resolve()))
            self.assertEqual(document["package_origin"], str(environment.resolve()))
            self.assertEqual(document["core_version"], "0.1.0")
            self.assertTrue(all((skill_fixture / name / "SKILL.md").is_file() for name in (
                "graph-engineering-codex", "graph-engineering-hermes",
            )))

    def test_gew_rt_042_independent_skill_and_running_executable_handshake_fail_closed(self) -> None:
        for mutation in (
            "stale-skill", "stale-protocol", "foreign-executable",
            "unrelated-origin", "config-digest",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                locator, config = self._installation(pathlib.Path(temporary))
                arguments = [
                    "capabilities", "--format", "json", "--locator", str(locator),
                    "--runtime-config", str(config), *self._resource_arguments(config.parent),
                ]
                output = io.StringIO()
                if mutation in {"stale-skill", "stale-protocol"}:
                    skill_path = config.parent / "skill-request.json"
                    document = json.loads(skill_path.read_text())
                    document[
                        "skill_version" if mutation == "stale-skill" else "protocol_version"
                    ] = "9.9.9"
                    document["request_digest"] = runtime_record_digest(
                        "skill-handshake-request",
                        {key: value for key, value in document.items() if key != "request_digest"},
                    )
                    skill_path.write_text(json.dumps(document))
                    skill_path.chmod(0o600)
                    error = RuntimeAdapterRejection
                    invoke = lambda: self._main(locator, arguments)
                elif mutation == "foreign-executable":
                    foreign = config.parent / "foreign"
                    foreign.write_bytes(b"#!/bin/sh\nexit 0\n")
                    foreign.chmod(0o700)
                    error = ExecutableLocatorError
                    def invoke() -> int:
                        with mock.patch.object(sys, "argv", [str(foreign)]):
                            return main(arguments)
                elif mutation == "unrelated-origin":
                    document = json.loads(locator.read_text())
                    unrelated = config.parent / "unrelated"
                    unrelated.mkdir(mode=0o700)
                    document["package_origin"] = str(unrelated.resolve())
                    locator.write_text(json.dumps(document))
                    locator.chmod(0o600)
                    error = ExecutableLocatorError
                    invoke = lambda: self._main(locator, arguments)
                else:
                    document = json.loads(config.read_text())
                    document["runtime_instance_id"] = "runtime:substituted"
                    config.write_text(json.dumps(document))
                    config.chmod(0o600)
                    error = RuntimeAdapterRejection
                    invoke = lambda: self._main(locator, arguments)
                with contextlib.redirect_stdout(output), self.assertRaises(error):
                    invoke()
                self.assertEqual(output.getvalue(), "")

    def test_gew_rt_043_isolated_wheel_executes_full_owner_turn_surface_for_all_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve()
            distribution = root / "dist"
            distribution.mkdir()
            build = subprocess.run(
                [sys.executable, str(ROOT / "scripts/build_wheel.py"), str(distribution)],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            wheel = next(distribution.glob("*.whl"))
            environment = root / "tool-environment"
            compatible_python = shutil.which("python3.14") or shutil.which("python3.13") or sys.executable
            subprocess.run([compatible_python, "-m", "venv", str(environment)], check=True)
            install = subprocess.run(
                [str(environment / "bin/python"), "-m", "pip", "install", "--no-deps", "--no-index", str(wheel)],
                check=False, capture_output=True, text=True,
                env={**os.environ, "PIP_CONFIG_FILE": os.devnull},
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            canonical = environment / "bin/graph-engineering"
            canonical.chmod(0o700)
            environment.chmod(0o700)
            distribution_origin = next(environment.glob("lib/python*/site-packages")).resolve()
            fixture_root = root / "fixture"
            fixture_root.mkdir(mode=0o700)
            contracts = fixture_root / "contracts"
            contracts.mkdir(mode=0o700)
            schemas = contracts / "schemas"
            shutil.copytree(ROOT / "config/contracts/schemas", schemas)
            for name in (
                "runtime-resource-policy-v1.json", "resource-profile-v1.json",
                "cost-schedule-v1.json", "repository-policy-v1.json",
                "migration-storage-policy-v1.json", "runtime-local-port-policy-v1.json",
                "schema-profile-v1.json",
                "graph-schema-registry-v1.json",
            ):
                target = contracts / name
                shutil.copyfile(ROOT / "config/contracts" / name, target)
                target.chmod(0o600)
            skills = fixture_root / "skills"
            for name in ("graph-engineering-codex", "graph-engineering-hermes"):
                shutil.copytree(ROOT / "skills" / name, skills / name)
            locator = fixture_root / "locator.json"
            locator.write_text(json.dumps({
                "schema_version": "1.0", "executable": str(canonical.resolve()),
                "package_origin": str(environment.resolve()),
                "executable_digest": "sha256-raw-v1:" + hashlib.sha256(canonical.read_bytes()).hexdigest(),
                "release_manifest_digest": FIXTURE["shared"]["release_manifest_digest"],
                "expected_core_version": FIXTURE["shared"]["core_version"],
                "distribution_name": "graph-engineering-workflow",
                "distribution_version": "0.1.0",
                "distribution_origin": str(distribution_origin),
            }))
            locator.chmod(0o600)
            approval = TaskApplicationIntegrationTests.approval()
            approval.pop("project_scope_ref")
            for cell in FIXTURE["cells"]:
                cell_root = fixture_root / cell["cell_id"]
                cell_root.mkdir(mode=0o700)
                configuration = adapter_document(cell)
                runtime_config = cell_root / "runtime.json"
                runtime_config.write_text(json.dumps(configuration)); runtime_config.chmod(0o600)
                skill_body = {
                    "schema_version": "1.0", "skill_id": configuration["skill_id"],
                    "skill_version": configuration["skill_version"],
                    "protocol_version": configuration["protocol_version"],
                    "runtime_kind": configuration["runtime_kind"],
                    "runtime_configuration_digest": configuration["configuration_digest"],
                }
                skill_request = cell_root / "skill-request.json"
                skill_request.write_text(json.dumps({
                    **skill_body,
                    "request_digest": runtime_record_digest("skill-handshake-request", skill_body),
                })); skill_request.chmod(0o600)
                runtime_input = cell_root / "runtime-input.json"
                user_id = next(iter(cell["owner_bindings"]))
                owner_id = cell["owner_bindings"][user_id]
                channel_ref = cell["allowed_channels"][0]
                thread_ref = f"thread:{cell['cell_id']}"
                request = cell_root / "owner-flow.json"
                lineage_id = f"lineage:{cell['cell_id']}:{user_id}:{channel_ref}:{thread_ref}"
                command = [
                    str(canonical), "owner-flow", "--format", "json",
                    "--locator", str(locator), "--runtime-config", str(runtime_config),
                    "--runtime-resource-policy", str(contracts / "runtime-resource-policy-v1.json"),
                    "--resource-profile", str(contracts / "resource-profile-v1.json"),
                    "--cost-schedule", str(contracts / "cost-schedule-v1.json"),
                    "--skill-request", str(skill_request), "--runtime-input", str(runtime_input),
                    "--repository-policy", str(contracts / "repository-policy-v1.json"),
                    "--migration-policy", str(contracts / "migration-storage-policy-v1.json"),
                    "--runtime-port-policy", str(contracts / "runtime-local-port-policy-v1.json"),
                    "--schema-profile", str(contracts / "schema-profile-v1.json"),
                    "--schema-manifest", str(contracts / "graph-schema-registry-v1.json"),
                    "--schema-root", str(schemas), "--repository-root", str(cell_root / "repository"),
                    "--control-root", str(cell_root / "control"), "--request", str(request),
                ]

                def run_turn(
                    ordinal: int, operation: str, task_id: str | None,
                    payload: dict[str, object],
                ) -> dict[str, object]:
                    runtime_input.write_text(json.dumps({
                        "user_id": user_id, "channel_kind": cell["channel_kind"],
                        "channel_ref": channel_ref, "thread_ref": thread_ref,
                        "session_id": f"session:{cell['cell_id']}:{ordinal}",
                    })); runtime_input.chmod(0o600)
                    body = {
                        "schema_version": "1.0", "turn_id": f"turn:{cell['cell_id']}:{ordinal}",
                        "operation": operation, "task_id": task_id, "owner_id": owner_id,
                        "runtime_kind": configuration["runtime_kind"],
                        "runtime_lineage_id": lineage_id, "payload": payload,
                    }
                    request.write_text(json.dumps({
                        **body, "request_digest": runtime_record_digest("owner-turn-request", body),
                    })); request.chmod(0o600)
                    completed = subprocess.run(
                        command, cwd=cell_root, check=False, capture_output=True, text=True,
                        env={
                            **os.environ, "PATH": "/usr/bin:/bin:/sbin:/usr/sbin",
                            "PYTHONPATH": "",
                        },
                    )
                    with self.subTest(cell=cell["cell_id"], operation=operation):
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        document = json.loads(completed.stdout)
                        self.assertEqual(document["exit_code"], 0)
                        self.assertEqual(document["operation"], operation)
                        self.assertEqual(document["owner_id"], owner_id)
                        self.assertEqual(document["runtime_lineage_id"], lineage_id)
                    return document

                discover = run_turn(1, "discover", None, {})
                created = run_turn(2, "create", None, {
                    "occurred_at": "turn:create", "lease_ttl_ns": 60_000_000_000,
                })
                task_id = created["task_id"]
                clarified = run_turn(3, "clarify", task_id, {
                    "expected_task_revision": created["result"]["task_revision"],
                    "occurred_at": "turn:clarify", "lease_ttl_ns": 60_000_000_000,
                    "project_scope": scope_document(),
                    "prd_candidate_ref": "artifact:fixture-prd-candidate",
                })
                approved = run_turn(4, "approve", task_id, {
                    "expected_task_revision": clarified["result"]["task_revision"],
                    "occurred_at": "turn:approve", "lease_ttl_ns": 60_000_000_000,
                    "approval": approval,
                })
                running = run_turn(5, "run", task_id, {
                    "expected_task_revision": approved["result"]["task_revision"],
                    "occurred_at": "turn:run", "lease_ttl_ns": 60_000_000_000,
                    "compatibility_evidence_ref": "evidence:fixture-compatible",
                    "lease_plan_ref": "lease-plan:fixture",
                })
                status = run_turn(6, "status", task_id, {})
                resumed = run_turn(7, "resume", task_id, {})
                escalated = run_turn(8, "escalate", task_id, {
                    "request_id": f"decision:{cell['cell_id']}",
                    "decision_kind": "owner-review",
                    "decision_payload_ref": "decision-payload:fixture",
                    "decision_payload_digest": FIXTURE["shared"]["release_manifest_digest"],
                })
                presentation_body = {
                    "schema_version": "1.0", "presentation_id": f"result:{cell['cell_id']}",
                    "task_id": task_id, "kind": "result", "segments": ["fixture result"],
                    "content_digest": resumed["result"]["snapshot_digest"],
                }
                presented = run_turn(9, "result", task_id, {"presentation": {
                    **presentation_body,
                    "presentation_digest": runtime_record_digest(
                        "delivery-presentation", presentation_body,
                    ),
                }})
                with self.subTest(cell=cell["cell_id"], sequence="durable"):
                    self.assertIsNone(discover["task_id"])
                    self.assertEqual(running["result"]["task_revision"], 6)
                    self.assertEqual(status["result"]["task_revision"], 6)
                    self.assertEqual(resumed["result"], status["result"])
                    self.assertEqual(escalated["result"]["status"], "pending")
                    self.assertEqual(presented["result"]["status"], "pending")

                illegal_body = {
                    "schema_version": "1.0", "turn_id": f"turn:{cell['cell_id']}:illegal",
                    "operation": "approve", "task_id": task_id, "owner_id": owner_id,
                    "runtime_kind": configuration["runtime_kind"],
                    "runtime_lineage_id": lineage_id,
                    "payload": {
                        "expected_task_revision": 6, "occurred_at": "turn:illegal",
                        "lease_ttl_ns": 60_000_000_000, "approval": approval,
                    },
                }
                request.write_text(json.dumps({
                    **illegal_body,
                    "request_digest": runtime_record_digest("owner-turn-request", illegal_body),
                })); request.chmod(0o600)
                illegal = subprocess.run(
                    command, cwd=cell_root, check=False, capture_output=True, text=True,
                    env={
                        **os.environ, "PATH": "/usr/bin:/bin:/sbin:/usr/sbin",
                        "PYTHONPATH": "",
                    },
                )
                with self.subTest(cell=cell["cell_id"], rejection="illegal-state"):
                    self.assertEqual(illegal.returncode, 4, illegal.stderr)
                    self.assertEqual(json.loads(illegal.stdout)["status"], "rejected")
                after_illegal = run_turn(10, "status", task_id, {})
                self.assertEqual(after_illegal["result"]["task_revision"], 6)

                rejected_body = {
                    "schema_version": "1.0", "turn_id": f"turn:{cell['cell_id']}:foreign",
                    "operation": "status", "task_id": task_id, "owner_id": owner_id,
                    "runtime_kind": "foreign-runtime", "runtime_lineage_id": lineage_id,
                    "payload": {},
                }
                rejected = cell_root / "foreign-owner-flow.json"
                rejected.write_text(json.dumps({
                    **rejected_body,
                    "request_digest": runtime_record_digest("owner-turn-request", rejected_body),
                })); rejected.chmod(0o600)
                foreign_repository = cell_root / "foreign-repository"
                foreign_control = cell_root / "foreign-control"
                rejected_command = list(command)
                rejected_command[rejected_command.index(str(cell_root / "repository"))] = str(foreign_repository)
                rejected_command[rejected_command.index(str(cell_root / "control"))] = str(foreign_control)
                rejected_command[rejected_command.index(str(request))] = str(rejected)
                rejected_result = subprocess.run(
                    rejected_command, cwd=cell_root, check=False, capture_output=True, text=True,
                    env={**os.environ, "PATH": "/usr/bin:/bin:/sbin:/usr/sbin", "PYTHONPATH": ""},
                )
                with self.subTest(cell=cell["cell_id"], rejection="foreign-runtime"):
                    self.assertEqual(rejected_result.returncode, 4, rejected_result.stderr)
                    self.assertEqual(
                        set(json.loads(rejected_result.stdout)),
                        {"schema_version", "status", "exit_code", "result_digest"},
                    )
                    self.assertFalse(foreign_repository.exists())
                    self.assertFalse(foreign_control.exists())

                missing_body = {
                    "schema_version": "1.0", "turn_id": f"turn:{cell['cell_id']}:missing",
                    "operation": "status", "task_id": "task:missing", "owner_id": owner_id,
                    "runtime_kind": configuration["runtime_kind"],
                    "runtime_lineage_id": lineage_id, "payload": {},
                }
                request.write_text(json.dumps({
                    **missing_body,
                    "request_digest": runtime_record_digest("owner-turn-request", missing_body),
                })); request.chmod(0o600)
                missing_result = subprocess.run(
                    command, cwd=cell_root, check=False, capture_output=True, text=True,
                    env={
                        **os.environ, "PATH": "/usr/bin:/bin:/sbin:/usr/sbin",
                        "PYTHONPATH": "",
                    },
                )
                with self.subTest(cell=cell["cell_id"], rejection="missing-task"):
                    self.assertEqual(missing_result.returncode, 4, missing_result.stderr)
                    self.assertEqual(missing_result.stdout, rejected_result.stdout)
                after_missing = run_turn(11, "status", task_id, {})
                self.assertEqual(after_missing["result"]["task_revision"], 6)


if __name__ == "__main__":
    unittest.main()
