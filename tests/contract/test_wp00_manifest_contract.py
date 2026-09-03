from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import source_manifest  # noqa: E402


class GateManifestContractTests(unittest.TestCase):
    def test_every_required_suite_and_command_is_declared_once(self) -> None:
        manifest = json.loads((ROOT / "config" / "verification" / "wp-00-gate.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["test_suites"], ["unit", "contract", "integration", "conformance", "security", "e2e"])
        command_ids = [command["id"] for command in manifest["commands"]]
        self.assertEqual(len(command_ids), len(set(command_ids)))
        for keyword in ("LINT", "TYPE", "SECURITY", "LICENSE", "SBOM", "PLATFORM", "TEST", "BUILD", "REPRODUCIBILITY"):
            self.assertTrue(any(keyword in command_id for command_id in command_ids), keyword)

    def test_source_manifest_is_exact_and_detects_mutation(self) -> None:
        manifest = source_manifest.create_manifest()
        self.assertEqual(source_manifest.verify(manifest), [])
        changed = json.loads(json.dumps(manifest))
        changed["files"][0]["sha256"] = "0" * 64
        self.assertEqual(source_manifest.verify(changed), ["SOURCE_MANIFEST_MISMATCH"])

    def test_every_owned_root_rejects_internal_and_external_symlink_nodes(self) -> None:
        owned_roots = ["core", "application", "storage", "adapters", "scripts", "tests", "config/verification", "config/release-coverage", "config/supply-chain"]
        with tempfile.TemporaryDirectory(prefix="gew-manifest-symlink-") as directory:
            root = pathlib.Path(directory) / "project"
            root.mkdir()
            (root / "pyproject.toml").write_text("project = true\n", encoding="utf-8")
            (root / "uv.lock").write_text("lock = true\n", encoding="utf-8")
            files = ["pyproject.toml", "uv.lock"]
            for root_name in owned_roots:
                owned = root / root_name
                owned.mkdir(parents=True)
                relative = f"{root_name}/owned.txt"
                (root / relative).write_text(root_name, encoding="utf-8")
                files.append(relative)
            target_spec = root / "config" / "verification" / "wp-00-targets.json"
            files.append(target_spec.relative_to(root).as_posix())
            target_spec.write_text(
                json.dumps({"schema_version": "1.0", "owned_roots": owned_roots, "files": sorted(files)}),
                encoding="utf-8",
            )
            internal_file = root / "internal-file.txt"
            internal_file.write_text("internal", encoding="utf-8")
            internal_directory = root / "internal-directory"
            internal_directory.mkdir()
            external_file = pathlib.Path(directory) / "external-file.txt"
            external_file.write_text("external", encoding="utf-8")
            external_directory = pathlib.Path(directory) / "external-directory"
            external_directory.mkdir()
            with mock.patch.object(source_manifest, "ROOT", root), mock.patch.object(source_manifest, "TARGET_SPEC", target_spec):
                baseline = source_manifest.create_manifest()
                self.assertEqual(source_manifest.verify(baseline), [])
                for root_name in owned_roots:
                    owned = root / root_name
                    for kind, target, is_directory in (
                        ("internal-file", internal_file, False),
                        ("external-file", external_file, False),
                        ("internal-directory", internal_directory, True),
                        ("external-directory", external_directory, True),
                    ):
                        link = owned / f"untracked-{kind}"
                        link.symlink_to(target, target_is_directory=is_directory)
                        with self.subTest(root=root_name, kind=kind):
                            with self.assertRaisesRegex(ValueError, "unexpected_nodes"):
                                source_manifest.create_manifest()
                        link.unlink()
                        self.assertEqual(source_manifest.verify(baseline), [])


if __name__ == "__main__":
    unittest.main()
