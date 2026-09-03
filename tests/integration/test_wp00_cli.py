from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BuildFrontendIntegrationTests(unittest.TestCase):
    def test_dependency_free_build_command_creates_one_wheel(self) -> None:
        with tempfile.TemporaryDirectory(prefix="gew-build-integration-") as directory:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "build_wheel.py"), directory],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list(pathlib.Path(directory).glob("*.whl"))), 1)


if __name__ == "__main__":
    unittest.main()
