from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class BuildConformanceTests(unittest.TestCase):
    def test_reproducibility_command_passes(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "verify_reproducible_build.py")],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
