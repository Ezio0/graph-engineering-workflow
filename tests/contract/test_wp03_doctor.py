from __future__ import annotations

import json
import pathlib
import platform
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.storage.connection import ConnectionFactory  # noqa: E402
from graph_engineering.storage.policy import RepositoryPolicy  # noqa: E402


class LiveRepositoryDoctorTests(unittest.TestCase):
    def test_live_supported_filesystem_vfs_and_sync_are_attested_before_open(self) -> None:
        self.assertIn(platform.system(), {"Darwin", "Linux"})
        policy = RepositoryPolicy.from_dict(json.loads(
            (ROOT / "config" / "contracts" / "repository-policy-v1.json").read_text()
        ))
        with tempfile.TemporaryDirectory(prefix="gew-live-doctor-") as directory:
            factory = ConnectionFactory.initialize(
                pathlib.Path(directory) / "repository", policy, "live-doctor-v1",
            )
            capability = factory.filesystem_capability
            self.assertTrue(capability.local_filesystem)
            self.assertTrue(capability.durable_sync)
            self.assertTrue(pathlib.Path(capability.mount_point).is_absolute())
            self.assertNotIn("conformance:", capability.filesystem_identity)
            self.assertEqual(capability.sqlite_vfs, policy.required_sqlite_vfs)
            with factory.open("doctor") as connection:
                snapshot = connection.pragma_snapshot()
            self.assertEqual(snapshot["synchronous"], 3)
            if platform.system() == "Darwin":
                self.assertEqual(snapshot["fullfsync"], 1)


if __name__ == "__main__":
    unittest.main()
