from __future__ import annotations

import copy
import json
import os
import pathlib
import platform
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.storage.connection import (  # noqa: E402
    ConnectionFactory,
    FilesystemCapability,
    RepositoryDoctor,
)
from graph_engineering.storage.errors import (  # noqa: E402
    RepositoryBusyError,
    RepositoryConfigurationError,
    RepositoryProcessError,
)
from graph_engineering.storage.policy import RepositoryPolicy  # noqa: E402


def policy_value() -> dict[str, object]:
    return json.loads((ROOT / "config" / "contracts" / "repository-policy-v1.json").read_text())


def mount_observation(root: pathlib.Path) -> dict[str, object]:
    system = platform.system()
    filesystem = "apfs" if system == "Darwin" else "ext4"
    return {
        "platform": system,
        "mount_point": str(root),
        "filesystem_type": filesystem,
        "mount_options": (filesystem, "local", "rw") if system == "Darwin" else ("rw",),
        "filesystem_identity": f"conformance:{system}:{filesystem}:{root}",
    }


class ConnectionFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = mock.patch.object(
            RepositoryDoctor, "_mount_observation", side_effect=mount_observation,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_policy_and_capability_are_closed_and_fail_on_durability_weakening(self) -> None:
        value = policy_value()
        policy = RepositoryPolicy.from_dict(value)
        self.assertEqual(policy.journal_mode, "DELETE")
        for name, mutate in (
            ("unknown", lambda item: item.update({"rogue": 1})),
            ("journal", lambda item: item.update({"journal_mode": "WAL"})),
            ("sync", lambda item: item.update({"synchronous": "NORMAL"})),
            ("mode", lambda item: item.update({"root_mode": 0o755})),
            ("timeout-bool", lambda item: item.update({"busy_timeout_ms": True})),
            ("path", lambda item: item.update({"database_filename": "../escape"})),
        ):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(RepositoryConfigurationError):
                RepositoryPolicy.from_dict(changed)
        with self.assertRaises(RepositoryConfigurationError):
            FilesystemCapability()
        with tempfile.TemporaryDirectory(prefix="gew-connection-untrusted-") as directory:
            rejected_root = pathlib.Path(directory) / "repository"
            with mock.patch.object(
                RepositoryDoctor,
                "_mount_observation",
                return_value={
                    "platform": platform.system(), "mount_point": directory,
                    "filesystem_type": "nfs", "mount_options": ("rw",),
                    "filesystem_identity": "untrusted-network-fixture",
                },
            ), self.assertRaises(RepositoryConfigurationError):
                ConnectionFactory.initialize(
                    rejected_root, policy, "repository-1",
                )
            self.assertFalse(rejected_root.exists())

    def test_open_contract_pragmas_roles_modes_and_symlink_fail_closed(self) -> None:
        policy = RepositoryPolicy.from_dict(policy_value())
        with tempfile.TemporaryDirectory(prefix="gew-connection-") as directory:
            root = pathlib.Path(directory) / "repository"
            factory = ConnectionFactory.initialize(root, policy, "repository-1")
            with self.assertRaisesRegex(RepositoryConfigurationError, "command scope"):
                factory.open("application")
            maintenance = factory._for_maintenance()
            with maintenance.open("application") as connection:
                pragmas = connection.pragma_snapshot()
                self.assertEqual(pragmas["journal_mode"], "DELETE")
                self.assertEqual(pragmas["synchronous"], 3)
                self.assertEqual(pragmas["foreign_keys"], 1)
                self.assertEqual(pragmas["busy_timeout"], policy.busy_timeout_ms)
                self.assertEqual(pragmas["locking_mode"], "NORMAL")
                self.assertEqual(pragmas["query_only"], 0)
            with factory.open("doctor") as connection:
                self.assertEqual(connection.pragma_snapshot()["query_only"], 1)
                with self.assertRaises(RepositoryConfigurationError):
                    connection.execute("DELETE FROM repository_meta")
                for statement in ("PRAGMA synchronous=NORMAL", "VACUUM INTO 'copy.db'", "ATTACH 'x' AS x"):
                    with self.subTest(statement=statement), self.assertRaises(
                        RepositoryConfigurationError
                    ):
                        connection.execute(statement)
            disguised_writes = (
                "WITH probe AS (SELECT 1) UPDATE schema_versions SET version='forged' WHERE component='storage'",
                "WITH probe AS (SELECT 1) DELETE FROM schema_versions WHERE component='storage'",
                "WITH probe AS (SELECT 1) INSERT INTO repository_meta(key,value) SELECT 'forged','1'",
            )
            for role in ("doctor", "backup"):
                with factory.open(role) as connection:
                    for statement in disguised_writes:
                        with self.subTest(role=role, statement=statement), self.assertRaises(
                            RepositoryConfigurationError,
                        ):
                            connection.execute(statement)
            with maintenance.open("application") as connection:
                self.assertEqual(connection.execute(
                    "SELECT version FROM schema_versions WHERE component='storage'",
                ).fetchone()[0], "1.0")
                self.assertIsNone(connection.execute(
                    "SELECT value FROM repository_meta WHERE key='forged'",
                ).fetchone())
            os.chmod(root / policy.database_filename, 0o644)
            with self.assertRaises(RepositoryConfigurationError):
                maintenance.open("application")
            os.chmod(root / policy.database_filename, policy.file_mode)
            alias = pathlib.Path(directory) / "alias"
            alias.symlink_to(root, target_is_directory=True)
            with self.assertRaises(RepositoryConfigurationError):
                ConnectionFactory.initialize(alias, policy, "repository-1")

            unsafe_root = pathlib.Path(directory) / "unsafe-root"
            unsafe_root.mkdir(mode=policy.root_mode)
            external_directory = pathlib.Path(directory) / "external-directory"
            external_directory.mkdir(mode=0o755)
            (unsafe_root / policy.objects_directory).symlink_to(
                external_directory, target_is_directory=True,
            )
            with self.assertRaises(RepositoryConfigurationError):
                ConnectionFactory.initialize(unsafe_root, policy, "repository-unsafe")
            self.assertEqual(external_directory.stat().st_mode & 0o777, 0o755)
            self.assertEqual(
                sorted(path.name for path in unsafe_root.iterdir()),
                [policy.objects_directory],
            )

            database_root = pathlib.Path(directory) / "database-symlink-root"
            database_root.mkdir(mode=policy.root_mode)
            for name in (
                policy.objects_directory, policy.staging_directory, policy.locks_directory,
            ):
                (database_root / name).mkdir(mode=policy.root_mode)
            (database_root / policy.locks_directory / policy.resources_directory).mkdir(
                mode=policy.root_mode,
            )
            external_database = pathlib.Path(directory) / "external-database"
            external_database.write_bytes(b"external-bytes")
            external_database.chmod(0o644)
            (database_root / policy.database_filename).symlink_to(external_database)
            with self.assertRaises(RepositoryConfigurationError):
                ConnectionFactory.initialize(database_root, policy, "repository-unsafe-db")
            self.assertEqual(external_database.read_bytes(), b"external-bytes")
            self.assertEqual(external_database.stat().st_mode & 0o777, 0o644)

    def test_connection_is_thread_and_fork_bound_and_transactions_are_explicit(self) -> None:
        policy = RepositoryPolicy.from_dict(policy_value())
        with tempfile.TemporaryDirectory(prefix="gew-connection-bound-") as directory:
            factory = ConnectionFactory.initialize(
                pathlib.Path(directory) / "repository", policy, "repository-1",
            )
            connection = factory._for_maintenance().open("application")
            errors: list[type[BaseException]] = []

            def cross_thread() -> None:
                try:
                    connection.execute("SELECT 1")
                except BaseException as error:
                    errors.append(type(error))

            thread = threading.Thread(target=cross_thread)
            thread.start()
            thread.join()
            self.assertEqual(errors, [RepositoryProcessError])
            if hasattr(os, "fork"):
                read_fd, write_fd = os.pipe()
                child = os.fork()
                if child == 0:
                    os.close(read_fd)
                    try:
                        connection.execute("SELECT 1")
                    except RepositoryProcessError:
                        os.write(write_fd, b"blocked")
                    finally:
                        os.close(write_fd)
                    os._exit(0)
                os.close(write_fd)
                self.assertEqual(os.read(read_fd, 32), b"blocked")
                os.close(read_fd)
                os.waitpid(child, 0)
            with connection.transaction():
                connection.execute("INSERT INTO repository_meta(key,value) VALUES('probe','before')")
                with self.assertRaises(RepositoryConfigurationError):
                    with connection.transaction():
                        pass
            connection.close()

    def test_busy_retry_is_finite_and_failed_transaction_has_no_partial_write(self) -> None:
        policy = RepositoryPolicy.from_dict(policy_value())
        with tempfile.TemporaryDirectory(prefix="gew-connection-busy-") as directory:
            factory = ConnectionFactory.initialize(
                pathlib.Path(directory) / "repository", policy, "repository-1",
            )
            maintenance = factory._for_maintenance()
            first = maintenance.open("application")
            second = maintenance.open("application")
            with first.transaction():
                first.execute("INSERT INTO repository_meta(key,value) VALUES('writer','one')")
                with self.assertRaises(RepositoryBusyError):
                    with second.transaction():
                        second.execute("INSERT INTO repository_meta(key,value) VALUES('writer2','two')")
            self.assertIsNone(second.execute(
                "SELECT value FROM repository_meta WHERE key='writer2'"
            ).fetchone())
            first.close()
            second.close()


if __name__ == "__main__":
    unittest.main()
