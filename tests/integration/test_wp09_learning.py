"""Real local repository tests for consent-gated product learning."""
from __future__ import annotations

import unittest
import threading
import subprocess
import sys
import signal
import sqlite3
from unittest import mock
from contextlib import contextmanager

from graph_engineering.storage.connection import ManagedConnection
from graph_engineering.storage.migration import MigrationRepositoryError
from tests.support.wp03_repository import repository_stack
from tests.support.source_checkout_attestation import CONTROL_OPTION


@contextmanager
def learning_stack():
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.application.runtime import RuntimeMutationGateway
    from graph_engineering.core.graph.state import TaskCommand
    from tests.integration.test_wp07_runtime_parity import session, FIXTURE, SCHEMAS, WORK
    with repository_stack() as stack:
        root, factory, locks, *_ = stack
        factory._test_installation_scope.__exit__(None, None, None)
        manager = factory._test_installation_manager
        manager.initialize_learning_storage()
        with manager.command_scope() as scope:
            bound = factory.bind_command_scope(scope)
            objects = ObjectRepository(bound, locks)
            leases = ResourceLeaseRepository(bound, locks)
            repository = TaskRepository(bound, locks, objects, command_scope=scope)
            application = TaskApplication(repository, repository, leases, schema_registry=SCHEMAS, context=WORK)
            active = session(FIXTURE['cells'][0])
            identity = {'task_id':'task:learning-1','owner_id':active.proof.owner_id,
                'runtime_kind':active.capabilities.runtime_kind,'runtime_lineage_id':active.proof.lineage_id}
            try:
                RuntimeMutationGateway.create(active, active.proof, identity,
                    lambda runtime: application.execute(identity['task_id'],TaskCommand('create',0,{'identity':identity}),runtime),
                    occurred_at='2026-10-04T00:00:00Z',lease_ttl_ns=100)
                yield application, active, bound, repository
            finally:
                active.close()
                objects.close()


def learning_request(operation, request_id, **fields):
    return {'schema_version':'1.0.0','operation':operation,'request_id':request_id,
        'task_id':'task:learning-1',**fields}


def learning_call(application, active, request):
    from graph_engineering.application.runtime import RuntimeMutationGateway
    return RuntimeMutationGateway.invoke(active,active.proof,
        lambda runtime: application.learning(request,runtime))


_MAINTENANCE_CHILD = r'''
import json, os, pathlib, signal, sys
from unittest import mock
root = pathlib.Path(sys.argv[1])
sys.path[:0] = [str(root)] + [str(root / part) for part in ("core", "application", "storage", "adapters")]
from tests.support.wp03_repository import policy, mount_observation
from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.migration import InstallationMigrationRepository
with mock.patch.object(RepositoryDoctor, "_mount_observation", side_effect=mount_observation), mock.patch("graph_engineering.storage.clock.time.time_ns", return_value=0):
    factory = ConnectionFactory._attach_existing_for_maintenance(pathlib.Path(sys.argv[2]), policy(), "repository-test-v1")
    locks = LockedFileRegistry(factory)
    objects = ObjectRepository(factory, locks)
    manager = InstallationMigrationRepository.attach_command_plane(factory, locks, objects,
        control_root=pathlib.Path(sys.argv[3]), policy_document=json.loads((root / "config/contracts/migration-storage-policy-v1.json").read_text()))
    def fault(point):
        if point == sys.argv[4]:
            os.kill(os.getpid(), signal.SIGKILL)
    manager._fault = fault
    try:
        manager.initialize_learning_storage()
    finally:
        manager.close()
        objects.close()
        locks.close()
'''


def _maintenance_child(root, factory, point="no-interruption"):
    from tests.support.wp03_repository import ROOT
    return subprocess.run([
        sys.executable, "-B", "-X", f"{CONTROL_OPTION}={sys._xoptions[CONTROL_OPTION]}",
        "-c", _MAINTENANCE_CHILD, str(ROOT), str(root),
        str(factory._test_installation_control_root), point,
    ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=20)


class LearningIntegrationTests(unittest.TestCase):
    def test_prospective_regrant(self):
        from graph_engineering.core.learning import LearningError
        with learning_stack() as (application, active, factory, _repository):
            grant = learning_request('grant_learning','grant:1',expected_generation=0,
                metric_ids=['revision_count','elapsed_bucket'],expires_at_ns='1000')
            first = learning_call(application,active,grant)
            self.assertEqual(first['generation'],1)
            self.assertEqual(first,learning_call(application,active,grant))
            with self.assertRaises(LearningError):
                learning_call(application,active,{**grant,'metric_ids':['elapsed_bucket']})
            revoke = learning_request('revoke_learning','revoke:1',expected_generation=1)
            suppressed = learning_call(application,active,revoke)
            self.assertEqual(suppressed['state'],'revoked')
            self.assertEqual(suppressed['generation'],2)
            with self.assertRaises(LearningError):
                learning_call(application,active,{**grant,'request_id':'stale:grant'})
            # Replaying an old exact request returns its old receipt, never a grant.
            self.assertEqual(learning_call(application,active,grant),first)
            with factory.open('doctor') as connection:
                self.assertEqual(connection.execute('SELECT state,generation FROM pmf_consents').fetchone(),('revoked',2))
            second = learning_call(application,active,{**grant,'request_id':'grant:2','expected_generation':2})
            self.assertEqual(second['generation'],3)
            with factory.open('doctor') as connection:
                row=connection.execute('SELECT consent_generation,observation_json,retained_epochs_json FROM pmf_aggregates').fetchone()
                self.assertEqual(row[0],3)
                import json
                observation=json.loads(row[1])
                self.assertEqual(observation['grant_sequence'],first['source_sequence'])
                self.assertIsNone(observation['start_sample'])
                self.assertIsNone(observation['current_prd_sequence'])
                epochs=json.loads(row[2])
                self.assertEqual(len(epochs),1)
                self.assertEqual(epochs[0]['generation'],1)
                self.assertEqual(epochs[0]['observation']['grant_sequence'],first['source_sequence'])

    def test_schema_upgrade_restart(self):
        with repository_stack() as stack:
            root, factory, *_ = stack
            manager = factory._test_installation_manager
            # A normal command retains a shared installation lease. Maintenance
            # cannot upgrade underneath it, even on the same thread.
            with self.assertRaises(MigrationRepositoryError):
                manager.initialize_learning_storage()
            with factory._for_maintenance().open("doctor") as connection:
                self.assertEqual(connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'pmf_%'"
                ).fetchone()[0], 0)
            factory._test_installation_scope.__exit__(None, None, None)
            manager.initialize_learning_storage()
            restarted = _maintenance_child(root, factory)
            self.assertEqual(restarted.returncode, 0, "fresh maintenance process failed")
            with factory._for_maintenance().open("doctor") as connection:
                self.assertEqual(connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pmf_%' ORDER BY name"
                ).fetchall(), [(name,) for name in (
                    "pmf_aggregates", "pmf_consents", "pmf_owner_context", "pmf_tombstones"
                )])
                self.assertEqual(connection.execute(
                    "SELECT version FROM schema_versions WHERE component='pmf'"
                ).fetchall(), [("1.0.0",)])
            with factory._for_maintenance().open("migration") as connection:
                with connection.transaction():
                    connection.execute("UPDATE schema_versions SET version='999' WHERE component='pmf'")
            with self.assertRaises(MigrationRepositoryError):
                manager.initialize_learning_storage()

    def test_schema_upgrade_crash(self):
        for point in ("learning.after_table.0", "learning.after_table.3", "learning.after_version"):
            with self.subTest(point=point), repository_stack() as stack:
                root, factory, *_ = stack
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                crashed = _maintenance_child(root, factory, point)
                self.assertEqual(crashed.returncode, -signal.SIGKILL)
                with factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(connection.execute(
                        "SELECT count(*) FROM sqlite_master WHERE name LIKE 'pmf_%'"
                    ).fetchone()[0], 0)
                    self.assertIsNone(connection.execute(
                        "SELECT version FROM schema_versions WHERE component='pmf'"
                    ).fetchone())
                restarted = _maintenance_child(root, factory)
                self.assertEqual(restarted.returncode, 0, "recovery process failed")
                manager.initialize_learning_storage()

    def test_migration_no_pmf_export(self):
        cases = (
            None,
            "full-schema",
            "CREATE TABLE pmf_consents (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_aggregates (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_owner_context (task_id TEXT PRIMARY KEY) STRICT",
            "CREATE TABLE pmf_tombstones (task_id TEXT PRIMARY KEY) STRICT",
            "INSERT INTO schema_versions VALUES ('pmf','999','test')",
            "consent-only",
            "tombstone-only",
        )
        for index, statement in enumerate(cases):
            with self.subTest(statement=statement), repository_stack() as stack:
                root, factory, *_ = stack
                factory._test_installation_scope.__exit__(None, None, None)
                manager = factory._test_installation_manager
                destination = root.parent / f"export-{index}"
                if statement is None:
                    manager.export_bundle(destination, export_id=f"export-{index}")
                    self.assertTrue(destination.is_dir())
                    continue
                if statement == "full-schema":
                    manager.initialize_learning_storage()
                else:
                    with factory._for_maintenance().open("migration") as connection:
                        with connection.transaction():
                            if statement in {"consent-only", "tombstone-only"}:
                                table = "pmf_consents" if statement == "consent-only" else "pmf_tombstones"
                                connection.execute(f"CREATE TABLE {table} (task_id TEXT PRIMARY KEY) STRICT")
                                connection.execute(f"INSERT INTO {table} VALUES ('synthetic-task')")
                            else:
                                connection.execute(statement)
                with mock.patch.object(ManagedConnection, "online_backup") as backup:
                    execute = ManagedConnection.execute
                    def no_export_hold(connection, sql, parameters=()):
                        if sql.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) and "export_holds" in sql:
                            self.fail("export hold mutated before rejection")
                        return execute(connection, sql, parameters)
                    with mock.patch.object(ManagedConnection, "execute", autospec=True, side_effect=no_export_hold):
                        with self.assertRaisesRegex(MigrationRepositoryError, "learning"):
                            manager.export_bundle(destination, export_id=f"export-{index}")
                    backup.assert_not_called()
                self.assertFalse(destination.exists())
                with factory._for_maintenance().open("doctor") as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM export_holds").fetchone()[0], 0)
        # Pause export after acquiring the installation lock. A second thread
        # cannot initialize learning between the guard and the online backup.
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            reached = threading.Event()
            attempted = threading.Event()
            failures = []
            def maintenance():
                if not reached.wait(5):
                    failures.append("export barrier was not reached")
                    attempted.set()
                    return
                try:
                    manager.initialize_learning_storage()
                except MigrationRepositoryError:
                    pass
                except BaseException as error:
                    failures.append(type(error).__name__)
                else:
                    failures.append("initialization crossed export lock")
                finally:
                    attempted.set()
            def barrier(point):
                if point == "export.before_backup":
                    reached.set()
                    self.assertTrue(attempted.wait(5))
            worker = threading.Thread(target=maintenance)
            worker.start()
            try:
                with mock.patch.object(manager, "_fault", side_effect=barrier):
                    manager.export_bundle(root.parent / "serialized-export", export_id="serialized")
            finally:
                reached.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            manager.initialize_learning_storage()
            with self.assertRaises(MigrationRepositoryError):
                manager.export_bundle(root.parent / "after-initialization", export_id="after")
            self.assertFalse((root.parent / "after-initialization").exists())
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            destination = root.parent / "during-initialization"
            reached, attempted = threading.Event(), threading.Event()
            failures = []
            def exporting():
                if not reached.wait(5):
                    failures.append("initialization barrier was not reached")
                    attempted.set()
                    return
                try:
                    manager.export_bundle(destination, export_id="during")
                except MigrationRepositoryError:
                    pass
                except BaseException as error:
                    failures.append(type(error).__name__)
                else:
                    failures.append("export crossed maintenance lock")
                finally:
                    attempted.set()
            def initializing(point):
                if point == "learning.after_table.0":
                    reached.set()
                    self.assertTrue(attempted.wait(5))
            worker = threading.Thread(target=exporting)
            worker.start()
            try:
                with mock.patch.object(manager, "_fault", side_effect=initializing), mock.patch.object(ManagedConnection, "online_backup") as backup:
                    manager.initialize_learning_storage()
                    backup.assert_not_called()
            finally:
                reached.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(failures, [])
            self.assertFalse(destination.exists())
        with repository_stack() as stack:
            root, factory, *_ = stack
            factory._test_installation_scope.__exit__(None, None, None)
            manager = factory._test_installation_manager
            execute = ManagedConnection.execute
            def metadata_error(connection, sql, parameters=()):
                if "lower(name)" in sql:
                    raise sqlite3.DatabaseError("private-metadata-canary")
                return execute(connection, sql, parameters)
            destination = root.parent / "metadata-error"
            with mock.patch.object(ManagedConnection, "execute", autospec=True, side_effect=metadata_error), mock.patch.object(ManagedConnection, "online_backup") as backup:
                with self.assertRaisesRegex(MigrationRepositoryError, "^learning export metadata is unavailable$"):
                    manager.export_bundle(destination, export_id="metadata-error")
                backup.assert_not_called()
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
