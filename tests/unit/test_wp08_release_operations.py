from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import pathlib
import tomllib
import unittest
from unittest import mock

from graph_engineering.adapters.local_release_simulator import ReleaseSimulatorError
from graph_engineering.application.release_operations import (
    ReleaseOperationsRegistryFactory,
    _semantic,
)
from graph_engineering.application.profile_execution import (
    CategoryCompletionOracle,
    CategoryExecutionError,
    CategoryExecutionPolicy,
    CategoryTargetObservationAuthority,
)
from graph_engineering.core.release_operations import (
    RELEASE_OPERATIONS_SCHEMA_IDS,
    ReleaseArtifactManifest,
    ReleaseOperationsError,
    ReleaseOperationsRegistry,
)
from tests.support.wp05_actions import action_stack, authority_document
from tests.support import wp08_category_execution as category_fixture
from tests.support.wp08_release_operations import (
    artifact_bytes,
    release_disclosure_plan,
    release_prepared_document,
    release_restore_prepared_document,
    retarget_security_binding,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = ROOT / "config" / "release-operations"


class WP08RetainedRootPrimitiveTests(unittest.TestCase):
    """Physical storage primitives only, not runtime/recovery evidence authority."""

    MEMBERS = {"active.bin": 0o600, "state.json": 0o600}

    @staticmethod
    def _binding(lease):  # type: ignore[no-untyped-def]
        from graph_engineering.core.release_operations import ReleaseRecoveryBinding

        value = WP08ReleaseRecoveryBindingTests.document()
        value.update(lease.binding_parts())
        value["binding_digest"] = _semantic(
            {k: v for k, v in value.items() if k != "binding_digest"},
            "release-recovery-binding",
        )
        return ReleaseRecoveryBinding.from_dict(value)

    def _create(self, namespace):  # type: ignore[no-untyped-def]
        lease = namespace.create("task-wp05", "target-project", members=self.MEMBERS)
        try:
            lease.initialize_file("active.bin", b"artifact-a\n")
            lease.initialize_file("state.json", b'{"generation":0}')
            binding = self._binding(lease)
            lease.seal(binding)
            return lease, binding
        except BaseException:
            lease.close()
            raise

    def test_close_retains_exact_bytes_and_readonly_reopen_does_not_write(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, binding = self._create(namespace)
                path = lease.path
                before = {p.name: p.read_bytes() for p in path.iterdir()}
                lease.close()
                with namespace.open_readonly(binding, members=self.MEMBERS, context=security_context()) as reader:
                    self.assertEqual(reader.read("active.bin", max_bytes=1024), b"artifact-a\n")
                    self.assertEqual(reader.binding_parts(), {
                        k: binding.to_dict()[k] for k in ("namespace_identity", "root_identity", "root_nonce")
                    })
                    with self.assertRaises(ReleaseSimulatorError):
                        reader.initialize_file("active.bin", b"replacement")
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
                namespace.destroy(binding, members=self.MEMBERS, context=security_context())
                self.assertFalse(path.exists())

    def test_existing_orphan_is_never_adopted_or_cleaned(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease = namespace.create("task-wp05", "target-project", members=self.MEMBERS)
                binding = self._binding(lease)
                path = lease.path
                lease.close()
                with self.assertRaises(ReleaseSimulatorError):
                    namespace.create("task-wp05", "target-project", members=self.MEMBERS)
                with self.assertRaises(ReleaseSimulatorError):
                    namespace.open_readonly(binding, members=self.MEMBERS, context=security_context())
                self.assertEqual(list(path.iterdir()), [])

    def test_typed_readonly_handle_keeps_one_gate_and_closes_without_writes(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-query-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, binding = self._create(namespace)
                path = lease.path
                before = {p.name: p.read_bytes() for p in path.iterdir()}
                lease.close()
                with namespace.open_readonly_handle(binding, members=self.MEMBERS,
                        context=security_context()) as handle:
                    self.assertEqual(dict(handle.query()), before)
                    self.assertEqual(namespace.active_leases, 1)
                    with self.assertRaises(TypeError):
                        handle.query()["active.bin"] = b"changed"
                    for name in ("target", "execute", "compensate", "initialize_file", "seal", "destroy"):
                        self.assertFalse(hasattr(handle, name))
                    with self.assertRaisesRegex(ReleaseSimulatorError, "busy"):
                        namespace.open_readonly_handle(binding, members=self.MEMBERS,
                            context=security_context())
                    self.assertEqual(dict(handle.query()), before)
                self.assertEqual(namespace.active_leases, 0)
                with self.assertRaises(ReleaseSimulatorError):
                    handle.query()
                handle.close()
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
                with namespace.open_readonly_handle(binding, members=self.MEMBERS,
                        context=security_context()) as reopened:
                    self.assertEqual(dict(reopened.query()), before)

    def test_typed_readonly_handle_rejects_foreign_identity_without_closing_owner(self) -> None:
        import pickle
        import tempfile
        import threading
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-query-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, binding = self._create(namespace)
                lease.close()
                with namespace.open_readonly_handle(binding, members=self.MEMBERS,
                        context=security_context()) as handle:
                    expected = dict(handle.query())
                    with self.assertRaises(TypeError):
                        type(handle)()
                    with self.assertRaises(TypeError):
                        copy.copy(handle)
                    with self.assertRaises(TypeError):
                        pickle.dumps(handle)
                    forged = object.__new__(type(handle))
                    for action in (forged.query, forged.close):
                        with self.assertRaises(ReleaseSimulatorError):
                            action()
                    errors = []
                    def foreign():
                        for action in (handle.query, handle.close):
                            try:
                                action()
                            except ReleaseSimulatorError as error:
                                errors.append(str(error))
                    thread = threading.Thread(target=foreign)
                    thread.start()
                    thread.join(10)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(len(errors), 2)
                    self.assertEqual(namespace.active_leases, 1)
                    self.assertEqual(dict(handle.query()), expected)

    def test_typed_readonly_handle_revalidates_binding_and_member_set_on_query(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, _RetainedRootLease
        from tests.support.wp05a_security import security_context

        for drift in ("marker", "member", "extra", "read-error", "same-byte-member", "same-byte-marker"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory(prefix="gew-retained-query-") as directory:
                with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                    lease, binding = self._create(namespace)
                    path = lease.path
                    marker = path / _RetainedRootLease.BINDING_NAME
                    marker_bytes = marker.read_bytes()
                    lease.close()
                    handle = namespace.open_readonly_handle(binding, members=self.MEMBERS,
                        context=security_context())
                    self.addCleanup(handle.close)
                    original = _RetainedRootLease.read
                    reached = []
                    replaced_snapshot = {}
                    def change_after_read(current, name, *, max_bytes):
                        body = original(current, name, max_bytes=max_bytes)
                        if name == "state.json" and not reached:
                            reached.append(drift)
                            if drift == "marker":
                                marker.chmod(0o600)
                                marker.write_bytes(b"{}")
                                marker.chmod(0o400)
                            elif drift == "member":
                                (path / "active.bin").write_bytes(b"changed\n")
                            elif drift == "extra":
                                (path / "unexpected").write_bytes(b"extra")
                            elif drift in ("same-byte-member", "same-byte-marker"):
                                victim = marker if drift == "same-byte-marker" else path / "active.bin"
                                metadata, unchanged = victim.stat(), victim.read_bytes()
                                replacement = path / "replacement"
                                replacement.write_bytes(unchanged)
                                replacement.chmod(metadata.st_mode & 0o777)
                                os.replace(replacement, victim)
                                current = victim.stat()
                                self.assertNotEqual((metadata.st_dev, metadata.st_ino),
                                    (current.st_dev, current.st_ino))
                                self.assertEqual(victim.read_bytes(), unchanged)
                                replaced_snapshot.update({p.name: p.read_bytes() for p in path.iterdir()})
                            else:
                                raise OSError("injected query read failure")
                        return body
                    with mock.patch.object(_RetainedRootLease, "read", change_after_read):
                        with self.assertRaises((ReleaseSimulatorError, OSError)):
                            handle.query()
                    self.assertEqual(reached, [drift])
                    self.assertEqual(namespace.active_leases, 0)
                    with self.assertRaises(ReleaseSimulatorError):
                        handle.query()
                    if replaced_snapshot:
                        self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, replaced_snapshot)
                    marker.chmod(0o600)
                    marker.write_bytes(marker_bytes)
                    marker.chmod(0o400)
                    (path / "active.bin").write_bytes(b"artifact-a\n")
                    if (path / "unexpected").exists():
                        (path / "unexpected").unlink()
                    with namespace.open_readonly_handle(binding, members=self.MEMBERS,
                            context=security_context()) as fresh:
                        self.assertEqual(fresh.query()["active.bin"], b"artifact-a\n")

    def test_competing_thread_is_busy_and_foreign_thread_cannot_close_lease(self) -> None:
        import tempfile
        import threading
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            path = pathlib.Path(directory).resolve()
            with _RetainedNamespace(path) as namespace:
                lease, binding = self._create(namespace)
                errors = []
                def compete():
                    try:
                        with _RetainedNamespace(path) as other:
                            other.open_readonly(binding, members=self.MEMBERS, context=security_context())
                    except ReleaseSimulatorError as error:
                        errors.append(str(error))
                    try:
                        lease.close()
                    except ReleaseSimulatorError as error:
                        errors.append(str(error))
                worker = threading.Thread(target=compete)
                worker.start()
                worker.join(10)
                self.assertFalse(worker.is_alive())
                self.assertEqual(len(errors), 2)
                self.assertIn("busy", errors[0])
                self.assertEqual(lease.read("active.bin", max_bytes=1024), b"artifact-a\n")
                lease.close()
                namespace.destroy(binding, members=self.MEMBERS, context=security_context())

    def test_busy_destroy_and_namespace_close_do_not_revoke_live_owner(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, binding = self._create(namespace)
                try:
                    with self.assertRaisesRegex(ReleaseSimulatorError, "busy"):
                        namespace.destroy(binding, members=self.MEMBERS, context=security_context())
                    with self.assertRaises(ReleaseSimulatorError):
                        namespace.close()
                    self.assertEqual(lease.read("active.bin", max_bytes=1024), b"artifact-a\n")
                finally:
                    lease.close()

    def test_symlink_hardlink_wrong_mode_and_unowned_residue_fail_closed(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        for attack in ("symlink", "hardlink", "mode", "residue"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
                with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                    lease, binding = self._create(namespace)
                    path = lease.path
                    lease.close()
                    if attack == "symlink":
                        (path / "state.json").unlink()
                        (path / "state.json").symlink_to("active.bin")
                    elif attack == "hardlink":
                        os.link(path / "active.bin", path.parent / "alias.bin")
                    elif attack == "mode":
                        (path / "state.json").chmod(0o644)
                    else:
                        (path / "unknown").write_bytes(b"not-owned")
                    with self.assertRaises(ReleaseSimulatorError):
                        namespace.open_readonly(binding, members=self.MEMBERS, context=security_context())
                    self.assertEqual(namespace.active_leases, 0)

    def test_copied_root_and_changed_marker_cannot_replace_physical_binding(self) -> None:
        import tempfile
        import shutil
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        for attack in ("copy", "marker"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
                with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                    lease, binding = self._create(namespace)
                    path = lease.path
                    lease.close()
                    if attack == "copy":
                        moved = path.with_name(path.name + "-old")
                        path.rename(moved)
                        shutil.copytree(moved, path)
                    else:
                        marker = path / ".release-simulator-root"
                        marker.chmod(0o600)
                        marker.write_bytes(b"{}")
                        marker.chmod(0o400)
                    with self.assertRaises(ReleaseSimulatorError):
                        namespace.open_readonly(binding, members=self.MEMBERS, context=security_context())
                    self.assertEqual(namespace.active_leases, 0)

    def test_interrupted_destruction_removes_binding_before_cleanup(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, binding = self._create(namespace)
                path = lease.path
                lease.close()
                original_unlink = os.unlink
                def cut(name, **kwargs):
                    if name != ".release-simulator-root":
                        raise OSError("injected cleanup interruption")
                    return original_unlink(name, **kwargs)
                with mock.patch("graph_engineering.adapters.local_release_simulator.os.unlink", side_effect=cut), self.assertRaises(OSError):
                    namespace.destroy(binding, members=self.MEMBERS, context=security_context())
                self.assertFalse((path / ".release-simulator-root").exists())
                self.assertTrue((path / "active.bin").exists())
                with self.assertRaises(ReleaseSimulatorError):
                    namespace.open_readonly(binding, members=self.MEMBERS, context=security_context())
                self.assertEqual(namespace.active_leases, 0)

    def test_bounded_read_rejects_fifo_replacement_without_blocking(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            with _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                lease, _binding = self._create(namespace)
                with lease:
                    with self.assertRaisesRegex(ReleaseSimulatorError, "exceeds read bound"):
                        lease.read("active.bin", max_bytes=1)
                    original_open = os.open
                    def replace_before_open(name, flags, *args, **kwargs):
                        if name == "active.bin":
                            (lease.path / name).unlink()
                            os.mkfifo(lease.path / name, 0o600)
                            self.assertTrue(flags & os.O_NONBLOCK)
                        return original_open(name, flags, *args, **kwargs)
                    with mock.patch("graph_engineering.adapters.local_release_simulator.os.open", side_effect=replace_before_open):
                        # Preserve the capability probe while interposing the member open.
                        with mock.patch.object(os, "supports_dir_fd", {*os.supports_dir_fd, os.open}):
                            with self.assertRaisesRegex(ReleaseSimulatorError, "changed before read"):
                                lease.read("active.bin", max_bytes=1024)

    def test_namespace_replacement_invalidates_live_lease(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            path = pathlib.Path(directory).resolve() / "namespace"
            path.mkdir(mode=0o700)
            with _RetainedNamespace(path) as namespace:
                lease, _binding = self._create(namespace)
                with lease:
                    path.rename(path.with_name("old-namespace"))
                    path.mkdir(mode=0o700)
                    with self.assertRaisesRegex(ReleaseSimulatorError, "namespace identity changed"):
                        lease.read("active.bin", max_bytes=1024)

    def test_namespace_and_member_inputs_reject_aliases_and_unsupported_primitives(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace

        with tempfile.TemporaryDirectory(prefix="gew-retained-unit-") as directory:
            path = pathlib.Path(directory).resolve()
            with mock.patch.object(os, "O_NOFOLLOW", 0), self.assertRaises(ReleaseSimulatorError):
                _RetainedNamespace(path)
            with _RetainedNamespace(path) as namespace:
                for members in ({"../escape": 0o600}, {"active.bin": 0o644}, {".release-simulator-root": 0o600}):
                    with self.subTest(members=members), self.assertRaises(ReleaseSimulatorError):
                        namespace.create("task-wp05", "target-project", members=members)
                self.assertEqual(list(path.iterdir()), [])


class WP08RestartSecurityReadTests(unittest.TestCase):
    @staticmethod
    def _database(fixture):  # type: ignore[no-untyped-def]
        with fixture.coordinator._factory.open("doctor") as connection:
            names = [row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
            ).fetchall()]
            return {name: sorted(connection.execute(
                'SELECT * FROM "' + name.replace('"', '""') + '"',
            ).fetchall(), key=repr) for name in names}

    @staticmethod
    def _change_state(fixture, change):  # type: ignore[no-untyped-def]
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest

        with fixture.coordinator._factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT state_json FROM task_security_states WHERE task_id=?", ("task-wp05",),
                ).fetchone()
                state = json.loads(row[0])
                change(state)
                connection.execute(
                    "UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                    (canonical_json(state), semantic_record_digest({
                        "contract": "task-security-state-v1", "value": state,
                    }), "task-wp05"),
                )

    def test_read_is_zero_write_immutable_data_not_mutation_context(self) -> None:
        from graph_engineering.application.security import ReadOnlyTaskSecurityProjection
        from graph_engineering.core.security.attestation import (
            TaskSecurityContext, SecurityAttestationError, require_runtime_context,
        )
        from graph_engineering.storage.errors import RepositoryConfigurationError

        with action_stack() as fixture:
            before = self._database(fixture)
            with mock.patch("graph_engineering.storage.security.trusted_now", side_effect=AssertionError("clock called")):
                record = fixture.issuer.read_task_state("task-wp05")
            self.assertEqual(self._database(fixture), before)
            self.assertIs(type(record), ReadOnlyTaskSecurityProjection)
            self.assertNotIsInstance(record, TaskSecurityContext)
            self.assertFalse(hasattr(record, "current_time"))
            self.assertFalse(hasattr(record, "_issuer"))
            with self.assertRaises(SecurityAttestationError):
                require_runtime_context(fixture.issuer.runtime, record)
            self.assertEqual(record.state["binding"]["task_id"], "task-wp05")
            with self.assertRaises(TypeError):
                record.state["binding"]["task_id"] = "foreign"
            with self.assertRaises(TypeError):
                ReadOnlyTaskSecurityProjection()
            with fixture.coordinator._factory.open("doctor") as connection:
                self.assertEqual(connection.pragma_snapshot()["query_only"], 1)
                with self.assertRaises(RepositoryConfigurationError):
                    connection.execute("UPDATE repository_meta SET value=value")

    def test_fresh_read_observes_revocation_without_reusing_old_data(self) -> None:
        with action_stack() as fixture:
            first = fixture.issuer.read_task_state("task-wp05")
            self.assertTrue(first.state["authority_digests"])
            self._change_state(fixture, lambda state: state.update(authority_digests=[]))
            before = self._database(fixture)
            second = fixture.issuer.read_task_state("task-wp05")
            self.assertEqual(second.state["authority_digests"], ())
            self.assertNotEqual(first.state_digest, second.state_digest)
            self.assertEqual(self._database(fixture), before)

    def test_missing_stale_foreign_and_malformed_state_reject(self) -> None:
        from graph_engineering.storage.errors import RepositoryIntegrityError

        mutations = (
            lambda state: state.update(task_revision=999),
            lambda state: state["binding"].update(task_id="foreign"),
            lambda state: state["binding"].update(binding_digest="sha256-jcs-v1:" + "0" * 64),
        )
        for change in mutations:
            with self.subTest(change=change.__code__.co_firstlineno), action_stack() as fixture:
                self._change_state(fixture, change)
                before = self._database(fixture)
                with self.assertRaises((ValueError, RepositoryIntegrityError)):
                    fixture.issuer.read_task_state("task-wp05")
                with self.assertRaises(RepositoryIntegrityError):
                    fixture.issuer.read_task_state("missing")
                self.assertEqual(self._database(fixture), before)

    def test_installed_runtime_substitution_rejects(self) -> None:
        import sqlite3
        from dataclasses import replace
        from graph_engineering.storage.errors import RepositoryIntegrityError
        from graph_engineering.storage.security import SecurityStateRepository

        with action_stack() as fixture:
            with fixture.coordinator._factory.open("application") as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"), connection.transaction():
                    connection.execute(
                        "UPDATE security_runtime_installation SET manifest_digest=?",
                        ("sha256-jcs-v1:" + "0" * 64,),
                    )
            before = self._database(fixture)
            installed = fixture.issuer._repository.load_installed_runtime(fixture.context)
            substituted = replace(installed, manifest_digest="sha256-jcs-v1:" + "0" * 64)
            with mock.patch.object(SecurityStateRepository, "load_installed_runtime", return_value=substituted), self.assertRaises((ValueError, RepositoryIntegrityError)):
                fixture.issuer.read_task_state("task-wp05")
            self.assertEqual(self._database(fixture), before)


class WP08RestartTaskBridgeTests(unittest.TestCase):
    @staticmethod
    def _wrapper():  # type: ignore[no-untyped-def]
        return {"task_id": "task", "revision": 2, "domain": {
            "identity": {"task_id": "task"}, "task_revision": 2, "last_event_seq": 2,
        }, "runner": {"opaque": ["unchanged"]}}

    @staticmethod
    def _history():  # type: ignore[no-untyped-def]
        return tuple({"task_id": "task", "sequence": i + 1,
            "expected_task_revision": i, "event_type": kind} for i, kind in enumerate((
                "task.created", "action.execution_started", "action.receipt_recorded",
                "action.reconciled_effect_verified", "project.scope_drafted",
            )))

    @staticmethod
    def _sequence(history, *, repository_revision=5, domain_count=2):  # type: ignore[no-untyped-def]
        from types import SimpleNamespace
        from graph_engineering.application.tasks import TaskApplication

        view = SimpleNamespace(task_id="task", repository_revision=repository_revision,
            snapshot=SimpleNamespace(task_revision=domain_count, last_event_seq=domain_count))
        return TaskApplication._repository_sequence(view, history)

    def test_action_preserves_closed_domain_wrapper(self) -> None:
        from graph_engineering.application.tasks import action_task_snapshot

        original = self._wrapper()
        result = action_task_snapshot(original, task_id="task", revision=2, action_state="reconciled")
        self.assertEqual(set(result), {"task_id", "revision", "domain", "runner"})
        self.assertEqual(result["revision"], 3)
        self.assertEqual(result["domain"], original["domain"])
        self.assertEqual(result["runner"], original["runner"])
        result["runner"]["opaque"].append("new")
        self.assertEqual(original["runner"]["opaque"], ["unchanged"])

    def test_malformed_domain_wrapper_is_not_stripped_or_adopted(self) -> None:
        from graph_engineering.application.tasks import action_task_snapshot, ApplicationError

        for change in (lambda v: v.update(action_state="old"), lambda v: v.pop("runner"),
                       lambda v: v["domain"].update(last_event_seq=9),
                       lambda v: v["domain"]["identity"].update(task_id="foreign"),
                       lambda v: v.update(revision=True)):
            value = self._wrapper()
            change(value)
            with self.subTest(value=value), self.assertRaises(ApplicationError):
                action_task_snapshot(value, task_id="task", revision=2, action_state="executing")

    def test_legacy_action_only_snapshot_preserves_existing_fields(self) -> None:
        from graph_engineering.application.tasks import action_task_snapshot

        self.assertEqual(action_task_snapshot({"task_id": "task", "revision": 1, "state": "ready"},
            task_id="task", revision=1, action_state="executing"),
            {"task_id": "task", "revision": 2, "state": "ready", "action_state": "executing"})

    def test_split_ordinals_and_multi_event_domain_transaction(self) -> None:
        history = self._history()
        self.assertEqual(self._sequence(history), 5)
        additional = {"task_id": "task", "sequence": 6, "expected_task_revision": 4,
                      "event_type": "task.prd_approval_requested"}
        self.assertEqual(self._sequence(history + (additional,), domain_count=3), 6)

    def test_unknown_mixed_or_multi_action_transaction_rejects(self) -> None:
        from graph_engineering.application.tasks import ApplicationError

        for index, patch in ((1, {"event_type": "action.foreign"}),
                             (4, {"event_type": "task.foreign"}),
                             (1, {"expected_task_revision": 0}),
                             (2, {"expected_task_revision": 1})):
            history = copy.deepcopy(self._history())
            history[index].update(patch)
            with self.subTest(index=index, patch=patch), self.assertRaises(ApplicationError):
                self._sequence(history)

    def test_stale_revision_wrong_domain_count_task_and_gap_reject(self) -> None:
        from graph_engineering.application.tasks import ApplicationError

        for kwargs in ({"repository_revision": 4}, {"domain_count": 5}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ApplicationError):
                self._sequence(self._history(), **kwargs)
        for patch in ({"task_id": "foreign"}, {"sequence": 9}):
            history = copy.deepcopy(self._history())
            history[-1].update(patch)
            with self.subTest(patch=patch), self.assertRaises(ApplicationError):
                self._sequence(history)


class WP08ReleaseOperationsFoundationTests(unittest.TestCase):
    @staticmethod
    def installation_documents() -> dict[str, object]:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        return {
            "policy_bytes": (ROOT / pin["policy-source"]).read_bytes(),
            "fixture_bytes": (ROOT / pin["fixture-source"]).read_bytes(),
            "bootstrap_bytes": (ROOT / pin["bootstrap-source"]).read_bytes(),
            "profile_schema_registry_bytes": (
                ROOT / pin["profile-schema-registry-source"]
            ).read_bytes(),
            "package_provenance_bytes": (ROOT / "pyproject.toml").read_bytes(),
            "schema_bodies": {
                json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
                for path in pin["schema-sources"]
            },
            "protected_resources": {
                path: (ROOT / path).read_bytes() for path in pin["protected-sources"]
            },
        }

    def registry(self) -> ReleaseOperationsRegistry:
        return ReleaseOperationsRegistry.from_dicts(
            json.loads((CONFIG / "release-operations-policy-registry-v1.json").read_text()),
            json.loads((CONFIG / "release-simulator-fixture-registry-v1.json").read_text()),
        )

    @staticmethod
    def issued_artifacts(
        factory: ReleaseOperationsRegistryFactory,
    ) -> tuple[ReleaseArtifactManifest, bytes, ReleaseArtifactManifest, bytes]:
        baseline = factory.issue_artifact_manifest(
            fixture_id="release-foundation-v1", artifact_id="artifact-a",
        )
        candidate = factory.issue_artifact_manifest(
            fixture_id="release-foundation-v1", artifact_id="artifact-b",
        )
        baseline_bytes = factory.artifact_bytes(baseline)
        candidate_bytes = factory.artifact_bytes(candidate)
        if (baseline_bytes, candidate_bytes) != artifact_bytes():
            raise AssertionError("installed fixture artifact bytes changed")
        return baseline, baseline_bytes, candidate, candidate_bytes

    def session(
        self,
        factory: ReleaseOperationsRegistryFactory,
        fixture,
        *,
        fault_hook=lambda _step: None,
    ):  # type: ignore[no-untyped-def]
        baseline, baseline_bytes, candidate, candidate_bytes = self.issued_artifacts(factory)
        session = factory.issue_simulator(
            action_coordinator=fixture.raw_coordinator,
            task_id="task-wp05",
            fixture_id="release-foundation-v1",
            target_id="target-project",
            resource_id="target:project",
            baseline_manifest=baseline,
            authorized_artifacts=(baseline, candidate),
            fault_hook=fault_hook,
        )
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        return session, baseline, baseline_bytes, candidate, candidate_bytes

    def execute_apply(
        self,
        fixture,
        session,
        baseline,
        candidate,
        candidate_bytes,
    ):  # type: ignore[no-untyped-def]
        document = release_prepared_document(
            fixture,
            target_digest=session.target.target_digest,
            baseline=baseline,
            candidate=candidate,
            candidate_bytes=candidate_bytes,
        )
        prepared = fixture.coordinator.prepare(document)
        fixture.coordinator.authorize(authority_document(
            prepared, context=fixture.context,
        ))
        outcome = fixture.coordinator.execute(
            prepared.action_id,
            owner_id="owner-wp05",
            runtime_kind="codex",
            runtime_lineage_id="lineage-wp05",
            lease=fixture.action_lease,
            target=session.target,
            observer=session.observer,
            disclosure_plan=release_disclosure_plan(fixture, prepared),
        )
        return prepared, outcome

    def test_nine_schema_pairs_are_exact_and_release_only(self) -> None:
        names = (
            "category-completion-assessment",
            "release-artifact-manifest",
            "release-deployment-observation",
            "release-health-observation",
            "release-operations-installation-bootstrap",
            "release-operations-observation",
            "release-operations-policy-registry",
            "release-recovery-binding",
            "release-simulator-fixture-registry",
        )
        expected = tuple(sorted(
            f"urn:gew:schema:{name}{suffix}:{'1.4.0' if name == 'category-completion-assessment' else '1.0.0'}"
            for name in names for suffix in ("", "-input")
        ))
        self.assertEqual(RELEASE_OPERATIONS_SCHEMA_IDS, expected)

    def test_policy_fixture_registry_is_closed_and_self_digest_bound(self) -> None:
        registry = self.registry()
        self.assertEqual(len(registry.operation_ids), 3)
        self.assertEqual(len(registry.fault_points), 5)
        policy = json.loads(
            (CONFIG / "release-operations-policy-registry-v1.json").read_text()
        )
        policy["deployment_policy"]["operation_ids"].append("release.real")
        with self.assertRaises(ReleaseOperationsError):
            ReleaseOperationsRegistry.from_dicts(
                policy,
                json.loads(
                    (CONFIG / "release-simulator-fixture-registry-v1.json").read_text()
                ),
            )

    def test_installed_bootstrap_and_protected_closure_are_current(self) -> None:
        factory = ReleaseOperationsRegistryFactory.from_installation()
        self.assertEqual(len(factory.registry().operation_ids), 3)

    def test_non_installation_factories_cannot_issue_or_enter_oracle(self) -> None:
        documents = self.installation_documents()
        schema_bodies = documents["schema_bodies"]
        self.assertIsInstance(schema_bodies, dict)
        bootstrap_bytes = documents["bootstrap_bytes"]
        self.assertIsInstance(bootstrap_bytes, bytes)

        def assert_zero_issuance(factory: ReleaseOperationsRegistryFactory) -> None:
            self.assertEqual(factory._issued, {})
            self.assertEqual(factory._issued_manifests, {})
            self.assertEqual(factory._issued_sessions, {})
            self.assertEqual(factory._issued_deployments, {})
            self.assertEqual(factory._issued_health, {})

        direct_fixture = json.loads(documents["fixture_bytes"])
        direct_fixture["fixtures"][0]["artifact_vectors"][0][
            "artifact_base64"
        ] = base64.b64encode(b"direct-constructor-artifact\n").decode("ascii")
        direct_fixture.pop("registry_digest")
        direct_fixture["registry_digest"] = _semantic(
            direct_fixture, "release-simulator-fixture-registry",
        )

        direct = ReleaseOperationsRegistryFactory(
            ReleaseOperationsRegistry.from_dicts(
                json.loads(documents["policy_bytes"]), direct_fixture,
            ),
            json.loads(bootstrap_bytes),
            schema_documents={
                schema_id: json.loads(body)
                for schema_id, body in schema_bodies.items()
            },
            currentness_check=lambda: None,
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            direct.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(direct)

        validation_only = ReleaseOperationsRegistryFactory.from_documents(**documents)
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            validation_only.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(validation_only)

        forged_fixture = json.loads(documents["fixture_bytes"])
        forged_fixture["fixtures"][0]["artifact_vectors"][0][
            "artifact_base64"
        ] = base64.b64encode(b"caller-owned-artifact\n").decode("ascii")
        forged_fixture.pop("registry_digest")
        forged_fixture["registry_digest"] = _semantic(
            forged_fixture, "release-simulator-fixture-registry",
        )
        forged_fixture_bytes = (
            json.dumps(forged_fixture, indent=2).encode("utf-8") + b"\n"
        )
        forged_fixture_bootstrap = json.loads(bootstrap_bytes)
        forged_fixture_bootstrap["fixture_registry_digest"] = forged_fixture[
            "registry_digest"
        ]
        forged_fixture_bootstrap["fixture_registry_raw_sha256"] = hashlib.sha256(
            forged_fixture_bytes
        ).hexdigest()
        forged_fixture_bootstrap.pop("bootstrap_digest")
        forged_fixture_bootstrap["bootstrap_digest"] = _semantic(
            forged_fixture_bootstrap, "release-operations-installation-bootstrap",
        )
        fixture_factory = ReleaseOperationsRegistryFactory.from_documents(
            **{
                **documents,
                "fixture_bytes": forged_fixture_bytes,
                "bootstrap_bytes": (
                    json.dumps(forged_fixture_bootstrap, indent=2).encode("utf-8")
                    + b"\n"
                ),
            },
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            fixture_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(fixture_factory)

        forged_schema_bodies = dict(schema_bodies)
        forged_schema_id = "urn:gew:schema:release-artifact-manifest:1.0.0"
        forged_schema_bodies[forged_schema_id] = json.dumps({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": forged_schema_id,
            "type": "object",
        }).encode("utf-8")
        forged_schema_bootstrap = json.loads(bootstrap_bytes)
        for row in forged_schema_bootstrap["schema_vectors"]:
            if row["schema_id"] == forged_schema_id:
                row["raw_sha256"] = hashlib.sha256(
                    forged_schema_bodies[forged_schema_id]
                ).hexdigest()
        forged_schema_bootstrap.pop("bootstrap_digest")
        forged_schema_bootstrap["bootstrap_digest"] = _semantic(
            forged_schema_bootstrap, "release-operations-installation-bootstrap",
        )
        schema_factory = ReleaseOperationsRegistryFactory.from_documents(
            **{
                **documents,
                "bootstrap_bytes": (
                    json.dumps(forged_schema_bootstrap, indent=2).encode("utf-8")
                    + b"\n"
                ),
                "schema_bodies": forged_schema_bodies,
            },
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            schema_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        assert_zero_issuance(schema_factory)

        profile_id = "release-operations"
        materialized = category_fixture.materialized_profile(profile_id)
        policy = CategoryExecutionPolicy.from_installation(
            profile_document=category_fixture.profile_document(profile_id),
            support_matrix_document=category_fixture.load_json(
                category_fixture.SUPPORT_MATRIX_PATH
            ),
            materialization_record=materialized.record,
        )
        with self.assertRaisesRegex(CategoryExecutionError, "authority is invalid"):
            CategoryCompletionOracle(
                policy=policy,
                target_authority=CategoryTargetObservationAuthority(policy),
                release_operations_factory=validation_only,
            )
        assert_zero_issuance(validation_only)

    def test_action_source_and_package_pin_substitutions_fail_closed(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        policy_bytes = (ROOT / pin["policy-source"]).read_bytes()
        fixture_bytes = (ROOT / pin["fixture-source"]).read_bytes()
        bootstrap = json.loads((ROOT / pin["bootstrap-source"]).read_bytes())
        profile_bytes = (ROOT / pin["profile-schema-registry-source"]).read_bytes()
        provenance_bytes = (ROOT / "pyproject.toml").read_bytes()
        schema_bodies = {
            json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
            for path in pin["schema-sources"]
        }
        protected = {
            path: (ROOT / path).read_bytes() for path in pin["protected-sources"]
        }
        mutations = (
            (
                "action authority pin",
                lambda value: value["action_authority_pins"].__setitem__(
                    "adapter_registry_digest", "sha256-jcs-v1:" + "f" * 64,
                ),
            ),
            (
                "source authority pin",
                lambda value: value["source_authority_pins"].__setitem__(
                    "source_file_count",
                    value["source_authority_pins"]["source_file_count"] + 1,
                ),
            ),
            (
                "package authority pin",
                lambda value: value["package_authority_pins"].__setitem__(
                    "distribution_name", "foreign-distribution",
                ),
            ),
        )
        for expected, mutate in mutations:
            with self.subTest(expected=expected):
                changed = copy.deepcopy(bootstrap)
                mutate(changed)
                changed.pop("bootstrap_digest")
                changed["bootstrap_digest"] = _semantic(
                    changed, "release-operations-installation-bootstrap",
                )
                with self.assertRaisesRegex(ReleaseOperationsError, expected):
                    ReleaseOperationsRegistryFactory.from_documents(
                        policy_bytes=policy_bytes,
                        fixture_bytes=fixture_bytes,
                        bootstrap_bytes=(
                            json.dumps(changed, indent=2).encode("utf-8") + b"\n"
                        ),
                        profile_schema_registry_bytes=profile_bytes,
                        package_provenance_bytes=provenance_bytes,
                        schema_bodies=schema_bodies,
                        protected_resources=protected,
                    )

        import graph_engineering

        installed = graph_engineering._release_operations_installation_resources()
        text = installed[0].decode("utf-8")
        marker = "[tool.gew.profile.release-operations]"
        before, section = text.split(marker, 1)
        section = section.replace(
            'distribution-name = "graph-engineering-workflow"',
            'distribution-name = "foreign-distribution"',
            1,
        )
        substituted = ((before + marker + section).encode("utf-8"), *installed[1:])
        with mock.patch.object(
            graph_engineering,
            "_release_operations_installation_resources",
            return_value=substituted,
        ), self.assertRaisesRegex(ReleaseOperationsError, "independent installation pin"):
            ReleaseOperationsRegistryFactory.from_installation()

    def test_validation_only_factory_still_enforces_currentness(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        policy_bytes = (ROOT / pin["policy-source"]).read_bytes()
        fixture_bytes = (ROOT / pin["fixture-source"]).read_bytes()
        bootstrap_bytes = (ROOT / pin["bootstrap-source"]).read_bytes()
        profile_bytes = (ROOT / pin["profile-schema-registry-source"]).read_bytes()
        package_provenance_bytes = (ROOT / "pyproject.toml").read_bytes()
        schema_bodies = {
            json.loads((ROOT / path).read_bytes())["$id"]: (ROOT / path).read_bytes()
            for path in pin["schema-sources"]
        }
        protected = {path: (ROOT / path).read_bytes() for path in pin["protected-sources"]}
        current = {
            "policy": policy_bytes,
            "fixture": fixture_bytes,
            "bootstrap": bootstrap_bytes,
            "profile-schema-registry": profile_bytes,
            "package-provenance": package_provenance_bytes,
            **{f"schema:{key}": value for key, value in schema_bodies.items()},
            **{f"protected:{key}": value for key, value in protected.items()},
        }
        factory = ReleaseOperationsRegistryFactory.from_documents(
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            bootstrap_bytes=bootstrap_bytes,
            profile_schema_registry_bytes=profile_bytes,
            package_provenance_bytes=package_provenance_bytes,
            schema_bodies=schema_bodies,
            protected_resources=protected,
            current_resource_reader=lambda: current,
        )
        with self.assertRaisesRegex(ReleaseOperationsError, "installed authority"):
            factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
        self.assertEqual(factory._issued_manifests, {})
        current["policy"] += b"\n"
        with self.assertRaisesRegex(ReleaseOperationsError, "currentness"):
            factory.registry()

    def test_manifest_and_mutation_capabilities_are_factory_confined(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                payload = {
                    "operation_id": "local-release-simulator.apply",
                    "expected_generation": 0,
                    "artifact_manifest": candidate.to_dict(),
                    "artifact_bytes_base64": base64.b64encode(candidate_bytes).decode(),
                }
                gate = session.target._durable_execution_gate
                self.assertFalse(hasattr(gate, "_arm"))
                self.assertFalse(hasattr(gate, "_issuer"))
                before = session.tree_digest()
                with self.assertRaisesRegex(ReleaseSimulatorError, "coordinator capability"):
                    session.target.invoke(
                        payload=payload, fencing_token=1, started_was_durable=True,
                    )
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 0)
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "fixture artifact identity",
                ):
                    factory.issue_artifact_manifest(
                        fixture_id="release-foundation-v1",
                        artifact_id="caller-controlled",
                    )
                clone = ReleaseArtifactManifest.from_dict(copy.deepcopy(baseline.to_dict()))
                with self.assertRaisesRegex(ReleaseOperationsError, "artifact authority"):
                    factory.issue_simulator(
                        action_coordinator=fixture.raw_coordinator,
                        task_id="task-wp05",
                        fixture_id="release-foundation-v1",
                        target_id="target-project-foreign",
                        resource_id="target:project",
                        baseline_manifest=clone,
                        authorized_artifacts=(clone,),
                    )

    def test_root_replacement_after_fault_hook_fails_before_write(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            holder: dict[str, object] = {}

            def fault(step: str) -> None:
                if step != "before-stage-write":
                    return
                session = holder["session"]
                root = session._root._root_path  # type: ignore[attr-defined]
                moved = root.with_name(root.name + ".moved")
                os.replace(root, moved)
                os.symlink(moved, root)
                holder["root"] = root
                holder["moved"] = moved

            session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture, fault_hook=fault,
            )
            holder["session"] = session
            try:
                with self.assertRaisesRegex(ReleaseSimulatorError, "root identity"):
                    self.execute_apply(
                        fixture, session, baseline, candidate, candidate_bytes,
                    )
                self.assertEqual(session.target.apply_count, 0)
            finally:
                root = holder.get("root")
                moved = holder.get("moved")
                if root is not None and moved is not None:
                    os.unlink(root)  # type: ignore[arg-type]
                    os.replace(moved, root)  # type: ignore[arg-type]
                session.close()

    def test_all_fault_cuts_preserve_queryable_atomic_states(self) -> None:
        expectations = {
            "before-stage-write": (0, "baseline", None, 0),
            "after-stage-durable": (0, "baseline", "candidate", 0),
            "before-active-switch": (0, "baseline", "candidate", 0),
            "after-active-switch-durable": (1, "candidate", "candidate", 1),
            "before-health-observe": (1, "candidate", "candidate", 1),
        }
        for fault_point, expected in expectations.items():
            with self.subTest(fault_point=fault_point), action_stack() as fixture:
                factory = ReleaseOperationsRegistryFactory.from_installation()

                def fault(step: str, *, selected=fault_point) -> None:
                    if step == selected:
                        raise TimeoutError("configured cut")

                session, baseline, _baseline_bytes, candidate, candidate_bytes = self.session(
                    factory, fixture, fault_hook=fault,
                )
                with session:
                    _prepared, outcome = self.execute_apply(
                        fixture, session, baseline, candidate, candidate_bytes,
                    )
                    self.assertEqual(outcome.route, "manual-reconciliation")
                    state = session.observer.observe()["state"]
                    generation, active, staged, mutations = expected
                    self.assertEqual(state["generation"], generation)
                    self.assertEqual(
                        state["active_artifact_digest"],
                        baseline.manifest_digest if active == "baseline" else candidate.manifest_digest,
                    )
                    self.assertEqual(
                        state["staged_artifact_digest"],
                        None if staged is None else candidate.manifest_digest,
                    )
                    self.assertEqual(session.target.apply_count, mutations)
                    if fault_point in {"after-stage-durable", "before-active-switch"}:
                        reconciled = fixture.coordinator.reconcile_unknown(
                            "action-wp05",
                            lease=fixture.action_lease,
                            observer=session.observer,
                        )
                        self.assertEqual(reconciled.route, "manual-reconciliation")
                        self.assertEqual(len(fixture.leases.unresolved_claims()), 1)

    def test_exact_original_receipt_restores_exact_baseline(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                _prepared, outcome = self.execute_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                forged = object.__new__(type(outcome))
                for field in (
                    "action_id", "state", "route", "claim_id", "receipt_digest",
                ):
                    object.__setattr__(forged, field, getattr(outcome, field))
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "coordinator-issued/current",
                ):
                    factory.issue_deployment_observation(
                        action_coordinator=fixture.raw_coordinator,
                        session=session,
                        outcome=forged,
                    )
                factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                restore_document = release_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=outcome.claim_id,
                    original_receipt_digest=str(outcome.receipt_digest),
                )
                prepared = fixture.coordinator.prepare(restore_document)
                fixture.coordinator.authorize(authority_document(
                    prepared, context=fixture.context,
                ))
                restored = fixture.coordinator.execute(
                    prepared.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=fixture.action_lease,
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, prepared),
                )
                self.assertEqual(restored.route, "reconciled-effect-verified")
                state = session.observer.observe()["state"]
                self.assertEqual(state["generation"], 2)
                self.assertEqual(state["active_artifact_digest"], baseline.manifest_digest)

    def test_wrong_restore_receipt_fails_before_restore_mutation(self) -> None:
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            session, baseline, baseline_bytes, candidate, candidate_bytes = self.session(
                factory, fixture,
            )
            with session:
                _prepared, outcome = self.execute_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                restore_document = release_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=outcome.claim_id,
                    original_receipt_digest="sha256-jcs-v1:" + "f" * 64,
                )
                prepared = fixture.coordinator.prepare(restore_document)
                fixture.coordinator.authorize(authority_document(
                    prepared, context=fixture.context,
                ))
                before = session.tree_digest()
                with self.assertRaisesRegex(ReleaseSimulatorError, "original receipt"):
                    fixture.coordinator.execute(
                        prepared.action_id,
                        owner_id="owner-wp05",
                        runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05",
                        lease=fixture.action_lease,
                        target=session.target,
                        observer=session.observer,
                        disclosure_plan=release_disclosure_plan(fixture, prepared),
                    )
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 1)


class WP08ReleaseRecoveryBindingTests(unittest.TestCase):
    """RS-1 data validation never grants retained-root or action authority."""

    @staticmethod
    def document() -> dict[str, object]:
        identity = {
            "kind": "posix-directory-v1", "device": 1, "inode": 2, "owner": 501,
            "birth_seconds": 1_700_000_000, "birth_nanoseconds": 123,
        }
        body = {
            "schema_version": "1.0.0",
            "binding_kind": "retained-local-release-root",
            "task_id": "task-wp05", "fixture_id": "release-foundation-v1",
            "target_id": "target-project", "resource_id": "target:project",
            "repository_scope_digest": "sha256-jcs-v1:" + "a" * 64,
            "namespace_identity": identity,
            "root_identity": {**identity, "inode": 3},
            "root_nonce": "b" * 64,
            "installation_pins": {
                "bootstrap_id": "release-operations-bootstrap-v1",
                **{name: "sha256-jcs-v1:" + "c" * 64 for name in (
                    "bootstrap_digest", "policy_registry_digest",
                    "fixture_registry_digest", "profile_schema_registry_digest",
                    "protected_closure_digest",
                )},
            },
        }
        body["binding_digest"] = _semantic(body, "release-recovery-binding")
        return body

    @staticmethod
    def parse(body):  # type: ignore[no-untyped-def]
        from graph_engineering.core.release_operations import ReleaseRecoveryBinding
        from tests.support.wp05a_security import security_context

        return ReleaseRecoveryBinding.from_bytes(body, context=security_context())

    def test_binding_round_trip_is_immutable_data_not_authority(self) -> None:
        body = self.document()
        binding = self.parse(json.dumps(body).encode())
        self.assertEqual(binding.to_dict(), body)
        body["task_id"] = "foreign"
        self.assertEqual(binding.to_dict()["task_id"], "task-wp05")
        self.assertFalse(hasattr(binding, "execute"))
        self.assertFalse(hasattr(binding, "open"))

    def test_closed_fields_and_digest_reject_substitution(self) -> None:
        for field in self.document():
            with self.subTest(field=field):
                body = self.document()
                del body[field]
                with self.assertRaises(ReleaseOperationsError):
                    self.parse(json.dumps(body).encode())
        for field, value in (
            ("unexpected", "extra"), ("schema_version", "2.0.0"),
            ("binding_kind", "disposable"), ("root_nonce", "d" * 64),
            ("task_id", "foreign"), ("binding_digest", "sha256-jcs-v1:" + "0" * 64),
        ):
            with self.subTest(field=field):
                body = self.document()
                body[field] = value
                with self.assertRaises(ReleaseOperationsError):
                    self.parse(json.dumps(body).encode())

    def test_identity_numbers_and_json_are_strict(self) -> None:
        for value in (True, 1.0, -1, 9_007_199_254_740_992):
            with self.subTest(value=value):
                body = self.document()
                body["root_identity"]["inode"] = value
                with self.assertRaises(ReleaseOperationsError):
                    self.parse(json.dumps(body).encode())
        raw = json.dumps(self.document()).encode()
        for malformed in (b'{"task_id":"duplicate",' + raw[1:], b"\xef\xbb\xbf" + raw):
            with self.assertRaises(ReleaseOperationsError):
                self.parse(malformed)

    def test_resigned_invalid_nested_contracts_still_reject(self) -> None:
        for path, value in (
            (("task_id",), " task-wp05"), (("target_id",), "x" * 256),
            (("root_nonce",), "B" * 64), (("root_identity", "unexpected"), 1),
            (("root_identity", "birth_nanoseconds"), 1_000_000_000),
            (("installation_pins", "bootstrap_digest"), "not-a-digest"),
        ):
            with self.subTest(path=path):
                body = self.document()
                target = body if len(path) == 1 else body[path[0]]
                target[path[-1]] = value
                del body["binding_digest"]
                body["binding_digest"] = _semantic(body, "release-recovery-binding")
                with self.assertRaises(ReleaseOperationsError):
                    self.parse(json.dumps(body).encode())

    def test_target_v2_binds_full_identity_and_is_not_legacy_digest(self) -> None:
        from graph_engineering.core.contracts.digest import semantic_digest

        body = self.document()
        binding = self.parse(json.dumps(body).encode())
        legacy = semantic_digest(
            {k: body[k] for k in ("fixture_id", "resource_id", "target_id")},
            contract_type="urn:gew:contract:local-release-target",
            projection_id="urn:gew:digest-projection:local-release-target:1.0.0",
            schema_id="urn:gew:schema:local-release-target:1.0.0",
        )
        self.assertNotEqual(binding.target_digest(), legacy)
        body["root_identity"]["inode"] += 1
        del body["binding_digest"]
        body["binding_digest"] = _semantic(body, "release-recovery-binding")
        self.assertNotEqual(
            binding.target_digest(), self.parse(json.dumps(body).encode()).target_digest(),
        )

    def test_parse_requires_real_context_and_enforces_its_resource_bound(self) -> None:
        from dataclasses import replace
        from graph_engineering.core.contracts.resources import WorkContext
        from graph_engineering.core.release_operations import ReleaseRecoveryBinding
        from tests.support.wp05a_security import security_context

        base = security_context()
        profile = replace(base.profile, limits={**base.profile.limits, "raw_document_bytes": 64})
        raw = json.dumps(self.document()).encode()
        with self.assertRaisesRegex(ReleaseOperationsError, "resource bound"):
            ReleaseRecoveryBinding.from_bytes(raw, context=WorkContext(profile, base.schedule))
        with self.assertRaises(ReleaseOperationsError):
            ReleaseRecoveryBinding.from_bytes(raw, context=object())
        with self.assertRaises(TypeError):
            ReleaseRecoveryBinding()

    def test_schema_pair_has_exact_closed_projection(self) -> None:
        from graph_engineering.core.contracts.schema import validate_instance

        schemas = ROOT / "config" / "contracts" / "schemas"
        full = json.loads((schemas / "release-recovery-binding-1.0.0.json").read_bytes())
        inputs = json.loads((schemas / "release-recovery-binding-input-1.0.0.json").read_bytes())
        self.assertEqual(set(full["required"]), set(self.document()))
        self.assertEqual(set(inputs["required"]), set(self.document()) - {"binding_digest"})
        self.assertIs(full["additionalProperties"], False)
        self.assertIs(inputs["additionalProperties"], False)
        self.assertEqual(set(full["properties"]), set(full["required"]))
        self.assertEqual(set(inputs["properties"]), set(inputs["required"]))
        body = self.document()
        self.assertEqual(validate_instance(full, body, source_id=full["$id"]), [])
        del body["binding_digest"]
        self.assertEqual(validate_instance(inputs, body, source_id=inputs["$id"]), [])


if __name__ == "__main__":
    unittest.main()
