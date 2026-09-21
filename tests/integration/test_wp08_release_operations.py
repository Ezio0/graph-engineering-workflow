from __future__ import annotations

import pathlib
import unittest
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from unittest import mock

from graph_engineering.application.release_operations import (
    ReleaseOperationsRegistryFactory,
    _semantic,
)
from graph_engineering.core.release_operations import ReleaseOperationsError
from tests.support import wp08_category_execution as category_fixture
from tests.support.wp05_actions import action_stack, authority_document
from tests.support.wp08_release_operations import (
    artifact_bytes,
    release_disclosure_plan,
    release_partial_restore_prepared_document,
    release_prepared_document,
    retarget_security_binding,
)


ROOT = pathlib.Path(__file__).resolve().parents[2]


class WP08ColdInstallationControlTests(unittest.TestCase):
    def test_retained_control_exceptions_do_not_keep_released_payloads(self):
        import dataclasses
        import json
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.migration import ActiveRepositoryManifest
        from graph_engineering.storage import migration
        from graph_engineering.storage.repository import _RecoveryReadBudget

        def contains_marker(value, marker, seen):
            if id(value) in seen: return False
            seen.add(id(value))
            if isinstance(value, (str, bytes)):
                return marker in value if isinstance(value, str) else marker.encode() in value
            if type(value) is dict:
                return any(contains_marker(item, marker, seen) for item in value.values())
            if type(value) in (tuple, list):
                return any(contains_marker(item, marker, seen) for item in value)
            if type(value) is ActiveRepositoryManifest:
                return any(contains_marker(getattr(value, field.name), marker, seen)
                    for field in dataclasses.fields(value))
            return False

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            manager = scope._manager
            names = (manager._policy.active_manifest_filename,
                     manager._policy.repository_locator_registry_filename)
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            errors = []
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    for name in names:
                        with self.subTest(member=name):
                            path = manager._control / name
                            original = path.read_bytes()
                            marker = "retained-control-payload-" + "x" * 1024
                            document = json.loads(original)
                            if name == names[0]: document["installation_id"] = marker
                            else: document["unexpected"] = marker
                            try:
                                path.write_bytes(canonical_bytes(document))
                                # Keep the original error and all tracebacks; assertRaises
                                # deliberately clears them and would miss this lifetime.
                                try: scope.require_current()
                                except migration.MigrationRepositoryError as error: errors.append(error)
                                else: self.fail("invalid control data was admitted")
                                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                                pending, seen, checked = [errors[-1]], set(), 0
                                while pending:
                                    error = pending.pop()
                                    if error is None or id(error) in seen: continue
                                    seen.add(id(error))
                                    tb = error.__traceback__
                                    while tb is not None:
                                        frame = tb.tb_frame
                                        if frame.f_code.co_filename == migration.__file__:
                                            checked += 1
                                            self.assertFalse(any(contains_marker(value, marker, set())
                                                for value in frame.f_locals.values()), frame.f_code.co_name)
                                        tb = tb.tb_next
                                    pending.extend((error.__cause__, error.__context__))
                                self.assertGreater(checked, 1)
                            finally:
                                path.write_bytes(original)
                    scope.require_current()
            finally:
                owner.close()
            self.assertEqual(len(errors), 2)
            self.assertEqual(context._temporary_units, 0)

    def test_control_close_failure_still_closes_the_directory_descriptor(self):
        import os
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            manager = scope._manager
            names = (manager._policy.active_manifest_filename,
                     manager._policy.repository_locator_registry_filename)
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            open_descriptor, close_descriptor = os.open, os.close
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    for failed_name in names:
                        opened, closed, injected = {}, [], []
                        def observed_open(path, *args, **kwargs):
                            fd = open_descriptor(path, *args, **kwargs)
                            if path == manager._control or (path in names and kwargs.get("dir_fd") is not None):
                                opened[fd] = path
                            return fd
                        def observed_close(fd):
                            if fd in opened: closed.append(fd)
                            close_descriptor(fd)
                            if opened.get(fd) == failed_name and not injected:
                                injected.append(fd)
                                raise OSError("injected control close failure")
                        with self.subTest(member=failed_name), \
                                mock.patch.object(os, "open", side_effect=observed_open), \
                                mock.patch.object(os, "close", side_effect=observed_close):
                            try: scope.require_current()
                            except (OSError, MigrationRepositoryError) as error:
                                pending, seen, injected_cause = [error], set(), False
                                while pending:
                                    current = pending.pop()
                                    if current is None or id(current) in seen: continue
                                    seen.add(id(current))
                                    injected_cause |= (type(current) is OSError
                                        and str(current) == "injected control close failure")
                                    pending.extend((current.__cause__, current.__context__))
                                self.assertTrue(injected_cause)
                            else: self.fail("control close failure was suppressed")
                        self.assertEqual(len(injected), 1)
                        self.assertEqual(len(opened), 4)
                        self.assertCountEqual(closed, opened)
                        for fd in opened:
                            with self.assertRaises(OSError): os.fstat(fd)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    scope.require_current()
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)

    def test_control_parser_accounts_for_live_long_string_copies(self):
        import json
        import sys
        from graph_engineering.core.contracts import strict_json
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            path = scope._manager._control / scope._manager._policy.active_manifest_filename
            original = path.read_bytes()
            document = json.loads(original); document["installation_id"] = "x" * 8192
            body = canonical_bytes(document)
            original_tokens, emit = strict_json._tokens, context.emit
            active, peaks = [], []
            def observed_tokens(text):
                tokens = original_tokens(text); active.append(tokens)
                try:
                    yield from tokens
                finally:
                    active.remove(tokens)
            def observed_emit(event, count, **kwargs):
                if event == "parse.string_scalar":
                    values, seen = [], set()
                    frame = sys._getframe(1)
                    while frame is not None:
                        if frame.f_code.co_filename == strict_json.__file__:
                            values.extend(frame.f_locals.get(key) for key in
                                ("body", "raw_body", "text", "token_text", "decoded"))
                        frame = frame.f_back
                    for tokens in active:
                        if tokens.gi_frame is not None:
                            values.extend(tokens.gi_frame.f_locals.get(key) for key in ("text", "raw", "decoded"))
                    payload = 0
                    for value in values:
                        if id(value) in seen: continue
                        seen.add(id(value))
                        if type(value) is bytes: payload += len(value)
                        elif type(value) is str: payload += len(value.encode("utf-8"))
                    peaks.append(payload)
                    self.assertGreaterEqual(owner.retained_bytes, payload,
                        "control raw/text/token/decoded payload exceeds its retained charge")
                return emit(event, count, **kwargs)
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            try:
                path.write_bytes(body)
                with owner.bind(ports=(fixture.repository, fixture.objects)), \
                        mock.patch.object(strict_json, "_tokens", side_effect=observed_tokens), \
                        mock.patch.object(context, "emit", side_effect=observed_emit):
                    with self.assertRaises(MigrationRepositoryError): scope.require_current()
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                self.assertGreater(max(peaks), 4 * len(body))
            finally:
                path.write_bytes(original); owner.close()

    def test_control_root_permissions_are_checked_on_opened_descriptor(self):
        import os
        from graph_engineering.storage import migration
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            manager = scope._manager
            original_check, read = migration._require_bounded_directory, os.read
            checks, target_reads = [], []
            inode = (manager._control / manager._policy.repository_locator_registry_filename).stat().st_ino
            def changed_after_check(path, *, mode):
                original_check(path, mode=mode)
                if path == manager._control:
                    checks.append(path)
                    if len(checks) == 2: path.chmod(0o755)
            def observed_read(fd, count):
                if os.fstat(fd).st_ino == inode: target_reads.append(count)
                return read(fd, count)
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)), \
                        mock.patch.object(migration, "_require_bounded_directory", side_effect=changed_after_check), \
                        mock.patch.object(os, "read", side_effect=observed_read):
                    with self.assertRaisesRegex(migration.MigrationRepositoryError, "root"):
                        scope.require_current()
                    self.assertEqual(target_reads, [])
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                manager._control.chmod(manager._policy.root_mode); owner.close()
            scope.require_current()

    def test_control_semantics_and_nested_admission_remain_current_and_read_only(self):
        import copy
        import json
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.migration import ActiveRepositoryManifest
        from graph_engineering.storage.codec import semantic_record_digest
        from graph_engineering.storage.migration import MigrationRepositoryError, _manifest_body
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            manager = scope._manager
            manifest_path = manager._control / manager._policy.active_manifest_filename
            locator_path = manager._control / manager._policy.repository_locator_registry_filename
            originals = {path: path.read_bytes() for path in (manifest_path, locator_path)}
            manifest, registry = (json.loads(originals[path]) for path in (manifest_path, locator_path))
            rows_before = WP08RetainedReleaseSessionTests._repository_rows(fixture)
            cases = []
            changed = copy.deepcopy(manifest); changed["manifest_digest"] = "sha256-jcs-v1:" + "0" * 64
            cases.append((manifest_path, changed, "manifest digest mismatch"))
            for field, value in (("mode", "blocked"), ("installation_id", "different-installation")):
                changed = {key: value for key, value in manifest.items() if key != "manifest_digest"}
                changed[field] = value
                changed["fencing_high_water"] = tuple(tuple(item) for item in changed["fencing_high_water"])
                cases.append((manifest_path, _manifest_body(ActiveRepositoryManifest.create(**changed)),
                              "command context is stale"))
            for fault, expected in (("digest", "locator digest mismatch"), ("duplicate-ref", "not canonical"),
                    ("duplicate-repository", "repository identity is duplicated"),
                    ("order", "not canonical"), ("root", "locator binding mismatch"),
                    ("schema", "registry is not exact")):
                changed = copy.deepcopy(registry)
                entry = changed["repositories"][0]
                if fault == "digest": entry["locator_digest"] = "sha256-jcs-v1:" + "0" * 64
                elif fault == "schema": changed["extra"] = True
                elif fault == "duplicate-ref": changed["repositories"].append(copy.deepcopy(entry))
                elif fault == "root":
                    entry["root"] += "/foreign"
                    entry["locator_digest"] = semantic_record_digest({k: v for k, v in entry.items() if k != "locator_digest"})
                else:
                    extra = copy.deepcopy(entry)
                    extra["locator_ref"] = "repository-locator:" + "0" * 64
                    if fault == "order": extra["repository_id"] = "unselected-repository"
                    extra["locator_digest"] = semantic_record_digest({k: v for k, v in extra.items() if k != "locator_digest"})
                    changed["repositories"].append(extra)
                    changed["repositories"].sort(key=lambda row: row["locator_ref"], reverse=fault == "order")
                cases.append((locator_path, changed, expected))
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)), \
                        mock.patch.object(manager, "_publish_manifest", side_effect=AssertionError("control write")), \
                        mock.patch.object(manager, "_register_locator", side_effect=AssertionError("locator write")):
                    for path, changed, expected in cases:
                        with self.subTest(member=path.name, rejection=expected):
                            scope.require_current()
                            path.write_bytes(canonical_bytes(changed))
                            try:
                                with self.assertRaisesRegex(MigrationRepositoryError, expected):
                                    with fixture.repository._factory.open("doctor"):
                                        self.fail("changed control admitted a nested connection")
                                self.assertFalse(scope._connections)
                                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                            finally:
                                path.write_bytes(originals[path])
                    # A sorted, fully valid unselected locator is not a duplicate.
                    valid = copy.deepcopy(registry)
                    extra = copy.deepcopy(valid["repositories"][0])
                    extra.update(locator_ref="repository-locator:" + "0" * 64,
                                 repository_id="unselected-repository")
                    extra["locator_digest"] = semantic_record_digest({k: v for k, v in extra.items() if k != "locator_digest"})
                    valid["repositories"].append(extra)
                    valid["repositories"].sort(key=lambda row: row["locator_ref"])
                    try:
                        locator_path.write_bytes(canonical_bytes(valid))
                        scope.require_current()
                    finally:
                        locator_path.write_bytes(originals[locator_path])
            finally:
                owner.close()
            self.assertEqual(WP08RetainedReleaseSessionTests._repository_rows(fixture), rows_before)
            self.assertEqual({path: path.read_bytes() for path in originals}, originals)
            self.assertEqual(context._temporary_units, 0)

    def test_control_permissions_and_locator_root_identity_are_preserved(self):
        import os
        from types import SimpleNamespace
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            manager = scope._manager
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            lstat, fstat = pathlib.Path.lstat, os.fstat
            def substituted(metadata, **changes):
                values = {key: getattr(metadata, key) for key in (
                    "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")}
                return SimpleNamespace(**{**values, **changes})
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    for name in (manager._policy.active_manifest_filename, manager._policy.repository_locator_registry_filename):
                        path = manager._control / name
                        for fault in ("mode", "symlink", "owner"):
                            with self.subTest(member=name, fault=fault):
                                saved, inode = path.with_name(name + ".test-original"), path.stat().st_ino
                                if fault == "mode": path.chmod(0o644)
                                elif fault == "symlink": path.rename(saved); path.symlink_to(saved.name)
                                def observed_fstat(fd):
                                    metadata = fstat(fd)
                                    return substituted(metadata, st_uid=metadata.st_uid + 1) if (
                                        fault == "owner" and metadata.st_ino == inode) else metadata
                                try:
                                    with mock.patch.object(os, "fstat", side_effect=observed_fstat):
                                        with self.assertRaises(MigrationRepositoryError): scope.require_current()
                                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                                finally:
                                    if fault == "mode": path.chmod(manager._policy.file_mode)
                                    elif fault == "symlink": path.unlink(); saved.replace(path)
                    for field in ("st_dev", "st_ino", "st_uid"):
                        def changed_root(path, *args, **kwargs):
                            metadata = lstat(path, *args, **kwargs)
                            return substituted(metadata, **{field: getattr(metadata, field) + 1}) if (
                                path == scope.repository_root) else metadata
                        with self.subTest(root_field=field), mock.patch.object(pathlib.Path, "lstat", new=changed_root):
                            with self.assertRaisesRegex(MigrationRepositoryError, "locator root identity changed"):
                                scope.require_current()
                    scope.require_current()
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)

    def test_locator_array_overflow_precedes_locator_construction(self):
        import json
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import migration
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            path = scope._manager._control / scope._manager._policy.repository_locator_registry_filename
            original, profile = path.read_bytes(), context.profile
            context.profile = replace(profile, limits={**profile.limits, "array_items": 1})
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    scope.require_current()
                    value = json.loads(original); value["repositories"] *= 2
                    path.write_bytes(canonical_bytes(value))
                    with mock.patch.object(migration._RepositoryLocator, "load",
                            side_effect=AssertionError("overflow constructed a locator")) as loader:
                        with self.assertRaises(ContractError) as rejected:
                            scope.require_current()
                        self.assertEqual(rejected.exception.detail.rule_id, "limit/array_items")
                        loader.assert_not_called()
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                path.write_bytes(original); owner.close(); context.profile = profile
            scope.require_current()
            self.assertEqual(context._temporary_units, 0)

    def test_control_reads_reject_short_growth_replacement_and_false_metadata(self):
        import os
        from types import SimpleNamespace
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope = fixture.repository.command_scope
            manager, context = scope._manager, fixture.context
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            read, stat = os.read, os.stat
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    for name in (manager._policy.active_manifest_filename,
                                 manager._policy.repository_locator_registry_filename):
                        path = manager._control / name
                        original = path.read_bytes()
                        for fault, expected in (("short", "short read"), ("growth", "grew"),
                                ("replacement", "changed during"), ("false-size", "descriptor/path")):
                            with self.subTest(member=name, fault=fault):
                                inode, reads, descriptors = path.stat().st_ino, [], set()
                                saved = path.with_name(path.name + ".test-original")
                                def observed_read(fd, size):
                                    if os.fstat(fd).st_ino != inode:
                                        return read(fd, size)
                                    reads.append(size); descriptors.add(fd)
                                    if fault == "short": return read(fd, size - 1)
                                    result = read(fd, size)
                                    if len(reads) == 1:
                                        if fault == "growth":
                                            with path.open("ab") as stream: stream.write(b"x")
                                        elif fault == "replacement":
                                            path.rename(saved); path.write_bytes(original)
                                    return result
                                def observed_stat(selected, *args, **kwargs):
                                    result = stat(selected, *args, **kwargs)
                                    if fault == "false-size" and selected == name and kwargs.get("dir_fd") is not None:
                                        values = {key: getattr(result, key) for key in (
                                            "st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size",
                                            "st_mtime_ns", "st_ctime_ns")}
                                        values["st_size"] = 1
                                        return SimpleNamespace(**values)
                                    return result
                                try:
                                    with mock.patch.object(os, "read", side_effect=observed_read), \
                                            mock.patch.object(os, "stat", side_effect=observed_stat):
                                        with self.assertRaisesRegex(MigrationRepositoryError, expected):
                                            scope.require_current()
                                    self.assertEqual(reads, [] if fault == "false-size" else
                                        [len(original)] if fault == "short" else [len(original), 1])
                                    for fd in descriptors:
                                        with self.assertRaises(OSError): os.fstat(fd)
                                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                                finally:
                                    if saved.exists(): saved.replace(path)
                                    else: path.write_bytes(original)
                    scope.require_current()
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)

    def test_control_frames_share_exact_remaining_allowance_and_keep_first_projection(self):
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import migration
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with action_stack() as fixture:
            scope, context, other = fixture.repository.command_scope, fixture.context, security_context()
            context.acquire_temporary(2, source_id="prior", operation_path=())
            other.acquire_temporary(3, source_id="prior", operation_path=())
            owner = _RecoveryReadBudget((context, other), task_id="task-wp05", command_scope=scope)
            projection = object()
            manager = scope._manager
            size = sum((manager._control / name).stat().st_size for name in
                (manager._policy.active_manifest_filename, manager._policy.repository_locator_registry_filename))
            load = migration._RepositoryLocator.load
            def observe_overlap(value):
                self.assertIn(id(projection), owner._projections)
                self.assertGreaterEqual(owner.retained_units, 11 + 8 * size + 2)
                self.assertGreaterEqual(owner.retained_bytes, 17 + 4 * size + 2)
                return load(value)
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    with owner.reserve(other, units=11, byte_count=17, source_id="first-closure") as reservation:
                        reservation.transfer(projection)
                    with mock.patch.object(migration._RepositoryLocator, "load", side_effect=observe_overlap):
                        scope.require_current()
                    needed_units, needed_bytes = owner.peak_units - 11, owner.peak_bytes - 17
                    for field, needed in (("units", needed_units), ("bytes", needed_bytes)):
                        for shortage in (0, 1):
                            with self.subTest(field=field, shortage=shortage):
                                held = ((owner.unit_limit - 11) if field == "units" else
                                        (owner.byte_limit - 17)) - needed + shortage
                                with owner.reserve(other, units=held if field == "units" else 0,
                                        byte_count=held if field == "bytes" else 0, source_id="outer-retained"):
                                    if shortage:
                                        with self.assertRaises(ContractError) as rejected:
                                            scope.require_current()
                                        self.assertEqual(rejected.exception.detail.code, "E_LIMIT")
                                    else:
                                        scope.require_current()
                                self.assertEqual((owner.retained_units, owner.retained_bytes), (11, 17))
                    owner.release_projection(projection)
            finally:
                owner.close()
            self.assertEqual((context._temporary_units, other._temporary_units), (2, 3))
            context.release_temporary(2); other.release_temporary(3)

    def test_control_owner_is_exact_nested_and_exception_safe(self):
        import copy
        import contextvars
        import os
        import threading
        from graph_engineering.storage.migration import MigrationRepositoryError
        from graph_engineering.storage.repository import _RecoveryReadBudget, _RECOVERY_INSTALLATION_CONTEXT
        from tests.support.wp05a_security import security_context

        with action_stack() as fixture:
            scope, context = fixture.repository.command_scope, fixture.context
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    self.assertIs(_RECOVERY_INSTALLATION_CONTEXT.get(), context)
                    for foreign in (None, security_context()):
                        token = _RECOVERY_INSTALLATION_CONTEXT.set(foreign)
                        try:
                            with self.assertRaisesRegex(MigrationRepositoryError, "context is (missing|foreign)"):
                                scope.require_current()
                        finally:
                            _RECOVERY_INSTALLATION_CONTEXT.reset(token)
                    for name, foreign in (("task_id", "different-task"), ("command_scope", copy.copy(scope))):
                        original = getattr(owner, name); setattr(owner, name, foreign)
                        try:
                            with self.assertRaisesRegex(ValueError, "task or command scope changed"):
                                scope.require_current()
                        finally:
                            setattr(owner, name, original)
                    with mock.patch.object(fixture.repository, "_recovery_read_budget", None):
                        with self.assertRaisesRegex(ValueError, "port binding changed"):
                            scope.require_current()
                    competing = _RecoveryReadBudget((security_context(),), task_id="other", command_scope=scope)
                    try:
                        with self.assertRaisesRegex(ValueError, "overlapping"):
                            with competing.bind(): self.fail("overlapping owner admitted")
                    finally:
                        competing.close()
                    failures = []
                    copied = contextvars.copy_context()
                    def worker():
                        try: copied.run(scope.require_current)
                        except Exception as error: failures.append(error)
                    thread = threading.Thread(target=worker); thread.start(); thread.join()
                    self.assertEqual(len(failures), 1)
                    self.assertIsInstance(failures[0], MigrationRepositoryError)
                    with mock.patch.object(os, "getpid", return_value=os.getpid() + 1):
                        with self.assertRaisesRegex(MigrationRepositoryError, "closed or foreign"):
                            scope.require_current()
                    scope.require_current()
                    with fixture.repository._factory.open("doctor") as connection:
                        self.assertEqual(connection._raw.execute("PRAGMA query_only").fetchone(), (1,))
                        self.assertEqual(len(scope._connections), 1)
                    self.assertFalse(scope._connections)
                self.assertIsNone(_RECOVERY_INSTALLATION_CONTEXT.get())
                for value in (scope, scope._manager, fixture.repository, fixture.objects, context):
                    self.assertFalse(hasattr(value, "_recovery_read_budget"))
                with self.assertRaisesRegex(RuntimeError, "injected exit"):
                    with owner.bind(ports=(fixture.repository, fixture.objects)):
                        scope.require_current(); raise RuntimeError("injected exit")
                self.assertIsNone(_RECOVERY_INSTALLATION_CONTEXT.get())
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                scope.require_current()
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)

    def test_control_files_reject_oversize_before_body_read(self):
        import os
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with action_stack() as fixture:
            scope = fixture.repository.command_scope
            manager, context = scope._manager, fixture.context
            originals = {manager._control / name: (manager._control / name).read_bytes()
                for name in (manager._policy.active_manifest_filename,
                             manager._policy.repository_locator_registry_filename)}
            owner = _RecoveryReadBudget((context,), task_id="task-wp05", command_scope=scope)
            read, read_text = os.read, pathlib.Path.read_text
            try:
                with owner.bind(ports=(fixture.repository, fixture.objects)):
                    for path, body in originals.items():
                        with self.subTest(member=path.name):
                            reads = []
                            path.write_bytes(body + b" " * (context.profile.limits["raw_document_bytes"] + 1 - len(body)))
                            inode = path.stat().st_ino
                            def observed_read(descriptor, size):
                                if os.fstat(descriptor).st_ino == inode:
                                    reads.append(size)
                                return read(descriptor, size)
                            def no_unbounded_read(selected, *args, **kwargs):
                                if selected == path:
                                    raise AssertionError("unbounded installation control read")
                                return read_text(selected, *args, **kwargs)
                            try:
                                with mock.patch.object(os, "read", side_effect=observed_read), \
                                        mock.patch.object(pathlib.Path, "read_text", new=no_unbounded_read):
                                    with self.assertRaises(ContractError) as rejected:
                                        scope.require_current()
                                self.assertEqual(rejected.exception.detail.code, "E_LIMIT")
                                self.assertEqual(reads, [])
                                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                            finally:
                                path.write_bytes(body)
                scope.require_current()
                self.assertEqual({path: path.read_bytes() for path in originals}, originals)
                self.assertFalse(scope._connections)
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)


class WP08RetainedReleaseSessionTests(unittest.TestCase):


    def test_cold_entry_locator_gap_and_ineligible_roots(self):
        import errno
        import os
        import socket
        import sqlite3
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.connection import ManagedConnection
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.actions import ActionJournalRepository
        from graph_engineering.adapters.local_release_simulator import LocalReleaseTarget

        for case in ("revision", "head", "cas", "markerless-orphan", "disposable"):
            with self.subTest(case=case), ExitStack() as setup:
                issue = self._issue
                if case == "disposable":
                    setup.enter_context(mock.patch.object(self, "_issue",
                        side_effect=lambda fixture, _namespace: issue(fixture, None)))
                values = setup.enter_context(self._same_task_assessment(cold=True))
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                root = session._root._root_path
                marker = root / session._root.names["identity"]
                marker_body = marker.read_bytes()
                session.close()
                connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
                saved = connection.execute("SELECT revision,head_digest FROM tasks WHERE task_id=?",
                    (probe.task_id,)).fetchone()
                path = fixture.objects._path(receipt.assessment.object_digest)
                body = path.read_bytes()
                def rows():
                    names = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                    return tuple((name, tuple(connection.execute('SELECT * FROM "' + name.replace('"', '""') + '"')))
                        for name, in names)
                def physical():
                    return {p.name: p.read_bytes() for p in root.iterdir()} if root.exists() else None
                def objects():
                    return {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                amended_rows, amended_cas = rows(), objects()
                if case == "markerless-orphan": marker.unlink()
                before_physical = physical()
                injected = False
                read_sources = fixture.repository.read_category_recovery_sources
                def raced(task_id, *, phase):
                    nonlocal injected, amended_rows, amended_cas
                    value = read_sources(task_id, phase=phase)
                    if phase == "locator" and not injected and case in ("revision", "head", "cas"):
                        self.assertFalse(fixture.repository.command_scope._connections)
                        fixture.raw_coordinator._require_retained_idle()
                        if case == "revision":
                            connection.execute("UPDATE tasks SET revision=revision+1 WHERE task_id=?", (task_id,))
                        elif case == "head":
                            connection.execute("UPDATE tasks SET head_digest=? WHERE task_id=?",
                                ("sha256-jcs-v1:" + "0" * 64, task_id))
                        else: path.write_bytes(bytes((body[0] ^ 1,)) + body[1:])
                        injected, amended_rows, amended_cas = True, rows(), objects()
                    return value
                execute = ManagedConnection.execute
                def only_reads(current, sql, parameters=()):
                    self.assertEqual(current._role, "doctor")
                    self.assertEqual(current._raw.execute("PRAGMA query_only").fetchone(), (1,))
                    self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                    return execute(current, sql, parameters)
                try:
                    with self._cold_cleanup_probe(fixture), ExitStack() as guards:
                        prohibited = []
                        guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                        guards.enter_context(mock.patch.object(fixture.repository,
                            "read_category_recovery_sources", side_effect=raced))
                        for kind, names in ((TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                                (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                                (ActionJournalRepository, ("load", "find_prepared")), (LocalReleaseTarget, ("invoke",))):
                            for name in names:
                                prohibited.append(guards.enter_context(mock.patch.object(kind, name,
                                    side_effect=AssertionError("forbidden recovery admission call"))))
                        for port, names in ((fixture.raw_coordinator,
                                ("execute", "reconcile_unknown", "compensate_unknown", "_read_action_authority")),
                                (app._task_application, ("runtime_show", "_materialization_for_graph_ref",
                                                        "_issue_materialization_reference")),
                                (fixture.leases, ("renew",)), (socket, ("socket", "getaddrinfo"))):
                            for name in names:
                                prohibited.append(guards.enter_context(mock.patch.object(port, name,
                                    side_effect=AssertionError("forbidden recovery admission call"))))
                        with self.assertRaises((RuntimeError, ValueError, OSError)) as rejected:
                            module.restore_current_release_assessment(task_application=app._task_application,
                                runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                                object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                                retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                        if case == "disposable":
                            self.assertIsInstance(rejected.exception, FileNotFoundError)
                            self.assertEqual(rejected.exception.errno, errno.ENOENT)
                        else:
                            self._assert_cold_semantic_rejection(rejected.exception, {
                                "revision": "cold source task snapshot is stale or invalid",
                                "head": "event stream does not match committed head",
                                "cas": "provenance object digest mismatch",
                                "markerless-orphan": "retained member is unavailable"}[case])
                        for call in prohibited: call.assert_not_called()
                    if case in ("revision", "head", "cas"): self.assertTrue(injected)
                    self.assertEqual(rows(), amended_rows)
                    self.assertEqual(objects(), amended_cas)
                    self.assertEqual(physical(), before_physical)
                    self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                finally:
                    connection.execute("UPDATE tasks SET revision=?,head_digest=? WHERE task_id=?", (*saved, probe.task_id))
                    connection.close()
                    path.write_bytes(body)
                    if case == "markerless-orphan":
                        marker.write_bytes(marker_body); marker.chmod(0o400)


    def test_binding_first_fsync_failure_preserves_orphan_without_session_or_actions(self):
        import os
        import stat
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedRootLease

        with action_stack(domain_task=True) as fixture, self._runtime() as runtime, \
                tempfile.TemporaryDirectory(prefix="gew-binding-fsync-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                before = self._repository_rows(fixture)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                writing, sync = _RetainedRootLease._write_new, os.fsync
                active, cuts, descriptors, roots = False, [], [], []
                def write_binding(lease, name, body):
                    nonlocal active
                    if name != lease.BINDING_NAME: return writing(lease, name, body)
                    active = True
                    descriptors.append(lease._descriptor)
                    roots.append(pathlib.Path(lease.path))
                    try: return writing(lease, name, body)
                    finally: active = False
                def cut_sync(fd):
                    if active and stat.S_ISREG(os.fstat(fd).st_mode):
                        cuts.append(fd); descriptors.append(fd)
                        raise OSError("injected before binding first fsync")
                    return sync(fd)
                with mock.patch.object(_RetainedRootLease, "_write_new", new=write_binding), \
                        mock.patch.object(os, "fsync", new=cut_sync), ExitStack() as guards:
                    prohibited = [guards.enter_context(mock.patch.object(fixture.raw_coordinator, name,
                        side_effect=AssertionError("initialization called action"))) for name in
                        ("prepare", "execute", "reconcile_unknown", "compensate_unknown")]
                    with self.assertRaisesRegex(OSError, "injected before binding first fsync"):
                        self._issue(fixture, namespace)
                    for call in prohibited: call.assert_not_called()
                self.assertEqual(len(cuts), 1)
                self.assertEqual(len(roots), 1)
                self.assertTrue(roots[0].is_dir())
                orphan = {p.name: p.read_bytes() for p in roots[0].iterdir()}
                self.assertEqual(set(orphan), {_RetainedRootLease.BINDING_NAME})
                self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 0)
                for descriptor in descriptors:
                    with self.assertRaises(OSError): os.fstat(descriptor)
                with self.assertRaisesRegex(ValueError, "already exists"):
                    self._issue(fixture, namespace)
                self.assertEqual({p.name: p.read_bytes() for p in roots[0].iterdir()}, orphan)
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 0)


    def test_cold_entry_stable_invalid_cas_and_review_lineage(self):
        import json
        import socket
        import sqlite3
        from graph_engineering.application import release_operations as module
        from graph_engineering.core.artifacts.records import RECORD_FIELDS, ARTIFACT_RECORD_SCHEMA
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.contracts.digest import semantic_digest
        from graph_engineering.core.graph.state import SNAPSHOT_PROJECTION
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest, object_digest
        from graph_engineering.storage.connection import ManagedConnection
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.actions import ActionJournalRepository

        for case in ("prior-acceptance", "target-resource", "target-generation", "prior-run",
                     "duplicate-assessment", "epoch", "graph-ref"):
            with self.subTest(case=case), self._same_task_assessment(cold=True) as values:
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                session.close()
                connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
                saved = connection.execute("SELECT snapshot_json,snapshot_digest FROM tasks WHERE task_id=?",
                    (probe.task_id,)).fetchone()
                saved_security = connection.execute("SELECT task_snapshot_digest,state_json,state_digest FROM task_security_states WHERE task_id=?",
                    (probe.task_id,)).fetchone()
                snapshot = json.loads(saved[0])
                references = connection.execute("SELECT * FROM object_references WHERE task_id=?",
                    (probe.task_id,)).fetchall()
                documents = {}
                for reference in references:
                    try: document = json.loads(fixture.objects._path(reference[1]).read_bytes())
                    except (ValueError, UnicodeError): continue
                    if type(document) is dict: documents[reference[1]] = document
                runner = snapshot["runner"]
                final = next(review for review in reversed(runner["review_history"]) if review["verdict"] == "PASS")
                prior = next(review for review in runner["review_history"] if
                    review["node_id"] == final["node_id"] and review["run_id"] == final["run_id"]
                    and review["body_digest"] != final["body_digest"])
                old_ref = new_ref = None
                if case == "prior-acceptance":
                    matches = [(ref, record) for ref, record in documents.items() if set(record) == RECORD_FIELDS
                        and record["body_digest"] == prior["body_digest"]
                        and record["reviewer_id"] == prior["reviewer_id"]]
                    self.assertEqual(len(matches), 1)
                    old_ref, record = matches[0]
                    self.assertTrue(all(old_ref not in output["evidence_refs"] for output in runner["node_outputs"].values()))
                    record["review_records"][0]["reviewer_id"] = "foreign-reviewer"
                    record["artifact_digest"] = semantic_digest(
                        {key: value for key, value in record.items() if key != "artifact_digest"},
                        contract_type="urn:gew:contract:artifact-record",
                        projection_id="urn:gew:digest-projection:identity:1.0.0", schema_id=ARTIFACT_RECORD_SCHEMA)
                    expected = "cold runner body is absent or ambiguous"
                elif case.startswith("target-"):
                    matches = [(ref, record) for ref, record in documents.items()
                        if record.get("record_kind") == "category-target-contract-v1"
                        and record["task_id"] == probe.task_id and record["target_id"] == target.target_id]
                    self.assertEqual(len(matches), 1)
                    old_ref, record = matches[0]
                    if case == "target-resource": record["resource_id"] = "foreign-release-resource"
                    else: record["expected_state"]["generation"] += 1
                    category_fixture.resign_durable_record(record)
                    expected = "cold release current physical target differs from committed contract"
                else:
                    if case == "prior-run":
                        prior["run_id"] += ":foreign"
                        expected = "cold review lineage or attempt order changed"
                    elif case == "duplicate-assessment":
                        reference = next(item for item in snapshot["domain"]["evidence"]
                            if item["evidence_type"] == "category-completion-assessment")
                        snapshot["domain"]["evidence"].append(dict(reference))
                        expected = "cold source assessment is missing or ambiguous"
                    else:
                        if case == "epoch":
                            snapshot["domain"]["invalidation_epoch"] += 1
                            expected = "cold domain replay differs from the captured snapshot"
                        else:
                            snapshot["domain"]["graph_ref"]["profile_digest"] = "sha256-jcs-v1:" + "0" * 64
                            expected = "materialized graph ref"
                        domain = snapshot["domain"]
                        domain["snapshot_digest"] = semantic_digest(
                            {key: value for key, value in domain.items() if key != "snapshot_digest"},
                            contract_type=SNAPSHOT_PROJECTION.contract_type,
                            projection_id=SNAPSHOT_PROJECTION.projection_id, schema_id=SNAPSHOT_PROJECTION.schema_id)
                    connection.execute("UPDATE tasks SET snapshot_json=?,snapshot_digest=? WHERE task_id=?",
                        (canonical_json(snapshot), semantic_record_digest(
                            {"contract": "repository-snapshot-v1", "value": snapshot}), probe.task_id))
                    # Keep the security index current so the intended later
                    # source join, rather than this unrelated index, rejects.
                    snapshot_digest = semantic_record_digest({"contract": "repository-snapshot-v1", "value": snapshot})
                    security_state = json.loads(saved_security[1])
                    security_state["task_snapshot_digest"] = snapshot_digest
                    security_state["binding"]["snapshot_digest"] = snapshot_digest
                    from graph_engineering.core.security import SecurityBinding
                    security_state["binding"]["binding_digest"] = SecurityBinding.digest_document(security_state["binding"])
                    connection.execute("UPDATE task_security_states SET task_snapshot_digest=?,state_json=?,state_digest=? WHERE task_id=?",
                        (snapshot_digest, canonical_json(security_state), semantic_record_digest(
                            {"contract": "task-security-state-v1", "value": security_state}), probe.task_id))
                if old_ref is not None:
                    body = canonical_bytes(record); new_ref = object_digest(body)
                    fixture.objects.put_verified(body, new_ref)
                    changed = connection.execute("UPDATE object_references SET digest=? WHERE task_id=? AND digest=?",
                        (new_ref, probe.task_id, old_ref))
                    self.assertEqual(changed.rowcount, 1)
                before = self._repository_rows(fixture)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                execute = ManagedConnection.execute
                def only_reads(current, sql, parameters=()):
                    self.assertEqual(current._role, "doctor")
                    self.assertEqual(current._raw.execute("PRAGMA query_only").fetchone(), (1,))
                    self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                    return execute(current, sql, parameters)
                try:
                    with self._cold_cleanup_probe(fixture), ExitStack() as guards:
                        prohibited = []
                        guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                        for kind, names in ((TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                                (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                                (ActionJournalRepository, ("load", "find_prepared"))):
                            for name in names:
                                prohibited.append(guards.enter_context(mock.patch.object(kind, name,
                                    side_effect=AssertionError("forbidden cold source call"))))
                        for name in ("execute", "reconcile_unknown", "compensate_unknown"):
                            prohibited.append(guards.enter_context(mock.patch.object(fixture.raw_coordinator, name,
                                side_effect=AssertionError("forbidden cold action"))))
                        for name in ("socket", "getaddrinfo"):
                            prohibited.append(guards.enter_context(mock.patch.object(socket, name,
                                side_effect=AssertionError("forbidden cold network"))))
                        if case == "duplicate-assessment":
                            prohibited.append(guards.enter_context(mock.patch.object(
                                fixture.retained_namespace._record()[4], "_open_cold_marker",
                                side_effect=AssertionError("ambiguous assessment reached root admission"))))
                        with self.assertRaises((RuntimeError, ValueError)) as rejected:
                            module.restore_current_release_assessment(task_application=app._task_application,
                                runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                                object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                                retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                        self._assert_cold_semantic_rejection(rejected.exception, expected)
                        for call in prohibited: call.assert_not_called()
                    self.assertEqual(self._repository_rows(fixture), before)
                    self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                    self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                finally:
                    connection.execute("UPDATE tasks SET snapshot_json=?,snapshot_digest=? WHERE task_id=?",
                        (*saved, probe.task_id))
                    connection.execute("UPDATE task_security_states SET task_snapshot_digest=?,state_json=?,state_digest=? WHERE task_id=?",
                        (*saved_security, probe.task_id))
                    if old_ref is not None:
                        connection.execute("UPDATE object_references SET digest=? WHERE task_id=? AND digest=?",
                            (old_ref, probe.task_id, new_ref))
                    connection.close()


    def test_cold_entry_resource_faults_at_locator(self):
        self._assert_cold_entry_resource_faults("locator")

    def test_cold_entry_resource_faults_at_gated_capture(self):
        self._assert_cold_entry_resource_faults("gated")

    def test_cold_entry_resource_faults_on_reuse(self):
        self._assert_cold_entry_resource_faults("reuse")

    def _assert_cold_entry_resource_faults(self, phase):
        import os
        import socket
        import sqlite3
        from graph_engineering.application import release_operations as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.codec import object_digest
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.actions import ActionJournalRepository
        from graph_engineering.storage import repository as repository_module
        from graph_engineering.storage.connection import ManagedConnection
        from graph_engineering.storage.leases import ResourceLeaseRepository
        from graph_engineering.adapters.local_release_simulator import LocalReleaseTarget

        modes = ("oversized", "false-size", "growth", "short", "sql-text", "rows", "control", "security")
        if phase != "locator": modes += ("aggregate",)
        for mode in modes:
            with self.subTest(phase=phase, mode=mode), self._same_task_assessment(cold=True) as values:
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                session.close()
                digest = receipt.assessment.object_digest
                path = fixture.objects._path(digest)
                body = path.read_bytes()
                context = fixture.repository._action_journal._context
                ceiling = context.profile.limits["raw_document_bytes"]
                connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
                reference = connection.execute("SELECT * FROM object_references WHERE task_id=? AND digest=?",
                    (probe.task_id, digest)).fetchone()
                extras = []
                if mode == "aggregate":
                    for index in range(18):
                        raw = bytes((index,)) * 65536
                        ref = object_digest(raw)
                        fixture.objects.put_verified(raw, ref)
                        extras.append(ref)
                def rows():
                    names = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                    return tuple((name, tuple(connection.execute('SELECT * FROM "' + name.replace('"', '""') + '"')))
                                 for name, in names)
                before = rows()
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                object_sizes = dict(connection.execute("SELECT digest,size FROM objects"))
                task_refs = {row[0] for row in connection.execute(
                    "SELECT digest FROM object_references WHERE task_id=?", (probe.task_id,))} | set(extras)
                root = session._root._root_path
                physical = {p.name: p.read_bytes() for p in root.iterdir()}
                manager = fixture.repository.command_scope._manager
                control_path = manager._control / manager._policy.active_manifest_filename
                original_control = control_path.read_bytes()
                snapshot = connection.execute("SELECT snapshot_json FROM tasks WHERE task_id=?", (probe.task_id,)).fetchone()[0]
                security = connection.execute("SELECT state_json FROM task_security_states WHERE task_id=?", (probe.task_id,)).fetchone()[0]
                injected, amended_rows, reads = False, None, []
                scopes, handle = [], None
                def inject():
                    nonlocal injected, amended_rows
                    if mode in ("oversized", "false-size"):
                        path.write_bytes(b"x" * (ceiling + 1))
                        if mode == "oversized":
                            connection.execute("UPDATE objects SET size=? WHERE digest=?", (ceiling + 1, digest))
                    elif mode == "sql-text":
                        connection.execute("UPDATE tasks SET snapshot_json=? WHERE task_id=?",
                            (snapshot + " " * (ceiling + 1), probe.task_id))
                    elif mode == "rows":
                        connection.execute("BEGIN")
                        connection.executemany("INSERT INTO object_references VALUES (?,?,?,?)",
                            ((probe.task_id, digest, "fault-row-" + str(index), reference[3])
                             for index in range(context.profile.limits["array_items"] + 1)))
                        connection.execute("COMMIT")
                    elif mode == "aggregate":
                        connection.execute("BEGIN")
                        connection.executemany("INSERT INTO object_references VALUES (?,?,?,?)",
                            ((probe.task_id, ref, "task", reference[3]) for ref in extras))
                        connection.execute("COMMIT")
                    elif mode == "control": control_path.write_bytes(original_control + b" " * (ceiling + 1))
                    elif mode == "security":
                        connection.execute("UPDATE task_security_states SET state_json=? WHERE task_id=?",
                            (security + " " * (ceiling + 1), probe.task_id))
                    injected, amended_rows = True, rows()
                initialize = module._ColdReleaseReadScope.__init__
                def observed(current, *args, **kwargs):
                    initialize(current, *args, **kwargs); scopes.append(current)
                read_sources = fixture.repository.read_category_recovery_sources
                def sources(task_id, *, phase):
                    if phase == "sources" and not injected: inject()
                    return read_sources(task_id, phase=phase)
                primitive, real_read = fixture.repository._read_provenance_object, os.read
                inode = path.stat().st_ino
                watched_inodes = {inode: digest, control_path.stat().st_ino: control_path.name}
                watched_inodes.update({fixture.objects._path(ref).stat().st_ino: ref for ref in object_sizes})
                observed_metadata, read_requests = [], []
                real_stat = os.fstat
                def descriptor_stat(fd):
                    value = real_stat(fd)
                    if injected and value.st_ino in watched_inodes:
                        observed_metadata.append((watched_inodes[value.st_ino], value.st_size))
                    return value
                def counted(fd, count):
                    metadata = real_stat(fd)
                    if not injected or metadata.st_ino not in watched_inodes:
                        return real_read(fd, count)
                    selected = watched_inodes[metadata.st_ino]
                    if selected == digest and mode == "growth" and not reads:
                        with path.open("ab") as stream: stream.write(b"x")
                    requested = count - 1 if selected == digest and mode == "short" and not reads else count
                    data = real_read(fd, requested)
                    read_requests.append((selected, count, requested, len(data)))
                    if selected == digest: reads.append(len(data))
                    return data
                def read_object(selected, size, *, retained_bytes):
                    if selected != digest:
                        result = primitive(selected, size, retained_bytes=retained_bytes)
                        if injected and selected in extras:
                            extra_reads.append((selected, len(result), retained_bytes))
                        return result
                    return primitive(selected, size, retained_bytes=retained_bytes)
                limits_failed, charges_failed, extra_reads = [], [], []
                extra_charges = []
                sql_entries, active_sql = [], []
                limit_check = type(context).check_limit
                charge = repository_module._RecoveryReadBudget._charge
                real_rows, execute = repository_module._recovery_rows, ManagedConnection.execute
                def checked(current, limit_id, value, **kwargs):
                    try: return limit_check(current, limit_id, value, **kwargs)
                    except ContractError as error:
                        if injected:
                            limits_failed.append((error.detail, value, current.profile.limits[limit_id]))
                        raise
                def charged(owner, current, *, units, byte_count, source_id):
                    before_charge = (source_id, units, byte_count, owner.retained_units,
                                     owner.retained_bytes, owner.unit_limit, owner.byte_limit)
                    if injected and source_id in extras:
                        extra_charges.append((id(owner), before_charge))
                    try: return charge(owner, current, units=units, byte_count=byte_count, source_id=source_id)
                    except ContractError as error:
                        if injected: charges_failed.append((id(owner), before_charge, error.detail))
                        raise
                @contextmanager
                def observed_rows(*args, **kwargs):
                    entry = {"source": kwargs["source_id"], "headers": [], "data_rows": 0, "failed": False}
                    if injected: sql_entries.append(entry)
                    with ExitStack() as lifetime:
                        active_sql.append(entry)
                        try:
                            try: result = lifetime.enter_context(real_rows(*args, **kwargs))
                            except (RuntimeError, ValueError):
                                entry["failed"] = True
                                raise
                        finally: active_sql.pop()
                        yield result
                class ObservedCursor:
                    def __init__(self, cursor, entry): self.cursor, self.entry = cursor, entry
                    def fetchone(self):
                        row = self.cursor.fetchone()
                        if row is not None:
                            if row[0] == "bounds": self.entry["headers"].append(row[1:5])
                            else: self.entry["data_rows"] += 1
                        return row
                    def __getattr__(self, name): return getattr(self.cursor, name)
                def only_reads(current, sql, parameters=()):
                    self.assertEqual(current._role, "doctor")
                    self.assertEqual(current._raw.execute("PRAGMA query_only").fetchone(), (1,))
                    self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                    cursor = execute(current, sql, parameters)
                    return ObservedCursor(cursor, active_sql[-1]) if active_sql and "SELECT 'bounds'," in sql else cursor
                def restore():
                    return module.restore_current_release_assessment(task_application=app._task_application,
                        runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                        object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                        retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                def blocked(*args, **kwargs): raise AssertionError("forbidden call during resource rejection")
                try:
                    with self._cold_cleanup_probe(fixture), ExitStack() as guards:
                        prohibited = []
                        guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed))
                        guards.enter_context(mock.patch.object(fixture.repository, "_read_provenance_object", side_effect=read_object))
                        guards.enter_context(mock.patch.object(type(context), "check_limit", new=checked))
                        guards.enter_context(mock.patch.object(repository_module._RecoveryReadBudget, "_charge", new=charged))
                        guards.enter_context(mock.patch.object(repository_module, "_recovery_rows", new=observed_rows))
                        guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                        guards.enter_context(mock.patch.object(os, "read", new=counted))
                        guards.enter_context(mock.patch.object(os, "fstat", new=descriptor_stat))
                        for kind, names in ((TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                                (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                                (ActionJournalRepository, ("load", "find_prepared")),
                                (ResourceLeaseRepository, ("renew",)), (LocalReleaseTarget, ("invoke",))):
                            for name in names:
                                prohibited.append(guards.enter_context(mock.patch.object(kind, name, side_effect=blocked)))
                        for name in ("execute", "reconcile_unknown", "compensate_unknown", "_read_action_authority"):
                            prohibited.append(guards.enter_context(mock.patch.object(fixture.raw_coordinator, name, side_effect=blocked)))
                        for name in ("runtime_show", "_materialization_for_graph_ref", "_issue_materialization_reference"):
                            prohibited.append(guards.enter_context(mock.patch.object(app._task_application, name, side_effect=blocked)))
                        for name in ("socket", "getaddrinfo"):
                            prohibited.append(guards.enter_context(mock.patch.object(socket, name, side_effect=blocked)))
                        if phase == "reuse": handle = restore()
                        if phase == "gated":
                            guards.enter_context(mock.patch.object(fixture.repository, "read_category_recovery_sources", side_effect=sources))
                        else: inject()
                        with self.assertRaises((RuntimeError, ValueError)) as rejected:
                            if handle is None: handle = restore()
                            else: handle.query()
                        self.assertTrue(injected)
                        if mode in ("growth", "short"):
                            self._assert_cold_semantic_rejection(rejected.exception,
                                "provenance object grew" if mode == "growth" else "provenance object short read")
                            self.assertEqual(sum(reads), len(body) + 1 if mode == "growth" else len(body) - 1)
                            self.assertEqual([item[1:] for item in read_requests if item[0] == digest],
                                [(len(body), len(body), len(body)), (1, 1, 1)] if mode == "growth"
                                else [(len(body), len(body) - 1, len(body) - 1)])
                        else:
                            pending, seen, errors = [rejected.exception], set(), []
                            while pending:
                                error = pending.pop()
                                if error is None or id(error) in seen: continue
                                seen.add(id(error))
                                self.assertNotIsInstance(error, AssertionError)
                                errors.append(error)
                                if isinstance(error, ContractError):
                                    self.assertNotEqual(error.detail.code, "E_BUDGET")
                                pending.extend((error.__cause__, error.__context__))
                            source = "category-recovery-" + ("locator" if phase == "locator" else "sources")
                            if mode in ("oversized", "false-size", "control", "rows"):
                                expected_source = (digest if mode in ("oversized", "false-size")
                                                   else control_path.name if mode == "control" else source)
                                expected_rule = ("temporary_units" if mode == "oversized" else
                                                 "array_items" if mode == "rows" else "raw_document_bytes")
                                matching = [(detail, value, limit) for detail, value, limit in limits_failed
                                    if detail.source_id == expected_source and detail.code == "E_LIMIT"
                                    and detail.rule_id == "limit/" + expected_rule
                                    and any(isinstance(error, ContractError) and error.detail is detail for error in errors)]
                                self.assertTrue(matching, (mode, limits_failed))
                                self.assertTrue(all(value > limit for _detail, value, limit in matching))
                            if mode in ("sql-text", "security", "rows"):
                                expected_source = "task-security-state" if mode == "security" else source
                                failed = [entry for entry in sql_entries if entry["failed"]
                                          and entry["source"] == expected_source]
                                self.assertEqual(len(failed), 1, sql_entries)
                                self.assertEqual(failed[0]["data_rows"], 0)
                                self.assertEqual(len(failed[0]["headers"]), 1)
                                count, _bytes, _units, bad = failed[0]["headers"][0]
                                if mode == "rows": self.assertGreater(count, context.profile.limits["array_items"])
                                else:
                                    self.assertGreater(bad, 0)
                                    self.assertTrue(any(str(error) == "recovery SQL value or aggregate is over limit"
                                                        for error in errors))
                            if mode in ("oversized", "false-size"): self.assertEqual(reads, [])
                            if mode in ("false-size", "control"):
                                selected = digest if mode == "false-size" else control_path.name
                                expected_size = ceiling + 1 + (len(original_control) if mode == "control" else 0)
                                self.assertIn((selected, expected_size), observed_metadata)
                                self.assertEqual([item for item in read_requests if item[0] == selected], [])
                            if mode == "aggregate":
                                self.assertGreaterEqual(len(extra_reads), 2)
                                self.assertTrue(all(size == 65536 for _ref, size, _retained in extra_reads))
                                # CAS is sorted by raw digest. Extra admitted
                                # bodies may exhaust room immediately before an
                                # original body; either is an aggregate failure.
                                failed = [item for item in charges_failed if item[1][0] in task_refs]
                                self.assertEqual(len(failed), 1, charges_failed)
                                owner_id, failed_charge, failed_detail = failed[0]
                                self.assertEqual(owner_id, id(scopes[0].budget))
                                ref, units, byte_count, held_units, held_bytes, unit_limit, byte_limit = failed_charge
                                self.assertEqual((units, byte_count), (object_sizes[ref], object_sizes[ref]))
                                self.assertNotIn(ref, [item[0] for item in extra_reads])
                                self.assertEqual([item for item in read_requests if item[0] == ref], [])
                                self.assertEqual((failed_detail.source_id, failed_detail.code), (ref, "E_LIMIT"))
                                self.assertTrue(any(isinstance(error, ContractError) and error.detail is failed_detail
                                    for error in errors))
                                self.assertTrue(all(owner_id == id(scopes[0].budget) for owner_id, _item in extra_charges))
                                first_charge = extra_charges[0][1]
                                self.assertLessEqual(units, first_charge[5] - first_charge[3])
                                self.assertLessEqual(byte_count, first_charge[6] - first_charge[4])
                                self.assertLessEqual(units, unit_limit)
                                self.assertLessEqual(byte_count, byte_limit)
                                self.assertTrue(held_units + units > unit_limit or held_bytes + byte_count > byte_limit)
                                self.assertGreaterEqual(min(held_units, held_bytes), sum(item[1] for item in extra_reads))
                        if handle is not None:
                            with self.assertRaises(ReleaseOperationsError): handle.query()
                        for call in prohibited: call.assert_not_called()
                    self.assertEqual(rows(), amended_rows)
                    expected_body = (b"x" * (ceiling + 1) if mode in ("oversized", "false-size")
                                     else body + b"x" if mode == "growth" else body)
                    self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()},
                        {**cas, path: expected_body})
                    self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, physical)
                    self.assertEqual(control_path.read_bytes(), original_control + b" " * (ceiling + 1) if mode == "control" else original_control)
                finally:
                    if handle is not None and scopes and not scopes[0].closed: handle.close()
                    path.write_bytes(body)
                    control_path.write_bytes(original_control)
                    connection.execute("UPDATE objects SET size=? WHERE digest=?", (len(body), digest))
                    connection.execute("UPDATE tasks SET snapshot_json=? WHERE task_id=?", (snapshot, probe.task_id))
                    connection.execute("UPDATE task_security_states SET state_json=? WHERE task_id=?", (security, probe.task_id))
                    connection.execute("DELETE FROM object_references WHERE task_id=? AND ref_kind LIKE 'fault-row-%'", (probe.task_id,))
                    for ref in extras:
                        connection.execute("DELETE FROM object_references WHERE task_id=? AND digest=?", (probe.task_id, ref))
                    self.assertEqual(rows(), before)
                    connection.close()


    def test_cold_handle_foreign_thread_cannot_revoke_owner_and_new_handle_has_new_epoch(self):
        import threading
        from graph_engineering.application import release_operations as module

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            before = self._repository_rows(fixture)
            cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            def restore():
                return module.restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy,
                    release_factory=ReleaseOperationsRegistryFactory.from_installation(),
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
            with self._cold_cleanup_probe(fixture):
                first = restore(); owner = first._record()[1]
                try:
                    errors = []
                    def foreign():
                        for operation in (first.query, first.close):
                            try: operation()
                            except BaseException as error: errors.append(error)
                    thread = threading.Thread(target=foreign)
                    thread.start(); thread.join(timeout=5)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(len(errors), 2)
                    self.assertTrue(all(isinstance(error, ReleaseOperationsError) for error in errors))
                    self.assertFalse(owner.closed)
                    one = first.query()
                finally: first.close()
                second = restore()
                try:
                    two = second.query()
                    self.assertNotEqual(one["observation_epoch"], two["observation_epoch"])
                    self.assertEqual(one["observation_revision"], two["observation_revision"])
                    self.assertEqual(one["assessment_bytes"], two["assessment_bytes"])
                finally: second.close()
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
            self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)

    def test_cold_handle_runtime_context_revocation_releases_its_owned_resources(self):
        from graph_engineering.application import release_operations as module
        from graph_engineering.application import tasks as task_module

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            handle = module.restore_current_release_assessment(task_application=app._task_application,
                runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
            scope = handle._record()[1]
            before = self._repository_rows(fixture)
            cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            issued = task_module._ISSUED_RUNTIME_CONTEXTS.pop(id(app._runtime))
            try:
                with self._cold_cleanup_probe(fixture):
                    with self.assertRaises((RuntimeError, ValueError)) as rejected: handle.query()
                    self._assert_cold_semantic_rejection(rejected.exception, "runtime context is missing, foreign, or expired")
                self.assertTrue(scope.closed)
                with self.assertRaises(ReleaseOperationsError): handle.query()
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
            finally:
                if not scope.closed: handle.close()
                task_module._ISSUED_RUNTIME_CONTEXTS[id(app._runtime)] = issued

    def test_cold_handle_cannot_authorize_a_new_live_assessment_commit(self):
        from graph_engineering.application import release_operations as module

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            original_rows = self._repository_rows(fixture)
            original_cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            original_physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            with self._cold_cleanup_probe(fixture):
                handle = module.restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                try:
                    with self._same_task_assessment(cold=True) as other:
                        _api2, second, live_session, live_app, _probe2, live_target, live_candidate, _evidence2, _ = other
                        before = self._repository_rows(second)
                        cas = {p: p.read_bytes() for p in second.objects._objects.rglob("*") if p.is_file()}
                        physical = {p.name: p.read_bytes() for p in live_session._root._root_path.iterdir()}
                        with self.assertRaises(ValueError) as rejected:
                            live_app.assess_and_commit(live_candidate, observer=live_target,
                                                      release_operations_evidence=handle)
                        self._assert_cold_semantic_rejection(rejected.exception, "release operations evidence is absent, stale, or foreign")
                        self.assertEqual(self._repository_rows(second), before)
                        self.assertEqual({p: p.read_bytes() for p in second.objects._objects.rglob("*") if p.is_file()}, cas)
                        self.assertEqual({p.name: p.read_bytes() for p in live_session._root._root_path.iterdir()}, physical)
                    handle.query()
                finally: handle.close()
            self.assertEqual(self._repository_rows(fixture), original_rows)
            self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, original_cas)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, original_physical)


    @contextmanager
    def _cold_cleanup_probe(self, fixture):
        import os
        from graph_engineering.application import release_operations as module

        opened, owners = [], []
        opening, closing = os.open, module._ColdReleaseReadScope.close
        def opened_file(*args, **kwargs):
            descriptor = opening(*args, **kwargs)
            opened.append(descriptor)
            return descriptor
        def closed_scope(current):
            if not current.closed:
                owners.append((current, tuple(current.ports)))
                if current.lease is not None:
                    opened.append(current.lease._descriptor)
            return closing(current)
        # The wrapper forwards every argument to the real dir_fd-capable open.
        # Preserve capability discovery while observing those descriptors.
        with mock.patch.object(os, "open", new=opened_file), \
                mock.patch.object(os, "supports_dir_fd", {*os.supports_dir_fd, opened_file}), \
                mock.patch.object(module._ColdReleaseReadScope, "close", new=closed_scope):
            yield
        self.assertTrue(owners)
        for current, ports in owners:
            self.assertTrue(current.closed)
            owner = current.budget
            self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            self.assertEqual(tuple(context._temporary_units for context in owner.contexts), owner._baseline)
            self.assertEqual(tuple(context._recovery_result_bytes for context in owner.contexts), owner._byte_baseline)
            for port in (*ports, *owner.contexts):
                self.assertIsNone(getattr(port, "_recovery_read_budget", None))
            for context in owner.contexts:
                self.assertIsNone(getattr(context, "_recovery_read_owner", None))
        self.assertFalse(fixture.repository.command_scope._connections)
        fixture.raw_coordinator._require_retained_idle()
        for descriptor in set(opened):
            with self.assertRaises(OSError): os.fstat(descriptor)


    def test_cold_entry_sql_closure_drift_between_captures(self):
        self._assert_cold_entry_sql_drift("between-captures")

    def test_cold_entry_sql_closure_drift_on_reuse(self):
        self._assert_cold_entry_sql_drift("reuse")

    def test_cold_entry_journal_growth_after_provenance_before_authority(self):
        self._assert_cold_entry_sql_drift("authority", cases=("journal",))

    def _assert_cold_entry_sql_drift(self, boundary, *, cases=(
            "revision", "head", "reference", "event", "transaction", "scope", "journal", "claim", "recovery")):
        import sqlite3
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.connection import ManagedConnection

        for case in cases:
            with self.subTest(boundary=boundary, case=case), self._same_task_assessment(
                    cold=True, partial=case == "recovery") as values:
                _api, fixture, session, app, probe, target, candidate, evidence, outcome = values
                receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                session.close()
                task_id, action_id = probe.task_id, outcome.action_id
                connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
                def rows():
                    names = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
                    return tuple((name, tuple(connection.execute('SELECT * FROM "' + name.replace('"', '""') + '"')))
                                 for name, in names)
                if case in ("revision", "head"):
                    table, field, where, parameters = "tasks", ("revision" if case == "revision" else "head_digest"), "task_id=?", (task_id,)
                    expected = ("cold source task snapshot is stale or invalid" if case == "revision"
                                else "event stream does not match committed head")
                elif case == "reference":
                    table, field, where, parameters = "object_references", None, "task_id=? AND digest=? AND ref_kind='task'", (
                        task_id, receipt.assessment.object_digest)
                    expected = "cold source assessment is not uniquely referenced"
                elif case in ("event", "transaction"):
                    sequence, transaction = connection.execute(
                        "SELECT sequence,transaction_id FROM events WHERE task_id=? ORDER BY sequence DESC LIMIT 1", (task_id,)).fetchone()
                    table, field = ("events", "event_digest") if case == "event" else ("transactions", "head_digest")
                    where, parameters = ("task_id=? AND sequence=?", (task_id, sequence)) if case == "event" else (
                        "task_id=? AND transaction_id=?", (task_id, transaction))
                    expected = ("stored event index columns or digest mismatch" if case == "event"
                                else "stored final transaction head digest is invalid")
                elif case == "scope":
                    table, field, where, parameters = "project_scopes", "metadata_revision", "task_id=? AND status='frozen'", (task_id,)
                    expected = "cold source ProjectScope source differs"
                elif case in ("journal", "claim"):
                    table, field, where, parameters = ("action_journal" if case == "journal" else "claims"), "revision", (
                        "task_id=? AND action_id=?"), (task_id, action_id)
                    expected = ("completed action original claim resources differ" if case == "claim" else
                        "completed action provenance changed during query" if boundary == "authority" else
                        "cold complete source or physical closure changed" if boundary == "between-captures" else
                        "cold assessment sources changed since issuance")
                else:
                    table, field, where, parameters = "claim_recovery_attempts", "revision", (
                        "task_id=? AND original_action_id=?"), (task_id, action_id)
                    expected = "completed compensation state or rollback postcondition differs"
                selected = connection.execute("SELECT " + (field or "*") + " FROM " + table + " WHERE " + where, parameters).fetchall()
                self.assertEqual(len(selected), 1)
                saved = selected[0]
                if case == "claim": self.assertEqual(saved[0], 2)
                if case == "recovery": self.assertEqual(saved[0], 3)
                replacement = (saved[0] + 1 if field in ("revision", "metadata_revision")
                               else "sha256-jcs-v1:" + "0" * 64)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                scopes, handle, injected, amended_rows = [], None, False, None
                initialize, capture = module._ColdReleaseReadScope.__init__, module._ColdReleaseReadScope._capture
                def observed(current, *args, **kwargs):
                    initialize(current, *args, **kwargs); scopes.append(current)
                def inject():
                    nonlocal injected, amended_rows
                    if field is None:
                        changed = connection.execute("DELETE FROM " + table + " WHERE " + where, parameters)
                    else:
                        changed = connection.execute("UPDATE " + table + " SET " + field + "=? WHERE " + where,
                                                     (replacement, *parameters))
                    self.assertEqual(changed.rowcount, 1)
                    injected, amended_rows = True, rows()
                def drift(current):
                    value = capture(current)
                    if not injected: inject()
                    return value
                authority = fixture.raw_coordinator._read_captured_action_authority
                def drift_authority(*args, **kwargs):
                    if not injected: inject()
                    return authority(*args, **kwargs)
                def restore():
                    return module.restore_current_release_assessment(task_application=app._task_application,
                        runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                        object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                        retained_namespace=fixture.retained_namespace, task_id=task_id)
                execute = ManagedConnection.execute
                def only_reads(current, sql, parameters=()):
                    self.assertEqual(current._role, "doctor")
                    self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                    return execute(current, sql, parameters)
                try:
                    with ExitStack() as guards:
                        guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed))
                        guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                        if boundary == "reuse":
                            handle = restore(); inject()
                        elif boundary == "authority":
                            guards.enter_context(mock.patch.object(fixture.raw_coordinator,
                                "_read_captured_action_authority", side_effect=drift_authority))
                        else:
                            guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "_capture", new=drift))
                        with self.assertRaises((RuntimeError, ValueError)) as rejected:
                            if handle is None: handle = restore()
                            else: handle.query()
                        self._assert_cold_semantic_rejection(rejected.exception, expected)
                    self.assertTrue(injected)
                    self.assertEqual(rows(), amended_rows)
                    self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                    self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                    self.assertTrue(scopes[0].closed)
                    self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                    self.assertTrue(all(getattr(context, "_recovery_read_budget", None) is None
                                        for context in scopes[0].budget.contexts))
                    self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                    self.assertFalse(fixture.repository.command_scope._connections)
                    if handle is not None:
                        with self.assertRaises(ReleaseOperationsError): handle.query()
                finally:
                    if handle is not None and scopes and not scopes[0].closed: handle.close()
                    if injected:
                        if field is None:
                            connection.execute("INSERT INTO " + table + " VALUES (" + ",".join("?" for _ in saved) + ")", saved)
                        else:
                            connection.execute("UPDATE " + table + " SET " + field + "=? WHERE " + where, (saved[0], *parameters))
                    connection.close()


    def test_cold_entry_missing_commit_and_busy_root_do_not_publish_a_handle(self):
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.errors import RepositoryIntegrityError

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            native = fixture.retained_namespace._record()[4]
            scopes = []
            initialize = module._ColdReleaseReadScope.__init__
            def observed(current, *args, **kwargs):
                initialize(current, *args, **kwargs); scopes.append(current)
            def restore():
                factory = ReleaseOperationsRegistryFactory.from_installation()
                return module.restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy, release_factory=factory,
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
            def unchanged(before, cas, physical):
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                self.assertTrue(scopes[-1].closed)
                self.assertEqual((scopes[-1].budget.retained_units, scopes[-1].budget.retained_bytes), (0, 0))
            with mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed):
                before = self._repository_rows(fixture)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                with mock.patch.object(native, "_open_cold_marker",
                        side_effect=AssertionError("uncommitted assessment reached root admission")):
                    with self.assertRaises(RepositoryIntegrityError) as rejected: restore()
                self._assert_cold_semantic_rejection(rejected.exception, "assessment is missing or ambiguous")
                unchanged(before, cas, physical)
                self.assertEqual(native.active_leases, 1)
                app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                before = self._repository_rows(fixture)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                with self.assertRaises(ReleaseOperationsError) as rejected: restore()
                self._assert_cold_semantic_rejection(rejected.exception, "root is busy")
                unchanged(before, cas, physical)
                self.assertEqual(native.active_leases, 1)
                session.close()
                handle = restore()
                try: handle.query()
                finally: handle.close()
                unchanged(before, cas, physical)
                self.assertEqual(native.active_leases, 0)

    def test_cold_entry_assessment_reference_removed_after_locator_releases_root(self):
        import sqlite3
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.errors import RepositoryIntegrityError

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            digest = receipt.assessment.object_digest
            connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
            saved = connection.execute("SELECT * FROM object_references WHERE task_id=? AND digest=?",
                (probe.task_id, digest)).fetchone()
            self.assertIsNotNone(saved)
            original = fixture.repository.read_category_recovery_sources
            scopes, deleted = [], False
            initialize = module._ColdReleaseReadScope.__init__
            def observed(current, *args, **kwargs):
                initialize(current, *args, **kwargs); scopes.append(current)
            def raced(task_id, *, phase):
                nonlocal deleted
                value = original(task_id, phase=phase)
                if phase == "locator" and not deleted:
                    self.assertFalse(fixture.repository.command_scope._connections)
                    connection.execute("DELETE FROM object_references WHERE task_id=? AND digest=?", (task_id, digest))
                    deleted = True
                return value
            cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            try:
                with mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed), \
                        mock.patch.object(fixture.repository, "read_category_recovery_sources", side_effect=raced):
                    with self.assertRaises(RepositoryIntegrityError) as rejected:
                        module.restore_current_release_assessment(task_application=app._task_application,
                            runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                            object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                            retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                self._assert_cold_semantic_rejection(rejected.exception, "assessment is not uniquely referenced")
                self.assertTrue(deleted)
                self.assertTrue(scopes[0].closed)
                self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                self.assertIsNone(connection.execute("SELECT * FROM object_references WHERE task_id=? AND digest=?",
                    (probe.task_id, digest)).fetchone())
                self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
            finally:
                if deleted:
                    connection.execute("INSERT INTO object_references VALUES (" + ",".join("?" for _ in saved) + ")", saved)
                connection.close()


    def test_cold_entry_every_referenced_cas_body_drift_between_captures(self):
        self._assert_cold_entry_cas_drift("between-captures")

    def test_cold_entry_every_referenced_cas_body_drift_on_reuse(self):
        self._assert_cold_entry_cas_drift("reuse")

    def _assert_cold_entry_cas_drift(self, boundary):
        import socket
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.actions import ActionJournalRepository

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            with fixture.repository._factory.open("doctor") as connection:
                digests = tuple(row[0] for row in connection.execute(
                    "SELECT DISTINCT digest FROM object_references WHERE task_id=? ORDER BY digest", (probe.task_id,)))
            self.assertGreater(len(digests), 1)
            before = self._repository_rows(fixture)
            cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            for index, digest in enumerate(digests):
                with self.subTest(boundary=boundary, source_index=index, source_count=len(digests)):
                    path = fixture.objects._path(digest)
                    original = cas[path]
                    self.assertTrue(original)
                    changed = bytes((original[0] ^ 1,)) + original[1:]
                    factory = ReleaseOperationsRegistryFactory.from_installation()
                    scopes, handle, injected = [], None, False
                    initialize, capture = module._ColdReleaseReadScope.__init__, module._ColdReleaseReadScope._capture
                    def observed(current, *args, **kwargs):
                        initialize(current, *args, **kwargs); scopes.append(current)
                    def drift(current):
                        nonlocal injected
                        result = capture(current)
                        if not injected:
                            path.write_bytes(changed); injected = True
                        return result
                    def restore():
                        return module.restore_current_release_assessment(task_application=app._task_application,
                            runtime=app._runtime, policy=app._policy, release_factory=factory,
                            object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                            retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                    blocked = lambda *a, **k: (_ for _ in ()).throw(AssertionError("forbidden cold side effect or legacy read"))
                    try:
                        with self._cold_cleanup_probe(fixture), ExitStack() as guards:
                            prohibited = []
                            guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed))
                            for kind, methods in (
                                    (TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                                    (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                                    (ActionJournalRepository, ("load", "find_prepared"))):
                                for name in methods:
                                    prohibited.append(guards.enter_context(mock.patch.object(kind, name, side_effect=blocked)))
                            for name in ("execute", "reconcile_unknown", "compensate_unknown"):
                                prohibited.append(guards.enter_context(mock.patch.object(fixture.raw_coordinator, name, side_effect=blocked)))
                            for name in ("socket", "getaddrinfo"):
                                prohibited.append(guards.enter_context(mock.patch.object(socket, name, side_effect=blocked)))
                            if boundary == "reuse":
                                handle = restore()
                                path.write_bytes(changed); injected = True
                            else:
                                guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "_capture", new=drift))
                            with self.assertRaises(Exception) as rejected:
                                if handle is None: handle = restore()
                                else: handle.query()
                            self._assert_cold_semantic_rejection(rejected.exception, "provenance object digest mismatch")
                            self.assertTrue(injected)
                            self.assertTrue(scopes[0].closed)
                            self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                            if handle is not None:
                                with self.assertRaises(ReleaseOperationsError): handle.query()
                            for blocked_call in prohibited: blocked_call.assert_not_called()
                        self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                        self.assertEqual(self._repository_rows(fixture), before)
                        self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()},
                            {**cas, path: changed})
                        self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                    finally:
                        if handle is not None and scopes and not scopes[0].closed: handle.close()
                        path.write_bytes(original)


    def test_cold_entry_each_physical_member_drift_between_captures_and_on_reuse(self):
        import json
        import socket
        from graph_engineering.application import release_operations as module
        from graph_engineering.adapters.local_release_simulator import _retained_members
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.actions import ActionJournalRepository

        for boundary in ("between-captures", "reuse"):
            for role in ("state", "active", "stage", "active_artifact", "stage_artifact", "identity"):
                with self.subTest(boundary=boundary, role=role), self._same_task_assessment(cold=True) as values:
                    _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                    app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                    session.close()
                    factory = fixture.release_factory
                    names = _retained_members(factory._registry.fixture("release-foundation-v1"))
                    root = session._root._root_path
                    path = root / names[role]
                    original = path.read_bytes()
                    mode = path.stat().st_mode & 0o777
                    def rewrite(body):
                        # Fault injection only: the durable identity marker is
                        # read-only. Restore its required mode before recovery.
                        path.chmod(0o600)
                        try: path.write_bytes(body)
                        finally: path.chmod(mode)
                    if role == "state":
                        value = json.loads(original); value["generation"] = 0
                        changed = json.dumps(value, separators=(",", ":")).encode()
                        expected = "cold release current physical target differs"
                    elif role in ("active", "stage"):
                        value = json.loads(original); value["artifact_version"] = "changed"
                        changed = json.dumps(value, separators=(",", ":")).encode()
                        expected = "artifact"
                    else:
                        changed = bytes((original[0] ^ 1,)) + original[1:]
                        expected = "cold marker changed" if role == "identity" else "cold release artifact bytes"
                    before = self._repository_rows(fixture)
                    cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                    physical = {p.name: p.read_bytes() for p in root.iterdir()}
                    physical[path.name] = changed
                    scopes, handle, injected = [], None, False
                    initialize, capture = module._ColdReleaseReadScope.__init__, module._ColdReleaseReadScope._capture
                    def observed(current, *args, **kwargs):
                        initialize(current, *args, **kwargs); scopes.append(current)
                    def drift(current):
                        nonlocal injected
                        result = capture(current)
                        if not injected:
                            rewrite(changed); injected = True
                        return result
                    def restore():
                        return module.restore_current_release_assessment(task_application=app._task_application,
                            runtime=app._runtime, policy=app._policy, release_factory=factory,
                            object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                            retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                    blocked = lambda *a, **k: (_ for _ in ()).throw(AssertionError("forbidden cold side effect or legacy read"))
                    try:
                        with self._cold_cleanup_probe(fixture), ExitStack() as guards:
                            prohibited = []
                            guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed))
                            for kind, methods in (
                                    (TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                                    (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                                    (ActionJournalRepository, ("load", "find_prepared"))):
                                for name in methods:
                                    prohibited.append(guards.enter_context(mock.patch.object(kind, name, side_effect=blocked)))
                            for name in ("execute", "reconcile_unknown", "compensate_unknown"):
                                prohibited.append(guards.enter_context(mock.patch.object(fixture.raw_coordinator, name, side_effect=blocked)))
                            for name in ("socket", "getaddrinfo"):
                                prohibited.append(guards.enter_context(mock.patch.object(socket, name, side_effect=blocked)))
                            if boundary == "reuse":
                                handle = restore()
                                rewrite(changed); injected = True
                            else:
                                guards.enter_context(mock.patch.object(module._ColdReleaseReadScope, "_capture", new=drift))
                            with self.assertRaises(ValueError) as rejected:
                                if handle is None: handle = restore()
                                else: handle.query()
                            self._assert_cold_semantic_rejection(rejected.exception, expected)
                            self.assertTrue(injected)
                            self.assertTrue(scopes[0].closed)
                            self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                            if handle is not None:
                                with self.assertRaises(ReleaseOperationsError): handle.query()
                            for blocked_call in prohibited: blocked_call.assert_not_called()
                        self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                        self.assertEqual(self._repository_rows(fixture), before)
                        self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                        self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, physical)
                    finally:
                        if handle is not None and scopes and not scopes[0].closed: handle.close()
                        rewrite(original)


    def test_cold_entry_rejects_relabelled_columns_and_legacy_assessment_before_root_admission(self):
        import copy
        from graph_engineering.application import release_operations as module
        from graph_engineering.application.profile_execution import _value_digest
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest, object_digest

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            with fixture.repository._factory.open("application") as connection:
                saved = connection.execute("SELECT snapshot_json,snapshot_digest FROM tasks WHERE task_id=?",
                    (probe.task_id,)).fetchone()
            snapshot = parse_canonical_json(saved[0])
            reference = next(item for item in snapshot["domain"]["evidence"]
                             if item["evidence_type"] == "category-completion-assessment")
            original = parse_canonical_json(fixture.objects.get(reference["source_ref"]).decode())
            cases = [("column_id", column) for column in app._policy.column_ids if column != "normal"]
            cases += [("schema_version", version) for version in ("1.0.0", "1.1.0", "1.2.0", "1.3.0")]
            cases += [("column_id", malformed) for malformed in (None, True, 7, [], {})]
            self.assertEqual(len(cases), 20)
            native = fixture.retained_namespace._record()[4]
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            for field, value in cases:
                with self.subTest(field=field, value=value):
                    changed = copy.deepcopy(original); changed[field] = value
                    changed.pop("assessment_digest")
                    changed["assessment_digest"] = _value_digest(changed, "category-completion-assessment")
                    body = canonical_bytes(changed); digest = object_digest(body)
                    fixture.objects.put_verified(body, digest)
                    amended = copy.deepcopy(snapshot)
                    amended_ref = next(item for item in amended["domain"]["evidence"]
                                       if item["evidence_type"] == "category-completion-assessment")
                    amended_ref.update(source_ref=digest, digest=changed["assessment_digest"],
                                       evidence_id=changed["assessment_digest"])
                    with fixture.repository._factory.open("application") as connection:
                        with connection.transaction():
                            connection.execute("UPDATE object_references SET digest=? WHERE task_id=? AND digest=?",
                                (digest, probe.task_id, reference["source_ref"]))
                            connection.execute("UPDATE tasks SET snapshot_json=?,snapshot_digest=? WHERE task_id=?",
                                (canonical_json(amended), semantic_record_digest(
                                    {"contract": "repository-snapshot-v1", "value": amended}), probe.task_id))
                    before = self._repository_rows(fixture)
                    cas = {str(path.relative_to(fixture.objects._objects)): path.read_bytes()
                           for path in fixture.objects._objects.rglob("*") if path.is_file()}
                    try:
                        # Each case uses a genuine installed issuer with a fresh
                        # work balance; the database/CAS locator is not mocked.
                        factory = ReleaseOperationsRegistryFactory.from_installation()
                        with mock.patch.object(native, "_open_cold_marker",
                                side_effect=AssertionError("unsupported assessment reached root admission")):
                            with self.assertRaisesRegex(ReleaseOperationsError, "selector is unsupported"):
                                module.restore_current_release_assessment(task_application=app._task_application,
                                    runtime=app._runtime, policy=app._policy, release_factory=factory,
                                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                        self.assertEqual(self._repository_rows(fixture), before)
                        self.assertEqual({str(path.relative_to(fixture.objects._objects)): path.read_bytes()
                            for path in fixture.objects._objects.rglob("*") if path.is_file()}, cas)
                        self.assertEqual(native.active_leases, 0)
                    finally:
                        with fixture.repository._factory.open("application") as connection:
                            with connection.transaction():
                                connection.execute("UPDATE object_references SET digest=? WHERE task_id=? AND digest=?",
                                    (reference["source_ref"], probe.task_id, digest))
                                connection.execute("UPDATE tasks SET snapshot_json=?,snapshot_digest=? WHERE task_id=?",
                                    (saved[0], saved[1], probe.task_id))
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)

    def test_cold_entry_whole_operation_exact_remaining_bounds_and_one_less_reject_without_writes(self):
        from graph_engineering import _ATTESTATION_KEY, _ATTESTATION_FILE
        from graph_engineering.application import release_operations as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        for dimension in ("temporary_units", "result_bytes"):
            with self.subTest(dimension=dimension), self._same_task_assessment(cold=True) as values:
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                session.close()
                before = self._repository_rows(fixture)
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                def restore():
                    # Every trial constructs a genuine fresh installed issuer;
                    # repeated calibration must not reset an exhausted work meter.
                    factory = ReleaseOperationsRegistryFactory.from_installation()
                    return module.restore_current_release_assessment(task_application=app._task_application,
                        runtime=app._runtime, policy=app._policy, release_factory=factory,
                        object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                        retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                # Streaming source hashes use whatever allowance remains. Their
                # observed peak is not a minimum: only one buffer byte is needed.
                # Estimate a candidate threshold from fixed allocations plus
                # that minimum. Only the real exact/-1 trials prove this bound.
                # Preserve every real charge and installed resource limit.
                charge = _RecoveryReadBudget._charge
                stream_names = {name for name, _size, _digest in
                    module._COLD_INSTALLATION_PLANS[fixture.release_factory].files}
                stream_names.update(("cold-discovery-buffer", _ATTESTATION_KEY, _ATTESTATION_FILE))
                measured_owner = None
                initialize = module._ColdReleaseReadScope.__init__
                def calibrating(current, *args, **kwargs):
                    nonlocal measured_owner
                    initialize(current, *args, **kwargs)
                    measured_owner = current.budget
                def measured(owner, context, *, units, byte_count, source_id):
                    nonlocal peak
                    count = units if dimension == "temporary_units" else byte_count
                    retained = owner.retained_units if dimension == "temporary_units" else owner.retained_bytes
                    if owner is measured_owner:
                        peak = max(peak, retained + (min(count, 1) if source_id in stream_names else count))
                    return charge(owner, context, units=units, byte_count=byte_count, source_id=source_id)
                for _trial in range(2):
                    peak = 0
                    with mock.patch.object(_RecoveryReadBudget, "_charge", new=measured), \
                            mock.patch.object(module._ColdReleaseReadScope, "__init__", new=calibrating):
                        handle = restore(); scope = handle._record()[1]
                        handle.query()
                    context = scope.budget.contexts[-1]
                    self.assertGreater(len(scope.budget.contexts), 1)
                    handle.close()
                capacity = context.profile.limits[dimension]
                self.assertLess(peak, capacity)
                for shortage in (0, 1):
                    prior = capacity - peak + shortage
                    if dimension == "temporary_units":
                        context.acquire_temporary(prior, source_id="prior-cold-caller", operation_path=())
                    else:
                        context._recovery_result_bytes += prior
                    scopes, handle = [], None
                    initialize = module._ColdReleaseReadScope.__init__
                    def observed(current, *args, **kwargs):
                        initialize(current, *args, **kwargs); scopes.append(current)
                    try:
                        with mock.patch.object(module._ColdReleaseReadScope, "__init__", new=observed):
                            if shortage:
                                with self.assertRaises(ContractError) as rejected:
                                    handle = restore(); handle.query()
                                self.assertEqual(rejected.exception.detail.code, "E_LIMIT")
                            else:
                                handle = restore(); handle.query()
                                owner = scopes[0].budget
                                self.assertEqual(owner.unit_limit if dimension == "temporary_units" else owner.byte_limit, peak)
                                self.assertEqual(owner.peak_units if dimension == "temporary_units" else owner.peak_bytes, peak)
                        if handle is not None and not scopes[0].closed: handle.close()
                        self.assertTrue(scopes[0].closed)
                        self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                        self.assertEqual(context._temporary_units if dimension == "temporary_units"
                                         else context._recovery_result_bytes, prior)
                        owner = scopes[0].budget
                        self.assertEqual(tuple(c._temporary_units for c in owner.contexts), owner._baseline)
                        self.assertEqual(tuple(c._recovery_result_bytes for c in owner.contexts), owner._byte_baseline)
                        self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                        self.assertEqual(self._repository_rows(fixture), before)
                        self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                        self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                    finally:
                        if handle is not None and scopes and not scopes[0].closed: handle.close()
                        if dimension == "temporary_units": context.release_temporary(prior)
                        else: context._recovery_result_bytes -= prior


    def test_cold_entry_rejects_equal_replacement_at_adoption_return_before_source_lookup(self):
        import copy
        from graph_engineering.application import release_operations as module
        from graph_engineering.core.contracts.immutable import freeze, thaw

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            factory = fixture.release_factory
            original = factory._adopt_cold_configuration
            before = self._repository_rows(fixture)
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            for name, boundary in ((name, boundary) for name in ("_bootstrap", "_schemas", "_registry")
                                   for boundary in ("after", "before")):
                with self.subTest(root=name, boundary=boundary):
                    old = getattr(factory, name)
                    replacement = (freeze(thaw(old)) if name == "_bootstrap" else
                                   dict(old) if name == "_schemas" else copy.copy(old))
                    scopes = []
                    def after_adoption(*args, **kwargs):
                        if boundary == "before":
                            setattr(factory, name, replacement)
                        result = original(*args, **kwargs)
                        scopes.append(kwargs["_operation"])
                        if boundary == "after":
                            setattr(factory, name, replacement)
                        return result
                    try:
                        with mock.patch.object(factory, "_adopt_cold_configuration", side_effect=after_adoption), \
                                mock.patch.object(fixture.repository, "read_category_recovery_sources",
                                    side_effect=AssertionError("source lookup before adopted identity rejection")):
                            with self.assertRaisesRegex(ReleaseOperationsError, "configuration changed"):
                                module.restore_current_release_assessment(task_application=app._task_application,
                                    runtime=app._runtime, policy=app._policy, release_factory=factory,
                                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                    finally:
                        setattr(factory, name, old)
                    self.assertEqual(len(scopes), 1)
                    self.assertTrue(scopes[0].closed)
                    self.assertEqual((scopes[0].budget.retained_units, scopes[0].budget.retained_bytes), (0, 0))
                    self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)

    def test_cold_entry_bounds_replaced_currentness_tuple_before_snapshot_expansion(self):
        import tracemalloc
        from graph_engineering.application import release_operations as module

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            factory = fixture.release_factory
            original = module._COLD_CURRENTNESS_INPUTS[factory]
            # Allocate the injected data before measuring the recovery operation.
            expanded = original + (None,) * 262144
            before = self._repository_rows(fixture)
            physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            def restore():
                return module.restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy, release_factory=factory,
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
            for reuse in (True, False):
                with self.subTest(reuse=reuse):
                    handle = restore() if reuse else None
                    scope = handle._record()[1] if reuse else None
                    module._COLD_CURRENTNESS_INPUTS[factory] = expanded
                    self.assertFalse(tracemalloc.is_tracing())
                    tracemalloc.start()
                    try:
                        with mock.patch.object(fixture.repository, "read_category_recovery_sources",
                                side_effect=AssertionError("source lookup before configuration rejection")):
                            with self.assertRaisesRegex(ReleaseOperationsError, "configuration changed"):
                                handle.query() if reuse else restore()
                        _current, peak = tracemalloc.get_traced_memory()
                    finally:
                        tracemalloc.stop()
                        module._COLD_CURRENTNESS_INPUTS[factory] = original
                        if scope is not None and not scope.closed:
                            handle.close()
                    # Even one copied tuple would need eight bytes per slot on
                    # this native 64-bit runtime. Reject before that allocation.
                    self.assertLess(peak, 4 * len(expanded))
                    if scope is not None:
                        self.assertTrue(scope.closed)
                        self.assertEqual((scope.budget.retained_units, scope.budget.retained_bytes), (0, 0))
                    self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)


    def test_cold_entry_joins_each_action_authority_to_the_outer_security_capture(self):
        import json
        import sqlite3
        from graph_engineering.application.release_operations import restore_current_release_assessment
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest

        for partial in (False, True):
            with self.subTest(partial=partial), self._same_task_assessment(cold=True, partial=partial) as values:
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                session.close()
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                reader = fixture.raw_coordinator
                connection = sqlite3.connect(fixture.repository._factory._database, isolation_level=None)
                original = connection.execute(
                    "SELECT state_json,state_digest FROM task_security_states WHERE task_id=?", (probe.task_id,)).fetchone()
                read = reader._read_completed_action_provenance_bounded
                def replace_security(row):
                    connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                                       (*row, probe.task_id))
                def restore():
                    return restore_current_release_assessment(task_application=app._task_application,
                        runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                        object_repository=fixture.objects, action_coordinator=reader,
                        retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                try:
                    for reuse in (False, True):
                        replace_security(original)
                        handle = restore() if reuse else None
                        scope = None if handle is None else handle._record()[1]
                        changed, rejected = [], None
                        def alternating(task_id, action_id):
                            # Each action subcapture sees the same authorized A;
                            # each following outer read sees the same revoked B.
                            replace_security(original)
                            result = read(task_id, action_id)
                            state = json.loads(original[0])
                            journals = result["provenance"]["journals"]
                            journal = next(item for item in journals if
                                (item["prepared"]["action_kind"] == "rollback") == partial)
                            state["authority_digests"].remove(journal["authority_digest"])
                            row = (canonical_json(state), semantic_record_digest({
                                "contract": "task-security-state-v1", "value": state}))
                            replace_security(row)
                            changed.append(row)
                            return result
                        try:
                            with mock.patch.object(reader, "_read_completed_action_provenance_bounded", side_effect=alternating):
                                if reuse:
                                    handle.query()
                                else:
                                    handle = restore()
                                    scope = handle._record()[1]
                        except (ValueError, RuntimeError) as error:
                            rejected = error
                        finally:
                            if scope is not None and not scope.closed:
                                handle.close()
                        self.assertTrue(changed)
                        self.assertIsNotNone(rejected, "identical mixed A/B captures were accepted")
                        self._assert_cold_semantic_rejection(rejected, "security capture differ")
                        self.assertEqual(connection.execute(
                            "SELECT state_json,state_digest FROM task_security_states WHERE task_id=?",
                            (probe.task_id,)).fetchone(), changed[-1])
                        self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                        self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)
                        if scope is not None:
                            self.assertEqual((scope.budget.retained_units, scope.budget.retained_bytes), (0, 0))
                finally:
                    replace_security(original)
                    connection.close()

    def test_cold_entry_rejects_equal_configuration_replacements_between_reads_and_on_reuse(self):
        import copy
        from graph_engineering.application.release_operations import restore_current_release_assessment, _ColdReleaseReadScope
        from graph_engineering.core.contracts.immutable import freeze, thaw

        for attack in ("bootstrap", "schemas", "registry", "schema-member", "connection-policy", "namespace-path"):
            for reuse in (False, True):
                with self.subTest(attack=attack, reuse=reuse), self._same_task_assessment(cold=True) as values:
                    _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                    app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
                    session.close()
                    before = self._repository_rows(fixture)
                    physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                    factory = fixture.release_factory
                    if attack in ("bootstrap", "schemas", "registry"):
                        selected, name = factory, "_" + attack
                        old = getattr(selected, name)
                        replacement = (freeze(thaw(old)) if attack == "bootstrap" else
                                       dict(old) if attack == "schemas" else copy.copy(old))
                        change = lambda: setattr(selected, name, replacement)
                        undo = lambda: setattr(selected, name, old)
                    elif attack == "schema-member":
                        name = next(iter(factory._schemas))
                        old = factory._schemas[name]
                        replacement = freeze(thaw(old))
                        change = lambda: factory._schemas.__setitem__(name, replacement)
                        undo = lambda: factory._schemas.__setitem__(name, old)
                    elif attack == "connection-policy":
                        selected, name = fixture.repository._factory, "_policy"
                        old = selected._policy
                        change = lambda: setattr(selected, name, copy.copy(old))
                        undo = lambda: setattr(selected, name, old)
                    else:
                        selected, name = fixture.retained_namespace._record()[4], "path"
                        old = selected.path
                        change = lambda: setattr(selected, name, pathlib.Path(str(old)))
                        undo = lambda: setattr(selected, name, old)
                    def restore():
                        return restore_current_release_assessment(task_application=app._task_application,
                            runtime=app._runtime, policy=app._policy, release_factory=factory,
                            object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                            retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                    handle = restore() if reuse else None
                    scope = None if handle is None else handle._record()[1]
                    captured, rejected = [], None
                    original_capture = _ColdReleaseReadScope._capture
                    def between(current):
                        result = original_capture(current)
                        captured.append(current)
                        if len(captured) == 1: change()
                        return result
                    try:
                        if reuse:
                            change()
                            handle.query()
                        else:
                            with mock.patch.object(_ColdReleaseReadScope, "_capture", new=between):
                                handle = restore()
                                scope = handle._record()[1]
                    except (ValueError, RuntimeError) as error:
                        rejected = error
                    finally:
                        undo()
                        if scope is not None and not scope.closed:
                            handle.close()
                    self.assertIsNotNone(rejected, "equal replacement bypassed adopted configuration identity")
                    self._assert_cold_semantic_rejection(rejected, "configuration changed")
                    self.assertEqual(self._repository_rows(fixture), before)
                    self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                    self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)


    def test_cold_partial_assessment_preserves_restored_baseline_and_generation(self):
        self._assert_cold_partial_assessment("normal")

    def test_cold_recovery_column_requires_same_action_restored_baseline(self):
        self._assert_cold_partial_assessment("recovery")

    def test_cold_rollback_column_adopts_completed_restore_without_replay(self):
        self._assert_cold_partial_assessment("rollback")

    def test_private_release_real_e2e_measures_apply_and_preapply_rejection(self):
        import tempfile
        from graph_engineering.core.actions import PreparedAction
        for accepted in (True, False):
            with self.subTest(accepted=accepted), action_stack(domain_task=True) as fixture, self._runtime() as runtime, \
                    tempfile.TemporaryDirectory(prefix="gew-release-real-") as directory:
                with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                        namespace_path=pathlib.Path(directory).resolve()) as namespace:
                    factory, session, baseline, artifact = self._issue(fixture, namespace)
                    with session:
                        retarget_security_binding(fixture, target_digest=session.target.target_digest)
                        document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                            baseline=baseline, candidate=artifact, candidate_bytes=factory.artifact_bytes(artifact))
                        document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                        if not accepted:
                            document["precondition"]["generation"] = 1
                            document["payload"]["expected_generation"] = 1
                            document["payload_digest"] = PreparedAction.payload_digest_for(document["payload"], fixture.context)
                        document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                        prepared = fixture.coordinator.prepare(document)
                        fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                        authority = factory._execute_category_action(action_coordinator=fixture.raw_coordinator,
                            session=session, action_id=prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                            disclosure_plan=release_disclosure_plan(fixture, prepared))
                        self.assertEqual(authority.disposition, "P" if accepted else "R")
                        self.assertEqual(session._root.mutation_count, int(accepted))
                        self.assertEqual(session.target.apply_count, int(accepted))
                        self.assertEqual(authority._execution["mutation_delta"], int(accepted))
                        self.assertEqual(fixture.journal.load(prepared.action_id).state,
                                         "reconciled" if accepted else "authorized")
                        self.assertEqual(fixture.leases.unresolved_claims(), ())
                        observer = authority.issue_observer()
                        self.assertEqual(observer.observe()["state"], session._root.state())

    def test_release_real_e2e_category_rejects_actual_preapply_failure_without_writes(self):
        from graph_engineering.application.profile_execution import CategoryExecutionError

        with self._same_task_assessment(cold=True, column="real-e2e", accepted=False) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            before, physical = self._repository_rows(fixture), session._root.state()
            self.assertIsNone(evidence)
            self.assertEqual(target._authority.disposition, "R")
            with self.assertRaisesRegex(CategoryExecutionError, "rejected before mutation"):
                app.assess_and_commit(candidate, observer=target)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual(session._root.state(), physical)
            self.assertEqual(session._root.mutation_count, 0)
            self.assertIsNone(app._resolver.current_body(probe.task_id))

    def test_release_real_e2e_rejects_cloned_authority_observer_and_predecessor(self):
        import copy
        from graph_engineering.application.profile_execution import (
            CategoryExecutionError, _require_real_category_observer,
        )
        from graph_engineering.application.release_operations import _ReleaseCategoryObserver

        with self._same_task_assessment(cold=True, column="real-e2e") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            authority = target._authority
            rows, state, mutations = self._repository_rows(fixture), session._root.state(), session._root.mutation_count
            with self.assertRaises(ValueError):
                _ReleaseCategoryObserver.require_issued(copy.copy(target))
            authority._observer = copy.copy(target)
            try:
                with self.assertRaises(ValueError):
                    _ReleaseCategoryObserver.require_issued(authority._observer)
            finally:
                authority._observer = target
            with self.assertRaises(ValueError):
                copy.copy(authority).require_current(expected_task_id=probe.task_id)
            with self.assertRaises(ValueError):
                authority.evidence_facts(copy.copy(authority._record))
            with self.assertRaises(ValueError):
                _require_real_category_observer(target, "new-feature")
            saved = authority._record
            authority._record = copy.copy(saved)
            try:
                with self.assertRaises(ValueError):
                    authority.require_current(expected_task_id=probe.task_id)
            finally:
                authority._record = saved
            duck = category_fixture.RetainedCategoryTarget(session)
            duck.is_test_double = False
            duck.execution_kind = target.execution_kind
            with self.assertRaises(ValueError):
                _require_real_category_observer(duck, "release-operations")
            self.assertEqual(self._repository_rows(fixture), rows)
            self.assertEqual(session._root.state(), state)
            self.assertEqual(session._root.mutation_count, mutations)

    def test_release_real_e2e_rejects_alternate_task_snapshot_and_unrelated_revision(self):
        from graph_engineering.application.release_operations import _ReleaseCategoryAuthority
        from tests.contract.test_wp02_graph import graph_schemas, work_context
        stage = _ReleaseCategoryAuthority.stage_task
        def alternate(authority, snapshot):
            return stage(authority, replace(snapshot, desired_state="paused",
                schema_registry=graph_schemas(), context=work_context()))
        with mock.patch.object(_ReleaseCategoryAuthority, "stage_task", new=alternate):
            with self.assertRaisesRegex(ValueError, "snapshot|source"):
                with self._same_task_assessment(cold=True, column="real-e2e"):
                    self.fail("alternate same-revision predecessor activated")
        with self._same_task_assessment(cold=True, column="real-e2e") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            view = app._task_application.runtime_show(probe.task_id, app._runtime)
            altered = replace(view.snapshot, task_revision=view.snapshot.task_revision + 1,
                last_event_seq=view.snapshot.last_event_seq + 1,
                schema_registry=graph_schemas(), context=work_context())
            with mock.patch.object(app._task_application, "runtime_show", return_value=replace(view, snapshot=altered)):
                with self.assertRaisesRegex(ValueError, "snapshot|transition"):
                    target._authority.require_current(expected_task_id=probe.task_id)

    def test_release_real_e2e_rejects_same_task_unexecuted_journal_substitution(self):
        from graph_engineering.core.actions import PreparedAction
        from graph_engineering.core.contracts.immutable import freeze, thaw
        with self._same_task_assessment(cold=True, column="real-e2e") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            authority = target._authority
            original = authority._journal
            document = thaw(freeze(fixture.raw_coordinator._journal.prepared_document(original.prepared)))
            document["action_id"] += ":unexecuted"
            document["idempotency_key"] += ":unexecuted"
            document["snapshot_digest"] = fixture.current_task_snapshot_digest()
            document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
            prepared = fixture.coordinator.prepare(document)
            fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
            authority._journal = fixture.journal.load(prepared.action_id)
            authority._security = fixture.raw_coordinator._issuer.read_task_state(probe.task_id)
            with self.assertRaisesRegex(ValueError, "capability"):
                authority.require_current(expected_task_id=probe.task_id)
            self.assertEqual(session._root.mutation_count, 1)

    def test_release_real_e2e_does_not_count_malformed_precondition_as_stale_generation(self):
        self._assert_rejected_release_precondition("extra-field")

    def test_release_real_e2e_rejects_boolean_payload_generation(self):
        self._assert_rejected_release_precondition("boolean-generation")

    def _assert_rejected_release_precondition(self, variant):
        import tempfile
        from graph_engineering.core.actions import PreparedAction
        with action_stack(domain_task=True) as fixture, self._runtime() as runtime, \
                tempfile.TemporaryDirectory(prefix="gew-release-real-malformed-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, artifact = self._issue(fixture, namespace)
                with session:
                    retarget_security_binding(fixture, target_digest=session.target.target_digest)
                    document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                        baseline=baseline, candidate=artifact, candidate_bytes=factory.artifact_bytes(artifact))
                    document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                    if variant == "extra-field":
                        document["precondition"]["irrelevant"] = True
                    else:
                        document["precondition"]["generation"] = 1
                        document["payload"]["expected_generation"] = True
                        document["payload_digest"] = PreparedAction.payload_digest_for(document["payload"], fixture.context)
                    document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                    prepared = fixture.coordinator.prepare(document)
                    fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                    before = self._repository_rows(fixture)
                    with self.assertRaisesRegex(ReleaseOperationsError, "not an exact stale-generation"):
                        factory._execute_category_action(action_coordinator=fixture.raw_coordinator,
                            session=session, action_id=prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                            disclosure_plan=release_disclosure_plan(fixture, prepared))
                    self.assertEqual(session._root.mutation_count, 0)
                    self.assertEqual(self._repository_rows(fixture), before)
                    self.assertEqual(factory._category_executions, {})

    def test_release_real_e2e_receipt_drift_at_precommit_rejects_without_replay(self):
        with self._same_task_assessment(cold=True, column="real-e2e") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, outcome = values
            before, physical = self._repository_rows(fixture), session._root.state()
            active = False
            journal = fixture.raw_coordinator._journal
            load = journal.load
            def changed(action_id):
                record = load(action_id)
                if active and action_id == outcome.action_id:
                    return replace(record, receipt={**record.receipt,
                        "receipt_digest": category_fixture.digest("substituted-real-receipt")})
                return record
            def fault(step):
                nonlocal active
                if step == "category-assessment.before-commit":
                    active = True
            app._fault = fault
            with mock.patch.object(journal, "load", side_effect=changed):
                with self.assertRaises(ValueError):
                    app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            self.assertTrue(active)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual(session._root.state(), physical)
            self.assertEqual(session._root.mutation_count, 1)
            self.assertIsNone(app._resolver.current_body(probe.task_id))

    def test_release_real_e2e_current_authority_consumes_exact_committed_assessment(self):
        with self._same_task_assessment(cold=True, column="real-e2e") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            assessment = app.assess_and_commit(candidate, observer=target,
                release_operations_evidence=evidence).assessment
            before = self._repository_rows(fixture)
            record = target._authority.require_current(expected_task_id=probe.task_id, require_success=True)
            self.assertEqual(record.body["snapshot_digest"], assessment.snapshot_digest)
            self.assertEqual(record.body["task_revision"], assessment.task_revision)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual(session._root.mutation_count, 1)

    def test_release_recovery_column_rejects_normal_apply_as_recovery(self):
        with self.assertRaisesRegex(ReleaseOperationsError, "requires completed compensation"):
            with self._same_task_assessment(cold=True, column="recovery"):
                self.fail("normal apply issued release recovery evidence")

    def test_completed_rollback_rejects_coherently_resigned_successor_snapshot_digest(self):
        from graph_engineering.application.profile_execution import CategoryExecutionError
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest
        from graph_engineering.core.security.identity import SecurityBinding
        with self._same_task_assessment(cold=True, partial=True, column="rollback") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _outcome = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            facts = probe.resolve_category_evidence(probe.task_id, "rollback")["facts"]
            app._rollback.require_evidence_facts(facts, final=True)
            with fixture.repository._factory.open("application") as connection, connection.transaction():
                old_task = connection.execute("SELECT snapshot_digest FROM tasks WHERE task_id=?", (probe.task_id,)).fetchone()[0]
                old_security = connection.execute("SELECT state_json,state_digest FROM task_security_states WHERE task_id=?", (probe.task_id,)).fetchone()
                state = parse_canonical_json(old_security[0])
                changed = category_fixture.digest("coherently-replaced-successor-snapshot")
                state["task_snapshot_digest"] = changed
                state["binding"]["snapshot_digest"] = changed
                state["binding"]["binding_digest"] = SecurityBinding.digest_document(state["binding"])
                connection.execute("UPDATE tasks SET snapshot_digest=? WHERE task_id=?", (changed, probe.task_id))
                connection.execute("UPDATE task_security_states SET task_snapshot_digest=?,state_json=?,state_digest=? WHERE task_id=?",
                    (changed, canonical_json(state), semantic_record_digest({"contract": "task-security-state-v1", "value": state}), probe.task_id))
            try:
                with self.assertRaises(CategoryExecutionError):
                    app._rollback.require_evidence_facts(facts, final=True)
            finally:
                with fixture.repository._factory.open("application") as connection, connection.transaction():
                    connection.execute("UPDATE tasks SET snapshot_digest=? WHERE task_id=?", (old_task, probe.task_id))
                    connection.execute("UPDATE task_security_states SET task_snapshot_digest=?,state_json=?,state_digest=? WHERE task_id=?", (old_task, *old_security, probe.task_id))
            app._rollback.require_evidence_facts(facts, final=True)

    def test_completed_rollback_rejects_foreign_adoption_and_terminal_fact_substitution(self):
        import copy
        from graph_engineering.application.profile_execution import CategoryExecutionError

        with self._same_task_assessment(cold=True, partial=True, column="rollback") as values:
            api, fixture, session, app, probe, target, candidate, evidence, outcome = values
            rows, physical = self._repository_rows(fixture), session._root.state()
            mutations = session._root.mutation_count
            facts = probe.resolve_category_evidence(probe.task_id, "rollback")["facts"]
            for field, replacement in (("action-id", outcome.action_id),
                    ("action-status", "compensated"),
                    ("claim-status", "reconciled_effect_verified")):
                changed = {**facts, field: replacement}
                for final in (False, True):
                    with self.subTest(field=field, final=final), self.assertRaises(CategoryExecutionError):
                        app._rollback.require_evidence_facts(changed, final=final)
            with self.assertRaises(TypeError):
                copy.deepcopy(evidence)
            for cloned in (copy.copy(evidence),):
                bridge = api.CategoryRollbackBridge(app._policy, fixture.raw_coordinator)
                with self.assertRaises((CategoryExecutionError, ReleaseOperationsError)):
                    bridge._adopt_completed_release(fixture.release_factory, cloned)
            bridge = api.CategoryRollbackBridge(app._policy, fixture.raw_coordinator)
            read = fixture.raw_coordinator._read_completed_action_provenance
            proof = read(task_id=probe.task_id, action_id=outcome.action_id)
            with mock.patch.object(fixture.raw_coordinator, "_read_completed_action_provenance",
                    side_effect=[proof, ValueError("second proof rejected")]):
                with self.assertRaisesRegex(ValueError, "second proof rejected"):
                    bridge._adopt_completed_release(fixture.release_factory, evidence)
            for final in (False, True):
                with self.assertRaises(CategoryExecutionError):
                    bridge.require_evidence_facts(facts, final=final)
            bridge = api.CategoryRollbackBridge(app._policy, fixture.raw_coordinator)
            with self.assertRaises((CategoryExecutionError, ReleaseOperationsError)):
                bridge._adopt_completed_release(ReleaseOperationsRegistryFactory.from_installation(), evidence)
            original_claim = fixture.leases.load_claim(outcome.claim_id)
            original_recovery = fixture.leases.recovery_attempt(outcome.claim_id)
            for field, changed in (("claim", {**original_claim, "state": "reconciled_effect_verified"}),
                    ("recovery", {**original_recovery, "compensation_action_id": outcome.action_id})):
                method = "load_claim" if field == "claim" else "recovery_attempt"
                with self.subTest(field=field), mock.patch.object(fixture.leases, method, return_value=changed):
                    with self.assertRaises(CategoryExecutionError):
                        app._rollback.require_evidence_facts(facts, final=True)
            self.assertEqual(self._repository_rows(fixture), rows)
            self.assertEqual(session._root.state(), physical)
            self.assertEqual(session._root.mutation_count, mutations)

    def test_completed_rollback_rechecks_recovery_at_precommit_without_replay(self):
        from graph_engineering.application.profile_execution import CategoryExecutionError

        with self._same_task_assessment(cold=True, partial=True, column="rollback") as values:
            _api, fixture, session, app, probe, target, candidate, evidence, outcome = values
            rows, physical = self._repository_rows(fixture), session._root.state()
            mutations = session._root.mutation_count
            recovery = fixture.leases.recovery_attempt(outcome.claim_id)
            active = False
            original = fixture.leases.recovery_attempt
            def changed(claim_id):
                result = original(claim_id)
                return {**result, "original_action_id": "action:foreign"} if active else result
            def fault(step):
                nonlocal active
                if step == "category-assessment.before-commit":
                    active = True
            app._fault = fault
            with mock.patch.object(fixture.leases, "recovery_attempt", side_effect=changed):
                with self.assertRaises(CategoryExecutionError):
                    app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            self.assertTrue(active)
            self.assertEqual(fixture.leases.recovery_attempt(outcome.claim_id), recovery)
            self.assertEqual(self._repository_rows(fixture), rows)
            self.assertEqual(session._root.state(), physical)
            self.assertEqual(session._root.mutation_count, mutations)

    def _assert_cold_partial_assessment(self, column):
        from graph_engineering.application.release_operations import restore_current_release_assessment

        with self._same_task_assessment(cold=True, partial=True, column=column) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, outcome = values
            prior_mutations = session._root.mutation_count
            prior_actions = len(fixture.raw_coordinator._issued_outcomes)
            prior_journal = fixture.journal.load(outcome.action_id)
            prior_claim = fixture.leases.load_claim(outcome.claim_id)
            receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            self.assertEqual(session._root.mutation_count, prior_mutations)
            self.assertEqual(len(fixture.raw_coordinator._issued_outcomes), prior_actions)
            self.assertEqual(fixture.journal.load(outcome.action_id), prior_journal)
            self.assertEqual(fixture.leases.load_claim(outcome.claim_id), prior_claim)
            expected = session._root.state()
            self.assertEqual(expected["generation"], 0)
            self.assertIsNone(expected["staged_artifact_digest"])
            session.close()
            before = self._repository_rows(fixture)
            handle = restore_current_release_assessment(task_application=app._task_application,
                runtime=app._runtime, policy=app._policy, release_factory=fixture.release_factory,
                object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
            read_scope = handle._record()[1]
            try:
                result = handle.query()
                self.assertEqual(result["assessment_bytes"], receipt.assessment.to_bytes())
                self.assertEqual(result["assessment"]["column_id"], column)
                projection = result["assessment"]["release_operations_projection"]
                self.assertEqual(projection["outcome"], "partial-deploy-restored")
                state_key = "rollback_state" if column == "rollback" else "expected_state"
                self.assertEqual(dict(result["source_projection"]["target"][state_key]), expected)
                if column == "rollback":
                    self.assertNotEqual(result["source_projection"]["target"]["expected_state"],
                                        result["source_projection"]["target"]["rollback_state"])
                self.assertEqual(projection["rollback_observation"]["artifact_manifest_digest"],
                                 expected["active_artifact_digest"])
            finally:
                if not read_scope.closed:
                    handle.close()
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)

    def test_cold_current_assessment_handle_revalidates_without_legacy_reads_or_writes(self):
        import copy
        import pickle
        from graph_engineering.application.release_operations import restore_current_release_assessment
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.storage.repository import TaskRepository
        from graph_engineering.storage.objects import ObjectRepository
        from graph_engineering.storage.actions import ActionJournalRepository

        with self._same_task_assessment(cold=True) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            before = self._repository_rows(fixture)
            physical = {p.name: p.read_bytes() for p in session._root.path.iterdir()} if hasattr(session._root, "path") else {
                p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            factory = fixture.release_factory
            factory._cold_artifact_authority()
            issued = (len(factory._issued), len(fixture.raw_coordinator._issued_outcomes))
            blocked = lambda *a, **k: (_ for _ in ()).throw(AssertionError("legacy or write call during cold recovery"))
            with ExitStack() as checks:
                for kind, methods in ((TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                        (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                        (ActionJournalRepository, ("load", "find_prepared"))):
                    for name in methods:
                        checks.enter_context(mock.patch.object(kind, name, side_effect=blocked))
                checks.enter_context(mock.patch.object(type(app._task_application), "runtime_show", side_effect=blocked))
                checks.enter_context(mock.patch.object(fixture.raw_coordinator, "_read_action_authority", side_effect=blocked))
                handle = restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy, release_factory=factory,
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                owner = handle._record()[1].budget
                try:
                    first = handle.query()
                    retained = (owner.retained_units, owner.retained_bytes)
                    second = handle.query()
                    self.assertEqual(first["assessment_bytes"], second["assessment_bytes"])
                    self.assertEqual(first["assessment_bytes"], canonical_bytes(first["assessment"]))
                    self.assertEqual(first["observation_epoch"], second["observation_epoch"])
                    self.assertGreater(second["observation_revision"], first["observation_revision"])
                    self.assertEqual((owner.retained_units, owner.retained_bytes), retained)
                    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                        with self.assertRaises(TypeError): operation(handle)
                    clone = object.__new__(type(handle))
                    with self.assertRaises(ReleaseOperationsError): clone.query()
                    self.assertEqual((len(factory._issued), len(fixture.raw_coordinator._issued_outcomes)), issued)
                    with self.assertRaises(ReleaseOperationsError): factory.require_current(handle)
                finally: handle.close()
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                with self.assertRaises(ReleaseOperationsError): handle.query()
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
            self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)

    def _assert_cold_semantic_rejection(self, error, expected):
        from graph_engineering.core.contracts.errors import ContractError

        pending, seen, messages = [error], set(), []
        while pending:
            current = pending.pop()
            if current is None or id(current) in seen:
                continue
            seen.add(id(current))
            self.assertFalse(isinstance(current, AssertionError),
                "an assertion or forbidden call cannot prove a semantic rejection")
            self.assertFalse(isinstance(current, ContractError)
                and current.detail.code in {"E_LIMIT", "E_BUDGET"},
                "a resource failure cannot prove a semantic rejection: " + repr(getattr(current, "detail", None)))
            messages.append(str(current))
            pending.extend((current.__cause__, current.__context__))
        self.assertTrue(any(expected in message for message in messages), messages)

    def test_cold_source_negative_oracle_rejects_wrapped_resource_failures(self):
        from graph_engineering.core.contracts.errors import ContractError, ErrorDetail

        for code in ("E_LIMIT", "E_BUDGET"):
            for link in ("__cause__", "__context__"):
                with self.subTest(code=code, link=link):
                    wrapper = ValueError("expected semantic rejection")
                    setattr(wrapper, link, ContractError(ErrorDetail(code, "limit", "test", "test")))
                    with self.assertRaisesRegex(AssertionError, "resource failure"):
                        self._assert_cold_semantic_rejection(wrapper, "expected semantic rejection")
        with self.assertRaises(AssertionError):
            self._assert_cold_semantic_rejection(ValueError("unrelated rejection"), "expected semantic rejection")
        for link in ("__cause__", "__context__"):
            guard = AssertionError("forbidden cold call during cleanup")
            setattr(guard, link, ValueError("expected semantic rejection"))
            with self.assertRaisesRegex(AssertionError, "assertion"):
                self._assert_cold_semantic_rejection(guard, "expected semantic rejection")
            wrapped = ValueError("outer failure")
            setattr(wrapped, link, guard)
            with self.assertRaisesRegex(AssertionError, "assertion"):
                self._assert_cold_semantic_rejection(wrapped, "expected semantic rejection")

    def test_cold_source_accepts_manifest_bound_opaque_control_like_bodies(self):
        from tests.support import wp04a_artifacts as artifacts
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.contracts.digest import raw_digest, semantic_digest

        original = artifacts.manifest_document
        unrelated_record = artifacts.loaded_golden("implementation")[0]
        examples = (b'{ "opaque": true }\n', b'{"unfinished":',
            b'{"duplicate":1,"duplicate":2}',
            canonical_bytes({"artifact_digest": "opaque", "manifest_id": "opaque",
                             "record_kind": "opaque-body-data"}),
            canonical_bytes(unrelated_record))
        seen = []
        def opaque_manifest(*args, **kwargs):
            _body, manifest = original(*args, **kwargs)
            body = examples[len(seen) % len(examples)]
            seen.append(body)
            entry = manifest["entries"][0]
            entry["selector"]["end"] = len(body)
            entry["extracted_body_digest"] = raw_digest(body)
            entry["entry_digest"] = semantic_digest(
                {key: value for key, value in entry.items() if key != "entry_digest"},
                contract_type="urn:gew:contract:logical-body-entry",
                projection_id=artifacts.IDENTITY_PROJECTION, schema_id=artifacts.LOGICAL_BODY_MANIFEST_SCHEMA)
            manifest["physical_body_digest"] = raw_digest(body)
            manifest["manifest_digest"] = semantic_digest(
                {key: value for key, value in manifest.items() if key != "manifest_digest"},
                contract_type="urn:gew:contract:logical-body-manifest",
                projection_id=artifacts.IDENTITY_PROJECTION, schema_id=artifacts.LOGICAL_BODY_MANIFEST_SCHEMA)
            return body, manifest
        with mock.patch.object(artifacts, "manifest_document", side_effect=opaque_manifest):
            self._check_cold_producer_sources(substitutions=False)
        self.assertEqual(set(seen), set(examples))

    def test_cold_producer_commits_complete_artifact_and_runner_sources(self):
        self._check_cold_producer_sources()

    def test_cold_revision_control_rejects_missing_ambiguous_and_false_lineage(self):
        self._check_cold_producer_sources(column="revise")

    def test_cold_drift_control_rejects_missing_ambiguous_and_foreign_target(self):
        self._check_cold_producer_sources(column="drift")

    def _check_cold_producer_sources(self, *, substitutions=True, column="normal"):
        import json
        from graph_engineering.core.artifacts.records import RECORD_FIELDS
        from graph_engineering.application.profile_execution import _validate_cold_artifact_record
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with self._same_task_assessment(cold=True, column=column) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            contracts, schemas, context = fixture.release_factory._cold_artifact_authority()
            baselines = dict(fixture.raw_coordinator._issuer.read_task_state(probe.task_id).state["binding"]["baselines"])
            budget = _RecoveryReadBudget((context, app._task_application._context,
                fixture.repository._action_journal._context), task_id=probe.task_id,
                command_scope=fixture.repository.command_scope)
            before = self._repository_rows(fixture)
            try:
                with budget.bind(ports=(fixture.repository, fixture.objects, app._task_application)):
                    capture = fixture.repository.read_category_recovery_sources(probe.task_id, phase="sources")
                    objects = dict(capture["objects"])
                    documents = {}
                    for ref, body in objects.items():
                        try: documents[ref] = json.loads(body)
                        except (ValueError, UnicodeError): pass
                    full = {ref: record for ref, record in documents.items()
                            if type(record) is dict and set(record) == RECORD_FIELDS
                            and record["task_id"] == probe.task_id}
                    self.assertEqual(len(full), len(app._policy.artifact_contract_ids) + 1)
                    with app._task_application._cold_task_view(capture, policy=app._policy, runtime=app._runtime) as view:
                        for output in view.runner_state["node_outputs"].values():
                            self.assertEqual(len(output["evidence_refs"]), 1)
                            self.assertEqual(full[output["evidence_refs"][0]]["body_digest"], output["body_digest"])
                    for ref in full:
                        validated = _validate_cold_artifact_record(record_ref=ref, documents=documents, objects=objects,
                            task_id=probe.task_id, owner_id=app._runtime.owner_id,
                            baselines=baselines,
                            target={"task_id": probe.task_id, "target_id": target.target_id, "target_digest": target.target_digest},
                            contracts=contracts, schemas=schemas, context=context)
                        budget.release_projection(validated)
                    from graph_engineering.application import profile_execution as module
                    closure = module._validate_cold_category_sources(capture=capture,
                        task_application=app._task_application, runtime=app._runtime, policy=app._policy,
                        contracts=contracts, schemas=schemas, context=context,
                        action_target={"task_id": probe.task_id, "target_id": target.target_id, "target_digest": target.target_digest},
                        action_baselines=baselines)
                    self.assertEqual(closure["assessment"]["task_id"], probe.task_id)
                    self.assertEqual(dict(closure["target"]["expected_state"]), target.expected_state)
                    budget.release_projection(closure)
                    import copy
                    from types import MappingProxyType
                    from graph_engineering.core.contracts.canonical import canonical_bytes, canonical_byte_length
                    from graph_engineering.core.contracts.digest import semantic_digest, raw_digest
                    from graph_engineering.core.contracts.immutable import freeze, thaw
                    first_ref = next(iter(capture["snapshot"]["runner"]["node_outputs"].values()))["evidence_refs"][0]
                    first_record = full[first_ref]
                    category_ref = next(ref for ref, record in documents.items()
                        if type(record) is dict and record.get("record_kind") == "category-artifact-record-v1"
                        and all(record[key] == first_record[key] for key in
                                ("task_id", "artifact_id", "contract_id", "body_digest", "author_id", "reviewer_id")))
                    manifest_ref = next(ref for ref, record in documents.items()
                        if type(record) is dict and record.get("manifest_id") == first_record["logical_body_ref"]["manifest_id"])
                    physical_ref = next(ref for ref, body in objects.items()
                        if raw_digest(body) == documents[manifest_ref]["physical_body_digest"])
                    runner_body_digests = {item["body_digest"] for item in capture["snapshot"]["runner"]["node_outputs"].values()}
                    runner_body_digests.update(item["body_digest"] for item in capture["snapshot"]["runner"]["review_history"])
                    unused_category_ref = next(ref for ref, record in documents.items()
                        if type(record) is dict and record.get("record_kind") == "category-artifact-record-v1"
                        and record["body_digest"] not in runner_body_digests)
                    unused_record_ref = next(ref for ref, record in full.items()
                        if all(record[key] == documents[unused_category_ref][key] for key in
                               ("task_id", "artifact_id", "contract_id", "body_digest", "author_id", "reviewer_id")))
                    expected_errors = {
                        "missing-record": "cold category record has no unique accepted body source",
                        "missing-manifest": "cold artifact manifest is absent or ambiguous",
                        "missing-physical": "cold artifact physical body is absent or ambiguous",
                        "duplicate-record": "cold category record has no unique accepted body source",
                        "category-extra-field": "cold category artifact contract closure differs",
                        "category-actor": "cold category record has no unique accepted body source",
                        "category-body-label": "cold category record has no unique accepted body source",
                        "output-evidence": "cold runner output has no explicit accepted raw source",
                        "output-body-label": "cold runner body is absent or ambiguous",
                        "output-reviewer": "cold runner body is absent or ambiguous",
                        "attempt-boolean": "output attempt is invalid",
                        "review-run": "cold review lineage or attempt order changed",
                        "review-order": "cold review lineage or attempt order changed",
                        "unknown-scenario": "category boundary scenario is not an approved PASS member",
                        "negative-scenario": "category boundary scenario is not an approved PASS member",
                        "noncanonical-assessment": "cold category assessment is unsupported or changed",
                        "malformed-assessment": "cold category assessment is unsupported or changed",
                        "opaque-target-fragment": None,
                        "opaque-category-fragment": None,
                        "opaque-evidence-fragment": None,
                        "opaque-manifest-alias": None,
                        "opaque-target-invalid-digest": None,
                        "opaque-category-invalid-digest": None,
                        "opaque-evidence-invalid-digest": None,
                        "opaque-artifact-invalid-digest": None,
                        "opaque-target-invalid-binding": None,
                        "opaque-category-invalid-binding": None,
                        "opaque-evidence-invalid-binding": None,
                        "opaque-artifact-invalid-binding": None,
                        "duplicate-manifest": "cold artifact manifest is absent or ambiguous",
                        "anchored-invalid-record": "cold artifact semantic record digest changed",
                        "missing-record-invalid-lookalike": "cold category record has no unique accepted body source",
                    }
                    control_ref = None
                    if column != "normal":
                        control_kind = {"revise": "category-revision-record-v1",
                                        "drift": "category-drift-record-v1"}[column]
                        control_ref = next(ref for ref, record in documents.items()
                            if type(record) is dict and record.get("record_kind") == control_kind)
                        expected_errors = {change: "cold column control is absent or ambiguous"
                            for change in ("control-missing", "control-extra", "control-duplicate",
                                "control-task", "control-snapshot", "control-epoch")}
                        expected_errors["control-semantic"] = (
                            "cold revision body or budget control changed" if column == "revise"
                            else "cold drift target control changed")
                    for change in expected_errors if substitutions else ():
                        with self.subTest(change=change):
                            copies_runner = (change.startswith(("output-", "attempt-", "review-"))
                                or change.endswith("scenario") or change == "anchored-invalid-record")
                            scratch_size = 2 * len(objects) + len(objects[first_ref]) + len(objects[category_ref])
                            if control_ref is not None:
                                scratch_size += 2 * len(objects[control_ref])
                            if copies_runner:
                                scratch_size += canonical_byte_length(capture["snapshot"])
                            if change.endswith("scenario"):
                                scratch_size += canonical_byte_length(capture["events"]) + len(capture["assessment_body"])
                            if change.startswith("opaque-"):
                                scratch_size += 2 * len(objects[unused_record_ref])
                            with budget.reserve(context, units=8 * scratch_size, byte_count=4 * scratch_size,
                                                source_id="test-owned-mutant") as reservation:
                                mutant = dict(capture)
                                sources = dict(objects)
                                snapshot = thaw(capture["snapshot"]) if copies_runner else None
                                runner = snapshot["runner"] if snapshot is not None else None
                                output = next(iter(runner["node_outputs"].values())) if runner is not None else None
                                replacement = None
                                if change.startswith("control-"):
                                    record = copy.deepcopy(documents[control_ref])
                                    if change != "control-duplicate":
                                        sources.pop(control_ref)
                                    if change == "control-extra": record["unexpected"] = True
                                    elif change == "control-task": record["task_id"] = "foreign-task"
                                    elif change == "control-snapshot": record["snapshot_digest"] = "sha256-jcs-v1:" + "0" * 64
                                    elif change == "control-epoch": record["invalidation_epoch"] = True
                                    elif change in ("control-duplicate", "control-semantic"):
                                        if column == "revise": record["budget_remaining"] = False
                                        else: record["target_digest"] = "sha256-jcs-v1:" + "0" * 64
                                    if change != "control-missing":
                                        category_fixture.resign_durable_record(record)
                                        body = canonical_bytes(record)
                                        sources[module.category_object_digest(body)] = body
                                elif change in ("missing-record", "missing-manifest", "missing-physical"):
                                    sources.pop({"missing-record": first_ref, "missing-manifest": manifest_ref,
                                                 "missing-physical": physical_ref}[change])
                                elif change in ("anchored-invalid-record", "missing-record-invalid-lookalike"):
                                    invalid = copy.deepcopy(first_record)
                                    invalid["artifact_digest"] = "sha256-jcs-v1:" + "0" * 64
                                    sources.pop(first_ref)
                                    body = canonical_bytes(invalid)
                                    invalid_ref = module.category_object_digest(body)
                                    sources[invalid_ref] = body
                                    if runner is not None:
                                        for item in runner["node_outputs"].values():
                                            item["evidence_refs"] = [invalid_ref if ref == first_ref else ref for ref in item["evidence_refs"]]
                                elif change == "duplicate-record":
                                    duplicate = copy.deepcopy(first_record)
                                    duplicate["created_at"] = "2026-09-21T00:00:00Z"
                                    duplicate["artifact_digest"] = semantic_digest(
                                        {key: value for key, value in duplicate.items() if key != "artifact_digest"},
                                        contract_type="urn:gew:contract:artifact-record",
                                        projection_id="urn:gew:digest-projection:identity:1.0.0",
                                        schema_id="urn:gew:schema:artifact-record:1.0.0")
                                    body = canonical_bytes(duplicate)
                                    sources[module.category_object_digest(body)] = body
                                elif change == "duplicate-manifest":
                                    from graph_engineering.core.artifacts.manifest import LogicalBodyManifest, LOGICAL_BODY_MANIFEST_SCHEMA
                                    duplicate = copy.deepcopy(documents[manifest_ref])
                                    duplicate["mode"] = "compact"
                                    duplicate["manifest_digest"] = semantic_digest(
                                        {key: value for key, value in duplicate.items() if key != "manifest_digest"},
                                        contract_type="urn:gew:contract:logical-body-manifest",
                                        projection_id="urn:gew:digest-projection:identity:1.0.0", schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
                                    LogicalBodyManifest.from_dict(duplicate, objects[physical_ref], schema_registry=schemas, context=context)
                                    body = canonical_bytes(duplicate)
                                    sources[module.category_object_digest(body)] = body
                                elif change.startswith("opaque-"):
                                    from graph_engineering.core.artifacts.manifest import LogicalBodyManifest, LOGICAL_BODY_MANIFEST_SCHEMA
                                    record = copy.deepcopy(full[unused_record_ref])
                                    if change == "opaque-target-fragment":
                                        opaque = {"record_kind": "category-target-contract-v1", "task_id": probe.task_id,
                                                  "target_id": target.target_id}
                                    elif change == "opaque-category-fragment":
                                        opaque = {"record_kind": "category-artifact-record-v1", "task_id": probe.task_id,
                                                  "contract_id": record["contract_id"]}
                                    elif change == "opaque-evidence-fragment":
                                        opaque = {"record_kind": "category-column-evidence-v1", "task_id": probe.task_id,
                                                  "column_id": "normal"}
                                    elif "-invalid-" in change:
                                        kind = change.split("-")[1]
                                        source_record = (first_record if kind == "artifact" else next(value for value in documents.values()
                                            if type(value) is dict and value.get("record_kind") == {
                                                "target": "category-target-contract-v1",
                                                "category": "category-artifact-record-v1",
                                                "evidence": "category-column-evidence-v1"}[kind]
                                            and (kind != "evidence" or value.get("column_id") == "normal")))
                                        opaque = copy.deepcopy(source_record)
                                        digest_key = "artifact_digest" if kind == "artifact" else "record_digest"
                                        if change.endswith("digest"):
                                            opaque[digest_key] = "sha256-jcs-v1:" + "0" * 64
                                        else:
                                            if kind == "target": opaque["resource_id"] = " invalid-resource "
                                            elif kind == "category": opaque["status"] = "candidate"
                                            elif kind == "evidence": opaque["task_revision"] += 1
                                            else: opaque["baseline_digests"]["intent"] = "sha256-jcs-v1:" + "0" * 64
                                            if kind == "artifact":
                                                opaque[digest_key] = semantic_digest(
                                                    {key: value for key, value in opaque.items() if key != digest_key},
                                                    contract_type="urn:gew:contract:artifact-record",
                                                    projection_id="urn:gew:digest-projection:identity:1.0.0",
                                                    schema_id="urn:gew:schema:artifact-record:1.0.0")
                                            else: category_fixture.resign_durable_record(opaque)
                                    else:
                                        opaque = copy.deepcopy(documents[manifest_ref])
                                        opaque["manifest_digest"] = "sha256-jcs-v1:" + "0" * 64
                                    old_manifest_ref = next(ref for ref, value in documents.items()
                                        if type(value) is dict and value.get("manifest_id") == record["logical_body_ref"]["manifest_id"])
                                    manifest = copy.deepcopy(documents[old_manifest_ref])
                                    old_physical_ref = next(ref for ref, body in objects.items()
                                        if raw_digest(body) == manifest["physical_body_digest"])
                                    physical = canonical_bytes(opaque)
                                    entry = manifest["entries"][0]
                                    entry["selector"] = {"start": 0, "end": len(physical)}
                                    entry["extracted_body_digest"] = raw_digest(physical)
                                    entry["entry_digest"] = semantic_digest(
                                        {key: value for key, value in entry.items() if key != "entry_digest"},
                                        contract_type="urn:gew:contract:logical-body-entry",
                                        projection_id="urn:gew:digest-projection:identity:1.0.0", schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
                                    manifest["physical_body_digest"] = raw_digest(physical)
                                    manifest["manifest_digest"] = semantic_digest(
                                        {key: value for key, value in manifest.items() if key != "manifest_digest"},
                                        contract_type="urn:gew:contract:logical-body-manifest",
                                        projection_id="urn:gew:digest-projection:identity:1.0.0", schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
                                    loaded = LogicalBodyManifest.from_dict(manifest, physical, schema_registry=schemas, context=context)
                                    record["logical_body_ref"].update(entry_digest=entry["entry_digest"],
                                        extracted_body_digest=entry["extracted_body_digest"])
                                    record["body_digest"] = loaded.semantic_body_digest(record["artifact_id"], record["semantic_fields"], context)
                                    for key in ("validation_records", "review_records", "approval_records"):
                                        for item in record[key]: item["body_digest"] = record["body_digest"]
                                    record["artifact_digest"] = semantic_digest(
                                        {key: value for key, value in record.items() if key != "artifact_digest"},
                                        contract_type="urn:gew:contract:artifact-record",
                                        projection_id="urn:gew:digest-projection:identity:1.0.0",
                                        schema_id="urn:gew:schema:artifact-record:1.0.0")
                                    category = copy.deepcopy(documents[unused_category_ref])
                                    category["body_digest"] = record["body_digest"]
                                    category_fixture.resign_durable_record(category)
                                    for ref in (unused_record_ref, old_manifest_ref, old_physical_ref, unused_category_ref):
                                        sources.pop(ref)
                                    for body in (physical, canonical_bytes(manifest), canonical_bytes(record), canonical_bytes(category)):
                                        sources[module.category_object_digest(body)] = body
                                    replacement = (module.category_object_digest(canonical_bytes(record)),
                                                   module.category_object_digest(physical), record["body_digest"])
                                elif change.startswith("category-"):
                                    category = copy.deepcopy(documents[category_ref])
                                    if change == "category-extra-field": category["extra"] = True
                                    elif change == "category-actor": category["reviewer_id"] = "foreign-reviewer"
                                    else: category["body_digest"] = "sha256-jcs-v1:" + first_ref.removeprefix("sha256:")
                                    category_fixture.resign_durable_record(category)
                                    sources.pop(category_ref)
                                    body = canonical_bytes(category)
                                    sources[module.category_object_digest(body)] = body
                                elif change == "output-evidence": output["evidence_refs"] = []
                                elif change == "output-body-label": output["body_digest"] = "sha256-jcs-v1:" + first_ref.removeprefix("sha256:")
                                elif change == "output-reviewer": output["reviewer_id"] = "foreign-reviewer"
                                elif change == "attempt-boolean": output["attempt"] = True
                                elif change == "review-run": runner["review_history"][-2]["run_id"] = "unrelated-run"
                                elif change == "review-order": runner["review_history"][-2]["attempt"] = 3
                                elif change.endswith("scenario"):
                                    from graph_engineering.core.graph.state import SNAPSHOT_PROJECTION
                                    from graph_engineering.storage.repository import event_digest, semantic_record_digest
                                    old_ref = capture["assessment_ref"]["source_ref"]
                                    assessment = json.loads(sources.pop(old_ref))
                                    assessment["scenario_id"] = ("unknown-cold-scenario-P" if change == "unknown-scenario"
                                        else next(item for item in app._policy.category_boundary_case_ids if item.endswith("-R")))
                                    selector = {"schema_version": "1.0.0", "request_id": assessment["request_id"],
                                        "task_id": probe.task_id, "column_id": "normal", "scenario_id": assessment["scenario_id"],
                                        "target_id": target.target_id}
                                    assessment["request_digest"] = module._selector_digest(selector)
                                    assessment["assessment_digest"] = module._value_digest(
                                        {key: value for key, value in assessment.items() if key != "assessment_digest"},
                                        "category-completion-assessment")
                                    body = canonical_bytes(assessment)
                                    new_ref = module.category_object_digest(body)
                                    sources[new_ref] = body
                                    evidence_ref = thaw(capture["assessment_ref"])
                                    evidence_ref.update(source_ref=new_ref, digest=assessment["assessment_digest"])
                                    mutant.update(assessment_ref=freeze(evidence_ref), assessment_body=body)
                                    snapshot["domain"]["evidence"] = [evidence_ref if item["source_ref"] == old_ref else item
                                        for item in snapshot["domain"]["evidence"]]
                                    snapshot["domain"]["snapshot_digest"] = semantic_digest(
                                        {key: value for key, value in snapshot["domain"].items() if key != "snapshot_digest"},
                                        contract_type=SNAPSHOT_PROJECTION.contract_type,
                                        projection_id=SNAPSHOT_PROJECTION.projection_id, schema_id=SNAPSHOT_PROJECTION.schema_id)
                                    events = [thaw(item) for item in capture["events"]]
                                    events[-1]["event"]["payload"]["evidence_ref"] = evidence_ref
                                    events[-1]["event"]["event_digest"] = event_digest(events[-1]["event"])
                                    events[-1]["transaction_head_digest"] = events[-1]["event"]["event_digest"]
                                    mutant["events"] = tuple(freeze(item) for item in events)
                                    mutant["task"] = freeze({**dict(capture["task"]),
                                        "head_digest": events[-1]["event"]["event_digest"],
                                        "snapshot_digest": semantic_record_digest({"contract": "repository-snapshot-v1", "value": snapshot})})
                                elif change.endswith("assessment"):
                                    old_ref = capture["assessment_ref"]["source_ref"]
                                    sources[old_ref] = (b" " + sources[old_ref] if change == "noncanonical-assessment"
                                                       else b'{"broken":')
                                mutant["objects"] = tuple(sources.items())
                                if snapshot is not None:
                                    mutant["snapshot"] = freeze(snapshot)
                                mutant = MappingProxyType(mutant)
                                reservation.transfer(mutant)
                                try:
                                    def validate_mutant():
                                        return module._validate_cold_category_sources(capture=mutant,
                                            task_application=app._task_application, runtime=app._runtime, policy=app._policy,
                                            contracts=contracts, schemas=schemas, context=context,
                                            action_target={"task_id": probe.task_id, "target_id": target.target_id,
                                                           "target_digest": target.target_digest}, action_baselines=baselines)
                                    if expected_errors[change] is None:
                                        closure = validate_mutant()
                                        try:
                                            self.assertIn(replacement, [(item["record_ref"], item["physical_object_ref"], item["body_digest"])
                                                for item in closure["artifacts"]])
                                        finally:
                                            budget.release_projection(closure)
                                    else:
                                        with self.assertRaises(ValueError) as rejection:
                                            validate_mutant()
                                        self._assert_cold_semantic_rejection(rejection.exception, expected_errors[change])
                                finally:
                                    budget.release_projection(mutant)
                    from graph_engineering.core.contracts import strict_json
                    from graph_engineering.core.contracts.errors import ContractError, ErrorDetail
                    for code in ("E_LIMIT", "E_BUDGET"):
                        before_failure = (budget.retained_units, budget.retained_bytes)
                        failure = ContractError(ErrorDetail(code, "limit", "injected-resource", "cold-source"))
                        with mock.patch.object(strict_json, "parse_json", side_effect=failure):
                            with self.assertRaises(ContractError) as rejected:
                                module._validate_cold_category_sources(capture=capture,
                                    task_application=app._task_application, runtime=app._runtime, policy=app._policy,
                                    contracts=contracts, schemas=schemas, context=context,
                                    action_target={"task_id": probe.task_id, "target_id": target.target_id,
                                                   "target_digest": target.target_digest}, action_baselines=baselines)
                        self.assertIs(rejected.exception, failure)
                        self.assertEqual((budget.retained_units, budget.retained_bytes), before_failure)
                        with mock.patch.object(type(schemas), "validate", side_effect=failure):
                            with self.assertRaises(ContractError) as rejected:
                                _validate_cold_artifact_record(record_ref=first_ref, documents=documents, objects=objects,
                                    task_id=probe.task_id, owner_id=app._runtime.owner_id,
                                    baselines=baselines,
                                    target={"task_id": probe.task_id, "target_id": target.target_id,
                                            "target_digest": target.target_digest},
                                    contracts=contracts, schemas=schemas, context=context)
                        self.assertIs(rejected.exception, failure)
                        self.assertEqual((budget.retained_units, budget.retained_bytes), before_failure)
                    budget.release_projection(capture)
            finally:
                budget.close()
            self.assertTrue(all(item._temporary_units == 0 for item in budget.contexts))
            self.assertEqual(self._repository_rows(fixture), before)

    def test_cold_task_view_uses_only_captured_materialization_and_events(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from graph_engineering.application.tasks import ApplicationError

        with self._same_task_assessment() as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            with fixture.repository._factory.open("application") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM object_references WHERE task_id=? AND transaction_id=?",
                        (probe.task_id, "test-only-category-tamper"))
            task = app._task_application
            contexts = (fixture.repository._action_journal._context, task._context)
            budget = _RecoveryReadBudget(contexts, task_id=probe.task_id,
                command_scope=fixture.repository.command_scope)
            before = self._repository_rows(fixture)
            try:
                with budget.bind(ports=(task, fixture.repository, fixture.objects)):
                    capture = fixture.repository.read_category_recovery_sources(probe.task_id, phase="sources")
                    with ExitStack() as guards:
                        for port, names in ((task, ("runtime_show", "_materialization_for_graph_ref", "_issue_materialization_reference")),
                                            (fixture.repository, ("load", "replay", "referenced_objects", "category_source_seal")),
                                            (fixture.objects, ("get",))):
                            for name in names:
                                guards.enter_context(mock.patch.object(port, name,
                                    side_effect=AssertionError("legacy source resolver")))
                        with task._cold_task_view(capture, policy=app._policy, runtime=app._runtime) as view:
                            self.assertEqual(view.task_id, probe.task_id)
                            self.assertEqual(view.snapshot.lifecycle, "completed")
                            self.assertEqual(view.snapshot.task_revision, receipt.assessment.task_revision + 1)
                        with self.assertRaises(ApplicationError):
                            with task._cold_task_view(dict(capture), policy=app._policy, runtime=app._runtime):
                                self.fail("unowned caller projection was accepted")
                    budget.release_projection(capture)
            finally:
                budget.close()
            self.assertTrue(all(context._temporary_units == 0 for context in set(contexts)))
            self.assertEqual(self._repository_rows(fixture), before)

    def test_cold_source_exact_aggregate_and_real_overlapping_security_read(self):
        from collections.abc import Mapping
        import sys
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        with self._same_task_assessment() as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            with fixture.repository._factory.open("application") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM object_references WHERE task_id=? AND transaction_id=?",
                        (probe.task_id, "test-only-category-tamper"))
            reader = fixture.raw_coordinator
            context = reader._journal._context
            other = security_context()
            profiles = (context.profile, other.profile)
            original_security_context = reader._issuer._context
            reader._issuer._context = other
            before = self._repository_rows(fixture)
            context.acquire_temporary(3, source_id="prior", operation_path=())
            other.acquire_temporary(5, source_id="prior", operation_path=())
            raw_rows, raw_json, canonical = module._recovery_rows, module._recovery_json, module.canonical_json
            primitive = reader._repository._read_provenance_object
            ports = (reader, reader._repository, reader._objects, reader._journal,
                     reader._issuer, reader._issuer._repository)
            observed_kinds, observed_peak = set(), [0]

            def trial(ceiling, phase, *, security=False, only_security=False, observe=False):
                context.profile = replace(profiles[0], limits={**profiles[0].limits, "result_bytes": ceiling})
                other.profile = replace(profiles[1], limits={**profiles[1].limits,
                    "result_bytes": min(profiles[1].limits["result_bytes"], ceiling + 64)})
                owner = module._RecoveryReadBudget((context, other), task_id=probe.task_id,
                    command_scope=reader._repository.command_scope)
                alive = []
                first = result = None
                def inspect_buffers(kind, *extra):
                    if not observe:
                        return
                    seen = set()
                    def payload(value):
                        if id(value) in seen:
                            return 0
                        seen.add(id(value))
                        if type(value) is bytes:
                            return len(value)
                        if type(value) is str:
                            return len(value.encode("utf-8"))
                        if isinstance(value, Mapping):
                            return sum(payload(k) + payload(v) for k, v in value.items())
                        if type(value) in (list, tuple):
                            return sum(payload(v) for v in value)
                        return 8 if type(value) is int else 0
                    values = [*alive, *extra]
                    frame = sys._getframe(1)
                    while frame is not None:
                        if frame.f_code.co_filename == module.__file__:
                            for name in ("encoded", "body", "value", "objects", "captured"):
                                if name in frame.f_locals:
                                    values.append(frame.f_locals[name])
                        frame = frame.f_back
                    actual = sum(payload(value) for value in values)
                    observed_kinds.add(kind)
                    observed_peak[0] = max(observed_peak[0], actual)
                    self.assertGreaterEqual(owner.retained_bytes, actual,
                        "live SQL/raw/parsed/canonical payload exceeds the independently measured reservation")
                    self.assertGreaterEqual(context._temporary_units + other._temporary_units - 8,
                        owner.retained_units)
                @contextmanager
                def rows(*args, **kwargs):
                    with raw_rows(*args, **kwargs) as value:
                        alive.append(value)
                        try:
                            inspect_buffers("sql")
                            yield value
                        finally:
                            alive.pop()
                @contextmanager
                def parsed(*args, **kwargs):
                    with raw_json(*args, **kwargs) as value:
                        alive.append(value)
                        try:
                            inspect_buffers("parsed")
                            yield value
                        finally:
                            alive.pop()
                def serialized(value):
                    text = canonical(value)
                    inspect_buffers("serialization", value, text)
                    return text
                def cas(*args, **kwargs):
                    body = primitive(*args, **kwargs)
                    inspect_buffers("raw", body)
                    return body
                try:
                    with owner.bind(ports=ports), ExitStack() as guards:
                        if observe:
                            guards.enter_context(mock.patch.object(module, "_recovery_rows", side_effect=rows))
                            guards.enter_context(mock.patch.object(module, "_recovery_json", side_effect=parsed))
                            guards.enter_context(mock.patch.object(module, "canonical_json", side_effect=serialized))
                            guards.enter_context(mock.patch.object(reader._repository, "_read_provenance_object", side_effect=cas))
                        if security:
                            first = reader._issuer.read_task_state(probe.task_id)
                            self.assertGreater(owner.retained_bytes, 0)
                        if not only_security:
                            result = reader._repository.read_category_recovery_sources(probe.task_id, phase=phase)
                    return True
                except (ContractError, module.RepositoryIntegrityError):
                    return False
                finally:
                    if result is not None:
                        owner.release_projection(result)
                    if first is not None:
                        owner.release_projection(first)
                    owner.close()
                    self.assertEqual((owner.retained_bytes, owner.retained_units), (0, 0))
                    self.assertEqual((context._temporary_units, other._temporary_units), (3, 5))
                    self.assertTrue(all(not hasattr(port, "_recovery_read_budget") for port in ports))
                    reader._retained_scope(require_idle=True)

            try:
                for phase in ("locator", "sources"):
                    low, high = 1, profiles[0].limits["result_bytes"]
                    self.assertTrue(trial(high, phase))
                    while low < high:
                        middle = (low + high) // 2
                        if trial(middle, phase):
                            high = middle
                        else:
                            low = middle + 1
                    with self.subTest(phase=phase, exact_shared_bytes=high):
                        self.assertTrue(trial(high, phase, observe=True))
                        self.assertFalse(trial(high - 1, phase))
                        # Both real operations fit alone, with distinct contexts
                        # and prior reservations. Keeping the first result alive
                        # makes the complete second operation exceed the bound.
                        self.assertTrue(trial(high, phase, security=True, only_security=True))
                        self.assertFalse(trial(high, phase, security=True))
                self.assertEqual(observed_kinds, {"sql", "parsed", "serialization", "raw"})
                self.assertGreater(observed_peak[0], 0)
                self.assertEqual(self._repository_rows(fixture), before)
            finally:
                context.profile, other.profile = profiles
                reader._issuer._context = original_security_context
                context.release_temporary(3)
                other.release_temporary(5)

    def test_cold_source_sql_and_cas_boundaries_preserve_rows_and_cleanup(self):
        import os
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module

        with self._same_task_assessment() as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            receipt = app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            session.close()
            with fixture.repository._factory.open("application") as connection:
                with connection.transaction():
                    connection.execute("DELETE FROM object_references WHERE task_id=? AND transaction_id=?",
                        (probe.task_id, "test-only-category-tamper"))
            digest = receipt.assessment.object_digest
            path = fixture.objects._path(digest)
            body = path.read_bytes()
            context = fixture.repository._action_journal._context
            profile = context.profile
            before = self._repository_rows(fixture)
            source_max = max(len(value) for _, value in fixture.repository.referenced_objects(probe.task_id))
            with fixture.repository._factory.open("doctor") as connection:
                snapshot_size = connection.execute("SELECT length(CAST(snapshot_json AS BLOB)) FROM tasks WHERE task_id=?",
                    (probe.task_id,)).fetchone()[0]
            real_read, primitive = os.read, fixture.repository._read_provenance_object
            for phase in ("locator", "sources"):
                for mode in ("exact", "sql-text", "rows", "aggregate", "oversized", "false-size", "growth", "short"):
                    with self.subTest(phase=phase, mode=mode):
                        limits = dict(profile.limits)
                        if mode == "exact":
                            limits["raw_document_bytes"] = max(snapshot_size,
                                len(body) if phase == "locator" else source_max)
                        elif mode == "sql-text":
                            limits["raw_document_bytes"] = 512
                        elif mode == "rows":
                            limits["array_items"] = 1
                        elif mode == "aggregate":
                            limits["result_bytes"] = 4096
                        context.profile = replace(profile, limits=limits)
                        if mode in ("false-size", "oversized"):
                            path.write_bytes(b"x" * (limits["raw_document_bytes"] + 1))
                        if mode == "oversized":
                            with fixture.repository._factory.open("application") as connection:
                                with connection.transaction():
                                    connection.execute("UPDATE objects SET size=? WHERE digest=?",
                                        (limits["raw_document_bytes"] + 1, digest))
                        query_before = self._repository_rows(fixture)
                        budget = module._RecoveryReadBudget((context,), task_id=probe.task_id,
                            command_scope=fixture.repository.command_scope)
                        reads, descriptors = [], []
                        def counted(fd, count):
                            if mode == "growth" and not reads:
                                with path.open("ab") as stream:
                                    stream.write(b"x")  # Explicit race injection.
                            chunk = real_read(fd, count - 1 if mode == "short" and not reads else count)
                            reads.append((count, len(chunk)))
                            descriptors.append(fd)
                            return chunk
                        def cas(selected, size, *, retained_bytes):
                            if selected != digest:
                                return primitive(selected, size, retained_bytes=retained_bytes)
                            with mock.patch.object(module.os, "read", side_effect=counted):
                                return primitive(selected, size, retained_bytes=retained_bytes)
                        try:
                            with budget.bind(ports=(fixture.repository, fixture.objects)), \
                                    mock.patch.object(fixture.repository, "_read_provenance_object", side_effect=cas), \
                                    mock.patch.object(fixture.objects, "get", side_effect=AssertionError("legacy CAS")):
                                if mode == "exact":
                                    result = fixture.repository.read_category_recovery_sources(probe.task_id, phase=phase)
                                    self.assertEqual(result["assessment_body"], body)
                                    self.assertEqual(sum(n for _, n in reads), len(body))
                                    budget.release_projection(result)
                                    del result
                                else:
                                    with self.assertRaises((RuntimeError, ValueError, ContractError)):
                                        fixture.repository.read_category_recovery_sources(probe.task_id, phase=phase)
                                    self.assertLessEqual(sum(n for _, n in reads),
                                        len(body) + 1 if mode == "growth" else len(body) - 1 if mode == "short" else 0)
                            self.assertEqual((budget.retained_units, budget.retained_bytes), (0, 0))
                            self.assertEqual(self._repository_rows(fixture), query_before)
                        finally:
                            budget.close()
                            context.profile = profile
                            path.write_bytes(body)  # Restore only the injected fixture race.
                            if mode == "oversized":
                                with fixture.repository._factory.open("application") as connection:
                                    with connection.transaction():
                                        connection.execute("UPDATE objects SET size=? WHERE digest=?", (len(body), digest))
                        for descriptor in set(descriptors):
                            with self.assertRaises(OSError):
                                os.fstat(descriptor)
                        self.assertEqual(context._temporary_units, 0)
                        fixture.raw_coordinator._retained_scope(require_idle=True)
                        self.assertEqual(self._repository_rows(fixture), before)

    def test_cold_action_second_capture_keeps_first_charge_and_rejects_shared_overflow(self):
        from graph_engineering.storage import repository as module
        from graph_engineering.core.contracts.errors import ContractError
        from tests.support.wp05a_security import security_context

        with self._owner_root(applied=True) as values:
            fixture, _, _, _, session, _, outcome = values
            session.close()
            reader = fixture.raw_coordinator
            other = security_context()
            other.profile = replace(other.profile, limits={**other.profile.limits,
                "result_bytes": 2 * other.profile.limits["result_bytes"]})
            context = reader._journal._context
            context.acquire_temporary(3, source_id="preexisting", operation_path=())
            other.acquire_temporary(5, source_id="preexisting", operation_path=())
            budget = module._RecoveryReadBudget((context, other), task_id="task-wp05",
                command_scope=reader._repository.command_scope)
            capture, observations = reader._repository._capture_action_provenance, []
            def nested(task_id, action_id):
                observations.append((budget.retained_units, budget.retained_bytes))
                if len(observations) == 2:
                    self.assertGreater(budget.retained_bytes, 0)
                    with budget.reserve(other, units=0,
                            byte_count=budget.byte_limit - budget.retained_bytes - 1, source_id="other-reader"):
                        return capture(task_id, action_id)
                return capture(task_id, action_id)
            try:
                with budget.bind(ports=(reader, reader._repository, reader._objects, reader._journal,
                        reader._issuer, reader._issuer._repository)), \
                        mock.patch.object(reader._repository, "_capture_action_provenance", side_effect=nested):
                    with self.assertRaises((ContractError, RuntimeError)):
                        reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(len(observations), 2)
                self.assertEqual((budget.retained_units, budget.retained_bytes), (0, 0))
                self.assertEqual((context._temporary_units, other._temporary_units), (3, 5))
                self.assertLessEqual(budget.peak_units, budget.unit_limit)
                self.assertLessEqual(budget.peak_bytes, budget.byte_limit)
            finally:
                budget.close()
                context.release_temporary(3)
                other.release_temporary(5)

    def test_cold_read_rejects_each_omitted_or_changed_context_before_io(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with action_stack(domain_task=True) as fixture:
            reader = fixture.raw_coordinator
            original = reader._journal._context
            policy_context = reader._policy._context
            journal_context, security = security_context(), security_context()
            reader._journal._context = journal_context
            reader._issuer._context = security
            contexts = (policy_context, journal_context, security)
            ports = (reader, reader._repository, reader._objects, reader._journal,
                     reader._issuer, reader._issuer._repository)
            try:
                for omitted in (*contexts, reader._objects):
                    budget = _RecoveryReadBudget(tuple(c for c in contexts if c is not omitted),
                        task_id="task-wp05", command_scope=reader._repository.command_scope)
                    try:
                        with budget.bind(ports=tuple(p for p in ports if p is not omitted)), ExitStack() as guards:
                            guards.enter_context(mock.patch.object(reader._repository._factory, "open",
                                side_effect=AssertionError("I/O before participant rejection")))
                            guards.enter_context(mock.patch.object(reader, "_read_action_authority",
                                side_effect=AssertionError("legacy action route")))
                            guards.enter_context(mock.patch.object(reader._journal, "load",
                                side_effect=AssertionError("legacy journal route")))
                            with self.assertRaises((ValueError, RuntimeError)):
                                reader._read_completed_action_provenance(task_id="task-wp05", action_id="absent")
                            if omitted in (journal_context, reader._objects):
                                with self.assertRaises((ValueError, RuntimeError)):
                                    reader._repository.read_category_recovery_sources("task-wp05", phase="locator")
                    finally:
                        budget.close()
                    self.assertEqual((budget.retained_units, budget.retained_bytes), (0, 0))
                    self.assertTrue(all(getattr(p, "_recovery_read_budget", None) is None for p in ports))
            finally:
                reader._journal._context = original
                reader._issuer._context = original

    def test_cold_action_capture_retains_both_reads_without_legacy_journal_calls(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with self._owner_root(applied=True) as values:
            fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
            session.close()
            reader = self._fresh_action_reader(fixture)
            context = reader._policy._context
            contexts = (context, reader._issuer._context, reader._journal._context)
            budget = _RecoveryReadBudget(contexts, task_id="task-wp05",
                command_scope=reader._repository.command_scope)
            before = self._repository_rows(fixture)
            try:
                with budget.bind(ports=(reader, reader._repository, reader._objects, reader._journal,
                        reader._issuer, reader._issuer._repository)), ExitStack() as guards:
                    for name in ("load", "find_prepared"):
                        guards.enter_context(mock.patch.object(reader._journal, name,
                            side_effect=AssertionError("legacy journal read")))
                    guards.enter_context(mock.patch.object(reader, "_read_action_authority",
                        side_effect=AssertionError("legacy action read")))
                    result = reader._read_completed_action_provenance(
                        task_id="task-wp05", action_id=outcome.action_id)
                    self.assertEqual(result["completion"], "reconciled_effect_verified")
                    self.assertGreater(budget.retained_bytes, 0)
                    self.assertGreater(budget.peak_bytes, budget.retained_bytes)
                    budget.release_projection(result)
                    del result
                self.assertEqual((budget.retained_units, budget.retained_bytes), (0, 0))
                self.assertEqual(self._repository_rows(fixture), before)
            finally:
                budget.close()

    def test_security_sql_rejects_large_fields_before_returning_them(self):
        import sqlite3
        from graph_engineering.storage.errors import RepositoryIntegrityError

        for table, field in (("security_runtime_installation", "manifest_json"),
                ("security_runtime_installation", "manifest_id"), ("task_security_states", "state_json")):
            with self.subTest(field=field), action_stack(domain_task=True) as fixture:
                issuer = fixture.raw_coordinator._issuer
                context = issuer._context
                context.profile = replace(context.profile, limits={**context.profile.limits,
                    "raw_document_bytes": 4096})
                # Exercise the real SELECT against SQLite with adversarial rows;
                # do not remove the production installation's immutable trigger.
                database = sqlite3.connect(":memory:")
                self.addCleanup(database.close)
                with fixture.repository._factory.open("doctor") as connection:
                    for name in ("security_runtime_installation", "task_security_states", "tasks"):
                        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone()[0]
                        database.execute(schema)
                        rows = connection.execute("SELECT * FROM " + name).fetchall()
                        for row in rows:
                            database.execute("INSERT INTO " + name + " VALUES(" + ",".join("?" for _ in row) + ")", row)
                database.execute("UPDATE " + table + " SET " + field + "=?", ("x" * 8192,))
                returned = []
                class BoundedCursor:
                    def __init__(inner, cursor):
                        inner.cursor = cursor
                    def fetchone(inner):
                        row = inner.cursor.fetchone()
                        if row:
                            for value in row:
                                if type(value) in (str, bytes):
                                    self.assertLessEqual(len(value), 4096,
                                        "oversized SQL field reached Python")
                            returned.append(row)
                        return row
                    def close(inner):
                        inner.cursor.close()
                class BoundedConnection:
                    def execute(inner, sql, parameters=()):
                        return BoundedCursor(database.execute(sql, parameters))
                @contextmanager
                def doctor(role):
                    self.assertEqual(role, "doctor")
                    yield BoundedConnection()
                with mock.patch.object(issuer._repository._factory, "open", new=doctor), \
                        self.assertRaises(RepositoryIntegrityError):
                    if table == "task_security_states":
                        issuer._repository.load_current_task_state_readonly("task-wp05", context)
                    else:
                        issuer._repository.load_installed_runtime(context)
                self.assertEqual(context._temporary_units, 0)

    def test_cold_source_capture_is_bounded_immutable_and_doctor_only(self):
        """Storage capture of a legacy fixture does not certify cold eligibility."""
        from graph_engineering.storage.connection import ManagedConnection
        from graph_engineering.storage.repository import _RecoveryReadBudget

        with self._same_task_assessment() as values:
            _api, fixture, session, application, probe, target, candidate, evidence, _outcome = values
            receipt = application.assess_and_commit(candidate, observer=target,
                release_operations_evidence=evidence)
            expected_body = receipt.assessment.to_bytes()
            expected_digest = receipt.assessment.object_digest
            session.close()
            context = fixture.repository._action_journal._context
            prior_units = context._temporary_units
            budget = _RecoveryReadBudget((context,), task_id=probe.task_id,
                command_scope=fixture.repository.command_scope)
            with budget.bind(ports=(fixture.repository, fixture.objects)):
                with self.assertRaisesRegex(RuntimeError, "unavailable or foreign"):
                    fixture.repository.read_category_recovery_sources(probe.task_id, phase="sources")
            # The legacy rollback fixture deliberately inserts this uncommitted
            # reference. It is a negative source; remove that test injection for
            # this storage-only positive, without manufacturing a transaction.
            with fixture.repository._factory.open("application") as connection:
                with connection.transaction():
                    removed = connection.execute(
                        "DELETE FROM object_references WHERE task_id=? AND transaction_id=?",
                        (probe.task_id, "test-only-category-tamper"))
                    self.assertEqual(removed.rowcount, 1)
            before = self._repository_rows(fixture)
            execute, queries = ManagedConnection.execute, []
            def only_reads(connection, sql, parameters=()):
                self.assertEqual(connection._role, "doctor")
                self.assertEqual(connection._raw.execute("PRAGMA query_only").fetchone(), (1,))
                self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                queries.append(sql)
                return execute(connection, sql, parameters)
            try:
                with budget.bind(ports=(fixture.repository, fixture.objects)), ExitStack() as guards:
                    guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                    for name in ("load", "replay", "referenced_objects", "category_source_seal"):
                        guards.enter_context(mock.patch.object(fixture.repository, name,
                            side_effect=AssertionError("legacy repository read")))
                    for name in ("get", "_verify_file", "_read_descriptor"):
                        guards.enter_context(mock.patch.object(fixture.objects, name,
                            side_effect=AssertionError("unbounded CAS read")))
                    guards.enter_context(mock.patch.object(fixture.task_application, "runtime_show",
                        side_effect=AssertionError("legacy task resolver")))
                    locator = fixture.repository.read_category_recovery_sources(probe.task_id, phase="locator")
                    self.assertEqual(locator["assessment_ref"]["source_ref"], expected_digest)
                    self.assertEqual(locator["assessment_body"], expected_body)
                    sources = fixture.repository.read_category_recovery_sources(probe.task_id, phase="sources")
                    self.assertEqual(dict(sources["objects"])[expected_digest], expected_body)
                    self.assertEqual(sources["snapshot"]["domain"]["lifecycle"], "completed")
                    self.assertEqual(sources["task"], locator["task"])
                    with self.assertRaises(TypeError):
                        sources["snapshot"]["domain"]["lifecycle"] = "created"
                    with self.assertRaises(TypeError):
                        sources["assessment_body"] = b"changed"
                    self.assertGreater(budget.retained_units, 0)
                    budget.release_projection(locator)
                    budget.release_projection(sources)
                    del locator, sources
                self.assertTrue(queries)
                self.assertEqual(self._repository_rows(fixture), before)
                fixture.raw_coordinator._retained_scope(require_idle=True)
            finally:
                budget.close()
            self.assertEqual(context._temporary_units, prior_units)

    @contextmanager
    def _owner_root(self, *, applied=False):
        import tempfile
        from graph_engineering.application.runtime import RuntimeSessionError

        with action_stack(domain_task=True) as fixture, ExitStack() as stack:
            runtime = self._runtime()
            def close_current_runtime():
                try:
                    runtime.require_current()
                except RuntimeSessionError:
                    return  # Revocation cases already closed this exact runtime.
                runtime.close()
            stack.callback(close_current_runtime)
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="gew-retained-owner-"))
            namespace = stack.enter_context(runtime.bind_release_namespace(
                action_coordinator=fixture.raw_coordinator, namespace_path=pathlib.Path(directory).resolve()))
            factory, session, baseline, artifact = self._issue(fixture, namespace)
            stack.enter_context(session)
            if applied:
                outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                    fixture, session, baseline, artifact, factory.artifact_bytes(artifact))
            else:
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                outcome = None
            yield fixture, runtime, namespace, factory, session, session.recovery_binding, outcome

    @staticmethod
    def _fresh_action_reader(fixture):
        from graph_engineering.application.actions import ActionCoordinator

        original = fixture.raw_coordinator
        return ActionCoordinator(journal=original._journal, repository=original._repository,
            leases=original._leases, locks=original._locks, objects=original._objects,
            security_issuer=original._issuer, action_policy=original._policy,
            installation_scope=original._repository.command_scope)

    @staticmethod
    def _repository_rows(fixture):
        with fixture.repository._factory.open("doctor") as connection:
            names = connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            return tuple((name, tuple(connection.execute(
                'SELECT * FROM "' + name.replace('"', '""') + '"').fetchall())) for name, in names)

    def test_completed_action_provenance_is_immutable_and_read_only(self):
        from graph_engineering.storage.codec import semantic_record_digest
        from graph_engineering.storage.connection import ManagedConnection

        with self._owner_root(applied=True) as values:
            fixture, _runtime, namespace, factory, session, binding, outcome = values
            reader = self._fresh_action_reader(fixture)
            session.close()
            fixture.expire_action_lease()
            before = self._repository_rows(fixture)
            cas_before = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
            root_before = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            execute, queries = ManagedConnection.execute, []
            def only_reads(connection, sql, parameters=()):
                self.assertEqual(connection._role, "doctor")
                self.assertEqual(connection._raw.execute("PRAGMA query_only").fetchone(), (1,))
                self.assertTrue(sql.lstrip().upper().startswith(("SELECT", "WITH")))
                queries.append(sql)
                return execute(connection, sql, parameters)
            with factory._open_retained_storage_query(action_coordinator=fixture.raw_coordinator,
                    retained_namespace=namespace, binding=binding) as handle, ExitStack() as guards:
                guards.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
                for name in ("_verify_file", "_verify_object", "_open_verified_descriptor",
                             "_verify_descriptor_binding", "_read_descriptor"):
                    guards.enter_context(mock.patch.object(fixture.objects, name,
                        side_effect=AssertionError("unbounded CAS helper")))
                guards.enter_context(mock.patch.object(reader, "_issue_outcome", side_effect=AssertionError("outcome")))
                guards.enter_context(mock.patch.object(reader, "issue_durable_execution_gate", side_effect=AssertionError("gate")))
                stored = fixture.repository.read_action_provenance("task-wp05", outcome.action_id)
                completed = reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(completed["provenance"], stored)
                self.assertEqual(completed["completion"], "reconciled_effect_verified")
                self.assertEqual(stored["claim"]["claim_id"], outcome.claim_id)
                self.assertEqual(stored["claim"]["outcome_digest"], semantic_record_digest({
                    "contract": "claim-outcome-v1", "state": "reconciled_effect_verified",
                    "value": stored["journals"][0]["reconciliation"]}))
                self.assertIsNone(stored["recovery"])
                self.assertEqual(len(stored["receipt_objects"]), 1)
                with self.assertRaises(TypeError):
                    completed["provenance"]["claim"]["fencing_tokens"]["changed"] = 1
                with self.assertRaises(ValueError):
                    reader.require_issued_outcome(completed)
                self.assertEqual(dict(handle.query()), root_before)
            self.assertTrue(any(sql.startswith("WITH") for sql in queries))
            self.assertEqual(reader._issued_outcomes, {})
            reader._retained_scope(require_idle=True)
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas_before)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, root_before)

    def test_provenance_cas_reader_enforces_actual_incremental_and_aggregate_bounds(self):
        import os
        import sys
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.errors import ObjectIntegrityError

        for mode in ("large-exact", "oversized", "false-size", "growth", "aggregate", "exact", "short"):
            with self.subTest(mode=mode), action_stack() as fixture:
                body = b"x" * (131073 if mode == "large-exact" else 12 if mode in {"oversized", "false-size"} else 8)
                digest = fixture.objects.digest(body)
                fixture.objects.put_verified(body, digest)
                prior_body = b"abc"
                prior_digest = fixture.objects.digest(prior_body)
                fixture.objects.put_verified(prior_body, prior_digest)
                path = fixture.objects._path(digest)
                context = fixture.repository._action_journal._context
                limits = dict(context.profile.limits)
                limits.update(raw_document_bytes=10, result_bytes=10, temporary_units=10)
                if mode == "large-exact":
                    limits.update(raw_document_bytes=len(body), result_bytes=len(body) + 3, temporary_units=len(body) + 3)
                before = self._repository_rows(fixture)
                read, close = os.read, os.close
                reads, closed, retained_sizes = [], [], []
                prior_live_size = 0 if mode in {"aggregate", "large-exact"} else 2
                def counted_read(fd, count):
                    if mode == "growth" and not reads:
                        with path.open("ab") as stream:
                            stream.write(b"grown")  # Explicit external race, not reader work.
                    chunk = read(fd, min(count, 7) if mode == "short" else count)
                    reads.append((count, len(chunk)))
                    return chunk
                def counted_close(fd):
                    closed.append(fd)
                    return close(fd)
                def trace(frame, event, arg):
                    if frame.f_code.co_name == "_read_provenance_object":
                        buffers = {}
                        def collect(value):
                            if type(value) in (bytes, bytearray):
                                buffers[id(value)] = len(value)
                            elif type(value) in (list, tuple):
                                for item in value:
                                    collect(item)
                        for value in frame.f_locals.values():
                            collect(value)
                        retained_sizes.append(prior_live_size + sum(buffers.values()))
                        return trace
                    return None
                with mock.patch.object(context, "profile", replace(context.profile, limits=limits)), \
                     mock.patch("graph_engineering.storage.repository.os.read", side_effect=counted_read), \
                     mock.patch("graph_engineering.storage.repository.os.close", side_effect=counted_close), \
                     mock.patch.object(fixture.objects, "_read_descriptor", side_effect=AssertionError("unbounded read")):
                    def query():
                        nonlocal prior_live_size
                        if mode in {"aggregate", "large-exact"}:
                            previous = fixture.repository._read_provenance_object(prior_digest, len(prior_body), retained_bytes=0)
                            self.assertEqual(previous, prior_body)
                            prior_live_size = len(previous)
                            reads.clear()
                        return fixture.repository._read_provenance_object(digest,
                            1 if mode == "false-size" else len(body), retained_bytes=prior_live_size)
                    previous_trace = sys.gettrace()
                    try:
                        sys.settrace(trace)
                        if mode in {"exact", "large-exact"}:
                            self.assertEqual(query(), body)
                            self.assertEqual(sum(size for _count, size in reads), len(body))
                        else:
                            with self.assertRaises((ContractError, ObjectIntegrityError)):
                                query()
                            self.assertLessEqual(sum(size for _count, size in reads), 9 if mode == "growth" else 7 if mode == "short" else 0)
                    finally:
                        sys.settrace(previous_trace)
                    self.assertLessEqual(max(retained_sizes, default=0), limits["temporary_units"])
                    self.assertTrue(closed)
                    for descriptor in closed:
                        with self.assertRaises(OSError):
                            os.fstat(descriptor)
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual(path.read_bytes(), body + (b"grown" if mode == "growth" else b""))
                self.assertEqual(context._temporary_units, 0)
                fixture.raw_coordinator._retained_scope(require_idle=True)


    @contextmanager
    def _completed_compensation(self):
        from graph_engineering.core.actions import PreparedAction

        with self._owner_root() as values:
            fixture, _runtime, _namespace, factory, session, _binding, _outcome = values
            baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
            candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
            def fault(step):
                if step == "after-stage-durable":
                    raise TimeoutError("provenance partial deployment")
            session._root.fault_hook = fault
            document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
            document["snapshot_digest"] = fixture.current_task_snapshot_digest()
            document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
            prepared = fixture.coordinator.prepare(document)
            fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
            unknown = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
            self.assertEqual(unknown.route, "manual-reconciliation")
            factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                session=session, outcome=unknown)
            restore = fixture.coordinator.prepare(release_partial_restore_prepared_document(fixture,
                target_digest=session.target.target_digest, baseline=baseline, baseline_bytes=factory.artifact_bytes(baseline),
                candidate=candidate, original_claim_id=unknown.claim_id, original_receipt_digest=unknown.receipt_digest))
            fixture.coordinator.authorize(authority_document(restore, context=fixture.context))
            completed = fixture.coordinator.compensate_unknown(prepared.action_id, compensation_action_id=restore.action_id,
                recovery_lease=fixture.action_lease, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", target=session.target, observer=session.observer,
                disclosure_plan=release_disclosure_plan(fixture, restore))
            self.assertEqual(completed.route, "compensation-reconciled")
            yield values, completed, restore.action_id

    def test_completed_compensation_reads_original_claim_and_distinct_restore(self):
        with self._completed_compensation() as (values, completed, restore_id):
            fixture, _runtime, namespace, factory, session, binding, _outcome = values
            session.close()
            fixture.expire_action_lease()
            reader = self._fresh_action_reader(fixture)
            before = self._repository_rows(fixture)
            with factory._open_retained_storage_query(action_coordinator=fixture.raw_coordinator,
                    retained_namespace=namespace, binding=binding), \
                 mock.patch.object(reader, "_issue_outcome", side_effect=AssertionError("outcome")), \
                 mock.patch.object(fixture.objects, "_verify_file", side_effect=AssertionError("unbounded CAS")):
                value = reader._read_completed_action_provenance(task_id="task-wp05", action_id=completed.action_id)
            stored = value["provenance"]
            self.assertEqual(value["completion"], "compensation_reconciled")
            self.assertEqual(stored["claim"]["claim_id"], completed.claim_id)
            self.assertEqual(stored["recovery"]["compensation_action_id"], restore_id)
            self.assertEqual(stored["recovery"]["receipt_digest"], completed.receipt_digest)
            journals = {journal["action_id"]: journal for journal in stored["journals"]}
            self.assertEqual(journals[completed.action_id]["state"], "compensated")
            self.assertEqual(journals[restore_id]["state"], "reconciled")
            self.assertEqual(journals[restore_id]["receipt"], stored["recovery"]["receipt"])
            self.assertEqual(journals[restore_id]["reconciliation"], journals[completed.action_id]["reconciliation"])
            self.assertEqual(len(value["authorities"]), 2)
            self.assertEqual(reader._issued_outcomes, {})
            self.assertEqual(self._repository_rows(fixture), before)
            reader._retained_scope(require_idle=True)

    def test_provenance_accepts_shared_receipt_from_earlier_committed_transaction(self):
        from tests.support.wp08_release_operations import release_restore_prepared_document

        with self._owner_root(applied=True) as values:
            fixture, _runtime, _namespace, factory, session, _binding, original = values
            factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                session=session, outcome=original)
            baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
            candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
            restored = fixture.coordinator.prepare(release_restore_prepared_document(fixture,
                target_digest=session.target.target_digest, baseline=baseline, baseline_bytes=factory.artifact_bytes(baseline),
                candidate=candidate, original_claim_id=original.claim_id, original_receipt_digest=original.receipt_digest))
            fixture.coordinator.authorize(authority_document(restored, context=fixture.context))
            outcome = fixture.coordinator.execute(restored.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, restored))
            self.assertEqual(outcome.route, "reconciled-effect-verified")
            session.close()
            reader = self._fresh_action_reader(fixture)
            first = reader._read_completed_action_provenance(task_id="task-wp05", action_id=original.action_id)
            second = reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
            digest = first["provenance"]["receipt_objects"][0]["digest"]
            self.assertEqual(second["provenance"]["receipt_objects"][0]["digest"], digest)
            reference = next(item for item in second["provenance"]["references"] if item["digest"] == digest)
            self.assertEqual(reference["transaction_id"], original.action_id + ":receipt")
            receipt_event = next(item for item in second["provenance"]["events"]
                if item["event"]["event_type"] == "action.receipt_recorded"
                and item["event"]["payload"]["action_id"] == outcome.action_id)
            self.assertNotEqual(reference["transaction_id"], receipt_event["transaction_id"])


    @staticmethod
    def _rewrite_provenance_event(fixture, kind, mutate):
        """Coherently rehash fixture history, so semantic joins must reject it."""
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json
        from graph_engineering.storage.repository import event_digest

        with fixture.repository._factory.open("application") as connection:
            with connection.transaction():
                rows = connection.execute("SELECT sequence,body_json,transaction_id FROM events "
                    "WHERE task_id=? ORDER BY sequence", ("task-wp05",)).fetchall()
                previous, heads = None, {}
                for sequence, encoded, transaction_id in rows:
                    event = parse_canonical_json(encoded)
                    if event["event_type"] == kind:
                        mutate(event)
                    event["previous_event_digest"] = previous
                    event["event_digest"] = event_digest(event)
                    connection.execute("UPDATE events SET event_type=?,body_json=?,previous_event_digest=?,event_digest=? "
                        "WHERE task_id=? AND sequence=?", (event["event_type"], canonical_json(event), previous,
                        event["event_digest"], "task-wp05", sequence))
                    previous = event["event_digest"]
                    heads[transaction_id] = previous
                for transaction_id, digest in heads.items():
                    connection.execute("UPDATE transactions SET head_digest=? WHERE transaction_id=?", (digest, transaction_id))
                connection.execute("UPDATE tasks SET head_digest=? WHERE task_id=?", (previous, "task-wp05"))

    def test_completed_provenance_rejects_corrupt_indexes_claims_references_and_semantics(self):
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest
        from graph_engineering.storage.errors import RepositoryIntegrityError, RepositoryConflictError

        modes = ("claim-outcome", "prepared-index", "authority-index", "digest-alias", "foreign-claim",
                 "foreign-fence", "foreign-lease", "receipt-fence", "observation", "missing-reference",
                 "foreign-reference", "future-reference", "event-index", "event-semantic", "duplicate-receipt",
                 "object-bytes", "unresolved")
        for mode in modes:
            with self.subTest(mode=mode), self._owner_root(applied=True) as values:
                fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
                session.close()
                reader = self._fresh_action_reader(fixture)
                with fixture.repository._factory.open("application") as connection:
                    with connection.transaction():
                        if mode == "claim-outcome":
                            connection.execute("UPDATE claims SET outcome_digest=? WHERE claim_id=?",
                                ("sha256-jcs-v1:" + "0" * 64, outcome.claim_id))
                        elif mode in {"prepared-index", "authority-index"}:
                            column = "prepared_digest" if mode == "prepared-index" else "authority_digest"
                            connection.execute("UPDATE action_journal SET " + column + "=? WHERE action_id=?",
                                ("sha256-jcs-v1:" + "0" * 64, outcome.action_id))
                        elif mode == "digest-alias":
                            connection.execute("INSERT INTO action_journal(action_id,task_id,state,revision,idempotency_key,"
                                "prepared_json,prepared_digest,authority_json,authority_digest,receipt_json,reconciliation_json) "
                                "SELECT 'alias-action',task_id,state,revision,'alias-key',prepared_json,prepared_digest,"
                                "authority_json,authority_digest,receipt_json,reconciliation_json FROM action_journal WHERE action_id=?",
                                (outcome.action_id,))
                        elif mode == "foreign-claim":
                            connection.execute("UPDATE claims SET action_id='foreign-action' WHERE claim_id=?", (outcome.claim_id,))
                        elif mode == "foreign-fence":
                            connection.execute("UPDATE claim_resources SET fencing_token=fencing_token+1 WHERE claim_id=?", (outcome.claim_id,))
                        elif mode == "foreign-lease":
                            connection.execute("INSERT INTO leases SELECT 'foreign-lease',request_digest,task_id,run_id,"
                                "operation_id,issued_at,expires_at,heartbeat_revision,state FROM leases WHERE lease_id=?", (fixture.action_lease.lease_id,))
                            connection.execute("UPDATE claims SET lease_id='foreign-lease' WHERE claim_id=?", (outcome.claim_id,))
                        elif mode in {"receipt-fence", "observation"}:
                            column = "receipt_json" if mode == "receipt-fence" else "reconciliation_json"
                            body = parse_canonical_json(connection.execute("SELECT " + column + " FROM action_journal WHERE action_id=?",
                                (outcome.action_id,)).fetchone()[0])
                            if mode == "receipt-fence":
                                body["fencing_token"] += 1
                                body["receipt_digest"] = semantic_record_digest({"contract": "action-receipt-v1",
                                    "value": {key: value for key, value in body.items() if key != "receipt_digest"}})
                            else:
                                body["state"]["generation"] += 1
                                connection.execute("UPDATE claims SET outcome_digest=? WHERE claim_id=?", (
                                    semantic_record_digest({"contract": "claim-outcome-v1", "state": "reconciled_effect_verified",
                                        "value": body}), outcome.claim_id))
                            connection.execute("UPDATE action_journal SET " + column + "=? WHERE action_id=?",
                                (canonical_json(body), outcome.action_id))
                        elif mode == "missing-reference":
                            connection.execute("DELETE FROM object_references WHERE task_id=?", ("task-wp05",))
                        elif mode in {"foreign-reference", "future-reference"}:
                            transaction = "foreign-tx" if mode == "foreign-reference" else outcome.action_id + ":reconciled_effect_verified"
                            if mode == "foreign-reference":
                                connection.execute("INSERT INTO transactions SELECT 'foreign-tx',request_digest,'foreign-task',revision,head_digest "
                                    "FROM transactions LIMIT 1")
                            connection.execute("UPDATE object_references SET transaction_id=? WHERE task_id=?", (transaction, "task-wp05"))
                        elif mode == "event-index":
                            connection.execute("UPDATE events SET event_type='action.wrong' WHERE task_id=? AND sequence="
                                "(SELECT MAX(sequence) FROM events WHERE task_id=?)", ("task-wp05", "task-wp05"))
                        elif mode == "unresolved":
                            connection.execute("UPDATE claims SET state='unresolved',outcome_digest=NULL WHERE claim_id=?", (outcome.claim_id,))
                if mode == "event-semantic":
                    self._rewrite_provenance_event(fixture, "action.reconciled_effect_verified",
                        lambda event: event["payload"].update(claim_id="foreign-claim"))
                if mode == "duplicate-receipt":
                    receipt = fixture.journal.load(outcome.action_id).receipt
                    def duplicate(event):
                        event["event_type"] = "action.receipt_recorded"
                        event["payload"] = {"action_id": outcome.action_id, "claim_id": outcome.claim_id,
                            "receipt_digest": receipt["receipt_digest"], "raw_receipt_object_digest": receipt["raw_receipt_object_digest"]}
                    self._rewrite_provenance_event(fixture, "action.reconciled_effect_verified", duplicate)
                if mode == "object-bytes":
                    receipt = fixture.journal.load(outcome.action_id).receipt
                    path = fixture.objects._path(receipt["raw_receipt_object_digest"])
                    path.write_bytes(b"x" * path.stat().st_size)
                before = self._repository_rows(fixture)
                cas = {p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}
                with self.assertRaises((ValueError, RepositoryIntegrityError, RepositoryConflictError)):
                    reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual({p: p.read_bytes() for p in fixture.objects._objects.rglob("*") if p.is_file()}, cas)
                self.assertEqual(reader._issued_outcomes, {})
                reader._retained_scope(require_idle=True)

    def test_completed_compensation_rejects_substitution_and_current_restore_revocation(self):
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest
        from graph_engineering.storage.errors import RepositoryIntegrityError, RepositoryConflictError

        for mode in ("outcome", "receipt-index", "receipt-object-index", "attempt-fences", "attempt-start",
                     "restore-receipt", "restore-observation", "original-state", "restore-revocation"):
            with self.subTest(mode=mode), self._completed_compensation() as (values, outcome, restore_id):
                fixture, _runtime, _namespace, _factory, session, _binding, _old = values
                session.close()
                reader = self._fresh_action_reader(fixture)
                with fixture.repository._factory.open("application") as connection:
                    with connection.transaction():
                        if mode == "outcome":
                            connection.execute("UPDATE claims SET outcome_digest=? WHERE claim_id=?",
                                ("sha256-jcs-v1:" + "0" * 64, outcome.claim_id))
                        elif mode in {"receipt-index", "receipt-object-index", "attempt-start"}:
                            column = {"receipt-index": "receipt_digest", "receipt-object-index": "receipt_object_digest",
                                      "attempt-start": "start_event_digest"}[mode]
                            prefix = "sha256:" if mode == "receipt-object-index" else "sha256-jcs-v1:"
                            connection.execute("UPDATE claim_recovery_attempts SET " + column + "=? WHERE claim_id=?",
                                (prefix + "0" * 64, outcome.claim_id))
                        elif mode == "attempt-fences":
                            connection.execute("UPDATE claim_recovery_attempts SET fencing_tokens_json=? WHERE claim_id=?",
                                (canonical_json({"target:project": 99, "task:task-wp05": 99}), outcome.claim_id))
                        elif mode in {"restore-receipt", "restore-observation"}:
                            column = "receipt_json" if mode == "restore-receipt" else "reconciliation_json"
                            body = parse_canonical_json(connection.execute("SELECT " + column + " FROM action_journal WHERE action_id=?",
                                (restore_id,)).fetchone()[0])
                            if mode == "restore-receipt":
                                body["lease_id"] = "foreign-lease"
                                body["receipt_digest"] = semantic_record_digest({"contract": "claim-compensation-receipt-v1",
                                    "value": {key: value for key, value in body.items() if key != "receipt_digest"}})
                            else:
                                body["observation_revision"] += 1
                                body["observation_digest"] = semantic_record_digest({"contract": "fresh-target-observation-v1",
                                    "value": {key: value for key, value in body.items() if key not in {"observation_digest", "bound_receipt_digest"}}})
                            connection.execute("UPDATE action_journal SET " + column + "=? WHERE action_id=?",
                                (canonical_json(body), restore_id))
                        elif mode == "original-state":
                            connection.execute("UPDATE action_journal SET state='reconciled' WHERE action_id=?", (outcome.action_id,))
                        else:
                            state = parse_canonical_json(connection.execute("SELECT state_json FROM task_security_states WHERE task_id=?",
                                ("task-wp05",)).fetchone()[0])
                            digest = connection.execute("SELECT authority_digest FROM action_journal WHERE action_id=?", (restore_id,)).fetchone()[0]
                            state["authority_digests"].remove(digest)
                            connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                                (canonical_json(state), semantic_record_digest({"contract": "task-security-state-v1", "value": state}), "task-wp05"))
                before = self._repository_rows(fixture)
                with self.assertRaises((ValueError, RepositoryIntegrityError, RepositoryConflictError)):
                    reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual(reader._issued_outcomes, {})
                reader._retained_scope(require_idle=True)

    def test_provenance_rejects_scope_sql_limits_and_drift_without_leaks(self):
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.codec import canonical_json
        from graph_engineering.storage.errors import RepositoryIntegrityError, RepositoryConflictError
        from graph_engineering.storage.repository import TaskRepository

        with self._owner_root(applied=True) as values:
            fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
            session.close()
            repository = fixture.repository
            query = lambda: repository.read_action_provenance("task-wp05", outcome.action_id)
            before = self._repository_rows(fixture)
            with action_stack() as foreign, mock.patch.object(repository, "_objects", foreign.objects):
                with self.assertRaises(RepositoryIntegrityError):
                    query()
            token = fixture.locks.acquire_installation("shared")
            try:
                with self.assertRaisesRegex(RepositoryIntegrityError, "token is held"):
                    query()
            finally:
                fixture.locks.release(token)
            with repository._factory.open("doctor"):
                with self.assertRaisesRegex(RepositoryIntegrityError, "connection is held"):
                    query()
            maintenance = TaskRepository._for_maintenance(repository._factory, fixture.locks, fixture.objects,
                action_journal=repository._action_journal)
            with self.assertRaises(RepositoryIntegrityError):
                maintenance.read_action_provenance("task-wp05", outcome.action_id)
            context = repository._action_journal._context
            with mock.patch.object(context, "profile", replace(context.profile,
                    limits={**context.profile.limits, "array_items": 1})):
                with self.assertRaises(ContractError):
                    query()
            self.assertEqual(self._repository_rows(fixture), before)
            capture, calls = repository._capture_action_provenance, []
            def drift(task_id, action_id):
                if calls:
                    with repository._factory.open("application") as connection:
                        with connection.transaction():
                            connection.execute("UPDATE action_journal SET revision=revision+1 WHERE action_id=?", (action_id,))
                calls.append(action_id)
                return capture(task_id, action_id)
            with mock.patch.object(repository, "_capture_action_provenance", side_effect=drift):
                with self.assertRaisesRegex(RepositoryConflictError, "changed during query"):
                    query()
            self.assertEqual(len(calls), 2)
            fixture.raw_coordinator._retained_scope(require_idle=True)
            with repository._factory.open("application") as connection:
                with connection.transaction():
                    connection.execute("UPDATE action_journal SET reconciliation_json=? WHERE action_id=?",
                        (" " * (context.profile.limits["raw_document_bytes"] + 1), outcome.action_id))
            before = self._repository_rows(fixture)
            with self.assertRaisesRegex(RepositoryIntegrityError, "over limit"):
                query()
            self.assertEqual(self._repository_rows(fixture), before)
            fixture.raw_coordinator._retained_scope(require_idle=True)


    def test_provenance_handles_unknown_receipt_and_compensation_without_original_receipt(self):
        from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
        from tests.support.wp05_actions import prepared_document, compensation_prepared_document, disclosure_plan

        for compensate in (False, True):
            with self.subTest(compensate=compensate), action_stack() as fixture:
                prepared = fixture.coordinator.prepare(prepared_document(context=fixture.context))
                fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                target = DeterministicFakeTarget(target_id=prepared.target_id, target_digest=prepared.target_digest,
                    resource_id="target:project", initial_state={"version": 1},
                    failure_mode="crash-after-effect" if compensate else "timeout-after-effect")
                def execute():
                    return fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=target,
                        observer=target.observer_port(), disclosure_plan=disclosure_plan(fixture, prepared))
                if compensate:
                    with self.assertRaisesRegex(RuntimeError, "crash after effect"):
                        execute()
                else:
                    self.assertEqual(execute().route, "manual-reconciliation")
                target.failure_mode = None
                if compensate:
                    restore = fixture.coordinator.prepare(compensation_prepared_document(
                        snapshot_digest=fixture.current_task_snapshot_digest()))
                    fixture.coordinator.authorize(authority_document(restore, context=fixture.context))
                    fixture.coordinator.compensate_unknown(prepared.action_id, compensation_action_id=restore.action_id,
                        recovery_lease=fixture.action_lease, owner_id="owner-wp05", runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05", target=target, observer=target.observer_port(),
                        disclosure_plan=disclosure_plan(fixture, restore))
                else:
                    fixture.coordinator.reconcile_unknown(prepared.action_id, lease=fixture.action_lease, observer=target.observer_port())
                before = self._repository_rows(fixture)
                value = self._fresh_action_reader(fixture)._read_completed_action_provenance(
                    task_id="task-wp05", action_id=prepared.action_id)
                journal = next(item for item in value["provenance"]["journals"] if item["action_id"] == prepared.action_id)
                if compensate:
                    self.assertIsNone(journal["receipt"])
                    self.assertEqual(value["completion"], "compensation_reconciled")
                else:
                    self.assertEqual(journal["receipt"]["result"], "unknown")
                    self.assertEqual(value["completion"], "reconciled_effect_verified")
                self.assertEqual(self._repository_rows(fixture), before)

    def test_provenance_cas_identity_permissions_and_failure_release_read_resources(self):
        import os
        from graph_engineering.storage.errors import ObjectIntegrityError

        for mode in ("symlink", "mode", "owner", "replace", "io"):
            with self.subTest(mode=mode), self._owner_root(applied=True) as values:
                fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
                session.close()
                receipt = fixture.journal.load(outcome.action_id).receipt
                path = fixture.objects._path(receipt["raw_receipt_object_digest"])
                body = path.read_bytes()
                if mode == "symlink":
                    other = path.with_name("fixture-target")
                    other.write_bytes(body)
                    path.unlink()
                    path.symlink_to(other)
                elif mode == "mode":
                    path.chmod(0o644)
                before = self._repository_rows(fixture)
                read, fstat, calls, descriptors = os.read, os.fstat, [], []
                def changed_read(fd, count):
                    calls.append(fd)
                    if mode == "replace" and len(calls) == 1:
                        path.unlink()
                        path.write_bytes(body)
                        path.chmod(0o600)
                    if mode == "io":
                        raise OSError("injected receipt read failure")
                    return read(fd, count)
                def changed_stat(fd):
                    metadata = fstat(fd)
                    if (metadata.st_dev, metadata.st_ino) == (path.stat().st_dev, path.stat().st_ino):
                        descriptors.append(fd)
                        if mode == "owner":
                            from types import SimpleNamespace
                            fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
                            return SimpleNamespace(**{key: (metadata.st_uid + 1 if key == "st_uid" else getattr(metadata, key)) for key in fields})
                    return metadata
                with mock.patch("graph_engineering.storage.repository.os.read", side_effect=changed_read), \
                     mock.patch("graph_engineering.storage.repository.os.fstat", side_effect=changed_stat):
                    with self.assertRaises(ObjectIntegrityError):
                        fixture.repository.read_action_provenance("task-wp05", outcome.action_id)
                self.assertEqual(self._repository_rows(fixture), before)
                fixture.raw_coordinator._retained_scope(require_idle=True)
                for descriptor in descriptors:
                    with self.assertRaises(OSError):
                        fstat(descriptor)
                if mode != "replace":
                    self.assertEqual(path.read_bytes(), body)

    def test_completed_provenance_rejects_authority_drift_after_storage_capture(self):
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest
        from graph_engineering.core.contracts.immutable import thaw

        with self._owner_root(applied=True) as values:
            fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
            session.close()
            reader = self._fresh_action_reader(fixture)
            read, calls, after = reader._read_action_authority, [], []
            def drift(**kwargs):
                if calls:
                    state = thaw(reader._issuer.read_task_state("task-wp05").state)
                    state["destinations"]["between-complete-reads"] = {"kind": "owner"}
                    with fixture.repository._factory.open("application") as connection:
                        with connection.transaction():
                            connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                                (canonical_json(state), semantic_record_digest({"contract": "task-security-state-v1", "value": state}), "task-wp05"))
                    after.append(self._repository_rows(fixture))
                calls.append(kwargs["action_id"])
                return read(**kwargs)
            with mock.patch.object(reader, "_read_action_authority", side_effect=drift):
                with self.assertRaisesRegex(ValueError, "changed during query"):
                    reader._read_completed_action_provenance(task_id="task-wp05", action_id=outcome.action_id)
            self.assertEqual(len(calls), 2)
            self.assertEqual(self._repository_rows(fixture), after[0])
            self.assertEqual(reader._issued_outcomes, {})
            reader._retained_scope(require_idle=True)


    def test_completed_provenance_rejects_boolean_number_substitution(self):
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json, semantic_record_digest

        for mode in ("observation", "receipt-fence"):
            with self.subTest(mode=mode), self._owner_root(applied=True) as values:
                fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
                session.close()
                with fixture.repository._factory.open("application") as connection:
                    with connection.transaction():
                        column = "reconciliation_json" if mode == "observation" else "receipt_json"
                        body = parse_canonical_json(connection.execute("SELECT " + column + " FROM action_journal WHERE action_id=?",
                            (outcome.action_id,)).fetchone()[0])
                        if mode == "observation":
                            self.assertEqual(body["state"]["generation"], 1)
                            body["state"]["generation"] = True
                            connection.execute("UPDATE claims SET outcome_digest=? WHERE claim_id=?", (
                                semantic_record_digest({"contract": "claim-outcome-v1",
                                    "state": "reconciled_effect_verified", "value": body}), outcome.claim_id))
                        else:
                            self.assertEqual(body["fencing_token"], 1)
                            body["fencing_token"] = True
                            body["receipt_digest"] = semantic_record_digest({"contract": "action-receipt-v1",
                                "value": {key: value for key, value in body.items() if key != "receipt_digest"}})
                        connection.execute("UPDATE action_journal SET " + column + "=? WHERE action_id=?",
                            (canonical_json(body), outcome.action_id))
                if mode == "receipt-fence":
                    self._rewrite_provenance_event(fixture, "action.receipt_recorded",
                        lambda event: event["payload"].update(receipt_digest=body["receipt_digest"]))
                before = self._repository_rows(fixture)
                with self.assertRaises(ValueError):
                    self._fresh_action_reader(fixture)._read_completed_action_provenance(
                        task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(self._repository_rows(fixture), before)

    def test_action_authority_reader_is_immutable_and_has_no_write_or_execution_authority(self):
        from graph_engineering.storage.connection import ManagedConnection

        with self._owner_root(applied=True) as values:
            fixture, _runtime, namespace, factory, session, binding, outcome = values
            reader = self._fresh_action_reader(fixture)
            session.close()
            fixture.expire_action_lease()
            before = self._repository_rows(fixture)
            root_before = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
            execute = ManagedConnection.execute
            reads = []
            def only_doctor_reads(connection, sql, parameters=()):
                self.assertEqual(connection._role, "doctor")
                self.assertTrue(sql.lstrip().upper().startswith("SELECT"))
                reads.append(sql)
                return execute(connection, sql, parameters)
            with factory._open_retained_storage_query(action_coordinator=fixture.raw_coordinator,
                    retained_namespace=namespace, binding=binding) as handle, \
                 mock.patch.object(ManagedConnection, "execute", new=only_doctor_reads), \
                 mock.patch.object(reader._issuer, "issue_task_context", side_effect=AssertionError("write context")), \
                 mock.patch.object(reader, "_issue_outcome", side_effect=AssertionError("mutation outcome")), \
                 mock.patch.object(reader, "issue_durable_execution_gate", side_effect=AssertionError("execution gate")):
                projection = reader._read_action_authority(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(projection, reader._read_action_authority(
                    task_id="task-wp05", action_id=outcome.action_id))
                self.assertEqual(projection["action_id"], outcome.action_id)
                self.assertEqual(projection["journal_state"], "reconciled")
                self.assertEqual(projection["authority"]["prepared_action_digest"],
                    projection["prepared"]["prepared_action_digest"])
                self.assertNotIn("receipt", projection)
                with self.assertRaises(TypeError):
                    projection["prepared"]["payload"]["changed"] = True
                with self.assertRaises(TypeError):
                    projection["authority"]["authorized_resources"][0] = "foreign"
                with self.assertRaisesRegex(ValueError, "missing, forged, or foreign"):
                    reader.require_issued_outcome(projection)
                self.assertEqual(dict(handle.query()), root_before)
                self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)
            self.assertTrue(reads)
            self.assertEqual(reader._issued_outcomes, {})
            self.assertEqual(reader._retained_actions, {})
            self.assertEqual(self._repository_rows(fixture), before)
            self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, root_before)
            self.assertEqual(session.target.apply_count, 1)

    def test_action_authority_reader_rejects_durable_substitution_and_revocation(self):
        import json
        from graph_engineering.core.actions import AuthorityEnvelope, PreparedAction
        from graph_engineering.core.contracts.immutable import thaw
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest
        from graph_engineering.storage.errors import RepositoryConflictError

        cases = ("missing-authority", "unfinished", "revoked", "prepared-action", "prepared-index",
            "authority-owner", "authority-resources", "authority-prepared", "authority-snapshot",
            "target", "revocation")
        for change in cases:
            with self.subTest(change=change), self._owner_root(applied=True) as values:
                fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
                session.close()
                reader = self._fresh_action_reader(fixture)
                state = thaw(reader._issuer.read_task_state("task-wp05").state)
                with fixture.repository._factory.open("application") as connection:
                    with connection.transaction():
                        prepared_text, authority_text = connection.execute(
                            "SELECT prepared_json,authority_json FROM action_journal WHERE action_id=?",
                            (outcome.action_id,)).fetchone()
                        prepared, authority = json.loads(prepared_text), json.loads(authority_text)
                        if change == "missing-authority":
                            connection.execute("UPDATE action_journal SET authority_json=NULL WHERE action_id=?",
                                (outcome.action_id,))
                        elif change in {"unfinished", "revoked"}:
                            connection.execute("UPDATE action_journal SET state=? WHERE action_id=?",
                                ("succeeded" if change == "unfinished" else "revoked", outcome.action_id))
                        elif change == "prepared-action":
                            prepared["action_id"] = "substituted-action"
                            prepared["prepared_action_digest"] = PreparedAction.digest_document(prepared, fixture.context)
                            connection.execute("UPDATE action_journal SET prepared_json=?,prepared_digest=? WHERE action_id=?",
                                (canonical_json(prepared), prepared["prepared_action_digest"], outcome.action_id))
                        elif change == "prepared-index":
                            connection.execute("UPDATE action_journal SET prepared_digest=? WHERE action_id=?",
                                ("sha256-jcs-v1:" + "0" * 64, outcome.action_id))
                        elif change.startswith("authority-"):
                            field, replacement = {
                                "authority-owner": ("owner_id", "foreign-owner"),
                                "authority-resources": ("authorized_resources", ["target:foreign"]),
                                "authority-prepared": ("prepared_action_digest", "sha256-jcs-v1:" + "0" * 64),
                                "authority-snapshot": ("snapshot_digest", "sha256-jcs-v1:" + "0" * 64),
                            }[change]
                            authority[field] = replacement
                            authority["authority_digest"] = AuthorityEnvelope.digest_document(authority, fixture.context)
                            connection.execute("UPDATE action_journal SET authority_json=?,authority_digest=? WHERE action_id=?",
                                (canonical_json(authority), authority["authority_digest"], outcome.action_id))
                            state["authority_digests"] = [authority["authority_digest"]]
                        elif change == "revocation":
                            state["authority_digests"] = []
                        if change.startswith("authority-") or change == "revocation":
                            state_digest = semantic_record_digest({"contract": "task-security-state-v1", "value": state})
                            connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                                (canonical_json(state), state_digest, "task-wp05"))
                if change == "target":
                    retarget_security_binding(fixture, target_digest="sha256-jcs-v1:" + "0" * 64)
                before = self._repository_rows(fixture)
                with self.assertRaises((ValueError, RepositoryConflictError)):
                    reader._read_action_authority(task_id="task-wp05", action_id=outcome.action_id)
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual(reader._issued_outcomes, {})

    def test_action_authority_reader_rejects_foreign_ports_locks_and_final_read_drift(self):
        from graph_engineering.storage.codec import canonical_json, semantic_record_digest
        from graph_engineering.core.contracts.immutable import thaw

        with self._owner_root(applied=True) as values:
            fixture, _runtime, _namespace, _factory, session, _binding, outcome = values
            session.close()
            reader = self._fresh_action_reader(fixture)
            read = lambda: reader._read_action_authority(task_id="task-wp05", action_id=outcome.action_id)
            before = self._repository_rows(fixture)
            with self.assertRaises(ValueError):
                reader._read_action_authority(task_id="foreign-task", action_id=outcome.action_id)
            for invalid in (None, {}, outcome):
                with self.subTest(invalid=type(invalid).__name__), self.assertRaises(ValueError):
                    reader._read_action_authority(task_id="task-wp05", action_id=invalid)
            token = fixture.locks.acquire_installation("shared")
            try:
                with self.assertRaisesRegex(ValueError, "repository.*held"):
                    read()
            finally:
                fixture.locks.release(token)
            with fixture.repository._factory.open("doctor"):
                with self.assertRaisesRegex(ValueError, "repository.*held"):
                    read()
            with action_stack() as foreign, mock.patch.object(reader, "_objects", foreign.objects):
                with self.assertRaisesRegex(ValueError, "scope differs"):
                    read()
            self.assertEqual(self._repository_rows(fixture), before)
            read_security = reader._issuer.read_task_state
            for change in ("security", "journal"):
                calls, drifted_rows = [], []
                def change_during_read(task_id):
                    calls.append(task_id)
                    if len(calls) == (2 if change == "security" else 1):
                        state = thaw(read_security(task_id).state)
                        state["destinations"]["changed-during-read"] = {"kind": "owner"}
                        digest = semantic_record_digest({"contract": "task-security-state-v1", "value": state})
                        with fixture.repository._factory.open("application") as connection:
                            with connection.transaction():
                                if change == "security":
                                    connection.execute("UPDATE task_security_states SET state_json=?,state_digest=? WHERE task_id=?",
                                        (canonical_json(state), digest, task_id))
                                else:
                                    connection.execute("UPDATE action_journal SET revision=revision+1 WHERE action_id=?",
                                        (outcome.action_id,))
                        drifted_rows.append(self._repository_rows(fixture))
                    return read_security(task_id)
                with self.subTest(change=change), \
                     mock.patch.object(reader._issuer, "read_task_state", side_effect=change_during_read):
                    with self.assertRaisesRegex(ValueError, "changed during query"):
                        read()
                self.assertEqual(len(calls), 2)
                self.assertEqual(self._repository_rows(fixture), drifted_rows[0])
                self.assertEqual(reader._issued_outcomes, {})
                read()  # A fresh read uses current data; the prior attempt stays rejected.

    def test_runtime_storage_query_keeps_one_lease_and_issues_no_mutation_authority(self):
        with self._owner_root(applied=True) as values:
            fixture, _runtime, namespace, original, session, binding, outcome = values
            coordinator = fixture.raw_coordinator
            native = namespace.require_current(coordinator)
            path = session._root._root_path
            session.close()
            factory = ReleaseOperationsRegistryFactory.from_installation()
            expected = {p.name: p.read_bytes() for p in path.iterdir()}
            task = fixture.repository.load("task-wp05")
            security = coordinator._issuer.read_task_state("task-wp05")
            journal, claim = fixture.journal.load(outcome.action_id), fixture.leases.load_claim(outcome.claim_id)
            read_security = coordinator._issuer.read_task_state
            reads = []
            def under_root(task_id):
                self.assertEqual(native.active_leases, 1)
                coordinator._require_retained_idle()
                reads.append(task_id)
                result = read_security(task_id)
                coordinator._require_retained_idle()
                return result
            with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=under_root), \
                 mock.patch.object(coordinator._issuer, "issue_task_context", side_effect=AssertionError("mutation context")), \
                 mock.patch.object(coordinator, "_issue_outcome", side_effect=AssertionError("mutation outcome")), \
                 mock.patch.object(coordinator, "issue_durable_execution_gate", side_effect=AssertionError("execution gate")):
                with factory._open_retained_storage_query(action_coordinator=coordinator,
                        retained_namespace=namespace, binding=binding) as handle:
                    self.assertEqual(dict(handle.query()), expected)
                    with mock.patch.object(native, "_open", side_effect=AssertionError("root reacquired")):
                        self.assertEqual(dict(handle.query()), expected)
                    self.assertEqual(native.active_leases, 1)
                    for name in ("target", "execute", "compensate", "reconcile", "destroy"):
                        self.assertFalse(hasattr(handle, name))
            self.assertGreaterEqual(len(reads), 5)
            self.assertEqual(native.active_leases, 0)
            self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, expected)
            self.assertEqual(fixture.repository.load("task-wp05"), task)
            self.assertEqual(coordinator._issuer.read_task_state("task-wp05"), security)
            self.assertEqual(fixture.journal.load(outcome.action_id), journal)
            self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
            self.assertEqual(session.target.apply_count, 1)
            for name in ("_issued", "_issued_sessions", "_issued_deployments", "_issued_health"):
                self.assertEqual(getattr(factory, name), {})

    def test_runtime_storage_query_rejects_foreign_busy_and_repository_lock_entries(self):
        import copy
        from graph_engineering.core.release_operations import ReleaseRecoveryBinding

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, binding, _outcome = values
            coordinator = fixture.raw_coordinator
            native = namespace.require_current(coordinator)
            path = session._root._root_path
            expected = {p.name: p.read_bytes() for p in path.iterdir()}
            def open_query(**overrides):
                return overrides.pop("factory", factory)._open_retained_storage_query(**{
                    "action_coordinator": coordinator, "retained_namespace": namespace,
                    "binding": binding, **overrides})
            with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=AssertionError("read before root gate")):
                with self.assertRaisesRegex(ValueError, "busy"):
                    open_query()
            session.close()
            with mock.patch.object(native, "open_readonly_handle", side_effect=AssertionError("root admission")):
                for overrides in ({"factory": copy.copy(factory)}, {"retained_namespace": copy.copy(namespace)},
                                  {"binding": binding.to_dict()}, {"action_coordinator": object()}):
                    with self.subTest(overrides=tuple(overrides)), self.assertRaises(ValueError):
                        open_query(**overrides)
                for field in ("repository_scope_digest", "installation_pins"):
                    value = binding.to_dict()
                    if field == "repository_scope_digest":
                        value[field] = "sha256-jcs-v1:" + "0" * 64
                    else:
                        value[field]["bootstrap_digest"] = "sha256-jcs-v1:" + "0" * 64
                    value.pop("binding_digest")
                    value["binding_digest"] = _semantic(value, "release-recovery-binding")
                    changed = ReleaseRecoveryBinding.from_dict(value)
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        open_query(binding=changed)
                token = fixture.locks.acquire_installation("shared")
                try:
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        open_query()
                finally:
                    fixture.locks.release(token)
                with fixture.repository._factory.open("doctor"):
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        open_query()
            handle = open_query()
            try:
                token = fixture.locks.acquire_installation("shared")
                try:
                    for action in (handle.query, handle.close):
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            action()
                    self.assertEqual(native.active_leases, 1)
                finally:
                    fixture.locks.release(token)
                self.assertEqual(dict(handle.query()), expected)
                with self.assertRaisesRegex(ValueError, "busy"):
                    open_query()
            finally:
                handle.close()
            self.assertEqual(native.active_leases, 0)
            self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, expected)

    def test_runtime_storage_query_revokes_on_runtime_security_and_final_read_drift(self):
        import os
        from graph_engineering.application.runtime import RuntimeSessionError

        for drift in ("runtime", "security", "final-file-swap", "read-error"):
            with self.subTest(drift=drift), self._owner_root() as values:
                fixture, runtime, namespace, factory, session, binding, _outcome = values
                coordinator = fixture.raw_coordinator
                native = namespace.require_current(coordinator)
                path = session._root._root_path
                session.close()
                handle = factory._open_retained_storage_query(action_coordinator=coordinator,
                    retained_namespace=namespace, binding=binding)
                self.addCleanup(handle.close)
                task = fixture.repository.load("task-wp05")
                expected = {p.name: p.read_bytes() for p in path.iterdir()}
                if drift == "runtime":
                    runtime.close()
                elif drift == "security":
                    retarget_security_binding(fixture, target_digest="sha256-jcs-v1:" + "0" * 64)
                read_security = coordinator._issuer.read_task_state
                reads = []
                def drift_during_final_read(task_id):
                    result = read_security(task_id)
                    reads.append(task_id)
                    if drift == "read-error":
                        raise OSError("injected read-only security failure")
                    if drift == "final-file-swap" and len(reads) == 2:
                        victim = path / session._root.names["active_artifact"]
                        previous = victim.stat()
                        replacement = path / "replacement"
                        replacement.write_bytes(victim.read_bytes())
                        replacement.chmod(previous.st_mode & 0o777)
                        os.replace(replacement, victim)
                        self.assertNotEqual(previous.st_ino, victim.stat().st_ino)
                    return result
                with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=drift_during_final_read):
                    error_type = RuntimeSessionError if drift == "runtime" else (
                        OSError if drift == "read-error" else ReleaseOperationsError)
                    with self.assertRaises(error_type):
                        handle.query()
                if drift == "final-file-swap":
                    self.assertEqual(len(reads), 2)
                self.assertEqual(native.active_leases, 0)
                with self.assertRaises(ValueError):
                    handle.query()
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, expected)
                self.assertEqual(fixture.repository.load("task-wp05"), task)

    def test_owner_destroy_quiesced_root_revokes_before_cleanup_without_repository_writes(self):
        import os

        for applied in (False, True):
            with self.subTest(applied=applied), self._owner_root(applied=applied) as values:
                fixture, _runtime, namespace, factory, session, binding, outcome = values
                coordinator = fixture.raw_coordinator
                native = namespace.require_current(coordinator)
                root = session._root._root_path
                session.close()
                before = fixture.repository.load("task-wp05")
                security = coordinator._issuer.read_task_state("task-wp05")
                journal = fixture.journal.load(outcome.action_id) if outcome else None
                claim = fixture.leases.load_claim(outcome.claim_id) if outcome else None
                events = []
                unlink, fsync = os.unlink, os.fsync

                def observe_unlink(name, *, dir_fd=None):
                    self.assertEqual(native.active_leases, 1)
                    events.append(("unlink", name))
                    if name != ".release-simulator-root":
                        self.assertEqual(events[:2], [("unlink", ".release-simulator-root"), ("fsync", None)])
                    return unlink(name, dir_fd=dir_fd)

                def observe_fsync(fd):
                    events.append(("fsync", None))
                    return fsync(fd)

                original_read = coordinator._issuer.read_task_state
                def read_under_lease(task_id):
                    self.assertEqual(native.active_leases, 1)
                    return original_read(task_id)

                with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=read_under_lease), \
                     mock.patch.object(coordinator._issuer, "issue_task_context", side_effect=AssertionError("mutable security read")), \
                     mock.patch("graph_engineering.adapters.local_release_simulator.os.unlink", side_effect=observe_unlink), \
                     mock.patch("graph_engineering.adapters.local_release_simulator.os.fsync", side_effect=observe_fsync):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                self.assertFalse(root.exists())
                self.assertEqual(native.active_leases, 0)
                self.assertEqual(fixture.repository.load("task-wp05"), before)
                self.assertEqual(coordinator._issuer.read_task_state("task-wp05"), security)
                if outcome:
                    self.assertEqual(fixture.journal.load(outcome.action_id), journal)
                    self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
                self.assertEqual(session.target.apply_count, int(applied))
                with self.assertRaises(ValueError):
                    session.observer.observe()
                with self.assertRaises(ValueError):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)

    def test_owner_destroy_rejects_live_foreign_cloned_and_repository_busy_entries(self):
        import copy
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, _binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            with mock.patch.object(_RetainedNamespace, "open_readonly", side_effect=AssertionError("root opened")):
                with self.assertRaisesRegex(ValueError, "quiesced"):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                session.close()
                for candidate, authority in ((copy.copy(session), namespace), (session, copy.copy(namespace)),
                                              (session, pathlib.Path(root.parent))):
                    with self.subTest(candidate=type(candidate).__name__, authority=type(authority).__name__), self.assertRaises(ValueError):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=authority, session=candidate)
                with action_stack() as foreign:
                    with self.assertRaises(ValueError):
                        factory.destroy_retained_simulator(action_coordinator=foreign.raw_coordinator,
                            retained_namespace=namespace, session=session)
                token = fixture.locks.acquire_installation("shared")
                try:
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=namespace, session=session)
                finally:
                    fixture.locks.release(token)
                with fixture.repository._factory.open("doctor"):
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=namespace, session=session)
                with self.assertRaises(ValueError):
                    ReleaseOperationsRegistryFactory.from_installation().destroy_retained_simulator(
                        action_coordinator=coordinator, retained_namespace=namespace, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)

    def test_owner_destroy_busy_root_preserves_competing_reader_and_checks_owner_under_lease(self):
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, _retained_members

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            members = {name: 0o600 for role, name in _retained_members(factory.registry().fixture("release-foundation-v1")).items() if role != "identity"}
            session.close()
            with _RetainedNamespace(root.parent) as other:
                with other.open_readonly(binding, members=members, context=coordinator._policy._context) as reader:
                    with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=AssertionError("read before root admission")):
                        with self.assertRaisesRegex(ValueError, "busy"):
                            factory.destroy_retained_simulator(action_coordinator=coordinator,
                                retained_namespace=namespace, session=session)
                    self.assertEqual(reader.read(".release-simulator-root", max_bytes=10000), before[".release-simulator-root"])
            with self._runtime("wrong-owner") as stranger:
                with stranger.bind_release_namespace(action_coordinator=coordinator, namespace_path=root.parent) as foreign:
                    with self.assertRaisesRegex(ValueError, "own"):
                        factory.destroy_retained_simulator(action_coordinator=coordinator,
                            retained_namespace=foreign, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)

    def test_owner_destroy_rejects_changed_target_and_revoked_runtime_without_cleanup(self):
        from tests.support.wp05_actions import digest

        for attack in ("target", "runtime"):
            with self.subTest(attack=attack), self._owner_root() as values:
                fixture, runtime, namespace, factory, session, _binding, _outcome = values
                root = session._root._root_path
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                session.close()
                if attack == "target":
                    retarget_security_binding(fixture, target_digest=digest("other-target"))
                else:
                    runtime.close()
                with self.assertRaises((ValueError, RuntimeError)):
                    factory.destroy_retained_simulator(action_coordinator=fixture.raw_coordinator,
                        retained_namespace=namespace, session=session)
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                self.assertEqual(namespace._record()[4].active_leases, 0)

    def test_owner_destroy_interrupted_cleanup_leaves_ineligible_orphan_and_releases_lease(self):
        import os

        with self._owner_root() as values:
            fixture, _runtime, namespace, factory, session, _binding, _outcome = values
            coordinator = fixture.raw_coordinator
            root = session._root._root_path
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            session.close()
            unlink = os.unlink
            def fail_cleanup(name, *, dir_fd=None):
                if name != ".release-simulator-root":
                    raise OSError("injected member cleanup interruption")
                return unlink(name, dir_fd=dir_fd)
            with mock.patch("graph_engineering.adapters.local_release_simulator.os.unlink", side_effect=fail_cleanup), \
                 self.assertRaisesRegex(OSError, "cleanup interruption"):
                factory.destroy_retained_simulator(action_coordinator=coordinator,
                    retained_namespace=namespace, session=session)
            self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()},
                {k: v for k, v in before.items() if k != ".release-simulator-root"})
            self.assertEqual(namespace.require_current(coordinator).active_leases, 0)
            with self.assertRaises(ValueError):
                factory.destroy_retained_simulator(action_coordinator=coordinator,
                    retained_namespace=namespace, session=session)
            with self.assertRaises(ValueError):
                self._issue(fixture, namespace)

    def test_owner_destroy_final_security_and_runtime_rereads_reject_midflight_drift(self):
        from tests.support.wp05_actions import digest

        for attack in ("security", "runtime"):
            with self.subTest(attack=attack), self._owner_root() as values:
                fixture, runtime, namespace, factory, session, _binding, _outcome = values
                coordinator = fixture.raw_coordinator
                root = session._root._root_path
                before = {p.name: p.read_bytes() for p in root.iterdir()}
                session.close()
                read = coordinator._issuer.read_task_state
                calls = []
                def drift(task_id):
                    value = read(task_id)
                    calls.append(task_id)
                    if len(calls) == 1 and attack == "security":
                        retarget_security_binding(fixture, target_digest=digest("midflight-target"))
                    if len(calls) == 2 and attack == "runtime":
                        runtime.close()
                    return value
                with mock.patch.object(coordinator._issuer, "read_task_state", side_effect=drift), \
                     self.assertRaises((ValueError, RuntimeError)):
                    factory.destroy_retained_simulator(action_coordinator=coordinator,
                        retained_namespace=namespace, session=session)
                self.assertEqual(calls, ["task-wp05", "task-wp05"])
                self.assertEqual({p.name: p.read_bytes() for p in root.iterdir()}, before)
                self.assertEqual(namespace._record()[4].active_leases, 0)

    @contextmanager
    def _same_task_assessment(self, *, cold=False, partial=False, column="normal", accepted=True, task_id="task-wp05"):
        """RS-2 live lease proof, not RS-4 artifact/target provenance proof.

        The legacy category observer and synthetic runner/artifact records stay
        test fixtures; this does not make them eligible for cold recovery.
        """
        import tempfile
        from tests.contract.test_wp02_graph import graph_schemas, work_context
        from graph_engineering.application.tasks import TaskApplication
        from graph_engineering.application.profile_execution import _category_selector

        profile_id = "release-operations"
        api = category_fixture.load_slice3_api()
        with ExitStack() as stack:
            fixture = stack.enter_context(action_stack(domain_task=True, task_id=task_id))
            # action_stack creates the domain before installing its action-aware
            # repository facade. Use one exact facade for subsequent consumers.
            fixture.task_application = TaskApplication(
                fixture.repository, fixture.repository, fixture.leases,
                schema_registry=graph_schemas(), context=work_context(),
                materialization_objects=fixture.objects)
            runtime = stack.enter_context(self._runtime())
            directory = stack.enter_context(tempfile.TemporaryDirectory(prefix="gew-retained-assessment-"))
            namespace = stack.enter_context(runtime.bind_release_namespace(
                action_coordinator=fixture.raw_coordinator,
                namespace_path=pathlib.Path(directory).resolve()))
            factory, session, baseline, artifact = self._issue(fixture, namespace)
            fixture.release_factory, fixture.retained_namespace = factory, namespace
            stack.enter_context(session)
            deployment = rollback_observation = None
            real_authority = None
            scenario_id = None
            if partial:
                self.assertTrue(cold)
                from graph_engineering.core.actions import PreparedAction

                def fault(step):
                    if step == "after-stage-durable":
                        raise TimeoutError("cold producer partial cut")
                session._root.fault_hook = fault
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=artifact, candidate_bytes=factory.artifact_bytes(artifact))
                document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                prepared = fixture.coordinator.prepare(document)
                fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                outcome = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                    observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
                self.assertEqual(outcome.route, "manual-reconciliation")
                deployment = factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                    session=session, outcome=outcome)
                restore = fixture.coordinator.prepare(release_partial_restore_prepared_document(fixture,
                    target_digest=session.target.target_digest, baseline=baseline,
                    baseline_bytes=factory.artifact_bytes(baseline), candidate=artifact,
                    original_claim_id=outcome.claim_id, original_receipt_digest=outcome.receipt_digest))
                fixture.coordinator.authorize(authority_document(restore, context=fixture.context))
                restored = fixture.coordinator.compensate_unknown(prepared.action_id,
                    compensation_action_id=restore.action_id, recovery_lease=fixture.action_lease,
                    owner_id="owner-wp05", runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                    target=session.target, observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, restore))
                self.assertEqual(restored.route, "compensation-reconciled")
                rollback_observation = factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator, session=session, outcome=restored)
                scenario_id = "GEW-PSC-RELEASE-OPERATIONS-PARTIAL-DEPLOY-P"
            elif column == "real-e2e":
                from graph_engineering.core.actions import PreparedAction
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=artifact, candidate_bytes=factory.artifact_bytes(artifact))
                document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                if not accepted:
                    document["precondition"]["generation"] = 1
                    document["payload"]["expected_generation"] = 1
                    document["payload_digest"] = PreparedAction.payload_digest_for(document["payload"], fixture.context)
                document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                prepared = fixture.coordinator.prepare(document)
                fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                real_authority = factory._execute_category_action(action_coordinator=fixture.raw_coordinator,
                    session=session, action_id=prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    disclosure_plan=release_disclosure_plan(fixture, prepared))
                outcome, deployment = real_authority._outcome, real_authority._deployment
            else:
                outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                    fixture, session, baseline, artifact, factory.artifact_bytes(artifact))
            fixture.leases.release(fixture.action_lease.lease_id)
            # Continue the existing domain task through its normal transitions.
            # Do not copy action rows or repair a wrapper snapshot after apply.
            shared = category_fixture.SharedProductionCategoryRuntime(
                profile_id, ExitStack(), fixture.factory, fixture.objects,
                fixture.repository, fixture.leases, graph_schemas(), work_context(),
                fixture.task_application, fixture.task_runtime)
            target = (category_fixture.RetainedCategoryTarget(session) if cold
                      else category_fixture.DisposableLocalTarget(profile_id))
            if real_authority is not None:
                target = real_authority.issue_observer()
            if column == "rollback":
                target.expected_state = {"schema_version": "1.0.0", **dict(prepared.expected_postcondition)}
            stack.callback(target.close)
            cold_options = {}
            if cold:
                from tests.support.wp05_actions import compensation_prepared_document, security_context
                cold_options = {"cold_release_factory": factory,
                    "intent_baseline": fixture.raw_coordinator._issuer.read_task_state(task_id).state["binding"]["baselines"]["intent"],
                    "committed_rollback_action_id": compensation_prepared_document(context=security_context())["action_id"]}
                if column == "rollback":
                    cold_options["committed_rollback_action_id"] = rollback_observation.to_dict()["action_id"]
                    cold_options["committed_rollback_claim_status"] = "compensation_reconciled"
            task_application, repository, objects, task_runtime, probe = (
                category_fixture.production_category_runtime(
                    profile_id, column, target=target, task_id=task_id,
                    shared_runtime=shared, existing_created_task=True, scenario_id=scenario_id,
                    real_e2e_authority=real_authority, **cold_options))
            stack.callback(probe.close)
            self.assertIs(repository, fixture.repository)
            self.assertIs(task_application, fixture.task_application)
            self.assertEqual(probe.task_id, fixture.journal.load(
                prepared.action_id if outcome is None else outcome.action_id).prepared.task_id)
            policy = api.CategoryExecutionPolicy.from_installation(
                profile_document=category_fixture.profile_document(profile_id),
                support_matrix_document=category_fixture.load_json(category_fixture.SUPPORT_MATRIX_PATH),
                materialization_record=category_fixture.materialized_profile(profile_id).record)
            target_authority = api.CategoryTargetObservationAuthority(policy)
            oracle = api.CategoryCompletionOracle(policy=policy,
                target_authority=target_authority, release_operations_factory=factory)
            # The unused rollback-column source remains the legacy fixture. The
            # normal release apply, task transitions and assessment share ports.
            if column == "rollback":
                rollback = api.CategoryRollbackBridge(policy, fixture.raw_coordinator)
            else:
                rollback_coordinator, rollback_context = category_fixture.action_rollback_binding(probe, target)
                rollback = api.CategoryRollbackBridge(policy, rollback_coordinator)
                rollback.prepare_action(**rollback_context)
            if not cold:
                probe.bind_rollback_evidence(rollback)
            application = api.CategoryExecutionApplication(repository=repository,
                object_repository=objects, policy=policy, reducer=api.CategoryExecutionReducer(policy),
                completion_oracle=oracle, rollback_bridge=rollback,
                assessment_resolver=api.CategoryAssessmentResolver(repository, objects,
                    task_application=task_application, runtime=task_runtime),
                task_application=task_application, runtime=task_runtime, target_observer=target)
            candidate = category_fixture.candidate_document(profile_id, column)
            if scenario_id is not None:
                candidate["scenario_id"] = scenario_id
            candidate["task_id"] = probe.task_id
            if cold:
                candidate["target_id"] = target.target_id
            if real_authority is not None and real_authority.disposition == "R":
                application.bind_current_sources(probe.task_id)
                yield api, fixture, session, application, probe, target, candidate, None, None
                return
            _issued, current = application._authoritative_candidate(_category_selector(candidate), target)
            if deployment is None:
                deployment = factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator, session=session, outcome=outcome)
            health = factory.issue_health_observation(session=session,
                terminal_observation=rollback_observation if partial else deployment)
            evidence = factory.issue_evidence(task_id=probe.task_id,
                task_revision=int(current["task_revision"]), snapshot_digest=str(current["snapshot_digest"]),
                invalidation_epoch=int(current["invalidation_epoch"]), graph_ref_pins=dict(current["digest_pins"]),
                artifact_manifest=artifact, deployment_observation=deployment, health_observation=health,
                rollback_observation=rollback_observation, session=session,
                owner_route="release-operations-owner" if partial else "reconciled-effect-verified",
                column_id=column, scenario_id=str(current["scenario_id"]),
                outcome="partial-deploy-restored" if partial else "artifact-provenance-verified")
            if column == "rollback":
                facts = rollback._adopt_completed_release(factory, evidence)
                record = probe.resolve_category_evidence(probe.task_id, "rollback")
                self.assertEqual(record["facts"], dict(facts))
            application.bind_current_sources(probe.task_id)
            yield api, fixture, session, application, probe, target, candidate, evidence, outcome

    def test_release_coverage_task_identity_is_created_before_action(self):
        from tests.support.wp08_release_operations import release_mandatory_runtime

        task_id = "task:wp08-coverage:gew-pro-release-operations-normal-p"
        with release_mandatory_runtime(column="normal", task_id=task_id, accepted=True) as value:
            _api, fixture, _session, application, probe, target, candidate, evidence, outcome = value
            self.assertEqual(probe.task_id, task_id)
            self.assertEqual(fixture.journal.load(outcome.action_id).prepared.task_id, task_id)
            self.assertEqual(candidate["task_id"], task_id)
            result = application.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
            self.assertEqual(result.assessment.task_id, task_id)
            self.assertEqual(result.assessment.schema_version, "1.4.0")

    def test_release_coverage_initial_authorities_use_selected_task(self):
        from tests.support.wp05_actions import prepared_document, compensation_prepared_document
        from graph_engineering.core.actions import PreparedAction

        task_id = "task:wp08-coverage:gew-pro-release-operations-normal-r"
        with action_stack(domain_task=True, task_id=task_id) as fixture:
            state = fixture.issuer.read_task_state(task_id).state
            authorities = []
            for build in (prepared_document, compensation_prepared_document):
                document = build(context=fixture.context)
                document["task_id"] = task_id
                document["resources"] = ["target:project", "task:" + task_id]
                document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                prepared = PreparedAction.from_dict(document, context=fixture.context)
                authorities.append(authority_document(prepared)["authority_digest"])
                if build is prepared_document:
                    self.assertEqual(state["destinations"]["owner-wp05"]["prepared_action_digest"], prepared.prepared_action_digest)
            self.assertEqual(sorted(state["authority_digests"]), sorted(authorities))

    def test_cold_mandatory_non_action_columns_restore_complete_sources_without_writes(self):
        from graph_engineering.application.release_operations import restore_current_release_assessment

        columns = ("boundary", "revise", "authority", "drift", "invalidation",
                   "artifacts", "review", "target")
        for column in columns:
            with self.subTest(column=column), self._same_task_assessment(cold=True, column=column) as values:
                _api, fixture, session, app, probe, target, candidate, evidence, _ = values
                receipt = app.assess_and_commit(candidate, observer=target,
                    release_operations_evidence=evidence)
                self.assertEqual(receipt.assessment.column_id, column)
                mutations, applies = session._root.mutation_count, session.target.apply_count
                physical = {p.name: p.read_bytes() for p in session._root._root_path.iterdir()}
                session.close()
                before = self._repository_rows(fixture)
                handle = restore_current_release_assessment(task_application=app._task_application,
                    runtime=app._runtime, policy=app._policy,
                    release_factory=ReleaseOperationsRegistryFactory.from_installation(),
                    object_repository=fixture.objects, action_coordinator=fixture.raw_coordinator,
                    retained_namespace=fixture.retained_namespace, task_id=probe.task_id)
                try:
                    first, second = handle.query(), handle.query()
                    self.assertEqual(first["assessment_bytes"], receipt.assessment.to_bytes())
                    self.assertEqual(second["assessment_bytes"], first["assessment_bytes"])
                    self.assertEqual(first["assessment"]["column_id"], column)
                    self.assertGreater(second["observation_revision"], first["observation_revision"])
                finally:
                    handle.close()
                self.assertEqual(self._repository_rows(fixture), before)
                self.assertEqual((session._root.mutation_count, session.target.apply_count), (mutations, applies))
                self.assertEqual({p.name: p.read_bytes() for p in session._root._root_path.iterdir()}, physical)
                self.assertEqual(fixture.retained_namespace._record()[4].active_leases, 0)

    def test_same_task_retained_assessment_commits_with_original_lease_and_preserves_root(self):
        with self._same_task_assessment() as values:
            api, fixture, session, application, probe, target, candidate, evidence, outcome = values
            root = session._root
            lease = root._retained_lease
            before = {p.name: p.read_bytes() for p in root._root_path.iterdir()}
            journal = fixture.journal.load(outcome.action_id)
            claim = fixture.leases.load_claim(outcome.claim_id)
            mutations = root.mutation_count
            observations = []

            def in_transaction(step):
                if step == "commit.before_commit":
                    root._require_open()
                    self.assertIs(root._retained_lease, lease)
                    # Closing under the repository fence must not release the
                    # root. Only the outer session owner can close after unwind.
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        session.close()
                    observations.append(step)

            fixture.repository._fault = in_transaction
            receipt = application.assess_and_commit(candidate, observer=target,
                release_operations_evidence=evidence)
            fixture.repository._fault = None
            self.assertEqual(observations, ["commit.before_commit"])
            self.assertEqual(receipt.assessment.schema_version, "1.4.0")
            self.assertIsNotNone(receipt.assessment.release_operations_projection)
            view = fixture.task_application.runtime_show(probe.task_id, fixture.task_runtime)
            self.assertEqual(view.snapshot.lifecycle, "completed")
            self.assertEqual(view.snapshot.task_revision, receipt.assessment.task_revision + 1)
            self.assertEqual(fixture.objects.get(receipt.assessment.object_digest), receipt.assessment.to_bytes())
            self.assertIn(receipt.assessment.object_digest,
                [item[0] for item in fixture.repository.referenced_objects(probe.task_id)])
            self.assertEqual(fixture.journal.load(outcome.action_id), journal)
            self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
            self.assertEqual(root.mutation_count, mutations)
            self.assertEqual(session.target.apply_count, 1)
            self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, before)
            session.close()
            self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, before)
            with self.assertRaises(ValueError):
                session.observer.observe()

    def test_existing_category_task_input_rejects_implicit_or_advanced_task_before_publication(self):
        from tests.contract.test_wp02_graph import graph_schemas, work_context

        with self._same_task_assessment() as values:
            _api, fixture, _session, _application, probe, target, *_rest = values
            shared = category_fixture.SharedProductionCategoryRuntime(
                "release-operations", ExitStack(), fixture.factory, fixture.objects,
                fixture.repository, fixture.leases, graph_schemas(), work_context(),
                fixture.task_application, fixture.task_runtime)
            before = probe.signature()
            with mock.patch.object(fixture.task_application, "preauthorize_materialization",
                    side_effect=AssertionError("unexpected publication")) as publish:
                for runtime, existing, message in (
                    (None, True, "explicit shared runtime"),
                    (shared, 1, "explicit shared runtime"),
                    (shared, True, "exact created domain task"),
                ):
                    with self.subTest(existing=existing, message=message), self.assertRaisesRegex(AssertionError, message):
                        category_fixture.production_category_runtime("release-operations", "normal",
                            target=target, task_id=probe.task_id, shared_runtime=runtime,
                            existing_created_task=existing)
                publish.assert_not_called()
            self.assertEqual(probe.signature(), before)

    def test_same_task_retained_assessment_close_cuts_do_not_commit_or_reapply(self):
        for cut in ("before", "precommit", "transaction", "observer"):
            with self.subTest(cut=cut), self._same_task_assessment() as values:
                api, fixture, session, application, probe, target, candidate, evidence, outcome = values
                before = probe.signature()
                root = session._root
                tree = {p.name: p.read_bytes() for p in root._root_path.iterdir()}
                journal = fixture.journal.load(outcome.action_id)
                claim = fixture.leases.load_claim(outcome.claim_id)
                mutations = root.mutation_count
                reached = []

                def close_at_cut():
                    reached.append(cut)
                    session.close()

                if cut == "before":
                    close_at_cut()
                elif cut == "precommit":
                    application._fault = lambda step: (
                        close_at_cut() if step == "category-assessment.before-commit" else None)
                elif cut == "transaction":
                    fixture.repository._fault = lambda step: (
                        close_at_cut() if step == "commit.before_commit" else None)
                else:
                    armed = [False]
                    fixture.repository._fault = lambda step: (
                        armed.__setitem__(0, True) if step == "commit.before_commit" else None)
                    original_observe = target.observe

                    def final_observe():
                        if armed[0]:
                            close_at_cut()
                        return original_observe()

                    target.observe = final_observe
                with self.assertRaises((api.CategoryExecutionError, ValueError)):
                    application.assess_and_commit(candidate, observer=target,
                        release_operations_evidence=evidence)
                fixture.repository._fault = None
                self.assertEqual(reached, [cut])
                self.assertEqual(probe.signature(), before)
                self.assertEqual(fixture.journal.load(outcome.action_id), journal)
                self.assertEqual(fixture.leases.load_claim(outcome.claim_id), claim)
                self.assertEqual(root.mutation_count, mutations)
                self.assertEqual(session.target.apply_count, 1)
                self.assertEqual({p.name: p.read_bytes() for p in root._root_path.iterdir()}, tree)
                # Transaction/fence rejection leaves the original lease intact.
                if cut in ("transaction", "observer"):
                    root._require_open()
                session.close()

    @staticmethod
    def _runtime(owner_id="owner-wp05"):
        from graph_engineering.application.runtime import RuntimeSession
        from graph_engineering.core.runtime import RuntimeLineage
        from tests.unit.test_wp07_runtime_contract import FixtureAdapter, fixture_adapter, request, lineage, signed

        class Adapter(FixtureAdapter):
            def resolve_lineage(self, raw_input):
                value = lineage(value=raw_input["lineage_id"]).to_dict()
                value["owner_id"] = raw_input["owner_id"]
                value.pop("proof_digest")
                return RuntimeLineage.from_dict(signed("lineage", "proof_digest", value))
        return RuntimeSession.establish(fixture_adapter(Adapter),
            {"owner_id": owner_id, "lineage_id": "lineage-wp05"}, request())

    @staticmethod
    def _issue(fixture, namespace):
        factory = ReleaseOperationsRegistryFactory.from_installation()
        baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
        candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
        session = factory.issue_simulator(action_coordinator=fixture.raw_coordinator,
            retained_namespace=namespace, task_id=fixture.task_id, fixture_id="release-foundation-v1",
            target_id="target-project", resource_id="target:project", baseline_manifest=baseline,
            authorized_artifacts=(baseline, candidate))
        return factory, session, baseline, candidate

    def test_runtime_issued_namespace_creates_retained_target_and_close_preserves_bytes(self):
        import tempfile
        from graph_engineering.application.release_operations import RetainedReleaseNamespace

        with action_stack(domain_task=True) as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                self.assertIs(type(namespace), RetainedReleaseNamespace)
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    binding = session.recovery_binding
                    self.assertEqual(binding.target_digest(), session.target.target_digest)
                    WP08ReleaseOperationsIntegrationTests()._assert_apply(fixture, session, baseline, candidate, factory.artifact_bytes(candidate))
                    path = session._root._root_path
                    before = {p.name: p.read_bytes() for p in path.iterdir()}
                self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
                with self.assertRaises(ValueError):
                    session.observer.observe()
                with self.assertRaises(ValueError):
                    self._issue(fixture, namespace)

    def test_raw_cloned_foreign_and_expired_namespace_cannot_issue_session(self):
        import copy
        import tempfile
        with action_stack() as fixture, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            runtime = self._runtime()
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                for invalid in (pathlib.Path(directory), object(), copy.copy(namespace)):
                    with self.subTest(invalid=type(invalid).__name__), self.assertRaises(ValueError):
                        self._issue(fixture, invalid)
                with action_stack() as foreign:
                    with self.assertRaises(ValueError):
                        self._issue(foreign, namespace)
                runtime.close()
                with self.assertRaises((ValueError, RuntimeError)):
                    self._issue(fixture, namespace)
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_repository_tokens_and_connections_reject_before_root_creation(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                token = fixture.locks.acquire_installation("shared")
                try:
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        self._issue(fixture, namespace)
                finally:
                    fixture.locks.release(token)
                with fixture.repository._factory.open("doctor"):
                    with self.assertRaisesRegex(ValueError, "repository.*held"):
                        self._issue(fixture, namespace)
                with action_stack() as other:
                    token = other.locks.acquire_installation("shared")
                    try:
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            self._issue(fixture, namespace)
                    finally:
                        other.locks.release(token)
                self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_closed_session_rejects_all_action_entries_before_repository_calls(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
                coordinator = fixture.raw_coordinator
                prepared = coordinator.prepare(document)
                authority = authority_document(prepared, context=fixture.context)
                session.close()
                with mock.patch.object(coordinator._journal, "record_prepared", side_effect=AssertionError("journal write")), \
                     mock.patch.object(coordinator._journal, "find_prepared", side_effect=AssertionError("journal read")), \
                     mock.patch.object(fixture.locks, "acquire_installation", side_effect=AssertionError("repository lock")):
                    attempts = (
                        lambda: coordinator.prepare(document),
                        lambda: coordinator.authorize(authority),
                        lambda: coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                            observer=session.observer, disclosure_plan=None),
                        lambda: coordinator.reconcile_unknown(prepared.action_id, lease=fixture.action_lease, observer=session.observer),
                        lambda: coordinator.compensate_unknown(prepared.action_id, compensation_action_id="unused",
                            recovery_lease=fixture.action_lease, owner_id="owner-wp05", runtime_kind="codex",
                            runtime_lineage_id="lineage-wp05", target=session.target, observer=session.observer, disclosure_plan=None),
                    )
                    for index, attempt in enumerate(attempts):
                        with self.subTest(entry=index), self.assertRaises(ValueError):
                            attempt()
                self.assertEqual(session.target.apply_count, 0)

    def test_closed_session_rejects_observation_before_repository_reads(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    outcome = WP08ReleaseOperationsIntegrationTests()._assert_apply(
                        fixture, session, baseline, candidate, factory.artifact_bytes(candidate))
                    deployment = factory.issue_deployment_observation(
                        action_coordinator=fixture.raw_coordinator, session=session, outcome=outcome)
                with mock.patch.object(fixture.raw_coordinator._journal, "load",
                        side_effect=AssertionError("repository read before lease check")):
                    with self.assertRaises(ValueError):
                        factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                            session=session, outcome=outcome)
                    with self.assertRaises(ValueError):
                        factory._require_live_projection({}, (session, deployment, None))

    def _unresolved_retained_action(self, fixture, session, factory, baseline, candidate):
        from graph_engineering.core.actions import PreparedAction

        def fault(step):
            if step == "after-active-switch-durable":
                raise TimeoutError("retained reconciliation cut")

        session._root.fault_hook = fault
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        document = release_prepared_document(fixture, target_digest=session.target.target_digest,
            baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
        document["snapshot_digest"] = fixture.current_task_snapshot_digest()
        document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
        prepared = fixture.coordinator.prepare(document)
        fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
        outcome = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
            runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
            observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
        self.assertEqual(outcome.route, "manual-reconciliation")
        self.assertEqual(fixture.journal.load(prepared.action_id).state, "unknown")
        return prepared

    def test_foreign_coordinator_rejects_live_and_closed_retained_observers_before_repository_access(self):
        import tempfile
        from graph_engineering.application.actions import ActionCoordinator

        for closed in (False, True):
            with self.subTest(closed=closed), action_stack(domain_task=True) as fixture, \
                 self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                        namespace_path=pathlib.Path(directory).resolve()) as namespace:
                    factory, session, baseline, candidate = self._issue(fixture, namespace)
                    with session:
                        prepared = self._unresolved_retained_action(fixture, session, factory, baseline, candidate)
                        owner = fixture.raw_coordinator
                        foreign = ActionCoordinator(journal=owner._journal, repository=owner._repository,
                            leases=owner._leases, locks=owner._locks, objects=owner._objects,
                            security_issuer=owner._issuer, action_policy=owner._policy,
                            installation_scope=owner._repository.command_scope)
                        self.assertIs(foreign._repository.command_scope, owner._repository.command_scope)
                        self.assertEqual(foreign._retained_actions, {})

                        def durable_state():
                            return (fixture.repository.load("task-wp05"), fixture.journal.load(prepared.action_id),
                                fixture.leases.load_claim("claim:" + prepared.action_id))

                        before = durable_state()
                        if closed:
                            session.close()
                        with mock.patch.object(fixture.locks, "acquire_installation", side_effect=AssertionError("repository lock")) as lock, \
                             mock.patch.object(owner._journal, "load", side_effect=AssertionError("journal read")) as journal, \
                             mock.patch.object(session.observer, "observe", side_effect=AssertionError("observer call")) as observe:
                            with self.assertRaisesRegex(ValueError, "live coordinator binding"):
                                foreign.reconcile_unknown(prepared.action_id, lease=fixture.action_lease,
                                    observer=session.observer)
                            lock.assert_not_called()
                            journal.assert_not_called()
                            observe.assert_not_called()
                        self.assertEqual(durable_state(), before)
                        self.assertEqual(session.target.apply_count, 1)

    def test_original_coordinator_reconciles_retained_and_disposable_actions(self):
        import tempfile
        from contextlib import nullcontext

        for retained in (True, False):
            with self.subTest(retained=retained), action_stack(domain_task=True) as fixture, \
                 self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                namespace_context = runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) if retained else nullcontext(None)
                with namespace_context as namespace:
                    factory, session, baseline, candidate = self._issue(fixture, namespace)
                    with session:
                        prepared = self._unresolved_retained_action(fixture, session, factory, baseline, candidate)
                        outcome = fixture.coordinator.reconcile_unknown(prepared.action_id,
                            lease=fixture.action_lease, observer=session.observer)
                        self.assertEqual(outcome.route, "reconciled-effect-verified")
                        self.assertEqual(fixture.journal.load(prepared.action_id).state, "reconciled")
                        self.assertEqual(fixture.leases.unresolved_claims(), ())
                        self.assertEqual(session.target.apply_count, 1)
                        if retained:
                            self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)
                        else:
                            self.assertIsNone(session.recovery_binding)

    def test_wrong_runtime_owner_and_failed_initialization_release_root_lease(self):
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedPrivateRoot
        for attack in ("owner", "initialization"):
            with self.subTest(attack=attack), action_stack(domain_task=True) as fixture, \
                 self._runtime("wrong-owner" if attack == "owner" else "owner-wp05") as runtime, \
                 tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
                with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                        namespace_path=pathlib.Path(directory).resolve()) as namespace:
                    before = fixture.repository.load("task-wp05")
                    if attack == "owner":
                        with self.assertRaisesRegex(ValueError, "does not own"):
                            self._issue(fixture, namespace)
                    else:
                        with mock.patch.object(_RetainedPrivateRoot, "_durable_write", side_effect=OSError("injected initial write failure")), self.assertRaises(OSError):
                            self._issue(fixture, namespace)
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 0)
                    self.assertEqual(fixture.repository.load("task-wp05"), before)
                    self.assertEqual(len(list(pathlib.Path(directory).iterdir())), 1)

    def test_live_namespace_cannot_close_and_runtime_revocation_invalidates_session(self):
        import tempfile
        with action_stack() as fixture, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            runtime = self._runtime()
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                _factory, session, _baseline, _candidate = self._issue(fixture, namespace)
                with session:
                    with self.assertRaises(ValueError):
                        namespace.close()
                    runtime.close()
                    with self.assertRaises(RuntimeError):
                        session.observer.observe()

    def test_close_waits_for_repository_tokens_and_connections_to_release(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                _factory, session, _baseline, _candidate = self._issue(fixture, namespace)
                with session:
                    token = fixture.locks.acquire_installation("shared")
                    try:
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            session.close()
                    finally:
                        fixture.locks.release(token)
                    with fixture.repository._factory.open("doctor"):
                        with self.assertRaisesRegex(ValueError, "repository.*held"):
                            session.close()
                    self.assertFalse(session._root.closed)
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)

    def test_retained_partial_compensation_restores_baseline_under_same_lease(self):
        import tempfile
        with action_stack() as fixture, self._runtime() as runtime, tempfile.TemporaryDirectory(prefix="gew-retained-session-") as directory:
            with runtime.bind_release_namespace(action_coordinator=fixture.raw_coordinator,
                    namespace_path=pathlib.Path(directory).resolve()) as namespace:
                factory, session, baseline, candidate = self._issue(fixture, namespace)
                with session:
                    def fault(step):
                        if step == "after-stage-durable":
                            raise TimeoutError("retained partial cut")
                    session._root.fault_hook = fault
                    retarget_security_binding(fixture, target_digest=session.target.target_digest)
                    prepared = fixture.coordinator.prepare(release_prepared_document(fixture,
                        target_digest=session.target.target_digest, baseline=baseline, candidate=candidate,
                        candidate_bytes=factory.artifact_bytes(candidate)))
                    fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                    unknown = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                        runtime_lineage_id="lineage-wp05", lease=fixture.action_lease, target=session.target,
                        observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, prepared))
                    self.assertEqual(unknown.route, "manual-reconciliation")
                    factory.issue_deployment_observation(action_coordinator=fixture.raw_coordinator,
                        session=session, outcome=unknown)
                    compensation = fixture.coordinator.prepare(release_partial_restore_prepared_document(fixture,
                        target_digest=session.target.target_digest, baseline=baseline, baseline_bytes=factory.artifact_bytes(baseline),
                        candidate=candidate, original_claim_id=unknown.claim_id, original_receipt_digest=unknown.receipt_digest))
                    fixture.coordinator.authorize(authority_document(compensation, context=fixture.context))
                    restored = fixture.coordinator.compensate_unknown(prepared.action_id,
                        compensation_action_id=compensation.action_id, recovery_lease=fixture.action_lease,
                        owner_id="owner-wp05", runtime_kind="codex", runtime_lineage_id="lineage-wp05",
                        target=session.target, observer=session.observer, disclosure_plan=release_disclosure_plan(fixture, compensation))
                    self.assertEqual(restored.route, "compensation-reconciled")
                    self.assertEqual(restored.claim_id, unknown.claim_id)
                    self.assertEqual(session.observer.observe()["state"], {"generation": 0,
                        "active_artifact_digest": baseline.manifest_digest, "staged_artifact_digest": None})
                    self.assertEqual(fixture.leases.unresolved_claims(), ())
                    self.assertEqual(namespace.require_current(fixture.raw_coordinator).active_leases, 1)


class WP08ColdAssessmentProcessTests(unittest.TestCase):
    """Producer and consumer share only durable bytes at their original paths."""

    CHILD = r'''
import json, os, pathlib, sys, tempfile
from contextlib import ExitStack, contextmanager
from types import SimpleNamespace
from unittest import mock

root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root))
from tests.support.source_checkout_attestation import issue_source_checkout_attestation, CONTROL_OPTION, CONTROL_ENVIRONMENT
control = pathlib.Path(sys.argv[2]).resolve()
issue_source_checkout_attestation(root, control)
sys._xoptions[CONTROL_OPTION] = str(control)
os.environ[CONTROL_ENVIRONMENT] = str(control)
sys.path[:0] = [str(root / name) for name in ("core", "application", "storage", "adapters")]

from tests.integration.test_wp08_release_operations import WP08RetainedReleaseSessionTests
from tests.support import wp08_category_execution as category
case = WP08RetainedReleaseSessionTests()
request = json.loads(sys.stdin.read())
base = pathlib.Path(request["directory"])
def tree(directory):
    return {str(path.relative_to(directory)): (path.read_bytes().hex(), path.stat().st_mode,
            path.stat().st_mtime_ns, path.stat().st_ctime_ns)
            for path in directory.rglob("*") if path.is_file()}
def produce():
    original = tempfile.TemporaryDirectory
    preserved = set()
    @contextmanager
    def directories(*args, **kwargs):
        prefix = kwargs.get("prefix")
        selected = {"gew-wp03-": "repository-fixture",
                    "gew-retained-assessment-": "retained-namespace"}.get(prefix)
        if selected is None or selected in preserved:
            with original(*args, **{**kwargs, "dir": base}) as path:
                yield path
        else:
            preserved.add(selected)
            path = base / selected
            path.mkdir(mode=0o700)
            yield str(path)
    with mock.patch.object(tempfile, "TemporaryDirectory", directories):
        with case._same_task_assessment(cold=True, partial=request["partial"],
                column=request.get("column", "normal")) as values:
            _api, fixture, session, app, probe, target, candidate, evidence, _ = values
            receipt = (None if request.get("crash_cut") == "before-reference" else
                app.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence))
            expected = session._root.state()
            paths = {"repository": str(fixture.repository._factory._root),
                     "installation_control": str(fixture.factory._test_installation_control_root),
                     "namespace": str(fixture.retained_namespace._record()[4].path)}
            result = {"pid": os.getpid(), "paths": paths, "task_id": probe.task_id,
                      "assessment": None if receipt is None else receipt.assessment.to_bytes().hex(), "expected": expected}
            if request.get("crash_cut"):
                assert fixture.retained_namespace._record()[4].active_leases == 1
                result.update(abrupt=True, lease_held=True)
                print(json.dumps(result), flush=True)
                os._exit(0)
            session.close()
    return result

def consume():
    import socket, subprocess
    from graph_engineering.application.actions import ActionCoordinator
    from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory, restore_current_release_assessment
    from graph_engineering.application.security import SecurityContextIssuer
    from graph_engineering.application.tasks import TaskApplication
    from graph_engineering.core.actions import ActionPolicy
    from graph_engineering.core.profile_execution import CategoryExecutionPolicy
    from graph_engineering.storage.actions import ActionJournalRepository
    from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor, ManagedConnection
    from graph_engineering.storage.leases import ResourceLeaseRepository
    from graph_engineering.storage.locks import LockedFileRegistry
    from graph_engineering.storage.migration import InstallationMigrationRepository
    from graph_engineering.storage.objects import ObjectRepository
    from graph_engineering.storage.repository import TaskRepository
    from graph_engineering.storage.security import SecurityStateRepository
    from tests.contract.test_wp02_graph import graph_schemas, work_context
    from tests.support.wp03_repository import policy as repository_policy, mount_observation
    from tests.support.wp05a_security import security_context, security_schema_registry
    from tests.support.wp07a_actions import action_adapter_schema_registry

    source = request["producer"]
    paths = {key: pathlib.Path(value) for key, value in source["paths"].items()}
    with ExitStack() as stack:
        stack.enter_context(mock.patch.object(RepositoryDoctor, "_mount_observation", side_effect=mount_observation))
        maintenance = ConnectionFactory._attach_existing_for_maintenance(
            paths["repository"], repository_policy(), "repository-test-v1")
        locks = LockedFileRegistry(maintenance); stack.callback(locks.close)
        maintenance_objects = ObjectRepository(maintenance, locks); stack.callback(maintenance_objects.close)
        manager = InstallationMigrationRepository.attach_command_plane(maintenance, locks, maintenance_objects,
            control_root=paths["installation_control"],
            policy_document=json.loads((root/"config/contracts/migration-storage-policy-v1.json").read_text()))
        stack.callback(manager.close)
        scope = stack.enter_context(manager.command_scope())
        factory = maintenance.bind_command_scope(scope)
        objects = ObjectRepository(factory, locks); stack.callback(objects.close)
        leases = ResourceLeaseRepository(factory, locks)
        context = security_context()
        schemas = security_schema_registry(context)
        journal = ActionJournalRepository(factory, schema_registry=schemas, context=context)
        repository = TaskRepository(factory, locks, objects, action_journal=journal,
            concrete_action_schemas=action_adapter_schema_registry(context),
            concrete_action_context=context, command_scope=scope)
        issuer = SecurityContextIssuer(SecurityStateRepository(factory), schema_registry=schemas, context=context)
        action_policy = ActionPolicy.from_dict(json.loads((root/"config/actions/action-policy-v1.json").read_text()),
            schema_registry=schemas, context=context, runtime=issuer.runtime)
        coordinator = ActionCoordinator(journal=journal, repository=repository, leases=leases, locks=locks,
            objects=objects, security_issuer=issuer, action_policy=action_policy, installation_scope=scope)
        app = TaskApplication(repository, repository, leases, schema_registry=graph_schemas(),
            context=work_context(), materialization_objects=objects)
        runtime = stack.enter_context(case._runtime())
        runtime_context = runtime._issue_context("2026-09-21T00:00:00Z", 10**15)
        namespace = stack.enter_context(runtime.bind_release_namespace(
            action_coordinator=coordinator, namespace_path=paths["namespace"]))
        profile = CategoryExecutionPolicy.from_installation(
            profile_document=category.profile_document("release-operations"),
            support_matrix_document=category.load_json(category.SUPPORT_MATRIX_PATH),
            materialization_record=category.materialized_profile("release-operations").record)
        release = ReleaseOperationsRegistryFactory.from_installation()
        assert len(release._issued) == len(coordinator._issued_outcomes) == 0
        before = case._repository_rows(SimpleNamespace(repository=repository))
        protected = (paths["namespace"], paths["installation_control"], objects._objects)
        file_before = [tree(path) for path in protected]
        contexts = (app._context, context)
        balances = [(ctx._temporary_units, getattr(ctx, "_recovery_result_bytes", 0)) for ctx in contexts]
        execute = ManagedConnection.execute
        queries = []
        def only_reads(connection, sql, parameters=()):
            assert connection._role == "doctor"
            assert connection._raw.execute("PRAGMA query_only").fetchone() == (1,)
            assert sql.lstrip().upper().startswith(("SELECT", "WITH")), sql
            queries.append(sql)
            return execute(connection, sql, parameters)
        def blocked(*args, **kwargs):
            raise AssertionError("legacy, write, live authority or network call during cold recovery")
        with ExitStack() as checks:
            checks.enter_context(mock.patch.object(ManagedConnection, "execute", new=only_reads))
            for kind, names in ((TaskRepository, ("load", "replay", "referenced_objects", "category_source_seal", "commit")),
                    (ObjectRepository, ("get", "_verify_file", "_read_descriptor", "put_verified")),
                    (ActionJournalRepository, ("load", "find_prepared")),
                    (TaskApplication, ("runtime_show",))):
                for name in names:
                    checks.enter_context(mock.patch.object(kind, name, side_effect=blocked))
            for name in ("_read_action_authority", "_issue_outcome", "issue_durable_execution_gate",
                         "prepare", "authorize", "execute", "compensate_unknown"):
                checks.enter_context(mock.patch.object(coordinator, name, side_effect=blocked))
            checks.enter_context(mock.patch.object(socket, "socket", side_effect=blocked))
            checks.enter_context(mock.patch.object(subprocess, "Popen", side_effect=blocked))
            if source["assessment"] is None:
                from graph_engineering.application import release_operations as release_module
                from graph_engineering.storage.errors import RepositoryIntegrityError
                scopes = []
                initialize = release_module._ColdReleaseReadScope.__init__
                def observed(current, *args, **kwargs):
                    initialize(current, *args, **kwargs); scopes.append(current)
                with mock.patch.object(release_module._ColdReleaseReadScope, "__init__", new=observed), \
                        mock.patch.object(namespace._record()[4], "_open_cold_marker", side_effect=blocked):
                    with case.assertRaises(RepositoryIntegrityError) as rejected:
                        restore_current_release_assessment(task_application=app, runtime=runtime_context,
                            policy=profile, release_factory=release, object_repository=objects,
                            action_coordinator=coordinator, retained_namespace=namespace, task_id=source["task_id"])
                case._assert_cold_semantic_rejection(rejected.exception, "assessment is missing or ambiguous")
                assert scopes[0].closed
                assert scopes[0].budget.retained_units == scopes[0].budget.retained_bytes == 0
                result = {"pid": os.getpid(), "rejected": "uncommitted-assessment", "queries": len(queries)}
            else:
                handle = restore_current_release_assessment(task_application=app, runtime=runtime_context,
                    policy=profile, release_factory=release, object_repository=objects,
                    action_coordinator=coordinator, retained_namespace=namespace, task_id=source["task_id"])
                read_scope = handle._record()[1]
                owner = read_scope.budget
                try:
                    first, second = handle.query(), handle.query()
                    assert first["assessment_bytes"].hex() == second["assessment_bytes"].hex() == source["assessment"]
                    assert first["assessment"]["column_id"] == request.get("column", "normal")
                    state_key = "rollback_state" if request.get("column") == "rollback" else "expected_state"
                    assert dict(first["source_projection"]["target"][state_key]) == source["expected"]
                    assert first["observation_epoch"] == second["observation_epoch"]
                    assert first["observation_revision"] < second["observation_revision"]
                    assert len(release._issued) == len(coordinator._issued_outcomes) == 0
                    result = {"pid": os.getpid(), "epoch": first["observation_epoch"],
                              "revision": second["observation_revision"], "queries": len(queries),
                              "generation": source["expected"]["generation"],
                              "peak_units": owner.peak_units, "peak_bytes": owner.peak_bytes}
                finally:
                    if not read_scope.closed:
                        handle.close()
                assert owner.retained_units == owner.retained_bytes == 0
        assert case._repository_rows(SimpleNamespace(repository=repository)) == before
        assert [tree(path) for path in protected] == file_before
        assert [(ctx._temporary_units, getattr(ctx, "_recovery_result_bytes", 0)) for ctx in contexts] == balances
        assert not scope._connections
        assert namespace._record()[4].active_leases == 0
        return result

print(json.dumps(produce() if request["mode"] == "produce" else consume()), flush=True)
'''

    def _child(self, directory, *, mode, partial, producer=None, crash_cut=None, column="normal"):
        import json
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory(prefix="gew-cold-exec-control-") as control:
            completed = subprocess.run([sys.executable, "-B", "-c", self.CHILD, str(ROOT), control],
                input=json.dumps({"directory": str(directory), "mode": mode,
                    "partial": partial, "producer": producer, "crash_cut": crash_cut, "column": column}),
                text=True, capture_output=True, timeout=120, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_fresh_producer_exit_and_fresh_consumer_restore_both_normal_and_partial_assessments(self):
        import os
        import tempfile

        for partial in (False, True):
            with self.subTest(partial=partial), tempfile.TemporaryDirectory(prefix="gew-cold-process-") as directory:
                path = pathlib.Path(directory).resolve()
                producer = self._child(path, mode="produce", partial=partial)
                consumer = self._child(path, mode="consume", partial=partial, producer=producer)
                self.assertNotEqual(producer["pid"], consumer["pid"])
                self.assertNotEqual(consumer["pid"], os.getpid())
                self.assertEqual(consumer["generation"], 0 if partial else 1)
                self.assertGreater(consumer["queries"], 0)
                self.assertGreater(consumer["revision"], 1)
                self.assertLessEqual(consumer["peak_units"], 1048576)
                self.assertLessEqual(consumer["peak_bytes"], 1048576)

    def test_fresh_process_mandatory_boundary_revise_authority_drift(self):
        self._assert_fresh_mandatory_columns(("boundary", "revise", "authority", "drift"))

    def test_fresh_process_mandatory_invalidation_artifacts_review_target(self):
        self._assert_fresh_mandatory_columns(("invalidation", "artifacts", "review", "target"))

    def test_fresh_process_mandatory_recovery_and_rollback(self):
        self._assert_fresh_mandatory_columns(("recovery", "rollback"), partial=True)

    def test_fresh_process_mandatory_real_e2e(self):
        self._assert_fresh_mandatory_columns(("real-e2e",))

    def _assert_fresh_mandatory_columns(self, columns, *, partial=False):
        import os
        import tempfile

        for column in columns:
            with self.subTest(column=column), tempfile.TemporaryDirectory(prefix="gew-cold-mandatory-") as directory:
                path = pathlib.Path(directory).resolve()
                producer = self._child(path, mode="produce", partial=partial, column=column)
                consumer = self._child(path, mode="consume", partial=partial, column=column, producer=producer)
                self.assertNotEqual(producer["pid"], consumer["pid"])
                self.assertNotEqual(consumer["pid"], os.getpid())
                self.assertEqual(consumer["generation"], 0 if partial else 1)
                self.assertGreater(consumer["queries"], 0)
                self.assertGreater(consumer["revision"], 1)
                self.assertLessEqual(consumer["peak_units"], 1048576)
                self.assertLessEqual(consumer["peak_bytes"], 1048576)



    def test_abrupt_exit_before_assessment_reference_refuses_fresh_recovery(self):
        self._assert_abrupt_assessment("before-reference")

    def test_abrupt_exit_after_assessment_reference_recovers_while_producer_held_lease(self):
        self._assert_abrupt_assessment("after-reference")

    def _assert_abrupt_assessment(self, cut):
        import tempfile

        with tempfile.TemporaryDirectory(prefix="gew-cold-crash-") as directory:
            path = pathlib.Path(directory).resolve()
            producer = self._child(path, mode="produce", partial=False, crash_cut=cut)
            self.assertTrue(producer["abrupt"])
            self.assertTrue(producer["lease_held"])
            consumer = self._child(path, mode="consume", partial=False, producer=producer)
            self.assertNotEqual(producer["pid"], consumer["pid"])
            if cut == "before-reference":
                self.assertIsNone(producer["assessment"])
                self.assertEqual(consumer["rejected"], "uncommitted-assessment")
            else:
                self.assertEqual(consumer["generation"], 1)
                self.assertGreater(consumer["revision"], 1)
            self.assertGreater(consumer["queries"], 0)


class WP08RetainedRootProcessTests(unittest.TestCase):
    """Fresh exec tests of storage only; no cold recovery evidence is issued."""

    CHILD = r'''
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[1])
sys.dont_write_bytecode = True
sys.path.insert(0, str(root))
from tests.support.source_checkout_attestation import (
    issue_source_checkout_attestation, CONTROL_OPTION, CONTROL_ENVIRONMENT,
)
def main(control):
    issue_source_checkout_attestation(root, pathlib.Path(control).resolve())
    sys._xoptions[CONTROL_OPTION] = str(pathlib.Path(control).resolve())
    os.environ[CONTROL_ENVIRONMENT] = sys._xoptions[CONTROL_OPTION]
    for part in ("core", "application", "storage", "adapters"):
        sys.path.insert(0, str(root / part))
    from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, ReleaseSimulatorError, _semantic
    from graph_engineering.core.release_operations import ReleaseRecoveryBinding
    from tests.support.wp05a_security import security_context
    request = json.loads(sys.stdin.read())
    members = {"active.bin": 0o600, "state.json": 0o600}
    with _RetainedNamespace(pathlib.Path(request["namespace"])) as namespace:
        if request["mode"] == "create":
            with namespace.create("task-wp05", "target-project", members=members) as lease:
                lease.initialize_file("active.bin", b"artifact-a\n")
                lease.initialize_file("state.json", b'{"generation":0}')
                value = request["binding"]
                value.update(lease.binding_parts())
                value["binding_digest"] = _semantic({k:v for k,v in value.items() if k != "binding_digest"}, "release-recovery-binding")
                lease.seal(ReleaseRecoveryBinding.from_dict(value))
                print(json.dumps({"pid": os.getpid(), "binding": value}), flush=True)
                if request["abrupt"]:
                    # Exit while owning the OS lock: no Python cleanup or inherited issuer.
                    os._exit(0)
        else:
            binding = ReleaseRecoveryBinding.from_dict(request["binding"])
            try:
                with namespace.open_readonly(binding, members=members, context=security_context()) as lease:
                    assert request["mode"] == "read", "competing exec acquired a live root"
                    print(json.dumps({"pid": os.getpid(), "artifact": lease.read("active.bin", max_bytes=1024).hex()}))
            except ReleaseSimulatorError as error:
                assert request["mode"] == "busy" and "busy" in str(error), str(error)
                assert namespace.active_leases == 0
                print(json.dumps({"pid": os.getpid(), "busy": True}))
main(sys.argv[2])
'''

    def _child(self, namespace, *, mode, binding, abrupt=False):  # type: ignore[no-untyped-def]
        import json
        import subprocess
        import sys
        import tempfile

        with tempfile.TemporaryDirectory(prefix="gew-retained-child-control-") as control:
            result = subprocess.run(
                [sys.executable, "-B", "-c", self.CHILD, str(ROOT), control],
                input=json.dumps({"namespace": str(namespace), "mode": mode,
                    "binding": binding, "abrupt": abrupt}),
                text=True, capture_output=True, timeout=30, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_fresh_exec_reopens_retained_bytes_after_producer_exit(self) -> None:
        import os
        import tempfile
        from tests.unit.test_wp08_release_operations import WP08ReleaseRecoveryBindingTests

        for abrupt in (False, True):
            with self.subTest(abrupt=abrupt), tempfile.TemporaryDirectory(prefix="gew-retained-exec-") as directory:
                path = pathlib.Path(directory).resolve()
                producer = self._child(path, mode="create", binding=WP08ReleaseRecoveryBindingTests.document(), abrupt=abrupt)
                retained = next(path.iterdir())
                before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in retained.iterdir()}
                consumer = self._child(path, mode="read", binding=producer["binding"])
                self.assertNotEqual(producer["pid"], consumer["pid"])
                self.assertNotEqual(consumer["pid"], os.getpid())
                self.assertEqual(consumer["artifact"], b"artifact-a\n".hex())
                self.assertEqual({p.name: (p.read_bytes(), p.stat().st_mtime_ns, p.stat().st_ctime_ns) for p in retained.iterdir()}, before)

    def test_fresh_exec_is_busy_until_live_owner_closes(self) -> None:
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from tests.unit.test_wp08_release_operations import WP08RetainedRootPrimitiveTests

        with tempfile.TemporaryDirectory(prefix="gew-retained-exec-") as directory:
            path = pathlib.Path(directory).resolve()
            with _RetainedNamespace(path) as namespace:
                lease, binding = WP08RetainedRootPrimitiveTests()._create(namespace)
                with lease:
                    result = self._child(path, mode="busy", binding=binding.to_dict())
                    self.assertTrue(result["busy"])
                    self.assertEqual(lease.read("active.bin", max_bytes=1024), b"artifact-a\n")
                result = self._child(path, mode="read", binding=binding.to_dict())
                self.assertEqual(result["artifact"], b"artifact-a\n".hex())


class WP08ReleaseOperationsIntegrationTests(unittest.TestCase):
    def test_same_task_action_then_domain_command_and_runner(self) -> None:
        from graph_engineering.core.actions import PreparedAction
        from graph_engineering.core.graph.state import TaskCommand
        from tests.integration.test_wp04_runner import (
            ApplicationRunnerIntegrationTests, PassingRuntime, PassingValidator, PassingReviewer,
        )
        from tests.integration.test_wp04_application import TaskApplicationIntegrationTests

        with action_stack(domain_task=True) as fixture:
            application = fixture.task_application
            runtime = fixture.task_runtime
            before = application.runtime_show("task-wp05", runtime)
            factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-a")
            candidate = factory.issue_artifact_manifest(fixture_id="release-foundation-v1", artifact_id="artifact-b")
            with factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator, task_id="task-wp05",
                fixture_id="release-foundation-v1", target_id="target-project",
                resource_id="target:project", baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
            ) as session:
                retarget_security_binding(fixture, target_digest=session.target.target_digest)
                document = release_prepared_document(fixture, target_digest=session.target.target_digest,
                    baseline=baseline, candidate=candidate, candidate_bytes=factory.artifact_bytes(candidate))
                document["snapshot_digest"] = fixture.current_task_snapshot_digest()
                document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
                prepared = fixture.coordinator.prepare(document)
                fixture.coordinator.authorize(authority_document(prepared, context=fixture.context))
                outcome = fixture.coordinator.execute(prepared.action_id, owner_id="owner-wp05",
                    runtime_kind="codex", runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=session.target, observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, prepared))
                self.assertEqual(outcome.route, "reconciled-effect-verified")
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                fixture.leases.release(fixture.action_lease.lease_id)
                after = application.runtime_show("task-wp05", runtime)
                self.assertEqual(after.snapshot.to_dict(), before.snapshot.to_dict())
                self.assertEqual(after.runner_state, before.runner_state)
                self.assertEqual(after.repository_revision, before.repository_revision + 3)
                self.assertEqual(set(fixture.repository.load("task-wp05")), {"task_id", "revision", "domain", "runner"})

                _schemas, context, graph, budgets = ApplicationRunnerIntegrationTests().stack()
                helper = TaskApplicationIntegrationTests()
                application.execute_scope("task-wp05", TaskCommand("bind_project_scope", 1,
                    {"project_scope_ref": helper.scope("drafted")}), helper.project_scope(), runtime)
                application.execute("task-wp05", TaskCommand("request_prd_approval", 2,
                    {"prd_candidate_ref": "artifact:bridge-prd"}), runtime)
                approval = helper.approval()
                approval["baseline_refs"][0]["approved_by"] = "owner-wp05"
                approval["graph_ref"].update(graph_id="test-delivery", graph_digest=graph.digest)
                application.execute("task-wp05", TaskCommand("approve_prd", 3, approval), runtime)
                application.execute("task-wp05", TaskCommand("run", 5, {
                    "compatibility_evidence_ref": "evidence:bridge-compatible", "lease_plan_ref": "lease-plan:none-v1",
                }), runtime)
                runner = application.create_runner(fixture.objects, budgets, context=context)
                result = runner.run_until_stable("task-wp05", runtime, graph,
                    PassingRuntime(), PassingValidator(), PassingReviewer(), max_steps=30)
                self.assertEqual(result.status, "completion_ready")
                final = application.runtime_show("task-wp05", runtime)
                history = fixture.repository.replay("task-wp05")
                self.assertEqual(len(history), final.snapshot.last_event_seq + 3)
                self.assertEqual({r.status for r in final.snapshot.node_runs.values()}, {"passed"})
                self.assertEqual(fixture.issuer.read_task_state("task-wp05").state["task_revision"], final.repository_revision)

    def test_non_release_completion_preserves_existing_fence_behavior(self) -> None:
        from tests.integration.test_wp08_category_execution import WP08CategoryExecutionTests

        _api, application, probe, target = WP08CategoryExecutionTests()._runtime(
            "new-feature", "normal",
        )
        try:
            receipt = application.assess_and_commit(
                category_fixture.candidate_document("new-feature", "normal"),
                observer=target,
            )
            self.assertEqual(receipt.assessment.schema_version, "1.0.0")
            self.assertIsNone(receipt.assessment.release_operations_projection)
            self.assertEqual(len(probe.signature()["object_references"]), 1)
        finally:
            probe.close()
            target.close()

    @contextmanager
    def _live_evidence(self):  # type: ignore[no-untyped-def]
        with action_stack() as fixture:
            factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            session = factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05", fixture_id="release-foundation-v1",
                target_id="target-project", resource_id="target:project",
                baseline_manifest=baseline, authorized_artifacts=(baseline, candidate),
            )
            with session:
                outcome = self._assert_apply(
                    fixture, session, baseline, candidate, factory.artifact_bytes(candidate),
                )
                deployment = factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session, outcome=outcome,
                )
                health = factory.issue_health_observation(
                    session=session, terminal_observation=deployment,
                )
                digest = "sha256-jcs-v1:" + "a" * 64
                arguments = dict(
                    task_id="task-wp05", task_revision=1, snapshot_digest=digest,
                    invalidation_epoch=0,
                    graph_ref_pins={name: digest for name in (
                        "base_graph_digest", "profile_digest", "overlay_digest",
                        "project_config_digest", "support_matrix_digest",
                        "materialization_digest",
                    )},
                    artifact_manifest=candidate, deployment_observation=deployment,
                    health_observation=health, rollback_observation=None,
                    session=session, owner_route="reconciled-effect-verified",
                    column_id="normal",
                    scenario_id="GEW-PSC-RELEASE-OPERATIONS-ARTIFACT-PROVENANCE-P",
                    outcome="artifact-provenance-verified",
                )
                evidence = factory.issue_evidence(**arguments)
                yield fixture, factory, session, outcome, evidence, arguments

    def test_live_evidence_rejects_closed_destroyed_or_changed_target(self) -> None:
        for attack in ("closed", "destroyed", "generation", "artifact"):
            with self.subTest(attack=attack), self._live_evidence() as values:
                _fixture, factory, session, _outcome, evidence, _arguments = values
                self.assertIs(factory.require_current(evidence), evidence)
                mutations = session._root.mutation_count
                if attack == "closed":
                    session.close()
                elif attack == "destroyed":
                    session._root._temporary.cleanup()
                elif attack == "generation":
                    state = session._root.state()
                    session._root._write_state({**state, "generation": state["generation"] + 1})
                else:
                    session._root._durable_write(
                        session._root.names["active_artifact"], b"changed", 0o600,
                    )
                for check in (factory.require_current, factory.projection):
                    with self.assertRaises(ReleaseOperationsError):
                        check(evidence)
                self.assertEqual(session._root.mutation_count, mutations)
                self.assertEqual(session.target.apply_count, 1)

    def test_live_evidence_and_final_issuance_reject_action_authority_drift(self) -> None:
        for attack in ("journal", "claim", "receipt"):
            with self.subTest(attack=attack), self._live_evidence() as values:
                fixture, factory, session, outcome, evidence, arguments = values
                record = fixture.journal.load(outcome.action_id)
                claim = fixture.leases.load_claim(outcome.claim_id)
                if attack == "claim":
                    patch = mock.patch.object(
                        fixture.leases, "load_claim", return_value={**claim, "state": "unresolved"},
                    )
                else:
                    changed = (
                        replace(record, state="unknown") if attack == "journal"
                        else replace(record, receipt={**record.receipt, "receipt_digest": "sha256-jcs-v1:" + "f" * 64})
                    )
                    patch = mock.patch.object(
                        fixture.raw_coordinator._journal, "load", return_value=changed,
                    )
                before = session.tree_digest()
                with patch:
                    for check in (factory.require_current, factory.projection):
                        with self.assertRaises(ReleaseOperationsError):
                            check(evidence)
                    issued_count = len(factory._issued)
                    with self.assertRaises(ReleaseOperationsError):
                        factory.issue_evidence(**arguments)
                    self.assertEqual(len(factory._issued), issued_count)
                self.assertEqual(session.tree_digest(), before)
                self.assertEqual(session.target.apply_count, 1)

    def test_apply_runs_through_durable_action_coordinator_and_fresh_observer(self) -> None:
        with action_stack() as fixture:
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            baseline_bytes = release_factory.artifact_bytes(baseline)
            candidate_bytes = release_factory.artifact_bytes(candidate)
            self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())
            session = release_factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05",
                fixture_id="release-foundation-v1",
                target_id="target-project",
                resource_id="target:project",
                baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
            )
            with session:
                outcome = self._assert_apply(
                    fixture, session, baseline, candidate, candidate_bytes,
                )
                deployment = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=outcome,
                )
                with (
                    mock.patch("socket.socket") as socket_call,
                    mock.patch("socket.getaddrinfo") as dns_call,
                    mock.patch("socket.create_connection") as connect_call,
                    mock.patch("subprocess.Popen") as process_call,
                    mock.patch("subprocess.run") as process_run,
                    mock.patch("urllib.request.urlopen") as url_call,
                    mock.patch("urllib.request.getproxies") as proxy_call,
                ):
                    health = release_factory.issue_health_observation(
                        session=session,
                        terminal_observation=deployment,
                    )
                socket_call.assert_not_called()
                dns_call.assert_not_called()
                connect_call.assert_not_called()
                process_call.assert_not_called()
                process_run.assert_not_called()
                url_call.assert_not_called()
                proxy_call.assert_not_called()
                self.assertEqual(deployment.to_dict()["current_generation"], 1)
                self.assertEqual(health.to_dict()["outcome"], "healthy")

    def test_partial_unknown_uses_same_claim_compensation_and_restores_exact_a(self) -> None:
        with action_stack() as fixture:
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            baseline = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-a",
            )
            candidate = release_factory.issue_artifact_manifest(
                fixture_id="release-foundation-v1", artifact_id="artifact-b",
            )
            baseline_bytes = release_factory.artifact_bytes(baseline)
            candidate_bytes = release_factory.artifact_bytes(candidate)
            self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())

            def fault(step: str) -> None:
                if step == "after-stage-durable":
                    raise TimeoutError("configured partial cut")

            session = release_factory.issue_simulator(
                action_coordinator=fixture.raw_coordinator,
                task_id="task-wp05",
                fixture_id="release-foundation-v1",
                target_id="target-project",
                resource_id="target:project",
                baseline_manifest=baseline,
                authorized_artifacts=(baseline, candidate),
                fault_hook=fault,
            )
            with session:
                retarget_security_binding(
                    fixture, target_digest=session.target.target_digest,
                )
                original_document = release_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    candidate=candidate,
                    candidate_bytes=candidate_bytes,
                )
                original = fixture.coordinator.prepare(original_document)
                fixture.coordinator.authorize(authority_document(
                    original, context=fixture.context,
                ))
                unknown = fixture.coordinator.execute(
                    original.action_id,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    lease=fixture.action_lease,
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, original),
                )
                self.assertEqual((unknown.state, unknown.route), (
                    "unknown", "manual-reconciliation",
                ))
                partial = session.observer.observe()["state"]
                self.assertEqual(partial, {
                    "generation": 0,
                    "active_artifact_digest": baseline.manifest_digest,
                    "staged_artifact_digest": candidate.manifest_digest,
                })
                deployment = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=unknown,
                )
                partial_health = release_factory.issue_health_observation(
                    session=session,
                    terminal_observation=deployment,
                )
                self.assertEqual(partial_health.to_dict()["outcome"], "unhealthy")
                digest = "sha256-jcs-v1:" + "a" * 64
                graph_pins = {
                    field: digest
                    for field in (
                        "base_graph_digest", "profile_digest", "overlay_digest",
                        "project_config_digest", "support_matrix_digest",
                        "materialization_digest",
                    )
                }
                with self.assertRaisesRegex(
                    ReleaseOperationsError, "scenario/health/rollback",
                ):
                    release_factory.issue_evidence(
                        task_id="task-wp05",
                        task_revision=1,
                        snapshot_digest=digest,
                        invalidation_epoch=0,
                        graph_ref_pins=graph_pins,
                        artifact_manifest=candidate,
                        deployment_observation=deployment,
                        health_observation=partial_health,
                        rollback_observation=None,
                        session=session,
                        owner_route="release-operations-owner",
                        column_id="normal",
                        scenario_id=(
                            "GEW-PSC-RELEASE-OPERATIONS-PARTIAL-DEPLOY-P"
                        ),
                        outcome="partial-deploy-restored",
                    )
                compensation_document = release_partial_restore_prepared_document(
                    fixture,
                    target_digest=session.target.target_digest,
                    baseline=baseline,
                    baseline_bytes=baseline_bytes,
                    candidate=candidate,
                    original_claim_id=unknown.claim_id,
                    original_receipt_digest=str(unknown.receipt_digest),
                )
                compensation = fixture.coordinator.prepare(compensation_document)
                fixture.coordinator.authorize(authority_document(
                    compensation, context=fixture.context,
                ))
                restored = fixture.coordinator.compensate_unknown(
                    original.action_id,
                    compensation_action_id=compensation.action_id,
                    recovery_lease=fixture.action_lease,
                    owner_id="owner-wp05",
                    runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05",
                    target=session.target,
                    observer=session.observer,
                    disclosure_plan=release_disclosure_plan(fixture, compensation),
                )
                self.assertEqual((restored.state, restored.route), (
                    "compensated", "compensation-reconciled",
                ))
                rollback = release_factory.issue_deployment_observation(
                    action_coordinator=fixture.raw_coordinator,
                    session=session,
                    outcome=restored,
                )
                self.assertEqual(
                    rollback.to_dict()["action_id"], compensation.action_id,
                )
                self.assertEqual(session.observer.observe()["state"], {
                    "generation": 0,
                    "active_artifact_digest": baseline.manifest_digest,
                    "staged_artifact_digest": None,
                })
                self.assertEqual(session.target.apply_count, 1)
                self.assertEqual(fixture.leases.unresolved_claims(), ())
                restored_health = release_factory.issue_health_observation(
                    session=session,
                    terminal_observation=rollback,
                )
                self.assertEqual(restored_health.to_dict()["outcome"], "healthy")
                evidence = release_factory.issue_evidence(
                    task_id="task-wp05",
                    task_revision=1,
                    snapshot_digest=digest,
                    invalidation_epoch=0,
                    graph_ref_pins=graph_pins,
                    artifact_manifest=candidate,
                    deployment_observation=deployment,
                    health_observation=restored_health,
                    rollback_observation=rollback,
                    session=session,
                    owner_route="release-operations-owner",
                    column_id="normal",
                    scenario_id="GEW-PSC-RELEASE-OPERATIONS-PARTIAL-DEPLOY-P",
                    outcome="partial-deploy-restored",
                )
                self.assertEqual(
                    release_factory.require_current(evidence), evidence,
                )

    def _assert_apply(
        self, fixture, session, baseline, candidate, candidate_bytes,
    ):  # type: ignore[no-untyped-def]
        retarget_security_binding(fixture, target_digest=session.target.target_digest)
        document = release_prepared_document(
            fixture,
            target_digest=session.target.target_digest,
            baseline=baseline,
            candidate=candidate,
            candidate_bytes=candidate_bytes,
        )
        if fixture.task_application is not None:
            from graph_engineering.core.actions import PreparedAction

            document["snapshot_digest"] = fixture.current_task_snapshot_digest()
            document["prepared_action_digest"] = PreparedAction.digest_document(document, fixture.context)
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
        self.assertEqual(outcome.route, "reconciled-effect-verified")
        self.assertEqual(session.target.apply_count, 1)
        state = session.observer.observe()["state"]
        self.assertEqual(state["generation"], 1)
        self.assertEqual(state["active_artifact_digest"], candidate.manifest_digest)
        record = fixture.journal.load(prepared.action_id)
        self.assertEqual(record.state, "reconciled")
        self.assertIsNotNone(record.receipt)
        self.assertEqual(fixture.leases.unresolved_claims(), ())
        return outcome

    def test_category_assessment_1_4_binds_and_restarts_release_evidence(self) -> None:
        self._category_assessment_case()

    def test_closed_release_evidence_cannot_issue_or_commit_assessment(self) -> None:
        for cut in ("issue", "precommit", "transaction", "observer"):
            with self.subTest(cut=cut):
                self._category_assessment_case(close_cut=cut)

    def _category_assessment_case(self, *, close_cut: str | None = None) -> None:
        api = category_fixture.load_slice3_api()
        profile_id = "release-operations"
        profile = category_fixture.profile_document(profile_id)
        materialized = category_fixture.materialized_profile(profile_id)
        policy = api.CategoryExecutionPolicy.from_installation(
            profile_document=profile,
            support_matrix_document=category_fixture.load_json(
                category_fixture.SUPPORT_MATRIX_PATH
            ),
            materialization_record=materialized.record,
        )
        target = category_fixture.DisposableLocalTarget(profile_id)
        try:
            (
                task_application,
                repository,
                objects,
                runtime,
                probe,
            ) = category_fixture.production_category_runtime(
                profile_id, "normal", target=target,
            )
            target_authority = api.CategoryTargetObservationAuthority(policy)
            release_factory = ReleaseOperationsRegistryFactory.from_installation()
            oracle = api.CategoryCompletionOracle(
                policy=policy,
                target_authority=target_authority,
                release_operations_factory=release_factory,
            )
            action_coordinator, action_context = category_fixture.action_rollback_binding(
                probe, target,
            )
            rollback = api.CategoryRollbackBridge(policy, action_coordinator)
            rollback.prepare_action(**action_context)
            probe.bind_rollback_evidence(rollback)
            application = api.CategoryExecutionApplication(
                repository=repository,
                object_repository=objects,
                policy=policy,
                reducer=api.CategoryExecutionReducer(policy),
                completion_oracle=oracle,
                rollback_bridge=rollback,
                assessment_resolver=api.CategoryAssessmentResolver(
                    repository,
                    objects,
                    task_application=task_application,
                    runtime=runtime,
                ),
                task_application=task_application,
                runtime=runtime,
                target_observer=target,
            )
            application.bind_current_sources(probe.task_id)
            candidate = category_fixture.candidate_document(profile_id, "normal")
            from graph_engineering.application.profile_execution import _category_selector

            _issued, current = application._authoritative_candidate(
                _category_selector(candidate), target,
            )
            with action_stack() as release_actions:
                baseline = release_factory.issue_artifact_manifest(
                    fixture_id="release-foundation-v1", artifact_id="artifact-a",
                )
                release_candidate = release_factory.issue_artifact_manifest(
                    fixture_id="release-foundation-v1", artifact_id="artifact-b",
                )
                baseline_bytes = release_factory.artifact_bytes(baseline)
                candidate_bytes = release_factory.artifact_bytes(release_candidate)
                self.assertEqual((baseline_bytes, candidate_bytes), artifact_bytes())
                session = release_factory.issue_simulator(
                    action_coordinator=release_actions.raw_coordinator,
                    task_id=str(current["task_id"]),
                    fixture_id="release-foundation-v1",
                    target_id="target-project",
                    resource_id="target:project",
                    baseline_manifest=baseline,
                    authorized_artifacts=(baseline, release_candidate),
                )
                with session:
                    action_outcome = self._assert_apply(
                        release_actions, session, baseline, release_candidate,
                        candidate_bytes,
                    )
                    deployment = release_factory.issue_deployment_observation(
                        action_coordinator=release_actions.raw_coordinator,
                        session=session,
                        outcome=action_outcome,
                    )
                    health = release_factory.issue_health_observation(
                        session=session,
                        terminal_observation=deployment,
                    )
                    evidence = release_factory.issue_evidence(
                        task_id=str(current["task_id"]),
                        task_revision=int(current["task_revision"]),
                        snapshot_digest=str(current["snapshot_digest"]),
                        invalidation_epoch=int(current["invalidation_epoch"]),
                        graph_ref_pins=dict(current["digest_pins"]),
                        artifact_manifest=release_candidate,
                        deployment_observation=deployment,
                        health_observation=health,
                        rollback_observation=None,
                        session=session,
                        owner_route="reconciled-effect-verified",
                        column_id=str(current["column_id"]),
                        scenario_id=str(current["scenario_id"]),
                        outcome="artifact-provenance-verified",
                    )
                    coherently_resigned = evidence.to_dict()
                    health_body = coherently_resigned["health_observation"]
                    health_body["unexpected"] = "forged"
                    health_body.pop("observation_digest")
                    health_body["observation_digest"] = _semantic(
                        health_body, "release-health-observation",
                    )
                    coherently_resigned["health_observation_digest"] = (
                        health_body["observation_digest"]
                    )
                    coherently_resigned.pop("observation_digest")
                    coherently_resigned["observation_digest"] = _semantic(
                        coherently_resigned, "release-operations-observation",
                    )
                    with self.assertRaisesRegex(
                        ReleaseOperationsError, "violates",
                    ):
                        release_factory.restore_projection(coherently_resigned)
                    if close_cut is not None:
                        before = probe.signature()
                        mutations = session._root.mutation_count
                        if close_cut == "issue":
                            session.close()
                        elif close_cut == "precommit":
                            application._fault = lambda step: (
                                session.close()
                                if step == "category-assessment.before-commit" else None
                            )
                        elif close_cut == "transaction":
                            repository._fault = lambda step: (
                                session.close() if step == "commit.before_commit" else None
                            )
                        else:
                            armed = [False]
                            repository._fault = lambda step: (
                                armed.__setitem__(0, True)
                                if step == "commit.before_commit" else None
                            )
                            original_observe = target.observe

                            def close_during_final_observation():  # type: ignore[no-untyped-def]
                                if armed[0]:
                                    session.close()
                                return original_observe()

                            target.observe = close_during_final_observation
                        with self.assertRaises(api.CategoryExecutionError):
                            application.assess_and_commit(
                                candidate, observer=target,
                                release_operations_evidence=evidence,
                            )
                        self.assertEqual(probe.signature(), before)
                        self.assertEqual(session._root.mutation_count, mutations)
                        self.assertEqual(session.target.apply_count, 1)
                        return
                    receipt = application.assess_and_commit(
                        candidate,
                        observer=target,
                        release_operations_evidence=evidence,
                    )
            self.assertEqual(receipt.assessment.schema_version, "1.4.0")
            self.assertIsNotNone(receipt.assessment.release_operations_projection)
            self.assertIsNone(receipt.assessment.scenario_truth_projection)
            schemas, context = category_fixture.category_schema_registry()
            evidence_document = evidence.to_dict()
            for name, document in (
                ("release-deployment-observation", evidence_document["deployment_observation"]),
                ("release-health-observation", evidence_document["health_observation"]),
            ):
                self.assertEqual(schemas.validate(
                    f"urn:gew:schema:{name}:1.0.0", document, context,
                ), [])
                input_document = dict(document)
                input_document.pop("observation_digest")
                self.assertEqual(schemas.validate(
                    f"urn:gew:schema:{name}-input:1.0.0",
                    input_document,
                    context,
                ), [])
            self.assertEqual(schemas.validate(
                "urn:gew:schema:release-operations-observation:1.0.0",
                evidence_document,
                context,
            ), [])
            evidence_input = dict(evidence_document)
            evidence_input.pop("observation_digest")
            self.assertEqual(schemas.validate(
                "urn:gew:schema:release-operations-observation-input:1.0.0",
                evidence_input,
                context,
            ), [])
            self.assertEqual(schemas.validate(
                "urn:gew:schema:category-completion-assessment:1.4.0",
                category_fixture.load_json_bytes(receipt.assessment.to_bytes()),
                context,
            ), [])
            restarted_task, restarted_runtime = probe.restart_authorities()
            with self.assertRaisesRegex(
                ReleaseOperationsError, "live target/journal revalidation",
            ):
                application.restart(
                    restarted_task, restarted_runtime, target,
                )
        finally:
            target.close()


if __name__ == "__main__":
    unittest.main()
