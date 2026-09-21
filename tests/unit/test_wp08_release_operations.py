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


class WP08ColdWheelDiscoveryTests(unittest.TestCase):
    def test_discovery_rechecks_earlier_roots_after_scanning_later_roots(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-cross-root-") as directory:
            early, later = pathlib.Path(directory) / "early", pathlib.Path(directory) / "later"
            early.mkdir(); later.mkdir()
            context = security_context()
            context.acquire_temporary(3, source_id="prior", operation_path=())
            context._recovery_result_bytes = 5
            owner = _RecoveryReadBudget((context,))
            scan, opened, iterators = os.scandir, [], []
            class Iterator:
                def __init__(self, value): self.value = value; self.closed = False
                def __next__(self): return next(self.value)
                def close(self): self.value.close(); self.closed = True
            def changed(descriptor):
                opened.append(descriptor)
                iterator = Iterator(scan(descriptor)); iterators.append(iterator)
                if os.fstat(descriptor).st_ino == later.stat().st_ino:
                    (early / "late.dist-info").mkdir()
                return iterator
            try:
                with owner.bind(), mock.patch.object(sys, "path", [str(early), str(later)]), \
                        mock.patch.object(os, "scandir", side_effect=changed):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "root topology changed"):
                        module._capture_installation_discovery(context, owner)
                self.assertTrue(all(iterator.closed for iterator in iterators))
                for descriptor in opened:
                    with self.assertRaises(OSError): os.fstat(descriptor)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
            self.assertEqual((context._temporary_units, context._recovery_result_bytes), (3, 5))
            context.release_temporary(3)

    def test_discovery_preserves_non_enumerable_root_states_and_permission_changes(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget, _recovery_equal
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-root-permission-") as directory:
            root = pathlib.Path(directory)
            for mode in (0, 0o100):
                hidden = root / str(mode)
                hidden.mkdir()
                (hidden / "late.dist-info").mkdir()
                hidden.chmod(mode)
                context = security_context()
                owner = _RecoveryReadBudget((context,))
                try:
                    with owner.bind(), mock.patch.object(sys, "path", [str(hidden)]):
                        first = module._capture_installation_discovery(context, owner)
                        self.assertEqual(first[1][0][2], "unavailable-directory")
                        hidden.chmod(0o700)
                        second = module._capture_installation_discovery(context, owner)
                        self.assertFalse(_recovery_equal(first, second, context, owner))
                        self.assertEqual(second[1][0][2], "directory")
                        owner.release_projection(first); owner.release_projection(second)
                finally:
                    hidden.chmod(0o700)
                    owner.close()

    def test_discovery_path_processing_bounds_link_chains_intermediates_and_native_buffers(self):
        import sys
        import tempfile
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-links-") as directory:
            root = pathlib.Path(directory)
            (root / "destination").mkdir()
            for index in range(40):
                (root / ("link" + str(index))).symlink_to("link" + str(index + 1) if index < 39 else "destination")
            for limit in (256, 24):
                context = security_context()
                context.profile = replace(context.profile, limits={**context.profile.limits, "array_items":limit})
                owner = _RecoveryReadBudget((context,))
                make, allocations = module.ctypes.create_string_buffer, []
                def admitted(size):
                    self.assertGreaterEqual(owner.retained_bytes, size)
                    self.assertGreaterEqual(context._temporary_units, size)
                    allocations.append(size)
                    return make(size)
                try:
                    with owner.bind(), mock.patch.object(sys, "path", [str(root / "link0")]), \
                            mock.patch.object(module.ctypes, "create_string_buffer", side_effect=admitted):
                        if limit == 256:
                            value = module._capture_installation_discovery(context, owner)
                            self.assertEqual(value[1][0][1], str(root.resolve() / "destination"))
                            owner.release_projection(value)
                        else:
                            with self.assertRaises(ContractError):
                                module._capture_installation_discovery(context, owner)
                    self.assertTrue(allocations)
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                finally:
                    owner.close()
            link = root / "long"
            link.symlink_to("a" * 800)
            context = security_context()
            owner = _RecoveryReadBudget((context,))
            try:
                with owner.bind(), mock.patch.object(sys, "path", [str(link) + "/" + "b" * 300]):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "intermediate path exceeds"):
                        module._capture_installation_discovery(context, owner)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()

    def test_path_native_scratch_exact_admission_and_retained_exception_cleanup(self):
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        size = os.pathconf("/", "PC_PATH_MAX")
        required = 16 * (size + 1)
        marker = "cold-path-retained-input"
        for allowance in (required, required - 1):
            context = security_context()
            context.profile = replace(context.profile, limits={**context.profile.limits,
                "result_bytes":allowance + 3})
            context._recovery_result_bytes = 3
            owner = _RecoveryReadBudget((context,))
            make, allocations, caught = module.ctypes.create_string_buffer, [], None
            def observed(count):
                allocations.append(count)
                self.assertGreaterEqual(owner.retained_bytes, required)
                return make(count)
            try:
                with owner.bind(), mock.patch.object(module.ctypes, "create_string_buffer", side_effect=observed):
                    try:
                        module._bounded_path_text(context, owner, size, link=marker)
                    except (ContractError, module.DistributionIdentityError) as error:
                        caught = error
                self.assertIsNotNone(caught)
                self.assertEqual(len(allocations), 1 if allowance == required else 0)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                trace = caught.__traceback__
                while trace is not None:
                    if trace.tb_frame.f_code.co_filename == module.__file__:
                        self.assertNotIn(marker, trace.tb_frame.f_locals.values())
                    trace = trace.tb_next
            finally:
                owner.close()
            self.assertEqual(context._recovery_result_bytes, 3)

    def test_discovery_uses_bounded_path_resolution_and_rechecks_live_topology(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-path-bound-") as directory:
            root = pathlib.Path(directory)
            left, right, link = root / "left", root / "right", root / "alias"
            left.mkdir(); right.mkdir(); link.symlink_to(left, target_is_directory=True)
            expected = str(left.resolve())
            context = security_context()
            owner = _RecoveryReadBudget((context,))
            cwd = os.getcwd()
            try:
                with owner.bind(), mock.patch.object(sys, "path", [str(link)]), \
                        mock.patch.object(os.path, "realpath", side_effect=AssertionError("unbounded realpath")), \
                        mock.patch.object(os, "getcwd", side_effect=AssertionError("unbounded getcwd")):
                    captured = module._capture_installation_discovery(context, owner)
                    self.assertEqual(captured[1][0][1], expected)
                    owner.release_projection(captured)
                for change in ("cwd", "link", "absent", "kind"):
                    absent = root / "absent"
                    kind = root / "kind"
                    kind.mkdir()
                    paths = [str(absent), str(kind), str(link)]
                    scan, triggered = os.scandir, []
                    def changed(path):
                        iterator = scan(path)
                        if not triggered and (change != "link" or
                                os.fstat(path).st_ino == left.stat().st_ino):
                            triggered.append(True)
                            if change == "cwd": os.chdir(right)
                            elif change == "link": link.unlink(); link.symlink_to(right, target_is_directory=True)
                            elif change == "absent": absent.mkdir()
                            else: kind.rmdir(); kind.write_text("now an archive root")
                        return iterator
                    with owner.bind(), mock.patch.object(sys, "path", paths), \
                            mock.patch.object(os, "scandir", side_effect=changed):
                        with self.assertRaisesRegex(module.DistributionIdentityError, "topology|root changed", msg=change):
                            module._capture_installation_discovery(context, owner)
                    os.chdir(cwd)
                    link.unlink(); link.symlink_to(left, target_is_directory=True)
                    if absent.exists(): absent.rmdir()
                    if kind.is_dir(): kind.rmdir()
                    else: kind.unlink()
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                os.chdir(cwd)
                owner.close()

    def test_discovery_preserves_unreadable_and_execute_only_candidate_fallbacks(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget, _recovery_equal
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-permission-") as directory:
            root = pathlib.Path(directory)
            blocked, searchable, single = root / "blocked.dist-info", root / "search.dist-info", root / "single.egg-info"
            for path in (blocked, searchable):
                path.mkdir()
                (path / "METADATA").write_text("Name: nonselected\n")
            single.write_text("Name: single\n")
            blocked.chmod(0); searchable.chmod(0o100); single.chmod(0)
            context = security_context()
            owner = _RecoveryReadBudget((context,))
            try:
                with owner.bind(), mock.patch.object(sys, "path", [directory]):
                    first = module._capture_installation_discovery(context, owner)
                    members = first[1][0][4]
                    self.assertEqual(members[searchable.name][0][0], "file")
                    self.assertEqual(members[blocked.name][0][0], "unavailable")
                    self.assertEqual(members[single.name][2][0], "unavailable")
                    blocked.chmod(0o700); searchable.chmod(0o700); single.chmod(0o600)
                    second = module._capture_installation_discovery(context, owner)
                    self.assertFalse(_recovery_equal(first, second, context, owner))
                    owner.release_projection(first); owner.release_projection(second)
            finally:
                blocked.chmod(0o700); searchable.chmod(0o700); single.chmod(0o600)
                owner.close()

    def test_discovery_rejects_candidate_symlinks_before_reads_and_mid_capture_mutation(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-candidate-race-") as directory:
            root = pathlib.Path(directory)
            info = root / "pkg.dist-info"
            outside = root / "ordinary"
            outside.mkdir()
            (outside / "METADATA").write_text("Name: outside\n")
            info.symlink_to(outside, target_is_directory=True)
            context = security_context()
            owner = _RecoveryReadBudget((context,))
            try:
                with owner.bind(), mock.patch.object(sys, "path", [directory]), \
                        mock.patch.object(os, "read", side_effect=AssertionError("symlink candidate was read")):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "symlink candidate"):
                        module._capture_installation_discovery(context, owner)
                info.unlink()
                info.mkdir()
                capture = module._discovery_file_state
                def changed(*args, **kwargs):
                    result = capture(*args, **kwargs)
                    if args[1].endswith("METADATA"):
                        (info / "METADATA").write_text("Name: late\n")
                    return result
                with owner.bind(), mock.patch.object(sys, "path", [directory]), \
                        mock.patch.object(module, "_discovery_file_state", side_effect=changed):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "candidate changed"):
                        module._capture_installation_discovery(context, owner)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()

    def test_discovery_rejects_directory_changes_after_enumeration(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-dir-race-") as directory:
            context = security_context()
            owner = _RecoveryReadBudget((context,))
            scan = os.scandir
            class Iterator:
                def __init__(self, original): self.original = original
                def __next__(self): return next(self.original)
                def close(self):
                    self.original.close()
                    (pathlib.Path(directory) / "late.dist-info").mkdir()
            try:
                with owner.bind(), mock.patch.object(sys, "path", [directory]), \
                        mock.patch.object(os, "scandir", side_effect=lambda path: Iterator(scan(path))):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "root changed"):
                        module._capture_installation_discovery(context, owner)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()

    def test_discovery_current_topology_includes_cwd_absence_and_nonselected_archives(self):
        import sys
        import tempfile
        import zipfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget, _recovery_equal
        from tests.support.wp05a_security import security_context

        context = security_context()
        owner = _RecoveryReadBudget((context,))
        with tempfile.TemporaryDirectory(prefix="gew-discovery-topology-") as directory:
            root = pathlib.Path(directory)
            left, right = root / "left", root / "right"
            left.mkdir(); right.mkdir()
            (left / "relative").mkdir(); (right / "relative").mkdir()
            archive = root / "unrelated.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("other.dist-info/METADATA", "Name: other\n")
            cwd = os.getcwd()
            try:
                for roots, change in ((["", "relative"], "cwd"),
                        ([str(root / "absent")], "absent"), ([str(archive)], "archive")):
                    os.chdir(left)
                    with owner.bind(), mock.patch.object(sys, "path", roots):
                        first = module._capture_installation_discovery(context, owner)
                        if change == "cwd": os.chdir(right)
                        elif change == "absent": (root / "absent").mkdir()
                        else:
                            with zipfile.ZipFile(archive, "w") as output:
                                output.writestr("new.dist-info/METADATA", "Name: graph-engineering-workflow\n")
                        second = module._capture_installation_discovery(context, owner)
                        self.assertFalse(_recovery_equal(first, second, context, owner))
                        owner.release_projection(first); owner.release_projection(second)
            finally:
                os.chdir(cwd)
                owner.close()
        self.assertEqual((context._temporary_units, context._recovery_result_bytes), (0, 0))

    def test_discovery_streaming_rejects_short_growth_and_member_removal(self):
        import sys
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-stream-") as directory:
            info = pathlib.Path(directory) / "pkg.dist-info"
            info.mkdir()
            member = info / "METADATA"
            for fault in ("short", "growth", "removed"):
                member.write_text("Name: stream-fixture\n")
                identity = (member.stat().st_dev, member.stat().st_ino)
                context = security_context()
                owner = _RecoveryReadBudget((context,))
                read, open_file = os.read, os.open
                opened, visited = [], []
                def observed_open(*args, **kwargs):
                    descriptor = open_file(*args, **kwargs); opened.append(descriptor); return descriptor
                def changed_read(descriptor, count):
                    metadata = os.fstat(descriptor)
                    if (metadata.st_dev, metadata.st_ino) != identity: return read(descriptor, count)
                    self.assertGreaterEqual(owner.retained_bytes, count)
                    self.assertGreaterEqual(context._temporary_units, count)
                    body = read(descriptor, count); visited.append(count)
                    if fault == "short" and body: return body[:-1]
                    if fault == "growth" and not body: return b"x"
                    if fault == "removed" and not body: member.unlink()
                    return body
                try:
                    with owner.bind(), mock.patch.object(sys, "path", [directory]), \
                            mock.patch.object(os, "read", side_effect=changed_read), \
                            mock.patch.object(os, "open", side_effect=observed_open):
                        with self.assertRaisesRegex(module.DistributionIdentityError,
                                {"short":"short read", "growth":"grew",
                                 "removed":"changed (during read|after opening)"}[fault]):
                            module._capture_installation_discovery(context, owner)
                    self.assertTrue(visited)
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    for descriptor in opened:
                        with self.assertRaises(OSError): os.fstat(descriptor)
                finally:
                    owner.close()

    def test_discovery_keeps_first_proof_and_enforces_exact_aggregate_bytes(self):
        import sys
        import tempfile
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-exact-") as directory:
            info = pathlib.Path(directory) / "tiny.dist-info"
            info.mkdir()
            (info / "METADATA").write_text("Name: x\n")
            probe_context = security_context()
            probe = _RecoveryReadBudget((probe_context,))
            with probe.bind(), mock.patch.object(sys, "path", [directory]):
                first = module._capture_installation_discovery(probe_context, probe)
                second = module._capture_installation_discovery(probe_context, probe)
            required = probe.peak_bytes
            probe.close()
            for allowance in (required, required - 1):
                left, right = security_context(), security_context()
                right.profile = replace(right.profile, limits={**right.profile.limits,
                    "result_bytes": allowance + 3})
                right._recovery_result_bytes = 3
                owner = _RecoveryReadBudget((left, right))
                try:
                    with owner.bind(), mock.patch.object(sys, "path", [directory]):
                        first = module._capture_installation_discovery(left, owner)
                        retained = (owner.retained_units, owner.retained_bytes)
                        if allowance == required:
                            second = module._capture_installation_discovery(left, owner)
                            owner.release_projection(second)
                        else:
                            with self.assertRaises(ContractError):
                                module._capture_installation_discovery(left, owner)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), retained)
                        owner.release_projection(first)
                finally:
                    owner.close()
                self.assertEqual((left._temporary_units, right._temporary_units), (0, 0))
                self.assertEqual(right._recovery_result_bytes, 3)

    def test_discovery_failure_drops_payloads_from_retained_tracebacks(self):
        import sys
        import tempfile
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        marker = "discovery-retired-frame"
        with tempfile.TemporaryDirectory(prefix=marker) as directory:
            info = pathlib.Path(directory) / "small.dist-info"
            info.mkdir()
            (info / "METADATA").write_text("Name: too-large\n")
            context = security_context()
            context.profile = replace(context.profile, limits={**context.profile.limits, "raw_document_bytes": 1})
            owner = _RecoveryReadBudget((context,))
            retained_error = None
            try:
                with owner.bind(), mock.patch.object(sys, "path", [directory]):
                    try: module._capture_installation_discovery(context, owner)
                    except ContractError as error: retained_error = error
                self.assertIsNotNone(retained_error)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                trace = retained_error.__traceback__
                while trace is not None:
                    if trace.tb_frame.f_code.co_filename == module.__file__:
                        for name, value in trace.tb_frame.f_locals.items():
                            if type(value) is str:
                                self.assertNotIn(marker, value, "released path remains in " + name)
                    trace = trace.tb_next
            finally:
                owner.close()

    def test_discovery_rejects_provider_implementation_and_mid_capture_path_changes(self):
        import sys
        import tempfile
        import importlib.machinery
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        class ForeignFinder:
            def find_distributions(self, *args, **kwargs):
                raise AssertionError("untrusted discovery provider ran")
        context = security_context()
        owner = _RecoveryReadBudget((context,))
        try:
            with owner.bind(), mock.patch.object(sys, "meta_path", [*sys.meta_path, ForeignFinder()]), \
                    mock.patch.object(os, "scandir", side_effect=AssertionError("provider rejection performed IO")):
                with self.assertRaisesRegex(module.DistributionIdentityError, "provider is unsupported"):
                    module._capture_installation_discovery(context, owner)
            with owner.bind(), mock.patch.object(importlib.machinery.PathFinder, "find_distributions",
                    side_effect=AssertionError("changed discovery function ran")):
                with self.assertRaisesRegex(module.DistributionIdentityError, "implementation changed"):
                    module._capture_installation_discovery(context, owner)
            with tempfile.TemporaryDirectory(prefix="gew-discovery-path-race-") as directory:
                paths, scan = [directory], os.scandir
                def changed(path):
                    iterator = scan(path)
                    paths.append(directory + "/late")
                    return iterator
                with owner.bind(), mock.patch.object(sys, "path", paths), \
                        mock.patch.object(os, "scandir", side_effect=changed):
                    with self.assertRaisesRegex(module.DistributionIdentityError, "search path changed"):
                        module._capture_installation_discovery(context, owner)
            self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
        finally:
            owner.close()

    def test_discovery_recaptures_every_metadata_fallback_archive_and_duplicate_root(self):
        import sys
        import tempfile
        import zipfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget, _recovery_equal
        from tests.support.wp05a_security import security_context

        context = security_context()
        owner = _RecoveryReadBudget((context,))
        with tempfile.TemporaryDirectory(prefix="gew-cold-discovery-") as directory:
            root = pathlib.Path(directory)
            info = root / "unrelated.dist-info"
            info.mkdir()
            (info / "METADATA").write_text("")
            metadata = info / "PKG-INFO"
            metadata.write_text("Name: unrelated\nVersion: 1\n")
            single = root / "single.egg-info"
            single.write_text("Name: single\nVersion: 1\n")
            egg = root / "legacy.egg"
            egg.mkdir()
            (egg / "EGG-INFO").mkdir()
            (egg / "EGG-INFO" / "PKG-INFO").write_text("Name: legacy\nVersion: 1\n")
            archive = root / "other.zip"
            with zipfile.ZipFile(archive, "w") as out:
                out.writestr("archive.dist-info/METADATA", "Name: archive\nVersion: 1\n")
            roots = [str(root), str(egg), str(archive), str(root / "absent"), str(root)]
            try:
                with mock.patch.object(sys, "path", roots), owner.bind():
                    first = module._capture_installation_discovery(context, owner)
                    retained = (owner.retained_units, owner.retained_bytes)
                    second = module._capture_installation_discovery(context, owner)
                    self.assertTrue(_recovery_equal(first, second, context, owner))
                    self.assertGreater(owner.retained_bytes, retained[1])
                    owner.release_projection(second)
                    self.assertEqual((owner.retained_units, owner.retained_bytes), retained)
                    for path, replacement in (
                            (metadata, "Name: graph-engineering-workflow\nVersion: 1\n"),
                            (info / "METADATA", "Name: earlier\nVersion: 1\n"),
                            (single, "Name: substituted\nVersion: 1\n"),
                            (egg / "EGG-INFO" / "PKG-INFO", "Name: changed\nVersion: 1\n")):
                        before = module._capture_installation_discovery(context, owner)
                        original = path.read_bytes()
                        path.write_text(replacement)
                        changed = module._capture_installation_discovery(context, owner)
                        self.assertFalse(_recovery_equal(before, changed, context, owner))
                        owner.release_projection(changed)
                        owner.release_projection(before)
                        path.write_bytes(original)
                    owner.release_projection(first)
            finally:
                owner.close()
        self.assertEqual((context._temporary_units, context._recovery_result_bytes), (0, 0))

    def test_non_candidates_and_duplicate_paths_consume_the_row_bound_and_close_iterators(self):
        import sys
        import tempfile
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-discovery-entries-") as directory:
            root = pathlib.Path(directory)
            for index in range(20):
                (root / (str(index) + ".txt")).write_text("not a distribution")
            for paths, limit in (([str(root)], 19), ([str(root), str(root)], 39)):
                context = security_context()
                context.profile = replace(context.profile, limits={**context.profile.limits, "array_items": limit})
                owner = _RecoveryReadBudget((context,))
                scan, opened = os.scandir, []
                class Iterator:
                    def __init__(self, value): self.value = value; self.closed = False
                    def __iter__(self): return self
                    def __next__(self): return next(self.value)
                    def close(self): self.closed = True; self.value.close()
                def observe(path):
                    value = Iterator(scan(path)); opened.append(value); return value
                try:
                    with owner.bind(), mock.patch.object(sys, "path", paths), \
                            mock.patch.object(os, "scandir", side_effect=observe):
                        with self.assertRaises(ContractError):
                            module._capture_installation_discovery(context, owner)
                    self.assertTrue(opened)
                    self.assertTrue(all(item.closed for item in opened))
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                finally:
                    owner.close()


class WP08ColdWheelCurrentnessTests(unittest.TestCase):
    def test_category_wheel_plan_rejects_changed_cached_inputs_and_issuance_drift(self):
        import subprocess
        import sys
        import tempfile
        import textwrap
        import zipfile

        probe = textwrap.dedent('''
            import base64, csv, hashlib, io, pathlib, sys
            from unittest import mock
            sys.path.insert(0, sys.argv[1])
            import graph_engineering as module
            from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory
            from graph_engineering.storage.repository import _RecoveryReadBudget
            factory = ReleaseOperationsRegistryFactory.from_installation()
            context = factory._cold_artifact_authority()[2]
            resources = module._release_operations_installation_resources()
            category = module._category_policy_installation_resources()
            for index in range(3):
                changed = list(category); changed[index] += b"\\n"
                owner = _RecoveryReadBudget((context,))
                try:
                    try: module._release_operations_wheel_read_plan(resources, context, owner,
                            category_resources=tuple(changed))
                    except module.DistributionIdentityError as error:
                        assert "category" in str(error), str(error)
                    else: raise AssertionError("changed cached category input accepted")
                    assert owner.retained_units == owner.retained_bytes == 0
                finally: owner.close()
            root = pathlib.Path(sys.argv[1])
            if root.is_dir():
                # Change actual installed policy and its RECORD after the first
                # physical capture; the fresh category read must join the inputs.
                name = module._category_policy_locations(category[0], location_kind="resource")[1]
                path = root / name; original_body = path.read_bytes()
                record = next(root.glob("*.dist-info/RECORD")); original_record = record.read_bytes()
                read = module._release_operations_installation_resources
                changed_body = original_body + b"\\n"
                def changed_read():
                    result = read()
                    rows = list(csv.reader(original_record.decode().splitlines()))
                    for row in rows:
                        if row[0] == name:
                            row[1] = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(changed_body).digest()).decode().rstrip("=")
                            row[2] = str(len(changed_body))
                    buffer = io.StringIO(); csv.writer(buffer, lineterminator="\\n").writerows(rows)
                    path.write_bytes(changed_body); record.write_text(buffer.getvalue())
                    return result
                owner = _RecoveryReadBudget((context,))
                try:
                    with mock.patch.object(module, "_release_operations_installation_resources", side_effect=changed_read):
                        try: module._release_operations_wheel_read_plan(resources, context, owner, category_resources=category)
                        except module.DistributionIdentityError as error:
                            assert "category inputs changed" in str(error), str(error)
                        else: raise AssertionError("actual installed category drift accepted")
                    assert path.read_bytes() == changed_body
                    assert owner.retained_units == owner.retained_bytes == 0
                finally:
                    owner.close(); path.write_bytes(original_body); record.write_bytes(original_record)
        ''')
        with tempfile.TemporaryDirectory(prefix="gew-category-wheel-") as directory:
            root = pathlib.Path(directory); dist = root / "dist"; dist.mkdir()
            built = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_wheel.py"), str(dist)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl")); unpacked = root / "unpacked"
            with zipfile.ZipFile(wheel) as archive: archive.extractall(unpacked)
            for installation in (wheel, unpacked):
                with self.subTest(installation=installation.name):
                    result = subprocess.run([sys.executable, "-B", "-I", "-c", probe, str(installation)],
                        cwd=root, capture_output=True, text=True, timeout=120)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_record_member_derivation_uses_the_exact_snapshot_despite_aba(self):
        import subprocess
        import sys
        import tempfile
        import textwrap
        import zipfile

        probe = textwrap.dedent('''
            import importlib.metadata, pathlib, sys
            from unittest import mock
            sys.path.insert(0, sys.argv[1])
            import graph_engineering as module
            from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory
            from graph_engineering.storage.repository import _RecoveryReadBudget
            factory = ReleaseOperationsRegistryFactory.from_installation()
            context = factory._cold_artifact_authority()[2]
            resources = module._release_operations_installation_resources()
            owner = _RecoveryReadBudget((context,))
            root = pathlib.Path(sys.argv[1])
            record = next(root.glob("*.dist-info/RECORD"))
            snapshot = record.read_bytes()
            name = "graph_engineering/adapters/__init__.py"
            assert (root / name).is_file()
            assert any(line.startswith(name + ",") for line in snapshot.decode().splitlines())
            files = importlib.metadata.Distribution.files
            calls = []
            def transient(distribution):
                # Only the old independent derivation read observes B. All
                # physical proofs and ordinary bootstrap reads observe A.
                if sys._getframe(1).f_code.co_name != "_release_operations_wheel_read_plan":
                    return files.fget(distribution)
                calls.append(True)
                record.write_bytes(b"\\n".join(line for line in snapshot.splitlines()
                    if not line.startswith(name.encode() + b",")) + b"\\n")
                try: return files.fget(distribution)
                finally: record.write_bytes(snapshot)
            try:
                with mock.patch.object(importlib.metadata.Distribution, "files", property(transient)):
                    plan = module._release_operations_wheel_read_plan(resources, context, owner)
                assert name in plan.names, "ABA omitted an installed adapter from the plan"
                assert record.read_bytes() == snapshot
                assert (owner.retained_units, owner.retained_bytes) == (0, 0)
            finally: owner.close()
        ''')
        with tempfile.TemporaryDirectory(prefix="gew-wheel-record-aba-") as directory:
            root = pathlib.Path(directory); dist = root / "dist"; dist.mkdir()
            built = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_wheel.py"), str(dist)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            with zipfile.ZipFile(next(dist.glob("*.whl"))) as archive:
                installation = root / "installed"; archive.extractall(installation)
            checked = subprocess.run([sys.executable, "-B", "-I", "-c", probe, str(installation)],
                cwd=root, capture_output=True, text=True, timeout=120)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_currentness_drops_proof_references_before_releasing_their_charge(self):
        import gc
        import sys
        import tempfile
        import weakref
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        for fail_second in (False, True):
            with self.subTest(fail_second=fail_second), tempfile.TemporaryDirectory(prefix="gew-wheel-proofs-") as directory:
                root = pathlib.Path(directory); (root / "member").write_bytes(b"current member")
                context = security_context(); context.acquire_temporary(3, source_id="prior", operation_path=())
                context._recovery_result_bytes = 5
                owner = _RecoveryReadBudget((context,))
                plan = module._WheelInstallationReadPlan(root, archive=False, names=("member",))
                reference, failures, releases, calls = weakref.ref(plan), [], [], []
                release, capture = owner.release_projection, module._capture_installation_discovery
                def observed(value):
                    frame = sys._getframe(1)
                    try:
                        self.assertEqual(frame.f_code.co_name, "require_current")
                        for name, item in frame.f_locals.items():
                            self.assertIsNot(item, value, "released proof still named " + name)
                            if type(item) in (list, tuple):
                                self.assertFalse(any(child is value for child in item), "released proof still in " + name)
                    finally:
                        # CPython caches this observer-created locals snapshot;
                        # discard it so the measurement does not pin the plan.
                        frame.f_locals.clear()
                        frame = item = None
                    releases.append(id(value)); release(value)
                def changed(*args):
                    calls.append(True)
                    if fail_second and len(calls) == 2: (root / "new.dist-info").mkdir()
                    return capture(*args)
                with owner.bind(), mock.patch.object(sys, "path", [str(root)]):
                    plan.discovery = capture(context, owner); owner.move_projection(plan.discovery, plan)
                    plan.members = plan._capture_members(context, owner); owner.move_projection(plan.members, plan)
                    baseline = (owner.retained_units, owner.retained_bytes)
                    with mock.patch.object(owner, "release_projection", new=observed), \
                            mock.patch.object(module, "_capture_installation_discovery", side_effect=changed):
                        try: plan.require_current(context, owner)
                        except module.DistributionIdentityError as error: failures.append(error)
                    self.assertEqual(bool(failures), fail_second)
                    self.assertEqual(len(releases), 4)
                    self.assertEqual((owner.retained_units, owner.retained_bytes), baseline)
                    owner.release_projection(plan)
                owner.close(); plan = None; gc.collect()
                self.assertIsNone(reference())
                self.assertEqual((context._temporary_units, context._recovery_result_bytes), (3, 5))
                context.release_temporary(3)

    def test_record_member_derivation_rejects_real_unpacked_issuance_race(self):
        import subprocess
        import sys
        import tempfile
        import textwrap
        import zipfile

        probe = textwrap.dedent('''
            import base64, hashlib, pathlib, sys
            from unittest import mock
            sys.path.insert(0, sys.argv[1])
            import graph_engineering as module
            from graph_engineering.application.release_operations import ReleaseOperationsRegistryFactory
            from graph_engineering.storage.repository import _RecoveryReadBudget
            factory = ReleaseOperationsRegistryFactory.from_installation()
            context = factory._cold_artifact_authority()[2]
            resources = module._release_operations_installation_resources()
            owner = _RecoveryReadBudget((context,))
            original = module._WheelInstallationReadPlan._capture_members
            calls = []
            def changed(plan, *args):
                if not calls:
                    calls.append(True)
                    root = pathlib.Path(sys.argv[1])
                    name = "graph_engineering/adapters/late_record_member.py"
                    body = b"# valid newly recorded adapter member\\n"
                    (root / name).write_bytes(body)
                    record = next(root.glob("*.dist-info/RECORD"))
                    digest = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).decode().rstrip("=")
                    with record.open("a") as stream:
                        stream.write(name + ",sha256=" + digest + "," + str(len(body)) + "\\n")
                return original(plan, *args)
            try:
                with mock.patch.object(module._WheelInstallationReadPlan, "_capture_members", changed):
                    try: module._release_operations_wheel_read_plan(resources, context, owner)
                    except module.DistributionIdentityError as error:
                        assert "RECORD" in str(error), str(error)
                    else: raise AssertionError("old derived closure accepted with new RECORD")
                assert len(calls) == 1
                assert (owner.retained_units, owner.retained_bytes) == (0, 0)
            finally: owner.close()
        ''')
        with tempfile.TemporaryDirectory(prefix="gew-wheel-record-race-") as directory:
            root = pathlib.Path(directory); dist = root / "dist"; dist.mkdir()
            built = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_wheel.py"), str(dist)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            with zipfile.ZipFile(next(dist.glob("*.whl"))) as archive:
                installation = root / "installed"; archive.extractall(installation)
            checked = subprocess.run([sys.executable, "-B", "-I", "-c", probe, str(installation)],
                cwd=root, capture_output=True, text=True, timeout=120)
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_changed_module_origin_rejects_before_any_path_conversion(self):
        import tempfile
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-wheel-origin-") as directory:
            plan = module._WheelInstallationReadPlan(pathlib.Path(directory), archive=False, names=())
            for origin in ("/" + "x" * (os.pathconf("/", "PC_PATH_MAX") + 1), "relative.py", object()):
                context = security_context(); owner = _RecoveryReadBudget((context,))
                try:
                    with owner.bind(), mock.patch.object(module, "__file__", origin), \
                            mock.patch.object(os.path, "abspath", side_effect=AssertionError("path conversion before rejection")), \
                            mock.patch.object(os.path, "normpath", side_effect=AssertionError("path conversion before rejection")):
                        with self.assertRaisesRegex(module.DistributionIdentityError, "module changed"):
                            plan._capture_members(context, owner)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                finally: owner.close()

    def test_require_current_entry_failure_drops_plan_from_actual_traceback(self):
        import gc
        import tempfile
        import weakref
        import graph_engineering as module
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-wheel-entry-") as directory:
            context = security_context(); owner = _RecoveryReadBudget((context,))
            plan = module._WheelInstallationReadPlan(pathlib.Path(directory), archive=False, names=())
            reference, failures = weakref.ref(plan), []
            try: plan.require_current(context, owner)
            except ValueError as error: failures.append(error)
            else: self.fail("unbound plan currentness succeeded")
            owner.close(); plan = None; gc.collect()
            self.assertIsNone(reference())
            self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))

    def test_wheel_plan_admission_failure_drops_the_plan_from_retained_exceptions(self):
        import gc
        import tempfile
        import weakref
        from dataclasses import replace
        import graph_engineering as module
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        with tempfile.TemporaryDirectory(prefix="gew-wheel-plan-lifetime-") as directory:
            context = security_context()
            context.profile = replace(context.profile, limits={**context.profile.limits, "temporary_units":1})
            owner = _RecoveryReadBudget((context,))
            plan = module._WheelInstallationReadPlan(pathlib.Path(directory), archive=False, names=())
            reference, retained_error = weakref.ref(plan), None
            with owner.bind():
                try: plan._capture_members(context, owner)
                except ContractError as error: retained_error = error
            self.assertIsNotNone(retained_error)
            owner.close()
            del plan
            gc.collect()
            self.assertIsNone(reference())

    def test_installed_wheel_rejects_discovery_member_and_between_capture_changes(self):
        import subprocess
        import sys
        import tempfile
        import textwrap
        import zipfile

        probe = textwrap.dedent('''
            import json, os, pathlib, sys
            from unittest import mock
            sys.path.insert(0, sys.argv[1])
            other = pathlib.Path("discovery")
            other.mkdir()
            info = other / "other.dist-info"
            info.mkdir()
            metadata = info / "METADATA"
            metadata.write_text("Name: other\\nVersion: 1\\n")
            sys.path.append(str(other.resolve()))
            import graph_engineering as installation
            from graph_engineering.application.release_operations import (
                ReleaseOperationsRegistryFactory, ReleaseOperationsError, _COLD_INSTALLATION_PLANS)
            from graph_engineering.storage.repository import _RecoveryReadBudget
            factory = ReleaseOperationsRegistryFactory.from_installation()
            plan = _COLD_INSTALLATION_PLANS[factory]
            _contracts, _schemas, context = factory._cold_artifact_authority()
            owner = _RecoveryReadBudget((context,))
            if sys.argv[2] == "issuance":
                read_resources = installation._release_operations_installation_resources
                resources = read_resources()
                def changed_semantics():
                    current = read_resources()
                    metadata.write_text("Name: changed-nonselected\\nVersion: 1\\n")
                    return current
                try:
                    with mock.patch.object(installation, "_release_operations_installation_resources",
                            side_effect=changed_semantics):
                        try: installation._release_operations_wheel_read_plan(resources, context, owner)
                        except installation.DistributionIdentityError as error:
                            assert "changed during plan issuance" in str(error), str(error)
                        else: raise AssertionError("mixed bootstrap plan accepted")
                    assert (owner.retained_units, owner.retained_bytes) == (0, 0)
                finally:
                    owner.close()
                print(json.dumps({"rejected":sys.argv[2]}))
                sys.exit(0)
            calls, before = [], []
            capture = installation._capture_installation_discovery
            def observed(*args):
                calls.append(True)
                if len(calls) == 2:
                    assert owner.retained_bytes > before[0]
                    assert len(owner._projections) >= 3
                    metadata.write_text("Name: graph-engineering-workflow\\nVersion: 1\\n")
                return capture(*args)
            try:
                with owner.bind(ports=(factory,)):
                    adopted = factory._adopt_cold_configuration(owner)
                    retained = (owner.retained_units, owner.retained_bytes)
                    before.append(owner.retained_bytes)
                    if sys.argv[2] == "discovery":
                        metadata.write_text("Name: graph-engineering-workflow\\nVersion: 1\\n")
                    elif sys.argv[2] == "physical":
                        target = pathlib.Path(sys.argv[1])
                        if target.is_dir(): target = next(target.glob("*.dist-info/RECORD"))
                        with target.open("ab") as output: output.write(b"\\n")
                    with mock.patch.object(installation, "_release_operations_installation_resources",
                            side_effect=AssertionError("legacy cold fallback")), \\
                         mock.patch.object(installation, "_capture_installation_discovery",
                            side_effect=observed if sys.argv[2] == "between" else capture):
                        try: factory.require_installed_authority()
                        except ReleaseOperationsError as error:
                            assert "cold wheel" in str(error.__cause__), str(error.__cause__)
                        else: raise AssertionError("changed installed closure accepted")
                    assert (owner.retained_units, owner.retained_bytes) == retained
                    if sys.argv[2] == "between": assert len(calls) == 2
                owner.release_projection(adopted)
            finally:
                owner.close()
            assert context._temporary_units == 0
            print(json.dumps({"rejected":sys.argv[2]}))
        ''')
        with tempfile.TemporaryDirectory(prefix="gew-cold-wheel-reject-") as directory:
            root = pathlib.Path(directory)
            dist = root / "dist"
            dist.mkdir()
            built = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_wheel.py"), str(dist)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            original = next(dist.glob("*.whl"))
            wheel_bytes = original.read_bytes()
            for mode in ("archive", "unpacked"):
                for fault in ("discovery", "physical", "between", "issuance"):
                    with self.subTest(mode=mode, fault=fault):
                        case = root / (mode + "-" + fault)
                        case.mkdir()
                        installation = case / original.name
                        installation.write_bytes(wheel_bytes)
                        if mode == "unpacked":
                            with zipfile.ZipFile(installation) as archive:
                                installation = case / "installed"
                                archive.extractall(installation)
                        checked = subprocess.run([sys.executable, "-B", "-I", "-c", probe,
                            str(installation), fault], cwd=case, capture_output=True, text=True, timeout=120)
                        self.assertEqual(checked.returncode, 0, checked.stderr)
                        self.assertEqual(json.loads(checked.stdout), {"rejected":fault})

    def test_fresh_archive_and_unpacked_factories_recheck_without_legacy_materialization(self):
        import subprocess
        import sys
        import tempfile
        import textwrap
        import zipfile

        probe = textwrap.dedent('''
            import json, os, pathlib, sys
            from unittest import mock
            sys.path.insert(0, sys.argv[1])
            import graph_engineering as installation
            from graph_engineering.application.release_operations import (
                ReleaseOperationsRegistryFactory, ReleaseOperationsError, _COLD_INSTALLATION_PLANS)
            from graph_engineering.storage.repository import _RecoveryReadBudget
            factory = ReleaseOperationsRegistryFactory.from_installation()
            plan = _COLD_INSTALLATION_PLANS[factory]
            assert type(plan).__name__ == "_WheelInstallationReadPlan", type(plan)
            category = installation._category_policy_installation_resources()
            assert set(installation._category_policy_locations(category[0], location_kind="resource")).issubset(plan.names)
            distribution = installation._matching_installed_distributions()[0]
            adapters = {str(item) for item in distribution.files
                if str(item).startswith("graph_engineering/adapters/") and str(item).endswith(".py")}
            assert adapters and adapters.issubset(plan.names)
            _contracts, _schemas, context = factory._cold_artifact_authority()
            owner = _RecoveryReadBudget((context,))
            read = os.read
            reads = []
            def observed(descriptor, count):
                assert owner.retained_bytes >= count
                assert context._temporary_units >= count
                body = read(descriptor, count)
                reads.append(len(body))
                return body
            try:
                with owner.bind(ports=(factory,)):
                    adopted = factory._adopt_cold_configuration(owner)
                    retained = (owner.retained_units, owner.retained_bytes)
                    with mock.patch.object(installation, "_release_operations_installation_resources",
                            side_effect=AssertionError("legacy installed currentness")), \\
                         mock.patch.object(installation, "_category_policy_installation_resources",
                            side_effect=AssertionError("legacy category currentness")), \\
                         mock.patch.object(installation, "_matching_installed_distributions",
                            side_effect=AssertionError("legacy discovery")), \\
                         mock.patch.object(pathlib.Path, "read_bytes",
                            side_effect=AssertionError("whole member materialization")), \\
                         mock.patch.object(os, "read", side_effect=observed):
                        factory.require_installed_authority()
                        first_read_count = len(reads)
                        factory.require_installed_authority()
                        assert len(reads) == 2 * first_read_count and first_read_count > 0
                        assert (owner.retained_units, owner.retained_bytes) == retained
                owner.release_projection(adopted)
                assert (owner.retained_units, owner.retained_bytes) == (0, 0)
            finally:
                owner.close()
            assert context._temporary_units == 0
            print(json.dumps({"plan":type(plan).__name__, "read_bytes":sum(reads)}))
        ''')
        with tempfile.TemporaryDirectory(prefix="gew-cold-wheel-native-") as directory:
            root = pathlib.Path(directory)
            dist = root / "dist"
            dist.mkdir()
            built = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/build_wheel.py"), str(dist)],
                cwd=ROOT, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(dist.glob("*.whl"))
            unpacked = root / "unpacked"
            with zipfile.ZipFile(wheel) as archive:
                archive.extractall(unpacked)
            for installation in (wheel, unpacked):
                with self.subTest(installation=installation.name):
                    checked = subprocess.run([sys.executable, "-B", "-I", "-c", probe, str(installation)],
                        cwd=root, capture_output=True, text=True, timeout=120)
                    self.assertEqual(checked.returncode, 0, checked.stderr)
                    result = json.loads(checked.stdout)
                    self.assertEqual(result["plan"], "_WheelInstallationReadPlan")
                    self.assertGreater(result["read_bytes"], 0)


class WP08ColdInstallationCurrentnessTests(unittest.TestCase):
    def test_source_plan_binds_each_current_category_input_to_the_attestation(self):
        import graph_engineering as module

        resources = module._release_operations_installation_resources()
        category = module._category_policy_installation_resources()
        plan = module._release_operations_read_plan(resources, category_resources=category)
        names = ("pyproject.toml", *module._category_policy_locations(category[0], location_kind="source"))
        files = {name: (size, digest) for name, size, digest in plan.files}
        for name, body in zip(names, category, strict=True):
            self.assertEqual(files[name], (len(body), hashlib.sha256(body).hexdigest()))
        for index in range(3):
            with self.subTest(input=index):
                changed = list(category); changed[index] += b"\n"
                with self.assertRaisesRegex(module.DistributionIdentityError, "cold category plan differs"):
                    module._release_operations_read_plan(resources, category_resources=tuple(changed))

    def test_factory_adoption_admits_field_table_before_allocation(self):
        from dataclasses import replace
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage import repository
        from graph_engineering.core.contracts.errors import ContractError

        factory = ReleaseOperationsRegistryFactory.from_installation()
        _contracts, _schemas, context = factory._cold_artifact_authority()
        original_profile = context.profile
        # Trusted type tuple8, field-map19, dynamic field tuples47,
        # two fixed field tuples11, roots9 including the category policy,
        # traversal setup scratch7.
        scratch_units = 8 + 19 + 47 + 11 + 9 + 7
        class Observed(Exception): pass
        for limit in (scratch_units, scratch_units - 1):
            context.profile = replace(original_profile, limits={**original_profile.limits,
                "temporary_units": limit + 3})
            context.acquire_temporary(3, source_id="prior", operation_path=())
            owner = repository._RecoveryReadBudget((context,))
            allocations = []
            def field_tuple(value):
                self.assertGreaterEqual(owner.retained_units, scratch_units)
                allocations.append(len(value))
                return tuple(value)
            def observe_roots(*args, **kwargs):
                self.assertEqual(owner.retained_units, scratch_units)
                raise Observed()
            try:
                with owner.bind(ports=(factory,)), mock.patch.object(module, "tuple",
                        side_effect=field_tuple, create=True), \
                        mock.patch.object(repository, "_recovery_adopt", side_effect=observe_roots):
                    with self.assertRaises(Observed if limit == scratch_units else ContractError):
                        factory._adopt_cold_configuration(owner)
                self.assertEqual(len(allocations), 7 if limit == scratch_units else 0)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 3)
            context.release_temporary(3)

    def test_factory_adoption_failure_does_not_pin_discarded_cache_through_traceback(self):
        import gc
        import weakref
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget

        for allowance in (1, 120):
            factory = ReleaseOperationsRegistryFactory.from_installation()
            _contracts, _schemas, context = factory._cold_artifact_authority()
            reference = weakref.ref(factory)
            context.profile = replace(context.profile, limits={**context.profile.limits,
                "temporary_units": allowance + 3})
            context.acquire_temporary(3, source_id="prior", operation_path=())
            owner = _RecoveryReadBudget((context,))
            retained_error = None
            try:
                with owner.bind(ports=(factory,)):
                    try:
                        factory._adopt_cold_configuration(owner)
                    except ContractError as error:
                        retained_error = error
                    self.assertIsNotNone(retained_error)
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 3)
            factory = None
            gc.collect()
            self.assertIsNone(reference(), "retained exception pinned the discarded installed factory")
            self.assertIsNotNone(retained_error.__traceback__)

    def test_factory_adopts_complete_live_configuration_without_serializing(self):
        from dataclasses import fields, is_dataclass
        from collections.abc import Mapping
        from graph_engineering.application import release_operations as module
        from graph_engineering.storage.repository import _RecoveryReadBudget

        factory = ReleaseOperationsRegistryFactory.from_installation()
        contracts, schemas, context = factory._cold_artifact_authority()
        expected, seen = 0, set()
        def measure(value):
            nonlocal expected
            if id(value) in seen: return
            seen.add(id(value))
            if type(value) is bytes: expected += len(value)
            elif type(value) is str: expected += len(value.encode())
            elif isinstance(value, Mapping):
                for key, item in value.items(): measure(key); measure(item)
            elif type(value) in (tuple, list):
                for item in value: measure(item)
            elif is_dataclass(value):
                for field in fields(value): measure(getattr(value, field.name))
        measure((factory._bootstrap, factory._schemas, factory._registry, contracts, schemas,
                 context.profile, context.schedule, module._COLD_ARTIFACT_INPUTS[factory],
                 vars(module._COLD_INSTALLATION_PLANS[factory])))
        owner = _RecoveryReadBudget((context,))
        try:
            with owner.bind(ports=(factory,)), mock.patch.object(module, "thaw",
                    side_effect=AssertionError("adoption copied an immutable cache")):
                adopted = factory._adopt_cold_configuration(owner)
                self.assertGreaterEqual(owner.retained_bytes, expected)
                retained = (owner.retained_units, owner.retained_bytes)
                factory.require_installed_authority()
                self.assertEqual((owner.retained_units, owner.retained_bytes), retained)
            with owner.bind(ports=(factory,)):
                factory.require_installed_authority()
                self.assertEqual((owner.retained_units, owner.retained_bytes), retained)
            owner.release_projection(adopted)
        finally:
            owner.close()
        self.assertEqual((context._temporary_units, context._recovery_result_bytes), (0, 0))

    def test_currentness_rejects_a_fifo_lock_without_blocking_or_leaking(self):
        import graph_engineering
        from graph_engineering.application.release_operations import _COLD_INSTALLATION_PLANS
        from graph_engineering.storage.repository import _RecoveryReadBudget

        factory = ReleaseOperationsRegistryFactory.from_installation()
        _contracts, _schemas, context = factory._cold_artifact_authority()
        plan = _COLD_INSTALLATION_PLANS[factory]
        lock = plan.control / graph_engineering._CONTROL_LOCK
        saved = lock.with_name(lock.name + ".test-original")
        open_descriptor, opened = os.open, []
        def observed_open(path, flags, *args, **kwargs):
            if path == lock:
                self.assertTrue(flags & os.O_NONBLOCK, "untrusted lock open could block on FIFO")
            descriptor = open_descriptor(path, flags, *args, **kwargs)
            opened.append(descriptor)
            return descriptor
        owner = _RecoveryReadBudget((context,))
        lock.rename(saved)
        try:
            os.mkfifo(lock, 0o600)
            with owner.bind(ports=(factory,)), mock.patch.object(os, "open", side_effect=observed_open):
                with self.assertRaises(ReleaseOperationsError) as rejected:
                    factory.require_installed_authority()
                self.assertIn("installation lock changed", str(rejected.exception.__cause__))
            self.assertTrue(opened)
            for descriptor in opened:
                with self.assertRaises(OSError): os.fstat(descriptor)
            self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
        finally:
            lock.unlink(); saved.rename(lock); owner.close()
        self.assertEqual(context._temporary_units, 0)

    def test_currentness_hashes_the_closed_source_set_and_detects_control_or_source_drift(self):
        import graph_engineering
        from graph_engineering.application.release_operations import _COLD_INSTALLATION_PLANS
        from graph_engineering.storage.repository import _RecoveryReadBudget

        factory = ReleaseOperationsRegistryFactory.from_installation()
        _contracts, _schemas, context = factory._cold_artifact_authority()
        plan = _COLD_INSTALLATION_PLANS[factory]
        owner = _RecoveryReadBudget((context,))
        read = os.read
        paths = {plan.source / name: size for name, size, _digest in plan.files}
        paths.update({plan.control / graph_engineering._ATTESTATION_KEY: plan.key[0],
                      plan.control / graph_engineering._ATTESTATION_FILE: plan.attestation[0]})
        identities = {(path.stat().st_dev, path.stat().st_ino): path for path in paths}
        observed = {}
        def observed_read(fd, count):
            metadata = os.fstat(fd)
            path = identities.get((metadata.st_dev, metadata.st_ino))
            if path is not None:
                self.assertGreaterEqual(owner.retained_bytes, count)
                self.assertGreaterEqual(context._temporary_units, count)
            body = read(fd, count)
            if path is not None: observed[path] = observed.get(path, 0) + len(body)
            return body
        try:
            with owner.bind(ports=(factory,)), mock.patch.object(os, "read", side_effect=observed_read):
                factory.require_installed_authority()
            self.assertEqual(observed, {path: size * (3 if path.parent == plan.control else 2)
                                       for path, size in paths.items()})
            for path in (plan.source / "pyproject.toml", plan.control / graph_engineering._ATTESTATION_FILE,
                         plan.control / graph_engineering._ATTESTATION_KEY):
                for fault in ("content", "short", "growth"):
                    with self.subTest(member=path.name, fault=fault):
                        identity = (path.stat().st_dev, path.stat().st_ino)
                        touched = []
                        def changed_read(fd, count):
                            metadata = os.fstat(fd)
                            body = read(fd, count)
                            if (metadata.st_dev, metadata.st_ino) != identity: return body
                            touched.append(count)
                            if fault == "content" and body: return bytes([body[0] ^ 1]) + body[1:]
                            if fault == "short" and body: return body[:-1]
                            if fault == "growth" and not body: return b"x"
                            return body
                        with owner.bind(ports=(factory,)), mock.patch.object(os, "read", side_effect=changed_read):
                            with self.assertRaises(ReleaseOperationsError) as rejected:
                                factory.require_installed_authority()
                            expected = {"content": "member changed", "short": "short read", "growth": "member grew"}[fault]
                            self.assertIn(expected, str(rejected.exception.__cause__))
                        self.assertTrue(touched)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
        finally:
            owner.close()
        self.assertEqual(context._temporary_units, 0)

    def test_currentness_rejects_omitted_factory_and_foreign_installed_context(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        factory = ReleaseOperationsRegistryFactory.from_installation()
        _contracts, _schemas, context = factory._cold_artifact_authority()
        for contexts, ports in (((context,), ()), ((security_context(),), (factory,))):
            owner = _RecoveryReadBudget(contexts)
            try:
                with owner.bind(ports=ports), mock.patch.object(factory, "_currentness_check",
                        side_effect=AssertionError("legacy currentness fallback")):
                    for read in (factory.require_installed_authority, factory.registry):
                        with self.assertRaisesRegex(ReleaseOperationsError, "not bound|read plan is unavailable"):
                            read()
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()

    def test_installed_currentness_streams_under_the_exact_owner(self):
        import graph_engineering
        from graph_engineering.storage.repository import _RecoveryReadBudget

        factory = ReleaseOperationsRegistryFactory.from_installation()
        _contracts, _schemas, context = factory._cold_artifact_authority()
        owner = _RecoveryReadBudget((context,))
        try:
            with owner.bind(ports=(factory,)), mock.patch.object(graph_engineering,
                    "_attested_source_member",
                    side_effect=AssertionError("cold currentness materialized the whole installation")):
                factory.require_installed_authority()
                self.assertIs(factory.registry(), factory._registry)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            self.assertGreater(owner.peak_bytes, 0)
            self.assertLess(owner.peak_bytes, owner.byte_limit)
        finally:
            owner.close()
        self.assertEqual(context._temporary_units, 0)


class WP08ColdArtifactSourceTests(unittest.TestCase):
    def test_full_record_requires_raw_manifest_body_and_independent_acceptance(self):
        from graph_engineering.application import profile_execution as module
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.contracts.digest import semantic_digest
        from graph_engineering.core.artifacts.records import ArtifactValidator
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp04a_artifacts import loaded_golden, manifest_document

        factory = ReleaseOperationsRegistryFactory.from_installation()
        contracts, schemas, context = factory._cold_artifact_authority()
        for artifact_type in ("implementation", "prd"):
            original, _manifest, _contracts, _schemas, _context, _validation = loaded_golden(artifact_type)
            physical, manifest = manifest_document(original["artifact_id"], original["semantic_fields"])
            expected_target = copy.deepcopy(original["target_refs"][0])
            for change in (None, "raw-semantic-label", "body", "missing-body", "duplicate-manifest", "opaque-invalid-manifest",
                           "manifest-entry", "manifest-selector", "validation", "review", "actors",
                           "open-finding", "target", "baseline", "contract", "status", "human-owner",
                           "semantic-missing", "semantic-extra", "semantic-renamed", "semantic-whitespace"):
                if change == "human-owner" and artifact_type != "prd":
                    continue
                with self.subTest(artifact_type=artifact_type, change=change):
                    record = copy.deepcopy(original)
                    value = copy.deepcopy(manifest)
                    bodies = {module.category_object_digest(physical): physical}
                    if change == "raw-semantic-label": record["body_digest"] = "sha256-jcs-v1:" + hashlib.sha256(physical).hexdigest()
                    elif change == "body": bodies = {module.category_object_digest(physical + b" "): physical + b" "}
                    elif change == "missing-body": bodies = {}
                    elif change == "manifest-entry": record["logical_body_ref"]["entry_digest"] = "sha256-jcs-v1:" + "0" * 64
                    elif change == "manifest-selector": value["entries"][0]["selector"]["end"] += 1
                    elif change == "validation": record["validation_records"].pop()
                    elif change == "review": record["review_records"][0]["body_digest"] = "sha256-jcs-v1:" + "0" * 64
                    elif change == "actors": record["reviewer_id"] = record["author_id"]
                    elif change == "open-finding": record["findings"] = [{"finding_id":"open", "severity":"minor", "status":"open"}]
                    elif change == "target": record["target_refs"][0]["target_digest"] = "sha256-jcs-v1:" + "0" * 64
                    elif change == "baseline": record["baseline_digests"]["intent"] = "sha256-jcs-v1:" + "0" * 64
                    elif change == "contract": record["contract_digest"] = "sha256-jcs-v1:" + "0" * 64
                    elif change == "status": record["status"] = "candidate"
                    elif change == "human-owner": record["approval_records"][0]["owner_id"] = "foreign-owner"
                    elif type(change) is str and change.startswith("semantic-"):
                        from graph_engineering.core.artifacts.manifest import LogicalBodyManifest
                        fields = record["semantic_fields"]
                        if change == "semantic-whitespace":
                            first = next(iter(fields))
                            fields[first] = " " + fields[first] + "\n"
                        elif change == "semantic-extra":
                            fields["uninstalled-field"] = "coherent but unauthorized field"
                        else:
                            removed = fields.pop(next(iter(fields)))
                            if change == "semantic-renamed": fields["renamed-field"] = removed
                        changed_body, value = manifest_document(record["artifact_id"], fields)
                        bodies = {module.category_object_digest(changed_body): changed_body}
                        parsed_manifest = LogicalBodyManifest.from_dict(value, changed_body,
                            schema_registry=schemas, context=context)
                        record["logical_body_ref"].update(entry_digest=parsed_manifest.entry_digest(record["artifact_id"]),
                            extracted_body_digest=parsed_manifest.extracted_digest(record["artifact_id"]))
                        record["body_digest"] = parsed_manifest.semantic_body_digest(record["artifact_id"], fields, context)
                        for item in (*record["validation_records"], *record["review_records"], *record["approval_records"]):
                            item["body_digest"] = record["body_digest"]
                    # Coherent record replacement: the raw and semantic record
                    # digests are valid; the independent body/acceptance join
                    # must detect the substituted assertion.
                    record["artifact_digest"] = semantic_digest(
                        {k:v for k,v in record.items() if k != "artifact_digest"},
                        contract_type="urn:gew:contract:artifact-record",
                        projection_id="urn:gew:digest-projection:identity:1.0.0",
                        schema_id="urn:gew:schema:artifact-record:1.0.0")
                    if change == "semantic-whitespace":
                        ArtifactValidator.load(record, context=context, **{**_validation, "manifest": parsed_manifest})
                    record_body, manifest_body = canonical_bytes(record), canonical_bytes(value)
                    record_ref = module.category_object_digest(record_body)
                    manifest_ref = module.category_object_digest(manifest_body)
                    bodies.update({record_ref: record_body, manifest_ref: manifest_body})
                    documents = {record_ref: record, manifest_ref: value}
                    if change in ("duplicate-manifest", "opaque-invalid-manifest"):
                        from graph_engineering.core.artifacts.manifest import LogicalBodyManifest, LOGICAL_BODY_MANIFEST_SCHEMA
                        duplicate = copy.deepcopy(value)
                        duplicate["mode"] = "compact" if change == "duplicate-manifest" else "single-sample"
                        if change == "duplicate-manifest":
                            duplicate["manifest_digest"] = semantic_digest(
                                {key: value for key, value in duplicate.items() if key != "manifest_digest"},
                                contract_type="urn:gew:contract:logical-body-manifest",
                                projection_id="urn:gew:digest-projection:identity:1.0.0", schema_id=LOGICAL_BODY_MANIFEST_SCHEMA)
                            LogicalBodyManifest.from_dict(duplicate, physical, schema_registry=schemas, context=context)
                        body = canonical_bytes(duplicate)
                        duplicate_ref = module.category_object_digest(body)
                        bodies[duplicate_ref], documents[duplicate_ref] = body, duplicate
                    owner = _RecoveryReadBudget((context,))
                    try:
                        with owner.bind(), mock.patch.object(ArtifactValidator, "load",
                                side_effect=AssertionError("recovery issued a new acceptance")):
                            arguments = dict(record_ref=record_ref, documents=documents, objects=bodies,
                                task_id=original["task_id"], owner_id="owner-wp04a",
                                baselines=original["baseline_digests"], target=expected_target,
                                contracts=contracts, schemas=schemas, context=context)
                            if change in (None, "semantic-whitespace", "opaque-invalid-manifest"):
                                result = module._validate_cold_artifact_record(**arguments)
                                self.assertEqual(result["record_ref"], record_ref)
                                expected_body = changed_body if change == "semantic-whitespace" else physical
                                self.assertEqual(result["physical_object_ref"], module.category_object_digest(expected_body))
                                self.assertEqual(result["body_digest"], record["body_digest"])
                                owner.release_projection(result)
                            else:
                                with self.assertRaises(CategoryExecutionError):
                                    module._validate_cold_artifact_record(**arguments)
                    finally:
                        owner.close()
                    self.assertEqual((owner.retained_bytes, owner.retained_units, context._temporary_units), (0, 0, 0))


class WP08ColdReadBudgetTests(unittest.TestCase):
    def test_digest_after_parser_exit_uses_shared_exact_allowance_before_serialization(self):
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        document = {"contract": "bounded-digest", "value": {"payload": "non-ascii 字" * 40}}
        encoded = module.canonical_json(document)
        for dimension in ("units", "bytes"):
            for short in (False, True):
                left, right = security_context(), security_context()
                left.acquire_temporary(3, source_id="prior", operation_path=())
                right.acquire_temporary(5, source_id="prior", operation_path=())
                owner = module._RecoveryReadBudget((left, right))
                observed = []
                try:
                    with owner.bind():
                        with module._recovery_json(encoded, left, owner, source_id="input") as value:
                            module._recovery_adopt(value, left, owner, record_fields={}, source_id="parsed-result")
                        size = canonical_byte_length(value)
                        need = (6 if dimension == "units" else 4) * size
                        available = (owner.unit_limit - owner.retained_units if dimension == "units"
                                     else owner.byte_limit - owner.retained_bytes)
                        with owner.reserve(left, units=available - need + int(short) if dimension == "units" else 0,
                                byte_count=available - need + int(short) if dimension == "bytes" else 0,
                                source_id="other-reader"):
                            before = owner.retained_units, owner.retained_bytes
                            original = module.semantic_record_digest
                            def actual_serialization(selected):
                                self.assertIs(selected, value)
                                self.assertIs(owner._projections[id(value)][0], value)
                                observed.append((owner.retained_units - before[0], owner.retained_bytes - before[1]))
                                return original(selected)
                            with mock.patch.object(module, "semantic_record_digest", side_effect=actual_serialization):
                                if short:
                                    with self.assertRaises(ContractError):
                                        module._recovery_record_digest(value, right, owner, source_id="digest")
                                else:
                                    self.assertEqual(module._recovery_record_digest(value, right, owner, source_id="digest"),
                                                     original(document))
                            self.assertEqual(observed, [] if short else [(6 * size, 4 * size)])
                            self.assertEqual((owner.retained_units, owner.retained_bytes), before)
                        owner.release_projection(value)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                finally:
                    owner.close()
                    self.assertEqual((left._temporary_units, right._temporary_units), (3, 5))
                    left.release_temporary(3); right.release_temporary(5)

    def test_owned_replay_validates_parsed_events_without_retaining_a_second_copy(self):
        from graph_engineering.core.contracts.canonical import canonical_byte_length
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        event = module.make_event(task_id="task-owned", sequence=1, event_id="event-owned",
            event_type="task.created", occurred_at="2026-09-21T00:00:00Z",
            actor={"kind": "runtime", "id": "lineage-owned"}, expected_task_revision=0,
            baseline_digests=[], payload={"task_id": "task-owned"}, previous_event_digest=None)
        encoded = module.canonical_json(event)
        context, other = security_context(), security_context()
        owner = module._RecoveryReadBudget((context, other))
        original = module.TaskRepository._validate_event.__func__
        calls = []
        try:
            with owner.bind():
                with module._recovery_json(encoded, context, owner, source_id="event") as parsed:
                    module._recovery_adopt(parsed, context, owner, record_fields={}, source_id="parsed-event")
                before = owner.retained_units, owner.retained_bytes
                def validate(cls, value, **kwargs):
                    calls.append(value)
                    self.assertIs(value, parsed)
                    self.assertIs(owner._projections[id(value)][0], value)
                    self.assertGreaterEqual(owner.retained_units - before[0], 6 * canonical_byte_length(value))
                    return original(cls, value, **kwargs)
                row = (1, encoded, event["event_id"], event["event_type"], None, event["event_digest"],
                       "transaction-owned", "task-owned", 1, event["event_digest"], "sha256-jcs-v1:" + "a" * 64)
                repository = object.__new__(module.TaskRepository)
                with mock.patch.object(module.TaskRepository, "_validate_event", classmethod(validate)), \
                        mock.patch.object(module.copy, "deepcopy", side_effect=AssertionError("extra retained event copy")):
                    result = repository._validate_replay_rows("task-owned", (1, 1, event["event_digest"], "ok"),
                        (row,), parser=lambda _body: parsed, _budget=owner, _context=other)
                self.assertEqual(calls, [parsed])
                self.assertIs(result[0], parsed)
                self.assertEqual((owner.retained_units, owner.retained_bytes), before)
                result = calls = None
                owner.release_projection(parsed)
        finally:
            owner.close()
        self.assertEqual((context._temporary_units, other._temporary_units), (0, 0))


    def test_freeze_construction_covers_empty_and_nested_mapping_headers(self):
        from graph_engineering.core.contracts.immutable import FrozenMap
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        original = FrozenMap.from_dict.__func__
        for value in ({}, {"nested": [{}, {}]}):
            context = security_context()
            owner = module._RecoveryReadBudget((context,))
            observed = []
            def construct(cls, values):
                result = original(cls, values)
                # The input dict is live alongside a FrozenMap field/header,
                # its mapping proxy and its separate backing dictionary.
                minimum = 5 + 4 * len(values)
                observed.append(minimum)
                self.assertGreaterEqual(owner.retained_units, minimum)
                return result
            try:
                with owner.bind(), mock.patch.object(FrozenMap, "from_dict", classmethod(construct)):
                    result = module._recovery_freeze(value, context, owner, source_id="small-freeze")
                    owner.release_projection(result)
                self.assertTrue(observed)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()

    def test_sql_cursor_close_failure_drops_captured_rows_from_retained_exception(self):
        import sqlite3
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        connection = sqlite3.connect(":memory:")
        connection.execute("CREATE TABLE facts(body TEXT)")
        connection.execute("INSERT INTO facts VALUES (?)", ("sensitive captured body " * 100,))
        class ClosingCursor:
            def __init__(self, cursor): self.cursor = cursor
            def fetchone(self): return self.cursor.fetchone()
            def close(self):
                self.cursor.close()
                raise OSError("real cursor closed then failed")
        class ReadConnection:
            def execute(self, *args): return ClosingCursor(connection.execute(*args))
        context = security_context()
        owner = module._RecoveryReadBudget((context,))
        retained_error = None
        try:
            with owner.bind():
                try:
                    with module._recovery_rows(ReadConnection(),
                            (("fact", ("body",), "facts"),), {}, context, owner, source_id="close-failure") as rows:
                        self.assertEqual(len(rows["fact"]), 1)
                except OSError as error:
                    retained_error = error
                self.assertIsNotNone(retained_error)
                trace = retained_error.__traceback__
                while trace is not None:
                    if trace.tb_frame.f_code.co_name == "_recovery_rows":
                        self.assertEqual(trace.tb_frame.f_locals["captured"], {})
                        self.assertIsNone(trace.tb_frame.f_locals["row"])
                        self.assertIsNone(trace.tb_frame.f_locals["fields"])
                    trace = trace.tb_next
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
        finally:
            owner.close()
            connection.close()

    def test_frozen_result_keeps_only_its_graph_and_preserves_string_aliases(self):
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        payload = "shared immutable result" * 100
        retained = []
        for distinct in (False, True):
            context = security_context()
            owner = module._RecoveryReadBudget((context,))
            try:
                with owner.bind():
                    result = module._recovery_freeze(
                        {"left":payload, "right":payload.encode().decode() if distinct else payload},
                        context, owner, source_id="closed-result")
                    retained.append((owner.retained_units, owner.retained_bytes))
                    self.assertEqual(result["left"], result["right"])
                    self.assertEqual(result["left"] is result["right"], not distinct)
                    self.assertGreater(owner.peak_units, owner.retained_units)
                    with self.assertRaises(TypeError):
                        result["left"] = "modified"
                    owner.release_projection(result)
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
        self.assertEqual(retained[1][0] - retained[0][0], len(payload) + 1)
        self.assertEqual(retained[1][1] - retained[0][1], len(payload))

    def test_configuration_structure_has_independent_exact_unit_bounds(self):
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.core.contracts.immutable import FrozenMap
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        token = "independently-counted-configuration"
        roots = ([token, token], FrozenMap.from_dict({"k": token}))
        # Six distinct objects: root/list/token/FrozenMap/proxy/key. Repeated
        # references still use slots. Retained structure is15 units beyond
        # token bytes; the admitted DFS/seen scratch peaks at another36.
        exact = len(token) + 51
        for allowance in (exact, exact - 1):
            left, right = security_context(), security_context()
            for context, prior in ((left, 3), (right, 5)):
                context.profile = replace(context.profile, limits={**context.profile.limits,
                    "temporary_units": allowance + prior})
                context.acquire_temporary(prior, source_id="existing", operation_path=())
            owner = module._RecoveryReadBudget((left, right))
            try:
                with owner.bind():
                    if allowance == exact:
                        module._recovery_adopt(roots, left, owner,
                            record_fields={}, source_id="structure")
                        self.assertEqual(owner.retained_units, len(token) + 15)
                        self.assertEqual(owner.retained_bytes, len(token) + 1)
                        owner.release_projection(roots)
                    else:
                        with self.assertRaises(ContractError):
                            module._recovery_adopt(roots, left, owner,
                                record_fields={}, source_id="structure-minus-one")
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
            self.assertEqual((left._temporary_units, right._temporary_units), (3, 5))

    def test_retained_failure_tracebacks_drop_unadmitted_payloads(self):
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        marker = "retained-error-payload-" * 400
        encoded = '{"value":"' + marker + '"}'
        class Record:
            def __init__(self): self.data = marker
        for failure in ("adopt-admission", "adopt-units", "adopt-child", "json-document", "json-admission", "json-units"):
            with self.subTest(failure=failure):
                context = security_context()
                narrowed = {"result_bytes": 1} if failure.endswith("admission") else {}
                if failure.endswith("units"): narrowed = {"temporary_units": 4}
                if failure == "json-document": narrowed = {"raw_document_bytes": 1}
                context.profile = replace(context.profile, limits={**context.profile.limits, **narrowed})
                context.acquire_temporary(3, source_id="pre-existing", operation_path=())
                context._recovery_result_bytes = 1
                owner = module._RecoveryReadBudget((context,))
                root = Record()
                retained_error = None
                try:
                    with owner.bind():
                        try:
                            if failure.startswith("adopt"):
                                module._recovery_adopt(root, context, owner,
                                    record_fields={Record: ("data", "missing")}, source_id=failure)
                            else:
                                with module._recovery_json(encoded, context, owner, source_id=failure):
                                    self.fail("rejected input was yielded")
                        except (AttributeError, ContractError) as error:
                            retained_error = error
                        self.assertIsNotNone(retained_error)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    pending, visited = [retained_error], set()
                    while pending:
                        error = pending.pop()
                        if error is None or id(error) in visited: continue
                        visited.add(id(error))
                        trace = error.__traceback__
                        while trace is not None:
                            if trace.tb_frame.f_code.co_filename == module.__file__:
                                for name, value in trace.tb_frame.f_locals.items():
                                    self.assertIsNot(value, root, "released root retained by " + name)
                                    if type(value) in (str, bytes):
                                        self.assertNotIn(marker, value.decode() if type(value) is bytes else value)
                            trace = trace.tb_next
                        pending.extend((error.__cause__, error.__context__))
                finally:
                    owner.close()
                self.assertEqual((context._temporary_units, context._recovery_result_bytes), (3, 1))

    def test_configuration_adoption_counts_aliases_and_distinct_equal_payloads(self):
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        payload = "configuration-" * 200
        separate = payload.encode().decode()
        self.assertIsNot(payload, separate)
        charges = []
        for roots in ((payload, payload), (payload, separate)):
            context = security_context()
            owner = module._RecoveryReadBudget((context,))
            try:
                with owner.bind(), mock.patch.object(module, "canonical_json",
                        side_effect=AssertionError("configuration adoption serialized its input")):
                    self.assertIs(module._recovery_adopt(roots, context, owner,
                        record_fields={}, source_id="installed-cache"), roots)
                    charges.append(owner.retained_bytes)
                # Configuration remains live between checks and uses the same
                # reservation on the next bind.
                with owner.bind():
                    self.assertEqual(owner.retained_bytes, charges[-1])
                owner.release_projection(roots)
                self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)
        self.assertEqual(charges[1] - charges[0], len(payload.encode()))

    def test_configuration_adoption_handles_cycles_and_only_declared_exact_types(self):
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        class Record:
            def __init__(self): self.data = {"name": "installed"}; self.back = self
        class Foreign(Record):
            def __getattribute__(self, name):
                raise AssertionError("foreign configuration code ran")
        fields = {Record: ("data", "back")}
        context = security_context()
        owner = module._RecoveryReadBudget((context,))
        with owner.bind():
            record = Record()
            module._recovery_adopt(record, context, owner, record_fields=fields, source_id="cycle")
            self.assertGreater(owner.retained_bytes, 0)
            owner.release_projection(record)
            with self.assertRaisesRegex(ValueError, "unsupported recovery configuration"):
                module._recovery_adopt(Foreign(), context, owner,
                    record_fields=fields, source_id="foreign")
            self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
        owner.close()
        self.assertEqual(context._temporary_units, 0)

    def test_configuration_adoption_uses_exact_shared_remaining_allowance(self):
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        roots = {"configuration": ("retained-" * 300, "second-" * 250)}
        context = security_context()
        probe = module._RecoveryReadBudget((context,))
        with probe.bind():
            module._recovery_adopt(roots, context, probe, record_fields={}, source_id="measure")
        required = probe.peak_bytes
        probe.close()
        for allowance in (required, required - 1):
            left, right = security_context(), security_context()
            right.profile = replace(right.profile, limits={**right.profile.limits,
                "result_bytes": allowance + 7})
            right._recovery_result_bytes = 7
            owner = module._RecoveryReadBudget((left, right))
            try:
                with owner.bind():
                    if allowance == required:
                        module._recovery_adopt(roots, left, owner,
                            record_fields={}, source_id="exact")
                        owner.release_projection(roots)
                    else:
                        with self.assertRaises(ContractError):
                            module._recovery_adopt(roots, left, owner,
                                record_fields={}, source_id="overflow")
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
            finally:
                owner.close()
            self.assertEqual((left._temporary_units, right._temporary_units), (0, 0))
            self.assertEqual(right._recovery_result_bytes, 7)

    def test_sql_string_parser_accounts_for_every_live_long_token_copy(self):
        import sys
        from graph_engineering.core.contracts import strict_json
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        encoded = '{"message":"' + "x" * 8192 + '"}'
        context = security_context()
        owner = module._RecoveryReadBudget((context,))
        tokens, emit = strict_json._tokens, context.emit
        active, peaks = [], []
        def observed_tokens(text):
            generator = tokens(text); active.append(generator)
            try: yield from generator
            finally: active.remove(generator)
        def observed_emit(event, count, **kwargs):
            if event == "parse.string_scalar":
                values, seen = [encoded], set()
                frame = sys._getframe(1)
                while frame is not None:
                    if frame.f_code.co_filename in (strict_json.__file__, module.__file__):
                        values.extend(frame.f_locals.get(key) for key in
                            ("body", "raw_body", "text", "token_text", "decoded"))
                    frame = frame.f_back
                for generator in active:
                    if generator.gi_frame is not None:
                        values.extend(generator.gi_frame.f_locals.get(key) for key in ("text", "raw", "decoded"))
                payload = 0
                for value in values:
                    if id(value) in seen: continue
                    seen.add(id(value))
                    if type(value) is bytes: payload += len(value)
                    elif type(value) is str: payload += len(value.encode("utf-8"))
                peaks.append(payload)
                self.assertGreaterEqual(owner.retained_bytes, payload,
                    "SQL input plus raw/text/token copies exceed the retained charge")
            return emit(event, count, **kwargs)
        try:
            with owner.bind(), owner.reserve(context, units=len(encoded), byte_count=len(encoded),
                    source_id="retained-sql-text"), \
                    mock.patch.object(strict_json, "_tokens", side_effect=observed_tokens), \
                    mock.patch.object(context, "emit", side_effect=observed_emit):
                with module._recovery_json(encoded, context, owner, source_id="long-sql-text") as value:
                    self.assertEqual(value, {"message": "x" * 8192})
            self.assertGreater(max(peaks), 5 * len(encoded))
        finally:
            owner.close()
        self.assertEqual(context._temporary_units, 0)

    def test_sql_row_overflow_is_rejected_before_any_data_row_is_returned(self):
        import sqlite3
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        connection = sqlite3.connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("CREATE TABLE rows (value TEXT)")
        connection.executemany("INSERT INTO rows VALUES (?)", [("one",), ("two",)])
        for limit in (2, 1):
            context = security_context()
            context.profile = replace(context.profile, limits={**context.profile.limits, "array_items": limit})
            owner = module._RecoveryReadBudget((context,))
            returned = []
            class Cursor:
                def __init__(self, cursor): self.cursor = cursor
                def fetchone(self):
                    value = self.cursor.fetchone()
                    returned.append(value)
                    return value
                def close(self): self.cursor.close()
            class Connection:
                def execute(self, query, params): return Cursor(connection.execute(query, params))
            try:
                with owner.bind(), mock.patch("graph_engineering.core.contracts.strict_json.parse_json",
                        side_effect=AssertionError("row bound reached a JSON parser")):
                    if limit == 2:
                        with module._recovery_rows(Connection(), [("rows", ("value",), "rows")], {},
                                context, owner, source_id="row-count") as rows:
                            self.assertEqual(rows["rows"], [("one",), ("two",)])
                    else:
                        with self.assertRaises(ContractError):
                            with module._recovery_rows(Connection(), [("rows", ("value",), "rows")], {},
                                    context, owner, source_id="row-count"):
                                self.fail("SQL row-count overflow was accepted")
                        self.assertEqual(len(returned), 1)
                        self.assertEqual(returned[0][:2], ("bounds", 2))
            finally:
                owner.close()
            self.assertEqual(context._temporary_units, 0)

    def test_sql_bounds_header_is_admitted_before_query_execution(self):
        from dataclasses import replace
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        context = security_context()
        context.profile = replace(context.profile, limits={**context.profile.limits, "result_bytes": 1})
        owner = module._RecoveryReadBudget((context,))
        connection = mock.Mock()
        connection.execute.side_effect = AssertionError("unadmitted SQL metadata allocation")
        with owner.bind(), self.assertRaises(RuntimeError):
            with module._recovery_rows(connection, [("x", ("digest",), "objects")], {},
                    context, owner, source_id="metadata"):
                self.fail("query exceeded remaining metadata allowance")
        connection.execute.assert_not_called()
        owner.close()

    def test_comparison_does_not_serialize_and_keeps_json_types_distinct(self):
        from graph_engineering.storage import repository as module
        from tests.support.wp05a_security import security_context

        context = security_context()
        owner = module._RecoveryReadBudget((context,))
        with owner.bind():
            with owner.reserve(context, units=0, byte_count=owner.byte_limit, source_id="retained"):
                with mock.patch.object(module, "canonical_json", side_effect=AssertionError("copy during equality")):
                    self.assertTrue(module._recovery_equal({"x": [1, True]}, {"x": (1, True)}, context, owner))
                    self.assertFalse(module._recovery_equal({"x": [1]}, {"x": [True]}, context, owner))
                self.assertEqual(owner.retained_bytes, owner.byte_limit)
        owner.close()
        self.assertEqual(context._temporary_units, 0)

    def test_sql_string_parse_admits_overlapping_buffers_before_encoding(self):
        from dataclasses import replace
        from graph_engineering.storage import repository as module
        from graph_engineering.core.contracts.errors import ContractError
        from tests.support.wp05a_security import security_context

        encoded = '{"message":"hello"}'
        expected = 6 * len(encoded)
        for ceiling in (expected, expected - 1):
            context = security_context()
            context.profile = replace(context.profile, limits={**context.profile.limits, "result_bytes": ceiling})
            owner = module._RecoveryReadBudget((context,))
            canonical = module.canonical_json
            calls = []
            def serialize(value):
                calls.append(value)
                # The SQL string, encoded input, parsed values and canonical
                # text/UTF-8 comparison buffers have overlapping lifetimes.
                self.assertGreaterEqual(owner.retained_bytes, expected)
                return canonical(value)
            with owner.bind(), mock.patch.object(module, "canonical_json", side_effect=serialize):
                if ceiling == expected:
                    with module._recovery_json(encoded, context, owner, source_id="sql") as value:
                        self.assertEqual(value, {"message": "hello"})
                else:
                    with self.assertRaises(ContractError):
                        with module._recovery_json(encoded, context, owner, source_id="sql"):
                            self.fail("overflow allocation")
                    self.assertEqual(calls, [])
            owner.close()
            self.assertEqual((owner.retained_units, owner.retained_bytes, context._temporary_units), (0, 0, 0))

    def test_cleanup_survives_revoked_authority_and_profile_drift_without_io(self):
        from dataclasses import replace
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        context = security_context()
        scope = mock.Mock()
        scope.require_current.side_effect = AssertionError("ledger performed authority I/O")
        port = mock.Mock(spec=[])
        context.acquire_temporary(2, source_id="prior", operation_path=())
        owner = _RecoveryReadBudget((context,), command_scope=scope)
        projection, remaining = object(), object()
        with owner.bind(ports=(port,)):
            with owner.reserve(context, units=3, byte_count=5, source_id="retained") as reservation:
                reservation.transfer(projection)
            with owner.reserve(context, units=7, byte_count=9, source_id="remaining") as reservation:
                reservation.transfer(remaining)
        context.profile = replace(context.profile)
        owner.release_projection(projection)
        owner.close()
        scope.require_current.assert_not_called()
        self.assertEqual(context._temporary_units, 2)
        self.assertFalse(hasattr(context, "_recovery_read_owner"))
        self.assertFalse(hasattr(port, "_recovery_read_budget"))
        context.release_temporary(2)

    def test_distinct_contexts_share_remaining_allowance_and_restore_reservations(self):
        from dataclasses import replace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        left, right = security_context(), security_context()
        left.profile = replace(left.profile, limits={**left.profile.limits,
            "temporary_units": 12, "result_bytes": 10})
        right.profile = replace(right.profile, limits={**right.profile.limits,
            "temporary_units": 10, "result_bytes": 12})
        left.acquire_temporary(2, source_id="prior", operation_path=())
        right.acquire_temporary(1, source_id="prior", operation_path=())
        budget = _RecoveryReadBudget((left, right))
        with budget.bind():
            with budget.reserve(left, units=4, byte_count=4, source_id="first"):
                with self.assertRaises(ContractError):
                    with budget.reserve(right, units=6, byte_count=6, source_id="second"):
                        self.fail("individually valid projections exceeded the shared allowance")
                with budget.reserve(right, units=5, byte_count=6, source_id="exact"):
                    self.assertEqual((budget.retained_units, budget.retained_bytes), (9, 10))
            self.assertEqual((budget.retained_units, budget.retained_bytes), (0, 0))
        self.assertEqual((left._temporary_units, right._temporary_units), (2, 1))
        self.assertEqual((budget.peak_units, budget.peak_bytes), (9, 10))
        budget.close()
        left.release_temporary(2)
        right.release_temporary(1)

    def test_transferred_projection_stays_charged_across_scope_and_reuse(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        context = security_context()
        budget = _RecoveryReadBudget((context,))
        projection = object()
        with budget.bind():
            with budget.reserve(context, units=7, byte_count=11, source_id="handle") as reservation:
                reservation.transfer(projection)
            self.assertEqual((budget.retained_units, budget.retained_bytes), (7, 11))
        self.assertEqual(context._temporary_units, 7)
        with budget.bind():
            with budget.reserve(context, units=3, byte_count=5, source_id="reuse"):
                self.assertEqual((budget.retained_units, budget.retained_bytes), (10, 16))
        budget.release_projection(projection)
        del projection
        budget.close()
        self.assertEqual(context._temporary_units, 0)

    def test_overlapping_or_foreign_context_bindings_fail_without_leaks(self):
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        context, foreign = security_context(), security_context()
        owner, competing = _RecoveryReadBudget((context,)), _RecoveryReadBudget((context,))
        with owner.bind():
            with self.assertRaises(ValueError):
                with owner.bind():
                    self.fail("reentrant owner")
            with self.assertRaises(ValueError):
                with competing.bind():
                    self.fail("overlapping owner")
            with self.assertRaises(ValueError):
                with owner.reserve(foreign, units=1, byte_count=1, source_id="foreign"):
                    self.fail("foreign context")
        self.assertIsNone(getattr(context, "_recovery_read_budget", None))
        self.assertEqual(context._temporary_units, 0)
        owner.close()
        competing.close()


class WP08ColdRetainedRootTests(unittest.TestCase):
    def test_final_enumeration_close_detects_added_and_replaced_members(self):
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        helper = WP08RetainedRootPrimitiveTests()
        for mutation in ("add", "replace"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="gew-cold-root-race-") as directory, \
                    _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                writer, _ = helper._create(namespace); path = writer.path; writer.close()
                context = security_context(); owner = _RecoveryReadBudget((context,), task_id="task-wp05")
                try:
                    with owner.bind(ports=(namespace,)):
                        lease = namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                        lease._admit_cold_members(helper.MEMBERS)
                        baseline = (owner.retained_units, owner.retained_bytes)
                        scanned, scan = [], os.scandir
                        class Changed:
                            def __init__(self, iterator): self.iterator = iterator
                            def __enter__(self): return self
                            def __iter__(self): return self
                            def __next__(self): return next(self.iterator)
                            def __exit__(self, *args):
                                self.iterator.close()
                                if len(scanned) == 2:
                                    if mutation == "add": (path / "residue").write_bytes(b"unowned")
                                    else:
                                        target = path / "active.bin"; body = target.read_bytes()
                                        target.unlink(); target.write_bytes(body); target.chmod(0o600)
                        def changed(descriptor):
                            scanned.append(descriptor); return Changed(scan(descriptor))
                        try:
                            with mock.patch.object(os, "scandir", new=changed):
                                with self.assertRaises(ReleaseSimulatorError): lease._capture_cold_members()
                            self.assertEqual(len(scanned), 2)
                            self.assertEqual((owner.retained_units, owner.retained_bytes), baseline)
                        finally: lease.close()
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    self.assertEqual(namespace.active_leases, 0)
                finally: owner.close()

    def test_real_descriptor_close_failure_cannot_leave_an_unreturned_projection(self):
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        helper = WP08RetainedRootPrimitiveTests()
        for phase in ("marker", "member"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(prefix="gew-cold-close-") as directory, \
                    _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                writer, _ = helper._create(namespace); path = writer.path; writer.close()
                context = security_context(); owner = _RecoveryReadBudget((context,), task_id="task-wp05")
                lease, held = None, []
                try:
                    with owner.bind(ports=(namespace,)):
                        if phase == "member":
                            lease = namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                            lease._admit_cold_members(helper.MEMBERS)
                        baseline = (owner.retained_units, owner.retained_bytes)
                        inode = (path / (".release-simulator-root" if phase == "marker" else "active.bin")).stat().st_ino
                        close, injected = os.close, []
                        def failed_close(fd):
                            selected = os.fstat(fd).st_ino == inode
                            close(fd)
                            if selected and not injected:
                                injected.append(fd); raise OSError("injected post-close failure")
                        with mock.patch.object(os, "close", new=failed_close):
                            try:
                                if phase == "marker": namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                                else: lease._capture_cold_members()
                            except OSError as error: held.append(error)
                            else: self.fail("close failure was swallowed")
                        self.assertEqual(len(injected), 1)
                        self.assertEqual((owner.retained_units, owner.retained_bytes), baseline)
                        if lease is not None: lease.close()
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    self.assertEqual(namespace.active_leases, 0)
                finally:
                    if lease is not None: lease.close()
                    owner.close()

    def test_marker_gate_precedes_member_admission_and_keeps_both_captures_charged(self):
        import tempfile
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        helper = WP08RetainedRootPrimitiveTests()
        with tempfile.TemporaryDirectory(prefix="gew-cold-marker-") as directory, \
                _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
            writer, binding = helper._create(namespace)
            before = {p.name: p.read_bytes() for p in writer.path.iterdir()}
            writer.close()
            context = security_context()
            owner = _RecoveryReadBudget((context,), task_id="task-wp05")
            try:
                with owner.bind(ports=(namespace,)):
                    with mock.patch.object(os, "scandir", side_effect=AssertionError("marker must not enumerate")):
                        lease = namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                    try:
                        self.assertEqual(lease._cold_binding, binding)
                        self.assertTrue(lease._marker_only)
                        with self.assertRaises(ReleaseSimulatorError):
                            lease.read("active.bin", max_bytes=1024)
                        with self.assertRaises(ReleaseSimulatorError):
                            lease._cold_read("active.bin")
                        lease._admit_cold_members(helper.MEMBERS)
                        self.assertFalse(lease._marker_only)
                        baseline = (owner.retained_units, owner.retained_bytes)
                        first = lease._capture_cold_members()
                        charged = (owner.retained_units, owner.retained_bytes)
                        second = lease._capture_cold_members()
                        self.assertEqual(first, second)
                        self.assertGreater(owner.retained_units, charged[0])
                        self.assertGreater(owner.retained_bytes, charged[1])
                        self.assertEqual({name: row[0] for name, row in first.items()}, before)
                        owner.release_projection(first); owner.release_projection(second)
                        first = second = None
                        self.assertEqual((owner.retained_units, owner.retained_bytes), baseline)
                        with self.assertRaises(ReleaseSimulatorError):
                            lease.initialize_file("active.bin", b"replacement")
                    finally:
                        path = lease.path
                        lease.close()
                    self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    self.assertEqual(namespace.active_leases, 0)
                    self.assertEqual({p.name: p.read_bytes() for p in path.iterdir()}, before)
            finally:
                owner.close()

    def test_marker_member_reads_admit_actual_bytes_and_reject_faults_without_leaks(self):
        import tempfile
        from dataclasses import replace
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        helper = WP08RetainedRootPrimitiveTests()
        for fault in ("oversize", "short", "growth", "replacement", "symlink", "fifo", "hardlink", "mode", "residue"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(prefix="gew-cold-marker-fault-") as directory, \
                    _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
                writer, _binding = helper._create(namespace)
                path, marker = writer.path, writer.path / writer.BINDING_NAME
                writer.close()
                if fault == "symlink":
                    original = marker.read_bytes(); marker.unlink()
                    (path / "elsewhere").write_bytes(original); marker.symlink_to("elsewhere")
                elif fault == "fifo":
                    marker.unlink(); os.mkfifo(marker, 0o400)
                elif fault == "hardlink": os.link(marker, path / "alias")
                elif fault == "mode": marker.chmod(0o600)
                elif fault == "residue": (path / "unexpected").write_bytes(b"residue")
                context = security_context()
                if fault == "oversize":
                    context.profile = replace(context.profile, limits={**context.profile.limits,
                        "raw_document_bytes": marker.stat().st_size - 1})
                owner = _RecoveryReadBudget((context,), task_id="task-wp05")
                read, touched, descriptors, held = os.read, [], [], []
                def observed(fd, count):
                    descriptors.append(fd)
                    self.assertGreaterEqual(owner.retained_bytes, count)
                    if not touched and count > 1:
                        touched.append(count)
                        if fault == "short": return read(fd, count - 1)
                        if fault == "growth":
                            marker.chmod(0o600)
                            with marker.open("ab") as stream: stream.write(b" ")
                            marker.chmod(0o400)
                        elif fault == "replacement":
                            value = marker.read_bytes(); marker.unlink(); marker.write_bytes(value); marker.chmod(0o400)
                    return read(fd, count)
                lease = None
                try:
                    with owner.bind(ports=(namespace,)), mock.patch.object(os, "read", side_effect=observed):
                        try:
                            lease = namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                            lease._admit_cold_members(helper.MEMBERS)
                        except (ReleaseSimulatorError, ContractError) as error:
                            held.append(error)
                        else: self.fail("unsafe marker/member admission succeeded")
                        finally:
                            if lease is not None: lease.close()
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    self.assertEqual(namespace.active_leases, 0)
                    for fd in descriptors:
                        with self.assertRaises(OSError): os.fstat(fd)
                    if fault in ("oversize", "symlink", "fifo", "hardlink", "mode"):
                        self.assertFalse(touched)
                    self.assertEqual(len(held), 1)
                finally: owner.close()

    def test_marker_admission_exact_common_allowance_and_retained_failure_cleanup(self):
        import tempfile
        import weakref
        import gc
        from dataclasses import replace
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, _RetainedRootLease
        from graph_engineering.core.contracts.errors import ContractError
        from graph_engineering.storage.repository import _RecoveryReadBudget
        from tests.support.wp05a_security import security_context

        helper = WP08RetainedRootPrimitiveTests()
        with tempfile.TemporaryDirectory(prefix="gew-cold-marker-limit-") as directory, \
                _RetainedNamespace(pathlib.Path(directory).resolve()) as namespace:
            writer, _ = helper._create(namespace); writer.close()
            context = security_context(); probe = _RecoveryReadBudget((context,), task_id="task-wp05")
            with probe.bind(ports=(namespace,)):
                lease = namespace._open_cold_marker("task-wp05", "target-project", context, probe)
                lease.close()
            required = probe.peak_bytes; probe.close()
            for allowance in (required, required - 1):
                context, other = security_context(), security_context()
                other.profile = replace(other.profile, limits={**other.profile.limits, "result_bytes": allowance + 5})
                other._recovery_result_bytes = 5
                owner = _RecoveryReadBudget((context, other), task_id="task-wp05")
                original, seen, errors = _RetainedRootLease.__init__, [], []
                def initialized(lease, *args, **kwargs):
                    original(lease, *args, **kwargs); seen.append(weakref.ref(lease))
                try:
                    with owner.bind(ports=(namespace,)), mock.patch.object(_RetainedRootLease, "__init__", initialized):
                        if allowance == required:
                            lease = namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                            lease.close(); lease = None
                        else:
                            try: namespace._open_cold_marker("task-wp05", "target-project", context, owner)
                            except ContractError as error: errors.append(error)
                            else: self.fail("aggregate marker overflow succeeded")
                        self.assertEqual((owner.retained_units, owner.retained_bytes), (0, 0))
                    self.assertEqual(namespace.active_leases, 0)
                finally: owner.close()
                gc.collect()
                self.assertTrue(all(reference() is None for reference in seen))
                self.assertEqual((context._temporary_units, other._recovery_result_bytes), (0, 5))


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

    def test_retained_namespace_root_and_member_symlinks_and_owners_reject_without_leaks(self) -> None:
        import tempfile
        from collections import Counter
        from types import SimpleNamespace
        from graph_engineering.adapters.local_release_simulator import _RetainedNamespace, _RetainedRootLease
        from tests.support.wp05a_security import security_context

        attacks = ("namespace-link-construction", "namespace-link-reopen", "root-link",
                   "namespace-owner-construction", "namespace-owner-reopen", "root-owner",
                   "member-owner", "marker-owner")
        for attack in attacks:
            with self.subTest(attack=attack), tempfile.TemporaryDirectory(prefix="gew-retained-identity-") as directory:
                ns_path = pathlib.Path(directory).resolve() / "namespace"
                ns_path.mkdir(mode=0o700)
                with _RetainedNamespace(ns_path) as namespace:
                    lease, binding = self._create(namespace)
                    root = lease.path
                    lease.close()
                    victim = (ns_path if attack.startswith("namespace") else
                              root if attack.startswith("root") else
                              root / ("active.bin" if attack == "member-owner" else _RetainedRootLease.BINDING_NAME))
                    identity = (victim.stat().st_dev, victim.stat().st_ino)
                    moved = None
                    if "link" in attack:
                        moved = victim.with_name(victim.name + "-real")
                        victim.rename(moved)
                        victim.symlink_to(moved, target_is_directory=True)
                    actual_root = (moved / root.name if attack.startswith("namespace-link") else
                                   moved if attack == "root-link" else root)
                    before = {p.name: p.read_bytes() for p in actual_root.iterdir()}
                    real_open, real_close, real_stat, real_fstat = os.open, os.close, os.stat, os.fstat
                    opened, closed, injected = [], [], []
                    def observed_open(*args, **kwargs):
                        fd = real_open(*args, **kwargs); opened.append(fd); return fd
                    def observed_close(fd):
                        result = real_close(fd); closed.append(fd); return result
                    def wrong_owner(value):
                        if "owner" in attack and (value.st_dev, value.st_ino) == identity:
                            injected.append(identity)
                            fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
                            fields["st_uid"] = os.getuid() + 1
                            return SimpleNamespace(**fields)
                        return value
                    def observed_stat(*args, **kwargs): return wrong_owner(real_stat(*args, **kwargs))
                    def observed_fstat(fd): return wrong_owner(real_fstat(fd))
                    message = ("not private and owner-bound" if attack.startswith("namespace-owner") else
                               "root identity changed" if attack == "root-owner" else
                               "member identity or permissions are unsafe" if "owner" in attack else
                               "cannot be opened" if attack.endswith("construction") else
                               "namespace is unavailable" if attack.startswith("namespace") else
                               "root is absent, unsafe or already exists")
                    try:
                        with mock.patch.object(os, "open", side_effect=observed_open), \
                                mock.patch.object(os, "close", side_effect=observed_close), \
                                mock.patch.object(os, "stat", side_effect=observed_stat), \
                                mock.patch.object(os, "fstat", side_effect=observed_fstat):
                            with mock.patch.object(os, "supports_dir_fd", {*os.supports_dir_fd, os.open, os.stat}):
                                with self.assertRaisesRegex(ReleaseSimulatorError, message):
                                    if attack.endswith("construction"):
                                        with _RetainedNamespace(ns_path):
                                            self.fail("unsafe namespace was admitted")
                                    else:
                                        with namespace.open_readonly(binding, members=self.MEMBERS,
                                                context=security_context()):
                                            self.fail("unsafe retained root was admitted")
                        if "owner" in attack: self.assertGreater(len(injected), 0)
                        self.assertGreater(len(opened), 0)
                        self.assertEqual(Counter(opened), Counter(closed))
                        for fd in set(opened):
                            with self.assertRaises(OSError): real_fstat(fd)
                        self.assertEqual(namespace._active, set())
                        self.assertEqual({p.name: p.read_bytes() for p in actual_root.iterdir()}, before)
                    finally:
                        if moved is not None:
                            victim.unlink()
                            moved.rename(victim)
                    self.assertEqual(namespace.active_leases, 0)
                    with namespace.open_readonly(binding, members=self.MEMBERS, context=security_context()) as reader:
                        self.assertEqual(reader.read("active.bin", max_bytes=1024), before["active.bin"])
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
