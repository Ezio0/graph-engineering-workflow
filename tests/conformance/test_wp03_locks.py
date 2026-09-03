from __future__ import annotations

import os
import pathlib
import sys
import threading
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))
sys.path.insert(0, str(ROOT))

from graph_engineering.storage.errors import (  # noqa: E402
    LockUnavailableError,
    RepositoryConfigurationError,
    RepositoryProcessError,
)
from graph_engineering.storage.locks import LockedFileRegistry  # noqa: E402
from tests.support.wp03_repository import repository_stack  # noqa: E402


class LockConformanceTests(unittest.TestCase):
    def test_resource_order_is_canonical_no_partial_and_same_thread_is_nonreentrant(self) -> None:
        with repository_stack() as (_root, factory, locks, _objects, _repository, _leases):
            with self.assertRaises(RepositoryConfigurationError):
                LockedFileRegistry(factory)
            token = locks.acquire_resources(("resource-b", "resource-a"))
            self.assertEqual(token.lock_ids, ("resource:resource-a", "resource:resource-b"))
            with self.assertRaises(RepositoryConfigurationError):
                locks.acquire_resources(("resource-a",))
            locks.release(token)
            later = locks.acquire_resources(("resource-b",))
            with self.assertRaises(RepositoryConfigurationError):
                locks.acquire_resources(("resource-a",))
            locks.release(later)
            with self.assertRaises(RepositoryConfigurationError):
                locks.acquire_resources(("resource-a", "resource-a"))

    def test_global_lock_order_and_reverse_release_are_mechanically_enforced(self) -> None:
        with repository_stack() as (_root, _factory, locks, _objects, _repository, _leases):
            object_token = locks.acquire_object("shared")
            with self.assertRaises(RepositoryConfigurationError):
                locks.acquire_installation("shared")
            locks.release(object_token)

            installation = locks.acquire_installation("shared")
            resources = locks.acquire_resources(("resource-a", "resource-b"))
            object_token = locks.acquire_object("shared")
            with self.assertRaises(RepositoryProcessError):
                locks.release(installation)
            locks.release(object_token)
            locks.release(resources)
            locks.release(installation)

    def test_post_initialization_lock_ancestor_replacement_has_zero_external_effect(self) -> None:
        for component in ("locks", "resources"):
            with self.subTest(component=component), repository_stack() as (
                root, factory, locks, _objects, _repository, _leases,
            ):
                if component == "locks":
                    path = root / factory.policy.locks_directory
                    original = root / "locks-attested-original"
                else:
                    lock_root = root / factory.policy.locks_directory
                    path = lock_root / factory.policy.resources_directory
                    original = lock_root / "resources-attested-original"
                path.rename(original)
                external = root.parent / f"external-{component}"
                external.mkdir(mode=factory.policy.root_mode)
                path.symlink_to(external, target_is_directory=True)
                before_mode = external.stat().st_mode & 0o777
                with self.assertRaises(RepositoryConfigurationError):
                    if component == "locks":
                        locks.acquire_installation("shared")
                    else:
                        locks.acquire_resources(("resource-replaced",))
                self.assertEqual(tuple(external.iterdir()), ())
                self.assertEqual(external.stat().st_mode & 0o777, before_mode)

    def test_shared_readers_block_exclusive_until_all_release(self) -> None:
        with repository_stack() as (_root, _factory, locks, _objects, _repository, _leases):
            ready = threading.Barrier(3)
            release = threading.Event()
            errors: list[BaseException] = []

            def reader() -> None:
                try:
                    token = locks.acquire_installation("shared")
                    ready.wait(timeout=2)
                    release.wait(timeout=2)
                    locks.release(token)
                except BaseException as error:
                    errors.append(error)

            threads = [threading.Thread(target=reader) for _ in range(2)]
            for thread in threads:
                thread.start()
            try:
                ready.wait(timeout=2)
                with self.assertRaises(LockUnavailableError):
                    locks.acquire_installation("exclusive")
            finally:
                release.set()
                for thread in threads:
                    thread.join(timeout=2)
            self.assertEqual(errors, [])
            exclusive = locks.acquire_installation("exclusive")
            locks.release(exclusive)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork required")
    def test_fork_child_cannot_release_parent_and_independent_process_conflicts(self) -> None:
        with repository_stack() as (_root, factory, locks, _objects, _repository, _leases):
            parent = locks.acquire_resources(("resource-a",))
            parent_publication = locks.acquire_publication("sha256:" + "1" * 64)
            parent_object = locks.acquire_object("exclusive")
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(read_fd)
                outcomes: list[str] = []
                try:
                    locks.release(parent)
                except RepositoryProcessError:
                    outcomes.append("inherited-blocked")
                child_registry = LockedFileRegistry(factory)
                try:
                    child_registry.acquire_resources(("resource-a",))
                except LockUnavailableError:
                    outcomes.append("external-conflict")
                try:
                    child_registry.acquire_publication("sha256:" + "1" * 64)
                except LockUnavailableError:
                    outcomes.append("publication-conflict")
                try:
                    child_registry.acquire_object("shared")
                except LockUnavailableError:
                    outcomes.append("object-conflict")
                os.write(write_fd, ",".join(outcomes).encode())
                os.close(write_fd)
                os._exit(0)
            os.close(write_fd)
            self.assertEqual(
                os.read(read_fd, 128),
                b"inherited-blocked,external-conflict,publication-conflict,object-conflict",
            )
            os.close(read_fd)
            os.waitpid(child, 0)
            locks.release(parent_object)
            locks.release(parent_publication)
            locks.release(parent)
            after = locks.acquire_resources(("resource-a",))
            locks.release(after)

    @unittest.skipUnless(hasattr(os, "fork"), "POSIX fork required")
    def test_opposing_process_resource_sequence_fails_finitely_before_deadlock(self) -> None:
        with repository_stack() as (_root, factory, locks, _objects, _repository, _leases):
            parent_b = locks.acquire_resources(("resource-b",))
            child_ready_read, child_ready_write = os.pipe()
            parent_go_read, parent_go_write = os.pipe()
            child_result_read, child_result_write = os.pipe()
            child = os.fork()
            if child == 0:
                os.close(child_ready_read)
                os.close(parent_go_write)
                os.close(child_result_read)
                outcomes: list[str] = []
                child_registry = LockedFileRegistry(factory)
                child_a = child_registry.acquire_resources(("resource-a",))
                os.write(child_ready_write, b"ready")
                os.close(child_ready_write)
                os.read(parent_go_read, 2)
                os.close(parent_go_read)
                try:
                    child_registry.acquire_resources(("resource-b",))
                except LockUnavailableError:
                    outcomes.append("external-conflict")
                child_registry.release(child_a)
                os.write(child_result_write, ",".join(outcomes).encode())
                os.close(child_result_write)
                os._exit(0)
            os.close(child_ready_write)
            os.close(parent_go_read)
            os.close(child_result_write)
            self.assertEqual(os.read(child_ready_read, 16), b"ready")
            os.close(child_ready_read)
            with self.assertRaises(RepositoryConfigurationError):
                locks.acquire_resources(("resource-a",))
            os.write(parent_go_write, b"go")
            os.close(parent_go_write)
            self.assertEqual(os.read(child_result_read, 64), b"external-conflict")
            os.close(child_result_read)
            os.waitpid(child, 0)
            locks.release(parent_b)


if __name__ == "__main__":
    unittest.main()
