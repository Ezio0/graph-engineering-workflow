from __future__ import annotations

from contextlib import contextmanager
import json
import pathlib
import platform
import tempfile
from typing import Iterator
from unittest import mock

from graph_engineering.storage.connection import ConnectionFactory, RepositoryDoctor
from graph_engineering.storage.leases import ResourceLeaseRepository
from graph_engineering.storage.locks import LockedFileRegistry
from graph_engineering.storage.objects import ObjectRepository
from graph_engineering.storage.policy import RepositoryPolicy
from graph_engineering.storage.repository import TaskRepository
from graph_engineering.storage.migration import InstallationMigrationRepository


ROOT = pathlib.Path(__file__).resolve().parents[2]


class ManualTime:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value

    def set(self, value: int) -> None:
        self.value = value


def policy() -> RepositoryPolicy:
    return RepositoryPolicy.from_dict(json.loads(
        (ROOT / "config" / "contracts" / "repository-policy-v1.json").read_text()
    ))


def mount_observation(root: pathlib.Path) -> dict[str, object]:
    system = platform.system()
    filesystem = "apfs" if system == "Darwin" else "ext4"
    options = (filesystem, "local", "rw") if system == "Darwin" else ("rw",)
    return {
        "platform": system,
        "mount_point": str(root),
        "filesystem_type": filesystem,
        "mount_options": options,
        "filesystem_identity": f"conformance:{system}:{filesystem}:{root}",
    }


@contextmanager
def repository_stack(
    *,
    object_fault=lambda _step: None,
    repository_fault=lambda _step: None,
    manual_time: ManualTime | None = None,
) -> Iterator[tuple[
    pathlib.Path,
    ConnectionFactory,
    LockedFileRegistry,
    ObjectRepository,
    TaskRepository,
    ResourceLeaseRepository,
]]:
    with tempfile.TemporaryDirectory(prefix="gew-wp03-") as directory:
        root = pathlib.Path(directory) / "repository"
        clock = ManualTime() if manual_time is None else manual_time
        with (
            mock.patch.object(
                RepositoryDoctor, "_mount_observation", side_effect=mount_observation,
            ),
            mock.patch("graph_engineering.storage.clock.time.time_ns", side_effect=clock),
        ):
            factory = ConnectionFactory.initialize(root, policy(), "repository-test-v1")
            locks = LockedFileRegistry(factory)
            maintenance_factory = factory._for_maintenance()
            maintenance_objects = ObjectRepository(
                maintenance_factory, locks, fault_hook=object_fault,
            )
            control_root = pathlib.Path(directory) / "installation-control"
            migration_policy = json.loads(
                (ROOT / "config" / "contracts" / "migration-storage-policy-v1.json").read_text()
            )
            manager = InstallationMigrationRepository.initialize(
                maintenance_factory, locks, maintenance_objects, control_root=control_root,
                policy_document=migration_policy,
            )
            scope = manager.command_scope()
            scope.__enter__()
            bound_factory = factory.bind_command_scope(scope)
            objects = ObjectRepository(bound_factory, locks, fault_hook=object_fault)
            leases = ResourceLeaseRepository(bound_factory, locks)
            repository = TaskRepository(
                bound_factory, locks, objects, fault_hook=repository_fault, command_scope=scope,
            )
            factory._test_installation_control_root = control_root
            factory._test_migration_policy = migration_policy
            factory._test_installation_scope = scope
            factory._test_installation_manager = manager
            try:
                yield root, factory, locks, objects, repository, leases
            finally:
                try:
                    scope.__exit__(None, None, None)
                except Exception:
                    pass
                try:
                    manager.close()
                except Exception:
                    pass
                try:
                    objects.close()
                except Exception:
                    pass
                try:
                    maintenance_objects.close()
                except Exception:
                    pass
                try:
                    locks.close()
                except Exception:
                    pass


@contextmanager
def command_scope_for_test(
    factory: ConnectionFactory,
    locks: LockedFileRegistry,
    objects: ObjectRepository,
):
    manager = InstallationMigrationRepository.attach_command_plane(
        factory,
        locks,
        objects,
        control_root=factory._test_installation_control_root,
        policy_document=factory._test_migration_policy,
    )
    try:
        with manager.command_scope() as scope:
            yield scope
    finally:
        manager.close()
