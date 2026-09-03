"""Backend-neutral storage ports and local repository implementations."""

from .errors import (
    LockUnavailableError,
    ObjectIntegrityError,
    RepositoryBusyError,
    RepositoryConfigurationError,
    RepositoryConflictError,
    RepositoryError,
    RepositoryIntegrityError,
    RepositoryProcessError,
)
from .faults import FaultController, InjectedPersistenceFault, PersistenceFaultSchedule
from .policy import RepositoryPolicy
from .ports import CommitBatch, CommitResult, LeaseGrant
from .connection import ConnectionFactory, ManagedConnection, RepositoryDoctor
from .leases import ResourceLeaseRepository
from .locks import LockedFileRegistry, LockToken
from .objects import ObjectRepository
from .repository import TaskRepository, event_digest, make_event
from .security import SecurityStateRepository
from .migration import (
    ImportedRepository,
    InstallationMigrationRepository,
    MigrationBundle,
    MigrationRepositoryError,
    MigrationStoragePolicy,
)

__all__ = [
    "CommitBatch", "CommitResult", "LeaseGrant", "LockUnavailableError",
    "ConnectionFactory", "FaultController",
    "InjectedPersistenceFault", "LockedFileRegistry", "LockToken",
    "ManagedConnection", "ObjectIntegrityError", "ObjectRepository", "RepositoryBusyError",
    "RepositoryConfigurationError",
    "RepositoryConflictError", "RepositoryError", "RepositoryIntegrityError",
    "PersistenceFaultSchedule", "RepositoryPolicy", "RepositoryProcessError",
    "RepositoryDoctor",
    "ResourceLeaseRepository",
    "TaskRepository", "event_digest", "make_event",
    "SecurityStateRepository",
    "ImportedRepository", "InstallationMigrationRepository", "MigrationBundle",
    "MigrationRepositoryError", "MigrationStoragePolicy",
]
