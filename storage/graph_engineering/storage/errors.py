"""Stable storage boundary failures."""

from __future__ import annotations


class RepositoryError(RuntimeError):
    """Base class for fail-closed local repository errors."""


class RepositoryConfigurationError(RepositoryError):
    """The repository policy, path, or capability is not approved."""


class RepositoryBusyError(RepositoryError):
    """The finite writer retry budget was exhausted."""


class RepositoryConflictError(RepositoryError):
    """CAS, idempotency, lease, or fence state conflicts."""


class RepositoryIntegrityError(RepositoryError):
    """Committed repository facts cannot be proven internally consistent."""


class RepositoryProcessError(RepositoryError):
    """A connection or lock handle crossed a PID/thread/fork boundary."""


class ObjectIntegrityError(RepositoryIntegrityError):
    """A content-addressed object is missing, malformed, or digest-invalid."""


class LockUnavailableError(RepositoryBusyError):
    """A canonical lock set could not be acquired atomically."""
