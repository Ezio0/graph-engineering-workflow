"""Versioned configuration for the SQLite + filesystem repository backend."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .errors import RepositoryConfigurationError


@dataclass(frozen=True, slots=True)
class RepositoryPolicy:
    schema_version: str
    policy_id: str
    database_filename: str
    objects_directory: str
    staging_directory: str
    locks_directory: str
    resources_directory: str
    journal_mode: str
    synchronous: str
    foreign_keys: bool
    locking_mode: str
    busy_timeout_ms: int
    busy_retry_delays_ms: tuple[int, ...]
    root_mode: int
    file_mode: int
    lock_mode: int
    object_fanout_chars: int
    approved_filesystem_types: tuple[str, ...]
    required_sqlite_vfs: str
    connection_roles: tuple[str, ...]

    REQUIRED_KEYS: ClassVar[frozenset[str]] = frozenset({
        "schema_version", "policy_id", "database_filename", "objects_directory",
        "staging_directory", "locks_directory", "resources_directory", "journal_mode",
        "synchronous", "foreign_keys", "locking_mode", "busy_timeout_ms",
        "busy_retry_delays_ms", "root_mode", "file_mode", "lock_mode",
        "object_fanout_chars", "connection_roles",
        "approved_filesystem_types", "required_sqlite_vfs",
    })
    REQUIRED_JOURNAL: ClassVar[str] = "DELETE"
    REQUIRED_SYNCHRONOUS: ClassVar[str] = "EXTRA"
    REQUIRED_LOCKING: ClassVar[str] = "NORMAL"
    REQUIRED_VERSION: ClassVar[str] = "1.0"

    @classmethod
    def from_dict(cls, value: object) -> RepositoryPolicy:
        if not isinstance(value, dict) or set(value) != cls.REQUIRED_KEYS:
            raise RepositoryConfigurationError("repository policy shape is not exact")
        strings = (
            "schema_version", "policy_id", "database_filename", "objects_directory",
            "staging_directory", "locks_directory", "resources_directory", "journal_mode",
            "synchronous", "locking_mode",
            "required_sqlite_vfs",
        )
        if any(type(value[name]) is not str or not value[name] for name in strings):
            raise RepositoryConfigurationError("repository policy string is invalid")
        path_fields = (
            "database_filename", "objects_directory", "staging_directory",
            "locks_directory", "resources_directory",
        )
        if any(
            "/" in value[name] or "\\" in value[name] or value[name] in {".", ".."}
            for name in path_fields
        ):
            raise RepositoryConfigurationError("repository policy path is not one component")
        if (
            value["schema_version"] != cls.REQUIRED_VERSION
            or value["journal_mode"] != cls.REQUIRED_JOURNAL
            or value["synchronous"] != cls.REQUIRED_SYNCHRONOUS
            or value["locking_mode"] != cls.REQUIRED_LOCKING
            or value["foreign_keys"] is not True
        ):
            raise RepositoryConfigurationError("repository durability policy is weakened")
        integer_fields = (
            "busy_timeout_ms", "root_mode", "file_mode", "lock_mode", "object_fanout_chars",
        )
        if any(type(value[name]) is not int or value[name] < 0 for name in integer_fields):
            raise RepositoryConfigurationError("repository policy integer is invalid")
        delays = value["busy_retry_delays_ms"]
        roles = value["connection_roles"]
        filesystems = value["approved_filesystem_types"]
        if (
            not isinstance(delays, list)
            or not delays
            or any(type(item) is not int or item < 0 for item in delays)
            or not isinstance(roles, list)
            or not roles
            or any(type(item) is not str or not item for item in roles)
            or len(set(roles)) != len(roles)
            or roles != sorted(roles)
            or not isinstance(filesystems, list)
            or not filesystems
            or any(type(item) is not str or not item or item != item.casefold() for item in filesystems)
            or filesystems != sorted(set(filesystems))
        ):
            raise RepositoryConfigurationError(
                "repository retry, role, or filesystem set is invalid",
            )
        if not (1 <= value["object_fanout_chars"] <= 8):
            raise RepositoryConfigurationError("object fanout is invalid")
        for mode_name in ("root_mode", "file_mode", "lock_mode"):
            if value[mode_name] & 0o077:
                raise RepositoryConfigurationError("repository modes must be owner-only")
        return cls(
            value["schema_version"], value["policy_id"], value["database_filename"],
            value["objects_directory"], value["staging_directory"], value["locks_directory"],
            value["resources_directory"], value["journal_mode"], value["synchronous"],
            value["foreign_keys"], value["locking_mode"], value["busy_timeout_ms"],
            tuple(delays), value["root_mode"], value["file_mode"], value["lock_mode"],
            value["object_fanout_chars"], tuple(filesystems), value["required_sqlite_vfs"],
            tuple(roles),
        )
