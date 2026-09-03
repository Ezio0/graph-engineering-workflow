"""Platform-neutral graph engineering semantics."""

from graph_engineering.core.version import installed_version
from graph_engineering.core.project import (
    ProjectScope,
    ProjectScopeError,
    RepositoryBinding,
    ScopeChange,
    ScopeTargetBinding,
    classify_scope_change,
)
from graph_engineering.core.migration import (
    ActiveRepositoryManifest,
    ExportSnapshotIdentity,
    MigrationControlError,
    MigrationState,
    RepositoryCommandContext,
    RestoreGap,
    select_committed_manifest,
)

__all__ = [
    "ProjectScope",
    "ProjectScopeError",
    "RepositoryBinding",
    "ScopeChange",
    "ScopeTargetBinding",
    "classify_scope_change",
    "ActiveRepositoryManifest",
    "ExportSnapshotIdentity",
    "MigrationControlError",
    "MigrationState",
    "RepositoryCommandContext",
    "RestoreGap",
    "select_committed_manifest",
    "installed_version",
]
