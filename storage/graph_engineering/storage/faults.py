"""Versioned deterministic fault schedule for repository conformance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar

from .errors import RepositoryConfigurationError, RepositoryError


class InjectedPersistenceFault(RepositoryError):
    def __init__(self, step: str, kind: str) -> None:
        super().__init__(f"injected persistence fault: {kind} at {step}")
        self.step = step
        self.kind = kind


@dataclass(frozen=True, slots=True)
class PersistenceFaultSchedule:
    schema_version: str
    schedule_id: str
    steps: tuple[str, ...]
    fault_kinds: tuple[str, ...]
    expected_states: tuple[str, ...]

    REQUIRED_STEPS: ClassVar[frozenset[str]] = frozenset({
        "commit.after_commit", "commit.after_events", "commit.before_commit",
        "commit.before_transaction", "object.after_file_fsync",
        "object.after_metadata_commit", "object.after_object_directory_fsync",
        "object.after_publication", "object.after_staging_directory_fsync",
        "object.before_metadata_commit", "object.before_staging_open",
        "purge.after_deleting_commit",
        "purge.after_directory_fsync",
    })
    REQUIRED_KINDS: ClassVar[frozenset[str]] = frozenset({
        "disk-full", "io-error", "process-kill",
    })
    REQUIRED_STATES: ClassVar[frozenset[str]] = frozenset({"old", "new", "blocked"})

    @classmethod
    def from_dict(cls, value: object) -> PersistenceFaultSchedule:
        required = {
            "schema_version", "schedule_id", "steps", "fault_kinds", "expected_states",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise RepositoryConfigurationError("persistence fault schedule shape is not exact")
        if (
            value["schema_version"] != "1.0"
            or type(value["schedule_id"]) is not str
            or not value["schedule_id"]
        ):
            raise RepositoryConfigurationError("persistence fault schedule identity is invalid")
        values: list[tuple[str, ...]] = []
        for name in ("steps", "fault_kinds", "expected_states"):
            items = value[name]
            if (
                not isinstance(items, list)
                or any(type(item) is not str or not item for item in items)
                or items != sorted(set(items))
            ):
                raise RepositoryConfigurationError("persistence fault schedule set is not canonical")
            values.append(tuple(items))
        steps, kinds, states = values
        if (
            set(steps) != cls.REQUIRED_STEPS
            or set(kinds) != cls.REQUIRED_KINDS
            or set(states) != cls.REQUIRED_STATES
        ):
            raise RepositoryConfigurationError("persistence fault schedule coverage is incomplete")
        return cls(value["schema_version"], value["schedule_id"], steps, kinds, states)


class FaultController:
    def __init__(
        self,
        schedule: PersistenceFaultSchedule,
        *,
        selected_step: str | None = None,
        fault_kind: str | None = None,
    ) -> None:
        if (selected_step is None) != (fault_kind is None):
            raise RepositoryConfigurationError("fault selection is incomplete")
        if selected_step is not None and selected_step not in schedule.steps:
            raise RepositoryConfigurationError("fault step is not scheduled")
        if fault_kind is not None and fault_kind not in schedule.fault_kinds:
            raise RepositoryConfigurationError("fault kind is not scheduled")
        self._schedule = schedule
        self._selected = selected_step
        self._kind = fault_kind
        self._trace: list[str] = []
        self._injected = False

    @property
    def trace(self) -> tuple[str, ...]:
        return tuple(self._trace)

    def __call__(self, step: str) -> None:
        if step not in self._schedule.steps:
            raise RepositoryConfigurationError("production emitted an undeclared fault step")
        self._trace.append(step)
        if step == self._selected and not self._injected:
            self._injected = True
            assert self._kind is not None
            raise InjectedPersistenceFault(step, self._kind)
