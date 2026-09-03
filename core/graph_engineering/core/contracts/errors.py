"""Stable deterministic contract errors."""

from __future__ import annotations

from dataclasses import dataclass


ERROR_CODES = frozenset({
    "E_SCHEMA",
    "E_OPERATOR",
    "E_TYPE",
    "E_PATH_MISSING",
    "E_PATH_TYPE",
    "E_PREDICATE",
    "E_BUDGET",
    "E_LIMIT",
})
ERROR_PHASES = frozenset({"limit", "schema", "registry", "static", "runtime", "budget"})


@dataclass(frozen=True, slots=True)
class ErrorDetail:
    """Exact machine-readable error body."""

    code: str
    phase: str
    rule_id: str
    source_id: str
    instance_path: tuple[str | int, ...] = ()
    definition_path: tuple[str | int, ...] = ()
    evaluation_path: tuple[str | int, ...] = ()

    def __post_init__(self) -> None:
        if self.code not in ERROR_CODES:
            raise ValueError(f"unknown error code: {self.code}")
        if self.phase not in ERROR_PHASES:
            raise ValueError(f"unknown error phase: {self.phase}")
        for path in (self.instance_path, self.definition_path, self.evaluation_path):
            if any(type(token) not in (str, int) or (type(token) is int and token < 0) for token in path):
                raise ValueError("invalid error path token")

    def as_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "definition_path": list(self.definition_path),
            "evaluation_path": list(self.evaluation_path),
            "instance_path": list(self.instance_path),
            "phase": self.phase,
            "rule_id": self.rule_id,
            "source_id": self.source_id,
        }


class ContractError(ValueError):
    """Fail-closed error with a stable detail record."""

    def __init__(self, detail: ErrorDetail) -> None:
        super().__init__(f"{detail.code}:{detail.rule_id}")
        self.detail = detail


def error_result(detail: ErrorDetail) -> dict[str, object]:
    return {"error": detail.as_dict(), "schema_version": "1.0.0", "status": "error"}


def ok_result(value: bool) -> dict[str, object]:
    if type(value) is not bool:
        raise TypeError("GEEL result value must be boolean")
    return {"schema_version": "1.0.0", "status": "ok", "value": value}
