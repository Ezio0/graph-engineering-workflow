"""Digest-bound loop budgets loaded from configuration."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.error_rules import ErrorRuleRegistry
from graph_engineering.core.contracts.geel import (
    GEELProgram,
    PredicateRegistry,
    RootPathType,
    StaticRootRegistry,
)
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext


LOOP_BUDGET_SCHEMA = "urn:gew:schema:loop-budget:1.0.0"
LOOP_BUDGET_REGISTRY_SCHEMA = "urn:gew:schema:loop-budget-registry:1.0.0"
IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
BUDGET_ROOTS = StaticRootRegistry((
    RootPathType("usage", (), "object"),
    RootPathType("usage", ("attempts_used",), "integer"),
    RootPathType("usage", ("revisions_used",), "integer"),
    RootPathType("usage", ("total_runs_used",), "integer"),
))


class LoopBudgetError(ValueError):
    """Invalid budget declaration or consumption."""


@dataclass(frozen=True, slots=True, init=False)
class LoopBudget:
    budget_id: str
    version: str
    max_attempts: int
    max_revisions: int
    max_total_runs: int
    exhausted_route: str
    _program: GEELProgram

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("LoopBudget must be loaded from a digest-bound configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> LoopBudget:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(predicates) is not PredicateRegistry
            or type(error_rules) is not ErrorRuleRegistry
            or type(context) is not WorkContext
        ):
            raise LoopBudgetError("loop budget requires attested registries and work context")
        if schema_registry.validate(LOOP_BUDGET_SCHEMA, value, context):
            raise LoopBudgetError("loop budget schema validation failed")
        return cls._from_validated(value, predicates, error_rules, context)

    @classmethod
    def _from_validated(
        cls,
        value: Mapping[str, object],
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> LoopBudget:
        fields = {
            "schema_version", "budget_id", "version", "max_attempts", "max_revisions",
            "max_total_runs", "exhausted_route",
        }
        if set(value) != fields or value.get("schema_version") != "1.0.0":
            raise LoopBudgetError("loop budget properties are not exact")
        for name in ("budget_id", "version", "exhausted_route"):
            if type(value[name]) is not str or not value[name]:
                raise LoopBudgetError("loop budget identity fields are invalid")
        for name in ("max_attempts", "max_revisions", "max_total_runs"):
            if type(value[name]) is not int or value[name] < 1:
                raise LoopBudgetError("loop budget values must be positive exact integers")
        if value["exhausted_route"] not in {"awaiting_human", "blocked", "failed"}:
            raise LoopBudgetError("unknown loop exhaustion route")
        expression = {
            "op": "all",
            "args": [
                {
                    "op": "lt",
                    "left": {"op": "path", "root": "usage", "tokens": [field]},
                    "right": {"op": "literal", "value": value[maximum]},
                }
                for field, maximum in (
                    ("attempts_used", "max_attempts"),
                    ("revisions_used", "max_revisions"),
                    ("total_runs_used", "max_total_runs"),
                )
            ],
        }
        program = GEELProgram.load(expression, BUDGET_ROOTS, predicates, error_rules, context)
        result = object.__new__(LoopBudget)
        for name in fields - {"schema_version"}:
            object.__setattr__(result, name, value[name])
        object.__setattr__(result, "_program", program)
        return result

    def allows_next(
        self,
        *,
        attempts_used: int,
        revisions_used: int,
        total_runs_used: int,
        context: WorkContext,
        operation_path: tuple[int, ...] = (),
    ) -> bool:
        """Return whether one more run may start from the committed usage counters."""

        if any(type(item) is not int or item < 0 for item in (attempts_used, revisions_used, total_runs_used)):
            raise LoopBudgetError("loop consumption must be nonnegative exact integers")
        if type(context) is not WorkContext:
            raise LoopBudgetError("loop decision requires work context")
        result = self._program.evaluate({
            "usage": {
                "attempts_used": attempts_used,
                "revisions_used": revisions_used,
                "total_runs_used": total_runs_used,
            },
        }, context, operation_path=operation_path)
        if result.get("status") != "ok" or type(result.get("value")) is not bool:
            raise LoopBudgetError("loop budget evaluation failed closed")
        return result["value"]  # type: ignore[return-value]


@dataclass(frozen=True, slots=True, init=False)
class LoopBudgetRegistry:
    registry_id: str
    registry_digest: str
    budgets: Mapping[str, LoopBudget]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("LoopBudgetRegistry must be loaded from a digest-bound configuration")

    @staticmethod
    def create_manifest(registry_id: str, budgets: list[dict[str, object]]) -> dict[str, object]:
        if type(registry_id) is not str or not registry_id.startswith("urn:gew:loop-budget-registry:"):
            raise LoopBudgetError("invalid loop budget registry ID")
        identities = [item.get("budget_id") for item in budgets if isinstance(item, Mapping)]
        if len(identities) != len(budgets) or identities != sorted(identities) or len(identities) != len(set(identities)):
            raise LoopBudgetError("loop budgets must be sorted and unique")
        return {
            "schema_version": "1.0.0",
            "registry_id": registry_id,
            "budgets": budgets,
        }

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        predicates: PredicateRegistry,
        error_rules: ErrorRuleRegistry,
        context: WorkContext,
    ) -> LoopBudgetRegistry:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(predicates) is not PredicateRegistry
            or type(error_rules) is not ErrorRuleRegistry
            or type(context) is not WorkContext
        ):
            raise LoopBudgetError("loop budget registry requires attested registries and work context")
        if schema_registry.validate(LOOP_BUDGET_REGISTRY_SCHEMA, value, context):
            raise LoopBudgetError("loop budget registry schema validation failed")
        if set(value) != {"schema_version", "registry_id", "budgets"} or value.get("schema_version") != "1.0.0":
            raise LoopBudgetError("loop budget registry properties are not exact")
        registry_id = value.get("registry_id")
        budgets = value.get("budgets")
        if type(registry_id) is not str or not isinstance(budgets, list):
            raise LoopBudgetError("loop budget registry fields are invalid")
        expected = cls.create_manifest(registry_id, budgets)
        if value != expected:
            raise LoopBudgetError("loop budget registry is not canonical")
        digest = semantic_digest_charged(
            value,
            context,
            contract_type="urn:gew:contract:loop-budget-registry",
            projection_id=IDENTITY_PROJECTION,
            schema_id=LOOP_BUDGET_REGISTRY_SCHEMA,
        )
        loaded = [
            LoopBudget._from_validated(item, predicates, error_rules, context)
            for item in budgets
        ]
        result = object.__new__(LoopBudgetRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "registry_digest", digest)
        object.__setattr__(result, "budgets", MappingProxyType({item.budget_id: item for item in loaded}))
        return result

    def resolve(self, budget_id: str) -> LoopBudget:
        try:
            return self.budgets[budget_id]
        except KeyError as error:
            raise LoopBudgetError("unknown loop budget") from error
