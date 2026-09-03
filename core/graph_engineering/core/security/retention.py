"""Configuration-driven retention and purge decisions."""

from __future__ import annotations

import datetime
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    exact_mapping,
    parse_timestamp,
    require_canonical_strings,
    require_digest,
    require_id,
    require_sensitivity,
)
from graph_engineering.core.security.attestation import (
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TaskSecurityContext,
    require_runtime_context,
)


RETENTION_POLICY_SCHEMA = "urn:gew:schema:retention-policy-registry:1.0.0"
RETENTION_CATEGORIES = (
    "artifact-body",
    "backup",
    "event-metadata",
    "evidence-body",
    "pmf-aggregate",
    "quarantine",
    "tool-raw-output",
)


class RetentionError(ValueError):
    """Retention policy or purge request is invalid."""


@dataclass(frozen=True, slots=True, init=False)
class RetentionPolicyRegistry:
    registry_id: str
    policies: Mapping[str, Mapping[str, object]]
    registry_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RetentionPolicyRegistry must be loaded from validated configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> RetentionPolicyRegistry:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
        ):
            raise RetentionError("retention registry requires attested contracts")
        if schema_registry.validate(RETENTION_POLICY_SCHEMA, value, context):
            raise RetentionError("retention registry schema validation failed")
        try:
            exact_mapping(value, {"schema_version", "registry_id", "policies", "registry_digest"}, "retention registry")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("retention registry version is invalid")
            registry_id = require_id(value.get("registry_id"), "retention registry ID")
            expected = require_digest(value.get("registry_digest"), "retention registry digest")
            raw_policies = value.get("policies")
            if type(raw_policies) is not list:
                raise ValueError("retention policies are invalid")
            categories = [item.get("category") for item in raw_policies if isinstance(item, Mapping)]
            if tuple(categories) != RETENTION_CATEGORIES:
                raise ValueError("retention registry category set is not exact")
            policies: dict[str, Mapping[str, object]] = {}
            fields = {"category", "max_age_seconds", "purge_triggers", "tombstone_required", "purge_after_extraction"}
            for raw in raw_policies:
                exact_mapping(raw, fields, "retention policy")
                category = require_id(raw.get("category"), "retention category")
                maximum_age = raw.get("max_age_seconds")
                triggers = require_canonical_strings(raw.get("purge_triggers"), "purge triggers", ids=True)
                if type(maximum_age) is not int or maximum_age < 0:
                    raise ValueError("retention maximum age is invalid")
                if type(raw.get("tombstone_required")) is not bool or type(raw.get("purge_after_extraction")) is not bool:
                    raise ValueError("retention policy flags are invalid")
                if raw.get("tombstone_required") is not True:
                    raise ValueError("retention purge must preserve an audit tombstone")
                frozen = freeze(raw)
                if not isinstance(frozen, FrozenMap):
                    raise AssertionError("retention policy did not freeze")
                policies[category] = frozen
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "registry_digest"},
                context,
                contract_type="urn:gew:contract:retention-policy-registry",
                projection_id=IDENTITY_PROJECTION,
                schema_id=RETENTION_POLICY_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected, actual):
                raise ValueError("retention registry digest mismatch")
            runtime.require_policy("retention", registry_id, expected)
        except (TypeError, ValueError) as error:
            raise RetentionError(str(error)) from error
        result = object.__new__(RetentionPolicyRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "policies", MappingProxyType(policies))
        object.__setattr__(result, "registry_digest", expected)
        return result

    def resolve(self, category: str) -> Mapping[str, object]:
        try:
            return self.policies[category]
        except KeyError as error:
            raise RetentionError("unknown retention category") from error


@dataclass(frozen=True, slots=True, init=False)
class RetentionDecision:
    action: str
    subject_ref: str
    category: str
    trigger: str
    tombstone_required: bool
    reason: str
    subject_snapshot_digest: str
    task_context_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RetentionDecision is emitted only by RetentionEngine")


def _decision(
    *,
    action: str,
    subject_ref: str,
    category: str,
    trigger: str,
    tombstone_required: bool,
    reason: str,
    subject_snapshot_digest: str,
    task_context_digest: str,
) -> RetentionDecision:
    result = object.__new__(RetentionDecision)
    for name, item in (
        ("action", action),
        ("subject_ref", subject_ref),
        ("category", category),
        ("trigger", trigger),
        ("tombstone_required", tombstone_required),
        ("reason", reason),
        ("subject_snapshot_digest", subject_snapshot_digest),
        ("task_context_digest", task_context_digest),
    ):
        object.__setattr__(result, name, item)
    return result


class RetentionEngine:
    @staticmethod
    def evaluate(
        *,
        runtime: SecurityRuntimeManifest,
        task_context: TaskSecurityContext,
        registry: RetentionPolicyRegistry,
        subject_ref: str,
        trigger: str,
    ) -> RetentionDecision:
        if (
            type(runtime) is not SecurityRuntimeManifest
            or type(task_context) is not TaskSecurityContext
            or type(registry) is not RetentionPolicyRegistry
        ):
            raise RetentionError("retention registry is invalid")
        try:
            require_runtime_context(runtime, task_context)
            runtime.require_policy("retention", registry.registry_id, registry.registry_digest)
            subject_ref = require_id(subject_ref, "retention subject ref")
            subject = exact_mapping(
                task_context.retention_subject(subject_ref),
                {
                    "category",
                    "created_at",
                    "sensitivity",
                    "extracted",
                    "legal_hold",
                    "rollback_dependency",
                    "unresolved_action",
                    "snapshot_digest",
                    "revision",
                },
                "retention subject snapshot",
            )
            category = require_id(subject.get("category"), "retention category")
            require_id(category, "retention category")
            require_id(trigger, "retention trigger")
            classification = require_sensitivity(subject.get("sensitivity"))
            created = parse_timestamp(subject.get("created_at"), "retention creation timestamp")
            now = parse_timestamp(task_context.current_time, "attested retention current timestamp")
            if now < created:
                raise ValueError("retention time moved backwards")
            extracted = subject.get("extracted")
            legal_hold = subject.get("legal_hold")
            rollback_dependency = subject.get("rollback_dependency")
            unresolved_action = subject.get("unresolved_action")
            if any(type(flag) is not bool for flag in (extracted, legal_hold, rollback_dependency, unresolved_action)):
                raise ValueError("retention flags are invalid")
            revision = subject.get("revision")
            subject_snapshot_digest = require_digest(
                subject.get("snapshot_digest"),
                "retention subject snapshot digest",
            )
            if type(revision) is not int or revision < 0:
                raise ValueError("retention subject revision is invalid")
            if subject_snapshot_digest != task_context.binding.snapshot_digest:
                raise ValueError("retention subject is stale for the current task snapshot")
            if classification == "secret":
                raise ValueError("raw secret bodies cannot enter retention storage")
            policy = registry.resolve(category)
            age = int((now - created).total_seconds())
            triggers = policy["purge_triggers"]
            purge_after_extraction = policy["purge_after_extraction"] is True and extracted and trigger == "extracted"
            age_expired = age >= int(policy["max_age_seconds"]) and trigger in triggers
            should_purge = purge_after_extraction or age_expired
        except (SecurityAttestationError, TypeError, ValueError) as error:
            if isinstance(error, RetentionError):
                raise
            raise RetentionError(str(error)) from error
        if should_purge and (legal_hold or rollback_dependency or unresolved_action):
            blockers = [
                name
                for name, present in (
                    ("legal-hold", legal_hold),
                    ("rollback-dependency", rollback_dependency),
                    ("unresolved-action", unresolved_action),
                )
                if present
            ]
            return _decision(
                action="blocked",
                subject_ref=subject_ref,
                category=category,
                trigger=trigger,
                tombstone_required=False,
                reason="+".join(blockers),
                subject_snapshot_digest=subject_snapshot_digest,
                task_context_digest=task_context.state_digest,
            )
        if should_purge:
            return _decision(
                action="purge",
                subject_ref=subject_ref,
                category=category,
                trigger=trigger,
                tombstone_required=bool(policy["tombstone_required"]),
                reason="extracted" if purge_after_extraction else "age-and-trigger",
                subject_snapshot_digest=subject_snapshot_digest,
                task_context_digest=task_context.state_digest,
            )
        return _decision(
            action="retain",
            subject_ref=subject_ref,
            category=category,
            trigger=trigger,
            tombstone_required=False,
            reason="policy-retain",
            subject_snapshot_digest=subject_snapshot_digest,
            task_context_digest=task_context.state_digest,
        )
