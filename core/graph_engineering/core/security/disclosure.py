"""Deterministic disclosure planning and receipt binding."""

from __future__ import annotations

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
    require_canonical_strings,
    require_digest,
    require_id,
    require_sensitivity,
    sensitivity_rank,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import (
    DisclosureJournalAttestation,
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TaskSecurityContext,
    require_journal_context,
    require_runtime_context,
)
from graph_engineering.core.security.privacy import RedactedPayload


DISCLOSURE_POLICY_SCHEMA = "urn:gew:schema:disclosure-policy:1.0.0"
DISCLOSURE_PLAN_SCHEMA = "urn:gew:schema:data-disclosure-plan:1.0.0"
DISCLOSURE_RECEIPT_SCHEMA = "urn:gew:schema:disclosure-receipt:1.0.0"


class DisclosureError(ValueError):
    """A disclosure is undeclared, over-broad, unbound, or unauditable."""


@dataclass(frozen=True, slots=True, init=False)
class DisclosurePolicy:
    policy_id: str
    rules: Mapping[tuple[str, str], Mapping[str, object]]
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("DisclosurePolicy must be loaded from validated configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> DisclosurePolicy:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
        ):
            raise DisclosureError("disclosure policy requires attested contracts")
        if schema_registry.validate(DISCLOSURE_POLICY_SCHEMA, value, context):
            raise DisclosureError("disclosure policy schema validation failed")
        try:
            exact_mapping(value, {"schema_version", "policy_id", "rules", "policy_digest"}, "disclosure policy")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("disclosure policy version is invalid")
            policy_id = require_id(value.get("policy_id"), "disclosure policy ID")
            expected = require_digest(value.get("policy_digest"), "disclosure policy digest")
            raw_rules = value.get("rules")
            if type(raw_rules) is not list or not raw_rules:
                raise ValueError("disclosure policy rules are invalid")
            keys = [
                (item.get("destination_kind"), item.get("trust_boundary"))
                for item in raw_rules
                if isinstance(item, Mapping)
            ]
            if keys != sorted(set(keys)):
                raise ValueError("disclosure policy rules are not canonical")
            rules: dict[tuple[str, str], Mapping[str, object]] = {}
            fields = {
                "destination_kind",
                "trust_boundary",
                "maximum_sensitivity",
                "allowed_purposes",
                "authority_required",
                "receipt_required",
                "redaction_required",
            }
            for raw in raw_rules:
                exact_mapping(raw, fields, "disclosure policy rule")
                kind = require_id(raw.get("destination_kind"), "destination kind")
                boundary = require_id(raw.get("trust_boundary"), "trust boundary")
                require_sensitivity(raw.get("maximum_sensitivity"))
                require_canonical_strings(raw.get("allowed_purposes"), "allowed purposes", ids=True)
                if any(type(raw.get(name)) is not bool for name in ("authority_required", "receipt_required", "redaction_required")):
                    raise ValueError("disclosure policy flags are invalid")
                if boundary == "external" and any(
                    raw.get(name) is not True
                    for name in ("authority_required", "receipt_required", "redaction_required")
                ):
                    raise ValueError("external disclosure cannot weaken authority, receipt, or redaction")
                if boundary not in {"external", "owner-session"} and any(
                    raw.get(name) is not True
                    for name in ("receipt_required", "redaction_required")
                ):
                    raise ValueError("runtime disclosure cannot weaken receipt or redaction")
                frozen = freeze(raw)
                if not isinstance(frozen, FrozenMap):
                    raise AssertionError("disclosure policy rule did not freeze")
                rules[(kind, boundary)] = frozen
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "policy_digest"},
                context,
                contract_type="urn:gew:contract:disclosure-policy",
                projection_id=IDENTITY_PROJECTION,
                schema_id=DISCLOSURE_POLICY_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected, actual):
                raise ValueError("disclosure policy digest mismatch")
            runtime.require_policy("disclosure", policy_id, expected)
        except (TypeError, ValueError) as error:
            raise DisclosureError(str(error)) from error
        result = object.__new__(DisclosurePolicy)
        object.__setattr__(result, "policy_id", policy_id)
        object.__setattr__(result, "rules", MappingProxyType(rules))
        object.__setattr__(result, "policy_digest", expected)
        return result

    def resolve(self, destination_kind: str, trust_boundary: str) -> Mapping[str, object]:
        try:
            return self.rules[(destination_kind, trust_boundary)]
        except KeyError as error:
            raise DisclosureError("destination and trust boundary are not declared") from error


@dataclass(frozen=True, slots=True, init=False)
class DataDisclosurePlan:
    disclosure_id: str
    destination: Mapping[str, object]
    purpose: str
    data_refs: tuple[Mapping[str, object], ...]
    maximum_sensitivity: str
    field_allowlist: tuple[str, ...]
    redaction_transforms: tuple[Mapping[str, object], ...]
    retention_class: str
    authority_digest: str | None
    prepared_action_digest: str
    snapshot_digest: str
    payload_digest: str
    receipt_required: bool
    plan_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("DataDisclosurePlan must be loaded by its deterministic validator")

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return unsigned_digest(
            value,
            digest_field="plan_digest",
            contract_type="urn:gew:contract:data-disclosure-plan",
            schema_id=DISCLOSURE_PLAN_SCHEMA,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        policy: DisclosurePolicy,
        runtime: SecurityRuntimeManifest,
        task_context: TaskSecurityContext,
        redacted_payload: RedactedPayload,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> DataDisclosurePlan:
        if (
            type(policy) is not DisclosurePolicy
            or type(runtime) is not SecurityRuntimeManifest
            or type(task_context) is not TaskSecurityContext
            or type(redacted_payload) is not RedactedPayload
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise DisclosureError("disclosure validation context is invalid")
        try:
            require_runtime_context(runtime, task_context)
            runtime.require_policy("disclosure", policy.policy_id, policy.policy_digest)
        except SecurityAttestationError as error:
            raise DisclosureError(str(error)) from error
        if schema_registry.validate(DISCLOSURE_PLAN_SCHEMA, value, context):
            raise DisclosureError("disclosure plan schema validation failed")
        fields = {
            "schema_version",
            "disclosure_id",
            "destination",
            "purpose",
            "data_refs",
            "maximum_sensitivity",
            "field_allowlist",
            "redaction_transforms",
            "retention_class",
            "authority_digest",
            "prepared_action_digest",
            "snapshot_digest",
            "payload_digest",
            "receipt_required",
            "plan_digest",
        }
        try:
            exact_mapping(value, fields, "disclosure plan")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("disclosure plan version is invalid")
            disclosure_id = require_id(value.get("disclosure_id"), "disclosure ID")
            destination = exact_mapping(value.get("destination"), {"identity_ref", "kind", "trust_boundary"}, "destination")
            destination_identity = require_id(destination.get("identity_ref"), "destination identity")
            destination_kind = require_id(destination.get("kind"), "destination kind")
            boundary = require_id(destination.get("trust_boundary"), "trust boundary")
            expected_destination = task_context.destination(destination_identity)
            if (
                expected_destination.get("kind") != destination_kind
                or expected_destination.get("trust_boundary") != boundary
            ):
                raise ValueError("disclosure destination identity binding mismatch")
            rule = policy.resolve(destination_kind, boundary)
            purpose = require_id(value.get("purpose"), "disclosure purpose")
            if purpose not in rule["allowed_purposes"]:
                raise ValueError("disclosure purpose is not allowed")
            raw_refs = value.get("data_refs")
            if type(raw_refs) is not list or not raw_refs:
                raise ValueError("disclosure data refs are invalid")
            ref_ids = [item.get("ref_id") for item in raw_refs if isinstance(item, Mapping)]
            if ref_ids != sorted(set(ref_ids)):
                raise ValueError("disclosure data refs are not canonical")
            sensitivities: list[str] = []
            frozen_refs: list[Mapping[str, object]] = []
            for raw in raw_refs:
                exact_mapping(raw, {"ref_id", "digest", "sensitivity"}, "disclosure data ref")
                ref_id = require_id(raw.get("ref_id"), "data ref ID")
                ref_digest = require_digest(raw.get("digest"), "data ref digest")
                sensitivity = require_sensitivity(raw.get("sensitivity"))
                expected_ref = task_context.data_ref(ref_id)
                if (
                    ref_digest != require_digest(expected_ref.get("digest"), "expected data ref digest")
                    or sensitivity != require_sensitivity(expected_ref.get("sensitivity"))
                ):
                    raise ValueError("disclosure data ref authority binding mismatch")
                sensitivities.append(sensitivity)
                frozen_ref = freeze(raw)
                if not isinstance(frozen_ref, FrozenMap):
                    raise AssertionError("data ref did not freeze")
                frozen_refs.append(frozen_ref)
            maximum = require_sensitivity(value.get("maximum_sensitivity"))
            actual_maximum = max(sensitivities, key=sensitivity_rank)
            if maximum != actual_maximum or sensitivity_rank(maximum) > sensitivity_rank(str(rule["maximum_sensitivity"])) or maximum == "secret":
                raise ValueError("disclosure classification is not permitted")
            allowlist = require_canonical_strings(value.get("field_allowlist"), "disclosure field allowlist")
            if allowlist != redacted_payload.field_allowlist:
                raise ValueError("disclosure field allowlist does not bind the payload")
            raw_transforms = value.get("redaction_transforms")
            if type(raw_transforms) is not list:
                raise ValueError("redaction transforms are invalid")
            transform_entries: list[Mapping[str, object]] = []
            descriptions: list[str] = []
            for raw in raw_transforms:
                exact_mapping(raw, {"path", "transform"}, "redaction transform")
                path = raw.get("path")
                transform = raw.get("transform")
                if type(path) is not str or type(transform) is not str:
                    raise ValueError("redaction transform values are invalid")
                descriptions.append(f"{path}:{transform}")
                frozen_transform = freeze(raw)
                if not isinstance(frozen_transform, FrozenMap):
                    raise AssertionError("redaction transform did not freeze")
                transform_entries.append(frozen_transform)
            if tuple(descriptions) != redacted_payload.applied_transforms:
                raise ValueError("redaction transforms do not bind the payload")
            if rule["redaction_required"] is True and maximum in {"confidential", "secret"} and not descriptions:
                raise ValueError("required redaction is missing")
            retention_class = require_id(value.get("retention_class"), "retention class")
            if any(task_context.data_ref(ref_id).get("retention_class") != retention_class for ref_id in ref_ids):
                raise ValueError("disclosure retention class is not authoritative")
            snapshot_digest = require_digest(value.get("snapshot_digest"), "snapshot digest")
            action_digest = require_digest(value.get("prepared_action_digest"), "prepared action digest")
            payload_digest = require_digest(value.get("payload_digest"), "payload digest")
            if snapshot_digest != task_context.binding.snapshot_digest:
                raise ValueError("disclosure snapshot binding mismatch")
            if action_digest != require_digest(
                expected_destination.get("prepared_action_digest"),
                "attested prepared action digest",
            ):
                raise ValueError("disclosure action binding mismatch")
            if payload_digest != redacted_payload.payload_digest:
                raise ValueError("disclosure payload digest mismatch")
            authority = value.get("authority_digest")
            if rule["authority_required"] is True:
                authority = require_digest(authority, "authority digest")
                if authority not in task_context.authority_digests:
                    raise ValueError("disclosure authority binding mismatch")
            elif authority is not None:
                raise ValueError("unneeded disclosure authority is not accepted")
            receipt_required = value.get("receipt_required")
            if type(receipt_required) is not bool or receipt_required is not rule["receipt_required"]:
                raise ValueError("disclosure receipt policy mismatch")
            expected_plan_digest = require_digest(value.get("plan_digest"), "plan digest")
            actual_plan_digest = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "plan_digest"},
                context,
                contract_type="urn:gew:contract:data-disclosure-plan",
                projection_id=IDENTITY_PROJECTION,
                schema_id=DISCLOSURE_PLAN_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected_plan_digest, actual_plan_digest):
                raise ValueError("disclosure plan digest mismatch")
        except (SecurityAttestationError, TypeError, ValueError) as error:
            if isinstance(error, DisclosureError):
                raise
            raise DisclosureError(str(error)) from error
        frozen_destination = freeze(destination)
        if not isinstance(frozen_destination, FrozenMap):
            raise AssertionError("destination did not freeze")
        result = object.__new__(DataDisclosurePlan)
        for name, item in (
            ("disclosure_id", disclosure_id),
            ("destination", frozen_destination),
            ("purpose", purpose),
            ("data_refs", tuple(frozen_refs)),
            ("maximum_sensitivity", maximum),
            ("field_allowlist", allowlist),
            ("redaction_transforms", tuple(transform_entries)),
            ("retention_class", retention_class),
            ("authority_digest", authority),
            ("prepared_action_digest", action_digest),
            ("snapshot_digest", snapshot_digest),
            ("payload_digest", payload_digest),
            ("receipt_required", receipt_required),
            ("plan_digest", expected_plan_digest),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class DisclosureReceipt:
    receipt_id: str
    plan_digest: str
    payload_digest: str
    destination_identity_ref: str
    occurred_at: str
    result: str
    target_receipt_digest: str
    receipt_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("DisclosureReceipt must be loaded by its deterministic validator")

    @staticmethod
    def document(
        *,
        receipt_id: str,
        plan: DataDisclosurePlan,
        occurred_at: str,
        result: str,
        target_receipt_digest: str,
    ) -> dict[str, object]:
        del receipt_id, plan, occurred_at, result, target_receipt_digest
        raise DisclosureError("disclosure receipts are minted only by the adapter action journal")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        plan: DataDisclosurePlan,
        runtime: SecurityRuntimeManifest,
        task_context: TaskSecurityContext,
        journal_attestation: DisclosureJournalAttestation,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> DisclosureReceipt:
        from graph_engineering.core.security._common import parse_timestamp

        if (
            type(plan) is not DataDisclosurePlan
            or type(runtime) is not SecurityRuntimeManifest
            or type(task_context) is not TaskSecurityContext
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise DisclosureError("disclosure receipt context is invalid")
        try:
            require_runtime_context(runtime, task_context)
            require_journal_context(runtime, journal_attestation)
        except SecurityAttestationError as error:
            raise DisclosureError(str(error)) from error
        if schema_registry.validate(DISCLOSURE_RECEIPT_SCHEMA, value, context):
            raise DisclosureError("disclosure receipt schema validation failed")
        fields = {"schema_version", "receipt_id", "plan_digest", "payload_digest", "destination_identity_ref", "occurred_at", "result", "target_receipt_digest", "receipt_digest"}
        try:
            exact_mapping(value, fields, "disclosure receipt")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("disclosure receipt version is invalid")
            receipt_id = require_id(value.get("receipt_id"), "receipt ID")
            plan_digest = require_digest(value.get("plan_digest"), "plan digest")
            payload_digest = require_digest(value.get("payload_digest"), "payload digest")
            destination = require_id(value.get("destination_identity_ref"), "destination identity")
            occurred_at = value.get("occurred_at")
            parse_timestamp(occurred_at, "receipt timestamp")
            outcome = value.get("result")
            target_digest = require_digest(value.get("target_receipt_digest"), "target receipt digest")
            expected = require_digest(value.get("receipt_digest"), "receipt digest")
            if dict(journal_attestation.receipt) != dict(value):
                raise ValueError("disclosure receipt was not issued by the bound action journal")
            if (
                journal_attestation.task_id != task_context.binding.task_id
                or journal_attestation.prepared_action_digest != plan.prepared_action_digest
                or journal_attestation.task_snapshot_digest != task_context.binding.snapshot_digest
            ):
                raise ValueError("disclosure journal action or task binding mismatch")
            if outcome not in {"delivered", "failed", "unknown"}:
                raise ValueError("disclosure receipt outcome is invalid")
            if plan_digest != plan.plan_digest or payload_digest != plan.payload_digest or destination != plan.destination["identity_ref"]:
                raise ValueError("disclosure receipt binding mismatch")
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "receipt_digest"},
                context,
                contract_type="urn:gew:contract:disclosure-receipt",
                projection_id=IDENTITY_PROJECTION,
                schema_id=DISCLOSURE_RECEIPT_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected, actual):
                raise ValueError("disclosure receipt digest mismatch")
        except (SecurityAttestationError, TypeError, ValueError) as error:
            raise DisclosureError(str(error)) from error
        result = object.__new__(DisclosureReceipt)
        for name, item in (
            ("receipt_id", receipt_id),
            ("plan_digest", plan_digest),
            ("payload_digest", payload_digest),
            ("destination_identity_ref", destination),
            ("occurred_at", occurred_at),
            ("result", outcome),
            ("target_receipt_digest", target_digest),
            ("receipt_digest", expected),
        ):
            object.__setattr__(result, name, item)
        return result
