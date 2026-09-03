"""Fresh, provenance-bound, review-aware evidence records."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    TRUST_LEVELS,
    exact_mapping,
    parse_timestamp,
    require_digest,
    require_id,
    require_sensitivity,
    require_trust,
    sensitivity_rank,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import (
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TaskSecurityContext,
    require_runtime_context,
)
from graph_engineering.core.security.privacy import LeakageIncident


EVIDENCE_RECORD_SCHEMA = "urn:gew:schema:evidence-record:1.0.0"
EVIDENCE_POLICY_SCHEMA = "urn:gew:schema:evidence-policy-registry:1.0.0"


class EvidenceError(ValueError):
    """Evidence is stale, untrusted, unbound, or structurally invalid."""


@dataclass(frozen=True, slots=True, init=False)
class EvidencePolicyRegistry:
    registry_id: str
    policies: Mapping[str, Mapping[str, object]]
    registry_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EvidencePolicyRegistry must be loaded from validated configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> EvidencePolicyRegistry:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
        ):
            raise EvidenceError("evidence policy requires attested contracts")
        if schema_registry.validate(EVIDENCE_POLICY_SCHEMA, value, context):
            raise EvidenceError("evidence policy schema validation failed")
        try:
            exact_mapping(value, {"schema_version", "registry_id", "policies", "registry_digest"}, "evidence policy registry")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("evidence policy version is invalid")
            registry_id = require_id(value.get("registry_id"), "evidence registry ID")
            expected = require_digest(value.get("registry_digest"), "evidence registry digest")
            raw_policies = value.get("policies")
            if type(raw_policies) is not list or not raw_policies:
                raise ValueError("evidence policies are invalid")
            evidence_types = [item.get("evidence_type") for item in raw_policies if isinstance(item, Mapping)]
            if evidence_types != sorted(set(evidence_types)):
                raise ValueError("evidence policies are not canonical")
            policies: dict[str, Mapping[str, object]] = {}
            for raw in raw_policies:
                exact_mapping(raw, {"evidence_type", "maximum_freshness_seconds", "minimum_trust", "maximum_sensitivity"}, "evidence policy")
                evidence_type = require_id(raw.get("evidence_type"), "evidence type")
                maximum_freshness = raw.get("maximum_freshness_seconds")
                require_trust(raw.get("minimum_trust"))
                require_sensitivity(raw.get("maximum_sensitivity"))
                if type(maximum_freshness) is not int or maximum_freshness < 0:
                    raise ValueError("evidence freshness policy is invalid")
                frozen = freeze(raw)
                if not isinstance(frozen, FrozenMap):
                    raise AssertionError("evidence policy did not freeze")
                policies[evidence_type] = frozen
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "registry_digest"},
                context,
                contract_type="urn:gew:contract:evidence-policy-registry",
                projection_id=IDENTITY_PROJECTION,
                schema_id=EVIDENCE_POLICY_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected, actual):
                raise ValueError("evidence policy digest mismatch")
            runtime.require_policy("evidence", registry_id, expected)
        except (TypeError, ValueError) as error:
            raise EvidenceError(str(error)) from error
        result = object.__new__(EvidencePolicyRegistry)
        object.__setattr__(result, "registry_id", registry_id)
        object.__setattr__(result, "policies", MappingProxyType(policies))
        object.__setattr__(result, "registry_digest", expected)
        return result

    def resolve(self, evidence_type: str) -> Mapping[str, object]:
        try:
            return self.policies[evidence_type]
        except KeyError as error:
            raise EvidenceError("unknown evidence type") from error


@dataclass(frozen=True, slots=True, init=False)
class EvidenceRecord:
    body: Mapping[str, object]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("EvidenceRecord must be loaded by EvidenceValidator")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("EvidenceRecord is final")

    @property
    def evidence_id(self) -> str:
        return self.body["evidence_id"]  # type: ignore[return-value]

    @property
    def trust(self) -> str:
        return self.body["trust"]  # type: ignore[return-value]

    @property
    def status(self) -> str:
        return self.body["status"]  # type: ignore[return-value]

    @property
    def record_digest(self) -> str:
        return self.body["record_digest"]  # type: ignore[return-value]

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return unsigned_digest(
            value,
            digest_field="record_digest",
            contract_type="urn:gew:contract:evidence-record",
            schema_id=EVIDENCE_RECORD_SCHEMA,
        )

    def as_dict(self) -> dict[str, object]:
        value = thaw(self.body)
        if type(value) is not dict:
            raise AssertionError("evidence body is not an object")
        return value

    @classmethod
    def quarantine(
        cls,
        record: EvidenceRecord,
        incident: LeakageIncident,
        *,
        context: WorkContext,
    ) -> EvidenceRecord:
        if type(record) is not EvidenceRecord or type(incident) is not LeakageIncident or type(context) is not WorkContext:
            raise EvidenceError("evidence quarantine context is invalid")
        body = record.as_dict()
        if incident.suspect_digest not in {body["content_digest"], body["record_digest"]}:
            raise EvidenceError("incident does not bind the evidence")
        body["trust"] = "untrusted"
        body["status"] = "quarantined"
        body["record_digest"] = semantic_digest_charged(
            {key: item for key, item in body.items() if key != "record_digest"},
            context,
            contract_type="urn:gew:contract:evidence-record",
            projection_id=IDENTITY_PROJECTION,
            schema_id=EVIDENCE_RECORD_SCHEMA,
            operation_path=context.child_path(()),
        )
        frozen = freeze(body)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("quarantined evidence did not freeze")
        result = object.__new__(EvidenceRecord)
        object.__setattr__(result, "body", frozen)
        return result


class EvidenceValidator:
    @staticmethod
    def load(
        value: Mapping[str, object],
        *,
        runtime: SecurityRuntimeManifest,
        task_context: TaskSecurityContext,
        policy_registry: EvidencePolicyRegistry,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> EvidenceRecord:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
            or type(task_context) is not TaskSecurityContext
            or type(policy_registry) is not EvidencePolicyRegistry
        ):
            raise EvidenceError("evidence validation requires attested contracts")
        try:
            require_runtime_context(runtime, task_context)
            runtime.require_policy(
                "evidence",
                policy_registry.registry_id,
                policy_registry.registry_digest,
            )
        except SecurityAttestationError as error:
            raise EvidenceError(str(error)) from error
        if schema_registry.validate(EVIDENCE_RECORD_SCHEMA, value, context):
            raise EvidenceError("evidence schema validation failed")
        fields = {
            "schema_version",
            "evidence_id",
            "evidence_type",
            "task_id",
            "source_ref",
            "collection_action_digest",
            "target_refs",
            "collected_at",
            "result",
            "producer_id",
            "baseline_digest",
            "snapshot_digest",
            "fresh_until",
            "sensitivity",
            "redaction",
            "content_digest",
            "provenance",
            "trust",
            "status",
            "record_digest",
        }
        try:
            exact_mapping(value, fields, "evidence record")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("evidence schema version is invalid")
            evidence_id = require_id(value.get("evidence_id"), "evidence ID")
            expected = task_context.evidence_expectation(evidence_id)
            evidence_type = require_id(value.get("evidence_type"), "evidence type")
            if evidence_type != require_id(expected.get("evidence_type"), "attested evidence type"):
                raise ValueError("evidence type binding mismatch")
            policy = policy_registry.resolve(evidence_type)
            task_id = require_id(value.get("task_id"), "task ID")
            source_ref = require_id(value.get("source_ref"), "evidence source")
            collection_action_digest = require_digest(value.get("collection_action_digest"), "collection action digest")
            if source_ref != require_id(expected.get("source_ref"), "attested evidence source"):
                raise ValueError("evidence source binding mismatch")
            if collection_action_digest != require_digest(
                expected.get("collection_action_digest"),
                "attested collection action digest",
            ):
                raise ValueError("evidence collection action binding mismatch")
            producer_id = require_id(value.get("producer_id"), "evidence producer")
            baseline_digest = require_digest(value.get("baseline_digest"), "baseline digest")
            snapshot_digest = require_digest(value.get("snapshot_digest"), "snapshot digest")
            content_digest = require_digest(value.get("content_digest"), "content digest")
            if content_digest != require_digest(expected.get("content_digest"), "attested content digest"):
                raise ValueError("evidence content binding mismatch")
            expected_record_digest = require_digest(value.get("record_digest"), "record digest")
            if task_id != task_context.binding.task_id or task_id != require_id(
                expected.get("task_id"),
                "attested task ID",
            ):
                raise ValueError("evidence task binding mismatch")
            if baseline_digest != require_digest(expected.get("baseline_digest"), "attested baseline digest"):
                raise ValueError("evidence baseline binding mismatch")
            if (
                snapshot_digest != task_context.binding.snapshot_digest
                or snapshot_digest != require_digest(expected.get("snapshot_digest"), "attested snapshot digest")
            ):
                raise ValueError("evidence snapshot binding mismatch")
            expected_target_digests = expected.get("target_digests")
            if not isinstance(expected_target_digests, Mapping) or not expected_target_digests:
                raise ValueError("expected target bindings are invalid")
            raw_targets = value.get("target_refs")
            if type(raw_targets) is not list or not raw_targets:
                raise ValueError("evidence target refs are invalid")
            target_ids = [item.get("target_id") for item in raw_targets if isinstance(item, Mapping)]
            if target_ids != sorted(set(target_ids)) or set(target_ids) != set(expected_target_digests):
                raise ValueError("evidence target set mismatch")
            for raw in raw_targets:
                exact_mapping(raw, {"target_id", "target_digest"}, "evidence target ref")
                target_id = require_id(raw.get("target_id"), "target ID")
                target_digest = require_digest(raw.get("target_digest"), "target digest")
                if target_digest != require_digest(expected_target_digests[target_id], "expected target digest"):
                    raise ValueError("evidence target digest mismatch")
            collected = parse_timestamp(value.get("collected_at"), "collection timestamp")
            fresh_until = parse_timestamp(value.get("fresh_until"), "freshness timestamp")
            now = parse_timestamp(task_context.current_time, "attested current timestamp")
            if collected > now or fresh_until < collected or now > fresh_until:
                raise ValueError("evidence is stale or temporally invalid")
            if int((fresh_until - collected).total_seconds()) > int(policy["maximum_freshness_seconds"]):
                raise ValueError("evidence freshness exceeds its policy")
            if value.get("result") not in {"PASS", "FAIL", "UNKNOWN"} or value.get("result") != expected.get("result"):
                raise ValueError("evidence result is invalid")
            sensitivity = require_sensitivity(value.get("sensitivity"))
            if sensitivity != require_sensitivity(expected.get("sensitivity")):
                raise ValueError("evidence classification does not match authoritative metadata")
            if sensitivity == "secret" or sensitivity_rank(sensitivity) > sensitivity_rank(str(policy["maximum_sensitivity"])):
                raise ValueError("secret evidence bodies cannot be persisted")
            redaction = exact_mapping(value.get("redaction"), {"status", "transforms"}, "evidence redaction")
            redaction_status = redaction.get("status")
            transforms = redaction.get("transforms")
            if redaction_status not in {"applied", "not-required"} or type(transforms) is not list or transforms != sorted(set(transforms)):
                raise ValueError("evidence redaction metadata is invalid")
            if sensitivity in {"internal", "confidential"} and redaction_status != "applied":
                raise ValueError("sensitive evidence is not redacted")
            expected_redaction = exact_mapping(
                expected.get("redaction"),
                {"status", "transforms"},
                "attested evidence redaction",
            )
            if (
                redaction_status != expected_redaction.get("status")
                or tuple(transforms) != tuple(expected_redaction.get("transforms", ()))
            ):
                raise ValueError("evidence redaction does not match its redaction receipt")
            provenance = value.get("provenance")
            if type(provenance) is not list or not provenance or provenance != sorted(set(provenance)):
                raise ValueError("evidence provenance is not canonical")
            for digest in provenance:
                require_digest(digest, "provenance digest")
            expected_provenance = expected.get("provenance")
            if type(expected_provenance) not in (list, tuple) or list(expected_provenance) != provenance:
                raise ValueError("evidence provenance does not match authoritative objects")
            trust = require_trust(value.get("trust"))
            required_trust = require_trust(policy["minimum_trust"])
            if TRUST_LEVELS.index(trust) < TRUST_LEVELS.index(required_trust):
                raise ValueError("evidence trust is insufficient")
            if producer_id != require_id(expected.get("producer_id"), "attested producer ID"):
                raise ValueError("evidence producer does not match its collection receipt")
            if trust != require_trust(expected.get("trust")):
                raise ValueError("evidence trust does not match its review receipt")
            author_id = require_id(expected.get("author_id"), "attested author ID")
            review_receipt = require_digest(
                expected.get("review_receipt_digest"),
                "attested review receipt digest",
            )
            if trust == "independently-reviewed" and (
                producer_id.casefold() == author_id.casefold()
                or review_receipt not in provenance
            ):
                raise ValueError("evidence independent review receipt is invalid")
            if value.get("status") != "valid":
                raise ValueError("invalidated or quarantined evidence cannot be consumed")
            actual_record_digest = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "record_digest"},
                context,
                contract_type="urn:gew:contract:evidence-record",
                projection_id=IDENTITY_PROJECTION,
                schema_id=EVIDENCE_RECORD_SCHEMA,
                operation_path=context.child_path(()),
            )
            if not hmac.compare_digest(expected_record_digest, actual_record_digest):
                raise ValueError("evidence record digest mismatch")
            del source_ref, content_digest
        except (SecurityAttestationError, TypeError, ValueError, KeyError) as error:
            raise EvidenceError(str(error)) from error
        frozen = freeze(value)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("evidence record did not freeze")
        result = object.__new__(EvidenceRecord)
        object.__setattr__(result, "body", frozen)
        return result
