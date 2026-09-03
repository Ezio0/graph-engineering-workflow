"""Opaque security-runtime and repository-state attestations.

Public validators consume these objects instead of trusting caller-supplied
identity, clock, producer, disclosure, or retention assertions.  The private
issuance functions are the application/storage adapter boundary; they are not
part of the public security API.
"""

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
    parse_timestamp,
    require_canonical_strings,
    require_digest,
    require_id,
    unsigned_digest,
)


RUNTIME_MANIFEST_SCHEMA_ID = "urn:gew:schema:security-runtime-manifest:1.0.0"
RUNTIME_MANIFEST_CONTRACT_ID = "urn:gew:contract:security-runtime-manifest"
TASK_CONTEXT_SCHEMA = "urn:gew:schema:task-security-context:1.0.0"
POLICY_KINDS = (
    "action",
    "disclosure",
    "evidence",
    "input-safety",
    "redaction",
    "retention",
)


class SecurityAttestationError(ValueError):
    """An installed runtime or durable-state attestation is invalid."""


@dataclass(frozen=True, slots=True, init=False)
class SecurityRuntimeManifest:
    """Installed, digest-pinned trust root for the security policy set."""

    manifest_id: str
    manifest_digest: str
    schema_registry_id: str
    schema_registry_digest: str
    allowed_runtime_kinds: tuple[str, ...]
    policies: Mapping[str, Mapping[str, str]]
    _issuer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SecurityRuntimeManifest must be loaded by trusted bootstrap")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SecurityRuntimeManifest is final")

    @staticmethod
    def digest_document(value: Mapping[str, object]) -> str:
        return unsigned_digest(
            value,
            digest_field="manifest_digest",
            contract_type=RUNTIME_MANIFEST_CONTRACT_ID,
            schema_id=RUNTIME_MANIFEST_SCHEMA_ID,
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        expected_manifest_id: str,
        expected_manifest_digest: str,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> SecurityRuntimeManifest:
        """Reject caller-selected trust pins at the core boundary."""

        del cls, value, expected_manifest_id, expected_manifest_digest, schema_registry, context
        raise SecurityAttestationError(
            "security runtime is loaded only from the durable installation record",
        )

    def require_policy(self, kind: str, policy_id: str, policy_digest: str) -> None:
        try:
            expected = self.policies[kind]
        except KeyError as error:
            raise SecurityAttestationError("unknown security policy kind") from error
        if (
            policy_id != expected["policy_id"]
            or not hmac.compare_digest(policy_digest, expected["policy_digest"])
        ):
            raise SecurityAttestationError("security policy does not match the installed runtime")


def validate_installed_runtime_document(
    value: Mapping[str, object],
    *,
    expected_manifest_id: str,
    expected_manifest_digest: str,
    schema_registry: ClosedSchemaRegistry,
    context: WorkContext,
) -> Mapping[str, object]:
    """Validate an installation-owned record without minting a trust object."""

    if type(schema_registry) is not ClosedSchemaRegistry or type(context) is not WorkContext:
        raise SecurityAttestationError("security runtime requires attested contracts")
    if schema_registry.validate(RUNTIME_MANIFEST_SCHEMA_ID, value, context):
        raise SecurityAttestationError("security runtime schema validation failed")
    try:
        exact_mapping(
            value,
            {
                "schema_version",
                "manifest_id",
                "schema_registry",
                "allowed_runtime_kinds",
                "policies",
                "manifest_digest",
            },
            "security runtime",
        )
        if value.get("schema_version") != "1.0.0":
            raise ValueError("security runtime version is invalid")
        manifest_id = require_id(value.get("manifest_id"), "security runtime ID")
        declared_digest = require_digest(value.get("manifest_digest"), "security runtime digest")
        if manifest_id != require_id(expected_manifest_id, "expected security runtime ID"):
            raise ValueError("security runtime ID does not match its installed pin")
        if not hmac.compare_digest(
            declared_digest,
            require_digest(expected_manifest_digest, "expected security runtime digest"),
        ):
            raise ValueError("security runtime digest does not match its installed pin")
        registry = exact_mapping(
            value.get("schema_registry"),
            {"registry_id", "registry_digest"},
            "security schema registry pin",
        )
        registry_id = require_id(registry.get("registry_id"), "security schema registry ID")
        registry_digest = require_digest(
            registry.get("registry_digest"),
            "security schema registry digest",
        )
        if (
            registry_id != schema_registry.registry_id
            or not hmac.compare_digest(registry_digest, schema_registry.registry_digest)
        ):
            raise ValueError("security schema registry does not match the installed runtime")
        allowed = require_canonical_strings(
            value.get("allowed_runtime_kinds"),
            "allowed runtime kinds",
            ids=True,
        )
        raw_policies = value.get("policies")
        if not isinstance(raw_policies, Mapping) or tuple(sorted(raw_policies)) != POLICY_KINDS:
            raise ValueError("security runtime policy set is not exact")
        policies: dict[str, Mapping[str, str]] = {}
        for kind in POLICY_KINDS:
            policy = exact_mapping(
                raw_policies[kind],
                {"policy_id", "policy_digest"},
                f"{kind} policy pin",
            )
            policies[kind] = MappingProxyType({
                "policy_id": require_id(policy.get("policy_id"), f"{kind} policy ID"),
                "policy_digest": require_digest(
                    policy.get("policy_digest"),
                    f"{kind} policy digest",
                ),
            })
        actual_digest = semantic_digest_charged(
            {key: item for key, item in value.items() if key != "manifest_digest"},
            context,
            contract_type=RUNTIME_MANIFEST_CONTRACT_ID,
            projection_id=IDENTITY_PROJECTION,
            schema_id=RUNTIME_MANIFEST_SCHEMA_ID,
            operation_path=context.child_path(()),
        )
        if not hmac.compare_digest(declared_digest, actual_digest):
            raise ValueError("security runtime manifest digest mismatch")
    except (KeyError, TypeError, ValueError) as error:
        raise SecurityAttestationError(str(error)) from error
    return MappingProxyType({
        "manifest_id": manifest_id,
        "manifest_digest": declared_digest,
        "schema_registry_id": registry_id,
        "schema_registry_digest": registry_digest,
        "allowed_runtime_kinds": allowed,
        "policies": MappingProxyType(policies),
    })


@dataclass(frozen=True, slots=True, init=False)
class TaskSecurityContext:
    """Repository/capability-issued immutable state used by security gates."""

    runtime_manifest_digest: str
    binding: object
    current_time: str
    destinations: Mapping[str, Mapping[str, object]]
    authority_digests: tuple[str, ...]
    data_refs: Mapping[str, Mapping[str, object]]
    evidence_expectations: Mapping[str, Mapping[str, object]]
    retention_subjects: Mapping[str, Mapping[str, object]]
    state_digest: str
    context_digest: str
    _issuer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("TaskSecurityContext is issued only from current durable state")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("TaskSecurityContext is final")

    def destination(self, identity_ref: str) -> Mapping[str, object]:
        try:
            return self.destinations[identity_ref]
        except KeyError as error:
            raise SecurityAttestationError("destination identity is not authorized") from error

    def data_ref(self, ref_id: str) -> Mapping[str, object]:
        try:
            return self.data_refs[ref_id]
        except KeyError as error:
            raise SecurityAttestationError("data ref is not authoritative") from error

    def evidence_expectation(self, evidence_id: str) -> Mapping[str, object]:
        try:
            return self.evidence_expectations[evidence_id]
        except KeyError as error:
            raise SecurityAttestationError("evidence collection is not attested") from error

    def retention_subject(self, subject_ref: str) -> Mapping[str, object]:
        try:
            return self.retention_subjects[subject_ref]
        except KeyError as error:
            raise SecurityAttestationError("retention subject is not attested") from error


@dataclass(frozen=True, slots=True, init=False)
class DisclosureJournalAttestation:
    """Adapter/action-journal-issued receipt binding for one concrete call."""

    runtime_manifest_digest: str
    task_id: str
    action_id: str
    prepared_action_digest: str
    task_snapshot_digest: str
    reconciliation_digest: str
    journal_entry_digest: str
    receipt: Mapping[str, object]
    receipt_digest: str
    _issuer: object

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("DisclosureJournalAttestation is issued only by the action journal")


def _canonical_frozen_map(value: Mapping[str, object], label: str) -> FrozenMap:
    if any(type(key) is not str or not key for key in value):
        raise SecurityAttestationError(f"{label} keys are invalid")
    frozen = freeze(value)
    if not isinstance(frozen, FrozenMap):
        raise AssertionError(f"{label} did not freeze")
    return frozen


def require_runtime_context(
    runtime: SecurityRuntimeManifest,
    task_context: TaskSecurityContext,
) -> None:
    if type(runtime) is not SecurityRuntimeManifest or type(task_context) is not TaskSecurityContext:
        raise SecurityAttestationError("security runtime context is invalid")
    if (
        task_context._issuer is not runtime._issuer
        or not hmac.compare_digest(task_context.runtime_manifest_digest, runtime.manifest_digest)
    ):
        raise SecurityAttestationError("task security context belongs to another runtime")


def require_journal_context(
    runtime: SecurityRuntimeManifest,
    attestation: DisclosureJournalAttestation,
) -> None:
    if type(attestation) is not DisclosureJournalAttestation:
        raise SecurityAttestationError("disclosure journal attestation is invalid")
    if (
        attestation._issuer is not runtime._issuer
        or not hmac.compare_digest(attestation.runtime_manifest_digest, runtime.manifest_digest)
    ):
        raise SecurityAttestationError("disclosure journal attestation belongs to another runtime")
