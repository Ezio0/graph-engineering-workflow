"""Test-only builders for exact WP-08A trust reducer operations."""

from __future__ import annotations

import copy
from collections.abc import Mapping

from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.security.extensions import (
    ExtensionTrustOperation,
    ExtensionTrustPolicy,
    ExtensionTrustPolicyReducer,
)


def _digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def operations_for_candidate(
    current: ExtensionTrustPolicy,
    candidate: ExtensionTrustPolicy,
) -> tuple[ExtensionTrustOperation, ...]:
    kinds = {
        "trust_keys": ("add-key", "rotate-key", "retire-key"),
        "production_policies": (
            "register-production-policy", "register-production-policy",
            "retire-production-policy",
        ),
        "source_rules": ("set-source-rule", "set-source-rule", "set-source-rule"),
        "namespace_rules": ("set-namespace-rule",) * 3,
        "extension_kind_rules": ("set-extension-kind-rule",) * 3,
        "capability_ceilings": ("set-capability-ceiling",) * 3,
        "compatibility_floors": ("set-compatibility-floor",) * 3,
        "revocations": (
            "apply-local-revocation", "apply-local-revocation", "apply-local-revocation",
        ),
    }
    documents: list[dict[str, object]] = []
    old_body = current.to_dict()
    new_body = candidate.to_dict()
    for field, operation_kinds in kinds.items():
        old_records = {
            ExtensionTrustPolicyReducer._identity(field, item): item
            for item in old_body[field]
        }
        new_records = {
            ExtensionTrustPolicyReducer._identity(field, item): item
            for item in new_body[field]
        }
        for target in sorted(set(old_records) | set(new_records)):
            old = old_records.get(target)
            new = new_records.get(target)
            if old == new or new is None:
                continue
            if old is None:
                kind = operation_kinds[0]
            elif new.get("status") == "retired":
                kind = operation_kinds[2]
            else:
                kind = operation_kinds[1]
            if field == "revocations" and new.get("input_kind") == "publisher-revocation":
                kind = "apply-publisher-revocation"
            body: dict[str, object] = {
                "schema_version": "1.0.0",
                "operation_id": f"operation.{len(documents) + 1}",
                "operation_kind": kind,
                "expected_policy_digest": current.policy_digest,
                "target_identity": target,
                "expected_old": copy.deepcopy(old),
                "new_value": copy.deepcopy(new),
            }
            body["operation_digest"] = _digest(body, "extension-trust-operation")
            documents.append(body)
    operations = tuple(
        sorted(
            (ExtensionTrustOperation.from_dict(item) for item in documents),
            key=lambda item: item.operation_digest,
        )
    )
    if not operations:
        raise ValueError("test candidate has no reducer operation")
    return operations
def authorize_operations(
    authorization: Mapping[str, object],
    operations: tuple[ExtensionTrustOperation, ...],
) -> dict[str, object]:
    result = dict(authorization)
    result["ordered_operations_digest"] = _digest(
        {
            "schema_version": "1.0.0",
            "operations": [item.to_dict() for item in operations],
        },
        "extension-trust-ordered-operations",
    )
    operation_documents = [item.to_dict() for item in operations]
    decision: dict[str, object] = {
        "schema_version": "1.0.0",
        "decision_id": f"decision.{result['transaction_id']}",
        "owner_identity": result["owner_identity"],
        "operation_digests": [item.operation_digest for item in operations],
        "expansion_targets": ExtensionTrustPolicyReducer.expansion_targets(operations),
    }
    decision["decision_digest"] = _digest(decision, "extension-trust-owner-decision")
    envelope: dict[str, object] = {
        "schema_version": "1.0.0",
        "envelope_id": f"envelope.{result['transaction_id']}",
        "owner_identity": result["owner_identity"],
        "allowed_operation_kinds": sorted(
            {str(item["operation_kind"]) for item in operation_documents}
        ),
        "allowed_target_identities": sorted(
            {str(item["target_identity"]) for item in operation_documents}
        ),
    }
    envelope["envelope_digest"] = _digest(envelope, "extension-trust-authority-envelope")
    result["owner_decision"] = decision
    result["authority_envelope"] = envelope
    result["owner_decision_digest"] = decision["decision_digest"]
    result["owner_authority_digest"] = envelope["envelope_digest"]
    return result
