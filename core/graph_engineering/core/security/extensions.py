"""Closed extension contracts and the ADR-0003 executable fail-closed gate."""

from __future__ import annotations

import hmac
import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import NoReturn

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import RAW_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.extensions import Ed25519VerificationRequest
from graph_engineering.core.security._common import (
    exact_mapping,
    require_digest,
    require_id,
    parse_timestamp,
)


class ExtensionError(ValueError):
    """An extension is executable, untrusted, or not in the closed built-in set."""


EXTENSION_ATTESTATION_CHRONOLOGY = (
    "source.issued_at",
    "build.started_at",
    "build.finished_at",
    "ingest.verified_at",
)


_IDENTITY_BODY_FIELDS = (
    "schema_version",
    "publisher_id",
    "extension_id",
    "extension_version",
    "release_id",
    "package_class",
    "extension_points",
    "exported_identities",
    "input_schema_ids",
    "output_schema_ids",
    "contract_registry_digest",
    "compatibility",
    "requested_capabilities",
    "operation_classes",
    "ordered_resources",
    "side_effects",
    "idempotency_semantics",
    "failure_semantics",
    "verification_semantics",
    "executable_contract",
)

_TRUST_ARRAY_FIELDS: Mapping[str, tuple[str, ...]] = {
    "revocations": (
        "target_kind",
        "target_identity_digest",
        "input_kind",
        "input_digest",
        "reason_code",
        "local_sequence",
        "effective_generation",
        "owner_decision_digest",
    ),
    "trust_keys": (
        "publisher_id",
        "key_id",
        "ed25519_public_key",
        "roles",
        "source_classes",
        "namespaces",
        "extension_kinds",
        "allowed_production_policy_digests",
        "capability_ceiling_digest",
        "not_before",
        "not_after",
        "status",
        "added_generation",
        "revocation_sequence",
    ),
    "production_policies": ("policy_id", "policy_digest", "issuer_id", "status", "added_generation"),
    "source_rules": ("source_type", "allowed_source_ids", "required_material_kinds", "rule_mode"),
    "namespace_rules": ("publisher_id", "namespace_prefix", "allowed_extension_kinds"),
    "extension_kind_rules": (
        "extension_kind",
        "data_allowed",
        "executable_allowed",
        "required_isolation_profiles",
    ),
    "capability_ceilings": (
        "subject_kind", "subject_id", "capability_ids", "capability_set_digest",
    ),
    "compatibility_floors": ("component_kind", "compatibility_policy_digest"),
}


def _require_string(value: object, label: str, *, maximum: int = 512) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _require_nonnegative_integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} is invalid")
    return value


def _require_version(value: object, label: str) -> str:
    return _require_string(value, label, maximum=64)


def _require_canonical_array(value: object, label: str) -> Sequence[object]:
    if type(value) not in (list, tuple):
        raise ValueError(f"{label} must be an array")
    encoded = [canonical_bytes(item) for item in value]
    if encoded != sorted(set(encoded)):
        raise ValueError(f"{label} is not canonical")
    return value


def _require_string_set(value: object, label: str) -> tuple[str, ...]:
    items = _require_canonical_array(value, label)
    if any(type(item) is not str or not item for item in items):
        raise ValueError(f"{label} is invalid")
    return tuple(items)  # type: ignore[arg-type]


def _require_records(
    value: object,
    fields: tuple[str, ...],
    label: str,
) -> tuple[Mapping[str, object], ...]:
    items = _require_canonical_array(value, label)
    records: list[Mapping[str, object]] = []
    for item in items:
        record = exact_mapping(item, set(fields), f"{label} item")
        records.append(record)
    return tuple(records)


def _verify_self_digest(
    value: Mapping[str, object],
    *,
    fields: set[str],
    digest_field: str,
    contract_name: str,
) -> FrozenMap:
    exact_mapping(value, fields, contract_name)
    frozen = freeze(value)
    if not isinstance(frozen, FrozenMap):
        raise TypeError(f"{contract_name} must be an object")
    complete = thaw(frozen)
    assert isinstance(complete, dict)
    expected = require_digest(complete.pop(digest_field, None), digest_field)
    actual = semantic_digest(
        freeze(complete),
        contract_type=f"urn:gew:contract:{contract_name}",
        projection_id=f"urn:gew:digest-projection:{contract_name}:1.0.0",
        schema_id=f"urn:gew:schema:{contract_name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise ValueError(f"{contract_name} self digest mismatch")
    return frozen


def extension_capability_set_digest(
    subject_kind: object, subject_id: object, capability_ids: object,
) -> str:
    kind = require_id(subject_kind, "capability subject kind")
    identity = require_id(subject_id, "capability subject ID")
    capabilities = _require_string_set(capability_ids, "capability IDs")
    for capability in capabilities:
        require_id(capability, "capability ID")
    return semantic_digest(
        {
            "schema_version": "1.0.0",
            "subject_kind": kind,
            "subject_id": identity,
            "capability_ids": list(capabilities),
        },
        contract_type="urn:gew:contract:extension-capability-set",
        projection_id="urn:gew:digest-projection:extension-capability-set:1.0.0",
        schema_id="urn:gew:schema:extension-capability-set-input:1.0.0",
    )


def _validate_trust_record(
    field: str,
    record: Mapping[str, object],
    *,
    generation: int | None = None,
    high_water: int | None = None,
) -> None:
    if field == "revocations":
        for name in ("target_kind", "input_kind", "reason_code"):
            require_id(record.get(name), f"revocation {name}")
        if record.get("input_kind") not in {"owner-revocation", "publisher-revocation"}:
            raise ValueError("extension revocation input kind is invalid")
        for name in (
            "target_identity_digest", "input_digest", "owner_decision_digest",
        ):
            require_digest(record.get(name), f"revocation {name}")
        sequence = _require_nonnegative_integer(
            record.get("local_sequence"), "revocation sequence"
        )
        effective = _require_nonnegative_integer(
            record.get("effective_generation"), "revocation generation"
        )
        if sequence < 1 or effective < 1:
            raise ValueError("extension revocation sequence/generation is invalid")
        if high_water is not None and sequence > high_water:
            raise ValueError("extension revocation exceeds policy high-water")
        if generation is not None and effective > generation:
            raise ValueError("extension revocation generation exceeds policy generation")
        return
    if field == "trust_keys":
        require_id(record.get("publisher_id"), "trust key publisher ID")
        require_id(record.get("key_id"), "trust key ID")
        encoded = _require_string(
            record.get("ed25519_public_key"), "Ed25519 public key", maximum=43
        )
        try:
            decoded = base64.urlsafe_b64decode(encoded + "=")
        except (ValueError, TypeError) as error:
            raise ValueError("Ed25519 public key is not canonical base64url") from error
        if (
            len(encoded) != 43
            or len(decoded) != 32
            or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != encoded
        ):
            raise ValueError("Ed25519 public key is not canonical base64url")
        for name in (
            "roles", "source_classes", "namespaces", "extension_kinds",
            "allowed_production_policy_digests",
        ):
            values = _require_string_set(record.get(name), f"trust key {name}")
            if name == "allowed_production_policy_digests":
                for item in values:
                    require_digest(item, "production policy digest")
        require_digest(record.get("capability_ceiling_digest"), "capability ceiling digest")
        not_before = parse_timestamp(record.get("not_before"), "trust key not-before")
        not_after = parse_timestamp(record.get("not_after"), "trust key not-after")
        if not_before > not_after or record.get("status") not in {"active", "retired"}:
            raise ValueError("extension trust key state is invalid")
        added = _require_nonnegative_integer(record.get("added_generation"), "key generation")
        sequence = _require_nonnegative_integer(
            record.get("revocation_sequence"), "key revocation sequence"
        )
        if added < 1 or (generation is not None and added > generation):
            raise ValueError("extension trust key generation is invalid")
        if high_water is not None and sequence > high_water:
            raise ValueError("extension trust key sequence exceeds high-water")
        return
    if field == "production_policies":
        require_id(record.get("policy_id"), "production policy ID")
        require_digest(record.get("policy_digest"), "production policy digest")
        require_id(record.get("issuer_id"), "production policy issuer")
        if record.get("status") not in {"active", "retired"}:
            raise ValueError("extension production policy status is invalid")
        added = _require_nonnegative_integer(
            record.get("added_generation"), "production policy generation"
        )
        if added < 1 or (generation is not None and added > generation):
            raise ValueError("extension production policy generation is invalid")
        return
    if field == "source_rules":
        require_id(record.get("source_type"), "source type")
        for name in ("allowed_source_ids", "required_material_kinds"):
            for item in _require_string_set(record.get(name), name):
                require_id(item, name)
        if record.get("rule_mode") != "exact":
            raise ValueError("extension source rule mode is invalid")
        return
    if field == "namespace_rules":
        require_id(record.get("publisher_id"), "namespace publisher")
        _require_string(record.get("namespace_prefix"), "namespace prefix")
        for item in _require_string_set(
            record.get("allowed_extension_kinds"), "allowed extension kinds"
        ):
            require_id(item, "allowed extension kind")
        return
    if field == "extension_kind_rules":
        require_id(record.get("extension_kind"), "extension kind")
        if (
            type(record.get("data_allowed")) is not bool
            or type(record.get("executable_allowed")) is not bool
        ):
            raise ValueError("extension kind flags are invalid")
        for item in _require_string_set(
            record.get("required_isolation_profiles"), "isolation profiles"
        ):
            require_id(item, "isolation profile")
        return
    if field == "capability_ceilings":
        actual = extension_capability_set_digest(
            record.get("subject_kind"), record.get("subject_id"),
            record.get("capability_ids"),
        )
        if not hmac.compare_digest(
            require_digest(record.get("capability_set_digest"), "capability set digest"),
            actual,
        ):
            raise ValueError("extension capability set digest mismatch")
        return
    if field == "compatibility_floors":
        require_id(record.get("component_kind"), "compatibility component")
        require_digest(record.get("compatibility_policy_digest"), "compatibility digest")
        return
    raise ValueError("extension trust record kind is unknown")


def _validate_identity_body(value: Mapping[str, object]) -> None:
    if value.get("schema_version") != "1.0.0":
        raise ValueError("extension package identity schema version is invalid")
    require_id(value.get("publisher_id"), "publisher ID")
    require_id(value.get("extension_id"), "extension ID")
    _require_version(value.get("extension_version"), "extension version")
    require_id(value.get("release_id"), "release ID")
    package_class = value.get("package_class")
    if package_class not in ("data-only", "executable"):
        raise ValueError("extension package class is invalid")
    for field in ("extension_points", "exported_identities"):
        for item in _require_records(value.get(field), ("kind", "id", "contract_digest"), field):
            require_id(item.get("kind"), f"{field} kind")
            require_id(item.get("id"), f"{field} ID")
            require_digest(item.get("contract_digest"), f"{field} contract digest")
    for field in ("input_schema_ids", "output_schema_ids"):
        _require_string_set(value.get(field), field)
    require_digest(value.get("contract_registry_digest"), "contract registry digest")
    compatibility = exact_mapping(
        value.get("compatibility"),
        {
            "core_version_range",
            "cli_protocol_range",
            "schema_profile_range",
            "geel_range",
            "runtime_capabilities_digest",
        },
        "extension compatibility",
    )
    for field in ("core_version_range", "cli_protocol_range", "schema_profile_range", "geel_range"):
        _require_string(compatibility.get(field), field, maximum=128)
    require_digest(compatibility.get("runtime_capabilities_digest"), "runtime capabilities digest")
    nested = {
        "requested_capabilities": ("capability_id", "parameter_schema_id", "parameter_constraint_digest"),
        "operation_classes": ("operation_class", "resource_schema_id", "authority_class", "side_effect_class"),
        "ordered_resources": ("resource_class", "selector_schema_id"),
        "side_effects": ("effect_class", "idempotency_class", "reconciliation_contract_digest"),
    }
    for field, fields in nested.items():
        for item in _require_records(value.get(field), fields, field):
            for name, item_value in item.items():
                if name.endswith("_digest"):
                    require_digest(item_value, name)
                else:
                    _require_string(item_value, name, maximum=256)
    for field in ("idempotency_semantics", "failure_semantics", "verification_semantics"):
        item = exact_mapping(
            value.get(field),
            {"contract_id", "contract_version", "contract_digest"},
            field,
        )
        require_id(item.get("contract_id"), f"{field} contract ID")
        _require_version(item.get("contract_version"), f"{field} contract version")
        require_digest(item.get("contract_digest"), f"{field} contract digest")
    executable = value.get("executable_contract")
    if package_class == "data-only":
        if executable is not None:
            raise ValueError("data-only package executable contract must be null")
    else:
        executable_record = exact_mapping(
            executable,
            {"locator", "raw_digest", "entry_protocol", "isolation_profiles"},
            "executable contract",
        )
        _require_string(executable_record.get("locator"), "executable locator")
        raw = executable_record.get("raw_digest")
        if type(raw) is not str or RAW_DIGEST.fullmatch(raw) is None:
            raise ValueError("executable raw digest is invalid")
        _require_string(executable_record.get("entry_protocol"), "entry protocol")
        _require_string_set(executable_record.get("isolation_profiles"), "isolation profiles")


@dataclass(frozen=True, slots=True, init=False)
class ExtensionPackageIdentity:
    """Exact ADR-0004 package identity; constructed only after self-digest validation."""

    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionPackageIdentity must be created by from_dict")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ExtensionPackageIdentity:
        frozen = _verify_self_digest(
            value,
            fields={*_IDENTITY_BODY_FIELDS, "package_identity_digest"},
            digest_field="package_identity_digest",
            contract_name="extension-package-identity",
        )
        _validate_identity_body(frozen)
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def package_identity_digest(self) -> str:
        return str(self._document["package_identity_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result

@dataclass(frozen=True, slots=True, init=False)
class ExtensionPackageManifest:
    """Exact package manifest whose declarations reconstruct one package identity."""

    _document: FrozenMap
    _identity: ExtensionPackageIdentity

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionPackageManifest must be created by from_dict")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ExtensionPackageManifest:
        extra = {
            "source_attestation_digest",
            "build_attestation_digest",
            "payload_root_digest",
            "package_identity_digest",
            "signing_suite",
            "publisher_key_id",
            "revocation_sequence_floor",
            "manifest_digest",
        }
        frozen = _verify_self_digest(
            value,
            fields={*_IDENTITY_BODY_FIELDS, *extra},
            digest_field="manifest_digest",
            contract_name="extension-package-manifest",
        )
        _validate_identity_body(frozen)
        for field in ("source_attestation_digest", "build_attestation_digest", "payload_root_digest"):
            require_digest(frozen.get(field), field)
        if frozen.get("signing_suite") != "ed25519-v1":
            raise ValueError("extension signing suite is invalid")
        require_id(frozen.get("publisher_key_id"), "publisher key ID")
        _require_nonnegative_integer(frozen.get("revocation_sequence_floor"), "revocation sequence floor")
        reconstructed = {field: thaw(frozen[field]) for field in _IDENTITY_BODY_FIELDS}
        reconstructed["package_identity_digest"] = frozen["package_identity_digest"]
        try:
            identity = ExtensionPackageIdentity.from_dict(reconstructed)
        except ValueError as error:
            raise ValueError("manifest package identity reconstruction failed") from error
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        object.__setattr__(result, "_identity", identity)
        return result

    @property
    def package_identity_digest(self) -> str:
        return self._identity.package_identity_digest

    def reconstructed_identity(self) -> ExtensionPackageIdentity:
        return self._identity

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


_POLICY_FIELDS = {
    "schema_version",
    "installation_id",
    "generation",
    "previous_policy_digest",
    "revocation_high_water",
    *_TRUST_ARRAY_FIELDS,
    "resource_policy_digest",
    "reducer_id",
    "reducer_version",
    "reducer_implementation_digest",
    "policy_digest",
}


@dataclass(frozen=True, slots=True, init=False)
class ExtensionTrustPolicy:
    """One closed policy body; authority is supplied later by the installation ledger."""

    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionTrustPolicy must be created by from_dict")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        previous: ExtensionTrustPolicy | None = None,
    ) -> ExtensionTrustPolicy:
        frozen = _verify_self_digest(
            value,
            fields=_POLICY_FIELDS,
            digest_field="policy_digest",
            contract_name="extension-trust-policy",
        )
        if frozen.get("schema_version") != "1.0.0":
            raise ValueError("extension trust policy schema version is invalid")
        installation_id = require_id(frozen.get("installation_id"), "installation ID")
        generation = _require_nonnegative_integer(frozen.get("generation"), "policy generation")
        high_water = _require_nonnegative_integer(
            frozen.get("revocation_high_water"), "revocation high-water"
        )
        for field, fields in _TRUST_ARRAY_FIELDS.items():
            records = _require_records(frozen.get(field), fields, field)
            for record in records:
                _validate_trust_record(
                    field, record, generation=generation, high_water=high_water
                )
        require_digest(frozen.get("resource_policy_digest"), "resource policy digest")
        require_id(frozen.get("reducer_id"), "reducer ID")
        _require_version(frozen.get("reducer_version"), "reducer version")
        require_digest(frozen.get("reducer_implementation_digest"), "reducer implementation digest")
        if previous is None:
            if generation != 0 or frozen.get("previous_policy_digest") is not None or high_water != 0:
                raise ValueError("only exact generation-zero trust genesis can lack a previous policy")
            if any(frozen[field] for field in _TRUST_ARRAY_FIELDS):
                raise ValueError("extension trust genesis arrays must be empty")
        else:
            if type(previous) is not ExtensionTrustPolicy:
                raise TypeError("previous extension trust policy is invalid")
            if installation_id != previous.installation_id:
                raise ValueError("extension trust policy installation changed")
            if generation != previous.generation + 1:
                raise ValueError("extension trust policy generation is not consecutive")
            if frozen.get("previous_policy_digest") != previous.policy_digest:
                raise ValueError("extension trust previous policy digest mismatch")
            if high_water < previous.revocation_high_water:
                raise ValueError("extension trust revocation high-water decreased")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def installation_id(self) -> str:
        return str(self._document["installation_id"])

    @property
    def generation(self) -> int:
        return int(self._document["generation"])

    @property
    def revocation_high_water(self) -> int:
        return int(self._document["revocation_high_water"])

    @property
    def policy_digest(self) -> str:
        return str(self._document["policy_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ExtensionTrustOperation:
    """One exact expected-old trust reducer operation."""

    _document: FrozenMap
    FIELDS = frozenset({
        "schema_version", "operation_id", "operation_kind", "expected_policy_digest",
        "target_identity", "expected_old", "new_value", "operation_digest",
    })
    OPERATION_KINDS = (
        "add-key", "retire-key", "rotate-key", "register-production-policy",
        "retire-production-policy", "set-source-rule", "set-namespace-rule",
        "set-extension-kind-rule", "set-capability-ceiling", "set-compatibility-floor",
        "apply-local-revocation", "apply-publisher-revocation",
    )

    @classmethod
    def from_dict(cls, value: object) -> ExtensionTrustOperation:
        if not isinstance(value, Mapping):
            raise ValueError("extension trust operation is not an object")
        frozen = _verify_self_digest(
            value,
            fields=set(cls.FIELDS),
            digest_field="operation_digest",
            contract_name="extension-trust-operation",
        )
        if frozen.get("schema_version") != "1.0.0":
            raise ValueError("extension trust operation version is invalid")
        require_id(frozen.get("operation_id"), "extension trust operation ID")
        kind = _require_string(frozen.get("operation_kind"), "extension trust operation kind")
        if kind not in cls.OPERATION_KINDS:
            raise ValueError("extension trust operation kind is unknown")
        require_digest(frozen.get("expected_policy_digest"), "expected trust policy digest")
        _require_string(frozen.get("target_identity"), "extension trust target identity")
        expected = frozen.get("expected_old")
        new = frozen.get("new_value")
        if expected is not None and not isinstance(expected, Mapping):
            raise ValueError("extension trust expected-old is invalid")
        if not isinstance(new, Mapping):
            raise ValueError("extension trust new value is invalid")
        field = ExtensionTrustPolicyReducer.FIELD_BY_KIND[kind]
        fields = _TRUST_ARRAY_FIELDS[field]
        if expected is not None:
            exact_mapping(expected, set(fields), "extension trust expected-old")
            _validate_trust_record(field, expected)
        exact_mapping(new, set(fields), "extension trust new value")
        _validate_trust_record(field, new)
        if kind.startswith("add-") or kind.startswith("register-"):
            if expected is not None:
                raise ValueError("extension trust add/apply operation expected-old must be absent")
        elif (kind.startswith("retire-") or kind == "rotate-key") and expected is None:
            raise ValueError("extension trust replace/retire operation requires expected-old")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def operation_kind(self) -> str:
        return str(self._document["operation_kind"])

    @property
    def operation_digest(self) -> str:
        return str(self._document["operation_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


_ISSUED_TRUST_REDUCERS: dict[int, object] = {}

_EXTENSION_TRUST_TRANSITION_SEMANTICS: Mapping[str, str] = {
    "add-key": "absent-to-active-next-generation",
    "retire-key": "active-to-retired-next-revocation-sequence",
    "rotate-key": "active-to-distinct-active-next-generation",
    "register-production-policy": "absent-to-active-next-generation",
    "retire-production-policy": "active-to-retired-immutable-identity",
    "set-source-rule": "expected-old-or-absent-no-noop",
    "set-namespace-rule": "expected-old-or-absent-no-noop",
    "set-extension-kind-rule": "expected-old-or-absent-no-noop",
    "set-capability-ceiling": "expected-old-or-absent-no-noop",
    "set-compatibility-floor": "expected-old-or-absent-no-noop",
    "apply-local-revocation": "append-only-next-sequence-next-generation",
    "apply-publisher-revocation": "append-only-next-sequence-next-generation",
}


EXTENSION_TRUST_REDUCER_PRODUCT = {
    "schema_version": "1.0.0",
    "reducer_id": "gew.extension-trust-policy-reducer",
    "reducer_version": "1.0.0",
    "operation_kinds": list(ExtensionTrustOperation.OPERATION_KINDS),
    "field_by_kind": {
        "add-key": "trust_keys", "retire-key": "trust_keys", "rotate-key": "trust_keys",
        "register-production-policy": "production_policies",
        "retire-production-policy": "production_policies",
        "set-source-rule": "source_rules", "set-namespace-rule": "namespace_rules",
        "set-extension-kind-rule": "extension_kind_rules",
        "set-capability-ceiling": "capability_ceilings",
        "set-compatibility-floor": "compatibility_floors",
        "apply-local-revocation": "revocations",
        "apply-publisher-revocation": "revocations",
    },
    "transition_semantics": dict(_EXTENSION_TRUST_TRANSITION_SEMANTICS),
}
EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST = semantic_digest(
    EXTENSION_TRUST_REDUCER_PRODUCT,
    contract_type="urn:gew:contract:extension-trust-reducer-product",
    projection_id="urn:gew:digest-projection:extension-trust-reducer-product:1.0.0",
    schema_id="urn:gew:schema:extension-trust-reducer-product-input:1.0.0",
)


class ExtensionTrustPolicyReducer:
    """Closed deterministic reducer selected by the product policy tuple."""

    OPERATION_KINDS = ExtensionTrustOperation.OPERATION_KINDS
    FIELD_BY_KIND: Mapping[str, str] = {
        "add-key": "trust_keys", "retire-key": "trust_keys", "rotate-key": "trust_keys",
        "register-production-policy": "production_policies",
        "retire-production-policy": "production_policies",
        "set-source-rule": "source_rules", "set-namespace-rule": "namespace_rules",
        "set-extension-kind-rule": "extension_kind_rules",
        "set-capability-ceiling": "capability_ceilings",
        "set-compatibility-floor": "compatibility_floors",
        "apply-local-revocation": "revocations",
        "apply-publisher-revocation": "revocations",
    }
    TRANSITION_SEMANTICS = _EXTENSION_TRUST_TRANSITION_SEMANTICS

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension trust reducers are product-issued")

    @classmethod
    def issue(cls, genesis: ExtensionTrustPolicy) -> ExtensionTrustPolicyReducer:
        if (
            type(genesis) is not ExtensionTrustPolicy
            or genesis.generation != 0
            or genesis.to_dict()["reducer_id"] != "gew.extension-trust-policy-reducer"
            or genesis.to_dict()["reducer_version"] != "1.0.0"
            or genesis.to_dict()["reducer_implementation_digest"]
            != EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST
        ):
            raise ValueError("extension trust reducer product attestation is invalid")
        result = object.__new__(cls)
        _ISSUED_TRUST_REDUCERS[id(result)] = result
        return result

    @classmethod
    def require_attested(cls, value: object) -> ExtensionTrustPolicyReducer:
        if type(value) is not cls or _ISSUED_TRUST_REDUCERS.get(id(value)) is not value:
            raise TypeError("extension trust reducer is not product-attested")
        return value

    @staticmethod
    def _identity(field: str, record: Mapping[str, object]) -> str:
        names = {
            "trust_keys": ("publisher_id", "key_id"),
            "production_policies": ("policy_id",),
            "source_rules": ("source_type",),
            "namespace_rules": ("publisher_id", "namespace_prefix"),
            "extension_kind_rules": ("extension_kind",),
            "capability_ceilings": ("subject_kind", "subject_id"),
            "compatibility_floors": ("component_kind",),
            "revocations": ("target_kind", "target_identity_digest"),
        }[field]
        return "/".join(str(record[name]) for name in names)

    @classmethod
    def expansion_targets(
        cls, operations: tuple[ExtensionTrustOperation, ...]
    ) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for operation in operations:
            document = operation.to_dict()
            kind = operation.operation_kind
            old = document["expected_old"]
            new = document["new_value"]
            assert isinstance(new, Mapping)
            expansion = kind in {
                "add-key", "rotate-key", "register-production-policy",
            }
            if kind == "set-source-rule":
                expansion = old is None or (
                    isinstance(old, Mapping)
                    and (
                        not set(new["allowed_source_ids"]).issubset(old["allowed_source_ids"])
                        or not set(new["required_material_kinds"]).issuperset(
                            old["required_material_kinds"]
                        )
                        or new["rule_mode"] != old["rule_mode"]
                    )
                )
            elif kind == "set-namespace-rule":
                expansion = old is None or (
                    isinstance(old, Mapping)
                    and not set(new["allowed_extension_kinds"]).issubset(
                        old["allowed_extension_kinds"]
                    )
                )
            elif kind == "set-extension-kind-rule":
                expansion = old is None or (
                    isinstance(old, Mapping)
                    and (
                        (not old["data_allowed"] and new["data_allowed"])
                        or (not old["executable_allowed"] and new["executable_allowed"])
                        or not set(new["required_isolation_profiles"]).issuperset(
                            old["required_isolation_profiles"]
                        )
                    )
                )
            elif kind in {"set-capability-ceiling", "set-compatibility-floor"}:
                expansion = old is None or old != new
            if expansion:
                result.append({
                    "operation_kind": kind,
                    "target_identity": str(document["target_identity"]),
                })
        result.sort(key=lambda item: (item["operation_kind"], item["target_identity"]))
        return result

    @classmethod
    def _validate_transition(
        cls,
        current: ExtensionTrustPolicy,
        kind: str,
        expected: object,
        new: Mapping[str, object],
        next_sequence: int,
    ) -> None:
        if expected == new:
            raise ValueError("extension trust operation is a no-op")
        next_generation = current.generation + 1
        if kind == "add-key":
            if (
                expected is not None
                or new["status"] != "active"
                or new["added_generation"] != next_generation
                or new["revocation_sequence"] != current.revocation_high_water
            ):
                raise ValueError("extension trust add-key transition is invalid")
        elif kind == "retire-key":
            if not isinstance(expected, Mapping):
                raise ValueError("extension trust retire-key expected-old is missing")
            immutable = set(_TRUST_ARRAY_FIELDS["trust_keys"]) - {
                "status", "revocation_sequence",
            }
            if (
                expected["status"] != "active"
                or new["status"] != "retired"
                or new["revocation_sequence"] != next_sequence
                or any(new[field] != expected[field] for field in immutable)
            ):
                raise ValueError("extension trust retire-key transition is invalid")
        elif kind == "rotate-key":
            if (
                not isinstance(expected, Mapping)
                or expected["status"] != "active"
                or new["status"] != "active"
                or new["ed25519_public_key"] == expected["ed25519_public_key"]
                or new["added_generation"] != next_generation
                or new["revocation_sequence"] != current.revocation_high_water
            ):
                raise ValueError("extension trust rotate-key transition is invalid")
        elif kind == "register-production-policy":
            if (
                expected is not None
                or new["status"] != "active"
                or new["added_generation"] != next_generation
            ):
                raise ValueError("extension trust production-policy registration is invalid")
        elif kind == "retire-production-policy":
            if not isinstance(expected, Mapping):
                raise ValueError("extension trust production-policy expected-old is missing")
            immutable = set(_TRUST_ARRAY_FIELDS["production_policies"]) - {"status"}
            if (
                expected["status"] != "active"
                or new["status"] != "retired"
                or any(new[field] != expected[field] for field in immutable)
            ):
                raise ValueError("extension trust production-policy retirement is invalid")
        elif kind in {"apply-local-revocation", "apply-publisher-revocation"}:
            expected_input = (
                "owner-revocation"
                if kind == "apply-local-revocation"
                else "publisher-revocation"
            )
            if (
                expected is not None
                or new["input_kind"] != expected_input
                or new["local_sequence"] != next_sequence
                or new["effective_generation"] != next_generation
            ):
                raise ValueError(
                    "extension trust revocation append sequence transition is invalid"
                )

    def security_join(
        self,
        previous: ExtensionTrustPolicy,
        published: ExtensionTrustPolicy,
    ) -> ExtensionTrustPolicy:
        """Restore prior grants while monotonically retaining every comparable deny."""

        self.require_attested(self)
        if (
            type(previous) is not ExtensionTrustPolicy
            or type(published) is not ExtensionTrustPolicy
            or published.installation_id != previous.installation_id
            or published.to_dict()["previous_policy_digest"] != previous.policy_digest
        ):
            raise ValueError("extension trust security join base is unprovable")
        old = previous.to_dict()
        new = published.to_dict()
        if new["resource_policy_digest"] != old["resource_policy_digest"]:
            raise ValueError("extension trust resource-policy ordering is unprovable")

        def indexed(field: str, body: Mapping[str, object]) -> dict[str, Mapping[str, object]]:
            return {
                self._identity(field, item): item
                for item in body[field]
                if isinstance(item, Mapping)
            }

        result = dict(old)
        old_revocations = indexed("revocations", old)
        new_revocations = indexed("revocations", new)
        if any(new_revocations.get(key) != value for key, value in old_revocations.items()):
            raise ValueError("extension trust revocation ordering is unprovable")
        result["revocations"] = new["revocations"]

        old_ceilings = indexed("capability_ceilings", old)
        new_ceilings = indexed("capability_ceilings", new)
        joined_ceilings: dict[str, dict[str, object]] = {}
        for identity, before in old_ceilings.items():
            after = new_ceilings.get(identity)
            if after is None:
                raise ValueError("extension capability ordering is unprovable")
            capabilities = sorted(
                set(str(item) for item in before["capability_ids"])
                & set(str(item) for item in after["capability_ids"])
            )
            joined_ceilings[identity] = {
                "subject_kind": before["subject_kind"],
                "subject_id": before["subject_id"],
                "capability_ids": capabilities,
                "capability_set_digest": extension_capability_set_digest(
                    before["subject_kind"], before["subject_id"], capabilities
                ),
            }
        result["capability_ceilings"] = sorted(
            joined_ceilings.values(), key=canonical_bytes
        )

        old_keys = indexed("trust_keys", old)
        new_keys = indexed("trust_keys", new)
        joined_keys: list[dict[str, object]] = []
        for identity, before in old_keys.items():
            after = new_keys.get(identity)
            if after is None:
                raise ValueError("extension trust-key ordering is unprovable")
            record = dict(before)
            for field in (
                "roles", "source_classes", "namespaces", "extension_kinds",
                "allowed_production_policy_digests",
            ):
                record[field] = sorted(
                    set(str(item) for item in before[field])
                    & set(str(item) for item in after[field])
                )
            record["status"] = (
                "retired"
                if "retired" in {before["status"], after["status"]}
                else "active"
            )
            record["revocation_sequence"] = max(
                int(before["revocation_sequence"]),
                int(after["revocation_sequence"]),
            )
            ceiling = joined_ceilings.get(f"publisher/{before['publisher_id']}")
            if ceiling is None and (
                before["capability_ceiling_digest"]
                != after["capability_ceiling_digest"]
            ):
                raise ValueError("extension key capability ordering is unprovable")
            if ceiling is not None:
                record["capability_ceiling_digest"] = ceiling["capability_set_digest"]
            joined_keys.append(record)
        result["trust_keys"] = sorted(joined_keys, key=canonical_bytes)

        old_production = indexed("production_policies", old)
        new_production = indexed("production_policies", new)
        joined_production: list[dict[str, object]] = []
        for identity, before in old_production.items():
            after = new_production.get(identity)
            if after is None or any(
                before[field] != after[field]
                for field in ("policy_id", "policy_digest", "issuer_id", "added_generation")
            ):
                raise ValueError("extension production-policy ordering is unprovable")
            record = dict(before)
            if after["status"] == "retired":
                record["status"] = "retired"
            joined_production.append(record)
        result["production_policies"] = sorted(joined_production, key=canonical_bytes)

        old_sources = indexed("source_rules", old)
        new_sources = indexed("source_rules", new)
        joined_sources: list[dict[str, object]] = []
        for identity, before in old_sources.items():
            after = new_sources.get(identity)
            if after is None or before["rule_mode"] != after["rule_mode"]:
                raise ValueError("extension source-rule ordering is unprovable")
            record = dict(before)
            record["allowed_source_ids"] = sorted(
                set(before["allowed_source_ids"]) & set(after["allowed_source_ids"])
            )
            record["required_material_kinds"] = sorted(
                set(before["required_material_kinds"])
                | set(after["required_material_kinds"])
            )
            joined_sources.append(record)
        result["source_rules"] = sorted(joined_sources, key=canonical_bytes)

        old_namespaces = indexed("namespace_rules", old)
        new_namespaces = indexed("namespace_rules", new)
        joined_namespaces: list[dict[str, object]] = []
        for identity, before in old_namespaces.items():
            after = new_namespaces.get(identity)
            if after is None:
                raise ValueError("extension namespace ordering is unprovable")
            record = dict(before)
            record["allowed_extension_kinds"] = sorted(
                set(before["allowed_extension_kinds"])
                & set(after["allowed_extension_kinds"])
            )
            joined_namespaces.append(record)
        result["namespace_rules"] = sorted(joined_namespaces, key=canonical_bytes)

        old_kinds = indexed("extension_kind_rules", old)
        new_kinds = indexed("extension_kind_rules", new)
        joined_kinds: list[dict[str, object]] = []
        for identity, before in old_kinds.items():
            after = new_kinds.get(identity)
            if after is None:
                raise ValueError("extension-kind ordering is unprovable")
            record = dict(before)
            record["data_allowed"] = bool(before["data_allowed"] and after["data_allowed"])
            record["executable_allowed"] = bool(
                before["executable_allowed"] and after["executable_allowed"]
            )
            record["required_isolation_profiles"] = sorted(
                set(before["required_isolation_profiles"])
                | set(after["required_isolation_profiles"])
            )
            joined_kinds.append(record)
        result["extension_kind_rules"] = sorted(joined_kinds, key=canonical_bytes)

        old_floors = indexed("compatibility_floors", old)
        new_floors = indexed("compatibility_floors", new)
        joined_floors = dict(old_floors)
        for identity, after in new_floors.items():
            before = old_floors.get(identity)
            if before is not None and before != after:
                raise ValueError("extension compatibility ordering is unprovable")
            joined_floors[identity] = after
        result["compatibility_floors"] = sorted(
            (dict(item) for item in joined_floors.values()), key=canonical_bytes
        )
        result.update(
            generation=published.generation + 1,
            previous_policy_digest=published.policy_digest,
            revocation_high_water=published.revocation_high_water,
        )
        result.pop("policy_digest")
        result["policy_digest"] = semantic_digest(
            result,
            contract_type="urn:gew:contract:extension-trust-policy",
            projection_id="urn:gew:digest-projection:extension-trust-policy:1.0.0",
            schema_id="urn:gew:schema:extension-trust-policy-input:1.0.0",
        )
        return ExtensionTrustPolicy.from_dict(result, previous=published)

    def reduce(
        self,
        current: ExtensionTrustPolicy,
        operations: tuple[ExtensionTrustOperation, ...],
    ) -> ExtensionTrustPolicy:
        self.require_attested(self)
        if not operations or any(type(item) is not ExtensionTrustOperation for item in operations):
            raise ValueError("extension trust reducer requires exact operations")
        documents = [item.to_dict() for item in operations]
        if [item.operation_digest for item in operations] != sorted(
            {item.operation_digest for item in operations}
        ):
            raise ValueError("extension trust operations are not canonical and unique")
        body = current.to_dict()
        for operation, document in zip(operations, documents, strict=True):
            if document["expected_policy_digest"] != current.policy_digest:
                raise ValueError("extension trust operation base policy is stale")
            field = self.FIELD_BY_KIND[operation.operation_kind]
            records = list(body[field])
            matches = [
                (index, record) for index, record in enumerate(records)
                if self._identity(field, record) == document["target_identity"]
            ]
            expected = document["expected_old"]
            if (expected is None and matches) or (
                expected is not None
                and (len(matches) != 1 or matches[0][1] != expected)
            ):
                raise ValueError("extension trust operation expected-old mismatch")
            new_value = document["new_value"]
            assert isinstance(new_value, Mapping)
            current_sequences = [current.revocation_high_water]
            current_sequences.extend(
                int(item["local_sequence"])
                for item in body["revocations"]
                if isinstance(item, Mapping)
            )
            current_sequences.extend(
                int(item["revocation_sequence"])
                for item in body["trust_keys"]
                if isinstance(item, Mapping)
            )
            self._validate_transition(
                current,
                operation.operation_kind,
                expected,
                new_value,
                max(current_sequences) + 1,
            )
            if self._identity(field, new_value) != document["target_identity"]:
                raise ValueError("extension trust operation target substitution")
            if matches:
                records[matches[0][0]] = new_value
            else:
                records.append(new_value)
            records.sort(key=canonical_bytes)
            body[field] = records
        revocations = body["revocations"]
        assert isinstance(revocations, list)
        keys = body["trust_keys"]
        assert isinstance(keys, list)
        body.update(
            generation=current.generation + 1,
            previous_policy_digest=current.policy_digest,
            revocation_high_water=max(
                [current.revocation_high_water]
                + [int(item["local_sequence"]) for item in revocations]
                + [int(item["revocation_sequence"]) for item in keys]
            ),
        )
        body.pop("policy_digest")
        body["policy_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:extension-trust-policy",
            projection_id="urn:gew:digest-projection:extension-trust-policy:1.0.0",
            schema_id="urn:gew:schema:extension-trust-policy-input:1.0.0",
        )
        return ExtensionTrustPolicy.from_dict(body, previous=current)


_LEDGER_COMMON = {
    "schema_version",
    "record_type",
    "installation_id",
    "transaction_id",
    "record_sequence",
    "previous_record_digest",
    "expected_head_digest",
    "owner_identity",
    "owner_decision_digest",
    "owner_authority_digest",
    "created_at",
    "record_digest",
}
_LEDGER_ADDITIONAL: Mapping[str, set[str]] = {
    "prepared": {
        "expected_generation",
        "expected_policy_digest",
        "expected_revocation_high_water",
        "candidate_generation",
        "candidate_policy_digest",
        "candidate_revocation_high_water",
        "ordered_operations_digest",
    },
    "commit": {
        "prepared_record_digest",
        "candidate_generation",
        "candidate_policy_digest",
        "candidate_revocation_high_water",
        "committed_at",
    },
    "abort": {"prepared_record_digest", "observed_head_digest", "reason_code", "aborted_at"},
    "rollback": {
        "prepared_record_digest",
        "rollback_of_record_digest",
        "restore_content_from_policy_digest",
        "candidate_generation",
        "candidate_policy_digest",
        "candidate_revocation_high_water",
        "committed_at",
    },
}


@dataclass(frozen=True, slots=True, init=False)
class ExtensionTrustLedgerRecord:
    """Closed four-kind append-only trust ledger record."""

    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionTrustLedgerRecord must be created by from_dict")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        current_policy: ExtensionTrustPolicy,
    ) -> ExtensionTrustLedgerRecord:
        if type(current_policy) is not ExtensionTrustPolicy:
            raise TypeError("current extension trust policy is invalid")
        record_type = value.get("record_type")
        if type(record_type) is not str or record_type not in _LEDGER_ADDITIONAL:
            raise ValueError("extension trust ledger record type is invalid")
        frozen = _verify_self_digest(
            value,
            fields=_LEDGER_COMMON | _LEDGER_ADDITIONAL[record_type],
            digest_field="record_digest",
            contract_name=f"extension-trust-{record_type}",
        )
        if frozen.get("schema_version") != "1.0.0":
            raise ValueError("extension trust ledger schema version is invalid")
        if require_id(frozen.get("installation_id"), "installation ID") != current_policy.installation_id:
            raise ValueError("extension trust ledger installation mismatch")
        require_id(frozen.get("transaction_id"), "transaction ID")
        require_id(frozen.get("owner_identity"), "owner identity")
        _require_nonnegative_integer(frozen.get("record_sequence"), "record sequence")
        for field in ("expected_head_digest", "owner_decision_digest", "owner_authority_digest"):
            require_digest(frozen.get(field), field)
        previous_digest = frozen.get("previous_record_digest")
        if previous_digest is not None:
            require_digest(previous_digest, "previous record digest")
        parse_timestamp(frozen.get("created_at"), "created at")
        if record_type == "prepared":
            if frozen.get("expected_generation") != current_policy.generation:
                raise ValueError("prepared expected generation mismatch")
            if frozen.get("expected_policy_digest") != current_policy.policy_digest:
                raise ValueError("prepared expected policy digest mismatch")
            if frozen.get("expected_revocation_high_water") != current_policy.revocation_high_water:
                raise ValueError("prepared expected revocation high-water mismatch")
            if frozen.get("candidate_generation") != current_policy.generation + 1:
                raise ValueError("prepared candidate generation is not consecutive")
            if not isinstance(frozen.get("candidate_revocation_high_water"), int) or frozen.get(
                "candidate_revocation_high_water"
            ) < current_policy.revocation_high_water:
                raise ValueError("prepared candidate revocation high-water decreased")
            for field in ("candidate_policy_digest", "ordered_operations_digest"):
                require_digest(frozen.get(field), field)
        else:
            require_digest(frozen.get("prepared_record_digest"), "prepared record digest")
            if record_type == "abort":
                require_digest(frozen.get("observed_head_digest"), "observed head digest")
                require_id(frozen.get("reason_code"), "abort reason code")
                parse_timestamp(frozen.get("aborted_at"), "aborted at")
            else:
                if record_type == "rollback":
                    require_digest(frozen.get("rollback_of_record_digest"), "rollback record digest")
                    require_digest(
                        frozen.get("restore_content_from_policy_digest"),
                        "restore policy digest",
                    )
                _require_nonnegative_integer(frozen.get("candidate_generation"), "candidate generation")
                require_digest(frozen.get("candidate_policy_digest"), "candidate policy digest")
                high_water = _require_nonnegative_integer(
                    frozen.get("candidate_revocation_high_water"), "candidate revocation high-water"
                )
                if high_water < current_policy.revocation_high_water:
                    raise ValueError("candidate revocation high-water decreased")
                parse_timestamp(frozen.get("committed_at"), "committed at")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def record_type(self) -> str:
        return str(self._document["record_type"])

    @property
    def record_digest(self) -> str:
        return str(self._document["record_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ExtensionTrustPolicyHead:
    """Self-digested installation trust-policy head value."""

    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionTrustPolicyHead must be created by from_dict")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        policy: ExtensionTrustPolicy,
    ) -> ExtensionTrustPolicyHead:
        if type(policy) is not ExtensionTrustPolicy:
            raise TypeError("extension trust policy is invalid")
        frozen = _verify_self_digest(
            value,
            fields={
                "schema_version",
                "installation_id",
                "generation",
                "policy_digest",
                "revocation_high_water",
                "terminal_record_digest",
                "ledger_sequence",
                "previous_head_digest",
                "head_digest",
            },
            digest_field="head_digest",
            contract_name="extension-trust-policy-head",
        )
        if frozen.get("schema_version") != "1.0.0":
            raise ValueError("extension trust policy head schema version is invalid")
        expected = (
            policy.installation_id,
            policy.generation,
            policy.policy_digest,
            policy.revocation_high_water,
        )
        actual = (
            frozen.get("installation_id"),
            frozen.get("generation"),
            frozen.get("policy_digest"),
            frozen.get("revocation_high_water"),
        )
        if actual != expected:
            raise ValueError("extension trust policy head does not bind the exact policy")
        _require_nonnegative_integer(frozen.get("ledger_sequence"), "ledger sequence")
        require_digest(frozen.get("terminal_record_digest"), "terminal record digest")
        previous_head = frozen.get("previous_head_digest")
        if previous_head is not None:
            require_digest(previous_head, "previous head digest")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def head_digest(self) -> str:
        return str(self._document["head_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ExtensionPublisherRevocationStatement:
    """Bounded publisher input; parsing this value grants no installation authority."""

    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionPublisherRevocationStatement must be created by from_dict")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
    ) -> ExtensionPublisherRevocationStatement:
        frozen = _verify_self_digest(
            value,
            fields={
                "schema_version",
                "publisher_id",
                "publisher_key_id",
                "target_kind",
                "target_identity_digest",
                "publisher_sequence",
                "reason_code",
                "issued_at",
                "signature",
                "statement_digest",
            },
            digest_field="statement_digest",
            contract_name="extension-publisher-revocation",
        )
        if frozen.get("schema_version") != "1.0.0":
            raise ValueError("publisher revocation schema version is invalid")
        for field in ("publisher_id", "publisher_key_id", "target_kind", "reason_code"):
            require_id(frozen.get(field), field)
        require_digest(frozen.get("target_identity_digest"), "target identity digest")
        if _require_nonnegative_integer(frozen.get("publisher_sequence"), "publisher sequence") < 1:
            raise ValueError("publisher sequence must be positive")
        parse_timestamp(frozen.get("issued_at"), "issued at")
        _require_string(frozen.get("signature"), "publisher revocation signature", maximum=4096)
        result = object.__new__(cls)
        object.__setattr__(result, "_document", frozen)
        return result

    @property
    def statement_digest(self) -> str:
        return str(self._document["statement_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result

    def verification_request(self, public_key: str) -> Ed25519VerificationRequest:
        body = self.to_dict()
        signature = body.pop("signature")
        body.pop("statement_digest")
        return Ed25519VerificationRequest.create(
            public_key=public_key,
            signature=signature,
            message=(
                b"GEW-EXTENSION-PUBLISHER-REVOCATION-V1\0" + canonical_bytes(body)
            ),
            purpose="extension-publisher-revocation",
        )


@dataclass(frozen=True, slots=True, init=False)
class ExtensionDescriptor:
    extension_id: str
    extension_version: str
    extension_kind: str
    source_kind: str
    executable: bool
    capabilities: tuple[str, ...]
    side_effects: tuple[str, ...]
    package_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("ExtensionDescriptor must be validated by ExtensionGate")


class ExtensionGate:
    @staticmethod
    def require_non_builtin_executable_disabled(extension_kind: str) -> NoReturn:
        require_id(extension_kind, "extension kind")
        raise ExtensionError(
            "E_EXTENSION_EXECUTABLE_CONTRACT_GATE: ADR-0003 executable-extension "
            "revision and conformance gate is not Accepted"
        )

    @staticmethod
    def validate(
        value: Mapping[str, object],
        *,
        approved_builtins: Mapping[str, str],
    ) -> ExtensionDescriptor:
        fields = {
            "schema_version",
            "extension_id",
            "extension_version",
            "extension_kind",
            "source_kind",
            "executable",
            "capabilities",
            "side_effects",
            "package_digest",
        }
        try:
            exact_mapping(value, fields, "extension descriptor")
            if value.get("schema_version") != "1.0.0" or not isinstance(approved_builtins, Mapping):
                raise ValueError("extension validation context is invalid")
            extension_id = require_id(value.get("extension_id"), "extension ID")
            version = value.get("extension_version")
            if type(version) is not str or not version or len(version) > 64:
                raise ValueError("extension version is invalid")
            kind = require_id(value.get("extension_kind"), "extension kind")
            source_kind = value.get("source_kind")
            executable = value.get("executable")
            capabilities = value.get("capabilities")
            side_effects = value.get("side_effects")
            package_digest = require_digest(value.get("package_digest"), "extension package digest")
            if type(executable) is not bool or type(capabilities) is not list or type(side_effects) is not list:
                raise ValueError("extension capability declaration is invalid")
            if capabilities != sorted(set(capabilities)) or side_effects != sorted(set(side_effects)):
                raise ValueError("extension capabilities or side effects are not canonical")
            for item in (*capabilities, *side_effects):
                require_id(item, "extension capability")
            if executable:
                ExtensionGate.require_non_builtin_executable_disabled(kind)
            if capabilities or side_effects:
                raise ValueError("data-only extension cannot request capabilities or side effects")
            if source_kind == "built-in":
                expected = approved_builtins.get(extension_id)
                if type(expected) is not str or not hmac.compare_digest(
                    require_digest(expected, "approved built-in digest"),
                    package_digest,
                ):
                    raise ValueError("built-in extension is not in the closed manifest")
            elif source_kind != "data-only":
                raise ValueError("extension source kind is not approved")
        except (TypeError, ValueError) as error:
            raise ExtensionError(str(error)) from error
        result = object.__new__(ExtensionDescriptor)
        for name, item in (
            ("extension_id", extension_id),
            ("extension_version", version),
            ("extension_kind", kind),
            ("source_kind", source_kind),
            ("executable", executable),
            ("capabilities", tuple(capabilities)),
            ("side_effects", tuple(side_effects)),
            ("package_digest", package_digest),
        ):
            object.__setattr__(result, name, item)
        return result
