"""Closed contracts for local data-only extension activation and task pins."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.extension_data import ExtensionCoreInvariantSet


class ExtensionActivationError(ValueError):
    """A local data-only activation or pin is invalid or unavailable."""


def _digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _text(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value.encode()) > 4096:
        raise ExtensionActivationError(f"{label} is invalid")
    return value


def _semantic_digest(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 78 or not text.startswith("sha256-jcs-v1:") or any(
        character not in "0123456789abcdef" for character in text[14:]
    ):
        raise ExtensionActivationError(f"{label} is invalid")
    return text


def _canonical_strings(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str or not item for item in value):
        raise ExtensionActivationError(f"{label} is invalid")
    encoded = [canonical_bytes(item) for item in value]
    if encoded != sorted(set(encoded)):
        raise ExtensionActivationError(f"{label} is not canonical")
    return tuple(value)


@dataclass(frozen=True, slots=True)
class ExtensionActivationPolicy:
    policy_id: str
    allowed_data_categories: tuple[str, ...]
    accepted_compatibility: Mapping[str, tuple[str, ...]]
    available_capabilities: tuple[str, ...]
    maximum_activations: int
    maximum_task_pins: int
    maximum_diagnostics: int
    local_activation_status: str
    formal_release_status: str
    executable_status: str
    policy_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ExtensionActivationPolicy:
        fields = {
            "schema_version", "policy_id", "allowed_data_categories", "accepted_compatibility",
            "available_capabilities", "maximum_activations", "maximum_task_pins",
            "maximum_diagnostics", "local_activation_status", "formal_release_status",
            "executable_status", "policy_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value.get("schema_version") != "1.0.0":
            raise ExtensionActivationError("extension activation policy is not exact")
        compatibility = value.get("accepted_compatibility")
        compatibility_fields = {
            "core_version_range", "cli_protocol_range", "schema_profile_range", "geel_range",
            "runtime_capabilities_digest",
        }
        if not isinstance(compatibility, Mapping) or set(compatibility) != compatibility_fields:
            raise ExtensionActivationError("extension compatibility policy is not exact")
        accepted = {
            field: _canonical_strings(compatibility[field], f"accepted {field}")
            for field in compatibility_fields
        }
        bounds = (
            value.get("maximum_activations"), value.get("maximum_task_pins"),
            value.get("maximum_diagnostics"),
        )
        if any(type(item) is not int or item < 1 for item in bounds):
            raise ExtensionActivationError("extension activation policy bound is invalid")
        statuses = (
            _text(value.get("local_activation_status"), "local activation status"),
            _text(value.get("formal_release_status"), "formal release status"),
            _text(value.get("executable_status"), "executable status"),
        )
        if statuses != (
            "local-data-only-active",
            "blocked-pending-wp10-release-install-manifest",
            "blocked-pending-adr0003-revision-and-conformance",
        ):
            raise ExtensionActivationError("extension activation gates were weakened")
        body = dict(value)
        claimed = _semantic_digest(body.pop("policy_digest", None), "activation policy digest")
        if not hmac.compare_digest(_digest(body, "extension-activation-policy"), claimed):
            raise ExtensionActivationError("extension activation policy self-digest mismatch")
        return cls(
            _text(value.get("policy_id"), "activation policy ID"),
            _canonical_strings(value.get("allowed_data_categories"), "data categories"),
            accepted,
            _canonical_strings(value.get("available_capabilities"), "available capabilities"),
            *bounds,  # type: ignore[arg-type]
            *statuses,
            claimed,
        )


@dataclass(frozen=True, slots=True)
class ExtensionBuiltInRegistry:
    registry_id: str
    protected_identities: frozenset[tuple[str, str]]
    registry_digest: str

    @classmethod
    def from_dict(cls, value: object) -> ExtensionBuiltInRegistry:
        if (
            not isinstance(value, Mapping)
            or set(value) != {
                "schema_version", "registry_id", "protected_identities", "registry_digest"
            }
            or value.get("schema_version") != "1.0.0"
            or type(value.get("protected_identities")) is not list
        ):
            raise ExtensionActivationError("built-in identity registry is not exact")
        pairs: list[tuple[str, str]] = []
        for item in value["protected_identities"]:  # type: ignore[index]
            if not isinstance(item, Mapping) or set(item) != {"kind", "id"}:
                raise ExtensionActivationError("built-in identity is not exact")
            pairs.append((_text(item.get("kind"), "built-in kind"), _text(item.get("id"), "built-in ID")))
        if pairs != sorted(set(pairs)):
            raise ExtensionActivationError("built-in identities are not canonical")
        body = dict(value)
        claimed = _semantic_digest(body.pop("registry_digest", None), "built-in registry digest")
        if not hmac.compare_digest(_digest(body, "extension-built-in-registry"), claimed):
            raise ExtensionActivationError("built-in identity registry self-digest mismatch")
        return cls(
            _text(value.get("registry_id"), "built-in registry ID"),
            frozenset(pairs),
            claimed,
        )


def activation_resource_binding_digest(
    policy: ExtensionActivationPolicy,
    built_in_registry: ExtensionBuiltInRegistry,
    core_invariant_set: ExtensionCoreInvariantSet,
) -> str:
    """Bind both closed activation resources to the Owner-authorized trust policy."""

    if (
        type(policy) is not ExtensionActivationPolicy
        or type(built_in_registry) is not ExtensionBuiltInRegistry
        or type(core_invariant_set) is not ExtensionCoreInvariantSet
    ):
        raise TypeError("extension activation resources are invalid")
    return _digest(
        {
            "schema_version": "1.0.0",
            "activation_policy_digest": policy.policy_digest,
            "built_in_registry_digest": built_in_registry.registry_digest,
            "core_invariant_set_digest": core_invariant_set.invariant_set_digest,
        },
        "extension-activation-resource-binding",
    )


class _SelfDigestedRequest:
    __slots__ = ("_document",)
    CONTRACT = ""
    DIGEST_FIELD = ""
    FIELDS: frozenset[str] = frozenset()
    DIGEST_FIELDS: tuple[str, ...] = ()
    OPTIONAL_DIGEST_FIELDS: tuple[str, ...] = ()
    TEXT_FIELDS: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, value: object) -> _SelfDigestedRequest:
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ExtensionActivationError(f"{cls.CONTRACT} is not exact")
        body = dict(value)
        claimed = _semantic_digest(body.pop(cls.DIGEST_FIELD, None), cls.DIGEST_FIELD)
        if _digest(body, cls.CONTRACT) != claimed or body.get("schema_version") != "1.0.0":
            raise ExtensionActivationError(f"{cls.CONTRACT} self-digest mismatch")
        for field in cls.DIGEST_FIELDS:
            if field in cls.OPTIONAL_DIGEST_FIELDS and body.get(field) is None:
                continue
            _semantic_digest(body.get(field), field)
        for field in cls.TEXT_FIELDS:
            _text(body.get(field), field)
        result = object.__new__(cls)
        result._document = freeze(value)
        return result

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


class ExtensionActivationRequest(_SelfDigestedRequest):
    CONTRACT = "extension-activation-request"
    DIGEST_FIELD = "request_digest"
    FIELDS = frozenset(
        {
            "schema_version", "activation_id", "installation_id", "ingest_record_digest",
            "owner_id", "runtime_kind", "runtime_lineage_id", "expected_trust_head_digest",
            "expected_trust_policy_digest", "expected_revocation_high_water",
            "expected_active_generation", "expected_active_manifest_digest",
            "conflict_override_digest", "owner_decision_digest", "owner_authority_digest",
            "requested_at", "request_digest",
        }
    )
    DIGEST_FIELDS = (
        "ingest_record_digest", "expected_trust_head_digest", "expected_trust_policy_digest",
        "expected_active_manifest_digest", "conflict_override_digest",
        "owner_decision_digest", "owner_authority_digest",
    )
    OPTIONAL_DIGEST_FIELDS = (
        "expected_active_manifest_digest", "conflict_override_digest",
    )
    TEXT_FIELDS = (
        "activation_id", "installation_id", "owner_id", "runtime_kind", "runtime_lineage_id",
        "requested_at",
    )

    @property
    def request_digest(self) -> str:
        return str(self._document["request_digest"])

    @classmethod
    def from_dict(cls, value: object) -> ExtensionActivationRequest:
        result = super().from_dict(value)
        generation = result.to_dict().get("expected_active_generation")
        if type(generation) is not int or generation < 0:
            raise ExtensionActivationError("expected active generation is invalid")
        return result  # type: ignore[return-value]


class ExtensionActiveSetRequest(_SelfDigestedRequest):
    CONTRACT = "extension-active-set-request"
    DIGEST_FIELD = "request_digest"
    FIELDS = frozenset(
        {
            "schema_version", "transition_id", "transition_kind", "installation_id",
            "extension_id", "target_activation_record_digest",
            "expected_active_generation", "expected_active_manifest_digest",
            "owner_id", "runtime_kind", "runtime_lineage_id",
            "expected_trust_head_digest", "expected_trust_policy_digest",
            "expected_revocation_high_water", "owner_decision_digest",
            "owner_authority_digest", "reason_code", "requested_at", "request_digest",
        }
    )
    DIGEST_FIELDS = (
        "target_activation_record_digest", "expected_active_manifest_digest",
        "expected_trust_head_digest", "expected_trust_policy_digest",
        "owner_decision_digest", "owner_authority_digest",
    )
    OPTIONAL_DIGEST_FIELDS = (
        "target_activation_record_digest", "expected_active_manifest_digest",
    )
    TEXT_FIELDS = (
        "transition_id", "transition_kind", "installation_id", "extension_id",
        "owner_id", "runtime_kind", "runtime_lineage_id", "reason_code", "requested_at",
    )

    @classmethod
    def from_dict(cls, value: object) -> ExtensionActiveSetRequest:
        result = super().from_dict(value)
        body = result.to_dict()
        kind = body.get("transition_kind")
        target = body.get("target_activation_record_digest")
        if kind not in {"rollback", "remove"} or (
            (kind == "rollback" and target is None)
            or (kind == "remove" and target is not None)
        ):
            raise ExtensionActivationError("active-set transition is invalid")
        generation = body.get("expected_active_generation")
        high_water = body.get("expected_revocation_high_water")
        if (
            type(generation) is not int
            or generation < 1
            or type(high_water) is not int
            or high_water < 0
        ):
            raise ExtensionActivationError("active-set transition CAS is invalid")
        return result  # type: ignore[return-value]

    @property
    def request_digest(self) -> str:
        return str(self._document["request_digest"])


class ExtensionTaskPinRequest(_SelfDigestedRequest):
    CONTRACT = "extension-task-pin-request"
    DIGEST_FIELD = "request_digest"
    FIELDS = frozenset(
        {
            "schema_version", "pin_id", "task_id", "installation_id",
            "activation_record_digests", "owner_id", "runtime_kind", "runtime_lineage_id",
            "graph_digest", "expected_active_generation", "expected_active_manifest_digest",
            "expected_contract_registry_digest", "expected_capability_profile_digest",
            "expected_trust_head_digest", "expected_trust_policy_digest",
            "expected_revocation_high_water", "owner_decision_digest", "owner_authority_digest",
            "requested_at", "request_digest",
        }
    )
    DIGEST_FIELDS = (
        "graph_digest", "expected_active_manifest_digest",
        "expected_contract_registry_digest", "expected_capability_profile_digest",
        "expected_trust_head_digest", "expected_trust_policy_digest",
        "owner_decision_digest", "owner_authority_digest",
    )
    TEXT_FIELDS = (
        "pin_id", "task_id", "installation_id", "owner_id", "runtime_kind",
        "runtime_lineage_id", "requested_at",
    )

    @property
    def request_digest(self) -> str:
        return str(self._document["request_digest"])

    @classmethod
    def from_dict(cls, value: object) -> ExtensionTaskPinRequest:
        result = super().from_dict(value)
        body = result.to_dict()
        values = _canonical_strings(body.get("activation_record_digests"), "activation record digests")
        if not values:
            raise ExtensionActivationError("task pin requires at least one activation")
        for item in values:
            _semantic_digest(item, "activation record digest")
        high_water = body.get("expected_revocation_high_water")
        generation = body.get("expected_active_generation")
        if (
            type(high_water) is not int
            or high_water < 0
            or type(generation) is not int
            or generation < 1
        ):
            raise ExtensionActivationError("task pin revocation high-water is invalid")
        return result  # type: ignore[return-value]


@dataclass(frozen=True, slots=True, init=False)
class ExtensionActivationManifest:
    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("activation manifests require exact decoding")

    @classmethod
    def from_dict(cls, value: object) -> ExtensionActivationManifest:
        fields = {
            "schema_version", "generation", "previous_manifest_digest", "transition_id",
            "transition_kind", "installation_id", "trust_policy_digest",
            "trust_head_digest", "revocation_high_water", "data_registry_digest",
            "active_packages", "tombstones", "owner_decision_digest",
            "owner_authority_digest", "activated_at", "manifest_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionActivationError("extension activation manifest is not exact")
        body = dict(value)
        claimed = _semantic_digest(body.pop("manifest_digest", None), "manifest digest")
        if body.get("schema_version") != "1.0.0" or not hmac.compare_digest(
            _digest(body, "extension-activation-manifest"), claimed
        ):
            raise ExtensionActivationError("extension activation manifest self-digest mismatch")
        generation = body.get("generation")
        previous = body.get("previous_manifest_digest")
        if (
            type(generation) is not int
            or generation < 1
            or (generation == 1) != (previous is None)
        ):
            raise ExtensionActivationError("extension activation manifest chain is invalid")
        if previous is not None:
            _semantic_digest(previous, "previous manifest digest")
        for field in ("transition_id", "installation_id", "activated_at"):
            _text(body.get(field), field)
        if body.get("transition_kind") not in {"activate", "supersede", "rollback", "remove"}:
            raise ExtensionActivationError("extension activation transition is invalid")
        for field in (
            "trust_policy_digest", "trust_head_digest", "data_registry_digest",
            "owner_decision_digest", "owner_authority_digest",
        ):
            _semantic_digest(body.get(field), field)
        if type(body.get("revocation_high_water")) is not int or body["revocation_high_water"] < 0:
            raise ExtensionActivationError("extension activation high-water is invalid")
        packages = body.get("active_packages")
        tombstones = body.get("tombstones")
        if type(packages) is not list or type(tombstones) is not list:
            raise ExtensionActivationError("extension activation set is invalid")
        package_ids: list[str] = []
        for package in packages:
            package_fields = {
                "schema_version", "extension_id", "extension_version", "activation_record_digest",
                "ingest_record_digest", "package_identity_digest", "package_manifest_digest",
                "content_root_ref", "content_root_digest", "package_binding_digest",
            }
            if not isinstance(package, Mapping) or set(package) != package_fields:
                raise ExtensionActivationError("extension active package binding is not exact")
            if package.get("schema_version") != "1.0.0":
                raise ExtensionActivationError("extension active package schema is invalid")
            package_body = dict(package)
            package_digest = _semantic_digest(
                package_body.pop("package_binding_digest", None), "package binding digest"
            )
            if not hmac.compare_digest(
                _digest(package_body, "extension-active-package-binding"), package_digest
            ):
                raise ExtensionActivationError("extension active package binding is invalid")
            package_ids.append(_text(package.get("extension_id"), "extension ID"))
            _text(package.get("extension_version"), "extension version")
            _text(package.get("content_root_ref"), "content root reference")
            for field in (
                "activation_record_digest", "ingest_record_digest",
                "package_identity_digest", "package_manifest_digest", "content_root_digest",
            ):
                _semantic_digest(package.get(field), field)
        if package_ids != sorted(set(package_ids)):
            raise ExtensionActivationError("extension active packages are not canonical")
        tombstone_encodings: list[bytes] = []
        for tombstone in tombstones:
            tombstone_fields = {
                "schema_version", "extension_id", "removed_activation_record_digest", "transition_id",
                "reason_code", "tombstone_digest",
            }
            if not isinstance(tombstone, Mapping) or set(tombstone) != tombstone_fields:
                raise ExtensionActivationError("extension activation tombstone is not exact")
            if tombstone.get("schema_version") != "1.0.0":
                raise ExtensionActivationError("extension activation tombstone schema is invalid")
            tombstone_body = dict(tombstone)
            tombstone_digest = _semantic_digest(
                tombstone_body.pop("tombstone_digest", None), "tombstone digest"
            )
            if not hmac.compare_digest(
                _digest(tombstone_body, "extension-activation-tombstone"), tombstone_digest
            ):
                raise ExtensionActivationError("extension activation tombstone is invalid")
            for field in ("extension_id", "transition_id", "reason_code"):
                _text(tombstone.get(field), field)
            _semantic_digest(
                tombstone.get("removed_activation_record_digest"),
                "removed activation record digest",
            )
            tombstone_encodings.append(canonical_bytes(tombstone))
        if tombstone_encodings != sorted(set(tombstone_encodings)):
            raise ExtensionActivationError("extension activation tombstones are not canonical")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", freeze(value))
        return result

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result


@dataclass(frozen=True, slots=True, init=False)
class ExtensionActiveSetPointer:
    _document: FrozenMap

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("active-set pointers require exact decoding")

    @classmethod
    def from_dict(cls, value: object) -> ExtensionActiveSetPointer:
        fields = {
            "schema_version", "generation", "manifest_digest", "previous_pointer_digest",
            "transition_id", "updated_at", "pointer_digest",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionActivationError("extension active-set pointer is not exact")
        body = dict(value)
        claimed = _semantic_digest(body.pop("pointer_digest", None), "pointer digest")
        generation = body.get("generation")
        previous = body.get("previous_pointer_digest")
        if (
            body.get("schema_version") != "1.0.0"
            or type(generation) is not int
            or generation < 1
            or (generation == 1) != (previous is None)
            or not hmac.compare_digest(_digest(body, "extension-active-set-pointer"), claimed)
        ):
            raise ExtensionActivationError("extension active-set pointer is invalid")
        _semantic_digest(body.get("manifest_digest"), "active manifest digest")
        for field in ("transition_id", "updated_at"):
            _text(body.get(field), field)
        if previous is not None:
            _semantic_digest(previous, "previous pointer digest")
        result = object.__new__(cls)
        object.__setattr__(result, "_document", freeze(value))
        return result

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result
