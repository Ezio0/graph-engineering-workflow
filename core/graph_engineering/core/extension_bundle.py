"""Platform-neutral records for the ADR-0004 offline bundle trust boundary."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.security._common import parse_timestamp

from .extensions import Ed25519VerificationRequest


class ExtensionBundleContractError(ValueError):
    """A bundle record does not satisfy the closed ADR-0004 contract."""


def _digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _require_digest(value: object, label: str, *, raw: bool = False) -> str:
    prefix = "sha256-raw-v1:" if raw else "sha256-jcs-v1:"
    if (
        type(value) is not str
        or len(value) != len(prefix) + 64
        or not value.startswith(prefix)
        or any(character not in "0123456789abcdef" for character in value[len(prefix):])
    ):
        raise ExtensionBundleContractError(f"{label} is invalid")
    return value


def _require_text(value: object, label: str, maximum: int = 512) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value.encode()) > maximum:
        raise ExtensionBundleContractError(f"{label} is invalid")
    return value


def _require_signature(value: object, label: str) -> str:
    text = _require_text(value, label, 86)
    try:
        decoded = base64.urlsafe_b64decode(text + "==")
    except (TypeError, ValueError) as error:
        raise ExtensionBundleContractError(f"{label} is invalid") from error
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != text:
        raise ExtensionBundleContractError(f"{label} is invalid")
    return text


def _materials(value: object, key: str) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list:
        raise ExtensionBundleContractError("ordered materials are invalid")
    result: list[Mapping[str, object]] = []
    previous: str | None = None
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {key, "digest"}:
            raise ExtensionBundleContractError("ordered material is not exact")
        identity = _require_text(item.get(key), f"material {key}")
        _require_digest(item.get("digest"), "material digest")
        if previous is not None and identity <= previous:
            raise ExtensionBundleContractError("ordered materials are not canonical")
        previous = identity
        result.append(item)
    return tuple(result)


def _strings(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise ExtensionBundleContractError(f"{label} is invalid")
    result = tuple(_require_text(item, label) for item in value)
    if list(result) != sorted(set(result)):
        raise ExtensionBundleContractError(f"{label} is not canonical")
    return result


@dataclass(frozen=True, slots=True)
class ExtensionAttestationProductionPolicy:
    """Signed publisher provenance policy; it grants no installation authority."""

    _document: FrozenMap

    FIELDS = frozenset({
        "schema_version", "policy_id", "issuer_id", "issuer_key_id",
        "allowed_source_types", "required_source_material_kinds",
        "allowed_attestor_ids", "allowed_builder_ids", "allowed_build_recipe_digests",
        "allowed_toolchain_digests", "dependency_and_sbom_rules",
        "maximum_attestation_lifetime", "issued_at", "not_before", "not_after",
        "policy_signature", "policy_digest",
    })

    @classmethod
    def from_dict(cls, value: object) -> ExtensionAttestationProductionPolicy:
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ExtensionBundleContractError("attestation production policy is not exact")
        body = dict(value)
        claimed = _require_digest(body.pop("policy_digest", None), "production policy digest")
        if _digest(body, "extension-attestation-production-policy") != claimed:
            raise ExtensionBundleContractError("attestation production policy digest mismatch")
        if body.get("schema_version") != "1.0.0":
            raise ExtensionBundleContractError("attestation production policy version is invalid")
        for field in ("policy_id", "issuer_id", "issuer_key_id", "issued_at", "not_before", "not_after"):
            _require_text(body.get(field), field)
        for field in (
            "allowed_source_types", "required_source_material_kinds", "allowed_attestor_ids",
            "allowed_builder_ids", "allowed_build_recipe_digests", "allowed_toolchain_digests",
        ):
            values = _strings(body.get(field), field)
            if not values:
                raise ExtensionBundleContractError(f"{field} is empty")
            if field.endswith("digests"):
                for digest in values:
                    _require_digest(digest, field)
        rules = body.get("dependency_and_sbom_rules")
        if not isinstance(rules, Mapping) or set(rules) != {
            "dependency_lock_required", "sbom_required",
        } or any(type(rules[field]) is not bool for field in rules):
            raise ExtensionBundleContractError("dependency and SBOM rules are not exact")
        lifetime = body.get("maximum_attestation_lifetime")
        if type(lifetime) is not int or lifetime < 1:
            raise ExtensionBundleContractError("maximum attestation lifetime is invalid")
        issued = parse_timestamp(body.get("issued_at"), "production policy issued-at")
        not_before = parse_timestamp(body.get("not_before"), "production policy not-before")
        not_after = parse_timestamp(body.get("not_after"), "production policy not-after")
        if not not_before <= issued <= not_after:
            raise ExtensionBundleContractError("production policy chronology is invalid")
        _require_signature(body.get("policy_signature"), "production policy signature")
        return cls(freeze(value))

    @property
    def policy_digest(self) -> str:
        return str(self._document["policy_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result

    def verification_request(self, public_key: str) -> Ed25519VerificationRequest:
        body = self.to_dict()
        signature = str(body.pop("policy_signature"))
        body.pop("policy_digest")
        return Ed25519VerificationRequest.create(
            public_key=public_key,
            signature=signature,
            message=b"GEW-EXTENSION-ATTESTATION-PRODUCTION-POLICY-V1\0"
            + canonical_bytes(body),
            purpose="extension-attestation-production-policy",
        )


@dataclass(frozen=True, slots=True)
class ExtensionPayloadRoot:
    entries: tuple[Mapping[str, object], ...]
    payload_root_digest: str

    @classmethod
    def from_members(cls, members: Mapping[str, bytes], modes: Mapping[str, int]) -> ExtensionPayloadRoot:
        entries: list[Mapping[str, object]] = []
        for path in sorted(name for name in members if name.startswith("payload/")):
            mode = modes.get(path)
            if mode not in {0o100444, 0o100555}:
                raise ExtensionBundleContractError("payload member mode is invalid")
            body = members[path]
            entries.append(
                {
                    "path": path,
                    "kind": "executable" if mode == 0o100555 else "data",
                    "size": len(body),
                    "raw_digest": raw_digest(body),
                    "executable": mode == 0o100555,
                }
            )
        source: dict[str, object] = {"schema_version": "1.0.0", "entries": entries}
        return cls(tuple(entries), _digest(source, "extension-payload-root"))


class _Attestation:
    __slots__ = ("_document",)
    CONTRACT = ""
    DOMAIN = b""
    FIELDS: frozenset[str] = frozenset()
    MATERIAL_KEY = ""
    OPTIONAL_FIELDS: frozenset[str] = frozenset()

    @classmethod
    def from_dict(cls, value: object) -> _Attestation:
        if (
            not isinstance(value, Mapping)
            or set(value) not in (cls.FIELDS, cls.FIELDS - cls.OPTIONAL_FIELDS)
        ):
            raise ExtensionBundleContractError(f"{cls.CONTRACT} is not exact")
        body = dict(value)
        claimed = _require_digest(body.pop("attestation_digest", None), "attestation digest")
        if _digest(body, cls.CONTRACT) != claimed:
            raise ExtensionBundleContractError(f"{cls.CONTRACT} self-digest mismatch")
        if body.get("schema_version") != "1.0.0":
            raise ExtensionBundleContractError("attestation schema version is invalid")
        _require_signature(body.get("attestation_signature"), "attestation signature")
        _materials(body.get("ordered_materials"), cls.MATERIAL_KEY)
        for field in cls.DIGEST_FIELDS:  # type: ignore[attr-defined]
            _require_digest(body.get(field), field)
        for field in cls.OPTIONAL_FIELDS:
            if field in body:
                _require_digest(body[field], field)
        for field in cls.TEXT_FIELDS:  # type: ignore[attr-defined]
            _require_text(body.get(field), field)
        not_before = parse_timestamp(body.get("not_before"), "attestation not-before")
        not_after = parse_timestamp(body.get("not_after"), "attestation not-after")
        if not_before > not_after:
            raise ExtensionBundleContractError("attestation validity interval is inverted")
        if cls.CONTRACT == "extension-source-attestation":
            issued = parse_timestamp(body.get("issued_at"), "source issued-at")
            if not not_before <= issued <= not_after:
                raise ExtensionBundleContractError("source attestation issuance is outside validity")
        else:
            started = parse_timestamp(body.get("started_at"), "build started-at")
            finished = parse_timestamp(body.get("finished_at"), "build finished-at")
            if not not_before <= started <= finished <= not_after:
                raise ExtensionBundleContractError("build attestation chronology is invalid")
        result = object.__new__(cls)
        result._document = freeze(value)
        return result

    @property
    def attestation_digest(self) -> str:
        return str(self._document["attestation_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result

    def verification_request(self, public_key: str) -> Ed25519VerificationRequest:
        body = self.to_dict()
        signature = str(body.pop("attestation_signature"))
        body.pop("attestation_digest")
        return Ed25519VerificationRequest.create(
            public_key=public_key,
            signature=signature,
            message=self.DOMAIN + b"\0" + canonical_bytes(body),
            purpose=self.CONTRACT,
        )


class ExtensionSourceAttestation(_Attestation):
    CONTRACT = "extension-source-attestation"
    DOMAIN = b"GEW-EXTENSION-SOURCE-ATTESTATION-V1"
    MATERIAL_KEY = "uri"
    FIELDS = frozenset(
        {
            "schema_version", "attestation_id", "source_type", "source_id", "source_revision",
            "source_tree_digest", "ordered_materials", "source_recipe_digest", "attestor_id",
            "attestor_key_id", "issued_at", "not_before", "not_after", "production_policy_id",
            "production_policy_digest", "attestation_signature", "attestation_digest",
            "previous_attestation_digest",
        }
    )
    DIGEST_FIELDS = ("source_tree_digest", "source_recipe_digest", "production_policy_digest")
    OPTIONAL_FIELDS = frozenset({"previous_attestation_digest"})
    TEXT_FIELDS = (
        "attestation_id", "source_type", "source_id", "source_revision", "attestor_id",
        "attestor_key_id", "issued_at", "not_before", "not_after", "production_policy_id",
    )


class ExtensionBuildAttestation(_Attestation):
    CONTRACT = "extension-build-attestation"
    DOMAIN = b"GEW-EXTENSION-BUILD-ATTESTATION-V1"
    MATERIAL_KEY = "name"
    FIELDS = frozenset(
        {
            "schema_version", "attestation_id", "builder_id", "builder_key_id", "build_id",
            "source_attestation_digest", "extension_id", "extension_version", "payload_root_digest",
            "package_identity_digest", "ordered_materials", "build_recipe_digest", "toolchain_digest",
            "dependency_lock_digest", "sbom_digest", "started_at", "finished_at", "not_before",
            "not_after", "production_policy_id", "production_policy_digest", "attestation_signature",
            "attestation_digest",
        }
    )
    DIGEST_FIELDS = (
        "source_attestation_digest", "payload_root_digest", "package_identity_digest",
        "build_recipe_digest", "toolchain_digest", "dependency_lock_digest", "sbom_digest",
        "production_policy_digest",
    )
    TEXT_FIELDS = (
        "attestation_id", "builder_id", "builder_key_id", "build_id", "extension_id",
        "extension_version", "started_at", "finished_at", "not_before", "not_after",
        "production_policy_id",
    )


@dataclass(frozen=True, slots=True)
class ExtensionPublisherSignature:
    _document: FrozenMap

    FIELDS = frozenset(
        {
            "schema_version", "build_attestation_digest", "manifest_digest", "payload_root_digest",
            "publisher_id", "publisher_key_id", "signing_suite", "signature",
            "signature_record_digest",
        }
    )

    @classmethod
    def from_dict(cls, value: object) -> ExtensionPublisherSignature:
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ExtensionBundleContractError("publisher signature is not exact")
        body = dict(value)
        claimed = _require_digest(body.pop("signature_record_digest", None), "signature record digest")
        if _digest(body, "extension-publisher-signature") != claimed:
            raise ExtensionBundleContractError("publisher signature self-digest mismatch")
        if body.get("schema_version") != "1.0.0" or body.get("signing_suite") != "ed25519-sha256-gew-jcs-v1":
            raise ExtensionBundleContractError("publisher signature suite is invalid")
        for field in ("build_attestation_digest", "manifest_digest", "payload_root_digest"):
            _require_digest(body.get(field), field)
        for field in ("publisher_id", "publisher_key_id"):
            _require_text(body.get(field), field)
        _require_signature(body.get("signature"), "publisher signature")
        return cls(freeze(value))

    @property
    def signature_record_digest(self) -> str:
        return str(self._document["signature_record_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result

    def verification_request(self, public_key: str) -> Ed25519VerificationRequest:
        document = self.to_dict()
        signature = str(document["signature"])
        statement = {
            field: document[field]
            for field in (
                "build_attestation_digest", "manifest_digest", "payload_root_digest",
                "publisher_id", "publisher_key_id", "schema_version", "signing_suite",
            )
        }
        return Ed25519VerificationRequest.create(
            public_key=public_key,
            signature=signature,
            message=b"GEW-EXTENSION-SIGNATURE-V1\0" + canonical_bytes(statement),
            purpose="extension-publisher-signature",
        )


@dataclass(frozen=True, slots=True)
class ExtensionInstallRequest:
    _document: FrozenMap

    FIELDS = frozenset(
        {
            "schema_version", "ingest_id", "installation_id", "owner_id", "runtime_kind",
            "runtime_lineage_id", "bundle_path", "expected_bundle_raw_digest",
            "expected_trust_head_digest", "expected_trust_policy_digest", "owner_decision_digest",
            "owner_authority_digest", "requested_at", "request_digest",
        }
    )

    @classmethod
    def from_dict(cls, value: object) -> ExtensionInstallRequest:
        if not isinstance(value, Mapping) or set(value) != cls.FIELDS:
            raise ExtensionBundleContractError("extension install request is not exact")
        body = dict(value)
        claimed = _require_digest(body.pop("request_digest", None), "install request digest")
        if _digest(body, "extension-install-request") != claimed:
            raise ExtensionBundleContractError("extension install request self-digest mismatch")
        if body.get("schema_version") != "1.0.0":
            raise ExtensionBundleContractError("extension install request version is invalid")
        for field in (
            "ingest_id", "installation_id", "owner_id", "runtime_kind", "runtime_lineage_id",
            "bundle_path", "requested_at",
        ):
            _require_text(body.get(field), field, 4096 if field == "bundle_path" else 512)
        _require_digest(body.get("expected_bundle_raw_digest"), "expected bundle digest", raw=True)
        for field in (
            "expected_trust_head_digest", "expected_trust_policy_digest", "owner_decision_digest",
            "owner_authority_digest",
        ):
            _require_digest(body.get(field), field)
        return cls(freeze(value))

    @property
    def request_digest(self) -> str:
        return str(self._document["request_digest"])

    def to_dict(self) -> dict[str, object]:
        result = thaw(self._document)
        assert isinstance(result, dict)
        return result
