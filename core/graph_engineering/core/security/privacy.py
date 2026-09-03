"""Secret references, deterministic redaction, and leakage-safe incidents."""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import semantic_digest, semantic_digest_charged
from graph_engineering.core.contracts.errors import ContractError
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext, bounded_measure
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    exact_mapping,
    require_canonical_strings,
    require_digest,
    require_id,
    unsigned_digest,
)
from graph_engineering.core.security.attestation import SecurityRuntimeManifest


REDACTION_POLICY_SCHEMA = "urn:gew:schema:redaction-policy:1.0.0"
REDACTION_POLICY_CONTRACT = "urn:gew:contract:redaction-policy"
REDACTED_PAYLOAD_SCHEMA = "urn:gew:schema:redacted-payload:1.0.0"


class RedactionError(ValueError):
    """Payload minimization or secret scanning failed closed."""


def classify_sensitivity(value: object) -> str:
    """Normalize ingress classification; unknown data is confidential by default."""

    return value if type(value) is str and value in {"public", "internal", "confidential", "secret"} else "confidential"


@dataclass(frozen=True, slots=True, init=False)
class SecretReference:
    provider_id: str
    key_ref: str
    version_ref: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SecretReference must be loaded from validated data")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> SecretReference:
        try:
            exact_mapping(value, {"schema_version", "provider_id", "key_ref", "version_ref"}, "secret reference")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("secret reference version is invalid")
            fields = (
                ("provider_id", require_id(value.get("provider_id"), "secret provider ID")),
                ("key_ref", require_id(value.get("key_ref"), "secret key ref")),
                ("version_ref", require_id(value.get("version_ref"), "secret version ref")),
            )
        except (TypeError, ValueError) as error:
            raise RedactionError(str(error)) from error
        result = object.__new__(SecretReference)
        for name, item in fields:
            object.__setattr__(result, name, item)
        return result

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "provider_id": self.provider_id,
            "key_ref": self.key_ref,
            "version_ref": self.version_ref,
        }


class SecretMaterial:
    """Ephemeral provider output whose repr and str never expose its value."""

    __slots__ = ("_value", "reference")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("SecretMaterial must be emitted by a provider boundary")

    @classmethod
    def from_provider(cls, value: bytes, *, reference: SecretReference) -> SecretMaterial:
        if type(value) is not bytes or not value or type(reference) is not SecretReference:
            raise RedactionError("secret provider output is invalid")
        result = object.__new__(SecretMaterial)
        object.__setattr__(result, "_value", bytearray(value))
        object.__setattr__(result, "reference", reference)
        return result

    def reveal(self) -> bytes:
        return bytes(self._value)

    def destroy(self) -> None:
        """Best-effort in-process erasure after the provider session closes."""

        for index in range(len(self._value)):
            self._value[index] = 0

    def __repr__(self) -> str:
        return "<SecretMaterial redacted>"

    __str__ = __repr__


@runtime_checkable
class SecretProvider(Protocol):
    """Port implemented by a runtime adapter; values remain ephemeral."""

    @property
    def provider_id(self) -> str: ...

    def resolve(self, reference: SecretReference) -> SecretMaterial: ...


@dataclass(frozen=True, slots=True, init=False)
class RedactionPolicy:
    policy_id: str
    allowed_transforms: tuple[str, ...]
    mask_marker: str
    max_fields: int
    policy_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RedactionPolicy must be loaded from validated configuration")

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, object],
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
        runtime: SecurityRuntimeManifest,
    ) -> RedactionPolicy:
        if (
            type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
            or type(runtime) is not SecurityRuntimeManifest
        ):
            raise RedactionError("redaction policy requires attested contracts")
        if schema_registry.validate(REDACTION_POLICY_SCHEMA, value, context):
            raise RedactionError("redaction policy schema validation failed")
        try:
            exact_mapping(value, {"schema_version", "policy_id", "allowed_transforms", "mask_marker", "max_fields", "policy_digest"}, "redaction policy")
            if value.get("schema_version") != "1.0.0":
                raise ValueError("redaction policy version is invalid")
            policy_id = require_id(value.get("policy_id"), "redaction policy ID")
            transforms = require_canonical_strings(value.get("allowed_transforms"), "redaction transforms", ids=True)
            if not set(transforms).issubset({"drop", "mask"}):
                raise ValueError("redaction transform is not implemented")
            marker = value.get("mask_marker")
            max_fields = value.get("max_fields")
            expected = require_digest(value.get("policy_digest"), "redaction policy digest")
            if type(marker) is not str or not marker or type(max_fields) is not int or max_fields <= 0:
                raise ValueError("redaction policy values are invalid")
            actual = semantic_digest_charged(
                {key: item for key, item in value.items() if key != "policy_digest"},
                context,
                contract_type=REDACTION_POLICY_CONTRACT,
                projection_id=IDENTITY_PROJECTION,
                schema_id=REDACTION_POLICY_SCHEMA,
                operation_path=context.child_path(()),
            )
            if actual != expected:
                raise ValueError("redaction policy digest mismatch")
            runtime.require_policy("redaction", policy_id, expected)
        except (TypeError, ValueError) as error:
            raise RedactionError(str(error)) from error
        result = object.__new__(RedactionPolicy)
        for name, item in (
            ("policy_id", policy_id),
            ("allowed_transforms", transforms),
            ("mask_marker", marker),
            ("max_fields", max_fields),
            ("policy_digest", expected),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class RedactedPayload:
    payload: Mapping[str, object]
    field_allowlist: tuple[str, ...]
    applied_transforms: tuple[str, ...]
    payload_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("RedactedPayload is emitted only by Redactor")

    def canonical_text(self) -> str:
        return canonical_bytes(self.payload).decode("utf-8")

    def as_dict(self) -> dict[str, object]:
        value = thaw(self.payload)
        if type(value) is not dict:
            raise AssertionError("redacted payload is not an object")
        return value


def _pointer_tokens(pointer: str) -> tuple[str, ...]:
    if type(pointer) is not str or not pointer.startswith("/") or pointer == "/":
        raise RedactionError("field allowlist contains an invalid JSON pointer")
    tokens: list[str] = []
    for raw in pointer[1:].split("/"):
        remainder = raw.replace("~0", "").replace("~1", "")
        if not raw or "~" in remainder:
            raise RedactionError("field allowlist contains an invalid JSON pointer")
        tokens.append(raw.replace("~1", "/").replace("~0", "~"))
    return tuple(tokens)


def _read_pointer(value: Mapping[str, object], tokens: tuple[str, ...]) -> object:
    current: object = value
    for token in tokens:
        if not isinstance(current, Mapping) or token not in current:
            raise RedactionError("allowlisted field does not exist")
        current = current[token]
    return current


def _write_pointer(target: dict[str, object], tokens: tuple[str, ...], value: object) -> None:
    current = target
    for token in tokens[:-1]:
        existing = current.setdefault(token, {})
        if type(existing) is not dict:
            raise RedactionError("allowlisted fields overlap")
        current = existing
    if tokens[-1] in current:
        raise RedactionError("duplicate allowlisted field")
    current[tokens[-1]] = value


def _strings(value: object) -> Iterator[str]:
    if type(value) is str:
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif type(value) in (list, tuple):
        for item in value:
            yield from _strings(item)


class Redactor:
    @staticmethod
    def redact(
        payload: Mapping[str, object],
        *,
        field_allowlist: tuple[str, ...],
        transforms: Mapping[str, str],
        secret_materials: tuple[SecretMaterial, ...],
        policy: RedactionPolicy,
        context: WorkContext,
    ) -> RedactedPayload:
        if (
            not isinstance(payload, Mapping)
            or type(field_allowlist) is not tuple
            or type(secret_materials) is not tuple
            or type(policy) is not RedactionPolicy
            or type(context) is not WorkContext
        ):
            raise RedactionError("redaction request is invalid")
        if (
            not field_allowlist
            or field_allowlist != tuple(sorted(set(field_allowlist)))
            or len(field_allowlist) > policy.max_fields
            or any(type(item) is not SecretMaterial for item in secret_materials)
            or not isinstance(transforms, Mapping)
            or any(type(key) is not str or type(item) is not str for key, item in transforms.items())
            or not set(transforms).issubset(field_allowlist)
            or not set(transforms.values()).issubset(policy.allowed_transforms)
        ):
            raise RedactionError("redaction allowlist or transforms are invalid")
        try:
            bounded_measure(
                payload,
                context,
                source_id=policy.policy_id,
                operation_path=context.child_path(()),
            )
        except (ContractError, RecursionError, TypeError, ValueError) as error:
            raise RedactionError("redaction input exceeds the deterministic resource envelope") from error
        context.check_limit("object_properties", len(field_allowlist), source_id=policy.policy_id)
        output: dict[str, object] = {}
        applied: list[str] = []
        pointers = [(pointer, _pointer_tokens(pointer)) for pointer in field_allowlist]
        for index, (pointer, tokens) in enumerate(pointers):
            if any(tokens[: len(other)] == other for _, other in pointers[:index]):
                raise RedactionError("allowlisted fields overlap")
            transform = transforms.get(pointer)
            source_value = _read_pointer(payload, tokens)
            if transform == "drop":
                applied.append(f"{pointer}:drop")
                continue
            selected = policy.mask_marker if transform == "mask" else freeze(source_value)
            if transform == "mask":
                applied.append(f"{pointer}:mask")
            _write_pointer(output, tokens, selected)
        frozen = freeze(output)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("redacted payload did not freeze")
        secrets = tuple(item.reveal() for item in secret_materials)
        for text in _strings(frozen):
            encoded = text.encode("utf-8")
            if any(secret in encoded for secret in secrets):
                raise RedactionError("known secret detected in redacted payload")
        payload_digest = semantic_digest_charged(
            frozen,
            context,
            contract_type="urn:gew:contract:redacted-payload",
            projection_id=IDENTITY_PROJECTION,
            schema_id=REDACTED_PAYLOAD_SCHEMA,
            operation_path=context.child_path(()),
        )
        result = object.__new__(RedactedPayload)
        for name, item in (
            ("payload", frozen),
            ("field_allowlist", field_allowlist),
            ("applied_transforms", tuple(applied)),
            ("payload_digest", payload_digest),
        ):
            object.__setattr__(result, name, item)
        return result


@dataclass(frozen=True, slots=True, init=False)
class LeakageIncident:
    body: Mapping[str, object]

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("LeakageIncident is emitted only by the incident factory")

    @property
    def status(self) -> str:
        return self.body["status"]  # type: ignore[return-value]

    @property
    def suspect_digest(self) -> str:
        return self.body["suspect_digest"]  # type: ignore[return-value]

    @classmethod
    def create(
        cls,
        *,
        incident_id: str,
        source_ref: str,
        suspect_digest: str,
        detector_ids: tuple[str, ...],
        occurred_at: str,
    ) -> LeakageIncident:
        from graph_engineering.core.security._common import parse_timestamp

        try:
            require_id(incident_id, "incident ID")
            require_id(source_ref, "incident source")
            require_digest(suspect_digest, "suspect digest")
            if type(detector_ids) is not tuple or detector_ids != tuple(sorted(set(detector_ids))):
                raise ValueError("detector IDs are not canonical")
            for detector_id in detector_ids:
                require_id(detector_id, "detector ID")
            parse_timestamp(occurred_at, "incident timestamp")
        except ValueError as error:
            raise RedactionError(str(error)) from error
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "incident_id": incident_id,
            "source_ref": source_ref,
            "suspect_digest": suspect_digest,
            "detector_ids": list(detector_ids),
            "occurred_at": occurred_at,
            "status": "quarantined",
        }
        body["incident_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:leakage-incident",
            projection_id=IDENTITY_PROJECTION,
            schema_id="urn:gew:schema:leakage-incident:1.0.0",
        )
        frozen = freeze(body)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("incident did not freeze")
        result = object.__new__(LeakageIncident)
        object.__setattr__(result, "body", frozen)
        return result

    def as_dict(self) -> dict[str, object]:
        value = thaw(self.body)
        if type(value) is not dict:
            raise AssertionError("incident body is not an object")
        return value
