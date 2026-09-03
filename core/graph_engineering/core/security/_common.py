"""Shared exact-value helpers for the security contract layer."""

from __future__ import annotations

import datetime
import hmac
from collections.abc import Mapping, Sequence

from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.formats import validate_format


IDENTITY_PROJECTION = "urn:gew:digest-projection:identity:1.0.0"
SENSITIVITIES = ("public", "internal", "confidential", "secret")
TRUST_LEVELS = ("untrusted", "validated", "independently-reviewed")


def exact_mapping(value: object, fields: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ValueError(f"{label} properties are not exact")
    if any(type(key) is not str for key in value):
        raise ValueError(f"{label} keys are invalid")
    return value


def require_id(value: object, label: str) -> str:
    if not validate_format("gew-id", value):
        raise ValueError(f"{label} is not canonical")
    return value  # type: ignore[return-value]


def require_digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is not a semantic digest")
    return value


def require_canonical_strings(
    value: object,
    label: str,
    *,
    allow_empty: bool = False,
    ids: bool = False,
) -> tuple[str, ...]:
    if (
        type(value) is not list
        or (not allow_empty and not value)
        or any(type(item) is not str or not item for item in value)
        or list(value) != sorted(set(value))
        or (ids and any(not validate_format("gew-id", item) for item in value))
    ):
        raise ValueError(f"{label} is not a canonical string set")
    return tuple(value)


def require_exact_string_sequence(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not tuple or any(type(item) is not str or not item for item in value):
        raise ValueError(f"{label} must be an exact string tuple")
    if value != tuple(sorted(set(value))):
        raise ValueError(f"{label} must be canonical")
    return value


def require_sensitivity(value: object) -> str:
    if type(value) is not str or value not in SENSITIVITIES:
        raise ValueError("sensitivity is invalid")
    return value


def sensitivity_rank(value: str) -> int:
    return SENSITIVITIES.index(require_sensitivity(value))


def require_trust(value: object) -> str:
    if type(value) is not str or value not in TRUST_LEVELS:
        raise ValueError("trust is invalid")
    return value


def parse_timestamp(value: object, label: str) -> datetime.datetime:
    if not validate_format("gew-timestamp", value):
        raise ValueError(f"{label} is invalid")
    return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def unsigned_digest(
    value: Mapping[str, object],
    *,
    digest_field: str,
    contract_type: str,
    schema_id: str,
) -> str:
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    return semantic_digest(
        unsigned,
        contract_type=contract_type,
        projection_id=IDENTITY_PROJECTION,
        schema_id=schema_id,
    )


def digest_matches(expected: str, actual: str) -> bool:
    return hmac.compare_digest(expected, actual)


def no_alias_json_sequence(value: object, label: str) -> Sequence[object]:
    if type(value) is not list:
        raise ValueError(f"{label} must be an array")
    return value
