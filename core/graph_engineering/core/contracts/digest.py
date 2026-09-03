"""Framed raw and semantic digest algorithms."""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.immutable import freeze, thaw
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from graph_engineering.core.contracts.resources import WorkContext


SEMANTIC_DIGEST = re.compile(r"sha256-jcs-v1:[0-9a-f]{64}\Z")
RAW_DIGEST = re.compile(r"sha256-raw-v1:[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class DigestProjection:
    """Immutable top-level self-digest projection contract."""

    projection_id: str
    source_schema_id: str
    digest_input_schema_id: str
    derived_field: str
    contract_type: str
    schema_id: str
    canonicalizer: str = "urn:gew:canonicalizer:jcs-input:1.0.0"
    digest_domain: str = "urn:gew:digest:semantic:1.0.0"

    def __post_init__(self) -> None:
        if not self.derived_field or "/" in self.derived_field:
            raise ValueError("v1 derived field must be one top-level property")
        for value in (
            self.projection_id,
            self.source_schema_id,
            self.digest_input_schema_id,
            self.contract_type,
            self.schema_id,
            self.canonicalizer,
            self.digest_domain,
        ):
            if type(value) is not str or not value.startswith("urn:gew:"):
                raise ValueError("digest projection IDs must be GEW URNs")


def raw_digest(body: bytes | bytearray | memoryview) -> str:
    return "sha256-raw-v1:" + hashlib.sha256(bytes(body)).hexdigest()


def semantic_preimage(
    body: object,
    *,
    contract_type: str,
    projection_id: str,
    schema_id: str,
    canonicalizer: str = "urn:gew:canonicalizer:jcs-input:1.0.0",
    digest_domain: str = "urn:gew:digest:semantic:1.0.0",
) -> bytes:
    envelope = {
        "algorithm": "sha-256",
        "body": body,
        "canonicalizer": canonicalizer,
        "contract_type": contract_type,
        "digest_domain": digest_domain,
        "projection_id": projection_id,
        "schema_id": schema_id,
    }
    return canonical_bytes(envelope)


def semantic_digest(
    body: object,
    *,
    contract_type: str,
    projection_id: str,
    schema_id: str,
    canonicalizer: str = "urn:gew:canonicalizer:jcs-input:1.0.0",
    digest_domain: str = "urn:gew:digest:semantic:1.0.0",
) -> str:
    preimage = semantic_preimage(
        body,
        contract_type=contract_type,
        projection_id=projection_id,
        schema_id=schema_id,
        canonicalizer=canonicalizer,
        digest_domain=digest_domain,
    )
    return "sha256-jcs-v1:" + hashlib.sha256(preimage).hexdigest()


def semantic_digest_charged(
    body: object,
    context: WorkContext,
    *,
    contract_type: str,
    projection_id: str,
    schema_id: str,
    canonicalizer: str = "urn:gew:canonicalizer:jcs-input:1.0.0",
    digest_domain: str = "urn:gew:digest:semantic:1.0.0",
    operation_path: tuple[int, ...] = (),
) -> str:
    from graph_engineering.core.contracts.canonical import canonicalize

    envelope = {
        "algorithm": "sha-256",
        "body": body,
        "canonicalizer": canonicalizer,
        "contract_type": contract_type,
        "digest_domain": digest_domain,
        "projection_id": projection_id,
        "schema_id": schema_id,
    }
    canonical_path = context.child_path(operation_path)
    preimage = canonicalize(envelope, context, source_id=schema_id, operation_path=canonical_path)
    digest_path = context.child_path(operation_path)
    for _ in preimage:
        context.emit("digest.input_byte", 1, operation_path=digest_path, source_id=schema_id)
    return "sha256-jcs-v1:" + hashlib.sha256(preimage).hexdigest()


def create_self_digest(
    candidate_without_digest: Mapping[str, object],
    projection: DigestProjection,
    *,
    validate_input: Callable[[object], None],
    validate_source: Callable[[object], None],
) -> dict[str, object]:
    if projection.derived_field in candidate_without_digest:
        raise ValueError("creation candidate already contains derived field")
    candidate = thaw(freeze(candidate_without_digest))
    if not isinstance(candidate, dict):
        raise TypeError("self-digest candidate must be an object")
    validate_input(thaw(freeze(candidate)))
    body = freeze(candidate)
    value = semantic_digest(
        body,
        contract_type=projection.contract_type,
        projection_id=projection.projection_id,
        schema_id=projection.schema_id,
        canonicalizer=projection.canonicalizer,
        digest_domain=projection.digest_domain,
    )
    complete = thaw(body)
    if not isinstance(complete, dict):
        raise AssertionError("self-digest candidate must be an object")
    complete[projection.derived_field] = value
    validate_source(thaw(freeze(complete)))
    result = thaw(freeze(complete))
    if not isinstance(result, dict):
        raise AssertionError("self-digest output must be an object")
    return result


def verify_self_digest(
    complete_record: Mapping[str, object],
    projection: DigestProjection,
    *,
    validate_input: Callable[[object], None],
    validate_source: Callable[[object], None],
) -> dict[str, object]:
    frozen_source = freeze(complete_record)
    complete = thaw(frozen_source)
    if not isinstance(complete, dict):
        raise TypeError("self-digest record must be an object")
    validate_source(thaw(frozen_source))
    expected = complete.get(projection.derived_field)
    if type(expected) is not str or SEMANTIC_DIGEST.fullmatch(expected) is None:
        raise ValueError("complete record has no valid derived digest")
    del complete[projection.derived_field]
    frozen_body = freeze(complete)
    validate_input(thaw(frozen_body))
    actual = semantic_digest(
        frozen_body,
        contract_type=projection.contract_type,
        projection_id=projection.projection_id,
        schema_id=projection.schema_id,
        canonicalizer=projection.canonicalizer,
        digest_domain=projection.digest_domain,
    )
    if not hmac.compare_digest(expected, actual):
        raise ValueError("self digest mismatch")
    result = thaw(frozen_source)
    if not isinstance(result, dict):
        raise AssertionError("self-digest output must be an object")
    return result


def create_self_digest_charged(
    candidate_without_digest: Mapping[str, object],
    projection: DigestProjection,
    context: WorkContext,
    *,
    validate_input: Callable[[object, tuple[int, ...]], None],
    validate_source: Callable[[object, tuple[int, ...]], None],
    operation_path: tuple[int, ...] = (),
) -> dict[str, object]:
    """Create one source record through the normative charged projection path."""

    if projection.derived_field in candidate_without_digest:
        raise ValueError("creation candidate already contains derived field")
    candidate = thaw(freeze(candidate_without_digest))
    if not isinstance(candidate, dict):
        raise TypeError("self-digest candidate must be an object")
    validate_input(thaw(freeze(candidate)), context.child_path(operation_path))
    body = freeze(candidate)
    value = semantic_digest_charged(
        body,
        context,
        contract_type=projection.contract_type,
        projection_id=projection.projection_id,
        schema_id=projection.schema_id,
        canonicalizer=projection.canonicalizer,
        digest_domain=projection.digest_domain,
        operation_path=context.child_path(operation_path),
    )
    complete = thaw(body)
    if not isinstance(complete, dict):
        raise AssertionError("self-digest candidate must be an object")
    complete[projection.derived_field] = value
    validate_source(thaw(freeze(complete)), context.child_path(operation_path))
    result = thaw(freeze(complete))
    if not isinstance(result, dict):
        raise AssertionError("self-digest output must be an object")
    return result


def verify_self_digest_charged(
    complete_record: Mapping[str, object],
    projection: DigestProjection,
    context: WorkContext,
    *,
    validate_input: Callable[[object, tuple[int, ...]], None],
    validate_source: Callable[[object, tuple[int, ...]], None],
    operation_path: tuple[int, ...] = (),
) -> dict[str, object]:
    """Verify one complete source record through the normative charged path."""

    frozen_source = freeze(complete_record)
    complete = thaw(frozen_source)
    if not isinstance(complete, dict):
        raise TypeError("self-digest record must be an object")
    validate_source(thaw(frozen_source), context.child_path(operation_path))
    expected = complete.get(projection.derived_field)
    if type(expected) is not str or SEMANTIC_DIGEST.fullmatch(expected) is None:
        raise ValueError("complete record has no valid derived digest")
    del complete[projection.derived_field]
    frozen_body = freeze(complete)
    validate_input(thaw(frozen_body), context.child_path(operation_path))
    actual = semantic_digest_charged(
        frozen_body,
        context,
        contract_type=projection.contract_type,
        projection_id=projection.projection_id,
        schema_id=projection.schema_id,
        canonicalizer=projection.canonicalizer,
        digest_domain=projection.digest_domain,
        operation_path=context.child_path(operation_path),
    )
    if not hmac.compare_digest(expected, actual):
        raise ValueError("self digest mismatch")
    result = thaw(frozen_source)
    if not isinstance(result, dict):
        raise AssertionError("self-digest output must be an object")
    return result


def validate_projection_schema_pair(
    source_schema: object,
    digest_input_schema: object,
    projection: DigestProjection,
) -> None:
    """Prove the v1 schema pair differs only by ID and one derived field."""

    source = thaw(freeze(source_schema))
    digest_input = thaw(freeze(digest_input_schema))
    if not isinstance(source, dict) or not isinstance(digest_input, dict):
        raise ValueError("digest projection schemas must be objects")
    if source.get("$id") != projection.source_schema_id:
        raise ValueError("source schema does not match digest projection")
    if digest_input.get("$id") != projection.digest_input_schema_id:
        raise ValueError("digest-input schema does not match digest projection")
    properties = source.get("properties")
    required = source.get("required")
    if (
        not isinstance(properties, dict)
        or projection.derived_field not in properties
        or not isinstance(required, list)
        or projection.derived_field not in required
    ):
        raise ValueError("source schema does not require the derived field")
    del properties[projection.derived_field]
    source["required"] = [item for item in required if item != projection.derived_field]
    source["$id"] = projection.digest_input_schema_id
    if freeze(source) != freeze(digest_input):
        raise ValueError("digest projection schema structural diff is not exact")
