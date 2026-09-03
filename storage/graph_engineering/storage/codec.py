"""Canonical storage encodings and digest grammars."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final

from graph_engineering.core.contracts.canonical import canonical_bytes

from .errors import RepositoryIntegrityError


OBJECT_DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
JCS_DIGEST: Final[re.Pattern[str]] = re.compile(r"sha256-jcs-v1:[0-9a-f]{64}")


def canonical_json(value: object) -> str:
    return canonical_bytes(value).decode("utf-8")


def parse_canonical_json(value: str) -> object:
    decoded = json.loads(value)
    if canonical_json(decoded) != value:
        raise RepositoryIntegrityError("stored JSON is not canonical")
    return decoded


def object_digest(body: bytes) -> str:
    return "sha256:" + hashlib.sha256(body).hexdigest()


def semantic_record_digest(value: object) -> str:
    return "sha256-jcs-v1:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def require_object_digest(value: object) -> str:
    if type(value) is not str or OBJECT_DIGEST.fullmatch(value) is None:
        raise RepositoryIntegrityError("object digest grammar is invalid")
    return value


def require_jcs_digest(value: object) -> str:
    if type(value) is not str or JCS_DIGEST.fullmatch(value) is None:
        raise RepositoryIntegrityError("semantic digest grammar is invalid")
    return value
