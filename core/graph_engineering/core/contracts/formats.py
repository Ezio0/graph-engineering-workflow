"""Assertion validators for GEW string formats."""

from __future__ import annotations

import base64
import binascii
import datetime
import re


BIGINT = re.compile(r"0|-?[1-9][0-9]*\Z")
DECIMAL = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
TIMESTAMP = re.compile(
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2})-(?P<day>[0-9]{2})T"
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"(?P<fraction>\.[0-9]{0,8}[1-9])?Z\Z"
)
DURATION = re.compile(r"PT(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?S\Z")
GEW_ID = re.compile(r"[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*\Z", re.ASCII)
OPAQUE = re.compile(r"[A-Za-z0-9_-]+\Z", re.ASCII)


def _valid_bigint(value: str) -> bool:
    return BIGINT.fullmatch(value) is not None and value != "-0"


def _valid_decimal(value: str) -> bool:
    return DECIMAL.fullmatch(value) is not None and value != "-0"


def _valid_timestamp(value: str) -> bool:
    match = TIMESTAMP.fullmatch(value)
    if match is None:
        return False
    fields = {key: int(match.group(key)) for key in ("year", "month", "day", "hour", "minute", "second")}
    if fields["hour"] > 23 or fields["minute"] > 59 or fields["second"] > 59:
        return False
    try:
        datetime.date(fields["year"], fields["month"], fields["day"])
    except ValueError:
        return False
    return True


def _valid_duration(value: str) -> bool:
    return DURATION.fullmatch(value) is not None


def _valid_id(value: str) -> bool:
    return 1 <= len(value) <= 255 and GEW_ID.fullmatch(value) is not None


def decode_opaque_ref(value: str) -> bytes:
    """Decode a canonical unpadded base64url opaque reference."""

    if not 2 <= len(value) <= 4096 or len(value) % 4 == 1 or OPAQUE.fullmatch(value) is None:
        raise ValueError("invalid opaque-ref lexical form")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("invalid opaque-ref encoding") from error
    if not 1 <= len(decoded) <= 3072:
        raise ValueError("opaque-ref payload size is invalid")
    text = decoded.decode("utf-8", errors="strict")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        raise ValueError("opaque-ref contains a surrogate")
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value:
        raise ValueError("opaque-ref has non-canonical pad bits")
    return decoded


def validate_format(format_id: str, value: object) -> bool:
    """Assert one closed GEW format without coercion."""

    if type(value) is not str:
        return False
    validators = {
        "gew-bigint": _valid_bigint,
        "gew-decimal": _valid_decimal,
        "gew-timestamp": _valid_timestamp,
        "gew-duration": _valid_duration,
        "gew-id": _valid_id,
    }
    if format_id == "gew-opaque-ref":
        try:
            decode_opaque_ref(value)
        except (UnicodeDecodeError, ValueError):
            return False
        return True
    validator = validators.get(format_id)
    if validator is None:
        raise ValueError(f"unknown GEW format: {format_id}")
    return validator(value)


def allowed_formats() -> frozenset[str]:
    return frozenset({"gew-bigint", "gew-decimal", "gew-timestamp", "gew-duration", "gew-id", "gew-opaque-ref"})
