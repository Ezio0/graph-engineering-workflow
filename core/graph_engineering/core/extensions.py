"""Platform-neutral extension cryptographic verification port."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Protocol


def _decode_canonical(value: object, size: int, label: str) -> tuple[str, bytes]:
    if type(value) is not str or not value or "=" in value:
        raise ValueError(f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label} is not canonical unpadded base64url") from error
    if len(decoded) != size or base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError(f"{label} has the wrong length or encoding")
    return value, decoded


@dataclass(frozen=True, slots=True, init=False)
class Ed25519VerificationRequest:
    public_key: str
    signature: str
    message: bytes
    purpose: str
    _public_key_bytes: bytes
    _signature_bytes: bytes

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("Ed25519 requests must be created by the core factory")

    @classmethod
    def create(
        cls,
        *,
        public_key: object,
        signature: object,
        message: object,
        purpose: object,
    ) -> Ed25519VerificationRequest:
        key_text, key = _decode_canonical(public_key, 32, "Ed25519 public key")
        signature_text, signature_bytes = _decode_canonical(signature, 64, "Ed25519 signature")
        if type(message) is not bytes:
            raise ValueError("Ed25519 message must be exact immutable bytes")
        if type(purpose) is not str or not purpose or purpose != purpose.strip():
            raise ValueError("Ed25519 verification purpose is invalid")
        result = object.__new__(cls)
        for name, value in (
            ("public_key", key_text), ("signature", signature_text),
            ("message", message), ("purpose", purpose),
            ("_public_key_bytes", key), ("_signature_bytes", signature_bytes),
        ):
            object.__setattr__(result, name, value)
        return result


@dataclass(frozen=True, slots=True)
class Ed25519VerificationResult:
    valid: bool
    provider_id: str
    provider_version: str
    purpose: str


class Ed25519Verifier(Protocol):
    def verify(self, request: Ed25519VerificationRequest) -> Ed25519VerificationResult: ...
