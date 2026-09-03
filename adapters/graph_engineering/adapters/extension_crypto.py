"""PyCA cryptography candidate verifier selected by ADR-0004 r5."""

from __future__ import annotations

import importlib.metadata
from collections.abc import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from graph_engineering.core.extensions import (
    Ed25519VerificationRequest,
    Ed25519VerificationResult,
)


class ExtensionCryptoProviderError(RuntimeError):
    """The exact offline provider requirement is unavailable or mismatched."""


_ISSUED_VERIFIERS: dict[int, object] = {}


class PycaEd25519CandidateVerifier:
    """Candidate-only verifier; WP-10 pins artifacts before release activation."""

    __slots__ = ("_provider_id", "_provider_version", "_maximum_message_bytes")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("extension crypto verifiers are requirement-issued")

    @classmethod
    def from_requirement(cls, value: object) -> PycaEd25519CandidateVerifier:
        fields = {
            "schema_version", "requirement_id", "distribution_name", "distribution_version",
            "python_requires", "import_prefix", "provider_id", "provider_version",
            "network_mode", "fallback", "activation_status", "required_release_install_pins",
            "update_authority", "maximum_message_bytes",
        }
        if not isinstance(value, Mapping) or set(value) != fields:
            raise ExtensionCryptoProviderError("crypto provider requirement is not exact")
        if (
            value.get("schema_version") != "1.0.0"
            or value.get("distribution_name") != "cryptography"
            or value.get("distribution_version") != "50.0.0"
            or value.get("import_prefix") != "cryptography"
            or value.get("network_mode") != "offline-only"
            or value.get("fallback") != "disabled"
            or value.get("activation_status") != "blocked-pending-wp10-release-install-manifest"
        ):
            raise ExtensionCryptoProviderError("crypto provider requirement is incompatible")
        try:
            installed = importlib.metadata.version("cryptography")
        except importlib.metadata.PackageNotFoundError as error:
            raise ExtensionCryptoProviderError("crypto provider is unavailable") from error
        if installed != value["distribution_version"]:
            raise ExtensionCryptoProviderError("crypto provider version mismatch")
        maximum = value.get("maximum_message_bytes")
        if type(maximum) is not int or maximum < 1:
            raise ExtensionCryptoProviderError("crypto provider message bound is invalid")
        instance = object.__new__(cls)
        instance._provider_id = str(value["provider_id"])
        instance._provider_version = str(value["provider_version"])
        instance._maximum_message_bytes = maximum
        _ISSUED_VERIFIERS[id(instance)] = instance
        return instance

    @classmethod
    def require_attested(cls, value: object) -> PycaEd25519CandidateVerifier:
        if type(value) is not cls or _ISSUED_VERIFIERS.get(id(value)) is not value:
            raise ExtensionCryptoProviderError("crypto verifier is not requirement-attested")
        return value

    def verify(self, request: Ed25519VerificationRequest) -> Ed25519VerificationResult:
        self.require_attested(self)
        if type(request) is not Ed25519VerificationRequest:
            raise TypeError("Ed25519 verification request is missing or forged")
        if len(request.message) > self._maximum_message_bytes:
            raise ExtensionCryptoProviderError("Ed25519 message exceeds configured bound")
        valid = True
        try:
            Ed25519PublicKey.from_public_bytes(request._public_key_bytes).verify(
                request._signature_bytes, request.message,
            )
        except InvalidSignature:
            valid = False
        return Ed25519VerificationResult(
            valid, self._provider_id, self._provider_version, request.purpose,
        )
