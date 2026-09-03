"""WP-08A offline bundle/provider/ingress slice (GEW-EXT-007..009)."""

from __future__ import annotations

import base64
import binascii
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.extension_bundle import ExtensionAttestationProductionPolicy


ROOT = Path(__file__).resolve().parents[2]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _archive(entries: list[tuple[str, bytes, int]]) -> bytes:
    """Build the exact stored/no-extra ZIP profile needed by the reader tests."""

    local = bytearray()
    central = bytearray()
    offset = 0
    for name, body, mode in entries:
        encoded = name.encode("utf-8")
        crc = binascii.crc32(body) & 0xFFFFFFFF
        local_header = struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50, 20, 0x800, 0, 0, 0x21, crc, len(body), len(body), len(encoded), 0,
        )
        local.extend(local_header + encoded + body)
        central_header = struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50, (3 << 8) | 20, 20, 0x800, 0, 0, 0x21, crc,
            len(body), len(body), len(encoded), 0, 0, 0, 0, mode << 16, offset,
        )
        central.extend(central_header + encoded)
        offset = len(local)
    end = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(central), len(local), 0
    )
    return bytes(local + central + end)


class ExtensionBundleTests(unittest.TestCase):
    def test_gew_ext_007_archive_reader_is_bounded_descriptor_safe_and_offline(self) -> None:
        from graph_engineering.storage.extension_bundle import ExtensionBundleError, ExtensionBundleReader

        policy = json.loads(
            (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
        )
        reader = ExtensionBundleReader.from_dict(policy)
        names = (
            "META-INF/extension-package-manifest.json",
            "META-INF/source-attestation.json",
            "META-INF/build-attestation.json",
            "META-INF/publisher-signature.json",
        )
        entries = [(name, b"{}", 0o100444) for name in names]
        entries.append(("payload/hello.txt", b"hello", 0o100444))
        with tempfile.TemporaryDirectory(prefix="gew-extension-bundle-") as directory:
            path = Path(directory).resolve(strict=True) / "extension.gewx"
            path.write_bytes(_archive(entries))
            with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
                loaded = reader.read(path)
            self.assertEqual(tuple(loaded.members), (*names, "payload/hello.txt"))
            self.assertEqual(loaded.members["payload/hello.txt"], b"hello")

            path.write_bytes(_archive([*entries, entries[-1]]))
            with self.assertRaisesRegex(ExtensionBundleError, "E_EXTENSION_ARCHIVE_PROFILE"):
                reader.read(path)
            path.write_bytes(_archive([*entries[:-1], ("../escape", b"x", 0o100444)]))
            with self.assertRaisesRegex(ExtensionBundleError, "E_EXTENSION_ARCHIVE_PROFILE"):
                reader.read(path)

    def test_gew_ext_008_pyca_provider_verifies_exact_detached_ed25519_inputs(self) -> None:
        from graph_engineering.adapters.extension_crypto import PycaEd25519CandidateVerifier
        from graph_engineering.core.extensions import Ed25519VerificationRequest

        requirement = json.loads(
            (ROOT / "config/supply-chain/extension-crypto-provider-requirement-v1.json").read_text()
        )
        verifier = PycaEd25519CandidateVerifier.from_requirement(requirement)
        request = Ed25519VerificationRequest.create(
            public_key=_b64(bytes.fromhex(
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            )),
            signature=_b64(bytes.fromhex(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )),
            message=b"",
            purpose="provider-conformance",
        )
        self.assertTrue(verifier.verify(request).valid)

        statement = {
            "build_attestation_digest": "sha256-jcs-v1:" + "0" * 64,
            "manifest_digest": "sha256-jcs-v1:" + "1" * 64,
            "payload_root_digest": "sha256-jcs-v1:" + "2" * 64,
            "publisher_id": "publisher.example",
            "publisher_key_id": "key-1",
            "schema_version": "1.0.0",
            "signing_suite": "ed25519-sha256-gew-jcs-v1",
        }
        message = b"GEW-EXTENSION-SIGNATURE-V1\0" + canonical_bytes(statement)
        golden = Ed25519VerificationRequest.create(
            public_key=request.public_key,
            signature=_b64(bytes.fromhex(
                "236c91c0f9853632b9af47ea1cec6118668c9ee4a224dcd0bb786486663ee2673"
                "df2eb53aaaac9a3bb3f517f96ba9f123f38ece230527acda2246f18101aae0b"
            )),
            message=message,
            purpose="extension-publisher-signature",
        )
        self.assertTrue(verifier.verify(golden).valid)
        changed = Ed25519VerificationRequest.create(
            public_key=golden.public_key,
            signature=golden.signature,
            message=message + b"x",
            purpose=golden.purpose,
        )
        self.assertFalse(verifier.verify(changed).valid)

        from graph_engineering.storage.extension_bundle import (
            ExtensionBundleReader,
            verify_extension_bundle,
        )
        from tests.support.wp08a_extension_bundle import trust_policy_chain, valid_bundle

        body, metadata = valid_bundle()
        with tempfile.TemporaryDirectory(prefix="gew-extension-verify-") as directory:
            path = Path(directory).resolve(strict=True) / "extension.gewx"
            path.write_bytes(body)
            loaded = ExtensionBundleReader.from_dict(
                json.loads(
                    (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
                )
            ).read(path)
            _genesis, policy = trust_policy_chain("installation.example")
            verified = verify_extension_bundle(
                loaded, policy, verifier, verified_at="2026-08-20T00:02:00Z",
                production_policy=ExtensionAttestationProductionPolicy.from_dict(
                    metadata["production_policy"]
                ),
            )
            self.assertEqual(
                verified.manifest.to_dict()["manifest_digest"],
                metadata["manifest"]["manifest_digest"],
            )

            tampered = bytearray(body)
            marker = b"source.attestation.1"
            position = tampered.index(marker)
            tampered[position] = ord("t")
            path.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError, "EXTENSION"):
                verify_extension_bundle(
                    ExtensionBundleReader.from_dict(
                        json.loads(
                            (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
                        )
                    ).read(path),
                    policy,
                    verifier,
                    verified_at="2026-08-20T00:02:00Z",
                    production_policy=ExtensionAttestationProductionPolicy.from_dict(
                        metadata["production_policy"]
                    ),
                )

    def test_gew_ext_009_install_application_requires_live_owner_session(self) -> None:
        from graph_engineering.application.extensions import ExtensionInstallationApplication

        self.assertFalse(hasattr(ExtensionInstallationApplication, "install_unscoped"))
        with self.assertRaises((TypeError, ValueError)):
            ExtensionInstallationApplication.install(None, None, None, None)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
