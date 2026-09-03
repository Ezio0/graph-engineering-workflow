"""Frozen executable ADR-0004 package golden/rejection corpus."""

from __future__ import annotations

import copy
import json
import os
import pathlib
import tempfile
import types
import unittest
from unittest import mock

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.extension_bundle import ExtensionAttestationProductionPolicy
from graph_engineering.storage.extension_bundle import (
    ExtensionBundleError,
    ExtensionBundleReader,
    verify_extension_bundle,
)
from tests.integration.test_wp08a_extension_policy_enforcement import _verifier
from tests.support.wp03_repository import ROOT
from tests.support.wp08a_extension_bundle import (
    archive,
    bundle_with_invalid_publisher_signature,
    trust_policy_chain,
    valid_bundle,
)


def _entries(metadata: dict[str, object]) -> list[tuple[str, bytes, int]]:
    return [
        ("META-INF/extension-package-manifest.json", canonical_bytes(metadata["manifest"]), 0o100444),
        ("META-INF/source-attestation.json", canonical_bytes(metadata["source"]), 0o100444),
        ("META-INF/build-attestation.json", canonical_bytes(metadata["build"]), 0o100444),
        ("META-INF/publisher-signature.json", canonical_bytes(metadata["publisher_signature"]), 0o100444),
        *metadata["payload_entries"],  # type: ignore[misc]
    ]


class ExtensionAdr4CorpusTests(unittest.TestCase):
    def _read(self, bundle: bytes):  # type: ignore[no-untyped-def]
        directory = tempfile.TemporaryDirectory(prefix="gew-adr4-corpus-")
        self.addCleanup(directory.cleanup)
        path = pathlib.Path(directory.name) / "candidate.gewx"
        path.write_bytes(bundle)
        os.chmod(path, 0o600)
        policy = json.loads(
            (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
        )
        return ExtensionBundleReader.from_dict(policy).read(path)

    def _verify(self, bundle: bytes, *, genesis: bool = False) -> None:
        bounded = self._read(bundle)
        first, current = trust_policy_chain("installation.adr4-corpus")
        _valid, metadata = valid_bundle()
        verify_extension_bundle(
            bounded, first if genesis else current, _verifier(),
            verified_at="2026-08-20T00:02:00Z",
            production_policy=ExtensionAttestationProductionPolicy.from_dict(
                metadata["production_policy"]
            ),
        )

    def _reject(self, bundle: bytes, code: str, *, genesis: bool = False) -> None:
        with self.assertRaisesRegex(ExtensionBundleError, code):
            self._verify(bundle, genesis=genesis)

    def test_adr4_pkg_p_001(self) -> None:
        self._verify(valid_bundle()[0])

    def test_adr4_pkg_r_001(self) -> None:
        _bundle, metadata = valid_bundle()
        metadata = copy.deepcopy(metadata)
        metadata["manifest"]["archive_raw_digest"] = "sha256-raw-v1:" + "0" * 64  # type: ignore[index]
        self._reject(archive(_entries(metadata)), "E_EXTENSION_DIGEST_CYCLE")

    def test_adr4_pkg_r_002(self) -> None:
        _bundle, metadata = valid_bundle()
        entries = _entries(metadata)
        entries.append((
            "payload/signature-copy.json",
            canonical_bytes(metadata["publisher_signature"]), 0o100444,
        ))
        entries[4:] = sorted(entries[4:], key=lambda item: item[0])
        self._reject(archive(entries), "E_EXTENSION_DIGEST_CYCLE")

    def test_adr4_pkg_r_003(self) -> None:
        _bundle, metadata = valid_bundle()
        entries = _entries(metadata)
        entries.append(entries[-1])
        self._reject(archive(entries), "E_EXTENSION_ARCHIVE_PROFILE")

    def test_adr4_pkg_r_004(self) -> None:
        _bundle, metadata = valid_bundle()
        entries = _entries(metadata)
        name, _body, mode = entries[-1]
        entries[-1] = (name, b"changed", mode)
        self._reject(archive(entries), "E_EXTENSION_PAYLOAD_ROOT")

    def test_adr4_pkg_r_005(self) -> None:
        _bundle, metadata = valid_bundle()
        metadata = copy.deepcopy(metadata)
        metadata["source"]["projection_substitution"] = True  # type: ignore[index]
        self._reject(archive(_entries(metadata)), "E_EXTENSION_PROJECTION")

    def test_adr4_pkg_r_006(self) -> None:
        self._reject(
            bundle_with_invalid_publisher_signature(), "E_EXTENSION_SIGNATURE_INPUT"
        )

    def test_adr4_pkg_r_007(self) -> None:
        self._reject(valid_bundle()[0], "E_EXTENSION_TRUST_ROOT", genesis=True)

    def test_adr4_pkg_r_008(self) -> None:
        bundle, _metadata = valid_bundle()
        directory = tempfile.TemporaryDirectory(prefix="gew-adr4-source-change-")
        self.addCleanup(directory.cleanup)
        path = pathlib.Path(directory.name) / "candidate.gewx"
        path.write_bytes(bundle)
        os.chmod(path, 0o600)
        policy = json.loads(
            (ROOT / "config/extensions/extension-bundle-policy-v1.json").read_text()
        )
        reader = ExtensionBundleReader.from_dict(policy)
        actual_fstat = os.fstat
        calls = 0

        def changed_fstat(descriptor: int):  # type: ignore[no-untyped-def]
            nonlocal calls
            result = actual_fstat(descriptor)
            calls += 1
            if calls != 2:
                return result
            return types.SimpleNamespace(
                st_mode=result.st_mode, st_uid=result.st_uid, st_nlink=result.st_nlink,
                st_size=result.st_size, st_dev=result.st_dev, st_ino=result.st_ino,
                st_mtime_ns=result.st_mtime_ns + 1,
            )

        with mock.patch(
            "graph_engineering.storage.extension_bundle.os.fstat",
            side_effect=changed_fstat,
        ), self.assertRaisesRegex(ExtensionBundleError, "E_EXTENSION_SOURCE_CHANGED"):
            reader.read(path)

    def test_adr4_pkg_r_009(self) -> None:
        _bundle, metadata = valid_bundle()
        metadata = copy.deepcopy(metadata)
        manifest = metadata["manifest"]
        manifest["exported_ids"] = manifest.pop("exported_identities")  # type: ignore[union-attr]
        self._reject(archive(_entries(metadata)), "E_EXTENSION_PACKAGE_IDENTITY")

    def test_adr4_pkg_r_010(self) -> None:
        _bundle, metadata = valid_bundle()
        metadata = copy.deepcopy(metadata)
        metadata["manifest"].pop("payload_root_digest")  # type: ignore[union-attr]
        self._reject(archive(_entries(metadata)), "E_EXTENSION_PAYLOAD_ROOT")


if __name__ == "__main__":
    unittest.main()
