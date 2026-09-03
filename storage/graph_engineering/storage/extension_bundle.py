"""Bounded offline reader for the ADR-0004 immutable ZIP profile."""

from __future__ import annotations

import io
import os
import pathlib
import stat
import struct
import unicodedata
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from graph_engineering.core.contracts.digest import raw_digest
from graph_engineering.core.extension_bundle import (
    ExtensionAttestationProductionPolicy,
    ExtensionBuildAttestation,
    ExtensionPayloadRoot,
    ExtensionPublisherSignature,
    ExtensionSourceAttestation,
)
from graph_engineering.core.extensions import Ed25519Verifier
from graph_engineering.core.security._common import parse_timestamp
from graph_engineering.core.security.extensions import (
    ExtensionPackageIdentity,
    ExtensionPackageManifest,
    ExtensionTrustPolicy,
    extension_capability_set_digest,
)

from .codec import canonical_json, parse_canonical_json


class ExtensionBundleError(ValueError):
    """The archive is outside the exact offline extension profile."""


@dataclass(frozen=True, slots=True)
class ExtensionBundlePolicy:
    policy_id: str
    required_metadata_members: tuple[str, ...]
    max_archive_bytes: int
    max_members: int
    max_member_bytes: int
    max_metadata_member_bytes: int
    max_total_uncompressed_bytes: int
    allowed_archive_file_modes: tuple[int, ...]
    data_member_mode: int
    executable_member_mode: int
    installed_content_directory: str
    installed_directory_mode: int
    installed_file_mode: int

    @classmethod
    def from_dict(cls, value: object) -> ExtensionBundlePolicy:
        fields = {
            "schema_version", "policy_id", "required_metadata_members",
            "max_archive_bytes", "max_members", "max_member_bytes",
            "max_metadata_member_bytes", "max_total_uncompressed_bytes",
            "allowed_archive_file_modes", "data_member_mode", "executable_member_mode",
            "installed_content_directory", "installed_directory_mode", "installed_file_mode",
        }
        if not isinstance(value, Mapping) or set(value) != fields or value.get("schema_version") != "1.0.0":
            raise ExtensionBundleError("extension bundle policy is not exact")
        identity = value.get("policy_id")
        metadata = value.get("required_metadata_members")
        modes = value.get("allowed_archive_file_modes")
        integers = (
            value.get("max_archive_bytes"), value.get("max_members"),
            value.get("max_member_bytes"), value.get("max_metadata_member_bytes"),
            value.get("max_total_uncompressed_bytes"), value.get("data_member_mode"),
            value.get("executable_member_mode"), value.get("installed_directory_mode"),
            value.get("installed_file_mode"),
        )
        content_directory = value.get("installed_content_directory")
        if (
            type(identity) is not str or not identity
            or type(metadata) is not list or not metadata
            or any(type(item) is not str or not item for item in metadata)
            or len(set(metadata)) != len(metadata)
            or type(modes) is not list or modes != sorted(set(modes))
            or any(type(mode) is not int or mode < 0 for mode in modes)
            or any(type(item) is not int or item < 1 for item in integers)
            or type(content_directory) is not str
            or content_directory != pathlib.PurePath(content_directory).name
            or not content_directory
            or integers[-2:] != (0o500, 0o400)
        ):
            raise ExtensionBundleError("extension bundle policy values are invalid")
        return cls(
            identity, tuple(metadata), *integers[:5], tuple(modes), *integers[5:7],
            content_directory, *integers[7:],  # type: ignore[arg-type]
        )


@dataclass(frozen=True, slots=True)
class BoundedExtensionBundle:
    archive_raw_digest: str
    members: Mapping[str, bytes]
    member_modes: Mapping[str, int]


@dataclass(frozen=True, slots=True)
class VerifiedExtensionBundle:
    archive_raw_digest: str
    manifest: ExtensionPackageManifest
    payload_root: ExtensionPayloadRoot
    source_attestation: ExtensionSourceAttestation
    build_attestation: ExtensionBuildAttestation
    publisher_signature: ExtensionPublisherSignature
    trust_policy_digest: str


class ExtensionBundleReader:
    """Read one local regular file without paths, callbacks, lookup, or network."""

    def __init__(self, policy: ExtensionBundlePolicy) -> None:
        self._policy = policy

    @classmethod
    def from_dict(cls, value: object) -> ExtensionBundleReader:
        return cls(ExtensionBundlePolicy.from_dict(value))

    @staticmethod
    def _reject(message: str) -> ExtensionBundleError:
        return ExtensionBundleError(f"E_EXTENSION_ARCHIVE_PROFILE: {message}")

    def read(self, path: pathlib.Path) -> BoundedExtensionBundle:
        if not isinstance(path, pathlib.Path) or not path.is_absolute():
            raise self._reject("archive path is not an exact absolute path")
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise self._reject("archive cannot be opened safely") from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != os.getuid()
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) not in self._policy.allowed_archive_file_modes
                or before.st_size > self._policy.max_archive_bytes
            ):
                raise self._reject("archive descriptor identity or size is invalid")
            chunks = bytearray()
            while len(chunks) <= self._policy.max_archive_bytes:
                chunk = os.read(descriptor, min(1024 * 1024, self._policy.max_archive_bytes + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            after = os.fstat(descriptor)
            if (
                len(chunks) != before.st_size
                or len(chunks) > self._policy.max_archive_bytes
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            ):
                raise ExtensionBundleError(
                    "E_EXTENSION_SOURCE_CHANGED: archive changed during bounded read"
                )
        finally:
            os.close(descriptor)
        body = bytes(chunks)
        try:
            archive = zipfile.ZipFile(io.BytesIO(body), "r")
            infos = archive.infolist()
        except (OSError, zipfile.BadZipFile) as error:
            raise self._reject("archive structure is invalid") from error
        try:
            if len(infos) > self._policy.max_members or not infos:
                raise self._reject("archive member count is invalid")
            names = [info.filename for info in infos]
            if len(set(names)) != len(names):
                raise self._reject("archive contains duplicate physical or logical members")
            metadata = list(self._policy.required_metadata_members)
            payload = names[len(metadata):]
            if names[:len(metadata)] != metadata or payload != sorted(payload):
                raise self._reject("archive member order is not canonical")
            total = 0
            loaded: dict[str, bytes] = {}
            modes: dict[str, int] = {}
            for index, info in enumerate(infos):
                name = info.filename
                pure = pathlib.PurePosixPath(name)
                if (
                    not name or "\\" in name or "\0" in name
                    or name != unicodedata.normalize("NFC", name)
                    or pure.is_absolute() or ".." in pure.parts or "." in pure.parts
                    or info.is_dir() or (index >= len(metadata) and not name.startswith("payload/"))
                    or info.flag_bits != 0x800 or info.compress_type != zipfile.ZIP_STORED
                    or info.create_system != 3 or info.create_version != 20 or info.extract_version != 20
                    or info.extra or info.comment or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or (info.external_attr >> 16)
                    not in {self._policy.data_member_mode, self._policy.executable_member_mode}
                    or info.file_size != info.compress_size
                    or info.file_size > self._policy.max_member_bytes
                    or (index < len(metadata) and info.file_size > self._policy.max_metadata_member_bytes)
                ):
                    raise self._reject("archive member profile is invalid")
                total += info.file_size
                if total > self._policy.max_total_uncompressed_bytes:
                    raise self._reject("archive aggregate size exceeds policy")
                self._verify_local_header(body, info)
                loaded[name] = archive.read(info)
                modes[name] = info.external_attr >> 16
                if len(loaded[name]) != info.file_size:
                    raise self._reject("archive member length changed")
            self._verify_end_record(body, len(infos))
            return BoundedExtensionBundle(
                raw_digest(body), MappingProxyType(loaded), MappingProxyType(modes)
            )
        except (OSError, RuntimeError, zipfile.BadZipFile) as error:
            raise self._reject("archive member verification failed") from error
        finally:
            archive.close()

    def _verify_local_header(self, body: bytes, info: zipfile.ZipInfo) -> None:
        try:
            values = struct.unpack_from("<IHHHHHIIIHH", body, info.header_offset)
        except struct.error as error:
            raise self._reject("local header is truncated") from error
        signature, version, flags, method, time, date, crc, compressed, size, name_size, extra_size = values
        start = info.header_offset + 30
        name = body[start:start + name_size]
        if (
            signature != 0x04034B50 or version != 20 or flags != 0x800 or method != 0
            or time != 0 or date != 0x21 or crc != info.CRC
            or compressed != info.compress_size or size != info.file_size or extra_size != 0
            or name != info.filename.encode("utf-8")
        ):
            raise self._reject("local and central headers do not match")

    def _verify_end_record(self, body: bytes, count: int) -> None:
        if len(body) < 22:
            raise self._reject("archive end record is missing")
        values = struct.unpack_from("<IHHHHIIH", body, len(body) - 22)
        signature, disk, central_disk, disk_count, total_count, central_size, central_offset, comment = values
        if (
            signature != 0x06054B50 or disk != 0 or central_disk != 0
            or disk_count != count or total_count != count or comment != 0
            or central_offset + central_size + 22 != len(body)
        ):
            raise self._reject("archive end record or trailing bytes are invalid")


def _metadata_document(bundle: BoundedExtensionBundle, name: str) -> Mapping[str, object]:
    try:
        encoded = bundle.members[name].decode("utf-8")
        value = parse_canonical_json(encoded)
    except (KeyError, UnicodeDecodeError, ValueError) as error:
        raise ExtensionBundleError("E_EXTENSION_PROJECTION: metadata is not canonical JSON") from error
    if not isinstance(value, Mapping) or canonical_json(value).encode() != bundle.members[name]:
        raise ExtensionBundleError("E_EXTENSION_PROJECTION: metadata body is not exact")
    return value


def _key(
    policy: ExtensionTrustPolicy,
    *,
    publisher_id: str,
    key_id: str,
    role: str,
    production_policy_digest: str,
    source_type: str,
    extension_id: str,
    extension_kind: str,
    verified_at: str,
) -> Mapping[str, object]:
    observed_at = parse_timestamp(verified_at, "extension verification time")
    matches = [
        item
        for item in policy.to_dict()["trust_keys"]
        if isinstance(item, Mapping)
        and item.get("publisher_id") == publisher_id
        and item.get("key_id") == key_id
        and item.get("status") == "active"
        and role in item.get("roles", [])
        and source_type in item.get("source_classes", [])
        and any(extension_id.startswith(str(prefix)) for prefix in item.get("namespaces", []))
        and extension_kind in item.get("extension_kinds", [])
        and production_policy_digest in item.get("allowed_production_policy_digests", [])
        and int(item.get("revocation_sequence", 0)) <= policy.revocation_high_water
        and parse_timestamp(item.get("not_before"), "trust key not-before") <= observed_at
        <= parse_timestamp(item.get("not_after"), "trust key not-after")
    ]
    if len(matches) != 1:
        raise ExtensionBundleError("E_EXTENSION_TRUST_ROOT: exact active trust key is unavailable")
    return matches[0]


def _revoked(policy: ExtensionTrustPolicy, kind: str, digest: str) -> bool:
    return any(
        isinstance(item, Mapping)
        and item.get("target_kind") == kind
        and item.get("target_identity_digest") == digest
        and int(item.get("local_sequence", 0)) <= policy.revocation_high_water
        for item in policy.to_dict()["revocations"]
    )


def _policy_digest(body: Mapping[str, object], name: str) -> str:
    from graph_engineering.core.contracts.digest import semantic_digest

    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def verify_extension_bundle(
    bundle: BoundedExtensionBundle,
    policy: ExtensionTrustPolicy,
    verifier: Ed25519Verifier,
    *,
    verified_at: str,
    production_policy: ExtensionAttestationProductionPolicy | None,
) -> VerifiedExtensionBundle:
    """Verify one bounded immutable bundle without granting activation authority."""

    if (
        type(bundle) is not BoundedExtensionBundle
        or type(policy) is not ExtensionTrustPolicy
        or type(production_policy) is not ExtensionAttestationProductionPolicy
    ):
        raise TypeError("extension bundle production policy verification inputs are invalid")
    manifest_document = _metadata_document(
        bundle, "META-INF/extension-package-manifest.json"
    )
    source_document = _metadata_document(bundle, "META-INF/source-attestation.json")
    build_document = _metadata_document(bundle, "META-INF/build-attestation.json")
    signature_document = _metadata_document(
        bundle, "META-INF/publisher-signature.json"
    )
    if any(
        field in manifest_document
        for field in (
            "archive_raw_digest", "publisher_signature_digest",
            "signature_record_digest",
        )
    ) or "manifest_digest" in build_document:
        raise ExtensionBundleError(
            "E_EXTENSION_DIGEST_CYCLE: bundle digest graph is cyclic"
        )
    if (
        "exported_identities" not in manifest_document
        or "exported_ids" in manifest_document
        or "exported" in manifest_document
    ):
        raise ExtensionBundleError(
            "E_EXTENSION_PACKAGE_IDENTITY: exported identity wire field is not exact"
        )
    signature_bytes = bundle.members["META-INF/publisher-signature.json"]
    if any(
        name.startswith("payload/")
        and ("signature" in name or body == signature_bytes)
        for name, body in bundle.members.items()
    ):
        raise ExtensionBundleError(
            "E_EXTENSION_DIGEST_CYCLE: signature member is payload-enumerated"
        )
    if "payload_root_digest" not in manifest_document:
        raise ExtensionBundleError(
            "E_EXTENSION_PAYLOAD_ROOT: payload-root version or digest is unavailable"
        )
    manifest_only = {
        "source_attestation_digest", "build_attestation_digest", "payload_root_digest",
        "signing_suite", "publisher_key_id", "revocation_sequence_floor",
        "manifest_digest",
    }
    try:
        ExtensionPackageIdentity.from_dict({
            key: value for key, value in manifest_document.items()
            if key not in manifest_only
        })
    except ValueError as error:
        raise ExtensionBundleError(
            "E_EXTENSION_PACKAGE_IDENTITY: manifest identity reconstruction failed"
        ) from error
    try:
        manifest = ExtensionPackageManifest.from_dict(manifest_document)
        source = ExtensionSourceAttestation.from_dict(
            source_document
        )
        build = ExtensionBuildAttestation.from_dict(
            build_document
        )
        signature = ExtensionPublisherSignature.from_dict(
            signature_document
        )
        payload = ExtensionPayloadRoot.from_members(bundle.members, bundle.member_modes)
    except ValueError as error:
        raise ExtensionBundleError("E_EXTENSION_PROJECTION: bundle contract verification failed") from error

    manifest_body = manifest.to_dict()
    source_body = source.to_dict()
    build_body = build.to_dict()
    signature_body = signature.to_dict()
    if manifest_body["payload_root_digest"] != payload.payload_root_digest:
        raise ExtensionBundleError(
            "E_EXTENSION_PAYLOAD_ROOT: payload projection differs from the manifest"
        )
    exact_links = (
        manifest_body["source_attestation_digest"] == source.attestation_digest,
        manifest_body["build_attestation_digest"] == build.attestation_digest,
        build_body["source_attestation_digest"] == source.attestation_digest,
        build_body["payload_root_digest"] == payload.payload_root_digest,
        build_body["package_identity_digest"] == manifest.package_identity_digest,
        build_body["extension_id"] == manifest_body["extension_id"],
        build_body["extension_version"] == manifest_body["extension_version"],
        signature_body["build_attestation_digest"] == build.attestation_digest,
        signature_body["manifest_digest"] == manifest_body["manifest_digest"],
        signature_body["payload_root_digest"] == payload.payload_root_digest,
        signature_body["publisher_id"] == manifest_body["publisher_id"],
        signature_body["publisher_key_id"] == manifest_body["publisher_key_id"],
    )
    if not all(exact_links):
        raise ExtensionBundleError("E_EXTENSION_PROVENANCE: exact subject/product linkage failed")
    observed_at = parse_timestamp(verified_at, "extension verification time")
    for attestation_body in (source_body, build_body):
        if not (
            parse_timestamp(attestation_body["not_before"], "attestation not-before")
            <= observed_at
            <= parse_timestamp(attestation_body["not_after"], "attestation not-after")
        ):
            raise ExtensionBundleError("E_EXTENSION_PROVENANCE: attestation is not currently valid")
    if not (
        parse_timestamp(source_body["issued_at"], "source issued-at")
        <= parse_timestamp(build_body["started_at"], "build started-at")
        <= parse_timestamp(build_body["finished_at"], "build finished-at")
        <= observed_at
    ):
        raise ExtensionBundleError("E_EXTENSION_PROVENANCE: cross-attestation chronology is invalid")
    if int(manifest_body["revocation_sequence_floor"]) > policy.revocation_high_water:
        raise ExtensionBundleError("E_EXTENSION_TRUST_ROOT: revocation high-water is stale")
    production_digest = str(source_body["production_policy_digest"])
    if (
        build_body["production_policy_id"] != source_body["production_policy_id"]
        or build_body["production_policy_digest"] != production_digest
    ):
        raise ExtensionBundleError("E_EXTENSION_PROVENANCE: production policy linkage failed")
    accepted = [
        item for item in policy.to_dict()["production_policies"]
        if isinstance(item, Mapping)
        and item.get("policy_id") == source_body["production_policy_id"]
        and item.get("policy_digest") == production_digest
        and item.get("status") == "active"
    ]
    if len(accepted) != 1:
        raise ExtensionBundleError("E_EXTENSION_TRUST_ROOT: production policy is not installed")

    production_body = production_policy.to_dict()
    if (
        production_body["policy_id"] != source_body["production_policy_id"]
        or production_policy.policy_digest != production_digest
    ):
        raise ExtensionBundleError("E_EXTENSION_PRODUCTION_POLICY: exact policy content is unavailable")
    extension_id = str(manifest_body["extension_id"])
    extension_kind = str(manifest_body["package_class"])
    source_type = str(source_body["source_type"])
    if any(
        _revoked(policy, kind, digest)
        for kind, digest in (
            ("package", manifest.package_identity_digest),
            ("package-identity", manifest.package_identity_digest),
            ("manifest", str(manifest_body["manifest_digest"])),
            ("source-attestation", source.attestation_digest),
            ("build-attestation", build.attestation_digest),
            ("production-policy", production_digest),
        )
    ):
        raise ExtensionBundleError("E_EXTENSION_REVOKED: bundle trust subject is revoked")

    source_rules = [
        item for item in policy.to_dict()["source_rules"]
        if isinstance(item, Mapping)
        and item.get("source_type") == source_type
        and source_body["source_id"] in item.get("allowed_source_ids", [])
        and item.get("rule_mode") == "exact"
    ]
    material_kinds = sorted({
        str(item["uri"]).partition(":")[0]
        for item in source_body["ordered_materials"]  # type: ignore[union-attr]
    })
    if (
        len(source_rules) != 1
        or material_kinds != list(source_rules[0]["required_material_kinds"])
        or material_kinds != list(production_body["required_source_material_kinds"])
        or source_type not in production_body["allowed_source_types"]
        or source_body["attestor_id"] not in production_body["allowed_attestor_ids"]
        or build_body["builder_id"] not in production_body["allowed_builder_ids"]
        or build_body["build_recipe_digest"] not in production_body["allowed_build_recipe_digests"]
        or build_body["toolchain_digest"] not in production_body["allowed_toolchain_digests"]
    ):
        raise ExtensionBundleError("E_EXTENSION_PRODUCTION_POLICY: provenance policy mismatch")
    namespace_rules = [
        item for item in policy.to_dict()["namespace_rules"]
        if isinstance(item, Mapping)
        and item.get("publisher_id") == manifest_body["publisher_id"]
        and extension_id.startswith(str(item.get("namespace_prefix")))
        and extension_kind in item.get("allowed_extension_kinds", [])
    ]
    kind_rules = [
        item for item in policy.to_dict()["extension_kind_rules"]
        if isinstance(item, Mapping) and item.get("extension_kind") == extension_kind
    ]
    if len(namespace_rules) != 1 or len(kind_rules) != 1 or not kind_rules[0]["data_allowed"]:
        raise ExtensionBundleError("E_EXTENSION_POLICY: namespace or extension-kind rule mismatch")

    requested_ids = sorted(
        str(item["capability_id"])
        for item in manifest_body["requested_capabilities"]
    )
    requested_digest = extension_capability_set_digest(
        "publisher", manifest_body["publisher_id"], requested_ids
    )
    ceilings = [
        item for item in policy.to_dict()["capability_ceilings"]
        if isinstance(item, Mapping)
        and item.get("subject_kind") == "publisher"
        and item.get("subject_id") == manifest_body["publisher_id"]
        and item.get("capability_ids") == requested_ids
        and item.get("capability_set_digest") == requested_digest
    ]
    if len(ceilings) != 1:
        raise ExtensionBundleError("E_EXTENSION_CAPABILITY: request exceeds exact ceiling")
    compatibility = manifest_body["compatibility"]
    floors = policy.to_dict()["compatibility_floors"]
    if not isinstance(compatibility, Mapping) or any(
        len([
            item for item in floors
            if isinstance(item, Mapping)
            and item.get("component_kind") == component
            and item.get("compatibility_policy_digest") == _policy_digest(
                {
                    "schema_version": "1.0.0", "component_kind": component,
                    "accepted_declarations": [declaration],
                },
                "extension-compatibility-floor",
            )
        ]) != 1
        for component, declaration in compatibility.items()
    ):
        raise ExtensionBundleError("E_EXTENSION_COMPATIBILITY: declaration is outside policy floors")

    production_observed = parse_timestamp(verified_at, "production policy observation time")
    if not (
        parse_timestamp(production_body["not_before"], "production policy not-before")
        <= production_observed
        <= parse_timestamp(production_body["not_after"], "production policy not-after")
    ):
        raise ExtensionBundleError("E_EXTENSION_PRODUCTION_POLICY: policy is expired")
    lifetime = int(production_body["maximum_attestation_lifetime"])
    for attestation_body in (source_body, build_body):
        duration = parse_timestamp(attestation_body["not_after"], "attestation not-after") - parse_timestamp(
            attestation_body["not_before"], "attestation not-before"
        )
        if duration.total_seconds() > lifetime:
            raise ExtensionBundleError("E_EXTENSION_PRODUCTION_POLICY: attestation lifetime exceeds policy")

    key_arguments = {
        "production_policy_digest": production_digest,
        "source_type": source_type,
        "extension_id": extension_id,
        "extension_kind": extension_kind,
        "verified_at": verified_at,
    }
    production_key = _key(
        policy,
        publisher_id=str(production_body["issuer_id"]),
        key_id=str(production_body["issuer_key_id"]),
        role="provenance-policy",
        **key_arguments,
    )
    if not verifier.verify(
        production_policy.verification_request(str(production_key["ed25519_public_key"]))
    ).valid:
        raise ExtensionBundleError("E_EXTENSION_PRODUCTION_POLICY: signature verification failed")

    requests = (
        source.verification_request(
            str(_key(
                policy,
                publisher_id=str(source_body["attestor_id"]),
                key_id=str(source_body["attestor_key_id"]),
                role="source-attestor",
                **key_arguments,
            )["ed25519_public_key"])
        ),
        build.verification_request(
            str(_key(
                policy,
                publisher_id=str(build_body["builder_id"]),
                key_id=str(build_body["builder_key_id"]),
                role="builder",
                **key_arguments,
            )["ed25519_public_key"])
        ),
        signature.verification_request(
            str(_key(
                policy,
                publisher_id=str(signature_body["publisher_id"]),
                key_id=str(signature_body["publisher_key_id"]),
                role="publisher-release",
                **key_arguments,
            )["ed25519_public_key"])
        ),
    )
    if not all(verifier.verify(request).valid for request in requests):
        raise ExtensionBundleError("E_EXTENSION_SIGNATURE_INPUT: detached signature verification failed")
    if manifest_body["package_class"] != "data-only" or any(
        entry["executable"] for entry in payload.entries
    ):
        raise ExtensionBundleError("E_EXTENSION_EXECUTABLE_CONTRACT_GATE")
    return VerifiedExtensionBundle(
        bundle.archive_raw_digest,
        manifest,
        payload,
        source,
        build,
        signature,
        policy.policy_digest,
    )
