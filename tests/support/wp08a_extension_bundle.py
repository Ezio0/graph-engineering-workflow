"""Deterministic, local-only ADR-0004 bundle fixtures."""

from __future__ import annotations

import base64
import binascii
import json
import pathlib
import struct
from collections.abc import Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import raw_digest, semantic_digest
from graph_engineering.core.extension_activation import (
    ExtensionActivationPolicy,
    ExtensionBuiltInRegistry,
    activation_resource_binding_digest,
)
from graph_engineering.core.extension_data import ExtensionCoreInvariantSet
from graph_engineering.core.security.extensions import (
    EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST,
    ExtensionTrustPolicy,
    extension_capability_set_digest,
)


DIGEST = "sha256-jcs-v1:" + "a" * 64
SEED = bytes(range(32))
_ABSENT = object()
ROOT = pathlib.Path(__file__).resolve().parents[2]


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _digest(body: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _complete(body: Mapping[str, object], name: str, field: str) -> dict[str, object]:
    return {**body, field: _digest(body, name)}


def archive(entries: list[tuple[str, bytes, int]]) -> bytes:
    local = bytearray()
    central = bytearray()
    offset = 0
    for name, body, mode in entries:
        encoded = name.encode()
        crc = binascii.crc32(body) & 0xFFFFFFFF
        local.extend(
            struct.pack(
                "<IHHHHHIIIHH", 0x04034B50, 20, 0x800, 0, 0, 0x21,
                crc, len(body), len(body), len(encoded), 0,
            )
            + encoded
            + body
        )
        central.extend(
            struct.pack(
                "<IHHHHHHIIIHHHHHII", 0x02014B50, (3 << 8) | 20, 20,
                0x800, 0, 0, 0x21, crc, len(body), len(body), len(encoded),
                0, 0, 0, 0, mode << 16, offset,
            )
            + encoded
        )
        offset = len(local)
    return bytes(
        local
        + central
        + struct.pack(
            "<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries),
            len(central), len(local), 0,
        )
    )


def valid_bundle(
    *,
    extension_id: str = "extension.example",
    extension_version: str = "1.0.0",
    extension_points: list[dict[str, object]] | None = None,
    exported_identities: list[dict[str, object]] | None = None,
    requested_capabilities: list[dict[str, object]] | None = None,
    compatibility: dict[str, object] | None = None,
    data_records: list[dict[str, object]] | None = None,
    previous_attestation_digest: object = _ABSENT,
    source_issued_at: str = "2026-08-20T00:00:00Z",
    build_started_at: str = "2026-08-20T00:00:00Z",
    build_finished_at: str = "2026-08-20T00:01:00Z",
) -> tuple[bytes, dict[str, object]]:
    private = Ed25519PrivateKey.from_private_bytes(SEED)
    public = _b64(
        private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    )
    points = [] if extension_points is None else extension_points
    if data_records is None and points:
        invariant = ExtensionCoreInvariantSet.from_dict(
            json.loads(
                (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text()
            )
        )
        generated: list[dict[str, object]] = []
        for point in points:
            kind = str(point["kind"])
            identity = str(point["id"])
            dependencies: list[dict[str, str]] = []
            body = {
                "node": {
                    "node_semantics": "declarative-only",
                    "input_schema_id": "urn:gew:schema:input-example:1.0.0",
                    "output_schema_id": "urn:gew:schema:output-example:1.0.0",
                    "invalidation_tags": [],
                },
                "edge": {
                    "source_id": "core.task-runner", "target_id": "core.task-runner",
                    "edge_type": "typed-data", "condition_ref": None,
                    "invalidation_mode": "descendants",
                },
                "policy": {"policy_effect": "constrain-only", "rule_ids": []},
                "template": {
                    "template_schema_id": "urn:gew:schema:template-example:1.0.0",
                    "template_text": "deterministic extension template",
                },
            }.get(kind)
            if body is None:
                continue
            if kind == "edge":
                dependencies = [{"kind": "node", "id": "core.task-runner"}]
            source = {
                "schema_version": "1.0.0", "data_kind": kind, "identity_id": identity,
                "data_version": "1.0.0", "dependencies": dependencies,
                "core_invariant_set_digest": invariant.invariant_set_digest,
                "security_effect": "constrain-only", "body": body,
            }
            generated.append(_complete(source, f"extension-data-{kind}", "record_digest"))
        data_records = generated
    records = [] if data_records is None else data_records
    record_by_identity = {
        (str(item["data_kind"]), str(item["identity_id"])): str(item["record_digest"])
        for item in records
    }
    normalized_points = [
        {
            **item,
            "contract_digest": record_by_identity.get(
                (str(item["kind"]), str(item["id"])), item["contract_digest"]
            ),
        }
        for item in points
    ]
    normalized_points.sort(key=canonical_bytes)
    source_exports = normalized_points if exported_identities is None else exported_identities
    normalized_exports = [
        {
            **item,
            "contract_digest": record_by_identity.get(
                (str(item["kind"]), str(item["id"])), item["contract_digest"]
            ),
        }
        for item in source_exports
    ]
    normalized_exports.sort(key=canonical_bytes)
    payload_entries = [("payload/hello.txt", b"hello", 0o100444)]
    payload_entries.extend(
        [
        (
            f"payload/data/{str(item['record_digest']).removeprefix('sha256-jcs-v1:')}.json",
            canonical_bytes(item),
            0o100444,
        )
        for item in records
        ]
    )
    payload_entries.sort(key=lambda item: item[0])
    payload_root_body = {
        "schema_version": "1.0.0",
        "entries": [
            {
                "path": path, "kind": "data", "size": len(payload),
                "raw_digest": raw_digest(payload), "executable": False,
            }
            for path, payload, _mode in payload_entries
        ],
    }
    payload_root_digest = _digest(payload_root_body, "extension-payload-root")
    semantics = {
        "contract_id": "extension.noop", "contract_version": "1.0.0",
        "contract_digest": DIGEST,
    }
    identity_body: dict[str, object] = {
        "schema_version": "1.0.0", "publisher_id": "publisher.example",
        "extension_id": extension_id, "extension_version": extension_version,
        "release_id": "release.example.1", "package_class": "data-only",
        "extension_points": normalized_points,
        "exported_identities": normalized_exports,
        "input_schema_ids": [],
        "output_schema_ids": [], "contract_registry_digest": DIGEST,
        "compatibility": compatibility or {
            "core_version_range": ">=0.1,<1", "cli_protocol_range": ">=1,<2",
            "schema_profile_range": ">=1,<2", "geel_range": ">=1,<2",
            "runtime_capabilities_digest": DIGEST,
        },
        "requested_capabilities": (
            [] if requested_capabilities is None else requested_capabilities
        ), "operation_classes": [], "ordered_resources": [],
        "side_effects": [], "idempotency_semantics": semantics,
        "failure_semantics": semantics, "verification_semantics": semantics,
        "executable_contract": None,
    }
    identity = _complete(identity_body, "extension-package-identity", "package_identity_digest")
    production_unsigned: dict[str, object] = {
        "schema_version": "1.0.0", "policy_id": "production.example.1",
        "issuer_id": "publisher.example", "issuer_key_id": "key.example.1",
        "allowed_source_types": ["local-fixture"],
        "required_source_material_kinds": ["file"],
        "allowed_attestor_ids": ["publisher.example"],
        "allowed_builder_ids": ["publisher.example"],
        "allowed_build_recipe_digests": [DIGEST],
        "allowed_toolchain_digests": [DIGEST],
        "dependency_and_sbom_rules": {
            "dependency_lock_required": True, "sbom_required": True,
        },
        "maximum_attestation_lifetime": 63_072_000,
        "issued_at": "2026-08-20T00:00:00Z",
        "not_before": "2026-08-19T00:00:00Z",
        "not_after": "2027-08-20T00:00:00Z",
    }
    production_signature = _b64(
        private.sign(
            b"GEW-EXTENSION-ATTESTATION-PRODUCTION-POLICY-V1\0"
            + canonical_bytes(production_unsigned)
        )
    )
    production_policy = _complete(
        {**production_unsigned, "policy_signature": production_signature},
        "extension-attestation-production-policy", "policy_digest",
    )
    production_digest = str(production_policy["policy_digest"])
    source_unsigned: dict[str, object] = {
        "schema_version": "1.0.0", "attestation_id": "source.attestation.1",
        "source_type": "local-fixture", "source_id": "source.example",
        "source_revision": "revision.1", "source_tree_digest": DIGEST,
        "ordered_materials": [{"uri": "file:source", "digest": DIGEST}],
        "source_recipe_digest": DIGEST, "attestor_id": "publisher.example",
        "attestor_key_id": "key.example.1", "issued_at": source_issued_at,
        "not_before": "2026-08-19T00:00:00Z", "not_after": "2027-08-20T00:00:00Z",
        "production_policy_id": "production.example.1",
        "production_policy_digest": production_digest,
    }
    if previous_attestation_digest is not _ABSENT:
        source_unsigned["previous_attestation_digest"] = previous_attestation_digest
    source_signature = _b64(
        private.sign(
            b"GEW-EXTENSION-SOURCE-ATTESTATION-V1\0" + canonical_bytes(source_unsigned)
        )
    )
    source = _complete(
        {**source_unsigned, "attestation_signature": source_signature},
        "extension-source-attestation", "attestation_digest",
    )
    build_unsigned: dict[str, object] = {
        "schema_version": "1.0.0", "attestation_id": "build.attestation.1",
        "builder_id": "publisher.example", "builder_key_id": "key.example.1",
        "build_id": "build.example.1", "source_attestation_digest": source["attestation_digest"],
        "extension_id": extension_id, "extension_version": extension_version,
        "payload_root_digest": payload_root_digest,
        "package_identity_digest": identity["package_identity_digest"],
        "ordered_materials": [{"name": "source", "digest": source["attestation_digest"]}],
        "build_recipe_digest": DIGEST, "toolchain_digest": DIGEST,
        "dependency_lock_digest": DIGEST, "sbom_digest": DIGEST,
        "started_at": build_started_at, "finished_at": build_finished_at,
        "not_before": "2026-08-19T00:00:00Z", "not_after": "2027-08-20T00:00:00Z",
        "production_policy_id": "production.example.1",
        "production_policy_digest": production_digest,
    }
    build_signature = _b64(
        private.sign(
            b"GEW-EXTENSION-BUILD-ATTESTATION-V1\0" + canonical_bytes(build_unsigned)
        )
    )
    build = _complete(
        {**build_unsigned, "attestation_signature": build_signature},
        "extension-build-attestation", "attestation_digest",
    )
    manifest_body = {
        **identity_body,
        "source_attestation_digest": source["attestation_digest"],
        "build_attestation_digest": build["attestation_digest"],
        "payload_root_digest": payload_root_digest,
        "package_identity_digest": identity["package_identity_digest"],
        "signing_suite": "ed25519-v1", "publisher_key_id": "key.example.1",
        "revocation_sequence_floor": 0,
    }
    manifest = _complete(manifest_body, "extension-package-manifest", "manifest_digest")
    statement = {
        "build_attestation_digest": build["attestation_digest"],
        "manifest_digest": manifest["manifest_digest"],
        "payload_root_digest": payload_root_digest,
        "publisher_id": "publisher.example", "publisher_key_id": "key.example.1",
        "schema_version": "1.0.0", "signing_suite": "ed25519-sha256-gew-jcs-v1",
    }
    publisher_signature = _complete(
        {**statement, "signature": _b64(private.sign(b"GEW-EXTENSION-SIGNATURE-V1\0" + canonical_bytes(statement)))},
        "extension-publisher-signature", "signature_record_digest",
    )
    entries = [
        ("META-INF/extension-package-manifest.json", canonical_bytes(manifest), 0o100444),
        ("META-INF/source-attestation.json", canonical_bytes(source), 0o100444),
        ("META-INF/build-attestation.json", canonical_bytes(build), 0o100444),
        ("META-INF/publisher-signature.json", canonical_bytes(publisher_signature), 0o100444),
        *payload_entries,
    ]
    return archive(entries), {
        "public_key": public, "production_policy_digest": production_digest,
        "production_policy": production_policy,
        "manifest": manifest, "source": source, "build": build,
        "publisher_signature": publisher_signature, "payload_entries": payload_entries,
    }


def bundle_with_invalid_publisher_signature() -> bytes:
    _body, metadata = valid_bundle()
    signature = dict(metadata["publisher_signature"])
    encoded = str(signature["signature"])
    signature["signature"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    signature.pop("signature_record_digest")
    signature = _complete(
        signature, "extension-publisher-signature", "signature_record_digest"
    )
    return archive(
        [
            (
                "META-INF/extension-package-manifest.json",
                canonical_bytes(metadata["manifest"]), 0o100444,
            ),
            (
                "META-INF/source-attestation.json",
                canonical_bytes(metadata["source"]), 0o100444,
            ),
            (
                "META-INF/build-attestation.json",
                canonical_bytes(metadata["build"]), 0o100444,
            ),
            (
                "META-INF/publisher-signature.json",
                canonical_bytes(signature), 0o100444,
            ),
            *metadata["payload_entries"],
        ]
    )


def trust_policy_chain(
    installation_id: str,
    *,
    requested_capabilities: list[dict[str, object]] | None = None,
    compatibility: dict[str, object] | None = None,
) -> tuple[ExtensionTrustPolicy, ExtensionTrustPolicy]:
    activation_policy = ExtensionActivationPolicy.from_dict(
        json.loads(
            (ROOT / "config/extensions/extension-activation-policy-v1.json").read_text(
                encoding="utf-8"
            )
        )
    )
    built_in_registry = ExtensionBuiltInRegistry.from_dict(
        json.loads(
            (ROOT / "config/extensions/extension-built-in-identities-v1.json").read_text(
                encoding="utf-8"
            )
        )
    )
    core_invariant_set = ExtensionCoreInvariantSet.from_dict(
        json.loads(
            (ROOT / "config/extensions/extension-core-invariants-v1.json").read_text(
                encoding="utf-8"
            )
        )
    )
    resource_policy_digest = activation_resource_binding_digest(
        activation_policy, built_in_registry, core_invariant_set
    )
    genesis_body: dict[str, object] = {
        "schema_version": "1.0.0", "installation_id": installation_id, "generation": 0,
        "previous_policy_digest": None, "revocation_high_water": 0, "revocations": [],
        "trust_keys": [], "production_policies": [], "source_rules": [], "namespace_rules": [],
        "extension_kind_rules": [], "capability_ceilings": [], "compatibility_floors": [],
        "resource_policy_digest": resource_policy_digest,
        "reducer_id": "gew.extension-trust-policy-reducer",
        "reducer_version": "1.0.0",
        "reducer_implementation_digest": EXTENSION_TRUST_REDUCER_IMPLEMENTATION_DIGEST,
    }
    genesis = ExtensionTrustPolicy.from_dict(
        _complete(genesis_body, "extension-trust-policy", "policy_digest")
    )
    _bundle, metadata = valid_bundle(
        requested_capabilities=requested_capabilities,
        compatibility=compatibility,
    )
    manifest = metadata["manifest"]
    assert isinstance(manifest, dict)
    compatibility = manifest["compatibility"]
    assert isinstance(compatibility, dict)
    capability_ids = sorted(
        str(item["capability_id"])
        for item in manifest["requested_capabilities"]
    )
    capability_ceiling_digest = extension_capability_set_digest(
        "publisher", "publisher.example", capability_ids
    )
    compatibility_floors = sorted(
        [
            {
                "component_kind": component,
                "compatibility_policy_digest": _digest(
                    {
                        "schema_version": "1.0.0",
                        "component_kind": component,
                        "accepted_declarations": [declaration],
                    },
                    "extension-compatibility-floor",
                ),
            }
            for component, declaration in compatibility.items()
        ],
        key=canonical_bytes,
    )
    body = genesis.to_dict()
    body.update(
        generation=1, previous_policy_digest=genesis.policy_digest,
        trust_keys=[
            {
                "publisher_id": "publisher.example", "key_id": "key.example.1",
                "ed25519_public_key": metadata["public_key"],
                "roles": ["builder", "provenance-policy", "publisher-release", "source-attestor"],
                "source_classes": ["local-fixture"], "namespaces": ["extension."],
                "extension_kinds": ["data-only"],
                "allowed_production_policy_digests": [metadata["production_policy_digest"]],
                "capability_ceiling_digest": capability_ceiling_digest,
                "not_before": "2026-08-19T00:00:00Z", "not_after": "2027-08-20T00:00:00Z",
                "status": "active", "added_generation": 1, "revocation_sequence": 0,
            }
        ],
        production_policies=[
            {
                "policy_id": "production.example.1",
                "policy_digest": metadata["production_policy_digest"],
                "issuer_id": "publisher.example", "status": "active", "added_generation": 1,
            }
        ],
        source_rules=[{
            "source_type": "local-fixture", "allowed_source_ids": ["source.example"],
            "required_material_kinds": ["file"], "rule_mode": "exact",
        }],
        namespace_rules=[{
            "publisher_id": "publisher.example", "namespace_prefix": "extension.",
            "allowed_extension_kinds": ["data-only"],
        }],
        extension_kind_rules=[{
            "extension_kind": "data-only", "data_allowed": True,
            "executable_allowed": False, "required_isolation_profiles": [],
        }],
        capability_ceilings=[{
            "subject_kind": "publisher", "subject_id": "publisher.example",
            "capability_ids": capability_ids,
            "capability_set_digest": capability_ceiling_digest,
        }],
        compatibility_floors=compatibility_floors,
    )
    body.pop("policy_digest")
    candidate = ExtensionTrustPolicy.from_dict(
        _complete(body, "extension-trust-policy", "policy_digest"), previous=genesis
    )
    return genesis, candidate
