"""Consumer-local ADR-0006 installation and observation authorities."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import pathlib
import tomllib
import weakref
from collections.abc import Mapping
from datetime import datetime, timezone

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version

from graph_engineering.core.contracts.canonical import canonical_bytes
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.dependency_security import (
    DEPENDENCY_SECURITY_SCHEMA_IDS,
    DEPENDENCY_GRAPH_SCHEMA_IDS,
    DependencyGraphPolicyData,
    DependencyRemediationRegistryData,
    DependencyAdvisoryRegistryData,
    DependencyEvaluation,
    DependencyEvaluationRow,
    DependencyRegistryRollbackAuthority,
    DependencySecurityError,
    _validate_verified_dependency_registry_update,
    parse_dependency_advisory_registry,
    parse_dependency_graph_policy_registry,
    parse_dependency_remediation_registry,
    source_is_current,
    validate_dependency_registry_update,
)


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise DependencySecurityError(f"{label} has a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DependencySecurityError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise DependencySecurityError(f"{label} root is not an object")
    return value


def _raw(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(item not in "0123456789abcdef" for item in value)
    ):
        raise DependencySecurityError(f"{label} is not a lowercase SHA-256")
    return value


def _digest(value: object, label: str) -> str:
    if type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None:
        raise DependencySecurityError(f"{label} is not a semantic digest")
    return value


def _self_digest(
    document: Mapping[str, object], *, name: str, field: str,
) -> str:
    expected = _digest(document.get(field), f"{name} digest")
    body = copy.deepcopy(dict(document))
    del body[field]
    actual = semantic_digest(
        freeze(body),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    if not hmac.compare_digest(expected, actual):
        raise DependencySecurityError(f"{name} self digest changed")
    return expected


def _bootstrap_projection() -> tuple[
    DependencyAdvisoryRegistryData,
    FrozenMap,
    tuple[str, ...],
]:
    from graph_engineering import (
        DistributionIdentityError,
        _dependency_advisory_installation_resources,
    )

    try:
        resources = _dependency_advisory_installation_resources()
        (
            provenance_bytes,
            registry_bytes,
            bootstrap_bytes,
            source_artifact_bytes,
            source_attestation_bytes,
            schema_registry_bytes,
        ) = resources[:6]
        schema_count = len(DEPENDENCY_SECURITY_SCHEMA_IDS)
        if len(resources) != 6 + schema_count + 8:
            raise DependencySecurityError(
                "dependency advisory installation resource closure is incomplete"
            )
        schema_bodies = tuple(resources[6:6 + schema_count])
        history_bodies = tuple(resources[6 + schema_count:])
        provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
        pin = provenance["tool"]["gew"]["profile"]["dependency-advisory"]
    except (
        DistributionIdentityError,
        KeyError,
        TypeError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise DependencySecurityError(
            "dependency advisory installation bootstrap is unavailable"
        ) from error
    expected_pin_fields = {
        "registry-id", "registry-digest", "registry-generation",
        "registry-raw-sha256", "registry-source", "registry-resource",
        "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
        "bootstrap-source", "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "source-artifact-id", "source-artifact-digest",
        "source-artifact-raw-sha256", "source-artifact-source",
        "source-artifact-resource", "source-attestation-id",
        "source-attestation-digest", "source-attestation-raw-sha256",
        "source-attestation-source", "source-attestation-resource",
        "source-history-vectors", "bootstrap-history-vectors",
        "schema-vectors", "graph-policy-id", "graph-policy-digest",
        "graph-policy-raw-sha256", "graph-policy-source",
        "graph-policy-resource", "remediation-id", "remediation-digest",
        "remediation-raw-sha256", "remediation-source",
        "remediation-resource", "graph-bootstrap-id",
        "graph-bootstrap-digest", "graph-bootstrap-raw-sha256",
        "graph-bootstrap-source", "graph-bootstrap-resource",
        "build-backend-raw-sha256", "build-backend-source",
        "build-backend-resource", "graph-schema-vectors",
    }
    if type(pin) is not dict or set(pin) != expected_pin_fields:
        raise DependencySecurityError("dependency advisory independent pin is not exact")
    for body, field in (
        (registry_bytes, "registry-raw-sha256"),
        (bootstrap_bytes, "bootstrap-raw-sha256"),
        (source_artifact_bytes, "source-artifact-raw-sha256"),
        (source_attestation_bytes, "source-attestation-raw-sha256"),
        (schema_registry_bytes, "profile-schema-registry-raw-sha256"),
    ):
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), _raw(pin[field], field)):
            raise DependencySecurityError("dependency advisory installation bytes changed")
    source_history = pin["source-history-vectors"]
    source_history_fields = {
        "generation", "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "source-artifact-id",
        "source-artifact-digest", "source-artifact-raw-sha256",
        "source-artifact-source", "source-artifact-resource",
        "source-attestation-id", "source-attestation-digest",
        "source-attestation-raw-sha256", "source-attestation-source",
        "source-attestation-resource",
    }
    if (
        type(source_history) is not list
        or len(source_history) != 2
        or any(
            type(item) is not dict or set(item) != source_history_fields
            for item in source_history
        )
        or [item["generation"] for item in source_history] != [1, 2]
    ):
        raise DependencySecurityError("dependency advisory source history is not exact")

    source_artifact_fields = {
        "schema_version", "artifact_id", "source_id", "source_revision",
        "issuer_id", "advisory_identities", "artifact_digest",
    }
    source_attestation_fields = {
        "schema_version", "attestation_id", "source_artifact_id", "source_id",
        "source_revision", "issuer_id", "source_artifact_raw_sha256",
        "source_artifact_digest", "provenance_kind", "network_mode",
        "attestation_digest",
    }
    identity_fields = {"advisory_id", "advisory_revision"}

    def validate_snapshot(
        vector: dict[str, object], bodies: tuple[bytes, bytes, bytes], label: str,
    ) -> tuple[DependencyAdvisoryRegistryData, dict[str, object]]:
        registry_body, artifact_body, attestation_body = bodies
        for body, field in (
            (registry_body, "registry-raw-sha256"),
            (artifact_body, "source-artifact-raw-sha256"),
            (attestation_body, "source-attestation-raw-sha256"),
        ):
            if not hmac.compare_digest(
                hashlib.sha256(body).hexdigest(), _raw(vector[field], field),
            ):
                raise DependencySecurityError(
                    "dependency advisory source history bytes changed"
                )
        registry_document = _strict_json(registry_body, f"{label} registry")
        parsed = parse_dependency_advisory_registry(registry_document)
        artifact = _strict_json(artifact_body, f"{label} source artifact")
        identities = artifact.get("advisory_identities")
        if (
            set(artifact) != source_artifact_fields
            or artifact.get("schema_version") != "1.0.0"
            or artifact.get("artifact_id") != vector["source-artifact-id"]
            or _self_digest(
                artifact,
                name="dependency-advisory-source-artifact",
                field="artifact_digest",
            ) != vector["source-artifact-digest"]
            or type(identities) is not list
            or not identities
            or any(type(item) is not dict or set(item) != identity_fields for item in identities)
            or tuple(
                (item["advisory_id"], item["advisory_revision"])
                for item in identities
            ) != tuple(sorted(set(
                (item["advisory_id"], item["advisory_revision"])
                for item in identities
            )))
        ):
            raise DependencySecurityError(
                "dependency advisory source history artifact changed"
            )
        attestation = _strict_json(attestation_body, f"{label} source attestation")
        if (
            set(attestation) != source_attestation_fields
            or attestation.get("schema_version") != "1.0.0"
            or attestation.get("attestation_id") != vector["source-attestation-id"]
            or attestation.get("source_artifact_id") != artifact["artifact_id"]
            or attestation.get("source_artifact_raw_sha256")
            != hashlib.sha256(artifact_body).hexdigest()
            or attestation.get("source_artifact_digest") != artifact["artifact_digest"]
            or attestation.get("provenance_kind")
            != "wp08a-protected-offline-advisory-source"
            or attestation.get("network_mode") != "offline-only"
            or _self_digest(
                attestation,
                name="dependency-advisory-source-attestation",
                field="attestation_digest",
            ) != vector["source-attestation-digest"]
        ):
            raise DependencySecurityError(
                "dependency advisory source history attestation changed"
            )
        source_states = {
            (item["source_id"], item["source_revision"]): item["status"]
            for item in registry_document["revocation_high_water"]["source_states"]
        }
        advisory_states = {
            (item["advisory_id"], item["advisory_revision"]): item["status"]
            for item in registry_document["revocation_high_water"]["advisory_states"]
        }
        active_sources = [
            item for item in registry_document["source_records"]
            if source_states[(item["source_id"], item["source_revision"])] == "active"
        ]
        active_advisories = [
            item for item in registry_document["advisories"]
            if advisory_states[(item["advisory_id"], item["advisory_revision"])] == "active"
        ]
        active_identities = tuple(
            (item["advisory_id"], item["advisory_revision"])
            for item in active_advisories
        )
        artifact_identities = tuple(
            (item["advisory_id"], item["advisory_revision"])
            for item in identities
        )
        if (
            parsed.registry_id != vector["registry-id"]
            or parsed.registry_digest != vector["registry-digest"]
            or parsed.generation != vector["generation"]
            or len(active_sources) != 1
            or active_identities != artifact_identities
            or any(
                (item["source_id"], item["source_revision"])
                != (active_sources[0]["source_id"], active_sources[0]["source_revision"])
                for item in active_advisories
            )
            or tuple(artifact.get(field) for field in (
                "source_id", "source_revision", "issuer_id",
            )) != tuple(active_sources[0].get(field) for field in (
                "source_id", "source_revision", "issuer_id",
            ))
            or tuple(attestation.get(field) for field in (
                "source_id", "source_revision", "issuer_id",
            )) != tuple(active_sources[0].get(field) for field in (
                "source_id", "source_revision", "issuer_id",
            ))
            or active_sources[0].get("source_artifact_raw_sha256")
            != hashlib.sha256(artifact_body).hexdigest()
            or active_sources[0].get("source_attestation_digest")
            != attestation["attestation_digest"]
        ):
            raise DependencySecurityError(
                "dependency advisory source history provenance changed"
            )
        return parsed, {
            "generation": parsed.generation,
            "registry_member": vector["registry-source"],
            "registry_digest": parsed.registry_digest,
            "registry_raw_sha256": vector["registry-raw-sha256"],
            "source_artifact_member": vector["source-artifact-source"],
            "source_artifact_id": artifact["artifact_id"],
            "source_artifact_raw_sha256": vector["source-artifact-raw-sha256"],
            "source_attestation_member": vector["source-attestation-source"],
            "source_attestation_id": attestation["attestation_id"],
            "source_attestation_raw_sha256": vector["source-attestation-raw-sha256"],
        }

    snapshot_bodies = (
        (history_bodies[0], history_bodies[1], history_bodies[2]),
        (history_bodies[3], history_bodies[4], history_bodies[5]),
    )
    snapshots: list[DependencyAdvisoryRegistryData] = []
    source_snapshot_history: list[dict[str, object]] = []
    for vector, bodies, label in zip(
        source_history, snapshot_bodies, ("generation-1", "generation-2"), strict=True,
    ):
        snapshot, snapshot_row = validate_snapshot(vector, bodies, label)
        snapshots.append(snapshot)
        source_snapshot_history.append(snapshot_row)
    validate_dependency_registry_update(
        snapshots[0].to_dict(), snapshots[1].to_dict(),
    )
    registry_document = _strict_json(registry_bytes, "dependency advisory registry")
    registry = parse_dependency_advisory_registry(registry_document)
    if (
        registry_bytes != snapshot_bodies[1][0]
        or source_artifact_bytes != snapshot_bodies[1][1]
        or source_attestation_bytes != snapshot_bodies[1][2]
        or registry.document != snapshots[1].document
        or registry.registry_id != pin["registry-id"]
        or registry.registry_digest != pin["registry-digest"]
        or registry.generation != pin["registry-generation"]
        or any(
            pin[field] != source_history[1][field]
            for field in (
                "registry-id", "registry-digest", "registry-raw-sha256",
                "registry-source", "registry-resource", "source-artifact-id",
                "source-artifact-digest", "source-artifact-raw-sha256",
                "source-artifact-source", "source-artifact-resource",
                "source-attestation-id", "source-attestation-digest",
                "source-attestation-raw-sha256", "source-attestation-source",
                "source-attestation-resource",
            )
        )
    ):
        raise DependencySecurityError("dependency advisory current snapshot changed")
    bootstrap = _strict_json(bootstrap_bytes, "dependency advisory bootstrap")
    bootstrap_fields = {
        "schema_version", "bootstrap_id", "registry_id", "registry_digest",
        "registry_generation", "registry_raw_sha256", "registry_history_digests",
        "profile_schema_registry_id",
        "profile_schema_registry_digest", "profile_schema_registry_raw_sha256",
        "source_artifact_id", "source_artifact_digest",
        "source_artifact_raw_sha256", "source_attestation_id",
        "source_attestation_digest", "source_attestation_raw_sha256",
        "schema_resources", "network_mode", "fallback", "activation_status",
        "source_snapshot_history", "bootstrap_digest",
    }
    if type(bootstrap) is not dict or set(bootstrap) != bootstrap_fields:
        raise DependencySecurityError("dependency advisory bootstrap is not exact")
    history = bootstrap["registry_history_digests"]
    if (
        type(history) is not list
        or not history
        or any(type(item) is not str or SEMANTIC_DIGEST.fullmatch(item) is None for item in history)
        or len(set(history)) != len(history)
        or history != [item.registry_digest for item in snapshots]
    ):
        raise DependencySecurityError("dependency registry history is not exact")
    expected_bootstrap_digest = _digest(
        bootstrap["bootstrap_digest"], "dependency bootstrap digest"
    )
    bootstrap_body = copy.deepcopy(bootstrap)
    del bootstrap_body["bootstrap_digest"]
    actual_bootstrap_digest = semantic_digest(
        freeze(bootstrap_body),
        contract_type="urn:gew:contract:dependency-advisory-installation-bootstrap",
        projection_id=(
            "urn:gew:digest-projection:dependency-advisory-installation-bootstrap:1.0.0"
        ),
        schema_id="urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.2.0",
    )
    if (
        not hmac.compare_digest(expected_bootstrap_digest, actual_bootstrap_digest)
        or not hmac.compare_digest(expected_bootstrap_digest, _digest(
            pin["bootstrap-digest"], "dependency bootstrap pin"
        ))
        or bootstrap["bootstrap_id"] != pin["bootstrap-id"]
        or bootstrap["registry_id"] != registry.registry_id
        or bootstrap["registry_digest"] != registry.registry_digest
        or bootstrap["registry_generation"] != registry.generation
        or bootstrap["registry_raw_sha256"] != pin["registry-raw-sha256"]
        or bootstrap["profile_schema_registry_id"] != pin["profile-schema-registry-id"]
        or bootstrap["profile_schema_registry_digest"]
        != pin["profile-schema-registry-digest"]
        or bootstrap["profile_schema_registry_raw_sha256"]
        != pin["profile-schema-registry-raw-sha256"]
        or bootstrap["source_artifact_id"] != pin["source-artifact-id"]
        or bootstrap["source_artifact_digest"] != pin["source-artifact-digest"]
        or bootstrap["source_artifact_raw_sha256"]
        != pin["source-artifact-raw-sha256"]
        or bootstrap["source_attestation_id"] != pin["source-attestation-id"]
        or bootstrap["source_attestation_digest"]
        != pin["source-attestation-digest"]
        or bootstrap["source_attestation_raw_sha256"]
        != pin["source-attestation-raw-sha256"]
        or bootstrap["network_mode"] != "offline-only"
        or bootstrap["fallback"] != "disabled"
        or bootstrap["activation_status"]
        != "blocked-pending-wp10-release-install-manifest"
        or bootstrap["source_snapshot_history"] != source_snapshot_history
    ):
        raise DependencySecurityError("dependency advisory bootstrap identity changed")
    bootstrap_history = pin["bootstrap-history-vectors"]
    bootstrap_history_fields = {
        "schema-version", "bootstrap-id", "bootstrap-digest",
        "bootstrap-raw-sha256", "bootstrap-source", "bootstrap-resource",
    }
    if (
        type(bootstrap_history) is not list
        or len(bootstrap_history) != 2
        or any(
            type(item) is not dict or set(item) != bootstrap_history_fields
            for item in bootstrap_history
        )
        or [item["schema-version"] for item in bootstrap_history]
        != ["1.0.0", "1.1.0"]
    ):
        raise DependencySecurityError("dependency advisory bootstrap history is not exact")
    historical_bootstraps: list[dict[str, object]] = []
    for vector, body in zip(bootstrap_history, history_bodies[6:], strict=True):
        if hashlib.sha256(body).hexdigest() != _raw(
            vector["bootstrap-raw-sha256"], "historical bootstrap raw digest",
        ):
            raise DependencySecurityError("dependency advisory bootstrap history bytes changed")
        historical = _strict_json(body, "historical dependency advisory bootstrap")
        digest = _digest(
            historical.get("bootstrap_digest"), "historical bootstrap digest",
        )
        digest_input = copy.deepcopy(historical)
        del digest_input["bootstrap_digest"]
        actual_digest = semantic_digest(
            freeze(digest_input),
            contract_type="urn:gew:contract:dependency-advisory-installation-bootstrap",
            projection_id=(
                "urn:gew:digest-projection:dependency-advisory-installation-bootstrap:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:dependency-advisory-installation-bootstrap-input:"
                + str(vector["schema-version"])
            ),
        )
        if (
            historical.get("schema_version") != vector["schema-version"]
            or historical.get("bootstrap_id") != vector["bootstrap-id"]
            or digest != vector["bootstrap-digest"]
            or not hmac.compare_digest(digest, actual_digest)
        ):
            raise DependencySecurityError("dependency advisory bootstrap history changed")
        historical_bootstraps.append(historical)
    if (
        historical_bootstraps[0].get("registry_id") != snapshots[0].registry_id
        or historical_bootstraps[0].get("registry_digest")
        != snapshots[0].registry_digest
        or historical_bootstraps[0].get("registry_generation")
        != snapshots[0].generation
        or historical_bootstraps[0].get("registry_raw_sha256")
        != source_history[0]["registry-raw-sha256"]
        or historical_bootstraps[0].get("source_artifact_id")
        != source_history[0]["source-artifact-id"]
        or historical_bootstraps[0].get("source_artifact_digest")
        != source_history[0]["source-artifact-digest"]
        or historical_bootstraps[0].get("source_artifact_raw_sha256")
        != source_history[0]["source-artifact-raw-sha256"]
        or historical_bootstraps[0].get("source_attestation_id")
        != source_history[0]["source-attestation-id"]
        or historical_bootstraps[0].get("source_attestation_digest")
        != source_history[0]["source-attestation-digest"]
        or historical_bootstraps[0].get("source_attestation_raw_sha256")
        != source_history[0]["source-attestation-raw-sha256"]
        or historical_bootstraps[1].get("base_bootstrap_id")
        != bootstrap_history[0]["bootstrap-id"]
        or historical_bootstraps[1].get("base_bootstrap_digest")
        != bootstrap_history[0]["bootstrap-digest"]
        or historical_bootstraps[1].get("base_bootstrap_raw_sha256")
        != bootstrap_history[0]["bootstrap-raw-sha256"]
    ):
        raise DependencySecurityError("dependency advisory bootstrap history is unbound")
    schema_registry = _strict_json(
        schema_registry_bytes, "Profile schema registry"
    )
    if (
        schema_registry.get("registry_id") != pin["profile-schema-registry-id"]
        or schema_registry.get("registry_digest")
        != pin["profile-schema-registry-digest"]
    ):
        raise DependencySecurityError("Profile schema registry pin changed")
    vectors = pin["schema-vectors"]
    bootstrap_vectors = bootstrap["schema_resources"]
    if (
        type(vectors) is not list
        or type(bootstrap_vectors) is not list
        or len(vectors) != len(DEPENDENCY_SECURITY_SCHEMA_IDS)
        or len(schema_bodies) != len(vectors)
    ):
        raise DependencySecurityError("dependency advisory schema closure is incomplete")
    identities: list[str] = []
    raw_digests: list[str] = []
    registry_resources = {
        item.get("schema_id"): item.get("body_digest")
        for item in schema_registry.get("resources", [])
        if type(item) is dict
    }
    for vector, bootstrap_vector, body in zip(
        vectors, bootstrap_vectors, schema_bodies, strict=True,
    ):
        fields = {"schema-id", "raw-sha256", "source", "resource"}
        if (
            type(vector) is not dict
            or set(vector) != fields
            or type(bootstrap_vector) is not dict
            or set(bootstrap_vector) != {"schema_id", "raw_sha256"}
        ):
            raise DependencySecurityError("dependency advisory schema pin is not exact")
        schema_id = vector["schema-id"]
        raw = hashlib.sha256(body).hexdigest()
        if (
            schema_id != bootstrap_vector["schema_id"]
            or raw != _raw(vector["raw-sha256"], "dependency schema digest")
            or raw != bootstrap_vector["raw_sha256"]
            or registry_resources.get(schema_id) != "sha256-raw-v1:" + raw
            or _strict_json(body, "dependency advisory schema").get("$id") != schema_id
        ):
            raise DependencySecurityError("dependency advisory schema bytes changed")
        identities.append(str(schema_id))
        raw_digests.append(raw)
    if tuple(identities) != DEPENDENCY_SECURITY_SCHEMA_IDS:
        raise DependencySecurityError("dependency advisory schema identities are not exact")
    projection = freeze({
        "registry_digest": registry.registry_digest,
        "registry_history_digests": history,
        "bootstrap_digest": expected_bootstrap_digest,
        "profile_schema_registry_digest": pin["profile-schema-registry-digest"],
        "source_artifact_raw_sha256": pin["source-artifact-raw-sha256"],
        "source_attestation_digest": pin["source-attestation-digest"],
        "source_snapshot_history": source_snapshot_history,
        "source_history_raw_sha256": [
            hashlib.sha256(body).hexdigest() for body in history_bodies[:6]
        ],
        "bootstrap_history": [
            {
                "bootstrap_id": item["bootstrap-id"],
                "bootstrap_digest": item["bootstrap-digest"],
                "raw_sha256": item["bootstrap-raw-sha256"],
            }
            for item in bootstrap_history
        ],
        "schema_raw_sha256": raw_digests,
    })
    if not isinstance(projection, FrozenMap):
        raise AssertionError("dependency advisory bootstrap did not freeze")
    return registry, projection, tuple(raw_digests)


def _graph_installation_projection() -> tuple[
    DependencyGraphPolicyData,
    DependencyRemediationRegistryData,
    FrozenMap,
]:
    """Load the protected ADR-0006 r7 graph/remediation installation bytes."""

    from graph_engineering import (
        DistributionIdentityError,
        _dependency_graph_installation_resources,
    )

    try:
        resources = _dependency_graph_installation_resources()
        if len(resources) != 8 + 32:
            raise DependencySecurityError(
                "dependency graph installation closure is incomplete"
            )
        (
            provenance_bytes, graph_bytes, remediation_bytes, bootstrap_bytes,
            base_bootstrap_bytes, advisory_registry_bytes, schema_registry_bytes,
            build_backend_bytes, *schema_bodies,
        ) = resources
        provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
        pin = provenance["tool"]["gew"]["profile"]["dependency-advisory"]
    except (
        DistributionIdentityError, KeyError, TypeError, UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise DependencySecurityError(
            "dependency graph installation bootstrap is unavailable"
        ) from error
    expected_pin_fields = {
        "registry-id", "registry-digest", "registry-generation",
        "registry-raw-sha256", "registry-source", "registry-resource",
        "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
        "bootstrap-source", "bootstrap-resource", "source-artifact-id",
        "source-artifact-digest", "source-artifact-raw-sha256",
        "source-artifact-source", "source-artifact-resource",
        "source-attestation-id", "source-attestation-digest",
        "source-attestation-raw-sha256", "source-attestation-source",
        "source-attestation-resource", "source-history-vectors",
        "bootstrap-history-vectors", "schema-vectors",
        "graph-policy-id", "graph-policy-digest", "graph-policy-raw-sha256",
        "graph-policy-source", "graph-policy-resource", "remediation-id",
        "remediation-digest", "remediation-raw-sha256", "remediation-source",
        "remediation-resource", "graph-bootstrap-id", "graph-bootstrap-digest",
        "graph-bootstrap-raw-sha256", "graph-bootstrap-source",
        "graph-bootstrap-resource",
        "profile-schema-registry-id", "profile-schema-registry-digest",
        "profile-schema-registry-raw-sha256", "profile-schema-registry-source",
        "profile-schema-registry-resource", "build-backend-raw-sha256",
        "build-backend-source", "build-backend-resource", "graph-schema-vectors",
    }
    if type(pin) is not dict or set(pin) != expected_pin_fields:
        raise DependencySecurityError("dependency graph independent pin is not exact")
    fixed_bodies = (
        (graph_bytes, "graph-policy-raw-sha256"),
        (remediation_bytes, "remediation-raw-sha256"),
        (bootstrap_bytes, "graph-bootstrap-raw-sha256"),
        (base_bootstrap_bytes, "bootstrap-raw-sha256"),
        (advisory_registry_bytes, "registry-raw-sha256"),
        (schema_registry_bytes, "profile-schema-registry-raw-sha256"),
        (build_backend_bytes, "build-backend-raw-sha256"),
    )
    for body, field in fixed_bodies:
        if hashlib.sha256(body).hexdigest() != _raw(pin[field], field):
            raise DependencySecurityError("dependency graph installation bytes changed")
    graph = parse_dependency_graph_policy_registry(
        _strict_json(graph_bytes, "dependency graph policy")
    )
    remediation = parse_dependency_remediation_registry(
        _strict_json(remediation_bytes, "dependency remediation registry")
    )
    base_bootstrap = _strict_json(
        base_bootstrap_bytes, "dependency advisory base bootstrap"
    )
    advisory_registry = parse_dependency_advisory_registry(
        _strict_json(advisory_registry_bytes, "dependency advisory registry")
    )
    schema_registry = _strict_json(schema_registry_bytes, "Profile schema registry")
    if (
        graph.registry_id != pin["graph-policy-id"]
        or graph.registry_digest != pin["graph-policy-digest"]
        or remediation.registry_id != pin["remediation-id"]
        or remediation.registry_digest != pin["remediation-digest"]
        or base_bootstrap.get("bootstrap_id") != pin["bootstrap-id"]
        or base_bootstrap.get("bootstrap_digest") != pin["bootstrap-digest"]
        or advisory_registry.registry_id != pin["registry-id"]
        or advisory_registry.registry_digest != pin["registry-digest"]
        or schema_registry.get("registry_id") != pin["profile-schema-registry-id"]
        or schema_registry.get("registry_digest")
        != pin["profile-schema-registry-digest"]
    ):
        raise DependencySecurityError("dependency graph installation identity changed")
    vectors = pin["graph-schema-vectors"]
    if (
        type(vectors) is not list or len(vectors) != 32
        or len(schema_bodies) != 32
    ):
        raise DependencySecurityError("dependency graph schema closure is incomplete")
    registry_resources = {
        item.get("schema_id"): item.get("body_digest")
        for item in schema_registry.get("resources", [])
        if type(item) is dict
    }
    identities: list[str] = []
    schema_rows: list[dict[str, str]] = []
    for vector, body in zip(vectors, schema_bodies, strict=True):
        if type(vector) is not dict or set(vector) != {
            "schema-id", "raw-sha256", "source", "resource",
        }:
            raise DependencySecurityError("dependency graph schema pin is not exact")
        schema_id = vector["schema-id"]
        raw = hashlib.sha256(body).hexdigest()
        if (
            raw != _raw(vector["raw-sha256"], "dependency graph schema digest")
            or registry_resources.get(schema_id) != "sha256-raw-v1:" + raw
            or _strict_json(body, "dependency graph schema").get("$id") != schema_id
        ):
            raise DependencySecurityError("dependency graph schema bytes changed")
        identities.append(str(schema_id))
        schema_rows.append({"schema_id": str(schema_id), "raw_sha256": raw})
    expected_schema_ids = tuple(sorted((
        *DEPENDENCY_SECURITY_SCHEMA_IDS, *DEPENDENCY_GRAPH_SCHEMA_IDS,
    )))
    if tuple(identities) != expected_schema_ids:
        raise DependencySecurityError("dependency graph schema identities are not exact")
    bootstrap = _strict_json(bootstrap_bytes, "dependency graph bootstrap")
    bootstrap_fields = {
        "schema_version", "bootstrap_id", "base_bootstrap_id",
        "base_bootstrap_digest", "base_bootstrap_raw_sha256",
        "graph_policy_registry_id", "graph_policy_registry_digest",
        "graph_policy_registry_raw_sha256", "remediation_registry_id",
        "remediation_registry_digest", "remediation_registry_raw_sha256",
        "profile_schema_registry_id", "profile_schema_registry_digest",
        "profile_schema_registry_raw_sha256", "schema_resources",
        "distribution_name", "distribution_version",
        "source_attestation_policy_id", "build_backend_raw_sha256",
        "protected_closure_digest", "network_mode", "fallback",
        "activation_status", "bootstrap_digest",
    }
    if type(bootstrap) is not dict or set(bootstrap) != bootstrap_fields:
        raise DependencySecurityError("dependency graph bootstrap is not exact")
    expected_bootstrap_digest = _digest(
        bootstrap.get("bootstrap_digest"), "dependency graph bootstrap digest",
    )
    bootstrap_input = copy.deepcopy(bootstrap)
    del bootstrap_input["bootstrap_digest"]
    actual_bootstrap_digest = semantic_digest(
        freeze(bootstrap_input),
        contract_type="urn:gew:contract:dependency-advisory-installation-bootstrap",
        projection_id=(
            "urn:gew:digest-projection:dependency-advisory-installation-bootstrap:1.0.0"
        ),
        schema_id=(
            "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0"
        ),
    )
    if not hmac.compare_digest(expected_bootstrap_digest, actual_bootstrap_digest):
        raise DependencySecurityError("dependency graph bootstrap digest changed")
    closure_rows = [
        {"identity": field, "raw_sha256": hashlib.sha256(body).hexdigest()}
        for body, field in fixed_bodies
        if field != "graph-bootstrap-raw-sha256"
    ] + [
        {"identity": row["schema_id"], "raw_sha256": row["raw_sha256"]}
        for row in schema_rows
    ]
    closure_rows.sort(key=lambda item: item["identity"])
    closure_digest = semantic_digest(
        freeze({"resources": closure_rows}),
        contract_type="urn:gew:contract:dependency-graph-protected-resource-closure",
        projection_id=(
            "urn:gew:digest-projection:dependency-graph-protected-resource-closure:1.0.0"
        ),
        schema_id=(
            "urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0"
        ),
    )
    bootstrap_history = pin["bootstrap-history-vectors"]
    historical_schema_rows = bootstrap.get("schema_resources")
    current_schema_by_id = {
        item["schema_id"]: item["raw_sha256"] for item in schema_rows
    }
    if (
        type(bootstrap_history) is not list
        or len(bootstrap_history) != 2
        or type(bootstrap_history[0]) is not dict
        or type(bootstrap_history[1]) is not dict
        or type(historical_schema_rows) is not list
        or len(historical_schema_rows) != 30
        or any(
            type(item) is not dict
            or set(item) != {"schema_id", "raw_sha256"}
            or current_schema_by_id.get(item["schema_id"]) != item["raw_sha256"]
            for item in historical_schema_rows
        )
        or tuple(item["schema_id"] for item in historical_schema_rows)
        != tuple(sorted({item["schema_id"] for item in historical_schema_rows}))
    ):
        raise DependencySecurityError("dependency graph bootstrap history is not exact")
    if (
        bootstrap["schema_version"] != "1.1.0"
        or bootstrap["bootstrap_id"] != pin["graph-bootstrap-id"]
        or expected_bootstrap_digest != pin["graph-bootstrap-digest"]
        or bootstrap["bootstrap_id"] != bootstrap_history[1].get("bootstrap-id")
        or expected_bootstrap_digest
        != bootstrap_history[1].get("bootstrap-digest")
        or pin["graph-bootstrap-raw-sha256"]
        != bootstrap_history[1].get("bootstrap-raw-sha256")
        or bootstrap["base_bootstrap_id"]
        != bootstrap_history[0].get("bootstrap-id")
        or bootstrap["base_bootstrap_digest"]
        != bootstrap_history[0].get("bootstrap-digest")
        or bootstrap["base_bootstrap_raw_sha256"]
        != bootstrap_history[0].get("bootstrap-raw-sha256")
        or bootstrap["network_mode"] != "offline-only"
        or bootstrap["fallback"] != "disabled"
        or bootstrap["activation_status"]
        != "blocked-pending-wp10-release-install-manifest"
    ):
        raise DependencySecurityError("dependency graph bootstrap identity changed")
    projection = freeze({
        "bootstrap_digest": expected_bootstrap_digest,
        "graph_policy_digest": graph.registry_digest,
        "remediation_registry_digest": remediation.registry_digest,
        "advisory_registry_digest": advisory_registry.registry_digest,
        "profile_schema_registry_digest": pin["profile-schema-registry-digest"],
        "protected_closure_digest": closure_digest,
        "schema_resources": schema_rows,
    })
    if not isinstance(projection, FrozenMap):
        raise AssertionError("dependency graph installation did not freeze")
    return graph, remediation, projection


class DependencyAdvisoryRegistryAuthority:
    """Opaque current registry authority issued by one consumer-local factory."""

    __slots__ = ("registry_id", "generation", "registry_digest", "_data", "_authority")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency advisory authorities are factory-issued")


class DependencyAdvisorySourceAuthority:
    """Opaque source identity owned by one current registry factory."""

    __slots__ = (
        "source_id", "source_revision", "source_record_digest", "_record",
        "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency advisory sources are factory-issued")


class DependencyAdvisoryIdentityAuthority:
    """Opaque advisory identity owned by one current registry factory."""

    __slots__ = (
        "advisory_id", "advisory_revision", "advisory_digest", "_record",
        "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency advisories are factory-issued")


class DependencyAdvisoryRegistryFactory:
    """Load and repeatedly revalidate one exact installed advisory head."""

    __slots__ = (
        "_projection", "_issued", "_issued_sources", "_issued_advisories",
        "_issued_rollback_proofs", "_repository", "_rollback_authority",
        "_history", "registry", "__weakref__",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency advisory factories are installation-issued")

    @classmethod
    def from_installation(cls, repository: object) -> DependencyAdvisoryRegistryFactory:
        del cls, repository
        raise AssertionError("dependency advisory factory issuer is not bound")

    def _clock_timestamp(self) -> str:
        try:
            observed_ns = self._repository.dependency_security_clock_ns()
        except Exception as error:
            raise DependencySecurityError(
                "dependency advisory repository clock is unavailable"
            ) from error
        if type(observed_ns) is not int or observed_ns < 0:
            raise DependencySecurityError("dependency advisory repository clock is invalid")
        return datetime.fromtimestamp(
            observed_ns // 1_000_000_000, tz=timezone.utc,
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _require_active_sources_current(
        self, data: DependencyAdvisoryRegistryData,
    ) -> str:
        observed_at = self._clock_timestamp()
        document = data.to_dict()
        source_states = {
            (item["source_id"], item["source_revision"]): item["status"]
            for item in document["revocation_high_water"]["source_states"]
        }
        for source in document["source_records"]:
            identity = (source["source_id"], source["source_revision"])
            if source_states[identity] == "active" and not source_is_current(
                source, observed_at,
            ):
                raise DependencySecurityError(
                    "active dependency advisory source is outside its validity interval"
                )
        return observed_at

    @staticmethod
    def _state_maps(
        data: DependencyAdvisoryRegistryData,
    ) -> tuple[dict[tuple[object, object], str], dict[tuple[object, object], str]]:
        document = data.to_dict()
        high_water = document["revocation_high_water"]
        return (
            {
                (item["source_id"], item["source_revision"]): str(item["status"])
                for item in high_water["source_states"]
            },
            {
                (item["advisory_id"], item["advisory_revision"]): str(item["status"])
                for item in high_water["advisory_states"]
            },
        )

    def require_current(
        self, value: object,
    ) -> DependencyAdvisoryRegistryAuthority:
        if (
            type(value) is not DependencyAdvisoryRegistryAuthority
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError("dependency advisory authority is foreign")
        current, projection, _schema_digests = _bootstrap_projection()
        if (
            projection != self._projection
            or current.registry_digest != value.registry_digest
            or current.generation != value.generation
            or current.registry_id != value.registry_id
            or current.document != value._data.document
        ):
            raise DependencySecurityError("dependency advisory installation changed")
        self._require_active_sources_current(current)
        return value

    def validate_update(self, candidate: object) -> DependencyAdvisoryRegistryData:
        """Validate a candidate only against this installation's verified head chain."""

        self.require_current(self.registry)
        parsed = parse_dependency_advisory_registry(candidate)
        document = parsed.to_dict()
        if document["update_kind"] != "rollback":
            return validate_dependency_registry_update(
                self.registry._data.to_dict(),
                candidate,
            )
        target = document["rollback_of_registry_digest"]
        if type(target) is not str:
            raise DependencySecurityError("dependency registry rollback target is invalid")
        self._require_registry_rollback_authority(
            self._rollback_authority,
            self.registry.registry_digest,
            target,
        )
        return _validate_verified_dependency_registry_update(
            self.registry._data.to_dict(),
            candidate,
            verified_rollback_target=target,
        )

    def _require_registry_rollback_authority(
        self,
        proof: object,
        current_digest: str,
        target_digest: str,
    ) -> None:
        del proof, current_digest, target_digest
        raise DependencySecurityError("dependency registry rollback verifier is not bound")

    def source(
        self, source_id: str, source_revision: int,
    ) -> DependencyAdvisorySourceAuthority:
        self.require_current(self.registry)
        if (
            type(source_id) is not str
            or not source_id
            or type(source_revision) is not int
            or not 1 <= source_revision <= 9_007_199_254_740_991
        ):
            raise DependencySecurityError(
                "dependency advisory source identity is not exact"
            )
        identity = (source_id, source_revision)
        source_states, _advisory_states = self._state_maps(self.registry._data)
        if source_states.get(identity) != "active":
            raise DependencySecurityError("dependency advisory source is inactive")
        record = next((
            item for item in self.registry._data.to_dict()["source_records"]
            if (item["source_id"], item["source_revision"]) == identity
        ), None)
        if record is None:
            raise DependencySecurityError("dependency advisory source is unavailable")
        issued = self._issued_sources.get(identity)
        if issued is None:
            issued = object.__new__(DependencyAdvisorySourceAuthority)
            issued.source_id = source_id
            issued.source_revision = source_revision
            issued.source_record_digest = str(record["source_record_digest"])
            issued._record = freeze(record)
            issued._authority = self
            self._issued_sources[identity] = issued
        return issued

    def advisory(
        self, advisory_id: str, advisory_revision: int,
    ) -> DependencyAdvisoryIdentityAuthority:
        self.require_current(self.registry)
        if (
            type(advisory_id) is not str
            or not advisory_id
            or type(advisory_revision) is not int
            or not 1 <= advisory_revision <= 9_007_199_254_740_991
        ):
            raise DependencySecurityError(
                "dependency advisory identity is not exact"
            )
        identity = (advisory_id, advisory_revision)
        source_states, advisory_states = self._state_maps(self.registry._data)
        if advisory_states.get(identity) != "active":
            raise DependencySecurityError("dependency advisory identity is inactive")
        record = next((
            item for item in self.registry._data.to_dict()["advisories"]
            if (item["advisory_id"], item["advisory_revision"]) == identity
        ), None)
        if record is None:
            raise DependencySecurityError("dependency advisory identity is unavailable")
        source_identity = (record["source_id"], record["source_revision"])
        if source_states.get(source_identity) != "active":
            raise DependencySecurityError("dependency advisory source is inactive")
        issued = self._issued_advisories.get(identity)
        if issued is None:
            issued = object.__new__(DependencyAdvisoryIdentityAuthority)
            issued.advisory_id = advisory_id
            issued.advisory_revision = advisory_revision
            issued.advisory_digest = str(record["advisory_digest"])
            issued._record = freeze(record)
            issued._authority = self
            self._issued_advisories[identity] = issued
        return issued

    def require_current_source(
        self, value: object,
    ) -> DependencyAdvisorySourceAuthority:
        if (
            type(value) is not DependencyAdvisorySourceAuthority
            or value._authority is not self
            or self._issued_sources.get(
                (value.source_id, value.source_revision)
            ) is not value
        ):
            raise DependencySecurityError("dependency advisory source is foreign")
        self.require_current(self.registry)
        if self.source(value.source_id, value.source_revision) is not value:
            raise DependencySecurityError("dependency advisory source changed")
        return value

    def require_current_advisory(
        self, value: object,
    ) -> DependencyAdvisoryIdentityAuthority:
        if (
            type(value) is not DependencyAdvisoryIdentityAuthority
            or value._authority is not self
            or self._issued_advisories.get(
                (value.advisory_id, value.advisory_revision)
            ) is not value
        ):
            raise DependencySecurityError("dependency advisory identity is foreign")
        self.require_current(self.registry)
        if self.advisory(value.advisory_id, value.advisory_revision) is not value:
            raise DependencySecurityError("dependency advisory identity changed")
        return value


def _bind_dependency_registry_factory_issuance() -> None:
    """Bind factory/proof identity to closure-held, non-exported weak registries."""

    factory_type = DependencyAdvisoryRegistryFactory
    issued_factories: weakref.WeakKeyDictionary[
        DependencyAdvisoryRegistryFactory,
        tuple[str, int, str, FrozenMap, tuple[str, ...]],
    ] = weakref.WeakKeyDictionary()
    issued_proofs: weakref.WeakKeyDictionary[
        DependencyRegistryRollbackAuthority,
        tuple[DependencyAdvisoryRegistryFactory, str, tuple[str, ...]],
    ] = weakref.WeakKeyDictionary()

    @classmethod
    def from_installation(
        cls: type[DependencyAdvisoryRegistryFactory], repository: object,
    ) -> DependencyAdvisoryRegistryFactory:
        from graph_engineering.storage.repository import TaskRepository

        if cls is not factory_type or type(repository) is not TaskRepository:
            raise DependencySecurityError(
                "dependency advisory repository clock authority is missing or foreign"
            )
        data, projection, _schema_digests = _bootstrap_projection()
        history = projection["registry_history_digests"]
        if (
            not isinstance(history, tuple)
            or not history
            or history[-1] != data.registry_digest
            or history != tuple(dict.fromkeys(history))
        ):
            raise DependencySecurityError("dependency registry history is not exact")
        result = object.__new__(factory_type)
        result._projection = projection
        result._repository = repository
        result._issued = {}
        result._issued_sources = {}
        result._issued_advisories = {}
        result._issued_rollback_proofs = {}
        result._history = history
        authority = object.__new__(DependencyAdvisoryRegistryAuthority)
        authority.registry_id = data.registry_id
        authority.generation = data.generation
        authority.registry_digest = data.registry_digest
        authority._data = data
        authority._authority = result
        result.registry = authority
        result._issued[id(authority)] = authority
        proof = object.__new__(DependencyRegistryRollbackAuthority)
        proof._owner = result
        proof._current_digest = data.registry_digest
        proof._historical_digests = history
        result._rollback_authority = proof
        result._issued_rollback_proofs[id(proof)] = (
            proof, data.registry_digest, history,
        )
        issued_factories[result] = (
            data.registry_id, data.generation, data.registry_digest,
            projection, history,
        )
        issued_proofs[proof] = (result, data.registry_digest, history)
        result._require_active_sources_current(data)
        return result

    def require_rollback_authority(
        self: DependencyAdvisoryRegistryFactory,
        proof: object,
        current_digest: str,
        target_digest: str,
    ) -> None:
        factory_binding = issued_factories.get(self)
        proof_binding = (
            issued_proofs.get(proof)
            if type(proof) is DependencyRegistryRollbackAuthority
            else None
        )
        if (
            type(self) is not factory_type
            or factory_binding != (
                self.registry.registry_id,
                self.registry.generation,
                self.registry.registry_digest,
                self._projection,
                self._history,
            )
            or proof is not self._rollback_authority
            or proof_binding != (self, current_digest, self._history)
            or self._issued_rollback_proofs.get(id(proof)) != (
                proof, current_digest, self._history,
            )
            or current_digest != self.registry.registry_digest
            or target_digest not in self._history[:-1]
        ):
            raise DependencySecurityError(
                "dependency registry rollback history is foreign"
            )
        self.require_current(self.registry)

    factory_type.from_installation = from_installation  # type: ignore[method-assign]
    factory_type._require_registry_rollback_authority = (  # type: ignore[method-assign]
        require_rollback_authority
    )


_bind_dependency_registry_factory_issuance()
del _bind_dependency_registry_factory_issuance


class _OpaqueFactory:
    __slots__ = ("_issued", "_registry")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency observation factories are factory-issued")

    @classmethod
    def _issue(cls, registry: DependencyAdvisoryRegistryFactory):
        if type(registry) is not DependencyAdvisoryRegistryFactory:
            raise DependencySecurityError("dependency registry factory is foreign")
        registry.require_current(registry.registry)
        result = object.__new__(cls)
        result._registry = registry
        result._issued = {}
        return result


class DependencyOfflineClosureObservation:
    """Opaque result of one exact WP08A candidate closure preflight."""

    __slots__ = (
        "observation_id", "phase", "parser_attestation_digest",
        "physical_closure_digest", "members", "observation_digest",
        "_candidate", "_wheelhouse", "_projection", "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency closure observations are factory-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "observation_id": self.observation_id,
            "phase": self.phase,
            "parser_attestation_digest": self.parser_attestation_digest,
            "physical_closure_digest": self.physical_closure_digest,
            "members": thaw(self.members),
            "observation_digest": self.observation_digest,
        }


class DependencyOfflineClosureObservationFactory(_OpaqueFactory):
    """Consumer-local wrapper around the verified WP08A physical preflight."""

    @classmethod
    def from_registry(
        cls, registry: DependencyAdvisoryRegistryFactory,
    ) -> DependencyOfflineClosureObservationFactory:
        return cls._issue(registry)

    @staticmethod
    def _current_projection(
        candidate: pathlib.Path,
        wheelhouse: pathlib.Path,
        phase: str,
    ) -> FrozenMap:
        from graph_engineering import (
            DistributionIdentityError,
            _dependency_advisory_preflight_observation,
        )

        try:
            projection = _dependency_advisory_preflight_observation(
                str(candidate), str(wheelhouse), phase,
            )
        except DistributionIdentityError as error:
            raise DependencySecurityError(
                "dependency closure observation is unavailable"
            ) from error
        frozen = freeze(projection)
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("dependency closure projection did not freeze")
        return frozen

    def observe_candidate(
        self,
        candidate: pathlib.Path,
        wheelhouse: pathlib.Path,
        *,
        phase: str,
    ) -> DependencyOfflineClosureObservation:
        self._registry.require_current(self._registry.registry)
        if not isinstance(candidate, pathlib.Path) or not isinstance(wheelhouse, pathlib.Path):
            raise DependencySecurityError("dependency closure paths are not exact")
        try:
            candidate_path = candidate.resolve(strict=True)
            wheelhouse_path = wheelhouse.resolve(strict=True)
        except OSError as error:
            raise DependencySecurityError("dependency closure path is unavailable") from error
        projection = self._current_projection(candidate_path, wheelhouse_path, phase)
        members = projection["members"]
        if not isinstance(members, tuple):
            raise DependencySecurityError("dependency closure members are not immutable")
        body = {
            "schema_version": "1.0.0",
            "observation_id": (
                f"dependency-closure:{phase}:{projection['physical_closure_digest']}"
            ),
            "phase": phase,
            "parser_attestation_digest": projection["parser_attestation_digest"],
            "physical_closure_digest": projection["physical_closure_digest"],
            "members": thaw(members),
        }
        digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-offline-closure-observation",
            projection_id=(
                "urn:gew:digest-projection:dependency-offline-closure-observation:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:dependency-offline-closure-observation-input:1.0.0"
            ),
        )
        result = object.__new__(DependencyOfflineClosureObservation)
        result.observation_id = str(body["observation_id"])
        result.phase = phase
        result.parser_attestation_digest = str(projection["parser_attestation_digest"])
        result.physical_closure_digest = str(projection["physical_closure_digest"])
        result.members = members
        result.observation_digest = digest
        result._candidate = candidate_path
        result._wheelhouse = wheelhouse_path
        result._projection = projection
        result._authority = self
        self._issued[id(result)] = result
        return result

    def require_current(
        self, value: object,
    ) -> DependencyOfflineClosureObservation:
        if (
            type(value) is not DependencyOfflineClosureObservation
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError("dependency closure observation is foreign")
        self._registry.require_current(self._registry.registry)
        projection = self._current_projection(
            value._candidate, value._wheelhouse, value.phase,
        )
        if projection != value._projection:
            raise DependencySecurityError("dependency closure observation changed")
        return value


class DependencyClosureGraphObservation:
    """Opaque installation-derived dependency graph for one physical closure."""

    __slots__ = (
        "observation_id", "phase", "graph_policy_digest", "root_node_id",
        "nodes", "edges", "selected_advisory_id",
        "selected_advisory_revision", "selected_distribution_name",
        "reachability_path", "physical_closure_digest",
        "parser_attestation_digest", "observation_digest", "_projection",
        "_closure", "_advisory", "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency graph observations are factory-issued")

    def to_dict(self) -> dict[str, object]:
        value = thaw(self._projection)
        if not isinstance(value, dict):
            raise AssertionError("dependency graph observation did not thaw")
        return {**value, "observation_digest": self.observation_digest}


class DependencyRemediationDispositionAuthority:
    """Opaque explicit fix-unavailable/fixed-closure disposition authority."""

    __slots__ = ("_projection", "_advisory", "_authority")

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency remediation dispositions are factory-issued")

    def to_dict(self) -> dict[str, object]:
        value = thaw(self._projection)
        if not isinstance(value, dict):
            raise AssertionError("dependency remediation disposition did not thaw")
        return value

    @property
    def disposition_id(self) -> str:
        return str(self._projection["disposition_id"])

    @property
    def status(self) -> str:
        return str(self._projection["status"])

    @property
    def reason_code(self) -> str:
        return str(self._projection["reason_code"])

    @property
    def residual_policy_id(self) -> str:
        return str(self._projection["residual_policy_id"])

    @property
    def owner_route(self) -> str:
        return str(self._projection["owner_route"])

    @property
    def expires_at(self) -> str:
        return str(self._projection["expires_at"])

    @property
    def disposition_digest(self) -> str:
        return str(self._projection["disposition_digest"])


class DependencyGraphObservationFactory:
    """Derive a closed graph only from protected wheel METADATA and RECORD bytes."""

    __slots__ = (
        "_registry", "_closures", "_policy", "_remediation",
        "_installation", "_issued", "_issued_dispositions",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency graph factories are installation-issued")

    @classmethod
    def from_registry_and_closures(
        cls,
        registry: DependencyAdvisoryRegistryFactory,
        closures: DependencyOfflineClosureObservationFactory,
    ) -> DependencyGraphObservationFactory:
        if (
            cls is not DependencyGraphObservationFactory
            or type(registry) is not DependencyAdvisoryRegistryFactory
            or type(closures) is not DependencyOfflineClosureObservationFactory
            or closures._registry is not registry
        ):
            raise DependencySecurityError("dependency graph authorities are foreign")
        registry.require_current(registry.registry)
        policy, remediation, installation = _graph_installation_projection()
        result = object.__new__(DependencyGraphObservationFactory)
        result._registry = registry
        result._closures = closures
        result._policy = policy
        result._remediation = remediation
        result._installation = installation
        result._issued = {}
        result._issued_dispositions = {}
        return result

    def _require_installation(self) -> None:
        policy, remediation, installation = _graph_installation_projection()
        if (
            policy != self._policy
            or remediation != self._remediation
            or installation != self._installation
        ):
            raise DependencySecurityError("dependency graph installation changed")

    @staticmethod
    def _node_id(name: str, version: str) -> str:
        return f"distribution:{canonicalize_name(name)}@{version}"

    def _body(
        self,
        advisory: DependencyAdvisoryIdentityAuthority,
        closure: DependencyOfflineClosureObservation,
    ) -> dict[str, object]:
        self._require_installation()
        self._registry.require_current_advisory(advisory)
        self._closures.require_current(closure)
        graph_members = closure._projection.get("graph_members")
        if not isinstance(graph_members, tuple) or not graph_members:
            raise DependencySecurityError("dependency graph METADATA closure is absent")
        policy = self._policy.to_dict()
        root_name = policy["root_distribution_policy"]["root_distribution_name"]
        environment = dict(thaw(self._policy.marker_environment))
        nodes: list[dict[str, object]] = []
        by_name: dict[str, tuple[str, Mapping[str, object]]] = {}
        for raw in graph_members:
            if not isinstance(raw, FrozenMap):
                raise DependencySecurityError("dependency graph node is mutable")
            row = thaw(raw)
            if type(row) is not dict or set(row) != {
                "distribution_name", "distribution_version", "wheel_raw_sha256",
                "record_raw_sha256", "metadata_raw_sha256", "requirements",
            }:
                raise DependencySecurityError("dependency graph node is not exact")
            name = row["distribution_name"]
            version = row["distribution_version"]
            if type(name) is not str or type(version) is not str:
                raise DependencySecurityError("dependency graph node identity is invalid")
            normalized = canonicalize_name(name)
            if normalized in by_name:
                raise DependencySecurityError("dependency graph distribution is ambiguous")
            node_id = self._node_id(name, version)
            by_name[normalized] = (node_id, row)
            nodes.append({
                "node_id": node_id,
                "distribution_name": normalized,
                "distribution_version": str(Version(version)),
                "wheel_raw_sha256": _raw(row["wheel_raw_sha256"], "graph wheel"),
                "metadata_raw_sha256": _raw(row["metadata_raw_sha256"], "graph METADATA"),
                "record_raw_sha256": _raw(row["record_raw_sha256"], "graph RECORD"),
            })
        nodes.sort(key=lambda item: str(item["node_id"]))
        root = by_name.get(canonicalize_name(str(root_name)))
        if root is None:
            raise DependencySecurityError("dependency graph root is absent")
        edges: list[dict[str, object]] = []
        adjacency: dict[str, list[str]] = {}
        for parent_name, (parent_id, row) in sorted(by_name.items()):
            requirements = row["requirements"]
            if type(requirements) is not list:
                raise DependencySecurityError(
                    "dependency requirement rows are not an exact frozen projection"
                )
            if requirements != sorted(set(requirements)):
                raise DependencySecurityError(
                    "dependency requirement rows are not canonical and unique"
                )
            normalized_requirements: set[
                tuple[str, str, tuple[str, ...], str | None]
            ] = set()
            for raw_requirement in requirements:
                if type(raw_requirement) is not str or not raw_requirement:
                    raise DependencySecurityError("dependency requirement row is invalid")
                try:
                    requirement = Requirement(raw_requirement)
                except InvalidRequirement as error:
                    raise DependencySecurityError(
                        "dependency requirement row is malformed"
                    ) from error
                if requirement.url is not None:
                    raise DependencySecurityError("dependency URL requirement is forbidden")
                marker = None if requirement.marker is None else str(requirement.marker)
                normalized_requirement = (
                    canonicalize_name(requirement.name),
                    str(requirement.specifier),
                    tuple(sorted(requirement.extras)),
                    marker,
                )
                if normalized_requirement in normalized_requirements:
                    raise DependencySecurityError(
                        "dependency requirement semantic identity is duplicated"
                    )
                normalized_requirements.add(normalized_requirement)
                if requirement.marker is not None and not requirement.marker.evaluate(environment):
                    continue
                child_name = canonicalize_name(requirement.name)
                child = by_name.get(child_name)
                if child is None:
                    raise DependencySecurityError("dependency graph edge target is absent")
                child_id, child_row = child
                if Version(str(child_row["distribution_version"])) not in requirement.specifier:
                    raise DependencySecurityError("dependency graph edge version is invalid")
                edge_body: dict[str, object] = {
                    "parent_node_id": parent_id,
                    "child_node_id": child_id,
                    "original_requirement": raw_requirement,
                    "normalized_name": child_name,
                    "normalized_specifier": str(requirement.specifier),
                    "normalized_extras": sorted(requirement.extras),
                    "normalized_marker": marker,
                    "marker_applies": True,
                }
                row_digest = semantic_digest(
                    freeze(edge_body),
                    contract_type="urn:gew:contract:dependency-graph-requirement-row",
                    projection_id="urn:gew:digest-projection:dependency-graph-requirement-row:1.0.0",
                    schema_id="urn:gew:schema:dependency-closure-graph-observation-input:1.0.0",
                )
                edges.append({
                    "edge_id": f"edge:{parent_id}:{child_id}:{row_digest}",
                    **edge_body,
                    "requirement_row_digest": row_digest,
                })
                adjacency.setdefault(parent_id, []).append(child_id)
        edges.sort(key=lambda item: (
            str(item["parent_node_id"]), str(item["child_node_id"]),
            str(item["requirement_row_digest"]),
        ))
        edge_identities = tuple(str(item["edge_id"]) for item in edges)
        edge_order = tuple(
            (
                str(item["parent_node_id"]),
                str(item["child_node_id"]),
                str(item["requirement_row_digest"]),
            )
            for item in edges
        )
        if (
            edge_identities != tuple(dict.fromkeys(edge_identities))
            or edge_order != tuple(sorted(set(edge_order)))
        ):
            raise DependencySecurityError(
                "dependency graph edge identities are not canonical and unique"
            )
        root_id = root[0]
        paths: dict[str, tuple[str, ...]] = {root_id: (root_id,)}
        queue = [root_id]
        while queue:
            parent = queue.pop(0)
            for child in sorted(adjacency.get(parent, [])):
                if child in paths:
                    continue
                paths[child] = (*paths[parent], child)
                queue.append(child)
        if set(paths) != {str(item["node_id"]) for item in nodes}:
            raise DependencySecurityError("dependency graph closure is not exact")
        advisory_row = thaw(advisory._record)
        if type(advisory_row) is not dict:
            raise DependencySecurityError("dependency advisory row is unavailable")
        selected_name = canonicalize_name(str(advisory_row["distribution_name"]))
        selected = by_name.get(selected_name)
        if selected is None or selected[0] not in paths:
            raise DependencySecurityError("dependency advisory is unreachable")
        return {
            "schema_version": "1.0.0",
            "observation_id": (
                f"dependency-graph:{closure.phase}:{advisory.advisory_id}@"
                f"{advisory.advisory_revision}:{closure.physical_closure_digest}"
            ),
            "phase": closure.phase,
            "graph_policy_digest": self._policy.registry_digest,
            "root_node_id": root_id,
            "nodes": nodes,
            "edges": edges,
            "selected_advisory_id": advisory.advisory_id,
            "selected_advisory_revision": advisory.advisory_revision,
            "selected_distribution_name": selected_name,
            "reachability_path": list(paths[selected[0]]),
            "physical_closure_digest": closure.physical_closure_digest,
            "parser_attestation_digest": closure.parser_attestation_digest,
        }

    def observe(
        self,
        advisory: DependencyAdvisoryIdentityAuthority,
        closure: DependencyOfflineClosureObservation,
    ) -> DependencyClosureGraphObservation:
        body = self._body(advisory, closure)
        digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-closure-graph-observation",
            projection_id="urn:gew:digest-projection:dependency-closure-graph-observation:1.0.0",
            schema_id="urn:gew:schema:dependency-closure-graph-observation-input:1.0.0",
        )
        result = object.__new__(DependencyClosureGraphObservation)
        for name, value in body.items():
            if name != "schema_version":
                setattr(result, name, freeze(value))
        result.observation_digest = digest
        result._projection = freeze(body)
        result._closure = closure
        result._advisory = advisory
        result._authority = self
        self._issued[id(result)] = result
        return result

    def require_current(
        self, value: object,
    ) -> DependencyClosureGraphObservation:
        if (
            type(value) is not DependencyClosureGraphObservation
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError("dependency graph observation is foreign")
        body = self._body(value._advisory, value._closure)
        expected = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-closure-graph-observation",
            projection_id="urn:gew:digest-projection:dependency-closure-graph-observation:1.0.0",
            schema_id="urn:gew:schema:dependency-closure-graph-observation-input:1.0.0",
        )
        if freeze(body) != value._projection or not hmac.compare_digest(
            expected, value.observation_digest,
        ):
            raise DependencySecurityError("dependency graph observation changed")
        return value

    def _disposition_row(
        self, advisory: DependencyAdvisoryIdentityAuthority,
    ) -> FrozenMap:
        self._require_installation()
        self._registry.require_current_advisory(advisory)
        rows = tuple(
            item for item in self._remediation.dispositions
            if item["advisory_id"] == advisory.advisory_id
            and item["advisory_revision"] == advisory.advisory_revision
            and item["graph_policy_digest"] == self._policy.registry_digest
        )
        if len(rows) != 1:
            raise DependencySecurityError("dependency remediation is not explicitly approved")
        row = rows[0]
        if self._registry._clock_timestamp() >= str(row["expires_at"]):
            raise DependencySecurityError("dependency remediation disposition expired")
        return row

    def disposition(
        self, advisory: DependencyAdvisoryIdentityAuthority,
    ) -> DependencyRemediationDispositionAuthority:
        row = self._disposition_row(advisory)
        identity = str(row["disposition_id"])
        issued = self._issued_dispositions.get(identity)
        if issued is None:
            issued = object.__new__(DependencyRemediationDispositionAuthority)
            object.__setattr__(issued, "_projection", row)
            object.__setattr__(issued, "_advisory", advisory)
            object.__setattr__(issued, "_authority", self)
            self._issued_dispositions[identity] = issued
        return issued

    def require_current_disposition(
        self, value: object,
    ) -> DependencyRemediationDispositionAuthority:
        if type(value) is not DependencyRemediationDispositionAuthority:
            raise DependencySecurityError("dependency remediation disposition is foreign")
        try:
            authority = value._authority
            advisory = value._advisory
            projection = value._projection
            identity = value.disposition_id
        except (AttributeError, KeyError, TypeError) as error:
            raise DependencySecurityError(
                "dependency remediation disposition is foreign"
            ) from error
        if (
            authority is not self
            or self._issued_dispositions.get(identity) is not value
        ):
            raise DependencySecurityError("dependency remediation disposition is foreign")
        current = self._disposition_row(advisory)
        if projection != current or value.to_dict() != thaw(current):
            raise DependencySecurityError("dependency remediation disposition changed")
        return value


class DependencyApplicabilityObservationFactory(_OpaqueFactory):
    """Issue selected advisory facts from same-authority physical closures."""

    __slots__ = ("_closures",)

    @classmethod
    def from_registry_and_closures(
        cls,
        registry: DependencyAdvisoryRegistryFactory,
        closures: DependencyOfflineClosureObservationFactory,
    ) -> DependencyApplicabilityObservationFactory:
        if (
            type(closures) is not DependencyOfflineClosureObservationFactory
            or closures._registry is not registry
        ):
            raise DependencySecurityError("dependency closure factory is foreign")
        result = cls._issue(registry)
        result._closures = closures
        return result

    def _body(
        self,
        registry: DependencyAdvisoryRegistryAuthority,
        advisory: DependencyAdvisoryIdentityAuthority,
        source: DependencyAdvisorySourceAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
    ) -> dict[str, object]:
        self._registry.require_current(registry)
        self._registry.require_current_advisory(advisory)
        self._registry.require_current_source(source)
        self._closures.require_current(before)
        self._closures.require_current(after)
        if before.phase != "before" or after.phase != "after":
            raise DependencySecurityError("dependency closure phases are substituted")
        advisory_record = thaw(advisory._record)
        if (
            not isinstance(advisory_record, dict)
            or (advisory_record["source_id"], advisory_record["source_revision"])
            != (source.source_id, source.source_revision)
        ):
            raise DependencySecurityError("dependency advisory source is cross-bound")
        evaluation = evaluate_dependency_closures(
            registry._data.to_dict(),
            before_closure=thaw(before.members),
            after_closure=thaw(after.members),
            clock_authority=self._registry,
        )
        row = next((
            item for item in evaluation.rows
            if (item.advisory_id, item.advisory_revision)
            == (advisory.advisory_id, advisory.advisory_revision)
        ), None)
        if row is None or row.disposition == "inactive":
            raise DependencySecurityError("selected dependency advisory is not active")
        return {
            "schema_version": "1.0.0",
            "registry_digest": registry.registry_digest,
            "advisory_id": advisory.advisory_id,
            "advisory_revision": advisory.advisory_revision,
            "advisory_digest": advisory.advisory_digest,
            "source_record_digest": source.source_record_digest,
            "before_closure_digest": before.observation_digest,
            "after_closure_digest": after.observation_digest,
            "before_affected": row.disposition in {"fixed", "residual"},
            "after_fixed": row.disposition == "fixed",
            "matched_before_version": row.matched_before_version,
            "matched_after_closure_id": row.matched_after_closure_id,
        }

    def observe(
        self,
        registry: DependencyAdvisoryRegistryAuthority,
        advisory: DependencyAdvisoryIdentityAuthority,
        source: DependencyAdvisorySourceAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
    ) -> DependencyApplicabilityObservation:
        body = self._body(registry, advisory, source, before, after)
        digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-applicability-observation",
            projection_id=(
                "urn:gew:digest-projection:dependency-applicability-observation:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:dependency-applicability-observation-input:1.0.0"
            ),
        )
        result = object.__new__(DependencyApplicabilityObservation)
        result.applicability_digest = digest
        result._body = freeze(body)
        result._registry = registry
        result._advisory = advisory
        result._source = source
        result._before = before
        result._after = after
        result._authority = self
        self._issued[id(result)] = result
        return result

    def require_current(
        self, value: object,
    ) -> DependencyApplicabilityObservation:
        if (
            type(value) is not DependencyApplicabilityObservation
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError("dependency applicability is foreign")
        body = self._body(
            value._registry, value._advisory, value._source,
            value._before, value._after,
        )
        if freeze(body) != value._body:
            raise DependencySecurityError("dependency applicability changed")
        return value


class DependencyResidualExposureFactory(_OpaqueFactory):
    """Issue the full canonical advisory evaluation universe."""

    __slots__ = ("_closures",)

    @classmethod
    def from_registry_and_closures(
        cls,
        registry: DependencyAdvisoryRegistryFactory,
        closures: DependencyOfflineClosureObservationFactory,
    ) -> DependencyResidualExposureFactory:
        if (
            type(closures) is not DependencyOfflineClosureObservationFactory
            or closures._registry is not registry
        ):
            raise DependencySecurityError("dependency closure factory is foreign")
        result = cls._issue(registry)
        result._closures = closures
        return result

    def _evaluate(
        self,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
    ) -> DependencyEvaluation:
        self._registry.require_current(registry)
        self._closures.require_current(before)
        self._closures.require_current(after)
        if before.phase != "before" or after.phase != "after":
            raise DependencySecurityError("dependency closure phases are substituted")
        return evaluate_dependency_closures(
            registry._data.to_dict(),
            before_closure=thaw(before.members),
            after_closure=thaw(after.members),
            clock_authority=self._registry,
        )

    def observe(
        self,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
    ) -> DependencyResidualExposureObservation:
        evaluation = self._evaluate(registry, before, after)
        result = object.__new__(DependencyResidualExposureObservation)
        result.residual_exposure_digest = evaluation.evaluation_digest
        result.rows = evaluation.rows
        result.active_advisory_ids = evaluation.active_advisory_ids
        result.residual_advisory_ids = evaluation.residual_advisory_ids
        result._registry = registry
        result._before = before
        result._after = after
        result._authority = self
        self._issued[id(result)] = result
        return result

    def require_current(
        self, value: object,
    ) -> DependencyResidualExposureObservation:
        if (
            type(value) is not DependencyResidualExposureObservation
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError("dependency residual exposure is foreign")
        evaluation = self._evaluate(
            value._registry, value._before, value._after,
        )
        if (
            evaluation.evaluation_digest != value.residual_exposure_digest
            or evaluation.rows != value.rows
            or evaluation.active_advisory_ids != value.active_advisory_ids
            or evaluation.residual_advisory_ids != value.residual_advisory_ids
        ):
            raise DependencySecurityError("dependency residual exposure changed")
        return value


class DependencyApplicabilityObservation:
    __slots__ = (
        "applicability_digest", "_body", "_registry", "_advisory", "_source",
        "_before", "_after", "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency applicability is factory-issued")

    def to_dict(self) -> dict[str, object]:
        body = thaw(self._body)
        if not isinstance(body, dict):
            raise AssertionError("dependency applicability did not thaw")
        return {**body, "applicability_digest": self.applicability_digest}


class DependencyResidualExposureObservation:
    __slots__ = (
        "residual_exposure_digest", "rows", "active_advisory_ids",
        "residual_advisory_ids", "_registry", "_before", "_after",
        "_authority",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency residual exposure is factory-issued")

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": "1.0.0",
            "registry_digest": self._registry.registry_digest,
            "rows": [item.to_dict() for item in self.rows],
            "active_advisory_ids": list(self.active_advisory_ids),
            "residual_advisory_ids": list(self.residual_advisory_ids),
            "residual_exposure_digest": self.residual_exposure_digest,
        }


class DependencySecurityObservation:
    """Opaque task-bound final dependency-security observation."""

    __slots__ = (
        "observation_id", "task_id", "task_revision", "snapshot_digest",
        "invalidation_epoch", "profile_id", "registry_digest",
        "applicability_digest", "residual_exposure_digest",
        "security_regression_digest", "target_observation_digest",
        "scenario_id", "graph_policy_digest", "remediation_registry_digest",
        "before_graph_digest", "after_graph_digest", "disposition_digest",
        "owner_route",
        "observation_digest", "_projection", "_registry_authority",
        "_before", "_after", "_applicabilities", "_residual", "_authority",
        "_before_graph", "_after_graph", "_disposition",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency security observations are factory-issued")

    def to_dict(self) -> dict[str, object]:
        body = thaw(self._projection)
        if not isinstance(body, dict):
            raise AssertionError("dependency security observation did not thaw")
        return {**body, "observation_digest": self.observation_digest}


class DependencySecurityObservationFactory:
    """Combine Slice-A authorities with one current dependency task.

    The factory deliberately retains the upstream opaque objects.  Revalidation
    recomputes every child from the installed registry, repository clock,
    physical before/after wheel descriptors, and current category task; caller
    mappings and persisted bytes are never authority inputs.
    """

    __slots__ = (
        "_registry", "_closures", "_applicability", "_residual",
        "_graph", "_category", "_issued",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency security observation factories are factory-issued")

    @classmethod
    def from_authorities(
        cls,
        *,
        registry: DependencyAdvisoryRegistryFactory,
        closures: DependencyOfflineClosureObservationFactory,
        applicability: DependencyApplicabilityObservationFactory,
        residual: DependencyResidualExposureFactory,
        category_application: object,
    ) -> DependencySecurityObservationFactory:
        from graph_engineering.application.profile_execution import (
            CategoryExecutionApplication,
        )

        if (
            cls is not DependencySecurityObservationFactory
            or type(registry) is not DependencyAdvisoryRegistryFactory
            or type(closures) is not DependencyOfflineClosureObservationFactory
            or type(applicability) is not DependencyApplicabilityObservationFactory
            or type(residual) is not DependencyResidualExposureFactory
            or type(category_application) is not CategoryExecutionApplication
            or closures._registry is not registry
            or applicability._registry is not registry
            or applicability._closures is not closures
            or residual._registry is not registry
            or residual._closures is not closures
            or registry._repository is not category_application._repository
            or category_application._policy.profile_id != "dependency-security"
        ):
            raise DependencySecurityError(
                "dependency security observation authorities are foreign"
            )
        registry.require_current(registry.registry)
        result = object.__new__(DependencySecurityObservationFactory)
        result._registry = registry
        result._closures = closures
        result._applicability = applicability
        result._residual = residual
        result._graph = None
        result._category = category_application
        result._issued = {}
        return result

    @classmethod
    def from_graph_authorities(
        cls,
        *,
        registry: DependencyAdvisoryRegistryFactory,
        closures: DependencyOfflineClosureObservationFactory,
        applicability: DependencyApplicabilityObservationFactory,
        residual: DependencyResidualExposureFactory,
        graph: DependencyGraphObservationFactory,
        category_application: object,
    ) -> DependencySecurityObservationFactory:
        """Bind the v1.1 final-observation branch to one exact graph factory."""

        if (
            cls is not DependencySecurityObservationFactory
            or type(graph) is not DependencyGraphObservationFactory
            or graph._registry is not registry
            or graph._closures is not closures
        ):
            raise DependencySecurityError(
                "dependency graph observation authorities are foreign"
            )
        result = cls.from_authorities(
            registry=registry,
            closures=closures,
            applicability=applicability,
            residual=residual,
            category_application=category_application,
        )
        graph._require_installation()
        result._graph = graph
        return result

    def _task_projection(self, task_id: str) -> tuple[int, str, int]:
        if type(task_id) is not str or not task_id:
            raise DependencySecurityError("dependency security task identity is invalid")
        try:
            assessment = self._category.current_assessment(
                task_id, expected_profile_id="dependency-security",
            )
            view = self._category._task_application.runtime_show(
                task_id, self._category._runtime,
            )
        except Exception as error:
            raise DependencySecurityError(
                "current dependency security task is unavailable"
            ) from error
        snapshot = view.snapshot
        graph_ref = snapshot.graph_ref
        required_pins = {
            "graph_digest", "profile_digest", "overlay_digest",
            "project_config_digest", "support_matrix_digest",
            "materialization_digest",
        }
        if (
            graph_ref.get("profile_id") != "dependency-security"
            or any(
                type(graph_ref.get(field)) is not str
                or SEMANTIC_DIGEST.fullmatch(str(graph_ref.get(field))) is None
                for field in required_pins
            )
        ):
            raise DependencySecurityError("dependency security task binding changed")
        if assessment is not None:
            dependency_projection = getattr(
                assessment, "dependency_graph_projection", None,
            )
            if (
                assessment.task_id != task_id
                or assessment.profile_id != "dependency-security"
                or assessment.invalidation_epoch != snapshot.invalidation_epoch
                or snapshot.task_revision != assessment.task_revision + 1
            ):
                raise DependencySecurityError(
                    "dependency security assessment binding changed"
                )
            if self._graph is None:
                if (
                    assessment.schema_version != "1.0.0"
                    or dependency_projection is not None
                    or assessment.migration_rehearsal_projection is not None
                    or assessment.performance_evidence_projection is not None
                ):
                    raise DependencySecurityError(
                        "generic dependency assessment binding changed"
                    )
            elif (
                assessment.schema_version != "1.2.0"
                or not isinstance(dependency_projection, FrozenMap)
                or assessment.migration_rehearsal_projection is not None
                or assessment.performance_evidence_projection is not None
            ):
                raise DependencySecurityError(
                    "dependency graph assessment binding changed"
                )
            return (
                assessment.task_revision,
                assessment.snapshot_digest,
                assessment.invalidation_epoch,
            )
        return (
            snapshot.task_revision,
            snapshot.snapshot_digest,
            snapshot.invalidation_epoch,
        )

    def _current_body(
        self,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
        applicabilities: tuple[DependencyApplicabilityObservation, ...],
        residual: DependencyResidualExposureObservation,
        task_id: str,
    ) -> dict[str, object]:
        self._registry.require_current(registry)
        self._closures.require_current(before)
        self._closures.require_current(after)
        self._residual.require_current(residual)
        if (
            before.phase != "before"
            or after.phase != "after"
            or residual._registry is not registry
            or residual._before is not before
            or residual._after is not after
            or type(applicabilities) is not tuple
        ):
            raise DependencySecurityError(
                "dependency security child authority is cross-bound"
            )
        active_identities = tuple(
            (item.rsplit("@", 1)[0], int(item.rsplit("@", 1)[1]))
            for item in residual.active_advisory_ids
        )
        observed_identities: list[tuple[str, int]] = []
        applicability_digests: list[str] = []
        for observation in applicabilities:
            current = self._applicability.require_current(observation)
            body = current.to_dict()
            identity = (str(body["advisory_id"]), int(body["advisory_revision"]))
            if (
                current._registry is not registry
                or current._before is not before
                or current._after is not after
                or body["before_affected"] is not True
                or body["after_fixed"] is not True
            ):
                raise DependencySecurityError(
                    "dependency applicability does not prove an approved fix"
                )
            observed_identities.append(identity)
            applicability_digests.append(current.applicability_digest)
        if (
            tuple(observed_identities) != tuple(sorted(set(observed_identities)))
            or tuple(observed_identities) != active_identities
            or residual.residual_advisory_ids
        ):
            raise DependencySecurityError(
                "dependency applicability or residual universe is incomplete"
            )
        registry_document = registry._data.to_dict()
        advisory_by_identity = {
            (item["advisory_id"], item["advisory_revision"]): item
            for item in registry_document["advisories"]
        }
        matched_rows = {
            (item.advisory_id, item.advisory_revision): item
            for item in residual.rows
            if item.disposition != "inactive"
        }
        fixed_closures: list[dict[str, object]] = []
        for identity in active_identities:
            advisory = advisory_by_identity[identity]
            row = matched_rows.get(identity)
            if row is None or row.disposition != "fixed":
                raise DependencySecurityError(
                    "dependency fixed closure result is unavailable"
                )
            closure = next((
                item for item in advisory["fixed_closures"]
                if item["closure_id"] == row.matched_after_closure_id
            ), None)
            if closure is None:
                raise DependencySecurityError(
                    "dependency fixed closure identity is unapproved"
                )
            fixed_closures.append({
                "advisory_id": identity[0],
                "advisory_revision": identity[1],
                "advisory_digest": advisory["advisory_digest"],
                "closure_id": closure["closure_id"],
                "closure_digest": closure["closure_digest"],
                "security_regression_policy_id": advisory[
                    "security_regression_policy_id"
                ],
                "security_regression_command_id": closure[
                    "security_regression_command_id"
                ],
            })
        task_revision, snapshot_digest, invalidation_epoch = (
            self._task_projection(task_id)
        )
        applicability_digest = semantic_digest(
            freeze({
                "schema_version": "1.0.0",
                "applicability_digests": applicability_digests,
            }),
            contract_type="urn:gew:contract:dependency-applicability-set",
            projection_id=(
                "urn:gew:digest-projection:dependency-applicability-set:1.0.0"
            ),
            schema_id="urn:gew:schema:dependency-applicability-observation:1.0.0",
        )
        security_regression_digest = semantic_digest(
            freeze({
                "schema_version": "1.0.0",
                "fixed_closures": fixed_closures,
                "after_closure_digest": after.observation_digest,
                "residual_exposure_digest": residual.residual_exposure_digest,
                "result": "PASS",
            }),
            contract_type="urn:gew:contract:dependency-security-regression",
            projection_id=(
                "urn:gew:digest-projection:dependency-security-regression:1.0.0"
            ),
            schema_id="urn:gew:schema:dependency-security-observation-input:1.0.0",
        )
        target_observation_digest = semantic_digest(
            freeze({
                "schema_version": "1.0.0",
                "before_closure_digest": before.observation_digest,
                "after_closure_digest": after.observation_digest,
                "physical_closure_digest": after.physical_closure_digest,
            }),
            contract_type="urn:gew:contract:dependency-security-target",
            projection_id="urn:gew:digest-projection:dependency-security-target:1.0.0",
            schema_id="urn:gew:schema:dependency-security-observation-input:1.0.0",
        )
        return {
            "schema_version": "1.0.0",
            "observation_id": f"dependency-security:{task_id}",
            "task_id": task_id,
            "task_revision": task_revision,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": invalidation_epoch,
            "profile_id": "dependency-security",
            "registry_digest": registry.registry_digest,
            "applicability_digest": applicability_digest,
            "residual_exposure_digest": residual.residual_exposure_digest,
            "security_regression_digest": security_regression_digest,
            "target_observation_digest": target_observation_digest,
        }

    def observe(
        self,
        *,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
        applicabilities: tuple[DependencyApplicabilityObservation, ...],
        residual: DependencyResidualExposureObservation,
        task_id: str,
    ) -> DependencySecurityObservation:
        body = self._current_body(
            registry, before, after, applicabilities, residual, task_id,
        )
        digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-security-observation",
            projection_id=(
                "urn:gew:digest-projection:dependency-security-observation:1.0.0"
            ),
            schema_id="urn:gew:schema:dependency-security-observation-input:1.0.0",
        )
        result = object.__new__(DependencySecurityObservation)
        for field, value in body.items():
            if field != "schema_version":
                setattr(result, field, value)
        result.observation_digest = digest
        result._projection = freeze(body)
        result._registry_authority = registry
        result._before = before
        result._after = after
        result._applicabilities = applicabilities
        result._residual = residual
        result._authority = self
        self._issued[id(result)] = result
        return result

    def _current_graph_body(
        self,
        *,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
        applicabilities: tuple[DependencyApplicabilityObservation, ...],
        residual: DependencyResidualExposureObservation,
        before_graph: DependencyClosureGraphObservation,
        after_graph: DependencyClosureGraphObservation | None,
        disposition: DependencyRemediationDispositionAuthority | None,
        scenario_id: str,
        task_id: str,
    ) -> dict[str, object]:
        if type(self._graph) is not DependencyGraphObservationFactory:
            raise DependencySecurityError(
                "dependency graph observation factory is unavailable"
            )
        self._registry.require_current(registry)
        self._closures.require_current(before)
        self._closures.require_current(after)
        self._residual.require_current(residual)
        current_before_graph = self._graph.require_current(before_graph)
        current_after_graph = (
            None
            if after_graph is None
            else self._graph.require_current(after_graph)
        )
        if (
            before.phase != "before"
            or after.phase != "after"
            or current_before_graph._closure is not before
            or (
                current_after_graph is not None
                and current_after_graph._closure is not after
            )
            or residual._registry is not registry
            or residual._before is not before
            or residual._after is not after
            or type(applicabilities) is not tuple
            or len(applicabilities) != 1
        ):
            raise DependencySecurityError(
                "dependency graph final observation is cross-bound"
            )
        applicability_observation = self._applicability.require_current(
            applicabilities[0]
        )
        applicability_body = applicability_observation.to_dict()
        before_graph_body = current_before_graph.to_dict()
        selected_identity = (
            before_graph_body["selected_advisory_id"],
            before_graph_body["selected_advisory_revision"],
        )
        if (
            applicability_observation._registry is not registry
            or applicability_observation._before is not before
            or applicability_observation._after is not after
            or (
                applicability_body["advisory_id"],
                applicability_body["advisory_revision"],
            ) != selected_identity
            or applicability_body["before_affected"] is not True
        ):
            raise DependencySecurityError(
                "dependency graph applicability is incomplete"
            )
        active_identity = (
            f"{selected_identity[0]}@{selected_identity[1]}"
        )
        if active_identity not in residual.active_advisory_ids:
            raise DependencySecurityError(
                "dependency graph advisory is outside the active universe"
            )
        if scenario_id == "transitive-dependency":
            if (
                current_after_graph is None
                or disposition is not None
                or len(before_graph.reachability_path) < 3
                or len(current_after_graph.reachability_path) < 3
                or current_after_graph.selected_advisory_id
                != before_graph.selected_advisory_id
                or current_after_graph.selected_advisory_revision
                != before_graph.selected_advisory_revision
                or applicability_body["after_fixed"] is not True
                or residual.residual_advisory_ids
            ):
                raise DependencySecurityError(
                    "transitive dependency proof is incomplete"
                )
            disposition_digest: str | None = None
            owner_route: str | None = None
        elif scenario_id == "fix-unavailable":
            if (
                current_after_graph is not None
                or type(disposition) is not DependencyRemediationDispositionAuthority
                or self._graph.require_current_disposition(disposition)
                is not disposition
                or disposition._advisory is not before_graph._advisory
                or disposition.status != "approved-unavailable"
                or not disposition.owner_route
                or applicability_body["after_fixed"] is not False
                or active_identity not in residual.residual_advisory_ids
            ):
                raise DependencySecurityError(
                    "fix-unavailable disposition proof is incomplete"
                )
            disposition_digest = disposition.disposition_digest
            owner_route = disposition.owner_route
        else:
            raise DependencySecurityError(
                "dependency graph scenario identity is invalid"
            )
        task_revision, snapshot_digest, invalidation_epoch = (
            self._task_projection(task_id)
        )
        after_graph_digest = (
            None
            if current_after_graph is None
            else current_after_graph.observation_digest
        )
        target_observation_digest = semantic_digest(
            freeze({
                "schema_version": "1.1.0",
                "scenario_id": scenario_id,
                "before_closure_digest": before.observation_digest,
                "after_closure_digest": after.observation_digest,
                "before_graph_digest": before_graph.observation_digest,
                "after_graph_digest": after_graph_digest,
                "disposition_digest": disposition_digest,
                "residual_exposure_digest": residual.residual_exposure_digest,
                "owner_route": owner_route,
            }),
            contract_type="urn:gew:contract:dependency-security-target",
            projection_id="urn:gew:digest-projection:dependency-security-target:1.1.0",
            schema_id="urn:gew:schema:dependency-security-observation-input:1.1.0",
        )
        return {
            "schema_version": "1.1.0",
            "observation_id": f"dependency-security:{scenario_id}:{task_id}",
            "task_id": task_id,
            "task_revision": task_revision,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": invalidation_epoch,
            "profile_id": "dependency-security",
            "scenario_id": scenario_id,
            "registry_digest": registry.registry_digest,
            "graph_policy_digest": self._graph._policy.registry_digest,
            "remediation_registry_digest": (
                self._graph._remediation.registry_digest
            ),
            "before_graph_digest": before_graph.observation_digest,
            "after_graph_digest": after_graph_digest,
            "disposition_digest": disposition_digest,
            "residual_exposure_digest": residual.residual_exposure_digest,
            "owner_route": owner_route,
            "target_observation_digest": target_observation_digest,
        }

    def observe_graph(
        self,
        *,
        registry: DependencyAdvisoryRegistryAuthority,
        before: DependencyOfflineClosureObservation,
        after: DependencyOfflineClosureObservation,
        applicabilities: tuple[DependencyApplicabilityObservation, ...],
        residual: DependencyResidualExposureObservation,
        before_graph: DependencyClosureGraphObservation,
        after_graph: DependencyClosureGraphObservation | None,
        disposition: DependencyRemediationDispositionAuthority | None,
        scenario_id: str,
        task_id: str,
    ) -> DependencySecurityObservation:
        body = self._current_graph_body(
            registry=registry,
            before=before,
            after=after,
            applicabilities=applicabilities,
            residual=residual,
            before_graph=before_graph,
            after_graph=after_graph,
            disposition=disposition,
            scenario_id=scenario_id,
            task_id=task_id,
        )
        digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-security-observation",
            projection_id=(
                "urn:gew:digest-projection:dependency-security-observation:1.1.0"
            ),
            schema_id="urn:gew:schema:dependency-security-observation-input:1.1.0",
        )
        result = object.__new__(DependencySecurityObservation)
        for field, item in body.items():
            if field != "schema_version":
                setattr(result, field, item)
        result.observation_digest = digest
        result._projection = freeze(body)
        result._registry_authority = registry
        result._before = before
        result._after = after
        result._applicabilities = applicabilities
        result._residual = residual
        result._before_graph = before_graph
        result._after_graph = after_graph
        result._disposition = disposition
        result._authority = self
        self._issued[id(result)] = result
        return result

    def require_current(
        self, value: object,
    ) -> DependencySecurityObservation:
        if (
            type(value) is not DependencySecurityObservation
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError(
                "dependency security observation is foreign"
            )
        graph_branch = value._projection.get("schema_version") == "1.1.0"
        body = (
            self._current_graph_body(
                registry=value._registry_authority,
                before=value._before,
                after=value._after,
                applicabilities=value._applicabilities,
                residual=value._residual,
                before_graph=value._before_graph,
                after_graph=value._after_graph,
                disposition=value._disposition,
                scenario_id=value.scenario_id,
                task_id=value.task_id,
            )
            if graph_branch
            else self._current_body(
                value._registry_authority,
                value._before,
                value._after,
                value._applicabilities,
                value._residual,
                value.task_id,
            )
        )
        version = "1.1.0" if graph_branch else "1.0.0"
        expected_digest = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-security-observation",
            projection_id=(
                "urn:gew:digest-projection:dependency-security-observation:"
                f"{version}"
            ),
            schema_id=(
                "urn:gew:schema:dependency-security-observation-input:"
                f"{version}"
            ),
        )
        if (
            freeze(body) != value._projection
            or not hmac.compare_digest(expected_digest, value.observation_digest)
        ):
            raise DependencySecurityError("dependency security observation changed")
        return value

    def precommit(self, value: object) -> DependencySecurityObservation:
        """Final use-time check immediately before a coverage commit."""

        return self.require_current(value)

    def restart(self, value: object) -> DependencySecurityObservation:
        """Resolve the retained immutable observation under current installation."""

        return self.require_current(value)


class DependencyGraphAssessmentEvidence:
    """Opaque durable projection input for one dependency graph assessment."""

    __slots__ = (
        "task_id", "scenario_id", "observation_digest", "_projection",
        "_authority", "_source_factory", "_source_observation",
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency graph assessment evidence is factory-issued")

    def to_dict(self) -> dict[str, object]:
        value = thaw(self._projection)
        if type(value) is not dict:
            raise AssertionError("dependency graph assessment evidence did not thaw")
        return value


class DependencyGraphAssessmentFactory:
    """Issue or restore a complete task-local graph proof without replaying work."""

    __slots__ = (
        "_repository", "_registry", "_graph_policy", "_remediation",
        "_graph_installation", "_issued",
    )

    _FIELDS = frozenset({
        "schema_version", "evidence_kind", "task_id", "task_revision",
        "snapshot_digest", "invalidation_epoch", "profile_id", "scenario_id",
        "graph_ref_pins", "advisory_installation", "graph_installation",
        "advisory_registry", "selected_source", "selected_advisory",
        "before_closure", "after_closure", "before_graph", "after_graph",
        "applicability", "residual_exposure", "disposition", "regression",
        "target", "action_authority", "observation", "projection_digest",
    })
    _PIN_FIELDS = frozenset({
        "base_graph_digest", "profile_digest", "overlay_digest",
        "project_config_digest", "support_matrix_digest",
        "materialization_digest",
    })

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("dependency graph assessment factories are installation-issued")

    @classmethod
    def from_installation(
        cls, repository: object,
    ) -> DependencyGraphAssessmentFactory:
        from graph_engineering.storage.repository import TaskRepository

        if cls is not DependencyGraphAssessmentFactory or type(repository) is not TaskRepository:
            raise DependencySecurityError(
                "dependency graph assessment repository is missing or foreign"
            )
        registry = DependencyAdvisoryRegistryFactory.from_installation(repository)
        graph_policy, remediation, graph_installation = (
            _graph_installation_projection()
        )
        result = object.__new__(cls)
        result._repository = repository
        result._registry = registry
        result._graph_policy = graph_policy
        result._remediation = remediation
        result._graph_installation = graph_installation
        result._issued = {}
        return result

    @staticmethod
    def _semantic(
        body: Mapping[str, object], *, contract: str,
    ) -> str:
        return semantic_digest(
            freeze(body),
            contract_type=f"urn:gew:contract:{contract}",
            projection_id=f"urn:gew:digest-projection:{contract}:1.0.0",
            schema_id=(
                "urn:gew:schema:category-completion-assessment-input:1.2.0"
            ),
        )

    @classmethod
    def _verify_nested_digest(
        cls,
        document: object,
        *,
        field: str,
        contract: str,
        exact_fields: frozenset[str] | None = None,
    ) -> dict[str, object]:
        if type(document) is not dict or (
            exact_fields is not None and set(document) != exact_fields
        ):
            raise DependencySecurityError(
                f"dependency graph {contract} projection is not exact"
            )
        expected = _digest(document.get(field), f"{contract} digest")
        body = copy.deepcopy(document)
        del body[field]
        if not hmac.compare_digest(
            expected,
            cls._semantic(body, contract=contract),
        ):
            raise DependencySecurityError(
                f"dependency graph {contract} projection digest changed"
            )
        return document

    @staticmethod
    def _public_digest(
        document: object,
        *,
        field: str,
        contract: str,
        version: str = "1.0.0",
    ) -> dict[str, object]:
        if type(document) is not dict:
            raise DependencySecurityError(
                f"dependency graph {contract} document is malformed"
            )
        expected = _digest(document.get(field), f"{contract} digest")
        body = copy.deepcopy(document)
        del body[field]
        actual = semantic_digest(
            freeze(body),
            contract_type=f"urn:gew:contract:{contract}",
            projection_id=f"urn:gew:digest-projection:{contract}:{version}",
            schema_id=f"urn:gew:schema:{contract}-input:{version}",
        )
        if not hmac.compare_digest(expected, actual):
            raise DependencySecurityError(
                f"dependency graph {contract} document digest changed"
            )
        return document

    @staticmethod
    def _action_authority(
        *,
        scenario_id: str,
        authority_refs: object,
        disposition: dict[str, object] | None,
    ) -> dict[str, object]:
        if type(authority_refs) not in {tuple, list}:
            raise DependencySecurityError(
                "dependency graph action authority refs are malformed"
            )
        refs = list(authority_refs)
        if (
            any(type(item) is not str or not item for item in refs)
            or refs != sorted(set(refs))
        ):
            raise DependencySecurityError(
                "dependency graph action authority refs are not canonical"
            )
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "scenario_id": scenario_id,
            "authority_refs": refs,
            "action_issued": False,
            "disposition_digest": (
                None if disposition is None else disposition["disposition_digest"]
            ),
            "owner_route": (
                None if disposition is None else disposition["owner_route"]
            ),
            "result": (
                "no-action-required"
                if disposition is None
                else "owner-route-required"
            ),
        }
        body["action_authority_digest"] = (
            DependencyGraphAssessmentFactory._semantic(
                body, contract="dependency-graph-action-authority",
            )
        )
        return dict(sorted(body.items()))

    @staticmethod
    def _target(
        *,
        observation: dict[str, object],
        before: dict[str, object],
        after: dict[str, object],
        before_graph: dict[str, object],
        after_graph: dict[str, object] | None,
        disposition: dict[str, object] | None,
        residual: dict[str, object],
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": "1.1.0",
            "scenario_id": observation["scenario_id"],
            "before_closure_digest": before["observation_digest"],
            "after_closure_digest": after["observation_digest"],
            "before_graph_digest": before_graph["observation_digest"],
            "after_graph_digest": (
                None if after_graph is None else after_graph["observation_digest"]
            ),
            "disposition_digest": (
                None if disposition is None else disposition["disposition_digest"]
            ),
            "residual_exposure_digest": residual["residual_exposure_digest"],
            "owner_route": (
                None if disposition is None else disposition["owner_route"]
            ),
        }
        body["target_observation_digest"] = semantic_digest(
            freeze(body),
            contract_type="urn:gew:contract:dependency-security-target",
            projection_id=(
                "urn:gew:digest-projection:dependency-security-target:1.1.0"
            ),
            schema_id=(
                "urn:gew:schema:dependency-security-observation-input:1.1.0"
            ),
        )
        return dict(sorted(body.items()))

    @classmethod
    def _regression(
        cls,
        *,
        observation: dict[str, object],
        applicability: dict[str, object],
        before_graph: dict[str, object],
        after_graph: dict[str, object] | None,
        disposition: dict[str, object] | None,
        residual: dict[str, object],
    ) -> dict[str, object]:
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "scenario_id": observation["scenario_id"],
            "registry_digest": observation["registry_digest"],
            "selected_advisory_id": before_graph["selected_advisory_id"],
            "selected_advisory_revision": before_graph[
                "selected_advisory_revision"
            ],
            "applicability_digest": applicability["applicability_digest"],
            "before_graph_digest": before_graph["observation_digest"],
            "after_graph_digest": (
                None if after_graph is None else after_graph["observation_digest"]
            ),
            "disposition_digest": (
                None if disposition is None else disposition["disposition_digest"]
            ),
            "residual_exposure_digest": residual["residual_exposure_digest"],
            "result": "PASS",
        }
        body["regression_digest"] = cls._semantic(
            body, contract="dependency-graph-regression",
        )
        return dict(sorted(body.items()))

    def issue(
        self,
        final_factory: object,
        final_observation: object,
        *,
        graph_ref_pins: object,
        authority_refs: object,
    ) -> DependencyGraphAssessmentEvidence:
        if (
            type(final_factory) is not DependencySecurityObservationFactory
            or type(final_observation) is not DependencySecurityObservation
            or final_observation._authority is not final_factory
            or final_factory._registry._repository is not self._repository
            or final_factory._graph is None
        ):
            raise DependencySecurityError(
                "dependency graph assessment source is foreign"
            )
        final_factory.require_current(final_observation)
        if (
            not isinstance(graph_ref_pins, Mapping)
            or set(graph_ref_pins) != self._PIN_FIELDS
            or any(
                type(item) is not str or SEMANTIC_DIGEST.fullmatch(item) is None
                for item in graph_ref_pins.values()
            )
        ):
            raise DependencySecurityError(
                "dependency graph assessment GraphRef pins are invalid"
            )
        before = final_observation._before.to_dict()
        after = final_observation._after.to_dict()
        before_graph = final_observation._before_graph.to_dict()
        after_graph = (
            None
            if final_observation._after_graph is None
            else final_observation._after_graph.to_dict()
        )
        applicability = final_observation._applicabilities[0].to_dict()
        residual = final_observation._residual.to_dict()
        disposition = (
            None
            if final_observation._disposition is None
            else final_observation._disposition.to_dict()
        )
        observation = final_observation.to_dict()
        advisory = thaw(final_observation._before_graph._advisory._record)
        if type(advisory) is not dict:
            raise DependencySecurityError(
                "dependency graph selected advisory is unavailable"
            )
        source = next((
            row for row in self._registry.registry._data.to_dict()["source_records"]
            if (
                row["source_id"], row["source_revision"]
            ) == (advisory["source_id"], advisory["source_revision"])
        ), None)
        if type(source) is not dict:
            raise DependencySecurityError(
                "dependency graph selected source is unavailable"
            )
        _current_registry, advisory_installation, _schemas = _bootstrap_projection()
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "evidence_kind": "dependency-graph-evidence-v1",
            "task_id": final_observation.task_id,
            "task_revision": final_observation.task_revision,
            "snapshot_digest": final_observation.snapshot_digest,
            "invalidation_epoch": final_observation.invalidation_epoch,
            "profile_id": "dependency-security",
            "scenario_id": final_observation.scenario_id,
            "graph_ref_pins": dict(sorted(graph_ref_pins.items())),
            "advisory_installation": dict(
                sorted(thaw(advisory_installation).items())
            ),
            "graph_installation": dict(
                sorted(thaw(self._graph_installation).items())
            ),
            "advisory_registry": self._registry.registry._data.to_dict(),
            "selected_source": source,
            "selected_advisory": advisory,
            "before_closure": before,
            "after_closure": after,
            "before_graph": before_graph,
            "after_graph": after_graph,
            "applicability": applicability,
            "residual_exposure": residual,
            "disposition": disposition,
            "regression": self._regression(
                observation=observation,
                applicability=applicability,
                before_graph=before_graph,
                after_graph=after_graph,
                disposition=disposition,
                residual=residual,
            ),
            "target": self._target(
                observation=observation,
                before=before,
                after=after,
                before_graph=before_graph,
                after_graph=after_graph,
                disposition=disposition,
                residual=residual,
            ),
            "action_authority": self._action_authority(
                scenario_id=final_observation.scenario_id,
                authority_refs=authority_refs,
                disposition=disposition,
            ),
            "observation": observation,
        }
        body["projection_digest"] = self._semantic(
            body, contract="dependency-graph-assessment-projection",
        )
        evidence = self._issue(
            body,
            source_factory=final_factory,
            source_observation=final_observation,
        )
        return self.require_current(evidence)

    def _issue(
        self,
        projection: Mapping[str, object],
        *,
        source_factory: object | None,
        source_observation: object | None,
    ) -> DependencyGraphAssessmentEvidence:
        frozen = freeze(projection)
        if not isinstance(frozen, FrozenMap):
            raise DependencySecurityError(
                "dependency graph assessment projection did not freeze"
            )
        result = object.__new__(DependencyGraphAssessmentEvidence)
        result.task_id = str(projection["task_id"])
        result.scenario_id = str(projection["scenario_id"])
        observation = projection["observation"]
        if type(observation) is not dict:
            raise DependencySecurityError(
                "dependency graph assessment observation is malformed"
            )
        result.observation_digest = str(observation["observation_digest"])
        result._projection = frozen
        result._authority = self
        result._source_factory = source_factory
        result._source_observation = source_observation
        self._issued[id(result)] = result
        return result

    @staticmethod
    def _canonical_graph(document: dict[str, object], label: str) -> None:
        nodes = document.get("nodes")
        edges = document.get("edges")
        path = document.get("reachability_path")
        if (
            type(nodes) is not list
            or type(edges) is not list
            or type(path) is not list
            or not path
            or nodes != sorted(nodes, key=lambda row: row["node_id"])
            or edges != sorted(
                edges,
                key=lambda row: (
                    row["parent_node_id"], row["child_node_id"],
                    row["requirement_row_digest"],
                ),
            )
            or len(path) != len(set(path))
            or path[0] != document.get("root_node_id")
        ):
            raise DependencySecurityError(
                f"dependency graph {label} topology is not canonical"
            )
        node_ids = {row.get("node_id") for row in nodes if type(row) is dict}
        edge_pairs = {
            (row.get("parent_node_id"), row.get("child_node_id"))
            for row in edges if type(row) is dict
        }
        if (
            len(node_ids) != len(nodes)
            or any(item not in node_ids for item in path)
            or any(pair not in edge_pairs for pair in zip(path, path[1:]))
            or path[-1]
            != next((
                row.get("node_id") for row in nodes
                if type(row) is dict
                and row.get("distribution_name")
                == document.get("selected_distribution_name")
            ), None)
        ):
            raise DependencySecurityError(
                f"dependency graph {label} reachability is not exact"
            )

    def _validate_projection(
        self, projection: object,
    ) -> dict[str, object]:
        if type(projection) is not dict or set(projection) != self._FIELDS:
            raise DependencySecurityError(
                "dependency graph assessment projection is not exact"
            )
        expected = _digest(
            projection["projection_digest"],
            "dependency graph assessment projection digest",
        )
        unsigned = copy.deepcopy(projection)
        del unsigned["projection_digest"]
        if (
            projection["schema_version"] != "1.0.0"
            or projection["evidence_kind"] != "dependency-graph-evidence-v1"
            or projection["profile_id"] != "dependency-security"
            or projection["scenario_id"] not in {
                "transitive-dependency", "fix-unavailable",
            }
            or type(projection["task_id"]) is not str
            or not projection["task_id"]
            or type(projection["task_revision"]) is not int
            or projection["task_revision"] < 1
            or type(projection["invalidation_epoch"]) is not int
            or projection["invalidation_epoch"] < 0
            or SEMANTIC_DIGEST.fullmatch(str(projection["snapshot_digest"])) is None
            or not hmac.compare_digest(
                expected,
                self._semantic(
                    unsigned,
                    contract="dependency-graph-assessment-projection",
                ),
            )
        ):
            raise DependencySecurityError(
                "dependency graph assessment projection identity changed"
            )
        pins = projection["graph_ref_pins"]
        if (
            type(pins) is not dict
            or set(pins) != self._PIN_FIELDS
            or any(
                type(item) is not str or SEMANTIC_DIGEST.fullmatch(item) is None
                for item in pins.values()
            )
        ):
            raise DependencySecurityError(
                "dependency graph assessment GraphRef pins changed"
            )
        current_registry, current_installation, _schemas = _bootstrap_projection()
        graph_policy, remediation, graph_installation = (
            _graph_installation_projection()
        )
        if (
            current_registry.to_dict() != projection["advisory_registry"]
            or thaw(current_installation) != projection["advisory_installation"]
            or thaw(graph_installation) != projection["graph_installation"]
            or graph_policy != self._graph_policy
            or remediation != self._remediation
            or graph_installation != self._graph_installation
        ):
            raise DependencySecurityError(
                "dependency graph assessment installation changed"
            )
        advisory = projection["selected_advisory"]
        source = projection["selected_source"]
        if type(advisory) is not dict or type(source) is not dict:
            raise DependencySecurityError(
                "dependency graph assessment selected authority is malformed"
            )
        advisory_rows = [
            row for row in current_registry.to_dict()["advisories"]
            if (
                row["advisory_id"], row["advisory_revision"]
            ) == (advisory.get("advisory_id"), advisory.get("advisory_revision"))
        ]
        source_rows = [
            row for row in current_registry.to_dict()["source_records"]
            if (
                row["source_id"], row["source_revision"]
            ) == (source.get("source_id"), source.get("source_revision"))
        ]
        if (
            len(advisory_rows) != 1
            or advisory_rows[0] != advisory
            or len(source_rows) != 1
            or source_rows[0] != source
            or (advisory.get("source_id"), advisory.get("source_revision"))
            != (source.get("source_id"), source.get("source_revision"))
        ):
            raise DependencySecurityError(
                "dependency graph assessment selected authority changed"
            )
        before = self._public_digest(
            projection["before_closure"],
            field="observation_digest",
            contract="dependency-offline-closure-observation",
        )
        after = self._public_digest(
            projection["after_closure"],
            field="observation_digest",
            contract="dependency-offline-closure-observation",
        )
        before_graph = self._public_digest(
            projection["before_graph"],
            field="observation_digest",
            contract="dependency-closure-graph-observation",
        )
        after_graph_raw = projection["after_graph"]
        after_graph = (
            None
            if after_graph_raw is None
            else self._public_digest(
                after_graph_raw,
                field="observation_digest",
                contract="dependency-closure-graph-observation",
            )
        )
        self._canonical_graph(before_graph, "before")
        if after_graph is not None:
            self._canonical_graph(after_graph, "after")
        applicability = self._public_digest(
            projection["applicability"],
            field="applicability_digest",
            contract="dependency-applicability-observation",
        )
        residual = projection["residual_exposure"]
        if type(residual) is not dict:
            raise DependencySecurityError(
                "dependency graph residual projection is malformed"
            )
        evaluation = evaluate_dependency_closures(
            current_registry.to_dict(),
            before_closure=before.get("members"),
            after_closure=after.get("members"),
            clock_authority=self._registry,
        )
        expected_residual = {
            "schema_version": "1.0.0",
            "registry_digest": evaluation.registry_digest,
            "rows": [item.to_dict() for item in evaluation.rows],
            "active_advisory_ids": list(evaluation.active_advisory_ids),
            "residual_advisory_ids": list(evaluation.residual_advisory_ids),
            "residual_exposure_digest": evaluation.evaluation_digest,
        }
        disposition = projection["disposition"]
        scenario_id = projection["scenario_id"]
        matching_dispositions = [
            thaw(row) for row in remediation.dispositions
            if (
                row["advisory_id"], row["advisory_revision"],
                row["graph_policy_digest"],
            ) == (
                advisory["advisory_id"], advisory["advisory_revision"],
                graph_policy.registry_digest,
            )
        ]
        if (
            before.get("phase") != "before"
            or after.get("phase") != "after"
            or before_graph.get("phase") != "before"
            or before_graph.get("physical_closure_digest")
            != before.get("physical_closure_digest")
            or before_graph.get("selected_advisory_id")
            != advisory.get("advisory_id")
            or before_graph.get("selected_advisory_revision")
            != advisory.get("advisory_revision")
            or applicability.get("advisory_digest")
            != advisory.get("advisory_digest")
            or applicability.get("before_closure_digest")
            != before.get("observation_digest")
            or applicability.get("after_closure_digest")
            != after.get("observation_digest")
            or expected_residual != residual
            or (
                scenario_id == "transitive-dependency"
                and (
                    after_graph is None
                    or disposition is not None
                    or len(before_graph["reachability_path"]) < 3
                    or len(after_graph["reachability_path"]) < 3
                    or after_graph.get("physical_closure_digest")
                    != after.get("physical_closure_digest")
                    or applicability.get("after_fixed") is not True
                )
            )
            or (
                scenario_id == "fix-unavailable"
                and (
                    after_graph is not None
                    or len(matching_dispositions) != 1
                    or disposition != matching_dispositions[0]
                    or applicability.get("after_fixed") is not False
                    or not disposition.get("owner_route")
                )
            )
        ):
            raise DependencySecurityError(
                "dependency graph assessment nested authority is mixed or stale"
            )
        observation = self._public_digest(
            projection["observation"],
            field="observation_digest",
            contract="dependency-security-observation",
            version="1.1.0",
        )
        target = projection["target"]
        regression = self._verify_nested_digest(
            projection["regression"],
            field="regression_digest",
            contract="dependency-graph-regression",
        )
        action = self._verify_nested_digest(
            projection["action_authority"],
            field="action_authority_digest",
            contract="dependency-graph-action-authority",
        )
        expected_target = self._target(
            observation=observation,
            before=before,
            after=after,
            before_graph=before_graph,
            after_graph=after_graph,
            disposition=disposition,
            residual=residual,
        )
        expected_regression = self._regression(
            observation=observation,
            applicability=applicability,
            before_graph=before_graph,
            after_graph=after_graph,
            disposition=disposition,
            residual=residual,
        )
        expected_action = self._action_authority(
            scenario_id=str(scenario_id),
            authority_refs=action.get("authority_refs"),
            disposition=disposition,
        )
        if (
            target != expected_target
            or regression != expected_regression
            or action != expected_action
            or observation.get("task_id") != projection["task_id"]
            or observation.get("task_revision") != projection["task_revision"]
            or observation.get("snapshot_digest") != projection["snapshot_digest"]
            or observation.get("invalidation_epoch")
            != projection["invalidation_epoch"]
            or observation.get("scenario_id") != scenario_id
            or observation.get("registry_digest")
            != current_registry.registry_digest
            or observation.get("graph_policy_digest")
            != graph_policy.registry_digest
            or observation.get("remediation_registry_digest")
            != remediation.registry_digest
            or observation.get("before_graph_digest")
            != before_graph["observation_digest"]
            or observation.get("after_graph_digest")
            != (None if after_graph is None else after_graph["observation_digest"])
            or observation.get("disposition_digest")
            != (None if disposition is None else disposition["disposition_digest"])
            or observation.get("residual_exposure_digest")
            != residual["residual_exposure_digest"]
            or observation.get("target_observation_digest")
            != target["target_observation_digest"]
        ):
            raise DependencySecurityError(
                "dependency graph assessment observation binding changed"
            )
        return projection

    def rehydrate_projection(
        self, projection: object,
    ) -> DependencyGraphAssessmentEvidence:
        source = thaw(freeze(projection))
        if type(source) is not dict:
            raise DependencySecurityError(
                "dependency graph assessment projection is malformed"
            )
        current = self._validate_projection(source)
        result = self._issue(
            current,
            source_factory=None,
            source_observation=None,
        )
        return self.require_current(result)

    def require_current(
        self, value: object,
    ) -> DependencyGraphAssessmentEvidence:
        if (
            type(value) is not DependencyGraphAssessmentEvidence
            or value._authority is not self
            or self._issued.get(id(value)) is not value
        ):
            raise DependencySecurityError(
                "dependency graph assessment evidence is foreign"
            )
        projection = value.to_dict()
        self._validate_projection(projection)
        source_factory = value._source_factory
        source_observation = value._source_observation
        if source_factory is not None or source_observation is not None:
            if (
                type(source_factory) is not DependencySecurityObservationFactory
                or type(source_observation) is not DependencySecurityObservation
                or source_observation._authority is not source_factory
            ):
                raise DependencySecurityError(
                    "dependency graph assessment source became foreign"
                )
            source_factory.require_current(source_observation)
        return value

    def projection(self, value: object) -> FrozenMap:
        return self.require_current(value)._projection

    def precommit(self, value: object) -> DependencyGraphAssessmentEvidence:
        return self.require_current(value)

    def restart(self, value: object) -> DependencyGraphAssessmentEvidence:
        return self.require_current(value)


def _closure_members(value: object, label: str) -> tuple[Mapping[str, object], ...]:
    if type(value) is not list or not value:
        raise DependencySecurityError(f"{label} must be a non-empty array")
    fields = {
        "distribution_name", "distribution_version", "wheel_raw_sha256",
        "record_raw_sha256",
    }
    members: list[Mapping[str, object]] = []
    identities: list[tuple[str, str]] = []
    for raw in value:
        if type(raw) is not dict or set(raw) != fields:
            raise DependencySecurityError(f"{label} member is not exact")
        name = raw["distribution_name"]
        version = raw["distribution_version"]
        if type(name) is not str or not name or type(version) is not str or not version:
            raise DependencySecurityError(f"{label} identity is invalid")
        _raw(raw["wheel_raw_sha256"], f"{label} wheel digest")
        _raw(raw["record_raw_sha256"], f"{label} RECORD digest")
        identities.append((name, version))
        members.append(raw)
    if tuple(identities) != tuple(sorted(set(identities))):
        raise DependencySecurityError(f"{label} is not canonical and unique")
    return tuple(members)


def evaluate_dependency_closures(
    registry_document: object,
    *,
    before_closure: object,
    after_closure: object,
    clock_authority: object,
) -> DependencyEvaluation:
    """Compute deterministic dispositions; version parsing stays in the WP08A pipe."""

    from graph_engineering import _dependency_advisory_specifier_matches

    registry = parse_dependency_advisory_registry(registry_document)
    if type(clock_authority) is not DependencyAdvisoryRegistryFactory:
        raise DependencySecurityError(
            "dependency evaluation repository clock authority is foreign"
        )
    current = clock_authority.require_current(clock_authority.registry)
    if current._data.document != registry.document:
        raise DependencySecurityError(
            "dependency evaluation registry is not the current installed head"
        )
    observed_at = clock_authority._clock_timestamp()
    document = registry.to_dict()
    before = _closure_members(before_closure, "before dependency closure")
    after = _closure_members(after_closure, "after dependency closure")
    before_by_name = {str(item["distribution_name"]): item for item in before}
    after_by_identity = {
        (str(item["distribution_name"]), str(item["distribution_version"])): item
        for item in after
    }
    sources = {
        (str(item["source_id"]), int(item["source_revision"])): item
        for item in document["source_records"]  # type: ignore[union-attr]
    }
    source_states = {
        (str(item["source_id"]), int(item["source_revision"])): item
        for item in document["revocation_high_water"]["source_states"]  # type: ignore[index]
    }
    advisory_states = {
        (str(item["advisory_id"]), int(item["advisory_revision"])): item
        for item in document["revocation_high_water"]["advisory_states"]  # type: ignore[index]
    }
    rows: list[DependencyEvaluationRow] = []
    active: list[str] = []
    residual: list[str] = []
    for advisory in document["advisories"]:  # type: ignore[union-attr]
        identity = (
            str(advisory["advisory_id"]), int(advisory["advisory_revision"])
        )
        state = advisory_states[identity]
        identity_text = f"{identity[0]}@{identity[1]}"
        if state["status"] != "active":
            rows.append(DependencyEvaluationRow(
                identity[0], identity[1], "inactive",
                str(advisory["advisory_digest"]), None, None, None,
            ))
            continue
        active.append(identity_text)
        source_identity = (
            str(advisory["source_id"]), int(advisory["source_revision"])
        )
        source = sources[source_identity]
        if source_states[source_identity]["status"] != "active" or not source_is_current(
            source, observed_at
        ):
            raise DependencySecurityError("active advisory source is not current")
        member = before_by_name.get(str(advisory["distribution_name"]))
        affected = False
        if member is not None:
            affected = any(
                _dependency_advisory_specifier_matches(
                    str(specifier), str(member["distribution_version"])
                )
                for specifier in advisory["affected_version_specifiers"]
            )
        disposition = "not-applicable"
        matched_version = None if member is None else str(member["distribution_version"])
        matched_closure = None
        if affected:
            for closure in advisory["fixed_closures"]:
                pins = closure["required_distribution_pins"]
                if all(
                    after_by_identity.get((
                        str(pin["distribution_name"]),
                        str(pin["distribution_version"]),
                    )) == pin
                    for pin in pins
                ):
                    disposition = "fixed"
                    matched_closure = str(closure["closure_id"])
                    break
            else:
                disposition = "residual"
                residual.append(identity_text)
        rows.append(DependencyEvaluationRow(
            identity[0], identity[1], disposition,
            str(advisory["advisory_digest"]),
            str(source["source_record_digest"]),
            matched_version,
            matched_closure,
        ))
    if tuple(active) != tuple(sorted(set(active))):
        raise DependencySecurityError("active advisory evaluation universe is not exact")
    body = {
        "schema_version": "1.0.0",
        "registry_digest": registry.registry_digest,
        "rows": [row.to_dict() for row in rows],
        "active_advisory_ids": active,
        "residual_advisory_ids": residual,
    }
    evaluation_digest = semantic_digest(
        freeze(body),
        contract_type="urn:gew:contract:dependency-residual-exposure-observation",
        projection_id=(
            "urn:gew:digest-projection:dependency-residual-exposure-observation:1.0.0"
        ),
        schema_id=(
            "urn:gew:schema:dependency-residual-exposure-observation-input:1.0.0"
        ),
    )
    return DependencyEvaluation(
        registry.registry_digest,
        tuple(rows), tuple(active), tuple(residual), evaluation_digest,
    )
