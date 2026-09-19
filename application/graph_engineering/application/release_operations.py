"""Installed authority and evidence factory for ADR-0009 release operations."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from weakref import WeakSet

from graph_engineering.adapters.local_release_simulator import (
    LocalReleaseSimulatorSession,
    _LocalReleaseSimulatorFactory,
)
from graph_engineering.core.contracts.digest import SEMANTIC_DIGEST, semantic_digest
from graph_engineering.core.contracts.immutable import FrozenMap, freeze, thaw
from graph_engineering.core.contracts.schema import validate_instance
from graph_engineering.core.release_operations import (
    RELEASE_OPERATIONS_SCHEMA_IDS,
    ReleaseArtifactManifest,
    ReleaseOperationsError,
    ReleaseOperationsRegistry,
)


_INSTALLED_RELEASE_FACTORIES: WeakSet[object] = WeakSet()


def _strict_json(body: bytes, label: str) -> dict[str, object]:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise ReleaseOperationsError(f"{label} has a duplicate key")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseOperationsError(f"{label} is malformed") from error
    if type(value) is not dict:
        raise ReleaseOperationsError(f"{label} root is not an object")
    return value


def _raw(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _semantic(value: Mapping[str, object], name: str) -> str:
    return semantic_digest(
        freeze(value),
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


_BOOTSTRAP_FIELDS = (
    "schema_version", "bootstrap_id", "policy_registry_id",
    "policy_registry_digest", "policy_registry_raw_sha256", "fixture_registry_id",
    "fixture_registry_digest", "fixture_registry_raw_sha256",
    "profile_schema_registry_id", "profile_schema_registry_digest",
    "profile_schema_registry_raw_sha256", "schema_vectors",
    "action_authority_pins", "source_authority_pins", "package_authority_pins",
    "protected_resources", "protected_closure_digest", "bootstrap_digest",
)


def _verify_bootstrap(
    bootstrap: Mapping[str, object],
    *,
    policy_bytes: bytes,
    fixture_bytes: bytes,
    profile_schema_registry_bytes: bytes,
    package_provenance_bytes: bytes,
    schema_bodies: Mapping[str, bytes],
    protected_resources: Mapping[str, bytes],
) -> None:
    if type(bootstrap) is not dict or tuple(bootstrap) != _BOOTSTRAP_FIELDS:
        raise ReleaseOperationsError("release bootstrap fields/order are not exact")
    policy = _strict_json(policy_bytes, "release policy registry")
    fixture = _strict_json(fixture_bytes, "release fixture registry")
    profile = _strict_json(profile_schema_registry_bytes, "Profile schema registry")
    if (
        bootstrap["schema_version"] != "1.0.0"
        or bootstrap["policy_registry_id"] != policy.get("registry_id")
        or bootstrap["policy_registry_digest"] != policy.get("registry_digest")
        or bootstrap["policy_registry_raw_sha256"] != _raw(policy_bytes)
        or bootstrap["fixture_registry_id"] != fixture.get("registry_id")
        or bootstrap["fixture_registry_digest"] != fixture.get("registry_digest")
        or bootstrap["fixture_registry_raw_sha256"] != _raw(fixture_bytes)
        or bootstrap["profile_schema_registry_id"] != profile.get("registry_id")
        or bootstrap["profile_schema_registry_digest"] != profile.get("registry_digest")
        or bootstrap["profile_schema_registry_raw_sha256"]
        != _raw(profile_schema_registry_bytes)
    ):
        raise ReleaseOperationsError("release bootstrap registry pins changed")
    vectors = bootstrap["schema_vectors"]
    if type(vectors) is not list or tuple(
        row.get("schema_id") for row in vectors if type(row) is dict
    ) != RELEASE_OPERATIONS_SCHEMA_IDS:
        raise ReleaseOperationsError("release bootstrap schema closure changed")
    for row in vectors:
        if type(row) is not dict or tuple(row) != ("schema_id", "raw_sha256"):
            raise ReleaseOperationsError("release bootstrap schema vector is not exact")
        body = schema_bodies.get(str(row["schema_id"]))
        if body is None or row["raw_sha256"] != _raw(body):
            raise ReleaseOperationsError("release bootstrap schema bytes changed")
    resources = bootstrap["protected_resources"]
    expected_paths = tuple(sorted(protected_resources))
    if type(resources) is not list or tuple(
        row.get("path") for row in resources if type(row) is dict
    ) != expected_paths:
        raise ReleaseOperationsError("release protected resource closure changed")
    closure_rows: list[dict[str, object]] = []
    for row in resources:
        if type(row) is not dict or tuple(row) != ("path", "raw_sha256"):
            raise ReleaseOperationsError("release protected resource is not exact")
        body = protected_resources.get(str(row["path"]))
        if body is None or row["raw_sha256"] != _raw(body):
            raise ReleaseOperationsError("release protected resource bytes changed")
        closure_rows.append(dict(row))
    closure = _semantic(
        {"schema_version": "1.0.0", "resources": closure_rows},
        "release-operations-protected-closure",
    )
    if bootstrap["protected_closure_digest"] != closure:
        raise ReleaseOperationsError("release protected closure changed")
    action_pins = bootstrap["action_authority_pins"]
    action_expected = {
        "adapter_registry_digest": (
            "config/contracts/action-adapter-registry-v1.json", "registry_digest",
        ),
        "concrete_policy_digest": (
            "config/actions/concrete-action-policy-v1.json", "policy_digest",
        ),
        "default_action_policy_digest": (
            "config/actions/action-policy-v1.json", "policy_digest",
        ),
        "local_action_policy_digest": (
            "config/actions/action-policy-local-actions-v1.json", "policy_digest",
        ),
        "default_runtime_digest": (
            "config/security/security-runtime-v1.json", "manifest_digest",
        ),
        "local_runtime_digest": (
            "config/security/security-runtime-local-actions-v1.json", "manifest_digest",
        ),
    }
    expected_action_fields = {
        field for key in action_expected for field in (key, key.removesuffix("_digest") + "_raw_sha256")
    }
    if type(action_pins) is not dict or set(action_pins) != expected_action_fields:
        raise ReleaseOperationsError("release action authority pins are not exact")
    for digest_field, (path, document_field) in action_expected.items():
        resource = protected_resources.get(path)
        if resource is None:
            raise ReleaseOperationsError("release action authority resource is absent")
        document = _strict_json(resource, path)
        raw_field = digest_field.removesuffix("_digest") + "_raw_sha256"
        if (
            action_pins[digest_field] != document.get(document_field)
            or action_pins[raw_field] != _raw(resource)
        ):
            raise ReleaseOperationsError("release action authority pin changed")
    source_pins = bootstrap["source_authority_pins"]
    if type(source_pins) is not dict or tuple(source_pins) != (
        "policy_id", "source_file_count", "source_issuer_raw_sha256",
    ):
        raise ReleaseOperationsError("release source authority pins are not exact")
    from graph_engineering import _SOURCE_FILES

    source_issuer = protected_resources.get(
        "core/graph_engineering/core/source_checkout.py"
    )
    if (
        source_pins["policy_id"] != "source-checkout-attestation-v1"
        or source_pins["source_file_count"] != len(_SOURCE_FILES)
        or source_issuer is None
        or source_pins["source_issuer_raw_sha256"] != _raw(source_issuer)
    ):
        raise ReleaseOperationsError("release source authority pin changed")
    package_pins = bootstrap["package_authority_pins"]
    if type(package_pins) is not dict or tuple(package_pins) != (
        "build_backend_raw_sha256", "distribution_name", "distribution_version",
    ):
        raise ReleaseOperationsError("release package authority pins are not exact")
    try:
        provenance = tomllib.loads(package_provenance_bytes.decode("utf-8", errors="strict"))
        project = provenance["project"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseOperationsError("release package provenance is malformed") from error
    build_backend = protected_resources.get("scripts/build_backend.py")
    if (
        type(project) is not dict
        or package_pins["distribution_name"] != project.get("name")
        or package_pins["distribution_version"] != project.get("version")
        or build_backend is None
        or package_pins["build_backend_raw_sha256"] != _raw(build_backend)
    ):
        raise ReleaseOperationsError("release package authority pin changed")
    unsigned = copy.deepcopy(dict(bootstrap))
    expected = unsigned.pop("bootstrap_digest", None)
    if (
        type(expected) is not str or SEMANTIC_DIGEST.fullmatch(expected) is None
        or not hmac.compare_digest(
            expected, _semantic(unsigned, "release-operations-installation-bootstrap")
        )
    ):
        raise ReleaseOperationsError("release bootstrap digest changed")


_PROJECTION_FIELDS = (
    "schema_version", "evidence_kind", "task_id", "task_revision",
    "snapshot_digest", "invalidation_epoch", "profile_id", "profile_version",
    "graph_ref_pins", "installation_pins",
    "artifact_manifest", "artifact_manifest_digest",
    "deployment_observation", "deployment_observation_digest",
    "health_observation", "health_observation_digest",
    "rollback_observation", "rollback_observation_digest",
    "current_target", "current_target_digest", "claim_id", "receipt_digest", "owner_route",
    "column_id", "scenario_id", "outcome", "observation_digest",
)

_GRAPH_PIN_FIELDS = frozenset({
    "base_graph_digest", "profile_digest", "overlay_digest",
    "project_config_digest", "support_matrix_digest", "materialization_digest",
})


@dataclass(frozen=True, slots=True, init=False)
class ReleaseOperationsEvidence:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


@dataclass(frozen=True, slots=True, init=False)
class ReleaseDeploymentObservation:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


@dataclass(frozen=True, slots=True, init=False)
class ReleaseHealthObservation:
    projection: FrozenMap
    _factory: object

    def to_dict(self) -> dict[str, object]:
        return thaw(self.projection)


class ReleaseOperationsRegistryFactory:
    """Validate installation bytes and issue factory-local release capabilities."""

    def __init__(
        self,
        registry: ReleaseOperationsRegistry,
        bootstrap: Mapping[str, object],
        *,
        schema_documents: Mapping[str, Mapping[str, object]],
        currentness_check: Callable[[], None],
    ) -> None:
        if type(registry) is not ReleaseOperationsRegistry or not callable(currentness_check):
            raise ReleaseOperationsError("release factory authority is invalid")
        self._registry = registry
        frozen = freeze(bootstrap)
        if not isinstance(frozen, FrozenMap):
            raise ReleaseOperationsError("release bootstrap did not freeze")
        self._bootstrap = frozen
        if set(schema_documents) != set(RELEASE_OPERATIONS_SCHEMA_IDS):
            raise ReleaseOperationsError("release schema authority is incomplete")
        self._schemas = {
            schema_id: freeze(document)
            for schema_id, document in schema_documents.items()
        }
        self._currentness_check = currentness_check
        self._issued: dict[int, ReleaseOperationsEvidence] = {}
        self._issued_manifests: dict[int, ReleaseArtifactManifest] = {}
        self._issued_artifact_bytes: dict[int, bytes] = {}
        self._issued_sessions: dict[int, LocalReleaseSimulatorSession] = {}
        self._session_coordinators: dict[int, object] = {}
        self._issued_deployments: dict[int, ReleaseDeploymentObservation] = {}
        self._deployment_sessions: dict[int, LocalReleaseSimulatorSession] = {}
        self._deployment_outcomes: dict[int, object] = {}
        self._evidence_bindings: dict[
            int, tuple[
                LocalReleaseSimulatorSession, ReleaseDeploymentObservation,
                ReleaseDeploymentObservation | None,
            ]
        ] = {}
        self._issued_health: dict[int, ReleaseHealthObservation] = {}
        self._health_bindings: dict[
            int, tuple[LocalReleaseSimulatorSession, ReleaseDeploymentObservation]
        ] = {}
        self._currentness_check()

    def _resolve_schema(
        self, current_id: str, reference: str,
    ) -> tuple[object, str]:
        if reference.startswith("#"):
            target_id, pointer = current_id, reference[1:]
        else:
            target_id, separator, pointer = reference.partition("#")
            if not separator:
                pointer = ""
        target = self._schemas.get(target_id)
        if target is None:
            raise ReleaseOperationsError("release schema reference is not installed")
        current: object = target
        if pointer:
            if not pointer.startswith("/"):
                raise ReleaseOperationsError("release schema pointer is invalid")
            for encoded in pointer[1:].split("/"):
                token = encoded.replace("~1", "/").replace("~0", "~")
                if not isinstance(current, Mapping) or token not in current:
                    raise ReleaseOperationsError("release schema pointer is unresolved")
                current = current[token]
        return current, target_id

    def _validate_document(self, schema_id: str, document: object) -> None:
        schema = self._schemas.get(schema_id)
        if schema is None:
            raise ReleaseOperationsError("release schema is not installed")
        try:
            failures = validate_instance(
                schema,
                document,
                source_id=schema_id,
                resolver=self._resolve_schema,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ReleaseOperationsError("release schema validation failed") from error
        if failures:
            raise ReleaseOperationsError(
                f"release document violates {schema_id}: {failures[0].rule_id}"
            )

    @classmethod
    def from_documents(
        cls,
        *,
        policy_bytes: bytes,
        fixture_bytes: bytes,
        bootstrap_bytes: bytes,
        profile_schema_registry_bytes: bytes,
        package_provenance_bytes: bytes,
        schema_bodies: Mapping[str, bytes],
        protected_resources: Mapping[str, bytes],
        current_resource_reader: Callable[[], Mapping[str, bytes]] | None = None,
    ) -> "ReleaseOperationsRegistryFactory":
        if any(type(body) is not bytes for body in (
            policy_bytes, fixture_bytes, bootstrap_bytes, profile_schema_registry_bytes,
            package_provenance_bytes,
        )):
            raise ReleaseOperationsError("release installation bodies are not exact bytes")
        policy = _strict_json(policy_bytes, "release policy registry")
        fixture = _strict_json(fixture_bytes, "release fixture registry")
        bootstrap = _strict_json(bootstrap_bytes, "release installation bootstrap")
        schemas = dict(schema_bodies)
        protected = dict(protected_resources)
        _verify_bootstrap(
            bootstrap,
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            profile_schema_registry_bytes=profile_schema_registry_bytes,
            package_provenance_bytes=package_provenance_bytes,
            schema_bodies=schemas,
            protected_resources=protected,
        )
        initial = {
            "policy": policy_bytes,
            "fixture": fixture_bytes,
            "bootstrap": bootstrap_bytes,
            "profile-schema-registry": profile_schema_registry_bytes,
            "package-provenance": package_provenance_bytes,
            **{f"schema:{key}": value for key, value in schemas.items()},
            **{f"protected:{key}": value for key, value in protected.items()},
        }
        expected = {key: _raw(value) for key, value in initial.items()}

        def current() -> None:
            if current_resource_reader is None:
                observed = initial
            else:
                observed = dict(current_resource_reader())
            if set(observed) != set(expected) or any(
                type(observed[key]) is not bytes or _raw(observed[key]) != digest
                for key, digest in expected.items()
            ):
                raise ReleaseOperationsError("release installation currentness changed")

        return cls(
            ReleaseOperationsRegistry.from_dicts(policy, fixture),
            bootstrap,
            schema_documents={
                schema_id: _strict_json(body, f"release schema {schema_id}")
                for schema_id, body in schemas.items()
            },
            currentness_check=current,
        )

    @classmethod
    def from_installation(cls) -> "ReleaseOperationsRegistryFactory":
        if cls is not ReleaseOperationsRegistryFactory:
            raise ReleaseOperationsError("release installation factory type is foreign")
        from graph_engineering import (
            DistributionIdentityError,
            _release_operations_installation_resources,
        )

        try:
            resources = _release_operations_installation_resources()
            provenance_bytes, policy_bytes, fixture_bytes, bootstrap_bytes, profile_bytes = (
                resources[:5]
            )
            schema_bodies = resources[5:5 + len(RELEASE_OPERATIONS_SCHEMA_IDS)]
            bootstrap = _strict_json(bootstrap_bytes, "release installation bootstrap")
            protected_count = len(bootstrap.get("protected_resources", ()))
            protected_bodies = resources[5 + len(RELEASE_OPERATIONS_SCHEMA_IDS):]
            provenance = tomllib.loads(provenance_bytes.decode("utf-8", errors="strict"))
            project = provenance["project"]
            pin = provenance["tool"]["gew"]["profile"]["release-operations"]
        except (
            DistributionIdentityError, KeyError, TypeError, UnicodeError,
            tomllib.TOMLDecodeError,
        ) as error:
            raise ReleaseOperationsError(
                "release installation bootstrap is unavailable"
            ) from error
        expected_pin_fields = {
            "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
            "bootstrap-source", "bootstrap-resource", "policy-source",
            "policy-resource", "fixture-source", "fixture-resource",
            "profile-schema-registry-source", "profile-schema-registry-resource",
            "schema-sources", "schema-resources", "protected-sources",
            "protected-resources", "distribution-name", "distribution-version",
        }
        if type(pin) is not dict or set(pin) != expected_pin_fields:
            raise ReleaseOperationsError("release independent installation pin is not exact")
        if (
            len(schema_bodies) != len(RELEASE_OPERATIONS_SCHEMA_IDS)
            or len(protected_bodies) != protected_count
            or pin["bootstrap-id"] != bootstrap.get("bootstrap_id")
            or pin["bootstrap-digest"] != bootstrap.get("bootstrap_digest")
            or not hmac.compare_digest(
                _raw(bootstrap_bytes), str(pin["bootstrap-raw-sha256"]),
            )
        ):
            raise ReleaseOperationsError("release installation pin changed")
        if (
            type(project) is not dict
            or pin["distribution-name"] != project.get("name")
            or pin["distribution-version"] != project.get("version")
            or pin["distribution-name"]
            != bootstrap.get("package_authority_pins", {}).get("distribution_name")
            or pin["distribution-version"]
            != bootstrap.get("package_authority_pins", {}).get("distribution_version")
        ):
            raise ReleaseOperationsError("release independent installation pin changed")
        schema_documents = {
            str(document["$id"]): body
            for body in schema_bodies
            for document in (_strict_json(body, "release schema"),)
        }
        protected_paths = tuple(
            str(row["path"])
            for row in bootstrap["protected_resources"]
            if type(row) is dict and "path" in row
        )
        if len(protected_paths) != protected_count:
            raise ReleaseOperationsError("release protected closure is malformed")
        protected = dict(zip(protected_paths, protected_bodies, strict=True))

        def read_current() -> Mapping[str, bytes]:
            try:
                current = _release_operations_installation_resources()
            except (DistributionIdentityError, OSError) as error:
                raise ReleaseOperationsError(
                    "release installation closure is unavailable"
                ) from error
            current_schema_bodies = current[5:5 + len(RELEASE_OPERATIONS_SCHEMA_IDS)]
            current_protected = current[5 + len(RELEASE_OPERATIONS_SCHEMA_IDS):]
            return {
                "policy": current[1],
                "fixture": current[2],
                "bootstrap": current[3],
                "profile-schema-registry": current[4],
                "package-provenance": current[0],
                **{
                    f"schema:{schema_id}": body
                    for schema_id, body in zip(
                        RELEASE_OPERATIONS_SCHEMA_IDS,
                        current_schema_bodies,
                        strict=True,
                    )
                },
                **{
                    f"protected:{path}": body
                    for path, body in zip(
                        protected_paths, current_protected, strict=True,
                    )
                },
            }

        factory = cls.from_documents(
            policy_bytes=policy_bytes,
            fixture_bytes=fixture_bytes,
            bootstrap_bytes=bootstrap_bytes,
            profile_schema_registry_bytes=profile_bytes,
            package_provenance_bytes=provenance_bytes,
            schema_bodies=schema_documents,
            protected_resources=protected,
            current_resource_reader=read_current,
        )
        _INSTALLED_RELEASE_FACTORIES.add(factory)
        return factory

    def registry(self) -> ReleaseOperationsRegistry:
        self._currentness_check()
        return self._registry

    def require_installed_authority(self) -> None:
        """Require the opaque authority granted only by ``from_installation``."""

        if (
            type(self) is not ReleaseOperationsRegistryFactory
            or self not in _INSTALLED_RELEASE_FACTORIES
        ):
            raise ReleaseOperationsError("release installed authority is absent")
        self._currentness_check()

    def issue_artifact_manifest(
        self,
        *,
        fixture_id: str,
        artifact_id: str,
    ) -> ReleaseArtifactManifest:
        """Issue only artifact bytes owned by the installed fixture registry."""

        self.require_installed_authority()
        vector = self._registry.fixture_artifact(fixture_id, artifact_id)
        encoded = vector["artifact_base64"]
        if type(encoded) is not str or not encoded.isascii():
            raise ReleaseOperationsError("release fixture artifact bytes are invalid")
        try:
            artifact_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as error:
            raise ReleaseOperationsError(
                "release fixture artifact bytes are invalid"
            ) from error
        if not artifact_bytes or base64.b64encode(artifact_bytes).decode("ascii") != encoded:
            raise ReleaseOperationsError("release fixture artifact bytes are not canonical")
        artifact_record = {
            "schema_version": "1.0.0",
            "fixture_id": fixture_id,
            "artifact": dict(vector),
        }
        record_digest = _semantic(artifact_record, "release-fixture-artifact-record")
        source_manifest_digest = _semantic(
            {
                "schema_version": "1.0.0",
                "fixture_id": fixture_id,
                "fixture_registry_id": self._bootstrap["fixture_registry_id"],
                "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            },
            "release-fixture-source-manifest",
        )
        build_attestation_digest = _semantic({
            "schema_version": "1.0.0",
            "attestation_kind": "installed-deterministic-release-fixture",
            "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            "artifact_record_digest": record_digest,
            "source_manifest_digest": source_manifest_digest,
            "protected_closure_digest": self._bootstrap["protected_closure_digest"],
        }, "release-fixture-build-attestation")
        manifest = ReleaseArtifactManifest._issue(
            artifact_id=artifact_id,
            artifact_version=str(vector["artifact_version"]),
            artifact_bytes=artifact_bytes,
            distribution_name=str(vector["distribution_name"]),
            distribution_version=str(vector["distribution_version"]),
            record_digest=record_digest,
            source_manifest_digest=source_manifest_digest,
            build_attestation_digest=build_attestation_digest,
            protected_closure_digest=str(self._bootstrap["protected_closure_digest"]),
        )
        self._validate_document(
            "urn:gew:schema:release-artifact-manifest:1.0.0",
            manifest.to_dict(),
        )
        self._issued_manifests[id(manifest)] = manifest
        self._issued_artifact_bytes[id(manifest)] = artifact_bytes
        return manifest

    def artifact_bytes(self, manifest: ReleaseArtifactManifest) -> bytes:
        """Return bytes for an exact factory-issued fixture artifact."""

        self.require_installed_authority()
        if self._issued_manifests.get(id(manifest)) is not manifest:
            raise ReleaseOperationsError("release artifact authority is foreign")
        body = self._issued_artifact_bytes.get(id(manifest))
        if type(body) is not bytes:
            raise ReleaseOperationsError("release artifact bytes are unavailable")
        return body

    def issue_simulator(
        self,
        *,
        action_coordinator: object,
        task_id: str,
        fixture_id: str,
        target_id: str,
        resource_id: str,
        baseline_manifest: ReleaseArtifactManifest,
        authorized_artifacts: tuple[ReleaseArtifactManifest, ...],
        fault_hook: Callable[[str], None] = lambda _step: None,
    ) -> LocalReleaseSimulatorSession:
        from graph_engineering.application.actions import ActionCoordinator

        self.require_installed_authority()
        if type(action_coordinator) is not ActionCoordinator:
            raise ReleaseOperationsError("release simulator coordinator is missing or forged")
        if any(
            self._issued_manifests.get(id(manifest)) is not manifest
            for manifest in authorized_artifacts
        ):
            raise ReleaseOperationsError("release simulator artifact authority is foreign")
        if self._issued_manifests.get(id(baseline_manifest)) is not baseline_manifest:
            raise ReleaseOperationsError("release simulator baseline authority is foreign")
        if baseline_manifest not in authorized_artifacts:
            raise ReleaseOperationsError("release simulator baseline is not authorized")
        baseline_artifact_bytes = self.artifact_bytes(baseline_manifest)
        exact_authorized = tuple(
            (manifest, self.artifact_bytes(manifest))
            for manifest in authorized_artifacts
        )
        session = _LocalReleaseSimulatorFactory(
            self._registry,
            currentness_check=self._currentness_check,
            durable_execution_gate=action_coordinator.issue_durable_execution_gate(),
            issuer=self,
        ).create(
            task_id=task_id,
            fixture_id=fixture_id,
            target_id=target_id,
            resource_id=resource_id,
            baseline_manifest=baseline_manifest,
            baseline_artifact_bytes=baseline_artifact_bytes,
            authorized_artifacts=exact_authorized,
            fault_hook=fault_hook,
        )
        self._issued_sessions[id(session)] = session
        self._session_coordinators[id(session)] = action_coordinator
        return session

    def issue_deployment_observation(
        self,
        *,
        action_coordinator: object,
        session: LocalReleaseSimulatorSession,
        outcome: object,
    ) -> ReleaseDeploymentObservation:
        from graph_engineering.application.actions import ActionCoordinator, ActionOutcome
        from graph_engineering.core.actions import ActionJournalRecord

        self.require_installed_authority()
        if (
            type(action_coordinator) is not ActionCoordinator
            or type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._session_coordinators.get(id(session)) is not action_coordinator
            or type(outcome) is not ActionOutcome
        ):
            raise ReleaseOperationsError("release deployment authority is foreign")
        try:
            outcome = action_coordinator.require_issued_outcome(outcome)
        except ValueError as error:
            raise ReleaseOperationsError(
                "release deployment outcome is not coordinator-issued/current"
            ) from error
        snapshot = session._release_snapshot()
        execution = snapshot["last_execution"]
        if type(execution) is not dict:
            raise ReleaseOperationsError("release deployment has no simulator execution")
        record_action_id = outcome.action_id
        if outcome.route == "compensation-reconciled":
            if execution.get("operation_id") != self._registry.operation_roles["restore"]:
                raise ReleaseOperationsError(
                    "release compensation observation is not a restore"
                )
            record_action_id = str(execution.get("action_id"))
        record = action_coordinator._journal.load(record_action_id)
        if (
            type(record) is not ActionJournalRecord
            or record.receipt is None
            or record.authority is None
            or outcome.route not in {
                "manual-reconciliation", "reconciled-effect-verified",
                "compensation-reconciled",
            }
            or outcome.claim_id != record.receipt.get("claim_id")
            or outcome.receipt_digest != record.receipt.get("receipt_digest")
            or record.prepared.target_id != session.target.target_id
            or record.prepared.target_digest != session.target.target_digest
            or (
                outcome.route == "manual-reconciliation"
                and record.state not in {"executing", "unknown"}
            )
            or (
                outcome.route == "reconciled-effect-verified"
                and record.state != "reconciled"
            )
            or (
                outcome.route == "compensation-reconciled"
                and record.state != "reconciled"
            )
        ):
            raise ReleaseOperationsError("release deployment journal binding changed")
        payload = thaw(record.prepared.payload)
        if (
            type(payload) is not dict
            or execution.get("action_id") != record.action_id
            or execution.get("claim_id") != outcome.claim_id
            or execution.get("prepared_action_digest")
            != record.prepared.prepared_action_digest
            or execution.get("artifact_manifest_digest")
            != payload.get("artifact_manifest", {}).get("manifest_digest")
        ):
            raise ReleaseOperationsError("release deployment simulator binding changed")
        before_state = execution["before_state"]
        after_state = execution["after_state"]
        if type(before_state) is not dict or type(after_state) is not dict:
            raise ReleaseOperationsError("release deployment states are invalid")
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "action_id": record.action_id,
            "claim_id": outcome.claim_id,
            "prepared_action_digest": record.prepared.prepared_action_digest,
            "authority_digest": record.authority.authority_digest,
            "receipt_digest": outcome.receipt_digest,
            "expected_generation": execution["expected_generation"],
            "current_generation": after_state["generation"],
            "artifact_manifest_digest": execution["artifact_manifest_digest"],
            "phase_transitions": snapshot["phase_transitions"],
            "fault_point": snapshot["fault_point"],
            "reconciliation_state": outcome.route,
            "before_target_digest": _semantic(
                before_state, "release-local-target-state",
            ),
            "after_target_digest": _semantic(
                after_state, "release-local-target-state",
            ),
        }
        body["observation_digest"] = _semantic(
            body, "release-deployment-observation",
        )
        self._validate_document(
            "urn:gew:schema:release-deployment-observation:1.0.0", body,
        )
        issued = object.__new__(ReleaseDeploymentObservation)
        object.__setattr__(issued, "projection", freeze(body))
        object.__setattr__(issued, "_factory", self)
        self._issued_deployments[id(issued)] = issued
        self._deployment_sessions[id(issued)] = session
        self._deployment_outcomes[id(issued)] = outcome
        operation_id = execution["operation_id"]
        apply_id = self._registry.operation_roles["apply"]
        if operation_id == apply_id and outcome.route in {
            "reconciled-effect-verified", "manual-reconciliation",
        }:
            session._root.bind_original_action(
                claim_id=outcome.claim_id,
                receipt_digest=str(outcome.receipt_digest),
                applied_artifact_digest=str(execution["artifact_manifest_digest"]),
                before_state=before_state,
                after_state=after_state,
            )
        return issued

    def issue_health_observation(
        self,
        *,
        session: LocalReleaseSimulatorSession,
        terminal_observation: ReleaseDeploymentObservation,
    ) -> ReleaseHealthObservation:
        self.require_installed_authority()
        if (
            type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._issued_deployments.get(id(terminal_observation))
            is not terminal_observation
            or self._deployment_sessions.get(id(terminal_observation)) is not session
        ):
            raise ReleaseOperationsError("release health authority is foreign")
        terminal = terminal_observation.to_dict()
        body = session.health_observer.observe(
            expected_generation=terminal["current_generation"],
            expected_artifact_digest=terminal["artifact_manifest_digest"],
        )
        expected = body.pop("observation_digest", None)
        if (
            type(expected) is not str
            or not hmac.compare_digest(
                expected, _semantic(body, "release-health-observation")
            )
        ):
            raise ReleaseOperationsError("release health observation digest changed")
        body["observation_digest"] = expected
        self._validate_document(
            "urn:gew:schema:release-health-observation:1.0.0", body,
        )
        issued = object.__new__(ReleaseHealthObservation)
        object.__setattr__(issued, "projection", freeze(body))
        object.__setattr__(issued, "_factory", self)
        self._issued_health[id(issued)] = issued
        self._health_bindings[id(issued)] = (session, terminal_observation)
        return issued

    def issue_evidence(
        self,
        *,
        task_id: str,
        task_revision: int,
        snapshot_digest: str,
        invalidation_epoch: int,
        graph_ref_pins: Mapping[str, object],
        artifact_manifest: ReleaseArtifactManifest,
        deployment_observation: ReleaseDeploymentObservation,
        health_observation: ReleaseHealthObservation,
        rollback_observation: ReleaseDeploymentObservation | None,
        session: LocalReleaseSimulatorSession,
        owner_route: str,
        column_id: str,
        scenario_id: str,
        outcome: str,
    ) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if (
            self._issued_manifests.get(id(artifact_manifest)) is not artifact_manifest
            or self._issued_deployments.get(id(deployment_observation))
            is not deployment_observation
            or self._issued_health.get(id(health_observation)) is not health_observation
            or (
                rollback_observation is not None
                and self._issued_deployments.get(id(rollback_observation))
                is not rollback_observation
            )
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or self._deployment_sessions.get(id(deployment_observation)) is not session
            or (
                rollback_observation is not None
                and self._deployment_sessions.get(id(rollback_observation)) is not session
            )
            or self._health_bindings.get(id(health_observation))
            != (
                session,
                rollback_observation
                if rollback_observation is not None
                else deployment_observation,
            )
        ):
            raise ReleaseOperationsError("release evidence component authority is foreign")
        deployment = deployment_observation.to_dict()
        health = health_observation.to_dict()
        rollback = (
            None if rollback_observation is None else rollback_observation.to_dict()
        )
        current_target = session.observer.observe()
        scenario_matches = tuple(
            row for row in self._registry.policy["scenarios"]
            if scenario_id == (
                "GEW-PSC-RELEASE-OPERATIONS-"
                + str(row["scenario_id"]).upper()
                + "-P"
            )
        )
        if len(scenario_matches) != 1:
            raise ReleaseOperationsError(
                "release evidence scenario is not a configured positive case"
            )
        scenario = scenario_matches[0]
        partial = scenario["scenario_id"] == "partial-deploy"
        terminal = rollback if rollback is not None else deployment
        if (
            health["outcome"] != self._registry.health_outcomes["healthy"]
            or outcome != scenario["success_outcome"]
            or deployment["artifact_manifest_digest"]
            != artifact_manifest.manifest_digest
            or (
                partial
                and (
                    deployment["reconciliation_state"] != "manual-reconciliation"
                    or rollback is None
                    or rollback["reconciliation_state"]
                    != "compensation-reconciled"
                    or owner_route
                    != self._registry.policy["rollback_policy"]["owner_route"]
                )
            )
            or (
                not partial
                and (
                    deployment["reconciliation_state"]
                    != "reconciled-effect-verified"
                    or rollback is not None
                    or owner_route != deployment["reconciliation_state"]
                )
            )
        ):
            raise ReleaseOperationsError(
                "release evidence scenario/health/rollback semantics changed"
            )
        if (
            health["task_id"] != task_id
            or current_target.get("target_id") != health["target_id"]
            or current_target.get("state", {}).get("generation") != health["generation"]
            or current_target.get("state", {}).get("active_artifact_digest")
            != health["active_artifact_digest"]
            or health["active_artifact_digest"]
            != terminal["artifact_manifest_digest"]
            or _semantic(
                {
                    "schema_version": "1.0.0",
                    **current_target.get("state", {}),
                },
                "release-local-target-state",
            ) != terminal["after_target_digest"]
            or (
                rollback is not None
                and rollback["action_id"] == deployment["action_id"]
            )
        ):
            raise ReleaseOperationsError("release evidence components do not bind")
        current_target_digest = _semantic(
            current_target, "release-current-target-observation",
        )
        body: dict[str, object] = {
            "schema_version": "1.0.0",
            "evidence_kind": self._registry.policy[
                "artifact_policy"
            ]["allowed_evidence_kind"],
            "task_id": task_id,
            "task_revision": task_revision,
            "snapshot_digest": snapshot_digest,
            "invalidation_epoch": invalidation_epoch,
            "profile_id": "release-operations",
            "profile_version": "1.0.0",
            "graph_ref_pins": copy.deepcopy(dict(graph_ref_pins)),
            "installation_pins": {
                "bootstrap_id": self._bootstrap["bootstrap_id"],
                "bootstrap_digest": self._bootstrap["bootstrap_digest"],
                "policy_registry_digest": self._bootstrap["policy_registry_digest"],
                "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
                "profile_schema_registry_digest": self._bootstrap[
                    "profile_schema_registry_digest"
                ],
                "protected_closure_digest": self._bootstrap[
                    "protected_closure_digest"
                ],
            },
            "artifact_manifest": artifact_manifest.to_dict(),
            "artifact_manifest_digest": artifact_manifest.manifest_digest,
            "deployment_observation": deployment,
            "deployment_observation_digest": deployment["observation_digest"],
            "health_observation": health,
            "health_observation_digest": health["observation_digest"],
            "rollback_observation": rollback,
            "rollback_observation_digest": (
                None if rollback is None else rollback["observation_digest"]
            ),
            "current_target": current_target,
            "current_target_digest": current_target_digest,
            "claim_id": deployment["claim_id"],
            "receipt_digest": deployment["receipt_digest"],
            "owner_route": owner_route,
            "column_id": column_id,
            "scenario_id": scenario_id,
            "outcome": outcome,
        }
        for field in (
            "snapshot_digest", "artifact_manifest_digest",
            "deployment_observation_digest", "health_observation_digest",
            "current_target_digest", "receipt_digest",
        ):
            if type(body[field]) is not str or SEMANTIC_DIGEST.fullmatch(body[field]) is None:
                raise ReleaseOperationsError(f"release {field} is invalid")
        if (
            type(task_id) is not str or not task_id
            or type(task_revision) is not int or task_revision < 1
            or type(invalidation_epoch) is not int or invalidation_epoch < 0
            or type(graph_ref_pins) is not dict
            or set(graph_ref_pins) != _GRAPH_PIN_FIELDS
            or any(
                type(value) is not str or SEMANTIC_DIGEST.fullmatch(value) is None
                for value in graph_ref_pins.values()
            )
            or type(body["claim_id"]) is not str
            or not str(body["claim_id"]).startswith("claim:")
            or any(
                type(item) is not str or not item
                for item in (owner_route, column_id, scenario_id, outcome)
            )
        ):
            raise ReleaseOperationsError("release evidence binding is invalid")
        body["observation_digest"] = _semantic(body, "release-operations-observation")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", body,
        )
        binding = (session, deployment_observation, rollback_observation)
        self._require_live_projection(body, binding)
        evidence = object.__new__(ReleaseOperationsEvidence)
        object.__setattr__(evidence, "projection", freeze(body))
        object.__setattr__(evidence, "_factory", self)
        self._issued[id(evidence)] = evidence
        self._evidence_bindings[id(evidence)] = binding
        return evidence

    def _require_live_projection(
        self,
        projection: Mapping[str, object],
        binding: tuple[
            LocalReleaseSimulatorSession, ReleaseDeploymentObservation,
            ReleaseDeploymentObservation | None,
        ],
    ) -> None:
        """Revalidate process-local authority without replaying an action."""

        from graph_engineering.application.actions import ActionCoordinator
        from graph_engineering.core.actions import ActionJournalRecord

        session, deployment, rollback = binding
        coordinator = self._session_coordinators.get(id(session))
        observations = (deployment,) if rollback is None else (deployment, rollback)
        if (
            type(session) is not LocalReleaseSimulatorSession
            or self._issued_sessions.get(id(session)) is not session
            or session._factory is not self
            or type(coordinator) is not ActionCoordinator
            or any(
                self._issued_deployments.get(id(item)) is not item
                or self._deployment_sessions.get(id(item)) is not session
                for item in observations
            )
        ):
            raise ReleaseOperationsError("release live authority is missing or foreign")
        terminal = rollback if rollback is not None else deployment
        try:
            # A compensated manual observation is history, not a live outcome.
            coordinator.require_issued_outcome(self._deployment_outcomes.get(id(terminal)))
            for item in observations:
                value = item.to_dict()
                record = coordinator._journal.load(value["action_id"])
                expected_state = (
                    "compensated" if item is deployment and rollback is not None
                    else "reconciled"
                )
                if (
                    type(record) is not ActionJournalRecord
                    or record.state != expected_state
                    or record.authority is None
                    or record.receipt is None
                    or record.prepared.prepared_action_digest != value["prepared_action_digest"]
                    or record.authority.authority_digest != value["authority_digest"]
                    or record.receipt.get("receipt_digest") != value["receipt_digest"]
                    or record.receipt.get("claim_id") != value["claim_id"]
                    or record.prepared.target_id != session.target.target_id
                    or record.prepared.target_digest != session.target.target_digest
                ):
                    raise ReleaseOperationsError("release live journal/receipt changed")
            terminal_body = terminal.to_dict()
            health = session.health_observer.observe(
                expected_generation=terminal_body["current_generation"],
                expected_artifact_digest=terminal_body["artifact_manifest_digest"],
            )
            current = session.observer.observe()
        except (ValueError, OSError) as error:
            raise ReleaseOperationsError("release live authority is no longer current") from error
        previous = projection["current_target"]
        if (
            health != projection["health_observation"]
            or {key: value for key, value in current.items() if key != "observation_revision"}
            != {key: value for key, value in previous.items() if key != "observation_revision"}
            or current["observation_revision"] <= previous["observation_revision"]
        ):
            raise ReleaseOperationsError("release live target/health changed")

    def require_current(self, evidence: object) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if (
            type(evidence) is not ReleaseOperationsEvidence
            or evidence._factory is not self
            or self._issued.get(id(evidence)) is not evidence
        ):
            raise ReleaseOperationsError("release evidence is missing, cloned, or foreign")
        projection = evidence.to_dict()
        if set(projection) != set(_PROJECTION_FIELDS):
            raise ReleaseOperationsError("release evidence projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", projection,
        )
        expected = projection.pop("observation_digest")
        self._require_nested_projection(projection)
        if not hmac.compare_digest(
            str(expected), _semantic(projection, "release-operations-observation")
        ):
            raise ReleaseOperationsError("release evidence changed")
        binding = self._evidence_bindings.get(id(evidence))
        if binding is None:
            raise ReleaseOperationsError("release evidence has no live authority binding")
        self._require_live_projection(projection, binding)
        return evidence

    def _require_nested_projection(self, projection: Mapping[str, object]) -> None:
        manifest = ReleaseArtifactManifest.from_dict(projection["artifact_manifest"])
        deployment = projection["deployment_observation"]
        health = projection["health_observation"]
        rollback = projection["rollback_observation"]
        current_target = projection["current_target"]
        if any(type(value) is not dict for value in (deployment, health, current_target)):
            raise ReleaseOperationsError("release nested projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-artifact-manifest:1.0.0",
            projection["artifact_manifest"],
        )
        self._validate_document(
            "urn:gew:schema:release-deployment-observation:1.0.0", deployment,
        )
        self._validate_document(
            "urn:gew:schema:release-health-observation:1.0.0", health,
        )
        for value, name, digest_field in (
            (deployment, "release-deployment-observation", "deployment_observation_digest"),
            (health, "release-health-observation", "health_observation_digest"),
            (current_target, "release-current-target-observation", "current_target_digest"),
        ):
            body = copy.deepcopy(value)
            embedded = body.pop("observation_digest", None) if name != "release-current-target-observation" else None
            calculated = _semantic(body if embedded is not None else value, name)
            expected = projection[digest_field]
            if embedded is not None and embedded != expected:
                raise ReleaseOperationsError("release nested observation binding changed")
            if not hmac.compare_digest(str(expected), calculated):
                raise ReleaseOperationsError("release nested observation digest changed")
        if manifest.manifest_digest != projection["artifact_manifest_digest"]:
            raise ReleaseOperationsError("release nested manifest digest changed")
        if rollback is None:
            if projection["rollback_observation_digest"] is not None:
                raise ReleaseOperationsError("release rollback absence changed")
        else:
            if type(rollback) is not dict:
                raise ReleaseOperationsError("release rollback projection is not exact")
            self._validate_document(
                "urn:gew:schema:release-deployment-observation:1.0.0", rollback,
            )
            body = copy.deepcopy(rollback)
            embedded = body.pop("observation_digest", None)
            expected = projection["rollback_observation_digest"]
            if (
                embedded != expected
                or type(expected) is not str
                or not hmac.compare_digest(
                    expected, _semantic(body, "release-deployment-observation")
                )
            ):
                raise ReleaseOperationsError("release rollback observation changed")

    def projection(self, evidence: object) -> FrozenMap:
        return self.require_current(evidence).projection

    def restore_projection(self, projection: Mapping[str, object]) -> ReleaseOperationsEvidence:
        self.require_installed_authority()
        if type(projection) is not dict or set(projection) != set(_PROJECTION_FIELDS):
            raise ReleaseOperationsError("stored release projection is not exact")
        self._validate_document(
            "urn:gew:schema:release-operations-observation:1.0.0", projection,
        )
        body = copy.deepcopy(dict(projection))
        expected = body.pop("observation_digest", None)
        if (
            type(expected) is not str
            or not hmac.compare_digest(
                expected, _semantic(body, "release-operations-observation")
            )
        ):
            raise ReleaseOperationsError("stored release projection changed")
        self._require_nested_projection(body)
        expected_installation = {
            "bootstrap_id": self._bootstrap["bootstrap_id"],
            "bootstrap_digest": self._bootstrap["bootstrap_digest"],
            "policy_registry_digest": self._bootstrap["policy_registry_digest"],
            "fixture_registry_digest": self._bootstrap["fixture_registry_digest"],
            "profile_schema_registry_digest": self._bootstrap[
                "profile_schema_registry_digest"
            ],
            "protected_closure_digest": self._bootstrap[
                "protected_closure_digest"
            ],
        }
        if body.get("installation_pins") != expected_installation:
            raise ReleaseOperationsError("stored release installation pins changed")
        raise ReleaseOperationsError(
            "stored release projection requires live target/journal revalidation"
        )
