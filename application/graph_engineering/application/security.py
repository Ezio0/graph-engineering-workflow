"""Application-owned issuance from current durable security state."""

from __future__ import annotations

from dataclasses import dataclass

from graph_engineering.core.contracts.digest import semantic_digest_charged
from graph_engineering.core.contracts.immutable import FrozenMap, thaw
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry
from graph_engineering.core.contracts.resources import WorkContext
from graph_engineering.core.security._common import (
    IDENTITY_PROJECTION,
    parse_timestamp,
    require_digest,
    require_id,
)
from graph_engineering.core.security.attestation import (
    DisclosureJournalAttestation,
    SecurityAttestationError,
    SecurityRuntimeManifest,
    TASK_CONTEXT_SCHEMA,
    TaskSecurityContext,
    _canonical_frozen_map,
    validate_installed_runtime_document,
)
from graph_engineering.core.security.identity import SecurityBinding
from graph_engineering.core.security.retention import RetentionDecision
from graph_engineering.storage.security import SecurityStateRepository


class SecurityIssuanceError(ValueError):
    """A durable security attestation cannot be issued."""


@dataclass(frozen=True, slots=True, init=False)
class ReadOnlyTaskSecurityProjection:
    """Validated data only; consumers must reread to establish currentness."""

    state: FrozenMap
    state_digest: str
    runtime_manifest_digest: str

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("read-only security facts come from a fresh durable read")


@dataclass(frozen=True, slots=True, init=False)
class PurgeAuthorization:
    """Audit receipt for an already consumed one-use purge fence."""

    authorization_id: str
    task_id: str
    subject_ref: str
    subject_snapshot_digest: str
    security_state_digest: str
    decision_digest: str
    consumed_at_ns: int

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("purge authorizations are issued only by durable security state")


class SecurityContextIssuer:
    """The only production path from durable rows to opaque core attestations."""

    def __init__(
        self,
        repository: SecurityStateRepository,
        *,
        schema_registry: ClosedSchemaRegistry,
        context: WorkContext,
    ) -> None:
        if (
            type(repository) is not SecurityStateRepository
            or type(schema_registry) is not ClosedSchemaRegistry
            or type(context) is not WorkContext
        ):
            raise SecurityIssuanceError("security issuer requires exact durable dependencies")
        self._repository = repository
        self._schemas = schema_registry
        self._context = context
        installed = repository.load_installed_runtime(context)
        fields = validate_installed_runtime_document(
            installed.manifest,
            expected_manifest_id=installed.manifest_id,
            expected_manifest_digest=installed.manifest_digest,
            schema_registry=schema_registry,
            context=context,
        )
        runtime = object.__new__(SecurityRuntimeManifest)
        for name in (
            "manifest_id",
            "manifest_digest",
            "schema_registry_id",
            "schema_registry_digest",
            "allowed_runtime_kinds",
            "policies",
        ):
            object.__setattr__(runtime, name, fields[name])
        object.__setattr__(runtime, "_issuer", object())
        self._runtime = runtime

    @property
    def runtime(self) -> SecurityRuntimeManifest:
        return self._runtime

    def read_task_state(self, task_id: str) -> ReadOnlyTaskSecurityProjection:
        """Validate current facts without issuing a clock-bearing capability."""

        installed = self._repository.load_installed_runtime(self._context)
        fields = validate_installed_runtime_document(
            installed.manifest,
            expected_manifest_id=installed.manifest_id,
            expected_manifest_digest=installed.manifest_digest,
            schema_registry=self._schemas,
            context=self._context,
        )
        if any(fields[name] != getattr(self._runtime, name) for name in (
            "manifest_id", "manifest_digest", "schema_registry_id",
            "schema_registry_digest", "allowed_runtime_kinds", "policies",
        )):
            raise SecurityIssuanceError("installed security runtime changed")
        record = self._repository.load_current_task_state_readonly(task_id, self._context)
        state = thaw(record.state)
        assert type(state) is dict
        try:
            binding = state["binding"]
            if type(binding) is not dict:
                raise ValueError("security binding is not an object")
            # Validate with the existing parser, but never expose its attestation.
            SecurityBinding._from_attested_dict(
                binding, runtime=self._runtime, schema_registry=self._schemas,
                context=self._context, issuer=self._runtime._issuer,
            )
            for name in ("destinations", "data_refs", "evidence_expectations", "retention_subjects"):
                _canonical_frozen_map(state[name], name)
            require_digest(record.state_digest, "task security state digest")
        except (KeyError, TypeError, ValueError, SecurityAttestationError) as error:
            raise SecurityIssuanceError(str(error)) from error
        result = object.__new__(ReadOnlyTaskSecurityProjection)
        object.__setattr__(result, "state", record.state)
        object.__setattr__(result, "state_digest", record.state_digest)
        object.__setattr__(result, "runtime_manifest_digest", self._runtime.manifest_digest)
        return result

    def issue_task_context(self, task_id: str) -> TaskSecurityContext:
        """Issue from a current task row plus repository-owned high-water clock."""

        record = self._repository.load_current_task_state(task_id, self._context)
        state = record.state
        try:
            parse_timestamp(record.current_time, "task security clock")
            authorities_value = state["authority_digests"]
            if type(authorities_value) is not list:
                raise ValueError("authority digest set is invalid")
            authorities = tuple(authorities_value)
            if authorities != tuple(sorted(set(authorities))):
                raise ValueError("authority digest set is not canonical")
            for item in authorities:
                require_digest(item, "authority digest")
            binding_value = state["binding"]
            if not isinstance(binding_value, dict):
                raise ValueError("security binding is not an object")
            binding = SecurityBinding._from_attested_dict(
                binding_value,
                runtime=self._runtime,
                schema_registry=self._schemas,
                context=self._context,
                issuer=self._runtime._issuer,
            )
            destinations = state["destinations"]
            data_refs = state["data_refs"]
            evidence = state["evidence_expectations"]
            retention = state["retention_subjects"]
            if not all(isinstance(item, dict) for item in (destinations, data_refs, evidence, retention)):
                raise ValueError("durable task security registries are invalid")
            frozen_destinations = _canonical_frozen_map(destinations, "destination registry")
            frozen_data_refs = _canonical_frozen_map(data_refs, "data ref registry")
            frozen_evidence = _canonical_frozen_map(evidence, "evidence registry")
            frozen_retention = _canonical_frozen_map(retention, "retention subject registry")
            require_digest(record.state_digest, "task security state digest")
            unsigned: dict[str, object] = {
                "schema_version": "1.0.0",
                "runtime_manifest_digest": self._runtime.manifest_digest,
                "binding_digest": binding.binding_digest,
                "security_state_digest": record.state_digest,
                "current_time": record.current_time,
                "destinations": frozen_destinations,
                "authority_digests": list(authorities),
                "data_refs": frozen_data_refs,
                "evidence_expectations": frozen_evidence,
                "retention_subjects": frozen_retention,
            }
            context_digest = semantic_digest_charged(
                unsigned,
                self._context,
                contract_type="urn:gew:contract:task-security-context",
                projection_id=IDENTITY_PROJECTION,
                schema_id=TASK_CONTEXT_SCHEMA,
                operation_path=self._context.child_path(()),
            )
        except (KeyError, TypeError, ValueError, SecurityAttestationError) as error:
            raise SecurityIssuanceError(str(error)) from error
        result = object.__new__(TaskSecurityContext)
        for name, item in (
            ("runtime_manifest_digest", self._runtime.manifest_digest),
            ("binding", binding),
            ("current_time", record.current_time),
            ("destinations", frozen_destinations),
            ("authority_digests", authorities),
            ("data_refs", frozen_data_refs),
            ("evidence_expectations", frozen_evidence),
            ("retention_subjects", frozen_retention),
            ("state_digest", record.state_digest),
            ("context_digest", context_digest),
            ("_issuer", self._runtime._issuer),
        ):
            object.__setattr__(result, name, item)
        return result

    def issue_disclosure_attestation(
        self,
        receipt_id: str,
    ) -> DisclosureJournalAttestation:
        """Issue only for one delivered/reconciled durable action-journal row."""

        record = self._repository.load_disclosure_journal(receipt_id, self._context)
        entry = record.entry
        try:
            receipt = entry["receipt"]
            if not isinstance(receipt, dict):
                raise ValueError("durable disclosure receipt is not an object")
            frozen = _canonical_frozen_map(receipt, "disclosure journal receipt")
            task_id = require_id(entry.get("task_id"), "disclosure task ID")
            action_id = require_id(entry.get("action_id"), "disclosure action ID")
            prepared = require_digest(
                entry.get("prepared_action_digest"),
                "prepared action digest",
            )
            snapshot = require_digest(
                entry.get("task_snapshot_digest"),
                "disclosure task snapshot digest",
            )
            reconciliation = require_digest(
                entry.get("reconciliation_digest"),
                "disclosure reconciliation digest",
            )
            journal_digest = require_digest(record.entry_digest, "disclosure journal digest")
            attestation_digest = semantic_digest_charged(
                {
                    "journal_entry_digest": journal_digest,
                    "receipt": frozen,
                },
                self._context,
                contract_type="urn:gew:contract:disclosure-journal-attestation",
                projection_id=IDENTITY_PROJECTION,
                schema_id="urn:gew:schema:disclosure-journal-attestation:1.0.0",
                operation_path=self._context.child_path(()),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise SecurityIssuanceError(str(error)) from error
        result = object.__new__(DisclosureJournalAttestation)
        for name, item in (
            ("runtime_manifest_digest", self._runtime.manifest_digest),
            ("task_id", task_id),
            ("action_id", action_id),
            ("prepared_action_digest", prepared),
            ("task_snapshot_digest", snapshot),
            ("reconciliation_digest", reconciliation),
            ("journal_entry_digest", journal_digest),
            ("receipt", frozen),
            ("receipt_digest", attestation_digest),
            ("_issuer", self._runtime._issuer),
        ):
            object.__setattr__(result, name, item)
        return result

    def authorize_purge(
        self,
        task_id: str,
        decision: RetentionDecision,
    ) -> PurgeAuthorization:
        """Transactionally revalidate and consume an engine-issued purge decision."""

        record = self._repository.authorize_purge(task_id, decision, self._context)
        result = object.__new__(PurgeAuthorization)
        for name in (
            "authorization_id",
            "task_id",
            "subject_ref",
            "subject_snapshot_digest",
            "security_state_digest",
            "decision_digest",
            "consumed_at_ns",
        ):
            object.__setattr__(result, name, getattr(record, name))
        return result
