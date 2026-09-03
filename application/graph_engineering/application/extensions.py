"""Live-session-only application ingress for extension installation."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from graph_engineering.core.extension_bundle import (
    ExtensionAttestationProductionPolicy,
    ExtensionInstallRequest,
)
from graph_engineering.core.extensions import Ed25519Verifier
from graph_engineering.core.extension_activation import (
    ExtensionActivationRequest,
    ExtensionActiveSetRequest,
    ExtensionTaskPinRequest,
)
from graph_engineering.core.security.extensions import (
    ExtensionPublisherRevocationStatement,
    ExtensionTrustOperation,
)

from graph_engineering.application.runtime import (
    RuntimeMutationGateway,
    RuntimeSession,
    RuntimeSessionProof,
)
from graph_engineering.application.tasks import RuntimeContext


class ExtensionInstallerPort(Protocol):
    def install(self, request: ExtensionInstallRequest, runtime: RuntimeContext) -> object: ...


class ExtensionInstallationApplication:
    """Dispatch installation only during one live owner runtime callback."""

    __slots__ = ("_installer",)

    def __init__(self, installer: ExtensionInstallerPort) -> None:
        require_attested = getattr(type(installer), "require_attested", None)
        if (
            not callable(getattr(installer, "install", None))
            or not callable(require_attested)
            or require_attested(installer) is not installer
        ):
            raise TypeError("extension installer port is invalid")
        self._installer = installer

    def install(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        request: ExtensionInstallRequest,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        if type(session) is not RuntimeSession or type(proof) is not RuntimeSessionProof:
            raise TypeError("extension installation requires an exact runtime session proof")
        session.require_current(proof)
        if "extension.install" not in session.capabilities.capabilities:
            raise ValueError("extension installation is unavailable")
        if type(request) is not ExtensionInstallRequest:
            raise TypeError("extension install request is missing or forged")
        request_body = request.to_dict()
        if (
            request_body["owner_id"] != proof.owner_id
            or request_body["runtime_kind"] != session.capabilities.runtime_kind
            or request_body["runtime_lineage_id"] != proof.lineage_id
        ):
            raise ValueError("extension installation is unavailable")
        return RuntimeMutationGateway.invoke(
            session,
            proof,
            lambda runtime: self._install_issued(request, runtime),
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )

    def _install_issued(self, request: ExtensionInstallRequest, runtime: RuntimeContext) -> object:
        runtime.require_issued()
        return self._installer.install(request, runtime)


class ExtensionManagementPort(Protocol):
    def activate(self, request: ExtensionActivationRequest, runtime: RuntimeContext) -> object: ...
    def transition_active_set(
        self, request: ExtensionActiveSetRequest, runtime: RuntimeContext
    ) -> object: ...
    def pin_task(self, request: ExtensionTaskPinRequest, runtime: RuntimeContext) -> object: ...


class ExtensionManagementApplication:
    """Live-session-only local data activation and task pin ingress."""

    __slots__ = ("_repository",)

    def __init__(self, repository: ExtensionManagementPort) -> None:
        require_attested = getattr(type(repository), "require_attested", None)
        if not callable(require_attested) or require_attested(repository) is not repository:
            raise TypeError("extension management port is invalid")
        self._repository = repository

    @staticmethod
    def _require(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        request: object,
        capability: str,
    ) -> None:
        if type(session) is not RuntimeSession or type(proof) is not RuntimeSessionProof:
            raise TypeError("extension management requires an exact runtime session proof")
        session.require_current(proof)
        if capability not in session.capabilities.capabilities:
            raise ValueError("extension management is unavailable")
        body = request.to_dict()  # type: ignore[attr-defined]
        if (
            body.get("owner_id") != proof.owner_id
            or body.get("runtime_kind") != session.capabilities.runtime_kind
            or body.get("runtime_lineage_id") != proof.lineage_id
        ):
            raise ValueError("extension management is unavailable")

    def activate(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        request: ExtensionActivationRequest,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        if type(request) is not ExtensionActivationRequest:
            raise TypeError("extension activation request is missing or forged")
        self._require(session, proof, request, "extension.activate")
        return RuntimeMutationGateway.invoke(
            session, proof, lambda runtime: self._repository.activate(request, runtime),
            occurred_at=occurred_at, lease_ttl_ns=lease_ttl_ns,
        )

    def pin_task(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        request: ExtensionTaskPinRequest,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        if type(request) is not ExtensionTaskPinRequest:
            raise TypeError("extension task pin request is missing or forged")
        self._require(session, proof, request, "extension.pin-task")
        return RuntimeMutationGateway.invoke(
            session, proof, lambda runtime: self._repository.pin_task(request, runtime),
            occurred_at=occurred_at, lease_ttl_ns=lease_ttl_ns,
        )

    def transition_active_set(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        request: ExtensionActiveSetRequest,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        if type(request) is not ExtensionActiveSetRequest:
            raise TypeError("extension active-set request is missing or forged")
        self._require(session, proof, request, "extension.activate")
        return RuntimeMutationGateway.invoke(
            session,
            proof,
            lambda runtime: self._repository.transition_active_set(request, runtime),
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )


class ExtensionTrustApplication:
    """The sole live-session mutation ingress for installation trust state."""

    __slots__ = ("_repository", "_verifier")

    def __init__(self, repository: object, verifier: Ed25519Verifier) -> None:
        require_repository = getattr(type(repository), "require_attested", None)
        require_verifier = getattr(type(verifier), "require_attested", None)
        if (
            not callable(require_repository)
            or require_repository(repository) is not repository
            or not callable(require_verifier)
            or require_verifier(verifier) is not verifier
        ):
            raise TypeError("extension trust application dependencies are not factory-issued")
        self._repository = repository
        self._verifier = verifier

    @staticmethod
    def _require(
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        authorization: object,
    ) -> Mapping[str, object]:
        if type(session) is not RuntimeSession or type(proof) is not RuntimeSessionProof:
            raise TypeError("extension trust mutation requires an exact runtime session proof")
        session.require_current(proof)
        if "extension.trust" not in session.capabilities.capabilities:
            raise ValueError("extension trust mutation is unavailable")
        if not isinstance(authorization, Mapping):
            raise TypeError("extension trust Owner authorization is invalid")
        if authorization.get("owner_identity") != proof.owner_id:
            raise ValueError("extension trust mutation is unavailable")
        return authorization

    def commit(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        operations: tuple[ExtensionTrustOperation, ...],
        authorization: object,
        *,
        production_policy: ExtensionAttestationProductionPolicy | None = None,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        self._require(session, proof, authorization)
        if not operations or any(type(item) is not ExtensionTrustOperation for item in operations):
            raise TypeError("extension trust operations are invalid")
        return RuntimeMutationGateway.invoke(
            session,
            proof,
            lambda runtime: self._repository._commit_operations_issued(  # type: ignore[attr-defined]
                operations, authorization=authorization, runtime=runtime,
                production_policy=production_policy, verifier=self._verifier,
            ),
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )

    def rollback(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        operations: tuple[ExtensionTrustOperation, ...],
        *,
        rollback_of_record_digest: str,
        restore_content_from_policy_digest: str,
        authorization: object,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        self._require(session, proof, authorization)
        return RuntimeMutationGateway.invoke(
            session,
            proof,
            lambda runtime: self._repository._rollback_operations_issued(  # type: ignore[attr-defined]
                operations,
                rollback_of_record_digest=rollback_of_record_digest,
                restore_content_from_policy_digest=restore_content_from_policy_digest,
                authorization=authorization,
                runtime=runtime,
            ),
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )

    def abort(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        *,
        operations: tuple[ExtensionTrustOperation, ...],
        authorization: object,
        reason_code: str,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        document = self._require(session, proof, authorization)
        return RuntimeMutationGateway.invoke(
            session,
            proof,
            lambda runtime: self._repository._abort_issued(  # type: ignore[attr-defined]
                operations=operations,
                authorization=document,
                reason_code=reason_code,
                runtime=runtime,
            ),
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )

    def apply_publisher_revocation(
        self,
        session: RuntimeSession,
        proof: RuntimeSessionProof,
        statement: ExtensionPublisherRevocationStatement,
        operation: ExtensionTrustOperation,
        authorization: object,
        *,
        occurred_at: str,
        lease_ttl_ns: int,
    ) -> object:
        self._require(session, proof, authorization)
        if (
            type(statement) is not ExtensionPublisherRevocationStatement
            or type(operation) is not ExtensionTrustOperation
        ):
            raise TypeError("publisher revocation inputs are invalid")

        def apply(runtime: RuntimeContext) -> object:
            verified = self._repository.verify_publisher_revocation(  # type: ignore[attr-defined]
                statement, self._verifier, observed_at=runtime.occurred_at
            )
            return self._repository._apply_publisher_revocation_issued(  # type: ignore[attr-defined]
                verified, operation=operation, authorization=authorization, runtime=runtime
            )

        return RuntimeMutationGateway.invoke(
            session,
            proof,
            apply,
            occurred_at=occurred_at,
            lease_ttl_ns=lease_ttl_ns,
        )
