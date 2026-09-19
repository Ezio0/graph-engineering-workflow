"""Installation-authorized source checkout attestation issuance."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import stat
import tempfile

from graph_engineering.core.actions import (
    ActionAdapterInstallationAttestation,
    ActionPolicy,
)


LOCK_FILENAME = "installation-maintenance.lock"
KEY_FILENAME = "source-checkout-attestation-v1.key"
ATTESTATION_FILENAME = "source-checkout-attestation-v1.json"
SOURCE_FILES = (
    "adapters/graph_engineering/adapters/__init__.py",
    "adapters/graph_engineering/adapters/action_adapters.py",
    "adapters/graph_engineering/adapters/command_native.py",
    "adapters/graph_engineering/adapters/connector_unavailable.py",
    "adapters/graph_engineering/adapters/git_native.py",
    "adapters/graph_engineering/adapters/local_release_simulator.py",
    "application/graph_engineering/application/actions.py",
    "application/graph_engineering/application/dependency_security.py",
    "application/graph_engineering/application/profile_coverage.py",
    "application/graph_engineering/application/profile_coverage_oracle.py",
    "application/graph_engineering/application/profile_execution.py",
    "application/graph_engineering/application/profile_real_e2e.py",
    "application/graph_engineering/application/profile_real_e2e_verifier.py",
    "application/graph_engineering/application/release_operations.py",
    "config/actions/concrete-action-policy-v1.json",
    "config/contracts/action-adapter-registry-v1.json",
    "config/contracts/action-adapter-schema-registry-v1.json",
    "config/contracts/profile-schema-registry-v1.json",
    "config/contracts/schemas/category-completion-assessment-1.4.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.4.0.json",
    "config/contracts/schemas/category-execution-policy-1.0.0.json",
    "config/contracts/schemas/category-execution-policy-input-1.0.0.json",
    "config/contracts/schemas/coverage-record-1.0.0.json",
    "config/contracts/schemas/coverage-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-record-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-registry-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-source-record-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-source-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-status-high-water-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-status-high-water-input-1.0.0.json",
    "config/contracts/schemas/dependency-applicability-observation-1.0.0.json",
    "config/contracts/schemas/dependency-applicability-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-input-1.0.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-input-1.0.0.json",
    "config/contracts/schemas/profile-coverage-assessment-reference-1.0.0.json",
    "config/contracts/schemas/profile-coverage-execution-plan-input-1.0.0.json",
    "config/contracts/schemas/profile-coverage-execution-record-1.0.0.json",
    "config/contracts/schemas/profile-coverage-observation-1.0.0.json",
    "config/contracts/schemas/profile-coverage-oracle-input-1.0.0.json",
    "config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json",
    "config/contracts/schemas/profile-coverage-plan-selector-1.0.0.json",
    "config/contracts/schemas/profile-coverage-request-1.0.0.json",
    "config/contracts/schemas/profile-coverage-task-state-1.0.0.json",
    "config/contracts/schemas/profile-real-e2e-binding-registry-input-1.0.0.json",
    "config/contracts/schemas/profile-real-e2e-predecessor-record-1.0.0.json",
    "config/contracts/schemas/release-artifact-manifest-1.0.0.json",
    "config/contracts/schemas/release-artifact-manifest-input-1.0.0.json",
    "config/contracts/schemas/release-coverage-assessment-1.0.0.json",
    "config/contracts/schemas/release-deployment-observation-1.0.0.json",
    "config/contracts/schemas/release-deployment-observation-input-1.0.0.json",
    "config/contracts/schemas/release-health-observation-1.0.0.json",
    "config/contracts/schemas/release-health-observation-input-1.0.0.json",
    "config/contracts/schemas/release-operations-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/release-operations-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/release-operations-observation-1.0.0.json",
    "config/contracts/schemas/release-operations-observation-input-1.0.0.json",
    "config/contracts/schemas/release-operations-policy-registry-1.0.0.json",
    "config/contracts/schemas/release-operations-policy-registry-input-1.0.0.json",
    "config/contracts/schemas/release-simulator-fixture-registry-1.0.0.json",
    "config/contracts/schemas/release-simulator-fixture-registry-input-1.0.0.json",
    "config/profiles/category-execution-policy-registry-v1.json",
    "config/profiles/category-execution-policy-v1.json",
    "config/profiles/profile-coverage-execution-plan-v1.json",
    "config/profiles/profile-real-e2e-binding-registry-v1.json",
    "config/release-operations/release-operations-installation-bootstrap-v1.json",
    "config/release-operations/release-operations-policy-registry-v1.json",
    "config/release-operations/release-simulator-fixture-registry-v1.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.json",
    "config/security/dependency-advisory-registry-v1.json",
    "config/security/security-runtime-local-actions-v1.json",
    "config/supply-chain/extension-package-parser-requirement-v1.json",
    "config/test-oracles/profile-dependency-security-artifacts-v1.json",
    "config/test-oracles/profile-dependency-security-authority-v1.json",
    "config/test-oracles/profile-dependency-security-boundary-v1.json",
    "config/test-oracles/profile-dependency-security-drift-v1.json",
    "config/test-oracles/profile-dependency-security-invalidation-v1.json",
    "config/test-oracles/profile-dependency-security-normal-v1.json",
    "config/test-oracles/profile-dependency-security-real-e2e-v1.json",
    "config/test-oracles/profile-dependency-security-recovery-v1.json",
    "config/test-oracles/profile-dependency-security-review-v1.json",
    "config/test-oracles/profile-dependency-security-revise-v1.json",
    "config/test-oracles/profile-dependency-security-rollback-v1.json",
    "config/test-oracles/profile-dependency-security-target-v1.json",
    "config/test-oracles/profile-new-feature-artifacts-v1.json",
    "config/test-oracles/profile-new-feature-authority-v1.json",
    "config/test-oracles/profile-new-feature-boundary-v1.json",
    "config/test-oracles/profile-new-feature-drift-v1.json",
    "config/test-oracles/profile-new-feature-invalidation-v1.json",
    "config/test-oracles/profile-new-feature-normal-v1.json",
    "config/test-oracles/profile-new-feature-real-e2e-v1.json",
    "config/test-oracles/profile-new-feature-recovery-v1.json",
    "config/test-oracles/profile-new-feature-review-v1.json",
    "config/test-oracles/profile-new-feature-revise-v1.json",
    "config/test-oracles/profile-new-feature-rollback-v1.json",
    "config/test-oracles/profile-new-feature-scaffold-v1.json",
    "config/test-oracles/profile-new-feature-target-v1.json",
    "config/test-oracles/profile-refactor-debt-artifacts-v1.json",
    "config/test-oracles/profile-refactor-debt-authority-v1.json",
    "config/test-oracles/profile-refactor-debt-boundary-v1.json",
    "config/test-oracles/profile-refactor-debt-drift-v1.json",
    "config/test-oracles/profile-refactor-debt-invalidation-v1.json",
    "config/test-oracles/profile-refactor-debt-normal-v1.json",
    "config/test-oracles/profile-refactor-debt-real-e2e-v1.json",
    "config/test-oracles/profile-refactor-debt-recovery-v1.json",
    "config/test-oracles/profile-refactor-debt-review-v1.json",
    "config/test-oracles/profile-refactor-debt-revise-v1.json",
    "config/test-oracles/profile-refactor-debt-rollback-v1.json",
    "config/test-oracles/profile-refactor-debt-target-v1.json",
    "core/graph_engineering/__init__.py",
    "core/graph_engineering/core/contracts/schema.py",
    "core/graph_engineering/core/dependency_security.py",
    "core/graph_engineering/core/profile_coverage.py",
    "core/graph_engineering/core/profile_execution.py",
    "core/graph_engineering/core/profiles.py",
    "core/graph_engineering/core/release_operations.py",
    "core/graph_engineering/core/source_checkout.py",
    "pyproject.toml",
    "scripts/build_backend.py",
    "storage/graph_engineering/storage/repository.py",
)


class SourceCheckoutAuthorityError(RuntimeError):
    """Installation authority could not attest the requested checkout."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _regular_bytes(path: pathlib.Path, owner: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
        ):
            raise SourceCheckoutAuthorityError("source checkout file is unsafe")
        body = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or len(body) != before.st_size
        ):
            raise SourceCheckoutAuthorityError("source checkout file changed")
        return bytes(body)
    finally:
        os.close(descriptor)


def _control_file(path: pathlib.Path, *, create: bool) -> int:
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    if create:
        flags |= os.O_CREAT
    descriptor = os.open(path, flags, 0o600)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
    ):
        os.close(descriptor)
        raise SourceCheckoutAuthorityError("installation control file is unsafe")
    return descriptor


def issue_source_checkout_attestation(
    source_root: pathlib.Path,
    control_root: pathlib.Path,
    *,
    authority: ActionAdapterInstallationAttestation,
) -> pathlib.Path:
    """Issue one checkout proof while holding the stable installation lock."""

    if (
        type(authority) is not ActionAdapterInstallationAttestation
        or type(authority._issuer) is not ActionPolicy
    ):
        raise SourceCheckoutAuthorityError(
            "source checkout attestation requires installation security authority"
        )
    source_root = source_root.resolve(strict=True)
    control_root = control_root.resolve(strict=True)
    source_metadata = os.lstat(source_root)
    control_metadata = os.lstat(control_root)
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or source_metadata.st_uid != os.getuid()
        or stat.S_IMODE(source_metadata.st_mode) & 0o022
        or not stat.S_ISDIR(control_metadata.st_mode)
        or stat.S_ISLNK(control_metadata.st_mode)
        or control_metadata.st_uid != source_metadata.st_uid
        or stat.S_IMODE(control_metadata.st_mode) != 0o700
    ):
        raise SourceCheckoutAuthorityError("source or installation control root is unsafe")
    lock_descriptor = _control_file(control_root / LOCK_FILENAME, create=False)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        key_path = control_root / KEY_FILENAME
        try:
            key_descriptor = _control_file(key_path, create=False)
        except FileNotFoundError:
            key_descriptor = os.open(
                key_path,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                os.write(key_descriptor, secrets.token_bytes(32))
                os.fsync(key_descriptor)
            finally:
                os.close(key_descriptor)
            key_descriptor = _control_file(key_path, create=False)
        try:
            key = os.read(key_descriptor, 64)
            if len(key) != 32 or os.read(key_descriptor, 1):
                raise SourceCheckoutAuthorityError("installation attestation key is invalid")
        finally:
            os.close(key_descriptor)
        file_digests: dict[str, str] = {}
        file_sizes: dict[str, int] = {}
        for relative in SOURCE_FILES:
            body = _regular_bytes(source_root / relative, source_metadata.st_uid)
            file_digests[relative] = hashlib.sha256(body).hexdigest()
            file_sizes[relative] = len(body)
        body = {
            "schema_version": "1.0.0",
            "attestation_id": "source-checkout-attestation-v1",
            "installation_id": "installation-control-sha256:"
            + hashlib.sha256(
                (
                    f"{control_metadata.st_dev}:{control_metadata.st_ino}:"
                    f"{control_metadata.st_uid}"
                ).encode()
            ).hexdigest(),
            "source_root": os.fspath(source_root),
            "source_root_device": source_metadata.st_dev,
            "source_root_inode": source_metadata.st_ino,
            "source_root_owner": source_metadata.st_uid,
            "source_root_mode": stat.S_IMODE(source_metadata.st_mode),
            "runtime_manifest_digest": authority.runtime_manifest_digest,
            "concrete_policy_id": authority.concrete_policy_id,
            "concrete_policy_digest": authority.concrete_policy_digest,
            "registry_id": authority.registry_id,
            "registry_digest": authority.registry_digest,
            "schema_registry_id": authority.schema_registry_id,
            "schema_registry_digest": authority.schema_registry_digest,
            "file_digests": file_digests,
            "file_sizes": file_sizes,
        }
        document = dict(body)
        document["attestation_hmac_sha256"] = hmac.new(
            key,
            _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".source-checkout-attestation-",
            dir=control_root,
        )
        temporary = pathlib.Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, _canonical(document) + b"\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        destination = control_root / ATTESTATION_FILENAME
        os.replace(temporary, destination)
        directory_descriptor = os.open(
            control_root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return destination
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
