"""Graph Engineering Workflow distribution namespace."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import importlib.metadata
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tomllib
import zipfile
from pkgutil import extend_path
from types import MappingProxyType


__path__ = extend_path(__path__, __name__)


_DISTRIBUTION_NAME = "graph-engineering-workflow"
_PROVENANCE_RESOURCE = "graph_engineering/pyproject.toml"
_MODULE_RESOURCE = "graph_engineering/__init__.py"
_CONTROL_OPTION = "gew_installation_control_root"
_CONTROL_LOCK = "installation-maintenance.lock"
_ATTESTATION_KEY = "source-checkout-attestation-v1.key"
_ATTESTATION_FILE = "source-checkout-attestation-v1.json"
_SOURCE_FILES = (
    "core/graph_engineering/__init__.py",
    "adapters/graph_engineering/adapters/__init__.py",
    "adapters/graph_engineering/adapters/action_adapters.py",
    "adapters/graph_engineering/adapters/command_native.py",
    "adapters/graph_engineering/adapters/connector_unavailable.py",
    "adapters/graph_engineering/adapters/git_native.py",
    "adapters/graph_engineering/adapters/performance_environment.py",
    "adapters/graph_engineering/adapters/performance_correctness.py",
    "pyproject.toml",
    "scripts/build_backend.py",
    "core/graph_engineering/core/source_checkout.py",
    "config/actions/action-policy-local-actions-v1.json",
    "config/actions/action-policy-v1.json",
    "config/actions/concrete-action-policy-v1.json",
    "config/contracts/action-adapter-registry-v1.json",
    "config/contracts/action-adapter-schema-registry-v1.json",
    "config/security/security-runtime-local-actions-v1.json",
    "config/security/security-runtime-v1.json",
    "config/profiles/category-execution-policy-registry-v1.json",
    "config/profiles/category-execution-policy-v1.json",
    "core/graph_engineering/core/dependency_security.py",
    "application/graph_engineering/application/dependency_security.py",
    "core/graph_engineering/core/performance_benchmark.py",
    "application/graph_engineering/application/performance_benchmark.py",
    "core/graph_engineering/core/migration_rehearsal.py",
    "application/graph_engineering/application/migration_rehearsal.py",
    "core/graph_engineering/core/scenario_truth.py",
    "application/graph_engineering/application/scenario_truth.py",
    "storage/graph_engineering/storage/migration.py",
    "config/migration/migration-rehearsal-registry-v1.json",
    "config/migration/migration-rehearsal-installation-bootstrap-v1.json",
    "config/migration/migration-rehearsal-fixture-v1.json",
    "config/migration/migration-rehearsal-transform-manifest-v1.json",
    "config/contracts/schemas/migration-crash-recovery-observation-1.0.0.json",
    "config/contracts/schemas/migration-crash-recovery-observation-input-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-fixture-manifest-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-fixture-manifest-input-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-observation-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-observation-input-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-registry-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-registry-input-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-transform-manifest-1.0.0.json",
    "config/contracts/schemas/migration-rehearsal-transform-manifest-input-1.0.0.json",
    "config/contracts/schemas/migration-step-observation-1.0.0.json",
    "config/contracts/schemas/migration-step-observation-input-1.0.0.json",
    "config/profiles/scenario-truth-policy-registry-v1.json",
    "config/profiles/scenario-truth-fixture-registry-v1.json",
    "config/profiles/scenario-truth-installation-bootstrap-v1.json",
    "config/contracts/schemas/category-completion-assessment-1.3.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.3.0.json",
    "config/contracts/schemas/scenario-truth-policy-registry-1.0.0.json",
    "config/contracts/schemas/scenario-truth-policy-registry-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-fixture-registry-1.0.0.json",
    "config/contracts/schemas/scenario-truth-fixture-registry-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-observation-1.0.0.json",
    "config/contracts/schemas/scenario-truth-observation-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/scenario-truth-installation-bootstrap-input-1.0.0.json",
    "config/performance/performance-benchmark-registry-v1.json",
    "config/performance/performance-benchmark-installation-bootstrap-v1.json",
    "config/performance/performance-benchmark-fixture-v1.json",
    "config/performance/performance-benchmark-sample-v1.json",
    "config/performance/performance-command-binding-v1.json",
    "config/performance/performance-command-runtime-policy-v1.json",
    "config/performance/performance-correctness-oracle-v1.json",
    "config/performance/performance-source-registry-v1.json",
    "config/security/dependency-advisory-registry-v1.json",
    "config/security/dependency-advisory-registry-v2.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.json",
    "config/security/dependency-advisory-source-v1.json",
    "config/security/dependency-advisory-source-v2.json",
    "config/security/dependency-advisory-source-attestation-v1.json",
    "config/security/dependency-advisory-source-attestation-v2.json",
    "config/security/dependency-graph-policy-registry-v1.json",
    "config/security/dependency-remediation-disposition-registry-v1.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.1.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.2.json",
    "config/contracts/schemas/dependency-advisory-source-record-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-source-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-record-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-status-high-water-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-status-high-water-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-registry-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.2.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.2.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-applicability-observation-1.0.0.json",
    "config/contracts/schemas/dependency-applicability-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-graph-policy-registry-1.0.0.json",
    "config/contracts/schemas/dependency-graph-policy-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-closure-graph-observation-1.0.0.json",
    "config/contracts/schemas/dependency-closure-graph-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-remediation-disposition-registry-1.0.0.json",
    "config/contracts/schemas/dependency-remediation-disposition-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-1.1.0.json",
    "config/contracts/schemas/dependency-security-observation-input-1.1.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.1.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.1.0.json",
    "config/contracts/schemas/performance-benchmark-case-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-case-input-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-registry-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-registry-input-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/performance-environment-observation-1.0.0.json",
    "config/contracts/schemas/performance-environment-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-correctness-observation-1.0.0.json",
    "config/contracts/schemas/performance-correctness-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-measurement-sample-1.0.0.json",
    "config/contracts/schemas/performance-measurement-sample-input-1.0.0.json",
    "config/contracts/schemas/performance-sample-set-observation-1.0.0.json",
    "config/contracts/schemas/performance-sample-set-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-statistics-observation-1.0.0.json",
    "config/contracts/schemas/performance-statistics-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-observation-1.0.0.json",
    "config/contracts/schemas/performance-observation-input-1.0.0.json",
    "config/contracts/schemas/category-completion-assessment-1.1.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.1.0.json",
    "config/contracts/schemas/category-completion-assessment-1.2.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.2.0.json",
    "config/supply-chain/extension-package-parser-requirement-v1.json",
    "core/graph_engineering/core/profile_coverage.py",
    "application/graph_engineering/application/profile_coverage.py",
    "application/graph_engineering/application/profile_coverage_oracle.py",
    "application/graph_engineering/application/profile_execution.py",
    "application/graph_engineering/application/profile_real_e2e.py",
    "application/graph_engineering/application/profile_real_e2e_verifier.py",
    "application/graph_engineering/application/actions.py",
    "storage/graph_engineering/storage/repository.py",
    "storage/graph_engineering/storage/clock.py",
    "core/graph_engineering/core/profile_execution.py",
    "config/profiles/profile-coverage-execution-plan-v1.json",
    "config/profiles/profile-real-e2e-binding-registry-v1.json",
    "config/test-oracles/profile-bug-fix-artifacts-v1.json",
    "config/test-oracles/profile-bug-fix-authority-v1.json",
    "config/test-oracles/profile-bug-fix-boundary-v1.json",
    "config/test-oracles/profile-bug-fix-drift-v1.json",
    "config/test-oracles/profile-bug-fix-false-reproduction-v1.json",
    "config/test-oracles/profile-bug-fix-invalidation-v1.json",
    "config/test-oracles/profile-bug-fix-normal-v1.json",
    "config/test-oracles/profile-bug-fix-real-e2e-v1.json",
    "config/test-oracles/profile-bug-fix-recovery-v1.json",
    "config/test-oracles/profile-bug-fix-regression-boundary-v1.json",
    "config/test-oracles/profile-bug-fix-reproducible-failure-v1.json",
    "config/test-oracles/profile-bug-fix-review-v1.json",
    "config/test-oracles/profile-bug-fix-revise-v1.json",
    "config/test-oracles/profile-bug-fix-rollback-v1.json",
    "config/test-oracles/profile-bug-fix-target-v1.json",
    "config/test-oracles/profile-dependency-security-artifacts-v1.json",
    "config/test-oracles/profile-dependency-security-authority-v1.json",
    "config/test-oracles/profile-dependency-security-boundary-v1.json",
    "config/test-oracles/profile-dependency-security-drift-v1.json",
    "config/test-oracles/profile-dependency-security-fix-unavailable-v1.json",
    "config/test-oracles/profile-dependency-security-invalidation-v1.json",
    "config/test-oracles/profile-dependency-security-normal-v1.json",
    "config/test-oracles/profile-dependency-security-real-e2e-v1.json",
    "config/test-oracles/profile-dependency-security-recovery-v1.json",
    "config/test-oracles/profile-dependency-security-review-v1.json",
    "config/test-oracles/profile-dependency-security-revise-v1.json",
    "config/test-oracles/profile-dependency-security-rollback-v1.json",
    "config/test-oracles/profile-dependency-security-target-v1.json",
    "config/test-oracles/profile-dependency-security-transitive-dependency-v1.json",
    "config/test-oracles/profile-dependency-security-vulnerable-graph-v1.json",
    "config/test-oracles/profile-hotfix-artifacts-v1.json",
    "config/test-oracles/profile-hotfix-authority-v1.json",
    "config/test-oracles/profile-hotfix-boundary-v1.json",
    "config/test-oracles/profile-hotfix-drift-v1.json",
    "config/test-oracles/profile-hotfix-emergency-baseline-v1.json",
    "config/test-oracles/profile-hotfix-invalidation-v1.json",
    "config/test-oracles/profile-hotfix-minimal-patch-v1.json",
    "config/test-oracles/profile-hotfix-normal-v1.json",
    "config/test-oracles/profile-hotfix-production-like-gate-v1.json",
    "config/test-oracles/profile-hotfix-real-e2e-v1.json",
    "config/test-oracles/profile-hotfix-recovery-v1.json",
    "config/test-oracles/profile-hotfix-review-v1.json",
    "config/test-oracles/profile-hotfix-revise-v1.json",
    "config/test-oracles/profile-hotfix-rollback-v1.json",
    "config/test-oracles/profile-hotfix-target-v1.json",
    "config/test-oracles/profile-incident-response-artifacts-v1.json",
    "config/test-oracles/profile-incident-response-authority-v1.json",
    "config/test-oracles/profile-incident-response-boundary-v1.json",
    "config/test-oracles/profile-incident-response-containment-v1.json",
    "config/test-oracles/profile-incident-response-detection-v1.json",
    "config/test-oracles/profile-incident-response-drift-v1.json",
    "config/test-oracles/profile-incident-response-invalidation-v1.json",
    "config/test-oracles/profile-incident-response-normal-v1.json",
    "config/test-oracles/profile-incident-response-real-e2e-v1.json",
    "config/test-oracles/profile-incident-response-recovery-v1.json",
    "config/test-oracles/profile-incident-response-review-v1.json",
    "config/test-oracles/profile-incident-response-revise-v1.json",
    "config/test-oracles/profile-incident-response-rollback-v1.json",
    "config/test-oracles/profile-incident-response-scenario-recovery-v1.json",
    "config/test-oracles/profile-incident-response-target-v1.json",
    "config/test-oracles/profile-incident-response-unknown-effects-v1.json",
    "config/test-oracles/profile-migration-artifacts-v1.json",
    "config/test-oracles/profile-migration-authority-v1.json",
    "config/test-oracles/profile-migration-backward-v1.json",
    "config/test-oracles/profile-migration-boundary-v1.json",
    "config/test-oracles/profile-migration-crash-window-v1.json",
    "config/test-oracles/profile-migration-drift-v1.json",
    "config/test-oracles/profile-migration-forward-v1.json",
    "config/test-oracles/profile-migration-invalidation-v1.json",
    "config/test-oracles/profile-migration-normal-v1.json",
    "config/test-oracles/profile-migration-partial-data-v1.json",
    "config/test-oracles/profile-migration-real-e2e-v1.json",
    "config/test-oracles/profile-migration-recovery-v1.json",
    "config/test-oracles/profile-migration-review-v1.json",
    "config/test-oracles/profile-migration-revise-v1.json",
    "config/test-oracles/profile-migration-rollback-v1.json",
    "config/test-oracles/profile-migration-target-v1.json",
    "config/test-oracles/profile-new-feature-artifacts-v1.json",
    "config/test-oracles/profile-new-feature-authority-v1.json",
    "config/test-oracles/profile-new-feature-boundary-v1.json",
    "config/test-oracles/profile-new-feature-drift-v1.json",
    "config/test-oracles/profile-new-feature-existing-feature-v1.json",
    "config/test-oracles/profile-new-feature-multi-target-v1.json",
    "config/test-oracles/profile-new-feature-invalidation-v1.json",
    "config/test-oracles/profile-new-feature-normal-v1.json",
    "config/test-oracles/profile-new-feature-recovery-v1.json",
    "config/test-oracles/profile-new-feature-review-v1.json",
    "config/test-oracles/profile-new-feature-revise-v1.json",
    "config/test-oracles/profile-new-feature-rollback-v1.json",
    "config/test-oracles/profile-new-feature-target-v1.json",
    "config/test-oracles/profile-new-feature-scaffold-v1.json",
    "config/test-oracles/profile-new-feature-real-e2e-v1.json",
    "config/test-oracles/profile-performance-artifacts-v1.json",
    "config/test-oracles/profile-performance-authority-v1.json",
    "config/test-oracles/profile-performance-boundary-v1.json",
    "config/test-oracles/profile-performance-correctness-regression-v1.json",
    "config/test-oracles/profile-performance-drift-v1.json",
    "config/test-oracles/profile-performance-invalidation-v1.json",
    "config/test-oracles/profile-performance-noise-outlier-v1.json",
    "config/test-oracles/profile-performance-normal-v1.json",
    "config/test-oracles/profile-performance-real-e2e-v1.json",
    "config/test-oracles/profile-performance-recovery-v1.json",
    "config/test-oracles/profile-performance-review-v1.json",
    "config/test-oracles/profile-performance-revise-v1.json",
    "config/test-oracles/profile-performance-rollback-v1.json",
    "config/test-oracles/profile-performance-stable-baseline-v1.json",
    "config/test-oracles/profile-performance-target-v1.json",
    "config/test-oracles/profile-refactor-debt-architecture-invariant-v1.json",
    "config/test-oracles/profile-refactor-debt-artifacts-v1.json",
    "config/test-oracles/profile-refactor-debt-authority-v1.json",
    "config/test-oracles/profile-refactor-debt-behavior-characterization-v1.json",
    "config/test-oracles/profile-refactor-debt-boundary-v1.json",
    "config/test-oracles/profile-refactor-debt-drift-v1.json",
    "config/test-oracles/profile-refactor-debt-invalidation-v1.json",
    "config/test-oracles/profile-refactor-debt-nonfunctional-target-v1.json",
    "config/test-oracles/profile-refactor-debt-normal-v1.json",
    "config/test-oracles/profile-refactor-debt-real-e2e-v1.json",
    "config/test-oracles/profile-refactor-debt-recovery-v1.json",
    "config/test-oracles/profile-refactor-debt-review-v1.json",
    "config/test-oracles/profile-refactor-debt-revise-v1.json",
    "config/test-oracles/profile-refactor-debt-rollback-v1.json",
    "config/test-oracles/profile-refactor-debt-target-v1.json",
    "core/graph_engineering/core/profiles.py",
    "core/graph_engineering/core/contracts/schema.py",
    "config/contracts/profile-schema-registry-v1.json",
    "config/contracts/schemas/coverage-record-input-1.0.0.json",
    "config/contracts/schemas/coverage-record-1.0.0.json",
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
    "config/contracts/schemas/category-execution-policy-1.0.0.json",
    "config/contracts/schemas/category-execution-policy-input-1.0.0.json",
    "config/contracts/schemas/release-coverage-assessment-1.0.0.json",
)


class DistributionIdentityError(RuntimeError):
    """The running distribution cannot be bound to an exact build identity."""


def _normalized_distribution_name(value: object) -> str | None:
    if type(value) is not str or not value:
        return None
    return re.sub(r"[-_.]+", "-", value).lower()


def _source_checkout_root(module_path: pathlib.Path) -> pathlib.Path | None:
    try:
        source_root = module_path.parents[2]
    except IndexError:
        return None
    if module_path != source_root / "core/graph_engineering/__init__.py":
        return None
    return source_root


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _read_owner_only_file(path: pathlib.Path, *, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_size > maximum
        ):
            raise DistributionIdentityError("source checkout attestation file is unsafe")
        body = os.read(descriptor, maximum + 1)
        if len(body) != metadata.st_size:
            raise DistributionIdentityError("source checkout attestation file changed")
        return body
    finally:
        os.close(descriptor)


def _source_file_projection(source_root: pathlib.Path, owner: int) -> tuple[dict[str, str], dict[str, int]]:
    digests: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for relative in _SOURCE_FILES:
        path = source_root / relative
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError as error:
            raise DistributionIdentityError(
                "source checkout attestation file binding is unavailable"
            ) from error
        try:
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != owner
                or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_nlink != 1
            ):
                raise DistributionIdentityError(
                    "source checkout attestation file binding is unsafe"
                )
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
                raise DistributionIdentityError(
                    "source checkout attestation file binding changed"
                )
        finally:
            os.close(descriptor)
        digests[relative] = hashlib.sha256(body).hexdigest()
        sizes[relative] = len(body)
    return digests, sizes


def _validate_source_checkout_attestation(source_root: pathlib.Path) -> None:
    configured = sys._xoptions.get(_CONTROL_OPTION)
    option_prefix = _CONTROL_OPTION + "="
    explicit_values: list[str] = []
    arguments = tuple(getattr(sys, "orig_argv", ()))
    for index, argument in enumerate(arguments):
        if argument == "-X" and index + 1 < len(arguments):
            value = arguments[index + 1]
            if value.startswith(option_prefix):
                explicit_values.append(value[len(option_prefix):])
        elif argument.startswith("-X" + option_prefix):
            explicit_values.append(argument[len("-X" + option_prefix):])
    if (
        type(configured) is not str
        or not configured
        or len(explicit_values) > 1
        or (explicit_values and explicit_values[0] != configured)
    ):
        raise DistributionIdentityError("source checkout attestation control root is unavailable")
    configured_path = pathlib.Path(configured)
    if not configured_path.is_absolute():
        raise DistributionIdentityError("source checkout attestation control root is unavailable")
    try:
        control_root = configured_path.resolve(strict=True)
    except OSError as error:
        raise DistributionIdentityError(
            "source checkout attestation control root is unavailable"
        ) from error
    if control_root != configured_path:
        raise DistributionIdentityError("source checkout attestation control root is unsafe")
    source_root = source_root.resolve(strict=True)
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
        raise DistributionIdentityError("source checkout attestation root binding is unsafe")
    lock_descriptor = os.open(
        control_root / _CONTROL_LOCK,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        lock_metadata = os.fstat(lock_descriptor)
        if (
            not stat.S_ISREG(lock_metadata.st_mode)
            or stat.S_IMODE(lock_metadata.st_mode) != 0o600
            or lock_metadata.st_uid != source_metadata.st_uid
            or lock_metadata.st_nlink != 1
        ):
            raise DistributionIdentityError("source checkout attestation lock is unsafe")
        fcntl.flock(lock_descriptor, fcntl.LOCK_SH)
        key = _read_owner_only_file(control_root / _ATTESTATION_KEY, maximum=32)
        if len(key) != 32:
            raise DistributionIdentityError("source checkout attestation key is invalid")
        raw = _read_owner_only_file(control_root / _ATTESTATION_FILE, maximum=65536)
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DistributionIdentityError("source checkout attestation is malformed") from error
        expected_keys = {
            "schema_version", "attestation_id", "installation_id", "source_root",
            "source_root_device", "source_root_inode", "source_root_owner",
            "source_root_mode", "runtime_manifest_digest", "concrete_policy_id",
            "concrete_policy_digest", "registry_id", "registry_digest",
            "schema_registry_id", "schema_registry_digest", "file_digests", "file_sizes",
            "attestation_hmac_sha256",
        }
        if type(document) is not dict or set(document) != expected_keys:
            raise DistributionIdentityError("source checkout attestation shape changed")
        signature = document.pop("attestation_hmac_sha256")
        if type(signature) is not str or not hmac.compare_digest(
            hmac.new(key, _canonical(document), hashlib.sha256).hexdigest(),
            signature,
        ):
            raise DistributionIdentityError("source checkout attestation signature changed")
        file_digests, file_sizes = _source_file_projection(
            source_root,
            source_metadata.st_uid,
        )
        runtime = json.loads(
            (source_root / "config/security/security-runtime-local-actions-v1.json").read_text(
                encoding="utf-8"
            )
        )
        concrete = json.loads(
            (source_root / "config/actions/concrete-action-policy-v1.json").read_text(
                encoding="utf-8"
            )
        )
        adapter_schemas = json.loads(
            (source_root / "config/contracts/action-adapter-schema-registry-v1.json").read_text(
                encoding="utf-8"
            )
        )
        expected = {
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
            "runtime_manifest_digest": runtime["manifest_digest"],
            "concrete_policy_id": concrete["policy_id"],
            "concrete_policy_digest": concrete["policy_digest"],
            "registry_id": concrete["registry_id"],
            "registry_digest": concrete["registry_digest"],
            "schema_registry_id": adapter_schemas["registry_id"],
            "schema_registry_digest": adapter_schemas["registry_digest"],
            "file_digests": file_digests,
            "file_sizes": file_sizes,
        }
        if document != expected:
            raise DistributionIdentityError("source checkout attestation binding changed")
    finally:
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        finally:
            os.close(lock_descriptor)


def _matching_installed_distributions() -> list[importlib.metadata.Distribution]:
    expected = _normalized_distribution_name(_DISTRIBUTION_NAME)
    matches: list[importlib.metadata.Distribution] = []
    for distribution in importlib.metadata.distributions():
        try:
            name = distribution.metadata["Name"]
        except (KeyError, TypeError):
            continue
        if _normalized_distribution_name(name) == expected:
            matches.append(distribution)
    return matches


def _record_resource(
    distribution: importlib.metadata.Distribution,
    distribution_root: pathlib.Path | None,
    distribution_archive: pathlib.Path | None,
    resource_name: str,
) -> bytes:
    files = distribution.files
    matches = [] if files is None else [
        item for item in files
        if pathlib.PurePosixPath(str(item)).as_posix() == resource_name
    ]
    if not matches:
        raise DistributionIdentityError(
            f"installed {resource_name} RECORD identity is unavailable"
        )
    if len(matches) != 1:
        raise DistributionIdentityError(
            f"installed {resource_name} RECORD identity is not unique"
        )
    located = distribution.locate_file(matches[0])
    try:
        if distribution_archive is not None:
            archive_root = getattr(located, "root", None)
            archive_name = getattr(archive_root, "filename", None)
            member_name = getattr(located, "at", None)
            if (
                type(archive_name) is not str
                or type(member_name) is not str
                or pathlib.Path(archive_name).resolve(strict=True) != distribution_archive
                or pathlib.PurePosixPath(member_name).as_posix() != resource_name
            ):
                raise DistributionIdentityError(
                    f"installed {resource_name} is outside the distribution"
                )
            member = archive_root.getinfo(member_name)
            member_mode = member.external_attr >> 16
            if member.is_dir() or stat.S_ISLNK(member_mode):
                raise DistributionIdentityError(f"installed {resource_name} is unsafe")
            body = located.read_bytes()
        else:
            if distribution_root is None:
                raise DistributionIdentityError("installed distribution root is unavailable")
            expected_path = (distribution_root / resource_name).resolve(strict=True)
            path = pathlib.Path(located).resolve(strict=True)
            if path != expected_path:
                raise DistributionIdentityError(
                    f"installed {resource_name} is outside the distribution"
                )
            metadata = os.lstat(path)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise DistributionIdentityError(f"installed {resource_name} is unsafe")
            body = path.read_bytes()
    except (KeyError, OSError) as error:
        raise DistributionIdentityError(
            f"installed {resource_name} is unavailable"
        ) from error
    recorded_hash = matches[0].hash
    if recorded_hash is None or recorded_hash.mode != "sha256":
        raise DistributionIdentityError(
            f"installed {resource_name} RECORD hash is missing"
        )
    encoded = base64.urlsafe_b64encode(hashlib.sha256(body).digest()).rstrip(b"=").decode()
    if not hmac.compare_digest(encoded, recorded_hash.value):
        raise DistributionIdentityError(f"installed {resource_name} RECORD hash changed")
    return body


def _validate_archive_members(
    distribution: importlib.metadata.Distribution,
    distribution_archive: pathlib.Path,
) -> tuple[tuple[str, ...], tuple[int, int, int, int, int, str]]:
    archive_identity = _archive_identity(distribution_archive)
    try:
        with zipfile.ZipFile(distribution_archive) as archive:
            names = [item.filename for item in archive.infolist()]
    except (OSError, zipfile.BadZipFile) as error:
        raise DistributionIdentityError("installed distribution archive is malformed") from error
    adapter_modules = sorted({
        name for name in names
        if name.startswith("graph_engineering/adapters/") and name.endswith(".py")
    })
    record_members = [name for name in names if name.endswith(".dist-info/RECORD")]
    metadata_members = [name for name in names if name.endswith(".dist-info/METADATA")]
    wheel_members = [name for name in names if name.endswith(".dist-info/WHEEL")]
    if not adapter_modules or any(
        not items for items in (record_members, metadata_members, wheel_members)
    ):
        raise DistributionIdentityError("installed archive RECORD identity is unavailable")
    for items in (record_members, metadata_members, wheel_members):
        if len(items) != 1:
            raise DistributionIdentityError(
                f"physical archive member is not unique: {items[0]}"
            )
    protected = (
        _MODULE_RESOURCE,
        _PROVENANCE_RESOURCE,
        *adapter_modules,
        record_members[0],
        metadata_members[0],
        wheel_members[0],
    )
    for member_name in protected:
        if names.count(member_name) != 1:
            raise DistributionIdentityError(
                f"physical archive member is not unique: {member_name}"
            )
    files = distribution.files
    record_names = set() if files is None else {
        pathlib.PurePosixPath(str(item)).as_posix() for item in files
    }
    if any(member_name not in record_names for member_name in adapter_modules):
        raise DistributionIdentityError("installed adapter module RECORD identity is unavailable")
    if _archive_identity(distribution_archive) != archive_identity:
        raise DistributionIdentityError("installed distribution archive changed")
    return tuple(adapter_modules), archive_identity


def _archive_identity(path: pathlib.Path) -> tuple[int, int, int, int, int, str]:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
        ):
            raise DistributionIdentityError("installed distribution archive is unsafe")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        after = os.fstat(descriptor)
        before_identity = (
            before.st_dev,
            before.st_ino,
            before.st_uid,
            stat.S_IMODE(before.st_mode),
            before.st_size,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_uid,
            stat.S_IMODE(after.st_mode),
            after.st_size,
        )
        if before_identity != after_identity or size != before.st_size:
            raise DistributionIdentityError("installed distribution archive changed")
        return (*before_identity, digest.hexdigest())
    finally:
        os.close(descriptor)


def _profile_coverage_protected_resources(provenance: bytes) -> tuple[str, ...]:
    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        coverage = document["tool"]["gew"]["profile"]["coverage-execution-plan"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "Profile coverage protected-member closure is malformed"
        ) from error
    expected = {
        "plan-id", "plan-digest", "plan-raw-sha256", "plan-source",
        "plan-resource", "oracle-vectors", "runner-raw-sha256",
        "runner-source", "runner-resource", "protected-sources",
        "protected-resources",
    }
    if type(coverage) is not dict or set(coverage) != expected:
        raise DistributionIdentityError(
            "Profile coverage protected-member closure is malformed"
        )
    sources = coverage["protected-sources"]
    values = coverage["protected-resources"]
    if (
        type(sources) is not list
        or type(values) is not list
        or not sources
        or len(sources) != len(values)
        or len(set(sources)) != len(sources)
        or len(set(values)) != len(values)
        or any(type(item) is not str for item in (*sources, *values))
    ):
        raise DistributionIdentityError(
            "Profile coverage protected-member closure is malformed"
        )
    for source, resource in zip(sources, values, strict=True):
        for item in (source, resource):
            path = pathlib.PurePosixPath(item)
            if path.is_absolute() or ".." in path.parts or "\\" in item:
                raise DistributionIdentityError(
                    "Profile coverage protected-member closure is malformed"
                )
        if source not in _SOURCE_FILES:
            raise DistributionIdentityError(
                "Profile coverage protected source is not attested"
            )
    return tuple(values)


def _validate_archive_resource_uniqueness(
    distribution: importlib.metadata.Distribution,
    distribution_archive: pathlib.Path,
    resources: tuple[str, ...],
) -> None:
    identity = _archive_identity(distribution_archive)
    try:
        with zipfile.ZipFile(distribution_archive) as archive:
            names = tuple(item.filename for item in archive.infolist())
    except (OSError, zipfile.BadZipFile) as error:
        raise DistributionIdentityError("installed distribution archive is malformed") from error
    files = distribution.files
    record_names = () if files is None else tuple(
        pathlib.PurePosixPath(str(item)).as_posix() for item in files
    )
    for resource in resources:
        if names.count(resource) != 1:
            raise DistributionIdentityError(
                f"physical archive member is not unique: {resource}"
            )
        if record_names.count(resource) != 1:
            raise DistributionIdentityError(
                f"installed {resource} RECORD identity is not unique"
            )
    if _archive_identity(distribution_archive) != identity:
        raise DistributionIdentityError("installed distribution archive changed")


def _validate_distribution_identity() -> (
    tuple[tuple[str, bytes], ...] | None
):
    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is not None:
        _validate_source_checkout_attestation(source_root)
        return None
    distributions = _matching_installed_distributions()
    if not distributions:
        raise DistributionIdentityError("installed distribution identity is unavailable")
    if len(distributions) != 1:
        raise DistributionIdentityError("installed distribution identity is not unique")
    distribution = distributions[0]
    root_location = distribution.locate_file("")
    archive_root = getattr(root_location, "root", None)
    archive_name = getattr(archive_root, "filename", None)
    archive_prefix = getattr(root_location, "at", None)
    distribution_root: pathlib.Path | None = None
    distribution_archive: pathlib.Path | None = None
    adapter_resources: tuple[str, ...] = ()
    archive_identity: tuple[int, int, int, int, int, str] | None = None
    if type(archive_name) is str and type(archive_prefix) is str:
        if pathlib.PurePosixPath(archive_prefix or ".").as_posix() not in {".", ""}:
            raise DistributionIdentityError("installed distribution root is invalid")
        distribution_archive = pathlib.Path(archive_name).resolve(strict=True)
        archive_metadata = os.lstat(distribution_archive)
        if stat.S_ISLNK(archive_metadata.st_mode) or not stat.S_ISREG(
            archive_metadata.st_mode
        ):
            raise DistributionIdentityError("installed distribution archive is unsafe")
        expected_origin = os.path.abspath(archive_name) + "/" + _MODULE_RESOURCE
        if os.path.normpath(os.fspath(raw_module_path)) != os.path.normpath(expected_origin):
            raise DistributionIdentityError(
                "installed distribution does not contain the loaded module"
            )
        adapter_resources, archive_identity = _validate_archive_members(
            distribution,
            distribution_archive,
        )
    else:
        distribution_root = pathlib.Path(root_location).resolve(strict=True)
        expected_module = (distribution_root / _MODULE_RESOURCE).resolve(strict=True)
        if module_path != expected_module:
            raise DistributionIdentityError(
                "installed distribution does not contain the loaded module"
            )
    _record_resource(
        distribution,
        distribution_root,
        distribution_archive,
        _MODULE_RESOURCE,
    )
    manifest_body = _record_resource(
        distribution,
        distribution_root,
        distribution_archive,
        _PROVENANCE_RESOURCE,
    )
    validated_adapters = tuple(
        (
            adapter_resource,
            _record_resource(
                distribution,
                distribution_root,
                distribution_archive,
                adapter_resource,
            ),
        )
        for adapter_resource in adapter_resources
    )
    if distribution_archive is not None and (
        archive_identity is None
        or _archive_identity(distribution_archive) != archive_identity
    ):
        raise DistributionIdentityError("installed distribution archive changed")
    try:
        manifest = tomllib.loads(manifest_body.decode("utf-8", errors="strict"))
        project = manifest["project"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "installed provenance resource is malformed"
        ) from error
    if (
        type(project) is not dict
        or project.get("name") != _DISTRIBUTION_NAME
        or project.get("version") != distribution.version
    ):
        raise DistributionIdentityError(
            "installed provenance distribution binding changed"
        )
    protected_resources = _profile_coverage_protected_resources(manifest_body)
    if distribution_archive is not None:
        _validate_archive_resource_uniqueness(
            distribution, distribution_archive, protected_resources,
        )
    validated_coverage = tuple(
        (
            resource,
            _record_resource(
                distribution,
                distribution_root,
                distribution_archive,
                resource,
            ),
        )
        for resource in protected_resources
    )
    if distribution_archive is not None and (
        archive_identity is None
        or _archive_identity(distribution_archive) != archive_identity
    ):
        raise DistributionIdentityError("installed distribution archive changed")
    if distribution_archive is None:
        return None
    return (
        *validated_adapters,
        (_PROVENANCE_RESOURCE, manifest_body),
        *validated_coverage,
    )


_VALIDATED_ARCHIVE = _validate_distribution_identity()
_VALIDATED_ARCHIVE_RESOURCES = MappingProxyType(
    {} if _VALIDATED_ARCHIVE is None else dict(_VALIDATED_ARCHIVE)
)


def _validated_archive_resource(resource_name: str) -> bytes | None:
    body = _VALIDATED_ARCHIVE_RESOURCES.get(resource_name)
    return None if body is None else bytes(body)


def _current_distribution_resource(resource_name: str) -> bytes:
    """Re-read one exact RECORD-bound resource from the loaded distribution."""

    _validate_distribution_identity()
    distributions = _matching_installed_distributions()
    if len(distributions) != 1:
        raise DistributionIdentityError("installed distribution identity is not unique")
    distribution = distributions[0]
    root_location = distribution.locate_file("")
    archive_root = getattr(root_location, "root", None)
    archive_name = getattr(archive_root, "filename", None)
    archive_prefix = getattr(root_location, "at", None)
    distribution_root: pathlib.Path | None = None
    distribution_archive: pathlib.Path | None = None
    if type(archive_name) is str and type(archive_prefix) is str:
        distribution_archive = pathlib.Path(archive_name).resolve(strict=True)
    else:
        distribution_root = pathlib.Path(root_location).resolve(strict=True)
    body = _record_resource(
        distribution,
        distribution_root,
        distribution_archive,
        resource_name,
    )
    _validate_distribution_identity()
    return body


def _category_policy_installation_resources() -> tuple[bytes, bytes, bytes]:
    """Return exact independently-attested bootstrap, registry, and policy bytes."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError as error:
        raise DistributionIdentityError("loaded distribution module is unavailable") from error
    source_root = _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        registry_resource, policy_resource = _category_policy_locations(
            provenance,
            location_kind="resource",
        )
        return (
            provenance,
            _current_distribution_resource(registry_resource),
            _current_distribution_resource(policy_resource),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    registry_source, policy_source = _category_policy_locations(
        provenance,
        location_kind="source",
    )
    bodies = [provenance]
    for relative in (registry_source, policy_source):
        if relative not in _SOURCE_FILES:
            raise DistributionIdentityError(
                "category policy source is outside the installation attestation"
            )
        bodies.append(_attested_source_member(source_root, relative, owner))
    _validate_source_checkout_attestation(source_root)
    return bodies[0], bodies[1], bodies[2]


def _category_policy_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[str, str]:
    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        category = document["tool"]["gew"]["profile"]["category-execution-policy"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError("category policy bootstrap is malformed") from error
    expected = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "policy-id", "policy-digest",
        "policy-raw-sha256", "policy-source", "policy-resource",
    }
    if type(category) is not dict or set(category) != expected:
        raise DistributionIdentityError("category policy bootstrap is not exact")
    values: list[str] = []
    for prefix in ("registry", "policy"):
        value = category.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str
            or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts
            or "\\" in value
        ):
            raise DistributionIdentityError("category policy bootstrap path is unsafe")
        values.append(pathlib.PurePosixPath(value).as_posix())
    return values[0], values[1]


def _dependency_advisory_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[str, str, str, str, str, tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact installation-pinned ADR-0006 protected members."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        advisory = document["tool"]["gew"]["profile"]["dependency-advisory"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "dependency advisory bootstrap is malformed"
        ) from error
    expected = {
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
    if type(advisory) is not dict or set(advisory) != expected:
        raise DistributionIdentityError(
            "dependency advisory bootstrap is not exact"
        )

    def location(prefix: str) -> str:
        value = advisory.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str
            or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts
            or "\\" in value
        ):
            raise DistributionIdentityError(
                "dependency advisory bootstrap path is unsafe"
            )
        return pathlib.PurePosixPath(value).as_posix()

    vectors = advisory["schema-vectors"]
    fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(vectors) is not list
        or len(vectors) != 22
        or any(type(item) is not dict or set(item) != fields for item in vectors)
    ):
        raise DistributionIdentityError(
            "dependency advisory schema vector is not exact"
        )
    identities: list[str] = []
    schema_locations: list[str] = []
    for item in vectors:
        schema_id = item["schema-id"]
        value = item[location_kind]
        if (
            type(schema_id) is not str
            or type(item["raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["raw-sha256"]) is None
            or type(value) is not str
            or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts
            or "\\" in value
        ):
            raise DistributionIdentityError(
                "dependency advisory schema vector is malformed"
            )
        identities.append(schema_id)
        schema_locations.append(pathlib.PurePosixPath(value).as_posix())
    if tuple(identities) != tuple(sorted(set(identities))):
        raise DistributionIdentityError(
            "dependency advisory schema vector is not canonical"
        )
    history_fields = {
        "generation", "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "source-artifact-id",
        "source-artifact-digest", "source-artifact-raw-sha256",
        "source-artifact-source", "source-artifact-resource",
        "source-attestation-id", "source-attestation-digest",
        "source-attestation-raw-sha256", "source-attestation-source",
        "source-attestation-resource",
    }
    source_history = advisory["source-history-vectors"]
    if (
        type(source_history) is not list
        or len(source_history) != 2
        or any(type(item) is not dict or set(item) != history_fields for item in source_history)
        or [item["generation"] for item in source_history] != [1, 2]
    ):
        raise DistributionIdentityError(
            "dependency advisory source history vector is not exact"
        )
    history_locations: list[str] = []
    history_identities: list[tuple[object, object, object, object]] = []
    for item in source_history:
        for field in (
            "registry-digest", "source-artifact-digest", "source-attestation-digest",
        ):
            if type(item[field]) is not str or re.fullmatch(
                r"sha256-jcs-v1:[0-9a-f]{64}", item[field]
            ) is None:
                raise DistributionIdentityError(
                    "dependency advisory source history digest is malformed"
                )
        for field in (
            "registry-raw-sha256", "source-artifact-raw-sha256",
            "source-attestation-raw-sha256",
        ):
            if type(item[field]) is not str or re.fullmatch(
                r"[0-9a-f]{64}", item[field]
            ) is None:
                raise DistributionIdentityError(
                    "dependency advisory source history raw digest is malformed"
                )
        history_identities.append((
            item["generation"], item["registry-id"],
            item["source-artifact-id"], item["source-attestation-id"],
        ))
        for prefix in ("registry", "source-artifact", "source-attestation"):
            value = item[f"{prefix}-{location_kind}"]
            if (
                type(value) is not str or not value
                or pathlib.PurePosixPath(value).is_absolute()
                or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
            ):
                raise DistributionIdentityError(
                    "dependency advisory source history path is unsafe"
                )
            history_locations.append(pathlib.PurePosixPath(value).as_posix())
    if len(set(history_identities)) != 2 or len(set(history_locations)) != 6:
        raise DistributionIdentityError(
            "dependency advisory source history vector is not canonical"
        )
    bootstrap_fields = {
        "schema-version", "bootstrap-id", "bootstrap-digest",
        "bootstrap-raw-sha256", "bootstrap-source", "bootstrap-resource",
    }
    bootstrap_history = advisory["bootstrap-history-vectors"]
    if (
        type(bootstrap_history) is not list
        or len(bootstrap_history) != 2
        or any(type(item) is not dict or set(item) != bootstrap_fields for item in bootstrap_history)
        or [item["schema-version"] for item in bootstrap_history] != ["1.0.0", "1.1.0"]
    ):
        raise DistributionIdentityError(
            "dependency advisory bootstrap history vector is not exact"
        )
    bootstrap_locations: list[str] = []
    for item in bootstrap_history:
        if (
            type(item["bootstrap-id"]) is not str or not item["bootstrap-id"]
            or type(item["bootstrap-digest"]) is not str
            or re.fullmatch(r"sha256-jcs-v1:[0-9a-f]{64}", item["bootstrap-digest"]) is None
            or type(item["bootstrap-raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["bootstrap-raw-sha256"]) is None
        ):
            raise DistributionIdentityError(
                "dependency advisory bootstrap history digest is malformed"
            )
        value = item[f"bootstrap-{location_kind}"]
        if (
            type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError(
                "dependency advisory bootstrap history path is unsafe"
            )
        bootstrap_locations.append(pathlib.PurePosixPath(value).as_posix())
    if len(set(bootstrap_locations)) != 2:
        raise DistributionIdentityError(
            "dependency advisory bootstrap history vector is not canonical"
        )
    return (
        location("registry"),
        location("bootstrap"),
        location("source-artifact"),
        location("source-attestation"),
        location("profile-schema-registry"),
        tuple(schema_locations),
        tuple((*history_locations, *bootstrap_locations)),
    )


def _dependency_advisory_installation_resources() -> tuple[bytes, ...]:
    """Re-read the complete current ADR-0006 installation projection."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        registry, bootstrap, source_artifact, source_attestation, schema_registry, schemas, history = (
            _dependency_advisory_locations(provenance, location_kind="resource")
        )
        return (
            provenance,
            _current_distribution_resource(registry),
            _current_distribution_resource(bootstrap),
            _current_distribution_resource(source_artifact),
            _current_distribution_resource(source_attestation),
            _current_distribution_resource(schema_registry),
            *(_current_distribution_resource(item) for item in schemas),
            *(_current_distribution_resource(item) for item in history),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    (
        registry, bootstrap, source_artifact, source_attestation,
        schema_registry, schemas, history,
    ) = _dependency_advisory_locations(
        provenance, location_kind="source"
    )
    locations = (
        registry, bootstrap, source_artifact, source_attestation,
        schema_registry, *schemas, *history,
    )
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "dependency advisory source is outside the installation attestation"
        )
    bodies = tuple(
        _attested_source_member(source_root, relative, owner)
        for relative in locations
    )
    _validate_source_checkout_attestation(source_root)
    return provenance, *bodies


def _dependency_graph_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact ADR-0006 r7 graph/remediation byte closure."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        graph = document["tool"]["gew"]["profile"]["dependency-advisory"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "dependency graph bootstrap is malformed"
        ) from error
    expected = {
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
    if type(graph) is not dict or set(graph) != expected:
        raise DistributionIdentityError("dependency graph bootstrap is not exact")

    def location(prefix: str) -> str:
        value = graph.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError("dependency graph path is unsafe")
        return pathlib.PurePosixPath(value).as_posix()

    vectors = graph["graph-schema-vectors"]
    fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(vectors) is not list or len(vectors) != 32
        or any(type(item) is not dict or set(item) != fields for item in vectors)
        or tuple(item["schema-id"] for item in vectors)
        != tuple(sorted({item["schema-id"] for item in vectors}))
    ):
        raise DistributionIdentityError("dependency graph schema vector is not exact")
    schemas: list[str] = []
    for item in vectors:
        value = item[location_kind]
        if (
            type(item["raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["raw-sha256"]) is None
            or type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError(
                "dependency graph schema pin is malformed"
            )
        schemas.append(pathlib.PurePosixPath(value).as_posix())
    fixed = tuple(location(prefix) for prefix in (
        "graph-policy", "remediation", "graph-bootstrap", "bootstrap",
        "registry", "profile-schema-registry", "build-backend",
    ))
    return fixed, tuple(schemas)


def _dependency_graph_installation_resources() -> tuple[bytes, ...]:
    """Re-read the current installed graph/remediation authority projection."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        fixed, schemas = _dependency_graph_locations(
            provenance, location_kind="resource",
        )
        return (
            provenance,
            *(_current_distribution_resource(item) for item in fixed),
            *(_current_distribution_resource(item) for item in schemas),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    fixed, schemas = _dependency_graph_locations(
        provenance, location_kind="source",
    )
    locations = (*fixed, *schemas)
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "dependency graph source is outside the installation attestation"
        )
    bodies = tuple(
        _attested_source_member(source_root, relative, owner)
        for relative in locations
    )
    _validate_source_checkout_attestation(source_root)
    return provenance, *bodies


def _migration_rehearsal_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact installation-pinned ADR-0002 r6 rehearsal members."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        migration = document["tool"]["gew"]["profile"]["migration-rehearsal"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "migration rehearsal bootstrap is malformed"
        ) from error
    expected = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "fixture-id", "fixture-digest",
        "fixture-raw-sha256", "fixture-source", "fixture-resource",
        "transform-id", "transform-digest", "transform-raw-sha256",
        "transform-source", "transform-resource", "bootstrap-id",
        "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
        "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "schema-vectors", "protected-resources", "protected-closure-digest",
        "distribution-name", "distribution-version", "source-attestation-policy-id",
        "build-backend-raw-sha256", "build-backend-source",
        "build-backend-resource",
    }
    if type(migration) is not dict or set(migration) != expected:
        raise DistributionIdentityError(
            "migration rehearsal independent pin is not exact"
        )

    def location(prefix: str) -> str:
        value = migration.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError("migration rehearsal path is unsafe")
        return pathlib.PurePosixPath(value).as_posix()

    vectors = migration["schema-vectors"]
    vector_fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(vectors) is not list or len(vectors) != 16
        or any(type(item) is not dict or set(item) != vector_fields for item in vectors)
        or tuple(item["schema-id"] for item in vectors)
        != tuple(sorted({item["schema-id"] for item in vectors}))
    ):
        raise DistributionIdentityError("migration rehearsal schema vector is not exact")
    schemas: list[str] = []
    for item in vectors:
        value = item[location_kind]
        if (
            type(item["raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["raw-sha256"]) is None
            or type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError("migration rehearsal schema pin is malformed")
        schemas.append(pathlib.PurePosixPath(value).as_posix())
    protected = migration["protected-resources"]
    protected_fields = {"raw-sha256", "source", "resource"}
    if (
        type(protected) is not list or not protected
        or any(type(item) is not dict or set(item) != protected_fields for item in protected)
        or tuple(item["source"] for item in protected)
        != tuple(sorted({item["source"] for item in protected}))
    ):
        raise DistributionIdentityError("migration rehearsal protected vector is not exact")
    protected_locations: list[str] = []
    for item in protected:
        value = item[location_kind]
        if (
            type(item["raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["raw-sha256"]) is None
            or type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError("migration rehearsal protected pin is malformed")
        protected_locations.append(pathlib.PurePosixPath(value).as_posix())
    return (
        tuple(location(prefix) for prefix in (
            "registry", "fixture", "transform", "bootstrap", "profile-schema-registry",
        )),
        tuple(schemas),
        tuple(protected_locations),
    )


def _migration_rehearsal_installation_resources() -> tuple[bytes, ...]:
    """Re-read the complete current ADR-0002 r6 installation projection."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        fixed, schemas, protected = _migration_rehearsal_locations(
            provenance, location_kind="resource",
        )
        return (
            provenance,
            *(_current_distribution_resource(item) for item in fixed),
            *(_current_distribution_resource(item) for item in schemas),
            *(_current_distribution_resource(item) for item in protected),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    fixed, schemas, protected = _migration_rehearsal_locations(
        provenance, location_kind="source",
    )
    locations = (*fixed, *schemas, *protected)
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "migration rehearsal source is outside the installation attestation"
        )
    bodies = tuple(
        _attested_source_member(source_root, relative, owner) for relative in locations
    )
    _validate_source_checkout_attestation(source_root)
    return provenance, *bodies


def _migration_rehearsal_installation_identity(
    provenance: bytes,
) -> MappingProxyType[str, object]:
    """Return the current source/installed RECORD identity for rehearsal use."""

    try:
        project = tomllib.loads(provenance.decode("utf-8", errors="strict"))["project"]
        name = project["name"]
        version = project["version"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "migration rehearsal distribution provenance is malformed"
        ) from error
    if type(name) is not str or type(version) is not str:
        raise DistributionIdentityError(
            "migration rehearsal distribution identity is invalid"
        )
    module_path = pathlib.Path(__file__).resolve(strict=True)
    source_root = _source_checkout_root(module_path)
    if source_root is not None:
        _validate_source_checkout_attestation(source_root)
        configured = sys._xoptions.get(_CONTROL_OPTION)
        if type(configured) is not str:
            raise DistributionIdentityError(
                "migration rehearsal source attestation is unavailable"
            )
        control_root = pathlib.Path(configured).resolve(strict=True)
        attestation = _read_owner_only_file(
            control_root / _ATTESTATION_FILE, maximum=65536,
        )
        document = json.loads(attestation)
        projection = _canonical({
            "file_digests": document["file_digests"],
            "runtime_manifest_digest": document["runtime_manifest_digest"],
        })
        return MappingProxyType({
            "distribution_root": os.fspath(source_root),
            "distribution_version": version,
            "installation_mode": "source-attested",
            "record_raw_sha256": hashlib.sha256(projection).hexdigest(),
            "source_attestation_digest": hashlib.sha256(attestation).hexdigest(),
        })
    distributions = _matching_installed_distributions()
    if len(distributions) != 1 or distributions[0].version != version:
        raise DistributionIdentityError(
            "migration rehearsal installed distribution is not unique"
        )
    distribution = distributions[0]
    files = tuple(distribution.files or ())
    records = tuple(
        item for item in files
        if pathlib.PurePosixPath(str(item)).name == "RECORD"
        and ".dist-info" in pathlib.PurePosixPath(str(item)).as_posix()
    )
    if len(records) != 1:
        raise DistributionIdentityError(
            "migration rehearsal installed RECORD is not unique"
        )
    record = distribution.locate_file(records[0]).read_bytes()
    return MappingProxyType({
        "distribution_root": os.fspath(distribution.locate_file("")),
        "distribution_version": version,
        "installation_mode": "installed-record",
        "record_raw_sha256": hashlib.sha256(record).hexdigest(),
        "source_attestation_digest": hashlib.sha256(record + provenance).hexdigest(),
    })


def _performance_benchmark_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact installation-pinned ADR-0007 protected members."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        benchmark = document["tool"]["gew"]["profile"]["performance-benchmark"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "performance benchmark bootstrap is malformed"
        ) from error
    expected = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource", "bootstrap-id",
        "bootstrap-digest", "bootstrap-raw-sha256", "bootstrap-source",
        "bootstrap-resource", "profile-schema-registry-id",
        "profile-schema-registry-digest", "profile-schema-registry-raw-sha256",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "fixture-id", "fixture-digest", "fixture-raw-sha256",
        "fixture-source", "fixture-resource", "sample-set-id",
        "sample-set-digest", "sample-raw-sha256", "sample-source",
        "sample-resource", "schema-vectors",
        "command-binding-id", "command-binding-digest", "command-binding-raw-sha256",
        "command-binding-source", "command-binding-resource",
        "command-runtime-policy-id", "command-runtime-policy-digest",
        "command-runtime-policy-raw-sha256", "command-runtime-policy-source",
        "command-runtime-policy-resource", "correctness-policy-id",
        "correctness-oracle-digest", "correctness-oracle-raw-sha256",
        "correctness-oracle-source", "correctness-oracle-resource",
        "source-registry-id", "source-registry-digest", "source-registry-raw-sha256",
        "source-registry-source", "source-registry-resource",
        "child-raw-sha256", "child-source", "child-resource",
        "build-backend-raw-sha256", "build-backend-source", "build-backend-resource",
        "distribution-name", "distribution-version", "source-attestation-policy-id",
        "maximum-warmup-count", "maximum-repetition-count",
        "protected-resources", "protected-closure-digest",
    }
    if type(benchmark) is not dict or set(benchmark) != expected:
        raise DistributionIdentityError(
            "performance benchmark independent pin is not exact"
        )

    def location(prefix: str) -> str:
        value = benchmark.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError(
                "performance benchmark bootstrap path is unsafe"
            )
        return pathlib.PurePosixPath(value).as_posix()

    vectors = benchmark["schema-vectors"]
    fields = {"schema-id", "raw-sha256", "source", "resource"}
    if (
        type(vectors) is not list or len(vectors) != 18
        or any(type(item) is not dict or set(item) != fields for item in vectors)
    ):
        raise DistributionIdentityError(
            "performance benchmark schema vector is not exact"
        )
    identities: list[str] = []
    locations: list[str] = []
    for item in vectors:
        schema_id = item["schema-id"]
        value = item[location_kind]
        if (
            type(schema_id) is not str
            or type(item["raw-sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", item["raw-sha256"]) is None
            or type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError(
                "performance benchmark schema vector is malformed"
            )
        identities.append(schema_id)
        locations.append(pathlib.PurePosixPath(value).as_posix())
    if tuple(identities) != tuple(sorted(set(identities))):
        raise DistributionIdentityError(
            "performance benchmark schema vector is not canonical"
        )
    prefixes = (
        "registry", "bootstrap", "profile-schema-registry", "fixture", "sample",
        "command-binding", "command-runtime-policy", "correctness-oracle",
        "source-registry", "child", "build-backend",
    )
    protected = benchmark["protected-resources"]
    protected_fields = {"raw-sha256", "source", "resource"}
    if (
        type(protected) is not list or not protected
        or any(type(item) is not dict or set(item) != protected_fields for item in protected)
        or tuple(item["source"] for item in protected)
        != tuple(sorted({item["source"] for item in protected}))
    ):
        raise DistributionIdentityError("performance protected resource vector is not exact")
    protected_locations: list[str] = []
    for item in protected:
        value = item[location_kind]
        if (
            type(value) is not str or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts or "\\" in value
        ):
            raise DistributionIdentityError("performance protected path is unsafe")
        protected_locations.append(pathlib.PurePosixPath(value).as_posix())
    return (
        tuple(location(prefix) for prefix in prefixes), tuple(locations),
        tuple(protected_locations),
    )


def _performance_benchmark_installation_resources() -> tuple[bytes, ...]:
    """Re-read the complete current ADR-0007 installation projection."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        fixed, schemas, protected = (
            _performance_benchmark_locations(provenance, location_kind="resource")
        )
        return (
            provenance,
            *(_current_distribution_resource(item) for item in fixed),
            *(_current_distribution_resource(item) for item in schemas),
            *(_current_distribution_resource(item) for item in protected),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    fixed, schemas, protected = (
        _performance_benchmark_locations(provenance, location_kind="source")
    )
    locations = (*fixed, *schemas, *protected)
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "performance benchmark source is outside the installation attestation"
        )
    bodies = tuple(
        _attested_source_member(source_root, relative, owner) for relative in locations
    )
    _validate_source_checkout_attestation(source_root)
    return provenance, *bodies


_DEPENDENCY_SPECIFIER_PIPE = r'''import base64,hashlib,json,pathlib,sys,tempfile
def canonical(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode("utf-8")
envelope=json.loads(sys.stdin.buffer.read())
fields={"backend_b64","provenance_b64","requirement_b64","requirement_path","specifier","version"}
if type(envelope) is not dict or set(envelope)!=fields:
    raise RuntimeError("dependency specifier envelope is not exact")
backend=base64.b64decode(envelope["backend_b64"],validate=True)
provenance=base64.b64decode(envelope["provenance_b64"],validate=True)
requirement=base64.b64decode(envelope["requirement_b64"],validate=True)
with tempfile.TemporaryDirectory(
    prefix="gew-dependency-parser-",
    dir=pathlib.Path(tempfile.gettempdir()).resolve(),
) as directory:
    root=pathlib.Path(directory)
    (root/"pyproject.toml").write_bytes(provenance)
    requirement_path=root/pathlib.PurePosixPath(envelope["requirement_path"])
    requirement_path.parent.mkdir(parents=True)
    requirement_path.write_bytes(requirement)
    scope={"__name__":"gew_dependency_parser","__file__":str(root/"scripts"/"build_backend.py")}
    exec(compile(backend,"<verified-dependency-parser>","exec",dont_inherit=True),scope,scope)
    scope["ROOT"]=root
    scope["PYPROJECT"]=root/"pyproject.toml"
    attestation=scope["_package_parser_attestation"]()
    parsed=scope["Requirement"]("candidate"+envelope["specifier"])
    version=scope["Version"](envelope["version"])
    matched=version in parsed.specifier
    body={"attestation_digest":attestation.attestation_digest,"matched":matched,"specifier":envelope["specifier"],"version":envelope["version"]}
    print(json.dumps({**body,"result_digest":hashlib.sha256(canonical(body)).hexdigest()},separators=(",",":"),sort_keys=True))
'''


def _dependency_parser_resources() -> tuple[bytes, bytes, bytes, str]:
    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        backend = _current_distribution_resource("graph_engineering/build_backend.py")
        requirement = _current_distribution_resource(
            "graph_engineering/config/supply-chain/extension-package-parser-requirement-v1.json"
        )
    else:
        _validate_source_checkout_attestation(source_root)
        owner = os.lstat(source_root).st_uid
        provenance = _attested_source_member(source_root, "pyproject.toml", owner)
        backend = _attested_source_member(source_root, "scripts/build_backend.py", owner)
        requirement = _attested_source_member(
            source_root,
            "config/supply-chain/extension-package-parser-requirement-v1.json",
            owner,
        )
        _validate_source_checkout_attestation(source_root)
    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        path = document["tool"]["gew"]["build"]["package-parser-requirement"]["path"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "dependency parser requirement bootstrap is malformed"
        ) from error
    if path != "config/supply-chain/extension-package-parser-requirement-v1.json":
        raise DistributionIdentityError(
            "dependency parser requirement path is substituted"
        )
    return backend, provenance, requirement, path


def _dependency_advisory_specifier_matches(specifier: str, version: str) -> bool:
    """Evaluate one specifier through the attested WP08A parser byte pipe."""

    if (
        type(specifier) is not str
        or not specifier
        or type(version) is not str
        or not version
        or any(ord(item) > 127 or item == "\x00" for item in specifier + version)
    ):
        raise DistributionIdentityError("dependency specifier input is invalid")
    backend, provenance, requirement, requirement_path = _dependency_parser_resources()
    envelope = {
        "backend_b64": base64.b64encode(backend).decode("ascii"),
        "provenance_b64": base64.b64encode(provenance).decode("ascii"),
        "requirement_b64": base64.b64encode(requirement).decode("ascii"),
        "requirement_path": requirement_path,
        "specifier": specifier,
        "version": version,
    }
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _DEPENDENCY_SPECIFIER_PIPE],
        input=json.dumps(
            envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if completed.returncode or completed.stderr:
        raise DistributionIdentityError(
            "dependency specifier parser failed closed"
        )
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DistributionIdentityError(
            "dependency specifier parser output is malformed"
        ) from error
    fields = {"attestation_digest", "matched", "specifier", "version", "result_digest"}
    if type(result) is not dict or set(result) != fields:
        raise DistributionIdentityError(
            "dependency specifier parser output is not exact"
        )
    body = {key: result[key] for key in fields if key != "result_digest"}
    if (
        result["specifier"] != specifier
        or result["version"] != version
        or type(result["matched"]) is not bool
        or type(result["attestation_digest"]) is not str
        or re.fullmatch(r"[0-9a-f]{64}", result["attestation_digest"]) is None
        or type(result["result_digest"]) is not str
        or not hmac.compare_digest(
            result["result_digest"],
            hashlib.sha256(json.dumps(
                body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).hexdigest(),
        )
    ):
        raise DistributionIdentityError(
            "dependency specifier parser result changed"
        )
    return result["matched"]


_DEPENDENCY_PREFLIGHT_PIPE = r'''import base64,email.policy,hashlib,json,pathlib,sys,tempfile,zipfile
from email.parser import BytesParser
def canonical(value):
    return json.dumps(value,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode("utf-8")
envelope=json.loads(sys.stdin.buffer.read())
fields={"backend_b64","candidate","phase","provenance_b64","requirement_b64","requirement_path","wheelhouse"}
if type(envelope) is not dict or set(envelope)!=fields or envelope["phase"] not in {"before","after"}:
    raise RuntimeError("dependency preflight envelope is not exact")
backend=base64.b64decode(envelope["backend_b64"],validate=True)
provenance=base64.b64decode(envelope["provenance_b64"],validate=True)
requirement=base64.b64decode(envelope["requirement_b64"],validate=True)
with tempfile.TemporaryDirectory(prefix="gew-dependency-preflight-",dir=pathlib.Path(tempfile.gettempdir()).resolve()) as directory:
    root=pathlib.Path(directory)
    (root/"pyproject.toml").write_bytes(provenance)
    requirement_path=root/pathlib.PurePosixPath(envelope["requirement_path"])
    requirement_path.parent.mkdir(parents=True)
    requirement_path.write_bytes(requirement)
    scope={"__name__":"gew_dependency_preflight","__file__":str(root/"scripts"/"build_backend.py")}
    exec(compile(backend,"<verified-dependency-preflight>","exec",dont_inherit=True),scope,scope)
    scope["ROOT"]=root
    scope["PYPROJECT"]=root/"pyproject.toml"
    plan=scope["preflight_offline_candidate"](
        pathlib.Path(envelope["candidate"]),pathlib.Path(envelope["wheelhouse"])
    )
    members=[]
    graph_members=[]
    for binding in plan.wheel_bindings:
        path=pathlib.Path(binding.path)
        name,version,_build,_tags=scope["parse_wheel_filename"](path.name)
        with zipfile.ZipFile(path) as archive:
            record_names=[item.filename for item in archive.infolist() if item.filename.endswith(".dist-info/RECORD")]
            metadata_names=[item.filename for item in archive.infolist() if item.filename.endswith(".dist-info/METADATA")]
            if len(record_names)!=1 or len(metadata_names)!=1:
                raise RuntimeError("dependency closure RECORD/METADATA is not singular")
            record_digest=hashlib.sha256(archive.read(record_names[0])).hexdigest()
            metadata_body=archive.read(metadata_names[0])
            metadata=BytesParser(policy=email.policy.compat32).parsebytes(metadata_body)
            requirements=metadata.get_all("Requires-Dist",[])
            if type(requirements) is not list or any(type(item) is not str or not item for item in requirements):
                raise RuntimeError("dependency closure requirement rows are malformed")
            if requirements!=sorted(set(requirements)):
                raise RuntimeError("dependency closure requirement rows are not canonical and unique")
            normalized_requirements=[]
            for raw_requirement in requirements:
                parsed_requirement=scope["Requirement"](raw_requirement)
                normalized_requirement=(scope["canonicalize_name"](parsed_requirement.name),str(parsed_requirement.specifier),tuple(sorted(parsed_requirement.extras)),None if parsed_requirement.marker is None else str(parsed_requirement.marker))
                if normalized_requirement in normalized_requirements:
                    raise RuntimeError("dependency closure requirement semantic identity is duplicated")
                normalized_requirements.append(normalized_requirement)
        members.append({"distribution_name":str(name),"distribution_version":str(version),"wheel_raw_sha256":binding.raw_digest,"record_raw_sha256":record_digest})
        graph_members.append({"distribution_name":str(name),"distribution_version":str(version),"wheel_raw_sha256":binding.raw_digest,"record_raw_sha256":record_digest,"metadata_raw_sha256":hashlib.sha256(metadata_body).hexdigest(),"requirements":requirements})
    members=sorted(members,key=lambda item:(item["distribution_name"],item["distribution_version"]))
    graph_members=sorted(graph_members,key=lambda item:(item["distribution_name"],item["distribution_version"]))
    if len({(item["distribution_name"],item["distribution_version"]) for item in members})!=len(members):
        raise RuntimeError("dependency closure member identity is ambiguous")
    closure_body={"members":members,"parser_attestation_digest":plan.parser_attestation.attestation_digest,"phase":envelope["phase"],"plan_digest":plan.plan_digest}
    body={"schema_version":"1.0.0","phase":envelope["phase"],"parser_attestation_digest":plan.parser_attestation.attestation_digest,"physical_closure_digest":hashlib.sha256(canonical(closure_body)).hexdigest(),"members":members,"graph_members":graph_members,"plan_digest":plan.plan_digest}
    print(json.dumps({**body,"result_digest":hashlib.sha256(canonical(body)).hexdigest()},separators=(",",":"),sort_keys=True))
'''


def _dependency_advisory_preflight_observation(
    candidate: str,
    wheelhouse: str,
    phase: str,
) -> dict[str, object]:
    """Run the exact verified WP08A preflight bytes and return a closed projection."""

    if (
        type(candidate) is not str
        or not candidate
        or type(wheelhouse) is not str
        or not wheelhouse
        or phase not in {"before", "after"}
    ):
        raise DistributionIdentityError("dependency preflight input is invalid")
    backend, provenance, requirement, requirement_path = _dependency_parser_resources()
    envelope = {
        "backend_b64": base64.b64encode(backend).decode("ascii"),
        "candidate": candidate,
        "phase": phase,
        "provenance_b64": base64.b64encode(provenance).decode("ascii"),
        "requirement_b64": base64.b64encode(requirement).decode("ascii"),
        "requirement_path": requirement_path,
        "wheelhouse": wheelhouse,
    }
    completed = subprocess.run(
        [sys.executable, "-I", "-c", _DEPENDENCY_PREFLIGHT_PIPE],
        input=json.dumps(
            envelope, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"),
        capture_output=True,
        check=False,
    )
    if completed.returncode or completed.stderr:
        raise DistributionIdentityError("dependency closure preflight failed closed")
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DistributionIdentityError(
            "dependency closure preflight output is malformed"
        ) from error
    fields = {
        "schema_version", "phase", "parser_attestation_digest",
        "physical_closure_digest", "members", "graph_members", "plan_digest",
        "result_digest",
    }
    if type(result) is not dict or set(result) != fields:
        raise DistributionIdentityError("dependency closure preflight output is not exact")
    body = {key: result[key] for key in fields if key != "result_digest"}
    if (
        result["schema_version"] != "1.0.0"
        or result["phase"] != phase
        or any(
            type(result[field]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", result[field]) is None
            for field in (
                "parser_attestation_digest", "physical_closure_digest",
                "plan_digest", "result_digest",
            )
        )
        or not hmac.compare_digest(
            result["result_digest"],
            hashlib.sha256(json.dumps(
                body, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).hexdigest(),
        )
    ):
        raise DistributionIdentityError("dependency closure preflight output changed")
    return body


def _scenario_truth_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact installed ADR-0008 scenario-truth member closure."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        value = document["tool"]["gew"]["profile"]["scenario-truth"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError("scenario truth bootstrap is malformed") from error
    expected = {
        "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
        "bootstrap-source", "bootstrap-resource", "policy-source",
        "policy-resource", "fixture-source", "fixture-resource",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "schema-sources", "schema-resources", "protected-sources",
        "protected-resources", "distribution-name", "distribution-version",
    }
    if type(value) is not dict or set(value) != expected:
        raise DistributionIdentityError("scenario truth independent pin is not exact")

    def safe(item: object) -> str:
        if (
            type(item) is not str or not item
            or pathlib.PurePosixPath(item).is_absolute()
            or ".." in pathlib.PurePosixPath(item).parts or "\\" in item
        ):
            raise DistributionIdentityError("scenario truth path is unsafe")
        return pathlib.PurePosixPath(item).as_posix()

    fixed = tuple(safe(value[f"{name}-{location_kind}"]) for name in (
        "policy", "fixture", "bootstrap", "profile-schema-registry",
    ))
    schemas = value[f"schema-{location_kind}s"]
    protected = value[f"protected-{location_kind}s"]
    if (
        type(schemas) is not list or len(schemas) != 10
        or type(protected) is not list or not protected
    ):
        raise DistributionIdentityError("scenario truth member vectors are incomplete")
    schema_paths = tuple(safe(item) for item in schemas)
    protected_paths = tuple(safe(item) for item in protected)
    if len(set(schema_paths)) != len(schema_paths) or len(set(protected_paths)) != len(protected_paths):
        raise DistributionIdentityError("scenario truth member vectors are not unique")
    return fixed, schema_paths, protected_paths


def _scenario_truth_installation_resources() -> tuple[bytes, ...]:
    """Re-read the complete current ADR-0008 installed/source projection."""

    module_path = pathlib.Path(__file__).resolve(strict=True)
    source_root = _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        fixed, schemas, protected = _scenario_truth_locations(
            provenance, location_kind="resource",
        )
        return (
            provenance,
            *(_current_distribution_resource(item) for item in fixed),
            *(_current_distribution_resource(item) for item in schemas),
            *(_current_distribution_resource(item) for item in protected),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    fixed, schemas, protected = _scenario_truth_locations(
        provenance, location_kind="source",
    )
    locations = (*fixed, *schemas, *protected)
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "scenario truth source is outside the installation attestation"
        )
    bodies = tuple(
        _attested_source_member(source_root, relative, owner) for relative in locations
    )
    _validate_source_checkout_attestation(source_root)
    return provenance, *bodies


def _profile_real_e2e_installation_resource() -> tuple[bytes, bytes]:
    """Return the exact independently-attested real-E2E binding registry."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError as error:
        raise DistributionIdentityError(
            "loaded distribution module is unavailable"
        ) from error
    source_root = _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        resource = _profile_real_e2e_location(
            provenance, location_kind="resource",
        )
        return provenance, _current_distribution_resource(resource)
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    source = _profile_real_e2e_location(provenance, location_kind="source")
    if source not in _SOURCE_FILES:
        raise DistributionIdentityError(
            "Profile real-E2E registry is outside the installation attestation"
        )
    body = _attested_source_member(source_root, source, owner)
    _validate_source_checkout_attestation(source_root)
    return provenance, body


def _profile_real_e2e_location(
    provenance: bytes,
    *,
    location_kind: str,
) -> str:
    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        registry = document["tool"]["gew"]["profile"]["real-e2e-bindings"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "Profile real-E2E bootstrap is malformed"
        ) from error
    expected = {
        "registry-id", "registry-digest", "registry-raw-sha256",
        "registry-source", "registry-resource",
    }
    value = None if type(registry) is not dict else registry.get(
        f"registry-{location_kind}"
    )
    if (
        type(registry) is not dict
        or set(registry) != expected
        or type(value) is not str
        or not value
        or pathlib.PurePosixPath(value).is_absolute()
        or ".." in pathlib.PurePosixPath(value).parts
        or "\\" in value
    ):
        raise DistributionIdentityError(
            "Profile real-E2E bootstrap is not exact"
        )
    return pathlib.PurePosixPath(value).as_posix()


def _profile_coverage_installation_resources(
) -> tuple[bytes, bytes, tuple[bytes, ...], bytes]:
    """Return exact installation-bound Profile coverage plan and oracle bytes."""

    raw_module_path = pathlib.Path(__file__)
    try:
        module_path = raw_module_path.resolve(strict=True)
    except OSError as error:
        raise DistributionIdentityError("loaded distribution module is unavailable") from error
    source_root = _source_checkout_root(module_path)
    if source_root is None:
        provenance = _current_distribution_resource(_PROVENANCE_RESOURCE)
        plan_resource, oracle_resources, runner_resource = _profile_coverage_locations(
            provenance,
            location_kind="resource",
        )
        return (
            provenance,
            _current_distribution_resource(plan_resource),
            tuple(_current_distribution_resource(item) for item in oracle_resources),
            _current_distribution_resource(runner_resource),
        )
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    plan_source, oracle_sources, runner_source = _profile_coverage_locations(
        provenance,
        location_kind="source",
    )
    bodies = [provenance]
    for relative in (plan_source, *oracle_sources, runner_source):
        if relative not in _SOURCE_FILES:
            raise DistributionIdentityError(
                "Profile coverage source is outside the installation attestation"
            )
        bodies.append(_attested_source_member(source_root, relative, owner))
    _validate_source_checkout_attestation(source_root)
    return bodies[0], bodies[1], tuple(bodies[2:-1]), bodies[-1]


def _profile_coverage_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[str, tuple[str, ...], str]:
    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        coverage = document["tool"]["gew"]["profile"]["coverage-execution-plan"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError(
            "Profile coverage bootstrap is malformed"
        ) from error
    expected = {
        "plan-id", "plan-digest", "plan-raw-sha256", "plan-source",
        "plan-resource", "oracle-vectors", "runner-raw-sha256",
        "runner-source", "runner-resource", "protected-sources",
        "protected-resources",
    }
    if type(coverage) is not dict or set(coverage) != expected:
        raise DistributionIdentityError("Profile coverage bootstrap is not exact")
    protected_sources = coverage["protected-sources"]
    protected_resources = coverage["protected-resources"]
    if (
        type(protected_sources) is not list
        or type(protected_resources) is not list
        or not protected_sources
        or len(protected_sources) != len(protected_resources)
        or len(set(protected_sources)) != len(protected_sources)
        or len(set(protected_resources)) != len(protected_resources)
    ):
        raise DistributionIdentityError(
            "Profile coverage protected-member closure is not exact"
        )
    for source, resource in zip(
        protected_sources, protected_resources, strict=True,
    ):
        for value in (source, resource):
            if (
                type(value) is not str
                or not value
                or pathlib.PurePosixPath(value).is_absolute()
                or ".." in pathlib.PurePosixPath(value).parts
                or "\\" in value
            ):
                raise DistributionIdentityError(
                    "Profile coverage protected-member path is unsafe"
                )
        if pathlib.PurePosixPath(source).as_posix() not in _SOURCE_FILES:
            raise DistributionIdentityError(
                "Profile coverage protected source is not attested"
            )
    values: list[str] = []
    for prefix in ("plan", "runner"):
        value = coverage.get(f"{prefix}-{location_kind}")
        if (
            type(value) is not str
            or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts
            or "\\" in value
        ):
            raise DistributionIdentityError("Profile coverage bootstrap path is unsafe")
        values.append(pathlib.PurePosixPath(value).as_posix())
    oracle_vectors = coverage.get("oracle-vectors")
    oracle_fields = {
        "oracle-id", "profile-id", "selector-kind", "column-id",
        "scenario-id", "category-boundary-case-id", "overlay-id", "oracle-digest",
        "oracle-raw-sha256", "oracle-source", "oracle-resource",
        "pass-task-id", "reject-task-id",
    }
    if (
        type(oracle_vectors) is not list
        or not oracle_vectors
        or any(type(item) is not dict or set(item) != oracle_fields
               for item in oracle_vectors)
    ):
        raise DistributionIdentityError("Profile coverage oracle vector is not exact")
    oracle_locations: list[str] = []
    identities: list[tuple[str, str, str, str, str]] = []
    for item in oracle_vectors:
        value = item.get(f"oracle-{location_kind}")
        if (
            type(value) is not str
            or not value
            or pathlib.PurePosixPath(value).is_absolute()
            or ".." in pathlib.PurePosixPath(value).parts
            or "\\" in value
        ):
            raise DistributionIdentityError("Profile coverage oracle path is unsafe")
        oracle_locations.append(pathlib.PurePosixPath(value).as_posix())
        identities.append((
            str(item["oracle-id"]), str(item["profile-id"]),
            str(item["selector-kind"]), str(item["column-id"]),
            str(item["scenario-id"]),
        ))
    if (
        tuple(identities) != tuple(sorted(identities))
        or len(set(identities)) != len(identities)
    ):
        raise DistributionIdentityError("Profile coverage oracle vector is not canonical")
    return values[0], tuple(oracle_locations), values[1]


def _attested_source_member(
    source_root: pathlib.Path,
    relative: str,
    owner: int,
) -> bytes:
    path = source_root.joinpath(*pathlib.PurePosixPath(relative).parts)
    descriptor = os.open(
        path,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != owner
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_nlink != 1
        ):
            raise DistributionIdentityError("category policy source is unsafe")
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
            raise DistributionIdentityError("category policy source changed")
        return bytes(body)
    finally:
        os.close(descriptor)
