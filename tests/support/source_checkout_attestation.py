"""Test-only issuer for owner-bound source checkout fixtures."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import pathlib
import secrets
import stat
import tempfile


CONTROL_ENVIRONMENT = "GEW_INSTALLATION_CONTROL_ROOT"
CONTROL_OPTION = "gew_installation_control_root"
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
    "adapters/graph_engineering/adapters/performance_correctness.py",
    "adapters/graph_engineering/adapters/performance_environment.py",
    "application/graph_engineering/application/actions.py",
    "application/graph_engineering/application/dependency_security.py",
    "application/graph_engineering/application/migration_rehearsal.py",
    "application/graph_engineering/application/performance_benchmark.py",
    "application/graph_engineering/application/profile_coverage.py",
    "application/graph_engineering/application/profile_coverage_oracle.py",
    "application/graph_engineering/application/profile_execution.py",
    "application/graph_engineering/application/profile_real_e2e.py",
    "application/graph_engineering/application/profile_real_e2e_verifier.py",
    "application/graph_engineering/application/release_operations.py",
    "application/graph_engineering/application/scenario_truth.py",
    "application/graph_engineering/application/security.py",
    "application/graph_engineering/application/tasks.py",
    "config/actions/action-policy-local-actions-v1.json",
    "config/actions/action-policy-v1.json",
    "config/actions/concrete-action-policy-v1.json",
    "config/contracts/action-adapter-registry-v1.json",
    "config/contracts/action-adapter-schema-registry-v1.json",
    "config/contracts/artifact-contracts-v1.json",
    "config/contracts/artifact-schema-registry-v1.json",
    "config/contracts/cost-schedule-v1.json",
    "config/contracts/profile-schema-registry-v1.json",
    "config/contracts/resource-profile-v1.json",
    "config/contracts/schema-profile-v1.json",
    "config/contracts/schemas/artifact-contract-registry-1.0.0.json",
    "config/contracts/schemas/artifact-lifecycle-event-1.0.0.json",
    "config/contracts/schemas/artifact-record-1.0.0.json",
    "config/contracts/schemas/category-completion-assessment-1.1.0.json",
    "config/contracts/schemas/category-completion-assessment-1.2.0.json",
    "config/contracts/schemas/category-completion-assessment-1.3.0.json",
    "config/contracts/schemas/category-completion-assessment-1.4.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.1.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.2.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.3.0.json",
    "config/contracts/schemas/category-completion-assessment-input-1.4.0.json",
    "config/contracts/schemas/category-execution-policy-1.0.0.json",
    "config/contracts/schemas/category-execution-policy-input-1.0.0.json",
    "config/contracts/schemas/coverage-record-1.0.0.json",
    "config/contracts/schemas/coverage-record-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.1.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.2.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.1.0.json",
    "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.2.0.json",
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
    "config/contracts/schemas/dependency-closure-graph-observation-1.0.0.json",
    "config/contracts/schemas/dependency-closure-graph-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-1.0.0.json",
    "config/contracts/schemas/dependency-fixed-closure-input-1.0.0.json",
    "config/contracts/schemas/dependency-graph-policy-registry-1.0.0.json",
    "config/contracts/schemas/dependency-graph-policy-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-offline-closure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-remediation-disposition-registry-1.0.0.json",
    "config/contracts/schemas/dependency-remediation-disposition-registry-input-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-1.0.0.json",
    "config/contracts/schemas/dependency-residual-exposure-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-1.1.0.json",
    "config/contracts/schemas/dependency-security-observation-input-1.0.0.json",
    "config/contracts/schemas/dependency-security-observation-input-1.1.0.json",
    "config/contracts/schemas/logical-body-manifest-1.0.0.json",
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
    "config/contracts/schemas/performance-benchmark-case-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-case-input-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-registry-1.0.0.json",
    "config/contracts/schemas/performance-benchmark-registry-input-1.0.0.json",
    "config/contracts/schemas/performance-correctness-observation-1.0.0.json",
    "config/contracts/schemas/performance-correctness-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-environment-observation-1.0.0.json",
    "config/contracts/schemas/performance-environment-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-measurement-sample-1.0.0.json",
    "config/contracts/schemas/performance-measurement-sample-input-1.0.0.json",
    "config/contracts/schemas/performance-observation-1.0.0.json",
    "config/contracts/schemas/performance-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-sample-set-observation-1.0.0.json",
    "config/contracts/schemas/performance-sample-set-observation-input-1.0.0.json",
    "config/contracts/schemas/performance-statistics-observation-1.0.0.json",
    "config/contracts/schemas/performance-statistics-observation-input-1.0.0.json",
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
    "config/contracts/schemas/release-recovery-binding-1.0.0.json",
    "config/contracts/schemas/release-recovery-binding-input-1.0.0.json",
    "config/contracts/schemas/release-simulator-fixture-registry-1.0.0.json",
    "config/contracts/schemas/release-simulator-fixture-registry-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-fixture-registry-1.0.0.json",
    "config/contracts/schemas/scenario-truth-fixture-registry-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-installation-bootstrap-1.0.0.json",
    "config/contracts/schemas/scenario-truth-installation-bootstrap-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-observation-1.0.0.json",
    "config/contracts/schemas/scenario-truth-observation-input-1.0.0.json",
    "config/contracts/schemas/scenario-truth-policy-registry-1.0.0.json",
    "config/contracts/schemas/scenario-truth-policy-registry-input-1.0.0.json",
    "config/migration/migration-rehearsal-fixture-v1.json",
    "config/migration/migration-rehearsal-installation-bootstrap-v1.json",
    "config/migration/migration-rehearsal-registry-v1.json",
    "config/migration/migration-rehearsal-transform-manifest-v1.json",
    "config/performance/performance-benchmark-fixture-v1.json",
    "config/performance/performance-benchmark-installation-bootstrap-v1.json",
    "config/performance/performance-benchmark-registry-v1.json",
    "config/performance/performance-benchmark-sample-v1.json",
    "config/performance/performance-command-binding-v1.json",
    "config/performance/performance-command-runtime-policy-v1.json",
    "config/performance/performance-correctness-oracle-v1.json",
    "config/performance/performance-source-registry-v1.json",
    "config/profiles/category-execution-policy-registry-v1.json",
    "config/profiles/category-execution-policy-v1.json",
    "config/profiles/profile-coverage-execution-plan-v1.json",
    "config/profiles/profile-real-e2e-binding-registry-v1.json",
    "config/profiles/scenario-truth-fixture-registry-v1.json",
    "config/profiles/scenario-truth-installation-bootstrap-v1.json",
    "config/profiles/scenario-truth-policy-registry-v1.json",
    "config/release-operations/release-operations-installation-bootstrap-v1.json",
    "config/release-operations/release-operations-policy-registry-v1.json",
    "config/release-operations/release-simulator-fixture-registry-v1.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.1.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.2.json",
    "config/security/dependency-advisory-installation-bootstrap-v1.json",
    "config/security/dependency-advisory-registry-v1.json",
    "config/security/dependency-advisory-registry-v2.json",
    "config/security/dependency-advisory-source-attestation-v1.json",
    "config/security/dependency-advisory-source-attestation-v2.json",
    "config/security/dependency-advisory-source-v1.json",
    "config/security/dependency-advisory-source-v2.json",
    "config/security/dependency-graph-policy-registry-v1.json",
    "config/security/dependency-remediation-disposition-registry-v1.json",
    "config/security/security-runtime-local-actions-v1.json",
    "config/security/security-runtime-v1.json",
    "config/supply-chain/extension-package-parser-requirement-v1.json",
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
    "config/test-oracles/profile-new-feature-invalidation-v1.json",
    "config/test-oracles/profile-new-feature-multi-target-v1.json",
    "config/test-oracles/profile-new-feature-normal-v1.json",
    "config/test-oracles/profile-new-feature-real-e2e-v1.json",
    "config/test-oracles/profile-new-feature-recovery-v1.json",
    "config/test-oracles/profile-new-feature-review-v1.json",
    "config/test-oracles/profile-new-feature-revise-v1.json",
    "config/test-oracles/profile-new-feature-rollback-v1.json",
    "config/test-oracles/profile-new-feature-scaffold-v1.json",
    "config/test-oracles/profile-new-feature-target-v1.json",
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
    "config/test-oracles/profile-release-operations-artifacts-v1.json",
    "config/test-oracles/profile-release-operations-authority-v1.json",
    "config/test-oracles/profile-release-operations-boundary-v1.json",
    "config/test-oracles/profile-release-operations-drift-v1.json",
    "config/test-oracles/profile-release-operations-invalidation-v1.json",
    "config/test-oracles/profile-release-operations-normal-v1.json",
    "config/test-oracles/profile-release-operations-real-e2e-v1.json",
    "config/test-oracles/profile-release-operations-recovery-v1.json",
    "config/test-oracles/profile-release-operations-review-v1.json",
    "config/test-oracles/profile-release-operations-revise-v1.json",
    "config/test-oracles/profile-release-operations-rollback-v1.json",
    "config/test-oracles/profile-release-operations-target-v1.json",
    "core/graph_engineering/__init__.py",
    "core/graph_engineering/core/artifacts/__init__.py",
    "core/graph_engineering/core/artifacts/contracts.py",
    "core/graph_engineering/core/artifacts/manifest.py",
    "core/graph_engineering/core/artifacts/records.py",
    "core/graph_engineering/core/contracts/schema.py",
    "core/graph_engineering/core/dependency_security.py",
    "core/graph_engineering/core/migration_rehearsal.py",
    "core/graph_engineering/core/performance_benchmark.py",
    "core/graph_engineering/core/profile_coverage.py",
    "core/graph_engineering/core/profile_execution.py",
    "core/graph_engineering/core/profiles.py",
    "core/graph_engineering/core/release_operations.py",
    "core/graph_engineering/core/scenario_truth.py",
    "core/graph_engineering/core/source_checkout.py",
    "pyproject.toml",
    "scripts/build_backend.py",
    "storage/graph_engineering/storage/clock.py",
    "storage/graph_engineering/storage/migration.py",
    "storage/graph_engineering/storage/repository.py",
    "storage/graph_engineering/storage/security.py",
)


class SourceCheckoutIssuanceError(RuntimeError):
    """A source checkout attestation could not be issued safely."""


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
            raise SourceCheckoutIssuanceError(f"unsafe source checkout file: {path.name}")
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
            raise SourceCheckoutIssuanceError(f"changed source checkout file: {path.name}")
        return bytes(body)
    finally:
        os.close(descriptor)


def _open_control_file(path: pathlib.Path, *, create: bool) -> int:
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
        raise SourceCheckoutIssuanceError(f"unsafe installation control file: {path.name}")
    return descriptor


def issue_source_checkout_attestation(
    source_root: pathlib.Path,
    control_root: pathlib.Path,
) -> pathlib.Path:
    """Bind one exact checkout to one configured owner-only control directory."""

    source_root = source_root.resolve(strict=True)
    source_metadata = os.lstat(source_root)
    if (
        not stat.S_ISDIR(source_metadata.st_mode)
        or stat.S_ISLNK(source_metadata.st_mode)
        or source_metadata.st_uid != os.getuid()
        or stat.S_IMODE(source_metadata.st_mode) & 0o022
    ):
        raise SourceCheckoutIssuanceError("source checkout root is unsafe")
    if not control_root.is_absolute():
        raise SourceCheckoutIssuanceError("installation control root must be absolute")
    control_root.mkdir(mode=0o700, parents=False, exist_ok=True)
    control_root = control_root.resolve(strict=True)
    control_metadata = os.lstat(control_root)
    if (
        not stat.S_ISDIR(control_metadata.st_mode)
        or stat.S_ISLNK(control_metadata.st_mode)
        or control_metadata.st_uid != source_metadata.st_uid
        or stat.S_IMODE(control_metadata.st_mode) != 0o700
    ):
        raise SourceCheckoutIssuanceError("installation control root is unsafe")

    lock_descriptor = _open_control_file(control_root / LOCK_FILENAME, create=True)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        key_path = control_root / KEY_FILENAME
        try:
            key_descriptor = _open_control_file(key_path, create=False)
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
            key_descriptor = _open_control_file(key_path, create=False)
        try:
            key = os.read(key_descriptor, 64)
            if len(key) != 32 or os.read(key_descriptor, 1):
                raise SourceCheckoutIssuanceError("installation attestation key is invalid")
        finally:
            os.close(key_descriptor)

        file_digests: dict[str, str] = {}
        file_sizes: dict[str, int] = {}
        for relative in SOURCE_FILES:
            body = _regular_bytes(source_root / relative, source_metadata.st_uid)
            file_digests[relative] = hashlib.sha256(body).hexdigest()
            file_sizes[relative] = len(body)
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
        document = dict(body)
        document["attestation_hmac_sha256"] = hmac.new(
            key,
            _canonical(body),
            hashlib.sha256,
        ).hexdigest()
        payload = _canonical(document) + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".source-checkout-attestation-",
            dir=control_root,
        )
        temporary = pathlib.Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor, payload)
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_root", type=pathlib.Path)
    parser.add_argument("control_root", type=pathlib.Path)
    arguments = parser.parse_args(argv)
    issue_source_checkout_attestation(arguments.source_root, arguments.control_root)
    print(f"{CONTROL_ENVIRONMENT}={arguments.control_root.resolve(strict=True)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
