"""Graph Engineering Workflow distribution namespace."""

from __future__ import annotations

import base64
import csv
import ctypes
import errno
import fcntl
import hashlib
import hmac
import importlib.machinery
import importlib.metadata
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tomllib
import threading
import zipfile
from contextlib import contextmanager
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
    "config/test-oracles/profile-release-operations-artifact-provenance-v1.json",
    "config/test-oracles/profile-release-operations-artifacts-v1.json",
    "config/test-oracles/profile-release-operations-authority-v1.json",
    "config/test-oracles/profile-release-operations-boundary-v1.json",
    "config/test-oracles/profile-release-operations-drift-v1.json",
    "config/test-oracles/profile-release-operations-health-gate-v1.json",
    "config/test-oracles/profile-release-operations-invalidation-v1.json",
    "config/test-oracles/profile-release-operations-normal-v1.json",
    "config/test-oracles/profile-release-operations-partial-deploy-v1.json",
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


def _source_attestation_transport_limit() -> int:
    # Each closed path occurs twice (digest and size). The fixed overhead
    # covers signed installation fields, independently of task resource limits.
    return max(65536, 4096 + sum(
        2 * len(relative.encode("utf-8")) + 96 for relative in _SOURCE_FILES
    ))


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


def _validate_source_checkout_attestation(source_root: pathlib.Path, *, _capture=False):
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
        raw = _read_owner_only_file(
            control_root / _ATTESTATION_FILE, maximum=_source_attestation_transport_limit(),
        )
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
        if _capture:
            return _SourceInstallationReadPlan(
                source_root, control_root, source_metadata, control_metadata,
                tuple((name, file_sizes[name], file_digests[name]) for name in _SOURCE_FILES),
                (len(key), hashlib.sha256(key).hexdigest()),
                (len(raw), hashlib.sha256(raw).hexdigest()),
            )
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
    except OSError:
        # Archive members have no standalone filesystem path. The distribution
        # branch still verifies the loaded module origin and each current RECORD.
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
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


_dependency_location_local = threading.local()
_DEPENDENCY_LOCATION_TOML_LOADS = tomllib.loads


class _DependencyLocationOperation:
    """At most three immutable projections, never live validation results."""

    __slots__ = ("owner", "entries")

    def __init__(self) -> None:
        self.owner = (os.getpid(), threading.get_ident())
        self.entries: dict[str, tuple[object, ...]] = {}


@contextmanager
def _dependency_location_operation():
    previous = getattr(_dependency_location_local, "current", None)
    operation = _DependencyLocationOperation()
    _dependency_location_local.current = operation
    try:
        yield operation
    finally:
        operation.entries.clear()
        _dependency_location_local.current = previous


def _immutable_dependency_location(value: object) -> bool:
    return type(value) is str or (
        type(value) is tuple
        and all(_immutable_dependency_location(item) for item in value)
    )


def _reuse_dependency_location(slot, projector, provenance, location_kind):
    operation = getattr(_dependency_location_local, "current", None)
    owned = (
        type(operation) is _DependencyLocationOperation
        and operation.owner == (os.getpid(), threading.get_ident())
    )
    eligible = (
        owned
        and type(slot) is str
        and _DEPENDENCY_LOCATION_PROJECTORS.get(slot) is projector
        and tomllib.loads is _DEPENDENCY_LOCATION_TOML_LOADS
        and type(provenance) is bytes
        and type(location_kind) is str
        and location_kind in ("source", "resource")
    )
    if not eligible:
        if owned and type(slot) is str:
            operation.entries.pop(slot, None)
        return projector(provenance, location_kind=location_kind)
    entry = operation.entries.get(slot)
    if entry is not None and (
        entry[0] is projector and entry[1] is tomllib.loads
        and entry[2:4] == (provenance, location_kind)
    ):
        return entry[4]
    # A failed/changed input must not leave an older success in this slot.
    operation.entries.pop(slot, None)
    value = projector(provenance, location_kind=location_kind)
    if _immutable_dependency_location(value):
        operation.entries[slot] = (
            projector, tomllib.loads, provenance, location_kind, value,
        )
    return value


def _dependency_advisory_locations(provenance: bytes, *, location_kind: str):
    return _reuse_dependency_location(
        "advisory", _parse_dependency_advisory_locations, provenance, location_kind,
    )


def _parse_dependency_advisory_locations(
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


def _dependency_graph_locations(provenance: bytes, *, location_kind: str):
    return _reuse_dependency_location(
        "graph", _parse_dependency_graph_locations, provenance, location_kind,
    )


def _parse_dependency_graph_locations(
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
            control_root / _ATTESTATION_FILE, maximum=_source_attestation_transport_limit(),
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


def _parse_dependency_parser_requirement_location(
    provenance: bytes, *, location_kind: str,
) -> str:
    del location_kind
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
    return path


def _dependency_parser_requirement_location(provenance: bytes, *, location_kind: str):
    return _reuse_dependency_location(
        "parser", _parse_dependency_parser_requirement_location,
        provenance, location_kind,
    )


_DEPENDENCY_LOCATION_PROJECTORS = MappingProxyType({
    "advisory": _parse_dependency_advisory_locations,
    "graph": _parse_dependency_graph_locations,
    "parser": _parse_dependency_parser_requirement_location,
})


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
    path = _dependency_parser_requirement_location(
        provenance, location_kind="resource" if source_root is None else "source",
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


def _release_operations_locations(
    provenance: bytes,
    *,
    location_kind: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Resolve the exact installed ADR-0009 release-operations closure."""

    try:
        document = tomllib.loads(provenance.decode("utf-8", errors="strict"))
        value = document["tool"]["gew"]["profile"]["release-operations"]
    except (KeyError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise DistributionIdentityError("release operations bootstrap is malformed") from error
    expected = {
        "bootstrap-id", "bootstrap-digest", "bootstrap-raw-sha256",
        "bootstrap-source", "bootstrap-resource", "policy-source",
        "policy-resource", "fixture-source", "fixture-resource",
        "profile-schema-registry-source", "profile-schema-registry-resource",
        "schema-sources", "schema-resources", "protected-sources",
        "protected-resources", "distribution-name", "distribution-version",
    }
    if type(value) is not dict or set(value) != expected:
        raise DistributionIdentityError("release operations independent pin is not exact")

    def safe(item: object) -> str:
        if (
            type(item) is not str or not item
            or pathlib.PurePosixPath(item).is_absolute()
            or ".." in pathlib.PurePosixPath(item).parts or "\\" in item
        ):
            raise DistributionIdentityError("release operations path is unsafe")
        return pathlib.PurePosixPath(item).as_posix()

    fixed = tuple(safe(value[f"{name}-{location_kind}"]) for name in (
        "policy", "fixture", "bootstrap", "profile-schema-registry",
    ))
    schemas = value[f"schema-{location_kind}s"]
    protected = value[f"protected-{location_kind}s"]
    if (
        type(schemas) is not list or len(schemas) != 18
        or type(protected) is not list or not protected
    ):
        raise DistributionIdentityError("release operations member vectors are incomplete")
    schema_paths = tuple(safe(item) for item in schemas)
    protected_paths = tuple(safe(item) for item in protected)
    if len(set(schema_paths)) != 18 or len(set(protected_paths)) != len(protected_paths):
        raise DistributionIdentityError("release operations member vectors are not unique")
    return fixed, schema_paths, protected_paths


def _standard_discovery_functions():
    metadata = importlib.metadata
    return (
        importlib.machinery.PathFinder.find_distributions,
        metadata.distributions, metadata.Distribution.discover.__func__,
        metadata.Distribution._discover_resolvers, metadata.Distribution.metadata.fget,
        metadata.MetadataPathFinder.find_distributions.__func__,
        metadata.MetadataPathFinder._search_paths.__func__,
        metadata.FastPath.children, metadata.FastPath.zip_children,
        metadata.FastPath.search, metadata.Lookup.__init__,
        metadata.PathDistribution.read_text, metadata.PathDistribution.locate_file,
    )


try:
    _STANDARD_DISCOVERY_FUNCTIONS = tuple(
        (function, function.__code__) for function in _standard_discovery_functions()
    )
except (AttributeError, TypeError):
    # An unsupported interpreter can keep ordinary installed behavior, but
    # cannot issue a cold proof based on an unknown discovery implementation.
    _STANDARD_DISCOVERY_FUNCTIONS = ()


def _require_standard_discovery(context):
    if not _STANDARD_DISCOVERY_FUNCTIONS or type(sys.meta_path) not in (tuple, list):
        raise DistributionIdentityError("cold discovery implementation is unsupported")
    context.check_limit("array_items", len(sys.meta_path), source_id="cold-discovery-providers")
    providers = 0
    for finder in sys.meta_path:
        resolver = getattr(finder, "find_distributions", None)
        if resolver is not None:
            if finder is not importlib.machinery.PathFinder:
                raise DistributionIdentityError("cold discovery provider is unsupported")
            providers += 1
    if providers != 1:
        raise DistributionIdentityError("cold discovery provider is unavailable")
    try:
        current = _standard_discovery_functions()
        changed = any(function is not expected or function.__code__ is not code
            for function, (expected, code) in zip(current, _STANDARD_DISCOVERY_FUNCTIONS, strict=True))
    except (AttributeError, TypeError, ValueError) as error:
        raise DistributionIdentityError("cold discovery implementation changed") from error
    if changed:
        raise DistributionIdentityError("cold discovery implementation changed")


_PATH_LIBC = ctypes.CDLL(None, use_errno=True)
_PATH_LIBC.getcwd.argtypes = (ctypes.c_void_p, ctypes.c_size_t)
_PATH_LIBC.getcwd.restype = ctypes.c_void_p
_PATH_LIBC.readlink.argtypes = (ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
_PATH_LIBC.readlink.restype = ctypes.c_ssize_t


def _bounded_path_text(context, budget, path_limit, *, link=None):
    """Use a fixed native buffer; callers keep their path-scratch lease live."""
    buffer = encoded = raw = result = None
    try:
        with budget.reserve(context, units=16 * (path_limit + 1), byte_count=16 * (path_limit + 1),
                            source_id="cold-path-native-buffer"):
            try:
                buffer = ctypes.create_string_buffer(path_limit + 1)
                if link is None:
                    if not _PATH_LIBC.getcwd(buffer, path_limit + 1):
                        raise DistributionIdentityError("cold cwd is unavailable or exceeds its path bound")
                    raw = buffer.value
                else:
                    if type(link) is not str or len(link) > path_limit:
                        raise DistributionIdentityError("cold link path exceeds its bound")
                    encoded = os.fsencode(link)
                    if len(encoded) > path_limit:
                        raise DistributionIdentityError("cold encoded link path exceeds its bound")
                    count = _PATH_LIBC.readlink(encoded, buffer, path_limit + 1)
                    if count < 0 or count > path_limit:
                        raise DistributionIdentityError("cold link changed or exceeds its path bound")
                    raw = buffer.raw[:count]
                result = os.fsdecode(raw)
                return result
            finally:
                buffer = encoded = raw = result = link = None
    finally:
        link = buffer = encoded = raw = result = context = budget = None


def _bounded_resolve_path(original, cwd, context, budget, path_limit):
    """Iterative real-path semantics with admitted links/components and frames."""
    resolved_location: str | None = None
    frames = frame = rest = name = candidate = target = None
    try:
        with budget.reserve(context, units=16 * (path_limit + 1), byte_count=16 * (path_limit + 1),
                            source_id="cold-path-component-scratch"), \
                budget.reserve(context, units=8, byte_count=0, source_id="cold-path-frames") as retained:
            try:
                if type(original) is not str or len(original) > path_limit:
                    raise DistributionIdentityError("cold discovery path exceeds its bound")
                resolved_location = "/" if original.startswith("/") else cwd
                frames, steps = [(original, 0, 0)], 0
                while frames:
                    rest, offset, charge = frames[-1]
                    if offset >= len(rest):
                        frames.pop()
                        rest = None
                        if charge:
                            retained.shrink(units=retained.units - charge - 4,
                                            byte_count=retained.byte_count - charge)
                        continue
                    steps += 1
                    context.check_limit("array_items", steps, source_id="cold-path-components")
                    context.emit("registry.resource", 1, source_id="cold-path-component", operation_path=())
                    end = rest.find("/", offset)
                    if end < 0: end = len(rest)
                    name = rest[offset:end]
                    frames[-1] = (rest, end + 1, charge)
                    if not name or name == ".": continue
                    if name == "..":
                        resolved_location = resolved_location.rpartition("/")[0] or "/"
                        continue
                    if len(resolved_location) + len(name) + (resolved_location != "/") > path_limit:
                        raise DistributionIdentityError("cold intermediate path exceeds its bound")
                    candidate = resolved_location.rstrip("/") + "/" + name
                    try:
                        metadata = os.lstat(candidate)
                    except OSError:
                        resolved_location = candidate
                        continue
                    if not stat.S_ISLNK(metadata.st_mode):
                        resolved_location = candidate
                        continue
                    target = _bounded_path_text(context, budget, path_limit, link=candidate)
                    if _SourceInstallationReadPlan._file_identity(os.lstat(candidate)) != \
                            _SourceInstallationReadPlan._file_identity(metadata):
                        raise DistributionIdentityError("cold discovery link changed during resolution")
                    context.check_limit("parse_depth", len(frames) + 1, source_id="cold-path-links")
                    charge = 4 * len(target)
                    retained.grow(units=charge + 4, byte_count=charge, source_id="cold-path-link-frame")
                    frames.append((target, 0, charge))
                    if target.startswith("/"): resolved_location = "/"
                    target = None
                return resolved_location
            finally:
                if frames is not None: frames.clear()
                original = cwd = frames = frame = rest = name = resolved_location = candidate = target = None
    finally:
        original = cwd = frames = frame = rest = name = resolved_location = candidate = target = context = budget = None


def _discovery_file_state(directory, relative, context, budget, retained, *, archive=False):
    """Read a discovery member's full bytes; retain only identity and hash."""
    retained.grow(units=96, byte_count=64, source_id="cold-discovery-file-state")
    descriptor: int | None = None
    chunk: bytes | None = None
    named = None
    try:
        named = os.stat(relative, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(named.st_mode):
            raise DistributionIdentityError("cold discovery symlink member is unsupported")
        descriptor = os.open(relative, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        before = os.fstat(descriptor)
        identity = _SourceInstallationReadPlan._file_identity(before)
        if identity != _SourceInstallationReadPlan._file_identity(named):
            raise DistributionIdentityError("cold discovery member changed before read")
        if stat.S_ISDIR(before.st_mode):
            return ("directory", _SourceInstallationReadPlan._root_identity(before))
        if not stat.S_ISREG(before.st_mode):
            raise DistributionIdentityError("cold discovery special member is unsupported")
        if not archive:
            context.check_limit("raw_document_bytes", before.st_size, source_id="cold-discovery-metadata")
        with budget.reserve(context, units=65, byte_count=65, source_id="cold-discovery-digest"):
            hashed, remaining = hashlib.sha256(), before.st_size
            while remaining:
                units, byte_count = budget.remaining(context)
                count = min(remaining, units, byte_count)
                if count <= 0:
                    context.check_limit("result_bytes", context.profile.limits["result_bytes"] + 1,
                                        source_id="cold-discovery-buffer")
                with budget.reserve(context, units=count, byte_count=count, source_id="cold-discovery-buffer"):
                    try:
                        chunk = os.read(descriptor, count)
                        if len(chunk) != count:
                            raise DistributionIdentityError("cold discovery member short read")
                        context.emit("digest.input_byte", count, source_id="cold-discovery", operation_path=())
                        hashed.update(chunk)
                    finally:
                        chunk = None
                remaining -= count
            if os.read(descriptor, 1):
                raise DistributionIdentityError("cold discovery member grew")
            if (identity != _SourceInstallationReadPlan._file_identity(os.fstat(descriptor))
                    or identity != _SourceInstallationReadPlan._file_identity(
                        os.stat(relative, dir_fd=directory, follow_symlinks=False))):
                raise DistributionIdentityError("cold discovery member changed during read")
            return ("file", identity, hashed.hexdigest())
    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
        # These are exactly the filesystem failures suppressed by the standard
        # PathDistribution reader. Preserve the failure and any known identity;
        # a later readable/earlier fallback is consequently a different proof.
        if descriptor is not None:
            raise DistributionIdentityError("cold discovery member changed after opening") from error
        return ("unavailable", error.errno, None if named is None else
                _SourceInstallationReadPlan._file_identity(named))
    finally:
        chunk = None
        if descriptor is not None:
            os.close(descriptor)


def _discovery_candidate_state(directory, name, context, budget, retained):
    """Hold a no-follow candidate descriptor throughout the fallback reads."""
    states: list[object] | None = None
    candidate = result = before = named = identity = None
    with budget.reserve(context, units=96, byte_count=0, source_id="cold-discovery-candidate-scratch"):
        try:
            named = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(named.st_mode):
                raise DistributionIdentityError("cold discovery symlink candidate is unsupported")
            flags = os.O_RDONLY
            if stat.S_ISDIR(named.st_mode):
                flags = getattr(os, "O_SEARCH", getattr(os, "O_PATH", os.O_RDONLY))
            try:
                candidate = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                    dir_fd=directory)
            except PermissionError as error:
                # Without directory search permission both child fallbacks are
                # unreadable; a regular file's child paths are non-directories.
                retained.grow(units=64, byte_count=0, source_id="cold-discovery-unreadable-candidate")
                identity = _SourceInstallationReadPlan._file_identity(named)
                if identity != _SourceInstallationReadPlan._file_identity(
                        os.stat(name, dir_fd=directory, follow_symlinks=False)):
                    raise DistributionIdentityError("cold discovery candidate changed during read") from error
                child_error = error.errno if stat.S_ISDIR(named.st_mode) else errno.ENOTDIR
                return (("unavailable", child_error, None), ("unavailable", child_error, None),
                        ("unavailable", error.errno, identity))
            before = os.fstat(candidate)
            identity = _SourceInstallationReadPlan._file_identity(before)
            if identity != _SourceInstallationReadPlan._file_identity(named):
                raise DistributionIdentityError("cold discovery candidate changed before read")
            if not (stat.S_ISDIR(before.st_mode) or stat.S_ISREG(before.st_mode)):
                raise DistributionIdentityError("cold discovery special candidate is unsupported")
            states = []
            for suffix in ("METADATA", "PKG-INFO"):
                states.append(_discovery_file_state(candidate, suffix, context, budget, retained))
            if stat.S_ISDIR(before.st_mode):
                states.append(_discovery_file_state(candidate, ".", context, budget, retained))
            else:
                states.append(_discovery_file_state(directory, name, context, budget, retained))
            if (identity != _SourceInstallationReadPlan._file_identity(os.fstat(candidate))
                    or identity != _SourceInstallationReadPlan._file_identity(
                        os.stat(name, dir_fd=directory, follow_symlinks=False))):
                raise DistributionIdentityError("cold discovery candidate changed during read")
            result = tuple(states)
            return result
        finally:
            states = result = before = named = identity = None
            if candidate is not None: os.close(candidate)


def _capture_installation_discovery(context, budget):
    """Fresh bounded path-based discovery proof, with no metadata parsing.

    Every directory entry is admitted and charged before filtering. Archive
    roots are hashed in full, including archives unrelated to this package.
    Metadata fallbacks retain absent, empty, directory and unreadable states.
    The initial semantic installation validation must bind this complete view.
    """
    paths: list[tuple[object, ...]] | None = None
    members: dict[str, object] | None = None
    result = entry = iterator = None
    descriptor = None
    with budget.reserve(context, units=64, byte_count=0, source_id="cold-discovery-control"), \
            budget.reserve(context, units=1, byte_count=0, source_id="cold-discovery-proof") as retained:
        try:
            _require_standard_discovery(context)
            if type(sys.path) not in (tuple, list):
                raise DistributionIdentityError("cold discovery path collection changed")
            context.check_limit("array_items", len(sys.path), source_id="cold-discovery-paths")
            retained.grow(units=len(sys.path) + 1, byte_count=0, source_id="cold-discovery-input-paths")
            input_paths = tuple(sys.path)
            # Filesystem-defined maxima bound temporary native path/DirEntry
            # representations before those operations return their actual text.
            path_limit = os.pathconf("/", "PC_PATH_MAX")
            if path_limit <= 0:
                raise DistributionIdentityError("cold discovery path bound is unavailable")
            paths = []
            entry_count = 0
            with budget.reserve(context, units=8 * path_limit, byte_count=8 * path_limit,
                                source_id="cold-discovery-path-scratch"):
                cwd = _bounded_path_text(context, budget, path_limit)
                retained.grow(units=4 * len(cwd) + 2, byte_count=4 * len(cwd), source_id="cold-discovery-cwd")
                for original in input_paths:
                    if type(original) is not str or len(original) > path_limit:
                        raise DistributionIdentityError("cold discovery path is unsupported")
                    resolved = _bounded_resolve_path(original, cwd, context, budget, path_limit)
                    context.emit("registry.resource", 1, source_id="cold-discovery-root", operation_path=())
                    retained.grow(units=4 * (len(original) + len(resolved)) + 64,
                                  byte_count=4 * (len(original) + len(resolved)),
                                  source_id="cold-discovery-root")
                    try:
                        metadata = os.stat(resolved, follow_symlinks=False)
                    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
                        paths.append((original, resolved, "unavailable", error.errno))
                        continue
                    if not stat.S_ISDIR(metadata.st_mode):
                        state = _discovery_file_state(None, resolved, context, budget, retained, archive=True)
                        paths.append((original, resolved, "archive", state))
                        state = None
                        continue
                    root_identity = _SourceInstallationReadPlan._root_identity(metadata)
                    root_metadata = _SourceInstallationReadPlan._file_identity(metadata)
                    try:
                        descriptor = os.open(resolved, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    except PermissionError as error:
                        if root_metadata != _SourceInstallationReadPlan._file_identity(
                                os.stat(resolved, follow_symlinks=False)):
                            raise DistributionIdentityError("cold discovery unavailable root changed") from error
                        # Standard FastPath cannot enumerate this directory;
                        # its archive fallback also cannot read a directory.
                        paths.append((original, resolved, "unavailable-directory", root_metadata, error.errno))
                        continue
                    if _SourceInstallationReadPlan._file_identity(os.fstat(descriptor)) != root_metadata:
                        raise DistributionIdentityError("cold discovery root descriptor changed")
                    name_limit = os.fpathconf(descriptor, "PC_NAME_MAX")
                    if name_limit <= 0:
                        raise DistributionIdentityError("cold discovery name bound is unavailable")
                    members: dict[str, object] | None = {}
                    iterator = os.scandir(descriptor)
                    try:
                        while True:
                            with budget.reserve(context, units=8 * name_limit + 32,
                                                byte_count=8 * name_limit + 32,
                                                source_id="cold-discovery-entry"):
                                try:
                                    entry = next(iterator)
                                except StopIteration:
                                    break
                                entry_count += 1
                                context.check_limit("array_items", entry_count, source_id="cold-discovery-entries")
                                context.emit("registry.resource", 1, source_id="cold-discovery-entry", operation_path=())
                                name = entry.name
                                low = name.lower()
                                if low.endswith((".dist-info", ".egg-info")) or (
                                        os.path.basename(original).lower().endswith(".egg") and low == "egg-info"):
                                    retained.grow(units=4 * len(name) + 16, byte_count=4 * len(name),
                                                  source_id="cold-discovery-candidate")
                                    members[name] = _discovery_candidate_state(
                                        descriptor, name, context, budget, retained)
                                entry = name = low = None
                    finally:
                        try:
                            iterator.close()
                        finally:
                            iterator = entry = None
                    if (root_metadata != _SourceInstallationReadPlan._file_identity(os.fstat(descriptor))
                            or root_metadata != _SourceInstallationReadPlan._file_identity(os.stat(resolved))):
                        raise DistributionIdentityError("cold discovery root changed")
                    os.close(descriptor)
                    descriptor = None
                    paths.append((original, resolved, "directory", root_metadata, members))
                    members = None
                if _bounded_path_text(context, budget, path_limit) != cwd:
                    raise DistributionIdentityError("cold discovery cwd topology changed")
                for original, resolved, kind, *details in paths:
                    if _bounded_resolve_path(original, cwd, context, budget, path_limit) != resolved:
                        raise DistributionIdentityError("cold discovery resolved topology changed")
                    try:
                        metadata = os.stat(resolved, follow_symlinks=False)
                    except (FileNotFoundError, NotADirectoryError, PermissionError) as error:
                        if kind != "unavailable" or error.errno != details[0]:
                            raise DistributionIdentityError("cold discovery unavailable topology changed") from error
                    else:
                        if kind == "unavailable-directory":
                            if details[0] != _SourceInstallationReadPlan._file_identity(metadata):
                                raise DistributionIdentityError("cold discovery unavailable root topology changed")
                            try:
                                descriptor = os.open(resolved,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                            except PermissionError as error:
                                if error.errno != details[1]:
                                    raise DistributionIdentityError("cold discovery unavailable root state changed") from error
                                continue
                            else:
                                os.close(descriptor)
                                descriptor = None
                                raise DistributionIdentityError("cold discovery root readability changed")
                        if (kind == "unavailable" or (kind == "directory") != stat.S_ISDIR(metadata.st_mode)
                                or (kind == "directory" and details[0] !=
                                    _SourceInstallationReadPlan._file_identity(metadata))
                                or (kind == "archive" and details[0][0] == "file" and details[0][1] !=
                                    _SourceInstallationReadPlan._file_identity(metadata))):
                            raise DistributionIdentityError("cold discovery root topology changed")
                if _bounded_path_text(context, budget, path_limit) != cwd:
                    raise DistributionIdentityError("cold discovery cwd topology changed")
            _require_standard_discovery(context)
            if (type(sys.path) not in (tuple, list) or len(sys.path) != len(input_paths)
                    or any(type(current) is not str or current != original
                           for current, original in zip(sys.path, input_paths))):
                raise DistributionIdentityError("cold discovery search path changed during capture")
            retained.grow(units=len(paths) + 4, byte_count=0, source_id="cold-discovery-result")
            result = (cwd, tuple(paths))
            retained.transfer(result)
            return result
        except BaseException as error:
            import traceback
            pending, seen = [error], set()
            while pending:
                cause = pending.pop()
                if cause is None or id(cause) in seen: continue
                seen.add(id(cause))
                traceback.clear_frames(cause.__traceback__)
                pending.extend((cause.__cause__, cause.__context__))
            raise
        finally:
            paths = result = members = entry = states = relative = None
            input_paths = original = resolved = cwd = name = low = state = root_identity = root_metadata = metadata = None
            details = None
            try:
                if iterator is not None: iterator.close()
            finally:
                if descriptor is not None: os.close(descriptor)


class _SourceInstallationReadPlan:
    """Previously validated identities; each use hashes their current bytes.

    Only immutable path/size/digest data is retained. A successful earlier
    check is never a substitute for the next complete current capture.
    """

    def __init__(self, source, control, source_metadata, control_metadata, files, key, attestation):
        self._source_path, self._control_path = str(source), str(control)
        self.source_identity = self._root_identity(source_metadata)
        self.control_identity = self._root_identity(control_metadata)
        self.files, self.key, self.attestation = files, key, attestation

    @property
    def source(self) -> pathlib.Path:
        return pathlib.Path(self._source_path)

    @property
    def control(self) -> pathlib.Path:
        return pathlib.Path(self._control_path)

    @staticmethod
    def _root_identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode)

    @staticmethod
    def _file_identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode,
                metadata.st_nlink, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)

    def _roots_current(self):
        if pathlib.Path(__file__).resolve(strict=True) != self.source / "core/graph_engineering/__init__.py":
            raise DistributionIdentityError("cold source loaded module identity changed")
        configured = sys._xoptions.get(_CONTROL_OPTION)
        if type(configured) is not str or pathlib.Path(configured) != self.control:
            raise DistributionIdentityError("cold source control option changed")
        prefix, explicit = _CONTROL_OPTION + "=", []
        arguments = tuple(getattr(sys, "orig_argv", ()))
        for index, argument in enumerate(arguments):
            if argument == "-X" and index + 1 < len(arguments) and arguments[index + 1].startswith(prefix):
                explicit.append(arguments[index + 1][len(prefix):])
            elif argument.startswith("-X" + prefix):
                explicit.append(argument[len("-X" + prefix):])
        if len(explicit) > 1 or explicit and explicit[0] != configured:
            raise DistributionIdentityError("cold source explicit control option changed")
        for path, expected in ((self.source, self.source_identity), (self.control, self.control_identity)):
            if path.resolve(strict=True) != path or self._root_identity(path.lstat()) != expected:
                raise DistributionIdentityError("cold source installation root changed")

    def _check_file(self, root, relative, expected, context, budget, *, private=False):
        """Hash one admitted descriptor without constructing a complete body."""
        size, digest = expected
        context.check_limit("raw_document_bytes", size, source_id=relative)
        descriptor = directory = None
        chunk = None
        try:
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            expected_root = self.control_identity if private else self.source_identity
            if self._root_identity(os.fstat(directory)) != expected_root:
                raise DistributionIdentityError("cold source root descriptor changed")
            parts = pathlib.PurePosixPath(relative).parts
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=directory)
                try:
                    metadata = os.fstat(child)
                    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != self.source_identity[2]
                            or stat.S_IMODE(metadata.st_mode) & 0o022):
                        raise DistributionIdentityError("cold source parent is untrusted")
                except BaseException:
                    os.close(child)
                    raise
                previous, directory = directory, child
                os.close(previous)
            named = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
            before = os.fstat(descriptor)
            mode = stat.S_IMODE(before.st_mode)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != self.source_identity[2]
                    or (mode != 0o600 if private else mode & 0o022)
                    or self._file_identity(named) != self._file_identity(before)
                    or before.st_size != size):
                raise DistributionIdentityError("cold source member identity or size changed")
            context.check_limit("raw_document_bytes", before.st_size, source_id=relative)
            hashed, remaining = hashlib.sha256(), size
            with budget.reserve(context, units=65, byte_count=65, source_id="cold-source-digest"):
                while remaining:
                    units, available = budget.remaining(context)
                    count = min(remaining, units, available)
                    if count <= 0:
                        context.check_limit("result_bytes", context.profile.limits["result_bytes"] + 1,
                                            source_id=relative)
                    with budget.reserve(context, units=count, byte_count=count, source_id=relative):
                        try:
                            chunk = os.read(descriptor, count)
                            if len(chunk) != count:
                                raise DistributionIdentityError("cold source member short read")
                            context.emit("digest.input_byte", count, source_id=relative, operation_path=())
                            hashed.update(chunk)
                        finally:
                            chunk = None
                    remaining -= count
                if os.read(descriptor, 1):
                    raise DistributionIdentityError("cold source member grew")
                if (self._file_identity(os.fstat(descriptor)) != self._file_identity(before)
                        or self._file_identity(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False))
                        != self._file_identity(before)
                        or self._file_identity((root / relative).lstat()) != self._file_identity(before)
                        or not hmac.compare_digest(hashed.hexdigest(), digest)):
                    raise DistributionIdentityError("cold source member changed")
        except OSError as error:
            raise DistributionIdentityError("cold source member is unavailable") from error
        finally:
            try:
                if descriptor is not None: os.close(descriptor)
            finally:
                if directory is not None: os.close(directory)

    def require_current(self, context: object, budget: object) -> None:
        budget._require_active()
        if tuple(name for name, _size, _digest in self.files) != _SOURCE_FILES:
            raise DistributionIdentityError("cold source installation membership changed")
        context.check_limit("array_items", len(self.files), source_id="cold-source-members")
        # The compact retained plan is adopted here until the caller adopts
        # its complete factory cache for the full cold operation.
        size = sum(len(name.encode("utf-8")) + len(digest) + 8 for name, _size, digest in self.files)
        with budget.reserve(context, units=size + 4 * len(self.files), byte_count=size,
                            source_id="cold-source-read-plan"):
            self._roots_current()
            lock = os.open(self.control / _CONTROL_LOCK,
                           os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
            locked = False
            try:
                metadata = os.fstat(lock)
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.control_identity[2]
                        or metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) != 0o600
                        or self._file_identity((self.control / _CONTROL_LOCK).lstat()) != self._file_identity(metadata)):
                    raise DistributionIdentityError("cold source installation lock changed")
                fcntl.flock(lock, fcntl.LOCK_SH)
                locked = True
                for _pass in range(2):
                    self._check_file(self.control, _ATTESTATION_KEY, self.key, context, budget, private=True)
                    self._check_file(self.control, _ATTESTATION_FILE, self.attestation, context, budget, private=True)
                    for name, count, digest in self.files:
                        self._check_file(self.source, name, (count, digest), context, budget)
                    self._roots_current()
                    if self._file_identity((self.control / _CONTROL_LOCK).lstat()) != self._file_identity(metadata):
                        raise DistributionIdentityError("cold source installation lock changed")
                self._check_file(self.control, _ATTESTATION_KEY, self.key, context, budget, private=True)
                self._check_file(self.control, _ATTESTATION_FILE, self.attestation, context, budget, private=True)
            finally:
                try:
                    if locked: fcntl.flock(lock, fcntl.LOCK_UN)
                finally:
                    os.close(lock)


class _WheelInstallationReadPlan:
    """Closed data from a validated wheel; cold use only streams current bytes."""

    def __init__(self, root, *, archive, names):
        self._root_path = str(root)
        self.archive = archive
        self.root_identity = _SourceInstallationReadPlan._root_identity(root.lstat())
        self.module_origin = __file__
        self.names = names
        self.discovery = self.members = None

    def _capture_members(self, context, budget):
        states: list[object] | None = None
        descriptor = child = result = state = parts = None
        try:
            with budget.reserve(context, units=96, byte_count=0, source_id="cold-wheel-member-control"), \
                    budget.reserve(context, units=len(self.names) + 2, byte_count=0,
                                   source_id="cold-wheel-members") as retained:
                try:
                    context.check_limit("array_items", len(self.names), source_id="cold-wheel-member-count")
                    path_limit = os.pathconf("/", "PC_PATH_MAX")
                    with budget.reserve(context, units=8 * path_limit, byte_count=8 * path_limit,
                                        source_id="cold-wheel-member-paths"):
                        if (type(__file__) is not str or len(__file__) > path_limit
                                or __file__ != self.module_origin):
                            raise DistributionIdentityError("cold wheel loaded module changed")
                        if _SourceInstallationReadPlan._root_identity(os.lstat(self._root_path)) != self.root_identity:
                            raise DistributionIdentityError("cold wheel root changed")
                        if self.archive:
                            state = _discovery_file_state(None, self._root_path, context, budget, retained, archive=True)
                            result = (state,)
                        else:
                            states = []
                            for name in self.names:
                                if len(name) > path_limit:
                                    raise DistributionIdentityError("cold wheel member path is over limit")
                                descriptor = os.open(self._root_path,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                                if _SourceInstallationReadPlan._root_identity(os.fstat(descriptor)) != self.root_identity:
                                    raise DistributionIdentityError("cold wheel root descriptor changed")
                                parts = name.split("/")
                                for part in parts[:-1]:
                                    child = os.open(part,
                                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=descriptor)
                                    previous, descriptor, child = descriptor, child, None
                                    os.close(previous)
                                state = _discovery_file_state(descriptor, parts[-1], context, budget, retained)
                                if state[0] != "file" or state[1] != _SourceInstallationReadPlan._file_identity(
                                        os.lstat(os.path.join(self._root_path, name))):
                                    raise DistributionIdentityError("cold wheel member path changed")
                                states.append(state)
                                os.close(descriptor)
                                descriptor = state = parts = None
                            result = tuple(states)
                        if _SourceInstallationReadPlan._root_identity(os.lstat(self._root_path)) != self.root_identity:
                            raise DistributionIdentityError("cold wheel root changed during capture")
                        retained.transfer(result)
                        return result
                except BaseException as error:
                    import traceback
                    pending, seen = [error], set()
                    while pending:
                        cause = pending.pop()
                        if cause is None or id(cause) in seen: continue
                        seen.add(id(cause))
                        traceback.clear_frames(cause.__traceback__)
                        pending.extend((cause.__cause__, cause.__context__))
                    raise
                finally:
                    result = states = state = parts = self = None
                    try:
                        if child is not None: os.close(child)
                    finally:
                        if descriptor is not None: os.close(descriptor)
        finally:
            self = result = states = state = parts = name = part = context = budget = None

    def require_current(self, context: object, budget: object) -> None:
        proofs: list[object] | None = None
        try:
            budget._require_active()
            with budget.reserve(context, units=8, byte_count=0, source_id="cold-wheel-proof-control"):
                proofs = []
                try:
                    # Fixed-depth proofs already own all payloads. Keep both
                    # complete pairs charged through their direct comparison.
                    for attempt in range(2):
                        proofs.append(_capture_installation_discovery(context, budget))
                        proofs.append(self._capture_members(context, budget))
                        if proofs[-2] != self.discovery or proofs[-1] != self.members:
                            raise DistributionIdentityError("cold wheel discovery or member changed")
                        if attempt and (proofs[-2] != proofs[0] or proofs[-1] != proofs[1]):
                            raise DistributionIdentityError("cold wheel changed between captures")
                finally:
                    # pop removes the caller's last temporary reference before
                    # the owner releases its matching retained allocation.
                    while proofs:
                        budget.release_projection(proofs.pop())
        except BaseException as error:
            import traceback
            pending, seen = [error], set()
            while pending:
                cause = pending.pop()
                if cause is None or id(cause) in seen: continue
                seen.add(id(cause))
                traceback.clear_frames(cause.__traceback__)
                pending.extend((cause.__cause__, cause.__context__))
            raise
        finally:
            self = proofs = context = budget = None


def _release_operations_wheel_read_plan(resources, context, budget, *, category_resources=None):
    """Bracket ordinary bootstrap validation with fresh bounded physical proofs.

    Called only while constructing the installed factory, before a cold caller
    can receive it. Legacy bootstrap parsing stays outside the bound read owner;
    the resulting closed plan is adopted with the factory at cold entry.
    """
    try:
        _require_standard_discovery(context)
    except (DistributionIdentityError, AttributeError, TypeError):
        return None
    first_discovery = first_members = after_discovery = after_members = None
    try:
        with budget.bind():
            first_discovery = _capture_installation_discovery(context, budget)
        # Force the same standard provider to discover against current directory
        # entries, including changes that preserved an earlier directory mtime.
        importlib.metadata.MetadataPathFinder.invalidate_caches()
        matches = _matching_installed_distributions()
        if len(matches) != 1 or type(matches[0]) is not importlib.metadata.PathDistribution:
            raise DistributionIdentityError("cold wheel distribution is not unique or standard")
        distribution = matches[0]
        location = distribution.locate_file("")
        archive_name = getattr(getattr(location, "root", None), "filename", None)
        archive = type(archive_name) is str
        root = pathlib.Path(archive_name if archive else location).resolve(strict=True)
        fixed, schemas, protected = _release_operations_locations(resources[0], location_kind="resource")
        category_names = () if category_resources is None else _category_policy_locations(
            resources[0], location_kind="resource")
        if category_resources is not None and category_resources[0] != resources[0]:
            raise DistributionIdentityError("cold category and release provenance differ")
        record_snapshot = distribution.read_text("RECORD")
        if type(record_snapshot) is not str:
            raise DistributionIdentityError("cold wheel selected RECORD is absent")
        # Derive every member from this exact snapshot. A separate files
        # property read can observe a transient RECORD and omit an adapter even
        # when both surrounding physical reads see the original bytes.
        records = []
        try:
            for row in csv.reader(record_snapshot.splitlines()):
                if not 1 <= len(row) <= 3:
                    raise ValueError("invalid RECORD row")
                name, digest, size = (*row, *(None for _ in range(3 - len(row))))
                item = importlib.metadata.PackagePath(name)
                item.hash = importlib.metadata.FileHash(digest) if digest else None
                item.size = int(size) if size else None
                item.dist = distribution
                records.append(item)
        except (csv.Error, TypeError, ValueError) as error:
            raise DistributionIdentityError("cold wheel RECORD is malformed") from error
        record_paths = tuple(str(item) for item in records if str(item).endswith(".dist-info/RECORD"))
        if len(record_paths) != 1:
            raise DistributionIdentityError("cold wheel RECORD is not unique")
        names = tuple(sorted(set((record_paths[0], _MODULE_RESOURCE, _PROVENANCE_RESOURCE,
            *fixed, *schemas, *protected, *category_names, *_profile_coverage_protected_resources(resources[0]),
            *(str(item) for item in records if str(item).startswith("graph_engineering/adapters/")
              and str(item).endswith(".py"))))))
        for name in names:
            if (not name or "\\" in name or pathlib.PurePosixPath(name).is_absolute()
                    or any(part in ("", ".", "..") for part in name.split("/"))):
                raise DistributionIdentityError("cold wheel member path is unsafe")
        plan = _WheelInstallationReadPlan(root, archive=archive, names=names)
        with budget.bind():
            first_members = plan._capture_members(context, budget)
        current = _release_operations_installation_resources()
        if len(current) != len(resources) or any(left != right for left, right in zip(current, resources)):
            raise DistributionIdentityError("cold wheel plan differs from factory inputs")
        if category_resources is not None and _category_policy_installation_resources() != category_resources:
            raise DistributionIdentityError("cold wheel category inputs changed during plan issuance")
        if not archive:
            for name, state in zip(names, first_members, strict=True):
                if name == record_paths[0]:
                    if hashlib.sha256(record_snapshot.encode("utf-8")).hexdigest() != state[2]:
                        raise DistributionIdentityError("cold wheel selected RECORD changed")
                    continue
                body = _record_resource(distribution, root, None, name)
                entries = tuple(item for item in records if str(item) == name)
                if (len(entries) != 1 or entries[0].size != len(body)
                        or len(body) != state[1][5] or hashlib.sha256(body).hexdigest() != state[2]):
                    raise DistributionIdentityError("cold wheel member differs from its RECORD")
                if name in category_names and body != category_resources[category_names.index(name) + 1]:
                    raise DistributionIdentityError("cold wheel category member differs from factory inputs")
        with budget.bind():
            after_discovery = _capture_installation_discovery(context, budget)
            after_members = plan._capture_members(context, budget)
            if after_discovery != first_discovery or after_members != first_members:
                raise DistributionIdentityError("cold wheel changed during plan issuance")
        plan.discovery, plan.members = first_discovery, first_members
        return plan
    finally:
        for value in (first_discovery, first_members, after_discovery, after_members):
            if value is not None: budget.release_projection(value)


def _release_operations_read_plan(resources, *, category_resources=None):
    try:
        module_path = pathlib.Path(__file__).resolve(strict=True)
    except OSError:
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        return None
    plan = _validate_source_checkout_attestation(source_root, _capture=True)
    fixed, schemas, protected = _release_operations_locations(resources[0], location_kind="source")
    expected = {name: (size, digest) for name, size, digest in plan.files}
    for name, body in zip(("pyproject.toml", *fixed, *schemas, *protected), resources, strict=True):
        if expected.get(name) != (len(body), hashlib.sha256(body).hexdigest()):
            raise DistributionIdentityError("cold installation plan differs from factory inputs")
    if category_resources is not None:
        names = ("pyproject.toml", *_category_policy_locations(resources[0], location_kind="source"))
        for name, body in zip(names, category_resources, strict=True):
            if expected.get(name) != (len(body), hashlib.sha256(body).hexdigest()):
                raise DistributionIdentityError("cold category plan differs from factory inputs")
    return plan


def _release_operations_installation_resources() -> tuple[bytes, ...]:
    """Re-read the complete current ADR-0009 installed/source projection."""

    try:
        module_path = pathlib.Path(__file__).resolve(strict=True)
    except OSError:
        # A module inside a validated wheel archive has no filesystem member
        # path. Its resources must still pass the current distribution RECORD.
        module_path = None
    source_root = None if module_path is None else _source_checkout_root(module_path)
    if source_root is None:
        # Verify the distribution around one complete capture. Each member
        # still gets its own current RECORD/path/hash checks; no cached bytes
        # or earlier validation stand in for a current installation read.
        _validate_distribution_identity()
        distributions = _matching_installed_distributions()
        if len(distributions) != 1:
            raise DistributionIdentityError("release distribution identity is not unique")
        distribution = distributions[0]
        root_location = distribution.locate_file("")
        archive_name = getattr(getattr(root_location, "root", None), "filename", None)
        archive_prefix = getattr(root_location, "at", None)
        archive = (pathlib.Path(archive_name).resolve(strict=True)
                   if type(archive_name) is str and type(archive_prefix) is str else None)
        root = pathlib.Path(root_location).resolve(strict=True) if archive is None else None
        identity = None if archive is None else _archive_identity(archive)
        record = distribution.read_text("RECORD")
        if type(record) is not str:
            raise DistributionIdentityError("release distribution RECORD is absent")
        def read(resource: str) -> bytes:
            return _record_resource(distribution, root, archive, resource)

        provenance = read(_PROVENANCE_RESOURCE)
        fixed, schemas, protected = _release_operations_locations(
            provenance, location_kind="resource",
        )
        locations = (*fixed, *schemas, *protected)
        if archive is not None:
            _validate_archive_resource_uniqueness(distribution, archive,
                (_PROVENANCE_RESOURCE, *locations))
        bodies = tuple(read(item) for item in locations)
        _validate_distribution_identity()
        if (record != distribution.read_text("RECORD") or read(_PROVENANCE_RESOURCE) != provenance
                or archive is not None and _archive_identity(archive) != identity):
            raise DistributionIdentityError("release distribution changed during capture")
        return provenance, *bodies
    _validate_source_checkout_attestation(source_root)
    owner = os.lstat(source_root).st_uid
    provenance = _attested_source_member(source_root, "pyproject.toml", owner)
    fixed, schemas, protected = _release_operations_locations(
        provenance, location_kind="source",
    )
    locations = (*fixed, *schemas, *protected)
    if any(relative not in _SOURCE_FILES for relative in locations):
        raise DistributionIdentityError(
            "release operations source is outside the installation attestation"
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
