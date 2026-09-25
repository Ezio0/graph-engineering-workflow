"""WP-08 Slice 4 production-coverage acceptance fixtures."""

from __future__ import annotations

import copy
import hashlib
import importlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import warnings
import zipfile
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from types import MappingProxyType

from graph_engineering.core.contracts.immutable import thaw
from tests.support import wp08_category_execution as category


PASS_TEST_ID = "GEW-PRO-NEW-FEATURE-NORMAL-P"
REJECT_TEST_ID = "GEW-PRO-NEW-FEATURE-NORMAL-R"
ROLLBACK_PASS_TEST_ID = "GEW-PRO-NEW-FEATURE-ROLLBACK-P"
ROLLBACK_REJECT_TEST_ID = "GEW-PRO-NEW-FEATURE-ROLLBACK-R"
SCAFFOLD_PASS_TEST_ID = "GEW-PSC-NEW-FEATURE-SCAFFOLD-P"
SCAFFOLD_REJECT_TEST_ID = "GEW-PSC-NEW-FEATURE-SCAFFOLD-R"
EXISTING_FEATURE_PASS_TEST_ID = "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE-P"
EXISTING_FEATURE_REJECT_TEST_ID = "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE-R"
BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID = (
    "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE-P"
)
BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID = (
    "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE-R"
)
BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID = (
    "GEW-PSC-BUG-FIX-FALSE-REPRODUCTION-P"
)
BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID = (
    "GEW-PSC-BUG-FIX-FALSE-REPRODUCTION-R"
)
BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID = (
    "GEW-PSC-BUG-FIX-REGRESSION-BOUNDARY-P"
)
BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID = (
    "GEW-PSC-BUG-FIX-REGRESSION-BOUNDARY-R"
)
HOTFIX_MINIMAL_PATCH_PASS_TEST_ID = "GEW-PSC-HOTFIX-MINIMAL-PATCH-P"
HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID = "GEW-PSC-HOTFIX-MINIMAL-PATCH-R"
PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID = (
    "GEW-PSC-PERFORMANCE-STABLE-BASELINE-P"
)
PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID = (
    "GEW-PSC-PERFORMANCE-STABLE-BASELINE-R"
)
PERFORMANCE_REMAINING_SCENARIO_IDS = (
    "correctness-regression", "noise-outlier",
)
PERFORMANCE_REMAINING_SCENARIO_TEST_IDS = tuple(
    f"GEW-PSC-PERFORMANCE-{scenario_id.upper()}-{disposition}"
    for scenario_id in PERFORMANCE_REMAINING_SCENARIO_IDS
    for disposition in ("P", "R")
)
NEW_FEATURE_MULTI_TARGET_SCENARIO_ID = "multi-target"
NEW_FEATURE_MULTI_TARGET_PASS_TEST_ID = "GEW-PSC-NEW-FEATURE-MULTI-TARGET-P"
NEW_FEATURE_MULTI_TARGET_REJECT_TEST_ID = "GEW-PSC-NEW-FEATURE-MULTI-TARGET-R"
NEW_FEATURE_MULTI_TARGET_BOUNDARY_CASE_ID = NEW_FEATURE_MULTI_TARGET_PASS_TEST_ID
HOTFIX_GUARDED_SCENARIO_IDS = ("emergency-baseline", "production-like-gate")
REFACTOR_SCENARIO_IDS = (
    "architecture-invariant",
    "behavior-characterization",
    "nonfunctional-target",
)
INCIDENT_SCENARIO_IDS = (
    "containment",
    "detection",
    "recovery",
    "unknown-effects",
)
SCENARIO_TRUTH_SCENARIO_IDS = (
    NEW_FEATURE_MULTI_TARGET_SCENARIO_ID,
    *HOTFIX_GUARDED_SCENARIO_IDS,
    *REFACTOR_SCENARIO_IDS,
    *INCIDENT_SCENARIO_IDS,
)
SCENARIO_TRUTH_BOUNDARY_CASE_IDS = (
    NEW_FEATURE_MULTI_TARGET_BOUNDARY_CASE_ID,
    *(
        f"GEW-PSC-HOTFIX-{scenario.upper()}-P"
        for scenario in HOTFIX_GUARDED_SCENARIO_IDS
    ),
    *(
        f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-P"
        for scenario in REFACTOR_SCENARIO_IDS
    ),
    *(
        f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-P"
        for scenario in INCIDENT_SCENARIO_IDS
    ),
)
DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID = (
    "GEW-PSC-DEPENDENCY-SECURITY-VULNERABLE-GRAPH-P"
)
DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID = (
    "GEW-PSC-DEPENDENCY-SECURITY-VULNERABLE-GRAPH-R"
)
DEPENDENCY_GRAPH_SCENARIO_IDS = (
    "fix-unavailable", "transitive-dependency",
)
DEPENDENCY_GRAPH_SCENARIO_TEST_IDS = tuple(
    f"GEW-PSC-DEPENDENCY-SECURITY-{scenario_id.upper()}-{disposition}"
    for scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
    for disposition in ("P", "R")
)
MIGRATION_SCENARIO_IDS = (
    "backward", "crash-window", "forward", "partial-data",
)
MIGRATION_SCENARIO_TEST_IDS = tuple(
    f"GEW-PSC-MIGRATION-{scenario_id.upper()}-{disposition}"
    for scenario_id in MIGRATION_SCENARIO_IDS
    for disposition in ("P", "R")
)
REAL_E2E_PASS_TEST_ID = "GEW-PRO-NEW-FEATURE-REAL-E2E-P"
REAL_E2E_REJECT_TEST_ID = "GEW-PRO-NEW-FEATURE-REAL-E2E-R"
REAL_E2E_FIXTURE_ROOT = category.ROOT / "tests/fixtures"
BUG_FIX_COLUMNS = (
    "normal",
    "boundary",
    "revise",
    "authority",
    "drift",
    "invalidation",
    "recovery",
    "artifacts",
    "review",
    "target",
    "rollback",
    "real-e2e",
)
EXPECTED_ORACLE_MANDATORY_PROFILES = (
    ("ORA-PROFILE-BUG-FIX", "bug-fix"),
    ("ORA-PROFILE-DEPENDENCY-SECURITY", "dependency-security"),
    ("ORA-PROFILE-HOTFIX", "hotfix"),
    ("ORA-PROFILE-INCIDENT-RESPONSE", "incident-response"),
    ("ORA-PROFILE-MIGRATION", "migration"),
    ("ORA-PROFILE-NEW-FEATURE", "new-feature"),
    ("ORA-PROFILE-PERFORMANCE", "performance"),
    ("ORA-PROFILE-REFACTOR-DEBT", "refactor-debt"),
)
EXPECTED_ORACLE_SCENARIOS = (
    (
        "ORA-PROFILE-BUG-FIX",
        "bug-fix",
        "scenario",
        "boundary",
        "false-reproduction",
    ),
    (
        "ORA-PROFILE-BUG-FIX",
        "bug-fix",
        "scenario",
        "boundary",
        "regression-boundary",
    ),
    (
        "ORA-PROFILE-BUG-FIX",
        "bug-fix",
        "scenario",
        "boundary",
        "reproducible-failure",
    ),
    (
        "ORA-PROFILE-DEPENDENCY-SECURITY",
        "dependency-security",
        "scenario",
        "boundary",
        "vulnerable-graph",
    ),
    *(
        (
            "ORA-PROFILE-DEPENDENCY-SECURITY",
            "dependency-security",
            "scenario",
            "boundary",
            scenario_id,
        )
        for scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
    ),
    (
        "ORA-PROFILE-HOTFIX",
        "hotfix",
        "scenario",
        "boundary",
        "minimal-patch",
    ),
    (
        "ORA-PROFILE-NEW-FEATURE",
        "new-feature",
        "scenario",
        "boundary",
        "existing-feature",
    ),
    (
        "ORA-PROFILE-NEW-FEATURE",
        "new-feature",
        "scenario",
        "boundary",
        "scaffold",
    ),
    (
        "ORA-PROFILE-NEW-FEATURE",
        "new-feature",
        "scenario",
        "boundary",
        "multi-target",
    ),
    (
        "ORA-PROFILE-PERFORMANCE",
        "performance",
        "scenario",
        "boundary",
        "stable-baseline",
    ),
    *(
        (
            "ORA-PROFILE-PERFORMANCE",
            "performance",
            "scenario",
            "boundary",
            scenario_id,
        )
        for scenario_id in PERFORMANCE_REMAINING_SCENARIO_IDS
    ),
    *(
        (
            "ORA-PROFILE-MIGRATION",
            "migration",
            "scenario",
            "boundary",
            scenario_id,
        )
        for scenario_id in MIGRATION_SCENARIO_IDS
    ),
    *(
        (
            "ORA-PROFILE-REFACTOR-DEBT",
            "refactor-debt",
            "scenario",
            "boundary",
            scenario_id,
        )
        for scenario_id in REFACTOR_SCENARIO_IDS
    ),
    *(
        (
            "ORA-PROFILE-INCIDENT-RESPONSE",
            "incident-response",
            "scenario",
            "boundary",
            scenario_id,
        )
        for scenario_id in INCIDENT_SCENARIO_IDS
    ),
)
SCAFFOLD_SCENARIO_ID = "scaffold"
SCAFFOLD_BOUNDARY_CASE_ID = SCAFFOLD_PASS_TEST_ID
EXISTING_FEATURE_SCENARIO_ID = "existing-feature"
EXISTING_FEATURE_BOUNDARY_CASE_ID = EXISTING_FEATURE_PASS_TEST_ID
BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID = "reproducible-failure"
BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID = (
    BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
)
BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID = "false-reproduction"
BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID = (
    BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID
)
BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID = "regression-boundary"
BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID = (
    BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID
)
HOTFIX_MINIMAL_PATCH_SCENARIO_ID = "minimal-patch"
HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID = HOTFIX_MINIMAL_PATCH_PASS_TEST_ID
PERFORMANCE_STABLE_BASELINE_SCENARIO_ID = "stable-baseline"
PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID = (
    PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID
)
DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID = "vulnerable-graph"
DEPENDENCY_SECURITY_VULNERABLE_GRAPH_BOUNDARY_CASE_ID = (
    DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID
)
NEW_MANDATORY_COLUMNS = (
    "boundary",
    "revise",
    "authority",
    "drift",
    "invalidation",
    "recovery",
    "artifacts",
    "review",
    "target",
)


def expected_oracle_binding_identities(
    *, selector: str | None = None,
) -> tuple[tuple[str, str, str, str, str | None], ...]:
    """Return an independent checkpoint closure; default to current P2d."""

    if selector == P3_CUMULATIVE274_R1_SELECTOR:
        return _c274_oracle_identities()
    checkpoint = (
        _P2D_CURRENT_CHECKPOINT
        if selector is None
        else _cumulative_checkpoint(selector)
    )
    scenarios = EXPECTED_ORACLE_SCENARIOS
    if selector is None:
        scenarios += tuple(
            ("ORA-PROFILE-HOTFIX", "hotfix", "scenario", "boundary", scenario_id)
            for scenario_id in HOTFIX_GUARDED_SCENARIO_IDS
        )
    elif selector == P2B_CUMULATIVE_R1_SELECTOR:
        scenarios = tuple(
            item
            for item in scenarios
            if item[1] not in {"refactor-debt", "incident-response"}
            or item[2] != "scenario"
        )
        scenarios += tuple(
            ("ORA-PROFILE-HOTFIX", "hotfix", "scenario", "boundary", scenario_id)
            for scenario_id in HOTFIX_GUARDED_SCENARIO_IDS
        )
    elif selector == P2A_CUMULATIVE_R2_SELECTOR:
        scenarios = tuple(
            item
            for item in scenarios
            if not (
                (item[1] == "refactor-debt" and item[2] == "scenario")
                or (
                    item[1] == "incident-response"
                    and item[2] == "scenario"
                )
                or (
                    item[1] == "hotfix"
                    and item[4] in HOTFIX_GUARDED_SCENARIO_IDS
                )
            )
        )

    identities = tuple(sorted((
        *(
            (oracle_id, profile_id, "mandatory", column, None)
            for oracle_id, profile_id in EXPECTED_ORACLE_MANDATORY_PROFILES
            for column in BUG_FIX_COLUMNS
        ),
        *scenarios,
    )))
    if (
        len(identities) != checkpoint.oracle_bindings
        or len(set(identities)) != checkpoint.oracle_bindings
    ):
        raise AssertionError("expected Profile coverage oracle closure is not exact")
    return identities


def coverage_task_id(test_id: str) -> str:
    """Return the frozen deterministic task identity for one coverage binding."""

    if type(test_id) is not str or not test_id.startswith("GEW-"):
        raise AssertionError("coverage stable ID is invalid")
    return "task:wp08-coverage:" + test_id.lower()


def mandatory_test_id(column: str, disposition: str) -> str:
    if column not in NEW_MANDATORY_COLUMNS or disposition not in {"P", "R"}:
        raise AssertionError("unknown new-feature mandatory coverage binding")
    return f"GEW-PRO-NEW-FEATURE-{column.upper()}-{disposition}"


def bug_fix_test_id(column: str, disposition: str) -> str:
    if column not in BUG_FIX_COLUMNS or disposition not in {"P", "R"}:
        raise AssertionError("unknown bug-fix mandatory coverage binding")
    return f"GEW-PRO-BUG-FIX-{column.upper()}-{disposition}"


def approved_mandatory_columns() -> tuple[str, ...]:
    """Load the exact installed Profile mandatory-column set."""

    document = category.load_json(
        category.ROOT / "config/profiles/profile-coverage-policy-v1.json"
    )
    columns = document.get("profile_column_ids")
    if (
        type(columns) is not list
        or not columns
        or any(type(item) is not str or not item for item in columns)
        or len(columns) != len(set(columns))
    ):
        raise AssertionError("approved Profile mandatory columns are invalid")
    return tuple(columns)


def profile_mandatory_test_id(
    profile_id: str,
    column: str,
    disposition: str,
) -> str:
    """Resolve one exact mandatory ID from approved config closure."""

    if (
        profile_id not in category.PROFILE_IDS
        or column not in approved_mandatory_columns()
        or disposition not in {"P", "R"}
    ):
        raise AssertionError("unknown Profile mandatory coverage binding")
    test_id = f"GEW-PRO-{profile_id.upper()}-{column.upper()}-{disposition}"
    matrix = category.load_json(category.SUPPORT_MATRIX_PATH)
    case_ids = matrix.get("profile_case_ids")
    if type(case_ids) is not list or test_id not in case_ids:
        raise AssertionError("Profile mandatory coverage binding is not approved")
    return test_id


def hotfix_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("hotfix", column, disposition)


def refactor_debt_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("refactor-debt", column, disposition)


def incident_response_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("incident-response", column, disposition)


def migration_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("migration", column, disposition)


def dependency_security_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("dependency-security", column, disposition)


def performance_test_id(column: str, disposition: str) -> str:
    return profile_mandatory_test_id("performance", column, disposition)


def real_e2e_profile_fixture(profile_id: str) -> dict[str, object] | None:
    if profile_id not in {
        "dependency-security", "hotfix", "incident-response", "migration",
        "performance", "refactor-debt",
    }:
        return None
    value = category.load_json(
        REAL_E2E_FIXTURE_ROOT / f"wp08-{profile_id}-real-e2e-v1.json"
    )
    if set(value) != {
        "schema_version", "profile_id", "artifact_name", "baseline_document",
        "desired_document", "foreign_document",
    } or any(
        type(value[name]) is not dict
        for name in ("baseline_document", "desired_document", "foreign_document")
    ) or value["schema_version"] != "1.0.0" or value["profile_id"] != profile_id:
        raise AssertionError("real-E2E Profile fixture is not exact")
    return copy.deepcopy(value)


def real_e2e_candidate(
    *, accepted: bool, profile_id: str = "new-feature", task_id: str | None = None,
) -> dict[str, object]:
    """Return the frozen selector for one approved real-target binding."""

    if (
        profile_id not in {"new-feature", "bug-fix"}
        and real_e2e_profile_fixture(profile_id) is None
    ):
        raise AssertionError("unknown real-E2E Profile fixture")
    candidate = category.candidate_document(profile_id, "real-e2e")
    candidate["request_id"] = (
        f"wp08-s4:{profile_id}:real-e2e:pass"
        if accepted
        else f"wp08-s4:{profile_id}:real-e2e:stale-expected-ref"
    )
    candidate["target_id"] = "target-project"
    candidate["task_id"] = (
        coverage_task_id(profile_mandatory_test_id(
            profile_id, "real-e2e", "P" if accepted else "R",
        ))
        if task_id is None
        else task_id
    )
    return candidate


def coverage_request_digest(candidate: dict[str, object]) -> str:
    """Digest one exact rejection request in the production coverage domain."""

    from graph_engineering.core.profile_coverage import profile_coverage_digest

    return profile_coverage_digest(
        candidate,
        contract="profile-coverage-request",
        schema="profile-coverage-request",
    )


class MissingProfileCoverageContract(AssertionError):
    """The production-backed Profile coverage surface does not exist yet."""


@dataclass(slots=True)
class SerialCoverageExecution:
    """One main-thread execution awaiting observation and issuance."""

    test_id: str
    profile_id: str
    column_id: str
    disposition: str
    application: object
    authority: object
    execution: object
    probe: category.ProductionCategoryProbe
    target: object
    candidate: dict[str, object]
    state_before: object
    state_after: object
    dependency_security_context: object | None = None
    dependency_reopen_authority: object | None = None
    dependency_reopen_seal: object | None = None
    performance_context: object | None = None
    migration_context: object | None = None
    migration_rehearsal_projection: object | None = None
    scenario_truth_context: object | None = None
    release_operations_context: object | None = None
    release_operations_reader: object | None = None
    binding_lifecycle: object | None = None
    private_repository_root: object | None = None
    private_action_root: object | None = None
    private_shared_runtime: object | None = None
    private_real_e2e_root: object | None = None
    private_real_e2e_handle: object | None = None

    @staticmethod
    def _lifecycle_json(value: object) -> object:
        if type(value) is bytes:
            return {
                "bytes_sha256": hashlib.sha256(value).hexdigest(),
                "length": len(value),
            }
        if isinstance(value, dict):
            return {
                str(key): SerialCoverageExecution._lifecycle_json(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [
                SerialCoverageExecution._lifecycle_json(item) for item in value
            ]
        if value is None or type(value) in {str, int, bool}:
            return value
        raise AssertionError(
            "coverage binding lifecycle projection contains a foreign value"
        )

    def binding_identity_projection(self) -> dict[str, object]:
        repository_root = self.private_repository_root
        action_root = self.private_action_root
        if repository_root is None or action_root is None:
            raise AssertionError("coverage binding private roots are unavailable")
        repository_identity = repository_root.identity_projection()
        action_identity = action_root.identity_projection()
        real_e2e_root = self.private_real_e2e_root
        if (
            real_e2e_root is not None
            and self.private_real_e2e_handle is None
        ):
            return real_e2e_root.binding_identity_projection()
        target_root = (
            self.target.root
            if real_e2e_root is None
            else real_e2e_root.project
        )
        target_metadata = target_root.lstat()
        target_identity = [
            int(target_metadata.st_dev),
            int(target_metadata.st_ino),
            int(target_metadata.st_uid),
        ]
        binding = self.authority._plan.binding(self.test_id)
        task_id = str(binding["task_id"])
        if real_e2e_root is None:
            target_id = self.target.target_id
            branch_ref = ["branch:" + task_id, "ref:" + task_id]
            command_root = repository_identity["command_root_identity"]
        else:
            current = self.probe.real_e2e_authority._fresh()
            lifecycle = self.binding_lifecycle
            real_e2e_root.record_observation(
                None if lifecycle is None else lifecycle.expected_purpose,
                current,
            )
            if not self.probe.real_e2e_authority._same_current_observation(
                current,
                self.probe.real_e2e_authority._execution["after"],
            ):
                raise AssertionError("real-E2E binding ref changed")
            target_id = self.probe.real_e2e_authority._expected_target.target_id
            branch_ref = [task_id, current.head_ref]
            command_root = real_e2e_root.identity_projection()[
                "command_root_identity"
            ]
        projection = {
            "action_root": action_identity["runtime_root_identity"],
            "branch_ref": branch_ref,
            "command_root": command_root,
            "repository_root": repository_identity[
                "repository_root_identity"
            ],
            "target": [target_id, *target_identity],
            "task": task_id,
        }
        if real_e2e_root is not None:
            real_e2e_root.seal_binding_identity(projection)
        return projection

    def _lifecycle_projection(self, shared: object) -> dict[str, object]:
        if shared is not self.private_shared_runtime:
            raise AssertionError("coverage binding repository handle is foreign")
        if self.private_real_e2e_root is not None:
            handle = self.private_real_e2e_handle
            if type(handle) is not PrivateRealE2EHandle:
                raise AssertionError("real-E2E live handle is unavailable")
            authority = self.probe.real_e2e_authority
            action_id = authority._action_id
            if type(action_id) is not str:
                raise AssertionError("real-E2E Action identity is unavailable")
            current = handle.adapter.observe(
                authority._target_plan_document,
                expected=authority._expected_target,
            )
            lifecycle = self.binding_lifecycle
            self.private_real_e2e_root.record_observation(
                None if lifecycle is None else lifecycle.expected_purpose,
                current,
            )
            current_document = current.to_dict()
            stable_current = {
                field: current_document[field]
                for field in authority._CURRENT_OBSERVATION_FIELDS
            }
            projection = {
                "action_state": self._lifecycle_json(
                    handle.action.repository.concrete_action_audit(action_id)
                ),
                "authority": self.authority._binding_lifecycle_projection(
                    self.execution,
                ),
                "binding_identity": self.binding_identity_projection(),
                "command_state": {
                    "cumulative_launch_count": (
                        authority._cumulative_launch_count
                    ),
                    "root_identity": self.private_real_e2e_root.identity_projection()[
                        "command_root_identity"
                    ],
                },
                "target_state": {
                    "current_observation": stable_current,
                    "durable_observation": authority._execution["after"],
                    "cumulative_mutation_count": (
                        authority._cumulative_mutation_count
                    ),
                    "target_id": authority._expected_target.target_id,
                },
            }
            dependency_reopen = self.dependency_reopen_authority
            if dependency_reopen is not None:
                dependency = self.authority._dependency_security
                if type(dependency) is not tuple or len(dependency) != 2:
                    raise AssertionError(
                        "generic dependency authority is unavailable"
                    )
                projection["dependency_state"] = self._lifecycle_json(
                    thaw(dependency_reopen.project_current(*dependency))
                )
            return projection
        target = self.target
        rollback = self.probe.rollback_signature()
        target_body = target.path.read_bytes()
        projection = {
            "action_state": self._lifecycle_json(rollback),
            "authority": self.authority._binding_lifecycle_projection(
                self.execution,
            ),
            "binding_identity": self.binding_identity_projection(),
            "command_state": {
                "launcher_replay_count": 0,
                "root_identity": self.private_repository_root.identity_projection()[
                    "command_root_identity"
                ],
            },
            "target_state": {
                "bytes_sha256": hashlib.sha256(target_body).hexdigest(),
                "mutation_count": target.mutation_count,
                "query_count": target.query_count,
                "revision": target._revision,
                "target_id": target.target_id,
            },
        }
        dependency_context = self.dependency_security_context
        dependency_reopen = self.dependency_reopen_authority
        if dependency_reopen is not None:
            dependency = self.authority._dependency_security
            if type(dependency) is not tuple or len(dependency) != 2:
                raise AssertionError("generic dependency authority is unavailable")
            projection["dependency_state"] = self._lifecycle_json(
                thaw(dependency_reopen.project_current(*dependency))
            )
        elif dependency_context is not None:
            binding = self.authority._plan.binding(self.test_id)
            projection["dependency_state"] = (
                dependency_context.seal_graph_assessment(
                    self.authority._dependency_security,
                    self.application,
                    task_id=str(binding["task_id"]),
                    scenario_id=str(binding["scenario_id"]),
                )
            )
        migration_projection = self.migration_rehearsal_projection
        if migration_projection is not None:
            from graph_engineering.core.contracts.immutable import FrozenMap

            if not isinstance(migration_projection, FrozenMap):
                raise AssertionError(
                    "migration lifecycle projection is not frozen"
                )
            assessment = self.application.current_assessment(
                self.probe.task_id,
                expected_profile_id="migration",
            )
            current_projection = (
                None
                if assessment is None
                else assessment.migration_rehearsal_projection
            )
            migration_factory = (
                self.application._oracle._migration_rehearsal_factory
            )
            if (
                current_projection != migration_projection
                or migration_factory is None
                or migration_factory._replay_count != 0
            ):
                raise AssertionError(
                    "migration lifecycle projection is stale or replayed"
                )
            projection["migration_state"] = {
                "projection": self._lifecycle_json(thaw(current_projection)),
                "replay_count": migration_factory._replay_count,
            }
        return projection

    def _close_lifecycle_handle(self, shared: object) -> None:
        if shared is not self.private_shared_runtime:
            raise AssertionError("coverage binding close handle is foreign")
        dependency_context = self.dependency_security_context
        dependency_reopen = self.dependency_reopen_authority
        if dependency_reopen is not None:
            dependency = self.authority._dependency_security
            if type(dependency) is not tuple or len(dependency) != 2:
                raise AssertionError("generic dependency authority is unavailable")
            self.dependency_reopen_seal = dependency_reopen.seal_current(
                *dependency
            )
            self.authority._quiesce_dependency_security(dependency)
            if dependency_context is not None:
                for field_name in (
                    "registry_factory", "registry", "closure_factory",
                    "before", "after", "applicability_factory",
                    "applicabilities", "residual_factory", "residual",
                ):
                    object.__setattr__(dependency_context, field_name, None)
        elif dependency_context is not None:
            binding = self.authority._plan.binding(self.test_id)
            dependency_context.quiesce_graph_assessment(
                self.authority._dependency_security,
                self.application,
                task_id=str(binding["task_id"]),
                scenario_id=str(binding["scenario_id"]),
            )
        performance_context = self.performance_context
        checkpoint_launches = getattr(
            performance_context, "checkpoint_launches", None,
        )
        if callable(checkpoint_launches):
            lifecycle = self.binding_lifecycle
            checkpoint_launches(
                None if lifecycle is None else lifecycle.expected_purpose,
            )
        real_e2e_root = self.private_real_e2e_root
        if real_e2e_root is not None:
            handle = self.private_real_e2e_handle
            if type(handle) is not PrivateRealE2EHandle:
                raise AssertionError("real-E2E live handle is unavailable")
            stack = getattr(self.probe, "_stack", None)
            close_stack = getattr(stack, "close", None)
            if callable(close_stack):
                close_stack()
                self.probe._stack = ExitStack()
            lifecycle = self.binding_lifecycle
            real_e2e_root.close_handle(
                handle,
                purpose=(
                    None if lifecycle is None else lifecycle.expected_purpose
                ),
            )
            self.private_repository_root.close_handle(shared)
            self.private_real_e2e_handle = None
            self.private_shared_runtime = None
            return
        application = self.application
        oracle = getattr(application, "_oracle", None)
        for name in (
            "_performance_registry_factory",
            "_migration_rehearsal_factory",
            "_scenario_truth_factory",
        ):
            close = getattr(getattr(oracle, name, None), "close", None)
            if callable(close):
                close()
        stack = getattr(self.probe, "_stack", None)
        close_stack = getattr(stack, "close", None)
        if callable(close_stack):
            close_stack()
            self.probe._stack = ExitStack()
        self.private_action_root.close_handle(
            self.probe.private_action_fixture,
        )
        self.private_repository_root.close_handle(shared)
        self.private_shared_runtime = None

    def _requiesce_dependency_reopen_after_failure(
        self, dependency: object,
    ) -> None:
        reopen = self.dependency_reopen_authority
        if reopen is None or reopen.state != "LIVE":
            return
        try:
            if type(dependency) is not tuple or len(dependency) != 2:
                raise AssertionError(
                    "reopened dependency authority is unavailable"
                )
            seal = reopen.seal_current(*dependency)
            self.dependency_reopen_seal = seal
            if self.authority._dependency_security is dependency:
                self.authority._quiesce_dependency_security(dependency)
        except BaseException:
            reopen.revoke()
            self.dependency_reopen_seal = None

    def _reopen_lifecycle_handle(self) -> object:
        if self.private_shared_runtime is not None:
            raise AssertionError("coverage binding is already live")
        shared = self.private_repository_root.open()
        real_e2e_root = self.private_real_e2e_root
        if real_e2e_root is not None:
            handle = None
            dependency_security = None
            try:
                handle = real_e2e_root.open()
                authority = self.probe.real_e2e_authority
                authority.reattach_current(
                    coordinator=handle.action.raw_coordinator,
                    action_repository=handle.action.repository,
                    adapter=handle.adapter,
                    launcher=handle.launcher,
                    task_application=shared.application,
                    task_repository=shared.repository,
                    objects=shared.objects,
                    runtime=shared.runtime,
                )
                previous_application = self.application
                previous_application._rollback._coordinator = (
                    handle.action.raw_coordinator
                )
                restarted = previous_application.restart(
                    shared.application, shared.runtime, self.target,
                )
                dependency_reopen = self.dependency_reopen_authority
                if dependency_reopen is not None:
                    dependency_security = dependency_reopen.rehydrate_current(
                        self.dependency_reopen_seal,
                        repository=shared.repository,
                        category_application=restarted,
                    )
                    self.dependency_reopen_seal = None
                self.application = restarted
                self.probe.factory = shared.repository._factory
                self.probe.repository = shared.repository
                self.probe.objects = shared.objects
                self.probe.task_application = shared.application
                self.probe.runtime = shared.runtime
                self.probe._rollback_action = handle.action
                self.probe.real_e2e_action_fixture = handle.action
                self.probe.real_e2e_adapter = handle.adapter
                self.probe.private_real_e2e_handle = handle
                self.authority._rebind_binding_runtime(
                    category_application=restarted,
                    task_application=shared.application,
                    repository=shared.repository,
                    object_repository=shared.objects,
                    runtime=shared.runtime,
                    dependency_security=dependency_security,
                )
                self.private_real_e2e_handle = handle
                self.private_shared_runtime = shared
                return shared
            except BaseException:
                self._requiesce_dependency_reopen_after_failure(
                    dependency_security
                )
                if handle is not None:
                    lifecycle = self.binding_lifecycle
                    real_e2e_root.close_handle(
                        handle,
                        purpose=(
                            None
                            if lifecycle is None
                            else lifecycle.expected_purpose
                        ),
                    )
                self.private_repository_root.close_handle(shared)
                raise
        action = None
        dependency_security = None
        try:
            action = self.private_action_root.open()
            previous_application = self.application
            previous_application._rollback._coordinator = action.raw_coordinator
            restarted = previous_application.restart(
                shared.application,
                shared.runtime,
                self.target,
            )
            dependency_context = self.dependency_security_context
            dependency_reopen = self.dependency_reopen_authority
            if dependency_reopen is not None:
                dependency_security = dependency_reopen.rehydrate_current(
                    self.dependency_reopen_seal,
                    repository=shared.repository,
                    category_application=restarted,
                )
                self.dependency_reopen_seal = None
            elif dependency_context is not None:
                binding = self.authority._plan.binding(self.test_id)
                dependency_security = dependency_context.rehydrate_graph_assessment(
                    shared.repository,
                    restarted,
                    task_id=str(binding["task_id"]),
                    scenario_id=str(binding["scenario_id"]),
                )
            self.authority._rebind_binding_runtime(
                category_application=restarted,
                task_application=shared.application,
                repository=shared.repository,
                object_repository=shared.objects,
                runtime=shared.runtime,
                dependency_security=dependency_security,
            )
            self.application = restarted
            self.probe.factory = shared.repository._factory
            self.probe.repository = shared.repository
            self.probe.objects = shared.objects
            self.probe.task_application = shared.application
            self.probe.runtime = shared.runtime
            self.probe._rollback_action = action
            self.probe.private_action_fixture = action
            self.private_shared_runtime = shared
            return shared
        except BaseException:
            self._requiesce_dependency_reopen_after_failure(
                dependency_security
            )
            if action is not None:
                self.private_action_root.close_handle(action)
            self.private_repository_root.close_handle(shared)
            raise

    def enable_quiescent_lifecycle(
        self,
        *,
        repository_root: object,
        action_root: object,
        shared_runtime: object,
        real_e2e_root: object | None = None,
        real_e2e_handle: object | None = None,
    ) -> None:
        from tests.support import wp08_scenario_truth as lifecycle_fixture

        if self.binding_lifecycle is not None:
            raise AssertionError("coverage binding lifecycle is already issued")
        self.private_repository_root = repository_root
        self.private_action_root = action_root
        self.private_shared_runtime = shared_runtime
        self.private_real_e2e_root = real_e2e_root
        self.private_real_e2e_handle = real_e2e_handle
        dependency = self.authority._dependency_security
        if type(dependency) is tuple and len(dependency) == 2:
            from graph_engineering.application import dependency_security

            factory, observation = dependency
            projection = getattr(observation, "_projection", None)
            if (
                type(factory)
                is dependency_security.DependencySecurityObservationFactory
                and type(observation)
                is dependency_security.DependencySecurityObservation
                and getattr(projection, "get", lambda _name: None)(
                    "schema_version"
                ) in {"1.0.0", "1.1.0"}
            ):
                self.dependency_reopen_authority = (
                    dependency_security.
                    DependencySecurityObservationReopenAuthority.from_current(
                        factory, observation,
                    )
                )
        lifecycle = lifecycle_fixture.issue_quiescent_binding(
            binding_identity=self.binding_identity_projection(),
            close_handle=self._close_lifecycle_handle,
            opened_handle=shared_runtime,
            private_root=repository_root.root,
            project_current=self._lifecycle_projection,
            reopen_handle=self._reopen_lifecycle_handle,
            terminate_root=self._terminate_lifecycle_root,
        )
        self.binding_lifecycle = lifecycle
        self.authority._bind_binding_lifecycle(lifecycle)

    def observe_current(self) -> object:
        return self.authority.observe(self.execution)

    def _terminate_lifecycle_root(self, action: str) -> None:
        dependency_reopen = self.dependency_reopen_authority
        if dependency_reopen is not None:
            dependency_reopen.revoke(self.dependency_reopen_seal)
            self.dependency_reopen_seal = None
        (
            self.private_action_root.terminate(action)
            if self.private_real_e2e_root is None
            else self.private_real_e2e_root.terminate(action)
        )
        self.private_repository_root.terminate(action)

    def close(self) -> None:
        lifecycle = self.binding_lifecycle
        if lifecycle is not None and lifecycle.state != "PERMANENTLY_CLOSED":
            lifecycle.terminate("revoke")
        dependency_reopen = self.dependency_reopen_authority
        if dependency_reopen is not None:
            dependency_reopen.revoke(self.dependency_reopen_seal)
        target = self.target
        probe = self.probe
        try:
            migration_context = self.migration_context
            if migration_context is not None:
                migration_context.__exit__(None, None, None)
            else:
                close = getattr(target, "close", None)
                if callable(close):
                    close()
                elif probe is not None:
                    probe.close()
        finally:
            release_context = self.release_operations_context
            if release_context is not None:
                release_context.__exit__(None, None, None)
                self.release_operations_context = None
            dependency_context = self.dependency_security_context
            close_dependency = getattr(dependency_context, "close", None)
            if callable(close_dependency):
                close_dependency()
            performance_context = self.performance_context
            close_performance = getattr(performance_context, "close", None)
            if callable(close_performance):
                close_performance()
            # A combined gate deliberately retains the canonical execution
            # contexts until their consumer-local authorities are revoked.
            # Once the backing resources are closed none of this diagnostic
            # object graph may remain reachable through the test harness.
            object.__setattr__(self, "application", None)
            object.__setattr__(self, "authority", None)
            object.__setattr__(self, "execution", None)
            object.__setattr__(self, "probe", None)
            object.__setattr__(self, "target", None)
            object.__setattr__(self, "candidate", {})
            object.__setattr__(self, "state_before", None)
            object.__setattr__(self, "state_after", None)
            object.__setattr__(self, "dependency_security_context", None)
            object.__setattr__(self, "dependency_reopen_authority", None)
            object.__setattr__(self, "dependency_reopen_seal", None)
            object.__setattr__(self, "performance_context", None)
            object.__setattr__(self, "migration_context", None)
            scenario_context = self.scenario_truth_context
            close_scenario = getattr(scenario_context, "close", None)
            if callable(close_scenario):
                close_scenario()
            object.__setattr__(self, "scenario_truth_context", None)

    def retain_gate_context(self) -> None:
        """Discard local diagnostics while retaining the gate authority graph."""

        self.application = None
        self.candidate = {}
        self.state_before = None
        self.state_after = None

def abort_uncommitted_coverage_factory(factory: object) -> object:
    """Finalize one partial production coverage fixture without a gate decision."""

    prepare = getattr(factory, "prepare_abort_uncommitted_candidate", None)
    abort = getattr(factory, "abort_uncommitted_candidate", None)
    if not callable(prepare) or not callable(abort):
        raise AssertionError("coverage candidate abort lifecycle is unavailable")
    capability = prepare()
    if prepare() is not capability:
        raise AssertionError("coverage candidate abort capability is not stable")
    abort(capability)
    abort(capability)
    return capability


def finalize_consumed_coverage_factory(
    factory: object,
    decision: object,
) -> object:
    """Finalize one production coverage fixture after its gate is consumed."""

    finalize = getattr(factory, "finalize_after_gate", None)
    if not callable(finalize):
        raise AssertionError("coverage candidate finalization is unavailable")
    finalize(decision)
    finalize(decision)
    return decision


@dataclass(frozen=True, slots=True)
class Slice4API:
    ProfileCoverageExecutionPlan: type
    ProfileCoverageExecutionRecord: type
    ProfileCoverageObservation: type
    ProfileCoverageAuthority: type
    ProfileCoverageError: type[Exception]


@dataclass(slots=True)
class PerformanceCoverageContext:
    """One consumer-local benchmark authority retained through coverage use."""

    registry_factory: object
    registry_authority: object
    root: object | None = None
    launcher: object | None = None
    session: object | None = None
    evidence: object | None = None
    cumulative_launch_count: int = 0
    phase_launch_deltas: dict[str, int] = field(default_factory=dict)
    measurement_durations_ns: tuple[tuple[int, ...], ...] = ()
    _accounted_launcher: object | None = None
    _accounted_launcher_count: int = 0

    def checkpoint_launches(self, purpose: str | None) -> int:
        """Accumulate one live launcher's monotonic count without retaining it."""

        if purpose is not None and purpose not in {
            "issue", "use", "precommit", "gate",
        }:
            raise AssertionError("performance lifecycle purpose is invalid")
        launcher = self.launcher
        if launcher is None:
            delta = 0
        else:
            observed = getattr(launcher, "launch_count", None)
            if type(observed) is not int or observed < 0:
                raise AssertionError("performance launcher count is invalid")
            if launcher is self._accounted_launcher:
                if observed < self._accounted_launcher_count:
                    raise AssertionError("performance launcher count regressed")
                delta = observed - self._accounted_launcher_count
            else:
                delta = observed
            self._accounted_launcher = launcher
            self._accounted_launcher_count = observed
        self.cumulative_launch_count += delta
        if purpose is not None:
            if purpose in self.phase_launch_deltas:
                raise AssertionError(
                    "performance lifecycle phase launch count was replayed"
                )
            self.phase_launch_deltas[purpose] = delta
        return delta

    def close(self) -> None:
        self.checkpoint_launches(None)
        session = self.session
        try:
            close_session = getattr(session, "close", None)
            if callable(close_session):
                close_session()
            else:
                close_launcher = getattr(self.launcher, "close", None)
                if callable(close_launcher):
                    close_launcher()
                close_root = getattr(self.root, "close", None)
                if callable(close_root):
                    close_root()
        finally:
            self.root = None
            self.launcher = None
            self.session = None
            self.evidence = None


def performance_coverage_context(
    probe: category.ProductionCategoryProbe,
    column: str,
    *,
    measure: bool,
    scenario_id: str | None = None,
) -> PerformanceCoverageContext:
    """Build exact A/B/A evidence for one performance task when requested."""

    from graph_engineering.application.performance_benchmark import (
        PerformanceBenchmarkRegistryFactory,
    )
    from tests.support import wp08_performance_benchmark as performance

    registry_factory = PerformanceBenchmarkRegistryFactory.from_installation()
    registry_authority = registry_factory.registry()
    context = PerformanceCoverageContext(
        registry_factory=registry_factory,
        registry_authority=registry_authority,
    )
    if not measure:
        return context
    if scenario_id is not None and scenario_id not in {
        PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID,
        *(
            f"GEW-PSC-PERFORMANCE-{member.upper()}-P"
            for member in PERFORMANCE_REMAINING_SCENARIO_IDS
        ),
    }:
        raise AssertionError("performance scenario boundary is not installed")
    try:
        root = registry_factory.private_root(registry_authority)
        context.root = root
        (
            launcher,
            request_document,
            invocation_document,
            expected,
            _correctness,
        ) = performance._launcher(registry_factory, registry_authority, root)
        context.launcher = launcher
        session = registry_factory.command_session(
            registry_authority, root, launcher,
        )
        context.session = session
        observer = registry_factory.observation_factory(
            registry_authority, session,
        )
        arguments = {
            "case_id": "performance-local-command-v1",
            "invocation_document": invocation_document,
            "expected": expected,
            "request_document": request_document,
        }
        baseline_source = registry_factory.observe_source(
            registry_authority, session,
        )
        baseline = observer.measure(
            sequence_kind="baseline",
            source_observation=baseline_source,
            **arguments,
        )
        registry_factory.transition_source(
            registry_authority, session, "source:performance-candidate-v1",
        )
        candidate_source = registry_factory.observe_source(
            registry_authority, session,
        )
        candidate = observer.measure(
            sequence_kind="candidate",
            source_observation=candidate_source,
            **arguments,
        )
        registry_factory.transition_source(
            registry_authority, session, "source:performance-baseline-v1",
        )
        rollback_source = registry_factory.observe_source(
            registry_authority, session,
        )
        rollback = observer.measure(
            sequence_kind="rollback",
            source_observation=rollback_source,
            **arguments,
        )
        target = observer.compare_target(baseline, candidate)
        restored = observer.compare_rollback(baseline, candidate, rollback)
        current = probe.task_application.runtime_show(
            probe.task_id, probe.runtime,
        ).snapshot
        graph_ref = current.graph_ref
        if not isinstance(graph_ref, dict):
            graph_ref = dict(graph_ref)
        task_binding = {
            "task_id": probe.task_id,
            "task_revision": current.task_revision,
            "snapshot_digest": current.snapshot_digest,
            "invalidation_epoch": current.invalidation_epoch,
            "profile_id": "performance",
            "profile_version": "1.0.0",
            "column_id": column,
            "graph_ref_pins": {
                "base_graph_digest": graph_ref["graph_digest"],
                "profile_digest": graph_ref["profile_digest"],
                "overlay_digest": graph_ref["overlay_digest"],
                "project_config_digest": graph_ref["project_config_digest"],
                "support_matrix_digest": graph_ref["support_matrix_digest"],
                "materialization_digest": graph_ref["materialization_digest"],
            },
        }
        context.evidence = observer.issue_task_evidence(
            task_binding=task_binding,
            source_history=(baseline_source, candidate_source, rollback_source),
            baseline=baseline,
            candidate=candidate,
            rollback=rollback,
            target=target,
            restored=restored,
        )
        projection = context.evidence.projection
        sample_sets = projection["sample_sets"]
        measured = tuple(
            tuple(sample["duration_ns"] for sample in row["samples"])
            for row in sample_sets
        )
        if (
            len(measured) != 3
            or any(len(row) != 5 for row in measured)
            or any(type(value) is not int or value < 1 for row in measured for value in row)
        ):
            raise AssertionError("performance parent timing projection is invalid")
        context.measurement_durations_ns = measured
        return context
    except BaseException:
        context.close()
        raise


def performance_coverage_authority_rejection_probes(
    *,
    api4: Slice4API,
    plan: object,
) -> tuple[str, ...]:
    """Exercise absent-evidence and closed-launcher issuance without task writes."""

    test_id = performance_test_id("artifacts", "R")
    task_id = str(plan.binding(test_id)["task_id"])
    rejected: list[str] = []
    for attack, measure in (
        ("missing-evidence", False),
        ("closed-launcher", True),
    ):
        _api, application, probe, target = production_runtime(
            "artifacts",
            profile_id="performance",
            task_id=task_id,
            performance_measurement=measure,
        )
        try:
            context = probe.performance_context
            if attack == "closed-launcher":
                context.session.close()
            before = _serial_state_signature(
                probe, target, real_e2e=False,
            )
            try:
                api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=application,
                    task_application=probe.task_application,
                    repository=probe.repository,
                    object_repository=probe.objects,
                    runtime=probe.runtime,
                )
            except api4.ProfileCoverageError:
                rejected.append(attack)
            else:
                raise AssertionError(
                    f"performance coverage {attack} unexpectedly issued"
                )
            if _serial_state_signature(
                probe, target, real_e2e=False,
            ) != before:
                raise AssertionError(
                    f"performance coverage {attack} changed durable state"
                )
        finally:
            target.close()
    return tuple(rejected)


def load_slice4_api() -> Slice4API:
    missing: list[str] = []
    try:
        core = importlib.import_module("graph_engineering.core.profile_coverage")
    except ModuleNotFoundError:
        core = None
        missing.append("graph_engineering.core.profile_coverage")
    try:
        application = importlib.import_module(
            "graph_engineering.application.profile_coverage"
        )
    except ModuleNotFoundError:
        application = None
        missing.append("graph_engineering.application.profile_coverage")
    core_names = (
        "ProfileCoverageExecutionPlan",
        "ProfileCoverageExecutionRecord",
        "ProfileCoverageObservation",
        "ProfileCoverageError",
    )
    application_names = ("ProfileCoverageAuthority",)
    for name in core_names:
        if core is None or not isinstance(getattr(core, name, None), type):
            missing.append(name)
    for name in application_names:
        if application is None or not isinstance(getattr(application, name, None), type):
            missing.append(name)
    if missing:
        raise MissingProfileCoverageContract(
            "WP-08 Slice 4 production coverage contract is absent: "
            + ", ".join(missing)
        )
    error_type = getattr(core, "ProfileCoverageError")
    if not issubclass(error_type, Exception):
        raise MissingProfileCoverageContract(
            "ProfileCoverageError is not an exception type"
        )
    return Slice4API(
        **{name: getattr(core, name) for name in core_names},
        **{name: getattr(application, name) for name in application_names},
    )


def production_runtime(
    column: str = "normal",
    *,
    profile_id: str = "new-feature",
    scenario_id: str | None = None,
    task_id: str | None = None,
    shared_runtime: category.SharedProductionCategoryRuntime | None = None,
    private_action_root: object | None = None,
    performance_measurement: bool = False,
):  # type: ignore[no-untyped-def]
    """Build one exact Slice 3 Profile/full-planned category path."""

    api = category.load_slice3_api()
    profile = category.profile_document(profile_id)
    materialized = category.materialized_profile(profile_id)
    policy = api.CategoryExecutionPolicy.from_installation(
        profile_document=profile,
        support_matrix_document=category.load_json(category.SUPPORT_MATRIX_PATH),
        materialization_record=materialized.record,
    )
    target = category.DisposableLocalTarget(profile_id)
    task_application, repository, objects, runtime, probe = (
        category.production_category_runtime(
            profile_id, column, target=target, scenario_id=scenario_id,
            task_id=task_id, shared_runtime=shared_runtime,
        )
    )
    target_authority = api.CategoryTargetObservationAuthority(policy)
    performance_context = None
    if profile_id == "performance":
        performance_context = performance_coverage_context(
            probe,
            column,
            measure=performance_measurement,
            scenario_id=scenario_id,
        )
    scenario_truth_factory = None
    if scenario_id in SCENARIO_TRUTH_BOUNDARY_CASE_IDS:
        from graph_engineering.application.scenario_truth import (
            ScenarioTruthRegistryFactory,
        )

        scenario_truth_factory = ScenarioTruthRegistryFactory.from_installation()
    oracle = api.CategoryCompletionOracle(
        policy=policy,
        target_authority=target_authority,
        performance_registry_factory=(
            None
            if performance_context is None
            else performance_context.registry_factory
        ),
        performance_registry_authority=(
            None
            if performance_context is None
            else performance_context.registry_authority
        ),
        scenario_truth_factory=scenario_truth_factory,
    )
    if private_action_root is None:
        action_coordinator, action_context = category.action_rollback_binding(
            probe, target,
        )
        private_action_fixture = None
    else:
        from tests.support import wp08_scenario_truth as lifecycle_fixture

        (
            action_coordinator,
            action_context,
            private_action_fixture,
        ) = lifecycle_fixture.bind_private_rollback_action(
            probe, target, private_action_root,
        )
    rollback = api.CategoryRollbackBridge(policy, action_coordinator)
    rollback.prepare_action(**action_context)
    probe.bind_rollback_evidence(rollback)
    resolver = api.CategoryAssessmentResolver(
        repository,
        objects,
        task_application=task_application,
        runtime=runtime,
    )
    application = api.CategoryExecutionApplication(
        repository=repository,
        object_repository=objects,
        policy=policy,
        reducer=api.CategoryExecutionReducer(policy),
        completion_oracle=oracle,
        rollback_bridge=rollback,
        assessment_resolver=resolver,
        task_application=task_application,
        runtime=runtime,
        target_observer=target,
    )
    application.bind_current_sources(probe.task_id)
    probe.performance_context = performance_context
    probe.scenario_truth_factory = scenario_truth_factory
    probe.private_action_fixture = private_action_fixture
    probe.private_action_root = private_action_root
    if performance_context is not None:
        probe._stack.callback(performance_context.close)
    if scenario_truth_factory is not None:
        probe._stack.callback(scenario_truth_factory.close)
    return api, application, probe, target


@dataclass(slots=True)
class PrivateRealE2EHandle:
    action: object
    adapter: object
    launcher: object


class PrivateRealE2ERoot:
    """Retain one exact Git/action/command root while handles are quiesced."""

    def __init__(self) -> None:
        from tests.support import wp08_scenario_truth as lifecycle_fixture

        self.__temporary = tempfile.TemporaryDirectory(
            prefix="gew-e1-private-real-e2e-"
        )
        self.root = pathlib.Path(self.__temporary.name).resolve(strict=True)
        self.project = self.root / "project"
        self.command_root = self.root
        self.action_root = lifecycle_fixture.PrivateActionRepositoryRoot()
        self.__configuration: tuple[object, ...] | None = None
        self.__live: PrivateRealE2EHandle | None = None
        self.__terminal = False
        self.__cumulative_mutation_count = 0
        self.__cumulative_launch_count = 0
        self.__phase_mutation_deltas: dict[str, int] = {}
        self.__phase_launch_deltas: dict[str, int] = {}
        self.__observation_receipts: dict[str, list[tuple[int, str]]] = {}
        self.__binding_identity: object | None = None

    @property
    def cumulative_mutation_count(self) -> int:
        return self.__cumulative_mutation_count

    @property
    def cumulative_launch_count(self) -> int:
        return self.__cumulative_launch_count

    @property
    def phase_mutation_deltas(self) -> dict[str, int]:
        return dict(self.__phase_mutation_deltas)

    @property
    def phase_launch_deltas(self) -> dict[str, int]:
        return dict(self.__phase_launch_deltas)

    @property
    def observation_receipts(self) -> dict[str, tuple[tuple[int, str], ...]]:
        return {
            purpose: tuple(receipts)
            for purpose, receipts in self.__observation_receipts.items()
        }

    @staticmethod
    def _identity(path: pathlib.Path) -> list[int]:
        import stat

        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AssertionError("private real-E2E root identity changed")
        return [
            int(metadata.st_dev), int(metadata.st_ino), int(metadata.st_uid),
            stat.S_IMODE(metadata.st_mode),
        ]

    def identity_projection(self) -> dict[str, object]:
        return {
            "action_root_identity": self.action_root.identity_projection()[
                "runtime_root_identity"
            ],
            "command_root_identity": self._identity(self.command_root),
            "project_root_identity": self._identity(self.project),
            "runtime_root_identity": self._identity(self.root),
        }

    def seal_binding_identity(self, projection: dict[str, object]) -> None:
        from graph_engineering.core.contracts.immutable import FrozenMap, freeze

        frozen = freeze(copy.deepcopy(projection))
        if not isinstance(frozen, FrozenMap):
            raise AssertionError("private real-E2E binding identity is malformed")
        if self.__binding_identity is None:
            self.__binding_identity = frozen
        elif self.__binding_identity != frozen:
            raise AssertionError("private real-E2E binding identity changed")

    def binding_identity_projection(self) -> dict[str, object]:
        from graph_engineering.core.contracts.immutable import thaw

        if self.__binding_identity is None:
            raise AssertionError("private real-E2E binding identity is unsealed")
        projection = thaw(self.__binding_identity)
        if type(projection) is not dict:
            raise AssertionError("private real-E2E binding identity is malformed")
        return projection

    def configure(
        self,
        *,
        adapter_factory: object,
        concrete_policy: object,
        registry: object,
        git_configuration: dict[str, object],
        provider_document: dict[str, object],
        command_document: dict[str, object],
        runtime_document: dict[str, object],
    ) -> None:
        if self.__configuration is not None:
            raise AssertionError("private real-E2E root was already configured")
        self.__configuration = (
            adapter_factory, concrete_policy, registry,
            copy.deepcopy(git_configuration), copy.deepcopy(provider_document),
            copy.deepcopy(command_document), copy.deepcopy(runtime_document),
        )

    def record_observation(
        self, purpose: str | None, observation: object,
    ) -> None:
        from graph_engineering.adapters.git_native import GitIdentityObservation

        if type(observation) is not GitIdentityObservation:
            raise AssertionError("private real-E2E observation is foreign")
        document = observation.to_dict()
        if GitIdentityObservation.from_dict(document) != observation:
            raise AssertionError("private real-E2E observation digest is stale")
        key = "initial" if purpose is None else purpose
        receipts = self.__observation_receipts.setdefault(key, [])
        if receipts and observation.observation_revision <= receipts[-1][0]:
            raise AssertionError(
                "private real-E2E observation revision did not advance"
            )
        receipts.append((
            observation.observation_revision, observation.observation_digest,
        ))

    def open(self) -> PrivateRealE2EHandle:
        if (
            self.__terminal or self.__live is not None
            or self.__configuration is None
        ):
            raise AssertionError("private real-E2E root cannot reopen")
        from graph_engineering.adapters.action_adapters import ActionAdapterFactory
        from graph_engineering.adapters.command_native import SecretProviderPorts

        (
            adapter_factory, concrete_policy, registry, git_configuration,
            provider_document, command_document, runtime_document,
        ) = self.__configuration
        if type(adapter_factory) is not ActionAdapterFactory:
            raise AssertionError("private real-E2E adapter factory is foreign")
        action = self.action_root.open(concrete_action_authority=(
            adapter_factory, concrete_policy, registry,
        ))
        adapter = None
        launcher = None
        try:
            adapter = adapter_factory.issue_git_native(git_configuration)
            provider = adapter_factory.issue_secret_provider(
                provider_document,
                SecretProviderPorts(resolve=lambda _reference: b"disposable-unused"),
            )
            launcher = adapter_factory.issue_project_command(
                command_document, runtime_document, provider=provider,
            )
            handle = PrivateRealE2EHandle(action, adapter, launcher)
            self.__live = handle
            return handle
        except BaseException:
            if launcher is not None:
                launcher.close()
            if adapter is not None:
                adapter.close()
            self.action_root.close_handle(action)
            raise

    def close_handle(
        self, handle: PrivateRealE2EHandle, *, purpose: str | None,
    ) -> None:
        if self.__live is not handle:
            raise AssertionError("private real-E2E handle is foreign")
        mutation_count = handle.adapter.mutation_count
        launch_count = handle.launcher.launch_count
        if purpose is None:
            if self.__phase_mutation_deltas or self.__phase_launch_deltas:
                raise AssertionError("private real-E2E initial handle was replayed")
            self.__cumulative_mutation_count = mutation_count
            self.__cumulative_launch_count = launch_count
        else:
            if purpose in self.__phase_mutation_deltas:
                raise AssertionError("private real-E2E phase was replayed")
            self.__phase_mutation_deltas[purpose] = mutation_count
            self.__phase_launch_deltas[purpose] = launch_count
            if mutation_count != 0 or launch_count != 0:
                raise AssertionError("private real-E2E phase replayed a side effect")
        try:
            handle.launcher.close()
            handle.adapter.close()
            self.action_root.close_handle(handle.action)
        finally:
            self.__live = None

    def terminate(self, action: str) -> None:
        if (
            action not in {"finalize", "revoke"}
            or self.__live is not None or self.__terminal
        ):
            raise AssertionError("private real-E2E root cannot terminate")
        self.action_root.terminate(action)
        self.__terminal = True
        self.__temporary.cleanup()


def production_real_e2e_runtime(
    *, accepted: bool, profile_id: str = "new-feature", task_id: str | None = None,
    private_repository_runtime: object | None = None,
    private_tool_root: object | None = None,
):  # type: ignore[no-untyped-def]
    """Build one exact disposable Git/action/command/category authority chain."""

    from graph_engineering.adapters.action_adapters import ActionAdapterFactory
    from graph_engineering.adapters.command_native import (
        CommandExecutionRequest,
        CommandRegistry,
        CommandRuntimePolicy,
        SecretProviderPorts,
        SecretProviderRegistry,
    )
    from graph_engineering.adapters.git_native import (
        GitAdapterConfiguration,
        GitTargetPlan,
    )
    from graph_engineering.application.profile_real_e2e import (
        ProfileRealE2EAuthority,
    )
    from graph_engineering.core.action_adapters import (
        ActionAdapterRegistry,
        ActionInvocation,
        ConcreteActionPolicy,
    )
    from graph_engineering.core.actions import PreparedAction
    from tests.contract.test_wp07a_action_contracts import invocation_document
    from tests.integration.test_wp07a_action_coordinator import disclosure
    from tests.integration.test_wp07a_git_readonly import mutation_payload, raw_git
    from tests.support.wp05_actions import (
        action_stack,
        authority_document,
        digest as action_digest,
        prepared_document,
    )
    from tests.support.wp07a_actions import installed_action_adapter_attestation

    stack = ExitStack()
    private_tool_handle = None
    try:
        if private_tool_root is None:
            directory = pathlib.Path(stack.enter_context(
                tempfile.TemporaryDirectory(prefix="gew-wp08-real-e2e-")
            ))
        else:
            if type(private_tool_root) is not PrivateRealE2ERoot:
                raise AssertionError("private real-E2E root is foreign")
            directory = private_tool_root.root
        project = directory / "project"
        git_name = shutil.which("git")
        if git_name is None:
            raise AssertionError("local Git executable is unavailable")
        git_executable = pathlib.Path(git_name).resolve(strict=True)
        subprocess.run(
            (os.fspath(git_executable), "init", "--quiet", os.fspath(project)),
            shell=False, check=True, capture_output=True, timeout=10,
        )
        if private_tool_root is not None:
            if type(task_id) is not str or not task_id:
                raise AssertionError("private real-E2E task namespace is invalid")
            branch_name = "gew-binding-" + hashlib.sha256(
                task_id.encode("utf-8")
            ).hexdigest()
            subprocess.run(
                (
                    os.fspath(git_executable), "-C", os.fspath(project),
                    "symbolic-ref", "HEAD", "refs/heads/" + branch_name,
                ),
                shell=False, check=True, capture_output=True, timeout=10,
            )
        if profile_id == "new-feature":
            artifact_name = "feature-contract.json"
            first_body = b'{"feature":"absent"}\n'
            desired_body = b'{"acceptance":"passed","feature":"scaffold"}\n'
            foreign_body = b'{"feature":"foreign"}\n'
        elif profile_id == "bug-fix":
            artifact_name = "bug-fix-contract.json"
            first_body = b'{"bug":"reproduced","regression_guard":"absent"}\n'
            desired_body = b'{"bug":"fixed","regression_guard":"passed"}\n'
            foreign_body = b'{"bug":"foreign","regression_guard":"absent"}\n'
        else:
            configured = real_e2e_profile_fixture(profile_id)
            if configured is None:
                raise AssertionError("unknown real-E2E Profile fixture")
            artifact_name = str(configured["artifact_name"])
            first_body = json.dumps(
                configured["baseline_document"],
                ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8") + b"\n"
            desired_body = json.dumps(
                configured["desired_document"],
                ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8") + b"\n"
            foreign_body = json.dumps(
                configured["foreign_document"],
                ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8") + b"\n"
        artifact = project / artifact_name

        def commit(message: str, body: bytes) -> str:
            artifact.write_bytes(body)
            subprocess.run(
                (os.fspath(git_executable), "-C", os.fspath(project), "add", "."),
                shell=False, check=True, capture_output=True, timeout=10,
            )
            subprocess.run(
                (
                    os.fspath(git_executable), "-C", os.fspath(project),
                    "-c", "user.name=Fixture", "-c",
                    "user.email=fixture@example.invalid", "commit", "--quiet",
                    "-m", message,
                ),
                shell=False, check=True, capture_output=True, timeout=10,
            )
            return raw_git(git_executable, project, "rev-parse", "HEAD")

        first_oid = commit("baseline", first_body)
        second_oid = commit("desired", desired_body)
        third_oid = commit("foreign", foreign_body)
        start_oid = first_oid if accepted else third_oid
        subprocess.run(
            (
                os.fspath(git_executable), "-C", os.fspath(project), "reset",
                "--quiet", "--hard", start_oid,
            ),
            shell=False, check=True, capture_output=True, timeout=10,
        )

        target_document: dict[str, object] = {
            "schema_version": "1.0.0",
            "plan_id": "git-plan-wp08-real-e2e",
            "target_id": "target-project",
            "target_digest": action_digest("target"),
            "allowed_root": os.fspath(directory),
            "relative_path": "project",
        }
        target_document["plan_digest"] = GitTargetPlan.digest_document(
            target_document
        )
        expected_target = GitTargetPlan.from_dict(target_document)
        git_configuration: dict[str, object] = {
            "schema_version": "1.0.0",
            "configuration_id": "git-native-wp08-real-e2e",
            "adapter_id": "git-native-v1",
            "executable": os.fspath(git_executable),
            "executable_sha256": hashlib.sha256(
                git_executable.read_bytes()
            ).hexdigest(),
            "max_output_bytes": 65536,
            "timeout_seconds": 10,
        }
        git_configuration["configuration_digest"] = (
            GitAdapterConfiguration.digest_document(git_configuration)
        )
        provider_document: dict[str, object] = {
            "schema_version": "1.0.0",
            "registry_id": "secret-provider-registry-wp08-real-e2e",
            "entries": [{
                "provider_id": "provider-wp08-disposable",
                "adapter_id": "secret-provider-v1",
                "implementation_ref": "port:disposable-empty-provider",
                "allowed_references": [{
                    "schema_version": "1.0.0",
                    "provider_id": "provider-wp08-disposable",
                    "key_ref": "unused-fixture-token",
                    "version_ref": "version-one",
                }],
            }],
        }
        provider_document["registry_digest"] = (
            SecretProviderRegistry.digest_document(provider_document)
        )
        verifier = (
            category.ROOT / "application/graph_engineering/application"
            / "profile_real_e2e_verifier.py"
        )
        python_executable = pathlib.Path(sys.executable).resolve(strict=True)
        artifact_sha256 = hashlib.sha256(desired_body).hexdigest()
        parameter_values = {
            "artifact_sha256": [artifact_sha256],
            "artifact_relative": [artifact.name],
            "expected_oid": [second_oid],
            "git_executable": [os.fspath(git_executable)],
        }
        command_document: dict[str, object] = {
            "schema_version": "1.0.0",
            "registry_id": "command-registry-wp08-real-e2e",
            "entries": [{
                "command_id": "profile-real-e2e-verifier-v1",
                "adapter_id": "project-command-v1",
                "executable": os.fspath(python_executable),
                "executable_sha256": hashlib.sha256(
                    python_executable.read_bytes()
                ).hexdigest(),
                "allowed_root": os.fspath(directory),
                "cwd_relative": "project",
                "argv_prefix": [os.fspath(verifier)],
                "parameter_order": sorted(parameter_values),
                "parameter_values": parameter_values,
                "static_environment": {"LANG": "C", "LC_ALL": "C"},
                "secret_environment": {},
                "side_effect_class": "read-only",
                "idempotency_class": "idempotent",
            }],
        }
        command_document["registry_digest"] = CommandRegistry.digest_document(
            command_document
        )
        runtime_document: dict[str, object] = {
            "schema_version": "1.0.0",
            "policy_id": "command-runtime-policy-wp08-real-e2e",
            "launcher_mode": "structured-argv-shell-false",
            "max_parameters": 4,
            "max_parameter_bytes": 512,
            "max_output_bytes": 4096,
            "read_chunk_bytes": 256,
            "timeout_ms": 5000,
            "poll_interval_ms": 10,
            "termination_grace_ms": 50,
            "termination_force_wait_ms": 250,
            "output_field_allowlist": [
                "accepted", "artifact_sha256", "head_oid",
            ],
            "secret_encodings": ["base64", "hex", "json", "raw", "sha256", "url"],
        }
        runtime_document["policy_digest"] = CommandRuntimePolicy.digest_document(
            runtime_document
        )
        registry = ActionAdapterRegistry.from_dict(category.load_json(
            category.ROOT / "config/contracts/action-adapter-registry-v1.json"
        ))
        concrete = ConcreteActionPolicy.from_dict(
            category.load_json(
                category.ROOT / "config/actions/concrete-action-policy-v1.json"
            ),
            registry=registry,
        )
        adapter_factory = ActionAdapterFactory(
            concrete,
            registry,
            installation_attestation=installed_action_adapter_attestation(),
            configuration_digests={
                "git-adapter-configuration": git_configuration[
                    "configuration_digest"
                ],
                "secret-provider-registry": provider_document["registry_digest"],
                "command-registry": command_document["registry_digest"],
                "command-runtime-policy": runtime_document["policy_digest"],
            },
        )
        if private_tool_root is None:
            action_fixture = stack.enter_context(action_stack(
                concrete_action_authority=(adapter_factory, concrete, registry)
            ))
            adapter = adapter_factory.issue_git_native(git_configuration)
            stack.callback(adapter.close)
            provider = adapter_factory.issue_secret_provider(
                provider_document,
                SecretProviderPorts(
                    resolve=lambda _reference: b"disposable-unused"
                ),
            )
            launcher = adapter_factory.issue_project_command(
                command_document, runtime_document, provider=provider,
            )
            stack.callback(launcher.close)
        else:
            private_tool_root.configure(
                adapter_factory=adapter_factory,
                concrete_policy=concrete,
                registry=registry,
                git_configuration=git_configuration,
                provider_document=provider_document,
                command_document=command_document,
                runtime_document=runtime_document,
            )
            private_tool_handle = private_tool_root.open()
            action_fixture = private_tool_handle.action
            adapter = private_tool_handle.adapter
            launcher = private_tool_handle.launcher
        before = adapter.observe(target_document, expected=expected_target)
        prepared_value = prepared_document()
        payload = mutation_payload(
            expected_target,
            ref_name=before.head_ref,
            expected_old_oid=first_oid,
            new_oid=second_oid,
        )
        prepared_value.update({
            "payload": payload,
            "payload_digest": PreparedAction.payload_digest_for(
                payload, action_fixture.context,
            ),
            "precondition": {"head_oid": first_oid, "head_ref": before.head_ref},
            "expected_postcondition": {
                "head_oid": second_oid, "head_ref": before.head_ref,
            },
            "required_capabilities": ["fresh-target-query", "native-precondition"],
        })
        prepared_value["prepared_action_digest"] = PreparedAction.digest_document(
            prepared_value, action_fixture.context,
        )
        prepared = action_fixture.coordinator.prepare(prepared_value)
        action_fixture.coordinator.authorize(authority_document(prepared))
        predecessor_id = "GEW-ACT-010" if accepted else "GEW-ACT-010A"
        authority = ProfileRealE2EAuthority(
            coordinator=action_fixture.raw_coordinator,
            action_repository=action_fixture.repository,
            adapter=adapter,
            target_plan_document=target_document,
            expected_target=expected_target,
            launcher=launcher,
            profile_id=profile_id,
            predecessor_id=predecessor_id,
        )
        arguments = {
            "owner_id": "owner-wp05",
            "runtime_kind": "codex",
            "runtime_lineage_id": "lineage-wp05",
            "lease": action_fixture.action_lease,
            "adapter": adapter,
            "target_plan_document": target_document,
            "expected_target": expected_target,
            "disclosure_plan": disclosure(
                action_fixture, action_fixture.issuer, prepared,
            ),
        }
        if accepted:
            action_outcome = action_fixture.raw_coordinator.execute_concrete_git(
                prepared.action_id, **arguments,
            )
            request_document: dict[str, object] = {
                "schema_version": "1.0.0",
                "request_id": "command-request-wp08-real-e2e",
                "command_id": "profile-real-e2e-verifier-v1",
                "parameters": {
                    name: values[0] for name, values in parameter_values.items()
                },
                "secret_references": [],
            }
            request_document["request_digest"] = (
                CommandExecutionRequest.digest_document(request_document)
            )
            invocation = invocation_document()
            invocation.update({
                "adapter_id": "project-command-v1",
                "operation_id": "project.run",
                "idempotency_class": "idempotent",
                "payload_digest": ActionInvocation.payload_digest_for(
                    request_document
                ),
            })
            invocation["invocation_digest"] = ActionInvocation.digest_document(
                invocation
            )
            authority.capture_success(
                action_id=prepared.action_id,
                action_outcome=action_outcome,
                command_request=request_document,
                command_invocation=invocation,
                expected_invocation=ActionInvocation.from_dict(invocation),
            )
        else:
            try:
                action_fixture.raw_coordinator.execute_concrete_git(
                    prepared.action_id, **arguments,
                )
            except ValueError as error:
                if str(error) != "concrete Git native precondition changed":
                    raise
            else:
                raise AssertionError("stale expected-ref unexpectedly mutated Git")
            authority.capture_stale_rejection(action_id=prepared.action_id)

        observer = authority.issue_observer()
        api = category.load_slice3_api()
        profile = category.profile_document(profile_id)
        materialized = category.materialized_profile(profile_id)
        policy = api.CategoryExecutionPolicy.from_installation(
            profile_document=profile,
            support_matrix_document=category.load_json(category.SUPPORT_MATRIX_PATH),
            materialization_record=materialized.record,
        )
        task_application, repository, objects, runtime, probe = (
            category.production_category_runtime(
                profile_id, "real-e2e", target=observer,
                real_e2e_authority=authority,
                task_id=task_id,
                shared_runtime=private_repository_runtime,
            )
        )
        target_authority = api.CategoryTargetObservationAuthority(policy)
        performance_context = None
        if profile_id == "performance":
            performance_context = performance_coverage_context(
                probe, "real-e2e", measure=True,
            )
        oracle = api.CategoryCompletionOracle(
            policy=policy,
            target_authority=target_authority,
            performance_registry_factory=(
                None
                if performance_context is None
                else performance_context.registry_factory
            ),
            performance_registry_authority=(
                None
                if performance_context is None
                else performance_context.registry_authority
            ),
        )
        if private_tool_root is None:
            rollback_action, rollback_context = category.action_rollback_binding(
                probe, observer,
            )
        else:
            from tests.support import wp08_scenario_truth as lifecycle_fixture

            rollback_action, rollback_context = (
                lifecycle_fixture.bind_rollback_action_fixture(
                    probe, observer, action_fixture,
                )
            )
        rollback = api.CategoryRollbackBridge(policy, rollback_action)
        rollback.prepare_action(**rollback_context)
        probe.bind_rollback_evidence(rollback)
        resolver = api.CategoryAssessmentResolver(
            repository, objects, task_application=task_application, runtime=runtime,
        )
        application = api.CategoryExecutionApplication(
            repository=repository,
            object_repository=objects,
            policy=policy,
            reducer=api.CategoryExecutionReducer(policy),
            completion_oracle=oracle,
            rollback_bridge=rollback,
            assessment_resolver=resolver,
            task_application=task_application,
            runtime=runtime,
            target_observer=observer,
        )
        application.bind_current_sources(probe.task_id)
        probe.performance_context = performance_context
        if performance_context is not None:
            probe._stack.callback(performance_context.close)
        if private_tool_root is None:
            probe._stack.callback(stack.close)
        probe.real_e2e_authority = authority
        probe.real_e2e_adapter = adapter
        probe.real_e2e_action_fixture = action_fixture
        probe.real_e2e_start_oid = start_oid
        probe.real_e2e_desired_oid = second_oid
        probe.real_e2e_foreign_oid = third_oid
        probe.real_e2e_git_executable = git_executable
        probe.real_e2e_project = project
        probe.private_real_e2e_handle = private_tool_handle
        probe.private_real_e2e_root = private_tool_root
        return api, application, probe, observer
    except BaseException:
        stack.close()
        if private_tool_root is not None and private_tool_handle is not None:
            private_tool_root.close_handle(private_tool_handle, purpose=None)
        raise


def apply_real_e2e_currentness_attack(
    probe: category.ProductionCategoryProbe,
    attack: str,
) -> None:
    """Apply one test-only substitution after a valid real-E2E observation."""

    authority = probe.real_e2e_authority
    action = probe.real_e2e_action_fixture
    action_id = authority._action_id
    if type(action_id) is not str:
        raise AssertionError("real-E2E action ID is unavailable")
    if attack == "predecessor-delete":
        object_digest = authority._record_object_digest
        if type(object_digest) is not str:
            raise AssertionError("real-E2E predecessor ref is unavailable")
        probe._delete_ref(object_digest)
        return
    if attack == "receipt-delete":
        with action.journal._factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "DELETE FROM concrete_action_records "
                    "WHERE action_id=? AND record_type='receipt'",
                    (action_id,),
                )
        return
    if attack == "result-replace":
        from graph_engineering.core.contracts.canonical import canonical_bytes
        from graph_engineering.core.contracts.digest import semantic_digest

        record = authority._record.to_dict()
        command = record.get("command_result")
        if type(command) is not dict or type(command.get("output")) is not dict:
            raise AssertionError("real-E2E command result is unavailable")
        command["output"]["accepted"] = False
        body = {key: value for key, value in record.items() if key != "record_digest"}
        record["record_digest"] = semantic_digest(
            body,
            contract_type="urn:gew:contract:profile-real-e2e-predecessor-record",
            projection_id=(
                "urn:gew:digest-projection:"
                "profile-real-e2e-predecessor-record:1.0.0"
            ),
            schema_id="urn:gew:schema:profile-real-e2e-predecessor-record:1.0.0",
        )
        old_digest = authority._record_object_digest
        replacement = canonical_bytes(record)
        replacement_digest = probe.objects.digest(replacement)
        probe.objects.put_verified(replacement, replacement_digest)
        probe._delete_ref(old_digest)
        probe._insert_ref(replacement_digest)
        return
    if attack == "stale-journal":
        action.journal.test_only_set_state(action_id, "succeeded")
        return
    if attack == "stale-claim":
        with action.journal._factory.open("application") as connection:
            with connection.transaction():
                connection.execute(
                    "UPDATE claims SET state='unresolved' WHERE action_id=?",
                    (action_id,),
                )
        return
    if attack == "post-observation-target-replace":
        subprocess.run(
            (
                os.fspath(probe.real_e2e_git_executable),
                "-C",
                os.fspath(probe.real_e2e_project),
                "update-ref",
                "HEAD",
                probe.real_e2e_foreign_oid,
            ),
            shell=False,
            check=True,
            capture_output=True,
            timeout=10,
        )
        return
    raise AssertionError(f"unknown real-E2E attack: {attack}")


def real_e2e_installation_attack(attack: str) -> object:
    """Return one post-issuance installation-registry substitution."""

    import graph_engineering
    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.contracts.digest import semantic_digest

    if attack == "delete":
        return graph_engineering.DistributionIdentityError(
            "Profile real-E2E registry disappeared"
        )
    provenance, registry_body = (
        graph_engineering._profile_real_e2e_installation_resource()
    )
    registry = json.loads(registry_body)
    if attack == "invalid":
        changed_body = b'{"registry":"invalid"}'
        changed_provenance = provenance.replace(
            hashlib.sha256(registry_body).hexdigest().encode(),
            hashlib.sha256(changed_body).hexdigest().encode(),
            1,
        )
        return changed_provenance, changed_body
    profiles = registry.get("profiles")
    if not isinstance(profiles, list):
        raise AssertionError("Profile real-E2E fixture registry is malformed")
    profile = next(
        item for item in profiles
        if isinstance(item, dict) and item.get("profile_id") == "new-feature"
    )
    bindings = profile.get("bindings")
    if not isinstance(bindings, list):
        raise AssertionError("Profile real-E2E fixture Profile is malformed")
    selected = next(
        item for item in bindings
        if isinstance(item, dict) and item.get("disposition") == "P"
    )
    if attack == "replace":
        selected["reconcile_route"] = "replacement-route"
        return provenance, canonical_bytes(registry)
    if attack == "coherent-resign":
        selected["reconcile_route"] = "coherently-resigned-route"
        old_digest = registry.pop("registry_digest")
        registry["registry_digest"] = semantic_digest(
            registry,
            contract_type=(
                "urn:gew:contract:profile-real-e2e-binding-registry"
            ),
            projection_id=(
                "urn:gew:digest-projection:"
                "profile-real-e2e-binding-registry:1.0.0"
            ),
            schema_id=(
                "urn:gew:schema:profile-real-e2e-binding-registry:1.0.0"
            ),
        )
        changed_body = canonical_bytes(registry)
        changed_provenance = provenance.replace(
            str(old_digest).encode(),
            str(registry["registry_digest"]).encode(),
            1,
        ).replace(
            hashlib.sha256(registry_body).hexdigest().encode(),
            hashlib.sha256(changed_body).hexdigest().encode(),
            1,
        )
        if changed_provenance == provenance:
            raise AssertionError("Profile real-E2E bootstrap was not re-signed")
        return changed_provenance, changed_body
    raise AssertionError(f"unknown Profile real-E2E installation attack: {attack}")


def real_e2e_state_signature(
    probe: category.ProductionCategoryProbe,
) -> tuple[object, ...]:
    """Capture every task/action/Git durable effect visible to this slice."""

    from tests.integration.test_wp07a_git_readonly import raw_git

    authority = probe.real_e2e_authority
    action_id = authority._action_id
    if type(action_id) is not str:
        raise AssertionError("Profile real-E2E action ID is unavailable")
    return (
        probe.signature(),
        copy.deepcopy(
            probe.real_e2e_action_fixture.repository.concrete_action_audit(
                action_id
            )
        ),
        probe.real_e2e_adapter.mutation_count,
        raw_git(
            probe.real_e2e_git_executable,
            probe.real_e2e_project,
            "rev-parse",
            "HEAD",
        ),
    )


def rejected_candidate() -> dict[str, object]:
    candidate = category.candidate_document("new-feature", "normal")
    candidate["task_id"] = coverage_task_id(REJECT_TEST_ID)
    return candidate


def rollback_candidate() -> dict[str, object]:
    candidate = category.candidate_document("new-feature", "rollback")
    candidate["task_id"] = coverage_task_id(ROLLBACK_REJECT_TEST_ID)
    return candidate


def install_rejection_source(probe: category.ProductionCategoryProbe) -> None:
    """Install a coherently self-digested but non-authoritative runner fact."""

    evidence = probe.resolve_category_evidence(probe.task_id, "normal")
    facts = evidence["facts"]
    if not isinstance(facts, dict):
        raise AssertionError("normal runner evidence facts are malformed")
    facts["runner-output-digest"] = category.digest("foreign-runner-output")
    category.resign_column_evidence(evidence)
    probe.replace_category_evidence_for("normal", evidence)


def mandatory_candidate(
    column: str, *, profile_id: str = "new-feature", task_id: str | None = None,
) -> dict[str, object]:
    """Return the frozen request selected by one mandatory binding."""

    if (
        profile_id not in category.PROFILE_IDS
        or column not in approved_mandatory_columns()
    ):
        raise AssertionError("unknown mandatory coverage column")
    candidate = category.candidate_document(profile_id, column)
    if task_id is not None:
        candidate["task_id"] = task_id
    return candidate


def install_mandatory_rejection_source(
    probe: category.ProductionCategoryProbe,
    column: str,
) -> None:
    """Replace one typed fact while preserving the record's canonical shape."""

    if column not in set(approved_mandatory_columns()) - {"real-e2e"}:
        raise AssertionError("unknown mandatory coverage column")
    evidence = probe.resolve_category_evidence(probe.task_id, column)
    facts = evidence.get("facts")
    if type(facts) is not dict or not facts:
        raise AssertionError("mandatory typed evidence facts are malformed")
    fact_id = sorted(facts)[0]
    value = facts[fact_id]
    if type(value) is int:
        changed: object = value + 1
    elif type(value) is list:
        changed = [*value, category.digest(f"foreign:{column}:{fact_id}")]
    elif type(value) is str and value.startswith("sha256-jcs-v1:"):
        changed = category.digest(f"foreign:{column}:{fact_id}")
    elif type(value) is str:
        changed = value + ":foreign"
    else:
        raise AssertionError("mandatory typed evidence fact cannot be substituted")
    facts[fact_id] = changed
    category.resign_column_evidence(evidence)
    probe.replace_category_evidence_for(column, evidence)


def _serial_state_signature(
    probe: category.ProductionCategoryProbe,
    target: object,
    *,
    real_e2e: bool,
) -> object:
    if real_e2e:
        return real_e2e_state_signature(probe)
    path = getattr(target, "path", None)
    if not isinstance(path, pathlib.Path):
        raise AssertionError("coverage serial local target is unavailable")
    return (
        probe.signature(),
        probe.rollback_signature(),
        path.read_bytes(),
        getattr(target, "mutation_count", None),
        getattr(target, "query_count", None),
    )



def _run_serial_release_binding(*, api4: Slice4API, plan: object, column: str,
    disposition: str, quiescent: bool, scenario: str | None = None) -> SerialCoverageExecution:
    from tests.support.wp08_release_operations import release_mandatory_runtime, PrivateReleaseCoverageRoot
    from tests.integration.test_wp08_release_operations import WP08RetainedReleaseSessionTests

    test_id = (profile_mandatory_test_id("release-operations", column, disposition) if scenario is None
        else "GEW-PSC-RELEASE-OPERATIONS-" + scenario.upper() + "-" + disposition)
    task_id = str(plan.binding(test_id)["task_id"])
    private_root = PrivateReleaseCoverageRoot() if quiescent else None
    context = private_root or release_mandatory_runtime(column=column, task_id=task_id,
        accepted=disposition == "P", scenario=scenario)
    try:
        values = (private_root.produce(column=column, task_id=task_id, accepted=disposition == "P", scenario=scenario)
            if private_root is not None else context.__enter__())
        _api, action, session, application, probe, target, candidate, evidence, _outcome = values
        candidate["request_id"] = "wp08-s4:release-operations:" + column + ":" + disposition.lower()
        if scenario is not None:
            candidate["request_id"] = "wp08-s4:release-operations:" + scenario + ":" + disposition.lower()
        if disposition == "R" and column != "real-e2e" and scenario is None:
            # Inject one coherently re-signed wrong fact. Preserve the real
            # reference transaction so this negative has no unrelated dangling
            # transaction introduced by the general tamper helper.
            original_ref = probe._evidence_by_column[column][0]
            with probe.factory.open("doctor") as connection:
                original_transaction = connection.execute(
                    "SELECT transaction_id FROM object_references WHERE task_id=? AND digest=?",
                    (task_id, original_ref)).fetchone()[0]
            install_mandatory_rejection_source(probe, column)
            replacement_ref = probe._evidence_by_column[column][0]
            with probe.factory.open("application") as connection, connection.transaction():
                connection.execute("UPDATE object_references SET transaction_id=? WHERE task_id=? AND digest=?",
                    (original_transaction, task_id, replacement_ref))
        def signature():
            return (WP08RetainedReleaseSessionTests._repository_rows(action),
                {p.name: p.read_bytes() for p in session._root._root_path.iterdir()},
                session._root.mutation_count, session.target.apply_count)
        before = signature()
        original_candidate = copy.deepcopy(candidate)
        if disposition == "P":
            application.assess_and_commit(candidate, observer=target, release_operations_evidence=evidence)
        authority = api4.ProfileCoverageAuthority(plan=plan, category_application=application,
            task_application=probe.task_application, repository=probe.repository,
            object_repository=probe.objects, runtime=probe.runtime)
        execution = (authority.observe_completion(test_id, task_id=task_id,
            expected_profile_id="release-operations") if disposition == "P"
            else authority.execute_rejection(test_id, candidate=candidate, observer=target))
        after = signature()
        if candidate != original_candidate or (disposition == "R" and before != after):
            raise AssertionError("release binding changed rejection state or caller request")
        result = SerialCoverageExecution(test_id=test_id, profile_id="release-operations",
            column_id=column, disposition=disposition, application=application,
            authority=authority, execution=execution, probe=probe, target=target,
            candidate=candidate, state_before=before, state_after=after,
            release_operations_context=context)
        if quiescent:
            from tests.support.wp08_scenario_truth import issue_quiescent_binding
            reader = authority._seal_release_reader(execution, action.retained_namespace)
            result.release_operations_reader = reader
            private_root.seal_producer(reader)
            private_root.open()
            reader._bind_source_reopener(private_root.refresh)
            def projection(handle):
                if handle is not reader:
                    raise AssertionError("release lifecycle handle is foreign")
                return {"authority": authority._binding_lifecycle_projection(execution),
                    "binding_identity": reader._context()["binding"].to_dict(),
                    "target_state": {"session_closed": reader.session_closed()}}
            lifecycle = issue_quiescent_binding(
                binding_identity=reader._context()["binding"].to_dict(),
                close_handle=private_root.close_handle, opened_handle=reader,
                private_root=private_root.path, project_current=projection,
                reopen_handle=private_root.open, terminate_root=private_root.terminate)
            result.binding_lifecycle = lifecycle
            authority._bind_binding_lifecycle(lifecycle)
        return result
    except BaseException:
        context.__exit__(None, None, None)
        raise

def run_serial_profile_binding(
    *,
    api4: Slice4API,
    plan: object,
    profile_id: str,
    column: str,
    disposition: str,
    shared_runtime: category.SharedProductionCategoryRuntime | None = None,
    quiescent: bool = False,
) -> SerialCoverageExecution:
    """Execute one isolated binding on its consumer-authority thread."""

    if profile_id == "release-operations":
        if shared_runtime is not None:
            raise AssertionError("release binding requires its own action and task roots")
        return _run_serial_release_binding(api4=api4, plan=plan, column=column,
            disposition=disposition, quiescent=quiescent)

    test_id = profile_mandatory_test_id(profile_id, column, disposition)
    binding = plan.binding(test_id)
    task_id = str(binding["task_id"])
    real_e2e = column == "real-e2e"
    probe: category.ProductionCategoryProbe | None = None
    target: object | None = None
    owned_dependency_context: object | None = None
    private_repository_root: object | None = None
    private_action_root: object | None = None
    private_shared_runtime: object | None = None
    private_real_e2e_root: object | None = None
    private_real_e2e_handle: object | None = None
    try:
        if real_e2e:
            if quiescent:
                from tests.support import wp08_scenario_truth as lifecycle_fixture

                if shared_runtime is not None:
                    raise AssertionError(
                        "quiescent real-E2E binding cannot share a Profile runtime"
                    )
                private_repository_root = (
                    lifecycle_fixture.PrivateCategoryRepositoryRoot(profile_id)
                )
                private_shared_runtime = private_repository_root.open()
                private_real_e2e_root = PrivateRealE2ERoot()
                private_action_root = private_real_e2e_root.action_root
            _api, application, probe, target = production_real_e2e_runtime(
                accepted=disposition == "P", profile_id=profile_id,
                task_id=task_id,
                private_repository_runtime=private_shared_runtime,
                private_tool_root=private_real_e2e_root,
            )
            private_real_e2e_handle = getattr(
                probe, "private_real_e2e_handle", None,
            )
            candidate = real_e2e_candidate(
                accepted=disposition == "P", profile_id=profile_id,
                task_id=task_id,
            )
        else:
            if quiescent:
                from tests.support import wp08_scenario_truth as lifecycle_fixture

                if shared_runtime is not None:
                    raise AssertionError(
                        "quiescent binding cannot share a Profile runtime"
                    )
                private_repository_root = (
                    lifecycle_fixture.PrivateCategoryRepositoryRoot(profile_id)
                )
                private_action_root = (
                    lifecycle_fixture.PrivateActionRepositoryRoot()
                )
                private_shared_runtime = private_repository_root.open()
                shared_runtime = private_shared_runtime
            _api, application, probe, target = production_runtime(
                column, profile_id=profile_id, task_id=task_id,
                shared_runtime=shared_runtime,
                private_action_root=private_action_root,
                performance_measurement=(
                    profile_id == "performance"
                ),
            )
            candidate = mandatory_candidate(
                column, profile_id=profile_id, task_id=task_id,
            )
            if disposition == "R":
                install_mandatory_rejection_source(probe, column)
        candidate_before = copy.deepcopy(candidate)
        state_before = _serial_state_signature(
            probe, target, real_e2e=real_e2e,
        )
        dependency_security: tuple[object, object] | None = None
        dependency_graph_scenario: str | None = None
        if profile_id == "dependency-security":
            from tests.support import wp08_dependency_security as dependency_fixture
            candidate_scenario = candidate.get("scenario_id")
            dependency_graph_scenario = next((
                scenario_id
                for scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
                if candidate_scenario == (
                    "GEW-PSC-DEPENDENCY-SECURITY-"
                    f"{scenario_id.upper()}-P"
                )
            ), None)
            if shared_runtime is not None and not real_e2e:
                dependency_context = shared_runtime.dependency_security_context
                if dependency_context is None:
                    dependency_context = (
                        dependency_fixture.dependency_security_coverage_context(
                            probe.repository,
                            after_fixed_closure=(
                                dependency_graph_scenario != "fix-unavailable"
                            ),
                            advisory_identity=(
                                ("advisory:cffi:security-v1", 1)
                                if dependency_graph_scenario
                                == "transitive-dependency"
                                else (
                                    "advisory:example-dependency:security-v1", 2
                                )
                            ),
                        )
                    )
                    shared_runtime.dependency_security_context = dependency_context
            else:
                dependency_context = (
                    dependency_fixture.dependency_security_coverage_context(
                        probe.repository,
                        after_fixed_closure=(
                            dependency_graph_scenario != "fix-unavailable"
                        ),
                        advisory_identity=(
                            ("advisory:cffi:security-v1", 1)
                            if dependency_graph_scenario == "transitive-dependency"
                            else ("advisory:example-dependency:security-v1", 2)
                        ),
                    )
                )
                owned_dependency_context = dependency_context
            if quiescent and owned_dependency_context is None:
                owned_dependency_context = dependency_context
                if (
                    shared_runtime is not None
                    and shared_runtime.dependency_security_context
                    is dependency_context
                ):
                    shared_runtime.dependency_security_context = None
            if dependency_graph_scenario is not None:
                dependency_security = dependency_context.observe_graph(
                    application,
                    probe.task_id,
                    scenario_id=dependency_graph_scenario,
                )
            else:
                dependency_security = dependency_context.observe(
                    application, probe.task_id,
                )
        if disposition == "P":
            performance_context = getattr(
                probe, "performance_context", None,
            )
            application.assess_and_commit(
                candidate,
                observer=target,
                performance_evidence=getattr(
                    performance_context, "evidence", None,
                ),
                dependency_graph_evidence=(
                    dependency_security
                    if dependency_graph_scenario is not None
                    else None
                ),
            )
        authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=application,
            task_application=probe.task_application,
            repository=probe.repository,
            object_repository=probe.objects,
            runtime=probe.runtime,
            dependency_security=dependency_security,
        )
        if disposition == "P":
            execution = authority.observe_completion(
                test_id,
                task_id=probe.task_id,
                expected_profile_id=profile_id,
            )
        else:
            execution = authority.execute_rejection(
                test_id, candidate=candidate, observer=target,
            )
        state_after = _serial_state_signature(
            probe, target, real_e2e=real_e2e,
        )
        if candidate != candidate_before:
            raise AssertionError("coverage serial execution mutated its caller input")
        if disposition == "R" and state_after != state_before:
            raise AssertionError("coverage serial rejection changed durable state")
        if getattr(execution, "test_id", None) != test_id:
            raise AssertionError("coverage serial execution returned the wrong stable ID")
        if getattr(execution, "result", None) != (
            "COMPLETED" if disposition == "P" else "EXPECTED_REJECTION"
        ):
            raise AssertionError("coverage serial execution returned the wrong result")
        result = SerialCoverageExecution(
            test_id=test_id,
            profile_id=profile_id,
            column_id=column,
            disposition=disposition,
            application=application,
            authority=authority,
            execution=execution,
            probe=probe,
            target=target,
            candidate=candidate,
            state_before=state_before,
            state_after=state_after,
            dependency_security_context=owned_dependency_context,
            performance_context=getattr(
                probe, "performance_context", None,
            ),
        )
        if quiescent:
            result.enable_quiescent_lifecycle(
                repository_root=private_repository_root,
                action_root=private_action_root,
                shared_runtime=private_shared_runtime,
                real_e2e_root=private_real_e2e_root,
                real_e2e_handle=private_real_e2e_handle,
            )
        return result
    except BaseException:
        if target is not None:
            close = getattr(target, "close", None)
            if callable(close):
                close()
            elif probe is not None:
                probe.close()
        elif probe is not None:
            probe.close()
        close_dependency = getattr(owned_dependency_context, "close", None)
        if callable(close_dependency):
            close_dependency()
        if private_real_e2e_root is not None:
            if private_real_e2e_handle is not None:
                try:
                    private_real_e2e_root.close_handle(
                        private_real_e2e_handle, purpose=None,
                    )
                except Exception:
                    pass
            try:
                private_real_e2e_root.terminate("revoke")
            except Exception:
                pass
            private_action_root = None
        if private_action_root is not None:
            private_action_fixture = getattr(
                probe, "private_action_fixture", None,
            )
            if private_action_fixture is not None:
                try:
                    private_action_root.close_handle(private_action_fixture)
                except Exception:
                    pass
            try:
                private_action_root.terminate("revoke")
            except Exception:
                pass
        if private_repository_root is not None:
            if private_shared_runtime is not None:
                try:
                    private_repository_root.close_handle(private_shared_runtime)
                except Exception:
                    pass
            try:
                private_repository_root.terminate("revoke")
            except Exception:
                pass
        raise


def run_serial_scenario_binding(
    *,
    api4: Slice4API,
    plan: object,
    scenario_id: str,
    disposition: str,
    quiescent: bool = False,
) -> SerialCoverageExecution:
    """Execute one exact installed scenario binding in isolation."""

    if scenario_id in ("artifact-provenance", "health-gate", "partial-deploy"):
        return _run_serial_release_binding(api4=api4, plan=plan, column="boundary",
            disposition=disposition, quiescent=quiescent, scenario=scenario_id)

    scenarios = {
        SCAFFOLD_SCENARIO_ID: (
            "new-feature",
            SCAFFOLD_PASS_TEST_ID,
            SCAFFOLD_REJECT_TEST_ID,
            SCAFFOLD_BOUNDARY_CASE_ID,
            scaffold_candidate,
        ),
        EXISTING_FEATURE_SCENARIO_ID: (
            "new-feature",
            EXISTING_FEATURE_PASS_TEST_ID,
            EXISTING_FEATURE_REJECT_TEST_ID,
            EXISTING_FEATURE_BOUNDARY_CASE_ID,
            existing_feature_candidate,
        ),
        NEW_FEATURE_MULTI_TARGET_SCENARIO_ID: (
            "new-feature",
            NEW_FEATURE_MULTI_TARGET_PASS_TEST_ID,
            NEW_FEATURE_MULTI_TARGET_REJECT_TEST_ID,
            NEW_FEATURE_MULTI_TARGET_BOUNDARY_CASE_ID,
            new_feature_multi_target_candidate,
        ),
        **{scenario: (
            "hotfix", f"GEW-PSC-HOTFIX-{scenario.upper()}-P",
            f"GEW-PSC-HOTFIX-{scenario.upper()}-R", f"GEW-PSC-HOTFIX-{scenario.upper()}-P",
            (lambda *, accepted, selected=scenario:
             hotfix_guarded_candidate(selected, accepted=accepted)),
        ) for scenario in HOTFIX_GUARDED_SCENARIO_IDS},
        **{scenario: (
            "refactor-debt",
            f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-P",
            f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-R",
            f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-P",
            (lambda *, accepted, selected=scenario:
             refactor_scenario_candidate(selected, accepted=accepted)),
        ) for scenario in REFACTOR_SCENARIO_IDS},
        **{scenario: (
            "incident-response",
            f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-P",
            f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-R",
            f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-P",
            (lambda *, accepted, selected=scenario:
             incident_scenario_candidate(selected, accepted=accepted)),
        ) for scenario in INCIDENT_SCENARIO_IDS},
        BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID: (
            "bug-fix",
            BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
            BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
            BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
            bug_fix_reproducible_failure_candidate,
        ),
        BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID: (
            "bug-fix",
            BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID,
            BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID,
            BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID,
            bug_fix_false_reproduction_candidate,
        ),
        BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID: (
            "bug-fix",
            BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID,
            BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID,
            BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID,
            bug_fix_regression_boundary_candidate,
        ),
        HOTFIX_MINIMAL_PATCH_SCENARIO_ID: (
            "hotfix",
            HOTFIX_MINIMAL_PATCH_PASS_TEST_ID,
            HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID,
            HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID,
            hotfix_minimal_patch_candidate,
        ),
        PERFORMANCE_STABLE_BASELINE_SCENARIO_ID: (
            "performance",
            PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
            PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID,
            PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID,
            performance_stable_baseline_candidate,
        ),
        **{
            performance_scenario_id: (
                "performance",
                f"GEW-PSC-PERFORMANCE-{performance_scenario_id.upper()}-P",
                f"GEW-PSC-PERFORMANCE-{performance_scenario_id.upper()}-R",
                f"GEW-PSC-PERFORMANCE-{performance_scenario_id.upper()}-P",
                (
                    lambda *, accepted, selected=performance_scenario_id:
                    performance_remaining_scenario_candidate(
                        selected, accepted=accepted,
                    )
                ),
            )
            for performance_scenario_id in PERFORMANCE_REMAINING_SCENARIO_IDS
        },
        DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID: (
            "dependency-security",
            DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID,
            DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID,
            DEPENDENCY_SECURITY_VULNERABLE_GRAPH_BOUNDARY_CASE_ID,
            dependency_security_vulnerable_graph_candidate,
        ),
        **{
            dependency_scenario_id: (
                "dependency-security",
                (
                    "GEW-PSC-DEPENDENCY-SECURITY-"
                    f"{dependency_scenario_id.upper()}-P"
                ),
                (
                    "GEW-PSC-DEPENDENCY-SECURITY-"
                    f"{dependency_scenario_id.upper()}-R"
                ),
                (
                    "GEW-PSC-DEPENDENCY-SECURITY-"
                    f"{dependency_scenario_id.upper()}-P"
                ),
                (
                    lambda *, accepted, scenario_id=dependency_scenario_id:
                    dependency_graph_scenario_candidate(
                        scenario_id, accepted=accepted,
                    )
                ),
            )
            for dependency_scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
        },
        **{
            migration_scenario_id: (
                "migration",
                f"GEW-PSC-MIGRATION-{migration_scenario_id.upper()}-P",
                f"GEW-PSC-MIGRATION-{migration_scenario_id.upper()}-R",
                f"GEW-PSC-MIGRATION-{migration_scenario_id.upper()}-P",
                (
                    lambda *, accepted, scenario_id=migration_scenario_id:
                    migration_scenario_candidate(
                        scenario_id, accepted=accepted,
                    )
                ),
            )
            for migration_scenario_id in MIGRATION_SCENARIO_IDS
        },
    }
    if scenario_id not in scenarios or disposition not in {"P", "R"}:
        raise AssertionError("unknown scenario coverage binding")
    (
        profile_id,
        pass_test_id,
        reject_test_id,
        boundary_case_id,
        candidate_factory,
    ) = scenarios[scenario_id]
    test_id = pass_test_id if disposition == "P" else reject_test_id
    binding = plan.binding(test_id)
    task_id = str(binding["task_id"])
    migration_context: object | None = None
    private_repository_root: object | None = None
    private_action_root: object | None = None
    private_shared_runtime: object | None = None
    if quiescent and profile_id == "migration" and disposition == "P":
        from tests.support import wp08_scenario_truth as lifecycle_fixture

        private_repository_root = lifecycle_fixture.PrivateCategoryRepositoryRoot(
            profile_id,
        )
        private_action_root = lifecycle_fixture.PrivateActionRepositoryRoot()
        private_shared_runtime = private_repository_root.open()
    if profile_id == "migration" and disposition == "P":
        from tests.support import wp08_migration_rehearsal as migration_fixture

        migration_context = migration_fixture._rehearsal_fixture(
            task_id=task_id,
            scenario_boundary_case_id=boundary_case_id,
            selector=candidate_factory(accepted=True),
            shared_runtime=private_shared_runtime,
            private_action_root=private_action_root,
        )
        fixture, _migration_document = migration_context.__enter__()
        application = fixture.category_application
        probe = fixture.probe
        target = fixture.target
        if quiescent:
            migration_handle = migration_fixture.migration_binding_handle(fixture)
            private_repository_root.adopt_active_repository(
                private_shared_runtime,
                migration_handle,
                fixture.repository,
            )
            private_shared_runtime = migration_handle
    else:
        if quiescent:
            from tests.support import wp08_scenario_truth as lifecycle_fixture

            private_repository_root = (
                lifecycle_fixture.PrivateCategoryRepositoryRoot(profile_id)
            )
            private_action_root = lifecycle_fixture.PrivateActionRepositoryRoot()
            private_shared_runtime = private_repository_root.open()
        _api, application, probe, target = production_runtime(
            "boundary",
            profile_id=profile_id,
            scenario_id=boundary_case_id,
            task_id=task_id,
            performance_measurement=(
                profile_id == "performance" and disposition == "P"
            ),
            shared_runtime=private_shared_runtime,
            private_action_root=private_action_root,
        )
    owned_dependency_context: object | None = None
    try:
        candidate = candidate_factory(accepted=disposition == "P")
        candidate_before = copy.deepcopy(candidate)
        state_before = _serial_state_signature(probe, target, real_e2e=False)
        dependency_security: tuple[object, object] | None = None
        if profile_id == "dependency-security":
            from tests.support import wp08_dependency_security as dependency_fixture

            owned_dependency_context = (
                dependency_fixture.dependency_security_coverage_context(
                    probe.repository,
                    after_fixed_closure=(
                        scenario_id != "fix-unavailable"
                    ),
                    advisory_identity=(
                        ("advisory:cffi:security-v1", 1)
                        if scenario_id == "transitive-dependency"
                        else ("advisory:example-dependency:security-v1", 2)
                    ),
                )
            )
            dependency_security = (
                owned_dependency_context.observe_graph(
                    application, probe.task_id, scenario_id=scenario_id,
                )
                if scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
                else owned_dependency_context.observe(
                    application, probe.task_id,
                )
            )
        scenario_truth_context = None
        if scenario_id in SCENARIO_TRUTH_SCENARIO_IDS:
            from tests.support import wp08_scenario_truth as scenario_fixture

            if disposition == "P":
                scenario_truth_context = scenario_fixture.observe_current_candidate(
                    application,
                    target,
                    candidate,
                    probe.scenario_truth_factory,
                )
            else:
                truth_candidate = candidate_factory(accepted=True)
                truth_candidate["task_id"] = task_id
                scenario_truth_context = scenario_fixture.reject_current_candidate(
                    application,
                    target,
                    candidate,
                    truth_candidate,
                    probe.scenario_truth_factory,
                    scenario_id=scenario_id,
                    test_id=test_id,
                    oracle_digest=str(plan.oracle_for(test_id)["oracle_digest"]),
                )
        if disposition == "P" and profile_id != "migration":
            application.assess_and_commit(
                candidate,
                observer=target,
                performance_evidence=(
                    None
                    if profile_id != "performance"
                    else probe.performance_context.evidence
                ),
                dependency_graph_evidence=(
                    dependency_security
                    if scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
                    else None
                ),
                scenario_truth_evidence=(
                    None
                    if scenario_truth_context is None
                    else scenario_truth_context.evidence
                ),
            )
        authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=application,
            task_application=probe.task_application,
            repository=probe.repository,
            object_repository=probe.objects,
            runtime=probe.runtime,
            dependency_security=dependency_security,
            scenario_rejection_factory=(
                scenario_truth_context.registry_factory
                if disposition == "R" and scenario_truth_context is not None
                else None
            ),
        )
        execution = (
            authority.observe_completion(
                test_id,
                task_id=probe.task_id,
                expected_profile_id=profile_id,
            )
            if disposition == "P"
            else authority.execute_rejection(
                test_id, candidate=candidate, observer=target,
                scenario_rejection_evidence=(
                    None if scenario_truth_context is None
                    else scenario_truth_context.evidence
                ),
            )
        )
        state_after = _serial_state_signature(probe, target, real_e2e=False)
        if candidate != candidate_before:
            raise AssertionError("scenario coverage mutated its caller input")
        if disposition == "R" and state_after != state_before:
            raise AssertionError("scenario coverage rejection changed durable state")
        if (
            disposition == "R"
            and scenario_id in SCENARIO_TRUTH_SCENARIO_IDS
            and (
                scenario_truth_context is None
                or scenario_truth_context.test_id != execution.test_id
                or scenario_truth_context.task_id != execution.task_id
                or scenario_truth_context.oracle_digest != execution.oracle_digest
            )
        ):
            raise AssertionError(
                "scenario rejection proof is not bound to its execution oracle"
            )
        if (
            execution.test_id != test_id
            or execution.selector_kind != "scenario"
            or execution.scenario_id != scenario_id
            or execution.category_boundary_case_id
            != boundary_case_id
            or execution.result
            != ("COMPLETED" if disposition == "P" else "EXPECTED_REJECTION")
        ):
            raise AssertionError("scenario coverage returned a mismatched execution")
        migration_rehearsal_projection = None
        if migration_context is not None and disposition == "P":
            from graph_engineering.core.contracts.immutable import (
                FrozenMap,
                freeze,
                thaw,
            )

            assessment = application.current_assessment(
                probe.task_id,
                expected_profile_id="migration",
            )
            current_projection = (
                None
                if assessment is None
                else assessment.migration_rehearsal_projection
            )
            migration_rehearsal_projection = freeze(
                copy.deepcopy(thaw(current_projection))
            )
            if not isinstance(migration_rehearsal_projection, FrozenMap):
                raise AssertionError(
                    "migration lifecycle projection did not freeze"
                )
        result = SerialCoverageExecution(
            test_id=test_id,
            profile_id=profile_id,
            column_id="boundary",
            disposition=disposition,
            application=application,
            authority=authority,
            execution=execution,
            probe=probe,
            target=target,
            candidate=candidate,
            state_before=state_before,
            state_after=state_after,
            dependency_security_context=owned_dependency_context,
            migration_context=migration_context,
            migration_rehearsal_projection=migration_rehearsal_projection,
            scenario_truth_context=scenario_truth_context,
        )
        if quiescent:
            result.enable_quiescent_lifecycle(
                repository_root=private_repository_root,
                action_root=private_action_root,
                shared_runtime=private_shared_runtime,
            )
        return result
    except BaseException:
        if migration_context is not None:
            migration_context.__exit__(*sys.exc_info())
        else:
            target.close()
        close_dependency = getattr(owned_dependency_context, "close", None)
        if callable(close_dependency):
            close_dependency()
        close_scenario = getattr(locals().get("scenario_truth_context"), "close", None)
        if callable(close_scenario):
            close_scenario()
        if private_action_root is not None:
            private_action_fixture = getattr(
                locals().get("probe"), "private_action_fixture", None,
            )
            if private_action_fixture is not None:
                try:
                    private_action_root.close_handle(private_action_fixture)
                except Exception:
                    pass
            try:
                private_action_root.terminate("revoke")
            except Exception:
                pass
        if private_repository_root is not None:
            if private_shared_runtime is not None:
                try:
                    private_repository_root.close_handle(private_shared_runtime)
                except Exception:
                    pass
            try:
                private_repository_root.terminate("revoke")
            except Exception:
                pass
        raise


@contextmanager
def serial_profile_binding(
    *,
    api4: Slice4API,
    plan: object,
    profile_id: str,
    column: str,
    disposition: str,
) -> Iterator[SerialCoverageExecution]:
    """Keep one serial binding live only for its exact validation scope."""

    result = run_serial_profile_binding(
        api4=api4,
        plan=plan,
        profile_id=profile_id,
        column=column,
        disposition=disposition,
    )
    try:
        yield result
    finally:
        result.close()


def coherent_candidate_variant() -> dict[str, object]:
    candidate = rejected_candidate()
    candidate["request_id"] = "wp08-s4:new-feature:normal:foreign"
    return candidate


def rollback_candidate_variant() -> dict[str, object]:
    candidate = rollback_candidate()
    candidate["request_id"] = "wp08-s4:new-feature:rollback:foreign"
    return candidate


def scaffold_candidate(*, accepted: bool) -> dict[str, object]:
    """Return the exact public scaffold boundary selector for Slice 4."""

    candidate = category.candidate_document("new-feature", "boundary")
    candidate["request_id"] = (
        "wp08-s4:new-feature:scaffold:pass"
        if accepted
        else "wp08-s4:new-feature:scaffold:reject"
    )
    candidate["scenario_id"] = (
        SCAFFOLD_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-NEW-FEATURE-SCAFFOLD"
    )
    candidate["task_id"] = coverage_task_id(
        SCAFFOLD_PASS_TEST_ID if accepted else SCAFFOLD_REJECT_TEST_ID
    )
    return candidate


def existing_feature_candidate(*, accepted: bool) -> dict[str, object]:
    """Return the exact public existing-feature boundary selector."""

    candidate = category.candidate_document("new-feature", "boundary")
    candidate["request_id"] = (
        "wp08-s4:new-feature:existing-feature:pass"
        if accepted
        else "wp08-s4:new-feature:existing-feature:reject"
    )
    candidate["scenario_id"] = (
        EXISTING_FEATURE_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE"
    )
    candidate["task_id"] = coverage_task_id(
        EXISTING_FEATURE_PASS_TEST_ID
        if accepted
        else EXISTING_FEATURE_REJECT_TEST_ID
    )
    return candidate


def hotfix_guarded_candidate(scenario_id: str, *, accepted: bool) -> dict[str, object]:
    if scenario_id not in HOTFIX_GUARDED_SCENARIO_IDS:
        raise ValueError("hotfix guarded scenario is not selected")
    candidate = category.candidate_document("hotfix", "boundary")
    candidate["request_id"] = f"wp08-s4:hotfix:{scenario_id}:" + ("pass" if accepted else "reject")
    prefix = f"GEW-PSC-HOTFIX-{scenario_id.upper()}"
    candidate["scenario_id"] = prefix + ("-P" if accepted else "")
    candidate["task_id"] = coverage_task_id(prefix + ("-P" if accepted else "-R"))
    return candidate


def refactor_scenario_candidate(
    scenario_id: str,
    *,
    accepted: bool,
) -> dict[str, object]:
    """Return one exact refactor-debt scenario selector."""

    if scenario_id not in REFACTOR_SCENARIO_IDS:
        raise ValueError("refactor scenario is not selected")
    candidate = category.candidate_document("refactor-debt", "boundary")
    candidate["request_id"] = (
        f"wp08-s4:refactor-debt:{scenario_id}:"
        + ("pass" if accepted else "reject")
    )
    prefix = f"GEW-PSC-REFACTOR-DEBT-{scenario_id.upper()}"
    candidate["scenario_id"] = prefix + ("-P" if accepted else "")
    candidate["task_id"] = coverage_task_id(
        prefix + ("-P" if accepted else "-R")
    )
    return candidate


def incident_scenario_candidate(
    scenario_id: str,
    *,
    accepted: bool,
) -> dict[str, object]:
    """Return one exact incident-response scenario selector."""

    if scenario_id not in INCIDENT_SCENARIO_IDS:
        raise ValueError("incident-response scenario is not selected")
    candidate = category.candidate_document("incident-response", "boundary")
    candidate["request_id"] = (
        f"wp08-s4:incident-response:{scenario_id}:"
        + ("pass" if accepted else "reject")
    )
    prefix = f"GEW-PSC-INCIDENT-RESPONSE-{scenario_id.upper()}"
    candidate["scenario_id"] = prefix + ("-P" if accepted else "")
    candidate["task_id"] = coverage_task_id(
        prefix + ("-P" if accepted else "-R")
    )
    return candidate


def new_feature_multi_target_candidate(*, accepted: bool) -> dict[str, object]:
    """Return only the public selector; local multi-target truth is factory-issued."""

    candidate = category.candidate_document("new-feature", "boundary")
    candidate["request_id"] = (
        "wp08-s4:new-feature:multi-target:pass"
        if accepted
        else "wp08-s4:new-feature:multi-target:reject"
    )
    candidate["scenario_id"] = (
        NEW_FEATURE_MULTI_TARGET_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-NEW-FEATURE-MULTI-TARGET"
    )
    candidate["task_id"] = coverage_task_id(
        NEW_FEATURE_MULTI_TARGET_PASS_TEST_ID
        if accepted
        else NEW_FEATURE_MULTI_TARGET_REJECT_TEST_ID
    )
    return candidate


def bug_fix_reproducible_failure_candidate(
    *, accepted: bool,
) -> dict[str, object]:
    """Return the exact public bug-fix reproducible-failure selector."""

    candidate = category.candidate_document("bug-fix", "boundary")
    candidate["request_id"] = (
        "wp08-s4:bug-fix:reproducible-failure:pass"
        if accepted
        else "wp08-s4:bug-fix:reproducible-failure:reject"
    )
    candidate["scenario_id"] = (
        BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE"
    )
    candidate["task_id"] = coverage_task_id(
        BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
        if accepted
        else BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID
    )
    return candidate


def bug_fix_false_reproduction_candidate(
    *, accepted: bool,
) -> dict[str, object]:
    """Return the exact public bug-fix false-reproduction selector."""

    candidate = category.candidate_document("bug-fix", "boundary")
    candidate["request_id"] = (
        "wp08-s4:bug-fix:false-reproduction:pass"
        if accepted
        else "wp08-s4:bug-fix:false-reproduction:reject"
    )
    candidate["scenario_id"] = (
        BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-BUG-FIX-FALSE-REPRODUCTION"
    )
    candidate["task_id"] = coverage_task_id(
        BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID
        if accepted
        else BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID
    )
    return candidate


def bug_fix_regression_boundary_candidate(
    *, accepted: bool,
) -> dict[str, object]:
    """Return the exact public bug-fix regression-boundary selector."""

    candidate = category.candidate_document("bug-fix", "boundary")
    candidate["request_id"] = (
        "wp08-s4:bug-fix:regression-boundary:pass"
        if accepted
        else "wp08-s4:bug-fix:regression-boundary:reject"
    )
    candidate["scenario_id"] = (
        BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-BUG-FIX-REGRESSION-BOUNDARY"
    )
    candidate["task_id"] = coverage_task_id(
        BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID
        if accepted
        else BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID
    )
    return candidate


def hotfix_minimal_patch_candidate(*, accepted: bool) -> dict[str, object]:
    """Return the exact public hotfix minimal-patch selector."""

    candidate = category.candidate_document("hotfix", "boundary")
    candidate["request_id"] = (
        "wp08-s4:hotfix:minimal-patch:pass"
        if accepted
        else "wp08-s4:hotfix:minimal-patch:reject"
    )
    candidate["scenario_id"] = (
        HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-HOTFIX-MINIMAL-PATCH"
    )
    candidate["task_id"] = coverage_task_id(
        HOTFIX_MINIMAL_PATCH_PASS_TEST_ID
        if accepted
        else HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID
    )
    return candidate


def performance_stable_baseline_candidate(
    *, accepted: bool,
) -> dict[str, object]:
    """Return the exact public performance stable-baseline selector."""

    candidate = category.candidate_document("performance", "boundary")
    candidate["request_id"] = (
        "wp08-s4:performance:stable-baseline:pass"
        if accepted
        else "wp08-s4:performance:stable-baseline:reject"
    )
    candidate["scenario_id"] = (
        PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-PERFORMANCE-STABLE-BASELINE"
    )
    candidate["task_id"] = coverage_task_id(
        PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID
        if accepted
        else PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID
    )
    return candidate


def performance_remaining_scenario_candidate(
    scenario_id: str, *, accepted: bool,
) -> dict[str, object]:
    """Return one exact remaining performance scenario selector."""

    if scenario_id not in PERFORMANCE_REMAINING_SCENARIO_IDS:
        raise AssertionError("unknown remaining performance scenario selector")
    stable = f"GEW-PSC-PERFORMANCE-{scenario_id.upper()}"
    candidate = category.candidate_document("performance", "boundary")
    candidate["request_id"] = (
        f"wp08-s4:performance:{scenario_id}:pass"
        if accepted
        else f"wp08-s4:performance:{scenario_id}:reject"
    )
    candidate["scenario_id"] = f"{stable}-P" if accepted else stable
    candidate["task_id"] = coverage_task_id(
        f"{stable}-{'P' if accepted else 'R'}"
    )
    return candidate


def dependency_security_vulnerable_graph_candidate(
    *, accepted: bool,
) -> dict[str, object]:
    """Return the exact dependency-security vulnerable-graph selector."""

    candidate = category.candidate_document("dependency-security", "boundary")
    candidate["request_id"] = (
        "wp08-s4:dependency-security:vulnerable-graph:pass"
        if accepted
        else "wp08-s4:dependency-security:vulnerable-graph:reject"
    )
    candidate["scenario_id"] = (
        DEPENDENCY_SECURITY_VULNERABLE_GRAPH_BOUNDARY_CASE_ID
        if accepted
        else "GEW-PSC-DEPENDENCY-SECURITY-VULNERABLE-GRAPH"
    )
    candidate["task_id"] = coverage_task_id(
        DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID
        if accepted
        else DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID
    )
    return candidate


def dependency_graph_scenario_candidate(
    scenario_id: str, *, accepted: bool,
) -> dict[str, object]:
    """Return one exact dependency graph/remediation boundary selector."""

    if scenario_id not in DEPENDENCY_GRAPH_SCENARIO_IDS:
        raise AssertionError("unknown dependency graph scenario selector")
    stable = f"GEW-PSC-DEPENDENCY-SECURITY-{scenario_id.upper()}"
    candidate = category.candidate_document("dependency-security", "boundary")
    candidate["request_id"] = (
        f"wp08-s4:dependency-security:{scenario_id}:pass"
        if accepted
        else f"wp08-s4:dependency-security:{scenario_id}:reject"
    )
    candidate["scenario_id"] = f"{stable}-P" if accepted else stable
    candidate["task_id"] = coverage_task_id(
        f"{stable}-{'P' if accepted else 'R'}"
    )
    return candidate


def migration_scenario_candidate(
    scenario_id: str, *, accepted: bool,
) -> dict[str, object]:
    """Return one exact public migration scenario boundary selector."""

    if scenario_id not in MIGRATION_SCENARIO_IDS:
        raise AssertionError("unknown migration scenario selector")
    member = f"GEW-PSC-MIGRATION-{scenario_id.upper()}"
    candidate = category.candidate_document("migration", "boundary")
    candidate["request_id"] = (
        f"wp08-s4:migration:{scenario_id}:pass"
        if accepted else f"wp08-s4:migration:{scenario_id}:reject"
    )
    candidate["scenario_id"] = f"{member}-P" if accepted else member
    candidate["task_id"] = coverage_task_id(
        f"{member}-{'P' if accepted else 'R'}"
    )
    return candidate


def install_rollback_rejection_source(
    probe: category.ProductionCategoryProbe,
    attack: str,
) -> None:
    """Install one exact rollback rejection condition after source pinning."""

    if attack in {"foreign-action-id", "wrong-action-status", "wrong-claim-status"}:
        evidence = probe.resolve_category_evidence(probe.task_id, "rollback")
        facts = evidence["facts"]
        if not isinstance(facts, dict):
            raise AssertionError("rollback evidence facts are malformed")
        if attack == "foreign-action-id":
            facts["action-id"] = "action:foreign"
        elif attack == "wrong-action-status":
            facts["action-status"] = "authorized"
        else:
            facts["claim-status"] = "unresolved"
        category.resign_column_evidence(evidence)
        probe.replace_category_evidence_for("rollback", evidence)
        return
    action = probe._rollback_action
    if action is None:
        raise AssertionError("rollback action authority is unavailable")
    bridge_action = probe.resolve_category_evidence(probe.task_id, "rollback")[
        "facts"
    ]
    if not isinstance(bridge_action, dict):
        raise AssertionError("rollback evidence facts are malformed")
    action_id = bridge_action["action-id"]
    if not isinstance(action_id, str):
        raise AssertionError("rollback action ID is malformed")
    if attack == "stale-journal":
        action.journal.test_only_set_state(action_id, "prepared")
        return
    if attack == "stale-target":
        local_target = probe._rollback_local_target
        if local_target is None:
            raise AssertionError("rollback local target is unavailable")
        local_target.force_observation_revision = 1
        return
    raise AssertionError(f"unknown rollback rejection attack: {attack}")


def coherently_resigned_oracle_resources(
    *,
    scenario: bool = False,
    scenario_id: str = SCAFFOLD_SCENARIO_ID,
    profile_id: str = "new-feature",
) -> tuple[
    bytes, bytes, tuple[bytes, ...], bytes
]:
    """Return exact live resources with one self-consistent foreign oracle body."""

    import graph_engineering
    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.profile_coverage import profile_coverage_digest

    provenance, plan, oracles, runner = (
        graph_engineering._profile_coverage_installation_resources()
    )
    index = next(
        candidate_index
        for candidate_index, body in enumerate(oracles)
        if (
            (document := json.loads(body)).get("profile_id") == profile_id
            and document.get("column_id") == ("boundary" if scenario else "rollback")
            and document.get("selector_kind") == (
                "scenario" if scenario else "mandatory"
            )
            and (
                not scenario or document.get("scenario_id") == scenario_id
            )
        )
    )
    changed = json.loads(oracles[index])
    changed["reject_error_message"] = (
        f"coherently substituted {scenario_id} oracle"
        if scenario
        else "coherently substituted rollback oracle"
    )
    changed.pop("oracle_digest")
    changed["oracle_digest"] = profile_coverage_digest(
        changed,
        contract="profile-coverage-oracle",
        schema="profile-coverage-oracle-input",
    )
    bodies = list(oracles)
    bodies[index] = canonical_bytes(changed)
    return provenance, plan, tuple(bodies), runner


def coherently_resigned_scenario_plan_resources(
    scenario_test_id: str = SCAFFOLD_PASS_TEST_ID,
) -> tuple[
    bytes, bytes, tuple[bytes, ...], bytes
]:
    """Return a self-consistent foreign scenario selector under stale bootstrap."""

    import graph_engineering
    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.profile_coverage import profile_coverage_digest

    provenance, plan_body, oracles, runner = (
        graph_engineering._profile_coverage_installation_resources()
    )
    plan = json.loads(plan_body)
    binding = next(
        item for item in plan["bindings"]
        if item["test_id"] == scenario_test_id
    )
    binding["overlay_id"] = "compact-planned"
    selector_fields = (
        "test_id", "profile_id", "selector_kind", "column_id", "scenario_id",
        "category_boundary_case_id", "overlay_id", "disposition",
        "expected_result", "execution_kind", "oracle_id", "oracle_digest",
        "task_id",
    )
    binding["selector_digest"] = profile_coverage_digest(
        {
            "schema_version": "1.0.0",
            **{field: binding[field] for field in selector_fields},
        },
        contract="profile-coverage-plan-selector",
        schema="profile-coverage-plan-selector",
    )
    plan.pop("plan_digest")
    plan["plan_digest"] = profile_coverage_digest(
        plan,
        contract="profile-coverage-execution-plan",
        schema="profile-coverage-execution-plan-input",
    )
    return provenance, canonical_bytes(plan), oracles, runner


def coherently_resigned_binding_plan_resources(attack: str) -> tuple[
    bytes, bytes, tuple[bytes, ...], bytes
]:
    """Return a foreign binding plan with every local plan pin coherently re-signed."""

    import graph_engineering
    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.profile_coverage import profile_coverage_digest

    provenance, plan_body, oracles, runner = (
        graph_engineering._profile_coverage_installation_resources()
    )
    plan = json.loads(plan_body)
    bindings = plan["bindings"]
    if not isinstance(bindings, list):
        raise AssertionError("coverage plan bindings are malformed")
    if attack == "mandatory-test-id-column-swap":
        normal = next(item for item in bindings if item["test_id"] == PASS_TEST_ID)
        rollback = next(
            item for item in bindings if item["test_id"] == ROLLBACK_PASS_TEST_ID
        )
        normal["test_id"], rollback["test_id"] = (
            rollback["test_id"], normal["test_id"],
        )
        bindings.sort(key=lambda item: item["test_id"])
    elif attack == "scenario-real-target":
        binding = next(
            item for item in bindings if item["test_id"] == SCAFFOLD_PASS_TEST_ID
        )
        binding["execution_kind"] = "real-target"
    elif attack == "pass-rejection-result":
        binding = next(item for item in bindings if item["test_id"] == PASS_TEST_ID)
        binding["expected_result"] = "EXPECTED_REJECTION"
    elif attack == "reject-completion-result":
        binding = next(item for item in bindings if item["test_id"] == REJECT_TEST_ID)
        binding["expected_result"] = "COMPLETED"
    elif attack in {"task-id-alias", "task-id-coherent-substitution"}:
        binding = next(item for item in bindings if item["test_id"] == PASS_TEST_ID)
        binding["task_id"] = (
            "task:wp08-coverage:gew-pro-foreign-normal-p"
        )
    elif attack == "duplicate-task-id":
        first = next(item for item in bindings if item["test_id"] == PASS_TEST_ID)
        second = next(item for item in bindings if item["test_id"] == REJECT_TEST_ID)
        second["task_id"] = first["task_id"]
    elif attack == "cross-binding-task-id":
        first = next(item for item in bindings if item["test_id"] == PASS_TEST_ID)
        second = next(
            item for item in bindings if item["test_id"] == ROLLBACK_PASS_TEST_ID
        )
        first["task_id"], second["task_id"] = (
            second["task_id"], first["task_id"],
        )
    elif attack == "binding-reorder":
        bindings[0], bindings[1] = bindings[1], bindings[0]
    else:
        raise AssertionError(f"unknown coverage plan binding attack: {attack}")

    selector_fields = (
        "test_id", "profile_id", "selector_kind", "column_id", "scenario_id",
        "category_boundary_case_id", "overlay_id", "disposition",
        "expected_result", "execution_kind", "oracle_id", "oracle_digest",
        "task_id",
    )
    for binding in bindings:
        binding["selector_digest"] = profile_coverage_digest(
            {
                "schema_version": "1.0.0",
                **{field: binding[field] for field in selector_fields},
            },
            contract="profile-coverage-plan-selector",
            schema="profile-coverage-plan-selector",
        )
    previous_plan_digest = plan.pop("plan_digest")
    plan["plan_digest"] = profile_coverage_digest(
        plan,
        contract="profile-coverage-execution-plan",
        schema="profile-coverage-execution-plan-input",
    )
    changed_plan = canonical_bytes(plan)
    previous_raw_digest = hashlib.sha256(plan_body).hexdigest()
    changed_raw_digest = hashlib.sha256(changed_plan).hexdigest()
    changed_provenance = provenance.replace(
        str(previous_plan_digest).encode(), str(plan["plan_digest"]).encode(), 1,
    ).replace(
        previous_raw_digest.encode(), changed_raw_digest.encode(), 1,
    )
    if changed_provenance == provenance:
        raise AssertionError("coverage plan bootstrap pins were not replaced")
    return changed_provenance, changed_plan, oracles, runner


def clone_opaque(value: object) -> object:
    clone = object.__new__(type(value))
    fields = getattr(type(value), "__dataclass_fields__", {})
    for field in fields:
        object.__setattr__(clone, field, getattr(value, field))
    return clone


def _changed_value(field: str, value: object) -> object:
    if field == "materialization_pins":
        changed = dict(value)  # type: ignore[arg-type]
        changed["materialization_digest"] = category.digest("coherent-resign")
        return changed
    if type(value) is int:
        return value + 1
    replacements = {
        "test_id": PASS_TEST_ID,
        "result": "COMPLETED",
        "profile_id": "bug-fix",
        "profile_version": "9.0.0",
        "column_id": "boundary",
        "overlay_id": "compact-planned",
        "overlay_version": "9.0.0",
        "task_id": "task:foreign:local",
        "oracle_id": "ORA-PROFILE-BUG-FIX",
        "runtime_kind": "foreign-runtime",
        "runtime_lineage_id": "foreign-lineage",
        "execution_kind": "real-target",
        "rejection_error_type": "ForeignCategoryError",
        "rejection_error_message": "coherently substituted rejection",
    }
    if field in replacements:
        return replacements[field]
    if value is None:
        return category.digest(f"coherent:{field}")
    if type(value) is str and value.startswith("sha256:"):
        return "sha256:" + hashlib.sha256(f"coherent:{field}".encode()).hexdigest()
    if type(value) is str and value.startswith("sha256-jcs-v1:"):
        return category.digest(f"coherent:{field}")
    if type(value) is str:
        return value + ":coherent"
    raise AssertionError(f"unsupported coherent field: {field}")


def coherently_resign_execution(value: object, field: str) -> dict[str, object]:
    """Mutate one live issued projection and recompute both public digests."""

    from graph_engineering.core.contracts.canonical import canonical_bytes
    from graph_engineering.core.profile_coverage import profile_coverage_digest

    original = {
        name: getattr(value, name)
        for name in type(value).__dataclass_fields__
        if not name.startswith("_")
    }
    object.__setattr__(value, field, _changed_value(field, original[field]))
    body = {
        "schema_version": "1.0.0",
        **{
            name: getattr(value, name)
            for name in original
            if name not in {"execution_digest", "execution_object_digest"}
        },
    }
    execution_digest = profile_coverage_digest(
        body,
        contract="profile-coverage-execution-record",
        schema="profile-coverage-execution-record",
    )
    object.__setattr__(value, "execution_digest", execution_digest)
    object_document = {**body, "execution_digest": execution_digest}
    object.__setattr__(
        value,
        "execution_object_digest",
        "sha256:" + hashlib.sha256(canonical_bytes(object_document)).hexdigest(),
    )
    return original


def coherently_resign_observation(value: object, field: str) -> dict[str, object]:
    """Mutate one live observation projection and recompute its public digest."""

    from graph_engineering.core.profile_coverage import profile_coverage_digest

    original = {
        name: getattr(value, name)
        for name in type(value).__dataclass_fields__
        if not name.startswith("_")
    }
    object.__setattr__(value, field, _changed_value(field, original[field]))
    body = {
        "schema_version": "1.0.0",
        **{
            name: getattr(value, name)
            for name in original
            if name != "observation_digest"
        },
    }
    object.__setattr__(
        value,
        "observation_digest",
        profile_coverage_digest(
            body,
            contract="profile-coverage-observation",
            schema="profile-coverage-observation",
        ),
    )
    return original


def coherently_resign_coverage_record(
    value: object, replacements: dict[str, object],
) -> dict[str, object]:
    """Apply a coherent observation projection to one live CoverageRecord."""

    from graph_engineering.core.contracts.digest import semantic_digest

    original = {
        name: getattr(value, name)
        for name in type(value).__dataclass_fields__
        if not name.startswith("_")
    }
    for field, item in replacements.items():
        if field in original and field != "record_digest":
            object.__setattr__(value, field, item)
    fields = tuple(name for name in original if name != "record_digest")
    object.__setattr__(
        value,
        "record_digest",
        semantic_digest(
            {
                "schema_version": "1.0.0",
                **{field: getattr(value, field) for field in fields},
            },
            contract_type="urn:gew:contract:coverage-record",
            projection_id="urn:gew:digest-projection:coverage-record:1.0.0",
            schema_id="urn:gew:schema:coverage-record-input:1.0.0",
        ),
    )
    return original


def coherently_substitute_issued_chain(
    execution: object,
    observation: object,
    coverage_record: object,
    field: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Coherently re-sign one live execution→observation→coverage chain."""

    execution_original = coherently_resign_execution(execution, field)
    observation_original = {
        name: getattr(observation, name)
        for name in type(observation).__dataclass_fields__
        if not name.startswith("_")
    }
    if field in observation_original:
        object.__setattr__(observation, field, getattr(execution, field))
    object.__setattr__(
        observation, "execution_digest", getattr(execution, "execution_digest")
    )
    object.__setattr__(
        observation, "evidence_digest", getattr(execution, "execution_object_digest")
    )
    object.__setattr__(
        observation,
        "evidence_ref",
        "profile-coverage-execution:"
        + str(getattr(execution, "execution_object_digest")),
    )
    from graph_engineering.core.profile_coverage import profile_coverage_digest

    observation_body = {
        "schema_version": "1.0.0",
        **{
            name: getattr(observation, name)
            for name in observation_original
            if name != "observation_digest"
        },
    }
    object.__setattr__(
        observation,
        "observation_digest",
        profile_coverage_digest(
            observation_body,
            contract="profile-coverage-observation",
            schema="profile-coverage-observation",
        ),
    )
    coverage_original = coherently_resign_coverage_record(
        coverage_record,
        {
            name: getattr(observation, name)
            for name in observation_original
            if hasattr(coverage_record, name)
        },
    )
    return execution_original, observation_original, coverage_original


def restore_fields(value: object, fields: dict[str, object]) -> None:
    for field, item in fields.items():
        object.__setattr__(value, field, item)


def source_post_attestation_mutation_is_rejected() -> bool:
    """Probe a copied, owner-attested checkout without touching live source bytes."""

    import graph_engineering
    from tests.support import source_checkout_attestation as issuer

    root = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="gew-s4-source-attack-") as directory:
        temporary = pathlib.Path(directory)
        source = temporary / "source"
        source.mkdir()
        for relative in issuer.SOURCE_FILES:
            source_path = root / relative
            destination = source / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, destination)
        protected_relative = "core/graph_engineering/core/profiles.py"
        protected = source / protected_relative
        if not protected.exists():
            protected.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / protected_relative, protected)
        control = temporary / "control"
        issuer.issue_source_checkout_attestation(source, control)
        protected.write_bytes(protected.read_bytes() + b"\n# post-attestation mutation\n")
        previous = sys._xoptions.get(issuer.CONTROL_OPTION)
        sys._xoptions[issuer.CONTROL_OPTION] = str(control.resolve(strict=True))
        try:
            try:
                graph_engineering._validate_source_checkout_attestation(source)
            except graph_engineering.DistributionIdentityError:
                return True
            return False
        finally:
            if previous is None:
                sys._xoptions.pop(issuer.CONTROL_OPTION, None)
            else:
                sys._xoptions[issuer.CONTROL_OPTION] = previous


def installed_distribution_attack_returncodes() -> dict[str, int]:
    """Build one wheel and probe unpacked RECORD and physical archive attacks."""

    root = pathlib.Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix="gew-s4-wheel-attacks-") as directory:
        temporary = pathlib.Path(directory)
        distribution = temporary / "dist"
        distribution.mkdir()
        built = subprocess.run(
            [sys.executable, str(root / "scripts/build_wheel.py"), str(distribution)],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if built.returncode:
            raise AssertionError(built.stderr.decode(errors="replace"))
        wheel = next(distribution.glob("*.whl"))
        protected_member = "graph_engineering/core/profiles.py"
        probe = (
            "import sys;sys.path.insert(0,sys.argv[1]);"
            "import graph_engineering;print(graph_engineering.__file__)"
        )

        unpacked = temporary / "unpacked"
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(unpacked)
        record = next(unpacked.glob("*.dist-info/RECORD"))
        record.write_bytes(
            record.read_bytes() + f"{protected_member},,\n".encode()
        )
        unpacked_result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(unpacked)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )

        duplicate = temporary / "duplicate.whl"
        shutil.copyfile(wheel, duplicate)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(duplicate, "a") as archive:
                archive.writestr(protected_member, archive.read(protected_member))
        duplicate_result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(duplicate)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )

        tampered = temporary / "tampered.whl"
        with zipfile.ZipFile(wheel) as source_archive, zipfile.ZipFile(
            tampered, "w"
        ) as target_archive:
            for info in source_archive.infolist():
                body = source_archive.read(info)
                if info.filename == protected_member:
                    body += b"\n# archive member mutation\n"
                target_archive.writestr(info, body)
        tampered_result = subprocess.run(
            [sys.executable, "-I", "-c", probe, str(tampered)],
            cwd=temporary,
            check=False,
            capture_output=True,
        )
        return {
            "unpacked-record": unpacked_result.returncode,
            "archive-duplicate": duplicate_result.returncode,
            "archive-tamper": tampered_result.returncode,
        }


def unchanged(value: object) -> object:
    return copy.deepcopy(value)


def apply_currentness_attack(
    attack: str,
    probe: category.ProductionCategoryProbe,
    execution: object,
    *,
    column: str = "normal",
) -> None:
    """Apply one test-only durable substitution after coverage observation."""

    assessment_object_digest = getattr(execution, "assessment_object_digest")
    if attack == "assessment-delete":
        probe._delete_ref(assessment_object_digest)
        return
    if attack == "assessment-replace":
        body = b'{"schema_version":"1.0.0","substituted":true}'
        replacement = probe.objects.digest(body)
        probe.objects.put_verified(body, replacement)
        probe._delete_ref(assessment_object_digest)
        probe._insert_ref(replacement)
        return
    if attack == "typed-evidence-delete":
        probe.replace_category_evidence_for(column, None)
        return
    if attack in {"typed-evidence-replace", "post-observation-replacement"}:
        evidence = probe.resolve_category_evidence(probe.task_id, column)
        facts = evidence["facts"]
        assert isinstance(facts, dict)
        fact_id = (
            "scenario-id" if column == "boundary" else "runner-output-digest"
        )
        facts[fact_id] = category.digest(f"substituted:{attack}")
        category.resign_column_evidence(evidence)
        probe.replace_category_evidence_for(column, evidence)
        return
    if attack in {"revision-drift", "epoch-drift"}:
        current = probe.task_application.runtime_show(
            probe.task_id, probe.runtime
        ).snapshot
        probe.replace_task_authority({
            "task_revision": (
                current.task_revision + 1
                if attack == "revision-drift"
                else current.task_revision
            ),
            "invalidation_epoch": (
                current.invalidation_epoch + 1
                if attack == "epoch-drift"
                else current.invalidation_epoch
            ),
        })
        return
    if attack == "graph-ref-drift":
        from graph_engineering.storage.codec import canonical_json, parse_canonical_json

        with probe.factory.open("application") as connection:
            with connection.transaction():
                row = connection.execute(
                    "SELECT snapshot_json FROM tasks WHERE task_id=?",
                    (probe.task_id,),
                ).fetchone()
                wrapper = parse_canonical_json(row[0])
                assert isinstance(wrapper, dict)
                domain = wrapper["domain"]
                assert isinstance(domain, dict)
                graph_ref = domain["graph_ref"]
                assert isinstance(graph_ref, dict)
                graph_ref["materialization_digest"] = category.digest(
                    "substituted-materialization"
                )
                connection.execute(
                    "UPDATE tasks SET snapshot_json=? WHERE task_id=?",
                    (canonical_json(wrapper), probe.task_id),
                )
        return
    raise AssertionError(f"unknown Slice4 currentness attack: {json.dumps(attack)}")


PERFORMANCE_AUTHORITY_R2_SELECTOR = "performance-authority-r2"
EXISTING_FEATURE_R1_SELECTOR = "existing-feature-r1"
REPRODUCIBLE_FAILURE_R1_SELECTOR = "reproducible-failure-r1"
FALSE_REPRODUCTION_R1_SELECTOR = "false-reproduction-r1"
REGRESSION_BOUNDARY_R1_SELECTOR = "regression-boundary-r1"
MINIMAL_PATCH_R1_SELECTOR = "minimal-patch-r1"
STABLE_BASELINE_R1_SELECTOR = "stable-baseline-r1"
VULNERABLE_GRAPH_R1_SELECTOR = "vulnerable-graph-r1"
MIGRATION_SCENARIOS_R1_SELECTOR = "migration-scenarios-r1"
DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR = "dependency-graph-scenarios-r1"
PERFORMANCE_REMAINING_R1_SELECTOR = "performance-remaining-r1"
P2A_CUMULATIVE_R2_SELECTOR = "p2a-cumulative-r2"
P2B_CUMULATIVE_R1_SELECTOR = "p2b-cumulative-r1"
P3_CUMULATIVE274_R1_SELECTOR = "p3-cumulative274-r1"
VERIFIED_RUNNER_SELECTORS = (
    DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR,
    EXISTING_FEATURE_R1_SELECTOR,
    FALSE_REPRODUCTION_R1_SELECTOR,
    MIGRATION_SCENARIOS_R1_SELECTOR,
    MINIMAL_PATCH_R1_SELECTOR,
    PERFORMANCE_AUTHORITY_R2_SELECTOR,
    PERFORMANCE_REMAINING_R1_SELECTOR,
    P2A_CUMULATIVE_R2_SELECTOR,
    P2B_CUMULATIVE_R1_SELECTOR,
    P3_CUMULATIVE274_R1_SELECTOR,
    REGRESSION_BOUNDARY_R1_SELECTOR,
    REPRODUCIBLE_FAILURE_R1_SELECTOR,
    STABLE_BASELINE_R1_SELECTOR,
    VULNERABLE_GRAPH_R1_SELECTOR,
)


@dataclass(frozen=True, slots=True)
class _CumulativeCheckpoint:
    """Frozen acceptance-oracle data, confined to this test fixture."""

    selector: str
    plan_bindings: int
    oracle_bindings: int
    missing_records: int
    total_records: int
    new_test_ids: frozenset[str]


_P2C_CURRENT_CHECKPOINT = _CumulativeCheckpoint(
    "p2c-current-plan",
    236,
    118,
    38,
    274,
    frozenset(
        f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-{disposition}"
        for scenario in REFACTOR_SCENARIO_IDS
        for disposition in ("P", "R")
    ),
)


_P2D_CURRENT_CHECKPOINT = _CumulativeCheckpoint(
    "p2d-current-plan",
    244,
    122,
    30,
    274,
    frozenset(
        f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-{disposition}"
        for scenario in INCIDENT_SCENARIO_IDS
        for disposition in ("P", "R")
    ),
)


_CUMULATIVE_CHECKPOINTS = MappingProxyType({
    P2A_CUMULATIVE_R2_SELECTOR: _CumulativeCheckpoint(
        P2A_CUMULATIVE_R2_SELECTOR, 226, 113, 48, 274,
        frozenset((NEW_FEATURE_MULTI_TARGET_PASS_TEST_ID,
                   NEW_FEATURE_MULTI_TARGET_REJECT_TEST_ID)),
    ),
    P2B_CUMULATIVE_R1_SELECTOR: _CumulativeCheckpoint(
        P2B_CUMULATIVE_R1_SELECTOR, 230, 115, 44, 274,
        frozenset(f"GEW-PSC-HOTFIX-{scenario.upper()}-{disposition}"
                  for scenario in HOTFIX_GUARDED_SCENARIO_IDS
                  for disposition in ("P", "R")),
    ),
})


def _cumulative_checkpoint(selector: str) -> _CumulativeCheckpoint:
    if type(selector) is str and selector == P3_CUMULATIVE274_R1_SELECTOR:
        return _CumulativeCheckpoint(selector, 274, 137, 0, 274, frozenset(_c274_case_ids()))
    if type(selector) is not str or selector not in _CUMULATIVE_CHECKPOINTS:
        raise AssertionError("unknown cumulative checkpoint")
    return _CUMULATIVE_CHECKPOINTS[selector]


def _validate_cumulative_plan(plan, matrix, checkpoint):  # type: ignore[no-untyped-def]
    """Reject wrong checkpoints before any expensive sibling or mutation."""

    expected_ids = frozenset((*matrix.profile_case_ids, *matrix.scenario_case_ids))
    oracle_keys = tuple(
        (row["oracle_id"], row["profile_id"], row["selector_kind"],
         row["column_id"], row["scenario_id"])
        for row in plan.oracle_bindings
    )
    if (
        len(plan.bindings) != checkpoint.plan_bindings
        or len(oracle_keys) != checkpoint.oracle_bindings
        or len(set(oracle_keys)) != checkpoint.oracle_bindings
        or len(expected_ids) != checkpoint.total_records
        or not set(plan.bindings) <= expected_ids
        or not checkpoint.new_test_ids <= set(plan.bindings)
        or len(expected_ids - set(plan.bindings)) != checkpoint.missing_records
    ):
        raise AssertionError("cumulative checkpoint plan preflight changed")


def _validate_cumulative_receipt(receipt, checkpoint):  # type: ignore[no-untyped-def]
    """Validate partial-checkpoint counts, never promote them to full success."""

    expected = {
        "selector": checkpoint.selector,
        "plan_bindings": checkpoint.plan_bindings,
        "oracle_bindings": checkpoint.oracle_bindings,
        "new_records": len(checkpoint.new_test_ids),
        "retained_records": checkpoint.plan_bindings - len(checkpoint.new_test_ids),
        "dynamic": {"valid": checkpoint.plan_bindings,
                    "missing": checkpoint.missing_records, "passed": False,
                    "invalid": 0, "stale": 0, "duplicate": 0},
        "static": {"valid": 0, "missing": checkpoint.total_records,
                   "passed": False, "invalid": 0, "stale": 0, "duplicate": 0},
    }

    def exact(actual, wanted):  # type: ignore[no-untyped-def]
        if type(actual) is not type(wanted):
            return False
        if isinstance(wanted, dict):
            return actual.keys() == wanted.keys() and all(
                exact(actual[key], value) for key, value in wanted.items()
            )
        return actual == wanted

    if type(receipt) is not dict or receipt.keys() != expected.keys() | {"p1_sibling"}:
        raise AssertionError("cumulative receipt fields changed")
    if not exact({key: receipt[key] for key in expected}, expected):
        raise AssertionError("cumulative receipt checkpoint changed")
    sibling = receipt["p1_sibling"]
    if type(sibling) is not dict or any(
        not exact(sibling.get(key), value) for key, value in {
            "selector": PERFORMANCE_REMAINING_R1_SELECTOR,
            "plan_bindings": checkpoint.plan_bindings,
            "oracle_bindings": checkpoint.oracle_bindings,
        }.items()
    ):
        raise AssertionError("cumulative receipt P1 sibling changed")
    return receipt


# Test-only frozen expectations for the reviewed installed plan. These are not
# caller-provided data and do not depend on detached workflow records at runtime.
_C274_PLAN_DIGEST = 'sha256-jcs-v1:0e717c5ffaba4f6f936294663957f04aea3c2017e01ef7dabf1358eaa116a3da'
_C274_ROWS_SHA256 = 'edf932f928d792976ce14585007b9fa0ac2490204e4b3396421e8089e80b92db'
_C274_SCENARIO_ATTACKS = tuple(sorted((
    "raw-alias", "mandatory-id", "rejection-member", "other-scenario",
    "other-profile", "same-id-changed-request", "oracle-coherent-substitution",
    "selector-overlay-coherent-substitution", "typed-evidence-delete",
    "typed-evidence-replace", "post-observation-replacement", "source-currentness",
)))
_C274_CORRECTNESS_ATTACKS = tuple(sorted((
    "observed-mismatch", "expected-substitution", "ignored-iteration",
    "duration-only", "wrong-phase", "wrong-case", "caller-correct",
)))


def _c274_oracle_identities():
    return tuple(sorted((
        *expected_oracle_binding_identities(),
        *(("ORA-PROFILE-RELEASE-OPERATIONS", "release-operations", "mandatory", column, None)
          for column in BUG_FIX_COLUMNS),
        *(("ORA-PROFILE-RELEASE-OPERATIONS", "release-operations", "scenario", "boundary", scenario)
          for scenario in ("artifact-provenance", "health-gate", "partial-deploy")),
    )))


def _c274_case_ids():
    return tuple(sorted(
        f"GEW-{'PRO' if kind == 'mandatory' else 'PSC'}-{profile.upper()}-{(column if kind == 'mandatory' else scenario).upper()}-{role}"
        for _oracle, profile, kind, column, scenario in _c274_oracle_identities()
        for role in ("P", "R")
    ))


def _validate_c274_plan(plan, matrix):
    expected_ids = _c274_case_ids()
    keys = tuple(sorted(tuple(row[k] for k in (
        "oracle_id", "profile_id", "selector_kind", "column_id", "scenario_id",
    )) for row in plan.oracle_bindings))
    projection = {"bindings": [thaw(row) for row in plan.bindings.values()],
                  "oracle_bindings": [thaw(row) for row in plan.oracle_bindings]}
    digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if (tuple(plan.bindings) != expected_ids or len(set(expected_ids)) != 274
        or keys != _c274_oracle_identities() or len(set(keys)) != 137
        or tuple(sorted((*matrix.profile_case_ids, *matrix.scenario_case_ids))) != expected_ids
        or plan.plan_digest != _C274_PLAN_DIGEST or digest != _C274_ROWS_SHA256):
        raise AssertionError("cumulative274 preflight identity or binding projection changed")


def _c274_p1_expected():
    return {
        "oracle_bindings": 137, "plan_bindings": 274,
        "restart": "current-launcher-zero",
        "correctness_rejections": list(_C274_CORRECTNESS_ATTACKS),
        "noise_rejection": {"kind": "integer-vector", "median": 100, "mad": 99,
                            "left_product": 198, "right_product": 100, "outcome": "inconclusive-noise"},
        "scenario_attacks": {s: list(_C274_SCENARIO_ATTACKS) for s in PERFORMANCE_REMAINING_SCENARIO_IDS},
        "selector": PERFORMANCE_REMAINING_R1_SELECTOR,
    }


def _validate_c274_p1(receipt):
    expected = _c274_p1_expected()
    if type(receipt) is not dict or receipt.keys() != expected.keys() | {"retained_outliers"}:
        raise AssertionError("cumulative274 P1 evidence fields changed")
    if not _exact_json({k: receipt[k] for k in expected}, expected):
        raise AssertionError("cumulative274 P1 evidence changed")
    outliers = receipt["retained_outliers"]
    if type(outliers) is not dict or outliers.keys() != {"noise-outlier"}:
        raise AssertionError("cumulative274 P1 outlier scenario changed")
    values = outliers["noise-outlier"]
    if (type(values) is not list or len(values) != 3 or any(type(v) is not int for v in values)
        or values[0] <= 0 or values[1] < 0 or values[2] <= values[1]):
        raise AssertionError("cumulative274 P1 outlier evidence is invalid")
    return receipt


def _exact_json(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(expected) is dict:
        return actual.keys() == expected.keys() and all(_exact_json(actual[k], v) for k, v in expected.items())
    if type(expected) is list:
        return len(actual) == len(expected) and all(_exact_json(a, b) for a, b in zip(actual, expected, strict=True))
    return actual == expected


def _c274_closure(plan, *, terminal, active, reopened, maximum):
    return {"case_ids": list(_c274_case_ids()),
            "oracle_identities": sorted([list(k) for k in _c274_oracle_identities()], key=lambda k: json.dumps(k)),
            "plan_digest": plan.plan_digest, "terminal_bindings": terminal,
            "active_handles": active, "active_reopened_bindings": reopened,
            "maximum_active_reopened_bindings": maximum}


def _validate_c274_receipt(receipt, plan):
    if type(receipt) is not dict or "p1_sibling" not in receipt:
        raise AssertionError("cumulative274 receipt changed")
    sibling = _validate_c274_p1(receipt["p1_sibling"])
    expected = {"selector": P3_CUMULATIVE274_R1_SELECTOR, "plan_bindings": 274, "oracle_bindings": 137,
        "dynamic": {"valid": 274, "missing": 0, "passed": True, "invalid": 0, "stale": 0, "duplicate": 0},
        "static": {"valid": 0, "missing": 274, "passed": False, "invalid": 0, "stale": 0, "duplicate": 0},
        "p1_sibling": sibling,
        "closure": _c274_closure(plan, terminal=274, active=0, reopened=0, maximum=1)}
    if plan.plan_digest != _C274_PLAN_DIGEST or not _exact_json(receipt, expected):
        raise AssertionError("cumulative274 receipt changed")
    return receipt


def _close_c274_factory(factory, decision):
    from graph_engineering.core.profiles import ProfileContractError
    if decision is not None:
        try:
            return finalize_consumed_coverage_factory(factory, decision)
        except ProfileContractError as error:
            # This exact deterministic precondition fails before any revoke.
            # Cleanup/revocation errors must propagate, never fall back to abort.
            if str(error) != "combined coverage gate was not consumed":
                raise
    return abort_uncommitted_coverage_factory(factory)


def _wait_for_c274_child(process, *, timeout_seconds, heartbeat_interval_seconds):
    try:
        return _wait_for_verified_child(process, selector=P3_CUMULATIVE274_R1_SELECTOR,
            timeout_seconds=timeout_seconds, heartbeat_interval_seconds=heartbeat_interval_seconds,
            reap_timeout_seconds=60)
    except BaseException as primary:
        try:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=60)
        except BaseException as cleanup:
            raise BaseExceptionGroup("cumulative274 child failure and reap failure", [primary, cleanup]) from None
        raise


def run_p3_cumulative274_r1_verified():
    # Entry availability is not launch authority. Unit tests mock the launch.
    args = _verified_plan(selector=P3_CUMULATIVE274_R1_SELECTOR)
    plan = args[-1]
    _validate_c274_plan(plan, args[3])
    limits = _cumulative_runner_testability()
    receipt = _run_verified_selector_in_fresh_child(P3_CUMULATIVE274_R1_SELECTOR,
        timeout_seconds=limits["cumulative_runtime_limit_seconds"],
        heartbeat_interval_seconds=limits["heartbeat_interval_seconds"])
    # Re-read parent inputs after execution; do not accept a stale parent plan.
    fresh = _verified_plan(selector=P3_CUMULATIVE274_R1_SELECTOR)
    _validate_c274_plan(fresh[-1], fresh[3])
    return _validate_c274_receipt(receipt, fresh[-1])


def _run_p3_cumulative274_r1_child():
    return _run_cumulative_child(P3_CUMULATIVE274_R1_SELECTOR)


def _verified_runner_contracts(
    profile_id: str = "new-feature",
):  # type: ignore[no-untyped-def]
    """Load exact installed Profile contracts without caller-owned expectations."""

    from tests.unit import test_wp08_profile_contracts as contracts

    api = contracts._profile_api()
    coverage = contracts._coverage_policy()
    matrix = api.SupportMatrixDefinition.from_dict(
        contracts._support_matrix_document(),
        approved_profiles=contracts._approved_registry(),
        coverage_policy=coverage,
    )
    profile = api.ProfileDefinition.from_dict(
        category.profile_document(profile_id),
        approved_profiles=contracts._approved_registry(),
        coverage_policy=coverage,
        semantic_policy=contracts._semantic_policy(),
    )
    overlay = api.RiskOverlayDefinition.from_dict(
        contracts._overlay_document(),
        approved_profiles=contracts._approved_registry(),
        coverage_policy=coverage,
    )
    return api, coverage, matrix, profile, overlay


def _verified_plan(*, selector: str | None = None):  # type: ignore[no-untyped-def]
    expected_oracles = expected_oracle_binding_identities(selector=selector)
    api, coverage, matrix, profile, overlay = _verified_runner_contracts()
    api4 = load_slice4_api()
    plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
    installed_oracles = tuple(sorted(
        (
            item["oracle_id"], item["profile_id"], item["selector_kind"],
            item["column_id"], item["scenario_id"],
        )
        for item in plan.oracle_bindings
    ))
    if installed_oracles != expected_oracles:
        raise AssertionError("installed coverage oracle closure changed")
    return api, api4, coverage, matrix, profile, overlay, plan


def _expect_verified_rejection(
    label: str,
    error_types: type[BaseException] | tuple[type[BaseException], ...],
    action,  # type: ignore[no-untyped-def]
) -> str:
    try:
        action()
    except error_types:
        return label
    raise AssertionError(f"verified runner attack was accepted: {label}")


def _coverage_authority_arguments(result: SerialCoverageExecution, plan: object) -> dict[str, object]:
    return {
        "plan": plan,
        "category_application": result.application,
        "task_application": result.probe.task_application,
        "repository": result.probe.repository,
        "object_repository": result.probe.objects,
        "runtime": result.probe.runtime,
    }


def _run_performance_authority_r2_child() -> dict[str, object]:
    """Run the exact R2 authority matrix without the monolithic rejection suite."""

    from graph_engineering.application.performance_benchmark import (
        PerformanceBenchmarkError,
    )

    api, api4, coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks: list[str] = []
    attack_result = run_serial_profile_binding(
        api4=api4,
        plan=plan,
        profile_id="performance",
        column="artifacts",
        disposition="R",
    )
    foreign_result: SerialCoverageExecution | None = None
    stale_result: SerialCoverageExecution | None = None
    try:
        state_before = _serial_state_signature(
            attack_result.probe, attack_result.target, real_e2e=False,
        )
        candidate_before = copy.deepcopy(attack_result.candidate)
        arguments = _coverage_authority_arguments(attack_result, plan)
        attacks.append(_expect_verified_rejection(
            "duplicate-bare",
            api4.ProfileCoverageError,
            lambda: api4.ProfileCoverageAuthority(**arguments),
        ))
        performance_factory = attack_result.performance_context.registry_factory
        attacks.append(_expect_verified_rejection(
            "same-app-foreign-authority",
            PerformanceBenchmarkError,
            lambda: performance_factory._issue_profile_coverage_registration(
                authority=object(),
                application=attack_result.application,
                task_application=attack_result.probe.task_application,
                repository=attack_result.probe.repository,
                object_repository=attack_result.probe.objects,
                runtime=attack_result.probe.runtime,
                plan=plan,
                registry_authority=(
                    attack_result.performance_context.registry_authority
                ),
            ),
        ))
        for label, factory in (
            ("shallow-copy", lambda: copy.copy(attack_result.authority)),
            ("deep-copy", lambda: copy.deepcopy(attack_result.authority)),
            ("object-new", lambda: object.__new__(api4.ProfileCoverageAuthority)),
        ):
            try:
                forged = factory()
            except BaseException:
                attacks.append(label)
                continue
            attacks.append(_expect_verified_rejection(
                label,
                api4.ProfileCoverageError,
                lambda forged=forged: forged.execute_rejection(
                    attack_result.test_id,
                    candidate=attack_result.candidate,
                    observer=attack_result.target,
                ),
            ))
        foreign_result = run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="performance",
            column="boundary",
            disposition="R",
        )
        attacks.append(_expect_verified_rejection(
            "foreign-registration",
            PerformanceBenchmarkError,
            lambda: performance_factory._require_profile_coverage_registration(
                foreign_result.authority._performance_registration,
                attack_result.authority,
            ),
        ))
        stale_result = run_serial_profile_binding(
            api4=api4,
            plan=plan,
            profile_id="performance",
            column="drift",
            disposition="R",
        )
        stale_before = _serial_state_signature(
            stale_result.probe, stale_result.target, real_e2e=False,
        )
        stale_result.performance_context.session.close()
        attacks.append(_expect_verified_rejection(
            "stale-registration",
            api4.ProfileCoverageError,
            lambda: stale_result.authority.observe(stale_result.execution),
        ))
        if _serial_state_signature(
            stale_result.probe, stale_result.target, real_e2e=False,
        ) != stale_before:
            raise AssertionError("stale registration rejection changed durable state")
        missing = performance_coverage_authority_rejection_probes(
            api4=api4, plan=plan,
        )
        attacks.extend(missing)
        original_observation = attack_result.authority.observe(
            attack_result.execution
        )
        if original_observation.test_id != attack_result.test_id:
            raise AssertionError("original performance authority is no longer current")
        if (
            _serial_state_signature(
                attack_result.probe, attack_result.target, real_e2e=False,
            ) != state_before
            or attack_result.candidate != candidate_before
        ):
            raise AssertionError("performance authority attack changed durable state")
    finally:
        if stale_result is not None:
            stale_result.close()
        if foreign_result is not None:
            foreign_result.close()
        attack_result.close()

    performance_results: list[SerialCoverageExecution] = []
    shared = category.shared_production_category_runtime("performance")
    restart_launcher_delta = -1
    decision = None
    records: tuple[object, ...] = ()
    try:
        for column in approved_mandatory_columns():
            for disposition in ("P", "R"):
                performance_results.append(run_serial_profile_binding(
                    api4=api4,
                    plan=plan,
                    profile_id="performance",
                    column=column,
                    disposition=disposition,
                    shared_runtime=shared,
                ))
        performance_results.sort(key=lambda item: item.test_id)
        expected_ids = tuple(sorted(
            binding["test_id"]
            for binding in plan.bindings.values()
            if (
                binding["profile_id"] == "performance"
                and binding["selector_kind"] == "mandatory"
            )
        ))
        if len(expected_ids) != 24 or len(set(expected_ids)) != 24:
            raise AssertionError("performance mandatory binding set changed")
        actual_ids = tuple(item.test_id for item in performance_results)
        if len(actual_ids) != 24 or len(set(actual_ids)) != 24:
            raise AssertionError("performance24 execution identity changed")
        if actual_ids != expected_ids:
            raise AssertionError("performance24 execution set changed")
        observations = tuple(
            item.authority.observe(item.execution)
            for item in performance_results
        )
        restart_result = next(
            item for item in performance_results
            if item.column_id == "real-e2e" and item.disposition == "P"
        )
        launches_before = restart_result.performance_context.launcher.launch_count
        restarted_task, restarted_runtime = restart_result.probe.restart_authorities()
        restarted_application = restart_result.application.restart(
            restarted_task, restarted_runtime, restart_result.target,
        )
        restarted_authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=restarted_application,
            task_application=restarted_task,
            repository=restart_result.probe.repository,
            object_repository=restart_result.probe.objects,
            runtime=restarted_runtime,
        )
        restored = restarted_authority.observe_completion(
            restart_result.test_id,
            task_id=restart_result.probe.task_id,
            expected_profile_id="performance",
        )
        if restored.execution_digest != restart_result.execution.execution_digest:
            raise AssertionError("performance restart execution changed")
        restart_launcher_delta = (
            restart_result.performance_context.launcher.launch_count
            - launches_before
        )
        if restart_launcher_delta != 0:
            raise AssertionError("performance restart invoked the launcher")
        restart_factory = api.CoverageRecordFactory(
            execution_authority=restarted_authority,
            coverage_policy=coverage,
        )
        abort_uncommitted_coverage_factory(restart_factory)

        _api, _coverage, _matrix, performance_profile, performance_overlay = (
            _verified_runner_contracts("performance")
        )
        factory = api.CoverageRecordFactory(
            execution_authority=tuple(
                item.authority for item in performance_results
            ),
            coverage_policy=coverage,
        )
        records = tuple(
            factory.issue_execution(
                observation,
                matrix=matrix,
                profile=performance_profile,
                overlay=performance_overlay,
            )
            for observation in observations
        )
        decision = api.ReleaseCoverageGate.evaluate(
            matrix,
            coverage_records=records,
            coverage_factory=factory,
        )
        expected_total = len(matrix.profile_case_ids) + len(matrix.scenario_case_ids)
        if (
            decision.passed
            or len(records) != len(expected_ids)
            or len(decision.missing_test_ids) != expected_total - len(records)
            or decision.invalid_test_ids
            or decision.stale_test_ids
        ):
            raise AssertionError("performance24 gate result changed")
        # This selector deliberately exercises only the 24 performance
        # bindings.  Its partial gate is diagnostic, not a consumed combined
        # gate, so it must take the pre-gate abort/revoke lifecycle rather
        # than pretending it can finalize the full plan.
        abort_uncommitted_coverage_factory(factory)
    finally:
        for result in reversed(performance_results):
            result.close()
        shared.close()

    representative = run_serial_profile_binding(
        api4=api4,
        plan=plan,
        profile_id="new-feature",
        column="normal",
        disposition="R",
    )
    try:
        observation = representative.authority.observe(representative.execution)
        nonperformance_factory = api.CoverageRecordFactory(
            execution_authority=representative.authority,
            coverage_policy=coverage,
        )
        record = nonperformance_factory.issue_execution(
            observation,
            matrix=matrix,
            profile=_verified_runner_contracts("new-feature")[3],
            overlay=_verified_runner_contracts("new-feature")[4],
        )
        nonperformance_decision = api.ReleaseCoverageGate.evaluate(
            matrix,
            coverage_records=(record,),
            coverage_factory=nonperformance_factory,
        )
        if nonperformance_decision.passed:
            raise AssertionError("non-performance representative gate changed")
        # The representative non-performance record is likewise a partial
        # diagnostic.  It verifies that performance authority did not alter
        # unrelated behavior, so revoke it through the pre-gate lifecycle.
        abort_uncommitted_coverage_factory(nonperformance_factory)
    finally:
        representative.close()

    if decision is None:
        raise AssertionError("performance24 gate was not evaluated")
    return {
        "attacks": tuple(sorted(attacks)),
        "gate_passed": decision.passed,
        "missing": len(decision.missing_test_ids),
        "nonperformance": "current",
        "performance_records": len(records),
        "restart_launcher_delta": restart_launcher_delta,
        "selector": PERFORMANCE_AUTHORITY_R2_SELECTOR,
    }


def _existing_feature_attack_receipt(
    *, api4: Slice4API, plan: object, matrix: object,
) -> tuple[str, ...]:
    from unittest import mock

    import graph_engineering

    attacks: list[str] = []
    positive = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=EXISTING_FEATURE_SCENARIO_ID,
        disposition="P",
    )
    rejected = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=EXISTING_FEATURE_SCENARIO_ID,
        disposition="R",
    )
    try:
        pass_binding = plan.binding(EXISTING_FEATURE_PASS_TEST_ID)
        reject_binding = plan.binding(EXISTING_FEATURE_REJECT_TEST_ID)
        if (
            tuple(pass_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind", "request_digest",
            ))
            != (
                "new-feature", "scenario", "boundary",
                EXISTING_FEATURE_SCENARIO_ID, EXISTING_FEATURE_BOUNDARY_CASE_ID,
                "full-planned", "P", "COMPLETED", "contract-test", None,
            )
            or tuple(reject_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind",
            ))
            != (
                "new-feature", "scenario", "boundary",
                EXISTING_FEATURE_SCENARIO_ID, EXISTING_FEATURE_BOUNDARY_CASE_ID,
                "full-planned", "R", "EXPECTED_REJECTION", "contract-test",
            )
            or reject_binding["request_digest"] != coverage_request_digest(
                existing_feature_candidate(accepted=False)
            )
        ):
            raise AssertionError("existing-feature installed tuple changed")

        restarted_task, restarted_runtime = positive.probe.restart_authorities()
        restarted_application = positive.application.restart(
            restarted_task, restarted_runtime, positive.target,
        )
        restarted_authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=restarted_application,
            task_application=restarted_task,
            repository=positive.probe.repository,
            object_repository=positive.probe.objects,
            runtime=restarted_runtime,
        )
        restored = restarted_authority.observe_completion(
            positive.test_id,
            task_id=positive.probe.task_id,
            expected_profile_id="new-feature",
        )
        if restored.execution_digest != positive.execution.execution_digest:
            raise AssertionError("existing-feature restart changed execution")

        rejection_state = _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        )
        invalid_scenarios = (
            ("raw-alias", EXISTING_FEATURE_SCENARIO_ID),
            ("mandatory-id", "GEW-PRO-NEW-FEATURE-BOUNDARY-P"),
            ("rejection-member", EXISTING_FEATURE_REJECT_TEST_ID),
            ("other-scenario", SCAFFOLD_PASS_TEST_ID),
            ("other-profile", "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE-P"),
        )
        for label, scenario_id in invalid_scenarios:
            changed = existing_feature_candidate(accepted=False)
            changed["scenario_id"] = scenario_id
            before = copy.deepcopy(changed)
            attacks.append(_expect_verified_rejection(
                label,
                api4.ProfileCoverageError,
                lambda changed=changed: rejected.authority.execute_rejection(
                    EXISTING_FEATURE_REJECT_TEST_ID,
                    candidate=changed,
                    observer=rejected.target,
                ),
            ))
            if changed != before:
                raise AssertionError("existing-feature rejection mutated input")
        changed_request = existing_feature_candidate(accepted=False)
        changed_request["request_id"] = (
            "wp08-s4:new-feature:existing-feature:foreign"
        )
        changed_before = copy.deepcopy(changed_request)
        attacks.append(_expect_verified_rejection(
            "same-id-changed-request",
            api4.ProfileCoverageError,
            lambda: rejected.authority.execute_rejection(
                EXISTING_FEATURE_REJECT_TEST_ID,
                candidate=changed_request,
                observer=rejected.target,
            ),
        ))
        if changed_request != changed_before:
            raise AssertionError("same-ID rejection mutated input")

        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_oracle_resources(
                scenario=True,
                scenario_id=EXISTING_FEATURE_SCENARIO_ID,
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "oracle-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: rejected.authority.observe(rejected.execution),
            ))
        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_scenario_plan_resources(
                EXISTING_FEATURE_PASS_TEST_ID
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "selector-overlay-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: api4.ProfileCoverageExecutionPlan.from_installation(
                    matrix=matrix,
                ),
            ))
        if _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        ) != rejection_state:
            raise AssertionError("existing-feature attack changed durable state")
        if (
            positive.authority.observe(positive.execution).test_id
            != EXISTING_FEATURE_PASS_TEST_ID
            or rejected.authority.observe(rejected.execution).test_id
            != EXISTING_FEATURE_REJECT_TEST_ID
        ):
            raise AssertionError("existing-feature canonical authorities are stale")
    finally:
        rejected.close()
        positive.close()

    for attack in (
        "typed-evidence-delete",
        "typed-evidence-replace",
        "post-observation-replacement",
    ):
        _api, application, probe, target = production_runtime(
            "boundary",
            scenario_id=EXISTING_FEATURE_BOUNDARY_CASE_ID,
            task_id=coverage_task_id(EXISTING_FEATURE_PASS_TEST_ID),
        )
        try:
            application.assess_and_commit(
                existing_feature_candidate(accepted=True), observer=target,
            )
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
            )
            execution = authority.observe_completion(
                EXISTING_FEATURE_PASS_TEST_ID,
                task_id=probe.task_id,
                expected_profile_id="new-feature",
            )
            apply_currentness_attack(attack, probe, execution, column="boundary")
            state_after_attack = _serial_state_signature(
                probe, target, real_e2e=False,
            )
            attacks.append(_expect_verified_rejection(
                attack,
                api4.ProfileCoverageError,
                lambda: authority.observe(execution),
            ))
            if _serial_state_signature(
                probe, target, real_e2e=False,
            ) != state_after_attack:
                raise AssertionError("evidence rejection changed durable state")
        finally:
            target.close()
    if not source_post_attestation_mutation_is_rejected():
        raise AssertionError("post-attestation source mutation was accepted")
    attacks.append("source-currentness")
    return tuple(sorted(attacks))


def _run_existing_feature_r1_child() -> dict[str, object]:
    """Run only exact existing-feature scenario P/R and rejection attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _existing_feature_attack_receipt(
        api4=api4, plan=plan, matrix=matrix,
    )
    return {
        "attacks": attacks,
        "plan_bindings": len(plan.bindings),
        "oracle_bindings": len(plan.oracle_bindings),
        "restart": "current",
        "selector": EXISTING_FEATURE_R1_SELECTOR,
    }


def _reproducible_failure_attack_receipt(
    *, api4: Slice4API, plan: object, matrix: object,
) -> tuple[str, ...]:
    """Exercise the exact bug-fix scenario tuple and its twelve attacks."""

    from unittest import mock

    import graph_engineering

    attacks: list[str] = []
    positive = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
        disposition="P",
    )
    rejected = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
        disposition="R",
    )
    try:
        pass_binding = plan.binding(BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID)
        reject_binding = plan.binding(BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID)
        if (
            tuple(pass_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind", "request_digest",
            ))
            != (
                "bug-fix", "scenario", "boundary",
                BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
                BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
                "full-planned", "P", "COMPLETED", "contract-test", None,
            )
            or tuple(reject_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind",
            ))
            != (
                "bug-fix", "scenario", "boundary",
                BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
                BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
                "full-planned", "R", "EXPECTED_REJECTION", "contract-test",
            )
            or reject_binding["request_digest"] != coverage_request_digest(
                bug_fix_reproducible_failure_candidate(accepted=False)
            )
        ):
            raise AssertionError("reproducible-failure installed tuple changed")

        restarted_task, restarted_runtime = positive.probe.restart_authorities()
        restarted_application = positive.application.restart(
            restarted_task, restarted_runtime, positive.target,
        )
        restarted_authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=restarted_application,
            task_application=restarted_task,
            repository=positive.probe.repository,
            object_repository=positive.probe.objects,
            runtime=restarted_runtime,
        )
        restored = restarted_authority.observe_completion(
            positive.test_id,
            task_id=positive.probe.task_id,
            expected_profile_id="bug-fix",
        )
        if restored.execution_digest != positive.execution.execution_digest:
            raise AssertionError("reproducible-failure restart changed execution")

        rejection_state = _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        )
        invalid_scenarios = (
            ("raw-alias", BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID),
            (
                "mandatory-id",
                profile_mandatory_test_id("bug-fix", "boundary", "P"),
            ),
            ("rejection-member", BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID),
            ("other-scenario", "GEW-PSC-BUG-FIX-FALSE-REPRODUCTION-P"),
            ("other-profile", SCAFFOLD_PASS_TEST_ID),
        )
        for label, scenario_id in invalid_scenarios:
            changed = bug_fix_reproducible_failure_candidate(accepted=False)
            changed["scenario_id"] = scenario_id
            before = copy.deepcopy(changed)
            attacks.append(_expect_verified_rejection(
                label,
                api4.ProfileCoverageError,
                lambda changed=changed: rejected.authority.execute_rejection(
                    BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
                    candidate=changed,
                    observer=rejected.target,
                ),
            ))
            if changed != before:
                raise AssertionError("reproducible-failure rejection mutated input")
        changed_request = bug_fix_reproducible_failure_candidate(accepted=False)
        changed_request["request_id"] = (
            "wp08-s4:bug-fix:reproducible-failure:foreign"
        )
        changed_before = copy.deepcopy(changed_request)
        attacks.append(_expect_verified_rejection(
            "same-id-changed-request",
            api4.ProfileCoverageError,
            lambda: rejected.authority.execute_rejection(
                BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
                candidate=changed_request,
                observer=rejected.target,
            ),
        ))
        if changed_request != changed_before:
            raise AssertionError("same-ID rejection mutated input")

        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_oracle_resources(
                scenario=True,
                scenario_id=BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
                profile_id="bug-fix",
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "oracle-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: rejected.authority.observe(rejected.execution),
            ))
        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_scenario_plan_resources(
                BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "selector-overlay-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: api4.ProfileCoverageExecutionPlan.from_installation(
                    matrix=matrix,
                ),
            ))
        if _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        ) != rejection_state:
            raise AssertionError("reproducible-failure attack changed durable state")
        if (
            positive.authority.observe(positive.execution).test_id
            != BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
            or rejected.authority.observe(rejected.execution).test_id
            != BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID
        ):
            raise AssertionError("reproducible-failure authorities are stale")
    finally:
        rejected.close()
        positive.close()

    for attack in (
        "typed-evidence-delete",
        "typed-evidence-replace",
        "post-observation-replacement",
    ):
        _api, application, probe, target = production_runtime(
            "boundary",
            profile_id="bug-fix",
            scenario_id=BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
            task_id=coverage_task_id(BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID),
        )
        try:
            application.assess_and_commit(
                bug_fix_reproducible_failure_candidate(accepted=True),
                observer=target,
            )
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
            )
            execution = authority.observe_completion(
                BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
                task_id=probe.task_id,
                expected_profile_id="bug-fix",
            )
            apply_currentness_attack(attack, probe, execution, column="boundary")
            state_after_attack = _serial_state_signature(
                probe, target, real_e2e=False,
            )
            attacks.append(_expect_verified_rejection(
                attack,
                api4.ProfileCoverageError,
                lambda: authority.observe(execution),
            ))
            if _serial_state_signature(
                probe, target, real_e2e=False,
            ) != state_after_attack:
                raise AssertionError("evidence rejection changed durable state")
        finally:
            target.close()
    if not source_post_attestation_mutation_is_rejected():
        raise AssertionError("post-attestation source mutation was accepted")
    attacks.append("source-currentness")
    return tuple(sorted(attacks))


def _run_reproducible_failure_r1_child() -> dict[str, object]:
    """Run only the bug-fix reproducible-failure P/R and twelve attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _reproducible_failure_attack_receipt(
        api4=api4, plan=plan, matrix=matrix,
    )
    if len(attacks) != 12:
        raise AssertionError("reproducible-failure attack matrix changed")
    return {
        "attacks": attacks,
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current",
        "selector": REPRODUCIBLE_FAILURE_R1_SELECTOR,
    }


def _scenario_attack_receipt(
    *,
    api4: Slice4API,
    plan: object,
    matrix: object,
    profile_id: str,
    scenario_id: str,
    boundary_case_id: str,
    pass_test_id: str,
    reject_test_id: str,
    candidate_factory: Callable[..., dict[str, object]],
    request_label: str,
    other_scenario_id: str,
) -> tuple[str, ...]:
    """Exercise one exact profile scenario P/R and closed attack matrix."""

    import graph_engineering
    from graph_engineering.core.profile_execution import CategoryExecutionError
    from unittest import mock

    attacks: list[str] = []
    positive = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=scenario_id,
        disposition="P",
    )
    rejected = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=scenario_id,
        disposition="R",
    )
    try:
        if profile_id == "migration":
            from graph_engineering.core.contracts.immutable import thaw

            assessment = positive.application.current_assessment(
                positive.probe.task_id,
                expected_profile_id="migration",
            )
            if assessment is None or assessment.migration_rehearsal_projection is None:
                raise AssertionError("migration scenario assessment is not task-bound")
            projection = thaw(assessment.migration_rehearsal_projection)
            observation = projection["observation"]
            if scenario_id == "forward" and not (
                observation["forward_step"]["target_generation"]
                > observation["forward_step"]["source_generation"]
                and observation["forward_step"]["integrity_projection"]["result"]
                == "verified"
                and observation["forward_step"]["compatibility_projection"]["result"]
                == "compatible"
            ):
                raise AssertionError("forward migration projection is not authoritative")
            if scenario_id == "backward" and not (
                observation["backward_step"]["target_generation"]
                > observation["backward_step"]["source_generation"]
                and observation["backward_step"]["target_activation_epoch"]
                > observation["backward_step"]["source_activation_epoch"]
            ):
                raise AssertionError("backward migration projection is not monotonic")
            if scenario_id == "partial-data" and sorted(
                row["disposition"] for row in observation["partial_data"]
            ) != ["defaulted", "owner-route", "preserved", "rejected"]:
                raise AssertionError("partial-data dispositions are not execution-derived")
            if scenario_id == "crash-window" and sorted(
                item["outcome"] for item in observation["crash_recoveries"]
            ) != ["new-active", "old-active"]:
                raise AssertionError("crash-window outcomes are not old-or-new")
            migration_factory = (
                positive.application._oracle._migration_rehearsal_factory
            )
            if migration_factory._replay_count != 0:
                raise AssertionError("migration scenario assessment replayed execution")
        elif (
            profile_id == "dependency-security"
            and scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
        ):
            assessment = positive.application.current_assessment(
                positive.probe.task_id,
                expected_profile_id="dependency-security",
            )
            if (
                assessment is None
                or assessment.schema_version != "1.2.0"
                or getattr(assessment, "dependency_graph_projection", None) is None
                or assessment.migration_rehearsal_projection is not None
                or assessment.performance_evidence_projection is not None
            ):
                raise AssertionError(
                    "dependency graph scenario assessment is not task-bound"
                )
            graph_factory, graph_observation = (
                positive.authority._dependency_security
            )
            graph_document = graph_observation.to_dict()
            before_graph = graph_observation._before_graph.to_dict()
            if (
                graph_document["schema_version"] != "1.1.0"
                or graph_document["scenario_id"] != scenario_id
                or len(before_graph["reachability_path"]) <= 1
                or graph_factory.require_current(graph_observation)
                is not graph_observation
            ):
                raise AssertionError(
                    "dependency graph scenario is not current and reachable"
                )
            if scenario_id == "transitive-dependency" and not (
                graph_document["after_graph_digest"] is not None
                and graph_document["disposition_digest"] is None
                and graph_document["owner_route"] is None
            ):
                raise AssertionError(
                    "transitive dependency proof is not a fixed graph closure"
                )
            if scenario_id == "fix-unavailable" and not (
                graph_document["after_graph_digest"] is None
                and graph_document["disposition_digest"]
                == graph_observation._disposition.disposition_digest
                and graph_document["owner_route"]
                == "owner:dependency-security"
            ):
                raise AssertionError(
                    "fix-unavailable proof is not config-owned"
                )
        pass_binding = plan.binding(pass_test_id)
        reject_binding = plan.binding(reject_test_id)
        if (
            tuple(pass_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind", "request_digest",
            ))
            != (
                profile_id, "scenario", "boundary",
                scenario_id,
                boundary_case_id,
                "full-planned", "P", "COMPLETED", "contract-test", None,
            )
            or tuple(reject_binding[field] for field in (
                "profile_id", "selector_kind", "column_id", "scenario_id",
                "category_boundary_case_id", "overlay_id", "disposition",
                "expected_result", "execution_kind",
            ))
            != (
                profile_id, "scenario", "boundary",
                scenario_id,
                boundary_case_id,
                "full-planned", "R", "EXPECTED_REJECTION", "contract-test",
            )
            or reject_binding["request_digest"] != coverage_request_digest(
                candidate_factory(accepted=False)
            )
        ):
            raise AssertionError(f"{scenario_id} installed tuple changed")

        restart_write_state = None
        if (
            profile_id == "dependency-security"
            and scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS
        ):
            restart_write_state = (
                len(positive.probe.repository.replay(positive.probe.task_id)),
                tuple(positive.probe.repository.referenced_objects(
                    positive.probe.task_id
                )),
                positive.target.path.read_bytes(),
                positive.target.mutation_count,
            )
        restarted_task, restarted_runtime = positive.probe.restart_authorities()
        restart_launches_before = (
            positive.probe.performance_context.launcher.launch_count
            if profile_id == "performance"
            else None
        )
        if profile_id == "migration":
            restarted_application = positive.application.restart(
                restarted_task, restarted_runtime, positive.target,
            )
            migration_factory = (
                restarted_application._oracle._migration_rehearsal_factory
            )
            if migration_factory is None:
                raise AssertionError(
                    "migration scenario restart did not install current authority"
                )
            restarted_assessment = restarted_application.current_assessment(
                positive.probe.task_id,
                expected_profile_id="migration",
            )
            if (
                restarted_assessment is None
                or restarted_assessment.migration_rehearsal_projection is None
                or migration_factory._replay_count != 0
            ):
                raise AssertionError(
                    "migration scenario restart did not rehydrate current assessment"
                )
        else:
            restarted_application = positive.application.restart(
                restarted_task, restarted_runtime, positive.target,
            )
        restarted_dependency_security: tuple[object, object] | None = None
        if profile_id == "dependency-security":
            if scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS:
                restarted_assessment = restarted_application.current_assessment(
                    positive.probe.task_id,
                    expected_profile_id="dependency-security",
                )
                restarted_factory = (
                    restarted_application._oracle._dependency_graph_factory
                )
                if (
                    restarted_assessment is None
                    or restarted_factory is None
                    or restarted_factory
                    is positive.application._oracle._dependency_graph_factory
                    or restarted_assessment._dependency_graph_evidence is None
                ):
                    raise AssertionError(
                        "dependency graph restart reused or lost assessment authority"
                    )
                restarted_dependency_security = (
                    restarted_factory,
                    restarted_assessment._dependency_graph_evidence,
                )
            else:
                restarted_dependency_security = (
                    positive.dependency_security_context.observe(
                        restarted_application, positive.probe.task_id,
                    )
                )
        restarted_authority = api4.ProfileCoverageAuthority(
            plan=plan,
            category_application=restarted_application,
            task_application=restarted_task,
            repository=positive.probe.repository,
            object_repository=positive.probe.objects,
            runtime=restarted_runtime,
            dependency_security=restarted_dependency_security,
        )
        restored = restarted_authority.observe_completion(
            positive.test_id,
            task_id=positive.probe.task_id,
            expected_profile_id=profile_id,
        )
        if restored.execution_digest != positive.execution.execution_digest:
            raise AssertionError(f"{scenario_id} restart changed execution")
        if restart_write_state is not None and (
            len(positive.probe.repository.replay(positive.probe.task_id)),
            tuple(positive.probe.repository.referenced_objects(
                positive.probe.task_id
            )),
            positive.target.path.read_bytes(),
            positive.target.mutation_count,
        ) != restart_write_state:
            raise AssertionError(
                "dependency graph scenario restart changed durable state"
            )
        if (
            profile_id == "migration"
            and positive.application._oracle._migration_rehearsal_factory._replay_count
            != 0
        ):
            raise AssertionError("migration scenario restart replayed execution")
        if (
            restart_launches_before is not None
            and positive.probe.performance_context.launcher.launch_count
            != restart_launches_before
        ):
            raise AssertionError("performance scenario restart relaunched command")

        rejection_state = _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        )
        invalid_scenarios = (
            ("raw-alias", scenario_id),
            (
                "mandatory-id",
                profile_mandatory_test_id(profile_id, "boundary", "P"),
            ),
            ("rejection-member", reject_test_id),
            ("other-scenario", other_scenario_id),
            ("other-profile", SCAFFOLD_PASS_TEST_ID),
        )
        for label, invalid_scenario_id in invalid_scenarios:
            changed = candidate_factory(accepted=False)
            changed["scenario_id"] = invalid_scenario_id
            before = copy.deepcopy(changed)
            attacks.append(_expect_verified_rejection(
                label,
                api4.ProfileCoverageError,
                lambda changed=changed: rejected.authority.execute_rejection(
                    reject_test_id,
                    candidate=changed,
                    observer=rejected.target,
                ),
            ))
            if changed != before:
                raise AssertionError(f"{request_label} rejection mutated input")
        changed_request = candidate_factory(accepted=False)
        changed_request["request_id"] = (
            f"wp08-s4:{profile_id}:{request_label}:foreign"
        )
        changed_before = copy.deepcopy(changed_request)
        attacks.append(_expect_verified_rejection(
            "same-id-changed-request",
            api4.ProfileCoverageError,
            lambda: rejected.authority.execute_rejection(
                reject_test_id,
                candidate=changed_request,
                observer=rejected.target,
            ),
        ))
        if changed_request != changed_before:
            raise AssertionError("same-ID rejection mutated input")

        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_oracle_resources(
                scenario=True,
                scenario_id=scenario_id,
                profile_id=profile_id,
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "oracle-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: rejected.authority.observe(rejected.execution),
            ))
        with mock.patch.object(
            graph_engineering,
            "_profile_coverage_installation_resources",
            return_value=coherently_resigned_scenario_plan_resources(
                pass_test_id
            ),
        ):
            attacks.append(_expect_verified_rejection(
                "selector-overlay-coherent-substitution",
                api4.ProfileCoverageError,
                lambda: api4.ProfileCoverageExecutionPlan.from_installation(
                    matrix=matrix,
                ),
            ))
        if _serial_state_signature(
            rejected.probe, rejected.target, real_e2e=False,
        ) != rejection_state:
            raise AssertionError(f"{request_label} attack changed durable state")
        if (
            positive.authority.observe(positive.execution).test_id
            != pass_test_id
            or rejected.authority.observe(rejected.execution).test_id
            != reject_test_id
        ):
            raise AssertionError(f"{request_label} authorities are stale")
    finally:
        rejected.close()
        positive.close()

    for attack in (
        "typed-evidence-delete",
        "typed-evidence-replace",
        "post-observation-replacement",
    ):
        _api, application, probe, target = production_runtime(
            "boundary",
            profile_id=profile_id,
            scenario_id=boundary_case_id,
            task_id=coverage_task_id(pass_test_id),
            performance_measurement=profile_id == "performance",
        )
        dependency_context: object | None = None
        try:
            dependency_security: tuple[object, object] | None = None
            if profile_id == "dependency-security":
                from tests.support import wp08_dependency_security as dependency_fixture

                dependency_context = (
                    dependency_fixture.dependency_security_coverage_context(
                        probe.repository,
                        after_fixed_closure=(scenario_id != "fix-unavailable"),
                        advisory_identity=(
                            ("advisory:cffi:security-v1", 1)
                            if scenario_id == "transitive-dependency"
                            else ("advisory:example-dependency:security-v1", 2)
                        ),
                    )
                )
                if scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS:
                    dependency_security = dependency_context.observe_graph(
                        application, probe.task_id, scenario_id=scenario_id,
                    )
            application.assess_and_commit(
                candidate_factory(accepted=True),
                observer=target,
                performance_evidence=(
                    None
                    if profile_id != "performance"
                    else probe.performance_context.evidence
                ),
                dependency_graph_evidence=dependency_security,
            )
            if profile_id == "dependency-security" and dependency_security is None:
                dependency_security = dependency_context.observe(
                    application, probe.task_id,
                )
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
                dependency_security=dependency_security,
            )
            execution = authority.observe_completion(
                pass_test_id,
                task_id=probe.task_id,
                expected_profile_id=profile_id,
            )
            apply_currentness_attack(attack, probe, execution, column="boundary")
            state_after_attack = _serial_state_signature(
                probe, target, real_e2e=False,
            )
            attacks.append(_expect_verified_rejection(
                attack,
                (
                    (api4.ProfileCoverageError, CategoryExecutionError)
                    if profile_id == "performance"
                    else api4.ProfileCoverageError
                ),
                lambda: authority.observe(execution),
            ))
            if _serial_state_signature(
                probe, target, real_e2e=False,
            ) != state_after_attack:
                raise AssertionError("evidence rejection changed durable state")
        finally:
            target.close()
            close_dependency = getattr(dependency_context, "close", None)
            if callable(close_dependency):
                close_dependency()
    if not source_post_attestation_mutation_is_rejected():
        raise AssertionError("post-attestation source mutation was accepted")
    attacks.append("source-currentness")
    return tuple(sorted(attacks))


def _run_false_reproduction_r1_child() -> dict[str, object]:
    """Run only the bug-fix false-reproduction P/R and twelve attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _scenario_attack_receipt(
        api4=api4,
        plan=plan,
        matrix=matrix,
        profile_id="bug-fix",
        scenario_id=BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID,
        boundary_case_id=BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID,
        pass_test_id=BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID,
        reject_test_id=BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID,
        candidate_factory=bug_fix_false_reproduction_candidate,
        request_label=BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID,
        other_scenario_id=BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
    )
    if len(attacks) != 12:
        raise AssertionError("false-reproduction attack matrix changed")
    return {
        "attacks": attacks,
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current",
        "selector": FALSE_REPRODUCTION_R1_SELECTOR,
    }


def _run_regression_boundary_r1_child() -> dict[str, object]:
    """Run only the bug-fix regression-boundary P/R and twelve attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _scenario_attack_receipt(
        api4=api4,
        plan=plan,
        matrix=matrix,
        profile_id="bug-fix",
        scenario_id=BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID,
        boundary_case_id=BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID,
        pass_test_id=BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID,
        reject_test_id=BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID,
        candidate_factory=bug_fix_regression_boundary_candidate,
        request_label=BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID,
        other_scenario_id=BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID,
    )
    if len(attacks) != 12:
        raise AssertionError("regression-boundary attack matrix changed")
    return {
        "attacks": attacks,
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current",
        "selector": REGRESSION_BOUNDARY_R1_SELECTOR,
    }


def _run_minimal_patch_r1_child() -> dict[str, object]:
    """Run only the hotfix minimal-patch P/R and twelve attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _scenario_attack_receipt(
        api4=api4,
        plan=plan,
        matrix=matrix,
        profile_id="hotfix",
        scenario_id=HOTFIX_MINIMAL_PATCH_SCENARIO_ID,
        boundary_case_id=HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID,
        pass_test_id=HOTFIX_MINIMAL_PATCH_PASS_TEST_ID,
        reject_test_id=HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID,
        candidate_factory=hotfix_minimal_patch_candidate,
        request_label=HOTFIX_MINIMAL_PATCH_SCENARIO_ID,
        other_scenario_id="GEW-PSC-HOTFIX-EMERGENCY-BASELINE-P",
    )
    if len(attacks) != 12:
        raise AssertionError("minimal-patch attack matrix changed")
    return {
        "attacks": attacks,
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current",
        "selector": MINIMAL_PATCH_R1_SELECTOR,
    }


def _run_stable_baseline_r1_child() -> dict[str, object]:
    """Run the performance stable-baseline P/R and authority attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _scenario_attack_receipt(
        api4=api4,
        plan=plan,
        matrix=matrix,
        profile_id="performance",
        scenario_id=PERFORMANCE_STABLE_BASELINE_SCENARIO_ID,
        boundary_case_id=PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID,
        pass_test_id=PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
        reject_test_id=PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID,
        candidate_factory=performance_stable_baseline_candidate,
        request_label=PERFORMANCE_STABLE_BASELINE_SCENARIO_ID,
        other_scenario_id="GEW-PSC-PERFORMANCE-NOISE-CEILING-P",
    )
    authority_attacks = list(performance_coverage_authority_rejection_probes(
        api4=api4, plan=plan,
    ))
    authority_probe = run_serial_profile_binding(
        api4=api4,
        plan=plan,
        profile_id="performance",
        column="boundary",
        disposition="R",
    )
    try:
        authority_attacks.append(_expect_verified_rejection(
            "duplicate-bare",
            api4.ProfileCoverageError,
            lambda: api4.ProfileCoverageAuthority(
                **_coverage_authority_arguments(authority_probe, plan)
            ),
        ))
        try:
            cloned = copy.copy(authority_probe.authority)
        except BaseException:
            authority_attacks.append("clone")
        else:
            authority_attacks.append(_expect_verified_rejection(
                "clone",
                api4.ProfileCoverageError,
                lambda: cloned.observe(authority_probe.execution),
            ))
        state_before = _serial_state_signature(
            authority_probe.probe, authority_probe.target, real_e2e=False,
        )
        authority_probe.probe.performance_context.session.close()
        authority_attacks.append(_expect_verified_rejection(
            "session-currentness",
            api4.ProfileCoverageError,
            lambda: authority_probe.authority.observe(authority_probe.execution),
        ))
        if _serial_state_signature(
            authority_probe.probe, authority_probe.target, real_e2e=False,
        ) != state_before:
            raise AssertionError("performance session rejection changed durable state")
    finally:
        authority_probe.close()
    authority_attacks = sorted(authority_attacks)
    if len(attacks) != 12 or tuple(authority_attacks) != (
        "clone", "closed-launcher", "duplicate-bare", "missing-evidence",
        "session-currentness",
    ):
        raise AssertionError(
            "stable-baseline attack matrix changed: "
            f"scenario={attacks!r} authority={authority_attacks!r}"
        )
    return {
        "attacks": attacks,
        "authority_attacks": tuple(authority_attacks),
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current-launcher-zero",
        "selector": STABLE_BASELINE_R1_SELECTOR,
    }


def _resign_performance_candidate_projection(
    document: dict[str, object],
) -> None:
    """Coherently re-sign one test-only candidate evidence mutation."""

    from tests.support import wp08_performance_benchmark as performance_fixture

    sequence = document["sample_sets"][1]
    for correctness in sequence["warmup_correctness_observations"]:
        performance_fixture._resign(
            correctness,
            "performance-correctness-observation",
            "correctness_digest",
        )
    for sample in sequence["samples"]:
        correctness = sample.get("correctness_observation")
        if type(correctness) is dict:
            performance_fixture._resign(
                correctness,
                "performance-correctness-observation",
                "correctness_digest",
            )
        performance_fixture._resign(
            sample, "performance-measurement-sample", "sample_digest",
        )
    sample_set = sequence["sample_set_observation"]
    sample_set["warmup_correctness_observations"] = copy.deepcopy(
        sequence["warmup_correctness_observations"]
    )
    sample_set["samples"] = copy.deepcopy(sequence["samples"])
    performance_fixture._resign(
        sample_set,
        "performance-sample-set-observation",
        "sample_set_observation_digest",
    )
    statistics = document["statistics_observations"][1]
    statistics["sample_set_observation"] = copy.deepcopy(sample_set)
    performance_fixture._resign(
        statistics,
        "performance-statistics-observation",
        "statistics_observation_digest",
    )
    performance_fixture._resign(
        document, "performance-evidence-projection", "projection_digest",
    )


def _performance_correctness_rejection_attacks(
    evidence: object,
) -> tuple[str, ...]:
    """Reject coherently signed caller attempts to bypass correctness."""

    from graph_engineering.application.performance_benchmark import (
        PerformanceBenchmarkError,
        PerformanceBenchmarkRegistryFactory,
    )
    from graph_engineering.core.contracts.immutable import thaw

    original = thaw(evidence.projection)
    alternate = category.digest("performance-correctness-regression")

    def candidate_sample(value: dict[str, object]) -> dict[str, object]:
        return value["sample_sets"][1]["samples"][0]

    mutations = (
        (
            "observed-mismatch",
            lambda value: candidate_sample(value)["correctness_observation"].update(
                {"observed_correctness_digest": alternate}
            ),
        ),
        (
            "expected-substitution",
            lambda value: candidate_sample(value)["correctness_observation"].update({
                "expected_correctness_digest": alternate,
                "observed_correctness_digest": alternate,
            }),
        ),
        (
            "ignored-iteration",
            lambda value: candidate_sample(value)["correctness_observation"].update(
                {"iteration_index": 1}
            ),
        ),
        (
            "duration-only",
            lambda value: candidate_sample(value).pop("correctness_observation"),
        ),
        (
            "wrong-phase",
            lambda value: candidate_sample(value)["correctness_observation"].update(
                {"iteration_kind": "warmup"}
            ),
        ),
        (
            "wrong-case",
            lambda value: candidate_sample(value)["correctness_observation"].update(
                {"benchmark_case_id": "foreign-performance-case"}
            ),
        ),
        (
            "caller-correct",
            lambda value: candidate_sample(value)["correctness_observation"].update(
                {"observed_correctness_digest": True}
            ),
        ),
    )
    rejected: list[str] = []
    for label, mutate in mutations:
        changed = copy.deepcopy(original)
        mutate(changed)
        _resign_performance_candidate_projection(changed)
        factory = PerformanceBenchmarkRegistryFactory.from_installation()
        authority = factory.registry()
        rejected.append(_expect_verified_rejection(
            label,
            PerformanceBenchmarkError,
            lambda changed=changed, factory=factory, authority=authority:
            factory.rehydrate_performance_evidence(authority, changed),
        ))
    return tuple(sorted(rejected))


def _run_performance_remaining_r1_child(
    *, cumulative_selector: str | None = None,
) -> dict[str, object]:
    """Run the two P1 performance scenario pairs and closed attack matrices."""

    from graph_engineering.core.performance_benchmark import (
        comparison_products,
        integer_statistics,
    )

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan(
        selector=cumulative_selector,
    )
    scenario_attacks: dict[str, tuple[str, ...]] = {}
    retained_outliers: dict[str, tuple[int, int, int]] = {}
    correctness_rejections: tuple[str, ...] = ()
    noise_rejection: dict[str, object] = {}
    for index, scenario_id in enumerate(PERFORMANCE_REMAINING_SCENARIO_IDS):
        other = PERFORMANCE_REMAINING_SCENARIO_IDS[
            (index + 1) % len(PERFORMANCE_REMAINING_SCENARIO_IDS)
        ]
        stable = f"GEW-PSC-PERFORMANCE-{scenario_id.upper()}"
        attacks = _scenario_attack_receipt(
            api4=api4,
            plan=plan,
            matrix=matrix,
            profile_id="performance",
            scenario_id=scenario_id,
            boundary_case_id=f"{stable}-P",
            pass_test_id=f"{stable}-P",
            reject_test_id=f"{stable}-R",
            candidate_factory=(
                lambda *, accepted, selected=scenario_id:
                performance_remaining_scenario_candidate(
                    selected, accepted=accepted,
                )
            ),
            request_label=scenario_id,
            other_scenario_id=f"GEW-PSC-PERFORMANCE-{other.upper()}-P",
        )
        if len(attacks) != 12:
            raise AssertionError(
                f"{scenario_id} standard attack matrix changed"
            )
        scenario_attacks[scenario_id] = attacks

        positive = run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id=scenario_id,
            disposition="P",
        )
        try:
            projection = positive.probe.performance_context.evidence.projection
            candidate_samples = tuple(
                item["duration_ns"]
                for item in projection["sample_sets"][1]["samples"]
            )
            candidate_statistics = projection["statistics_observations"][1]
            if any(
                sample["correctness_observation"]["observed_correctness_digest"]
                != sample["correctness_observation"]["expected_correctness_digest"]
                for sample in projection["sample_sets"][1]["samples"]
            ):
                raise AssertionError(
                    "candidate correctness regression was accepted"
                )
            if scenario_id == "noise-outlier":
                oracle = plan.oracle_for(
                    "GEW-PSC-PERFORMANCE-NOISE-OUTLIER-R"
                )
                rejection_input = oracle["rejection_input"]
                values = rejection_input["values"]
                registry = (
                    positive.probe.performance_context
                    .registry_authority.registry
                )
                benchmark_case = registry.benchmark_cases[0]
                policies = tuple(
                    policy for policy in registry.statistics_policies
                    if policy.statistics_policy_id
                    == benchmark_case.statistics_policy_id
                )
                if len(policies) != 1:
                    raise AssertionError("noise rejection policy is ambiguous")
                rejection_median, rejection_mad, rejection_quiet = (
                    integer_statistics(values, policies[0])
                )
                rejection_left, rejection_right = comparison_products(
                    rejection_mad,
                    rejection_median,
                    policies[0].noise_ceiling_numerator,
                    policies[0].noise_ceiling_denominator,
                )
                if (
                    (rejection_median, rejection_mad, rejection_quiet)
                    != (100, 99, False)
                    or (rejection_left, rejection_right) != (198, 100)
                    or tuple(candidate_samples) == tuple(values)
                    or "[1,2,100,200,201]" in oracle["reject_error_message"]
                ):
                    raise AssertionError(
                        "typed noise rejection did not remain R-only"
                    )
                noise_rejection = {
                    "kind": rejection_input["kind"],
                    "median": rejection_median,
                    "mad": rejection_mad,
                    "left_product": rejection_left,
                    "right_product": rejection_right,
                    "outcome": "inconclusive-noise",
                }
                median = candidate_statistics["median_ns"]
                mad = candidate_statistics["mad_ns"]
                maximum_deviation = max(
                    abs(value - median) for value in candidate_samples
                )
                if maximum_deviation <= mad:
                    raise AssertionError(
                        "noise-outlier did not retain an outlier"
                    )
                retained_outliers[scenario_id] = (
                    median, mad, maximum_deviation,
                )
            elif scenario_id == "correctness-regression":
                correctness_rejections = (
                    _performance_correctness_rejection_attacks(
                        positive.probe.performance_context.evidence
                    )
                )
            before = positive.probe.performance_context.launcher.launch_count
            restarted_task, restarted_runtime = positive.probe.restart_authorities()
            restarted_application = positive.application.restart(
                restarted_task, restarted_runtime, positive.target,
            )
            restarted_authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=restarted_application,
                task_application=restarted_task,
                repository=positive.probe.repository,
                object_repository=positive.probe.objects,
                runtime=restarted_runtime,
            )
            restored = restarted_authority.observe_completion(
                positive.test_id,
                task_id=positive.probe.task_id,
                expected_profile_id="performance",
            )
            if (
                restored.execution_digest != positive.execution.execution_digest
                or positive.probe.performance_context.launcher.launch_count != before
            ):
                raise AssertionError(
                    "performance P1 restart changed evidence or replayed launcher"
                )
        finally:
            positive.close()
    return {
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current-launcher-zero",
        "correctness_rejections": correctness_rejections,
        "noise_rejection": noise_rejection,
        "retained_outliers": retained_outliers,
        "scenario_attacks": scenario_attacks,
        "selector": PERFORMANCE_REMAINING_R1_SELECTOR,
    }


def _run_cumulative_child(selector: str) -> dict[str, object]:
    """Run one exact checkpoint through the shared serial lifecycle."""

    checkpoint = _cumulative_checkpoint(selector)

    from tests.support import wp08_scenario_truth as lifecycle_fixture
    from tests.unit import test_wp08_profile_contracts as contracts

    fd_before = len(os.listdir("/dev/fd"))
    started_ns = time.monotonic_ns()
    prior_ns = started_ns

    def progress(stage: str, **fields: object) -> None:
        nonlocal prior_ns
        observed_ns = time.monotonic_ns()
        print(json.dumps(
            {
                "delta_ns": observed_ns - prior_ns,
                "elapsed_ns": observed_ns - started_ns,
                "stage": stage,
                "selector": checkpoint.selector,
                **fields,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ), file=sys.stderr, flush=True)
        prior_ns = observed_ns

    progress("plan-load-start")
    api, api4, coverage, matrix, profile, overlay, plan = _verified_plan(
        selector=checkpoint.selector,
    )
    progress(
        "plan-load-done",
        oracle_bindings=len(plan.oracle_bindings),
        plan_bindings=len(plan.bindings),
    )
    full = selector == P3_CUMULATIVE274_R1_SELECTOR
    if full:
        _validate_c274_plan(plan, matrix)
    else:
        _validate_cumulative_plan(plan, matrix, checkpoint)
    progress("p1-sibling-start")
    p1_sibling = _run_performance_remaining_r1_child(
        cumulative_selector=checkpoint.selector,
    )
    progress("p1-sibling-done")
    if full:
        p1_sibling = json.loads(json.dumps(p1_sibling))
        _validate_c274_p1(p1_sibling)
    results: list[SerialCoverageExecution] = []
    observations: list[object] = []
    records: tuple[object, ...] = ()
    factory = None
    factory_closed = False
    dynamic_decision = None
    static_decision = None
    try:
        for index, (test_id, binding) in enumerate(plan.bindings.items(), start=1):
            progress(
                "binding-start",
                index=index,
                selector_kind=binding["selector_kind"],
                test_id=test_id,
            )
            if binding["selector_kind"] == "mandatory":
                result = run_serial_profile_binding(
                    api4=api4,
                    plan=plan,
                    profile_id=str(binding["profile_id"]),
                    column=str(binding["column_id"]),
                    disposition=str(binding["disposition"]),
                    quiescent=True,
                )
            elif binding["selector_kind"] == "scenario":
                result = run_serial_scenario_binding(
                    api4=api4,
                    plan=plan,
                    scenario_id=str(binding["scenario_id"]),
                    disposition=str(binding["disposition"]),
                    quiescent=True,
                )
            else:
                raise AssertionError("cumulative selector kind changed")
            results.append(result)
            if result.test_id != test_id:
                raise AssertionError("cumulative execution order changed")
            lifecycle = result.binding_lifecycle
            if (
                lifecycle is None
                or (
                    lifecycle.state,
                    lifecycle.generation,
                    lifecycle.expected_purpose,
                ) != ("QUIESCED", 0, "issue")
            ):
                raise AssertionError("cumulative binding did not quiesce at g0")
            progress("binding-executed", index=index, test_id=test_id)
            observations.append(result.observe_current())
            if (
                lifecycle.state,
                lifecycle.generation,
                lifecycle.expected_purpose,
            ) != ("QUIESCED", 1, "use"):
                raise AssertionError("cumulative issue phase did not requiesce")
            if (
                lifecycle_fixture.PrivateBindingReopenPort.active_handle_count()
                or lifecycle_fixture.PrivateBindingReopenPort.
                active_reopened_binding_count()
            ):
                raise AssertionError("cumulative issue retained a live binding")
            progress("binding-observed", index=index, test_id=test_id)

        execution_ids = tuple(result.test_id for result in results)
        if (
            len(execution_ids) != checkpoint.plan_bindings
            or len(set(execution_ids)) != checkpoint.plan_bindings
            or set(execution_ids) != set(plan.bindings)
        ):
            raise AssertionError("cumulative execution closure changed")
        oracle_keys = tuple(
            (
                row["oracle_id"], row["profile_id"], row["selector_kind"],
                row["column_id"], row["scenario_id"],
            )
            for row in plan.oracle_bindings
        )
        if (
            len(oracle_keys) != checkpoint.oracle_bindings
            or len(set(oracle_keys)) != checkpoint.oracle_bindings
        ):
            raise AssertionError("cumulative oracle closure changed")

        identity_fields = (
            "repository_root", "task", "target", "branch_ref",
            "action_root", "command_root",
        )
        binding_identities = tuple(
            result.binding_identity_projection() for result in results
        )

        def identity_key(value: object) -> str:
            return json.dumps(
                value,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )

        if any(
            len({identity_key(row[field]) for row in binding_identities})
            != checkpoint.plan_bindings
            for field in identity_fields
        ) or len({
            tuple(identity_key(row[field]) for field in identity_fields)
            for row in binding_identities
        }) != checkpoint.plan_bindings:
            raise AssertionError("cumulative binding identities are shared")

        progress("factory-start", authorities=len(results))
        factory = api.CoverageRecordFactory(
            execution_authority=tuple(result.authority for result in results),
            coverage_policy=coverage,
        )
        progress("factory-done", authorities=len(results))
        profile_contracts: dict[str, tuple[object, object]] = {
            "new-feature": (profile, overlay),
        }
        issued_records: list[object] = []
        for index, (result, observation) in enumerate(
            zip(results, observations, strict=True), start=1,
        ):
            progress("record-start", index=index, test_id=result.test_id)
            current_profile = profile_contracts.get(result.profile_id)
            if current_profile is None:
                loaded = _verified_runner_contracts(result.profile_id)
                current_profile = (loaded[3], loaded[4])
                profile_contracts[result.profile_id] = current_profile
            issued_records.append(factory.issue_execution(
                observation,
                matrix=matrix,
                profile=current_profile[0],
                overlay=current_profile[1],
            ))
            lifecycle = result.binding_lifecycle
            if (
                lifecycle.state,
                lifecycle.generation,
                lifecycle.expected_purpose,
            ) != ("QUIESCED", 3, "gate"):
                raise AssertionError(
                    "cumulative use/precommit phases did not requiesce"
                )
            if lifecycle_fixture.PrivateBindingReopenPort.active_handle_count():
                raise AssertionError(
                    "cumulative record issuance retained a live binding"
                )
            progress("record-done", index=index, test_id=result.test_id)
        records = tuple(issued_records)
        progress("dynamic-gate-start", records=len(records))
        dynamic_decision = api.ReleaseCoverageGate.evaluate(
            matrix,
            coverage_records=records,
            coverage_factory=factory,
        )
        record_ids = tuple(record.test_id for record in records)
        if (
            dynamic_decision.passed is not full
            or len(record_ids) != checkpoint.plan_bindings
            or len(set(record_ids)) != checkpoint.plan_bindings
            or set(record_ids) != set(plan.bindings)
            or len(dynamic_decision.missing_test_ids) != checkpoint.missing_records
            or set(dynamic_decision.missing_test_ids) != (
                set((*matrix.profile_case_ids, *matrix.scenario_case_ids))
                - set(plan.bindings)
            )
            or dynamic_decision.invalid_test_ids
            or dynamic_decision.stale_test_ids
        ):
            raise AssertionError("cumulative dynamic gate changed")
        if any((
            result.binding_lifecycle.state,
            result.binding_lifecycle.generation,
            result.binding_lifecycle.expected_purpose,
        ) != ("QUIESCED", 4, None) for result in results):
            raise AssertionError("cumulative gate phases did not requiesce")
        if (
            lifecycle_fixture.PrivateBindingReopenPort.active_handle_count()
            or lifecycle_fixture.PrivateBindingReopenPort.
            active_reopened_binding_count()
            or lifecycle_fixture.PrivateBindingReopenPort.
            maximum_active_reopened_binding_count() > 1
        ):
            raise AssertionError("cumulative gate violated strict serial reopen")
        progress(
            "dynamic-gate-done",
            missing=len(dynamic_decision.missing_test_ids),
            records=len(records),
        )

        progress("static-gate-start")
        static_registry = api.EvidenceObservationRegistry.from_dict(
            contracts._evidence_registry_document(),
            coverage_policy=coverage,
            oracle_manifest_bytes=contracts._oracle_manifest_bytes(),
        )
        static_authority = api.EvidenceObservationAuthority(
            static_registry,
            evidence_root=contracts.ROOT / "tests/fixtures",
        )
        static_observation = static_authority.observe(
            PASS_TEST_ID,
            matrix=matrix,
            profile=profile,
            overlay=overlay,
        )
        static_factory = api.CoverageRecordFactory(
            authority=static_authority,
            coverage_policy=coverage,
        )
        static_record = static_factory.issue(
            static_observation,
            matrix=matrix,
            profile=profile,
            overlay=overlay,
        )
        static_decision = api.ReleaseCoverageGate.evaluate(
            matrix,
            coverage_records=(static_record,),
            coverage_factory=static_factory,
        )
        if (
            static_decision.passed
            or len(static_decision.missing_test_ids) != checkpoint.total_records
            or set(static_decision.missing_test_ids) != set(
                (*matrix.profile_case_ids, *matrix.scenario_case_ids)
            )
            or static_decision.invalid_test_ids
            or static_decision.stale_test_ids
        ):
            raise AssertionError("cumulative static gate changed")
        progress(
            "static-gate-done",
            missing=len(static_decision.missing_test_ids),
        )
        finalize_consumed_coverage_factory(factory, dynamic_decision)
        factory_closed = True
        if any(
            result.binding_lifecycle.state != "PERMANENTLY_CLOSED"
            for result in results
        ):
            raise AssertionError("cumulative bindings did not become terminal")
        progress("terminal-done", results=len(results))
    finally:
        primary = sys.exc_info()[1]
        cleanup_errors = []
        try:
            if factory is not None and not factory_closed:
                if full:
                    _close_c274_factory(factory, dynamic_decision)
                elif dynamic_decision is None:
                    abort_uncommitted_coverage_factory(factory)
                else:
                    finalize_consumed_coverage_factory(factory, dynamic_decision)
        except BaseException as error:
            cleanup_errors.append(error)
        finally:
            progress("teardown-start", results=len(results))
            for index, result in enumerate(reversed(results), start=1):
                try:
                    result.close()
                except BaseException as error:
                    cleanup_errors.append(error)
                progress("teardown-result", index=index, test_id=result.test_id)
            progress("teardown-done", results=len(results))
        if cleanup_errors:
            if full and primary is not None:
                raise BaseExceptionGroup("cumulative274 failed with cleanup errors", [primary, *cleanup_errors]) from None
            if full and len(cleanup_errors) > 1:
                raise BaseExceptionGroup("cumulative274 cleanup errors", cleanup_errors)
            raise cleanup_errors[0]
    if (
        lifecycle_fixture.PrivateBindingReopenPort.active_handle_count()
        or lifecycle_fixture.PrivateBindingReopenPort.
        active_reopened_binding_count()
        or len(os.listdir("/dev/fd")) != fd_before
    ):
        raise AssertionError("cumulative resources did not return to baseline")
    if dynamic_decision is None or static_decision is None:
        raise AssertionError("cumulative gates were not evaluated")
    if full:
        receipt = {
            "selector": selector, "plan_bindings": len(plan.bindings), "oracle_bindings": len(plan.oracle_bindings),
            "dynamic": {"valid": len(records), "missing": len(dynamic_decision.missing_test_ids),
                "passed": dynamic_decision.passed, "invalid": len(dynamic_decision.invalid_test_ids),
                "stale": len(dynamic_decision.stale_test_ids), "duplicate": len(records)-len({r.test_id for r in records})},
            "static": {"valid": 0, "missing": len(static_decision.missing_test_ids),
                "passed": static_decision.passed, "invalid": len(static_decision.invalid_test_ids),
                "stale": len(static_decision.stale_test_ids), "duplicate": 0},
            "p1_sibling": p1_sibling,
            "closure": _c274_closure(plan,
                terminal=sum(r.binding_lifecycle.state == "PERMANENTLY_CLOSED" for r in results),
                active=lifecycle_fixture.PrivateBindingReopenPort.active_handle_count(),
                reopened=lifecycle_fixture.PrivateBindingReopenPort.active_reopened_binding_count(),
                maximum=lifecycle_fixture.PrivateBindingReopenPort.maximum_active_reopened_binding_count()),
        }
        return _validate_c274_receipt(receipt, plan)
    new_ids = checkpoint.new_test_ids
    return {
        "dynamic": {
            "valid": len(records),
            "missing": len(dynamic_decision.missing_test_ids),
            "passed": dynamic_decision.passed,
            "invalid": len(dynamic_decision.invalid_test_ids),
            "stale": len(dynamic_decision.stale_test_ids),
            "duplicate": len(records) - len({record.test_id for record in records}),
        },
        "new_records": len(tuple(
            record for record in records if record.test_id in new_ids
        )),
        "oracle_bindings": len(plan.oracle_bindings),
        "p1_sibling": p1_sibling,
        "plan_bindings": len(plan.bindings),
        "retained_records": len(tuple(
            record for record in records if record.test_id not in new_ids
        )),
        "selector": checkpoint.selector,
        "static": {
            "valid": 0,
            "missing": len(static_decision.missing_test_ids),
            "passed": static_decision.passed,
            "invalid": len(static_decision.invalid_test_ids),
            "stale": len(static_decision.stale_test_ids),
            "duplicate": 0,
        },
    }


def _run_p2a_cumulative_r2_child() -> dict[str, object]:
    """Preserve the P2a checkpoint and distinct selector identity."""

    return _run_cumulative_child(P2A_CUMULATIVE_R2_SELECTOR)


def _run_p2b_cumulative_r1_child() -> dict[str, object]:
    """Entry availability does not authorize a P2b cumulative launch."""

    return _run_cumulative_child(P2B_CUMULATIVE_R1_SELECTOR)


def _run_vulnerable_graph_r1_child() -> dict[str, object]:
    """Run the dependency-security vulnerable-graph P/R and attacks."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    attacks = _scenario_attack_receipt(
        api4=api4,
        plan=plan,
        matrix=matrix,
        profile_id="dependency-security",
        scenario_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID,
        boundary_case_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_BOUNDARY_CASE_ID,
        pass_test_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID,
        reject_test_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID,
        candidate_factory=dependency_security_vulnerable_graph_candidate,
        request_label=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID,
        other_scenario_id="GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P",
    )
    if len(attacks) != 12:
        raise AssertionError("vulnerable-graph standard attack matrix changed")
    dependency_attacks = _dependency_security_scenario_attack_receipt(
        api4=api4, plan=plan,
    )
    if len(dependency_attacks) != 10:
        raise AssertionError("vulnerable-graph dependency attack matrix changed")
    return {
        "attacks": attacks,
        "dependency_attacks": dependency_attacks,
        "dependency_security": "current-task-bound",
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current-launcher-zero",
        "selector": VULNERABLE_GRAPH_R1_SELECTOR,
    }


def _dependency_graph_currentness_attack_receipt(
    *, api4: Slice4API, plan: object,
) -> dict[str, tuple[str, ...]]:
    """Exercise graph/disposition identity and offline currentness per scenario."""

    import graph_engineering
    import socket
    from tests.support import wp08_dependency_security as dependency_fixture
    from unittest import mock

    receipts: dict[str, tuple[str, ...]] = {}
    for scenario_id in DEPENDENCY_GRAPH_SCENARIO_IDS:
        result = run_serial_scenario_binding(
            api4=api4,
            plan=plan,
            scenario_id=scenario_id,
            disposition="P",
        )
        labels: list[str] = []
        try:
            final_factory, observation = result.authority._dependency_security
            durable_state = (
                len(result.probe.repository.replay(result.probe.task_id)),
                tuple(result.probe.repository.referenced_objects(
                    result.probe.task_id
                )),
                result.target.path.read_bytes(),
                result.target.mutation_count,
            )
            assessment = result.application.current_assessment(
                result.probe.task_id,
                expected_profile_id="dependency-security",
            )
            if (
                assessment is None
                or assessment.schema_version != "1.2.0"
                or assessment.dependency_graph_projection is None
            ):
                raise AssertionError(
                    "dependency graph assessment projection is absent"
                )

            def resign_projection(document: dict[str, object]) -> None:
                from graph_engineering.core.contracts.digest import semantic_digest
                from graph_engineering.core.contracts.immutable import freeze

                body = copy.deepcopy(document)
                body.pop("projection_digest", None)
                document["projection_digest"] = semantic_digest(
                    freeze(body),
                    contract_type=(
                        "urn:gew:contract:dependency-graph-assessment-projection"
                    ),
                    projection_id=(
                        "urn:gew:digest-projection:"
                        "dependency-graph-assessment-projection:1.0.0"
                    ),
                    schema_id=(
                        "urn:gew:schema:"
                        "category-completion-assessment-input:1.2.0"
                    ),
                )

            def resign_assessment(document: dict[str, object]) -> None:
                from graph_engineering.core.contracts.digest import semantic_digest
                from graph_engineering.core.contracts.immutable import freeze

                body = copy.deepcopy(document)
                body.pop("assessment_digest", None)
                document["assessment_digest"] = semantic_digest(
                    freeze(body),
                    contract_type=(
                        "urn:gew:contract:category-completion-assessment"
                    ),
                    projection_id=(
                        "urn:gew:digest-projection:"
                        "category-completion-assessment:1.2.0"
                    ),
                    schema_id=(
                        "urn:gew:schema:"
                        "category-completion-assessment-input:1.2.0"
                    ),
                )

            assessment_attacks: list[tuple[str, dict[str, object]]] = []
            absent = assessment.to_dict()
            absent.pop("dependency_graph_projection")
            resign_assessment(absent)
            assessment_attacks.append(("assessment-projection-absent", absent))

            for label, mutate in (
                (
                    "assessment-projection-stale",
                    lambda projection: projection.__setitem__(
                        "snapshot_digest", category.digest("stale-dependency-snapshot")
                    ),
                ),
                (
                    "assessment-projection-foreign",
                    lambda projection: projection.__setitem__(
                        "task_id", "task:foreign:dependency-graph"
                    ),
                ),
                (
                    "assessment-projection-reordered",
                    lambda projection: projection["before_graph"].__setitem__(
                        "edges", list(reversed(projection["before_graph"]["edges"]))
                    ),
                ),
                (
                    "assessment-projection-mixed",
                    lambda projection: (
                        projection.__setitem__(
                            "before_closure", projection["after_closure"]
                        ),
                        projection.__setitem__(
                            "after_closure", projection["before_closure"]
                        ),
                    ),
                ),
                (
                    "assessment-projection-coherent-resign",
                    lambda projection: projection["advisory_installation"].__setitem__(
                        "registry_digest", category.digest("resigned-registry-history")
                    ),
                ),
            ):
                changed = assessment.to_dict()
                projection = changed["dependency_graph_projection"]
                if type(projection) is not dict:
                    raise AssertionError(
                        "dependency graph assessment attack projection is malformed"
                    )
                mutate(projection)
                resign_projection(projection)
                resign_assessment(changed)
                assessment_attacks.append((label, changed))

            for label, changed in assessment_attacks:
                body = json.dumps(
                    changed,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                labels.append(_expect_verified_rejection(
                    label,
                    Exception,
                    lambda body=body: result.application._oracle.restore(body),
                ))
            labels.append(_expect_verified_rejection(
                "clone",
                Exception,
                lambda: final_factory.require_current(copy.copy(observation)),
            ))

            original_before_graph = observation._before_graph
            object.__setattr__(
                observation, "_before_graph", copy.copy(original_before_graph),
            )
            try:
                labels.append(_expect_verified_rejection(
                    "before-graph-currentness",
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))
            finally:
                object.__setattr__(
                    observation, "_before_graph", original_before_graph,
                )

            original_projection = observation._projection
            changed_projection = dependency_fixture.thaw(original_projection)
            changed_projection["target_observation_digest"] = category.digest(
                f"foreign-dependency-graph:{scenario_id}"
            )
            object.__setattr__(
                observation,
                "_projection",
                dependency_fixture.freeze(changed_projection),
            )
            try:
                labels.append(_expect_verified_rejection(
                    "observation-projection-currentness",
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))
            finally:
                object.__setattr__(
                    observation, "_projection", original_projection,
                )

            if scenario_id == "fix-unavailable":
                original_disposition = observation._disposition
                object.__setattr__(
                    observation,
                    "_disposition",
                    copy.copy(original_disposition),
                )
                label = "disposition-currentness"
                restore_field = "_disposition"
                restore_value = original_disposition
            else:
                original_after_graph = observation._after_graph
                object.__setattr__(
                    observation,
                    "_after_graph",
                    copy.copy(original_after_graph),
                )
                label = "after-graph-currentness"
                restore_field = "_after_graph"
                restore_value = original_after_graph
            try:
                labels.append(_expect_verified_rejection(
                    label,
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))
            finally:
                object.__setattr__(observation, restore_field, restore_value)

            resources = list(
                graph_engineering._dependency_graph_installation_resources()
            )
            changed_policy = json.loads(resources[1])
            changed_policy["root_distribution_policy"][
                "root_distribution_name"
            ] = "caller-root"
            dependency_fixture._resign(
                changed_policy,
                "dependency-graph-policy-registry",
                "registry_digest",
            )
            resources[1] = json.dumps(
                changed_policy,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            with mock.patch.object(
                graph_engineering,
                "_dependency_graph_installation_resources",
                return_value=tuple(resources),
            ):
                labels.append(_expect_verified_rejection(
                    "installation-currentness",
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))

            with mock.patch.object(
                socket,
                "socket",
                side_effect=AssertionError("network forbidden"),
            ):
                coverage_observation = result.authority.observe(
                    result.execution
                )
                if (
                    final_factory.require_current(observation) is not observation
                    or result.authority._require_observation(
                        coverage_observation
                    ) is not coverage_observation
                ):
                    raise AssertionError(
                        "dependency graph offline currentness changed"
                    )
            labels.append("offline-currentness")
            if (
                len(result.probe.repository.replay(result.probe.task_id)),
                tuple(result.probe.repository.referenced_objects(
                    result.probe.task_id
                )),
                result.target.path.read_bytes(),
                result.target.mutation_count,
            ) != durable_state:
                raise AssertionError(
                    "dependency graph currentness attack changed durable state"
                )
            receipts[scenario_id] = tuple(sorted(labels))
        finally:
            result.close()
    return receipts


def _run_dependency_graph_scenarios_r1_child() -> dict[str, object]:
    """Run both graph/remediation scenario pairs and closed attack matrices."""

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    scenario_attacks: dict[str, tuple[str, ...]] = {}
    for index, scenario_id in enumerate(DEPENDENCY_GRAPH_SCENARIO_IDS):
        other = DEPENDENCY_GRAPH_SCENARIO_IDS[
            (index + 1) % len(DEPENDENCY_GRAPH_SCENARIO_IDS)
        ]
        stable = f"GEW-PSC-DEPENDENCY-SECURITY-{scenario_id.upper()}"
        attacks = _scenario_attack_receipt(
            api4=api4,
            plan=plan,
            matrix=matrix,
            profile_id="dependency-security",
            scenario_id=scenario_id,
            boundary_case_id=f"{stable}-P",
            pass_test_id=f"{stable}-P",
            reject_test_id=f"{stable}-R",
            candidate_factory=(
                lambda *, accepted, selected=scenario_id:
                dependency_graph_scenario_candidate(
                    selected, accepted=accepted,
                )
            ),
            request_label=scenario_id,
            other_scenario_id=(
                "GEW-PSC-DEPENDENCY-SECURITY-"
                f"{other.upper()}-P"
            ),
        )
        if len(attacks) != 12:
            raise AssertionError(
                f"{scenario_id} standard attack matrix changed"
            )
        scenario_attacks[scenario_id] = attacks
    graph_attacks = _dependency_graph_currentness_attack_receipt(
        api4=api4, plan=plan,
    )
    if any(len(attacks) != 12 for attacks in graph_attacks.values()):
        raise AssertionError("dependency graph currentness matrix changed")
    return {
        "graph_attacks": graph_attacks,
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current-replay-zero",
        "scenario_attacks": scenario_attacks,
        "selector": DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR,
    }


def _dependency_security_scenario_attack_receipt(
    *, api4: Slice4API, plan: object,
) -> tuple[str, ...]:
    """Exercise ADR-0006 currentness beneath the vulnerable-graph pair."""

    import graph_engineering
    from tests.support import wp08_dependency_security as dependency_fixture
    from unittest import mock

    attacks: list[str] = []
    result = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID,
        disposition="P",
    )
    foreign_context = dependency_fixture.dependency_security_coverage_context(
        result.probe.repository,
    )
    try:
        factory, observation = result.authority._dependency_security
        foreign_factory, foreign_observation = foreign_context.observe(
            result.application, result.probe.task_id,
        )
        arguments = _coverage_authority_arguments(result, plan)
        arguments["dependency_security"] = (factory, foreign_observation)
        attacks.append(_expect_verified_rejection(
            "foreign",
            api4.ProfileCoverageError,
            lambda: api4.ProfileCoverageAuthority(**arguments),
        ))
        clone = copy.copy(observation)
        attacks.append(_expect_verified_rejection(
            "clone",
            Exception,
            lambda: factory.require_current(clone),
        ))

        def mutated_observation(label: str, field: str, value: object) -> None:
            original = getattr(observation, field)
            state = _serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            setattr(observation, field, value)
            try:
                attacks.append(_expect_verified_rejection(
                    label,
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))
                if _serial_state_signature(
                    result.probe, result.target, real_e2e=False,
                ) != state:
                    raise AssertionError(
                        "dependency observation rejection changed durable state"
                    )
            finally:
                setattr(observation, field, original)

        mutated_observation(
            "applicability-residual", "_residual", foreign_context.residual,
        )
        mutated_observation(
            "closure-record", "_after", foreign_context.after,
        )
        altered_projection = dependency_fixture.thaw(observation._projection)
        altered_projection["target_observation_digest"] = category.digest(
            "foreign-dependency-target"
        )
        mutated_observation(
            "regression-target",
            "_projection",
            dependency_fixture.freeze(altered_projection),
        )

        current_resources = graph_engineering._dependency_advisory_installation_resources()

        def registry_attack(label: str, document: dict[str, object]) -> None:
            resources = list(current_resources)
            resources[1] = json.dumps(
                document, ensure_ascii=False, separators=(",", ":"), sort_keys=True,
            ).encode("utf-8")
            state = _serial_state_signature(
                result.probe, result.target, real_e2e=False,
            )
            with mock.patch.object(
                graph_engineering,
                "_dependency_advisory_installation_resources",
                return_value=tuple(resources),
            ):
                attacks.append(_expect_verified_rejection(
                    label,
                    api4.ProfileCoverageError,
                    lambda: result.authority.observe(result.execution),
                ))
            if _serial_state_signature(
                result.probe, result.target, real_e2e=False,
            ) != state:
                raise AssertionError("dependency registry attack changed durable state")

        replacement = dependency_fixture._candidate_document()
        registry_attack("coherent-replacement", replacement)
        expired = dependency_fixture.registry_document()
        expired["source_records"][0]["not_after"] = "2020-01-01T00:00:00Z"
        dependency_fixture._resign(
            expired["source_records"][0],
            "dependency-advisory-source-record",
            "source_record_digest",
        )
        expired["advisories"][0]["not_after"] = "2020-01-01T00:00:00Z"
        dependency_fixture._resign(
            expired["advisories"][0],
            "dependency-advisory-record",
            "advisory_digest",
        )
        dependency_fixture._resign(
            expired, "dependency-advisory-registry", "registry_digest",
        )
        registry_attack("expired", expired)
        revoked = dependency_fixture.registry_document()
        revoked["revocation_high_water"]["source_states"][0]["status"] = "revoked"
        revoked["revocation_high_water"]["advisory_states"][0]["status"] = "revoked"
        dependency_fixture._resign(
            revoked["revocation_high_water"],
            "dependency-advisory-status-high-water",
            "high_water_digest",
        )
        dependency_fixture._resign(
            revoked, "dependency-advisory-registry", "registry_digest",
        )
        registry_attack("revoked", revoked)
    finally:
        foreign_context.close()
        result.close()

    stale_result = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID,
        disposition="P",
    )
    try:
        apply_currentness_attack(
            "revision-drift", stale_result.probe, stale_result.execution,
            column="boundary",
        )
        state = _serial_state_signature(
            stale_result.probe, stale_result.target, real_e2e=False,
        )
        attacks.append(_expect_verified_rejection(
            "stale",
            api4.ProfileCoverageError,
            lambda: stale_result.authority.observe(stale_result.execution),
        ))
        if _serial_state_signature(
            stale_result.probe, stale_result.target, real_e2e=False,
        ) != state:
            raise AssertionError("stale dependency rejection changed durable state")
    finally:
        stale_result.close()

    graph_result = run_serial_scenario_binding(
        api4=api4,
        plan=plan,
        scenario_id=DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID,
        disposition="P",
    )
    try:
        apply_currentness_attack(
            "graph-ref-drift", graph_result.probe, graph_result.execution,
            column="boundary",
        )
        state = _serial_state_signature(
            graph_result.probe, graph_result.target, real_e2e=False,
        )
        attacks.append(_expect_verified_rejection(
            "task-graph-ref",
            api4.ProfileCoverageError,
            lambda: graph_result.authority.observe(graph_result.execution),
        ))
        if _serial_state_signature(
            graph_result.probe, graph_result.target, real_e2e=False,
        ) != state:
            raise AssertionError("GraphRef rejection changed durable state")
    finally:
        graph_result.close()
    return tuple(sorted(attacks))


def _run_migration_scenarios_r1_child() -> dict[str, object]:
    """Run the four task-bound migration scenario pairs and closed attacks."""

    import unittest

    from tests.support import wp08_migration_rehearsal as migration_fixture

    _api, api4, _coverage, matrix, _profile, _overlay, plan = _verified_plan()
    scenario_attacks: dict[str, tuple[str, ...]] = {}
    for index, scenario_id in enumerate(MIGRATION_SCENARIO_IDS):
        other = MIGRATION_SCENARIO_IDS[(index + 1) % len(MIGRATION_SCENARIO_IDS)]
        member = f"GEW-PSC-MIGRATION-{scenario_id.upper()}"
        attacks = _scenario_attack_receipt(
            api4=api4,
            plan=plan,
            matrix=matrix,
            profile_id="migration",
            scenario_id=scenario_id,
            boundary_case_id=f"{member}-P",
            pass_test_id=f"{member}-P",
            reject_test_id=f"{member}-R",
            candidate_factory=(
                lambda *, accepted, selected=scenario_id:
                migration_scenario_candidate(selected, accepted=accepted)
            ),
            request_label=scenario_id,
            other_scenario_id=f"GEW-PSC-MIGRATION-{other.upper()}-P",
        )
        if len(attacks) != 12:
            raise AssertionError(
                f"{scenario_id} standard attack matrix changed"
            )
        scenario_attacks[scenario_id] = attacks

    case = unittest.TestCase()
    migration_fixture.assert_migration_rehearsal_slice_a_rejections(case)
    migration_fixture.assert_migration_rehearsal_slice_a_r1_contracts(case)
    return {
        "authority_attacks": "slice-a-current",
        "oracle_bindings": len(plan.oracle_bindings),
        "plan_bindings": len(plan.bindings),
        "restart": "current-replay-zero",
        "scenario_attacks": scenario_attacks,
        "selector": MIGRATION_SCENARIOS_R1_SELECTOR,
    }


def _stderr_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return "" if value is None else str(value)


def _wait_for_verified_child(
    process: object,
    *,
    selector: str,
    timeout_seconds: int,
    heartbeat_interval_seconds: int,
    reap_timeout_seconds: int | None = None,
) -> dict[str, object]:
    """Wait for one child while reporting bounded deterministic progress."""

    if (
        type(timeout_seconds) is not int
        or type(heartbeat_interval_seconds) is not int
        or timeout_seconds <= 0
        or heartbeat_interval_seconds <= 0
        or heartbeat_interval_seconds >= timeout_seconds
    ):
        raise AssertionError("verified runner testability limits are invalid")
    communicate = getattr(process, "communicate", None)
    kill = getattr(process, "kill", None)
    if not callable(communicate) or not callable(kill):
        raise AssertionError("verified runner child process is invalid")
    started_ns = time.monotonic_ns()
    elapsed_ns = 0
    sequence = 0
    progress = ""
    while True:
        remaining_ns = timeout_seconds * 1_000_000_000 - elapsed_ns
        wait_seconds = min(
            heartbeat_interval_seconds,
            remaining_ns / 1_000_000_000,
        )
        try:
            stdout, stderr = communicate(timeout=wait_seconds)
        except subprocess.TimeoutExpired as error:
            progress = _stderr_text(error.stderr)[-16384:] or progress
            elapsed_ns = time.monotonic_ns() - started_ns
            if elapsed_ns >= timeout_seconds * 1_000_000_000:
                kill()
                _final_stdout, final_stderr = (communicate() if reap_timeout_seconds is None
                    else communicate(timeout=reap_timeout_seconds))
                detail = (_stderr_text(final_stderr) or progress)[-16384:]
                raise AssertionError(
                    f"verified runner child timed out ({selector}): {detail}"
                ) from error
            sequence += 1
            heartbeat = {
                "elapsed_seconds": elapsed_ns // 1_000_000_000,
                "heartbeat_sequence": sequence,
                "last_child_stderr": progress,
                "selector": selector,
            }
            print(
                json.dumps(heartbeat, sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
                flush=True,
            )
            continue
        returncode = getattr(process, "returncode", None)
        if returncode != 0:
            raise AssertionError(
                f"verified runner child failed ({selector}): "
                f"{_stderr_text(stderr) or _stderr_text(stdout)}"
            )
        try:
            receipt = json.loads(_stderr_text(stdout))
        except json.JSONDecodeError as error:
            raise AssertionError("verified runner receipt is not exact JSON") from error
        if type(receipt) is not dict or receipt.get("selector") != selector:
            raise AssertionError("verified runner receipt selector changed")
        return receipt


def _cumulative_runner_testability():  # type: ignore[no-untyped-def]
    """Re-read immutable cumulative-runner limits from current authority."""

    from graph_engineering.application.scenario_truth import (
        ScenarioTruthRegistryFactory,
    )

    factory = ScenarioTruthRegistryFactory.from_installation()
    try:
        return factory.registry().testability
    finally:
        factory.close()


def _p2a_cumulative_runner_testability():  # type: ignore[no-untyped-def]
    """Compatibility entry for the original P2a testability checks."""

    return _cumulative_runner_testability()


@contextmanager
def _verified_control_directory(selector):
    """Do not delete a full-run control root while its child may still be live."""
    if selector != P3_CUMULATIVE274_R1_SELECTOR:
        with tempfile.TemporaryDirectory(prefix="gew-wp08-verified-runner-") as directory:
            yield directory, {}
        return
    directory = tempfile.mkdtemp(prefix="gew-wp08-cumulative274-")
    owned = {}
    try:
        yield directory, owned
    finally:
        primary = sys.exc_info()[1]
        process = owned.get("process")
        if process is None or process.poll() is not None:
            try:
                shutil.rmtree(directory)
            except BaseException as cleanup:
                if primary is not None:
                    raise BaseExceptionGroup("cumulative274 failure and control-root cleanup failure", [primary, cleanup]) from None
                raise
        else:
            # Preserve the root for owner reconciliation if reap itself failed.
            print(json.dumps({"selector": selector, "cleanup": "unreaped-child-root-retained",
                              "control_root": directory}), file=sys.stderr, flush=True)


def _run_verified_selector_in_fresh_child(
    selector: str,
    *,
    timeout_seconds: int,
    heartbeat_interval_seconds: int | None = None,
) -> dict[str, object]:
    """Issue a fresh source attestation and run one exact selector in isolation."""

    from importlib import metadata

    from tests.support.source_checkout_attestation import (
        issue_source_checkout_attestation,
    )

    if selector not in VERIFIED_RUNNER_SELECTORS:
        raise AssertionError("unknown WP08 verified runner selector")
    if metadata.version("packaging") != "26.3":
        raise AssertionError("verified runner requires canonical packaging==26.3")
    with _verified_control_directory(selector) as (directory, owned):
        control = pathlib.Path(directory).resolve(strict=True) / "control"
        issue_source_checkout_attestation(category.ROOT, control)
        control = control.resolve(strict=True)
        environment = dict(os.environ)
        environment.pop("PYTHONHOME", None)
        environment["GEW_INSTALLATION_CONTROL_ROOT"] = os.fspath(control)
        environment["GEW_WP08_VERIFIED_RUNNER_CHILD"] = selector
        environment["PYTHONPATH"] = os.pathsep.join(
            os.fspath(category.ROOT / path)
            for path in ("core", "adapters", "application", "storage", ".")
        )
        if heartbeat_interval_seconds is not None:
            process = subprocess.Popen(
                (
                    sys.executable,
                    "-X", f"gew_installation_control_root={control}",
                    "-m", "tests.support.wp08_release_coverage",
                    "--verified-child", selector,
                ),
                cwd=category.ROOT,
                env=environment,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if selector == P3_CUMULATIVE274_R1_SELECTOR:
                owned["process"] = process
                return _wait_for_c274_child(process, timeout_seconds=timeout_seconds,
                    heartbeat_interval_seconds=heartbeat_interval_seconds)
            return _wait_for_verified_child(
                process,
                selector=selector,
                timeout_seconds=timeout_seconds,
                heartbeat_interval_seconds=heartbeat_interval_seconds,
            )
        try:
            result = subprocess.run(
                (
                    sys.executable,
                    "-X", f"gew_installation_control_root={control}",
                    "-m", "tests.support.wp08_release_coverage",
                    "--verified-child", selector,
                ),
                cwd=category.ROOT,
                env=environment,
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            progress = _stderr_text(error.stderr)[-16384:]
            raise AssertionError(
                f"verified runner child timed out ({selector}): {progress}"
            ) from error
        if result.returncode != 0:
            raise AssertionError(
                f"verified runner child failed ({selector}): "
                f"{result.stderr or result.stdout}"
            )
        try:
            receipt = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise AssertionError("verified runner receipt is not exact JSON") from error
        if type(receipt) is not dict or receipt.get("selector") != selector:
            raise AssertionError("verified runner receipt selector changed")
        return receipt


def run_performance_authority_r2_verified() -> dict[str, object]:
    """Run WP08-PERF-CAND-R2-001 under a fresh attested private root."""

    return _run_verified_selector_in_fresh_child(
        PERFORMANCE_AUTHORITY_R2_SELECTOR, timeout_seconds=3600,
    )


def run_existing_feature_r1_verified() -> dict[str, object]:
    """Run WP08-EXISTING-FEATURE-CAND-R1-001 attacks only."""

    return _run_verified_selector_in_fresh_child(
        EXISTING_FEATURE_R1_SELECTOR, timeout_seconds=600,
    )


def run_reproducible_failure_r1_verified() -> dict[str, object]:
    """Run the bug-fix scenario pair under a fresh attested private root."""

    return _run_verified_selector_in_fresh_child(
        REPRODUCIBLE_FAILURE_R1_SELECTOR, timeout_seconds=600,
    )


def run_false_reproduction_r1_verified() -> dict[str, object]:
    """Run the bug-fix false-reproduction pair under a fresh private root."""

    return _run_verified_selector_in_fresh_child(
        FALSE_REPRODUCTION_R1_SELECTOR, timeout_seconds=600,
    )


def run_regression_boundary_r1_verified() -> dict[str, object]:
    """Run the bug-fix regression-boundary pair under a fresh private root."""

    return _run_verified_selector_in_fresh_child(
        REGRESSION_BOUNDARY_R1_SELECTOR, timeout_seconds=600,
    )


def run_minimal_patch_r1_verified() -> dict[str, object]:
    """Run the hotfix minimal-patch pair under a fresh private root."""

    return _run_verified_selector_in_fresh_child(
        MINIMAL_PATCH_R1_SELECTOR, timeout_seconds=600,
    )


def run_stable_baseline_r1_verified() -> dict[str, object]:
    """Run the performance stable-baseline pair under a fresh private root."""

    return _run_verified_selector_in_fresh_child(
        STABLE_BASELINE_R1_SELECTOR, timeout_seconds=1800,
    )


def run_performance_remaining_r1_verified() -> dict[str, object]:
    """Run the two remaining performance scenario pairs in isolation."""

    return _run_verified_selector_in_fresh_child(
        PERFORMANCE_REMAINING_R1_SELECTOR, timeout_seconds=3600,
    )


def run_p2a_cumulative_r2_verified() -> dict[str, object]:
    """Run the exact P2a cumulative selector in one fresh attested child."""

    testability = _p2a_cumulative_runner_testability()
    receipt = _run_verified_selector_in_fresh_child(
        P2A_CUMULATIVE_R2_SELECTOR,
        timeout_seconds=testability["cumulative_runtime_limit_seconds"],
        heartbeat_interval_seconds=testability["heartbeat_interval_seconds"],
    )
    return _validate_cumulative_receipt(
        receipt, _cumulative_checkpoint(P2A_CUMULATIVE_R2_SELECTOR),
    )


def run_p2b_cumulative_r1_verified() -> dict[str, object]:
    """Run only with separate Human launch authority; entry tests must mock launch."""

    testability = _cumulative_runner_testability()
    receipt = _run_verified_selector_in_fresh_child(
        P2B_CUMULATIVE_R1_SELECTOR,
        timeout_seconds=testability["cumulative_runtime_limit_seconds"],
        heartbeat_interval_seconds=testability["heartbeat_interval_seconds"],
    )
    return _validate_cumulative_receipt(
        receipt, _cumulative_checkpoint(P2B_CUMULATIVE_R1_SELECTOR),
    )


def run_vulnerable_graph_r1_verified() -> dict[str, object]:
    """Run the dependency-security vulnerable-graph pair in isolation."""

    return _run_verified_selector_in_fresh_child(
        VULNERABLE_GRAPH_R1_SELECTOR, timeout_seconds=1800,
    )


def run_migration_scenarios_r1_verified() -> dict[str, object]:
    """Run the four migration scenario pairs under one fresh attested root."""

    return _run_verified_selector_in_fresh_child(
        MIGRATION_SCENARIOS_R1_SELECTOR, timeout_seconds=3600,
    )


def run_dependency_graph_scenarios_r1_verified() -> dict[str, object]:
    """Run the two dependency graph/remediation pairs in isolation."""

    return _run_verified_selector_in_fresh_child(
        DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR, timeout_seconds=1800,
    )


def _verified_runner_main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if (
        len(values) == 2
        and values[0] == "--verified-child"
        and values[1] in VERIFIED_RUNNER_SELECTORS
    ):
        selector = values[1]
        if os.environ.get("GEW_WP08_VERIFIED_RUNNER_CHILD") != selector:
            raise AssertionError("verified runner child handoff is foreign")
        if selector == PERFORMANCE_AUTHORITY_R2_SELECTOR:
            receipt = _run_performance_authority_r2_child()
        elif selector == FALSE_REPRODUCTION_R1_SELECTOR:
            receipt = _run_false_reproduction_r1_child()
        elif selector == REGRESSION_BOUNDARY_R1_SELECTOR:
            receipt = _run_regression_boundary_r1_child()
        elif selector == MINIMAL_PATCH_R1_SELECTOR:
            receipt = _run_minimal_patch_r1_child()
        elif selector == DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR:
            receipt = _run_dependency_graph_scenarios_r1_child()
        elif selector == MIGRATION_SCENARIOS_R1_SELECTOR:
            receipt = _run_migration_scenarios_r1_child()
        elif selector == REPRODUCIBLE_FAILURE_R1_SELECTOR:
            receipt = _run_reproducible_failure_r1_child()
        elif selector == STABLE_BASELINE_R1_SELECTOR:
            receipt = _run_stable_baseline_r1_child()
        elif selector == PERFORMANCE_REMAINING_R1_SELECTOR:
            receipt = _run_performance_remaining_r1_child()
        elif selector == P2A_CUMULATIVE_R2_SELECTOR:
            receipt = _run_p2a_cumulative_r2_child()
        elif selector == P2B_CUMULATIVE_R1_SELECTOR:
            receipt = _run_p2b_cumulative_r1_child()
        elif selector == P3_CUMULATIVE274_R1_SELECTOR:
            receipt = _run_p3_cumulative274_r1_child()
        elif selector == VULNERABLE_GRAPH_R1_SELECTOR:
            receipt = _run_vulnerable_graph_r1_child()
        else:
            receipt = _run_existing_feature_r1_child()
    elif values == [PERFORMANCE_AUTHORITY_R2_SELECTOR]:
        receipt = run_performance_authority_r2_verified()
    elif values == [EXISTING_FEATURE_R1_SELECTOR]:
        receipt = run_existing_feature_r1_verified()
    elif values == [REPRODUCIBLE_FAILURE_R1_SELECTOR]:
        receipt = run_reproducible_failure_r1_verified()
    elif values == [FALSE_REPRODUCTION_R1_SELECTOR]:
        receipt = run_false_reproduction_r1_verified()
    elif values == [REGRESSION_BOUNDARY_R1_SELECTOR]:
        receipt = run_regression_boundary_r1_verified()
    elif values == [MINIMAL_PATCH_R1_SELECTOR]:
        receipt = run_minimal_patch_r1_verified()
    elif values == [DEPENDENCY_GRAPH_SCENARIOS_R1_SELECTOR]:
        receipt = run_dependency_graph_scenarios_r1_verified()
    elif values == [MIGRATION_SCENARIOS_R1_SELECTOR]:
        receipt = run_migration_scenarios_r1_verified()
    elif values == [STABLE_BASELINE_R1_SELECTOR]:
        receipt = run_stable_baseline_r1_verified()
    elif values == [PERFORMANCE_REMAINING_R1_SELECTOR]:
        receipt = run_performance_remaining_r1_verified()
    elif values == [P2A_CUMULATIVE_R2_SELECTOR]:
        receipt = run_p2a_cumulative_r2_verified()
    elif values == [P2B_CUMULATIVE_R1_SELECTOR]:
        receipt = run_p2b_cumulative_r1_verified()
    elif values == [P3_CUMULATIVE274_R1_SELECTOR]:
        receipt = run_p3_cumulative274_r1_verified()
    elif values == [VULNERABLE_GRAPH_R1_SELECTOR]:
        receipt = run_vulnerable_graph_r1_verified()
    else:
        print(
            "usage: python -m tests.support.wp08_release_coverage "
            f"{{{'|'.join(VERIFIED_RUNNER_SELECTORS)}}}",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(receipt, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(_verified_runner_main())
