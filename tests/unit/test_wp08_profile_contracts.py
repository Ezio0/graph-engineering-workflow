"""WP-08 first RED slice: closed Profile contracts and coverage metadata."""

from __future__ import annotations

import copy
import importlib
import json
import os
import pathlib
import tempfile
import sys
import unittest
from collections.abc import Iterator, Mapping


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT))

from graph_engineering.core.contracts.digest import semantic_digest  # noqa: E402
from graph_engineering.core.contracts.registry import ClosedSchemaRegistry  # noqa: E402
from graph_engineering.core.contracts.resources import (  # noqa: E402
    CostSchedule,
    ResourceProfile,
    WorkContext,
)
from graph_engineering.core.contracts.schema import SchemaProfilePolicy  # noqa: E402
from graph_engineering.core.graph.state import (  # noqa: E402
    DomainEvent,
    TaskSnapshot,
    _validate_graph_ref,
    apply_events,
)
from tests.contract.test_wp02_graph import loop_budgets as load_loop_budgets  # noqa: E402
from tests.support.wp08_dependency_security import (  # noqa: E402
    DEPENDENCY_GRAPH_SCHEMA_IDS,
    DEPENDENCY_SECURITY_SCHEMA_IDS,
    assert_dependency_graph_slice_a_positive,
    assert_dependency_graph_slice_a_rejections,
    assert_slice_a_positive,
    assert_slice_a_rejections,
    assert_slice_a_reviewer_repairs,
    assert_slice_a_schema_instances,
)
from tests.support.wp08_migration_rehearsal import (  # noqa: E402
    MIGRATION_REHEARSAL_SCHEMA_IDS,
    assert_migration_rehearsal_schema_instances,
    assert_migration_rehearsal_slice_a_positive,
    assert_migration_rehearsal_slice_a_rejections,
    assert_migration_rehearsal_slice_a_r1_contracts,
)
from tests.support.wp08_performance_benchmark import (  # noqa: E402
    PERFORMANCE_BENCHMARK_SCHEMA_IDS,
    assert_performance_slice_a_positive,
    assert_performance_slice_a_r1_contracts,
    assert_performance_slice_a_rejections,
    assert_performance_slice_a_schema_instances,
)


APPROVED_SPEC_SHA256 = "e632cd2c8b4f13b1455fa1f962491df6603b34d2eef0c46a84b350200e0f8d65"
DIGEST = "sha256-jcs-v1:" + "a" * 64
PROFILE_IDS = (
    "new-feature",
    "bug-fix",
    "hotfix",
    "refactor-debt",
    "migration",
    "dependency-security",
    "performance",
    "release-operations",
    "incident-response",
)
PROFILE_COLUMNS = (
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
RISK_PATH_IDS = ("full-planned", "compact-planned", "emergency")
SCENARIO_IDS = {
    "new-feature": ("scaffold", "existing-feature", "multi-target"),
    "bug-fix": ("reproducible-failure", "false-reproduction", "regression-boundary"),
    "hotfix": ("emergency-baseline", "minimal-patch", "production-like-gate"),
    "refactor-debt": (
        "behavior-characterization",
        "architecture-invariant",
        "nonfunctional-target",
    ),
    "migration": ("forward", "backward", "partial-data", "crash-window"),
    "dependency-security": ("vulnerable-graph", "transitive-dependency", "fix-unavailable"),
    "performance": ("stable-baseline", "noise-outlier", "correctness-regression"),
    "release-operations": ("artifact-provenance", "health-gate", "partial-deploy"),
    "incident-response": ("detection", "containment", "recovery", "unknown-effects"),
}
PROFILE_CASE_IDS = tuple(sorted(
    f"GEW-PRO-{profile.upper()}-{column.upper()}-{outcome}"
    for profile in PROFILE_IDS
    for column in PROFILE_COLUMNS
    for outcome in ("P", "R")
))
SCENARIO_CASE_IDS = tuple(sorted(
    f"GEW-PSC-{profile.upper()}-{scenario.upper()}-{outcome}"
    for profile, scenarios in SCENARIO_IDS.items()
    for scenario in scenarios
    for outcome in ("P", "R")
))
PROFILE_DOMAIN_SCHEMA_IDS = frozenset({
    "urn:gew:schema:approved-profile-body-input:1.0.0",
    "urn:gew:schema:approved-profile-definition-body-input:1.0.0",
    "urn:gew:schema:approved-profile-identity-registry-input:1.0.0",
    "urn:gew:schema:approved-profile-identity-registry:1.0.0",
    "urn:gew:schema:approved-risk-overlay-body-input:1.0.0",
    "urn:gew:schema:category-completion-assessment-input:1.0.0",
    "urn:gew:schema:category-completion-assessment:1.0.0",
    "urn:gew:schema:category-completion-assessment-input:1.1.0",
    "urn:gew:schema:category-completion-assessment:1.1.0",
    "urn:gew:schema:category-execution-policy-input:1.0.0",
    "urn:gew:schema:category-execution-policy:1.0.0",
    "urn:gew:schema:category-execution-state-input:1.0.0",
    "urn:gew:schema:category-execution-state:1.0.0",
    "urn:gew:schema:category-rollback-assessment-input:1.0.0",
    "urn:gew:schema:category-rollback-assessment:1.0.0",
    "urn:gew:schema:category-target-observation-input:1.0.0",
    "urn:gew:schema:category-target-observation:1.0.0",
    "urn:gew:schema:coverage-record-input:1.0.0",
    "urn:gew:schema:coverage-record:1.0.0",
    "urn:gew:schema:evidence-observation-input:1.0.0",
    "urn:gew:schema:materialization-record-input:1.0.0",
    "urn:gew:schema:materialization-record:1.0.0",
    "urn:gew:schema:profile-coverage-assessment-reference:1.0.0",
    "urn:gew:schema:profile-coverage-execution-plan-input:1.0.0",
    "urn:gew:schema:profile-coverage-execution-record:1.0.0",
    "urn:gew:schema:profile-coverage-observation:1.0.0",
    "urn:gew:schema:profile-coverage-oracle-input:1.0.0",
    "urn:gew:schema:profile-coverage-plan-selector:1.0.0",
    "urn:gew:schema:profile-coverage-policy-input:1.0.0",
    "urn:gew:schema:profile-coverage-policy:1.0.0",
    "urn:gew:schema:profile-coverage-request:1.0.0",
    "urn:gew:schema:profile-coverage-task-state:1.0.0",
    "urn:gew:schema:profile-definition-input:1.0.0",
    "urn:gew:schema:profile-definition:1.0.0",
    "urn:gew:schema:profile-evidence-observation-registry-input:1.0.0",
    "urn:gew:schema:profile-evidence-observation-registry:1.0.0",
    "urn:gew:schema:profile-materialization-input:1.0.0",
    "urn:gew:schema:profile-real-e2e-binding-registry-input:1.0.0",
    "urn:gew:schema:profile-real-e2e-predecessor-record:1.0.0",
    "urn:gew:schema:profile-semantic-policy-input:1.0.0",
    "urn:gew:schema:profile-semantic-policy:1.0.0",
    "urn:gew:schema:project-profile-configuration-input:1.0.0",
    "urn:gew:schema:project-tightening-policy-input:1.0.0",
    "urn:gew:schema:project-tightening-policy:1.0.0",
    "urn:gew:schema:release-coverage-assessment:1.0.0",
    "urn:gew:schema:risk-overlay-definition-input:1.0.0",
    "urn:gew:schema:risk-overlay-definition:1.0.0",
    "urn:gew:schema:support-matrix-definition-input:1.0.0",
    "urn:gew:schema:support-matrix-definition:1.0.0",
}) | frozenset(DEPENDENCY_SECURITY_SCHEMA_IDS) | frozenset(DEPENDENCY_GRAPH_SCHEMA_IDS) | frozenset(PERFORMANCE_BENCHMARK_SCHEMA_IDS) | frozenset(MIGRATION_REHEARSAL_SCHEMA_IDS)


class _DuplicateKeyMapping(Mapping[str, object]):
    """Mapping-shaped adversarial input whose iteration preserves duplicate keys."""

    def __init__(self, pairs: tuple[tuple[str, object], ...]) -> None:
        self._pairs = pairs

    def __getitem__(self, key: str) -> object:
        return next(value for candidate, value in reversed(self._pairs) if candidate == key)

    def __iter__(self) -> Iterator[str]:
        return (key for key, _value in self._pairs)

    def __len__(self) -> int:
        return len(self._pairs)


def _profile_api():  # type: ignore[no-untyped-def]
    """Load the production API inside each case so every missing contract is visible in RED."""

    return importlib.import_module("graph_engineering.core.profiles")


def _complete(body: dict[str, object], name: str, field: str) -> dict[str, object]:
    document = copy.deepcopy(body)
    document[field] = semantic_digest(
        body,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )
    return document


def _approved_registry_document() -> dict[str, object]:
    return json.loads(
        (ROOT / "config/profiles/approved-profile-identities-v1.json").read_text(
            encoding="utf-8"
        )
    )


def _coverage_policy_document() -> dict[str, object]:
    return json.loads(
        (ROOT / "config/profiles/profile-coverage-policy-v1.json").read_text(
            encoding="utf-8"
        )
    )


def _semantic_policy_document() -> dict[str, object]:
    return json.loads(
        (ROOT / "config/profiles/profile-semantic-policy-v1.json").read_text(
            encoding="utf-8"
        )
    )


def _evidence_registry_document() -> dict[str, object]:
    return json.loads(
        (ROOT / "config/profiles/profile-evidence-observation-registry-v1.json").read_text(
            encoding="utf-8"
        )
    )


def _oracle_manifest_bytes() -> bytes:
    return (ROOT / "config/release-coverage/oracle-manifest-v1.json").read_bytes()


def _profile_document() -> dict[str, object]:
    required_cases = sorted(
        case_id for case_id in (*PROFILE_CASE_IDS, *SCENARIO_CASE_IDS)
        if "-NEW-FEATURE-" in case_id
    )
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "profile_id": "new-feature",
        "version": "1.0.0",
        "approved_profile_registry_digest": _approved_registry_document()["registry_digest"],
        "coverage_policy_digest": _coverage_policy_document()["policy_digest"],
        "profile_semantic_policy_digest": _semantic_policy_document()["policy_digest"],
        "required_node_ids": [
            "candidate-review",
            "completion-gate",
            "implementation",
            "project-discovery",
            "regression-verification",
            "target-acceptance",
            "target-verification",
        ],
        "optional_node_ids": [],
        "required_edge_ids": [
            "candidate-review-to-completion-gate",
            "implementation-to-regression-verification",
            "project-discovery-to-target-acceptance",
            "regression-verification-to-candidate-review",
            "target-acceptance-to-implementation",
            "target-verification-to-completion-gate",
        ],
        "optional_edge_ids": [],
        "route_overrides": [],
        "artifact_contract_ids": [
            "urn:gew:artifact-contract:candidate-review:1.0.0",
            "urn:gew:artifact-contract:completion-record:1.0.0",
            "urn:gew:artifact-contract:impact:1.0.0",
            "urn:gew:artifact-contract:implementation:1.0.0",
            "urn:gew:artifact-contract:plan:1.0.0",
            "urn:gew:artifact-contract:prd:1.0.0",
            "urn:gew:artifact-contract:tech-spec:1.0.0",
            "urn:gew:artifact-contract:test-plan:1.0.0",
            "urn:gew:artifact-contract:verification:1.0.0",
        ],
        "validator_ids": [
            "new-feature-acceptance",
            "new-feature-regression",
            "new-feature-target-realization",
        ],
        "completion_predicate_ids": [
            "all-required-nodes-passed",
            "independent-candidate-review-passed",
            "project-gates-passed",
            "target-state-matched",
        ],
        "compatible_risk_paths": list(RISK_PATH_IDS),
        "rollback_contract": {
            "eligible_action_kinds": ["profile-change-rollback"],
            "precondition_ids": ["current-target-matches-receipt"],
            "compensation_graph_ref": "graph:new-feature-compensation:1.0.0",
            "authority_requirement": "action-scoped-rollback",
            "verification_ids": ["restored-target-state"],
            "rollback_not_possible": "route-owner-with-residual-state",
        },
        "required_case_ids": required_cases,
        "category_boundary_case_ids": [
            "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE-P",
            "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE-R",
            "GEW-PSC-NEW-FEATURE-MULTI-TARGET-P",
            "GEW-PSC-NEW-FEATURE-MULTI-TARGET-R",
            "GEW-PSC-NEW-FEATURE-SCAFFOLD-P",
            "GEW-PSC-NEW-FEATURE-SCAFFOLD-R",
        ],
        "real_e2e_requirement_id": "GEW-PRO-NEW-FEATURE-REAL-E2E-P",
        "required_capabilities": ["project-read", "target-observe"],
        "unsupported_integrations": [],
        "evidence_policy": {
            "owner_gate": "WP-08",
            "required_oracle_ids": ["ORA-PROFILE-NEW-FEATURE"],
        },
    }
    return _complete(body, "profile-definition", "digest")


def _overlay_document() -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "overlay_id": "full-planned",
        "version": "1.0.0",
        "approved_profile_registry_digest": _approved_registry_document()["registry_digest"],
        "coverage_policy_digest": _coverage_policy_document()["policy_digest"],
        "node_additions": [],
        "edge_additions": [],
        "merge_rules": [],
        "artifact_compaction_mapping": [],
        "budget_policy": {"mode": "preserve", "overrides": []},
        "required_invariant_ids": [
            "authority",
            "completion",
            "digest",
            "finite-budget",
            "independent-review",
            "invalidation",
            "replay-protection",
            "schema",
        ],
        "entry_condition_ids": ["approved-intent-baseline"],
        "exit_condition_ids": ["trustworthy-completion"],
        "allowed_profile_ids": list(PROFILE_IDS),
        "forbidden_profile_ids": [],
    }
    return _complete(body, "risk-overlay-definition", "digest")


def _case_binding(test_id: str) -> dict[str, object]:
    profiles = tuple(
        profile for profile in PROFILE_IDS
        if f"-{profile.upper()}-" in test_id
    )
    profile = profiles[0] if len(profiles) == 1 else "unknown"
    return {
        "test_id": test_id,
        "fixture_id": f"profile:{profile}:1.0.0",
        "oracle_id": f"ORA-PROFILE-{profile.upper()}",
        "evidence_type": "coverage-record",
        "owner_gate": "WP-08",
    }


def _support_matrix_document() -> dict[str, object]:
    bindings = [_case_binding(test_id) for test_id in (*PROFILE_CASE_IDS, *SCENARIO_CASE_IDS)]
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "matrix_id": "urn:gew:support-matrix:profiles:v1",
        "version": "1.0.0",
        "approved_profile_registry_digest": _approved_registry_document()["registry_digest"],
        "coverage_policy_digest": _coverage_policy_document()["policy_digest"],
        "profile_ids": list(PROFILE_IDS),
        "profile_column_ids": list(PROFILE_COLUMNS),
        "risk_path_ids": list(RISK_PATH_IDS),
        "profile_case_ids": list(PROFILE_CASE_IDS),
        "scenario_case_ids": list(SCENARIO_CASE_IDS),
        "case_bindings": bindings,
    }
    return _complete(body, "support-matrix-definition", "digest")


def _resign_matrix(document: dict[str, object]) -> None:
    document.pop("digest", None)
    document["digest"] = semantic_digest(
        document,
        contract_type="urn:gew:contract:support-matrix-definition",
        projection_id="urn:gew:digest-projection:support-matrix-definition:1.0.0",
        schema_id="urn:gew:schema:support-matrix-definition-input:1.0.0",
    )


def _resign(document: dict[str, object], name: str, field: str) -> None:
    document.pop(field, None)
    document[field] = semantic_digest(
        document,
        contract_type=f"urn:gew:contract:{name}",
        projection_id=f"urn:gew:digest-projection:{name}:1.0.0",
        schema_id=f"urn:gew:schema:{name}-input:1.0.0",
    )


def _approved_registry():  # type: ignore[no-untyped-def]
    return _profile_api().ApprovedProfileIdentityRegistry.from_dict(
        _approved_registry_document(),
        expected_registry_digest=_approved_registry_document()["registry_digest"],
    )


def _coverage_policy():  # type: ignore[no-untyped-def]
    return _profile_api().ProfileCoveragePolicy.from_dict(
        _coverage_policy_document(),
        approved_profiles=_approved_registry(),
        expected_policy_digest=_coverage_policy_document()["policy_digest"],
    )


def _semantic_policy():  # type: ignore[no-untyped-def]
    return _profile_api().ProfileSemanticPolicy.from_dict(
        _semantic_policy_document(),
        approved_profiles=_approved_registry(),
        coverage_policy=_coverage_policy(),
        loop_budgets=_loop_budget_registry(),
        expected_policy_digest=_semantic_policy_document()["policy_digest"],
    )


def _loop_budget_registry():  # type: ignore[no-untyped-def]
    schemas, context = _graph_contracts()
    return load_loop_budgets(schemas=schemas, context=context)


def _graph_contracts() -> tuple[ClosedSchemaRegistry, WorkContext]:
    schema_root = ROOT / "config/contracts/schemas"
    filenames = (
        "completion-policy-1.0.0.json",
        "completion-policy-registry-1.0.0.json",
        "graph-definition-1.0.0.json",
        "graph-definition-digest-input-1.0.0.json",
        "loop-budget-1.0.0.json",
        "loop-budget-registry-1.0.0.json",
        "node-payload-1.0.0.json",
        "task-snapshot-1.0.0.json",
        "task-snapshot-digest-input-1.0.0.json",
    )
    schema_bodies = {
        json.loads((schema_root / filename).read_text(encoding="utf-8"))["$id"]:
            (schema_root / filename).read_bytes()
        for filename in filenames
    }
    resource_profile = ResourceProfile.from_dict(json.loads(
        (ROOT / "config/contracts/resource-profile-v1.json").read_text(encoding="utf-8")
    ))
    cost_schedule = CostSchedule.from_dict(json.loads(
        (ROOT / "config/contracts/cost-schedule-v1.json").read_text(encoding="utf-8")
    ))
    schema_policy = SchemaProfilePolicy.from_dict(json.loads(
        (ROOT / "config/contracts/schema-profile-v1.json").read_text(encoding="utf-8")
    ))
    manifest = json.loads(
        (ROOT / "config/contracts/graph-schema-registry-v1.json").read_text(encoding="utf-8")
    )
    registry = ClosedSchemaRegistry.build(
        manifest, schema_bodies, resource_profile, schema_policy,
    )
    return registry, WorkContext(resource_profile, cost_schedule)


def _snapshot_events(graph_ref: Mapping[str, object]) -> tuple[DomainEvent, ...]:
    return (
        DomainEvent(1, 0, "task.created", {
            "identity": {
                "task_id": "task-wp08-profile-roundtrip",
                "owner_id": "owner-wp08",
                "runtime_kind": "codex",
                "runtime_lineage_id": "core-profile-materializer-v1",
            },
        }),
        DomainEvent(2, 1, "project.scope_drafted", {
            "project_scope_ref": {
                "scope_id": "scope-wp08", "version": 1,
                "digest": "scope-digest-wp08", "status": "drafted",
            },
        }),
        DomainEvent(3, 2, "task.prd_approval_requested", {
            "prd_candidate_ref": "artifact:prd-wp08",
        }),
        DomainEvent(4, 3, "project.scope_frozen", {
            "project_scope_ref": {
                "scope_id": "scope-wp08", "version": 1,
                "digest": "scope-digest-wp08", "status": "frozen",
            },
        }),
        DomainEvent(5, 4, "task.prd_approved", {
            "baseline_refs": [{
                "kind": "intent", "version": 1, "digest": "baseline-wp08",
                "approved_by": "owner-wp08", "approved_at": "2026-08-23T00:00:00Z",
            }],
            "graph_ref": graph_ref,
            "authority_refs": ["authority:wp08-profile"],
            "owner_decision_ref": "decision:wp08-profile",
        }),
    )


def _coverage_evidence(
    test_id: str,
    *,
    matrix: object,
    profile: object,
    overlay: object,
) -> dict[str, object]:
    binding = _case_binding(test_id)
    return {
        "schema_version": "1.0.0",
        "test_id": test_id,
        "status": "PASS",
        "fixture_id": binding["fixture_id"],
        "oracle_id": binding["oracle_id"],
        "evidence_type": binding["evidence_type"],
        "owner_gate": binding["owner_gate"],
        "evidence_ref": f"evidence:{test_id.lower()}",
        "evidence_digest": DIGEST,
        "resolved": True,
        "matrix_digest": matrix.digest,
        "profile_id": profile.profile_id,
        "profile_version": profile.version,
        "profile_digest": profile.digest,
        "overlay_id": overlay.overlay_id,
        "overlay_version": overlay.version,
        "overlay_digest": overlay.digest,
        "runtime_kind": "platform-neutral",
        "runtime_lineage_id": "core-profile-materializer-v1",
        "runtime_digest": "sha256-jcs-v1:" + "b" * 64,
        "execution_kind": "contract-test",
    }


class WP08ProfileContractTests(unittest.TestCase):
    maxDiff = None

    def test_gew_req_fr14_p_closed_registry_profile_and_overlay_are_digest_bound(self) -> None:
        api = _profile_api()
        schema_manifest = json.loads(
            (ROOT / "config/contracts/profile-schema-registry-v1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            {item["schema_id"] for item in schema_manifest["resources"]},
            PROFILE_DOMAIN_SCHEMA_IDS,
        )
        self.assertEqual(tuple(api.PROFILE_DOMAIN_SCHEMA_IDS), tuple(sorted(
            PROFILE_DOMAIN_SCHEMA_IDS,
        )))
        expected_owned_files = {
            schema_id.removeprefix("urn:gew:schema:").replace(":", "-") + ".json"
            for schema_id in PROFILE_DOMAIN_SCHEMA_IDS
        }
        self.assertEqual(
            {
                path.name for path in (ROOT / "config/contracts/schemas").iterdir()
                if path.name in expected_owned_files
            },
            expected_owned_files,
        )
        schema_bodies: dict[str, bytes] = {}
        for resource in schema_manifest["resources"]:
            filename = resource["schema_id"].removeprefix("urn:gew:schema:").replace(":", "-")
            schema_bodies[resource["schema_id"]] = (
                ROOT / "config/contracts/schemas" / f"{filename}.json"
            ).read_bytes()
        profile_schema_registry = api.build_profile_schema_registry(
            schema_manifest,
            schema_bodies,
            ResourceProfile.from_dict(json.loads(
                (ROOT / "config/contracts/resource-profile-v1.json").read_text(encoding="utf-8")
            )),
            SchemaProfilePolicy.from_dict(json.loads(
                (ROOT / "config/contracts/schema-profile-v1.json").read_text(encoding="utf-8")
            )),
        )
        resource_profile = ResourceProfile.from_dict(json.loads(
            (ROOT / "config/contracts/resource-profile-v1.json").read_text(encoding="utf-8")
        ))
        cost_schedule = CostSchedule.from_dict(json.loads(
            (ROOT / "config/contracts/cost-schedule-v1.json").read_text(encoding="utf-8")
        ))
        assert_slice_a_schema_instances(
            self,
            profile_schema_registry,
            lambda: WorkContext(resource_profile, cost_schedule),
        )
        assert_migration_rehearsal_schema_instances(
            self,
            profile_schema_registry,
            lambda: WorkContext(resource_profile, cost_schedule),
        )
        assert_performance_slice_a_schema_instances(
            self,
            profile_schema_registry,
            lambda: WorkContext(resource_profile, cost_schedule),
        )
        registry = api.ApprovedProfileIdentityRegistry.from_dict(
            _approved_registry_document(),
            expected_registry_digest=_approved_registry_document()["registry_digest"],
        )
        self.assertEqual(registry.profile_ids, PROFILE_IDS)
        profile = api.ProfileDefinition.from_dict(
            _profile_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(), semantic_policy=_semantic_policy(),
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            _overlay_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(),
        )
        self.assertEqual((profile.profile_id, overlay.overlay_id), ("new-feature", "full-planned"))
        semantic_policy = _semantic_policy()
        self.assertEqual(tuple(semantic_policy.profiles), PROFILE_IDS)
        self.assertEqual(
            semantic_policy.core_invariant_ids,
            tuple(_coverage_policy_document()["required_invariant_ids"]),
        )
        assert_slice_a_positive(self)
        assert_dependency_graph_slice_a_positive(
            self,
            profile_schema_registry,
            lambda: WorkContext(resource_profile, cost_schedule),
        )
        assert_migration_rehearsal_slice_a_positive(self)
        assert_performance_slice_a_positive(
            self,
            profile_schema_registry,
            lambda: WorkContext(resource_profile, cost_schedule),
        )

    def test_gew_req_fr14_r_alias_extra_missing_and_digest_mutations_are_rejected(self) -> None:
        assert_migration_rehearsal_slice_a_rejections(self)
        assert_migration_rehearsal_slice_a_r1_contracts(self)
        assert_slice_a_reviewer_repairs(self)
        assert_slice_a_rejections(self)
        assert_dependency_graph_slice_a_rejections(self)
        assert_performance_slice_a_rejections(self)
        assert_performance_slice_a_r1_contracts(self)
        api = _profile_api()
        registry_mutations: list[dict[str, object]] = []
        for mutate in (
            lambda ids: ids.__setitem__(0, "feature"),
            lambda ids: ids.pop(),
            lambda ids: ids.append("unknown-profile"),
            lambda ids: ids.append(ids[0]),
        ):
            candidate = _approved_registry_document()
            ids = candidate["profile_ids"]
            self.assertIsInstance(ids, list)
            mutate(ids)  # type: ignore[arg-type]
            candidate.pop("registry_digest")
            candidate["registry_digest"] = semantic_digest(
                candidate,
                contract_type="urn:gew:contract:approved-profile-identity-registry",
                projection_id="urn:gew:digest-projection:approved-profile-identity-registry:1.0.0",
                schema_id="urn:gew:schema:approved-profile-identity-registry-input:1.0.0",
            )
            registry_mutations.append(candidate)
        stale = _approved_registry_document()
        stale["registry_digest"] = DIGEST
        registry_mutations.append(stale)
        for candidate in registry_mutations:
            with self.subTest(profile_ids=candidate["profile_ids"]):
                with self.assertRaises(ValueError):
                    api.ApprovedProfileIdentityRegistry.from_dict(
                        candidate,
                        expected_registry_digest=_approved_registry_document()["registry_digest"],
                    )

        registry = _approved_registry()
        for source, factory, extra_arguments in (
            (_profile_document(), api.ProfileDefinition, {"semantic_policy": _semantic_policy()}),
            (_overlay_document(), api.RiskOverlayDefinition, {}),
        ):
            extra = copy.deepcopy(source)
            extra["unknown"] = True
            with self.subTest(factory=factory.__name__):
                with self.assertRaises(ValueError):
                    factory.from_dict(
                        extra, approved_profiles=registry,
                        coverage_policy=_coverage_policy(),
                        **extra_arguments,
                    )

        profile_mutations: list[tuple[str, dict[str, object]]] = []
        for field, member in (
            ("required_node_ids", "implementation"),
            ("validator_ids", "new-feature-acceptance"),
            ("completion_predicate_ids", "all-required-nodes-passed"),
            ("required_node_ids", "target-verification"),
        ):
            candidate = _profile_document()
            candidate[field].remove(member)  # type: ignore[union-attr]
            _resign(candidate, "profile-definition", "digest")
            profile_mutations.append((f"{field}:{member}", candidate))
        rollback_weakened = _profile_document()
        rollback_weakened["rollback_contract"]["verification_ids"].remove(  # type: ignore[index]
            "restored-target-state"
        )
        _resign(rollback_weakened, "profile-definition", "digest")
        profile_mutations.append(("rollback-verification", rollback_weakened))
        for label, candidate in profile_mutations:
            issued: list[object] = []
            before = copy.deepcopy(candidate)
            with self.subTest(semantic_weakening=label), self.assertRaises(ValueError):
                issued.append(api.ProfileDefinition.from_dict(
                    candidate,
                    approved_profiles=registry,
                    coverage_policy=_coverage_policy(),
                    semantic_policy=_semantic_policy(),
                ))
            self.assertEqual(issued, [])
            self.assertEqual(candidate, before)

        weakened_semantics = _semantic_policy_document()
        weakened_semantics["core_invariant_ids"].remove("authority")  # type: ignore[union-attr]
        _resign(weakened_semantics, "profile-semantic-policy", "policy_digest")
        with self.assertRaises(ValueError):
            api.ProfileSemanticPolicy.from_dict(
                weakened_semantics,
                approved_profiles=registry,
                coverage_policy=_coverage_policy(),
                loop_budgets=_loop_budget_registry(),
                expected_policy_digest=_semantic_policy_document()["policy_digest"],
            )

        schema_manifest = json.loads(
            (ROOT / "config/contracts/profile-schema-registry-v1.json").read_text(
                encoding="utf-8"
            )
        )
        schema_root = ROOT / "config/contracts/schemas"
        complete_bodies = {
            schema_id: (
                schema_root
                / f"{schema_id.removeprefix('urn:gew:schema:').replace(':', '-')}.json"
            ).read_bytes()
            for schema_id in PROFILE_DOMAIN_SCHEMA_IDS
        }
        profile_resource = ResourceProfile.from_dict(json.loads(
            (ROOT / "config/contracts/resource-profile-v1.json").read_text(
                encoding="utf-8"
            )
        ))
        profile_policy = SchemaProfilePolicy.from_dict(json.loads(
            (ROOT / "config/contracts/schema-profile-v1.json").read_text(
                encoding="utf-8"
            )
        ))
        registry_mutations: list[tuple[str, dict[str, object], dict[str, bytes]]] = []
        missing = copy.deepcopy(schema_manifest)
        missing["resources"].pop()
        registry_mutations.append(("missing", missing, complete_bodies))
        duplicate = copy.deepcopy(schema_manifest)
        duplicate["resources"].append(copy.deepcopy(duplicate["resources"][0]))
        registry_mutations.append(("duplicate", duplicate, complete_bodies))
        stale = copy.deepcopy(schema_manifest)
        stale["resources"][0]["body_digest"] = "sha256-raw-v1:" + "0" * 64
        registry_mutations.append(("stale", stale, complete_bodies))
        extra = copy.deepcopy(schema_manifest)
        extra["resources"].append({
            "schema_id": "urn:gew:schema:unknown-profile-domain:1.0.0",
            "body_digest": "sha256-raw-v1:" + "0" * 64,
        })
        registry_mutations.append((
            "extra", extra,
            {**complete_bodies, "urn:gew:schema:unknown-profile-domain:1.0.0": b"{}"},
        ))
        for label, manifest, bodies in registry_mutations:
            manifest["registry_digest"] = semantic_digest(
                {key: value for key, value in manifest.items() if key != "registry_digest"},
                contract_type="urn:gew:contract:schema-registry",
                projection_id="urn:gew:digest-projection:schema-registry:1.0.0",
                schema_id="urn:gew:schema:schema-registry:1.0.0",
            )
            before = copy.deepcopy(manifest)
            with self.subTest(profile_schema_closure=label), self.assertRaises(ValueError):
                api.build_profile_schema_registry(
                    manifest, bodies, profile_resource, profile_policy,
                )
            self.assertEqual(manifest, before)

    def test_gew_cov_001_exact_216_profile_and_58_scenario_bindings_are_accepted(self) -> None:
        api = _profile_api()
        matrix = api.SupportMatrixDefinition.from_dict(
            _support_matrix_document(), approved_profiles=_approved_registry(),
            coverage_policy=_coverage_policy(),
        )
        self.assertEqual(len(matrix.profile_case_ids), 216)
        self.assertEqual(len(matrix.scenario_case_ids), 58)
        self.assertEqual(set(matrix.profile_case_ids), set(PROFILE_CASE_IDS))
        self.assertEqual(set(matrix.scenario_case_ids), set(SCENARIO_CASE_IDS))

    def test_gew_cov_002_deleting_any_profile_or_scenario_cell_is_rejected(self) -> None:
        api = _profile_api()
        for field in ("profile_case_ids", "scenario_case_ids"):
            candidate = _support_matrix_document()
            removed = candidate[field].pop()  # type: ignore[union-attr]
            candidate["case_bindings"] = [
                item for item in candidate["case_bindings"]  # type: ignore[union-attr]
                if item["test_id"] != removed
            ]
            _resign_matrix(candidate)
            with self.subTest(field=field, removed=removed):
                with self.assertRaises(ValueError):
                    api.SupportMatrixDefinition.from_dict(
                        candidate, approved_profiles=_approved_registry(),
                        coverage_policy=_coverage_policy(),
                    )

    def test_gew_cov_003_deleting_either_pass_or_reject_member_is_rejected(self) -> None:
        api = _profile_api()
        candidate = _support_matrix_document()
        rejected = "GEW-PRO-NEW-FEATURE-NORMAL-R"
        candidate["profile_case_ids"].remove(rejected)  # type: ignore[union-attr]
        candidate["case_bindings"] = [
            item for item in candidate["case_bindings"]  # type: ignore[union-attr]
            if item["test_id"] != rejected
        ]
        _resign_matrix(candidate)
        with self.assertRaises(ValueError):
            api.SupportMatrixDefinition.from_dict(
                candidate, approved_profiles=_approved_registry(),
                coverage_policy=_coverage_policy(),
            )

    def test_gew_cov_004_empty_fixture_oracle_evidence_or_owner_is_rejected(self) -> None:
        api = _profile_api()
        for field in ("fixture_id", "oracle_id", "evidence_type", "owner_gate"):
            for replacement in ("", f"wrong-{field}"):
                candidate = _support_matrix_document()
                candidate["case_bindings"][0][field] = replacement  # type: ignore[index]
                _resign_matrix(candidate)
                before = copy.deepcopy(candidate)
                with self.subTest(field=field, replacement=replacement):
                    with self.assertRaises(ValueError):
                        api.SupportMatrixDefinition.from_dict(
                            candidate, approved_profiles=_approved_registry(),
                            coverage_policy=_coverage_policy(),
                        )
                    self.assertEqual(candidate, before)

    def test_gew_cov_005_duplicate_placeholder_range_and_unknown_members_are_rejected(self) -> None:
        api = _profile_api()
        mutations: list[dict[str, object]] = []
        duplicate = _support_matrix_document()
        duplicate["case_bindings"].append(copy.deepcopy(duplicate["case_bindings"][0]))  # type: ignore[union-attr,index]
        mutations.append(duplicate)
        for injected in (
            "GEW-PRO-<PROFILE>-<COLUMN>-P",
            "GEW-PRO-NEW-FEATURE-NORMAL-P..R",
            "GEW-PRO-UNKNOWN-NORMAL-P",
        ):
            candidate = _support_matrix_document()
            candidate["profile_case_ids"].append(injected)  # type: ignore[union-attr]
            candidate["case_bindings"].append(_case_binding(injected))  # type: ignore[union-attr]
            mutations.append(candidate)
        for candidate in mutations:
            _resign_matrix(candidate)
            with self.subTest(last=candidate["case_bindings"][-1]):  # type: ignore[index]
                with self.assertRaises(ValueError):
                    api.SupportMatrixDefinition.from_dict(
                        candidate, approved_profiles=_approved_registry(),
                        coverage_policy=_coverage_policy(),
                    )
        matrix_json = json.dumps(_support_matrix_document(), separators=(",", ":"))
        duplicate_key_json = matrix_json.replace(
            '"matrix_id":', '"matrix_id":"urn:gew:substituted", "matrix_id":', 1,
        )
        with self.assertRaises(ValueError):
            api.SupportMatrixDefinition.from_json(
                duplicate_key_json,
                approved_profiles=_approved_registry(),
                coverage_policy=_coverage_policy(),
            )

    def test_gew_pro_new_feature_normal_p_materialization_binds_every_input_digest(self) -> None:
        api = _profile_api()
        registry = _approved_registry()
        profile = api.ProfileDefinition.from_dict(
            _profile_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(), semantic_policy=_semantic_policy(),
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            _overlay_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(),
        )
        support_matrix = api.SupportMatrixDefinition.from_dict(
            _support_matrix_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(),
        )
        materialized = api.ProfileMaterializer.materialize(
            base_graph_document={
                "graph_id": "base-delivery",
                "graph_version": "1.0.0",
                "graph_digest": DIGEST,
                "node_ids": list(profile.required_node_ids),
                "edge_ids": list(profile.required_edge_ids),
            },
            profile=profile,
            overlay=overlay,
            project_config={},
            approved_profiles=registry,
            support_matrix=support_matrix,
            semantic_policy=_semantic_policy(),
        )
        expected_pins = {
            "base_graph_digest",
            "profile_digest",
            "overlay_digest",
            "project_config_digest",
            "support_matrix_digest",
            "materialization_digest",
        }
        self.assertEqual(set(materialized.digest_pins), expected_pins)
        self.assertEqual(materialized.profile_id, "new-feature")
        self.assertEqual(materialized.overlay_id, "full-planned")
        self.assertIs(type(materialized.record), api.MaterializationRecord)
        self.assertRegex(materialized.record.object_digest, r"\Asha256:[0-9a-f]{64}\Z")

        tightened_document = _profile_document()
        tightened_document["required_node_ids"].append("security-verification")  # type: ignore[union-attr]
        tightened_document["required_node_ids"].sort()  # type: ignore[union-attr]
        tightened_document["validator_ids"].append("security-tightening")  # type: ignore[union-attr]
        tightened_document["validator_ids"].sort()  # type: ignore[union-attr]
        tightened_document["completion_predicate_ids"].append(  # type: ignore[union-attr]
            "security-tightening-passed"
        )
        tightened_document["completion_predicate_ids"].sort()  # type: ignore[union-attr]
        _resign(tightened_document, "profile-definition", "digest")
        tightened = api.ProfileDefinition.from_dict(
            tightened_document,
            approved_profiles=registry,
            coverage_policy=_coverage_policy(),
            semantic_policy=_semantic_policy(),
        )
        tightened_results: list[object] = []
        with self.assertRaises(ValueError):
            tightened_results.append(api.ProfileMaterializer.materialize(
                base_graph_document={
                    "graph_id": "base-delivery",
                    "graph_version": "1.0.0",
                    "graph_digest": DIGEST,
                    "node_ids": list(tightened.required_node_ids),
                    "edge_ids": list(tightened.required_edge_ids),
                },
                profile=tightened,
                overlay=overlay,
                project_config={},
                approved_profiles=registry,
                support_matrix=support_matrix,
                semantic_policy=_semantic_policy(),
            ))
        self.assertEqual(tightened_results, [])

        graph_ref = materialized.graph_ref()
        self.assertEqual(
            _validate_graph_ref(graph_ref, materialization_record=materialized.record),
            graph_ref,
        )

        schema_registry, work_context = _graph_contracts()
        events = _snapshot_events(graph_ref)
        snapshot = apply_events(
            None, events, schema_registry=schema_registry, context=work_context,
            materialization_record=materialized.record,
        )
        serialized = snapshot.to_dict()
        restored = TaskSnapshot.from_dict(
            serialized, schema_registry=schema_registry, context=work_context,
            materialization_record=materialized.record,
        )
        replayed = apply_events(
            None, events, schema_registry=schema_registry, context=work_context,
            materialization_record=materialized.record,
        )
        self.assertEqual(restored, snapshot)
        self.assertEqual(replayed, snapshot)
        self.assertEqual(dict(restored.graph_ref), dict(graph_ref))
        self.assertEqual(restored.snapshot_digest, snapshot.snapshot_digest)
        for field in (
            "graph_digest", "profile_digest", "overlay_digest",
            "project_config_digest", "support_matrix_digest", "materialization_digest",
        ):
            self.assertEqual(restored.graph_ref[field], graph_ref[field])

    def test_gew_pro_new_feature_normal_r_substitution_and_weakening_emit_no_result(self) -> None:
        api = _profile_api()
        registry = _approved_registry()
        profile = api.ProfileDefinition.from_dict(
            _profile_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(), semantic_policy=_semantic_policy(),
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            _overlay_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(),
        )
        support_matrix = api.SupportMatrixDefinition.from_dict(
            _support_matrix_document(), approved_profiles=registry,
            coverage_policy=_coverage_policy(),
        )
        weakened_overlay = _overlay_document()
        weakened_overlay["required_invariant_ids"].remove("authority")  # type: ignore[union-attr]
        weakened_overlay.pop("digest")
        weakened_overlay["digest"] = semantic_digest(
            weakened_overlay,
            contract_type="urn:gew:contract:risk-overlay-definition",
            projection_id="urn:gew:digest-projection:risk-overlay-definition:1.0.0",
            schema_id="urn:gew:schema:risk-overlay-definition-input:1.0.0",
        )
        issued: list[object] = []
        with self.assertRaises(ValueError):
            issued.append(api.RiskOverlayDefinition.from_dict(
                weakened_overlay,
                approved_profiles=registry,
                coverage_policy=_coverage_policy(),
            ))
        self.assertEqual(issued, [])
        for project_config in (
            {"remove_required_node_ids": ["target-verification"]},
            {"disable_invariant_ids": ["authority"]},
            {"risk_path": "unknown"},
        ):
            issued = []
            with self.subTest(project_config=project_config):
                with self.assertRaises(ValueError):
                    issued.append(api.ProfileMaterializer.materialize(
                        base_graph_document={
                            "graph_id": "base-delivery",
                            "graph_version": "1.0.0",
                            "graph_digest": DIGEST,
                            "node_ids": list(profile.required_node_ids),
                            "edge_ids": list(profile.required_edge_ids),
                        },
                        profile=profile,
                        overlay=overlay,
                        project_config=project_config,
                        approved_profiles=registry,
                        support_matrix=support_matrix,
                        semantic_policy=_semantic_policy(),
                    ))
                self.assertEqual(issued, [])

        good = api.ProfileMaterializer.materialize(
            base_graph_document={
                "graph_id": "base-delivery",
                "graph_version": "1.0.0",
                "graph_digest": DIGEST,
                "node_ids": list(profile.required_node_ids),
                "edge_ids": list(profile.required_edge_ids),
            },
            profile=profile,
            overlay=overlay,
            project_config={},
            approved_profiles=registry,
            support_matrix=support_matrix,
            semantic_policy=_semantic_policy(),
        )
        with self.assertRaises(ValueError):
            _validate_graph_ref(good.graph_ref())
        partial_ref = dict(good.graph_ref())
        del partial_ref["support_matrix_digest"]
        with self.assertRaises(ValueError):
            _validate_graph_ref(partial_ref)
        substituted_ref = dict(good.graph_ref())
        substituted_ref["overlay_id"] = "emergency"
        with self.assertRaises(ValueError):
            _validate_graph_ref(substituted_ref)
        substituted_pin = dict(good.graph_ref())
        substituted_pin["profile_digest"] = DIGEST
        with self.assertRaises(ValueError):
            _validate_graph_ref(substituted_pin)

        schema_registry, work_context = _graph_contracts()
        snapshot = apply_events(
            None,
            _snapshot_events(good.graph_ref()),
            schema_registry=schema_registry,
            context=work_context,
            materialization_record=good.record,
        )
        serialized = snapshot.to_dict()
        snapshot_mutations: list[tuple[str, dict[str, object]]] = []
        for label, mutate in (
            (
                "partial",
                lambda graph: graph.pop("support_matrix_digest"),
            ),
            (
                "extra",
                lambda graph: graph.__setitem__("unknown_pin", DIGEST),
            ),
            (
                "invalid",
                lambda graph: graph.__setitem__("profile_digest", "invalid"),
            ),
            (
                "substitution",
                lambda graph: graph.__setitem__("overlay_id", "emergency"),
            ),
            (
                "pin-substitution",
                lambda graph: graph.__setitem__("profile_digest", DIGEST),
            ),
        ):
            candidate = copy.deepcopy(serialized)
            graph = candidate["graph_ref"]
            self.assertIsInstance(graph, dict)
            mutate(graph)  # type: ignore[arg-type]
            snapshot_mutations.append((label, candidate))
        for label, candidate in snapshot_mutations:
            before = copy.deepcopy(candidate)
            with self.subTest(snapshot_graph_ref=label), self.assertRaises(ValueError):
                TaskSnapshot.from_dict(
                    candidate,
                    schema_registry=schema_registry,
                    context=work_context,
                    materialization_record=good.record,
                )
            self.assertEqual(candidate, before)

    def test_gew_psc_new_feature_scaffold_p_declares_category_completion_rollback_and_target(self) -> None:
        api = _profile_api()
        profile = api.ProfileDefinition.from_dict(
            _profile_document(), approved_profiles=_approved_registry(),
            coverage_policy=_coverage_policy(), semantic_policy=_semantic_policy(),
        )
        self.assertIn("new-feature-acceptance", profile.validator_ids)
        self.assertIn("target-state-matched", profile.completion_predicate_ids)
        self.assertEqual(
            profile.rollback_contract["rollback_not_possible"],
            "route-owner-with-residual-state",
        )
        self.assertIn(
            "GEW-PSC-NEW-FEATURE-SCAFFOLD-P", profile.required_case_ids
        )

    def test_gew_psc_new_feature_scaffold_r_incomplete_matrix_gate_is_zero_write_fail_closed(self) -> None:
        api = _profile_api()
        coverage_policy = _coverage_policy()
        matrix_document = _support_matrix_document()
        before = json.dumps(matrix_document, sort_keys=True, separators=(",", ":"))
        matrix = api.SupportMatrixDefinition.from_dict(
            matrix_document, approved_profiles=_approved_registry(),
            coverage_policy=coverage_policy,
        )
        profile = api.ProfileDefinition.from_dict(
            _profile_document(), approved_profiles=_approved_registry(),
            coverage_policy=coverage_policy, semantic_policy=_semantic_policy(),
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            _overlay_document(), approved_profiles=_approved_registry(),
            coverage_policy=coverage_policy,
        )
        test_id = "GEW-PRO-NEW-FEATURE-NORMAL-P"
        observation_registry = api.EvidenceObservationRegistry.from_dict(
            _evidence_registry_document(),
            coverage_policy=coverage_policy,
            oracle_manifest_bytes=_oracle_manifest_bytes(),
        )
        registry_json = json.dumps(_evidence_registry_document(), separators=(",", ":"))
        duplicate_registry_json = registry_json.replace(
            '"registry_id":', '"registry_id":"forged", "registry_id":', 1,
        )
        with self.assertRaises(ValueError):
            api.EvidenceObservationRegistry.from_json(
                duplicate_registry_json,
                coverage_policy=coverage_policy,
                oracle_manifest_bytes=_oracle_manifest_bytes(),
            )
        forged_manifest = json.loads(_oracle_manifest_bytes())
        forged_manifest["oracles"][-1]["implementation"] = "tests.forged"  # type: ignore[index]
        with self.assertRaises(ValueError):
            api.EvidenceObservationRegistry.from_dict(
                _evidence_registry_document(),
                coverage_policy=coverage_policy,
                oracle_manifest_bytes=json.dumps(
                    forged_manifest, sort_keys=True, separators=(",", ":"),
                ).encode(),
            )
        fake_real_registry = _evidence_registry_document()
        fake_real_registry["observations"][0]["test_id"] = (  # type: ignore[index]
            "GEW-PRO-NEW-FEATURE-REAL-E2E-P"
        )
        fake_real_registry["observations"][0]["execution_kind"] = "real-target"  # type: ignore[index]
        _resign(
            fake_real_registry,
            "profile-evidence-observation-registry",
            "registry_digest",
        )
        with self.assertRaises(ValueError):
            api.EvidenceObservationRegistry.from_dict(
                fake_real_registry,
                coverage_policy=coverage_policy,
                oracle_manifest_bytes=_oracle_manifest_bytes(),
            )
        authority = api.EvidenceObservationAuthority(
            observation_registry,
            evidence_root=ROOT / "tests/fixtures",
        )
        evidence_bytes = (ROOT / "tests/fixtures/wp08-new-feature-normal-p-evidence.json").read_bytes()
        evidence_before = bytes(evidence_bytes)
        observation = authority.observe(
            test_id, matrix=matrix, profile=profile, overlay=overlay,
        )
        factory = api.CoverageRecordFactory(
            authority=authority,
            coverage_policy=coverage_policy,
        )
        observation_clone = object.__new__(api.EvidenceObservation)
        for field in api.EvidenceObservation.__dataclass_fields__:
            object.__setattr__(observation_clone, field, getattr(observation, field))
        with self.assertRaises(ValueError):
            factory.issue(
                observation_clone, matrix=matrix, profile=profile, overlay=overlay,
            )
        record = factory.issue(
            observation,
            matrix=matrix,
            profile=profile,
            overlay=overlay,
        )
        with self.assertRaises(TypeError):
            api.CoverageRecord()
        with self.assertRaises(TypeError):
            type("ForgedCoverageRecord", (api.CoverageRecord,), {})
        record_clone = object.__new__(api.CoverageRecord)
        for field in api.CoverageRecord.__dataclass_fields__:
            object.__setattr__(record_clone, field, getattr(record, field))
        with self.assertRaises(ValueError):
            api.ReleaseCoverageGate.evaluate(
                matrix, coverage_records=(record_clone,), coverage_factory=factory,
            )
        issued_release_records: list[object] = []
        decision = api.ReleaseCoverageGate.evaluate(
            matrix, coverage_records=(record,), coverage_factory=factory,
        )
        if decision.passed:
            issued_release_records.append(decision)
        self.assertFalse(decision.passed)
        self.assertIn("GEW-PSC-NEW-FEATURE-SCAFFOLD-R", decision.missing_test_ids)
        self.assertEqual(issued_release_records, [])
        self.assertEqual(
            json.dumps(matrix_document, sort_keys=True, separators=(",", ":")), before
        )
        self.assertEqual(evidence_bytes, evidence_before)

        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = pathlib.Path(temporary)
            evidence_path = evidence_root / "wp08-new-feature-normal-p-evidence.json"
            evidence_path.write_bytes(evidence_bytes)
            replacement_authority = api.EvidenceObservationAuthority(
                observation_registry, evidence_root=evidence_root,
            )
            replaced = replacement_authority.observe(
                test_id, matrix=matrix, profile=profile, overlay=overlay,
            )
            replacement_factory = api.CoverageRecordFactory(
                authority=replacement_authority, coverage_policy=coverage_policy,
            )
            replacement = evidence_root / "replacement.json"
            replacement.write_bytes(evidence_bytes + b" ")
            os.replace(replacement, evidence_path)
            with self.assertRaises(ValueError):
                replacement_factory.issue(
                    replaced, matrix=matrix, profile=profile, overlay=overlay,
                )

        with tempfile.TemporaryDirectory() as temporary:
            evidence_root = pathlib.Path(temporary)
            evidence_path = evidence_root / "wp08-new-feature-normal-p-evidence.json"
            evidence_path.write_bytes(evidence_bytes)
            gate_authority = api.EvidenceObservationAuthority(
                observation_registry, evidence_root=evidence_root,
            )
            gate_observation = gate_authority.observe(
                test_id, matrix=matrix, profile=profile, overlay=overlay,
            )
            gate_factory = api.CoverageRecordFactory(
                authority=gate_authority, coverage_policy=coverage_policy,
            )
            gate_record = gate_factory.issue(
                gate_observation, matrix=matrix, profile=profile, overlay=overlay,
            )
            replacement = evidence_root / "replacement.json"
            replacement.write_bytes(evidence_bytes + b" ")
            os.replace(replacement, evidence_path)
            with self.assertRaises(ValueError):
                api.ReleaseCoverageGate.evaluate(
                    matrix, coverage_records=(gate_record,), coverage_factory=gate_factory,
                )

        forged_all: dict[str, object] = {
            case_id: _coverage_evidence(
                case_id, matrix=matrix, profile=profile, overlay=overlay,
            )
            for case_id in (*PROFILE_CASE_IDS, *SCENARIO_CASE_IDS)
        }
        forged_before = copy.deepcopy(forged_all)
        for case_id, fabricated in forged_all.items():
            with self.subTest(fabricated_case=case_id), self.assertRaises(ValueError):
                factory.issue(
                    fabricated, matrix=matrix, profile=profile, overlay=overlay,
                )
        self.assertEqual(forged_all, forged_before)
        self.assertEqual(issued_release_records, [])

        forged_records: list[object] = []
        template = record.to_dict()
        template.pop("schema_version")
        for case_id in (*PROFILE_CASE_IDS, *SCENARIO_CASE_IDS):
            forged = object.__new__(api.CoverageRecord)
            values = dict(template)
            values["test_id"] = case_id
            values["record_digest"] = semantic_digest(
                {
                    "schema_version": "1.0.0",
                    **{
                        field: values[field] for field in values
                        if field != "record_digest"
                    },
                },
                contract_type="urn:gew:contract:coverage-record",
                projection_id="urn:gew:digest-projection:coverage-record:1.0.0",
                schema_id="urn:gew:schema:coverage-record-input:1.0.0",
            )
            for field, value in values.items():
                object.__setattr__(forged, field, value)
            forged_records.append(forged)
        with self.assertRaises(ValueError):
            api.ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=tuple(forged_records),
                coverage_factory=factory,
            )
        self.assertEqual(len(forged_records), 274)

        duplicate_mapping = _DuplicateKeyMapping((
            (test_id, _coverage_evidence(
                test_id, matrix=matrix, profile=profile, overlay=overlay,
            )),
            (test_id, {**_coverage_evidence(
                test_id, matrix=matrix, profile=profile, overlay=overlay,
            ), "status": "FAIL"}),
        ))
        with self.assertRaises(ValueError):
            api.ReleaseCoverageGate.evaluate(
                matrix, coverage_records=duplicate_mapping, coverage_factory=factory,
            )
        duplicate_json = json.dumps(
            _coverage_evidence(test_id, matrix=matrix, profile=profile, overlay=overlay),
            separators=(",", ":"),
        ).replace(
            '"status":"PASS"', '"status":"FAIL","status":"PASS"', 1,
        )
        with self.assertRaises(ValueError):
            factory.issue_json(
                duplicate_json,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )

        for field, replacement in (
            ("resolved", False),
            ("fixture_id", "profile:wrong:1.0.0"),
            ("oracle_id", "ORA-WRONG"),
            ("evidence_type", "wrong-evidence"),
            ("owner_gate", "WP-WRONG"),
            ("profile_digest", DIGEST),
            ("profile_version", "0.9.0"),
            ("overlay_digest", DIGEST),
            ("overlay_version", "0.9.0"),
            ("runtime_digest", DIGEST),
            ("runtime_lineage_id", "stale-runtime-lineage"),
        ):
            candidate = _coverage_evidence(
                test_id, matrix=matrix, profile=profile, overlay=overlay,
            )
            candidate[field] = replacement
            candidate_before = copy.deepcopy(candidate)
            issued: list[object] = []
            with self.subTest(field=field), self.assertRaises(ValueError):
                issued.append(factory.issue(
                    candidate,
                    matrix=matrix,
                    profile=profile,
                    overlay=overlay,
                ))
            self.assertEqual(issued, [])
            self.assertEqual(candidate, candidate_before)

        real_e2e_id = "GEW-PRO-NEW-FEATURE-REAL-E2E-P"
        fake_real_e2e = _coverage_evidence(
            real_e2e_id, matrix=matrix, profile=profile, overlay=overlay,
        )
        fake_before = copy.deepcopy(fake_real_e2e)
        with self.assertRaises(ValueError):
            factory.issue(
                fake_real_e2e,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
        self.assertEqual(fake_real_e2e, fake_before)


if __name__ == "__main__":
    unittest.main()
