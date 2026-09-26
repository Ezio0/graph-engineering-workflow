"""WP-08 slice 2 RED: closed Profile/overlay sets and real composition."""

from __future__ import annotations

import copy
import json
import pathlib
import types
import unittest
from collections.abc import Mapping

from graph_engineering.core.contracts.digest import semantic_digest
from tests.unit import test_wp08_profile_contracts as slice1


ROOT = pathlib.Path(__file__).resolve().parents[2]
PROFILE_DEFINITION_ROOT = ROOT / "config/profiles/definitions"
RISK_OVERLAY_ROOT = ROOT / "config/profiles/risk-overlays"
SUPPORT_MATRIX_PATH = ROOT / "config/profiles/support-matrix-v1.json"
PROJECT_TIGHTENING_POLICY_PATH = (
    ROOT / "config/profiles/project-tightening-policy-v1.json"
)
GOLDEN_PATH = ROOT / "tests/fixtures/wp08-profile-materialization-golden-v1.json"
COMMON_NODES = ("candidate-review", "completion-gate", "target-verification")
COMMON_COMPLETION = (
    "all-required-nodes-passed",
    "independent-candidate-review-passed",
    "project-gates-passed",
)
ARTIFACT_CONTRACTS = (
    "urn:gew:artifact-contract:candidate-review:1.0.0",
    "urn:gew:artifact-contract:completion-record:1.0.0",
    "urn:gew:artifact-contract:impact:1.0.0",
    "urn:gew:artifact-contract:implementation:1.0.0",
    "urn:gew:artifact-contract:plan:1.0.0",
    "urn:gew:artifact-contract:prd:1.0.0",
    "urn:gew:artifact-contract:tech-spec:1.0.0",
    "urn:gew:artifact-contract:test-plan:1.0.0",
    "urn:gew:artifact-contract:verification:1.0.0",
)


def _golden() -> dict[str, object]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def _golden_member(field: str, identity_field: str, identity: str) -> Mapping[str, object]:
    members = _golden()[field]
    if not isinstance(members, list):
        raise AssertionError("materialization golden set is invalid")
    matches = tuple(
        item for item in members
        if isinstance(item, dict) and item.get(identity_field) == identity
    )
    if len(matches) != 1:
        raise AssertionError("materialization golden identity is not exact")
    return matches[0]


def _semantic_entry(profile_id: str) -> Mapping[str, object]:
    document = slice1._semantic_policy_document()
    matches = tuple(
        item for item in document["profiles"]
        if isinstance(item, dict) and item.get("profile_id") == profile_id
    )
    if len(matches) != 1:
        raise AssertionError("semantic Profile fixture is not exact")
    return matches[0]


def _profile_document(profile_id: str) -> dict[str, object]:
    entry = _semantic_entry(profile_id)
    minima = entry["semantic_minima"]
    if not isinstance(minima, dict):
        raise AssertionError("semantic minimum fixture is invalid")
    cases = sorted(
        case_id for case_id in (*slice1.PROFILE_CASE_IDS, *slice1.SCENARIO_CASE_IDS)
        if f"-{profile_id.upper()}-" in case_id
    )
    scenario_cases = sorted(case_id for case_id in cases if case_id.startswith("GEW-PSC-"))
    required_nodes = sorted({*COMMON_NODES, *minima["required_node_ids"]})
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "profile_id": profile_id,
        "version": entry["profile_version"],
        "approved_profile_registry_digest": (
            slice1._approved_registry_document()["registry_digest"]
        ),
        "coverage_policy_digest": slice1._coverage_policy_document()["policy_digest"],
        "profile_semantic_policy_digest": (
            slice1._semantic_policy_document()["policy_digest"]
        ),
        "required_node_ids": required_nodes,
        "optional_node_ids": [],
        "required_edge_ids": sorted(minima["required_edge_ids"]),
        "optional_edge_ids": [],
        "route_overrides": [],
        "artifact_contract_ids": list(ARTIFACT_CONTRACTS),
        "validator_ids": sorted(minima["validator_ids"]),
        "completion_predicate_ids": sorted({
            *COMMON_COMPLETION, *minima["completion_predicate_ids"],
        }),
        "compatible_risk_paths": list(slice1.RISK_PATH_IDS),
        "rollback_contract": {
            "eligible_action_kinds": ["profile-change-rollback"],
            "precondition_ids": ["current-target-matches-receipt"],
            "compensation_graph_ref": f"graph:{profile_id}-compensation:1.0.0",
            "authority_requirement": "action-scoped-rollback",
            "verification_ids": sorted(minima["rollback_verification_ids"]),
            "rollback_not_possible": "route-owner-with-residual-state",
        },
        "required_case_ids": cases,
        "category_boundary_case_ids": scenario_cases,
        "real_e2e_requirement_id": f"GEW-PRO-{profile_id.upper()}-REAL-E2E-P",
        "required_capabilities": sorted(minima["required_capability_ids"]),
        "unsupported_integrations": [],
        "evidence_policy": {
            "owner_gate": "WP-08",
            "required_oracle_ids": [f"ORA-PROFILE-{profile_id.upper()}"],
        },
    }
    return slice1._complete(body, "profile-definition", "digest")


def _overlay_document(overlay_id: str) -> dict[str, object]:
    golden = _golden_member("overlay_semantic_sets", "overlay_id", overlay_id)
    node_additions: list[object] = list(golden["node_additions"])
    edge_additions: list[object] = list(golden["edge_additions"])
    merge_rules: list[object] = []
    compaction: list[object] = []
    budget: dict[str, object] = {"mode": "preserve", "overrides": []}
    if overlay_id == "compact-planned":
        merge_rules = [{
            "operation": "co-locate",
            "logical_contract_ids": [
                "urn:gew:artifact-contract:impact:1.0.0",
                "urn:gew:artifact-contract:plan:1.0.0",
            ],
        }]
        compaction = [{
            "logical_contract_id": "urn:gew:artifact-contract:impact:1.0.0",
            "physical_group_id": "fixture-compact-planning",
        }, {
            "logical_contract_id": "urn:gew:artifact-contract:plan:1.0.0",
            "physical_group_id": "fixture-compact-planning",
        }]
        budget = {
            "mode": "tighten",
            "overrides": [{"budget_id": "loop:bounded-v1", "maximum": 4}],
        }
    elif overlay_id == "emergency":
        budget = {
            "mode": "tighten",
            "overrides": [{"budget_id": "loop:bounded-v1", "maximum": 2}],
        }
    body: dict[str, object] = {
        "schema_version": "1.0.0",
        "overlay_id": overlay_id,
        "version": "1.0.0",
        "approved_profile_registry_digest": (
            slice1._approved_registry_document()["registry_digest"]
        ),
        "coverage_policy_digest": slice1._coverage_policy_document()["policy_digest"],
        "node_additions": node_additions,
        "edge_additions": edge_additions,
        "merge_rules": merge_rules,
        "artifact_compaction_mapping": compaction,
        "budget_policy": budget,
        "required_invariant_ids": list(
            slice1._semantic_policy_document()["core_invariant_ids"]
        ),
        "entry_condition_ids": list(golden["entry_condition_ids"]),
        "exit_condition_ids": list(golden["exit_condition_ids"]),
        "allowed_profile_ids": list(slice1.PROFILE_IDS),
        "forbidden_profile_ids": [],
    }
    return slice1._complete(body, "risk-overlay-definition", "digest")


def _project_tightening() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "required_node_additions": ["fixture-project-verification"],
        "required_edge_additions": ["fixture-project-verification-to-completion"],
        "validator_additions": ["fixture-project-validator"],
        "completion_predicate_additions": ["fixture-project-verified"],
        "artifact_contract_additions": [
            "urn:gew:artifact-contract:verification:1.0.0",
        ],
        "required_invariant_additions": ["fixture-project-data-boundary"],
        "budget_tightenings": [
            {"budget_id": "loop:bounded-v1", "maximum": 1},
        ],
    }


def _base_graph(profile: object) -> dict[str, object]:
    return {
        "graph_id": "fixture-base-delivery",
        "graph_version": "1.0.0",
        "graph_digest": "sha256-jcs-v1:" + "d" * 64,
        "node_ids": sorted({"fixture-base-node", *profile.required_node_ids}),
        "edge_ids": sorted({"fixture-base-edge", *profile.required_edge_ids}),
    }


def _read_documents(root: pathlib.Path, identities: tuple[str, ...]) -> tuple[dict[str, object], ...]:
    documents: list[dict[str, object]] = []
    for identity in identities:
        path = root / f"{identity}-v1.json"
        if path.is_file():
            documents.append(json.loads(path.read_text(encoding="utf-8")))
    return tuple(documents)


class WP08ProfileExpansionTests(unittest.TestCase):
    maxDiff = None

    def test_gew_wp08_s2_profile_set_p(self) -> None:
        """GEW-WP08-S2-PROFILE-SET-P."""

        api = slice1._profile_api()
        documents = _read_documents(PROFILE_DEFINITION_ROOT, slice1.PROFILE_IDS)
        self.assertEqual(len(documents), 9)
        profiles = tuple(
            api.ProfileDefinition.from_dict(
                document,
                approved_profiles=slice1._approved_registry(),
                coverage_policy=slice1._coverage_policy(),
                semantic_policy=slice1._semantic_policy(),
            )
            for document in documents
        )
        profile_set = api.ProfileDefinitionSet.from_documents(
            profiles,
            approved_profiles=slice1._approved_registry(),
            semantic_policy=slice1._semantic_policy(),
        )
        self.assertEqual(profile_set.profile_ids, slice1.PROFILE_IDS)
        base_golden = _golden()["base_semantic_sets"]
        if not isinstance(base_golden, dict):
            raise AssertionError("base semantic golden set is invalid")
        for profile in profiles:
            with self.subTest(profile=profile.profile_id):
                minima = _semantic_entry(profile.profile_id)["semantic_minima"]
                golden = _golden_member(
                    "profile_semantic_sets", "profile_id", profile.profile_id,
                )
                expected_scenarios = tuple(sorted(
                    case_id for case_id in slice1.SCENARIO_CASE_IDS
                    if f"-{profile.profile_id.upper()}-" in case_id
                ))
                self.assertEqual(profile.category_boundary_case_ids, expected_scenarios)
                self.assertTrue(set(minima["required_node_ids"]).issubset(
                    profile.required_node_ids,
                ))
                self.assertTrue(set(minima["validator_ids"]).issubset(
                    profile.validator_ids,
                ))
                self.assertTrue(set(minima["completion_predicate_ids"]).issubset(
                    profile.completion_predicate_ids,
                ))
                self.assertTrue(set(minima["rollback_verification_ids"]).issubset(
                    profile.rollback_contract["verification_ids"],
                ))
                target_ids = set(minima["target_verification_ids"])
                implemented_targets = {
                    *profile.required_node_ids,
                    *profile.validator_ids,
                    *profile.completion_predicate_ids,
                }
                self.assertTrue(target_ids.issubset(implemented_targets))
                self.assertEqual(profile.evidence_policy["owner_gate"], "WP-08")
                self.assertEqual(
                    profile.evidence_policy["required_oracle_ids"],
                    (f"ORA-PROFILE-{profile.profile_id.upper()}",),
                )
                self.assertEqual(
                    set(profile.required_node_ids),
                    {*base_golden["required_node_ids"], *golden["required_node_ids"]},
                )
                self.assertEqual(
                    set(profile.required_edge_ids), set(golden["required_edge_ids"]),
                )
                self.assertEqual(
                    set(profile.artifact_contract_ids),
                    set(base_golden["artifact_contract_ids"]),
                )
                self.assertEqual(set(profile.validator_ids), set(golden["validator_ids"]))
                self.assertEqual(
                    set(profile.completion_predicate_ids),
                    {
                        *base_golden["completion_predicate_ids"],
                        *golden["completion_predicate_ids"],
                    },
                )
                self.assertEqual(
                    set(profile.required_capabilities),
                    set(golden["required_capability_ids"]),
                )

    def test_gew_wp08_s2_profile_set_r(self) -> None:
        """GEW-WP08-S2-PROFILE-SET-R."""

        api = slice1._profile_api()
        approved = slice1._approved_registry()
        coverage = slice1._coverage_policy()
        semantic = slice1._semantic_policy()
        profiles = tuple(
            api.ProfileDefinition.from_dict(
                _profile_document(profile_id),
                approved_profiles=approved,
                coverage_policy=coverage,
                semantic_policy=semantic,
            )
            for profile_id in slice1.PROFILE_IDS
        )
        for profile_id in slice1.PROFILE_IDS:
            minima = _semantic_entry(profile_id)["semantic_minima"]
            if not isinstance(minima, dict):
                raise AssertionError("semantic minimum fixture is invalid")
            mutations: list[tuple[str, object]] = [
                (
                    "scenario-subset",
                    lambda value: value["category_boundary_case_ids"].pop(),
                ),
                (
                    "oracle-alias",
                    lambda value: value["evidence_policy"].__setitem__(
                        "required_oracle_ids", ["ORA-PROFILE-ALIAS"],
                    ),
                ),
                (
                    "owner-alias",
                    lambda value: value["evidence_policy"].__setitem__(
                        "owner_gate", "WP-ALIAS",
                    ),
                ),
                (
                    "profile-alias",
                    lambda value: value.__setitem__("profile_id", "profile-alias"),
                ),
                (
                    "stale-version",
                    lambda value: value.__setitem__("version", "0.0.0"),
                ),
            ]
            for field in (
                "required_node_ids",
                "validator_ids",
                "completion_predicate_ids",
            ):
                required_values = minima[field]
                if not isinstance(required_values, list) or not required_values:
                    raise AssertionError("semantic minimum fixture is empty")
                required_value = required_values[0]
                mutations.append((
                    f"semantic-minimum-{field}",
                    lambda value, field=field, required_value=required_value: (
                        value[field].remove(required_value)
                    ),
                ))
            rollback_values = minima["rollback_verification_ids"]
            if not isinstance(rollback_values, list) or not rollback_values:
                raise AssertionError("rollback minimum fixture is empty")
            rollback_value = rollback_values[0]
            mutations.append((
                "rollback-verification-minimum",
                lambda value, rollback_value=rollback_value: (
                    value["rollback_contract"]["verification_ids"].remove(
                        rollback_value,
                    )
                ),
            ))
            target_values = minima["target_verification_ids"]
            if not isinstance(target_values, list) or not target_values:
                raise AssertionError("target-verification minimum fixture is empty")
            for target_value in target_values:
                target_field = next(
                    field for field in (
                        "required_node_ids",
                        "validator_ids",
                        "completion_predicate_ids",
                    )
                    if target_value in _profile_document(profile_id)[field]
                )
                mutations.append((
                    f"target-verification-{target_value}",
                    lambda value, field=target_field, target_value=target_value: (
                        value[field].remove(target_value)
                    ),
                ))
            for label, mutate in mutations:
                candidate = _profile_document(profile_id)
                mutate(candidate)
                slice1._resign(candidate, "profile-definition", "digest")
                before = copy.deepcopy(candidate)
                with self.subTest(profile=profile_id, mutation=label), self.assertRaises(ValueError):
                    api.ProfileDefinition.from_dict(
                        candidate,
                        approved_profiles=approved,
                        coverage_policy=coverage,
                        semantic_policy=semantic,
                    )
                self.assertEqual(candidate, before)
        self.assertTrue(hasattr(api, "ProfileDefinitionSet"))
        if hasattr(api, "ProfileDefinitionSet"):
            foreign = types.SimpleNamespace(
                profile_id="profile-extra",
                digest="sha256-jcs-v1:" + "f" * 64,
            )
            mutations = (
                ("missing", profiles[:-1]),
                ("extra", (*profiles, foreign)),
                ("duplicate", (*profiles[:-1], profiles[0])),
            )
            for label, candidate in mutations:
                before = tuple(
                    (id(item), getattr(item, "digest", None)) for item in candidate
                )
                with self.subTest(set_mutation=label), self.assertRaises(ValueError):
                    api.ProfileDefinitionSet.from_documents(
                        candidate, approved_profiles=approved, semantic_policy=semantic,
                    )
                self.assertEqual(tuple(
                    (id(item), getattr(item, "digest", None)) for item in candidate
                ), before)

    def test_gew_wp08_s2_overlay_set_p(self) -> None:
        """GEW-WP08-S2-OVERLAY-SET-P."""

        api = slice1._profile_api()
        documents = _read_documents(RISK_OVERLAY_ROOT, slice1.RISK_PATH_IDS)
        self.assertEqual(len(documents), 3)
        overlays = tuple(
            api.RiskOverlayDefinition.from_dict(
                document,
                approved_profiles=slice1._approved_registry(),
                coverage_policy=slice1._coverage_policy(),
            )
            for document in documents
        )
        overlay_set = api.RiskOverlayDefinitionSet.from_documents(
            overlays,
            approved_profiles=slice1._approved_registry(),
            semantic_policy=slice1._semantic_policy(),
        )
        self.assertEqual(overlay_set.overlay_ids, slice1.RISK_PATH_IDS)
        for overlay in overlays:
            with self.subTest(overlay=overlay.overlay_id):
                golden = _golden_member(
                    "overlay_semantic_sets", "overlay_id", overlay.overlay_id,
                )
                expected_mode = (
                    "preserve" if overlay.overlay_id == "full-planned" else "tighten"
                )
                self.assertEqual(overlay.budget_policy["mode"], expected_mode)
                if expected_mode == "preserve":
                    self.assertEqual(overlay.budget_policy["overrides"], ())
                else:
                    self.assertTrue(overlay.budget_policy["overrides"])
                    for override in overlay.budget_policy["overrides"]:
                        self.assertIsInstance(override["maximum"], int)
                        self.assertGreater(override["maximum"], 0)
                self.assertFalse(any(
                    rule.get("operation") == "remove" for rule in overlay.merge_rules
                ))
                self.assertTrue(set(
                    slice1._semantic_policy_document()["core_invariant_ids"]
                ).issubset(overlay.required_invariant_ids))
                self.assertEqual(set(overlay.node_additions), set(golden["node_additions"]))
                self.assertEqual(set(overlay.edge_additions), set(golden["edge_additions"]))
                self.assertEqual(
                    set(overlay.entry_condition_ids), set(golden["entry_condition_ids"]),
                )
                self.assertEqual(
                    set(overlay.exit_condition_ids), set(golden["exit_condition_ids"]),
                )
                self.assertEqual(
                    set(overlay.required_invariant_ids),
                    set(golden["required_invariant_ids"]),
                )
        compact = next(
            item for item in overlays if item.overlay_id == "compact-planned"
        )
        emergency = next(item for item in overlays if item.overlay_id == "emergency")
        compact_budgets = {
            item["budget_id"]: item["maximum"]
            for item in compact.budget_policy["overrides"]
        }
        emergency_budgets = {
            item["budget_id"]: item["maximum"]
            for item in emergency.budget_policy["overrides"]
        }
        for budget_id in compact_budgets.keys() & emergency_budgets.keys():
            self.assertLessEqual(emergency_budgets[budget_id], compact_budgets[budget_id])

    def test_gew_wp08_s2_overlay_set_r(self) -> None:
        """GEW-WP08-S2-OVERLAY-SET-R."""

        api = slice1._profile_api()
        approved = slice1._approved_registry()
        coverage = slice1._coverage_policy()
        semantic = slice1._semantic_policy()
        overlays = tuple(
            api.RiskOverlayDefinition.from_dict(
                _overlay_document(overlay_id),
                approved_profiles=approved,
                coverage_policy=coverage,
            )
            for overlay_id in slice1.RISK_PATH_IDS
        )
        if hasattr(api, "RiskOverlayDefinitionSet"):
            foreign = types.SimpleNamespace(
                overlay_id="overlay-extra",
                digest="sha256-jcs-v1:" + "f" * 64,
            )
            for label, candidate in (
                ("missing", overlays[:-1]),
                ("extra", (*overlays, foreign)),
                ("duplicate", (*overlays[:-1], overlays[0])),
            ):
                before = tuple(
                    (id(item), getattr(item, "digest", None)) for item in candidate
                )
                with self.subTest(set_mutation=label), self.assertRaises(ValueError):
                    api.RiskOverlayDefinitionSet.from_documents(
                        candidate, approved_profiles=approved, semantic_policy=semantic,
                    )
                self.assertEqual(tuple(
                    (id(item), getattr(item, "digest", None)) for item in candidate
                ), before)
        for overlay_id in slice1.RISK_PATH_IDS:
            for label, mutate in (
                (
                    "budget-expansion",
                    lambda value: value.__setitem__(
                        "budget_policy",
                        {"mode": "expand", "overrides": [
                            {"budget_id": "fixture-profile-loop", "maximum": 1000},
                        ]},
                    ),
                ),
                (
                    "semantic-removal",
                    lambda value: value.__setitem__(
                        "merge_rules",
                        [{"operation": "remove", "target_id": "completion-gate"}],
                    ),
                ),
                (
                    "invariant-removal",
                    lambda value: value["required_invariant_ids"].pop(),
                ),
                (
                    "overlay-alias",
                    lambda value: value.__setitem__("overlay_id", "overlay-alias"),
                ),
                (
                    "stale-version",
                    lambda value: value.__setitem__("version", "0.0.0"),
                ),
            ):
                candidate = _overlay_document(overlay_id)
                mutate(candidate)
                slice1._resign(candidate, "risk-overlay-definition", "digest")
                before = copy.deepcopy(candidate)
                with self.subTest(overlay=overlay_id, mutation=label), self.assertRaises(ValueError):
                    api.RiskOverlayDefinition.from_dict(
                        candidate,
                        approved_profiles=approved,
                        coverage_policy=coverage,
                    )
                self.assertEqual(candidate, before)
        self.assertTrue(hasattr(api, "RiskOverlayDefinitionSet"))

    def test_gew_wp08_s2_materialization_p(self) -> None:
        """GEW-WP08-S2-MATERIALIZATION-P."""

        api = slice1._profile_api()
        approved = slice1._approved_registry()
        coverage = slice1._coverage_policy()
        semantic = slice1._semantic_policy()
        matrix = api.SupportMatrixDefinition.from_dict(
            json.loads(SUPPORT_MATRIX_PATH.read_text(encoding="utf-8")),
            approved_profiles=approved,
            coverage_policy=coverage,
        )
        installed_project_policy = api.ProjectTighteningPolicy.from_dict(
            json.loads(PROJECT_TIGHTENING_POLICY_PATH.read_text(encoding="utf-8")),
            loop_budgets=slice1._loop_budget_registry(),
        )
        self.assertEqual(
            installed_project_policy.policy_digest,
            semantic.project_tightening_policy.policy_digest,
        )
        loop_golden = _golden()["loop_budget_registry"]
        if not isinstance(loop_golden, dict):
            raise AssertionError("loop budget golden authority is invalid")
        self.assertEqual(
            installed_project_policy.loop_budget_registry_id,
            loop_golden["registry_id"],
        )
        self.assertEqual(
            installed_project_policy.loop_budget_registry_digest,
            loop_golden["registry_digest"],
        )
        self.assertEqual(
            dict(installed_project_policy.base_budget_limits),
            loop_golden["budget_limits"],
        )
        profiles = {
            profile_id: api.ProfileDefinition.from_dict(
                _profile_document(profile_id),
                approved_profiles=approved,
                coverage_policy=coverage,
                semantic_policy=semantic,
            )
            for profile_id in slice1.PROFILE_IDS
        }
        overlays = {
            overlay_id: api.RiskOverlayDefinition.from_dict(
                _overlay_document(overlay_id),
                approved_profiles=approved,
                coverage_policy=coverage,
            )
            for overlay_id in slice1.RISK_PATH_IDS
        }
        base_golden = _golden()["base_semantic_sets"]
        if not isinstance(base_golden, dict):
            raise AssertionError("base semantic golden set is invalid")
        for profile_id in slice1.PROFILE_IDS:
            for overlay_id in slice1.RISK_PATH_IDS:
                profile = profiles[profile_id]
                overlay = overlays[overlay_id]
                profile_golden = _golden_member(
                    "profile_semantic_sets", "profile_id", profile_id,
                )
                overlay_golden = _golden_member(
                    "overlay_semantic_sets", "overlay_id", overlay_id,
                )
                base = _base_graph(profile)
                project = _project_tightening()
                before = copy.deepcopy((base, project))
                first = api.ProfileMaterializer.materialize(
                    base_graph_document=base,
                    profile=profile,
                    overlay=overlay,
                    project_config={},
                    approved_profiles=approved,
                    support_matrix=matrix,
                    semantic_policy=semantic,
                )
                second = api.ProfileMaterializer.materialize(
                    base_graph_document=base,
                    profile=profile,
                    overlay=overlay,
                    project_config={},
                    approved_profiles=approved,
                    support_matrix=matrix,
                    semantic_policy=semantic,
                )
                with self.subTest(
                    profile=profile_id, overlay=overlay_id, phase="determinism-pins",
                ):
                    self.assertEqual(first.record.to_bytes(), second.record.to_bytes())
                    self.assertEqual(first.graph_ref(), second.graph_ref())
                    self.assertEqual(set(first.digest_pins), {
                        "base_graph_digest", "profile_digest", "overlay_digest",
                        "project_config_digest", "support_matrix_digest",
                        "materialization_digest",
                    })
                    self.assertEqual(
                        first.loop_budget_registry_id,
                        installed_project_policy.loop_budget_registry_id,
                    )
                    self.assertEqual(
                        first.loop_budget_registry_digest,
                        installed_project_policy.loop_budget_registry_digest,
                    )
                    record_document = first.record.to_dict()
                    self.assertEqual(
                        record_document["loop_budget_registry_id"],
                        installed_project_policy.loop_budget_registry_id,
                    )
                    self.assertEqual(
                        record_document["loop_budget_registry_digest"],
                        installed_project_policy.loop_budget_registry_digest,
                    )
                    self.assertNotIn("loop_budget_registry_digest", first.graph_ref())
                with self.subTest(
                    profile=profile_id, overlay=overlay_id, phase="output-merge-digest",
                ):
                    expected_nodes = {
                        *base["node_ids"], *base_golden["required_node_ids"],
                        *profile_golden["required_node_ids"],
                        *overlay_golden["node_additions"],
                    }
                    expected_edges = {
                        *base["edge_ids"], *profile_golden["required_edge_ids"],
                        *overlay_golden["edge_additions"],
                    }
                    self.assertEqual(set(first.node_ids), expected_nodes)
                    self.assertEqual(set(first.edge_ids), expected_edges)
                    self.assertEqual(
                        set(first.artifact_contract_ids),
                        set(base_golden["artifact_contract_ids"]),
                    )
                    self.assertEqual(
                        set(first.validator_ids), set(profile_golden["validator_ids"]),
                    )
                    self.assertEqual(
                        set(first.completion_predicate_ids),
                        {
                            *base_golden["completion_predicate_ids"],
                            *profile_golden["completion_predicate_ids"],
                        },
                    )
                    self.assertEqual(
                        set(first.required_invariant_ids),
                        set(base_golden["required_invariant_ids"]),
                    )
                with self.subTest(
                    profile=profile_id, overlay=overlay_id, phase="budget-merge",
                ):
                    self.assertEqual(
                        dict(first.budget_limits),
                        overlay_golden["budget_limits"],
                    )
                with self.subTest(
                    profile=profile_id, overlay=overlay_id, phase="digest-output-binding",
                ):
                    output = {
                        "node_ids": list(first.node_ids),
                        "edge_ids": list(first.edge_ids),
                        "artifact_contract_ids": list(first.artifact_contract_ids),
                        "validator_ids": list(first.validator_ids),
                        "completion_predicate_ids": list(first.completion_predicate_ids),
                        "required_invariant_ids": list(first.required_invariant_ids),
                        "budget_limits": dict(first.budget_limits),
                    }
                    expected = semantic_digest(
                        {
                            "schema_version": "1.0.0",
                            "graph_id": first.graph_id,
                            "graph_version": first.graph_version,
                            "profile_id": first.profile_id,
                            "profile_version": first.profile_version,
                            "overlay_id": first.overlay_id,
                            "overlay_version": first.overlay_version,
                            "digest_pins": {
                                name: first.digest_pins[name]
                                for name in (
                                    "base_graph_digest", "profile_digest", "overlay_digest",
                                    "project_config_digest", "support_matrix_digest",
                                )
                            },
                            "output": output,
                        },
                        contract_type="urn:gew:contract:profile-materialization",
                        projection_id=(
                            "urn:gew:digest-projection:profile-materialization:1.0.0"
                        ),
                        schema_id="urn:gew:schema:profile-materialization-input:1.0.0",
                    )
                    self.assertEqual(first.digest_pins["materialization_digest"], expected)
                with self.subTest(
                    profile=profile_id, overlay=overlay_id, phase="project-tightening",
                ):
                    tightened = api.ProfileMaterializer.materialize(
                        base_graph_document=base,
                        profile=profile,
                        overlay=overlay,
                        project_config=project,
                        approved_profiles=approved,
                        support_matrix=matrix,
                        semantic_policy=semantic,
                    )
                    self.assertTrue(set(project["required_node_additions"]).issubset(
                        tightened.node_ids,
                    ))
                    self.assertTrue(set(project["validator_additions"]).issubset(
                        tightened.validator_ids,
                    ))
                    self.assertTrue(set(
                        project["completion_predicate_additions"]
                    ).issubset(tightened.completion_predicate_ids))
                    self.assertTrue(set(project["required_invariant_additions"]).issubset(
                        tightened.required_invariant_ids,
                    ))
                    self.assertEqual(
                        dict(tightened.budget_limits),
                        {"loop:bounded-v1": 1},
                    )
                    self.assertNotEqual(
                        first.digest_pins["materialization_digest"],
                        tightened.digest_pins["materialization_digest"],
                    )
                self.assertEqual((base, project), before)

    def test_gew_wp08_s2_materialization_r(self) -> None:
        """GEW-WP08-S2-MATERIALIZATION-R."""

        api = slice1._profile_api()
        approved = slice1._approved_registry()
        coverage = slice1._coverage_policy()
        semantic = slice1._semantic_policy()
        matrix = api.SupportMatrixDefinition.from_dict(
            slice1._support_matrix_document(),
            approved_profiles=approved,
            coverage_policy=coverage,
        )
        profile = api.ProfileDefinition.from_dict(
            _profile_document("new-feature"),
            approved_profiles=approved,
            coverage_policy=coverage,
            semantic_policy=semantic,
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            _overlay_document("full-planned"),
            approved_profiles=approved,
            coverage_policy=coverage,
        )
        for label, mutate in (
            (
                "rollback-authority",
                lambda value: value["rollback_contract"].__setitem__(
                    "authority_requirement", "expanded-rollback-authority",
                ),
            ),
            (
                "artifact-substitution",
                lambda value: value["artifact_contract_ids"].append(
                    "urn:gew:artifact-contract:substituted:1.0.0",
                ),
            ),
            (
                "capability-expansion",
                lambda value: value["required_capabilities"].append(
                    "external-system-write",
                ),
            ),
            (
                "route-substitution",
                lambda value: value["route_overrides"].append(
                    {"route_id": "unapproved-route"},
                ),
            ),
        ):
            candidate = _profile_document("new-feature")
            mutate(candidate)
            for field in ("artifact_contract_ids", "required_capabilities"):
                candidate[field].sort()
            slice1._resign(candidate, "profile-definition", "digest")
            substituted = api.ProfileDefinition.from_dict(
                candidate,
                approved_profiles=approved,
                coverage_policy=coverage,
                semantic_policy=semantic,
            )
            base = _base_graph(substituted)
            before = copy.deepcopy((candidate, base))
            issued = []
            with self.subTest(profile_mutation=label), self.assertRaises(ValueError):
                issued.append(api.ProfileMaterializer.materialize(
                    base_graph_document=base,
                    profile=substituted,
                    overlay=overlay,
                    project_config={},
                    approved_profiles=approved,
                    support_matrix=matrix,
                    semantic_policy=semantic,
                ))
            self.assertEqual(issued, [])
            self.assertEqual((candidate, base), before)
        for label, project in (
            ("semantic-removal", {"remove_required_node_ids": ["completion-gate"]}),
            ("invariant-removal", {"disable_invariant_ids": ["authority"]}),
            ("budget-expansion", {"budget_tightenings": [
                {"budget_id": "loop:bounded-v1", "maximum": 1000},
            ]}),
            ("unknown-budget", {"budget_tightenings": [
                {"budget_id": "unknown-loop", "maximum": 1},
            ]}),
            ("alias-field", {"required_nodes": ["fixture-alias"]}),
            ("extra-field", {**_project_tightening(), "unknown": True}),
        ):
            base = _base_graph(profile)
            before = copy.deepcopy((base, project))
            issued: list[object] = []
            with self.subTest(project_mutation=label), self.assertRaises(ValueError):
                issued.append(api.ProfileMaterializer.materialize(
                    base_graph_document=base,
                    profile=profile,
                    overlay=overlay,
                    project_config=project,
                    approved_profiles=approved,
                    support_matrix=matrix,
                    semantic_policy=semantic,
                ))
            self.assertEqual(issued, [])
            self.assertEqual((base, project), before)
        stale_overlay = _overlay_document("full-planned")
        stale_overlay["coverage_policy_digest"] = "sha256-jcs-v1:" + "e" * 64
        slice1._resign(stale_overlay, "risk-overlay-definition", "digest")
        before = copy.deepcopy(stale_overlay)
        with self.assertRaises(ValueError):
            api.RiskOverlayDefinition.from_dict(
                stale_overlay,
                approved_profiles=approved,
                coverage_policy=coverage,
            )
        self.assertEqual(stale_overlay, before)
        substituted_overlay = _overlay_document("full-planned")
        substituted_overlay["node_additions"].append("fixture-substitution")
        slice1._resign(
            substituted_overlay, "risk-overlay-definition", "digest",
        )
        before = copy.deepcopy(substituted_overlay)
        issued = []
        with self.subTest(overlay_mutation="coherent-substitution"), self.assertRaises(ValueError):
            issued.append(api.RiskOverlayDefinition.from_dict(
                substituted_overlay,
                approved_profiles=approved,
                coverage_policy=coverage,
            ))
        self.assertEqual(issued, [])
        self.assertEqual(substituted_overlay, before)

        for label, mutate in (
            (
                "stale-loop-registry",
                lambda value: value["project_tightening_policy"].__setitem__(
                    "loop_budget_registry_digest", "sha256-jcs-v1:" + "0" * 64,
                ),
            ),
            (
                "unknown-loop-budget",
                lambda value: value["project_tightening_policy"][
                    "base_budget_limits"
                ][0].__setitem__("budget_id", "loop:unknown-v1"),
            ),
            (
                "base-artifact-removal",
                lambda value: value["base_semantic_sets"][
                    "artifact_contract_ids"
                ].pop(),
            ),
            (
                "emergency-postmortem-removal",
                lambda value: value["risk_path_minima"][2][
                    "exit_condition_ids"
                ].remove("postmortem-required"),
            ),
        ):
            candidate = slice1._semantic_policy_document()
            mutate(candidate)
            if label in {"stale-loop-registry", "unknown-loop-budget"}:
                slice1._resign(
                    candidate["project_tightening_policy"],
                    "project-tightening-policy",
                    "policy_digest",
                )
            slice1._resign(
                candidate, "profile-semantic-policy", "policy_digest",
            )
            before = copy.deepcopy(candidate)
            with self.subTest(semantic_policy_mutation=label), self.assertRaises(ValueError):
                api.ProfileSemanticPolicy.from_dict(
                    candidate,
                    approved_profiles=approved,
                    coverage_policy=coverage,
                    loop_budgets=slice1._loop_budget_registry(),
                    expected_policy_digest=(
                        candidate["policy_digest"]
                        if label in {"stale-loop-registry", "unknown-loop-budget"}
                        else slice1._semantic_policy_document()["policy_digest"]
                    ),
                )
            self.assertEqual(candidate, before)


class DependencyPureProjectionTests(unittest.TestCase):
    def test_reuses_pure_results_but_rereads_and_detaches(self):
        import graph_engineering as package
        from graph_engineering.application import dependency_security as dep
        from unittest import mock

        for loader_name, reader_name, parser_name in (
            ("_dependency_advisory_installation_resources", "_bootstrap_projection", "_parse_bootstrap_projection"),
            ("_dependency_graph_installation_resources", "_graph_installation_projection", "_parse_graph_installation_projection"),
        ):
            reader = getattr(dep, reader_name)
            expected = reader()
            with mock.patch.object(package, loader_name, wraps=getattr(package, loader_name)) as loader, mock.patch.object(dep, parser_name, wraps=getattr(dep, parser_name)) as parser:
                with dep._dependency_pure_operation() as operation:
                    first = reader()
                    self.assertEqual(first, expected)
                    object.__setattr__(first[0], "registry_id", "poisoned-return")
                    self.assertEqual(reader(), expected)
                    self.assertEqual(loader.call_count, 2)
                    self.assertEqual(parser.call_count, 1)
                    self.assertLessEqual(len(operation.entries), 2)
                self.assertFalse(operation.entries)
                self.assertEqual(reader(), expected)
                self.assertEqual(parser.call_count, 2)

    def test_changed_bytes_and_loader_failure_reject_after_hit(self):
        import graph_engineering as package
        from graph_engineering.application import dependency_security as dep
        from unittest import mock

        with dep._dependency_pure_operation():
            expected = dep._bootstrap_projection()
            resources = package._dependency_advisory_installation_resources()
            changed = (resources[0], resources[1] + b" ", *resources[2:])
            with mock.patch.object(package, "_dependency_advisory_installation_resources", return_value=changed):
                for _ in range(2):
                    with self.assertRaises(dep.DependencySecurityError):
                        dep._bootstrap_projection()
            self.assertEqual(dep._bootstrap_projection(), expected)
            with mock.patch.object(package, "_dependency_advisory_installation_resources", side_effect=package.DistributionIdentityError("physical source changed")):
                with self.assertRaises(dep.DependencySecurityError):
                    dep._bootstrap_projection()

    def test_schema_identity_is_part_of_key(self):
        from graph_engineering.application import dependency_security as dep
        from unittest import mock
        with dep._dependency_pure_operation():
            dep._bootstrap_projection()
            with mock.patch.object(dep, "DEPENDENCY_SECURITY_SCHEMA_IDS", tuple(reversed(dep.DEPENDENCY_SECURITY_SCHEMA_IDS))):
                with self.assertRaises(dep.DependencySecurityError):
                    dep._bootstrap_projection()
            dep._graph_installation_projection()
            with mock.patch.object(dep, "DEPENDENCY_GRAPH_SCHEMA_IDS", ("urn:gew:foreign-schema", *dep.DEPENDENCY_GRAPH_SCHEMA_IDS[1:])):
                with self.assertRaises(dep.DependencySecurityError):
                    dep._graph_installation_projection()

    def test_nested_thread_and_process_identity_do_not_share_results(self):
        import threading
        from graph_engineering.application import dependency_security as dep
        from unittest import mock
        original = dep._parse_bootstrap_projection
        with mock.patch.object(dep, "_parse_bootstrap_projection", wraps=original) as parser:
            with dep._dependency_pure_operation() as outer:
                expected = dep._bootstrap_projection()
                with dep._dependency_pure_operation() as inner:
                    self.assertEqual(dep._bootstrap_projection(), expected)
                    self.assertIsNot(outer, inner)
                self.assertFalse(inner.entries)
                self.assertEqual(dep._bootstrap_projection(), expected)
                self.assertEqual(parser.call_count, 2)
                results = []
                def read_other_thread():
                    try: results.append(dep._bootstrap_projection())
                    except BaseException as error: results.append(error)
                thread = threading.Thread(target=read_other_thread)
                thread.start(); thread.join()
                self.assertEqual(results, [expected])
                self.assertEqual(parser.call_count, 3)
                # Simulate inherited storage with a foreign recorded process owner;
                # do not change os.getpid used by the actual source attestation.
                owner = outer.owner
                outer.owner = (-1, owner[1])
                self.assertEqual(dep._bootstrap_projection(), expected)
                self.assertEqual(parser.call_count, 4)
                outer.owner = owner
            self.assertFalse(outer.entries)

    def test_exception_clears_scope_and_new_phase_reparses(self):
        from graph_engineering.application import dependency_security as dep
        from unittest import mock
        class Abort(BaseException): pass
        with mock.patch.object(dep, "_parse_bootstrap_projection", wraps=dep._parse_bootstrap_projection) as parser:
            with self.assertRaises(Abort):
                with dep._dependency_pure_operation() as failed:
                    dep._bootstrap_projection()
                    raise Abort()
            self.assertFalse(failed.entries)
            with dep._dependency_pure_operation():
                dep._bootstrap_projection()
            self.assertEqual(parser.call_count, 2)

    def test_resource_type_and_parser_identity_cannot_reuse_entry(self):
        import graph_engineering as package
        from graph_engineering.application import dependency_security as dep
        from unittest import mock
        with dep._dependency_pure_operation():
            expected = dep._bootstrap_projection()
            with mock.patch.object(dep, "_parse_bootstrap_projection", side_effect=dep.DependencySecurityError("different parser")):
                with self.assertRaises(dep.DependencySecurityError):
                    dep._bootstrap_projection()
            resources = package._dependency_advisory_installation_resources()
            with mock.patch.object(package, "_dependency_advisory_installation_resources", return_value=list(resources)), mock.patch.object(dep, "_parse_bootstrap_projection", wraps=dep._parse_bootstrap_projection) as parser:
                self.assertEqual(dep._bootstrap_projection(), expected)
                self.assertEqual(dep._bootstrap_projection(), expected)
                self.assertEqual(parser.call_count, 2)


if __name__ == "__main__":
    unittest.main()
