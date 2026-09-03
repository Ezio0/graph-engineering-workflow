"""WP-08 Slice 4 production-backed coverage records."""

from __future__ import annotations

import copy
import hashlib
import pickle
import unittest
from unittest import mock

from graph_engineering.core.profiles import ReleaseCoverageGate
from tests.support import wp08_release_coverage as fixture
from tests.support import wp08_dependency_security as dependency_fixture
from tests.unit import test_wp08_profile_contracts as slice1


class WP08ReleaseCoverageTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def _profile_contracts(
        profile_id: str = "new-feature",
    ):  # type: ignore[no-untyped-def]
        api = slice1._profile_api()
        coverage = slice1._coverage_policy()
        matrix = api.SupportMatrixDefinition.from_dict(
            slice1._support_matrix_document(),
            approved_profiles=slice1._approved_registry(),
            coverage_policy=coverage,
        )
        profile = api.ProfileDefinition.from_dict(
            fixture.category.profile_document(profile_id),
            approved_profiles=slice1._approved_registry(),
            coverage_policy=coverage,
            semantic_policy=slice1._semantic_policy(),
        )
        overlay = api.RiskOverlayDefinition.from_dict(
            slice1._overlay_document(),
            approved_profiles=slice1._approved_registry(),
            coverage_policy=coverage,
        )
        return api, coverage, matrix, profile, overlay

    def _assert_profile_rejection_attacks(
        self,
        *,
        api4: fixture.Slice4API,
        plan: object,
        profile_id: str,
        foreign_profile_id: str,
    ) -> None:
        normal_test_id = fixture.profile_mandatory_test_id(
            profile_id, "normal", "R",
        )
        (
            _attack_api,
            attack_application,
            attack_probe,
            attack_target,
        ) = fixture.production_runtime(
            "normal",
            profile_id=profile_id,
            task_id=fixture.coverage_task_id(normal_test_id),
        )
        (
            _foreign_api,
            _foreign_application,
            foreign_probe,
            foreign_target,
        ) = fixture.production_runtime("normal", profile_id=foreign_profile_id)
        try:
            original_evidence = attack_probe.resolve_category_evidence(
                attack_probe.task_id, "normal",
            )
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=attack_application,
                task_application=attack_probe.task_application,
                repository=attack_probe.repository,
                object_repository=attack_probe.objects,
                runtime=attack_probe.runtime,
            )
            candidate = fixture.mandatory_candidate(
                "normal",
                profile_id=profile_id,
                task_id=fixture.coverage_task_id(normal_test_id),
            )
            for attack, changed in (
                (
                    "cross-profile-coherent-evidence",
                    foreign_probe.resolve_category_evidence(
                        foreign_probe.task_id, "normal",
                    ),
                ),
                (
                    "cross-column-coherent-evidence",
                    attack_probe.resolve_category_evidence(
                        attack_probe.task_id, "boundary",
                    ),
                ),
            ):
                changed["column_id"] = "normal"
                fixture.category.resign_column_evidence(changed)
                attack_probe.replace_category_evidence_for("normal", changed)
                before_state = fixture._serial_state_signature(
                    attack_probe, attack_target, real_e2e=False,
                )
                before_candidate = copy.deepcopy(candidate)
                issued: list[object] = []
                with self.subTest(
                    stable_id=normal_test_id,
                    profile_id=profile_id,
                    attack=attack,
                ), self.assertRaises(api4.ProfileCoverageError):
                    issued.append(authority.execute_rejection(
                        normal_test_id,
                        candidate=candidate,
                        observer=attack_target,
                    ))
                self.assertEqual(issued, [])
                self.assertEqual(
                    fixture._serial_state_signature(
                        attack_probe, attack_target, real_e2e=False,
                    ),
                    before_state,
                )
                self.assertEqual(candidate, before_candidate)
                attack_probe.replace_category_evidence_for(
                    "normal", original_evidence,
                )

            fixture.install_mandatory_rejection_source(attack_probe, "normal")
            changed_request = fixture.mandatory_candidate(
                "normal",
                profile_id=profile_id,
                task_id=fixture.coverage_task_id(normal_test_id),
            )
            changed_request["request_id"] = (
                f"wp08-s3:{profile_id}:normal:foreign"
            )
            before_state = fixture._serial_state_signature(
                attack_probe, attack_target, real_e2e=False,
            )
            before_candidate = copy.deepcopy(changed_request)
            issued = []
            with self.subTest(
                stable_id=normal_test_id,
                profile_id=profile_id,
                attack="same-id-different-request",
            ), self.assertRaises(api4.ProfileCoverageError):
                issued.append(authority.execute_rejection(
                    normal_test_id,
                    candidate=changed_request,
                    observer=attack_target,
                ))
            self.assertEqual(issued, [])
            self.assertEqual(
                fixture._serial_state_signature(
                    attack_probe, attack_target, real_e2e=False,
                ),
                before_state,
            )
            self.assertEqual(changed_request, before_candidate)
        finally:
            foreign_target.close()
            attack_target.close()

        revise_test_id = fixture.profile_mandatory_test_id(
            profile_id, "revise", "R",
        )
        (
            _source_api,
            source_application,
            source_probe,
            source_target,
        ) = fixture.production_runtime(
            "revise",
            profile_id=profile_id,
            task_id=fixture.coverage_task_id(revise_test_id),
        )
        try:
            source = source_probe.resolve_category_source(
                "category-revision-record-v1",
            )
            source["owner_route"] = "owner:foreign"
            fixture.category.resign_durable_record(source)
            source_probe.replace_category_source(
                "category-revision-record-v1", source,
            )
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=source_application,
                task_application=source_probe.task_application,
                repository=source_probe.repository,
                object_repository=source_probe.objects,
                runtime=source_probe.runtime,
            )
            candidate = fixture.mandatory_candidate(
                "revise",
                profile_id=profile_id,
                task_id=fixture.coverage_task_id(revise_test_id),
            )
            before_state = fixture._serial_state_signature(
                source_probe, source_target, real_e2e=False,
            )
            before_candidate = copy.deepcopy(candidate)
            issued = []
            with self.subTest(
                stable_id=revise_test_id,
                profile_id=profile_id,
                attack="coherent-source-substitution",
            ), self.assertRaises(api4.ProfileCoverageError):
                issued.append(authority.execute_rejection(
                    revise_test_id,
                    candidate=candidate,
                    observer=source_target,
                ))
            self.assertEqual(issued, [])
            self.assertEqual(
                fixture._serial_state_signature(
                    source_probe, source_target, real_e2e=False,
                ),
                before_state,
            )
            self.assertEqual(candidate, before_candidate)
        finally:
            source_target.close()

    def test_gew_wp08_s4_production_coverage_p(self) -> None:
        """GEW-WP08-S4-PRODUCTION-COVERAGE-P."""

        dependency_fixture.load_slice_b_api()
        api4 = fixture.load_slice4_api()
        api, coverage, matrix, profile, overlay = self._profile_contracts()
        category_api, application, probe, target = fixture.production_runtime(
            task_id=fixture.coverage_task_id(fixture.PASS_TEST_ID),
        )
        candidate = fixture.category.candidate_document("new-feature", "normal")
        candidate["task_id"] = fixture.coverage_task_id(fixture.PASS_TEST_ID)
        before_candidate = copy.deepcopy(candidate)
        try:
            receipt = application.assess_and_commit(candidate, observer=target)
            self.assertIs(type(receipt.assessment), category_api.CategoryCompletionAssessment)
            plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
            with self.subTest(
                stable_id="WP08-DEP-OPTION1-DOCS-ARCH-R1-001",
                phase="installed-additive-offline-v2-provenance",
            ):
                required = tuple(
                    dependency_fixture.ROOT / path
                    for path in (
                        "config/security/dependency-advisory-registry-v2.json",
                        "config/security/dependency-advisory-source-v2.json",
                        "config/security/dependency-advisory-source-attestation-v2.json",
                        "config/security/dependency-advisory-installation-bootstrap-v1.2.json",
                        "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.2.0.json",
                        "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.2.0.json",
                    )
                )
                self.assertEqual(
                    tuple(
                        str(path.relative_to(dependency_fixture.ROOT))
                        for path in required if not path.is_file()
                    ),
                    (),
                )
                self.assertEqual(
                    tuple(
                        hashlib.sha256(
                            (dependency_fixture.ROOT / path).read_bytes()
                        ).hexdigest()
                        for path in (
                            "config/security/dependency-advisory-registry-v1.json",
                            "config/security/dependency-advisory-source-v1.json",
                            "config/security/dependency-advisory-source-attestation-v1.json",
                            "config/security/dependency-advisory-installation-bootstrap-v1.json",
                            "config/security/dependency-advisory-installation-bootstrap-v1.1.json",
                            "config/contracts/schemas/dependency-advisory-installation-bootstrap-1.1.0.json",
                            "config/contracts/schemas/dependency-advisory-installation-bootstrap-input-1.1.0.json",
                        )
                    ),
                    (
                        "c8f085a572c97b63758d6ad60efc318e1f1659e18f4ffe08ab4b006c4476f0b2",
                        "2a992cbaaa6e68f668ba3ae7673a2de5cdd15cb501b00ca01272ed2842d7867e",
                        "79034ebc3eafd88c5d660837a2380d1785b5f79bda4c4ea79e2cfaa410391d89",
                        "ed7beba6ce8754dde49bb9a8fb6c149b72f51b2e937e692af4d83d51828ff09e",
                        "fb343c66de46daca5438aca54745492e637cfc558fc217b5818bb620b9920b76",
                        "c58227b079a123399565fa7f797de9b9459e58234bf2119a670033800c4562af",
                        "25f067e11664c78881bfeb6f79a3858dccf43562a4414d904bd1985b7f6c7ce9",
                    ),
                )
            with self.subTest(
                stable_id="GEW-PSC-DEPENDENCY-SECURITY-GRAPH-SLICEB",
                phase="installed-dependency-graph-scenario-bindings",
            ):
                dependency_graph_ids = (
                    "GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P",
                    "GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-R",
                    "GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P",
                    "GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-R",
                )
                self.assertEqual(
                    tuple(
                        test_id for test_id in dependency_graph_ids
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(len(plan.bindings), 220)
                self.assertEqual(len(plan.oracle_bindings), 110)
                self.assertIn(
                    "dependency-graph-scenarios-r1",
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id="GEW-PSC-MIGRATION-SLICEB",
                phase="installed-migration-scenario-bindings",
            ):
                self.assertEqual(
                    tuple(
                        test_id for test_id in fixture.MIGRATION_SCENARIO_TEST_IDS
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(len(plan.bindings), 220)
                self.assertEqual(len(plan.oracle_bindings), 110)
                self.assertIn(
                    fixture.MIGRATION_SCENARIOS_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id=(
                    fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID
                ),
                phase="installed-dependency-vulnerable-graph-bindings",
            ):
                self.assertEqual(
                    tuple(
                        test_id
                        for test_id in (
                            fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID,
                            fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID,
                        )
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(len(plan.bindings), 220)
                self.assertEqual(len(plan.oracle_bindings), 110)
                self.assertIn(
                    fixture.VULNERABLE_GRAPH_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id=fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
                phase="installed-performance-stable-baseline-bindings",
            ):
                self.assertEqual(
                    tuple(
                        test_id
                        for test_id in (
                            fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
                            fixture.PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID,
                        )
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(len(plan.bindings), 220)
                self.assertEqual(len(plan.oracle_bindings), 110)
                self.assertIn(
                    fixture.STABLE_BASELINE_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            expected_dependency_security_ids = tuple(sorted(
                dependency_fixture.dependency_security_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            self.assertEqual(
                tuple(
                    test_id for test_id in expected_dependency_security_ids
                    if test_id not in plan.bindings
                ),
                (),
            )
            expected_performance_ids = tuple(sorted(
                fixture.performance_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            self.assertEqual(
                tuple(
                    test_id for test_id in expected_performance_ids
                    if test_id not in plan.bindings
                ),
                (),
            )
            expected_incident_ids = tuple(sorted(
                fixture.incident_response_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            expected_migration_ids = tuple(sorted(
                fixture.migration_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            with self.subTest(
                phase="installed-incident-response-bindings",
            ):
                self.assertEqual(
                    tuple(
                        test_id for test_id in expected_incident_ids
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(
                    tuple(
                        test_id for test_id in expected_migration_ids
                        if test_id not in plan.bindings
                    ),
                    (),
                )
            with self.subTest(
                finding="WP08-S4-TASK-IDENTITY",
                phase="closed-per-binding-task-identities",
            ):
                task_ids = tuple(
                    plan.binding(test_id)["task_id"]
                    for test_id in sorted(plan.bindings)
                )
                self.assertEqual(len(task_ids), 220)
                self.assertEqual(len(task_ids), len(set(task_ids)))
                for test_id, task_id in zip(
                    sorted(plan.bindings), task_ids, strict=True,
                ):
                    binding = plan.binding(test_id)
                    oracle = plan.oracle_for(test_id)
                    self.assertEqual(task_id, fixture.coverage_task_id(test_id))
                    self.assertEqual(
                        oracle["task_ids"][binding["disposition"]], task_id,
                    )
            for column in fixture.BUG_FIX_COLUMNS:
                for disposition in ("P", "R"):
                    test_id = fixture.bug_fix_test_id(column, disposition)
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-bug-fix-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(binding["profile_id"], "bug-fix")
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target" if column == "real-e2e" else "contract-test",
                        )
                        self.assertEqual(
                            binding["expected_result"],
                            "COMPLETED" if disposition == "P" else "EXPECTED_REJECTION",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(oracle["oracle_id"], "ORA-PROFILE-BUG-FIX")
                        self.assertEqual(oracle["profile_id"], "bug-fix")
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    test_id = fixture.hotfix_test_id(column, disposition)
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-hotfix-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(binding["profile_id"], "hotfix")
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target" if column == "real-e2e" else "contract-test",
                        )
                        self.assertEqual(
                            binding["expected_result"],
                            "COMPLETED" if disposition == "P" else "EXPECTED_REJECTION",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(oracle["oracle_id"], "ORA-PROFILE-HOTFIX")
                        self.assertEqual(oracle["profile_id"], "hotfix")
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            with self.subTest(stable_id=fixture.REAL_E2E_PASS_TEST_ID, phase="installed-binding"):
                real_e2e = plan.binding(fixture.REAL_E2E_PASS_TEST_ID)
                self.assertEqual(real_e2e["selector_kind"], "mandatory")
                self.assertEqual(real_e2e["profile_id"], "new-feature")
                self.assertEqual(real_e2e["column_id"], "real-e2e")
                self.assertEqual(real_e2e["overlay_id"], "full-planned")
                self.assertEqual(real_e2e["execution_kind"], "real-target")
                self.assertEqual(real_e2e["disposition"], "P")
                self.assertIsNone(real_e2e["request_digest"])
            for column in fixture.NEW_MANDATORY_COLUMNS:
                test_id = fixture.mandatory_test_id(column, "P")
                with self.subTest(stable_id=test_id, phase="installed-binding"):
                    binding = plan.binding(test_id)
                    self.assertEqual(binding["selector_kind"], "mandatory")
                    self.assertEqual(binding["column_id"], column)
                    self.assertEqual(binding["disposition"], "P")
                    self.assertIsNone(binding["scenario_id"])
                    self.assertIsNone(binding["category_boundary_case_id"])
                    self.assertIsNone(binding["request_digest"])
            with self.subTest(stable_id=fixture.SCAFFOLD_PASS_TEST_ID):
                scaffold_binding = plan.binding(fixture.SCAFFOLD_PASS_TEST_ID)
                self.assertEqual(scaffold_binding["selector_kind"], "scenario")
                self.assertEqual(scaffold_binding["profile_id"], "new-feature")
                self.assertEqual(scaffold_binding["column_id"], "boundary")
                self.assertEqual(
                    scaffold_binding["scenario_id"], fixture.SCAFFOLD_SCENARIO_ID,
                )
                self.assertEqual(
                    scaffold_binding["category_boundary_case_id"],
                    fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                )
                self.assertEqual(scaffold_binding["overlay_id"], "full-planned")
                self.assertEqual(scaffold_binding["disposition"], "P")
                self.assertIsNone(scaffold_binding["request_digest"])
                for mandatory_id in (
                    fixture.PASS_TEST_ID,
                    fixture.REJECT_TEST_ID,
                    fixture.ROLLBACK_PASS_TEST_ID,
                    fixture.ROLLBACK_REJECT_TEST_ID,
                ):
                    mandatory = plan.binding(mandatory_id)
                    self.assertEqual(mandatory["selector_kind"], "mandatory")
                    self.assertIsNone(mandatory["scenario_id"])
                    self.assertIsNone(mandatory["category_boundary_case_id"])
            with self.subTest(stable_id=fixture.EXISTING_FEATURE_PASS_TEST_ID):
                existing_feature = plan.binding(
                    fixture.EXISTING_FEATURE_PASS_TEST_ID
                )
                self.assertEqual(existing_feature["selector_kind"], "scenario")
                self.assertEqual(existing_feature["profile_id"], "new-feature")
                self.assertEqual(existing_feature["column_id"], "boundary")
                self.assertEqual(
                    existing_feature["scenario_id"],
                    fixture.EXISTING_FEATURE_SCENARIO_ID,
                )
                self.assertEqual(
                    existing_feature["category_boundary_case_id"],
                    fixture.EXISTING_FEATURE_BOUNDARY_CASE_ID,
                )
                self.assertEqual(existing_feature["overlay_id"], "full-planned")
                self.assertEqual(existing_feature["execution_kind"], "contract-test")
                self.assertEqual(existing_feature["disposition"], "P")
                self.assertEqual(existing_feature["expected_result"], "COMPLETED")
                self.assertIsNone(existing_feature["request_digest"])
            with self.subTest(
                stable_id=fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
            ):
                reproducible_failure = plan.binding(
                    fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
                )
                self.assertEqual(
                    (
                        reproducible_failure["profile_id"],
                        reproducible_failure["selector_kind"],
                        reproducible_failure["column_id"],
                        reproducible_failure["scenario_id"],
                        reproducible_failure["category_boundary_case_id"],
                        reproducible_failure["overlay_id"],
                        reproducible_failure["execution_kind"],
                        reproducible_failure["disposition"],
                        reproducible_failure["expected_result"],
                        reproducible_failure["task_id"],
                        reproducible_failure["request_digest"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "P",
                        "COMPLETED",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID
                        ),
                        None,
                    ),
                )
            with self.subTest(
                stable_id=fixture.BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID,
            ):
                false_reproduction = plan.binding(
                    fixture.BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID
                )
                self.assertEqual(
                    (
                        false_reproduction["profile_id"],
                        false_reproduction["selector_kind"],
                        false_reproduction["column_id"],
                        false_reproduction["scenario_id"],
                        false_reproduction["category_boundary_case_id"],
                        false_reproduction["overlay_id"],
                        false_reproduction["execution_kind"],
                        false_reproduction["disposition"],
                        false_reproduction["expected_result"],
                        false_reproduction["task_id"],
                        false_reproduction["request_digest"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID,
                        fixture.BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "P",
                        "COMPLETED",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID
                        ),
                        None,
                    ),
                )
                self.assertIn(
                    fixture.FALSE_REPRODUCTION_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id=fixture.BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID,
            ):
                regression_boundary = plan.binding(
                    fixture.BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID
                )
                self.assertEqual(
                    (
                        regression_boundary["profile_id"],
                        regression_boundary["selector_kind"],
                        regression_boundary["column_id"],
                        regression_boundary["scenario_id"],
                        regression_boundary["category_boundary_case_id"],
                        regression_boundary["overlay_id"],
                        regression_boundary["execution_kind"],
                        regression_boundary["disposition"],
                        regression_boundary["expected_result"],
                        regression_boundary["task_id"],
                        regression_boundary["request_digest"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID,
                        fixture.BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "P",
                        "COMPLETED",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID
                        ),
                        None,
                    ),
                )
                self.assertIn(
                    fixture.REGRESSION_BOUNDARY_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(stable_id=fixture.HOTFIX_MINIMAL_PATCH_PASS_TEST_ID):
                minimal_patch = plan.binding(
                    fixture.HOTFIX_MINIMAL_PATCH_PASS_TEST_ID
                )
                self.assertEqual(
                    (
                        minimal_patch["profile_id"],
                        minimal_patch["selector_kind"],
                        minimal_patch["column_id"],
                        minimal_patch["scenario_id"],
                        minimal_patch["category_boundary_case_id"],
                        minimal_patch["overlay_id"],
                        minimal_patch["execution_kind"],
                        minimal_patch["disposition"],
                        minimal_patch["expected_result"],
                        minimal_patch["task_id"],
                        minimal_patch["request_digest"],
                    ),
                    (
                        "hotfix",
                        "scenario",
                        "boundary",
                        fixture.HOTFIX_MINIMAL_PATCH_SCENARIO_ID,
                        fixture.HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "P",
                        "COMPLETED",
                        fixture.coverage_task_id(
                            fixture.HOTFIX_MINIMAL_PATCH_PASS_TEST_ID
                        ),
                        None,
                    ),
                )
                self.assertIn(
                    fixture.MINIMAL_PATCH_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id=fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
            ):
                stable_baseline = plan.binding(
                    fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID
                )
                self.assertEqual(
                    tuple(stable_baseline[field] for field in (
                        "profile_id", "selector_kind", "column_id", "scenario_id",
                        "category_boundary_case_id", "overlay_id", "execution_kind",
                        "disposition", "expected_result", "task_id", "request_digest",
                    )),
                    (
                        "performance", "scenario", "boundary",
                        fixture.PERFORMANCE_STABLE_BASELINE_SCENARIO_ID,
                        fixture.PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID,
                        "full-planned", "contract-test", "P", "COMPLETED",
                        fixture.coverage_task_id(
                            fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID
                        ),
                        None,
                    ),
                )
            with self.subTest(stable_id=fixture.ROLLBACK_PASS_TEST_ID):
                rollback_binding = plan.binding(fixture.ROLLBACK_PASS_TEST_ID)
                self.assertEqual(rollback_binding["profile_id"], "new-feature")
                self.assertEqual(rollback_binding["column_id"], "rollback")
                self.assertEqual(rollback_binding["disposition"], "P")
                self.assertEqual(
                    tuple(
                        (
                            item["oracle_id"],
                            item["profile_id"],
                            item["selector_kind"],
                            item["column_id"],
                            item["scenario_id"],
                        )
                        for item in plan.oracle_bindings
                    ),
                    fixture.expected_oracle_binding_identities(),
                )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    test_id = fixture.refactor_debt_test_id(
                        column, disposition,
                    )
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-refactor-debt-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(binding["profile_id"], "refactor-debt")
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target"
                            if column == "real-e2e"
                            else "contract-test",
                        )
                        self.assertEqual(
                            binding["expected_result"],
                            "COMPLETED"
                            if disposition == "P"
                            else "EXPECTED_REJECTION",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(
                            oracle["oracle_id"],
                            "ORA-PROFILE-REFACTOR-DEBT",
                        )
                        self.assertEqual(oracle["profile_id"], "refactor-debt")
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    test_id = dependency_fixture.dependency_security_test_id(
                        column, disposition,
                    )
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-dependency-security-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(
                            binding["profile_id"], "dependency-security",
                        )
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target"
                            if column == "real-e2e"
                            else "contract-test",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(
                            oracle["oracle_id"],
                            "ORA-PROFILE-DEPENDENCY-SECURITY",
                        )
                        self.assertEqual(
                            oracle["profile_id"], "dependency-security",
                        )
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    test_id = fixture.migration_test_id(column, disposition)
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-migration-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(binding["profile_id"], "migration")
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target"
                            if column == "real-e2e"
                            else "contract-test",
                        )
                        self.assertEqual(
                            binding["expected_result"],
                            "COMPLETED"
                            if disposition == "P"
                            else "EXPECTED_REJECTION",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(
                            oracle["oracle_id"], "ORA-PROFILE-MIGRATION",
                        )
                        self.assertEqual(oracle["profile_id"], "migration")
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    test_id = fixture.incident_response_test_id(
                        column, disposition,
                    )
                    with self.subTest(
                        stable_id=test_id,
                        phase="installed-incident-response-binding",
                    ):
                        binding = plan.binding(test_id)
                        self.assertEqual(
                            binding["profile_id"], "incident-response",
                        )
                        self.assertEqual(binding["selector_kind"], "mandatory")
                        self.assertEqual(binding["column_id"], column)
                        self.assertIsNone(binding["scenario_id"])
                        self.assertIsNone(binding["category_boundary_case_id"])
                        self.assertEqual(binding["overlay_id"], "full-planned")
                        self.assertEqual(binding["disposition"], disposition)
                        self.assertEqual(
                            binding["execution_kind"],
                            "real-target"
                            if column == "real-e2e"
                            else "contract-test",
                        )
                        self.assertEqual(
                            binding["expected_result"],
                            "COMPLETED"
                            if disposition == "P"
                            else "EXPECTED_REJECTION",
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(
                            oracle["oracle_id"],
                            "ORA-PROFILE-INCIDENT-RESPONSE",
                        )
                        self.assertEqual(
                            oracle["profile_id"], "incident-response",
                        )
                        self.assertEqual(oracle["column_id"], column)
                        self.assertEqual(oracle["selector_kind"], "mandatory")
            _hotfix_api, _hotfix_coverage, _hotfix_matrix, hotfix_profile, hotfix_overlay = (
                self._profile_contracts("hotfix")
            )
            self.assertFalse(
                (
                    fixture.category.ROOT
                    / "tests/fixtures/wp08-coverage-harness-v1.json"
                ).exists()
            )
            for removed_parallel_api in (
                "run_canonical_profile_batch",
                "reissue_batch_for_serial_observation",
                "CanonicalCoverageBatch",
                "CanonicalCoverageWorkerError",
            ):
                self.assertFalse(hasattr(fixture, removed_parallel_api))
            hotfix_positive_results: list[fixture.SerialCoverageExecution] = []
            hotfix_shared = fixture.category.shared_production_category_runtime(
                "hotfix"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    hotfix_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="hotfix",
                            column=column,
                            disposition="P",
                            shared_runtime=hotfix_shared,
                        )
                    )
                hotfix_positive_results.sort(key=lambda item: item.test_id)
                self.assertEqual(len(hotfix_positive_results), 12)
                hotfix_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority
                        for result in hotfix_positive_results
                    ),
                    coverage_policy=coverage,
                )
                hotfix_records = tuple(
                    hotfix_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=hotfix_profile,
                        overlay=hotfix_overlay,
                    )
                    for result in hotfix_positive_results
                )
                self.assertEqual(
                    tuple(record.test_id for record in hotfix_records),
                    tuple(sorted(
                        fixture.hotfix_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                hotfix_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=hotfix_records,
                    coverage_factory=hotfix_factory,
                )
                self.assertFalse(hotfix_decision.passed)
                self.assertEqual(len(hotfix_decision.missing_test_ids), 262)
                fixture.abort_uncommitted_coverage_factory(hotfix_factory)
                for result in hotfix_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(hotfix_positive_results):
                    result.close()
                hotfix_shared.close()
            (
                _refactor_api,
                _refactor_coverage,
                _refactor_matrix,
                refactor_profile,
                refactor_overlay,
            ) = self._profile_contracts("refactor-debt")
            refactor_positive_results: list[fixture.SerialCoverageExecution] = []
            refactor_shared = fixture.category.shared_production_category_runtime(
                "refactor-debt"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    refactor_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="refactor-debt",
                            column=column,
                            disposition="P",
                            shared_runtime=refactor_shared,
                        )
                    )
                refactor_positive_results.sort(key=lambda item: item.test_id)
                refactor_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority for result in refactor_positive_results
                    ),
                    coverage_policy=coverage,
                )
                refactor_records = tuple(
                    refactor_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=refactor_profile,
                        overlay=refactor_overlay,
                    )
                    for result in refactor_positive_results
                )
                self.assertEqual(len(refactor_records), 12)
                self.assertEqual(
                    tuple(record.test_id for record in refactor_records),
                    tuple(sorted(
                        fixture.refactor_debt_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                fixture.abort_uncommitted_coverage_factory(refactor_factory)
                for result in refactor_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(refactor_positive_results):
                    result.close()
                refactor_shared.close()
            (
                _incident_api,
                _incident_coverage,
                _incident_matrix,
                incident_profile,
                incident_overlay,
            ) = self._profile_contracts("incident-response")
            incident_positive_results: list[fixture.SerialCoverageExecution] = []
            incident_shared = fixture.category.shared_production_category_runtime(
                "incident-response"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    incident_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="incident-response",
                            column=column,
                            disposition="P",
                            shared_runtime=incident_shared,
                        )
                    )
                incident_positive_results.sort(key=lambda item: item.test_id)
                incident_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority for result in incident_positive_results
                    ),
                    coverage_policy=coverage,
                )
                incident_records = tuple(
                    incident_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=incident_profile,
                        overlay=incident_overlay,
                    )
                    for result in incident_positive_results
                )
                self.assertEqual(len(incident_records), 12)
                self.assertEqual(
                    tuple(record.test_id for record in incident_records),
                    tuple(sorted(
                        fixture.incident_response_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                incident_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=incident_records,
                    coverage_factory=incident_factory,
                )
                self.assertFalse(incident_decision.passed)
                self.assertEqual(len(incident_decision.missing_test_ids), 262)
                fixture.abort_uncommitted_coverage_factory(incident_factory)
                for result in incident_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(incident_positive_results):
                    result.close()
                incident_shared.close()
            (
                _migration_api,
                _migration_coverage,
                _migration_matrix,
                migration_profile,
                migration_overlay,
            ) = self._profile_contracts("migration")
            migration_positive_results: list[
                fixture.SerialCoverageExecution
            ] = []
            migration_shared = fixture.category.shared_production_category_runtime(
                "migration"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    migration_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="migration",
                            column=column,
                            disposition="P",
                            shared_runtime=migration_shared,
                        )
                    )
                migration_positive_results.sort(key=lambda item: item.test_id)
                migration_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority for result in migration_positive_results
                    ),
                    coverage_policy=coverage,
                )
                migration_records = tuple(
                    migration_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=migration_profile,
                        overlay=migration_overlay,
                    )
                    for result in migration_positive_results
                )
                self.assertEqual(len(migration_records), 12)
                self.assertEqual(
                    tuple(record.test_id for record in migration_records),
                    tuple(sorted(
                        fixture.migration_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                migration_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=migration_records,
                    coverage_factory=migration_factory,
                )
                self.assertFalse(migration_decision.passed)
                self.assertEqual(len(migration_decision.missing_test_ids), 262)
                migration_real = next(
                    result for result in migration_positive_results
                    if result.column_id == "real-e2e"
                )
                migration_mandatory_assessment = (
                    migration_real.application.current_assessment(
                        migration_real.probe.task_id,
                        expected_profile_id="migration",
                    )
                )
                self.assertIsNotNone(migration_mandatory_assessment)
                self.assertIsNone(
                    migration_mandatory_assessment.migration_rehearsal_projection
                )
                restarted_task, restarted_runtime = (
                    migration_real.probe.restart_authorities()
                )
                restarted_application = migration_real.application.restart(
                    restarted_task,
                    restarted_runtime,
                    migration_real.target,
                )
                self.assertIsNone(
                    restarted_application._oracle._migration_rehearsal_factory
                )
                restarted_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=restarted_application,
                    task_application=restarted_task,
                    repository=migration_real.probe.repository,
                    object_repository=migration_real.probe.objects,
                    runtime=restarted_runtime,
                )
                restored = restarted_authority.observe_completion(
                    migration_real.test_id,
                    task_id=migration_real.probe.task_id,
                    expected_profile_id="migration",
                )
                self.assertEqual(
                    restored.execution_digest,
                    migration_real.execution.execution_digest,
                )
                self.assertEqual(
                    migration_real.probe.real_e2e_adapter.mutation_count, 1,
                )
                fixture.abort_uncommitted_coverage_factory(migration_factory)
                for result in migration_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(migration_positive_results):
                    result.close()
                migration_shared.close()
            (
                _dependency_api,
                _dependency_coverage,
                _dependency_matrix,
                dependency_profile,
                dependency_overlay,
            ) = self._profile_contracts("dependency-security")
            dependency_positive_results: list[
                fixture.SerialCoverageExecution
            ] = []
            dependency_shared = fixture.category.shared_production_category_runtime(
                "dependency-security"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    dependency_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="dependency-security",
                            column=column,
                            disposition="P",
                            shared_runtime=dependency_shared,
                        )
                    )
                dependency_positive_results.sort(key=lambda item: item.test_id)
                dependency_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority for result in dependency_positive_results
                    ),
                    coverage_policy=coverage,
                )
                dependency_records = tuple(
                    dependency_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=dependency_profile,
                        overlay=dependency_overlay,
                    )
                    for result in dependency_positive_results
                )
                self.assertEqual(len(dependency_records), 12)
                self.assertEqual(
                    tuple(record.test_id for record in dependency_records),
                    tuple(sorted(
                        dependency_fixture.dependency_security_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                dependency_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=dependency_records,
                    coverage_factory=dependency_factory,
                )
                self.assertFalse(dependency_decision.passed)
                self.assertEqual(len(dependency_decision.missing_test_ids), 262)
                dependency_real = next(
                    result for result in dependency_positive_results
                    if result.column_id == "real-e2e"
                )
                restarted_task, restarted_runtime = (
                    dependency_real.probe.restart_authorities()
                )
                restarted_application = dependency_real.application.restart(
                    restarted_task,
                    restarted_runtime,
                    dependency_real.target,
                )
                restarted_assessment = restarted_application.current_assessment(
                    dependency_real.probe.task_id,
                    expected_profile_id="dependency-security",
                )
                restarted_dependency_factory = (
                    restarted_application._oracle._dependency_graph_factory
                )
                self.assertIsNotNone(restarted_assessment)
                self.assertIsNotNone(restarted_dependency_factory)
                self.assertIsNot(
                    restarted_dependency_factory,
                    dependency_real.application._oracle._dependency_graph_factory,
                )
                self.assertIsNotNone(
                    restarted_assessment._dependency_graph_evidence
                )
                restarted_dependency = (
                    restarted_dependency_factory,
                    restarted_assessment._dependency_graph_evidence,
                )
                restarted_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=restarted_application,
                    task_application=restarted_task,
                    repository=dependency_real.probe.repository,
                    object_repository=dependency_real.probe.objects,
                    runtime=restarted_runtime,
                    dependency_security=restarted_dependency,
                )
                restored = restarted_authority.observe_completion(
                    dependency_real.test_id,
                    task_id=dependency_real.probe.task_id,
                    expected_profile_id="dependency-security",
                )
                self.assertEqual(
                    restored.execution_digest,
                    dependency_real.execution.execution_digest,
                )
                self.assertEqual(
                    dependency_real.probe.real_e2e_adapter.mutation_count, 1,
                )
                fixture.abort_uncommitted_coverage_factory(dependency_factory)
                for result in dependency_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(dependency_positive_results):
                    result.close()
                dependency_shared.close()
            (
                _performance_api,
                _performance_coverage,
                _performance_matrix,
                performance_profile,
                performance_overlay,
            ) = self._profile_contracts("performance")
            performance_positive_results: list[
                fixture.SerialCoverageExecution
            ] = []
            performance_shared = fixture.category.shared_production_category_runtime(
                "performance"
            )
            try:
                for column in fixture.approved_mandatory_columns():
                    performance_positive_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="performance",
                            column=column,
                            disposition="P",
                            shared_runtime=performance_shared,
                        )
                    )
                performance_positive_results.sort(key=lambda item: item.test_id)
                performance_factory = api.CoverageRecordFactory(
                    execution_authority=tuple(
                        result.authority
                        for result in performance_positive_results
                    ),
                    coverage_policy=coverage,
                )
                performance_records = tuple(
                    performance_factory.issue_execution(
                        result.authority.observe(result.execution),
                        matrix=matrix,
                        profile=performance_profile,
                        overlay=performance_overlay,
                    )
                    for result in performance_positive_results
                )
                self.assertEqual(len(performance_records), 12)
                self.assertEqual(
                    tuple(record.test_id for record in performance_records),
                    tuple(sorted(
                        fixture.performance_test_id(column, "P")
                        for column in fixture.approved_mandatory_columns()
                    )),
                )
                performance_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=performance_records,
                    coverage_factory=performance_factory,
                )
                self.assertFalse(performance_decision.passed)
                self.assertEqual(len(performance_decision.missing_test_ids), 262)
                performance_real = next(
                    result for result in performance_positive_results
                    if result.column_id == "real-e2e"
                )
                launches_before_restart = (
                    performance_real.performance_context.launcher.launch_count
                )
                restarted_task, restarted_runtime = (
                    performance_real.probe.restart_authorities()
                )
                restarted_application = performance_real.application.restart(
                    restarted_task,
                    restarted_runtime,
                    performance_real.target,
                )
                restarted_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=restarted_application,
                    task_application=restarted_task,
                    repository=performance_real.probe.repository,
                    object_repository=performance_real.probe.objects,
                    runtime=restarted_runtime,
                )
                restored = restarted_authority.observe_completion(
                    performance_real.test_id,
                    task_id=performance_real.probe.task_id,
                    expected_profile_id="performance",
                )
                self.assertEqual(
                    restored.execution_digest,
                    performance_real.execution.execution_digest,
                )
                self.assertEqual(
                    performance_real.performance_context.launcher.launch_count,
                    launches_before_restart,
                )
                self.assertEqual(
                    performance_real.probe.real_e2e_adapter.mutation_count, 1,
                )
                fixture.abort_uncommitted_coverage_factory(performance_factory)
                for result in performance_positive_results:
                    result.retain_gate_context()
            finally:
                for result in reversed(performance_positive_results):
                    result.close()
                performance_shared.close()
            _bug_api, _bug_coverage, _bug_matrix, bug_profile, bug_overlay = (
                self._profile_contracts("bug-fix")
            )
            for column in fixture.BUG_FIX_COLUMNS:
                if column == "real-e2e":
                    continue
                test_id = fixture.bug_fix_test_id(column, "P")
                (
                    bug_category_api,
                    bug_application,
                    bug_probe,
                    bug_target,
                ) = fixture.production_runtime(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(test_id),
                )
                bug_candidate = fixture.mandatory_candidate(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(test_id),
                )
                bug_candidate_before = copy.deepcopy(bug_candidate)
                try:
                    with self.subTest(
                        stable_id=test_id,
                        phase="bug-fix-production-completion",
                    ):
                        bug_receipt = bug_application.assess_and_commit(
                            bug_candidate, observer=bug_target,
                        )
                        self.assertIs(
                            type(bug_receipt.assessment),
                            bug_category_api.CategoryCompletionAssessment,
                        )
                        oracle = plan.oracle_for(test_id)
                        typed = bug_probe.resolve_category_evidence(
                            bug_probe.task_id, column,
                        )
                        self.assertEqual(typed["evidence_kind"], oracle["evidence_kind"])
                        self.assertEqual(typed["outcome"], oracle["required_outcome"])
                        self.assertEqual(
                            tuple(sorted(typed["facts"])),
                            tuple(oracle["required_fact_ids"]),
                        )
                        bug_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=bug_application,
                            task_application=bug_probe.task_application,
                            repository=bug_probe.repository,
                            object_repository=bug_probe.objects,
                            runtime=bug_probe.runtime,
                        )
                        bug_execution = bug_authority.observe_completion(
                            test_id,
                            task_id=bug_probe.task_id,
                            expected_profile_id="bug-fix",
                        )
                        bug_factory = api.CoverageRecordFactory(
                            execution_authority=bug_authority,
                            coverage_policy=coverage,
                        )
                        bug_record = bug_factory.issue_execution(
                            bug_authority.observe(bug_execution),
                            matrix=matrix,
                            profile=bug_profile,
                            overlay=bug_overlay,
                        )
                        self.assertEqual(bug_record.test_id, test_id)
                        self.assertEqual(bug_record.profile_id, "bug-fix")
                        self.assertEqual(bug_candidate, bug_candidate_before)
                        fixture.abort_uncommitted_coverage_factory(bug_factory)
                finally:
                    bug_target.close()
            for column in fixture.NEW_MANDATORY_COLUMNS:
                test_id = fixture.mandatory_test_id(column, "P")
                (
                    column_api,
                    column_application,
                    column_probe,
                    column_target,
                ) = fixture.production_runtime(
                    column, task_id=fixture.coverage_task_id(test_id),
                )
                column_candidate = fixture.mandatory_candidate(
                    column, task_id=fixture.coverage_task_id(test_id),
                )
                column_candidate_before = copy.deepcopy(column_candidate)
                try:
                    with self.subTest(stable_id=test_id, phase="production-completion"):
                        column_receipt = column_application.assess_and_commit(
                            column_candidate,
                            observer=column_target,
                        )
                        self.assertIs(
                            type(column_receipt.assessment),
                            column_api.CategoryCompletionAssessment,
                        )
                        self.assertEqual(column_receipt.assessment.column_id, column)
                        typed = column_probe.resolve_category_evidence(
                            column_probe.task_id, column,
                        )
                        oracle = plan.oracle_for(test_id)
                        self.assertEqual(typed["evidence_kind"], oracle["evidence_kind"])
                        self.assertEqual(typed["outcome"], oracle["required_outcome"])
                        self.assertEqual(
                            tuple(sorted(typed["facts"])),
                            tuple(oracle["required_fact_ids"]),
                        )
                        column_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=column_application,
                            task_application=column_probe.task_application,
                            repository=column_probe.repository,
                            object_repository=column_probe.objects,
                            runtime=column_probe.runtime,
                        )
                        column_execution = column_authority.observe_completion(
                            test_id,
                            task_id=column_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                        self.assertEqual(column_execution.column_id, column)
                        self.assertEqual(column_execution.result, "COMPLETED")
                        self.assertEqual(
                            column_execution.column_evidence_digest,
                            column_receipt.assessment.column_evidence_digest,
                        )
                        column_factory = api.CoverageRecordFactory(
                            execution_authority=column_authority,
                            coverage_policy=coverage,
                        )
                        column_record = column_factory.issue_execution(
                            column_authority.observe(column_execution),
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        column_decision = ReleaseCoverageGate.evaluate(
                            matrix,
                            coverage_records=(column_record,),
                            coverage_factory=column_factory,
                        )
                        self.assertFalse(column_decision.passed)
                        self.assertEqual(len(column_decision.missing_test_ids), 273)

                        restarted_task, restarted_runtime = (
                            column_probe.restart_authorities()
                        )
                        restarted_application = column_application.restart(
                            restarted_task,
                            restarted_runtime,
                            column_target,
                        )
                        restarted_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=restarted_application,
                            task_application=restarted_task,
                            repository=column_probe.repository,
                            object_repository=column_probe.objects,
                            runtime=restarted_runtime,
                        )
                        restored = restarted_authority.observe_completion(
                            test_id,
                            task_id=column_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                        self.assertEqual(
                            restored.execution_digest,
                            column_execution.execution_digest,
                        )
                        self.assertEqual(column_candidate, column_candidate_before)
                        fixture.abort_uncommitted_coverage_factory(column_factory)
                finally:
                    column_target.close()
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
            )
            execution = authority.observe_completion(
                fixture.PASS_TEST_ID,
                task_id=probe.task_id,
                expected_profile_id="new-feature",
            )
            self.assertIs(type(execution), api4.ProfileCoverageExecutionRecord)
            self.assertEqual(execution.test_id, fixture.PASS_TEST_ID)
            self.assertEqual(execution.task_revision, receipt.assessment.task_revision + 1)
            self.assertEqual(execution.invalidation_epoch, 0)
            self.assertEqual(execution.materialization_pins, receipt.assessment.materialization_pins)
            self.assertEqual(execution.assessment_digest, receipt.assessment.assessment_digest)
            self.assertEqual(execution.assessment_object_digest, receipt.assessment.object_digest)
            self.assertEqual(
                execution.column_evidence_digest,
                receipt.assessment.column_evidence_digest,
            )
            with self.subTest(reviewer="R1-001-column-selector"):
                self.assertEqual(execution.column_id, "normal")
                self.assertEqual(
                    execution.plan_selector_digest,
                    plan.binding(fixture.PASS_TEST_ID)["selector_digest"],
                )
            observation = authority.observe(execution)
            factory = api.CoverageRecordFactory(
                execution_authority=authority,
                coverage_policy=coverage,
            )
            record = factory.issue_execution(
                observation,
                matrix=matrix,
                profile=profile,
                overlay=overlay,
            )
            decision = ReleaseCoverageGate.evaluate(
                matrix,
                coverage_records=(record,),
                coverage_factory=factory,
            )
            self.assertFalse(decision.passed)
            self.assertEqual(len(decision.missing_test_ids), 273)

            restarted_task, restarted_runtime = probe.restart_authorities()
            restarted_application = application.restart(
                restarted_task, restarted_runtime, target,
            )
            restarted_authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=restarted_application,
                task_application=restarted_task,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=restarted_runtime,
            )
            restored = restarted_authority.observe_completion(
                fixture.PASS_TEST_ID,
                task_id=probe.task_id,
                expected_profile_id="new-feature",
            )
            self.assertIsNot(restored, execution)
            self.assertEqual(restored.execution_digest, execution.execution_digest)
            self.assertEqual(candidate, before_candidate)

            with self.subTest(stable_id=fixture.ROLLBACK_PASS_TEST_ID):
                (
                    rollback_api,
                    rollback_application,
                    rollback_probe,
                    rollback_target,
                ) = fixture.production_runtime(
                    "rollback",
                    task_id=fixture.coverage_task_id(
                        fixture.ROLLBACK_PASS_TEST_ID
                    ),
                )
                rollback_candidate = fixture.rollback_candidate()
                rollback_candidate["task_id"] = fixture.coverage_task_id(
                    fixture.ROLLBACK_PASS_TEST_ID
                )
                rollback_candidate_before = copy.deepcopy(rollback_candidate)
                action_before = rollback_probe.rollback_signature()
                try:
                    rollback_receipt = rollback_application.assess_and_commit(
                        rollback_candidate, observer=rollback_target,
                    )
                    self.assertIs(
                        type(rollback_receipt.assessment),
                        rollback_api.CategoryCompletionAssessment,
                    )
                    self.assertEqual(
                        rollback_receipt.assessment.column_id, "rollback",
                    )
                    self.assertNotEqual(
                        rollback_probe.rollback_signature(), action_before,
                    )
                    self.assertEqual(
                        fixture.category.load_json(rollback_target.path),
                        rollback_target.rollback_state,
                    )
                    rollback_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=rollback_application,
                        task_application=rollback_probe.task_application,
                        repository=rollback_probe.repository,
                        object_repository=rollback_probe.objects,
                        runtime=rollback_probe.runtime,
                    )
                    rollback_execution = rollback_authority.observe_completion(
                        fixture.ROLLBACK_PASS_TEST_ID,
                        task_id=rollback_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(rollback_execution.column_id, "rollback")
                    self.assertEqual(
                        rollback_execution.oracle_digest,
                        plan.oracle_for(fixture.ROLLBACK_PASS_TEST_ID)[
                            "oracle_digest"
                        ],
                    )
                    combined_factory = api.CoverageRecordFactory(
                        execution_authority=(authority, rollback_authority),
                        coverage_policy=coverage,
                    )
                    normal_record = combined_factory.issue_execution(
                        authority.observe(execution),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    rollback_record = combined_factory.issue_execution(
                        rollback_authority.observe(rollback_execution),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    two_decision = ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(normal_record, rollback_record),
                        coverage_factory=combined_factory,
                    )
                    self.assertFalse(two_decision.passed)
                    self.assertEqual(len(two_decision.missing_test_ids), 272)

                    restarted_task, restarted_runtime = (
                        rollback_probe.restart_authorities()
                    )
                    restarted_rollback = rollback_application.restart(
                        restarted_task, restarted_runtime, rollback_target,
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_rollback,
                        task_application=restarted_task,
                        repository=rollback_probe.repository,
                        object_repository=rollback_probe.objects,
                        runtime=restarted_runtime,
                    )
                    restarted_execution = restarted_authority.observe_completion(
                        fixture.ROLLBACK_PASS_TEST_ID,
                        task_id=rollback_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(
                        restarted_execution.execution_digest,
                        rollback_execution.execution_digest,
                    )
                    self.assertEqual(rollback_candidate, rollback_candidate_before)
                    fixture.abort_uncommitted_coverage_factory(factory)
                    fixture.abort_uncommitted_coverage_factory(combined_factory)
                finally:
                    rollback_target.close()

            with self.subTest(stable_id=fixture.SCAFFOLD_PASS_TEST_ID):
                (
                    scenario_api,
                    scenario_application,
                    scenario_probe,
                    scenario_target,
                ) = fixture.production_runtime(
                    "boundary", scenario_id=fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                    task_id=fixture.coverage_task_id(
                        fixture.SCAFFOLD_PASS_TEST_ID
                    ),
                )
                scenario_candidate = fixture.scaffold_candidate(accepted=True)
                scenario_candidate["task_id"] = fixture.coverage_task_id(
                    fixture.SCAFFOLD_PASS_TEST_ID
                )
                scenario_candidate_before = copy.deepcopy(scenario_candidate)
                try:
                    scenario_receipt = scenario_application.assess_and_commit(
                        scenario_candidate,
                        observer=scenario_target,
                    )
                    self.assertIs(
                        type(scenario_receipt.assessment),
                        scenario_api.CategoryCompletionAssessment,
                    )
                    self.assertEqual(
                        scenario_receipt.assessment.scenario_id,
                        fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                    )
                    typed = scenario_probe.resolve_category_evidence(
                        scenario_probe.task_id, "boundary",
                    )
                    self.assertEqual(typed["evidence_kind"], "scenario-membership")
                    self.assertEqual(typed["outcome"], "scenario-accepted")
                    self.assertEqual(
                        typed["facts"],
                        {"scenario-id": fixture.SCAFFOLD_BOUNDARY_CASE_ID},
                    )
                    scenario_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=scenario_application,
                        task_application=scenario_probe.task_application,
                        repository=scenario_probe.repository,
                        object_repository=scenario_probe.objects,
                        runtime=scenario_probe.runtime,
                    )
                    scenario_execution = scenario_authority.observe_completion(
                        fixture.SCAFFOLD_PASS_TEST_ID,
                        task_id=scenario_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(scenario_execution.selector_kind, "scenario")
                    self.assertEqual(scenario_execution.scenario_id, "scaffold")
                    self.assertEqual(
                        scenario_execution.category_boundary_case_id,
                        fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                    )
                    self.assertEqual(scenario_execution.column_id, "boundary")
                    self.assertEqual(scenario_execution.overlay_id, "full-planned")
                    self.assertEqual(
                        scenario_execution.materialization_pins,
                        scenario_receipt.assessment.materialization_pins,
                    )
                    scenario_factory = api.CoverageRecordFactory(
                        execution_authority=scenario_authority,
                        coverage_policy=coverage,
                    )
                    scenario_record = scenario_factory.issue_execution(
                        scenario_authority.observe(scenario_execution),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    scenario_decision = ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(scenario_record,),
                        coverage_factory=scenario_factory,
                    )
                    self.assertFalse(scenario_decision.passed)
                    self.assertEqual(len(scenario_decision.missing_test_ids), 273)

                    restarted_task, restarted_runtime = (
                        scenario_probe.restart_authorities()
                    )
                    restarted_scenario = scenario_application.restart(
                        restarted_task, restarted_runtime, scenario_target,
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_scenario,
                        task_application=restarted_task,
                        repository=scenario_probe.repository,
                        object_repository=scenario_probe.objects,
                        runtime=restarted_runtime,
                    )
                    restored_scenario = restarted_authority.observe_completion(
                        fixture.SCAFFOLD_PASS_TEST_ID,
                        task_id=scenario_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(
                        restored_scenario.execution_digest,
                        scenario_execution.execution_digest,
                    )
                    self.assertEqual(scenario_candidate, scenario_candidate_before)
                    fixture.abort_uncommitted_coverage_factory(scenario_factory)
                finally:
                    scenario_target.close()

            with self.subTest(stable_id=fixture.EXISTING_FEATURE_PASS_TEST_ID):
                existing_feature = fixture.run_serial_scenario_binding(
                    api4=api4,
                    plan=plan,
                    scenario_id=fixture.EXISTING_FEATURE_SCENARIO_ID,
                    disposition="P",
                )
                try:
                    typed = existing_feature.probe.resolve_category_evidence(
                        existing_feature.probe.task_id, "boundary",
                    )
                    self.assertEqual(typed["evidence_kind"], "scenario-membership")
                    self.assertEqual(typed["outcome"], "scenario-accepted")
                    self.assertEqual(
                        typed["facts"],
                        {
                            "scenario-id": (
                                fixture.EXISTING_FEATURE_BOUNDARY_CASE_ID
                            )
                        },
                    )
                    existing_factory = api.CoverageRecordFactory(
                        execution_authority=existing_feature.authority,
                        coverage_policy=coverage,
                    )
                    existing_record = existing_factory.issue_execution(
                        existing_feature.authority.observe(
                            existing_feature.execution
                        ),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    existing_decision = ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(existing_record,),
                        coverage_factory=existing_factory,
                    )
                    self.assertFalse(existing_decision.passed)
                    self.assertEqual(len(existing_decision.missing_test_ids), 273)

                    restarted_task, restarted_runtime = (
                        existing_feature.probe.restart_authorities()
                    )
                    restarted_application = existing_feature.application.restart(
                        restarted_task,
                        restarted_runtime,
                        existing_feature.target,
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_application,
                        task_application=restarted_task,
                        repository=existing_feature.probe.repository,
                        object_repository=existing_feature.probe.objects,
                        runtime=restarted_runtime,
                    )
                    restored = restarted_authority.observe_completion(
                        fixture.EXISTING_FEATURE_PASS_TEST_ID,
                        task_id=existing_feature.probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(
                        restored.execution_digest,
                        existing_feature.execution.execution_digest,
                    )
                    fixture.abort_uncommitted_coverage_factory(existing_factory)
                finally:
                    existing_feature.close()

            with self.subTest(
                stable_id=fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
            ):
                reproducible_failure = fixture.run_serial_scenario_binding(
                    api4=api4,
                    plan=plan,
                    scenario_id=(
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID
                    ),
                    disposition="P",
                )
                try:
                    typed = reproducible_failure.probe.resolve_category_evidence(
                        reproducible_failure.probe.task_id, "boundary",
                    )
                    self.assertEqual(typed["evidence_kind"], "scenario-membership")
                    self.assertEqual(typed["outcome"], "scenario-accepted")
                    self.assertEqual(
                        typed["facts"],
                        {
                            "scenario-id": (
                                fixture.BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID
                            )
                        },
                    )
                    restarted_task, restarted_runtime = (
                        reproducible_failure.probe.restart_authorities()
                    )
                    restarted_application = (
                        reproducible_failure.application.restart(
                            restarted_task,
                            restarted_runtime,
                            reproducible_failure.target,
                        )
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_application,
                        task_application=restarted_task,
                        repository=reproducible_failure.probe.repository,
                        object_repository=reproducible_failure.probe.objects,
                        runtime=restarted_runtime,
                    )
                    restored = restarted_authority.observe_completion(
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
                        task_id=reproducible_failure.probe.task_id,
                        expected_profile_id="bug-fix",
                    )
                    self.assertEqual(
                        restored.execution_digest,
                        reproducible_failure.execution.execution_digest,
                    )
                finally:
                    reproducible_failure.close()

            with self.subTest(stable_id=fixture.REAL_E2E_PASS_TEST_ID):
                (
                    real_api,
                    real_application,
                    real_probe,
                    real_observer,
                ) = fixture.production_real_e2e_runtime(
                    accepted=True,
                    task_id=fixture.coverage_task_id(
                        fixture.REAL_E2E_PASS_TEST_ID
                    ),
                )
                real_candidate = fixture.real_e2e_candidate(
                    accepted=True,
                    task_id=fixture.coverage_task_id(
                        fixture.REAL_E2E_PASS_TEST_ID
                    ),
                )
                real_candidate_before = copy.deepcopy(real_candidate)
                try:
                    real_receipt = real_application.assess_and_commit(
                        real_candidate,
                        observer=real_observer,
                    )
                    self.assertIs(
                        type(real_receipt.assessment),
                        real_api.CategoryCompletionAssessment,
                    )
                    self.assertEqual(real_receipt.assessment.column_id, "real-e2e")
                    self.assertEqual(real_probe.real_e2e_adapter.mutation_count, 1)
                    real_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=real_application,
                        task_application=real_probe.task_application,
                        repository=real_probe.repository,
                        object_repository=real_probe.objects,
                        runtime=real_probe.runtime,
                    )
                    real_execution = real_authority.observe_completion(
                        fixture.REAL_E2E_PASS_TEST_ID,
                        task_id=real_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(real_execution.column_id, "real-e2e")
                    self.assertEqual(real_execution.execution_kind, "real-target")
                    real_factory = api.CoverageRecordFactory(
                        execution_authority=real_authority,
                        coverage_policy=coverage,
                    )
                    real_record = real_factory.issue_execution(
                        real_authority.observe(real_execution),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    real_decision = ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(real_record,),
                        coverage_factory=real_factory,
                    )
                    self.assertFalse(real_decision.passed)
                    self.assertEqual(len(real_decision.missing_test_ids), 273)

                    restarted_task, restarted_runtime = (
                        real_probe.restart_authorities()
                    )
                    restarted_application = real_application.restart(
                        restarted_task,
                        restarted_runtime,
                        real_observer,
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_application,
                        task_application=restarted_task,
                        repository=real_probe.repository,
                        object_repository=real_probe.objects,
                        runtime=restarted_runtime,
                    )
                    restored = restarted_authority.observe_completion(
                        fixture.REAL_E2E_PASS_TEST_ID,
                        task_id=real_probe.task_id,
                        expected_profile_id="new-feature",
                    )
                    self.assertEqual(
                        restored.execution_digest,
                        real_execution.execution_digest,
                    )
                    self.assertEqual(real_probe.real_e2e_adapter.mutation_count, 1)
                    self.assertEqual(real_candidate, real_candidate_before)
                    fixture.abort_uncommitted_coverage_factory(real_factory)
                finally:
                    real_probe.close()

            bug_real_test_id = fixture.bug_fix_test_id("real-e2e", "P")
            with self.subTest(stable_id=bug_real_test_id):
                (
                    bug_real_api,
                    bug_real_application,
                    bug_real_probe,
                    bug_real_observer,
                ) = fixture.production_real_e2e_runtime(
                    accepted=True,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(bug_real_test_id),
                )
                bug_real_candidate = fixture.real_e2e_candidate(
                    accepted=True,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(bug_real_test_id),
                )
                bug_real_before = copy.deepcopy(bug_real_candidate)
                try:
                    bug_real_receipt = bug_real_application.assess_and_commit(
                        bug_real_candidate, observer=bug_real_observer,
                    )
                    self.assertIs(
                        type(bug_real_receipt.assessment),
                        bug_real_api.CategoryCompletionAssessment,
                    )
                    self.assertEqual(bug_real_probe.real_e2e_adapter.mutation_count, 1)
                    bug_real_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=bug_real_application,
                        task_application=bug_real_probe.task_application,
                        repository=bug_real_probe.repository,
                        object_repository=bug_real_probe.objects,
                        runtime=bug_real_probe.runtime,
                    )
                    bug_real_execution = bug_real_authority.observe_completion(
                        bug_real_test_id,
                        task_id=bug_real_probe.task_id,
                        expected_profile_id="bug-fix",
                    )
                    bug_real_factory = api.CoverageRecordFactory(
                        execution_authority=bug_real_authority,
                        coverage_policy=coverage,
                    )
                    bug_real_record = bug_real_factory.issue_execution(
                        bug_real_authority.observe(bug_real_execution),
                        matrix=matrix,
                        profile=bug_profile,
                        overlay=bug_overlay,
                    )
                    self.assertEqual(bug_real_record.test_id, bug_real_test_id)
                    restarted_task, restarted_runtime = (
                        bug_real_probe.restart_authorities()
                    )
                    restarted_application = bug_real_application.restart(
                        restarted_task, restarted_runtime, bug_real_observer,
                    )
                    restarted_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=restarted_application,
                        task_application=restarted_task,
                        repository=bug_real_probe.repository,
                        object_repository=bug_real_probe.objects,
                        runtime=restarted_runtime,
                    )
                    restored = restarted_authority.observe_completion(
                        bug_real_test_id,
                        task_id=bug_real_probe.task_id,
                        expected_profile_id="bug-fix",
                    )
                    self.assertEqual(
                        restored.execution_digest,
                        bug_real_execution.execution_digest,
                    )
                    self.assertEqual(bug_real_probe.real_e2e_adapter.mutation_count, 1)
                    self.assertEqual(bug_real_candidate, bug_real_before)
                    fixture.abort_uncommitted_coverage_factory(bug_real_factory)
                finally:
                    bug_real_probe.close()

            for installation_attack in (
                "invalid", "delete", "replace", "coherent-resign",
            ):
                with self.subTest(
                    stable_id=fixture.REAL_E2E_PASS_TEST_ID,
                    finding="WP08-S4-REAL-E2E-R1-001",
                    installation_attack=installation_attack,
                ):
                    import graph_engineering

                    (
                        _registry_api,
                        registry_application,
                        registry_probe,
                        registry_observer,
                    ) = fixture.production_real_e2e_runtime(
                        accepted=True,
                        task_id=fixture.coverage_task_id(
                            fixture.REAL_E2E_PASS_TEST_ID
                        ),
                    )
                    registry_authority = registry_probe.real_e2e_authority
                    replacement = fixture.real_e2e_installation_attack(
                        installation_attack
                    )

                    def attacked(operation):  # type: ignore[no-untyped-def]
                        arguments = (
                            {"side_effect": replacement}
                            if isinstance(replacement, BaseException)
                            else {"return_value": replacement}
                        )
                        before = fixture.real_e2e_state_signature(registry_probe)
                        issued: list[object] = []
                        errors: list[ValueError] = []
                        with mock.patch.object(
                            graph_engineering,
                            "_profile_real_e2e_installation_resource",
                            **arguments,
                        ) as loader:
                            try:
                                issued.append(operation())
                            except ValueError as error:
                                errors.append(error)
                        return (
                            loader.call_count > 0,
                            len(issued),
                            len(errors),
                            fixture.real_e2e_state_signature(registry_probe)
                            == before,
                        ), issued

                    try:
                        with self.subTest(phase="direct-require-current"):
                            observed, _issued = attacked(
                                lambda: registry_authority.require_current(
                                    expected_task_id=registry_probe.task_id,
                                )
                            )
                            self.assertEqual(observed, (True, 0, 1, True))

                        with self.subTest(phase="assessment-precommit"):
                            current_resource = (
                                graph_engineering
                                ._profile_real_e2e_installation_resource()
                            )
                            attack_active = False

                            def late_loader():  # type: ignore[no-untyped-def]
                                if not attack_active:
                                    return current_resource
                                if isinstance(replacement, BaseException):
                                    raise replacement
                                return replacement

                            def activate_attack(step: str) -> None:
                                nonlocal attack_active
                                if step == "category-assessment.before-commit":
                                    attack_active = True

                            before = fixture.real_e2e_state_signature(
                                registry_probe
                            )
                            assessment_issued: list[object] = []
                            errors: list[ValueError] = []
                            original_fault = registry_application._fault
                            with mock.patch.object(
                                graph_engineering,
                                "_profile_real_e2e_installation_resource",
                                side_effect=late_loader,
                            ) as loader:
                                registry_application._fault = activate_attack
                                try:
                                    assessment_issued.append(
                                        registry_application.assess_and_commit(
                                            fixture.real_e2e_candidate(
                                                accepted=True
                                            ),
                                            observer=registry_observer,
                                        )
                                    )
                                except ValueError as error:
                                    errors.append(error)
                                finally:
                                    registry_application._fault = original_fault
                            observed = (
                                loader.call_count > 0,
                                len(assessment_issued),
                                len(errors),
                                fixture.real_e2e_state_signature(registry_probe)
                                == before,
                            )
                            self.assertEqual(observed, (True, 0, 1, True))
                        if not assessment_issued:
                            registry_application.assess_and_commit(
                                fixture.real_e2e_candidate(accepted=True),
                                observer=registry_observer,
                            )

                        coverage_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=registry_application,
                            task_application=registry_probe.task_application,
                            repository=registry_probe.repository,
                            object_repository=registry_probe.objects,
                            runtime=registry_probe.runtime,
                        )
                        execution = coverage_authority.observe_completion(
                            fixture.REAL_E2E_PASS_TEST_ID,
                            task_id=registry_probe.task_id,
                            expected_profile_id="new-feature",
                        )

                        with self.subTest(phase="restart-observe"):
                            def restart_observe():  # type: ignore[no-untyped-def]
                                restarted_task, restarted_runtime = (
                                    registry_probe.restart_authorities()
                                )
                                restarted = registry_application.restart(
                                    restarted_task,
                                    restarted_runtime,
                                    registry_observer,
                                )
                                restarted_coverage = api4.ProfileCoverageAuthority(
                                    plan=plan,
                                    category_application=restarted,
                                    task_application=restarted_task,
                                    repository=registry_probe.repository,
                                    object_repository=registry_probe.objects,
                                    runtime=restarted_runtime,
                                )
                                return restarted_coverage.observe_completion(
                                    fixture.REAL_E2E_PASS_TEST_ID,
                                    task_id=registry_probe.task_id,
                                    expected_profile_id="new-feature",
                                )

                            observed, _issued = attacked(restart_observe)
                            self.assertEqual(observed, (True, 0, 1, True))

                        with self.subTest(phase="coverage-observer"):
                            observed, _issued = attacked(
                                lambda: coverage_authority.observe(execution)
                            )
                            self.assertEqual(observed, (True, 0, 1, True))
                        observation = coverage_authority.observe(execution)
                        coverage_factory = api.CoverageRecordFactory(
                            execution_authority=coverage_authority,
                            coverage_policy=coverage,
                        )

                        with self.subTest(phase="coverage-factory"):
                            observed, _issued = attacked(
                                lambda: coverage_factory.issue_execution(
                                    observation,
                                    matrix=matrix,
                                    profile=profile,
                                    overlay=overlay,
                                )
                            )
                            self.assertEqual(observed, (True, 0, 1, True))
                        coverage_record = coverage_factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )

                        with self.subTest(phase="release-gate"):
                            observed, _issued = attacked(
                                lambda: ReleaseCoverageGate.evaluate(
                                    matrix,
                                    coverage_records=(coverage_record,),
                                    coverage_factory=coverage_factory,
                                )
                            )
                            self.assertEqual(observed, (True, 0, 1, True))
                        fixture.abort_uncommitted_coverage_factory(
                            coverage_factory,
                        )
                    finally:
                        registry_probe.close()

            for attack in (
                "predecessor-delete",
                "receipt-delete",
                "result-replace",
                "stale-journal",
                "stale-claim",
                "post-observation-target-replace",
            ):
                with self.subTest(
                    stable_id=fixture.REAL_E2E_PASS_TEST_ID,
                    attack=attack,
                ):
                    (
                        _attack_api,
                        attack_application,
                        attack_probe,
                        attack_observer,
                    ) = fixture.production_real_e2e_runtime(
                        accepted=True,
                        task_id=fixture.coverage_task_id(
                            fixture.REAL_E2E_PASS_TEST_ID
                        ),
                    )
                    try:
                        attack_application.assess_and_commit(
                            fixture.real_e2e_candidate(accepted=True),
                            observer=attack_observer,
                        )
                        attack_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=attack_application,
                            task_application=attack_probe.task_application,
                            repository=attack_probe.repository,
                            object_repository=attack_probe.objects,
                            runtime=attack_probe.runtime,
                        )
                        attack_execution = attack_authority.observe_completion(
                            fixture.REAL_E2E_PASS_TEST_ID,
                            task_id=attack_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                        attack_observation = attack_authority.observe(
                            attack_execution
                        )
                        attack_factory = api.CoverageRecordFactory(
                            execution_authority=attack_authority,
                            coverage_policy=coverage,
                        )
                        fixture.apply_real_e2e_currentness_attack(
                            attack_probe,
                            attack,
                        )
                        task_before = attack_probe.signature()
                        issued: list[object] = []
                        with self.assertRaises(ValueError):
                            issued.append(attack_factory.issue_execution(
                                attack_observation,
                                matrix=matrix,
                                profile=profile,
                                overlay=overlay,
                            ))
                        self.assertEqual(issued, [])
                        self.assertEqual(attack_probe.signature(), task_before)
                        fixture.abort_uncommitted_coverage_factory(attack_factory)
                    finally:
                        attack_probe.close()

            with self.subTest(
                stable_id=fixture.REAL_E2E_PASS_TEST_ID,
                attack="clone-observer",
            ):
                (
                    _clone_api,
                    clone_application,
                    clone_probe,
                    clone_observer,
                ) = fixture.production_real_e2e_runtime(
                    accepted=True,
                    task_id=fixture.coverage_task_id(
                        fixture.REAL_E2E_PASS_TEST_ID
                    ),
                )
                clone_before = clone_probe.signature()
                clone_candidate = fixture.real_e2e_candidate(accepted=True)
                clone_candidate_before = copy.deepcopy(clone_candidate)
                try:
                    with self.assertRaises(category_api.CategoryExecutionError):
                        clone_application.assess_and_commit(
                            clone_candidate,
                            observer=fixture.clone_opaque(clone_observer),
                        )
                    self.assertEqual(clone_probe.signature(), clone_before)
                    self.assertEqual(clone_candidate, clone_candidate_before)
                finally:
                    clone_probe.close()

            with self.subTest(
                stable_id=fixture.REAL_E2E_PASS_TEST_ID,
                attack="foreign-observer-authority",
            ):
                (
                    _consumer_api,
                    consumer_application,
                    consumer_probe,
                    _consumer_observer,
                ) = fixture.production_real_e2e_runtime(
                    accepted=True,
                    task_id=fixture.coverage_task_id(
                        fixture.REAL_E2E_PASS_TEST_ID
                    ),
                )
                (
                    _foreign_api,
                    _foreign_application,
                    foreign_probe,
                    foreign_observer,
                ) = fixture.production_real_e2e_runtime(
                    accepted=True,
                    task_id=fixture.coverage_task_id(
                        fixture.REAL_E2E_PASS_TEST_ID
                    ),
                )
                consumer_before = consumer_probe.signature()
                foreign_candidate = fixture.real_e2e_candidate(accepted=True)
                foreign_candidate_before = copy.deepcopy(foreign_candidate)
                try:
                    with self.assertRaises(category_api.CategoryExecutionError):
                        consumer_application.assess_and_commit(
                            foreign_candidate,
                            observer=foreign_observer,
                        )
                    self.assertEqual(consumer_probe.signature(), consumer_before)
                    self.assertEqual(foreign_candidate, foreign_candidate_before)
                finally:
                    foreign_probe.close()
                    consumer_probe.close()

            with self.subTest(reviewer="R1-001-boundary-masquerades-as-normal"):
                (
                    _boundary_api,
                    boundary_application,
                    boundary_probe,
                    boundary_target,
                ) = fixture.production_runtime(
                    "boundary",
                    task_id=fixture.coverage_task_id(fixture.PASS_TEST_ID),
                )
                try:
                    boundary_candidate = fixture.category.candidate_document(
                        "new-feature", "boundary"
                    )
                    boundary_candidate["task_id"] = fixture.coverage_task_id(
                        fixture.PASS_TEST_ID
                    )
                    boundary_application.assess_and_commit(
                        boundary_candidate,
                        observer=boundary_target,
                    )
                    boundary_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=boundary_application,
                        task_application=boundary_probe.task_application,
                        repository=boundary_probe.repository,
                        object_repository=boundary_probe.objects,
                        runtime=boundary_probe.runtime,
                    )
                    issued: list[object] = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(boundary_authority.observe_completion(
                            fixture.PASS_TEST_ID,
                            task_id=boundary_probe.task_id,
                            expected_profile_id="new-feature",
                        ))
                    self.assertEqual(issued, [])
                finally:
                    boundary_target.close()
        finally:
            target.close()

    def test_gew_wp08_s4_production_coverage_r(self) -> None:
        """GEW-WP08-S4-PRODUCTION-COVERAGE-R."""

        dependency_fixture.load_slice_b_api()
        api4 = fixture.load_slice4_api()
        api, coverage, matrix, profile, overlay = self._profile_contracts()
        category_api, application, probe, target = fixture.production_runtime(
            task_id=fixture.coverage_task_id(fixture.REJECT_TEST_ID),
        )
        fixture.install_rejection_source(probe)
        rejected = fixture.rejected_candidate()
        rejected["task_id"] = fixture.coverage_task_id(fixture.REJECT_TEST_ID)
        before_candidate = copy.deepcopy(rejected)
        before_repository = probe.signature()
        rollback_target = None
        scenario_target = None
        batch_targets: list[object] = []
        real_e2e_probes: list[object] = []
        batch_authorities: list[object] = []
        batch_observations: list[object] = []
        bug_fix_targets: list[object] = []
        bug_fix_real_probes: list[object] = []
        bug_fix_authorities: list[object] = []
        bug_fix_observations: list[object] = []
        hotfix_results: list[fixture.SerialCoverageExecution] = []
        hotfix_observations: tuple[object, ...] = ()
        refactor_debt_results: list[fixture.SerialCoverageExecution] = []
        refactor_debt_observations: tuple[object, ...] = ()
        incident_response_results: list[fixture.SerialCoverageExecution] = []
        incident_response_observations: tuple[object, ...] = ()
        migration_results: list[fixture.SerialCoverageExecution] = []
        migration_observations: tuple[object, ...] = ()
        dependency_security_results: list[fixture.SerialCoverageExecution] = []
        dependency_security_observations: tuple[object, ...] = ()
        performance_results: list[fixture.SerialCoverageExecution] = []
        performance_observations: tuple[object, ...] = ()
        existing_feature_results: list[fixture.SerialCoverageExecution] = []
        existing_feature_observations: tuple[object, ...] = ()
        reproducible_failure_results: list[fixture.SerialCoverageExecution] = []
        reproducible_failure_observations: tuple[object, ...] = ()
        false_reproduction_results: list[fixture.SerialCoverageExecution] = []
        false_reproduction_observations: tuple[object, ...] = ()
        regression_boundary_results: list[fixture.SerialCoverageExecution] = []
        regression_boundary_observations: tuple[object, ...] = ()
        minimal_patch_results: list[fixture.SerialCoverageExecution] = []
        minimal_patch_observations: tuple[object, ...] = ()
        stable_baseline_results: list[fixture.SerialCoverageExecution] = []
        stable_baseline_observations: tuple[object, ...] = ()
        vulnerable_graph_results: list[fixture.SerialCoverageExecution] = []
        vulnerable_graph_observations: tuple[object, ...] = ()
        dependency_graph_scenario_results: list[
            fixture.SerialCoverageExecution
        ] = []
        dependency_graph_scenario_observations: tuple[object, ...] = ()
        migration_scenario_results: list[fixture.SerialCoverageExecution] = []
        migration_scenario_observations: tuple[object, ...] = ()
        batch_records: tuple[object, ...] = ()
        bug_fix_records: tuple[object, ...] = ()
        hotfix_records: tuple[object, ...] = ()
        refactor_debt_records: tuple[object, ...] = ()
        incident_response_records: tuple[object, ...] = ()
        migration_records: tuple[object, ...] = ()
        dependency_security_records: tuple[object, ...] = ()
        performance_records: tuple[object, ...] = ()
        existing_feature_records: tuple[object, ...] = ()
        reproducible_failure_records: tuple[object, ...] = ()
        false_reproduction_records: tuple[object, ...] = ()
        regression_boundary_records: tuple[object, ...] = ()
        minimal_patch_records: tuple[object, ...] = ()
        stable_baseline_records: tuple[object, ...] = ()
        vulnerable_graph_records: tuple[object, ...] = ()
        dependency_graph_scenario_records: tuple[object, ...] = ()
        migration_scenario_records: tuple[object, ...] = ()
        combined_records: tuple[object, ...] = ()
        record_documents: tuple[object, ...] = ()
        hotfix_shared = None
        refactor_shared = None
        incident_shared = None
        migration_shared = None
        dependency_security_shared = None
        performance_shared = None
        try:
            plan = api4.ProfileCoverageExecutionPlan.from_installation(matrix=matrix)
            with self.subTest(
                stable_id=(
                    fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID
                ),
                phase="installed-dependency-vulnerable-graph-rejection-binding",
            ):
                self.assertEqual(
                    tuple(
                        test_id
                        for test_id in (
                            fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID,
                            fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID,
                        )
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(len(plan.bindings), 220)
                self.assertEqual(len(plan.oracle_bindings), 110)
                self.assertIn(
                    fixture.VULNERABLE_GRAPH_R1_SELECTOR,
                    fixture.VERIFIED_RUNNER_SELECTORS,
                )
            with self.subTest(
                stable_id=fixture.PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID,
                phase="installed-performance-stable-baseline-rejection-binding",
            ):
                stable_baseline = plan.binding(
                    fixture.PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID
                )
                self.assertEqual(
                    tuple(stable_baseline[field] for field in (
                        "profile_id", "selector_kind", "column_id", "scenario_id",
                        "category_boundary_case_id", "overlay_id", "execution_kind",
                        "disposition", "expected_result", "task_id",
                    )),
                    (
                        "performance", "scenario", "boundary",
                        fixture.PERFORMANCE_STABLE_BASELINE_SCENARIO_ID,
                        fixture.PERFORMANCE_STABLE_BASELINE_BOUNDARY_CASE_ID,
                        "full-planned", "contract-test", "R", "EXPECTED_REJECTION",
                        fixture.coverage_task_id(
                            fixture.PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID
                        ),
                    ),
                )
                self.assertEqual(
                    stable_baseline["request_digest"],
                    fixture.coverage_request_digest(
                        fixture.performance_stable_baseline_candidate(accepted=False)
                    ),
                )
            expected_dependency_security_ids = tuple(sorted(
                dependency_fixture.dependency_security_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            self.assertEqual(
                tuple(
                    test_id for test_id in expected_dependency_security_ids
                    if test_id not in plan.bindings
                ),
                (),
            )
            expected_performance_ids = tuple(sorted(
                fixture.performance_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            self.assertEqual(
                tuple(
                    test_id for test_id in expected_performance_ids
                    if test_id not in plan.bindings
                ),
                (),
            )
            with self.subTest(
                finding="WP08-S4-AUTHORITY-LIFECYCLE",
                phase="factory-owned-close-contract",
            ):
                self.assertTrue(
                    hasattr(api.CoverageRecordFactory, "finalize_after_gate")
                )
                self.assertTrue(
                    hasattr(
                        api.CoverageRecordFactory,
                        "prepare_abort_uncommitted_candidate",
                    )
                )
                self.assertTrue(
                    hasattr(
                        api.CoverageRecordFactory,
                        "abort_uncommitted_candidate",
                    )
                )
                self.assertTrue(
                    hasattr(api4.ProfileCoverageAuthority, "_revoke_from_factory")
                )
            expected_incident_ids = tuple(sorted(
                fixture.incident_response_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            expected_migration_ids = tuple(sorted(
                fixture.migration_test_id(column, disposition)
                for column in fixture.approved_mandatory_columns()
                for disposition in ("P", "R")
            ))
            with self.subTest(
                phase="installed-incident-response-rejection-bindings",
            ):
                self.assertEqual(
                    tuple(
                        test_id for test_id in expected_incident_ids
                        if test_id not in plan.bindings
                    ),
                    (),
                )
                self.assertEqual(
                    tuple(
                        test_id for test_id in expected_migration_ids
                        if test_id not in plan.bindings
                    ),
                    (),
                )
            _bug_api, _bug_coverage, _bug_matrix, bug_profile, bug_overlay = (
                self._profile_contracts("bug-fix")
            )
            _hotfix_api, _hotfix_coverage, _hotfix_matrix, hotfix_profile, hotfix_overlay = (
                self._profile_contracts("hotfix")
            )
            (
                _refactor_api,
                _refactor_coverage,
                _refactor_matrix,
                refactor_profile,
                refactor_overlay,
            ) = self._profile_contracts("refactor-debt")
            (
                _incident_api,
                _incident_coverage,
                _incident_matrix,
                incident_profile,
                incident_overlay,
            ) = self._profile_contracts("incident-response")
            (
                _migration_api,
                _migration_coverage,
                _migration_matrix,
                migration_profile,
                migration_overlay,
            ) = self._profile_contracts("migration")
            (
                _dependency_api,
                _dependency_coverage,
                _dependency_matrix,
                dependency_profile,
                dependency_overlay,
            ) = self._profile_contracts("dependency-security")
            (
                _performance_api,
                _performance_coverage,
                _performance_matrix,
                performance_profile,
                performance_overlay,
            ) = self._profile_contracts("performance")
            with self.subTest(stable_id=fixture.REAL_E2E_REJECT_TEST_ID, phase="installed-binding"):
                real_e2e = plan.binding(fixture.REAL_E2E_REJECT_TEST_ID)
                self.assertEqual(real_e2e["selector_kind"], "mandatory")
                self.assertEqual(real_e2e["profile_id"], "new-feature")
                self.assertEqual(real_e2e["column_id"], "real-e2e")
                self.assertEqual(real_e2e["overlay_id"], "full-planned")
                self.assertEqual(real_e2e["execution_kind"], "real-target")
                self.assertEqual(real_e2e["disposition"], "R")
                self.assertEqual(
                    real_e2e["request_digest"],
                    fixture.coverage_request_digest(
                        fixture.real_e2e_candidate(accepted=False)
                        | {
                            "task_id": fixture.coverage_task_id(
                                fixture.REAL_E2E_REJECT_TEST_ID
                            )
                        }
                    ),
                )
            (
                _real_positive_api,
                real_positive_application,
                real_positive_probe,
                real_positive_observer,
            ) = fixture.production_real_e2e_runtime(
                accepted=True,
                task_id=fixture.coverage_task_id(
                    fixture.REAL_E2E_PASS_TEST_ID
                ),
            )
            real_e2e_probes.append(real_positive_probe)
            real_positive_candidate = fixture.real_e2e_candidate(
                accepted=True,
                task_id=fixture.coverage_task_id(
                    fixture.REAL_E2E_PASS_TEST_ID
                ),
            )
            real_positive_before = copy.deepcopy(real_positive_candidate)
            real_positive_application.assess_and_commit(
                real_positive_candidate,
                observer=real_positive_observer,
            )
            real_positive_authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=real_positive_application,
                task_application=real_positive_probe.task_application,
                repository=real_positive_probe.repository,
                object_repository=real_positive_probe.objects,
                runtime=real_positive_probe.runtime,
            )
            real_positive_execution = real_positive_authority.observe_completion(
                fixture.REAL_E2E_PASS_TEST_ID,
                task_id=real_positive_probe.task_id,
                expected_profile_id="new-feature",
            )
            batch_authorities.append(real_positive_authority)
            batch_observations.append(
                real_positive_authority.observe(real_positive_execution)
            )
            self.assertEqual(real_positive_candidate, real_positive_before)
            self.assertEqual(real_positive_probe.real_e2e_adapter.mutation_count, 1)

            (
                _real_reject_api,
                real_reject_application,
                real_reject_probe,
                real_reject_observer,
            ) = fixture.production_real_e2e_runtime(
                accepted=False,
                task_id=fixture.coverage_task_id(
                    fixture.REAL_E2E_REJECT_TEST_ID
                ),
            )
            real_e2e_probes.append(real_reject_probe)
            real_reject_candidate = fixture.real_e2e_candidate(
                accepted=False,
                task_id=fixture.coverage_task_id(
                    fixture.REAL_E2E_REJECT_TEST_ID
                ),
            )
            real_reject_before = copy.deepcopy(real_reject_candidate)
            real_reject_state_before = real_reject_probe.signature()
            real_action_id = real_reject_probe.real_e2e_authority._action_id
            real_action_before = (
                real_reject_probe.real_e2e_action_fixture.repository
                .concrete_action_audit(real_action_id)
            )
            real_reject_authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=real_reject_application,
                task_application=real_reject_probe.task_application,
                repository=real_reject_probe.repository,
                object_repository=real_reject_probe.objects,
                runtime=real_reject_probe.runtime,
            )
            real_reject_execution = real_reject_authority.execute_rejection(
                fixture.REAL_E2E_REJECT_TEST_ID,
                candidate=real_reject_candidate,
                observer=real_reject_observer,
            )
            self.assertEqual(real_reject_execution.column_id, "real-e2e")
            self.assertEqual(
                real_reject_execution.rejection_error_message,
                "real E2E predecessor is not reconciled: stale-expected-ref",
            )
            self.assertEqual(real_reject_probe.signature(), real_reject_state_before)
            self.assertEqual(real_reject_candidate, real_reject_before)
            self.assertEqual(real_reject_probe.real_e2e_adapter.mutation_count, 0)
            self.assertEqual(
                real_reject_probe.real_e2e_action_fixture.repository
                .concrete_action_audit(real_action_id),
                real_action_before,
            )
            batch_authorities.append(real_reject_authority)
            batch_observations.append(
                real_reject_authority.observe(real_reject_execution)
            )
            changed_real_request = fixture.real_e2e_candidate(
                accepted=False,
                task_id=fixture.coverage_task_id(
                    fixture.REAL_E2E_REJECT_TEST_ID
                ),
            )
            changed_real_request["request_id"] = (
                "wp08-s4:new-feature:real-e2e:stale-expected-ref:foreign"
            )
            changed_real_before = copy.deepcopy(changed_real_request)
            changed_real_state = real_reject_probe.signature()
            with self.subTest(
                stable_id=fixture.REAL_E2E_REJECT_TEST_ID,
                attack="same-id-different-request",
            ):
                issued: list[object] = []
                with self.assertRaises(api4.ProfileCoverageError):
                    issued.append(real_reject_authority.execute_rejection(
                        fixture.REAL_E2E_REJECT_TEST_ID,
                        candidate=changed_real_request,
                        observer=real_reject_observer,
                    ))
                self.assertEqual(issued, [])
                self.assertEqual(real_reject_probe.signature(), changed_real_state)
                self.assertEqual(changed_real_request, changed_real_before)
            for column in fixture.NEW_MANDATORY_COLUMNS:
                test_id = fixture.mandatory_test_id(column, "R")
                with self.subTest(stable_id=test_id, phase="installed-binding"):
                    binding = plan.binding(test_id)
                    self.assertEqual(binding["selector_kind"], "mandatory")
                    self.assertEqual(binding["column_id"], column)
                    self.assertEqual(binding["disposition"], "R")
                    self.assertIsNone(binding["scenario_id"])
                    self.assertIsNone(binding["category_boundary_case_id"])
                    self.assertIsInstance(binding["request_digest"], str)
            for index, column in enumerate(fixture.NEW_MANDATORY_COLUMNS):
                pass_test_id = fixture.mandatory_test_id(column, "P")
                reject_test_id = fixture.mandatory_test_id(column, "R")
                (
                    _column_positive_api,
                    column_positive_application,
                    column_positive_probe,
                    column_positive_target,
                ) = fixture.production_runtime(
                    column, task_id=fixture.coverage_task_id(pass_test_id),
                )
                batch_targets.append(column_positive_target)
                positive_candidate = fixture.mandatory_candidate(
                    column, task_id=fixture.coverage_task_id(pass_test_id),
                )
                positive_candidate_before = copy.deepcopy(positive_candidate)
                column_positive_application.assess_and_commit(
                    positive_candidate,
                    observer=column_positive_target,
                )
                positive_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=column_positive_application,
                    task_application=column_positive_probe.task_application,
                    repository=column_positive_probe.repository,
                    object_repository=column_positive_probe.objects,
                    runtime=column_positive_probe.runtime,
                )
                positive_execution = positive_authority.observe_completion(
                    pass_test_id,
                    task_id=column_positive_probe.task_id,
                    expected_profile_id="new-feature",
                )
                batch_authorities.append(positive_authority)
                batch_observations.append(
                    positive_authority.observe(positive_execution)
                )
                self.assertEqual(positive_candidate, positive_candidate_before)

                (
                    _column_reject_api,
                    column_reject_application,
                    column_reject_probe,
                    column_reject_target,
                ) = fixture.production_runtime(
                    column, task_id=fixture.coverage_task_id(reject_test_id),
                )
                batch_targets.append(column_reject_target)
                fixture.install_mandatory_rejection_source(
                    column_reject_probe, column,
                )
                reject_candidate = fixture.mandatory_candidate(
                    column, task_id=fixture.coverage_task_id(reject_test_id),
                )
                reject_candidate_before = copy.deepcopy(reject_candidate)
                reject_state_before = column_reject_probe.signature()
                reject_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=column_reject_application,
                    task_application=column_reject_probe.task_application,
                    repository=column_reject_probe.repository,
                    object_repository=column_reject_probe.objects,
                    runtime=column_reject_probe.runtime,
                )
                with self.subTest(
                    stable_id=reject_test_id,
                    phase="production-rejection",
                ):
                    reject_execution = reject_authority.execute_rejection(
                        reject_test_id,
                        candidate=reject_candidate,
                        observer=column_reject_target,
                    )
                    self.assertEqual(
                        reject_execution.result, "EXPECTED_REJECTION",
                    )
                    self.assertEqual(reject_execution.column_id, column)
                    self.assertEqual(
                        reject_execution.rejection_error_type,
                        "CategoryExecutionError",
                    )
                    self.assertEqual(
                        reject_execution.rejection_error_message,
                        "typed column evidence does not match authoritative "
                        f"durable facts: {column}",
                    )
                    self.assertEqual(
                        reject_execution.before_state_digest,
                        reject_execution.after_state_digest,
                    )
                    self.assertEqual(column_reject_probe.signature(), reject_state_before)
                    self.assertEqual(reject_candidate, reject_candidate_before)
                reject_observation = reject_authority.observe(reject_execution)
                batch_authorities.append(reject_authority)
                batch_observations.append(reject_observation)

                foreign_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=column_reject_application,
                    task_application=column_reject_probe.task_application,
                    repository=column_reject_probe.repository,
                    object_repository=column_reject_probe.objects,
                    runtime=column_reject_probe.runtime,
                )
                with self.subTest(
                    stable_id=reject_test_id,
                    attack="foreign-execution-authority",
                ):
                    with self.assertRaises(api4.ProfileCoverageError):
                        foreign_authority.observe(reject_execution)
                    self.assertEqual(column_reject_probe.signature(), reject_state_before)

                (
                    _attack_api,
                    attacked_application,
                    attacked_probe,
                    attacked_target,
                ) = fixture.production_runtime(
                    column, task_id=fixture.coverage_task_id(reject_test_id),
                )
                try:
                    original_evidence = attacked_probe.resolve_category_evidence(
                        attacked_probe.task_id, column,
                    )
                    other_column = fixture.NEW_MANDATORY_COLUMNS[
                        (index + 1) % len(fixture.NEW_MANDATORY_COLUMNS)
                    ]
                    cross_column = attacked_probe.resolve_category_evidence(
                        attacked_probe.task_id, other_column,
                    )
                    cross_column["column_id"] = column
                    fixture.category.resign_column_evidence(cross_column)
                    attacked_probe.replace_category_evidence_for(
                        column, cross_column,
                    )
                    attacked_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=attacked_application,
                        task_application=attacked_probe.task_application,
                        repository=attacked_probe.repository,
                        object_repository=attacked_probe.objects,
                        runtime=attacked_probe.runtime,
                    )
                    attacked_candidate = fixture.mandatory_candidate(
                        column,
                        task_id=fixture.coverage_task_id(reject_test_id),
                    )
                    attacked_candidate_before = copy.deepcopy(attacked_candidate)
                    attacked_before = attacked_probe.signature()
                    with self.subTest(
                        stable_id=reject_test_id,
                        attack="cross-column-coherent-evidence",
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(attacked_authority.execute_rejection(
                                reject_test_id,
                                candidate=attacked_candidate,
                                observer=attacked_target,
                            ))
                        self.assertEqual(issued, [])
                        self.assertEqual(attacked_probe.signature(), attacked_before)
                        self.assertEqual(attacked_candidate, attacked_candidate_before)

                    attacked_probe.replace_category_evidence_for(
                        column, original_evidence,
                    )
                    fixture.apply_currentness_attack(
                        "revision-drift", attacked_probe, reject_execution,
                    )
                    stale_before = attacked_probe.signature()
                    with self.subTest(
                        stable_id=reject_test_id,
                        attack="stale-task-revision",
                    ):
                        issued = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(attacked_authority.execute_rejection(
                                reject_test_id,
                                candidate=attacked_candidate,
                                observer=attacked_target,
                            ))
                        self.assertEqual(issued, [])
                        self.assertEqual(attacked_probe.signature(), stale_before)
                        self.assertEqual(attacked_candidate, attacked_candidate_before)
                finally:
                    attacked_target.close()

                source_kinds = {
                    "revise": "category-revision-record-v1",
                    "drift": "category-drift-record-v1",
                    "recovery": "category-recovery-record-v1",
                }
                source_kind = source_kinds.get(column)
                if source_kind is not None:
                    (
                        _source_api,
                        source_application,
                        source_probe,
                        source_target,
                    ) = fixture.production_runtime(
                        column,
                        task_id=fixture.coverage_task_id(reject_test_id),
                    )
                    try:
                        source = source_probe.resolve_category_source(source_kind)
                        if column == "revise":
                            source["owner_route"] = "owner:foreign"
                        else:
                            source["status"] = "foreign"
                        fixture.category.resign_durable_record(source)
                        source_probe.replace_category_source(source_kind, source)
                        source_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=source_application,
                            task_application=source_probe.task_application,
                            repository=source_probe.repository,
                            object_repository=source_probe.objects,
                            runtime=source_probe.runtime,
                        )
                        source_candidate = fixture.mandatory_candidate(
                            column,
                            task_id=fixture.coverage_task_id(reject_test_id),
                        )
                        source_candidate_before = copy.deepcopy(source_candidate)
                        source_before = source_probe.signature()
                        with self.subTest(
                            stable_id=reject_test_id,
                            attack="coherent-durable-source-substitution",
                        ):
                            issued = []
                            with self.assertRaises(api4.ProfileCoverageError):
                                issued.append(source_authority.execute_rejection(
                                    reject_test_id,
                                    candidate=source_candidate,
                                    observer=source_target,
                                ))
                            self.assertEqual(issued, [])
                            self.assertEqual(source_probe.signature(), source_before)
                            self.assertEqual(
                                source_candidate, source_candidate_before,
                            )
                    finally:
                        source_target.close()
            for column in fixture.BUG_FIX_COLUMNS:
                pass_test_id = fixture.bug_fix_test_id(column, "P")
                reject_test_id = fixture.bug_fix_test_id(column, "R")
                if column == "real-e2e":
                    (
                        _bug_real_positive_api,
                        bug_positive_application,
                        bug_positive_probe,
                        bug_positive_observer,
                    ) = fixture.production_real_e2e_runtime(
                        accepted=True,
                        profile_id="bug-fix",
                        task_id=fixture.coverage_task_id(pass_test_id),
                    )
                    bug_fix_real_probes.append(bug_positive_probe)
                    bug_positive_candidate = fixture.real_e2e_candidate(
                        accepted=True,
                        profile_id="bug-fix",
                        task_id=fixture.coverage_task_id(pass_test_id),
                    )
                    bug_positive_before = copy.deepcopy(bug_positive_candidate)
                    bug_positive_application.assess_and_commit(
                        bug_positive_candidate, observer=bug_positive_observer,
                    )
                    bug_positive_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=bug_positive_application,
                        task_application=bug_positive_probe.task_application,
                        repository=bug_positive_probe.repository,
                        object_repository=bug_positive_probe.objects,
                        runtime=bug_positive_probe.runtime,
                    )
                    bug_positive_execution = (
                        bug_positive_authority.observe_completion(
                            pass_test_id,
                            task_id=bug_positive_probe.task_id,
                            expected_profile_id="bug-fix",
                        )
                    )
                    self.assertEqual(
                        bug_positive_probe.real_e2e_adapter.mutation_count, 1,
                    )
                    self.assertEqual(bug_positive_candidate, bug_positive_before)

                    (
                        _bug_real_reject_api,
                        bug_reject_application,
                        bug_reject_probe,
                        bug_reject_observer,
                    ) = fixture.production_real_e2e_runtime(
                        accepted=False,
                        profile_id="bug-fix",
                        task_id=fixture.coverage_task_id(reject_test_id),
                    )
                    bug_fix_real_probes.append(bug_reject_probe)
                    bug_reject_candidate = fixture.real_e2e_candidate(
                        accepted=False,
                        profile_id="bug-fix",
                        task_id=fixture.coverage_task_id(reject_test_id),
                    )
                    bug_reject_before = copy.deepcopy(bug_reject_candidate)
                    bug_reject_state = fixture.real_e2e_state_signature(
                        bug_reject_probe,
                    )
                    bug_reject_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=bug_reject_application,
                        task_application=bug_reject_probe.task_application,
                        repository=bug_reject_probe.repository,
                        object_repository=bug_reject_probe.objects,
                        runtime=bug_reject_probe.runtime,
                    )
                    bug_reject_execution = bug_reject_authority.execute_rejection(
                        reject_test_id,
                        candidate=bug_reject_candidate,
                        observer=bug_reject_observer,
                    )
                    self.assertEqual(
                        bug_reject_execution.rejection_error_message,
                        "real E2E predecessor is not reconciled: stale-expected-ref",
                    )
                    self.assertEqual(
                        fixture.real_e2e_state_signature(bug_reject_probe),
                        bug_reject_state,
                    )
                    self.assertEqual(bug_reject_candidate, bug_reject_before)
                    bug_fix_authorities.extend((
                        bug_positive_authority, bug_reject_authority,
                    ))
                    bug_fix_observations.extend((
                        bug_positive_authority.observe(bug_positive_execution),
                        bug_reject_authority.observe(bug_reject_execution),
                    ))
                    continue

                (
                    _bug_positive_api,
                    bug_positive_application,
                    bug_positive_probe,
                    bug_positive_target,
                ) = fixture.production_runtime(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(pass_test_id),
                )
                bug_fix_targets.append(bug_positive_target)
                bug_positive_candidate = fixture.mandatory_candidate(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(pass_test_id),
                )
                bug_positive_before = copy.deepcopy(bug_positive_candidate)
                bug_positive_application.assess_and_commit(
                    bug_positive_candidate, observer=bug_positive_target,
                )
                bug_positive_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=bug_positive_application,
                    task_application=bug_positive_probe.task_application,
                    repository=bug_positive_probe.repository,
                    object_repository=bug_positive_probe.objects,
                    runtime=bug_positive_probe.runtime,
                )
                bug_positive_execution = bug_positive_authority.observe_completion(
                    pass_test_id,
                    task_id=bug_positive_probe.task_id,
                    expected_profile_id="bug-fix",
                )
                self.assertEqual(bug_positive_candidate, bug_positive_before)

                (
                    _bug_reject_api,
                    bug_reject_application,
                    bug_reject_probe,
                    bug_reject_target,
                ) = fixture.production_runtime(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(reject_test_id),
                )
                bug_fix_targets.append(bug_reject_target)
                fixture.install_mandatory_rejection_source(
                    bug_reject_probe, column,
                )
                bug_reject_candidate = fixture.mandatory_candidate(
                    column,
                    profile_id="bug-fix",
                    task_id=fixture.coverage_task_id(reject_test_id),
                )
                bug_reject_before = copy.deepcopy(bug_reject_candidate)
                bug_reject_state = bug_reject_probe.signature()
                bug_reject_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=bug_reject_application,
                    task_application=bug_reject_probe.task_application,
                    repository=bug_reject_probe.repository,
                    object_repository=bug_reject_probe.objects,
                    runtime=bug_reject_probe.runtime,
                )
                with self.subTest(
                    stable_id=reject_test_id,
                    phase="bug-fix-production-rejection",
                ):
                    bug_reject_execution = bug_reject_authority.execute_rejection(
                        reject_test_id,
                        candidate=bug_reject_candidate,
                        observer=bug_reject_target,
                    )
                    self.assertEqual(
                        bug_reject_execution.rejection_error_message,
                        plan.oracle_for(reject_test_id)["reject_error_message"],
                    )
                    self.assertEqual(
                        bug_reject_execution.before_state_digest,
                        bug_reject_execution.after_state_digest,
                    )
                    self.assertEqual(bug_reject_probe.signature(), bug_reject_state)
                    self.assertEqual(bug_reject_candidate, bug_reject_before)
                foreign_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=bug_reject_application,
                    task_application=bug_reject_probe.task_application,
                    repository=bug_reject_probe.repository,
                    object_repository=bug_reject_probe.objects,
                    runtime=bug_reject_probe.runtime,
                )
                with self.subTest(
                    stable_id=reject_test_id,
                    attack="bug-fix-foreign-execution-authority",
                ):
                    with self.assertRaises(api4.ProfileCoverageError):
                        foreign_authority.observe(bug_reject_execution)
                    self.assertEqual(bug_reject_probe.signature(), bug_reject_state)
                bug_fix_authorities.extend((
                    bug_positive_authority, bug_reject_authority,
                ))
                bug_fix_observations.extend((
                    bug_positive_authority.observe(bug_positive_execution),
                    bug_reject_authority.observe(bug_reject_execution),
                ))

            (
                _bug_attack_api,
                bug_attack_application,
                bug_attack_probe,
                bug_attack_target,
            ) = fixture.production_runtime("normal", profile_id="bug-fix")
            (
                _foreign_profile_api,
                _foreign_profile_application,
                foreign_profile_probe,
                foreign_profile_target,
            ) = fixture.production_runtime("normal", profile_id="new-feature")
            try:
                original_bug_evidence = bug_attack_probe.resolve_category_evidence(
                    bug_attack_probe.task_id, "normal",
                )
                bug_attack_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=bug_attack_application,
                    task_application=bug_attack_probe.task_application,
                    repository=bug_attack_probe.repository,
                    object_repository=bug_attack_probe.objects,
                    runtime=bug_attack_probe.runtime,
                )
                bug_attack_candidate = fixture.mandatory_candidate(
                    "normal", profile_id="bug-fix",
                )
                for attack, changed in (
                    (
                        "cross-profile-coherent-evidence",
                        foreign_profile_probe.resolve_category_evidence(
                            foreign_profile_probe.task_id, "normal",
                        ),
                    ),
                    (
                        "cross-column-coherent-evidence",
                        bug_attack_probe.resolve_category_evidence(
                            bug_attack_probe.task_id, "boundary",
                        ),
                    ),
                ):
                    changed["column_id"] = "normal"
                    fixture.category.resign_column_evidence(changed)
                    bug_attack_probe.replace_category_evidence_for(
                        "normal", changed,
                    )
                    attack_before = bug_attack_probe.signature()
                    candidate_before = copy.deepcopy(bug_attack_candidate)
                    with self.subTest(
                        stable_id=fixture.bug_fix_test_id("normal", "R"),
                        attack=attack,
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(bug_attack_authority.execute_rejection(
                                fixture.bug_fix_test_id("normal", "R"),
                                candidate=bug_attack_candidate,
                                observer=bug_attack_target,
                            ))
                        self.assertEqual(issued, [])
                        self.assertEqual(bug_attack_probe.signature(), attack_before)
                        self.assertEqual(bug_attack_candidate, candidate_before)
                    bug_attack_probe.replace_category_evidence_for(
                        "normal", original_bug_evidence,
                    )
            finally:
                foreign_profile_target.close()
                bug_attack_target.close()

            hotfix_shared = fixture.category.shared_production_category_runtime(
                "hotfix"
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    hotfix_results.append(fixture.run_serial_profile_binding(
                        api4=api4,
                        plan=plan,
                        profile_id="hotfix",
                        column=column,
                        disposition=disposition,
                        shared_runtime=hotfix_shared,
                    ))
            hotfix_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(hotfix_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in hotfix_results),
                tuple(sorted(
                    fixture.hotfix_test_id(column, disposition)
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in hotfix_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="hotfix-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "hotfix")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    self.assertEqual(result.execution.profile_id, "hotfix")
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        foreign_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=result.application,
                            task_application=result.probe.task_application,
                            repository=result.probe.repository,
                            object_repository=result.probe.objects,
                            runtime=result.probe.runtime,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            foreign_authority.observe(result.execution)
                        self.assertEqual(result.state_after, result.state_before)
            hotfix_observations = tuple(
                result.authority.observe(result.execution)
                for result in hotfix_results
            )
            for result in hotfix_results:
                result.retain_gate_context()

            refactor_shared = fixture.category.shared_production_category_runtime(
                "refactor-debt"
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    refactor_debt_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="refactor-debt",
                            column=column,
                            disposition=disposition,
                            shared_runtime=refactor_shared,
                        )
                    )
            refactor_debt_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(refactor_debt_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in refactor_debt_results),
                tuple(sorted(
                    fixture.refactor_debt_test_id(column, disposition)
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in refactor_debt_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="refactor-debt-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "refactor-debt")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(result.execution.profile_id, "refactor-debt")
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        foreign_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=result.application,
                            task_application=result.probe.task_application,
                            repository=result.probe.repository,
                            object_repository=result.probe.objects,
                            runtime=result.probe.runtime,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            foreign_authority.observe(result.execution)
                        self.assertEqual(result.state_after, result.state_before)
            refactor_debt_observations = tuple(
                result.authority.observe(result.execution)
                for result in refactor_debt_results
            )
            for result in refactor_debt_results:
                result.retain_gate_context()

            incident_shared = fixture.category.shared_production_category_runtime(
                "incident-response"
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    incident_response_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="incident-response",
                            column=column,
                            disposition=disposition,
                            shared_runtime=incident_shared,
                        )
                    )
            incident_response_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(incident_response_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in incident_response_results),
                tuple(sorted(
                    fixture.incident_response_test_id(column, disposition)
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in incident_response_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="incident-response-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "incident-response")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    self.assertEqual(
                        result.execution.profile_id, "incident-response",
                    )
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        foreign_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=result.application,
                            task_application=result.probe.task_application,
                            repository=result.probe.repository,
                            object_repository=result.probe.objects,
                            runtime=result.probe.runtime,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            foreign_authority.observe(result.execution)
                        self.assertEqual(result.state_after, result.state_before)
            incident_response_observations = tuple(
                result.authority.observe(result.execution)
                for result in incident_response_results
            )
            for result in incident_response_results:
                result.retain_gate_context()

            migration_shared = fixture.category.shared_production_category_runtime(
                "migration"
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    migration_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="migration",
                            column=column,
                            disposition=disposition,
                            shared_runtime=migration_shared,
                        )
                    )
            migration_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(migration_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in migration_results),
                tuple(sorted(
                    fixture.migration_test_id(column, disposition)
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in migration_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="migration-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "migration")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    self.assertEqual(result.execution.profile_id, "migration")
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        foreign_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=result.application,
                            task_application=result.probe.task_application,
                            repository=result.probe.repository,
                            object_repository=result.probe.objects,
                            runtime=result.probe.runtime,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            foreign_authority.observe(result.execution)
                        self.assertEqual(result.state_after, result.state_before)
            migration_observations = tuple(
                result.authority.observe(result.execution)
                for result in migration_results
            )
            for result in migration_results:
                result.retain_gate_context()
            self._assert_profile_rejection_attacks(
                api4=api4,
                plan=plan,
                profile_id="migration",
                foreign_profile_id="incident-response",
            )

            dependency_security_shared = (
                fixture.category.shared_production_category_runtime(
                    "dependency-security"
                )
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    dependency_security_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="dependency-security",
                            column=column,
                            disposition=disposition,
                            shared_runtime=dependency_security_shared,
                        )
                    )
            dependency_security_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(dependency_security_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in dependency_security_results),
                tuple(sorted(
                    dependency_fixture.dependency_security_test_id(
                        column, disposition,
                    )
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in dependency_security_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="dependency-security-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "dependency-security")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    self.assertEqual(
                        result.execution.profile_id, "dependency-security",
                    )
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        with self.assertRaises(api4.ProfileCoverageError):
                            api4.ProfileCoverageAuthority(
                                plan=plan,
                                category_application=result.application,
                                task_application=result.probe.task_application,
                                repository=result.probe.repository,
                                object_repository=result.probe.objects,
                                runtime=result.probe.runtime,
                            )
                        if result.column_id == "artifacts":
                            for forged in (
                                copy.copy(result.authority),
                                object.__new__(api4.ProfileCoverageAuthority),
                            ):
                                with self.subTest(
                                    stable_id=result.test_id,
                                    phase="performance-coverage-authority-identity",
                                    attack=type(forged).__name__,
                                ):
                                    before_attack = result.probe.signature()
                                    candidate_before = copy.deepcopy(result.candidate)
                                    with self.assertRaises(api4.ProfileCoverageError):
                                        forged.execute_rejection(
                                            result.test_id,
                                            candidate=result.candidate,
                                            observer=result.target,
                                        )
                                    self.assertEqual(
                                        result.probe.signature(), before_attack,
                                    )
                                    self.assertEqual(
                                        result.candidate, candidate_before,
                                    )
                            performance_context = result.performance_context
                            performance_factory = (
                                performance_context.registry_factory
                            )
                            original_evidence = performance_context.evidence
                            launches_before_attack = (
                                performance_context.launcher.launch_count
                            )
                            performance_factory._task_evidence[
                                result.probe.task_id
                            ] = copy.copy(original_evidence)
                            try:
                                with self.assertRaises(
                                    api4.ProfileCoverageError
                                ):
                                    result.authority.observe(result.execution)
                                self.assertEqual(
                                    performance_context.launcher.launch_count,
                                    launches_before_attack,
                                )
                                self.assertEqual(
                                    result.probe.signature(), before_attack,
                                )
                            finally:
                                performance_factory._task_evidence[
                                    result.probe.task_id
                                ] = original_evidence
                        self.assertEqual(result.state_after, result.state_before)
            dependency_security_observations = tuple(
                result.authority.observe(result.execution)
                for result in dependency_security_results
            )
            dependency_pass = next(
                result for result in dependency_security_results
                if result.column_id == "normal" and result.disposition == "P"
            )
            dependency_other = next(
                result for result in dependency_security_results
                if result.column_id == "boundary" and result.disposition == "P"
            )
            dependency_factory, dependency_observation = (
                dependency_pass.authority._dependency_security
            )
            other_dependency_observation = (
                dependency_other.authority._dependency_security[1]
            )
            with self.subTest(
                finding="WP08-DEPENDENCY-SECURITY-SLICEB",
                phase="consumer-local-final-observation",
            ):
                self.assertIs(
                    dependency_factory.require_current(dependency_observation),
                    dependency_observation,
                )
                self.assertIs(
                    dependency_factory.precommit(dependency_observation),
                    dependency_observation,
                )
                self.assertIs(
                    dependency_factory.restart(dependency_observation),
                    dependency_observation,
                )
                dependency_error = (
                    dependency_fixture.load_slice_b_api().DependencySecurityError
                )
                with self.assertRaises(dependency_error):
                    dependency_factory.require_current(
                        copy.copy(dependency_observation)
                    )
                with self.assertRaises(dependency_error):
                    dependency_factory.require_current(
                        other_dependency_observation
                    )
                before_state = dependency_pass.probe.signature()
                after_closure = dependency_observation._after
                packaging_wheel = (
                    after_closure._wheelhouse
                    / "packaging-26.3-py3-none-any.whl"
                )
                packaging_bytes = packaging_wheel.read_bytes()
                packaging_wheel.write_bytes(b"coherently-substituted")
                try:
                    with self.assertRaises(api4.ProfileCoverageError):
                        dependency_pass.authority.observe(
                            dependency_pass.execution
                        )
                    self.assertEqual(
                        dependency_pass.probe.signature(), before_state,
                    )
                finally:
                    packaging_wheel.write_bytes(packaging_bytes)
            for result in dependency_security_results:
                result.retain_gate_context()

            performance_shared = (
                fixture.category.shared_production_category_runtime(
                    "performance"
                )
            )
            for column in fixture.approved_mandatory_columns():
                for disposition in ("P", "R"):
                    performance_results.append(
                        fixture.run_serial_profile_binding(
                            api4=api4,
                            plan=plan,
                            profile_id="performance",
                            column=column,
                            disposition=disposition,
                            shared_runtime=performance_shared,
                        )
                    )
            performance_results.sort(key=lambda item: item.test_id)
            self.assertEqual(len(performance_results), 24)
            self.assertEqual(
                tuple(result.test_id for result in performance_results),
                tuple(sorted(
                    fixture.performance_test_id(column, disposition)
                    for column in fixture.approved_mandatory_columns()
                    for disposition in ("P", "R")
                )),
            )
            for result in performance_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="performance-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "performance")
                    self.assertEqual(result.execution.column_id, result.column_id)
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    self.assertEqual(result.execution.profile_id, "performance")
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        with self.assertRaises(api4.ProfileCoverageError):
                            api4.ProfileCoverageAuthority(
                                plan=plan,
                                category_application=result.application,
                                task_application=result.probe.task_application,
                                repository=result.probe.repository,
                                object_repository=result.probe.objects,
                                runtime=result.probe.runtime,
                            )
                        if result.column_id == "artifacts":
                            for attack, forged in (
                                ("shallow-copy", copy.copy(result.authority)),
                                (
                                    "object-new",
                                    object.__new__(api4.ProfileCoverageAuthority),
                                ),
                            ):
                                with self.subTest(
                                    stable_id=result.test_id,
                                    phase="performance-coverage-authority-identity",
                                    attack=attack,
                                ):
                                    before_attack = result.probe.signature()
                                    candidate_before = copy.deepcopy(result.candidate)
                                    with self.assertRaises(api4.ProfileCoverageError):
                                        forged.execute_rejection(
                                            result.test_id,
                                            candidate=result.candidate,
                                            observer=result.target,
                                        )
                                    self.assertEqual(
                                        result.probe.signature(), before_attack,
                                    )
                                    self.assertEqual(
                                        result.candidate, candidate_before,
                                    )
                        self.assertEqual(result.state_after, result.state_before)
            self.assertEqual(
                fixture.performance_coverage_authority_rejection_probes(
                    api4=api4, plan=plan,
                ),
                ("missing-evidence", "closed-launcher"),
            )
            performance_observations = tuple(
                result.authority.observe(result.execution)
                for result in performance_results
            )
            performance_real = next(
                result for result in performance_results
                if result.column_id == "real-e2e"
                and result.disposition == "P"
            )
            launches_before_restart = (
                performance_real.performance_context.launcher.launch_count
            )
            restarted_task, restarted_runtime = (
                performance_real.probe.restart_authorities()
            )
            restarted_application = performance_real.application.restart(
                restarted_task,
                restarted_runtime,
                performance_real.target,
            )
            restarted_authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=restarted_application,
                task_application=restarted_task,
                repository=performance_real.probe.repository,
                object_repository=performance_real.probe.objects,
                runtime=restarted_runtime,
            )
            restored = restarted_authority.observe_completion(
                performance_real.test_id,
                task_id=performance_real.probe.task_id,
                expected_profile_id="performance",
            )
            self.assertEqual(
                restored.execution_digest,
                performance_real.execution.execution_digest,
            )
            self.assertEqual(
                performance_real.performance_context.launcher.launch_count,
                launches_before_restart,
            )
            self.assertEqual(
                performance_real.probe.real_e2e_adapter.mutation_count, 1,
            )
            for result in performance_results:
                result.retain_gate_context()

            for disposition in ("P", "R"):
                existing_feature_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=fixture.EXISTING_FEATURE_SCENARIO_ID,
                        disposition=disposition,
                    )
                )
            existing_feature_results.sort(key=lambda item: item.test_id)
            self.assertEqual(
                tuple(item.test_id for item in existing_feature_results),
                (
                    fixture.EXISTING_FEATURE_PASS_TEST_ID,
                    fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                ),
            )
            for result in existing_feature_results:
                with self.subTest(
                    stable_id=result.test_id,
                    phase="existing-feature-independent-production-execution",
                ):
                    self.assertEqual(result.profile_id, "new-feature")
                    self.assertEqual(result.column_id, "boundary")
                    self.assertEqual(result.execution.selector_kind, "scenario")
                    self.assertEqual(
                        result.execution.scenario_id,
                        fixture.EXISTING_FEATURE_SCENARIO_ID,
                    )
                    self.assertEqual(
                        result.execution.category_boundary_case_id,
                        fixture.EXISTING_FEATURE_BOUNDARY_CASE_ID,
                    )
                    self.assertEqual(
                        result.execution.result,
                        "COMPLETED"
                        if result.disposition == "P"
                        else "EXPECTED_REJECTION",
                    )
                    if result.disposition == "R":
                        self.assertEqual(result.state_after, result.state_before)
                        foreign = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=result.application,
                            task_application=result.probe.task_application,
                            repository=result.probe.repository,
                            object_repository=result.probe.objects,
                            runtime=result.probe.runtime,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            foreign.observe(result.execution)
                        self.assertEqual(result.state_after, result.state_before)
            existing_reject = next(
                item for item in existing_feature_results
                if item.disposition == "R"
            )
            existing_state = fixture._serial_state_signature(
                existing_reject.probe,
                existing_reject.target,
                real_e2e=False,
            )
            invalid_existing_scenarios = {
                "raw-scenario": "existing-feature",
                "mandatory-boundary-id": "GEW-PRO-NEW-FEATURE-BOUNDARY-P",
                "rejection-member": fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                "other-scenario": fixture.SCAFFOLD_PASS_TEST_ID,
                "other-profile": "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE-P",
            }
            for attack, scenario_id in invalid_existing_scenarios.items():
                changed = fixture.existing_feature_candidate(accepted=False)
                changed["scenario_id"] = scenario_id
                changed_before = copy.deepcopy(changed)
                with self.subTest(
                    stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                    attack=attack,
                ):
                    issued: list[object] = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(existing_reject.authority.execute_rejection(
                            fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                            candidate=changed,
                            observer=existing_reject.target,
                        ))
                    self.assertEqual(issued, [])
                    self.assertEqual(changed, changed_before)
                    self.assertEqual(
                        fixture._serial_state_signature(
                            existing_reject.probe,
                            existing_reject.target,
                            real_e2e=False,
                        ),
                        existing_state,
                    )
            changed_request = fixture.existing_feature_candidate(accepted=False)
            changed_request["request_id"] = (
                "wp08-s4:new-feature:existing-feature:foreign"
            )
            changed_request_before = copy.deepcopy(changed_request)
            with self.subTest(
                stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                attack="same-id-different-request",
            ):
                with self.assertRaises(api4.ProfileCoverageError):
                    existing_reject.authority.execute_rejection(
                        fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                        candidate=changed_request,
                        observer=existing_reject.target,
                    )
                self.assertEqual(changed_request, changed_request_before)
                self.assertEqual(
                    fixture._serial_state_signature(
                        existing_reject.probe,
                        existing_reject.target,
                        real_e2e=False,
                    ),
                    existing_state,
                )
            with self.subTest(
                stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                attack="oracle-coherent-replacement",
            ):
                import graph_engineering

                with mock.patch.object(
                    graph_engineering,
                    "_profile_coverage_installation_resources",
                    return_value=fixture.coherently_resigned_oracle_resources(
                        scenario=True,
                        scenario_id=fixture.EXISTING_FEATURE_SCENARIO_ID,
                    ),
                ):
                    with self.assertRaises(api4.ProfileCoverageError):
                        existing_reject.authority.observe(
                            existing_reject.execution
                        )
                self.assertEqual(
                    fixture._serial_state_signature(
                        existing_reject.probe,
                        existing_reject.target,
                        real_e2e=False,
                    ),
                    existing_state,
                )
            with self.subTest(
                stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                attack="selector-overlay-coherent-substitution",
            ):
                import graph_engineering

                with mock.patch.object(
                    graph_engineering,
                    "_profile_coverage_installation_resources",
                    return_value=(
                        fixture.coherently_resigned_scenario_plan_resources(
                            fixture.EXISTING_FEATURE_PASS_TEST_ID
                        )
                    ),
                ):
                    with self.assertRaises(api4.ProfileCoverageError):
                        api4.ProfileCoverageExecutionPlan.from_installation(
                            matrix=matrix,
                        )
                self.assertEqual(
                    fixture._serial_state_signature(
                        existing_reject.probe,
                        existing_reject.target,
                        real_e2e=False,
                    ),
                    existing_state,
                )
            existing_feature_observations = tuple(
                item.authority.observe(item.execution)
                for item in existing_feature_results
            )
            for result in existing_feature_results:
                result.retain_gate_context()

            for disposition in ("P", "R"):
                reproducible_failure_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=(
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID
                        ),
                        disposition=disposition,
                    )
                )
                false_reproduction_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=fixture.BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID,
                        disposition=disposition,
                    )
                )
                regression_boundary_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=fixture.BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID,
                        disposition=disposition,
                    )
                )
                minimal_patch_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=fixture.HOTFIX_MINIMAL_PATCH_SCENARIO_ID,
                        disposition=disposition,
                    )
                )
                stable_baseline_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=(
                            fixture.PERFORMANCE_STABLE_BASELINE_SCENARIO_ID
                        ),
                        disposition=disposition,
                    )
                )
                vulnerable_graph_results.append(
                    fixture.run_serial_scenario_binding(
                        api4=api4,
                        plan=plan,
                        scenario_id=(
                            fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_SCENARIO_ID
                        ),
                        disposition=disposition,
                    )
                )
                for dependency_graph_scenario_id in (
                    fixture.DEPENDENCY_GRAPH_SCENARIO_IDS
                ):
                    dependency_graph_scenario_results.append(
                        fixture.run_serial_scenario_binding(
                            api4=api4,
                            plan=plan,
                            scenario_id=dependency_graph_scenario_id,
                            disposition=disposition,
                        )
                    )
                for migration_scenario_id in fixture.MIGRATION_SCENARIO_IDS:
                    migration_scenario_results.append(
                        fixture.run_serial_scenario_binding(
                            api4=api4,
                            plan=plan,
                            scenario_id=migration_scenario_id,
                            disposition=disposition,
                        )
                    )
            migration_scenario_results.sort(key=lambda item: item.test_id)
            dependency_graph_scenario_results.sort(
                key=lambda item: item.test_id,
            )
            self.assertEqual(
                tuple(item.test_id for item in reproducible_failure_results),
                (
                    fixture.BUG_FIX_REPRODUCIBLE_FAILURE_PASS_TEST_ID,
                    fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in false_reproduction_results),
                (
                    fixture.BUG_FIX_FALSE_REPRODUCTION_PASS_TEST_ID,
                    fixture.BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in regression_boundary_results),
                (
                    fixture.BUG_FIX_REGRESSION_BOUNDARY_PASS_TEST_ID,
                    fixture.BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in minimal_patch_results),
                (
                    fixture.HOTFIX_MINIMAL_PATCH_PASS_TEST_ID,
                    fixture.HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in stable_baseline_results),
                (
                    fixture.PERFORMANCE_STABLE_BASELINE_PASS_TEST_ID,
                    fixture.PERFORMANCE_STABLE_BASELINE_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in vulnerable_graph_results),
                (
                    fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_PASS_TEST_ID,
                    fixture.DEPENDENCY_SECURITY_VULNERABLE_GRAPH_REJECT_TEST_ID,
                ),
            )
            self.assertEqual(
                tuple(item.test_id for item in migration_scenario_results),
                tuple(sorted(fixture.MIGRATION_SCENARIO_TEST_IDS)),
            )
            self.assertEqual(
                tuple(
                    item.test_id for item in dependency_graph_scenario_results
                ),
                tuple(sorted(fixture.DEPENDENCY_GRAPH_SCENARIO_TEST_IDS)),
            )
            reproducible_failure_observations = tuple(
                item.authority.observe(item.execution)
                for item in reproducible_failure_results
            )
            false_reproduction_observations = tuple(
                item.authority.observe(item.execution)
                for item in false_reproduction_results
            )
            regression_boundary_observations = tuple(
                item.authority.observe(item.execution)
                for item in regression_boundary_results
            )
            minimal_patch_observations = tuple(
                item.authority.observe(item.execution)
                for item in minimal_patch_results
            )
            stable_baseline_observations = tuple(
                item.authority.observe(item.execution)
                for item in stable_baseline_results
            )
            vulnerable_graph_observations = tuple(
                item.authority.observe(item.execution)
                for item in vulnerable_graph_results
            )
            dependency_graph_scenario_observations = tuple(
                item.authority.observe(item.execution)
                for item in dependency_graph_scenario_results
            )
            migration_scenario_observations = tuple(
                item.authority.observe(item.execution)
                for item in migration_scenario_results
            )
            for result in (
                *reproducible_failure_results,
                *false_reproduction_results,
                *regression_boundary_results,
                *minimal_patch_results,
                *stable_baseline_results,
                *vulnerable_graph_results,
                *dependency_graph_scenario_results,
                *migration_scenario_results,
            ):
                result.retain_gate_context()

            with self.subTest(
                stable_id=fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
            ):
                reproducible_failure = fixture.run_serial_scenario_binding(
                    api4=api4,
                    plan=plan,
                    scenario_id=(
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID
                    ),
                    disposition="R",
                )
                try:
                    state_before_attack = fixture._serial_state_signature(
                        reproducible_failure.probe,
                        reproducible_failure.target,
                        real_e2e=False,
                    )
                    self.assertEqual(
                        reproducible_failure.state_after,
                        reproducible_failure.state_before,
                    )
                    invalid_scenarios = {
                        "raw-scenario": (
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID
                        ),
                        "mandatory-boundary-id": "GEW-PRO-BUG-FIX-BOUNDARY-P",
                        "rejection-member": (
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID
                        ),
                        "other-scenario": "GEW-PSC-BUG-FIX-FALSE-REPRODUCTION-P",
                        "other-profile": fixture.SCAFFOLD_PASS_TEST_ID,
                    }
                    for attack, scenario_id in invalid_scenarios.items():
                        changed = (
                            fixture.bug_fix_reproducible_failure_candidate(
                                accepted=False,
                            )
                        )
                        changed["scenario_id"] = scenario_id
                        changed_before = copy.deepcopy(changed)
                        with self.subTest(attack=attack):
                            with self.assertRaises(api4.ProfileCoverageError):
                                reproducible_failure.authority.execute_rejection(
                                    fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
                                    candidate=changed,
                                    observer=reproducible_failure.target,
                                )
                            self.assertEqual(changed, changed_before)
                            self.assertEqual(
                                fixture._serial_state_signature(
                                    reproducible_failure.probe,
                                    reproducible_failure.target,
                                    real_e2e=False,
                                ),
                                state_before_attack,
                            )
                    changed_request = (
                        fixture.bug_fix_reproducible_failure_candidate(
                            accepted=False,
                        )
                    )
                    changed_request["request_id"] = (
                        "wp08-s4:bug-fix:reproducible-failure:foreign"
                    )
                    changed_before = copy.deepcopy(changed_request)
                    with self.assertRaises(api4.ProfileCoverageError):
                        reproducible_failure.authority.execute_rejection(
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
                            candidate=changed_request,
                            observer=reproducible_failure.target,
                        )
                    self.assertEqual(changed_request, changed_before)
                    self.assertEqual(
                        fixture._serial_state_signature(
                            reproducible_failure.probe,
                            reproducible_failure.target,
                            real_e2e=False,
                        ),
                        state_before_attack,
                    )
                finally:
                    reproducible_failure.close()

            (
                _refactor_attack_api,
                refactor_attack_application,
                refactor_attack_probe,
                refactor_attack_target,
            ) = fixture.production_runtime(
                "normal", profile_id="refactor-debt",
            )
            (
                _refactor_foreign_api,
                _refactor_foreign_application,
                refactor_foreign_probe,
                refactor_foreign_target,
            ) = fixture.production_runtime("normal", profile_id="bug-fix")
            try:
                original_refactor_evidence = (
                    refactor_attack_probe.resolve_category_evidence(
                        refactor_attack_probe.task_id, "normal",
                    )
                )
                refactor_attack_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=refactor_attack_application,
                    task_application=refactor_attack_probe.task_application,
                    repository=refactor_attack_probe.repository,
                    object_repository=refactor_attack_probe.objects,
                    runtime=refactor_attack_probe.runtime,
                )
                refactor_attack_candidate = fixture.mandatory_candidate(
                    "normal", profile_id="refactor-debt",
                )
                for attack, changed in (
                    (
                        "refactor-debt-cross-profile-coherent-evidence",
                        refactor_foreign_probe.resolve_category_evidence(
                            refactor_foreign_probe.task_id, "normal",
                        ),
                    ),
                    (
                        "refactor-debt-cross-column-coherent-evidence",
                        refactor_attack_probe.resolve_category_evidence(
                            refactor_attack_probe.task_id, "boundary",
                        ),
                    ),
                ):
                    changed["column_id"] = "normal"
                    fixture.category.resign_column_evidence(changed)
                    refactor_attack_probe.replace_category_evidence_for(
                        "normal", changed,
                    )
                    attack_before = fixture._serial_state_signature(
                        refactor_attack_probe,
                        refactor_attack_target,
                        real_e2e=False,
                    )
                    candidate_before = copy.deepcopy(refactor_attack_candidate)
                    with self.subTest(
                        stable_id=fixture.refactor_debt_test_id("normal", "R"),
                        attack=attack,
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(
                                refactor_attack_authority.execute_rejection(
                                    fixture.refactor_debt_test_id("normal", "R"),
                                    candidate=refactor_attack_candidate,
                                    observer=refactor_attack_target,
                                )
                            )
                        self.assertEqual(issued, [])
                        self.assertEqual(
                            fixture._serial_state_signature(
                                refactor_attack_probe,
                                refactor_attack_target,
                                real_e2e=False,
                            ),
                            attack_before,
                        )
                        self.assertEqual(
                            refactor_attack_candidate, candidate_before,
                        )
                    refactor_attack_probe.replace_category_evidence_for(
                        "normal", original_refactor_evidence,
                    )

                fixture.install_mandatory_rejection_source(
                    refactor_attack_probe, "normal",
                )
                changed_request = fixture.mandatory_candidate(
                    "normal", profile_id="refactor-debt",
                )
                changed_request["request_id"] = (
                    "wp08-s3:refactor-debt:normal:foreign"
                )
                changed_request_before = copy.deepcopy(changed_request)
                changed_request_state = fixture._serial_state_signature(
                    refactor_attack_probe,
                    refactor_attack_target,
                    real_e2e=False,
                )
                with self.subTest(
                    stable_id=fixture.refactor_debt_test_id("normal", "R"),
                    attack="refactor-debt-same-id-different-request",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(
                            refactor_attack_authority.execute_rejection(
                                fixture.refactor_debt_test_id("normal", "R"),
                                candidate=changed_request,
                                observer=refactor_attack_target,
                            )
                        )
                    self.assertEqual(issued, [])
                    self.assertEqual(
                        fixture._serial_state_signature(
                            refactor_attack_probe,
                            refactor_attack_target,
                            real_e2e=False,
                        ),
                        changed_request_state,
                    )
                    self.assertEqual(changed_request, changed_request_before)
            finally:
                refactor_foreign_target.close()
                refactor_attack_target.close()

            (
                _refactor_source_api,
                refactor_source_application,
                refactor_source_probe,
                refactor_source_target,
            ) = fixture.production_runtime(
                "revise", profile_id="refactor-debt",
            )
            try:
                source = refactor_source_probe.resolve_category_source(
                    "category-revision-record-v1",
                )
                source["owner_route"] = "owner:foreign"
                fixture.category.resign_durable_record(source)
                refactor_source_probe.replace_category_source(
                    "category-revision-record-v1", source,
                )
                source_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=refactor_source_application,
                    task_application=refactor_source_probe.task_application,
                    repository=refactor_source_probe.repository,
                    object_repository=refactor_source_probe.objects,
                    runtime=refactor_source_probe.runtime,
                )
                source_candidate = fixture.mandatory_candidate(
                    "revise", profile_id="refactor-debt",
                )
                source_before = fixture._serial_state_signature(
                    refactor_source_probe,
                    refactor_source_target,
                    real_e2e=False,
                )
                candidate_before = copy.deepcopy(source_candidate)
                with self.subTest(
                    stable_id=fixture.refactor_debt_test_id("revise", "R"),
                    attack="refactor-debt-coherent-source-substitution",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(source_authority.execute_rejection(
                            fixture.refactor_debt_test_id("revise", "R"),
                            candidate=source_candidate,
                            observer=refactor_source_target,
                        ))
                    self.assertEqual(issued, [])
                    self.assertEqual(
                        fixture._serial_state_signature(
                            refactor_source_probe,
                            refactor_source_target,
                            real_e2e=False,
                        ),
                        source_before,
                    )
                    self.assertEqual(source_candidate, candidate_before)
            finally:
                refactor_source_target.close()

            (
                _incident_response_attack_api,
                incident_response_attack_application,
                incident_response_attack_probe,
                incident_response_attack_target,
            ) = fixture.production_runtime(
                "normal", profile_id="incident-response",
            )
            (
                _incident_response_foreign_api,
                _incident_response_foreign_application,
                incident_response_foreign_probe,
                incident_response_foreign_target,
            ) = fixture.production_runtime("normal", profile_id="bug-fix")
            try:
                original_incident_response_evidence = (
                    incident_response_attack_probe.resolve_category_evidence(
                        incident_response_attack_probe.task_id, "normal",
                    )
                )
                incident_response_attack_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=incident_response_attack_application,
                    task_application=incident_response_attack_probe.task_application,
                    repository=incident_response_attack_probe.repository,
                    object_repository=incident_response_attack_probe.objects,
                    runtime=incident_response_attack_probe.runtime,
                )
                incident_response_attack_candidate = fixture.mandatory_candidate(
                    "normal", profile_id="incident-response",
                )
                for attack, changed in (
                    (
                        "incident-response-cross-profile-coherent-evidence",
                        incident_response_foreign_probe.resolve_category_evidence(
                            incident_response_foreign_probe.task_id, "normal",
                        ),
                    ),
                    (
                        "incident-response-cross-column-coherent-evidence",
                        incident_response_attack_probe.resolve_category_evidence(
                            incident_response_attack_probe.task_id, "boundary",
                        ),
                    ),
                ):
                    changed["column_id"] = "normal"
                    fixture.category.resign_column_evidence(changed)
                    incident_response_attack_probe.replace_category_evidence_for(
                        "normal", changed,
                    )
                    attack_before = fixture._serial_state_signature(
                        incident_response_attack_probe,
                        incident_response_attack_target,
                        real_e2e=False,
                    )
                    candidate_before = copy.deepcopy(incident_response_attack_candidate)
                    with self.subTest(
                        stable_id=fixture.incident_response_test_id("normal", "R"),
                        attack=attack,
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(
                                incident_response_attack_authority.execute_rejection(
                                    fixture.incident_response_test_id("normal", "R"),
                                    candidate=incident_response_attack_candidate,
                                    observer=incident_response_attack_target,
                                )
                            )
                        self.assertEqual(issued, [])
                        self.assertEqual(
                            fixture._serial_state_signature(
                                incident_response_attack_probe,
                                incident_response_attack_target,
                                real_e2e=False,
                            ),
                            attack_before,
                        )
                        self.assertEqual(
                            incident_response_attack_candidate, candidate_before,
                        )
                    incident_response_attack_probe.replace_category_evidence_for(
                        "normal", original_incident_response_evidence,
                    )

                fixture.install_mandatory_rejection_source(
                    incident_response_attack_probe, "normal",
                )
                changed_request = fixture.mandatory_candidate(
                    "normal", profile_id="incident-response",
                )
                changed_request["request_id"] = (
                    "wp08-s3:incident-response:normal:foreign"
                )
                changed_request_before = copy.deepcopy(changed_request)
                changed_request_state = fixture._serial_state_signature(
                    incident_response_attack_probe,
                    incident_response_attack_target,
                    real_e2e=False,
                )
                with self.subTest(
                    stable_id=fixture.incident_response_test_id("normal", "R"),
                    attack="incident-response-same-id-different-request",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(
                            incident_response_attack_authority.execute_rejection(
                                fixture.incident_response_test_id("normal", "R"),
                                candidate=changed_request,
                                observer=incident_response_attack_target,
                            )
                        )
                    self.assertEqual(issued, [])
                    self.assertEqual(
                        fixture._serial_state_signature(
                            incident_response_attack_probe,
                            incident_response_attack_target,
                            real_e2e=False,
                        ),
                        changed_request_state,
                    )
                    self.assertEqual(changed_request, changed_request_before)
            finally:
                incident_response_foreign_target.close()
                incident_response_attack_target.close()

            (
                _incident_response_source_api,
                incident_response_source_application,
                incident_response_source_probe,
                incident_response_source_target,
            ) = fixture.production_runtime(
                "revise", profile_id="incident-response",
            )
            try:
                source = incident_response_source_probe.resolve_category_source(
                    "category-revision-record-v1",
                )
                source["owner_route"] = "owner:foreign"
                fixture.category.resign_durable_record(source)
                incident_response_source_probe.replace_category_source(
                    "category-revision-record-v1", source,
                )
                source_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=incident_response_source_application,
                    task_application=incident_response_source_probe.task_application,
                    repository=incident_response_source_probe.repository,
                    object_repository=incident_response_source_probe.objects,
                    runtime=incident_response_source_probe.runtime,
                )
                source_candidate = fixture.mandatory_candidate(
                    "revise", profile_id="incident-response",
                )
                source_before = fixture._serial_state_signature(
                    incident_response_source_probe,
                    incident_response_source_target,
                    real_e2e=False,
                )
                candidate_before = copy.deepcopy(source_candidate)
                with self.subTest(
                    stable_id=fixture.incident_response_test_id("revise", "R"),
                    attack="incident-response-coherent-source-substitution",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(source_authority.execute_rejection(
                            fixture.incident_response_test_id("revise", "R"),
                            candidate=source_candidate,
                            observer=incident_response_source_target,
                        ))
                    self.assertEqual(issued, [])
                    self.assertEqual(
                        fixture._serial_state_signature(
                            incident_response_source_probe,
                            incident_response_source_target,
                            real_e2e=False,
                        ),
                        source_before,
                    )
                    self.assertEqual(source_candidate, candidate_before)
            finally:
                incident_response_source_target.close()

            (
                _hotfix_attack_api,
                hotfix_attack_application,
                hotfix_attack_probe,
                hotfix_attack_target,
            ) = fixture.production_runtime("normal", profile_id="hotfix")
            (
                _hotfix_foreign_api,
                _hotfix_foreign_application,
                hotfix_foreign_probe,
                hotfix_foreign_target,
            ) = fixture.production_runtime("normal", profile_id="bug-fix")
            try:
                original_hotfix_evidence = (
                    hotfix_attack_probe.resolve_category_evidence(
                        hotfix_attack_probe.task_id, "normal",
                    )
                )
                hotfix_attack_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=hotfix_attack_application,
                    task_application=hotfix_attack_probe.task_application,
                    repository=hotfix_attack_probe.repository,
                    object_repository=hotfix_attack_probe.objects,
                    runtime=hotfix_attack_probe.runtime,
                )
                hotfix_attack_candidate = fixture.mandatory_candidate(
                    "normal", profile_id="hotfix",
                )
                for attack, changed in (
                    (
                        "hotfix-cross-profile-coherent-evidence",
                        hotfix_foreign_probe.resolve_category_evidence(
                            hotfix_foreign_probe.task_id, "normal",
                        ),
                    ),
                    (
                        "hotfix-cross-column-coherent-evidence",
                        hotfix_attack_probe.resolve_category_evidence(
                            hotfix_attack_probe.task_id, "boundary",
                        ),
                    ),
                ):
                    changed["column_id"] = "normal"
                    fixture.category.resign_column_evidence(changed)
                    hotfix_attack_probe.replace_category_evidence_for(
                        "normal", changed,
                    )
                    attack_before = hotfix_attack_probe.signature()
                    candidate_before = copy.deepcopy(hotfix_attack_candidate)
                    with self.subTest(
                        stable_id=fixture.hotfix_test_id("normal", "R"),
                        attack=attack,
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(
                                hotfix_attack_authority.execute_rejection(
                                    fixture.hotfix_test_id("normal", "R"),
                                    candidate=hotfix_attack_candidate,
                                    observer=hotfix_attack_target,
                                )
                            )
                        self.assertEqual(issued, [])
                        self.assertEqual(
                            hotfix_attack_probe.signature(), attack_before,
                        )
                        self.assertEqual(
                            hotfix_attack_candidate, candidate_before,
                        )
                    hotfix_attack_probe.replace_category_evidence_for(
                        "normal", original_hotfix_evidence,
                    )
            finally:
                hotfix_foreign_target.close()
                hotfix_attack_target.close()

            (
                _hotfix_source_api,
                hotfix_source_application,
                hotfix_source_probe,
                hotfix_source_target,
            ) = fixture.production_runtime("revise", profile_id="hotfix")
            try:
                source = hotfix_source_probe.resolve_category_source(
                    "category-revision-record-v1",
                )
                source["owner_route"] = "owner:foreign"
                fixture.category.resign_durable_record(source)
                hotfix_source_probe.replace_category_source(
                    "category-revision-record-v1", source,
                )
                source_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=hotfix_source_application,
                    task_application=hotfix_source_probe.task_application,
                    repository=hotfix_source_probe.repository,
                    object_repository=hotfix_source_probe.objects,
                    runtime=hotfix_source_probe.runtime,
                )
                source_candidate = fixture.mandatory_candidate(
                    "revise", profile_id="hotfix",
                )
                source_before = hotfix_source_probe.signature()
                candidate_before = copy.deepcopy(source_candidate)
                with self.subTest(
                    stable_id=fixture.hotfix_test_id("revise", "R"),
                    attack="hotfix-coherent-source-substitution",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(source_authority.execute_rejection(
                            fixture.hotfix_test_id("revise", "R"),
                            candidate=source_candidate,
                            observer=hotfix_source_target,
                        ))
                    self.assertEqual(issued, [])
                    self.assertEqual(hotfix_source_probe.signature(), source_before)
                    self.assertEqual(source_candidate, candidate_before)
            finally:
                hotfix_source_target.close()

            for attack in (
                "mandatory-test-id-column-swap",
                "scenario-real-target",
                "pass-rejection-result",
                "reject-completion-result",
                "task-id-alias",
                "task-id-coherent-substitution",
                "duplicate-task-id",
                "cross-binding-task-id",
                "binding-reorder",
            ):
                with self.subTest(
                    finding="WP08-S4-SCENARIO-R1-001",
                    attack=attack,
                ):
                    import graph_engineering

                    resources = fixture.coherently_resigned_binding_plan_resources(
                        attack,
                    )
                    issued_plans: list[object] = []
                    with mock.patch.object(
                        graph_engineering,
                        "_profile_coverage_installation_resources",
                        return_value=resources,
                    ):
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued_plans.append(
                                api4.ProfileCoverageExecutionPlan.from_installation(
                                    matrix=matrix,
                                )
                            )
                    self.assertEqual(issued_plans, [])
                    self.assertEqual(probe.signature(), before_repository)
                    self.assertEqual(rejected, before_candidate)
            with self.subTest(stable_id=fixture.SCAFFOLD_REJECT_TEST_ID):
                scaffold_binding = plan.binding(fixture.SCAFFOLD_REJECT_TEST_ID)
                self.assertEqual(scaffold_binding["selector_kind"], "scenario")
                self.assertEqual(scaffold_binding["scenario_id"], "scaffold")
                self.assertEqual(scaffold_binding["column_id"], "boundary")
                self.assertEqual(scaffold_binding["disposition"], "R")
                self.assertIsInstance(scaffold_binding["request_digest"], str)
            with self.subTest(stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID):
                existing_feature = plan.binding(
                    fixture.EXISTING_FEATURE_REJECT_TEST_ID
                )
                self.assertEqual(existing_feature["selector_kind"], "scenario")
                self.assertEqual(existing_feature["profile_id"], "new-feature")
                self.assertEqual(existing_feature["column_id"], "boundary")
                self.assertEqual(
                    existing_feature["scenario_id"],
                    fixture.EXISTING_FEATURE_SCENARIO_ID,
                )
                self.assertEqual(
                    existing_feature["category_boundary_case_id"],
                    fixture.EXISTING_FEATURE_BOUNDARY_CASE_ID,
                )
                self.assertEqual(existing_feature["overlay_id"], "full-planned")
                self.assertEqual(existing_feature["execution_kind"], "contract-test")
                self.assertEqual(existing_feature["disposition"], "R")
                self.assertEqual(
                    existing_feature["expected_result"], "EXPECTED_REJECTION",
                )
                self.assertIsInstance(existing_feature["request_digest"], str)
            with self.subTest(
                stable_id=fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID,
            ):
                reproducible_failure = plan.binding(
                    fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID
                )
                self.assertEqual(
                    (
                        reproducible_failure["profile_id"],
                        reproducible_failure["selector_kind"],
                        reproducible_failure["column_id"],
                        reproducible_failure["scenario_id"],
                        reproducible_failure["category_boundary_case_id"],
                        reproducible_failure["overlay_id"],
                        reproducible_failure["execution_kind"],
                        reproducible_failure["disposition"],
                        reproducible_failure["expected_result"],
                        reproducible_failure["task_id"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_SCENARIO_ID,
                        fixture.BUG_FIX_REPRODUCIBLE_FAILURE_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "R",
                        "EXPECTED_REJECTION",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_REPRODUCIBLE_FAILURE_REJECT_TEST_ID
                        ),
                    ),
                )
                self.assertIsInstance(
                    reproducible_failure["request_digest"], str,
                )
            with self.subTest(
                stable_id=fixture.BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID,
            ):
                false_reproduction = plan.binding(
                    fixture.BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID
                )
                self.assertEqual(
                    (
                        false_reproduction["profile_id"],
                        false_reproduction["selector_kind"],
                        false_reproduction["column_id"],
                        false_reproduction["scenario_id"],
                        false_reproduction["category_boundary_case_id"],
                        false_reproduction["overlay_id"],
                        false_reproduction["execution_kind"],
                        false_reproduction["disposition"],
                        false_reproduction["expected_result"],
                        false_reproduction["task_id"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_FALSE_REPRODUCTION_SCENARIO_ID,
                        fixture.BUG_FIX_FALSE_REPRODUCTION_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "R",
                        "EXPECTED_REJECTION",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_FALSE_REPRODUCTION_REJECT_TEST_ID
                        ),
                    ),
                )
                self.assertIsInstance(false_reproduction["request_digest"], str)
            with self.subTest(
                stable_id=fixture.BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID,
            ):
                regression_boundary = plan.binding(
                    fixture.BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID
                )
                self.assertEqual(
                    (
                        regression_boundary["profile_id"],
                        regression_boundary["selector_kind"],
                        regression_boundary["column_id"],
                        regression_boundary["scenario_id"],
                        regression_boundary["category_boundary_case_id"],
                        regression_boundary["overlay_id"],
                        regression_boundary["execution_kind"],
                        regression_boundary["disposition"],
                        regression_boundary["expected_result"],
                        regression_boundary["task_id"],
                    ),
                    (
                        "bug-fix",
                        "scenario",
                        "boundary",
                        fixture.BUG_FIX_REGRESSION_BOUNDARY_SCENARIO_ID,
                        fixture.BUG_FIX_REGRESSION_BOUNDARY_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "R",
                        "EXPECTED_REJECTION",
                        fixture.coverage_task_id(
                            fixture.BUG_FIX_REGRESSION_BOUNDARY_REJECT_TEST_ID
                        ),
                    ),
                )
                self.assertIsInstance(regression_boundary["request_digest"], str)
            with self.subTest(stable_id=fixture.HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID):
                minimal_patch = plan.binding(
                    fixture.HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID
                )
                self.assertEqual(
                    (
                        minimal_patch["profile_id"],
                        minimal_patch["selector_kind"],
                        minimal_patch["column_id"],
                        minimal_patch["scenario_id"],
                        minimal_patch["category_boundary_case_id"],
                        minimal_patch["overlay_id"],
                        minimal_patch["execution_kind"],
                        minimal_patch["disposition"],
                        minimal_patch["expected_result"],
                        minimal_patch["task_id"],
                    ),
                    (
                        "hotfix",
                        "scenario",
                        "boundary",
                        fixture.HOTFIX_MINIMAL_PATCH_SCENARIO_ID,
                        fixture.HOTFIX_MINIMAL_PATCH_BOUNDARY_CASE_ID,
                        "full-planned",
                        "contract-test",
                        "R",
                        "EXPECTED_REJECTION",
                        fixture.coverage_task_id(
                            fixture.HOTFIX_MINIMAL_PATCH_REJECT_TEST_ID
                        ),
                    ),
                )
                self.assertIsInstance(minimal_patch["request_digest"], str)
            with self.subTest(stable_id=fixture.ROLLBACK_REJECT_TEST_ID):
                rollback_binding = plan.binding(fixture.ROLLBACK_REJECT_TEST_ID)
                self.assertEqual(rollback_binding["profile_id"], "new-feature")
                self.assertEqual(rollback_binding["column_id"], "rollback")
                self.assertEqual(rollback_binding["disposition"], "R")
                self.assertIsInstance(rollback_binding["request_digest"], str)
            authority = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
            )
            rejected_execution = authority.execute_rejection(
                fixture.REJECT_TEST_ID,
                candidate=rejected,
                observer=target,
            )
            self.assertEqual(rejected_execution.result, "EXPECTED_REJECTION")
            self.assertEqual(rejected_execution.before_state_digest, rejected_execution.after_state_digest)
            self.assertEqual(probe.signature(), before_repository)
            self.assertEqual(rejected, before_candidate)

            (
                rollback_api,
                rollback_application,
                rollback_probe,
                rollback_target,
            ) = fixture.production_runtime(
                "rollback",
                task_id=fixture.coverage_task_id(
                    fixture.ROLLBACK_REJECT_TEST_ID
                ),
            )
            fixture.install_rollback_rejection_source(
                rollback_probe, "foreign-action-id",
            )
            rollback_rejected = fixture.rollback_candidate()
            rollback_rejected["task_id"] = fixture.coverage_task_id(
                fixture.ROLLBACK_REJECT_TEST_ID
            )
            rollback_candidate_before = copy.deepcopy(rollback_rejected)
            rollback_task_before = rollback_probe.signature()
            rollback_action_before = rollback_probe.rollback_signature()
            with self.subTest(
                stable_id=fixture.ROLLBACK_REJECT_TEST_ID,
                phase="production-rejection",
            ):
                rollback_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=rollback_application,
                    task_application=rollback_probe.task_application,
                    repository=rollback_probe.repository,
                    object_repository=rollback_probe.objects,
                    runtime=rollback_probe.runtime,
                )
                rollback_rejected_execution = rollback_authority.execute_rejection(
                    fixture.ROLLBACK_REJECT_TEST_ID,
                    candidate=rollback_rejected,
                    observer=rollback_target,
                )
                self.assertEqual(
                    rollback_rejected_execution.result, "EXPECTED_REJECTION",
                )
                self.assertEqual(rollback_rejected_execution.column_id, "rollback")
                self.assertEqual(rollback_probe.signature(), rollback_task_before)
                self.assertEqual(
                    rollback_probe.rollback_signature(), rollback_action_before,
                )
                self.assertEqual(rollback_rejected, rollback_candidate_before)
                rollback_reject_observation = rollback_authority.observe(
                    rollback_rejected_execution,
                )

                with self.subTest(
                    stable_id=fixture.ROLLBACK_REJECT_TEST_ID,
                    attack="normal-selector-mismatch",
                ):
                    for test_id, changed_candidate in (
                        (fixture.REJECT_TEST_ID, fixture.rollback_candidate()),
                        (fixture.ROLLBACK_REJECT_TEST_ID, fixture.rejected_candidate()),
                    ):
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(rollback_authority.execute_rejection(
                                test_id,
                                candidate=changed_candidate,
                                observer=rollback_target,
                            ))
                        self.assertEqual(issued, [])
                    self.assertEqual(rollback_probe.signature(), rollback_task_before)
                    self.assertEqual(
                        rollback_probe.rollback_signature(), rollback_action_before,
                    )

                for attack in (
                    "wrong-action-status",
                    "wrong-claim-status",
                    "stale-journal",
                    "stale-target",
                ):
                    with self.subTest(
                        stable_id=fixture.ROLLBACK_REJECT_TEST_ID,
                        attack=attack,
                    ):
                        (
                            _attack_api,
                            attacked_application,
                            attacked_probe,
                            attacked_target,
                        ) = fixture.production_runtime(
                            "rollback",
                            task_id=fixture.coverage_task_id(
                                fixture.ROLLBACK_REJECT_TEST_ID
                            ),
                        )
                        try:
                            fixture.install_rollback_rejection_source(
                                attacked_probe, attack,
                            )
                            attacked_task_before = attacked_probe.signature()
                            attacked_action_before = (
                                attacked_probe.rollback_signature()
                            )
                            attacked_candidate = fixture.rollback_candidate()
                            attacked_candidate["task_id"] = fixture.coverage_task_id(
                                fixture.ROLLBACK_REJECT_TEST_ID
                            )
                            attacked_candidate_before = copy.deepcopy(
                                attacked_candidate,
                            )
                            attacked_authority = api4.ProfileCoverageAuthority(
                                plan=plan,
                                category_application=attacked_application,
                                task_application=attacked_probe.task_application,
                                repository=attacked_probe.repository,
                                object_repository=attacked_probe.objects,
                                runtime=attacked_probe.runtime,
                            )
                            issued = []
                            if attack in {
                                "wrong-action-status", "wrong-claim-status",
                            }:
                                issued.append(
                                    attacked_authority.execute_rejection(
                                        fixture.ROLLBACK_REJECT_TEST_ID,
                                        candidate=attacked_candidate,
                                        observer=attacked_target,
                                    )
                                )
                                self.assertEqual(
                                    issued[0].result, "EXPECTED_REJECTION",
                                )
                            else:
                                with self.assertRaises(api4.ProfileCoverageError):
                                    issued.append(
                                        attacked_authority.execute_rejection(
                                            fixture.ROLLBACK_REJECT_TEST_ID,
                                            candidate=attacked_candidate,
                                            observer=attacked_target,
                                        )
                                    )
                                self.assertEqual(issued, [])
                            self.assertEqual(
                                attacked_probe.signature(), attacked_task_before,
                            )
                            self.assertEqual(
                                attacked_probe.rollback_signature(),
                                attacked_action_before,
                            )
                            self.assertEqual(
                                attacked_candidate, attacked_candidate_before,
                            )
                        finally:
                            attacked_target.close()

                with self.subTest(
                    stable_id=fixture.ROLLBACK_REJECT_TEST_ID,
                    attack="same-id-different-request",
                ):
                    issued = []
                    with self.assertRaises(api4.ProfileCoverageError):
                        issued.append(rollback_authority.execute_rejection(
                            fixture.ROLLBACK_REJECT_TEST_ID,
                            candidate=fixture.rollback_candidate_variant(),
                            observer=rollback_target,
                        ))
                    self.assertEqual(issued, [])
                    self.assertEqual(rollback_probe.signature(), rollback_task_before)
                    self.assertEqual(
                        rollback_probe.rollback_signature(), rollback_action_before,
                    )

                with self.subTest(
                    stable_id=fixture.ROLLBACK_REJECT_TEST_ID,
                    attack="oracle-coherent-replacement",
                ):
                    import graph_engineering

                    with mock.patch.object(
                        graph_engineering,
                        "_profile_coverage_installation_resources",
                        return_value=fixture.coherently_resigned_oracle_resources(),
                    ):
                        with self.assertRaises(api4.ProfileCoverageError):
                            rollback_authority.observe(
                                rollback_rejected_execution,
                            )
                    self.assertEqual(rollback_probe.signature(), rollback_task_before)
                    self.assertEqual(
                        rollback_probe.rollback_signature(), rollback_action_before,
                    )

            (
                scenario_api,
                scenario_application,
                scenario_probe,
                scenario_target,
            ) = fixture.production_runtime(
                "boundary", scenario_id=fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                task_id=fixture.coverage_task_id(
                    fixture.SCAFFOLD_REJECT_TEST_ID
                ),
            )
            scenario_rejected = fixture.scaffold_candidate(accepted=False)
            scenario_rejected["task_id"] = fixture.coverage_task_id(
                fixture.SCAFFOLD_REJECT_TEST_ID
            )
            scenario_candidate_before = copy.deepcopy(scenario_rejected)
            scenario_task_before = scenario_probe.signature()
            with self.subTest(
                stable_id=fixture.SCAFFOLD_REJECT_TEST_ID,
                phase="production-rejection",
            ):
                scenario_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=scenario_application,
                    task_application=scenario_probe.task_application,
                    repository=scenario_probe.repository,
                    object_repository=scenario_probe.objects,
                    runtime=scenario_probe.runtime,
                )
                scenario_rejected_execution = scenario_authority.execute_rejection(
                    fixture.SCAFFOLD_REJECT_TEST_ID,
                    candidate=scenario_rejected,
                    observer=scenario_target,
                )
                self.assertEqual(
                    scenario_rejected_execution.result, "EXPECTED_REJECTION",
                )
                self.assertEqual(
                    scenario_rejected_execution.rejection_error_type,
                    "CategoryExecutionError",
                )
                self.assertEqual(
                    scenario_rejected_execution.rejection_error_message,
                    "typed column evidence does not match authoritative durable facts: boundary",
                )
                self.assertEqual(
                    scenario_rejected_execution.before_state_digest,
                    scenario_rejected_execution.after_state_digest,
                )
                self.assertEqual(
                    scenario_rejected_execution.selector_kind, "scenario",
                )
                self.assertEqual(scenario_rejected_execution.scenario_id, "scaffold")
                self.assertEqual(
                    scenario_rejected_execution.category_boundary_case_id,
                    fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                )
                self.assertEqual(scenario_probe.signature(), scenario_task_before)
                self.assertEqual(scenario_rejected, scenario_candidate_before)
                scenario_reject_observation = scenario_authority.observe(
                    scenario_rejected_execution,
                )

                invalid_scenarios = {
                    "raw-scenario": "scaffold",
                    "mandatory-boundary-id": "GEW-PRO-NEW-FEATURE-BOUNDARY-P",
                    "rejection-member": fixture.SCAFFOLD_REJECT_TEST_ID,
                    "other-scenario": "GEW-PSC-NEW-FEATURE-EXISTING-FEATURE-P",
                    "other-profile": "GEW-PSC-BUG-FIX-REPRODUCIBLE-FAILURE-P",
                }
                for attack, scenario_id in invalid_scenarios.items():
                    with self.subTest(
                        stable_id=fixture.SCAFFOLD_REJECT_TEST_ID,
                        attack=attack,
                    ):
                        changed = fixture.scaffold_candidate(accepted=False)
                        changed["task_id"] = fixture.coverage_task_id(
                            fixture.SCAFFOLD_REJECT_TEST_ID
                        )
                        changed["scenario_id"] = scenario_id
                        changed_before = copy.deepcopy(changed)
                        issued: list[object] = []
                        with self.assertRaises(api4.ProfileCoverageError):
                            issued.append(scenario_authority.execute_rejection(
                                fixture.SCAFFOLD_REJECT_TEST_ID,
                                candidate=changed,
                                observer=scenario_target,
                            ))
                        self.assertEqual(issued, [])
                        self.assertEqual(changed, changed_before)
                        self.assertEqual(scenario_probe.signature(), scenario_task_before)

                with self.subTest(
                    stable_id=fixture.SCAFFOLD_REJECT_TEST_ID,
                    attack="oracle-coherent-replacement",
                ):
                    import graph_engineering

                    with mock.patch.object(
                        graph_engineering,
                        "_profile_coverage_installation_resources",
                        return_value=fixture.coherently_resigned_oracle_resources(
                            scenario=True,
                        ),
                    ):
                        with self.assertRaises(api4.ProfileCoverageError):
                            scenario_authority.observe(
                                scenario_rejected_execution,
                            )
                    self.assertEqual(scenario_probe.signature(), scenario_task_before)

                with self.subTest(
                    stable_id=fixture.SCAFFOLD_REJECT_TEST_ID,
                    attack="selector-overlay-coherent-substitution",
                ):
                    import graph_engineering

                    with mock.patch.object(
                        graph_engineering,
                        "_profile_coverage_installation_resources",
                        return_value=(
                            fixture.coherently_resigned_scenario_plan_resources()
                        ),
                    ):
                        with self.assertRaises(api4.ProfileCoverageError):
                            api4.ProfileCoverageExecutionPlan.from_installation(
                                matrix=matrix,
                            )
                    self.assertEqual(scenario_probe.signature(), scenario_task_before)

                foreign_scenario = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=scenario_application,
                    task_application=scenario_probe.task_application,
                    repository=scenario_probe.repository,
                    object_repository=scenario_probe.objects,
                    runtime=scenario_probe.runtime,
                )
                with self.assertRaises(api4.ProfileCoverageError):
                    foreign_scenario.observe(scenario_rejected_execution)
                self.assertEqual(scenario_probe.signature(), scenario_task_before)

            with self.subTest(reviewer="R1-001-fresh-authority-same-id-request"):
                fresh = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=application,
                    task_application=probe.task_application,
                    repository=probe.repository,
                    object_repository=probe.objects,
                    runtime=probe.runtime,
                )
                issued: list[object] = []
                with self.assertRaises(api4.ProfileCoverageError):
                    issued.append(fresh.execute_rejection(
                        fixture.REJECT_TEST_ID,
                        candidate=fixture.coherent_candidate_variant(),
                        observer=target,
                    ))
                self.assertEqual(issued, [])

            reject_observation = authority.observe(rejected_execution)
            reject_factory = api.CoverageRecordFactory(
                execution_authority=authority,
                coverage_policy=coverage,
            )
            execution_projection_fields = tuple(
                field
                for field in type(rejected_execution).__dataclass_fields__
                if not field.startswith("_")
                and field not in {"execution_digest", "execution_object_digest"}
            )
            with self.subTest(reviewer="R1-001-record-column-is-immutable"):
                self.assertIn("column_id", execution_projection_fields)
                self.assertIn("selector_kind", execution_projection_fields)
                self.assertIn("scenario_id", execution_projection_fields)
                self.assertIn("category_boundary_case_id", execution_projection_fields)
                self.assertIn("plan_selector_digest", execution_projection_fields)
            for field in execution_projection_fields:
                with self.subTest(reviewer="R1-002-execution-resign", field=field):
                    original = fixture.coherently_resign_execution(
                        rejected_execution, field,
                    )
                    try:
                        with self.assertRaises(api4.ProfileCoverageError):
                            authority.observe(rejected_execution)
                    finally:
                        fixture.restore_fields(rejected_execution, original)

            observation_projection_fields = tuple(
                field
                for field in type(reject_observation).__dataclass_fields__
                if not field.startswith("_") and field != "observation_digest"
            )
            for field in observation_projection_fields:
                with self.subTest(reviewer="R1-002-observation-resign", field=field):
                    original = fixture.coherently_resign_observation(
                        reject_observation, field,
                    )
                    try:
                        with self.assertRaises(ValueError):
                            reject_factory.issue_execution(
                                reject_observation,
                                matrix=matrix,
                                profile=profile,
                                overlay=overlay,
                            )
                    finally:
                        fixture.restore_fields(reject_observation, original)
            (
                _positive_api,
                positive_application,
                positive_probe,
                positive_target,
            ) = fixture.production_runtime(
                task_id=fixture.coverage_task_id(fixture.PASS_TEST_ID),
            )
            try:
                positive_candidate = fixture.category.candidate_document(
                    "new-feature", "normal"
                )
                positive_candidate["task_id"] = fixture.coverage_task_id(
                    fixture.PASS_TEST_ID
                )
                positive_application.assess_and_commit(
                    positive_candidate,
                    observer=positive_target,
                )
                positive_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=positive_application,
                    task_application=positive_probe.task_application,
                    repository=positive_probe.repository,
                    object_repository=positive_probe.objects,
                    runtime=positive_probe.runtime,
                )
                positive_execution = positive_authority.observe_completion(
                    fixture.PASS_TEST_ID,
                    task_id=positive_probe.task_id,
                    expected_profile_id="new-feature",
                )
                (
                    _rollback_positive_api,
                    rollback_positive_application,
                    rollback_positive_probe,
                    rollback_positive_target,
                ) = fixture.production_runtime(
                    "rollback",
                    task_id=fixture.coverage_task_id(
                        fixture.ROLLBACK_PASS_TEST_ID
                    ),
                )
                scenario_positive_target = None
                try:
                    rollback_positive_candidate = fixture.rollback_candidate()
                    rollback_positive_candidate["task_id"] = (
                        fixture.coverage_task_id(fixture.ROLLBACK_PASS_TEST_ID)
                    )
                    rollback_positive_application.assess_and_commit(
                        rollback_positive_candidate,
                        observer=rollback_positive_target,
                    )
                    rollback_positive_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=rollback_positive_application,
                        task_application=rollback_positive_probe.task_application,
                        repository=rollback_positive_probe.repository,
                        object_repository=rollback_positive_probe.objects,
                        runtime=rollback_positive_probe.runtime,
                    )
                    rollback_positive_execution = (
                        rollback_positive_authority.observe_completion(
                            fixture.ROLLBACK_PASS_TEST_ID,
                            task_id=rollback_positive_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                    )
                    (
                        _scenario_positive_api,
                        scenario_positive_application,
                        scenario_positive_probe,
                        scenario_positive_target,
                    ) = fixture.production_runtime(
                        "boundary", scenario_id=fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                        task_id=fixture.coverage_task_id(
                            fixture.SCAFFOLD_PASS_TEST_ID
                        ),
                    )
                    scenario_positive_candidate = fixture.scaffold_candidate(
                        accepted=True
                    )
                    scenario_positive_candidate["task_id"] = (
                        fixture.coverage_task_id(fixture.SCAFFOLD_PASS_TEST_ID)
                    )
                    scenario_positive_application.assess_and_commit(
                        scenario_positive_candidate,
                        observer=scenario_positive_target,
                    )
                    scenario_positive_authority = api4.ProfileCoverageAuthority(
                        plan=plan,
                        category_application=scenario_positive_application,
                        task_application=scenario_positive_probe.task_application,
                        repository=scenario_positive_probe.repository,
                        object_repository=scenario_positive_probe.objects,
                        runtime=scenario_positive_probe.runtime,
                    )
                    scenario_positive_execution = (
                        scenario_positive_authority.observe_completion(
                            fixture.SCAFFOLD_PASS_TEST_ID,
                            task_id=scenario_positive_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                    )
                    factory = api.CoverageRecordFactory(
                        execution_authority=(
                            positive_authority,
                            authority,
                            rollback_positive_authority,
                            rollback_authority,
                            scenario_positive_authority,
                            scenario_authority,
                            *(
                                item.authority
                                for item in existing_feature_results
                            ),
                            *(
                                item.authority
                                for item in reproducible_failure_results
                            ),
                            *(
                                item.authority
                                for item in false_reproduction_results
                            ),
                            *(
                                item.authority
                                for item in regression_boundary_results
                            ),
                            *(
                                item.authority
                                for item in minimal_patch_results
                            ),
                            *(
                                item.authority
                                for item in stable_baseline_results
                            ),
                            *(
                                item.authority
                                for item in vulnerable_graph_results
                            ),
                            *batch_authorities,
                            *bug_fix_authorities,
                            *(result.authority for result in hotfix_results),
                            *(
                                result.authority
                                for result in refactor_debt_results
                            ),
                            *(
                                result.authority
                                for result in incident_response_results
                            ),
                            *(
                                result.authority
                                for result in migration_results
                            ),
                            *(
                                result.authority
                                for result in dependency_security_results
                            ),
                            *(
                                result.authority
                                for result in performance_results
                            ),
                        ),
                        coverage_policy=coverage,
                    )
                    reject_record = factory.issue_execution(
                        reject_observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    positive_record = factory.issue_execution(
                        positive_authority.observe(positive_execution),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    rollback_reject_record = factory.issue_execution(
                        rollback_reject_observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    rollback_positive_record = factory.issue_execution(
                        rollback_positive_authority.observe(
                            rollback_positive_execution,
                        ),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    scenario_reject_record = factory.issue_execution(
                        scenario_reject_observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    scenario_positive_record = factory.issue_execution(
                        scenario_positive_authority.observe(
                            scenario_positive_execution,
                        ),
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                    existing_feature_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        for observation in existing_feature_observations
                    )
                    reproducible_failure_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=bug_profile,
                            overlay=bug_overlay,
                        )
                        for observation in reproducible_failure_observations
                    )
                    false_reproduction_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=bug_profile,
                            overlay=bug_overlay,
                        )
                        for observation in false_reproduction_observations
                    )
                    regression_boundary_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=bug_profile,
                            overlay=bug_overlay,
                        )
                        for observation in regression_boundary_observations
                    )
                    minimal_patch_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=hotfix_profile,
                            overlay=hotfix_overlay,
                        )
                        for observation in minimal_patch_observations
                    )
                    stable_baseline_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=performance_profile,
                            overlay=performance_overlay,
                        )
                        for observation in stable_baseline_observations
                    )
                    vulnerable_graph_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=dependency_profile,
                            overlay=dependency_overlay,
                        )
                        for observation in vulnerable_graph_observations
                    )
                    dependency_graph_scenario_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=dependency_profile,
                            overlay=dependency_overlay,
                        )
                        for observation in dependency_graph_scenario_observations
                    )
                    batch_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=profile,
                            overlay=overlay,
                        )
                        for observation in batch_observations
                    )
                    bug_fix_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=bug_profile,
                            overlay=bug_overlay,
                        )
                        for observation in bug_fix_observations
                    )
                    hotfix_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=hotfix_profile,
                            overlay=hotfix_overlay,
                        )
                        for observation in hotfix_observations
                    )
                    refactor_debt_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=refactor_profile,
                            overlay=refactor_overlay,
                        )
                        for observation in refactor_debt_observations
                    )
                    incident_response_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=incident_profile,
                            overlay=incident_overlay,
                        )
                        for observation in incident_response_observations
                    )
                    migration_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=migration_profile,
                            overlay=migration_overlay,
                        )
                        for observation in migration_observations
                    )
                    dependency_security_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=dependency_profile,
                            overlay=dependency_overlay,
                        )
                        for observation in dependency_security_observations
                    )
                    performance_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=performance_profile,
                            overlay=performance_overlay,
                        )
                        for observation in performance_observations
                    )
                    migration_scenario_records = tuple(
                        factory.issue_execution(
                            observation,
                            matrix=matrix,
                            profile=migration_profile,
                            overlay=migration_overlay,
                        )
                        for observation in migration_scenario_observations
                    )
                    combined_records = (
                            positive_record,
                            reject_record,
                            rollback_positive_record,
                            rollback_reject_record,
                            scenario_positive_record,
                            scenario_reject_record,
                            *existing_feature_records,
                            *reproducible_failure_records,
                            *false_reproduction_records,
                            *regression_boundary_records,
                            *minimal_patch_records,
                            *stable_baseline_records,
                            *vulnerable_graph_records,
                            *dependency_graph_scenario_records,
                            *migration_scenario_records,
                            *batch_records,
                            *bug_fix_records,
                            *hotfix_records,
                            *refactor_debt_records,
                            *incident_response_records,
                            *migration_records,
                            *dependency_security_records,
                            *performance_records,
                    )
                    decision = ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=combined_records,
                        coverage_factory=factory,
                    )
                    self.assertFalse(decision.passed)
                    self.assertEqual(len(batch_records), 20)
                    self.assertEqual(len(bug_fix_records), 24)
                    self.assertEqual(len(hotfix_records), 24)
                    self.assertEqual(len(refactor_debt_records), 24)
                    self.assertEqual(len(incident_response_records), 24)
                    self.assertEqual(len(migration_records), 24)
                    self.assertEqual(len(dependency_security_records), 24)
                    self.assertEqual(len(performance_records), 24)
                    self.assertEqual(len(existing_feature_records), 2)
                    self.assertEqual(len(reproducible_failure_records), 2)
                    self.assertEqual(len(false_reproduction_records), 2)
                    self.assertEqual(len(regression_boundary_records), 2)
                    self.assertEqual(len(minimal_patch_records), 2)
                    self.assertEqual(len(stable_baseline_records), 2)
                    self.assertEqual(len(vulnerable_graph_records), 2)
                    self.assertEqual(len(dependency_graph_scenario_records), 4)
                    self.assertEqual(len(migration_scenario_records), 8)
                    self.assertEqual(len(decision.missing_test_ids), 54)
                finally:
                    if scenario_positive_target is not None:
                        scenario_positive_target.close()
                    rollback_positive_target.close()

                with self.subTest(reviewer="R1-002-gate-coherent-chain"):
                    originals = fixture.coherently_substitute_issued_chain(
                        rejected_execution,
                        reject_observation,
                        reject_record,
                        "profile_digest",
                    )
                    try:
                        with self.assertRaises(ValueError):
                            ReleaseCoverageGate.evaluate(
                                matrix,
                                coverage_records=(positive_record, reject_record),
                                coverage_factory=factory,
                            )
                    finally:
                        fixture.restore_fields(rejected_execution, originals[0])
                        fixture.restore_fields(reject_observation, originals[1])
                        fixture.restore_fields(reject_record, originals[2])
            finally:
                positive_target.close()

            with self.assertRaises(api4.ProfileCoverageError):
                authority.observe(fixture.clone_opaque(rejected_execution))
            foreign = api4.ProfileCoverageAuthority(
                plan=plan,
                category_application=application,
                task_application=probe.task_application,
                repository=probe.repository,
                object_repository=probe.objects,
                runtime=probe.runtime,
            )
            with self.assertRaises(api4.ProfileCoverageError):
                foreign.observe(rejected_execution)
            with self.assertRaises(api4.ProfileCoverageError):
                authority.execute_rejection(
                    fixture.REJECT_TEST_ID,
                    candidate=fixture.coherent_candidate_variant(),
                    observer=target,
                )

            static_registry = api.EvidenceObservationRegistry.from_dict(
                slice1._evidence_registry_document(),
                coverage_policy=coverage,
                oracle_manifest_bytes=slice1._oracle_manifest_bytes(),
            )
            static_authority = api.EvidenceObservationAuthority(
                static_registry,
                evidence_root=slice1.ROOT / "tests/fixtures",
            )
            static_observation = static_authority.observe(
                fixture.PASS_TEST_ID,
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
            with self.subTest(reviewer="R1-004-static-diagnostic-counts-zero"):
                static_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=(static_record,),
                    coverage_factory=static_factory,
                )
                self.assertFalse(static_decision.passed)
                self.assertEqual(len(static_decision.missing_test_ids), 274)
            with self.assertRaises(ValueError):
                ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=(static_record, reject_record),
                    coverage_factory=factory,
                )

            attacks = (
                "assessment-delete",
                "assessment-replace",
                "typed-evidence-delete",
                "typed-evidence-replace",
                "revision-drift",
                "epoch-drift",
                "graph-ref-drift",
                "post-observation-replacement",
            )
            for attack in attacks:
                with self.subTest(attack=attack):
                    category_api, attacked_app, attacked_probe, attacked_target = (
                        fixture.production_runtime(
                            task_id=fixture.coverage_task_id(
                                fixture.PASS_TEST_ID
                            ),
                        )
                    )
                    try:
                        attacked_candidate = fixture.category.candidate_document(
                            "new-feature", "normal"
                        )
                        attacked_candidate["task_id"] = fixture.coverage_task_id(
                            fixture.PASS_TEST_ID
                        )
                        attacked_app.assess_and_commit(
                            attacked_candidate,
                            observer=attacked_target,
                        )
                        attacked_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=attacked_app,
                            task_application=attacked_probe.task_application,
                            repository=attacked_probe.repository,
                            object_repository=attacked_probe.objects,
                            runtime=attacked_probe.runtime,
                        )
                        observed = attacked_authority.observe_completion(
                            fixture.PASS_TEST_ID,
                            task_id=attacked_probe.task_id,
                            expected_profile_id="new-feature",
                        )
                        fixture.apply_currentness_attack(
                            attack, attacked_probe, observed,
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            attacked_authority.observe(observed)
                    finally:
                        attacked_target.close()

            for attack in (
                "typed-evidence-delete",
                "typed-evidence-replace",
                "post-observation-replacement",
            ):
                with self.subTest(
                    stable_id=fixture.SCAFFOLD_REJECT_TEST_ID,
                    attack=attack,
                ):
                    (
                        _scenario_attack_api,
                        scenario_attack_app,
                        scenario_attack_probe,
                        scenario_attack_target,
                    ) = fixture.production_runtime(
                        "boundary", scenario_id=fixture.SCAFFOLD_BOUNDARY_CASE_ID,
                        task_id=fixture.coverage_task_id(
                            fixture.SCAFFOLD_PASS_TEST_ID
                        ),
                    )
                    try:
                        scenario_attack_app.assess_and_commit(
                            fixture.scaffold_candidate(accepted=True),
                            observer=scenario_attack_target,
                        )
                        scenario_attack_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=scenario_attack_app,
                            task_application=scenario_attack_probe.task_application,
                            repository=scenario_attack_probe.repository,
                            object_repository=scenario_attack_probe.objects,
                            runtime=scenario_attack_probe.runtime,
                        )
                        scenario_observed = (
                            scenario_attack_authority.observe_completion(
                                fixture.SCAFFOLD_PASS_TEST_ID,
                                task_id=scenario_attack_probe.task_id,
                                expected_profile_id="new-feature",
                            )
                        )
                        fixture.apply_currentness_attack(
                            attack,
                            scenario_attack_probe,
                            scenario_observed,
                            column="boundary",
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            scenario_attack_authority.observe(scenario_observed)
                    finally:
                        scenario_attack_target.close()

            for attack in (
                "typed-evidence-delete",
                "typed-evidence-replace",
                "post-observation-replacement",
            ):
                with self.subTest(
                    stable_id=fixture.EXISTING_FEATURE_REJECT_TEST_ID,
                    attack=attack,
                ):
                    (
                        _existing_attack_api,
                        existing_attack_app,
                        existing_attack_probe,
                        existing_attack_target,
                    ) = fixture.production_runtime(
                        "boundary",
                        scenario_id=fixture.EXISTING_FEATURE_BOUNDARY_CASE_ID,
                        task_id=fixture.coverage_task_id(
                            fixture.EXISTING_FEATURE_PASS_TEST_ID
                        ),
                    )
                    try:
                        existing_attack_app.assess_and_commit(
                            fixture.existing_feature_candidate(accepted=True),
                            observer=existing_attack_target,
                        )
                        existing_attack_authority = api4.ProfileCoverageAuthority(
                            plan=plan,
                            category_application=existing_attack_app,
                            task_application=existing_attack_probe.task_application,
                            repository=existing_attack_probe.repository,
                            object_repository=existing_attack_probe.objects,
                            runtime=existing_attack_probe.runtime,
                        )
                        existing_observed = (
                            existing_attack_authority.observe_completion(
                                fixture.EXISTING_FEATURE_PASS_TEST_ID,
                                task_id=existing_attack_probe.task_id,
                                expected_profile_id="new-feature",
                            )
                        )
                        fixture.apply_currentness_attack(
                            attack,
                            existing_attack_probe,
                            existing_observed,
                            column="boundary",
                        )
                        with self.assertRaises(api4.ProfileCoverageError):
                            existing_attack_authority.observe(existing_observed)
                    finally:
                        existing_attack_target.close()

            with self.subTest(reviewer="R1-003-source-post-attestation"):
                self.assertTrue(
                    fixture.source_post_attestation_mutation_is_rejected()
                )
            for attack, returncode in (
                fixture.installed_distribution_attack_returncodes().items()
            ):
                with self.subTest(reviewer="R1-003-installed-distribution", attack=attack):
                    self.assertNotEqual(returncode, 0)

            execution_schema = fixture.category.load_json(
                fixture.category.ROOT
                / "config/contracts/schemas/profile-coverage-execution-record-1.0.0.json"
            )
            observation_schema = fixture.category.load_json(
                fixture.category.ROOT
                / "config/contracts/schemas/profile-coverage-observation-1.0.0.json"
            )
            with self.subTest(reviewer="R1-005-exact-digest-patterns"):
                self.assertEqual(
                    execution_schema["$defs"]["object"]["pattern"],
                    "^sha256:[0-9a-f]{64}$",
                )
                self.assertEqual(
                    observation_schema["properties"]["evidence_ref"]["pattern"],
                    "^profile-coverage-execution:sha256:[0-9a-f]{64}$",
                )
            schemas, schema_context = fixture.category.category_schema_registry()
            real_e2e_registry_schema_id = (
                "urn:gew:schema:profile-real-e2e-binding-registry-input:1.0.0"
            )
            real_e2e_registry = fixture.category.load_json(
                fixture.category.ROOT
                / "config/profiles/profile-real-e2e-binding-registry-v1.json"
            )
            self.assertEqual(
                schemas.validate(
                    real_e2e_registry_schema_id,
                    real_e2e_registry,
                    schema_context,
                ),
                [],
            )
            self.assertEqual(
                tuple(
                    item["profile_id"]
                    for item in real_e2e_registry["profiles"]
                ),
                (
                    "bug-fix", "dependency-security", "hotfix",
                    "incident-response", "migration", "new-feature",
                    "refactor-debt",
                ),
            )
            for attack in (
                "missing-migration", "extra-profile", "profile-reorder",
                "coherent-resign",
            ):
                changed_registry = copy.deepcopy(real_e2e_registry)
                profiles = changed_registry["profiles"]
                self.assertIsInstance(profiles, list)
                if attack == "missing-migration":
                    profiles[:] = [
                        item for item in profiles
                        if item["profile_id"] != "migration"
                    ]
                elif attack == "extra-profile":
                    profiles.append(copy.deepcopy(profiles[-1]))
                elif attack == "profile-reorder":
                    profiles[2], profiles[3] = profiles[3], profiles[2]
                else:
                    migration_binding = next(
                        item for item in profiles
                        if item["profile_id"] == "migration"
                    )
                    migration_binding["bindings"][0]["reconcile_route"] = (
                        "coherently-resigned-route"
                    )
                if attack == "coherent-resign":
                    from graph_engineering.core.contracts.digest import (
                        semantic_digest,
                    )

                    changed_registry.pop("registry_digest")
                    changed_registry["registry_digest"] = semantic_digest(
                        changed_registry,
                        contract_type=(
                            "urn:gew:contract:profile-real-e2e-binding-registry"
                        ),
                        projection_id=(
                            "urn:gew:digest-projection:"
                            "profile-real-e2e-binding-registry:1.0.0"
                        ),
                        schema_id=(
                            "urn:gew:schema:"
                            "profile-real-e2e-binding-registry:1.0.0"
                        ),
                    )
                with self.subTest(
                    phase="migration-real-e2e-schema-closure",
                    attack=attack,
                ):
                    self.assertTrue(schemas.validate(
                        real_e2e_registry_schema_id,
                        changed_registry,
                        schema_context,
                    ))
            execution_document = rejected_execution.to_dict()
            observation_document = {
                "schema_version": "1.0.0",
                **{
                    field: getattr(reject_observation, field)
                    for field in type(reject_observation).__dataclass_fields__
                    if not field.startswith("_")
                },
            }
            self.assertEqual(schemas.validate(
                "urn:gew:schema:profile-coverage-execution-record:1.0.0",
                execution_document,
                schema_context,
            ), [])
            self.assertEqual(schemas.validate(
                "urn:gew:schema:profile-coverage-observation:1.0.0",
                observation_document,
                schema_context,
            ), [])
            invalid_digest_suffixes = (
                "a" * 63,
                "a" * 65,
                "A" * 64,
                "g" * 64,
            )
            for invalid in (
                "a" * 64,
                *("sha256-jcs-v1:" + suffix for suffix in invalid_digest_suffixes),
            ):
                with self.subTest(reviewer="R1-005-semantic-digest", invalid=invalid):
                    changed = copy.deepcopy(execution_document)
                    changed["request_digest"] = invalid
                    self.assertTrue(schemas.validate(
                        "urn:gew:schema:profile-coverage-execution-record:1.0.0",
                        changed,
                        schema_context,
                    ))
            for invalid in (
                "a" * 64,
                *("sha256:" + suffix for suffix in invalid_digest_suffixes),
            ):
                with self.subTest(reviewer="R1-005-object-digest", invalid=invalid):
                    changed = copy.deepcopy(observation_document)
                    changed["evidence_digest"] = invalid
                    self.assertTrue(schemas.validate(
                        "urn:gew:schema:profile-coverage-observation:1.0.0",
                        changed,
                        schema_context,
                    ))
            for invalid in (
                "sha256:" + "a" * 64,
                *("profile-coverage-execution:sha256:" + suffix
                  for suffix in invalid_digest_suffixes),
                "profile-coverage-execution:sha256:" + "a" * 64 + "x",
            ):
                with self.subTest(reviewer="R1-005-evidence-ref", invalid=invalid):
                    changed = copy.deepcopy(observation_document)
                    changed["evidence_ref"] = invalid
                    self.assertTrue(schemas.validate(
                        "urn:gew:schema:profile-coverage-observation:1.0.0",
                        changed,
                        schema_context,
                    ))

            with self.subTest(
                finding="WP08-S4-AUTHORITY-LIFECYCLE",
                phase="partial-and-foreign-finalize-fail-closed",
            ):
                partial_factory = api.CoverageRecordFactory(
                    execution_authority=authority,
                    coverage_policy=coverage,
                )
                partial_record = partial_factory.issue_execution(
                    reject_observation,
                    matrix=matrix,
                    profile=profile,
                    overlay=overlay,
                )
                partial_decision = ReleaseCoverageGate.evaluate(
                    matrix,
                    coverage_records=(partial_record,),
                    coverage_factory=partial_factory,
                )
                with self.assertRaises(ValueError):
                    partial_factory.finalize_after_gate(partial_decision)
                foreign_decision = type(decision)(
                    decision.passed,
                    decision.missing_test_ids,
                    decision.invalid_test_ids,
                    decision.stale_test_ids,
                    decision.assessment_digest,
                )
                with self.assertRaises(ValueError):
                    factory.finalize_after_gate(foreign_decision)
                self.assertIs(
                    authority._require_observation(reject_observation),
                    reject_observation,
                )

                partial_abort_capability = (
                    partial_factory.prepare_abort_uncommitted_candidate()
                )
                self.assertIs(
                    partial_factory.prepare_abort_uncommitted_candidate(),
                    partial_abort_capability,
                )
                partial_factory.abort_uncommitted_candidate(
                    partial_abort_capability,
                )
                partial_factory.abort_uncommitted_candidate(
                    partial_abort_capability,
                )
                self.assertIs(
                    authority._require_observation(reject_observation),
                    reject_observation,
                )

            with self.subTest(
                finding="WP08-S4-AUTHORITY-LIFECYCLE",
                phase="pre-gate-abort-atomic-handoff-and-revocation",
            ):
                abort_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=application,
                    task_application=probe.task_application,
                    repository=probe.repository,
                    object_repository=probe.objects,
                    runtime=probe.runtime,
                )
                abort_execution = abort_authority.execute_rejection(
                    fixture.REJECT_TEST_ID,
                    candidate=copy.deepcopy(rejected),
                    observer=target,
                )
                abort_observation = abort_authority.observe(abort_execution)
                abort_factory = api.CoverageRecordFactory(
                    execution_authority=abort_authority,
                    coverage_policy=coverage,
                )
                abort_record = abort_factory.issue_execution(
                    abort_observation,
                    matrix=matrix,
                    profile=profile,
                    overlay=overlay,
                )
                abort_record_document = abort_record.to_dict()
                abort_durable_before = probe.signature()

                with mock.patch.object(
                    api.CoverageRecordFactory,
                    "_freeze_abort_preparation",
                    side_effect=RuntimeError("before-abort-tuple"),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "before-abort-tuple",
                    ):
                        abort_factory.prepare_abort_uncommitted_candidate()
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__lifecycle[0],
                    "active-uncommitted",
                )
                self.assertIs(
                    abort_authority._require_observation(abort_observation),
                    abort_observation,
                )

                with mock.patch.object(
                    api.CoverageRecordFactory,
                    "_return_prepared_abort_capability",
                    side_effect=RuntimeError("abort-capability-return-lost"),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "abort-capability-return-lost",
                    ):
                        abort_factory.prepare_abort_uncommitted_candidate()
                prepared_state = (
                    abort_factory._CoverageRecordFactory__lifecycle
                )
                self.assertEqual(prepared_state[0], "abort-prepared")
                prepared = prepared_state[1]
                abort_capability = (
                    abort_factory.prepare_abort_uncommitted_candidate()
                )
                self.assertIs(abort_capability, prepared.capability)
                self.assertIs(
                    abort_factory.prepare_abort_uncommitted_candidate(),
                    abort_capability,
                )
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__lifecycle[1]
                    .projection_digest,
                    prepared.projection_digest,
                )
                with self.assertRaises(ValueError):
                    abort_factory.issue_execution(
                        abort_observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                with self.assertRaises(ValueError):
                    ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(abort_record,),
                        coverage_factory=abort_factory,
                    )
                with self.assertRaises(ValueError):
                    abort_factory.finalize_after_gate(decision)
                with self.assertRaises(ValueError):
                    abort_authority._coverage_registration._register_factory(
                        abort_authority,
                        abort_factory,
                    )

                clone_capability = object.__new__(type(abort_capability))
                with self.assertRaises(ValueError):
                    abort_factory.abort_uncommitted_candidate(
                        clone_capability,
                    )
                with self.assertRaises(TypeError):
                    pickle.dumps(abort_capability)

                original_record_digest = abort_record.record_digest
                object.__setattr__(
                    abort_record,
                    "record_digest",
                    "sha256-jcs-v1:" + "f" * 64,
                )
                with self.assertRaisesRegex(
                    ValueError, "coverage abort frozen projection changed",
                ):
                    abort_factory.abort_uncommitted_candidate(
                        abort_capability,
                    )
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__lifecycle[0],
                    "abort-prepared",
                )
                object.__setattr__(
                    abort_record,
                    "record_digest",
                    original_record_digest,
                )

                foreign_abort_authority = api4.ProfileCoverageAuthority(
                    plan=plan,
                    category_application=application,
                    task_application=probe.task_application,
                    repository=probe.repository,
                    object_repository=probe.objects,
                    runtime=probe.runtime,
                )
                foreign_abort_factory = api.CoverageRecordFactory(
                    execution_authority=foreign_abort_authority,
                    coverage_policy=coverage,
                )
                foreign_abort_capability = (
                    foreign_abort_factory.prepare_abort_uncommitted_candidate()
                )
                with self.assertRaises(ValueError):
                    abort_factory.abort_uncommitted_candidate(
                        foreign_abort_capability,
                    )
                with self.assertRaises(ValueError):
                    foreign_abort_factory.abort_uncommitted_candidate(
                        abort_capability,
                    )
                foreign_abort_factory.abort_uncommitted_candidate(
                    foreign_abort_capability,
                )

                abort_registration = abort_factory._execution_registrations[0][1]
                registration_type = type(abort_registration)
                original_revoke = registration_type._revoke
                injected_after_revoke = False

                def revoke_then_lose_return(
                    registration: object,
                    authority_to_revoke: object,
                    factory_to_revoke: object,
                    registration_capability: object,
                ) -> None:
                    nonlocal injected_after_revoke
                    original_revoke(
                        registration,
                        authority_to_revoke,
                        factory_to_revoke,
                        registration_capability,
                    )
                    if (
                        registration is abort_registration
                        and not injected_after_revoke
                    ):
                        injected_after_revoke = True
                        raise RuntimeError("abort-revoke-return-lost")

                with mock.patch.object(
                    registration_type,
                    "_revoke",
                    new=revoke_then_lose_return,
                ):
                    with self.assertRaisesRegex(
                        ValueError, "coverage abort revocation is incomplete",
                    ):
                        abort_factory.abort_uncommitted_candidate(
                            abort_capability,
                        )
                self.assertTrue(injected_after_revoke)
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__lifecycle[0],
                    "aborting",
                )
                abort_factory.abort_uncommitted_candidate(abort_capability)
                abort_factory.abort_uncommitted_candidate(abort_capability)
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__lifecycle,
                    ("aborted", abort_capability),
                )
                self.assertEqual(
                    abort_factory._CoverageRecordFactory__issued,
                    {},
                )
                self.assertEqual(abort_factory._execution_registrations, ())
                self.assertEqual(abort_record.to_dict(), abort_record_document)
                self.assertEqual(probe.signature(), abort_durable_before)
                with self.assertRaises(ValueError):
                    abort_factory.prepare_abort_uncommitted_candidate()
                with self.assertRaises(ValueError):
                    abort_factory.require_issued(abort_record, matrix=matrix)
                with self.assertRaises(ValueError):
                    ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=(abort_record,),
                        coverage_factory=abort_factory,
                    )
                with self.assertRaises(ValueError):
                    abort_factory.finalize_after_gate(decision)
                with self.assertRaises(api4.ProfileCoverageError):
                    abort_authority.observe(abort_execution)
                with self.assertRaises(ValueError):
                    api.CoverageRecordFactory(
                        execution_authority=abort_authority,
                        coverage_policy=coverage,
                    )

                reject_abort_capability = (
                    reject_factory.prepare_abort_uncommitted_candidate()
                )
                reject_factory.abort_uncommitted_candidate(
                    reject_abort_capability,
                )
                self.assertIs(
                    authority._require_observation(reject_observation),
                    reject_observation,
                )

            with self.subTest(
                finding="WP08-S4-AUTHORITY-LIFECYCLE",
                phase="combined-gate-finalize-and-revoke",
            ):
                self.assertEqual(len(combined_records), 220)
                self.assertEqual(len({id(item) for item in combined_records}), 220)
                self.assertEqual(
                    len(factory._CoverageRecordFactory__issued),
                    220,
                )
                durable_before_close = probe.signature()
                record_documents = tuple(item.to_dict() for item in combined_records)
                decision_projection = (
                    decision.passed,
                    decision.missing_test_ids,
                    decision.invalid_test_ids,
                    decision.stale_test_ids,
                    decision.assessment_digest,
                )
                factory.finalize_after_gate(decision)
                factory.finalize_after_gate(decision)
                self.assertEqual(factory._CoverageRecordFactory__issued, {})
                self.assertEqual(factory._execution_registrations, ())
                self.assertEqual(
                    tuple(item.to_dict() for item in combined_records),
                    record_documents,
                )
                self.assertEqual(
                    (
                        decision.passed,
                        decision.missing_test_ids,
                        decision.invalid_test_ids,
                        decision.stale_test_ids,
                        decision.assessment_digest,
                    ),
                    decision_projection,
                )
                self.assertEqual(probe.signature(), durable_before_close)
                with self.assertRaises(ValueError):
                    factory.require_issued(positive_record, matrix=matrix)
                with self.assertRaises(ValueError):
                    factory.issue_execution(
                        reject_observation,
                        matrix=matrix,
                        profile=profile,
                        overlay=overlay,
                    )
                with self.assertRaises(ValueError):
                    ReleaseCoverageGate.evaluate(
                        matrix,
                        coverage_records=combined_records,
                        coverage_factory=factory,
                    )
                with self.assertRaises(api4.ProfileCoverageError):
                    authority.observe(rejected_execution)
                closed_candidate = fixture.rejected_candidate()
                closed_candidate["task_id"] = fixture.coverage_task_id(
                    fixture.REJECT_TEST_ID
                )
                closed_candidate_before = copy.deepcopy(closed_candidate)
                closed_state_before = probe.signature()
                with self.assertRaises(api4.ProfileCoverageError):
                    authority.execute_rejection(
                        fixture.REJECT_TEST_ID,
                        candidate=closed_candidate,
                        observer=target,
                    )
                self.assertEqual(closed_candidate, closed_candidate_before)
                self.assertEqual(probe.signature(), closed_state_before)
                with self.assertRaises(ValueError):
                    api.CoverageRecordFactory(
                        execution_authority=authority,
                        coverage_policy=coverage,
                    )
        finally:
            for result in reversed(migration_scenario_results):
                result.close()
            for result in reversed(dependency_graph_scenario_results):
                result.close()
            for result in reversed(vulnerable_graph_results):
                result.close()
            for result in reversed(minimal_patch_results):
                result.close()
            for result in reversed(regression_boundary_results):
                result.close()
            for result in reversed(false_reproduction_results):
                result.close()
            for result in reversed(reproducible_failure_results):
                result.close()
            for result in reversed(existing_feature_results):
                result.close()
            for result in reversed(performance_results):
                result.close()
            for result in reversed(dependency_security_results):
                result.close()
            for result in reversed(migration_results):
                result.close()
            for result in reversed(incident_response_results):
                result.close()
            for result in reversed(refactor_debt_results):
                result.close()
            for result in reversed(hotfix_results):
                result.close()
            if refactor_shared is not None:
                refactor_shared.close()
            if incident_shared is not None:
                incident_shared.close()
            if migration_shared is not None:
                migration_shared.close()
            if dependency_security_shared is not None:
                dependency_security_shared.close()
            if performance_shared is not None:
                performance_shared.close()
            if hotfix_shared is not None:
                hotfix_shared.close()
            for real_e2e_probe in reversed(bug_fix_real_probes):
                real_e2e_probe.close()
            for batch_target in reversed(bug_fix_targets):
                batch_target.close()
            for real_e2e_probe in reversed(real_e2e_probes):
                real_e2e_probe.close()
            for batch_target in reversed(batch_targets):
                batch_target.close()
            if scenario_target is not None:
                scenario_target.close()
            if rollback_target is not None:
                rollback_target.close()
            target.close()
            migration_results.clear()
            dependency_security_results.clear()
            performance_results.clear()
            existing_feature_results.clear()
            reproducible_failure_results.clear()
            false_reproduction_results.clear()
            regression_boundary_results.clear()
            minimal_patch_results.clear()
            stable_baseline_results.clear()
            vulnerable_graph_results.clear()
            dependency_graph_scenario_results.clear()
            migration_scenario_results.clear()
            incident_response_results.clear()
            refactor_debt_results.clear()
            hotfix_results.clear()
            batch_targets.clear()
            real_e2e_probes.clear()
            batch_authorities.clear()
            batch_observations.clear()
            bug_fix_targets.clear()
            bug_fix_real_probes.clear()
            bug_fix_authorities.clear()
            bug_fix_observations.clear()
            hotfix_observations = ()
            refactor_debt_observations = ()
            incident_response_observations = ()
            migration_observations = ()
            dependency_security_observations = ()
            performance_observations = ()
            existing_feature_observations = ()
            reproducible_failure_observations = ()
            false_reproduction_observations = ()
            regression_boundary_observations = ()
            minimal_patch_observations = ()
            stable_baseline_observations = ()
            vulnerable_graph_observations = ()
            batch_records = ()
            bug_fix_records = ()
            hotfix_records = ()
            refactor_debt_records = ()
            incident_response_records = ()
            migration_records = ()
            dependency_security_records = ()
            performance_records = ()
            existing_feature_records = ()
            reproducible_failure_records = ()
            false_reproduction_records = ()
            regression_boundary_records = ()
            minimal_patch_records = ()
            stable_baseline_records = ()
            vulnerable_graph_records = ()
            dependency_graph_scenario_records = ()
            combined_records = ()
            record_documents = ()
