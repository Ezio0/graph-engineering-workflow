"""Contracts for the Human-approved GEW-REMAINING54-V1 closure."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
import tomllib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "application"))
sys.path.insert(0, str(ROOT))

from tests.support import wp08_release_coverage as fixture  # noqa: E402
from tests.unit import test_wp08_profile_contracts as contracts  # noqa: E402


class Remaining54P1ContractsTest(unittest.TestCase):
    """Freeze the exact additive P1 execution-plan boundary."""

    def test_p1_oracle_input_v11_is_typed_closed_and_versioned(self) -> None:
        from graph_engineering.core.contracts.schema import (
            SchemaProfilePolicy,
            validate_instance,
            validate_schema_profile,
        )

        schema_path = (
            ROOT
            / "config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json"
        )
        schema = json.loads(schema_path.read_text())
        policy = SchemaProfilePolicy.from_dict(json.loads(
            (ROOT / "config/contracts/schema-profile-v1.json").read_text()
        ))
        self.assertEqual(
            validate_schema_profile(schema, policy),
            "urn:gew:schema:profile-coverage-oracle-input:1.1.0",
        )
        self.assertIs(schema.get("unevaluatedProperties"), False)

        oracle = json.loads((
            ROOT / "config/test-oracles/profile-performance-noise-outlier-v1.json"
        ).read_text())
        self.assertEqual(oracle["schema_version"], "1.1.0")
        self.assertEqual(
            oracle["rejection_input"],
            {"kind": "integer-vector", "values": [1, 2, 100, 200, 201]},
        )
        self.assertNotIn("[1,2,100,200,201]", oracle["reject_error_message"])
        digest_input = copy.deepcopy(oracle)
        digest_input.pop("oracle_digest")
        self.assertEqual(
            validate_instance(schema, digest_input, source_id=schema["$id"]),
            [],
        )
        for field, replacement in (
            ("oracle_id", "ORA-PROFILE-BUG-FIX"),
            ("profile_id", "bug-fix"),
            ("selector_kind", "mandatory"),
            ("column_id", "normal"),
            ("scenario_id", "correctness-regression"),
            (
                "category_boundary_case_id",
                "GEW-PSC-PERFORMANCE-CORRECTNESS-REGRESSION-P",
            ),
        ):
            changed = copy.deepcopy(digest_input)
            changed[field] = replacement
            with self.subTest(tuple_substitution=field):
                self.assertTrue(validate_instance(
                    schema, changed, source_id=schema["$id"],
                ))

        mutations: list[tuple[str, object]] = [
            ("stringified", "[1,2,100,200,201]"),
            ("boolean", [1, 2, True, 200, 201]),
            ("float", [1, 2, 100.0, 200, 201]),
            ("zero", [0, 2, 100, 200, 201]),
            ("negative", [-1, 2, 100, 200, 201]),
            ("unsafe", [1, 2, 100, 200, 9007199254740992]),
            ("null", None),
            ("object", {"sample": 1}),
            ("nested", [1, 2, [100], 200, 201]),
        ]
        for label, values in mutations:
            changed = copy.deepcopy(digest_input)
            changed["rejection_input"]["values"] = values
            with self.subTest(mutation=label):
                self.assertTrue(validate_instance(
                    schema, changed, source_id=schema["$id"],
                ))

        generation_one_schema = json.loads((
            ROOT
            / "config/contracts/schemas/profile-coverage-oracle-input-1.0.0.json"
        ).read_text())
        generation_one = json.loads((
            ROOT
            / "config/test-oracles/profile-bug-fix-normal-v1.json"
        ).read_text())
        generation_one.pop("oracle_digest")
        generation_one["rejection_input"] = copy.deepcopy(
            digest_input["rejection_input"]
        )
        generation_one_failures = validate_instance(
            generation_one_schema,
            generation_one,
            source_id=generation_one_schema["$id"],
        )
        self.assertTrue(generation_one_failures)
        self.assertIn(
            ("rejection_input",),
            tuple(item.instance_path for item in generation_one_failures),
        )

        core_source = (
            ROOT / "core/graph_engineering/core/profile_coverage.py"
        ).read_text()
        for forbidden in (
            "noise-outlier",
            "correctness-regression",
            "[1, 2, 100, 200, 201]",
            "noise_ceiling_numerator",
            "noise_ceiling_denominator",
        ):
            with self.subTest(core_literal=forbidden):
                self.assertNotIn(forbidden, core_source)
        for label, mutate in (
            ("missing-input", lambda value: value.pop("rejection_input")),
            (
                "extra-input-field",
                lambda value: value["rejection_input"].update({"outcome": "pass"}),
            ),
            (
                "message-encoded-vector",
                lambda value: (
                    value.pop("rejection_input"),
                    value.update({"reject_error_message": "[1,2,100,200,201]"}),
                ),
            ),
            (
                "cross-version",
                lambda value: value.update({"schema_version": "1.0.0"}),
            ),
        ):
            changed = copy.deepcopy(digest_input)
            mutate(changed)
            with self.subTest(mutation=label):
                self.assertTrue(validate_instance(
                    schema, changed, source_id=schema["$id"],
                ))

    def test_p1_preserves_generation_one_oracle_and_dependency_bytes(self) -> None:
        frozen = {
            "config/contracts/schemas/profile-coverage-oracle-input-1.0.0.json": (
                "5dfd2ce59af685b92bcc5b79a48ec1130c310ff701e65fdc6162f5eee8c96e98"
            ),
            "config/security/dependency-advisory-installation-bootstrap-v1.1.json": (
                "fb343c66de46daca5438aca54745492e637cfc558fc217b5818bb620b9920b76"
            ),
        }
        for member, expected in frozen.items():
            with self.subTest(member=member):
                self.assertEqual(
                    hashlib.sha256((ROOT / member).read_bytes()).hexdigest(),
                    expected,
                )

    def test_p1_plan_has_four_scenario_bindings_and_two_oracles(self) -> None:
        api = contracts._profile_api()
        coverage = contracts._coverage_policy()
        matrix = api.SupportMatrixDefinition.from_dict(
            contracts._support_matrix_document(),
            approved_profiles=contracts._approved_registry(),
            coverage_policy=coverage,
        )
        plan = fixture.load_slice4_api().ProfileCoverageExecutionPlan.from_installation(
            matrix=matrix,
        )

        self.assertEqual(len(plan.bindings), 274)
        self.assertEqual(len(plan.oracle_bindings), 137)
        self.assertEqual(
            tuple(
                test_id
                for test_id in fixture.PERFORMANCE_REMAINING_SCENARIO_TEST_IDS
                if test_id not in plan.bindings
            ),
            (),
        )
        for scenario_id in fixture.PERFORMANCE_REMAINING_SCENARIO_IDS:
            for disposition in ("P", "R"):
                test_id = (
                    f"GEW-PSC-PERFORMANCE-{scenario_id.upper()}-{disposition}"
                )
                binding = plan.binding(test_id)
                self.assertEqual(binding["profile_id"], "performance")
                self.assertEqual(binding["selector_kind"], "scenario")
                self.assertEqual(binding["scenario_id"], scenario_id)
                self.assertEqual(binding["column_id"], "boundary")
                self.assertEqual(binding["disposition"], disposition)
        self.assertIn(
            fixture.PERFORMANCE_REMAINING_R1_SELECTOR,
            fixture.VERIFIED_RUNNER_SELECTORS,
        )

    def test_p2a_cumulative_selector_contract_is_registered(self) -> None:
        self.assertEqual(
            fixture.P2A_CUMULATIVE_R2_SELECTOR,
            "p2a-cumulative-r2",
        )
        self.assertIn(
            fixture.P2A_CUMULATIVE_R2_SELECTOR,
            fixture.VERIFIED_RUNNER_SELECTORS,
        )
        self.assertTrue(callable(fixture.run_p2a_cumulative_r2_verified))

    def test_p1_verified_selector_closes_attacks_and_restart(self) -> None:
        receipt = fixture.run_performance_remaining_r1_verified()

        self.assertEqual(
            receipt["selector"], fixture.PERFORMANCE_REMAINING_R1_SELECTOR,
        )
        self.assertEqual(receipt["plan_bindings"], 274)
        self.assertEqual(receipt["oracle_bindings"], 137)
        self.assertEqual(receipt["restart"], "current-launcher-zero")
        self.assertEqual(
            tuple(sorted(receipt["scenario_attacks"])),
            tuple(sorted(fixture.PERFORMANCE_REMAINING_SCENARIO_IDS)),
        )
        self.assertEqual(
            tuple(sorted(receipt["retained_outliers"])),
            ("noise-outlier",),
        )
        self.assertEqual(
            receipt["noise_rejection"],
            {
                "kind": "integer-vector",
                "median": 100,
                "mad": 99,
                "left_product": 198,
                "right_product": 100,
                "outcome": "inconclusive-noise",
            },
        )
        self.assertEqual(
            tuple(receipt["correctness_rejections"]),
            (
                "caller-correct",
                "duration-only",
                "expected-substitution",
                "ignored-iteration",
                "observed-mismatch",
                "wrong-case",
                "wrong-phase",
            ),
        )
        for attacks in receipt["scenario_attacks"].values():
            self.assertEqual(len(attacks), 12)


class Remaining54P2bContractsTest(unittest.TestCase):
    def test_p2b_cumulative_entry_rejects_the_newer_current_plan_without_running(self):
        _, _, _, matrix, _, _, plan = fixture._verified_plan()
        checkpoint = fixture._cumulative_checkpoint("p2b-cumulative-r1")
        with self.assertRaises(AssertionError):
            fixture._validate_cumulative_plan(plan, matrix, checkpoint)
        self.assertEqual((checkpoint.plan_bindings, checkpoint.oracle_bindings,
                          checkpoint.missing_records), (230, 115, 44))
        self.assertEqual(checkpoint.new_test_ids, frozenset(
            f"GEW-PSC-HOTFIX-{scenario.upper()}-{disposition}"
            for scenario in ("emergency-baseline", "production-like-gate")
            for disposition in ("P", "R")))
        self.assertTrue(callable(fixture.run_p2b_cumulative_r1_verified))
        with self.assertRaises(AssertionError):
            fixture._validate_cumulative_plan(
                plan,
                matrix,
                fixture._cumulative_checkpoint("p2a-cumulative-r2"),
            )

    def test_all_touched_schemas_conform_to_frozen_schema_profile(self):
        from graph_engineering.core.contracts.schema import SchemaProfilePolicy, validate_schema_profile
        policy = SchemaProfilePolicy.from_dict(json.loads((ROOT / "config/contracts/schema-profile-v1.json").read_text()))
        for name in ("scenario-truth-fixture-registry", "scenario-truth-observation", "category-completion-assessment"):
            version = "1.3.0" if name == "category-completion-assessment" else "1.0.0"
            for suffix in ("", "-input"):
                schema = json.loads((ROOT / f"config/contracts/schemas/{name}{suffix}-{version}.json").read_text())
                self.assertEqual(validate_schema_profile(schema, policy), schema["$id"])

    def test_guarded_contracts_are_config_owned_and_closed(self):
        from graph_engineering.core.scenario_truth import validate_execution_contract, ScenarioTruthError
        rows = json.loads((ROOT / "config/profiles/scenario-truth-fixture-registry-v1.json").read_text())["fixtures"]
        guarded = [row for row in rows if "execution_contract" in row]
        self.assertEqual({(row["profile_id"], row["scenario_id"]) for row in guarded},
                         {("hotfix", scenario) for scenario in fixture.HOTFIX_GUARDED_SCENARIO_IDS})
        for row in guarded:
            value = row["execution_contract"]
            validate_execution_contract(value, row["target_roles"])
            for mutate in (
                lambda d: d.update(extra=True),
                lambda d: d.update(environment_classification="production"),
                lambda d: d.update(minimal_change_budget=True),
                lambda d: d.update(minimal_change_budget=-1),
                lambda d: d.update(impact_roles=[]),
                lambda d: d.update(containment_roles=["foreign"]),
                lambda d: d["controls"].pop(),
                lambda d: d["controls"][1].update(path_id=d["controls"][0]["path_id"]),
                lambda d: d["health_predicates"][0].update(target_role="foreign"),
                lambda d: d["health_predicates"][0].update(expected=1.5),
                lambda d: d["ordered_gates"].reverse(),
                lambda d: d["ordered_gates"].pop(),
            ):
                bad = copy.deepcopy(value)
                mutate(bad)
                with self.assertRaises(ScenarioTruthError): validate_execution_contract(bad, row["target_roles"])
        for path in (ROOT / "core/graph_engineering/core/scenario_truth.py",
                     ROOT / "application/graph_engineering/application/scenario_truth.py"):
            source = path.read_text()
            for scenario in fixture.HOTFIX_GUARDED_SCENARIO_IDS:
                self.assertNotIn(scenario, source)
            for row in guarded:
                self.assertNotIn(row["execution_contract"]["environment_id"], source)

    def test_p2b_plan_and_package_membership_are_exact(self):
        import tomllib
        from graph_engineering import _SOURCE_FILES
        from tests.support.source_checkout_attestation import SOURCE_FILES
        from tests.integration.test_wp08_scenario_truth import ScenarioTruthIntegrationTests
        plan = fixture.load_slice4_api().ProfileCoverageExecutionPlan.from_installation(
            matrix=ScenarioTruthIntegrationTests.matrix())
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (274, 137))
        manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
        table = manifest["tool"]["gew"]["profile"]["coverage-execution-plan"]
        for scenario in fixture.HOTFIX_GUARDED_SCENARIO_IDS:
            path = "config/test-oracles/profile-hotfix-" + scenario + "-v1.json"
            self.assertIn(path, _SOURCE_FILES)
            self.assertIn(path, SOURCE_FILES)
            vector = next(row for row in table["oracle-vectors"] if row["scenario-id"] == scenario)
            self.assertEqual(vector["oracle-source"], path)
            self.assertEqual(vector["oracle-resource"], "graph_engineering/" + path)
            self.assertEqual(vector["oracle-raw-sha256"], hashlib.sha256((ROOT / path).read_bytes()).hexdigest())
            for disposition in ("P", "R"):
                binding = plan.binding(f"GEW-PSC-HOTFIX-{scenario.upper()}-{disposition}")
                self.assertEqual(binding["profile_id"], "hotfix")
                self.assertEqual(binding["disposition"], disposition)
                self.assertEqual(binding["request_digest"], None if disposition == "P" else
                                 fixture.coverage_request_digest(fixture.hotfix_guarded_candidate(scenario, accepted=False)))


class Remaining54P2cContractsTest(unittest.TestCase):
    scenarios = (
        "architecture-invariant",
        "behavior-characterization",
        "nonfunctional-target",
    )

    def test_p2c_plan_oracles_and_package_membership_are_exact(self) -> None:
        import tomllib
        from graph_engineering import _SOURCE_FILES
        from tests.support.source_checkout_attestation import SOURCE_FILES
        from tests.integration.test_wp08_scenario_truth import ScenarioTruthIntegrationTests

        plan = fixture.load_slice4_api().ProfileCoverageExecutionPlan.from_installation(
            matrix=ScenarioTruthIntegrationTests.matrix(),
        )
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (274, 137))
        manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
        vectors = manifest["tool"]["gew"]["profile"]["coverage-execution-plan"]["oracle-vectors"]
        for scenario in self.scenarios:
            path = f"config/test-oracles/profile-refactor-debt-{scenario}-v1.json"
            self.assertTrue((ROOT / path).is_file())
            self.assertIn(path, _SOURCE_FILES)
            self.assertIn(path, SOURCE_FILES)
            vector = next(
                row for row in vectors
                if row.get("profile-id") == "refactor-debt"
                and row.get("scenario-id") == scenario
            )
            self.assertEqual(vector["oracle-source"], path)
            self.assertEqual(vector["oracle-resource"], "graph_engineering/" + path)
            self.assertEqual(
                vector["oracle-raw-sha256"],
                hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
            )
            for disposition in ("P", "R"):
                test_id = f"GEW-PSC-REFACTOR-DEBT-{scenario.upper()}-{disposition}"
                binding = plan.binding(test_id)
                self.assertEqual(binding["profile_id"], "refactor-debt")
                self.assertEqual(binding["scenario_id"], scenario)
                self.assertEqual(binding["disposition"], disposition)

    def test_refactor_values_are_config_owned_not_embedded_in_logic(self) -> None:
        rows = json.loads(
            (ROOT / "config/profiles/scenario-truth-fixture-registry-v1.json").read_text()
        )["fixtures"]
        refactor = [row for row in rows if "refactor_contract" in row]
        self.assertEqual(
            {(row["profile_id"], row["scenario_id"]) for row in refactor},
            {("refactor-debt", scenario) for scenario in self.scenarios},
        )
        sources = "\n".join(
            path.read_text()
            for path in (
                ROOT / "core/graph_engineering/core/scenario_truth.py",
                ROOT / "application/graph_engineering/application/scenario_truth.py",
            )
        )
        for row in refactor:
            contract = row["refactor_contract"]
            self.assertNotIn(contract["contract_id"], sources)
            self.assertNotIn(contract["environment_id"], sources)
            for case in contract["behavior_cases"]:
                self.assertNotIn(case["case_id"], sources)
            for edge in (*contract["required_edges"], *contract["forbidden_edges"]):
                self.assertNotIn(edge["from_path_id"], sources)
                self.assertNotIn(edge["to_path_id"], sources)
            if contract["nonfunctional_target"] is not None:
                self.assertNotIn(
                    contract["nonfunctional_target"]["metric_id"], sources,
                )
                self.assertNotIn(str(contract["nonfunctional_target"]["threshold"]), sources)


class Remaining54P2dContractsTest(unittest.TestCase):
    scenarios = ("containment", "detection", "recovery", "unknown-effects")

    def test_p2d_plan_oracles_and_package_membership_are_exact(self) -> None:
        import tomllib
        from graph_engineering import _SOURCE_FILES
        from tests.support.source_checkout_attestation import SOURCE_FILES
        from tests.integration.test_wp08_scenario_truth import (
            ScenarioTruthIntegrationTests,
        )

        plan = fixture.load_slice4_api().ProfileCoverageExecutionPlan.from_installation(
            matrix=ScenarioTruthIntegrationTests.matrix(),
        )
        self.assertEqual((len(plan.bindings), len(plan.oracle_bindings)), (274, 137))
        manifest = tomllib.loads((ROOT / "pyproject.toml").read_text())
        vectors = manifest["tool"]["gew"]["profile"]["coverage-execution-plan"][
            "oracle-vectors"
        ]
        for scenario in self.scenarios:
            suffix = "scenario-recovery" if scenario == "recovery" else scenario
            path = f"config/test-oracles/profile-incident-response-{suffix}-v1.json"
            self.assertTrue((ROOT / path).is_file())
            self.assertIn(path, _SOURCE_FILES)
            self.assertIn(path, SOURCE_FILES)
            vector = next(
                row for row in vectors
                if row.get("profile-id") == "incident-response"
                and row.get("selector-kind") == "scenario"
                and row.get("scenario-id") == scenario
            )
            self.assertEqual(vector["oracle-source"], path)
            self.assertEqual(vector["oracle-resource"], "graph_engineering/" + path)
            self.assertEqual(
                vector["oracle-raw-sha256"],
                hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
            )
            for disposition in ("P", "R"):
                test_id = (
                    f"GEW-PSC-INCIDENT-RESPONSE-{scenario.upper()}-{disposition}"
                )
                binding = plan.binding(test_id)
                self.assertEqual(binding["profile_id"], "incident-response")
                self.assertEqual(binding["scenario_id"], scenario)
                self.assertEqual(binding["disposition"], disposition)
                self.assertEqual(
                    binding["request_digest"],
                    None if disposition == "P" else fixture.coverage_request_digest(
                        fixture.incident_scenario_candidate(
                            scenario, accepted=False,
                        )
                    ),
                )

        mandatory_recovery = next(
            row for row in vectors
            if row.get("profile-id") == "incident-response"
            and row.get("selector-kind") == "mandatory"
            and row.get("column-id") == "recovery"
        )
        scenario_recovery = next(
            row for row in vectors
            if row.get("profile-id") == "incident-response"
            and row.get("selector-kind") == "scenario"
            and row.get("scenario-id") == "recovery"
        )
        self.assertEqual(
            mandatory_recovery["oracle-raw-sha256"],
            "6e223a032f5549ce5489bd11877ec1309c437cf858568539e437da694024527c",
        )
        self.assertNotEqual(
            mandatory_recovery["oracle-source"], scenario_recovery["oracle-source"],
        )

    def test_incident_values_are_config_owned_not_embedded_in_logic(self) -> None:
        rows = json.loads(
            (ROOT / "config/profiles/scenario-truth-fixture-registry-v1.json").read_text()
        )["fixtures"]
        incidents = [row for row in rows if "incident_contract" in row]
        self.assertEqual(
            {(row["profile_id"], row["scenario_id"]) for row in incidents},
            {("incident-response", scenario) for scenario in self.scenarios},
        )
        sources = "\n".join(
            path.read_text()
            for path in (
                ROOT / "core/graph_engineering/core/scenario_truth.py",
                ROOT / "application/graph_engineering/application/scenario_truth.py",
            )
        )
        for row in incidents:
            contract = row["incident_contract"]
            for value in (
                contract["contract_id"],
                contract["signal"]["signal_id"],
                contract["residual_state_id"],
                contract["owner_route"],
                *contract["action_ids"],
                *contract["forbidden_action_ids"],
            ):
                self.assertNotIn(value, sources)


class Remaining54P3FoundationContractsTest(unittest.TestCase):
    """Freeze the bounded P3 foundation without issuing release coverage."""

    schema_versions = {
        "category-completion-assessment": "1.4.0",
        "release-artifact-manifest": "1.0.0",
        "release-deployment-observation": "1.0.0",
        "release-health-observation": "1.0.0",
        "release-operations-installation-bootstrap": "1.0.0",
        "release-operations-observation": "1.0.0",
        "release-operations-policy-registry": "1.0.0",
        "release-recovery-binding": "1.0.0",
        "release-simulator-fixture-registry": "1.0.0",
    }
    digest_fields = {
        "category-completion-assessment": "assessment_digest",
        "release-artifact-manifest": "manifest_digest",
        "release-deployment-observation": "observation_digest",
        "release-health-observation": "observation_digest",
        "release-operations-installation-bootstrap": "bootstrap_digest",
        "release-operations-observation": "observation_digest",
        "release-operations-policy-registry": "registry_digest",
        "release-recovery-binding": "binding_digest",
        "release-simulator-fixture-registry": "registry_digest",
    }

    def test_p3_nine_schema_pairs_are_closed_registered_and_digest_projected(self) -> None:
        from graph_engineering.core.contracts.schema import (
            SchemaProfilePolicy,
            validate_schema_profile,
        )

        policy = SchemaProfilePolicy.from_dict(json.loads(
            (ROOT / "config/contracts/schema-profile-v1.json").read_text()
        ))
        registry = json.loads(
            (ROOT / "config/contracts/profile-schema-registry-v1.json").read_text()
        )
        rows = {row["schema_id"]: row["body_digest"] for row in registry["resources"]}
        expected_ids: set[str] = set()
        for name, version in self.schema_versions.items():
            output_id = f"urn:gew:schema:{name}:{version}"
            input_id = f"urn:gew:schema:{name}-input:{version}"
            expected_ids.update((input_id, output_id))
            output_path = ROOT / f"config/contracts/schemas/{name}-{version}.json"
            input_path = ROOT / f"config/contracts/schemas/{name}-input-{version}.json"
            output = json.loads(output_path.read_text())
            digest_input = json.loads(input_path.read_text())
            digest_field = self.digest_fields[name]
            with self.subTest(schema=name):
                self.assertEqual(validate_schema_profile(output, policy), output_id)
                self.assertEqual(validate_schema_profile(digest_input, policy), input_id)
                self.assertIs(output["unevaluatedProperties"], False)
                self.assertIs(digest_input["unevaluatedProperties"], False)
                self.assertIn(digest_field, output["required"])
                self.assertNotIn(digest_field, digest_input["required"])
                self.assertIn(digest_field, output["properties"])
                self.assertNotIn(digest_field, digest_input["properties"])
                self.assertEqual(
                    rows[output_id],
                    "sha256-raw-v1:" + hashlib.sha256(output_path.read_bytes()).hexdigest(),
                )
                self.assertEqual(
                    rows[input_id],
                    "sha256-raw-v1:" + hashlib.sha256(input_path.read_bytes()).hexdigest(),
                )
        self.assertEqual(
            [row["schema_id"] for row in registry["resources"]],
            sorted(row["schema_id"] for row in registry["resources"]),
        )
        self.assertLessEqual(expected_ids, set(rows))
        for filename in (
            "release-operations-observation-1.0.0.json",
            "release-operations-observation-input-1.0.0.json",
            "category-completion-assessment-1.4.0.json",
            "category-completion-assessment-input-1.4.0.json",
        ):
            body = json.loads((ROOT / "config/contracts/schemas" / filename).read_text())
            encoded = json.dumps(body, sort_keys=True)
            self.assertIn("urn:gew:schema:release-artifact-manifest:1.0.0", encoded)
            self.assertIn("urn:gew:schema:release-deployment-observation:1.0.0", encoded)
            self.assertIn("urn:gew:schema:release-health-observation:1.0.0", encoded)

    def test_restart_five_installation_provenance_loaders_reject_stale_bytes(self) -> None:
        from unittest import mock
        import graph_engineering
        from graph_engineering.application import (
            dependency_security, migration_rehearsal, performance_benchmark,
            release_operations, scenario_truth,
        )

        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        # These are installed-input loaders only: no repository, workload,
        # observation, execution sequence or coverage authority is issued.
        loaders = (
            ("release-operations", "_release_operations_installation_resources",
             release_operations.ReleaseOperationsRegistryFactory.from_installation),
            ("scenario-truth", "_scenario_truth_installation_resources",
             scenario_truth.ScenarioTruthRegistryFactory.from_installation),
            ("performance-benchmark", "_performance_benchmark_installation_resources",
             performance_benchmark.PerformanceBenchmarkRegistryFactory.from_installation),
            ("migration-rehearsal", "_migration_rehearsal_installation_resources",
             migration_rehearsal._installation_projection),
            ("dependency-advisory", "_dependency_advisory_installation_resources",
             dependency_security._bootstrap_projection),
        )
        for name, reader_name, load in loaders:
            with self.subTest(profile=name):
                self.assertIsNotNone(load())
                pin = project["tool"]["gew"]["profile"][name]
                resources = getattr(graph_engineering, reader_name)()
                schema_path = (
                    pin["schema-sources"][0] if "schema-sources" in pin
                    else pin["schema-vectors"][0]["source"]
                )
                source_path = (
                    pin["protected-sources"][0] if "protected-sources" in pin
                    else pin["protected-resources"][0]["source"]
                    if "protected-resources" in pin else pin["source-artifact-source"]
                )
                for kind, path in (
                    ("bootstrap", pin["bootstrap-source"]),
                    ("schema", schema_path), ("source", source_path),
                ):
                    with self.subTest(profile=name, stale=kind):
                        expected = (ROOT / path).read_bytes()
                        positions = [
                            index for index, body in enumerate(resources) if body == expected
                        ]
                        self.assertTrue(positions)
                        # Some schemas also belong to the protected-source
                        # closure. Corrupt each occurrence independently.
                        for position in positions:
                            replacement = expected + b"\n"
                            if kind == "bootstrap":
                                stale = json.loads(expected)
                                stale["bootstrap_digest"] = "sha256-jcs-v1:" + "0" * 64
                                replacement = json.dumps(stale).encode()
                            changed = tuple(
                                replacement if index == position else body
                                for index, body in enumerate(resources)
                            )
                            with mock.patch.object(graph_engineering, reader_name, return_value=changed):
                                with self.assertRaises(ValueError):
                                    load()

    def test_p3_configuration_package_and_missing_count_closures_are_current(self) -> None:
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())
        pin = project["tool"]["gew"]["profile"]["release-operations"]
        policy = json.loads((ROOT / pin["policy-source"]).read_text())
        bootstrap_path = ROOT / pin["bootstrap-source"]
        bootstrap = json.loads(bootstrap_path.read_text())
        plan = json.loads((
            ROOT / "config/profiles/profile-coverage-execution-plan-v1.json"
        ).read_text())
        self.assertEqual((len(plan["bindings"]), len(plan["oracle_bindings"])), (274, 137))
        release_bindings = [row for row in plan["bindings"] if row["profile_id"] == "release-operations"]
        self.assertEqual(len(release_bindings), 30)
        self.assertEqual(sum(row["selector_kind"] == "mandatory" and row["scenario_id"] is None
            for row in release_bindings), 24)
        self.assertEqual({(row["scenario_id"], row["disposition"]) for row in release_bindings
            if row["selector_kind"] == "scenario"}, {(scenario, role)
                for scenario in ("artifact-provenance", "health-gate", "partial-deploy") for role in ("P", "R")})
        self.assertEqual(policy["deployment_policy"]["operation_roles"], {
            "apply": "local-release-simulator.apply",
            "query": "local-release-simulator.query",
            "restore": "local-release-simulator.restore",
        })
        self.assertEqual(len(policy["deployment_policy"]["fault_points"]), 5)
        self.assertEqual(len(pin["schema-sources"]), 18)
        self.assertEqual(len(set(pin["schema-sources"])), 18)
        coverage = project["tool"]["gew"]["profile"]["coverage-execution-plan"]
        packaged = dict(zip(
            coverage["protected-sources"], coverage["protected-resources"], strict=True,
        ))
        for suffix in ("", "-input"):
            source = f"config/contracts/schemas/release-recovery-binding{suffix}-1.0.0.json"
            self.assertEqual(packaged[source], "graph_engineering/" + source)
            self.assertIn(source, pin["schema-sources"])
        self.assertEqual(
            bootstrap["schema_vectors"],
            [{
                "schema_id": json.loads((ROOT / path).read_text())["$id"],
                "raw_sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest(),
            } for path in pin["schema-sources"]],
        )
        self.assertEqual(
            pin["bootstrap-raw-sha256"], hashlib.sha256(bootstrap_path.read_bytes()).hexdigest(),
        )
        protected = {row["path"]: row["raw_sha256"] for row in bootstrap["protected_resources"]}
        self.assertEqual(set(protected), set(pin["protected-sources"]))
        for path, raw_sha256 in protected.items():
            self.assertEqual(raw_sha256, hashlib.sha256((ROOT / path).read_bytes()).hexdigest())
        source_targets = set(json.loads(
            (ROOT / "config/verification/wp-00-targets.json").read_text()
        )["files"])
        self.assertLessEqual({
            "adapters/graph_engineering/adapters/local_release_simulator.py",
            "application/graph_engineering/application/release_operations.py",
            "core/graph_engineering/core/release_operations.py",
            pin["bootstrap-source"], pin["policy-source"], pin["fixture-source"],
            *pin["schema-sources"],
        }, source_targets)


if __name__ == "__main__":
    unittest.main()
