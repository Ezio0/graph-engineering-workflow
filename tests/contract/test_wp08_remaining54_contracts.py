"""Contracts for the Human-approved GEW-REMAINING54-V1 closure."""

from __future__ import annotations

import copy
import hashlib
import json
import pathlib
import sys
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

        self.assertEqual(len(plan.bindings), 226)
        self.assertEqual(len(plan.oracle_bindings), 113)
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
        self.assertEqual(receipt["plan_bindings"], 226)
        self.assertEqual(receipt["oracle_bindings"], 113)
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


if __name__ == "__main__":
    unittest.main()
