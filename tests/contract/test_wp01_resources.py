from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.resources import (  # noqa: E402
    EVENT_IDS,
    LIMIT_IDS,
    CostSchedule,
    ResourceProfile,
    WorkContext,
    compare_charge,
    measure,
)
from graph_engineering.core.contracts.strict_json import parse_json  # noqa: E402


class ResourceContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile_value = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        self.schedule_value = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())

    def test_profile_and_schedule_are_closed_and_overrides_only_narrow(self) -> None:
        profile = ResourceProfile.from_dict(self.profile_value)
        schedule = CostSchedule.from_dict(self.schedule_value)
        self.assertEqual(set(profile.limits), LIMIT_IDS)
        self.assertEqual(set(schedule.coefficients), EVENT_IDS)
        narrowed = json.loads(json.dumps(self.profile_value))
        narrowed["work_budget"] -= 1
        narrowed["limits"]["ast_nodes"] -= 1
        self.assertEqual(profile.narrowed_by(narrowed).work_budget, profile.work_budget - 1)
        raised = json.loads(json.dumps(self.profile_value))
        raised["limits"]["ast_nodes"] += 1
        with self.assertRaises(ValueError):
            profile.narrowed_by(raised)
        for invalid in (0, -1, 1.5, True, 9_007_199_254_740_992):
            changed = json.loads(json.dumps(self.schedule_value))
            changed["coefficients"]["geel.node"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                CostSchedule.from_dict(changed)
        direct_limits = dict(profile.limits)
        direct_profile = ResourceProfile(profile.profile_id, profile.schema_version, direct_limits, profile.work_budget)
        direct_limits["ast_nodes"] = 1
        self.assertNotEqual(direct_profile.limits["ast_nodes"], 1)
        direct_coefficients = dict(schedule.coefficients)
        direct_schedule = CostSchedule(schedule.schedule_id, schedule.schema_version, direct_coefficients)
        direct_coefficients["geel.node"] = 9
        self.assertEqual(direct_schedule.coefficients["geel.node"], 1)

    def test_measure_and_inline_compare_trace_are_exact(self) -> None:
        profile = ResourceProfile.from_dict(self.profile_value)
        schedule = CostSchedule.from_dict(self.schedule_value)
        context = WorkContext(profile, schedule)
        value = {"a": ["x", 1]}
        self.assertEqual(measure(value).nodes, 4)
        self.assertEqual(measure(value).members, 1)
        self.assertEqual(measure(value).items, 2)
        compare_charge(value, value, context, operation_path=(0,), source_id="urn:gew:test")
        self.assertEqual(
            [record["event_id"] for record in context.trace],
            ["compare.base", "compare.node", "compare.member", "compare.item", "compare.string_scalar", "compare.canonical_byte"],
        )
        self.assertEqual([record["event_ordinal"] for record in context.trace], [str(index) for index in range(6)])
        self.assertTrue(all(record["operation_path"] == [0] for record in context.trace))

    def test_budget_rejection_is_atomic_and_limit_precedes_charge(self) -> None:
        small = json.loads(json.dumps(self.profile_value))
        small["work_budget"] = 2
        context = WorkContext(ResourceProfile.from_dict(small), CostSchedule.from_dict(self.schedule_value))
        context.emit("geel.node", 1, source_id="urn:gew:test")
        with self.assertRaises(ContractError) as caught:
            context.emit("geel.operand", 2, source_id="urn:gew:test")
        self.assertEqual(caught.exception.detail.code, "E_BUDGET")
        self.assertEqual(context.balance, 1)
        self.assertEqual(context.trace[-1]["status"], "rejected")
        self.assertNotIn("post_balance", context.trace[-1])
        trace_size = len(context.trace)
        with self.assertRaises(ContractError) as limited:
            context.check_limit("ast_depth", context.profile.limits["ast_depth"] + 1, source_id="urn:gew:test")
        self.assertEqual(limited.exception.detail.code, "E_LIMIT")
        self.assertEqual(len(context.trace), trace_size)

    def test_profile_is_deeply_immutable_and_parse_limits_precede_decode(self) -> None:
        source = json.loads(json.dumps(self.profile_value))
        profile = ResourceProfile.from_dict(source)
        source["limits"]["ast_nodes"] = 1
        self.assertNotEqual(profile.limits["ast_nodes"], 1)
        with self.assertRaises(TypeError):
            profile.limits["ast_nodes"] = 1  # type: ignore[index]

        limited = json.loads(json.dumps(self.profile_value))
        limited["limits"]["raw_document_bytes"] = 1
        context = WorkContext(ResourceProfile.from_dict(limited), CostSchedule.from_dict(self.schedule_value))
        with self.assertRaises(ContractError) as caught:
            parse_json(b"  ???", context=context, source_id="urn:gew:test")
        self.assertEqual(caught.exception.detail.code, "E_LIMIT")
        self.assertEqual(context.trace, [])

        traced = WorkContext(ResourceProfile.from_dict(self.profile_value), CostSchedule.from_dict(self.schedule_value))
        parse_json(b'{"a":[1]}', context=traced, source_id="urn:gew:test")
        self.assertEqual(traced._temporary_units, 0)

    def test_parse_releases_each_container_at_freeze_instead_of_accumulating_siblings(self) -> None:
        boundary = json.loads(json.dumps(self.profile_value))
        boundary["limits"]["temporary_units"] = 4
        context = WorkContext(ResourceProfile.from_dict(boundary), CostSchedule.from_dict(self.schedule_value))
        self.assertEqual(parse_json(b"[[],[]]", context=context, source_id="urn:gew:test"), [[], []])
        self.assertEqual(context._temporary_units, 0)

        over_one = json.loads(json.dumps(boundary))
        over_one["limits"]["temporary_units"] = 3
        rejected = WorkContext(ResourceProfile.from_dict(over_one), CostSchedule.from_dict(self.schedule_value))
        with self.assertRaises(ContractError) as caught:
            parse_json(b"[[],[]]", context=rejected, source_id="urn:gew:test")
        self.assertEqual(caught.exception.detail.code, "E_LIMIT")
        self.assertEqual(rejected._temporary_units, 0)

    def test_invalid_lexical_units_are_rejected_before_parse_token_charge(self) -> None:
        for raw in (b"???", b"trux", b"01", b'"\\x"'):
            context = WorkContext(ResourceProfile.from_dict(self.profile_value), CostSchedule.from_dict(self.schedule_value))
            with self.subTest(raw=raw), self.assertRaises((ValueError, json.JSONDecodeError)):
                parse_json(raw, context=context, source_id="urn:gew:test")
            self.assertNotIn("parse.token", [record["event_id"] for record in context.trace])

    def test_every_limit_and_charge_event_has_before_exact_and_after_boundary(self) -> None:
        schedule = CostSchedule.from_dict(self.schedule_value)
        for limit_id in sorted(LIMIT_IDS):
            profile = ResourceProfile.from_dict(self.profile_value)
            context = WorkContext(profile, schedule)
            boundary = profile.limits[limit_id]
            context.check_limit(limit_id, boundary, source_id="urn:gew:test")
            with self.subTest(limit_id=limit_id), self.assertRaises(ContractError) as caught:
                context.check_limit(limit_id, boundary + 1, source_id="urn:gew:test")
            self.assertEqual(caught.exception.detail.code, "E_LIMIT")

        for event_id in sorted(EVENT_IDS):
            coefficient = schedule.coefficients[event_id]
            amount = coefficient * 2
            for delta, status in ((-1, "rejected"), (0, "charged"), (1, "charged")):
                value = json.loads(json.dumps(self.profile_value))
                value["work_budget"] = amount + delta
                context = WorkContext(ResourceProfile.from_dict(value), schedule)
                if status == "rejected":
                    with self.subTest(event_id=event_id, delta=delta), self.assertRaises(ContractError) as caught:
                        context.emit(event_id, 2, operation_path=(7,), source_id="urn:gew:test")
                    self.assertEqual(caught.exception.detail.code, "E_BUDGET")
                else:
                    context.emit(event_id, 2, operation_path=(7,), source_id="urn:gew:test")
                self.assertEqual(context.trace[-1]["status"], status)
                self.assertEqual(context.trace[-1]["operation_path"], [7])
                self.assertEqual(context.trace[-1]["event_ordinal"], "0")
                self.assertEqual(context.balance, amount + delta if status == "rejected" else delta)


if __name__ == "__main__":
    unittest.main()
