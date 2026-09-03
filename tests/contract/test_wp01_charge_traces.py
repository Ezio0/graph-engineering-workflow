from __future__ import annotations

import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.contracts.canonical import canonicalize  # noqa: E402
from graph_engineering.core.contracts.digest import semantic_digest_charged  # noqa: E402
from graph_engineering.core.contracts.errors import ContractError  # noqa: E402
from graph_engineering.core.contracts.resources import CostSchedule, ResourceProfile, WorkContext  # noqa: E402
from graph_engineering.core.contracts.strict_json import parse_json  # noqa: E402


class ChargeTraceTests(unittest.TestCase):
    def setUp(self) -> None:
        profile = json.loads((ROOT / "config" / "contracts" / "resource-profile-v1.json").read_text())
        schedule = json.loads((ROOT / "config" / "contracts" / "cost-schedule-v1.json").read_text())
        self.profile_value = profile
        self.schedule = CostSchedule.from_dict(schedule)

    def context(self, budget: int | None = None) -> WorkContext:
        profile = json.loads(json.dumps(self.profile_value))
        if budget is not None:
            profile["work_budget"] = budget
        return WorkContext(ResourceProfile.from_dict(profile), self.schedule)

    def test_parse_trace_follows_byte_then_lexical_source_order(self) -> None:
        context = self.context()
        value = parse_json(b'{"a":["x",1]}', context=context, source_id="urn:gew:test")
        self.assertEqual(value, {"a": ["x", 1]})
        events = [record["event_id"] for record in context.trace]
        byte_count = len(b'{"a":["x",1]}')
        self.assertEqual(events[:byte_count], ["parse.input_byte"] * byte_count)
        lexical = events[byte_count:]
        self.assertEqual(lexical[0:2], ["parse.token", "parse.container"])
        self.assertIn("parse.member", lexical)
        self.assertIn("parse.item", lexical)
        self.assertEqual([record["event_ordinal"] for record in context.trace], [str(index) for index in range(len(context.trace))])

    def test_canonical_and_digest_are_nested_and_budget_cutoffs_are_atomic(self) -> None:
        arguments = {
            "contract_type": "urn:gew:contract:test",
            "projection_id": "urn:gew:digest-projection:identity:1.0.0",
            "schema_id": "urn:gew:schema:test:1.0.0",
        }
        context = self.context()
        digest = semantic_digest_charged({"a": 1}, context, **arguments)
        self.assertTrue(digest.startswith("sha256-jcs-v1:"))
        events = [record["event_id"] for record in context.trace]
        first_digest = events.index("digest.input_byte")
        self.assertTrue(all(event.startswith("canonical.") for event in events[:first_digest]))
        self.assertTrue(all(event == "digest.input_byte" for event in events[first_digest:]))
        canonical_paths = {tuple(record["operation_path"]) for record in context.trace[:first_digest]}
        digest_paths = {tuple(record["operation_path"]) for record in context.trace[first_digest:]}
        self.assertEqual(len(canonical_paths), 1)
        self.assertEqual(len(digest_paths), 1)
        self.assertNotEqual(canonical_paths, digest_paths)

        for balance in range(1, 8):
            limited = self.context(balance)
            try:
                canonicalize({"a": 1}, limited, source_id="urn:gew:test")
            except ContractError as error:
                self.assertEqual(error.detail.code, "E_BUDGET")
                self.assertEqual(limited.trace[-1]["status"], "rejected")
                self.assertNotIn("post_balance", limited.trace[-1])


if __name__ == "__main__":
    unittest.main()
