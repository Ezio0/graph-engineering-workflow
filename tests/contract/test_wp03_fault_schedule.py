from __future__ import annotations

import copy
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
for responsibility in ("core", "storage"):
    sys.path.insert(0, str(ROOT / responsibility))

from graph_engineering.storage.errors import RepositoryConfigurationError  # noqa: E402
from graph_engineering.storage.faults import (  # noqa: E402
    FaultController,
    InjectedPersistenceFault,
    PersistenceFaultSchedule,
)


class PersistenceFaultScheduleTests(unittest.TestCase):
    def test_schedule_is_closed_complete_and_injection_is_single_deterministic(self) -> None:
        value = json.loads(
            (ROOT / "config" / "contracts" / "persistence-fault-schedule-v1.json").read_text()
        )
        schedule = PersistenceFaultSchedule.from_dict(value)
        for name, mutate in (
            ("missing", lambda item: item["steps"].pop()),
            ("unknown", lambda item: item["fault_kinds"].append("delay")),
            ("duplicate", lambda item: item["expected_states"].append("old")),
        ):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(RepositoryConfigurationError):
                PersistenceFaultSchedule.from_dict(changed)
        controller = FaultController(
            schedule, selected_step="commit.before_commit", fault_kind="io-error",
        )
        controller("commit.after_events")
        with self.assertRaises(InjectedPersistenceFault) as raised:
            controller("commit.before_commit")
        self.assertEqual(
            (raised.exception.step, raised.exception.kind),
            ("commit.before_commit", "io-error"),
        )
        controller("commit.before_commit")
        self.assertEqual(controller.trace, (
            "commit.after_events", "commit.before_commit", "commit.before_commit",
        ))
        with self.assertRaises(RepositoryConfigurationError):
            controller("undeclared.step")
