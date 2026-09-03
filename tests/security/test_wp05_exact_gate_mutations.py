from __future__ import annotations

import copy
import itertools
import json
import unittest

from graph_engineering.adapters.fake_actions import DeterministicFakeTarget
from graph_engineering.core.actions import ActionGateError, ExecuteGateDecisionTable
from tests.support.wp05_actions import ROOT, action_stack, authority_document, disclosure_plan, prepared_document


MANIFEST = json.loads((ROOT / "config" / "verification" / "wp-05-gate-mutations.json").read_text())
CODES = tuple(MANIFEST["frozen_precedence"])


class WP05ExactExecuteGateMutations(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._stack = action_stack()
        cls.fixture = cls._stack.__enter__()
        cls.prepared = cls.fixture.coordinator.prepare(prepared_document())
        cls.fixture.coordinator.authorize(authority_document(cls.prepared))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stack.__exit__(None, None, None)

    def _assert_actual_rejection(self, code: str) -> None:
        candidate = copy.deepcopy(prepared_document())
        failure_mode = None
        initial_state = {"version": 1}
        if code == "GEW-AUT-PRECONDITION-CHANGED":
            initial_state = {"version": 9}
        elif code == "GEW-AUT-PRECONDITION-UNVERIFIABLE":
            failure_mode = "query-unverifiable"
        elif code == "GEW-AUT-TARGET-EVIDENCE-STALE":
            failure_mode = "stale-query"
        elif code == "GEW-AUT-IDEMPOTENCY-KEY-CHANGED":
            candidate["idempotency_key"] = "idempotency-mutated"
        elif code == "GEW-AUT-IDEMPOTENCY-CLASS-CHANGED":
            candidate["idempotency_class"] = "idempotent"
        elif code == "GEW-AUT-ROLLBACK-MISSING":
            candidate.pop("rollback_plan")
        elif code == "GEW-AUT-ROLLBACK-CHANGED":
            candidate["rollback_plan"] = {"capability": "changed", "set": {"version": 0}}
        elif code == "GEW-AUT-VERIFY-MISSING":
            candidate.pop("verification_plan")
        elif code == "GEW-AUT-VERIFY-CHANGED":
            candidate["verification_plan"] = {"capability": "fresh-target-query", "predicate": "changed"}
        else:
            self.fail(f"code needs journal-history fixture: {code}")
        target = DeterministicFakeTarget(
            target_id="target-project",
            target_digest=self.prepared.target_digest,
            resource_id="target:project",
            initial_state=initial_state,
            failure_mode=failure_mode,
        )
        claims_before = self.fixture.leases.unresolved_claims()
        head_before = self.fixture.journal._journal.current_task_head(self.prepared.task_id)
        with self.assertRaises(ActionGateError) as caught:
            self.fixture.coordinator.execute(
                self.prepared.action_id,
                owner_id="owner-wp05",
                runtime_kind="codex",
                runtime_lineage_id="lineage-wp05",
                lease=self.fixture.action_lease,
                target=target,
                observer=target.observer_port(),
                disclosure_plan=disclosure_plan(self.fixture, self.prepared),
                candidate_action=candidate,
            )
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(target.call_count, 0)
        self.assertEqual(self.fixture.leases.unresolved_claims(), claims_before)
        head_after = self.fixture.journal._journal.current_task_head(self.prepared.task_id)
        self.assertEqual((head_after.revision, head_after.head_digest), (head_before.revision, head_before.head_digest))

    def test_manifest_exactly_matches_frozen_decision_table(self) -> None:
        self.assertEqual(CODES, ExecuteGateDecisionTable.PRECEDENCE)
        self.assertTrue(MANIFEST["all_unordered_pairs_required"])
        self.assertEqual(MANIFEST["combined_mutation_id"], "GEW-AUT-COMBINED-MUTATION")


def _single_test(code: str):
    def test(self: WP05ExactExecuteGateMutations) -> None:
        self._assert_actual_rejection(code)
    return test


for _code in CODES:
    if _code not in {"GEW-AUT-IDEMPOTENCY-DUPLICATE", "GEW-AUT-IDEMPOTENCY-UNKNOWN"}:
        setattr(
            WP05ExactExecuteGateMutations,
            "test_exact_" + _code.lower().replace("-", "_"),
            _single_test(_code),
        )


class WP05CombinedMutationPrecedence(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._stack = action_stack()
        cls.fixture = cls._stack.__enter__()
        cls.prepared = cls.fixture.coordinator.prepare(prepared_document())
        cls.fixture.coordinator.authorize(authority_document(cls.prepared))

    @classmethod
    def tearDownClass(cls) -> None:
        cls._stack.__exit__(None, None, None)

    def _assert_actual_pair(self, codes: set[str]) -> None:
        history = codes.intersection({
            "GEW-AUT-IDEMPOTENCY-DUPLICATE", "GEW-AUT-IDEMPOTENCY-UNKNOWN",
        })
        if len(history) == 2:
            return  # Mutually exclusive journal states; the table remains the oracle for this pair.
        candidate = copy.deepcopy(prepared_document())
        if "GEW-AUT-IDEMPOTENCY-KEY-CHANGED" in codes:
            candidate["idempotency_key"] = "combined-key"
        if "GEW-AUT-IDEMPOTENCY-CLASS-CHANGED" in codes:
            candidate["idempotency_class"] = "idempotent"
        if "GEW-AUT-ROLLBACK-MISSING" in codes:
            candidate.pop("rollback_plan")
        elif "GEW-AUT-ROLLBACK-CHANGED" in codes:
            candidate["rollback_plan"] = {"capability": "changed", "set": {"version": 0}}
        if "GEW-AUT-VERIFY-MISSING" in codes:
            candidate.pop("verification_plan")
        elif "GEW-AUT-VERIFY-CHANGED" in codes:
            candidate["verification_plan"] = {"capability": "fresh-target-query", "predicate": "changed"}
        target = DeterministicFakeTarget(
            target_id="target-project", target_digest=self.prepared.target_digest,
            resource_id="target:project",
            initial_state={"version": 9} if "GEW-AUT-PRECONDITION-CHANGED" in codes else {"version": 1},
            failure_mode="stale-query" if "GEW-AUT-TARGET-EVIDENCE-STALE" in codes else None,
        )
        observer = target.observer_port()
        if "GEW-AUT-PRECONDITION-UNVERIFIABLE" in codes:
            observer.observe = lambda: {
                "target_id": self.prepared.target_id,
                "target_digest": "sha256-jcs-v1:" + "0" * 64,
                "resource_id": "target:project",
                "fresh": "GEW-AUT-TARGET-EVIDENCE-STALE" not in codes,
                "observation_revision": 1,
                "state": {"version": 9}
                if "GEW-AUT-PRECONDITION-CHANGED" in codes else {"version": 1},
            }
        if history:
            self.fixture.journal.test_only_set_state(
                self.prepared.action_id,
                "unknown" if "GEW-AUT-IDEMPOTENCY-UNKNOWN" in history else "executing",
            )
        claims_before = self.fixture.leases.unresolved_claims()
        head_before = self.fixture.journal._journal.current_task_head(self.prepared.task_id)
        expected = min(codes, key=ExecuteGateDecisionTable.PRECEDENCE.index)
        try:
            with self.assertRaises(ActionGateError) as caught:
                self.fixture.coordinator.execute(
                    self.prepared.action_id,
                    owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=self.fixture.action_lease,
                    target=target, observer=observer,
                    disclosure_plan=disclosure_plan(self.fixture, self.prepared),
                    candidate_action=candidate,
                )
            self.assertEqual(caught.exception.code, expected)
            self.assertEqual(target.call_count, 0)
            self.assertEqual(self.fixture.leases.unresolved_claims(), claims_before)
            head_after = self.fixture.journal._journal.current_task_head(self.prepared.task_id)
            self.assertEqual(
                (head_after.revision, head_after.head_digest),
                (head_before.revision, head_before.head_digest),
            )
        finally:
            if history:
                self.fixture.journal.test_only_set_state(self.prepared.action_id, "authorized")


def _pair_test(first: str, second: str):
    def test(self: WP05CombinedMutationPrecedence) -> None:
        expected = min((first, second), key=ExecuteGateDecisionTable.PRECEDENCE.index)
        with self.assertRaises(ActionGateError) as caught:
            ExecuteGateDecisionTable.reject({first, second}, "mechanically generated combined mutation")
        self.assertEqual(caught.exception.code, expected)
        self._assert_actual_pair({first, second})
    return test


for _left, _right in itertools.combinations(CODES, 2):
    setattr(
        WP05CombinedMutationPrecedence,
        "test_combined_" + _left.lower().replace("-", "_") + "__" + _right.lower().replace("-", "_"),
        _pair_test(_left, _right),
    )


class WP05JournalHistorySingletons(unittest.TestCase):
    def _replay_target(self, prepared):
        return DeterministicFakeTarget(
            target_id="target-project", target_digest=prepared.target_digest,
            resource_id="target:project", initial_state={"version": 1},
        )

    def test_gew_aut_idempotency_duplicate_singleton(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            original_target = self._replay_target(prepared)
            plan = disclosure_plan(fixture, prepared)
            fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=original_target, observer=original_target.observer_port(),
                disclosure_plan=plan,
            )
            replay_target = self._replay_target(prepared)
            claims_before = fixture.leases.unresolved_claims()
            head_before = fixture.journal._journal.current_task_head(prepared.task_id)
            with self.assertRaises(ActionGateError) as caught:
                fixture.coordinator.execute(
                    prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=replay_target, observer=replay_target.observer_port(),
                    disclosure_plan=plan,
                )
            self.assertEqual(caught.exception.code, "GEW-AUT-IDEMPOTENCY-DUPLICATE")
            self.assertEqual(replay_target.call_count, 0)
            self.assertEqual(fixture.leases.unresolved_claims(), claims_before)
            head_after = fixture.journal._journal.current_task_head(prepared.task_id)
            self.assertEqual((head_after.revision, head_after.head_digest), (head_before.revision, head_before.head_digest))

    def test_gew_aut_idempotency_unknown_singleton(self) -> None:
        with action_stack() as fixture:
            prepared = fixture.coordinator.prepare(prepared_document())
            fixture.coordinator.authorize(authority_document(prepared))
            original_target = DeterministicFakeTarget(
                target_id="target-project", target_digest=prepared.target_digest,
                resource_id="target:project", initial_state={"version": 1},
                failure_mode="timeout-after-effect",
            )
            plan = disclosure_plan(fixture, prepared)
            fixture.coordinator.execute(
                prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                target=original_target, observer=original_target.observer_port(),
                disclosure_plan=plan,
            )
            replay_target = self._replay_target(prepared)
            claims_before = fixture.leases.unresolved_claims()
            head_before = fixture.journal._journal.current_task_head(prepared.task_id)
            with self.assertRaises(ActionGateError) as caught:
                fixture.coordinator.execute(
                    prepared.action_id, owner_id="owner-wp05", runtime_kind="codex",
                    runtime_lineage_id="lineage-wp05", lease=fixture.action_lease,
                    target=replay_target, observer=replay_target.observer_port(),
                    disclosure_plan=plan,
                )
            self.assertEqual(caught.exception.code, "GEW-AUT-IDEMPOTENCY-UNKNOWN")
            self.assertEqual(replay_target.call_count, 0)
            self.assertEqual(fixture.leases.unresolved_claims(), claims_before)
            head_after = fixture.journal._journal.current_task_head(prepared.task_id)
            self.assertEqual((head_after.revision, head_after.head_digest), (head_before.revision, head_before.head_digest))


if __name__ == "__main__":
    unittest.main()
