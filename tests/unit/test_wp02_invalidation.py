from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "core"))

from graph_engineering.core.graph.invalidation import (  # noqa: E402
    DependencyIndex,
    DependencyRecord,
    DriftClass,
    InvalidationError,
    classify_drift,
)


def digest(label: str) -> str:
    return "sha256-jcs-v1:" + hashlib.sha256(label.encode()).hexdigest()


class InvalidationTests(unittest.TestCase):
    def record(
        self,
        ref_id: str,
        inputs: tuple[str, ...],
        *,
        external: bool = False,
    ) -> DependencyRecord:
        return DependencyRecord(
            ref_id=ref_id,
            ref_kind="artifact",
            content_digest=digest(ref_id),
            input_refs=inputs,
            input_digests={item: digest(item) for item in inputs},
            baseline_digests={"intent": digest("baseline")},
            graph_version="graph:1.0.0",
            profile_version="profile:1.0.0",
            policy_version="policy:1.0.0",
            producer_run_ref=f"run:{ref_id}",
            validation_record_refs=(f"validation:{ref_id}",),
            review_record_refs=(f"review:{ref_id}",),
            semantic_tags=("delivery",),
            freshness_policy_ref="freshness:current-v1",
            status="trusted",
            has_external_effect=external,
        )

    def index(self) -> DependencyIndex:
        return DependencyIndex.build((
            self.record("prd", ()),
            self.record("spec", ("prd",)),
            self.record("impact", ("prd",)),
            self.record("implementation", ("spec", "impact"), external=True),
            self.record("verification", ("implementation",)),
            self.record("unrelated", ()),
        ))

    def test_minimal_descendant_invalidation_is_sorted_and_replayable(self) -> None:
        records = self.index().invalidate(("spec",), epoch=4, reason="input-digest-changed")
        self.assertEqual([record.ref_id for record in records], ["implementation", "spec", "verification"])
        self.assertEqual([record.action for record in records], ["reconcile", "invalidate", "invalidate"])
        self.assertTrue(all(record.epoch == 4 for record in records))
        self.assertNotIn("impact", {record.ref_id for record in records})
        self.assertNotIn("unrelated", {record.ref_id for record in records})
        self.assertEqual(records, self.index().invalidate(("spec",), epoch=4, reason="input-digest-changed"))

    def test_shared_dependency_and_cycle_or_unknown_reference_fail_closed(self) -> None:
        invalidated = self.index().invalidate(("prd",), epoch=1, reason="baseline-changed")
        self.assertEqual(
            {record.ref_id for record in invalidated},
            {"prd", "spec", "impact", "implementation", "verification"},
        )
        with self.assertRaisesRegex(InvalidationError, "unknown"):
            self.index().invalidate(("missing",), epoch=1, reason="changed")
        with self.assertRaisesRegex(InvalidationError, "cycle"):
            DependencyIndex.build((
                self.record("a", ("b",)),
                self.record("b", ("a",)),
            ))

    def test_dependency_records_bind_provenance_and_exact_input_digests(self) -> None:
        record = self.record("spec", ("prd",))
        self.assertEqual(record.input_digests["prd"], digest("prd"))
        with self.assertRaises(TypeError):
            record.input_digests["prd"] = "changed"  # type: ignore[index]
        with self.assertRaisesRegex(InvalidationError, "same dependencies"):
            DependencyRecord(
                ref_id="spec", ref_kind="artifact", content_digest=digest("spec"),
                input_refs=("prd",), input_digests={}, baseline_digests={"intent": digest("baseline")},
                graph_version="1", profile_version="1", policy_version="1", producer_run_ref="run",
                validation_record_refs=("validation",), review_record_refs=("review",),
                semantic_tags=("delivery",), freshness_policy_ref="freshness", status="trusted",
                has_external_effect=False,
            )
        stale = self.record("spec", ("prd",))
        object.__setattr__(stale, "input_digests", {"prd": digest("stale")})
        with self.assertRaisesRegex(InvalidationError, "digest mismatch"):
            DependencyIndex.build((self.record("prd", ()), stale))

    def test_digest_baseline_and_control_drift_select_minimal_roots_then_propagate(self) -> None:
        index = self.index()
        unchanged = index.invalidate_changed_inputs(
            {"spec": digest("spec")}, epoch=2, reason="input-check",
        )
        self.assertEqual(unchanged, ())
        changed = index.invalidate_changed_inputs(
            {"spec": digest("spec-v2")}, epoch=2, reason="input-check",
        )
        self.assertEqual(
            tuple(item.ref_id for item in changed),
            ("implementation", "spec", "verification"),
        )
        self.assertEqual(index.invalidate_baselines(
            {"intent": digest("baseline")}, epoch=3, reason="baseline-check",
        ), ())
        baseline_changed = index.invalidate_baselines(
            {"intent": digest("baseline-v2")}, epoch=3, reason="baseline-check",
        )
        self.assertEqual(
            {item.ref_id for item in baseline_changed},
            {"prd", "spec", "impact", "implementation", "verification", "unrelated"},
        )
        self.assertEqual(index.invalidate_control_versions(
            graph_version="graph:1.0.0", profile_version="profile:1.0.0",
            policy_version="policy:1.0.0", epoch=4, reason="control-check",
        ), ())
        control_changed = index.invalidate_control_versions(
            graph_version="graph:2.0.0", profile_version="profile:1.0.0",
            policy_version="policy:1.0.0", epoch=4, reason="control-check",
        )
        self.assertEqual(len(control_changed), 6)

    def test_drift_classification_distinguishes_intent_authority_control_and_metadata(self) -> None:
        self.assertEqual(classify_drift("baseline", digest("old"), digest("new")), DriftClass.INTENT)
        self.assertEqual(classify_drift("project_scope", digest("old"), digest("new")), DriftClass.INTENT)
        self.assertEqual(classify_drift("authority", digest("old"), digest("new")), DriftClass.AUTHORITY)
        self.assertEqual(classify_drift("graph", digest("old"), digest("new")), DriftClass.CONTROL)
        self.assertEqual(classify_drift("artifact", digest("old"), digest("new")), DriftClass.DEPENDENCY)
        self.assertEqual(classify_drift("artifact", digest("same"), digest("same")), DriftClass.METADATA_ONLY)

    def test_drift_classification_rejects_unknown_kind_and_invalid_digests(self) -> None:
        with self.assertRaisesRegex(InvalidationError, "kind"):
            classify_drift("unknown", digest("old"), digest("new"))
        invalid = (
            "",
            "sha256-jcs-v1:" + "0" * 63,
            "sha256-jcs-v1:" + "A" * 64,
            "sha256-raw-v1:" + "0" * 64,
            1,
            True,
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaisesRegex(InvalidationError, "digests"):
                classify_drift("artifact", value, digest("new"))  # type: ignore[arg-type]
            with self.subTest(equal=value), self.assertRaisesRegex(InvalidationError, "digests"):
                classify_drift("artifact", value, value)  # type: ignore[arg-type]

        with self.assertRaisesRegex(InvalidationError, "content digest"):
            DependencyRecord(
                ref_id="invalid", ref_kind="artifact", content_digest="garbage",
                input_refs=(), input_digests={}, baseline_digests={"intent": digest("baseline")},
                graph_version="graph:1.0.0", profile_version="profile:1.0.0",
                policy_version="policy:1.0.0", producer_run_ref="run:invalid",
                validation_record_refs=("validation:invalid",),
                review_record_refs=("review:invalid",), semantic_tags=("delivery",),
                freshness_policy_ref="freshness:current-v1", status="trusted",
                has_external_effect=False,
            )
        with self.assertRaisesRegex(InvalidationError, "current input digests"):
            self.index().invalidate_changed_inputs(
                {"spec": "garbage"}, epoch=1, reason="invalid",
            )
        with self.assertRaisesRegex(InvalidationError, "baseline digests"):
            self.index().invalidate_baselines(
                {"intent": "sha256-jcs-v1:" + "0" * 63}, epoch=1, reason="invalid",
            )


if __name__ == "__main__":
    unittest.main()
