# Preflight configuration parse reuse — implementation plan

## 1. Summary

Implement the reviewed [design](../specs/preflight-configuration-parse-reuse.md)
only after the C274-RUN-005 target-boundary approval. Four dependent tasks cover
red tests, backend implementation and pins, bounded verification, and independent
Candidate review. Planning estimate: 4–7 hours; actual time is not yet known.
Completion means behavior and closure tests pass with exact evidence; it does
not mean the full274 timeout is resolved.

## 2. Phases

P0: record approval and bind the repair Manifest; exit with valid scope and
artifact reviews. P1: red tests then implementation; exit with green behavior
and active closure checks. P2: bounded comparison and independent review; exit
with a concrete Candidate or a documented failed/inconclusive result.

## 3. Tasks and dependencies

Owner for edits: /root. Independent reviewer: existing project reviewer.
Task IDs are local tracking IDs; no external board is used.

- T1 (S, 1–2h, P0/P1): bind approved targets and write behavioral tests in
  `tests/unit/test_wp00_packaging.py`; depends on human scope approval.
  - [ ] New positive-reuse expectations fail against baseline for the intended reason.
  - [ ] Existing rejection expectations remain valid; baseline failure retained.
- T2 (S, 1–2h, P1): implement backend context and refresh six-file pin closure;
  depends on T1; blocks T3.
  - [ ] No physical read/check site removed or reordered.
  - [ ] All direct and reverse pins validate using current consumers.
- T3 (S, 1–2h, P2): execute the [test plan](../test-plans/preflight-configuration-parse-reuse.md);
  depends on T2; blocks T4.
  - [ ] Every critical journey has current passing evidence or a reported blocker.
  - [ ] Unprofiled comparison reports measured times without extrapolation.
- T4 (XS, 30–60min, P2): exact Manifest/staged-tree binding and independent
  implementation, verification and Candidate review; depends on T3.
  - [ ] All findings resolved within approved budgets; no manufactured file changes.
  - [ ] Commit remains unexecuted until separately authorized.

Actual time for T1–T4: not started; record on completion.

## 4. Dependencies

Internal: reviewed design, current source at the pinned base, and human target
amendment (pending). Infrastructure: existing Python environment and source
attestation helper (available). External dependencies: none; no network needed.
Approval is the entry prerequisite, not a substitute for independent artifact gates.

## 5. Development risks

Pin omissions are high-impact; validate all four active consumers and real wheel
resources before any workload. Context behavior regressions require focused
red/green tests. Excess copying may erase savings; compare unprofiled runs and
stop if inconclusive. Preserve the design's read and exception constraints.

## 6. Rollout and rollback

Local Candidate only; no production rollout, feature flag or percentage traffic.
A single changed rejection outcome, stale pin or scope mismatch blocks completion.
Rollback restores the proposed change set and associated pins together; expected
editing effort is under 30 minutes, verification time depends on failed checks.
No commit or full-run operation is included in this plan.

## 7. Verification

Follow the linked test plan: focused unit behavior, real isolated preflight,
installation/package closure and existing adversarial regressions. Use fresh
attested roots and explicit project Manifest/Policy for canonical checks.
Native command cap 290 seconds, canonical cap 300 seconds, strict serial work.
Run applicable static and repository checks required by current project Policy.

## 8. Open decisions

Before implementation: human approval of exact C274-RUN-005 allowlist and bounded
verification. Before Candidate: exact changed targets and current evidence binding.
Before any complete workload retry: separate one-run request, after measured gain
and package preflight; that request is outside this plan.

## 9. References

[Spec](../specs/preflight-configuration-parse-reuse.md),
[Impact](../impact/preflight-configuration-parse-reuse.md),
[PRD](../prd/graph-engineering-workflow.md),
[Positioning](../positioning/graph-engineering-workflow.md).

## 10. History

2026-09-29: prepared bounded proposal; implementation not started. Checklist
adaptation: local tasks replace board fields; production rollout and arbitrary
coverage percentages do not apply. Human approval and independent reviews remain
pending for implementation entry; document preparation does not mark them passed.
