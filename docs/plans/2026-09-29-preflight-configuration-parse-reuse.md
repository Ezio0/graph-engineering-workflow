# Preflight configuration parse reuse implementation plan

## Objective

Implement the approved [Spec](../specs/preflight-configuration-parse-reuse.md)
without weakening currentness, then establish actual whole-path benefit.

## Inputs

Use approval r3, comprehensive diagnosis/request r0, existing approved PRD,
Impact and Test Plan. Preserve historical rejected revisions. The proposed budget amendment allows
revision 4, following revision 3; it does not reset prior attempts.

## T-301: Design and authority (XS, estimate 30 min)

Depends on human scope approval, received. Actual recorded by detached timestamps.
- [ ] Bind the 17-path allowlist and actual Manifest changes; independently review four artifacts.
- [ ] Replay prior reductions and advance only on current reducer decisions.

## T-302: Semantic tests and implementation (S, estimate 1–2 h)

Depends on T-301. Actual recorded in command evidence.
- [ ] Add failing behavior tests for all three slots, owner/parser/failure cases.
- [ ] Add observer success/failure/restoration tests and P four-phase selector.
- [ ] Implement bounded package scope, application entry and test-local observer.
- [ ] Refresh active closure pins and pass focused tests.

## T-303: Performance screening (S, estimate 1 h)

Depends on T-302 semantic pass. Actual captured per command.
- [ ] Freeze tree fingerprints and exact P/R paired sequence before running.
- [ ] Execute exactly two pairs per disposition with continuous four phases.
- [ ] Stop on timeout/nonconvergence; preserve outputs, never add favorable runs.
- [ ] After approved correction, sample other high-cost profiles with lawful abort/cleanup.
  Keep full combined-gate finalization unmeasured; do not infer it from abort.

## T-304: Verification and Candidate (S, estimate 1 h)

Depends on T-303. Actual captured in canonical recorder and review records.
- [ ] Independently review implementation; run approved canonical selectors.
- [ ] Produce workload-weighted model including unknowns, no speculative speedup.
- [ ] Independently review verification and Candidate, stop before commit.

## Dependencies and ownership

T-301 -> T-302 -> T-303 -> T-304 is acyclic. Coordinator owns all source edits;
independent reviewers are read-only. No concurrent source writers/worktrees.
All new workflow evidence remains under the existing detached directory.

## Stop and rollback

Native 290s/canonical 300s remain. At failed comparison preserve the exact diff,
restore rejected runtime and pins if required, and report structural feasibility.
At reducer E_LOOP or any material expansion stop without resetting history.
Insufficient total headroom forbids recommending another full run. Separate
human authority is required for commit and any full274 attempt.
