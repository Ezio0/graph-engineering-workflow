# Action authority registration implementation plan

## 1. Summary

Implement [Spec](../specs/action-authority-registration.md) in four sequential phases, with test-first work, then independent Candidate review. Estimated engineering effort is 20–28 hours, not elapsed-time commitment; actual time is unrecorded until execution. Done means the approved command boundary passes against the exact Candidate, genuine mixed events are proven, and limitations remain explicit. It does not mean WP09 or the project is complete.

## 2. Phases

| Phase | Goal / deliverable | Exit |
|---|---|---|
| P0 | Reviewed scope and contracts | Independent package PASS + owner implementation envelope |
| P1 | Genuine runtime decision and durable registration | Closed-contract and atomicity tests pass |
| P2 | All start/revoke/recovery boundaries | Both real race orders and stale/restore rejection pass |
| P3 | Mixed source, package parity, regression | Exact evidence complete, independent Candidate verdict |

Phases depend on the preceding phase. Spec §6 supplies all three owner operations; Spec §7 defines the error surface.

## 3. Task breakdown

All tasks owned by `/root`; A01–A07 implemented and development-verified, A08 formal Candidate verification/review pending. Independent reviewer owns only review. File scope is the exact boundary inventory; no concurrent writers. Size estimates are engineering estimates; actual elapsed engineering effort is not recorded.

| ID | Phase / size / estimate | Depends / blocks | Work and files |
|---|---|---|---|
| A01 | P0 / S / 1–2h | none / A02 | Freeze package, authority and boundary JSON; no code before approval |
| A02 | P1 / M / 3–4h | A01 / A03 | Core action-authority contracts, installed policy, runtime port/capability; contract/unit tests first |
| A03 | P1 / M / 4h | A02 / A04 | Storage ledger, maintenance initializer, current scope derivation, locked membership/journal helpers |
| A04 | P1 / M / 3–4h | A03 / A05 | Application authorize/status/revoke; local scope lifecycle; genuine runtime tests |
| A05 | P2 / M / 4h | A04 / A06 | TaskRepository pre-head start enforcement, coordinator stale return and all start paths; race tests |
| A06 | P2 / M / 3–4h | A05 / A07 | Migration/restore compatibility and live-claim preservation; interrupted recovery and old contract tests |
| A07 | P3 / S / 1–2h | A06 / A08 | Genuine mixed chain, installed-wheel parity, refresh changed resource pins and exact source attestation lists |
| A08 | P3 / S / 1–4h | A07 / none | Exact regression/static evidence and independent Candidate; report remaining work |

- [x] A01: all design artifacts independently reviewed; expanded files/tests explicitly authorized.
- [x] A02: old generic decisions cannot grant; capability unavailable when action port absent; closed fields/digests reject tampering.
- [x] A03: faults before commit leave zero split state; committed retry returns one receipt; capacity retains terminal slots.
- [x] A04: three owner operations work; human port observes zero held installation scope; no caller decision registration API.
- [x] A05: direct CommitBatch bypass and revoke-first never call target; claim-first preserves receipt/reconcile; concrete and compensation share checks.
- [x] A06: supported restore/activation invalidates old approvals; no new start without ledger/current epoch; existing claims are inspectable.
- [x] A07: mixed action/domain chain accepted with correct ordinal/source-gap; wheel contract parity equals source.
- [ ] A08: required named checks pass with no skip/timeout; exact staged Candidate reviewed; no external action or completion claim without authority.

Dependency graph: A01 → A02 → A03 → A04 → A05 → A06 → A07 → A08. There is no agent parallel implementation dependency.

## 4. Dependencies

Internal: approved product PRD/Intent and checkpoint `ecaa416` available. Infrastructure: existing local SQLite, attested runtime factories, isolated wheel tooling available. External: none for synthetic implementation tests; real human adapter interaction and native Linux release evidence remain outside this boundary. Implementation authority was approved for 54 exact targets, 241 selectors and six statics; commit and external actions remain separate.

## 5. Risks & mitigations

- Contract/fixture breadth (likely, high): inventory real consumers and retain old generic ABI; convert positive injected-authority fixtures, never add legacy bypass.
- Lock lifecycle integration (possible, high): test control-plane exclusive acquisition while the human port waits, before wiring happy path.
- Digest closure churn (likely, medium): refresh pins only after behavior settles, update all reverse-referenced bootstraps (including scenario-truth), both source-file lists and package resources; run source/wheel parity on same tree.
- Recovery scope growth (possible, high): do not invent disaster-recovery authority or weaken blocked state; stop on material missing restore contract and report it.

## 6. Rollout strategy

No production rollout here; tests use disposable installations and synthetic targets. A single invalid authorization/start or corrupted component fails this increment. Preserve the last committed source; do not downgrade a live new-component DB to a permissive old binary. Recovery time is not measured and is not promised. Old code does not enforce the new ledger, so no automatic rejection guarantee is made. WP10 owns real installation upgrade/rollback isolation and validation under separate authority.

## 7. Verification plan

[Test Plan](../test-plans/action-authority-registration.md) governs tests. Unit contracts, real SQLite integration/process races, and isolated-wheel end-to-end port flow are required. Existing checkpoint 132 selectors and six statics are retained; impacted runtime/action/migration regression methods are enumerated in the boundary, not wildcard discovery at execution time. Record exact command, tree, outputs and duration. Passing evidence is reused unless inputs changed or a concrete concern invalidates it.

## 8. Open questions

A02 prerequisites are satisfied by the approved package and source-inventory amendment. Final Candidate verification and independent review remain. No technical endpoint is deferred. Any newly discovered requirement outside exact targets/commands is an affected-scope amendment, not permission to widen silently. Spec §11 retains release-platform and unsupported full-control-plane restore limitations.

## 9. References

[Spec](../specs/action-authority-registration.md), [PRD](../prd/graph-engineering-workflow.md), [Positioning](../positioning/graph-engineering-workflow.md), [Impact](../impact/action-authority-registration.md), [ADR](../adr/0011-action-authority-decision-ledger.md).

## 10. History

2026-10-06: initial detailed plan after direction approval. Actual task durations and completion boxes remain unset; no fabricated execution results.

2026-10-06 implementation update: 241 distinct development selectors passed across sandbox and system-native clock runs, plus six static commands. Three independent-review verification gaps were repaired and their selectors passed. Formal staged evidence and Candidate review are still pending; no commit or release is authorized.
