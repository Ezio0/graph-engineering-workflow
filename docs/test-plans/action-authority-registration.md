# Action authority registration test plan

## 1. Scope & coverage targets

Implementation verification is in progress; authoritative results are the detached records bound to the final Candidate. This scope extends the approved WP09 checkpoint after owner approval of the new implementation envelope. Covers Spec contracts, genuine runtime provenance, atomic durable registration, all action-start routes, revoke races, supported epoch invalidation and mixed learning sources. No real Git/network/deploy/release target, real user data, full-control-plane rollback or new authorized-stage metric claim.

All following critical user journeys require coverage; no fabricated line-coverage percentage or required test pyramid ratio is introduced:

| CUJ | Behavior | Exact new test method(s) |
|---|---|---|
| C1 | Owner approves exact prepared action once | `test_genuine_approval_registration`, `test_wheel_runtime_port_parity` |
| C2 | Pending/rejected/forged/mismatched response never grants | `test_pending_rejected_no_membership`, `test_forged_or_wrong_source_refused`, `test_nonce_session_binding` |
| C3 | Restart/retry cannot replay an old decision | `test_superseded_invocation_refused`, `test_restart_pending_requires_new_decision`, `test_exact_request_conflict` |
| C4 | Human wait permits installation change, then rejects stale response | `test_wait_releases_installation_scope`, `test_precondition_changes_refused` |
| C5 | Commit crash leaves whole tuple or none | `test_atomic_commit_faults_and_retry` |
| C6 | Owner revokes pending/live authority, both race orders safe | `test_revoke_pending_and_approved`, all three `*_process_race` tests |
| C7 | Every start path and direct batch enforces current authority | `test_three_start_paths_share_guard`, `test_direct_commit_batch_cannot_bypass` |
| C8 | Capacity/version/epoch changes fail closed and preserve claims | `test_capacity_reserves_terminal_entries`, `test_unsupported_component_and_contract`, `test_restore_epoch_and_claim_audit`, `test_migration_component_compatibility` |
| C9 | Genuine mixed chain keeps learning semantics truthful | `test_mixed_learning_source_chain` |
| C10 | Configured local approved status is not human provenance | `test_local_config_cannot_approve` |

## 2. Layers and command boundary

[Plan](../plans/2026-10-06-action-authority-registration.md) tasks A02–A08 map to this suite. Exact selectors/argv live in `config/verification/action-authority-registration-boundary-v1.json`: 132 checkpoint selectors, 79 additional existing impacted regressions, 30 new methods (8 unit, 20 integration, 2 isolated-wheel integration/E2E); 241 total, plus six existing static commands. All 30 methods have been collected and exercised during development; formal completion requires final Candidate-bound evidence. Existing 211 selectors were inventoried by AST from checked-in tests without executing them. No wildcard discovery, full274/P1 run or live-platform test is authorized by this design document.

For each exact selector use `.venv/bin/python -B scripts/run_wp09_tests.py --test <selector> --timeout-seconds 290`. Existing runner requires exactly one collected/executed method with no skip; subcases belong to that method. Canonical evidence groups have a 300-second ceiling; group by measured runtime, not 241 tests in one group. Static commands are architecture, lint, type, build, reproducible build and `git diff --check`, with literal argv in the boundary. Review budget remains four cycles.

No new arbitrary unit coverage percentage, per-test 10 ms requirement or E2E count is inherited from a generic template: persistence races require more integration coverage than unit coverage. This is a documented risk-based exception supported by the test-plan skill's current instructions.

## 3. Strategy by layer

Unit (A02): closed fields/version/type/digest, invocation/session/nonce binding, legal lifecycle, request conflicts, policy admission bounds, receipts and epoch equality. Real core code, no runtime fabrication. Runner ceiling 290 seconds; report actual duration, do not claim that ceiling as a performance target.

Integration (A03–A06): real SQLite, genuine installation/session factories and two independent processes/connections for races. Replace only external human port and deterministic target/observer. Prohibit `_issued_contexts`/`object.__new__` runtime forgery or SQL-injected authority in success paths. Fault points bracket challenge, attempt, each approval write and transaction commit; verify from a fresh connection after failure. Genuine approval registration must keep task snapshot unchanged while advancing ledger/journal/security tuple.

Detailed assertions:

- Exact approved retry returns original receipt only after current revalidation; relevant task/baseline/prepared/scope change rejects, unrelated security mutation does not falsely stale it. Exercising already-authorized `ActionCoordinator.authorize` must prove its former early return is gone.
- Pending→retry uses a new nonce; cross-session, superseded generation, wrong kind, digest, owner, task or lineage rejects. Same request ID with different challenge always conflicts. Approval lost before commit requires a new port call, not a deserialized approved object.
- Human wait closes the entire command scope; a separate process acquires installation-exclusive access during the wait. Resuming uses newly bound repository objects and current session checks, no reuse of a closed scope-bound factory.
- Revoke-first barriers block result/start until revoke commits, then verify zero claims/events/target calls. Claim-first barriers pause after committed claim, revoke without clearing it, then complete the already-started call and receipt/reconciliation. Compensations validate their own fresh grant. Assert child exit and bounded waits; no sleeps as the race oracle.
- Direct CommitBatch with copied authority digest/generation cannot evade the storage guard; generic, concrete and compensation routes use the same transaction check. Concrete target remains deterministic fake/simulator; no real Git command.
- Capacity test fills the configured finite limit, still permits reserved terminal writes, rejects the next identity and retains old terminal conflicts after restart. Unsupported schema/capability fails only the appropriate surface; ordinary tasks/audit remain available under current guards.
- Restore test uses genuine registered grants for positive setup. Supported activation, failed-activation rollback and restore-gap transitions change current epoch; old authority cannot start. Claims remain historical facts. Missing recovery authority remains blocked—never inject it and call the result production recovery proof. Whole control-plane rollback remains explicitly unsupported.
- Migration manifest v1.0/v1.1 and component all-or-none/version checks preserve exact audit digest or refuse incompatible bundles. Test v1.0 plus injected component/stray backup table, v1.1 missing marker/table, mismatched columns/chain and genuine v1.1 round-trip. Old bundles do not acquire action authority through import. PMF export restriction stays unchanged.

Mixed source (A07): genuine approved runtime decision → normal action coordinator against synthetic target → repository ordinal exceeds domain ordinal → collect real mixed chain. Assert valid chain accepted, tampered ordinal refused, missing observation still reports source-gap, consent regrant starts a new prospective window without backfill. Authorized-stage remains unavailable.

Isolated wheel (A07): build/install into disposable environment using existing tooling; invoke genuine adapter/runtime/owner surfaces for Codex/Hermes cells with injected external human port only. No editable/source-shadow imports. Check exact equality of production/source-test attestation file lists and reverse-referenced bootstrap digests, including scenario-truth. Verify no capability when optional port absent, malformed echo rejected and local generic `human_status=approved` cannot register. These tests prove adapter composition, not a real online human conversation. Each named method obeys 290-second ceiling; timeout is failure, not permission to enlarge silently.

## 4. Test data

Synthetic owner/task/session/action IDs, deterministic fake targets and controlled trusted clock fixture. Per-test temporary installation and DB; no project-owner repository maintenance. Keep evidence outside fixtures, keyed by exact tree/command. Clean only owned temporary paths through existing context managers. Clock advance is supported test-clock input, never a production-time bypass. Forged records appear only in explicitly negative tests.

## 5. Environments

Local macOS source and isolated wheel are in this boundary. Reuse offline wheelhouse; no new dependency/download/service. CI/native Linux and actual Codex/Hermes interactive approval remain WP10/WP11 evidence with separate execution boundary. Staging/production testing is not part of this local library increment. Do not equate OS-mocked tests with native Linux execution. Old-binary access to a component-enabled DB is an unsupported unsafe downgrade; no old-binary automatic rejection is claimed or tested in this increment. WP10 must isolate supported upgrade/rollback routes.

## 6. Non-functional verification

Security: provenance, replay, resources/owner isolation and direct-storage bypass in scope. Recovery: process crash, SQLite atomicity, supported epoch transitions and claim preservation in scope. Performance: bounded parsing/rows/retries and measured command duration in scope, no new throughput SLO. Compatibility: generic runtime, old task/audit behavior, unsupported component refusal and package digest closure in scope. Accessibility/UI appearance not applicable to this library/API change.

## 7. Open questions and stop rules

Before tests/code: independent package PASS and owner expanded boundary approval. Every failure produces a cause/evidence record; repair only within target/test scope and four review cycles. Do not repeat passed checks without changed inputs or concrete risk. At Candidate, bind all required evidence to the exact staged tree and narrow Candidate targets to actual staged files; never call a permitted-but-unchanged file a staged target. Commit/push remain separate authority.

## 8. References

[Plan](../plans/2026-10-06-action-authority-registration.md), [Spec](../specs/action-authority-registration.md), [PRD](../prd/graph-engineering-workflow.md), [Positioning](../positioning/graph-engineering-workflow.md), [Impact](../impact/action-authority-registration.md).
