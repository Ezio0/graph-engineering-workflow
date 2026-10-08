# Authorized stage learning test plan

## 1. Scope and coverage targets

Design revision1, 2026-10-08. Uses reviewed [Spec](../specs/authorized-stage-learning.md), [Impact](../impact/authorized-stage-learning.md) and [Plan](../plans/2026-10-07-authorized-stage-learning.md). This stage defines verification; product tests/maintenance are not executed. Future in-scope boundary is37 named files,49 new methods and162 existing methods (211 total), plus6 static commands. Existing selectors were mechanically checked by AST without imports/execution; proposed methods do not yet exist.

Out of scope: full274/P1, live installation upgrades, real user data, real external targets, production release, network benchmarks, removing PMF export prohibition. CUJ coverage is100% of these nine required behaviors, not an arbitrary line-coverage or pyramid-count quota:

| CUJ | Required behavior | Primary named coverage |
| --- | --- | --- |
| AS-CUJ01 | Genuine current human approval becomes consented metric | genuine_approval_count, installed_genuine_chain, foreign_identity_epoch |
| AS-CUJ02 | Exact category/request dedup | category_dedup, alias_mapping, same_category_retry |
| AS-CUJ03 | Prospective consent/PRD window and current challenge | late_consent_excludes_approval, unchanged_pending_commit_window, prd_reapproval_rejects_old_challenge, regrant_rejects_changed_security |
| AS-CUJ04 | Both orders of independent-process races and report replay | consent_first_process_race, approval_first_process_race, report_first_process_race, approval_before_report_process_race |
| AS-CUJ05 | Historical willingness distinct from execution permission | revoke_expiry_keeps_history and existing three_start_paths_share_guard |
| AS-CUJ06 | Old/current formats, explicit upgrade/epochs | old_policy_compatibility, pmf_upgrade_legacy_unavailable, legacy_bundle_import, bundle_v12_roundtrip, new_epoch_reseal |
| AS-CUJ07 | Consent/tenant/privacy and total admission limits | no_consent_no_ledger_read, selected_task_body_gate, selected_body_tamper, total_preallocation, canary_absent, forged_order_partition |
| AS-CUJ08 | Atomic recovery/idempotent retry | order_append_atomic_faults, anchor_upgrade_atomic_faults and existing purge_crash_restart |
| AS-CUJ09 | Source/wheel and old owner contracts | installed_genuine_chain, installed_old_owner_contract, resource_closure and six statics |

No new line-coverage threshold is invented. Each named method must collect and execute exactly once without skip; each required case/subtest must pass. Existing project-specific exact selector/installed resource evidence is the completion standard.

## 2. Layers and exact new selectors

12 unit methods check pure count/closed source logic,10 contract methods check versioned installed resources,18 storage/application integration methods check genuine SQLite/runtime semantics,2 installed-wheel journeys check actual distribution boundary, and7 privacy methods check reader/admission/retention behavior. Risk placement, not a cosmetic pyramid, determines counts. All correspond to [Plan T01–T06](../plans/2026-10-07-authorized-stage-learning.md).

| Exact selector | Acceptance oracle |
| --- | --- |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_closed_watermark` | Reject extra fields, booleans, bad epoch/digest and non-canonical ordinals. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_category_dedup` | Repeated events/request IDs/category aliases yield exact set cardinality. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_alias_mapping` | Two configured kinds may share one explicit category; other categories count separately. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_mapping_digest` | Changed mapping is a changed bound source, not silent reinterpretation. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_unmapped_category_unavailable` | Unknown approved kind prevents a partial observed count/zero. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_pending_rejected_excluded` | Pending/rejected/created/attempt have no approval contribution. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_revoked_history_retained` | Historical approved event remains after terminal revoke/expiry. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_revision_baseline_filter` | Only same current baseline with adequate validated PRD transaction revision qualifies. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_unknown_vs_zero` | Missing window/component differs from complete observed0. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_ordinal_bounds` | Safe integer, contiguous sequence and overflow refusal. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_source_projection` | Exact closed source tuple/projection and digest are deterministic. |
| `tests.unit.test_authorized_stage_learning.AuthorizedStageUnitTests.test_count_bounds` | Category cardinality fits configured mapping<=64; no arbitrary counts accepted. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_policy_v11_closed` | New policy schema/mapping limits reject malformed/extra fields. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_record_v11_closed` | Window/source fields are closed and old/new record versions validate separately. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_report_v11_source_vector` | Cohort digest binds exact end watermark/window/mapping/PRD proof. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_input_v10_unchanged` | All original owner-turn learning requests retain1.0.0 fields. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_receipt_v10_unchanged` | Original action receipt/event bytes and digests survive upgrade/retry. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_old_policy_compatibility` | Historical policy/record/report resources remain usable for validation, without invented window. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_resource_closure` | New source/resource/policy bytes match attestation and package paths. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_unknown_component_version` | Missing optional provenance is unavailable; partial/unknown enabled components fail affected writes. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_experiment_schema_compatibility` | Old experiment document validates against its preserved schema, not new policy. |
| `tests.contract.test_authorized_stage_learning.AuthorizedStageContractTests.test_mapping_change_requires_regrant` | Changed digest cannot reuse old consent/source or report receipt. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_genuine_approval_count` | Actual factory→issued session→human port→approval tuple→collect produces exact count; include two independent approval writers with distinct requests and unique committed order. Include the AS-TEST-01 successful-collect replay subcase below, comparing authorization_source at unchanged task head/generation/context. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_same_category_retry` | Duplicate kinds/request retries return original receipt and do not inflate. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_late_consent_excludes_approval` | Approve before grant at unchanged task head is excluded. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_consent_first_process_race` | Barrier ensures grant commits first; fresh valid approval belongs to new window. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_approval_first_process_race` | Reverse barrier order excludes approval from subsequent grant window. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_report_first_process_race` | Report commits before approval is valid then; later replay is stale. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_approval_before_report_process_race` | Approval first invalidates existing aggregate at unchanged head; recollect/re-report returns new value. Also owns the barrier-driven capture/publication and stale internal-capture negative subcases below. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_unchanged_pending_commit_window` | Pending request with unchanged CAS conditions belongs by final approval commit order. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_prd_reapproval_rejects_old_challenge` | Reapproval changes baseline/revision, old pending result cannot commit; new decision qualifies. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_regrant_rejects_changed_security` | Security-changing regrant rejects old challenge; only a new current decision can approve. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_revoke_expiry_keeps_history` | Revoked/expired approved authority still contributes historical count but no new action starts. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_order_append_atomic_faults` | Existing approval fault cuts plus genuine storage failure/restart leave all four surfaces old/new, never partial; retry preserves digest. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_anchor_upgrade_atomic_faults` | Each schema/anchor/marker maintenance cut plus kill/restart has exact old/new state and idempotent retry. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_pmf_upgrade_legacy_unavailable` | Preserve four tables/tombstones/holds/receipts; old consent has no fabricated cursor; prospective regrant starts new window. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_legacy_bundle_import` | 1.0/1.1 bundles preserve original chains without synthesized order. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_bundle_v12_roundtrip` | 1.2 preserves all optional ordering epochs, seals/digests, exact namespace/marker; tampering refuses. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_new_epoch_reseal` | Restored old-epoch sources are unavailable, grants cannot start; explicit synthetic reseal+fresh consent recovers forward evidence. |
| `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_forged_order_partition` | Gap/duplicate/foreign pointer/wrong original digest/modified legacy metadata fail before metrics; no rowid/time substitution. |
| `tests.integration.test_authorized_stage_learning_wheel.AuthorizedStageWheelTests.test_installed_genuine_chain` | Offline built wheel actual factory/session/port→approval→consented count/report matches source. |
| `tests.integration.test_authorized_stage_learning_wheel.AuthorizedStageWheelTests.test_installed_old_owner_contract` | Original non-learning owner operations and action request/receipt contract survive installation. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_no_consent_no_ledger_read` | Missing/revoked/expired/metric-omitted consent causes zero authorization body reads and no source sampling. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_total_preallocation` | Oversized metadata and separately oversized eligible bodies reject before materialization; multi-task capture has one8MiB budget and16KiB aggregate reserve. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_foreign_identity_epoch` | Foreign owner/task/lineage/epoch cannot become count source or current execution authority. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_canary_absent` | Prompt, resource body, nonce, decision ref and synthetic canary absent from PMF output/error/log payloads. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_purge_keeps_action_audit` | PMF purge retains action ledger/order/audit and export prohibition; existing retention authority and legal holds apply. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_selected_task_body_gate` | Eligible task sharing repository with unselected, foreign-owner, revoked, expired and metric-omitted tasks: instrumented body queries/materialization is zero for each excluded endpoint, while bounded metadata checks remain allowed. |
| `tests.security.test_authorized_stage_learning.AuthorizedStagePrivacyTests.test_selected_body_tamper` | Matching selected-task request body with bad digest/binding refuses, never yields observed count. |

## 3. Strategy and exact verification commands

One named method per attested process uses this exact template (replace only selector with each fully listed name):

```text
.venv/bin/python -B scripts/run_wp09_tests.py --test <exact-selector> --timeout-seconds 290
```

Use the49 new selectors above and162 existing selectors below. The runner must emit PASS with collected1/executed1/exact ID and no skipped methods. Its genuine source-checkout attestation and installed resource checks are required; no graph-engineering import is authorized through an untrusted ad-hoc path. Canonical workflow evidence timeout is300s per argv. Execute each selector as its own canonical argv, avoiding nested group-timeout overruns. Child/process-tree timeout is290s; failures/timeouts/skips remain failed evidence. Record command wall time; no p99/throughput performance claim follows.

Unit/contract tests use production validators/projection, with synthetic values. Integration/privacy/wheel tests use genuine DB, installation scope, actual adapter factory and issued session; inject only the external human decision port for positive transitions. Fault injection may interrupt genuine storage/transactions at existing fault seams or produce genuine storage failure; it cannot manufacture positive approval/commit evidence. Independent processes/barriers force both commit orders; assertions cover database state, aggregate/report receipt and zero unauthorized target calls. No sleep-order guesses, mocked clocks replacing native evidence, direct security-membership positives, generic approved escalation or caller watermark credentials.

Reproduce the exact legacy seal recipe from Spec§5, compare body-derived event digests only inside explicit maintenance or consented selected-task reads, and instrument SQL/result materialization to enforce AS-SPEC-01. Shared budget tests charge ordering metadata, legacy projection, eligible request bodies and existing PMF/event sources before allocating. Body-gate tests distinguish SQLite task-id index inspection from returning raw authorization JSON.

AS-TEST-01 exact subcases (within the existing49 selector inventory):

1. `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_genuine_approval_count` must first complete a genuine successful collect and save the original request/receipt, task head, consent generation, context version/digest and derived row bytes. A second independent process commits a new genuine approval after a barrier, while those task/consent/context bindings remain unchanged. Replaying the exact original collect request must raise LEARNING_STALE; it must not return its retained success receipt, append a receipt, or change aggregate/security-retention rows. Compare the complete relevant persisted tuple before/after the failed replay. A fresh collect with a new request ID must produce the new exact count/end watermark; the original committed action receipt stays identical. This fails when replay checks only aggregate_ref/task head.
2. `tests.integration.test_authorized_stage_learning.AuthorizedStageIntegrationTests.test_approval_before_report_process_race` also checks collect capture/publication. Use actual independent processes/barriers at source capture and before publication. The current transaction uses BEGIN IMMEDIATE (connection.py), so a competing approval cannot commit between capture and publication while that same writer transaction is held. Assert that real exclusion without releasing the production lock for a test; collect linearizes first and returns a consistent old watermark, approval commits after the collection transaction releases, and the later original collect replay is stale. If capture ever moves outside the final writer transaction, force approval commit in that interval: collection must refuse with LEARNING_STALE or capture a fresh consistent count/watermark, never publish the old source.
3. The same exact method includes a negative stale-internal-capture case to test the publication guard directly: obtain source capture through the genuine authenticated capture helper in a completed transaction; then barrier-confirm a genuine approval commit in the other process; finally attempt to publish that old capture through the existing private storage collector in a fresh owned transaction. This deliberately stale internal input is a negative case, not a public API/credential or fabricated positive approval. Require LEARNING_STALE and unchanged aggregate/receipt/security-retention tuple; a fresh genuine collection succeeds. It fails if publication omits current end-watermark validation. Do not weaken locks or add a production test-only interface to obtain the interleaving.

Fault matrix includes existing action_authority.after_security, after_journal, before_result_commit, after_result_commit and learning.before_commit/after_purge_delete, plus each new schema/anchor/marker maintenance cut and genuine ledger/order append failure. After crash/restart only the exact old tuple or complete new tuple may exist. Pending results lost before commit need a fresh invocation; exact committed retry preserves original receipts. No success labels for interrupted attempts.

Exact static argv after implementation:

- `.venv/bin/python -B scripts/check_architecture.py`
- `.venv/bin/python -B scripts/check_sources.py lint`
- `.venv/bin/python -B scripts/check_sources.py type`
- `.venv/bin/python -B scripts/verify_build.py`
- `.venv/bin/python -B scripts/verify_reproducible_build.py`
- `git diff --check`

Architecture/lint/type/build/reproducibility checks apply to the final product tree; git diff --check checks repository whitespace. Canonical evidence, independent Candidate and irreversible authority remain separate project steps; Test Plan approval does not commit/push.

## 4. Test data

Use synthetic isolated installations/repositories in managed temporary roots. A genuine owner turn prepares actions, obtains live runtime capability, dispatches the injected external human port and registers approvals through production code. Task and action IDs/resources are synthetic. Mixed repositories contain eligible and deliberately foreign/unselected/revoked/expired/metric-omitted endpoints. Canary text occurs only in synthetic authorization bodies; outputs are searched for its absence. Factories create typed domain state; direct mutation is only a negative corruption/fault case, never positive provenance. Every test cleans its own temporary scope after process exit; no real directory/installation/user consent is modified.

## 5. Environments

Local macOS/venv and offline wheel are the authorized future bounded rehearsal environment. CI can execute identical named argv when separately available, but no CI run is claimed here. Native Linux evidence requires an actual Linux environment later. No staging/production execution is part of these tests; actual install upgrades/release smoke tests belong to WP10/WP11. Native elapsed regressions retain real provider checks and may require an authorized system context where sandbox disallows the read; a sandbox failure is retained rather than relabeled PASS.

## 6. Non-functional and compatibility verification

Security/privacy, admission/recovery, epoch fencing, migration schema compatibility and reproducible package/resource parity are in scope. Network throughput and UI accessibility are inapplicable because no network/UI product surface is added. Old action events/receipt digests, old learning inputs, known experiment format and owner operations remain compatible; unknown/partial enabled components fail affected paths, legacy unordered windows remain unavailable. Regrant after upgrade is prospective and may change security state, so stale pending challenge results must refuse. Restore old epoch cannot restart grants. Initialized PMF blocks export even after purge. Retention holds/authority consumption remain protected.

The211 exact methods are the proposed justified boundary: learning files affect all existing WP09 semantics; action ordering affects registration and action-start invariants; migration1.2/epoch compatibility affects existing migration lifecycle/fault tests. Runtime adapters themselves are unchanged, so unrelated broad runtime suites and full274/P1 are not silently added. New failures or scope changes may require a concrete amendment; passed unaffected checks are not repeated without cause.

## 7. Open questions and gate

No product metric meaning, API or success predicate is left for implementation to invent. Before implementation authority, independent review must approve these exact methods/commands and inventory digest, and deterministic design reducer must complete. Proposed new test IDs are checked structurally now and must be AST-verified/collected once after authoring. All failures and review revisions are retained within budget4. Test execution, product implementation and real maintenance remain outside the current design envelope.

Existing regression selectors (complete162-method list; no directory discovery at execution):

- `tests.unit.test_wp09_learning.LearningTests.test_closed_fields`
- `tests.unit.test_wp09_learning.LearningTests.test_rational_denominators`
- `tests.unit.test_wp09_learning.LearningTests.test_duplicate_identity`
- `tests.unit.test_wp09_learning.LearningTests.test_window_unknown_vs_zero`
- `tests.unit.test_wp09_learning.LearningTests.test_counter_evidence_rules`
- `tests.unit.test_wp09_learning.LearningTests.test_caller_time_not_trusted`
- `tests.unit.test_wp09_learning.LearningTests.test_context_relation_identity`
- `tests.unit.test_wp09_learning.LearningTests.test_boundary_limits`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_native_monotonic`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_cross_process_domain`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_changed_domain`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_forged_provider`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_integer_and_backward`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_wall_clock_independence`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_six_operations`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_explicit_consent_parser`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_unknown_schema_policy`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_installed_resource_binding`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_legacy_owner_operations`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_replay_request_conflict`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_failure_recovery_sequence`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_source_mapping_unknowns`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_caller_time_provenance`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_relation_endpoint_currentness`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_revoke_publish_race`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_fr13_positive`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_fr13_refusal`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_terminal_vs_self_report`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_context_cas_stale_recollect`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_source_head_race`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_prospective_regrant`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_schema_upgrade_restart`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_schema_upgrade_crash`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_migration_no_pmf_export`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_reapproval_window`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_restart_start_sample`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_review_no_double_count`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_forged_review_binding`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_repeat_wait_entry`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_pause_resume`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_non_decision_waits`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_revoke_commit_race`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_wheel_real_provider`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_source_gap`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_duplicate_transaction`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_human_interruptions`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_missing_boundary`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_review_verdicts`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_context_preserves_observation`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_pre_post_approval_grants`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_run_terminal`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_no_consent_no_sampling`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_late_grant_unknown`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_rollback_and_crash`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_tampered_installed_policy`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_cas_body_not_copied`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_canary_absent`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_crash_restart`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_legal_hold`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_retained_handle_currentness`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_authority_consumption`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_corrupt_chain_rejected`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_expired_consent_no_read`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_preallocation_bounds`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_foreign_identity_before_read`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_clock_rollback`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_closed_contracts`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_digest_binding`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_nonce_session_binding`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_terminal_transitions`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_exact_request_conflict`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_policy_bounds`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_receipt_status`
- `tests.unit.test_action_authority.ActionAuthorityContractTests.test_epoch_tuple`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_forged_or_wrong_source_refused`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_capacity_reserves_terminal_entries`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_genuine_approval_registration`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_pending_rejected_no_membership`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_atomic_commit_faults_and_retry`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_revoke_pending_and_approved`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_superseded_invocation_refused`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_direct_commit_batch_cannot_bypass`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_wait_releases_installation_scope`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_restart_pending_requires_new_decision`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_precondition_changes_refused`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_unrelated_security_change_and_relevant_staleness`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_unsupported_component_and_contract`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_migration_component_compatibility`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_revoke_first_process_race`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_claim_first_process_race`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_registration_revoke_process_race`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_three_start_paths_share_guard`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_restore_epoch_and_claim_audit`
- `tests.integration.test_action_authority.ActionAuthorityTests.test_mixed_learning_source_chain`
- `tests.integration.test_action_authority_wheel.ActionAuthorityWheelTests.test_wheel_runtime_port_parity`
- `tests.integration.test_action_authority_wheel.ActionAuthorityWheelTests.test_local_config_cannot_approve`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_011_public_export_is_complete_and_clears_durable_hold`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_012_migration_held_export_reuses_exact_exclusive_token`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_013_bundle_tamper_or_missing_object_fails_validation`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_014_import_replays_exact_history_and_objects_in_isolated_root`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_015_activation_recovery_exposes_only_verified_active_or_blocked`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_016_stale_restore_creates_gap_and_never_lowers_fence`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_017_fault_schedule_is_exact_sorted_and_executable`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_018_interrupted_export_hold_requires_explicit_recovery`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_019_concurrent_public_exports_do_not_reenter_or_partial_publish`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_020_sigkill_before_verifying_preserves_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_021_sigkill_after_verifying_rolls_back_to_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_022_sigkill_before_active_rolls_back_to_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_023_sigkill_after_active_preserves_new_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_024_two_process_activation_has_one_authority`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_025_command_shared_scope_cannot_cross_activation_switch`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_026_corrupt_history_publishes_stable_explicit_blocked`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_040_one_control_authority_spans_exact_durable_migration_graph`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_041_ledger_history_and_head_tamper_fail_exact_validation`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_post_activation_operations_route_only_current_repository`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_042_versioned_fault_schedule_covers_every_production_cut`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_043_every_durable_cut_sigkill_recovers_active_or_blocked`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_044_two_process_orchestrators_have_one_exact_authority`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_045_recovery_cuts_preserve_hold_and_rollback_oracles`
- `tests.integration.test_wp06_migration_orchestration.WP06MigrationOrchestrationTests.test_gew_mig_046_restore_gap_cuts_recover_blocked_or_reactivated`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_034_export_uses_exact_stable_control_exclusive`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_035_bundle_binds_approved_snapshot_identity`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_036_bundle_reader_is_exact_bounded_and_no_follow`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_037_activation_recomputes_exact_candidate`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_038_activation_seeds_candidate_fencing_high_water`
- `tests.integration.test_wp06_migration_authority.WP06MigrationAuthorityTests.test_gew_mig_039_restore_gap_is_persistent_and_blocks_commands`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_receipt_and_compensation_have_no_direct_durable_or_adapter_bypass`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_prepare_authorize_started_claim_call_receipt_and_target_reconcile`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_wp05_code_r1_002_normal_receipt_object_is_durable_and_exactly_bound`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_non_idempotent_timeout_is_unknown_and_never_auto_replayed`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_crash_after_effect_leaves_started_claim_and_never_replays`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_failure_before_effect_reconciles_no_effect_without_replay`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_success_receipt_with_target_mismatch_remains_durably_unreconciled`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_post_call_observation_binding_mutations_never_consume_claim`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_reconcile_observation_binding_mutations_never_consume_claim`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_succeeded_unresolved_action_can_later_reconcile_with_fresh_exact_evidence`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_compensation_with_stale_snapshot_is_zero_write_rejected`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_missing_repository_authority_membership_is_zero_write_fail_closed`
- `tests.integration.test_wp05_action_protocol.WP05ActionProtocolTests.test_durable_action_bodies_are_bounded_before_model_digest_or_use`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_wp05_code_r1_001_rejects_recomputed_wrong_observation_resource`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_wp05_code_r1_001_rejects_recomputed_wrong_rollback_state`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_claim_expired_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_wp05_code_r1_002_compensation_receipt_object_is_durable_and_exactly_bound`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_claim_live_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_start_replay_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_claim_exact_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_no_new_lease_claim_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_authority_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_compensation_only_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_verify_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_attempt_id_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_concurrency_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_lock_span_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_verify_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_no_replay_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_attempt_id_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_receipt_binding_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_start_event_payload_exact_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_reconcile_event_payload_exact_r`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_claim_freeze_p`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_gew_act_recovery_process_crash_matrix`
- `tests.integration.test_wp05_recovery_claim.WP05RecoveryClaimTests.test_wp05_code_r1_002_invocation_oracle_rejects_known_double_call_mutation`

## 8. References

[Plan](../plans/2026-10-07-authorized-stage-learning.md), [Spec](../specs/authorized-stage-learning.md), [Impact](../impact/authorized-stage-learning.md), [ADR0012](../adr/0012-authorization-learning-window-cursor.md), [PRD](../prd/graph-engineering-workflow.md), [Positioning](../positioning/graph-engineering-workflow.md). Exact inventory is detached wp09-authorized-stage-implementation-inventory-draft-r1.json, hashed in the review source record; AS-SPEC-01 closure is bound in the immutable Spec r1 verdict/decision.
