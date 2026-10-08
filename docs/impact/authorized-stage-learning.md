# Authorized stage learning impact

## Scope and upstream

Design revision 0, 2026-10-08. [Spec](../specs/authorized-stage-learning.md) and [ADR 0012](../adr/0012-authorization-learning-window-cursor.md) passed independent Spec review with actual reducer ADVANCE to Impact. PRD FR-13/US-12 and the frozen Intent Baseline remain unchanged. Current design authority covers only the six named files; future inventory is a proposal, not write/test authority.

## Components and data ownership

| Area | Proposed impact | Preserved contract |
| --- | --- | --- |
| Core learning | Pure category cardinality and closed count bounds | No runtime adapter or user-specific thresholds |
| Application policy loader | New installed policy/record/report resources, separate old experiment validation | Issued owner/runtime checks and v1 requests |
| Action ledger storage | Optional ordered sidecar; one extra append per new event transaction | Original component, challenge/decision/receipt digests |
| PMF storage | Window and end-watermark fields in existing observation/derived JSON, marker1.1.0 | Four tables, explicit consent and no backfill |
| Migration maintenance | Explicit initializer, bundle1.2 optional namespaces, epoch resealing | Exclusive scope, legacy bundle validation, PMF export refusal |
| Source/wheel trust | Exact resource/source closure, bootstrap pins and packaging entries | Installed-byte checks, no reference-repository runtime dependency |

## Transaction and concurrency risks

Order append shares the original request ledger writer transaction. Approval/order/security membership/action journal are one commit; no human wait lock. Consent captures watermark in its write transaction. Report/collect revalidate end watermark, baseline/revision, consent and policy in the final transaction, including receipt replay at unchanged task head. Test both independent-process commit orders; a report that commits first is valid then, while its replay after a later approval is stale. Conservative unrelated-event invalidation is acceptable and deterministic.

## Privacy and admission

AS-SPEC-01 is resolved by the reviewed split between exclusive maintenance/full ledger validation, foreground global metadata, and selected consented task body readers. The global seal projects only request_id,sequence,event_digest, sorted by BINARY request_id/sequence; no foreign challenge/invocation/decision/authority body is materialized. Metadata and selected bodies share the existing capture budget with other sources, with lengths/counts checked before allocation. Over-limit/corrupt source refuses; no partial count or false zero. Instrumented selected/unselected/foreign/revoked/expired reads and canary output tests are mandatory downstream.

## Compatibility and migration

Keep old action receipts and input schemas unchanged. New optional action-authority-order marker1.0 and PMF marker1.1.0 require explicit maintenance. Preserve v1.0 policy/record/report resources for historical validation; new policy uses a new path and digest. Existing v1.0 consent is not silently converted into an ordered window: after isolated upgrade the new metric remains unavailable until a prospective genuine regrant. Prior tombstones, retention holds and purge receipts remain enforceable. Unknown/partial versions fail closed at affected endpoints while ordinary tasks retain their existing safe path.

Bundle1.2 carries bounded ordering epochs and marker; old bundles have no synthesized order. Current epoch anchors only after explicit resealing; old order remains audit evidence, old grants cannot start. PMF initialization still blocks export even with empty tables or after purge. No rollback drops tables/markers to evade this restriction.

## Verification and development boundary

All nine CUJs must be represented in a named Test Plan, including atomic maintenance/append fault points, old receipt retry, foreground body gates, digest/partition tampering, source currentness and source/wheel parity. Proposed regressions are selected from explicit AST inventories; no claim of execution is made. Product lint/type/build and reproducible wheel checks follow only implementation approval. Native macOS proof will not stand in for Linux proof; real installs remain excluded.

## Rollback and release

During isolated rehearsal, a failed maintenance transaction returns exactly old state; a fully committed new component remains validated and cannot be destructively downgraded. The reversible operational fallback is to disable/omit this metric with explicit consent/policy behavior and return unavailable; action authority continues under its original enforcement. Release operations and production recovery are not executed in this stage. Migration1.2 source validation must precede any later rollout proposal.

## Review and remaining decisions

Routine source/traceability/testability corrections stay inside design budget4. Impact is not permission to implement. After independent Impact, Plan and Test Plan review and deterministic reducer completion, present exact files, exact named verification argv and remaining implementation authority. WP09 exit evidence, WP10 installation/upgrade and WP11 release are not complete merely because these designs converge.
