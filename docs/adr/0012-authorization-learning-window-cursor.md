# ADR 0012: Authorization learning window cursor

## Status

Recommended design, 2026-10-08; independent review pending. Owner approved evaluating the R1 direction and six-file design scope, not running upgrades or implementing it. This supplements [ADR 0010](0010-local-product-learning-storage.md) and [ADR 0011](0011-action-authority-decision-ledger.md).

## Context

FR-13 now needs a prospective count of distinct genuinely approved action categories. Consent uses task sequence, while action approval changes no task head. Per-request generations do not order approvals across requests. Creation time, port dispatch time and SQLite rowid cannot prove commit order. Current PRD scope approval already supplies validated revision/baseline proof, which remains authoritative.

## Decision

Recommend one optional, same-database append-only ordering sidecar and schema marker, digest-binding new ledger events and a legacy inventory anchor. Preserve original ledger/receipt digests. Allocate ordinals inside the existing SQLite writer transaction; append approval/order/membership/journal atomically. Capture consent watermark transactionally. Reuse PRD revision and action CAS. Only validated matching approved events strictly after that watermark count; classify distinct configured categories. Old entries are sealed for integrity but receive no historical ordinals. The exact legacy seal is the semantic-record digest of contract action-authority-legacy-seal-v1, columns [request_id,sequence,event_digest] and rows sorted with BINARY request_id/ascending sequence. Explicit installation maintenance validates the original digests against full bodies. Foreground checks the repository-wide metadata partition and ordering digests only, then validates full bodies only for selected, owner-authorized tasks with live metric consent. It never materializes unselected/foreign/revoked/expired task authorization bodies to recompute the seal. New-epoch activation requires explicit resealing and fresh consent; no automatic schema/epoch upgrade.

[Spec sections 5–10](../specs/authorized-stage-learning.md) define exact fields, failure/currentness, migration and bounds. Original ledger component and receipt contracts remain 1.0; sidecar marker is action-authority-order:1.0, PMF marker/record/policy/report 1.1.0, migration bundle 1.2. Keep four PMF tables and the accepted export prohibition.

## Alternatives

| Alternative | Reason |
| --- | --- |
| Per-task request-head watermark vector | Bounds must cover up to 1,024 request identities and digests; cannot guarantee 16KiB aggregate size. Would still need full proof validation and explicit handling of absent/new identities. |
| Task sequence only | Approval and consent can occur at the same task head. |
| Timestamp or SQLite rowid | Not validated commit order or portable migration semantics. |
| Rewrite original ledger bodies with ordinal | Changes already issued event/receipt digests and complicates compatibility unnecessarily. |
| New fifth PMF table | Violates established local PMF storage boundary; independent action audit is the correct owner of ordering. |

## Consequences

Watermark storage is constant-size; capture remains bounded and may refuse a large ledger. A global watermark conservatively invalidates reports after unrelated ledger events. New writes pay one extra row/digest in the same transaction. Ordering is relative to the current repository epoch, not a guarantee against arbitrary whole-control-plane rollback. Existing action starts retain indexed request proof and no PMF dependency. Synthetic maintenance/import/crash tests are required before implementation can be accepted; real upgrades retain a separate human gate.

## Authority and validation

Design scope recorded by wp09-authorized-stage-design-approval-r0.json. Routine precision changes are independently reviewed within revision budget 4. No implementation/commit/push/deploy/release authority follows from ADR review. Tests must show contiguous/unique ordering, atomic rollback, exact receipt retry, both race orders, no legacy backfill, unknown-version refusal and privacy limits.
