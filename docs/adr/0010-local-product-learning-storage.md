# ADR-0010: Local product learning storage

Status: storage location accepted by the owner through spoken approval; detailed implementation boundary and export limitation accepted by the owner on 2026-10-04.

## Context

WP09 requires local consent, minimized aggregates, owner context and deletion suppression with atomic currentness checks. Task event/CAS history has a different lifetime from disposable metrics. A second database would require cross-database consent and purge coordination.

## Decision

Use four dedicated tables in the existing local repository database: `pmf_consents`, `pmf_aggregates`, `pmf_owner_context`, `pmf_tombstones`. Reuse its issued runtime identity, connection, locking and transaction boundaries. Store only the closed W9 fields. No raw prompt, source, secret or arbitrary owner text. Grant is explicit and prospective; every operation rechecks consent and context/relation currentness.

## Approved implementation boundary

Track the PMF schema independently in `schema_versions`. Create or upgrade it only under explicit maintenance control in one transaction, with crash/restart and idempotency tests. Reads never install schema. Unknown PMF schema blocks learning while preserving ordinary task operations. No destructive downgrade or automatic real-data migration.

Do not silently include or discard PMF data in migration exports. The approved implementation rejects export whenever any PMF table or PMF schema-version marker exists, even with empty tables or only tombstones. The same exclusive installation token must protect the check before destination creation, hold mutation or database backup; enabling PMF export needs a separate privacy/authority design. Tombstones remain local and are not erased to unblock an export.

## Consequences

Same-database transactions provide a common linearization point for revocation, aggregation and guarded purge. Physical deletion remains subject to retention holds and consumed authorization; logical deletion is not a forensic-erasure promise. Rollback disables learning without dropping its tables or audit tombstones. No network or background collector is added. After explicit current consent, genuine foreground task transactions synchronously maintain minimized observation state within pmf_aggregates. There is no sampling without valid consent and no fifth PMF table.

## Validation and remaining boundary

Use the accepted W9-D2 exact path and command inventory. Runtime contract, privacy, race/crash, source/wheel and regression tests must pass on the implemented bytes. Existing timestamps are caller-reported; this decision does not certify historical duration. The approved updated increment includes genuine-source elapsed, revision and interruption metrics under the main Spec supplement. Authorized-stage statistics remain unavailable. The owner explicitly accepted disabling migration export after PMF initialization.

## Authority record

Accepted storage choice is bound in `wp09-storage-decision-approval-r0.json` in the project detached delivery records. The current decision is bound by `wp09-implementation-approval-r0.json` and synchronized with the affected four main design artifacts. Implementation and bounded verification are approved; commit and push remain separate actions.
