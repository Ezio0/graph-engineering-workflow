# ADR 0011: Durable human action decisions

Date: 2026-10-06. Status: architectural direction accepted by the owner; detailed implementation package under review.

## Context

`escalate` returns a generic decision; action authorization requires a digest already in security state. A test helper currently supplies that membership. Production needs a genuine runtime-bound decision path and atomic registration. Current journal rows represent action state, not repeated pending/rejected human interactions.

## Decision

Use a dedicated application authorization use case, a versioned action-decision contract and an independent append-only ledger in the same SQLite repository. Bind each invocation to a persisted challenge, fresh nonce and genuine live session. Commit approved ledger event, security membership and journal authority together; serialize revocation and claim-start against the same ledger generation. Reuse the real active installation epoch for supported migration/restore invalidation.

The owner approved this direction against proposal r1 SHA-256 `921662b5b8f00897d2a6af344bdfd96302fda6e10e36a72ee4d790aeee8a5bd9`, after independent review. The [detailed Spec](../specs/action-authority-registration.md) defines the contracts; this ADR does not authorize implementation, schema upgrade or any external action.

## Alternatives

Extending the action journal can be safe, but still needs immutable challenge/attempt history and couples decision lifetime to current action rows. An independent same-DB ledger keeps denied and pending requests durable with one atomic commit. An external service introduces unneeded deployment and cross-store atomicity. Using caller-provided approval dictionaries or collector writes would remove the provenance boundary and is rejected.

## Consequences

Additional schema, installed policy, bounded audit capacity, export/import and version checks are required. No record eviction may revive request IDs. Human waits must release installation scopes, not only SQL connections. Existing tests using authority injection cannot serve as positive integration evidence. No claim of protection against arbitrary control-plane/database rollback is made; path-derived installation identity alone is not a new disaster-recovery incarnation.
