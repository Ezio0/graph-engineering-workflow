# Action authority registration — impact

Status: proposed implementation scope following the 2026-10-06 architecture-direction approval. [Spec](../specs/action-authority-registration.md) is normative. Product PRD and Intent Baseline are unchanged.

The current checkpoint has no production writer connecting a genuine human decision to security authority membership. Adding only that writer would leave stale-return and revoke/start race gaps. This change therefore covers application registration, runtime contract provenance, durable ledger, all execution-start paths and maintenance compatibility together.

| Surface | Change | Compatibility/risk |
|---|---|---|
| Core/runtime | Separate closed action-decision request/result and capability | Generic v1 decisions remain; no downgrade to generic approved status |
| Owner turn/composition | Three operations, two short repository scopes around human wait | Existing long-lived local scope must not be retained by new use case |
| Action coordinator | Registered-grant validation, unified revoke, three start paths | Callers that injected membership must migrate; no legacy start exemption |
| SQLite | Bounded append-only component, atomic ledger/security/journal commit | Explicit isolated maintenance only; missing schema blocks new starts |
| Task commit | Validate authority before head mutation in writer transaction | Direct CommitBatch bypass must fail; existing receipt/reconcile remains usable |
| Migration | Ledger compatibility, epoch binding, old claim audit | Whole control-plane rollback is unsupported; recovery is not automatic |
| Learning | Genuine mixed source integration evidence | Preserve source-gap and unavailable authorized-stage semantics |
| Package resources | Installed policy and protected digest closure | Source and isolated-wheel parity, no editable/shadow source trust |

No new dependency, external write, real Git target, user data collection, production installation upgrade, commit or push is included. Existing 132-test checkpoint plus six statics remains the regression base; the proposed envelope adds exact tests for this capability and impacted action/runtime/migration modules. Old action fixtures must exercise real registration if they assert a valid new start. Negative tests may construct forged inputs only to prove rejection, clearly separate from success evidence.

Rollout is source implementation and isolated fixture/wheel verification. An installed old repository fails with upgrade-required on the new action surface; unrelated tasks/read-only audit retain current guards. No foreground table creation. Reverting code cannot safely reinterpret new ledger authority as old security membership: old binaries do not inspect this ledger and may accept its legacy membership/journal fields. Therefore running an old binary against a repository with this component is an unsupported, unsafe code downgrade; this increment does not promise automatic old-binary rejection. A release migration/rollback procedure remains WP10 work, not implicit permission in this scope.

No existing code is deleted. [ADR](../adr/0011-action-authority-decision-ledger.md) records ledger choice; [Plan](../plans/2026-10-06-action-authority-registration.md) records sequential work. Exact proposed files and command selectors are recorded in `config/verification/action-authority-registration-boundary-v1.json`; the Candidate later uses only actual staged paths, not every permitted file. Independent review is required before requesting implementation authority.
