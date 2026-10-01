# Preflight configuration parse reuse

Status: revision 4 corrected design, within the human-approved comprehensive runtime repair.
Base: `1e61b5b2e7b59ae52f4e90c888327dfde1d7fc6e`. Backend TOML reuse at this
base is retained. The rejected copy experiment is not part of this revision.

## 1. Overview

Reduce repeated pure provenance-to-location parsing in the parent process of
coverage lifecycles, and expose per-binding gate progress in the test harness.

```text
coverage lifecycle -> dependency pure operation -> package location scope
fresh resource acquisition -> pure location lookup -> original physical checks
cumulative test -> scoped phase observer -> unchanged lifecycle/gate -> cleanup
```

## 2. Goals

Preserve the approved [PRD](../prd/graph-engineering-workflow.md) validation,
authority and replay semantics. Retain every read, attestation and subprocess.
For repeated identical supported inputs, parse once per each of three slots
within a phase. Retain zero entries after exit. Report every observed gate
binding start and success/failure without changing its result. Demonstrate
complete-path performance using the fixed comparison boundary in the Test Plan.

## 3. Non-goals

No currentness/attestation success caching: external resources remain mutable.
No persistent subprocesses or batching: isolation and observation timing stay.
No global canonical encoder change: whole-path benefit is unproven. No copy
specialization: its previous comparison failed. No full274 run, timeout change,
commit or deployment authority follows from this design. PRD intent is unchanged.

## 4. Architecture

The package root owns a private thread-local location operation. The existing
application `_dependency_pure_operation` enters it, preserving the existing
bootstrap/graph projection operation and nested-scope restoration. This adds
no package-to-application import and no new dependency. All code stays in the
existing synchronous parent process; isolated backend children are unchanged.
Public resource loaders acquire and validate exactly as before; pure wrappers
around advisory/graph location functions and an extracted parser-requirement
path function consult the operation after acquisition. The latter never caches
`_dependency_parser_resources` results. Setup outside a phase stays uncached.

Test-only `_observe_cumulative_phases` temporarily wraps
`ProfileCoverageBindingLifecycle.run` around the existing dynamic gate call.
It maps existing lifecycle identities to binding IDs, calls the original exactly
once, and restores it in `finally`. Unknown lifecycles pass through. Production
classes, algorithms and APIs do not change. Test progress emission is best-effort:
observer failures, including BaseException, cannot mask a primary exception or
change a successful result. Original callback exceptions propagate unchanged.
The serial harness owns this scoped wrapper; it is never an application hook.

## 5. Data model

Three one-entry slots: advisory tuple, graph tuple, parser path. Each entry binds
exact bytes, exact location kind, original pure projector identity and original
`tomllib.loads` identity. PID/thread ownership is checked on each lookup. Store
only exact strings and recursively exact tuples of strings returned successfully
by original projectors. No mutable tree, authority, timestamp or validation result
is retained. Unsupported inputs/results or replaced functions execute uncached.
A cache miss evicts its slot before parsing, including on malformed input, so
changed then restored bytes reparse. Nested operations start empty and restore
the parent after clearing; forked owners cannot reuse inherited entries.

## 6. API surface

Existing public APIs and loader signatures remain unchanged. Private package
context and pure projector helpers are internal, without flags or persistent
configuration. Advisory/graph wrappers retain keyword-only `location_kind`.
The parser path extraction retains its original decode/shape/path exceptions.
Telemetry adds only diagnostic stage rows with binding ID, phase, index and
monotonic duration; no private resource bytes, credentials or environment dumps.

## 7. Error model

Original read/decode/parse/attestation exceptions propagate at their original
boundaries. No parse failure is cached or retried. Operation cleanup covers
BaseException. Observer failure is ignored; lifecycle failure is reported on a
best-effort basis and re-raised unchanged. Existing cleanup exception-group
behavior remains; terminal and teardown measurements do not replace failures.

## 8. Failure modes

| Input or event | Required behavior |
| --- | --- |
| Changed/malformed/reverted bytes | Miss, evict, original parse/rejection |
| Replaced parser or projector | Uncached calls, no warm result bypass |
| Mutable/unsupported result | Return original result without storing it |
| Nested/thread/fork owner | Fresh operation or uncached fallback |
| Cancellation | Clear slots and restore parent/wrapper |
| Same-byte physical replacement | Existing attestation rejection preserved |
| Observer or cleanup failure | Preserve original value/exception behavior |

## 9. Performance budget

The audited latest run reached gate at 12,283.947 seconds. Its adjacent-phase
proxy for gate is 2,392.047 seconds; this is neither an upper bound nor measured
completion. A normal-P full chain passed in 283.034 seconds with gate 49.078
seconds; advisory/graph pure locations consumed about 5.006 inclusive seconds
there. Inclusive profile costs must not be summed. Prior cProfile and string
microbenchmark results are hypotheses, not end-to-end benefits.

Use P/R each two serial baseline/prototype pairs, no cProfile, fresh attested
roots, same whole-chain selectors. Each reduction must exceed its disposition's
baseline range. Native cap remains 290 seconds; canonical cap 300 seconds.
Timeouts stop comparison, preserve evidence and never justify splitting a
continuous chain into falsely equivalent passing pieces. After explicit correction authority, sample performance-P
and release-operations-P with complete phases and
legal single-binding abort/cleanup. A single record from the full installation
plan cannot consume the combined gate; complete-plan finalization stays unknown. Unknown whole-run gate/cleanup costs remain explicit.
Proposed launch target is 20% headroom below 14,400 seconds, not a Policy change.
At the current proxy this requires at least 52.6 minutes saving before terminal
costs. This small optimization is not presumed sufficient. Inconclusive benefit
or insufficient feasibility stops launch preparation, not physical checks.

## 10. Security and resources

The approved PRD and [ADR-0006](../adr/0006-offline-dependency-advisory-authority.md)
remain authoritative. No permissions or personal data are added. The agent may
edit within the 17-path approved allowlist; the Manifest and Candidate
enumerate only actual changed paths; reviewers assess quality independently;
only the human grants commit/full274/external actions. Recompute changed active
module raw pins, protected closures and bootstrap digests, and validate source
and actual built-wheel consumers. Historical verification gates stay unchanged.

## 11. Decisions and rollback

The human approved the consolidated request; no material architecture choice is
introduced. If a test-local observation seam cannot preserve lifecycle behavior,
stop before widening core scope. Before Candidate, resolve actual speedup and
closure validity; before any later run, resolve whole-workload feasibility and
separate launch authority. Rollback restores the package/application/test support
and their active pins together. Preserve evidence and all earlier revisions.

## 12. References

- [Positioning](../positioning/graph-engineering-workflow.md)
- [PRD](../prd/graph-engineering-workflow.md)
- [System Spec](graph-engineering-workflow.md)
- [Impact](../impact/preflight-configuration-parse-reuse.md)
- [Plan](../plans/2026-09-29-preflight-configuration-parse-reuse.md)
- [Test Plan](../test-plans/preflight-configuration-parse-reuse.md)
- Detached `p3-c274-location-approval-r3.json`, comprehensive diagnosis/request
  and independent review r0, copy performance report r0, budget feasibility r0.
