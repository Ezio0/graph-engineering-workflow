# Preflight configuration parse reuse

Status: design assessment; not implementation or run authority. Base commit:
`7c2e4a00c305628d3c392cf2811a65f2eb4a5d8c`. This follows the rejected pure-graph
optimization and the independently reviewed preflight cost diagnosis.

## 1. Overview

Reuse only TOML decoding of identical freshly read configuration text during one
`preflight_offline_candidate` invocation. The build backend owns the operation;
each existing caller retains its live reads and all subsequent validation.

```text
isolated child / direct backend caller
  -> preflight operation begins with empty private slot
  -> each original _configuration call
       -> original PYPROJECT.read_text(encoding="utf-8")
       -> exact text + trusted parser identity lookup
       -> detached parsed value
  -> original attestation / wheel / policy / physical checks
  -> original result or exception -> slot cleared
```

## 2. Goals

- Preserve the count and order of configuration reads, physical rechecks and
  parser attestations for each existing execution path.
- For an unchanged input and supported parser, reduce 12 successful TOML parses
  to one in the measured normal-R preflight case; still perform all 12 reads.
- Return independently mutable results, with zero cache entries surviving an
  operation, including exceptional exits.
- Establish an unprofiled bounded before/after comparison before claiming any
  performance benefit. No full274 completion-time claim is made.

These preserve the existing requirements linked in §12; they add no user-facing
behavior or authority semantics.

## 3. Non-goals

No cached currentness or attestation verdicts, because checks observe mutable
resources. No persistent child or combined preflight, because those change
isolation or observation timing. No cross-operation reuse or timeout increase.
No redesign of phase validation, public API, PRD intent or deployment topology.

## 4. Architecture

Proposed implementation belongs in `scripts/build_backend.py`: a private
operation context around the existing preflight body and a pure parsing slot
consulted by `_configuration` only after its original read succeeds. No change
to the isolated protocol in `core/graph_engineering/__init__.py` is proposed.
Direct backend preflight callers get the same bounded operation; other backend
operations retain uncached parsing.

Use a context-local slot, with PID and thread ownership checks. Preflight is
synchronous; no asynchronous work may escape this scope. Nested preflights get
an empty child slot and restore the parent after clearing the child. Foreign
PID/thread contexts use the uncached path. Do not add a process-global result
cache or patch `tomllib.loads` in the child protocol.

Alternative: process-global memoization is rejected because the backend is
also used directly and may persist across requests. Injecting memoization from
the parent protocol is rejected because it splits policy ownership between
attested code and its caller. These choices are design proposals, not approval.

## 5. Data model

One slot per active preflight stores owner PID/thread, operation identity,
exact parser callable, exact decoded text and a private parsed tree. Compare
complete text, not a digest, path, mtime or object identity. Text is the exact
argument consumed by the current parser: preserve UTF-8 decoding and newline
translation of `read_text`; do not change the read API for this optimization.

Reuse is eligible only for the backend's captured standard TOML parser with its
existing default options. A replaced parser executes uncached on every call;
do not assume an arbitrary replacement is pure merely because identity matches.
On a miss, parse, retain a private defensive copy and return an independent
value. On a hit, return a defensive copy. Preserve TOML native scalar types,
including date/time values and floating-point special values; JSON round trips
are not an acceptable copying mechanism. No failure or capability is stored.

## 6. API surface

The existing `preflight_offline_candidate(candidate_wheel, wheelhouse, *,
_probe_hook=None)` signature and return type remain unchanged. `_configuration()`
continues returning a dictionary. Private context/helper names are implementation
details, with no new flags, caller-supplied cache or public activation switch.

The context is entered after the existing probe-hook type check and encloses
all original preflight work. Lookup does not move or reorder any caller checks.
Tests can compare baseline and proposed behavior in disposable loaded modules;
production code must not accept a caller's claimed validation result.

## 7. Error model

Original read/decode errors, TOML errors and validation exceptions propagate at
their original boundary. Do not cache errors, retry automatically or swallow
exceptions on a reuse path. Unsupported/replaced parser or foreign ownership
uses the original parser path, not a previously saved success. Cleanup runs
under `finally` for all `BaseException` exits and restores the parent context.

## 8. Failure modes and verification

| Case | Required result |
|---|---|
| Repeated identical text | One eligible parse; original read count/order; independent results |
| Changed text, then original text | Reparse on each one-slot miss; no stale configuration |
| Malformed text/read failure after warm entry | Original exception at that read/parse boundary |
| Caller mutates nested return value | Later results and private slot unaffected |
| Parser replacement | Replacement called every time, no warm-cache bypass |
| Nested operation, foreign thread or fork | No inherited reuse; correct parent restoration |
| Cancellation or unexpected exception | Slot cleared and no subsequent operation reuse |
| Wheel/requirement replacement after warm entry | Existing physical/attestation rejection preserved |
| Same-byte replacement | Preserve existing read/check behavior; do not invent a new identity guarantee |

Use real source/package closure regressions as well as focused helper tests.
Cover direct preflight and the existing isolated protocol, normal R four phases,
bounded P coverage and a representative rejection scenario. Existing P coverage
limitations must remain explicit rather than claiming complete P acceptance.

## 9. Performance evidence and budget

The normal-R diagnostic passed in 182.827 seconds. Gate preflight ran 95 times:
19.505 seconds total, 2.201 resource acquisition, 17.183 subprocess wall, and
0.120 parent residual. Two profiled children each parsed configuration 12 times;
TOML parsing accounted for 66.32% / 66.86% of recorded profiler time.

cProfile overhead distorts those fractions; do not extrapolate them to elapsed
savings. The parent residual includes instrumentation and output processing.
Subprocess wall is not process-startup time. Only two children were profiled.

After authorized implementation, first prove parser/read counts and behavior,
then compare unprofiled equivalent baseline/prototype workloads using fresh
attested roots, identical selectors and strict serial execution. Begin with a
bounded paired sample; if inconclusive, report that rather than expanding runs
without a defined budget. Native commands remain <=290 seconds, canonical
commands <=300 seconds; full274 remains a separate single-run authority.
Account for defensive-copy cost. Stop this optimization if measured savings
are not distinguishable from variability. No p95 or full-run estimate is
supported by current evidence.

## 10. Security, trust and affected resources

No new permissions, external service or personal data is introduced. The slot
contains only configuration text and parsed values within the existing process.
Physical source reads, installed-resource checks, packaging attestation,
wheelhouse safety, all three parser attestations and isolated execution remain.

Read-only reverse-pin inspection found the current backend hash in:

- `pyproject.toml` (five direct occurrences across its bootstrap sections).
- `config/migration/migration-rehearsal-installation-bootstrap-v1.json`.
- `config/performance/performance-benchmark-installation-bootstrap-v1.json`.
- `config/profiles/scenario-truth-installation-bootstrap-v1.json`.
- `config/release-operations/release-operations-installation-bootstrap-v1.json`.

Any implementation must recompute affected raw hashes, protected closure and
bootstrap digests and their reverse references using current validators. This
inventory identifies direct bindings; it is not a complete transitive write
allowlist. Verification must initialize affected registries and validate actual
wheel resources, preventing recurrence of the earlier stale performance pin.

`config/verification/wp-07a-gate.json` and `wp-08a-gate.json` also mention this
backend with historical hashes. Classify their evidence roles before changing
anything; do not rewrite historical verification records to match new code.

## 11. Delivery decision and remaining gates

Recommend a bounded backend parse-reuse implementation proposal, subject to
independent assessment of this design and project authority. The current
`GEW-REMAINING54-V1/authority-envelope.json` does not include
`scripts/build_backend.py` in `allowed_targets`. Thus this assessment does not
silently authorize backend changes, pin updates or a Manifest replacement.

Before implementation, resolve the transitive pin closure, exact write targets,
Impact and test plan, and the required authority amendment. The deadline for
these decisions is the implementation gate. Proposed tests belong alongside
existing packaging and scenario regressions; final target selection belongs
in that bounded proposal. Commit and full274 rerun remain separate decisions.

Rollback must restore backend bytes and all associated active bindings together,
then verify source and installed closures. It must not remove safety checks.

## 12. References

- [Positioning](../positioning/graph-engineering-workflow.md)
- [PRD](../prd/graph-engineering-workflow.md)
- [System Spec](graph-engineering-workflow.md)
- [Earlier phase-context assessment](../../.workflow/delivery/GEW-REMAINING54-V1/detached/p3-c274-phase-context-design-archive-r0.md)
- [Offline dependency authority ADR](../adr/0006-offline-dependency-advisory-authority.md)
- [Performance authority ADR](../adr/0007-offline-performance-benchmark-authority.md)
- Evidence under `.workflow/delivery/GEW-REMAINING54-V1/detached/`:
  `p3-c274-preflight-cost-report-r0.json`, its independent review,
  `p3-c274-pure-graph-report-r0.json`, and `p3-c274-run-result-r4.json`.

This document is a design assessment, not a passed implementation, Candidate,
benchmark or authority gate. No runtime edits or workload runs are part of it.
