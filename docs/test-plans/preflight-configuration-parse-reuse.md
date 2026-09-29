# Preflight configuration parse reuse — test plan

## 1. Scope and critical journeys

The [plan](../plans/2026-09-29-preflight-configuration-parse-reuse.md) is a proposal
pending target approval. All following journeys require evidence; no numerical
line-coverage quota replaces behavior checks.

CUJ1: identical text is read at every old site and parsed once per operation.
CUJ2: changed/malformed/unreadable text and physical resource attacks reject at
the original boundary after a warm entry. CUJ3: returned mutations, nesting,
exceptions, parser replacement, thread and PID changes cannot borrow results.
CUJ4: all affected source installations and real wheel resources validate.
CUJ5: real isolated normal-R and representative rejection paths preserve their
outcomes and lifecycle ordering. CUJ6: an unprofiled comparison measures actual
cost with all checks active. Full274/P1, network and deployment are out of scope.

## 2. Layers and ownership

T1/T2 unit tests use unittest in `tests/unit/test_wp00_packaging.py`; T3 integration
uses existing scenario and WP08a adversarial selectors. Package checks build a
real wheel in a disposable directory. /root owns implementation, an independent
reviewer assesses evidence. Test counts are determined by distinct behaviors,
not template quotas. Direct helper tests do not substitute for the child protocol.

## 3. Behavioral strategy

Unit checks use real TOML parsing and temporary files. Instrument read/parse counts
without replacing the eligible parser's identity; use profiling/call tracing or
an internal deterministic observation available only in test-loaded modules.
A parser spy replacing the callable tests the uncached replacement branch only.
Require repeated reads, one eligible parse for unchanged text, misses for changed
text and reversion, and independent nested dictionaries/lists/scalars including
TOML date/time and non-finite floats. Warm before read failures and malformed text.
Check normal and BaseException cleanup, nested parent restoration, separate
operations, foreign thread and forked process fallback using disposable modules.

Integration runs the real isolated protocol and normal-R four-phase regression.
Use existing preflight probe hooks for post-warm wheel/requirement replacement
and compare original error boundaries. No mocks for attestation, wheel traversal,
currentness, parser trust or child execution. Instrumentation must not skip work.
Retain existing P issue-only coverage with its limitations; do not claim same-
instance P four-phase completion. Representative scenario rejection runs separately.

Closure checks extend the existing performance pin test to migration, scenario
and release consumers, retaining performance coverage. Verify bootstrap/closure
semantic digests via real consumer initialization/currentness, raw source hashes,
TOML reverse pins and actual packaged bytes at each declared resource path.
Also execute the source drift and identical-content root replacement regression.
Existing WP08a tests `test_wp08a_qr_r3_008_parser_attestation_rejects_missing_wrong_and_shadow`,
`test_wp08a_qr_r3_008_same_path_replacements_reject_before_plan`, and
`test_wp08a_final_r3_008_002_parser_protected_fields_are_exact` remain unchanged.

## 4. Data and cleanup

Use synthetic existing wheel/registry fixtures and isolated temporary directories.
No real personal data. Source attestation must bind each comparison checkout's
actual bytes; environment and -X control roots must agree. Clear contexts on all
exits, close fixtures and preserve failed results. Do not alter tracked sources
while a measurement is running.

## 5. Environment and limits

Use the existing .venv Python with -B, strict serial commands, native <=290 seconds
and canonical <=300 seconds. Split independent test cases into bounded commands;
never splice one lifecycle across processes and claim continuous completion.
No installation, network, staging or production is required. Canonical evidence
must bind the final Manifest, exact changed tree and explicit project Policy.
Any project-mandated static/hygiene checks remain required; this plan does not
waive them. No test execution has occurred as part of plan preparation.

## 6. Performance and security acceptance

First confirm behavior, then run two serial baseline/prototype pairs of the same
normal-R regression without cProfile (four commands max, <=290s each). Use separate
fresh roots with their own complete attested closures and fixed fixtures. Report
phase wall times, live read/preflight counts and parse counts. Keep a reduction
claim only if both pairs improve and the smallest pair reduction exceeds baseline
run-to-run variation; otherwise report inconclusive and stop this experiment.
This is a screening rule, not statistical confidence or a full274 prediction.
A safety mismatch rejects the optimization regardless of speed. No automatic
repetition beyond these pairs; timeout/failure stops the experiment for diagnosis.

## 7. Completion and unresolved decisions

CUJ1–CUJ6 must have explicit outcomes before Candidate. An inconclusive performance
result is not approval to increase budgets or remove checks. Independent review
checks exact source binding and limits; preserve red and failed records. Human
scope approval is required before new test/runtime writes. Commit and complete
workload authority remain separate; no open test issue is silently waived.

## 8. References

[Design](../specs/preflight-configuration-parse-reuse.md),
[Plan](../plans/2026-09-29-preflight-configuration-parse-reuse.md),
[Impact](../impact/preflight-configuration-parse-reuse.md),
[PRD](../prd/graph-engineering-workflow.md),
[Positioning](../positioning/graph-engineering-workflow.md).
Checklist adaptation: risk-based counts and bounded local times replace generic
pyramid counts, millisecond limits and staging examples. No current PASS is claimed.
