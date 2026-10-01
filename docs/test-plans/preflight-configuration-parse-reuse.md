# Preflight configuration parse reuse test plan

## Boundary

This is bounded repair verification, not full274 acceptance. Keep existing
290s native and 300s canonical limits; no timeout increase or retries.

## CUJ-1: Safe pure reuse

Packaging-level tests use real provenance bytes. Verify equal immutable outputs
and one eligible parse per slot for repeated inputs; changed/reverted/malformed
bytes, replaced parser/projector and unsupported results cannot reuse success.
Test nested scopes, thread/foreign PID (plus actual fork where supported) and
BaseException cleanup. Counting spies may instrument lower-level parsing only
when deliberately testing replacement fallback; never replace trusted parser
identity and then claim a production cache hit.

## CUJ-2: Fresh acquisition

Exercise real source attestation and actual built wheel closure consumers.
Existing same-byte cold replacement, isolated preflight and active bootstrap
regressions remain. Compare resource acquisition, source projection and child
counts on equivalent full phases using wrappers outside pure-projector identity
checks. Counts must remain unchanged; no fake validation result is accepted.

## CUJ-3: Observation transparency

Test helper `_observe_cumulative_phases` around a fake lifecycle whose original
run returns a sentinel or raises a specific BaseException. Assert one call,
original object identity, per-binding start/done/error and restored method after
normal, observer-failure and body-failure exits. Unknown lifecycle delegates.
Run real four-phase regressions and preserve cleanup error-group behavior.
Add best-effort finalization start/done/error events at existing call boundaries.

## CUJ-4: Real complete paths

Normal P entry: existing `_dependency_routes_reopen_all_four_phases` with
`(('normal','normal',None,'P'),)` in one test. R entry: existing
`test_dependency_pure_reuse_normal_rejection_all_phases`. Both retain original
assertions for all four generations, quiescence, bytes and no action replay.
Each command contains one entire chain; a timeout is failure, not partial pass.

## Fixed performance experiment

Before runs snapshot baseline commit and prototype tracked-file bytes into fresh
roots. Order: R baseline1/prototype1, R baseline2/prototype2, P baseline1/prototype1,
P baseline2/prototype2. Eight commands maximum, each <=290s. No cProfile or
projector substitution. Exact same injected P test body runs on both revisions.
Capture wall elapsed plus phase and unchanged physical/child counts; instrumentation
is identical in both. Each reduction must exceed its disposition's baseline
range. Failure stops remaining dependent work; no extra samples to manufacture pass.

## Representative and terminal sampling

After the original eight-command screening and approved correction: for each
baseline/prototype, run a single
`normal`, P, quiescent `run_serial_profile_binding` for `performance` and
`release-operations`. Use `_verified_runner_contracts(profile_id)`, installation
plan, `observe_current`, factory issue, `ReleaseCoverageGate.evaluate`, and
`abort_uncommitted_coverage_factory`, then result.close in finally.
Do not invoke complete-plan finalization: _bind_combined_gate requires all
plan.bindings, and one record never grants that consumption state. Validate four
phase generations, expected incomplete-matrix decision, terminal state and zero
active handles. The original baseline failure remains recorded. After explicit correction
authority, allow four remaining commands: corrected performance baseline and
prototype, then release-operations baseline and prototype; five representative
attempts total including the retained failure, each <=290s. No further retries.
Measured terminal time is abort/cleanup only. Full combined-gate finalization
remains unknown and cannot be replaced by these measurements.

## Canonical evidence

Reuse the existing canonical closure/regression selectors for packaging and
source/wheel consumers, adding the new focused cache/observer suite and P selector
in separate commands as needed to stay within 300s. Freeze exact argv/counts in
a detached canonical plan before staging/capture; do not expand full acceptance.
Independent implementation, verification and Candidate reviews remain required.

## Model and stop criteria

Use historical nine-profile counts and disjoint stage timings. Credit measured
improvement only to covered representative categories with explicit uncertainty;
uncovered categories receive no speedup credit. Keep whole-gate, cross-hour
variance and terminal scaling unknown rather than zero. Target 20% headroom is
an engineering feasibility criterion, not Policy or run authority. Insufficient
headroom leads to a structural decision, never another automatic 4h attempt.

## Evidence reuse after correction

Retain all eight original P/R results as evidence for their exact runtime bytes;
do not rerun them for this document/budget-only correction. Verify equality of
all execution inputs and installation protected resources before reusing those
measurements. They are not new-tree canonical evidence; capture the fixed
canonical commands only after the corrected artifact tree is reviewed/staged.

## Evidence and authority

Retain failed runs, logs, exact source hashes and historical revisions. No true
PII, network, deployment or credential access. Tests use private synthetic roots.
User authorized this bounded repair; commit and full274 remain separate gates.
