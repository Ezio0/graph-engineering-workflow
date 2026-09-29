# Preflight configuration parse reuse — impact

## Scope

This is the prepared C274-RUN-005 repair proposal, not implementation authority.
It follows the independently reviewed [design](../specs/preflight-configuration-parse-reuse.md).
The approved product intent and validation contract remain unchanged.

## Active dependency closure

At base commit `7c2e4a00c305628d3c392cf2811a65f2eb4a5d8c`, reverse traversal of
current raw SHA256, bootstrap_digest and protected_closure_digest references in
tracked config files and pyproject.toml yields six active source/config targets:

1. `scripts/build_backend.py`
2. `config/migration/migration-rehearsal-installation-bootstrap-v1.json`
3. `config/performance/performance-benchmark-installation-bootstrap-v1.json`
4. `config/profiles/scenario-truth-installation-bootstrap-v1.json`
5. `config/release-operations/release-operations-installation-bootstrap-v1.json`
6. `pyproject.toml`

The four bootstraps reference the backend; their raw and semantic digests feed
pyproject.toml. Backend raw pins also occur directly in five TOML entries.
Update leaf backend hashes, protected-closure digests, bootstrap digests, then
raw bootstrap hashes and TOML references. Use the existing canonical digest
algorithms and validators; never replace an unrelated equal-looking value.
The audit record is `p3-c274-preflight-parse-pin-audit-r0.json` in detached evidence.
Its literal-reference traversal is supplemented by actual consumer and wheel
checks in the test plan; it is not proof against dynamically derived references.

## Runtime and compatibility impact

Only backend preflight parsing changes. Every read, parser attestation, wheel
validation, isolation boundary, exception path and public signature is preserved.
Build operations outside preflight retain uncached behavior. Defensive copies
must preserve TOML types; their cost is included in comparison measurements.
No dependency, schema, clock policy, deployment or external access changes.

## Verification and historical boundaries

Extend `tests/unit/test_wp00_packaging.py` for operation behavior and all four
active installation closures; extend `tests/integration/test_wp08_scenario_truth.py`
for the real isolated preflight path when a new assertion is needed. Existing
WP08a parser/physical attack regressions run unchanged and retain original outcomes.
The WP07a/WP08a gate configurations bind historical work-package runtime pins and
source manifests, including hashes different from the current backend. This
repair neither rewrites their historical evidence nor claims to rerun their
whole historical gate. Relevant regression selectors are run against this repair.
Current repair verification must be independently bound to its own Candidate.

## Risks and rollback

A cached mutable result could hide policy changes: detached returns and warm-cache
mutation tests are mandatory. A missing reverse pin can prevent startup: source
registry and actual installed wheel checks cover each affected family. Context
leaks can reuse results in another invocation: nested, thread, fork and exceptional
exit tests are required. Insufficient measured gain means stop and report the
outcome; do not increase the full-run limit or remove checks.
Rollback restores backend and six-file closure consistently, then revalidates
source and wheel resources. Preserve all failed evidence.

## Authority and delivery

The exact proposed allowlist is in the detached C274-RUN-005 implementation request.
It includes the six targets above, two test files, four repair documents and the
Manifest. Historical authority files are preserved; approval is recorded as a new
scoped effective envelope, following prior repair practice. Target additions,
new dependencies and security-contract changes require another human decision.
Commit, push, full274/P1 run, deployment and external communication are excluded.
