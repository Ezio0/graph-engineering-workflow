# Graph Engineering Workflow — Test Plan

## 2026-09-20 RS-C installed currentness checks

Source currentness must measure actual owner reservations before each read and
cover all327 attested members, control key/attestation, both factory read methods,
missing/foreign context bindings, changed bytes/size, short read, growth, FIFO
control lock, descriptor cleanup and exact entry accounting on failure.

Before accepting the pending wheel read strategy, test both unpacked and archive
installations in fresh native processes. Include added/removed duplicates,
in-place non-selected metadata Name changes, single-file egg-info and
egg/EGG-INFO fallback (including empty files), new earlier metadata fallback, non-selected archive
candidate changes, empty/relative sys.path with changed cwd, absent roots becoming
present, changed discovery provider/implementation, selected RECORD and archive
central-directory duplicates, loaded-module identity, streaming short read/growth,
exact common allowance and minus-one rejection, retained first proof, and cleanup.
Exercise many non-candidate directory entries with few or no candidates, repeated
root occurrences, overflow without truncation, and iterator closure on exception
or early rejection. Filtering cannot hide uncounted enumeration work or memory.
Legacy distribution.files, full resource tuples, TOML and ZipFile metadata paths
must be unreachable from cold checks; their original installation validation is
not replaced by a caller-supplied plan. All previous policy limits and the
failfast600second native-batch boundary remain unchanged.

## 2026-09-20 RS-C installation-control read tests — proposed R0

Human update (2026-09-20): the owner replied “确认” to the final one-file
request, approving GEW-REMAINING54-P3-COLD-INSTALLATION-CONTROL-V1. The
append-only p3_restart_cold_installation_control_amendment records this exact
extension. Current boundaries are185 product /195 effective /41 selected
targets. The reviewed proposal below is historical; its implementation scope
and all exclusions remain unchanged. Prior RS-C R2 approval stays valid.

Run these focused RED-first cases only after the one-file authority amendment
`GEW-REMAINING54-P3-COLD-INSTALLATION-CONTROL-V1`. Use the existing release
integration/unit tests and Remaining54 authority test; no new test file, stored
data, configured budget or workload is introduced.

- Active manifest and locator registry each reject actual descriptor bytes
  above the installed document or remaining aggregate bound before a body
  allocation; falsely small metadata, growth, short read and path replacement
  fail without retry. Observe descriptor read counts/maximum requested bytes.
- Locator array overflow rejects before `_RepositoryLocator` construction.
  Valid sorted entries remain accepted; duplicate locator/repository IDs,
  altered locator digest and foreign root device/inode/path remain rejected.
- Changed manifest digest/context/mode and control-file owner/mode/symlink
  substitutions still reject. Cover first cold read, every nested
  `_connection_opened` check and reuse after an earlier successful closure.
- Hold the first complete closure while admitting the control reads: exact
  remaining allowance succeeds and one unit/byte less fails. Inspect live raw,
  decoded, parsed and locator reservations, including distinct participating
  contexts and pre-existing retained use. A resource failure cannot satisfy a
  semantic-substitution oracle.
- Missing/foreign/overlapping/cross-thread lexical owners reject; exceptions
  restore the binding and release descriptors, tokens and scratch. Success and
  all failures preserve database/control-file/retained-root bytes with zero
  clock writes, registration, activation, migration or action replay.
- Preserve ordinary command/currentness behavior and the full installed
  provenance checks. Update only the exact185 authority assertion after Human
  approval; verify subtraction recovers the historical184 and earlier sets.

Fresh private source attestation, serial native execution, the authorized real
parent600-second timeout and independent review remain required. These are
proposed cases, not execution evidence or complete cold recovery acceptance.

## 2026-09-20 RS-C source, locator and cold-use verification — R2

Human update (2026-09-20): the owner's response “继续” to the final R2
API request authorizes GEW-REMAINING54-P3-COLD-SOURCE-READ-API-V1, recorded
in p3_restart_cold_source_read_api_amendment. The not-yet-authorized wording
in the reviewed proposal below is historical and is superseded only for this
exact API, consumers, resource hardening, tests and independent review.
The184/194 boundaries and all irreversible exclusions remain unchanged.

Scope is Spec RS-C and existing RS-CUJ1–6; all named journeys/negative groups
remain required. Native unittest uses serial fresh private fixtures, attested
source checkout, explicit installation scope, parent monotonic_ns and600second
failfast cap. No code-coverage percentage or performance result is claimed.

| CUJ | Positive and mandatory rejection evidence | Lowest useful layer |
|---|---|---|
| C-B | RS-C-0 locator/gated/reuse reads are bounded before SQL/CAS materialization; exact-limit success and oversize/false-size/growth/short/aggregate/row-count failures reject without leaks or writes | Existing release integration |
| C-P | Exact installed artifact source/schema/wheel closure; changed config/source/RECORD rejects; direct documents do not issue cold authority | Existing release unit and installed-wheel tests |
| C-S1 | Unique referenced assessment, exact lifecycle/revision/epoch/GraphRef/authorities, normal discriminator; all11 other columns refuse before source issuance | Release integration |
| C-S2 | Real committed logical bodies, exact runner node/output/actor and final/prior review linkage; digest type confusion, duplicate/missing/unreferenced body, foreign/extra output and unrelated PASS reject | Release integration and source units |
| C-S3 | Category -> full ArtifactRecord -> manifest -> raw body joins; field/schema/version/status/actor/review/contract/baseline/target/selector/content substitutions reject, including coherent re-signing of only one link | Release integration |
| C-S4 | Exact same retained target contract, expected terminal state/resources and selector, full typed normal evidence; legacy dummy target/label-only sources reject | Release integration |
| C-L | Locator is data only; all repository tokens released before gate; altered ref between locator and gated read rejects; marker admission bounds, wrong fixture, residue and partial descriptors refuse safely | Release adapter/integration |
| C-E | Fresh exec producer exits, consumer rebuilds installed/runtime/repository authorities, recovers exact historical bytes for apply-B and completed partial compensation-A; twice-use revision is local and increasing | Two-process integration |
| C-R | Each source and physical byte changes after first capture/before publication/on second use; revoke handle and close all resources, preserve existing final callback completion fence | Release integration |

Use actual CAS, SQLite, physical root and factory/currentness code. Mocks may
inject a race/fault or assert a prohibited call; they cannot supply authoritative
source success. Producer setup, injected tampering and recovery are separately
counted. Persist real raw bodies/manifests/records and evidence_refs through
existing APIs; no product claim that synthetic producer ran actual specialist
NodeCandidate loops. Keep legacy synthetic fixtures as negative cold tests.

Every successful or rejected recovery measures unchanged task/event/snapshot/
CAS/reference/action/claim/receipt/target content, zero execution/reconciliation/
renewal/apply/restore/network calls, and descriptor/root lease release. Count
first-read and repeat-use failures separately. No assessment is reissued into a
live oracle or release evidence registry, and no old capability crosses exec.

At each locator, gated capture and repeat-use entry, independently inject
oversized actual CAS with correct or falsely small metadata, growth after
fstat, short read, oversized SQL fields, too many SQL rows/references, and
aggregate overflow from individually admissible bodies. Include exact-limit
success and a multi-body case measuring overlapping SQL/raw/parsed/serialized
representations. Count bytes actually read and peak retained allocation;
post-return length checks alone do not establish a bound.

Patch legacy TaskApplication.runtime_show, TaskRepository.load/replay/
referenced_objects/category_source_seal, ObjectRepository.get/_verify_file/
_read_descriptor and legacy materialization lookup to raise if entered during
cold recovery. Positive and resource-rejection cases must still take the new
bounded route. Record descriptor, connection, token and reservation cleanup
after every failure. Resource limits come from installed WorkContext, never
new fixed constants. Also inject oversized installation-manifest and task-security JSON/index fields
at issuer construction, root admission, gated capture and reuse. Bound the
SQLite output before Python receives those fields. Inject journal growth after
the bounded provenance capture and before its authority validation; the repeat
capture must reject it. Patch ActionJournal.load/find_prepared and the legacy
_read_action_authority route to fail during cold success and rejection cases.
All revocation, installed issuer/policy, owner, lineage, baseline, target and
currentness negatives remain required; no security check may be skipped.

Use distinct installed WorkContext objects with different limits and existing
reservations. Construct a case where each source/action/security result fits
alone but retained first closure plus nested and second captures exceed the
common remaining allowance. Reject before that allocation. Include exact
aggregate-limit success, internal RS-AP double captures, physical-member reads,
parse/freeze/thaw/serialization copies and a handle projection carried into
reuse. Measure both byte and structural-unit peaks in the shared ledger and
local contexts. Transfer ownership before return, retain the first closure's
charge through comparison, and prove no gap or double release. Entry failure
and closed handles restore entry reservations; a live handle keeps exactly
its retained projection charge. Foreign/missing/reentrant ledger bindings
refuse, and port bindings are removed on every exit.

Cold records requiring unsupported extension/external
realization authority reject before evidence publication. Source schema validation uses installed closed
artifact schemas; cannot rely on fixture supplied expected digests. Full
original authoring-input/requirements reevaluation is outside this read proof;
test that it is never falsely obtained from the record's own fields.

Compatibility covers assessment1.0–1.4 schema validation, unchanged live source/
target completion fences and disposable behavior, current five installed
factories,18-member release loader and wheel. Existing RS-5 crash/rejection
matrix remains required. No mandatory/scenario/cumulative/performance run.
Independent design review precedes code, and independent source review plus
actual reducer binds final evidence; these documents alone are not a PASS.


## 2026-09-20 RS-AP provenance verification — R1

### 1. Scope and critical journeys

Spec RS-AP and Plan AP-H–AP-V govern this bounded slice. Every listed CUJ needs
passing evidence: P1 normal apply survives a new coordinator read; P2 completed
partial-deployment compensation validates original claim plus separate restore
journal/receipt; P3 genuine shared receipt CAS accepts an earlier committed
same-task reference; P4 corrupted/duplicate/unresolved/revoked provenance
rejects; P5 reads and failures preserve every logical repository table and
target/CAS bytes, leave no locks, and issue no executable authority.
Full assessment rehydration/RS-5 process proof, all non-normal coverage columns,
performance/cumulative work, network and production remain outside this slice.

### 2. Layers and traceability

Use existing WP08 unit/integration files plus Remaining54 authority/package
checks. Database/CAS joins need real integration fixtures; do not invent unit
tests mirroring SQL text or a pyramid count. Pure shape/digest/resource cases
may use lower-level helpers when useful. New cold-process E2E is deliberately
deferred to RS-5; existing retained-root exec/package tests are adjacent checks.
No percentage or full-suite claim substitutes for these five CUJs.

### 3. Strategies and negative matrix

Use real native SQLite, current security/journal/lease/object ports and local
release simulator, fresh fixture per corruption group. Mock only explicit
fault/race injection and forbidden issuance/write hooks. Test missing or altered
claim outcome digest, both journal digest index columns, equal-digest aliases,
foreign task/action/resource/fences, receipt digest/object bytes, missing or
foreign/future reference transactions, broken or duplicate event joins,
incomplete/substituted recovery attempt and mismatched restore receipt/
observation/postcondition. Re-sign bodies where appropriate so joins, not
only stale digests, must reject. Historical expiry must not demand renewal.

Inject a change between snapshots and an object/read failure; assert rejection,
no retry and released repository tokens/connections. Assert doctor query_only
and SELECT-only execution with writes/clock/renewal/issuance paths replaced by
rejecting hooks; compare all SQLite tables, references, CAS and target bytes
outside fixture setup/tampering. Exercise configured resource limits and deep
immutability. The previous authorization reader's negative cases remain valid.

For the bounded CAS reader, test (a) an oversized receipt with matching database
size, (b) oversized actual bytes with falsely small size metadata, (c) growth
after descriptor inspection, (d) aggregate receipt-byte overflow across unique
objects and (e) exact-limit success. Preflight oversize must read zero body bytes;
growth reads at most the admitted allowance plus one sentinel and retains no
more than the allowance. Measure read sizes/counts and aggregate retained bytes,
not just the final exception. Assert no repository/CAS writes and release of
all descriptors, connections and lock tokens on every failure. Exercise
no-follow/type/owner/mode/path/digest checks and patch existing unbounded CAS
helpers to fail if reached; independent implementation review must confirm
neither the new reader nor its event validation can reach them. Smaller limits
may target the private helper to avoid unrelated journal-parser limits.

### 4. Data and cleanup

Only private synthetic existing action/release fixtures, no user repository or
PII. Setup/corruption writes are outside read measurements. Close sessions,
retained handles and every fixture on failure; keep only authorized audit
records. No success mock may replace provenance or current authority validation.

### 5. Environments and budget

One native Python3.12 command at a time, explicit fresh private source-checkout
attestation via -X and matching locator, serial failfast and real parent
monotonic_ns;600second native cap, unchanged300second canonical evidence cap.
Record measured duration; no invented latency target. Run focused new cases,
then affected action/compensation/retained-root/authority/package regressions.
Broaden or repeat only for changed inputs, failure or a concrete concern.

### 6. Non-functional boundaries

Read-only integrity/currentness, resource bounds and compatibility are required.
Benchmark, monitoring, accessibility, deployment and full recovery issuance are
not part of this internal read boundary. No DB schema or role changes are tested
as permissible behavior; current permissions must remain effective.

### 7. Gate and completion

Independent AP-D review precedes code; AP-V requires passing CUJs, pin/Manifest/
historical-record checks and independent implementation review. The approved
single-path addition needs no repeat approval. Any further source/authority
expansion follows existing Policy. Full RS-4/RS-5 evidence remains separate.

### 8. References

[Spec](../specs/graph-engineering-workflow.md),
[Impact](../impact/graph-engineering-workflow.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[PRD](../prd/graph-engineering-workflow.md),
[Positioning](../positioning/graph-engineering-workflow.md).

## 2026-09-19 RS-BS prerequisite verification — R0

### 1. Scope and CUJs

References: Plan RS-BS, Spec RS-BS-1/2 and ADR-0009 RS-BS; original Positioning,
PRD and accepted Test Plan sections below remain unchanged. In scope: (B1)
same task survives local action and resumes domain transitions, (B2) existing
legacy action-only behavior, (S1) current security facts read with zero writes,
(S2) rejection of stale/foreign/malformed/revoked substitutions. Every CUJ must
have executable evidence before BS-R. No new coverage-percentage claim; existing
project baseline applies to final delivery, not this bounded prerequisite.

Out of scope for BS-R: retained-root/cold restart completion, all non-normal
columns, coverage issuance, cumulative/performance runs, production, network,
monitoring and irreversible actions. RS-5 retains its separate exec proof.

### 2. Pyramid and traceability

BS-S: at least four focused unit/read-contract tests for exact immutable shape,
runtime/binding validation, current revocation and zero-write reads. BS-T: at
least six pure bridge/mapping tests (positive split ordinals, malformed wrappers,
unknown/mixed kinds, wrong domain count, stale repository revision, legacy).
BS-I: two bounded real-repository integration journeys, one same-task simulator
producer and one legacy execution. Unit > integration > E2E; zero new E2E in
this prerequisite is a deliberate exemption, because the already-approved
RS-5 exec-based cold proof depends on later retained-root implementation.

### 3. Strategy per layer

Use native unittest, real repository/journal/lease/security ports and existing
local simulator. Pure mapping tests may construct exact data; they do not
substitute for producer proof. Mock only fault injection/observers that assert
the forbidden write/clock paths are never called; no mocked success at security
or action authority boundaries. Bound commands to 600 seconds, serial failfast,
fresh roots; record measured duration, not unsupported per-test speed claims.
Both domain command and internal runner write paths must be exercised after
action history. All eight action snapshot sites, including concrete/compensation,
must use the bridge; adjacent legacy apply/compensation tests preserve behavior.

For security: compare all relevant logical database tables before/after the
public read (including repository_meta clock row); patch trusted_now to fail
if called; assert doctor query_only/SQL authorizer rejects mutation. Missing
state, stale task revision, cross-task binding, malformed digest, nested
immutability and installed runtime substitution must reject. An explicit
fixture revocation between two reads must remove authority from the second
projection; old data remains non-authoritative and cannot enter mutation APIs.
Setup/tampering writes are outside the measured read interval.

### 4. Data

Synthetic existing fixtures, no user projects or PII. Same-task fixture creates
a real TaskApplication domain task, then independently attests its fixture
security/action authority in the same private repository before execution.
It never imports another task's action rows or strips action_state afterward.
Close every handle/lease/root even on failure; no retained artifacts outside
approved detached evidence containers.

### 5. Environments

Local serial native commands only. CI/staging/production are not invoked.
Installed-wheel/package compatibility is bounded and only rerun when source,
packaging or a concrete regression invalidates prior evidence.

### 6. Non-functional boundaries

Security/currentness/no-write and legacy compatibility are in scope. Explicit
negative races must fail closed rather than retry. Performance benchmarking,
accessibility, production monitoring and cold recovery are out of this slice;
the latter remains covered by the distinct RS-5 plan.

### 7. Open questions and gates

No new Human choice is required within the approved two designs/paths.
Independent design findings must resolve before implementation; newly required
unapproved source or authority stops only that affected work. No full restart
or Candidate completion claim until remaining RS-2–RS-5 evidence and review.

### 8. References

[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md),
[ADR](../adr/0009-offline-release-operations-simulator-authority.md),
[PRD](../prd/graph-engineering-workflow.md),
[Positioning](../positioning/graph-engineering-workflow.md).
This supplement follows the existing eight-section Test Plan; quantitative
timing, pyramid/E2E exemptions and bounded-vs-final-coverage claims are explicit.

## 2026-09-19 P3 restart design verification proposal — R1

This section defines future bounded acceptance, not test results. Current
design authority runs no product workload. The accepted foundation's 30 passing
tests are historical evidence at `ff7feda`, not proof of this proposed recovery.
P3-RS-A's Spec RS-1–RS-6 and ADR-0009 are the test basis. All scoped CUJs and
negative groups below are mandatory; no percentile sampling or waiver.

| CUJ / source | Setup and required observation | Layer / proposed existing test home |
|---|---|---|
| RS-CUJ-1 / RS-1, RS-2 | New retained root, durable identity in original target/action, completed committed assessment; close does not delete; fresh exec process recovers exact old bytes/digests with no inherited issuer | Integration `tests/integration/test_wp08_release_operations.py` |
| RS-CUJ-2 / RS-3 | Completed apply-B and separately completed partial-compensation-to-A histories; exact original claim, recovery attempt, actual restore journal/receipt and full health/state | Integration release file plus existing recovery-claim regressions |
| RS-CUJ-3 / RS-4 | Cold unique current CAS and six-part normal source reconstruction; task rev is assessment rev+1; every other column refuses before source-seal issuance | Integration release/category tests |
| RS-CUJ-4 / RS-5 | Use handle twice under fresh lease epoch; counter does not trust stored revision; source/target/artifact drift on second use refuses | Unit/integration release tests |
| RS-CUJ-5 / RS-2, RS-6 | Busy root, abrupt child exit, explicit close and owner destroy/abort, missing marker, interrupted cleanup and orphan | Integration/security Remaining54 tests |
| RS-CUJ-6 / RS-6 | Legacy disposable/v1 target rejects cold restore; assessment1.0–1.4 schemas and non-release/live completion fence semantics preserved | Existing contracts/unit/category integration/package tests |

The cold-process positive must use independent exec workers, not fork-inherited
Python objects or `CategoryExecutionApplication.restart()` on the old instance.
The test owner retains only the configured namespace/repository locations and
sanitized logical identifiers. Producer exits, then the consumer constructs
fresh installed/runtime/repository authorities and reads only existing state.
Observe process IDs and zero inherited live handles/issuer objects. OS tests use
fresh test-owned storage only, never the user repository as a mutation target.

Mandatory rejection matrix (each row verifies no returned authority, zero
recovery writes/replay/network and descriptor/lock release):

| Group | Exact attacks / crash cuts |
|---|---|
| Binding | Extra/missing/duplicate fields, wrong version, bool/float identity, wrong scope/task/fixture/target/resource/pins, caller-created/from_documents issuer, coherent re-sign against unchanged durable anchor |
| Filesystem | Namespace/root/member symlink, parent traversal, absolute/caller path, hard link, wrong owner/mode, copied root/new inode, nonce substitution, missing/extra/torn marker, residue, old identity scheme, descriptor/path swap before or during reads |
| Durable source | Missing/duplicate/stale/unreferenced/replaced CAS, wrong GraphRef/epoch/revision/request/profile, changed source/review/artifact/target contract, copied source seal; never reissue from assessment facts alone |
| Action chain | Missing/foreign/stale/revoked prepared/authority/receipt/claim; wrong resource/fence; unresolved/unknown action; mismatched original-vs-compensation ID; absent/duplicate/incomplete recovery attempt; restore receipt substitution |
| Target/health | Missing or changed installed/artifact/manifest bytes, RECORD/source/build/policy drift, generation rollback, staged/active mismatch, partial cleanup, wrong health predicate/outcome; metadata-only state equality is insufficient |
| Currentness race | Change each bound source after first read; inject at final generic observer callback and before read-only handle publication; repeat-use drift; preserve the existing after-callback completion binding regression |
| Crash/lifetime | Before binding fsync, after binding before prepare, each existing five apply cuts, after action terminal before assessment CAS ref, after CAS ref, during owner binding removal/cleanup, competing live writer/reopener, process exit while holding lease |
| Capability | Copy/clone/serialize/foreign/closed handle, use read-only evidence for issue/commit/mutation, attempt apply/restore/reconcile/lease renewal, process-local result falsely presented as cold recovery |

Crash expectations are precise: only a completed assessment whose entire
durable closure and retained target are current can recover. Cuts before its
unique committed reference never create a PASS; executing/unknown/partial
state is reported blocked with owner route and is not repaired. A crash after
committed reference can succeed if all terminal bytes are durable; a torn or
mixed state must reject. A completed compensated case proves recovery of the
recorded restored-A result, not automatic compensation during restart.

Capture counters before and after the recovery phase: apply=0, restore=0,
coordinator execution/reconciliation/claim-renewal=0, task/event/snapshot/CAS/
reference/action/claim/receipt/target-content writes=0, DNS/socket/proxy=0.
Setup work and deliberately injected tampering are counted separately.
Compare durable object/ref/table and target tree digests with their before
values, excluding OS access times and ephemeral lock state. Do not claim a
recovery receipt if a worker times out or cleanup fails.

After implementation authority: RED first, native selector commands individually
bounded to 600 seconds, serial fresh fixtures, stop on first failure, no automatic
whole-run retry. Layer order is binding/schema units -> retained root/readonly
action integrations -> cold-CAS/source/race matrix -> affected authority/contracts
-> package/installed-wheel and adjacent bounded ActionCoordinator regressions.
Re-run only changed-input dependents or actual failures. No cumulative,
performance, mandatory/scenario issuance or monitoring. Existing foundation
selectors may be reused only where unchanged-input evidence remains valid.

Exit evidence must bind actual commands, interpreter, elapsed time, counts,
zero-delta counters, independent review, source closure and real reducer result.
Scope remains plan244/oracle122/30 missing; design or cold-recovery success
cannot be substituted for dynamic274/137 acceptance or whole-project static
PASS. Resource acceptance uses exact lifecycle/counter return and at most one
open root, not a machine-specific RSS threshold. Unsupported OS primitives are
an explicit fail-closed result and cannot silently skip a required positive.

### R1 review-closure cases (planned, not executed)

For `GEW-REMAINING54-P3-RESTART-DESIGN-R0-001`, instrument each acquire/release
in create -> apply/compensate -> assessment commit -> quiesce -> cold open ->
reuse -> close/destroy. Command control token is distinct from repository tokens.
Assert no outer repository token around public readers, no second acquisition
of the same root lease, unchanged installation/object/resource rank order,
and no root acquisition under any repository lock. Both same-process threads
and separate exec processes compete with a LIVE writer and an open reader:
loser gets bounded busy-root denial, winner completes; all failures/early exits
restore descriptor/lock counters, with no storage edits or write side effects.

For `GEW-REMAINING54-P3-RESTART-DESIGN-R0-003`, ordinary apply-B and completed
compensation-A positives both use the normal column. Before the consumer's FIRST
read, independently change: final review author/reviewer/node/body/prior body;
required output trust/verdict/closure; artifact contract/body/status/independence/
reference closure; target/profile/resource/expected state; owner authority refs,
open findings or unresolved claims. Retain the same assessment reference and
use coherent local record digests where applicable. Every attack must reject
before new read-only source seal, even if before/after reads are identical.
No unchanged source seal, generic normal-output digest or old issuer may stand
in for the six-part validation. All eleven unsupported columns reject explicitly.

For `GEW-REMAINING54-P3-RESTART-DESIGN-R0-002`, after future implementation:

| Pin consumer | Bounded selector / test change (no workload execution) |
|---|---|
| Release schema/loader/bootstrap | Existing tests.unit.test_wp08_release_operations and Remaining54P3FoundationContractsTest; update exact member assertion to 18, retain missing/extra/equal-cardinality substitution attacks |
| Performance/migration/scenario/dependency current bootstraps | Add a named factory-only provenance regression to existing tests/contract/test_wp08_remaining54_contracts.py: load all five current installed closures, substitute each stale source/schema/bootstrap pin independently and reject; do not issue benchmark/migration/scenario execution |
| Shared category/scenario compatibility | Existing test_non_release_completion_preserves_existing_fence_behavior plus bounded installed scenario-currentness tests; no P/R cumulative helper |
| Dual action-runtime branch, if changed | Existing ScenarioTruthSecurityTests.test_action_provenance_has_two_current_non_interchangeable_runtime_branches and test_runtime_topology_attacks_fail_against_installed_current_pins; WP07A focused action contracts retain substitution negatives |
| Source/wheel/RECORD | Existing GateManifestContractTests.test_source_manifest_is_exact_and_detects_mutation and InstalledWheelTests.test_wheel_runs_inside_decoy_project_without_source_imports; packaging closure tests and new exact pair membership assertion |

Every selector is subject to the same native 600-second bound, serial fresh
fixtures and first-failure stop. Loader checks are source/package validation,
not performance measurements or full-run acceptance. Any test name added later
must be recorded exactly in implementation evidence before it is executed.


## 2026-09-18 P3 foundation evidence-path amendment

Human approval `明确批准这五个路径` authorizes
`GEW-REMAINING54-P3-FOUNDATION-RECORDS-WP07A-V1`: the Envelope grows
from 174 to 179 exact targets, adding only
`tests/contract/test_wp07a_action_contracts.py` and the four
`p3-foundation-{source-manifest,state,review-verdict,decision}-r2.json`
records under `.workflow/delivery/GEW-REMAINING54-V1/`. Correct only the
WP07A exact adapter-kind expectation and preserve its substitution tests;
align the existing authority-membership regression with the five-path delta.
Persist bounded verification and independent review using the new paths.
Historical r1 records remain unchanged. The prior exact174 and pending-r2
statements below describe the 2026-09-17 boundary; all other foundation
constraints, including 244 bindings / 122 oracles / 30 missing, still apply.

## 2026-09-10 approved memory-repair regression supplement

The exact174 amendment `GEW-REMAINING54-LOSSLESS-TRACE-MEMORY-REPAIR`
governs this repair; prior revision history below is unchanged. Before coding,
add regressions in the already authorized WP-08 unit test file for: repeated
events stored without per-event dictionaries; complete decoded trace equivalence
including every run boundary/count/multiplier/path, rejection, zero-count no-op
and external balance change; retained live-list references, mutation, assignment,
JSON and frozen serialization; and action-document helpers using fresh contexts
by default while retaining explicit caller-owned audit/budget behavior.

Run existing WP-01 charge/resource/schema/digest/versioning and WP-02 contract
and cross-implementation tests to compare logical trace bytes and budget cutoffs.
Run bounded scenario-truth unit, authority, action and lifecycle regressions;
exclude cumulative selectors. Reproduce document/schema memory measurements in
isolated processes, measuring unread compact storage before materialization and
release after dropping the context. Distinguish diagnostic byte measurements from
acceptance evidence: no invented full-run receipt, performance PASS or Candidate
closure. Independent reviewer validates the exact source manifest and findings;
the deterministic reducer alone decides the next authorized reversible node.

Repair verification record (2026-09-10, not cumulative evidence): new regressions
first failed on old code (3 failed / 2 passed), then the final WP-08 unit/authority
plus WP-01 charge/resource selection passed 63 tests / 130 subtests on Python
3.11.14. Broader WP-01/02 contracts and independent Node conformance, WP-02 units,
WP-05 action/recovery/security and bounded parsing passed 208 tests / 899 subtests
in 154.44 seconds. Python 3.12.12 passed the final seven memory regressions plus
WP-01 charge/resource tests (16 tests), and the initial five memory regressions
plus four lifecycle regressions (9 tests, 303.220 seconds). Source architecture
scan and diff whitespace checks passed. Command details and remaining focused
verification belong in the r2 source manifest, followed by independent review.

Isolated diagnostics: three discarded compensation documents previously retained
12,719,384 traced bytes / 19,134 events in the global fixture context; after the
repair the same probe retained 23,852 bytes with zero global events. Combined
security/action schema loading previously retained 55,292,697 bytes for 83,158
events; now it retains 1,900,496 bytes in 12,845 runs, decodes all 83,158 events,
and retains 38,760 bytes after dropping the context and collecting garbage.
These are local tracemalloc observations, not a universal memory ceiling. Full
decode intentionally still costs O(events) memory. No full-run result is claimed.

## 2026-09-17 P3 foundation bounded test supplement

`GEW-REMAINING54-P3-FOUNDATION-BOUNDED-V1` keeps the current exact174 target
boundary unchanged; exact168 references below are historical. Before
implementation, RED must prove the absence of the eight schema pairs, installed
policy/fixture/bootstrap, local simulator/observer, ActionCoordinator release
path and assessment 1.4 branch. GREEN verification is strict serial with fresh
private roots and each native command bounded to 600 seconds. It must cover
exact schema/config/currentness closure, path and symlink rejection, generation
CAS, the five ADR-0009 fault cuts, zero-network observation, no mutation on
foreign/stale authority, no automatic apply/restore replay, package/RECORD
closure and release-only single-projection assessment 1.4. Plan/oracle remains
244/122 with all 30 release IDs missing. Do not run mandatory/scenario coverage,
cumulative/performance selectors, monitoring, network, WP-10 or irreversible
actions. Historical F2 `p3-foundation-*-r1.json` records remain untouched; new
append-only review paths require separate Human authority.

The fault matrix additionally requires the staged-B/active-A cuts to issue a
typed manual deployment observation bound to the original receipt, retain the
unresolved claim, prepare one rollback authority, and use `compensate_unknown`
once. The final observer must equal the original A precondition byte-for-byte,
the claim must be reconciled, and apply invocation count must not increase.
Final release evidence and assessment schemas must resolve exact artifact,
deployment and health references and reject extra or structurally incomplete
nested bodies.

The security-negative closure also requires: the target gate exposes no arming
method or issuer and direct invocation leaves mutation/claim/journal unchanged;
unknown fixture artifact IDs cannot acquire provenance; object-constructed or
foreign ActionOutcome values cannot issue deployment observations; unhealthy
partial state without rollback cannot issue final evidence; a healthy restored
partial path requires its typed compensation observation; coherently re-signed
nested extra/type changes fail exact output schemas; and a destroyed or absent
simulator target makes restart fail closed. Independently compare pyproject
distribution name/version with both project metadata and bootstrap package pins.
Direct-constructor registry injection, coherent fixture/bootstrap replacement,
permissive schema replacement and non-installation oracle injection must each
produce zero issuance and zero target mutation; only `from_installation()` may
grant the opaque production-issuance seal.

## 1. 文档控制

| 项目 | 内容 |
|---|---|
| 版本 | v1，implementation-alignment revision 43 |
| 状态 | Historical reviews preserved；remaining54 F1 routine source/observation traceability R1 candidate |
| 日期 | 2026-09-06 |
| Author | Codex `/root` |
| Plan | current governing `docs/plans/2026-08-13-graph-engineering-workflow.md` implementation-alignment revision 35 |
| Intent Baseline | PRD v2 `594b4437301853919ce3b4aa93e703a395ed45bff924ea6266b3a8e202a30be7` |
| Spec | current governing v1 implementation-alignment revision 36 |
| Impact | current governing implementation-alignment revision 30 |
| Accepted ADRs | 0001～0006 historical；current remaining54 suite为0007 revision 13、0008 revision 12、0009 revision 12 |
| Review lineage | Historical Test Plan reviews preserved；revision 32 historically froze P1/P2/P3；revision 33 historically added `pyproject.toml`/R2 links；revision 34 historically tested R3 exact159/noise authority；revision 35 historically tested Human-approved `GEW-REMAINING54-ORACLE-REJECTION-INPUT-A` exact164 typed rejection input；revision 36 historically closed `GEW-REMAINING54-ORACLE-CASCADE-A-R1-001`；revision 37 historically tested Human-approved `GEW-REMAINING54-ACTION-PROVENANCE-B` exact165 directed action provenance/currentness closure；revision 38 historically tested Human-approved `GEW-REMAINING54-ACTION-RUNTIME-C` exact166 dual-runtime closure and closed `GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001`；revision 39 historically tested Human-approved `GEW-REMAINING54-WP07A-BUILD-BASELINE-D` exact167 test-only repair authority；revision 40 historically tested initial Human-approved `GEW-REMAINING54-PROCESS-LOCAL-QUIESCENT-REOPEN-E1` lifecycle authority；revision 41 historically addressed `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001` pending independent review；revision 42 is the independently accepted Human-approved `GEW-REMAINING54-F1-DEPENDENCY-SECURITY-REHYDRATE` exact168 one-target authority；current revision 43 tests routine `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001` and `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002` corrections with no authority/API/schema/target change |
| Authority task | `GEW-PLAN-V1` |
| 当前授权 | `GEW-REMAINING54-V1` 仅授权本仓库本地/离线测试、实现证据与审核；不授权真实deploy/release、network、WP-10、commit/push/merge/外部通信 |

## 2. 质量目标

v1 测试的核心不是证明“代码跑过”，而是证明：

1. 同一合法输入在支持环境中得到 byte-identical contract、state、route 和 decision；
2. crash、并发、恢复或未知副作用不会制造 partial truth、重复动作或虚假完成；
3. authority、intent、target、digest、evidence、privacy 任一不匹配都在副作用前 fail closed；
4. Codex/Hermes Skills 只改变交互适配，不改变确定性安全语义；
5. 九类任务的完整承诺逐类成立，不能用框架表达力或其他类别代替；
6. 成功指标/PMF 数据可用且最小化，不泄露源码、prompt 或秘密。

## 3. 范围

### 3.1 In scope

- contract/schema/digest/GEEL/ResourceProfile；
- graph/reducer/routing/join/fallback/invalidation/completion；
- SQLite repository、objects、locks、leases/claims、backup/migration；
- authority/action/reconciliation/privacy/evidence；
- lifecycle、runtime adapters、Codex/Hermes Skills；
- 九类 Profiles、full/compact/emergency overlays；
- packaging/install/upgrade/rollback/supply chain；
- Candidate/ReleaseCoverage/PMF evidence。

### 3.2 Out of scope

- 多用户协作、跨 runtime 续接、daemon/background execution、远程状态服务；
- Windows、任意 VCS、任意业务工作流；
- 未通过 extension trust ADR 的第三方 executable predicates/validators/transforms；
- 已取得同进程任意产品代码执行能力后的 module/class/metaclass mutation；这是 TCB compromise，
  由 source/build/install attestation、dependency policy 与进程 sandbox 验证，不伪装成 domain
  contract immutability case；
- 未声明厂商集成的“兼容猜测”。

Out-of-scope 能力若被请求，必须明确拒绝；不能静默降级成未测试路径。

## 4. 测试方法与层次

| 层 | 位置 | 主要目的 | 默认外部访问 |
|---|---|---|---|
| Unit/model/property | `tests/unit/` | pure contract、reducer、policy、state table | 禁止 |
| Contract/golden | `tests/contract/` | schema、JCS、GEEL、adapter wire parity | 禁止 |
| Repository conformance | `tests/conformance/` | backend/lock/crash/migration semantics | 仅隔离 temp root |
| Integration | `tests/integration/` | application + repository + fake adapters | 禁止 |
| Security/privacy | `tests/security/` | identity、path、digest、secret、disclosure、extension | 禁止 |
| E2E fixtures | `tests/e2e/` | installed wheel/CLI/Skill + disposable projects | 默认禁止网络 |
| Real runtime/target | action-scoped evidence run | Codex/Hermes/Telegram/Discord/真实工具链 | 必须单独授权 |

测试先于对应实现加入：失败用例先证明门禁缺失，再实现直至 PASS。测试自身不能复刻被测
算法作为 oracle；优先使用冻结 vectors、independent implementation、model/state table、真实
target query 和 fault injection。

## 5. 环境矩阵

### 5.1 Release-blocking environments

| 维度 | 必须覆盖 |
|---|---|
| OS | 当前支持的 macOS latest-1/latest；Linux 两个声明发行版版本 |
| Architecture | 发布声明中的 macOS arm64/x86_64 与 Linux x86_64；无制品即不声明支持 |
| Python | 每个支持 minor 的最低与最新 patch；exact managed interpreter |
| SQLite/VFS | 随 release 绑定/验证的 exact runtime；macOS fullfsync、Linux durability conformance |
| Install | clean user、upgrade from previous supported candidate、tampered/incompatible inputs |
| Runtime | Codex；Hermes via Telegram；Hermes via Discord |
| Risk path | `full-planned`、`compact-planned`、`emergency` |
| Profile | 九类全部 |

具体版本值由 release configuration/manifest 提供，不写入 engine code或本计划。matrix expansion
可以增加测试；缩小已冻结 release claim 需要新的产品/发布决定。

### 5.2 Isolation

- 每 case 使用新 temp data/control/project roots、独立 HOME-like test config 和 fake secrets；
- 禁止读取用户真实仓库、真实消息历史、系统凭据或旧项目；
- 时间、random、PID、crash point、disk-full、connector result 通过受控 harness 注入；
- 真实 runtime/target case 使用一次性 fixture account/resource 和独立 action authority；
- case 完成后先验证 evidence，再清理；unknown action/failed cleanup 保留 quarantine record。

## 6. Test ID 与证据规则

所有 concrete test ID 必须匹配 `^GEW-[A-Z0-9]+(?:-[A-Z0-9]+)*$`；numeric family（例如
`GEW-CON-001`）和 semantic/cell ID（例如 `GEW-REQ-FR01-P`）都合法。文中的 `<...>` 只表示
生成模板，不是可登记 ID；generator 将 canonical kebab ID 转成 uppercase kebab 后必须通过
同一 regex。stable ID 语义不可复用。每次结果至少记录：

- test ID/version、requirements、profile/overlay/runtime/environment manifest；
- source/build/install artifact digests、Graph/Profile/schema/registry/config digests；
- isolated target identity、authority/action digest（如适用）；
- start/end、result、machine-readable assertion/receipt/target-state evidence digest；
- retry/failure injection seed、redaction/classification、reviewer lineage。

只接受当前 baseline/snapshot/build 的 fresh evidence。rerun 产生新 evidence record，不覆盖失败；
flaky test 是 blocker，不能以“重跑通过”抹除。

### 6.1 机械追踪矩阵

实现前创建并 schema-lock `config/release-coverage/trace-matrix-v1.json`；本节就是它的 normative
source。每一 row 必含 `obligation_id`、一个正向 `pass_test_id`、一个拒绝/失败
`reject_test_id`、`fixture_id`、`oracle_id`、`evidence_type`、`owner_gate`，禁止空值、range、
placeholder、duplicate test ID 或同义 obligation。coverage validator 对下列 frozen sets 做 exact
set equality；删除任何 row/cell、增加 unknown row、把 P/R 指向同一 case 或没有 evidence 都 FAIL。

#### Requirement rows

| Obligations | Exact P/R test IDs | Fixture | Oracle ID | Evidence | Owner gate |
|---|---|---|---|---|---|
| FR-01 | `GEW-REQ-FR01-P` / `GEW-REQ-FR01-R` | skill-lifecycle | `ORA-ADAPTER-CONTRACT` | runtime transcript/receipt | WP-07 |
| FR-02 | `GEW-REQ-FR02-P` / `GEW-REQ-FR02-R` | runtime-owner-binding | `ORA-STATE-MODEL` | event/rejection | WP-07 |
| FR-03 | `GEW-REQ-FR03-P` / `GEW-REQ-FR03-R` | durable-replay | `ORA-REPOSITORY-MODEL` | head/snapshot | WP-03 |
| FR-04 | `GEW-REQ-FR04-P` / `GEW-REQ-FR04-R` | typed-graph | `ORA-GRAPH-MODEL` | trace/error | WP-02 |
| FR-05 | `GEW-REQ-FR05-P` / `GEW-REQ-FR05-R` | review-loop | `ORA-CONVERGENCE-MODEL` | finding trace | WP-04 |
| FR-06 | `GEW-REQ-FR06-P` / `GEW-REQ-FR06-R` | intent-drift | `ORA-DEPENDENCY-MODEL` | invalidation trace | WP-02 |
| FR-07 | `GEW-REQ-FR07-P` / `GEW-REQ-FR07-R` | authority-mutations | `ORA-EXECUTE-GATE-MODEL` | zero-call/rejection | WP-05 |
| FR-08 | `GEW-REQ-FR08-P` / `GEW-REQ-FR08-R` | crash-resume | `ORA-PERSISTENCE-FAULT-MODEL` | replay/claim | WP-05 |
| FR-09 | `GEW-REQ-FR09-P` / `GEW-REQ-FR09-R` | ten-artifacts | `ORA-ARTIFACT-CONTRACT` | artifact records | WP-04A |
| FR-10 | `GEW-REQ-FR10-P` / `GEW-REQ-FR10-R` | false-completion | `ORA-COMPLETION-MODEL` | completion record | WP-04 |
| FR-11 | `GEW-REQ-FR11-P` / `GEW-REQ-FR11-R` | privacy-evidence | `ORA-PRIVACY-TAINT` | redacted evidence | WP-05A |
| FR-12 | `GEW-REQ-FR12-P` / `GEW-REQ-FR12-R` | config-swap | `ORA-ARCHITECTURE-SCAN` | scan/config digest | WP-01 |
| FR-13 | `GEW-REQ-FR13-P` / `GEW-REQ-FR13-R` | pmf-counterexample | `ORA-PMF-SCHEMA` | PMF report | WP-09 |
| FR-14 | `GEW-REQ-FR14-P` / `GEW-REQ-FR14-R` | profile-matrix | `ORA-COVERAGE-SET` | coverage record | WP-08 |
| FR-15 | `GEW-REQ-FR15-P` / `GEW-REQ-FR15-R` | lifecycle-conflict | `ORA-LIFECYCLE-MODEL` | catalog/lease | WP-06 |
| FR-16 | `GEW-REQ-FR16-P` / `GEW-REQ-FR16-R` | install-upgrade | `ORA-RELEASE-MANIFEST` | install/migration | WP-10 |
| FR-17 | `GEW-REQ-FR17-P` / `GEW-REQ-FR17-R` | concrete-action | `ORA-AUTHORITATIVE-TARGET` | receipt/state | WP-07A |
| FR-18 | `GEW-REQ-FR18-P` / `GEW-REQ-FR18-R` | trusted-extension | `ORA-EXTENSION-POLICY` | load/rejection | WP-08A |
| NFR-01 | `GEW-REQ-NFR01-P` / `GEW-REQ-NFR01-R` | clean-skill-use | `ORA-PROCESS-INSTALL` | UX/process record | WP-10 |
| NFR-02 | `GEW-REQ-NFR02-P` / `GEW-REQ-NFR02-R` | fail-closed | `ORA-INVARIANT-MODEL` | blocked/completion | WP-04 |
| NFR-03 | `GEW-REQ-NFR03-P` / `GEW-REQ-NFR03-R` | resume-unknown | `ORA-PERSISTENCE-FAULT-MODEL` | replay/claim | WP-05 |
| NFR-04 | `GEW-REQ-NFR04-P` / `GEW-REQ-NFR04-R` | adapter-substitution | `ORA-DEPENDENCY-SCAN` | import/contract | WP-07 |
| NFR-05 | `GEW-REQ-NFR05-P` / `GEW-REQ-NFR05-R` | environment-swap | `ORA-DATA-LOGIC-SCAN` | scan report | WP-00 |
| NFR-06 | `GEW-REQ-NFR06-P` / `GEW-REQ-NFR06-R` | disclosure-secret | `ORA-PRIVACY-TAINT` | leak scan | WP-05A |
| NFR-07 | `GEW-REQ-NFR07-P` / `GEW-REQ-NFR07-R` | audit-replay | `ORA-INDEPENDENT-REDUCER` | trace digest | WP-11 |
| NFR-08 | `GEW-REQ-NFR08-P` / `GEW-REQ-NFR08-R` | compatibility | `ORA-COMPATIBILITY-MATRIX` | compatibility record | WP-10 |

#### Work-package exit rows

exact obligation/test pairs为：`WP-00,01,02,03,04A,04,05A,05,06,07,07A,08A,08,09,10,11`；
每个 X 必须存在 `obligation_id="WP-X-EXIT"`、`GEW-WP-X-EXIT-P` 与
`GEW-WP-X-EXIT-R`。fixture 是该 WP §Plan exit fixture manifest；oracle 是对应 contract/state/
target/independent-review gate；evidence 是 `WorkPackageExitRecord`；owner gate 即 WP-X。validator
按上面 explicit 16-item set 展开，不接受数字 range 或漏掉带字母的 WP。

#### ADR validation rows

| Obligation IDs | Exact test IDs (`-P`/`-R`) | Fixture/oracle | Evidence | Owner |
|---|---|---|---|---|
| `ADR1-NAMESPACE`, `ADR1-INSTALL`, `ADR1-SUPPLY`, `ADR1-SKILL`, `ADR1-UPGRADE` | `GEW-ADR1-NAMESPACE-P/R`, `GEW-ADR1-INSTALL-P/R`, `GEW-ADR1-SUPPLY-P/R`, `GEW-ADR1-SKILL-P/R`, `GEW-ADR1-UPGRADE-P/R` | decoy/import, clean install, tamper, handshake, failure injection / Accepted ADR | build/install evidence | WP-00/10 |
| `ADR2-CONNECTION`, `ADR2-TRANSACTION`, `ADR2-LOCK`, `ADR2-OBJECT`, `ADR2-EXPORT`, `ADR2-MIGRATION` | `GEW-ADR2-CONNECTION-P/R`, `GEW-ADR2-TRANSACTION-P/R`, `GEW-ADR2-LOCK-P/R`, `GEW-ADR2-OBJECT-P/R`, `GEW-ADR2-EXPORT-P/R`, `GEW-ADR2-MIGRATION-P/R` | repository/fault fixtures / conformance model | crash/state evidence | WP-03/06 |
| `ADR3-SCHEMA`, `ADR3-REF`, `ADR3-JCS`, `ADR3-DIGEST`, `ADR3-MODEL`, `ADR3-GEEL`, `ADR3-BUDGET`, `ADR3-EXEC`, `ADR3-VERSION` | exact `GEW-ADR3-<suffix>-P/R` for each listed suffix | golden/cross-implementation corpus / ADR algorithms | bytes/result/trace | WP-01 |

#### Cross-product rows

- canonical Profile ID set 不由 Test Plan 自行声明，而从绑定 Tech Spec digest
  `e632cd2c8b4f13b1455fa1f962491df6603b34d2eef0c46a84b350200e0f8d65` 的 immutable
  `ApprovedProfileIdentityRegistry` 加载并要求 exact 为 `new-feature,bug-fix,hotfix,refactor-debt,
  migration,dependency-security,performance,release-operations,incident-response`。matrix、fixture、
  OracleManifest、evidence 与 registry 做双向 exact equality；不接受任何别名。column set exact 为
  `normal,boundary,revise,authority,drift,invalidation,recovery,artifacts,review,target,rollback,
  real-e2e`。每个 Cartesian cell 必须有两个 distinct IDs：
  `GEW-PRO-<PROFILE>-<COLUMN>-P` 与 `GEW-PRO-<PROFILE>-<COLUMN>-R`，共 216 个 concrete tests；
  fixture 为对应 versioned Profile fixture，oracle 是 category completion/rollback/target contract，
  evidence owner WP-08。validator 对两个 explicit sets 的 product × `{P,R}` 做 exact equality；
- runtime/path exact cells：`GEW-RTP-CODEX-FULL-PLANNED`, `GEW-RTP-CODEX-COMPACT-PLANNED`,
  `GEW-RTP-CODEX-EMERGENCY`, `GEW-RTP-HERMES-FULL-PLANNED`,
  `GEW-RTP-HERMES-COMPACT-PLANNED`, `GEW-RTP-HERMES-EMERGENCY`；channel exact cells：
  `GEW-CH-HERMES-TELEGRAM-CONTRACT`、
  `GEW-CH-HERMES-DISCORD-CONTRACT`。每 cell另有同 ID `-REJECT` case；fixture 是 disposable
  runtime/channel identity，oracle 是 RuntimeAdapter/channel contract，evidence owner WP-07；
- release environment dimension exact set 为 `OS,ARCH,PYTHON,SQLITE-VFS,INSTALL`；对
  ReleaseInstallManifest 中每个 `(dimension, canonical value)` 计算
  `value_key = uppercase(first 16 hex SHA-256(UTF-8(dimension + U+0000 + value)))`，concrete IDs 为
  `GEW-ENV-<DIMENSION>-<VALUEKEY>-P` 与 `...-R`。因此同 dimension 多 values 不复用 ID；row 还
  保存 exact canonical value。fixture 是 clean image/VM，oracle 是 manifest/capability check，
  evidence owner WP-10。manifest claim 与 matrix values 必须双向 exact equality。

coverage validator 的 meta-suite `GEW-COV-001` 从完整 matrix PASS；`GEW-COV-002` 对上述每个
obligation/cell逐一删除；`GEW-COV-003` 删除 P 或 R；`GEW-COV-004` 替换 fixture/oracle/evidence/
owner 为空；`GEW-COV-005` 注入 duplicate/placeholder/range/unknown。所有 mutation 必须 FAIL。

### 6.2 OracleManifest 与独立性

`config/test-oracles/oracle-manifest-v1.json` 是 versioned、schema/JCS-digested closed registry；
trace matrix 的 `oracle_id` 必须 exact resolve，不能自由填写 class label。每项包含：

- stable `oracle_id`、version、family、`kind`（`frozen-vector|independent-model|independent-
  implementation|authoritative-target-observer|architecture-scan`）；
- authoritative source/standard/Accepted ADR ref 与 digest；oracle artifact/module digest；
- dependency allowlist、prohibited production import prefixes、build/runtime process boundary；
- independence method、known-fault corpus、input/output schema、evidence type；
- target observer 时的 read-only capability、credential/identity、observed raw fields、freshness、
  separate implementation/process 和与 mutation adapter 不同的 package/module digest。

生成 rows 的 oracle IDs 也完全冻结：WP exits 用 `ORA-WP-<WP>-EXIT`；ADR rows 用
`ORA-ADR<NUMBER>-<OBLIGATION>`；Profile mandatory/category scenarios 用
`ORA-PROFILE-<PROFILE>`；runtime/path/channel 用 `ORA-RUNTIME-<RUNTIME>` 或
`ORA-CHANNEL-<CHANNEL>`；environment 用 `ORA-ENV-<DIMENSION>`；ArtifactContract 用
`ORA-ARTIFACT-CONTRACT`；Execute Gate 用 `ORA-EXECUTE-GATE-MODEL`。每个生成 ID 都必须在
OracleManifest 中存在恰好一项。

独立性规则：

1. reducer、route、invalidation、completion、authority、coverage 等 deterministic decisions
   使用 frozen state table/vector 或独立 model/implementation；oracle dependency graph 禁止导入
   `graph_engineering.core/application/storage/adapters` 对应被测 decision modules，也不能调用产品
   CLI 得到 expected value；
2. schema/JCS/GEEL 使用标准 vectors + 至少一个独立 implementation；oracle artifact digest 不得
   等于生产 implementation digest；共享第三方 library 时仍必须有 frozen expected bytes/errors；
3. repository/fault oracle 是 ADR old/new/blocked transition model，不读 production reducer 结果；
4. real action/Profile E2E 的 mutation receipt 只证明“调用发生”，不能证明 target 达标。另一个
   read-only observer process 通过目标系统权威接口/原始 Git object/fixture health endpoint 读取
   raw state，用 frozen acceptance model判断；不能 import/delegate 到 mutation/target-query adapter，
   不能共享其 implementation digest或只消费其缓存 receipt；
5. target observer 若无法独立授权、fresh query 或验证 identity，case 为 blocked，不以 adapter
   self-report PASS。

meta-tests：`GEW-ORA-001` closed registry完整 PASS；`GEW-ORA-002` 注入 production decision import；
`GEW-ORA-003` 令 oracle/production digest 相同；`GEW-ORA-004` 删除 independence/source digest；
`GEW-ORA-005` 让 target observer 复用 mutation adapter/receipt；`GEW-ORA-006` 用 known-faulty
production variants（wrong reducer route、false completion、stale target query）确认 oracle 必须
逐个检出，同时 golden valid cases PASS。architecture/coverage build 对任一失败均阻止实现 gate。

## 7. Contract 与确定性测试

| ID 范围 | 测试集 | 必须断言 |
|---|---|---|
| GEW-CON-001～020 | strict JSON/I-JSON | duplicate/escape/surrogate/number/UTF-8 边界一致拒绝；无 normalization |
| GEW-CON-021～050 | Schema Profile | allowed/forbidden vocabulary、keyword、format、bounds；两个实现 accept/reject 一致 |
| GEW-CON-051～070 | Closed registry | exact IDs/digests、refs/pointers/cycle/remote lookup；证明零 network/filesystem retrieval |
| GEW-CON-071～100 | JCS/formats | RFC vectors、UTF-16 key order、safe int、decimal/time/duration/id、opaque-ref aliases |
| GEW-CON-101～130 | Digest projection | identity/self-digest candidate/source/body/envelope/preimage；错误 omission/null/placeholder 拒绝 |
| GEW-CON-131～170 | GEEL | 每 operator/type/path/missing/null/empty/multi-error/eager/order truth table |
| GEW-CON-171～210 | Budget/cost | exact charge trace、temp peak、limit/budget precedence；每 emitted event 前后 boundary |
| GEW-CON-211～230 | Immutable model | nested alias/mutation、bool-int、round-trip、iteration/order independence |
| GEW-CON-231～250 | Version/migration | exact pins、directional compatibility、唯一 transform path 与 byte-identical provenance |

`GEW-ADR3-SCHEMA-FROZEN-R` 必须对同一 schema 的 raw JSON-list 与 registry-frozen tuple 逐 case
比较 normalized validation failures、完整 canonical charge trace 与余额；覆盖 `required`、至少一个
combinator、`prefixItems`、`dependentRequired` 的 valid、invalid 与 missing 输入。只断言 event ID
存在或只比较 accept/reject 不足以关闭该回归。

Release blocker：任一 cross-implementation bytes/result/error/trace divergence。

## 8. Graph Kernel 与 Application 测试

### 8.1 Graph validation

`GEW-GRA-001～060` 覆盖：

- node/edge unique identity、typed input/output、required trust、route、join、fallback；
- Graph source/digest-input schema structural diff 只允许移除 derived `digest`，source/input
  schema、projection/domain/registry pin 任一 swap 必须拒绝；
- Graph create/load trace 必须出现 schema/canonical/digest charges，exact budget 成功、少 1
  budget 在对应 occurrence 原子拒绝，hard limit 优先；
- Graph create/load 与 Snapshot create/restore 的完整 charge trace 必须逐 record 锁定
  `event_ordinal + operation_path + amount/balance/status`；独立 Node 从同一 frozen semantic inputs、
  schema 与 CostSchedule 自行生成四条 trace，再与 Python canonical bytes/record exact 比较，不能
  只 hash Python 输出；Node executable/version/binary digest 与 oracle source digest 必须进入
  command/exit evidence，任一 runtime、oracle、顶层 schema event 或 child-call ordinal 漂移都失败；
- 每条 frozen trace 的每一个 emitted occurrence 都用 `amount - 1` 初始余额重放，必须产生该
  event/path 的 atomic `rejected` attempt，不能执行后续工作；
- unreachable/dead-end/cycle、无 budget loop、ambiguous route/join、missing completion predicate；
- typed mapping 只接受 resolved source/target schema fragment canonical-identical 的 single-type
  exact assignability；shared `$ref` 正向通过，disjoint const/enum/range、required object members、
  array items、带 sibling assertion 的 `$ref` 逐类拒绝；primitive type 相同不能单独证明兼容；
- normal/failure topology 使用同一 reachability/cycle-budget 语义；closed registry ID/digest
  pin、completion-policy pin 或实际 registry swap 不得改变已锁定 graph 的行为；
- Graph 的 exact semantic pins 同时覆盖 complete schema/predicate/error/completion/loop registry
  manifests、ResourceProfile ID/body digest 与 CostSchedule ID/body digest；无关 schema addition、
  same-ID body drift、limit/work-budget/coefficients 或 graph content drift 全部在 validation/evaluation
  前拒绝；
- Profile + overlay materialization 与安全单调性；
- config/registry digest swap、unknown version、executable extension injection；
- 同 inputs materialize byte-identical graph。

### 8.2 Reducer/state model

`GEW-RED-001～120` 从 Spec command/state tables 生成笛卡尔模型：

- 每个 `(state, command, precondition)` 只产生规定 events/target；未列组合拒绝；
- PRD decision、compatibility/lease、resolution、rollback action/plan/authority、retention/
  rollback-clearance precondition refs 必须 exact 且进入 event，缺失或空引用拒绝；
- event replay、snapshot rebuild、transaction idempotency；query 不产生 event；
- TaskSnapshot source/digest-input schema pair、charged self-digest trace、exact/after budget
  boundary 与 restore digest mismatch；未提供 attested registry/WorkContext 的构造/恢复拒绝；
- Snapshot required `contract_pins` 绑定 complete schema registry manifest、ResourceProfile 与
  CostSchedule exact body digest；restore/replay/command decision 在 schema validation 或 transition
  前拒绝 registry addition、same-ID manifest、profile/schedule drift；非空 GraphRef exact 绑定
  `graph_digest`，改变 graph content 必须改变 snapshot digest；
- NodeRun ready/running/review/revise/pass/blocked/cancelled；run/node/status 只接受 exact string，
  attempt 只接受 exact positive integer；DependencyRecord、current/baseline drift 与 classify 输入的
  semantic digest 必须满足 lowercase `sha256-jcs-v1:<64 hex>`，equal malformed digest 也先拒绝；
- author/reviewer identity 分离、review digest binding；
- baseline/project scope/artifact/evidence/profile/graph change 的最小 descendant invalidation；
- executed action 不删除历史，进入 reconcile/compensate route。

### 8.3 Routing/convergence/completion

`GEW-RUN-001～100` 覆盖 routine findings、stable finding IDs、digest progress、重复 finding、
冲突 review、budget exhaustion、owner routing、runtime stop/resume。Completion tests 逐项删除
target verification、acceptance、project gate、review、fresh evidence、scope binding 或 current
snapshot，均必须保持 incomplete；伪造/陈旧/cross-task evidence 拒绝。

WP-04 r3 gate 必须机械执行并绑定以下新增 case，而不是仅依赖范围声明：

- command 的多 domain-event/单 repository-transaction 原子性、两类 revision 不混用、request
  idempotency、Owner/runtime lineage mismatch 零写入；list/search/show 前后 event stream byte-identical；
- runtime stop 后 event count 不变；同 lineage resume 完成两节点 route/join；candidate object 必须先
  durable/reference，validation 与独立 review 后才升级 trust；
- routine `REVISE` 在 changed body digest 后关闭 stable finding；相同 digest 再次 `REVISE`、finding
  内容冲突、缺少/耗尽 budget 均稳定升级；REVISE 后 reviewer 对同 body digest 返回 PASS 也必须保留
  open finding 并升级，不得写 `node.passed`；declared stable error 选择 frozen fallback，unknown error
  进入 `blocked`；
- `TaskApplication` public surface 不暴露 reducer-owned transition commit。缺失、stale、错误 scope 或
  event-types 不匹配的 opaque authority 注入 `node.passed`/`task.completed` 时 event stream byte-identical；
  stale source、wrong task、wrong scope、event-type mismatch 与 one-use reuse 必须分别具有独立
  qualified test 和 gate binding；
- `ApplicationRunner` direct construction 拒绝，注册 channel 不返回 authority，generic channel 禁止
  review/pass/completion critical events。review result 先以 `node.review_recorded` 单独持久化；即使取得
  registered channel 并组合 forged PASS runner state，也不能写 `node.passed`。下一事务 PASS 必须精确
  消费 repository 中 latest review、body digest、独立 actor、trust 与 finding-close events；completion
  authority 只能由 current Completion Gate PASS 内部产生；在 review-record transaction 后停止并
  resume 时必须消费 durable record，不得再次调用 reviewer；
- Completion Gate 正例必须传入 `ArtifactValidator` attested Candidate Review/Completion Record；逐项
  删除 node、baseline、authority、scope、Must trace、project gate、candidate review、external target、
  TargetBinding、fresh evidence、unresolved-state clearance 或 completion-record binding 时保持
  `INCOMPLETE`，repository event count 不变。

route/join/completion/loop-budget condition 必须全部走 GEEL + WorkContext。completion/loop
registry document 先通过 closed schema，再计算 charged identity digest；schema 明确拒绝的
version/shape、condition 与 kind 不一致、unknown policy/budget 均不得由 public loader 接受。
Graph projection digest、四条完整 charge traces 与 completion/join/loop truth table 必须和独立
Node implementation 一致。trace golden fixture 逐 bytes 绑定所有 23,266 个现行收费事件，不以
抽样 path 或总预算替代。

### 8.4 十类 ArtifactContract fixtures

logical artifact exact set 为 `positioning,prd,tech-spec,impact,plan,test-plan,implementation,
verification,candidate-review,completion-record`。每类必须有以下 exact case product：

| Case code | Mutation/oracle |
|---|---|
| `GOLD` | valid complete logical artifact 通过对应 ArtifactContract |
| `SEMANTICS` | 删除/损坏每个 contract-specific required semantic section，逐字段拒绝 |
| `INPUTS` | missing/stale/wrong-task/wrong-baseline input refs、invented/unknown authoritative target 拒绝；双 current baseline 正例通过，ref 保持 ID/kind/digest 但 swap 到另一 baseline 必须拒绝 |
| `TRACE` | requirement/decision/dependency trace missing、duplicate、unknown 或不闭合拒绝；多 input/target/requirement 的完整闭包通过 |
| `DIGEST` | body/extracted/input/contract digest 任一 swap、type confusion、stale digest 拒绝 |
| `STATUS` | 非法 state transition、虚假 PASS/Approved/Complete 拒绝 |
| `FINDINGS` | open blocking finding、revision 未关闭 stable ID、digest 无进展拒绝 |
| `REVIEW` | same author/reviewer、case/whitespace identity alias、wrong digest、missing trust/independence/approval policy 拒绝 |
| `EXIT` | 删除每个 artifact exit predicate 或所需 evidence，逐项拒绝 |
| `INVALIDATE` | 上游语义/事实/metadata change 分类后只产生规定 descendant invalidation |

每个 exact ID 为 `GEW-ART-<artifact>-<case-code>`；coverage validator 对上述 explicit 10×10
set equality，共 100 个 case，不接受范围或缺 cell。fixture 是 `artifact-<artifact>-v1` 的 valid
golden 加单一 mutation；oracle 是独立 ArtifactContract/schema/dependency model；evidence 是
`ArtifactValidationRecord`/`InvalidationRecord`；owner gate WP-04A。

merged-body 的额外 exact cases：

- `GEW-ART-MERGED-MANIFEST-GOLD`：full/compact/emergency manifest 与 extracted bodies valid；
- `GEW-ART-MERGED-SELECTOR-MISSING`、`...-AMBIGUOUS`、`...-OUT-OF-BOUNDS`：selector 拒绝；
- `GEW-ART-MERGED-OVERLAP`：未声明 shared section 或 overlap 拒绝；
- `GEW-ART-MERGED-EXTRACTED-DIGEST`：physical file valid 但一个 extracted digest swap 拒绝；
- `GEW-ART-MERGED-INDEPENDENT-INVALIDATION`：只改一个 logical body，只失效该 body declared
  descendants，其他 logical artifacts/current reviews 保持；
- `GEW-ART-MERGED-SHARED-INVALIDATION`：改 declared shared section，精确失效所有 consumers；
- `GEW-ART-MERGED-REVIEW-BINDING`：每个 logical artifact review 绑定自己的 extracted digest，
  不能用 physical file aggregate review 替代。

mutation generator 必须逐项删除 ArtifactContract schema 中每个 `required` property，以及十类
registry 声明的每个 required semantic/trace/review/exit rule；若 schema 新增 required rule 而
没有自动生成对应 failing fixture，coverage build FAIL。

`config/verification/wp-04a-mutations.json` 另外按 exact set 冻结 30 个 subcases：caller mapping
single-snapshot、canonical actor
identity、authoritative target、多 input/target/requirement 正反例、validation/lifecycle direct
construction、revision predecessor、raw/result/temporary/budget boundary，以及 selector/dependency/
manifest lineage/unselected-gap invalidation。`GEW-ART-MUTATION-COVERAGE-R` 必须实际执行每组
probe；每个 concrete assertion 只回报自己实际执行的 subcase，最终对 declared/executed 做 set
equality。注入没有 dispatcher/oracle 的 declaration 必须得到 `DECLARED_EXECUTION_MISMATCH`；只列
ID、组测试后批量标记或只跑 10×10 表面 cell 都不算覆盖。

## 9. Repository、并发与恢复测试

### 9.1 Connection/transaction

`GEW-REP-001～060`：错误 path/owner/mode/symlink/filesystem/VFS/SQLite/PRAGMA/PID/thread/fork
在 transaction 前拒绝；BEGIN IMMEDIATE/CAS/idempotency/busy retry 有限；hot journal 只恢复
完整 old/new；raw copy/move/unlink API 被阻止。

### 9.2 Crash matrix

`GEW-REP-061～140` 在 event/head/snapshot/catalog/lease/claim/object staging/rename/fsync/ref
commit/GC deleting/purge 的每个 durable step 之前和之后 kill process，断言：

- committed transaction 全部可见或全部不可见；
- committed object reference 永不 missing；orphan 不受信任且可安全回收；
- unresolved claim、rollback/export/legal hold 所需 object 不删除；
- corruption/missing referenced object 进入 integrity blocked，不重写历史。

这组测试使用 versioned `PersistenceFaultSchedule` 和三层 harness，而不是只 kill process：

1. **Deterministic syscall model**：所有 DB/object/journal/directory/hold/manifest storage ports 在
   conformance build 中经 fault shim；每个 open/write/truncate/rename/fsync/fdatasync/fullfsync/
   xSync/close 有 monotonic step ID。seeded schedule 可 drop、delay、reorder 未同步 writes、partial/
   torn write、ENOSPC/EIO、crash；只有被正确 file+directory sync 的 dependency 可进入 durable
   image。recovery 从该 image 启动，oracle 是 ADR-0002 old/new/blocked state model；
2. **SQLite/OS process harness**：真实 SQLite/VFS 在 disposable local filesystem/VM 中逐 durable
   point SIGKILL 和强制 VM power-cut/restart，使用 journal/integrity/event replay/objects/manifest
   oracle；seed、step map、pre/post image digest 可重复。不能提供 power-cut runner 的环境不能
   进入 release support claim；
3. **Platform capability probes**：macOS 故意关闭/伪报 `fullfsync`，Linux 使用 rejecting/no-op
   `xSync` test VFS 与 unsupported/network filesystem fixture；doctor 必须在 mutation 前 blocked。
   release evidence 记录真实 VFS/filesystem/SQLite/OS capability，不以一次成功写入代替证明。

durability exact case IDs：

- `GEW-DUR-PROCESS-CRASH`、`GEW-DUR-OS-POWER-CUT`、`GEW-DUR-DISK-FULL`、
  `GEW-DUR-IO-ERROR`、`GEW-DUR-REORDER`、`GEW-DUR-TORN-WRITE`；
- `GEW-DUR-DB-JOURNAL`、`GEW-DUR-OBJECT-FILE`、`GEW-DUR-OBJECT-DIRECTORY`、
  `GEW-DUR-GC-PURGE`、`GEW-DUR-EXPORT-HOLD`、`GEW-DUR-ACTIVE-MANIFEST`；
- `GEW-DUR-MACOS-FULLFSYNC-P/R`、`GEW-DUR-LINUX-XSYNC-P/R`、
  `GEW-DUR-UNSUPPORTED-FS-R`。

前两组 fault-class × durable-unit 做 exact Cartesian coverage；每个 step before/after 与 seed 在
manifest 中枚举。golden oracle 只允许 complete old、complete new 或 explicit integrity/
capability blocked。遗漏 directory sync、无效 fullfsync/xSync、接受 torn/reordered image 或相同
seed 不可复现，均为 blocker。

### 9.3 Locks/concurrency

`GEW-LOC-001～080`：same-thread、multi-thread、two-process、fork-during-call、child unlock/exit、
exec、process crash、inode replacement、symlink/path attack、相反 multi-resource order、partial
acquire。断言 process mutex + POSIX lock + durable claim 一致，不死锁、不部分 ownership，child
不释放/延长 parent，stale generation 命令不跨 activation。

### 9.4 Export/migration

`GEW-MIG-001～100`：public export 与 migration-held export 不递归锁；持续 writes/GC 下 bundle
内部 DB 导出相同 manifest且 objects 完整；import/replay/integrity/compatibility；每个 manifest
switch 前后 crash；两进程 activation、command-versus-switch、rollback、restore gap、fencing
high-water。只允许一个 activation authority，普通命令只看到 verified active 或 blocked。

### 9.5 WP-03 candidate gate 与 release durability 分层

WP-03 candidate gate 必须精确绑定：WP-02 r4 source/commands/exit/PASS verdict、当前 source
manifest、Spec/Impact/Plan/Test Plan/ADR-0002 的 governing manifest、managed interpreter、SQLite
library/compile options、repository policy、fault schedule，以及 live filesystem/VFS/sync capability。
门禁的最低机械用例包括：

- factory-only capability、unsupported filesystem 拒绝、live mount + exact `unix` VFS +
  DELETE/EXTRA/fullfsync readback，并证明 capability 在每次 open 前复核；初始化与 object fanout
  必须在任何 mutation 前 no-follow 验证，symlink/unsupported filesystem 拒绝保持外部 target 与
  repository contents 不变；初始化后将 top-level objects、staging、locks 或 resources 替换为
  外部 symlink 时，所有 filesystem 动作必须通过原 attested directory descriptor，且在首个 fault
  hook/创建/open/link 前拒绝；外部 node、bytes、mode、links 精确不变；
- separate thread/process 在 staging directory fsync 后替换 staging name，或在 publication link 后
  替换 final name，均必须由 retained staging descriptor、final no-follow descriptor 与重复 digest
  校验检出；调用必须失败、错误 final 与 staging name 必须清除，fresh candidate 不得存在
  `available` metadata；同一要求覆盖 `after_object_directory_fsync` 和 transaction 内
  `before_metadata_commit`。`GEW-ADR2-OBJECT-DEDUP-R` 必须先成功写入同 digest，再在第二次
  deduplicated put 的两个窗口分别替换 final；当前 transaction 必须回滚，旧 `available` metadata
  必须由独立 durable transaction 转为 `quarantined`，final/staging 均清理。若 metadata 已提交后
  检出 mismatch，同样必须转 `quarantined` 后失败；
- `GEW-ADR2-OBJECT-CLEANUP-ISOLATION-R` 在上述两个窗口分别暂停 writer A 的 stale cleanup，
  同时让 writer B 通过正常 public `put_verified` 竞争同一 digest；B 在 A 持锁期间必须有限失败或
  等待而不能越过 cleanup，A 释放后 B 重试必须成功。最终 canonical final 必须是 B 已验证 bytes、
  metadata 为 `available`、staging 为空；跨进程 object/resource lock 证据必须证明相同排他语义。
  cleanup 的 unlink 还必须与 mismatch 时及删除前一致的 device/inode 绑定；
- `GEW-ADR2-OBJECT-LOCK-COMPOSITION-P` 分别预持字典序低于和高于旧 hidden identity 的合法
  action resources，再通过同一 public `put_verified` durable raw receipt；API 必须复用 outer
  installation scope、在全部 action resources 后取得独立 publication tier、随后取得 object
  shared，且 caller 可按逆序正常释放原 locks。publication conflict 的独立进程必须有限失败、
  不产生 partial ownership；resource ID 拼写不得改变结果；
- `doctor`/`backup` 同时以 read-only URI、`query_only` 和 authorizer 拒绝 direct write 及
  `WITH ... UPDATE/DELETE/INSERT`；
- caller 不能提交 `issued_at`/`validated_at`；TTL 使用 repository-owned wall clock 与持久化
  non-decreasing high-water，clock rollback 不复活 stale lease；
- task revision CAS、event/index/transaction/head exact binding、idempotent recovery、snapshot
  authoritative replay repair、committed object corruption/missing fail closed；event index、
  transaction revision/head/task 任一 corruption 时 replay 与 recover 均必须 integrity-blocked；
- atomic acquire-many、monotonic fences、PID/thread/fork lock ownership、canonical lock order、
  process shared/exclusive semantics；canonical resource ID 升序必须跨同线程所有 held token，
  并以 two-process `b→a` 对 `a→b` 证明有限失败而非死锁；
- action claim 绑定同 transaction 的 exact started event type + `action_id` payload；reconciliation
  绑定 exact outcome event + `claim_id` payload。过期 lease 只能通过同 task/lease/latest-fence 的
  unresolved claim reconciliation path 推进，不能执行新 action；direct `CommitBatch` 对 missing、
  extra、empty、stale fence 与 wrong lease claim set 均必须拒绝；
- versioned high-level fault schedule 的所有 step 可枚举，真实 process SIGKILL 至少覆盖
  transaction commit 前/后 old/new，object orphan/staging/deleting 可幂等恢复。

这一 candidate gate 不替代 §9.2 的 release matrix。syscall drop/reorder/torn/partial、真实 ENOSPC/
EIO、VM power-cut/restart、Linux rejecting/no-op `xSync` VFS，以及 export-hold/active-manifest
durability 仍需在相应 WP 和 release environment 产生 fresh evidence；缺少任何一项时不得声明
对应平台或 release durability 支持。

## 10. Authority、Action 与 Privacy 测试

### 10.1 Deterministic gate

`GEW-AUT-001～100` 对已准备动作逐一改变 Owner/runtime/lineage/target identity、Intent、scope、
snapshot/revision、payload/action digest、authority class/target、expiry、revocation、disclosure、
lease/fence/capability；每个 case 在 adapter/tool call counter 仍为 0 时拒绝。

pre-call mutation exact set 还必须包含：

| Exact test ID | 单一 mutation |
|---|---|
| `GEW-AUT-PRECONDITION-CHANGED` | adapter 重新读取的 target precondition 与 prepared value 不同 |
| `GEW-AUT-PRECONDITION-UNVERIFIABLE` | adapter 无法 fresh query 或 identity/freshness 不可证明 |
| `GEW-AUT-IDEMPOTENCY-KEY-CHANGED` | action idempotency key 与 authorized record 不同 |
| `GEW-AUT-IDEMPOTENCY-CLASS-CHANGED` | idempotent/non-idempotent class 改变 |
| `GEW-AUT-IDEMPOTENCY-DUPLICATE` | journal 已有 prepared/started/succeeded same key 的冲突记录 |
| `GEW-AUT-IDEMPOTENCY-UNKNOWN` | same key 存在 unknown/unresolved claim |
| `GEW-AUT-ROLLBACK-MISSING` | action class 要求 rollback 但 plan 缺失 |
| `GEW-AUT-ROLLBACK-CHANGED` | rollback body/digest/target/capability 与授权后不同 |
| `GEW-AUT-VERIFY-MISSING` | target verification plan 或 query adapter 缺失 |
| `GEW-AUT-VERIFY-CHANGED` | verification predicates/target/query digest 改变 |
| `GEW-AUT-TARGET-EVIDENCE-STALE` | precondition query evidence revision/freshness 超出允许边界 |
| `GEW-AUT-COMBINED-MUTATION` | 上述每个 pair 的组合；必须按冻结 gate precedence 返回同一 first rejection |

每个 case 的 oracle 是独立 ExecuteGate decision table；断言指定 stable rejection code、没有
`action.execution_started`、没有新 claim（已有 unknown claim 保持）、所有 adapter/tool side-
effect counters 为 0。fresh target re-read 本身必须是声明的只读 capability，receipt 绑定当前
target identity/revision；不能以缓存 evidence 代替。mutation generator 对 PreparedAction/
Authority/rollback/verification schema 的每个 gate-bound property逐项改变，新增 property 没有
case 时 coverage FAIL。

### 10.2 Action crash/reconciliation

`GEW-ACT-001～100` 覆盖 prepare、authorize、started commit、tool call before/after、receipt body
durable、receipt commit、target query、completion 各 crash point；idempotent 与 non-idempotent
分别验证：

- 未证明未执行的 non-idempotent action 不自动 replay；
- call-span lock 丢失后 durable claim 仍阻止第二任务；
- adapter 原生 precondition/fence 失败不伪装 success；
- `unknown` 只能通过 target reconciliation、compensation 或 Human decision 解除；
- action success 但 target 不达标不能完成。

ADR-0005 recovery-claim compensation 增加以下 mandatory exact cases；全部只使用 deterministic
fake target，且 `real_external_actions_enabled=false`：

| Exact test ID | 必须证明 |
|---|---|
| `GEW-ACT-RECOVERY-CLAIM-LIVE-P` | live original lease 下复用唯一 unresolved claim；不创建第二 claim |
| `GEW-ACT-RECOVERY-CLAIM-EXPIRED-P` | expired original lease 仍以 same task/lease、完整 resources/latest fences durable started/receipt/verify/consume |
| `GEW-ACT-RECOVERY-CLAIM-EXACT-R` | wrong task/lease、missing/extra/reordered-duplicate resource、missing/stale/extra fence 全部 pre-call reject |
| `GEW-ACT-RECOVERY-AUTHORITY-R` | missing/wrong/revoked/superseded/expired rollback authority，或 authority 的 target/resource/baseline/snapshot/payload/verify/disclosure 任一改变，tool counter 为 0 |
| `GEW-ACT-RECOVERY-COMPENSATION-ONLY-R` | normal action、original action/payload replay、其他 action kind 与 authority class 全部拒绝 |
| `GEW-ACT-RECOVERY-NO-NEW-LEASE-CLAIM-R` | normal replacement lease、renewal、second claim 或提前 claim reconciliation 均无法提交 |
| `GEW-ACT-RECOVERY-LOCK-SPAN-P` | installation shared + 全部 resource locks 覆盖 started durable 到 receipt durable；调用时无 DB transaction |
| `GEW-ACT-RECOVERY-VERIFY-P` | 独立 fresh read-only target observation 精确证明 rollback postcondition 后，claim 才与 reconciled event 原子消费 |
| `GEW-ACT-RECOVERY-VERIFY-R` | stale/unverifiable/wrong identity/wrong state observation 保持 original claim unresolved、资源冻结且不完成 |
| `GEW-ACT-RECOVERY-NO-REPLAY-R` | timeout/crash/ambiguous receipt 后恢复只 query/reconcile/manual，不再次调用 original 或 compensation tool |
| `GEW-ACT-RECOVERY-ATTEMPT-ID-P` | exact attempt tuple 确定产生相同 attempt ID 与 start/receipt/reconcile transaction IDs；每次 exact replay 返回既有 result |
| `GEW-ACT-RECOVERY-ATTEMPT-ID-R` | action/authority/claim/lease/resource/fence/expected claim revision 任一改变产生 distinct attempt；复用旧 transaction ID 必须 conflict |
| `GEW-ACT-RECOVERY-START-REPLAY-R` | start `NOT_COMMITTED` 可重跑；start `COMMITTED` 后同 request 只读回既有 result且 tool-call delta=0，distinct start/action/authority fail closed |
| `GEW-ACT-RECOVERY-RECEIPT-BINDING-R` | receipt 缺失或改变 attempt/start event、original claim、compensation action、task/target/lease/full fences、source/body digest 任一字段均拒绝且 claim unresolved |
| `GEW-ACT-RECOVERY-CONCURRENCY-R` | 两进程/线程竞争同 claim：最多一个 fresh start 获得单次 call permission；loser 只读 committed result或 conflict，不能调用 tool/创建 claim/取得 lease |
| `GEW-ACT-RECOVERY-CLAIM-FREEZE-P` | start/receipt 前后 `claims.state='unresolved'`，acquire-many 对全部原 resources 持续拒绝；只有 verified reconcile transaction 改终态 |

crash matrix 对 compensation gate before/after、started commit before/after、tool effect before/after、
raw receipt durable before/after、receipt event commit before/after、fresh target query、reconciliation
commit 和 claim consumption 每个点分别注入真实 process termination/fault。每点必须只恢复为：

- compensation 未调用且 original claim 完整 unresolved；或
- compensation effect/receipt 状态未知且 claim 完整 unresolved，路由 query/manual；或
- receipt durable、fresh verification 成功且 reconciliation event 与 claim consumption 同一 commit。

禁止出现 claim 已消费但 target 未验证、部分 resource/fence claim、第二 claim、replacement lease、
original replay、receipt 无 started binding，或 journal/task/claim 状态分叉。expired path 还必须证明
unrelated task/action 不能借 recovery assertion 绕过普通 live-lease gate。

attempt/crash oracle 还必须逐点断言 `tool_call_count_delta`：start commit 前 crash 为 0，fresh start
commit 后至 call boundary crash 为 0 或唯一一次，start committed 的任何恢复 invocation 恒为 0；
tool effect 后、raw response 前、receipt body durable 前后、receipt event commit 前后都不得产生第二
次调用。receipt commit crash-replay 使用相同 `<attempt_id>:receipt` + request digest 返回既有 result；
不同 receipt digest conflict。两个并发 recovery processes 必须在真实 call-span locks 与 repository
CAS 下证明总 tool-call count 至多 1，且任何时刻 original claim lifecycle state 均为 unresolved。

### 10.3 Security/privacy

`GEW-SEC-001～120`：path traversal、symlink escape、argument/shell injection、prompt injection、
identity spoof、digest/type confusion、malicious schema/graph/extension、resource exhaustion、
package/path shadowing。`GEW-PRI-001～080`：secret value scanning、provider refs、redaction、
classification、retention/purge/quarantine、destination allowlist、payload receipt。任何 secret
value 出现在 state/log/evidence/PMF/report 都是 release blocker并触发 fixture rotation。

## 11. Lifecycle 与 Runtime Contract 测试

### 11.1 Project/task lifecycle

`GEW-LIF-001～100`：new/existing Git、actual realization、多仓库/服务/环境、non-Git reject、
canonical duplicate/symlink/allowlist escape、并行资源冲突；create/list/search/show、pause/
resume/cancel/revoke/archive/rollback；批准后事实更新与语义 scope change 分类。rollback 不能
删除 audit 或降低 fence。

### 11.2 Codex/Hermes parity

Runtime contract suite `GEW-RT-001～080` 由同一 fixtures 驱动两个 adapter：

- discover/create/clarify/approve/run/status/resume/escalate/result；
- stable Owner/session/thread lineage，其他用户/会话输入拒绝；
- independent reviewer identity/capability；
- runtime 关闭即停止、同 runtime 恢复；另一 runtime continuation 明确拒绝且不泄露；
- capability/version mismatch 在 mutation 前拒绝；
- Skills 调用 canonical executable，thin-Skill static scan 无核心门禁逻辑。

Hermes 的 Telegram/Discord 分别执行 pairing/allowlist、channel/thread lineage、长消息分段与
delivery receipt；真实消息发送属于需单独授权的 action，不由测试计划隐式允许。

## 12. 九类 Profile Release Matrix

每类必须执行同一 mandatory columns，并增加类别专属 cases；exact IDs 和 216-test P/R set 以
§6.1 Cross-product rows 为准：

| Profile | 专属必须场景 | Completion/rollback 重点 |
|---|---|---|
| 新项目/功能 | scaffold、既有项目 feature、multi-target | build/test/acceptance/target realization；可撤销变更 |
| Bug 修复 | reproducible failing fixture、边界、false reproduction | 修前失败修后通过且无回归；恢复原行为 |
| Hotfix | emergency baseline、最小 patch、production-like gate | 风险/授权/target health；快速 rollback |
| 重构/技术债 | behavior characterization、architecture invariant | 行为等价+质量目标；恢复旧 implementation |
| 数据库/架构迁移 | forward/backward/partial data/crash | integrity/compat window；forward/rollback contract |
| 依赖/安全修复 | vulnerable graph、transitive、unavailable fix | exposure/remediation/residual risk；version rollback |
| 性能优化 | stable baseline、noise/outlier、regression | statistically valid target + correctness；config/code rollback |
| 发布/运维 | artifact provenance、health、partial deploy | exact release/target state；deployment rollback |
| 事故响应 | detection/contain/recover/unknown effects | service safety and evidence；compensation/follow-up |

对每一行，`GEW-PRO-<PROFILE>-<COLUMN>-P/R` 固定覆盖：normal、category boundary、failed revision、
authority failure、intent drift、invalidation、runtime recovery、standard artifacts、independent
review、target verification、rollback 和至少一个 real project/toolchain E2E。12 项全部 PASS；
不得 waiver，不得以其他 Profile 或 shared-core case 代替。

类别专属 scenario 不是散文说明；以下 frozen set 每项都生成 distinct
`GEW-PSC-<PROFILE>-<SCENARIO>-P` 与 `...-R`，fixture 使用同名 Profile/scenario manifest，oracle
是独立 category acceptance/rollback model，evidence owner WP-08：

| Canonical Profile ID | Exact scenario IDs |
|---|---|
| `new-feature` | `scaffold`, `existing-feature`, `multi-target` |
| `bug-fix` | `reproducible-failure`, `false-reproduction`, `regression-boundary` |
| `hotfix` | `emergency-baseline`, `minimal-patch`, `production-like-gate` |
| `refactor-debt` | `behavior-characterization`, `architecture-invariant`, `nonfunctional-target` |
| `migration` | `forward`, `backward`, `partial-data`, `crash-window` |
| `dependency-security` | `vulnerable-graph`, `transitive-dependency`, `fix-unavailable` |
| `performance` | `stable-baseline`, `noise-outlier`, `correctness-regression` |
| `release-operations` | `artifact-provenance`, `health-gate`, `partial-deploy` |
| `incident-response` | `detection`, `containment`, `recovery`, `unknown-effects` |

coverage validator 对上面 29-scenario explicit set × `{P,R}` 做 exact equality；新增/删除/别名/
duplicate/missing rejection member 全部 FAIL。category table 的中文标题只是 display label，不能
成为另一个 identity。

每个 mandatory/scenario P/R stable binding 都有 config-owned、确定性且唯一的 `task_id`；
exact tuple 为 test ID、Profile、selector kind、column/scenario、overlay、disposition、expected
result、execution kind、task identity。task identity 必须进入 selector/request/oracle/plan digest
链；missing/extra/alias/duplicate/reorder、跨 binding task substitution 或 coherent re-sign 均在
execution/observation/CoverageRecord 之前 FAIL，且 task/event/snapshot/object/ref/target/action 零写。

Historical pre-E1 Option C曾允许coverage fixture在每Profile一个disposable repository/application stack内创建独立task
rows；该历史优化不适用于Human-approved E1或current cumulative。E1要求每binding独占fresh private repository root、
task、target、branch/ref、action root与command root，攻击/substitution probe用后立即关闭，real-E2E Git/project fixture
也不得跨binding/profile共享。strict-serial路径必须产生相同stable-ID ordered digests/outcomes；最终仍由同一次combined
`ReleaseCoverageGate` 对全部 current records 判定，禁止 shard、cache token 或 static evidence
替代。focused harness 在 `OK` 后 120 秒内自然 exit 0；超时即 FAIL，而不是强制退出隐藏。

同一 existing WP-08 P/R discovery methods 内还要验证 coverage authority lifecycle。先以 RED 证明
candidate 创建时签发 abort capability 会遗漏随后 registrations，因而不允许。GREEN 中，对尚未产生
combined gate decision 且未 finalized 的 candidate，factory 仅在调用
`prepare_abort_uncommitted_candidate` 时于 register/gate/finalize 共用锁内冻结 exact candidate generation、
plan digest、完整 current issuance/registered-authority projection及其 digest，并把 `abort-prepared` state、
frozen snapshot/version、one-shot capability identity 作为一个 tuple 原子存入 consumer-local table 后才返回
capability。调用者不能提交 projection；register 先赢则 identity 进入 frozen
snapshot，prepare 先赢则 register/gate/finalize 拒绝。canonical exact capability 可令
`active-uncommitted → abort-prepared → aborting → aborted`，且不调用 gate、不生成 assessment/decision、
不删除 immutable record documents、不产生
task/event/snapshot/object/ref/action/target 写。aborted 后 observe/execute/current/restart/factory
issue/require/gate/finalize/register/reopen 全部拒绝；重复 exact abort 幂等。

abort rejection matrix exact 覆盖 foreign/clone/`object.__new__` capability、wrong factory/candidate、partial/
missing/extra/duplicate/reorder/substituted caller selection（API 必须拒绝该输入）、coherent re-sign、已
finalized candidate 与 capability reuse across candidate。所有拒绝都不能撤销正确 candidate 或改变输入；
还要证明旧 create-time/early capability 不存在，later registrations 全部进入 prepare 时冻结的 exact
snapshot，且 freeze 后 registration/gate/finalize 全拒绝。in-process exception matrix 覆盖 prepare
tuple commit 前、tuple commit 后 return 前、committed return 丢失与重复 prepare、`abort-prepared` 后
capability 消费前、`aborting` 后首个 registry revoke 前、任一 registry/authority cleanup 中间与 terminal
写后：tuple 前同一对象仍 active 且无 stored cap；tuple 后同一 factory/candidate 重复 prepare 必须返回
同一个 cap identity、不改变 snapshot/version、不新签 cap；foreign/clone/different snapshot retry拒绝；
consume 后 prepare拒绝但same-cap abort幂等；
consume 后永不 reopen，同一对象 exact retry 只继续 frozen snapshot cleanup。独立 process-termination probe
则证明 local
factory/capability 不可跨 restart 恢复，immutable durable documents 字节不变且没有 use authority。
gate consumption/finalize 与 abort 并发时以同一 factory-local lock 的第一个线性化点为唯一赢家；
gate/finalize 先赢则 abort 拒绝，abort 先赢则 gate/finalize 拒绝。

对已产生 exact combined gate decision 的 candidate，abort 永远拒绝；factory 对 exact decision 的首次
finalize 才能走 `combined-gate-consumed → closing → finalized` 并撤销全部 execution/observation/
CoverageRecord identity graph，重复 finalize 幂等。partial/sharded gate、少/多/duplicate/reorder-
substitution record、foreign/clone decision/factory/authority、coherent re-sign 以及异常切点都不能获得
finalize capability。函数级、24+24 与 170-record synthetic lifecycle probe 必须分别证明两条 terminal
branch 的 retained identity/FD 峰值有界、immutable record/legitimate decision digest 与 durable signatures
保持不变、资源最终回到基线，method `OK` 后 120 秒内自然 exit 0。

### 12.1 Dependency-security offline advisory authority

ADR-0006 的 24 mandatory bindings 必须继续放在 existing WP-08 P/R 两个 discovered methods 内，以
subtests 保持每个 stable ID、task、request、execution、observation 与 `CoverageRecord` 独立。exact
column/source/oracle set 为：

| Column | Exact P/R IDs | Authoritative durable source / required outcome | Exact oracle member |
|---|---|---|---|
| normal | `GEW-PRO-DEPENDENCY-SECURITY-NORMAL-P`, `GEW-PRO-DEPENDENCY-SECURITY-NORMAL-R` | `runner-execution` / `runner-accepted`，包含 current closure runner output digest | `config/test-oracles/profile-dependency-security-normal-v1.json` |
| boundary | `GEW-PRO-DEPENDENCY-SECURITY-BOUNDARY-P`, `GEW-PRO-DEPENDENCY-SECURITY-BOUNDARY-R` | `scenario-membership` / `scenario-accepted`，只接受 Profile exact boundary member | `config/test-oracles/profile-dependency-security-boundary-v1.json` |
| revise | `GEW-PRO-DEPENDENCY-SECURITY-REVISE-P`, `GEW-PRO-DEPENDENCY-SECURITY-REVISE-R` | `revision-lineage` / `revision-accepted`，new body、budget、owner route exact | `config/test-oracles/profile-dependency-security-revise-v1.json` |
| authority | `GEW-PRO-DEPENDENCY-SECURITY-AUTHORITY-P`, `GEW-PRO-DEPENDENCY-SECURITY-AUTHORITY-R` | `authority-decision` / `authority-current` | `config/test-oracles/profile-dependency-security-authority-v1.json` |
| drift | `GEW-PRO-DEPENDENCY-SECURITY-DRIFT-P`, `GEW-PRO-DEPENDENCY-SECURITY-DRIFT-R` | `drift-assessment` / `drift-resolved`，target/closure digest current | `config/test-oracles/profile-dependency-security-drift-v1.json` |
| invalidation | `GEW-PRO-DEPENDENCY-SECURITY-INVALIDATION-P`, `GEW-PRO-DEPENDENCY-SECURITY-INVALIDATION-R` | `invalidation-record` / `invalidation-current` | `config/test-oracles/profile-dependency-security-invalidation-v1.json` |
| recovery | `GEW-PRO-DEPENDENCY-SECURITY-RECOVERY-P`, `GEW-PRO-DEPENDENCY-SECURITY-RECOVERY-R` | `recovery-record` / `recovered`，unknown 不自动 replay | `config/test-oracles/profile-dependency-security-recovery-v1.json` |
| artifacts | `GEW-PRO-DEPENDENCY-SECURITY-ARTIFACTS-P`, `GEW-PRO-DEPENDENCY-SECURITY-ARTIFACTS-R` | `artifact-records` / `artifacts-accepted`，包含 advisory/source/closure/regression/residual evidence refs | `config/test-oracles/profile-dependency-security-artifacts-v1.json` |
| review | `GEW-PRO-DEPENDENCY-SECURITY-REVIEW-P`, `GEW-PRO-DEPENDENCY-SECURITY-REVIEW-R` | `independent-review` / `review-accepted`，author/reviewer 与 reviewed digests exact | `config/test-oracles/profile-dependency-security-review-v1.json` |
| target | `GEW-PRO-DEPENDENCY-SECURITY-TARGET-P`, `GEW-PRO-DEPENDENCY-SECURITY-TARGET-R` | `target-observation` / `target-matched`，fresh fixed-closure target | `config/test-oracles/profile-dependency-security-target-v1.json` |
| rollback | `GEW-PRO-DEPENDENCY-SECURITY-ROLLBACK-P`, `GEW-PRO-DEPENDENCY-SECURITY-ROLLBACK-R` | `action-rollback` / `rollback-verified`，ActionCoordinator journal/claim + `dependency-state-restored` | `config/test-oracles/profile-dependency-security-rollback-v1.json` |
| real-e2e | `GEW-PRO-DEPENDENCY-SECURITY-REAL-E2E-P`, `GEW-PRO-DEPENDENCY-SECURITY-REAL-E2E-R` | `real-toolchain-execution` / `real-toolchain-attested`，current advisory + WP08A closure + regression + residual facts | `config/test-oracles/profile-dependency-security-real-e2e-v1.json` |

每个 oracle exact 绑定 `(oracle_id=ORA-PROFILE-DEPENDENCY-SECURITY, profile_id,
selector_kind=mandatory, column_id, overlay_id=full-planned, task_ids.P/R)`、registry/source/advisory/
closure policy digests与 column-specific typed outcome。cross-column/profile/oracle/task/source substitution、
same-ID different request、alias/duplicate/reorder 或 coherent re-sign 在 execution 前拒绝。

#### Registry/bootstrap/schema matrix

canonical registry 必须由 installation byte pipe 读取并通过 exact source/input schema、self-digest、
installed distribution RECORD/source checkout attestation。下列每项各有 positive/rejection subcase：

schema registry exact closure包含ADR-0006的10组IDs：

| Stem | Source schema | Digest-input schema |
|---|---|---|
| `dependency-advisory-source-record` | `urn:gew:schema:dependency-advisory-source-record:1.0.0` | `urn:gew:schema:dependency-advisory-source-record-input:1.0.0` |
| `dependency-fixed-closure` | `urn:gew:schema:dependency-fixed-closure:1.0.0` | `urn:gew:schema:dependency-fixed-closure-input:1.0.0` |
| `dependency-advisory-record` | `urn:gew:schema:dependency-advisory-record:1.0.0` | `urn:gew:schema:dependency-advisory-record-input:1.0.0` |
| `dependency-advisory-status-high-water` | `urn:gew:schema:dependency-advisory-status-high-water:1.0.0` | `urn:gew:schema:dependency-advisory-status-high-water-input:1.0.0` |
| `dependency-advisory-registry` | `urn:gew:schema:dependency-advisory-registry:1.0.0` | `urn:gew:schema:dependency-advisory-registry-input:1.0.0` |
| `dependency-advisory-installation-bootstrap` | `urn:gew:schema:dependency-advisory-installation-bootstrap:1.0.0` | `urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.0.0` |
| `dependency-offline-closure-observation` | `urn:gew:schema:dependency-offline-closure-observation:1.0.0` | `urn:gew:schema:dependency-offline-closure-observation-input:1.0.0` |
| `dependency-applicability-observation` | `urn:gew:schema:dependency-applicability-observation:1.0.0` | `urn:gew:schema:dependency-applicability-observation-input:1.0.0` |
| `dependency-residual-exposure-observation` | `urn:gew:schema:dependency-residual-exposure-observation:1.0.0` | `urn:gew:schema:dependency-residual-exposure-observation-input:1.0.0` |
| `dependency-security-observation` | `urn:gew:schema:dependency-security-observation:1.0.0` | `urn:gew:schema:dependency-security-observation-input:1.0.0` |

每组source/input member path与raw SHA双向exact；digest-input只删除自身derived digest field，parent仍必须
包含nested child body/digest。逐层删除/替换child digest、只摘要ID、错误排除nested body、unknown
projection与coherent parent/child re-sign均拒绝。bootstrap exact pin registry member/raw/semantic/generation、
10 pairs、Profile schema registry、source/build/distribution/RECORD attestations及protected list/digest。

- root/source/advisory/fixed-closure missing、extra、null、wrong type、unknown enum、unsorted、duplicate、alias；
- raw SHA、semantic digest、source attestation、source/advisory/closure digest 长度/字符/prefix 错误；
- genesis非`generation=1`、non-null previous/rollback-of、wrong update kind；forward/rollback downgrade、skip、
  wrong/null previous、wrong rollback-of；
- revocation high-water fields/order/identity set mismatch、unsorted/duplicate state、invalid status enum/transition、
  removed state、revoked resurrection；candidate head `g=current+1`中new identity必须active且
  `status_generation=g`、unchanged status必须保留prior generation、transition必须使用`g`，且所有row
  满足`1 <= status_generation <= g`；future/stale/bump/wrong generation全部拒绝；
- source half-open `not_before <= clock < not_after`边界、expired/revoked/superseded/foreign issuer与repository
  clock rollback；
- affected specifier、distribution normalization、advisory/source cross-binding、fixed pin/wheel/RECORD/command
  substitution，以及完整 coherent registry+bootstrap re-sign但 installation identity不变；new advisory
  revision可以在candidate head作为new active identity，旧superseded/revoked identity不得复活；
- registry/schema/source delete、same-path atomic replacement、post-issuance replace、unpacked RECORD tamper、
  archive duplicate/tamper、PYTHONPATH/project shadow 与 fallback。

任何 rejection 都必须在 factory/observation issuance 前发生，installation loader/current-check counter
证明实际重读；registry、task/event/snapshot/object/ref/action/Git/inputs 全部不变。

#### Closure/applicability/real-E2E matrix

P fixture 是完全 disposable local Git project + wheelhouse。A commit 包含 registry 当前 advisory 命中的
affected distribution/version closure；ActionCoordinator prepared→authorized→`git.update-ref` 一次切换
到 B；B wheelhouse 必须由 WP08A exact preflight 证明 physical ZIP/METADATA/WHEEL/RECORD、normalized
name/version/requirements、完整 dependency closure 与 closure budgets，且匹配 registry approved fixed
closure。随后 factory-issued structured security-regression record PASS，residual advisory set empty 或按
exact policy 明确记录；residual set必须由current registry全部advisory/source evaluation rows deterministic
派生，不能由fixture/caller提供。fresh observer 证明 target B，restart 重解同一 unique object ref且 zero replay。

R fixture 在相同 registry/advisory 下准备 stale expected A、actual C；native precondition 在 mutation前拒绝，
Git delta、start/claim/invocation/receipt/observation、task/category assessment/ref/CAS 增量全为零。wrong
advisory/affected range/fixed closure、missing/unreferenced/duplicate wheel、hidden member、metadata/RECORD/
parser drift、closure budget exhaustion、security-regression missing/wrong/foreign/stale、residual exposure
omitted、target post-observation replace 或 unexpected error 均不能签发 execution；只有 exact approved
rejection error、前后摘要和 oracle 完成后才可签发 R record。

issue、category assessment precommit、restart、coverage observer/factory/gate 的每个 cut 都分别注入
registry/source/advisory/closure/target replacement并要求 current re-read。foreign factory/authority/record、
`object.__new__` clone、persisted bytes promotion、equality/hash match、process-global identity table 均拒绝。
applicability issuer还要逐项攻击same-factory registry/advisory/source与before/after closure identity：caller
affected/fixed bool、list/mapping、missing source、foreign/clone/cross-advisory/source、before/after swap、coherent
re-sign与post-observation closure replacement全部zero issuance。residual issuer必须遍历current registry全量；
evaluation universe exact为high-water中active advisory identity set，必须与rows中非inactive identities双向相等；
历史superseded/revoked identities保留exact inactive rows，不要求历史source active/time-valid且不进入
residual set。caller residual bool/list/count、遗漏active或historical identity、duplicate row、伪造inactive
identity为active、删除/reorder/substitute evaluation row或after closure replacement均拒绝，
use/precommit/restart每次重算rows/set。

update/revocation probe由existing installation-verification boundary比较current→candidate，证明generation
exact +1、previous exact、high-water identity append-only；new identity active/status-generation=candidate head，
unchanged status generation byte-exact不变，transition status-generation=candidate head，且所有row在`1..head`；
future/stale/bump/wrong generation拒绝，旧revision不改写/不复活；rollback 是current+1并保留全部deny。
同时断言WP-08未创建registry head DB/pointer/transaction。

所有 preflight/issue/use/restart/rollback 测试包裹 DNS resolver、socket connect、proxy/environment/index
probe，调用 exact 为零；任何网络尝试直接 FAIL。不得安装/激活 candidate，不生成
ReleaseInstallManifest，不访问用户 repository/secret/外部系统，也不得把 WP08A preflight success 单独
计为 dependency-security PASS。

#### Gate, lifecycle and verification order

RED 先证明 exact 24 plan/oracle members 与新 registry/observation authority 缺失；GREEN 顺序为 schema/
bootstrap → registry/source currentness → WP08A closure wrapper → observation/use/precommit/restart →
representative NORMAL P/R → REAL-E2E P/R → existing 2 methods。Historical pre-E1 Option C的per-Profile shared repository
只保留为lineage且不适用于E1/current cumulative；E1要求每binding fresh private repository root及unique
task/target/branch-ref/action-root/command-root，real-E2E Git/wheelhouse不跨binding/profile共享并strict serial。

本 batch 后 exact plan `170`、oracle bindings `85`、production gate
`170 valid / 104 missing / passed=false`，static evidence `0/274`，不得发行 WP-08 exit。combined gate 前
finalize拒绝；不进入 combined gate 的 partial P/R candidate 必须用 exact capability abort，且不产生 gate
decision。exact combined gate后 lifecycle finalize/revoke 清空 local identity graph；aborted/finalized 后所有
advisory/closure/observation/coverage current/restart/register入口拒绝，immutable records、合法 decision 与
durable task/action/target不变，两个分支 cleanup 均 <120s自然 exit 0。验证只运行 dependency-security focused、Slice3代表、
WP08A parser/physical-closure regression、ActionCoordinator/Git/command、contracts/source/package/wheel与
lint/type/architecture；不跑 full/evidence，不改历史 WP08A tuple/gate/evidence。

### 12.2 Performance offline benchmark authority

ADR-0007 的24 mandatory bindings继续放在existing WP-08 P/R两个discovered methods内。每个stable ID、unique
task、request、execution、observation与`CoverageRecord`独立；exact column/source/oracle set为：

| Column | Exact P/R IDs | Authoritative durable source / required outcome | Exact oracle member |
|---|---|---|---|
| normal | `GEW-PRO-PERFORMANCE-NORMAL-P`, `GEW-PRO-PERFORMANCE-NORMAL-R` | `runner-execution` / `runner-accepted`，绑定current benchmark runner output | `config/test-oracles/profile-performance-normal-v1.json` |
| boundary | `GEW-PRO-PERFORMANCE-BOUNDARY-P`, `GEW-PRO-PERFORMANCE-BOUNDARY-R` | `scenario-membership` / `scenario-accepted`，只接受performance exact boundary member | `config/test-oracles/profile-performance-boundary-v1.json` |
| revise | `GEW-PRO-PERFORMANCE-REVISE-P`, `GEW-PRO-PERFORMANCE-REVISE-R` | `revision-lineage` / `revision-accepted`，new body、budget、owner route exact | `config/test-oracles/profile-performance-revise-v1.json` |
| authority | `GEW-PRO-PERFORMANCE-AUTHORITY-P`, `GEW-PRO-PERFORMANCE-AUTHORITY-R` | `authority-decision` / `authority-current`，benchmark factory consumer-local | `config/test-oracles/profile-performance-authority-v1.json` |
| drift | `GEW-PRO-PERFORMANCE-DRIFT-P`, `GEW-PRO-PERFORMANCE-DRIFT-R` | `drift-assessment` / `drift-resolved`，source/environment/current target exact | `config/test-oracles/profile-performance-drift-v1.json` |
| invalidation | `GEW-PRO-PERFORMANCE-INVALIDATION-P`, `GEW-PRO-PERFORMANCE-INVALIDATION-R` | `invalidation-record` / `invalidation-current` | `config/test-oracles/profile-performance-invalidation-v1.json` |
| recovery | `GEW-PRO-PERFORMANCE-RECOVERY-P`, `GEW-PRO-PERFORMANCE-RECOVERY-R` | `recovery-record` / `recovered`，restart只重读，不replay benchmark | `config/test-oracles/profile-performance-recovery-v1.json` |
| artifacts | `GEW-PRO-PERFORMANCE-ARTIFACTS-P`, `GEW-PRO-PERFORMANCE-ARTIFACTS-R` | `artifact-records` / `artifacts-accepted`，包含environment/sample/statistics/correctness refs | `config/test-oracles/profile-performance-artifacts-v1.json` |
| review | `GEW-PRO-PERFORMANCE-REVIEW-P`, `GEW-PRO-PERFORMANCE-REVIEW-R` | `independent-review` / `review-accepted`，reviewed benchmark digests exact | `config/test-oracles/profile-performance-review-v1.json` |
| target | `GEW-PRO-PERFORMANCE-TARGET-P`, `GEW-PRO-PERFORMANCE-TARGET-R` | `target-observation` / `target-matched`，fresh B source/code identity | `config/test-oracles/profile-performance-target-v1.json` |
| rollback | `GEW-PRO-PERFORMANCE-ROLLBACK-P`, `GEW-PRO-PERFORMANCE-ROLLBACK-R` | `action-rollback` / `rollback-verified`，restore A + correctness/noise/rollback ratio | `config/test-oracles/profile-performance-rollback-v1.json` |
| real-e2e | `GEW-PRO-PERFORMANCE-REAL-E2E-P`, `GEW-PRO-PERFORMANCE-REAL-E2E-R` | `real-toolchain-execution` / `real-toolchain-attested`，protected command + parent timing + current statistics | `config/test-oracles/profile-performance-real-e2e-v1.json` |

每个oracle exact绑定`(ORA-PROFILE-PERFORMANCE, performance, mandatory, column_id, full-planned,
task_ids.P/R)`、benchmark registry/case/environment/statistics/correctness digests与column-specific outcome。
cross-profile/column/case/oracle/task/source substitution、same-ID different request、alias/duplicate/reorder或
coherent re-sign在command launch前拒绝。

#### Registry/bootstrap/schema matrix

Profile schema registry exact包含ADR-0007的9组source/input IDs：

| Stem | Source schema | Digest-input schema |
|---|---|---|
| `performance-benchmark-case` | `urn:gew:schema:performance-benchmark-case:1.0.0` | `urn:gew:schema:performance-benchmark-case-input:1.0.0` |
| `performance-benchmark-registry` | `urn:gew:schema:performance-benchmark-registry:1.0.0` | `urn:gew:schema:performance-benchmark-registry-input:1.0.0` |
| `performance-benchmark-installation-bootstrap` | `urn:gew:schema:performance-benchmark-installation-bootstrap:1.0.0` | `urn:gew:schema:performance-benchmark-installation-bootstrap-input:1.0.0` |
| `performance-environment-observation` | `urn:gew:schema:performance-environment-observation:1.0.0` | `urn:gew:schema:performance-environment-observation-input:1.0.0` |
| `performance-correctness-observation` | `urn:gew:schema:performance-correctness-observation:1.0.0` | `urn:gew:schema:performance-correctness-observation-input:1.0.0` |
| `performance-measurement-sample` | `urn:gew:schema:performance-measurement-sample:1.0.0` | `urn:gew:schema:performance-measurement-sample-input:1.0.0` |
| `performance-sample-set-observation` | `urn:gew:schema:performance-sample-set-observation:1.0.0` | `urn:gew:schema:performance-sample-set-observation-input:1.0.0` |
| `performance-statistics-observation` | `urn:gew:schema:performance-statistics-observation:1.0.0` | `urn:gew:schema:performance-statistics-observation-input:1.0.0` |
| `performance-observation` | `urn:gew:schema:performance-observation:1.0.0` | `urn:gew:schema:performance-observation-input:1.0.0` |

canonical source/input schemas必须closed、strict typed、nested self-digest exact；每个input只删除自身derived
digest，parent保留child body/digest。逐contract覆盖missing/extra/null/wrong type、bool-int/float/string alias、
unsorted/duplicate、bad digest pattern、unknown enum、wrong order与coherent child/parent re-sign。bootstrap必须
固定registry、9 pairs、Profile schema registry、command registry/runtime policy/executable/cwd、fixture/sample、
distribution/RECORD/source-build attestation及protected ordered closure。same-path replacement、unpacked RECORD
tamper、archive duplicate/tamper、project/PYTHONPATH shadow或fallback全部在factory issuance前拒绝。

上述9 pairs只计benchmark authority stems；Option B另演进既有category completion assessment contract为exact
1.1 source/input pair，不删除或重签1.0，也不增加task event/storage schema。1.1只接受performance projection，
1.0与所有非performance assessment含该字段均拒绝。

#### Clock, environment, samples and statistics matrix

- launcher必须由existing ActionAdapterFactory签发且`require_attested`通过；foreign/clone/`object.__new__`、
  executable/cwd replacement、request/parameter/result substitution与child extra output均拒绝；
- 用factory-owned monotonic clock在每次`launcher.execute`完整调用立即前后取exact integer start/end；断言
  process startup在窗口内、`end > start`、child只返回expected correctness digest。caller clock、wall-clock、
  persisted timestamps与child elapsed/PASS不能影响duration；
- config warmup为exact nonnegative integer，repetition为bounded odd integer且至少3；warmup result绑定provenance
  但不进入statistics。missing/extra/duplicate/reorder iteration、warmup混入、zero/negative/unsafe duration拒绝；
- baseline/candidate/rollback environment observation覆盖OS/architecture/CPU、Python/distribution/RECORD、command/
  toolchain、fixture root、locale/timezone与safe env projection，body/digest必须exact相同。逐字段remove/replace、
  same values foreign issuer、post-observation change与cross-hardware normalization全部拒绝；
- independent oracle从ordered durations重算sorted vector、odd median、absolute deviations与MAD。逐一攻击caller
  median/MAD、float/rounding、outlier removal、resample-until-pass、wrong ratio/cross-product和coherent statistics
  re-sign；
- exact noise公式为`mad*noise_denominator <= median*noise_numerator`；超限必须
  `inconclusive-noise`且zero P issuance。target/rollback分别用ADR-0007 integer cross-products；correctness
  mismatch即使更快也拒绝；
- R3 exact断言current registry的noise numerator/denominator为`1/2`，且core/source中不存在scenario-specific
  threshold或sample literal。P必须由真实parent `monotonic_ns`围绕完整`launcher.execute`采样并满足noise、
  correctness、target、fresh B与current environment；任何oracle vector注入P都拒绝；
- A `noise-outlier` R必须从oracle 1.1 exact typed `rejection_input.values`读取真正numeric
  `[1,2,100,200,201]`，独立断言sorted
  `[1,2,100,200,201]`、median `100`、deviations `[99,98,0,100,101]`、sorted deviations
  `[0,98,99,100,101]`、MAD `99`及`99*2=198 > 100*1=100`。唯一允许outcome是
  `inconclusive-noise`/fail-closed；不得产生P observation、target PASS或CoverageRecord success；vector不得出现在
  `reject_error_message`，且从message解析/恢复input必须失败；
- issue、每次invocation、final observe、assessment precommit、restart、coverage observer/factory/gate各cut注入
  registry/schema/fixture/sample/source/command/environment/target replacement；要求actual loader/current counters
  增加且task/event/snapshot/object/ref/action/target/input零写；
- DNS resolver、socket connect、proxy、external service与package install调用exact为零；不访问用户repo/secret，
  不增加benchmark dependency。

#### Baseline, target, rollback and real-E2E

P fixture是disposable local Git/project target。先在A source/code identity运行exact baseline sequence；
ActionCoordinator prepared→authorized→GitNativeAdapter expected-ref一次mutation到B；再运行candidate sequence。
两侧exact environment/case/toolchain/fixture/correctness一致，noise通过，candidate target cross-product通过，fresh
target observer证明B。restart从task唯一object ref重读全部samples/results、重算statistics、重验current
installation且benchmark replay count为零。

rollback probe使用existing action-scoped flow恢复exact A；unknown只query/reconcile/owner且不replay。fresh A
target后运行restored sequence，correctness、noise与rollback cross-product全通过才产生rollback PASS；只恢复Git
而measurement不通过必须保留unresolved owner route。

R fixture使用stale expected A、actual C，在native mutation和benchmark launch前拒绝，Git delta、command
launch、action journal/claim、task/category/object/ref增量全部为零；只有exact approved rejection error与before/
after target digests完成后才签发isolated R record。另以negative subtests覆盖noise outlier、correctness
regression、target miss、environment drift、clock substitution与post-observation replacement，不把它们冒充P。

#### Option B durable assessment, precommit and restart matrix

每个performance binding使用其Option C unique task。现有`task.category_assessed` EvidenceRef必须exact为
`evidence_id=assessment_digest`、`evidence_type=category-completion-assessment`、
`source_ref=assessment_object_digest`、`digest=assessment_digest`、`trust=factory-attested`，并唯一指向一个
referenced assessment CAS object。禁止caller自建EvidenceRef、复用另一binding/task的ref或以相同digest别名。

冻结既有category completion assessment 1.0 pair；新增
`urn:gew:schema:category-completion-assessment:1.1.0` /
`urn:gew:schema:category-completion-assessment-input:1.1.0` 的performance-discriminated branch要求exact ordered
`performance_evidence_projection`：

- task/profile/column/revision/snapshot/epoch与GraphRef six pins；
- registry/bootstrap/schema registry、distribution root/version、singular RECORD、protected closure、source/build、
  command/runtime/executable/cwd的installation pins；
- consumer-local factory seal、environment observation与launcher/command/request/session pins；
- ordered A→B→A source observations，generation exact `1,2,3`，previous-digest chain exact；
- baseline/candidate/restored warmup provenance、ordered samples、correctness bodies/digests、statistics bodies/digests；
- noise、target与rollback exact integer cross-products/outcomes，以及final performance observation；
- nested bodies/digests与只排除自身derived field的projection digest。

canonical schema/projection roundtrip通过；非performance assessment含该字段、performance缺失字段、extra/null/
wrong type、bool-int alias、reorder/duplicate、label-only A、同root异bytes、wrong/skip generation、wrong previous、
cross-task/profile/column/factory/session、nested coherent re-sign与CAS digest alias全部拒绝且输入不变。

assessment issuance probe必须证明只消费same-factory current projection seal，并独立重算sample/statistics/
comparisons/final observation。precommit cut matrix覆盖projection publish前、publish后但event commit前、全部hooks后
final reread、DB COMMIT前与commit后：前四类zero task/event/snapshot/reference/action/target write，unreferenced CAS
只由existing doctor回收；commit后EvidenceRef、assessment与内嵌projection同时可见。target/source/environment/
installation/session在每个cut的delete/replace/coherent resign均拒绝。

restart probe从current task唯一EvidenceRef以`require_referenced=true`重读CAS，重算object/assessment/projection/
nested digests、median/MAD/noise及target/rollback products，并重验task revision/snapshot/epoch、profile/column、
GraphRef与all pins。canonical restart重新签发consumer-local use authority且launcher count=`0`；missing/duplicate/
foreign/clone/stale EvidenceRef、CAS delete/replace、A/B/A reorder、current pin drift或same-ID different request均
zero task/object-ref/action/target write。不得新增generic task event、DB/storage schema、GraphRef pin、network或
外部权限；existing CategoryFacts、combined gate、finalize/revoke与abort regression保持GREEN。

#### Gate, lifecycle and verification order

RED先证明registry/clock/environment/statistics/final observation authority、Option B durable assessment与24 plan/12 oracle members缺失；GREEN
顺序为schema/bootstrap → registry/environment/clock → samples/statistics/correctness → durable assessment/use/precommit/restart →
representative NORMAL P/R → REAL-E2E P/R → existing2 methods。Historical pre-E1 Option C曾共享per-Profile
repository/application，但该历史优化不适用于E1/current cumulative；E1严格serial且每binding使用fresh private
repository root及unique task/target/branch-ref/action-root/command-root，benchmark/Git fixture不跨binding/profile共享。

batch后plan exact`194`、oracle bindings`97`、production gate
`194 valid / 80 missing / passed=false`、static`0/274`，不得发行WP-08 exit。combined gate前finalize拒绝；
partial candidate只用exact one-shot abort且无gate decision。combined gate后finalize/revoke与pre-gate abort两条
branch均保持immutable records/durable task/action/target，terminal后benchmark/current/restart/register全部拒绝，
identity/FD回到baseline且<120s自然exit0。验证只运行performance focused、Slice3代表、runner/StructuredCommand/
ActionCoordinator/Git、contracts/source/package/wheel与lint/type/architecture；不跑full/evidence、不改WP08A历史
tuple/gate/evidence。

### 12.3 Migration rehearsal scenario authority

ADR-0002 revision 6只增加四个existing stable scenario pairs，不增加unittest discovery：

| Scenario | Exact IDs | Positive authoritative outcome | Rejection boundary |
|---|---|---|---|
| forward | `GEW-PSC-MIGRATION-FORWARD-P/R` | exact A bundle经唯一transform/import/replay/integrity/compatibility成为更高generation/epoch verified B | wrong transform/source/version、partial B、stale A在任何active switch前拒绝 |
| backward | `GEW-PSC-MIGRATION-BACKWARD-P/R` | B→A作为新migration，generation/epoch/fence继续递增，fresh A target current | old pointer/counter rollback、foreign previous、skipped generation拒绝 |
| partial-data | `GEW-PSC-MIGRATION-PARTIAL-DATA-P/R` | fixture每row exact `preserved|defaulted|rejected|owner-route`，integrity digest current | omit/duplicate/reorder/alias、caller default、silent drop、unknown owner route拒绝 |
| crash-window | `GEW-PSC-MIGRATION-CRASH-WINDOW-P/R` | config全部cut各自恢复完整old A或完整verified new B | mixed object/manifest、`verifying` exposure、claim/fence/restore-gap丢失拒绝 |

四oracles分别是`profile-migration-forward-v1.json`、`profile-migration-backward-v1.json`、
`profile-migration-partial-data-v1.json`与`profile-migration-crash-window-v1.json`；每个exact绑定Profile/scenario/
boundary/full-planned/disposition/result/contract-test/unique task IDs、registry/bootstrap/fixture/transform digest与
scenario-specific outcome。P仍是scenario acceptance；R必须exact expected rejection且task/repository/target/input
zero-write。

schema matrix逐一验证以下7 pairs，full IDs以`urn:gew:schema:`为前缀：

- `migration-rehearsal-fixture-manifest:1.0.0` / `...-input:1.0.0`；
- `migration-rehearsal-transform-manifest:1.0.0` / `...-input:1.0.0`；
- `migration-rehearsal-registry:1.0.0` / `...-input:1.0.0`；
- `migration-rehearsal-installation-bootstrap:1.0.0` / `...-input:1.0.0`；
- `migration-step-observation:1.0.0` / `...-input:1.0.0`；
- `migration-crash-recovery-observation:1.0.0` / `...-input:1.0.0`；
- `migration-rehearsal-observation:1.0.0` / `...-input:1.0.0`。

canonical source/input roundtrip、exact built-in types/order/enums/bounds、nested body/digest、raw/semantic digest、
registry/fixture/transform sorted uniqueness与bootstrap protected pins全部通过；missing/extra/null/bool-int alias、
reorder/duplicate、wrong projection、coherent child/parent re-sign、source/unpacked/archive/RECORD replacement拒绝。

`MigrationRehearsalFactory` attacks覆盖bare/foreign/clone/`object.__new__`、same repository foreign factory、wrong
private root、bundle/manifest/ledger substitution、state omit/reorder、epoch/fence/high-water rollback、transform code/
fixture replacement、partial-data disposition replacement与每个crash cut before/after。执行/观察/assessment/
precommit/restart/gate每个cut都要求current reread；reject前后task event/head/snapshot、CAS referenced count、action/
claim/target、input bytes与active manifest不变。restart从current task唯一assessment ref重读并重算，migration
execution delta=`0`。

category assessment contract新增exact1.2 pair；migration branch只允许`migration_rehearsal_projection`，绑定task/
revision/snapshot/epoch/six pins、installation/registry/fixture/transform、A/B/A manifests、ledger/history、partial rows、
crash results、claims/fences/target及nested digests。dependency branch或dual projection、performance1.1/generic1.0
携带该字段全部拒绝。precommit异常zero durable writes，commit后event/ref/CAS同时可见；无新event/table/schema。

验证顺序：schemas/bootstrap→factory/forward/backward→partial/crash→assessment use/precommit/restart→四P/R
targeted selectors→authoritative combined P。完成后plan`216`、oracles`108`、gate
`216 valid / 58 missing / false`、static`0/274`。Historical pre-E1 Option C的per-Profile repository共享不适用于
E1/current cumulative；E1每binding独占fresh private repository root与unique task/target/branch-ref/action-root/
command-root，并strict serial。combined gate后finalize/revoke，未入gate candidate只走same-cap abort；terminal后所有
rehearsal current/restart/register/gate拒绝、durable state不变、cleanup<120s。不得真实activation、network、
用户repo、WP10、full/evidence。

### 12.4 Dependency graph and unavailable-fix scenario authority

ADR-0006 revision 8保留revision 7 graph/remediation contract并exact增加config-owned cffi transitive binding：

| Scenario | Exact IDs | Positive authoritative outcome | Rejection boundary |
|---|---|---|---|
| transitive dependency | `GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P/R` | exact cffi advisory；root→cryptography→cffi三节点/two-edge physical path、after approved cffi fixed closure、regression/target current | direct packaging substitution、caller advisory/graph、foreign/broken/reordered path或closure mismatch在assessment/observation/record前拒绝 |
| fix unavailable | `GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P/R` | affected reachable node + current explicit `approved-unavailable` row + complete residual row/set + nonempty owner route | missing/expired/wrong advisory disposition、caller owner route或missing-fix inference拒绝 |

oracles exact为`profile-dependency-security-transitive-dependency-v1.json`与
`profile-dependency-security-fix-unavailable-v1.json`，各自绑定P/R unique tasks、advisory/source/graph/remediation/
bootstrap/policy digests、reachability/disposition outcome。它们不能复用vulnerable-graph oracle或只检查scenario
membership。

Historical revision 7新增以下5 schema pairs：

| Stem | Source | Digest input |
|---|---|---|
| graph policy | `urn:gew:schema:dependency-graph-policy-registry:1.0.0` | `urn:gew:schema:dependency-graph-policy-registry-input:1.0.0` |
| closure graph | `urn:gew:schema:dependency-closure-graph-observation:1.0.0` | `urn:gew:schema:dependency-closure-graph-observation-input:1.0.0` |
| remediation dispositions | `urn:gew:schema:dependency-remediation-disposition-registry:1.0.0` | `urn:gew:schema:dependency-remediation-disposition-registry-input:1.0.0` |
| final observation | `urn:gew:schema:dependency-security-observation:1.1.0` | `urn:gew:schema:dependency-security-observation-input:1.1.0` |
| installation bootstrap | `urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0` | `urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0` |

Historical existing10/new5/profile-schema registry exact equality；bootstrap1.1固定两个新增registry、advisory registry、schemas、
distribution/RECORD/source-build/protected closure。schema attacks覆盖1.0/1.1 cross-use、missing/extra/reorder/
duplicate/alias、bad digest、nested omission及coherent all-document re-sign。

revision 8 exact只增加第6组bootstrap1.2 source/input pair；revision 7五组加本组累计六组，不允许no-new-schema
解释或第七组隐式pair。1.2 history rows必须分别使用无alias的
`config/security/dependency-advisory-registry-v1.json`与
`config/security/dependency-advisory-registry-v2.json`并双向绑定v1/v2 snapshot+attestation。
Current A仍以bootstrap1.2为dependency current authority；historical bootstrap1.1 bytes/digest保持不变，A只补齐
Envelope、source/package与wheel/RECORD的current pin闭包。

graph positive从physical closure每个exact METADATA requirement row重建root/nodes/edges；逐项验证normalized
name/version、wheel/METADATA/RECORD、parent/child、original/normalized specifier/extras/marker与fixed marker
environment。closure/path双向exact，direct/transitive不可label替代。attacks覆盖missing/extra/reordered edge、wrong
parent、duplicate/cycle alias、marker/env substitution、caller graph/list、only-set comparison、foreign/clone/stale
factory及post-observation METADATA/RECORD replacement。

revision 8 R2 registry fixture先关闭stable finding `WP08-DEP-OPTION1-DOCS-ARCH-R1-001`：generation-1 registry、
offline-v1 artifact/attestation/bootstrap/schema bytes与digests必须保持baseline exact；generation-2 forward head新增
`source:dependency-advisory:offline-v2@1`、v2 full snapshot与matching attestation。断言v1 source和packaging revision 1
为superseded/status-generation 2，v2 source、packaging revision 2与`advisory:cffi:security-v1@1`为active/
status-generation 2；每个active advisory exact解析到active/time-valid v2 source完整row与v2 artifact/attestation，
v2 snapshot identity set exact为packaging revision 2+cffi revision 1。source/advisory/high-water identity sets必须
双向exact，错误genesis/wrong previous、old-source omission、mixed/delta snapshot、artifact-attestation cross-pair、
history omission/reorder/replacement、same-path replacement及coherent registry/bootstrap re-sign全部在issuance前
fail closed且task/action/target/input writes=0。cffi advisory exact断言affected `>=2.0.0,<3.0.0`、fixed closure
`closure:cffi:2.0.0`、唯一`cffi==2.0.0` pin及冻结wheel/RECORD hashes；before affected和after fixed closure
分别取证，phase/closure bytes/digest不得因相同版本折叠。

bootstrap/schema positive必须通过bootstrap1.2与source/input1.2 pair验证closed ordered history exact为gen1
registry↔v1 artifact/attestation及gen2
registry↔v2 full snapshot/attestation，current row=2，并逐项匹配member path、source ID/revision、artifact/
attestation/registry raw与semantic digests。source/package protected lists和wheel RECORD必须同时包含两代registry、
artifacts、attestations、bootstrap/schema历史；逐一删除或交换任一member都在factory construction前拒绝。

transitive P的ordered node IDs exact为`distribution:graph-engineering-workflow@0.1.0`、
`distribution:cryptography@50.0.0`、`distribution:cffi@2.0.0`；edge rows exact对应root
`cryptography==50.0.0`与cryptography `cffi>=2.0.0`。正向断言path length=3、edges=2、selected advisory=cffi，
且after graph/applicability/fixed closure/regression/fresh target全部current。负向逐一替换为existing packaging direct
path、raw/normalized advisory alias、caller advisory/graph、two-node threshold、missing/duplicate/reordered edge、wrong
parent或phase/pin mismatch；每例都在assessment、observation、CoverageRecord计数前失败，task/event/snapshot/object/
ref/action/target/input bytes与mutation counters保持零增量。

remediation positive只接受same-advisory/revision current/time-valid registry row；`approved-unavailable`必须explicit
reason/residual policy/owner route。empty fixed closures、unknown package、command failure、network absence或missing row
均保持unavailable=false。attacks覆盖wrong status/generation/advisory/source、expired disposition、foreign/clone owner、
residual omission/route substitution、registry coherent re-sign与after-observation replacement。

assessment1.2 dependency branch只允许`dependency_graph_projection`，保存task/six pins、factory/advisory/bootstrap/
graph/remediation registry、before/after closures、complete nodes/edges/path、disposition/residual rows/owner route、
regression/action/target与nested digests。issue/precommit/restart/gate重新byte-pipe读取和重建；restart graph/action
replay=`0`。所有拒绝task/event/snapshot/object/ref/action/Git/target/input零写，DNS/socket/proxy/index/scanner
call=`0`。

restart/currentness matrix还必须在fresh attestation root验证generation-2 advisory/high-water/v2 snapshot+
attestation/bootstrap history、unique
transitive task CAS ref、before/after graph与final observation的object identity/current projection。重启不得复用
old factory/token/cache，不得产生resolver/action replay或网络；source/high-water、advisory selection、path、fixed
closure或target任一post-observation replacement均使旧execution/observation/record fail closed且durable signatures不变。

验证顺序：new schemas/registries/bootstrap→graph construction/currentness→remediation disposition→assessment/
restart→transitive P/R→fix-unavailable P/R→combined P。migration batch后加入四records，plan`220`、oracles`110`、
gate`220 valid / 54 missing / false`、static`0/274`；coverage lifecycle/finalize/revoke/abort与<120s teardown不变。
不安装/激活dependency，不访问用户repo，不运行online resolver/scanner，不改WP08A historical evidence。

### 12.5 Remaining54 P1 performance scenarios

先在existing discovered WP-08 tests中加入四stable IDs与两个oracle members的absence RED，断言production plan仍
220/110。GREEN复用ADR-0007现有authority，只新增Human-approved oracle input 1.1 schema、不新增registry/action；
threshold/sample仍只来自config/oracle：

| Scenario | P assertions | R/attack assertions |
|---|---|---|
| `noise-outlier` | parent `monotonic_ns`真实测量每次完整`StructuredCommand`（含startup），全部odd repetitions保留；independent重算后baseline/candidate满足config `1/2`，correctness/target/fresh B/current environment全部通过；P拒绝任何`rejection_input`替代 | 从oracle 1.1 typed `rejection_input.values`取numeric `[1,2,100,200,201]`；median100、MAD99、`99*2 > 100*1`必须得`inconclusive-noise`且无PASS issuance；message encoding/parsing、drop/reorder/duplicate/resample、warmup混入、threshold替换、vector注入P、float/rounding、caller MAD/outcome、coherent re-sign全部拒绝 |
| `correctness-regression` | 同environment/case中candidate全部invocation correctness exact，noise/target/fresh B通过 | 任一candidate mismatch在statistics/target success前fail closed；expected digest替换、忽略iteration、duration-only、wrong phase/case、caller correct、coherent re-sign全部拒绝 |

每对另测P/R task/request/observation identity分离、cross-scenario substitution、foreign/clone/stale factory、source/
environment/target post-observation replacement；restart launcher invocation delta=0。每次拒绝task/event/snapshot/object/
ref/action/target/input零写，network=0。P1 focused selector在fresh source-attested root strict serial运行；完成后plan224/
oracle112/gate`224 valid,50 missing,false`，static-only仍0/274。

#### Oracle input 1.0/1.1 and cascade contract

1. 固定1.0 schema pre-A raw SHA-256并断言文件byte-identical、registry row unchanged、existing 1.0 oracle digests不变；
2. 1.1 schema必须closed：top-level exact fields为1.0 digest input fields加required `rejection_input`；该object exact
   `kind,values`，kind仅`integer-vector`，values non-empty ordered positive safe JSON integers。逐项拒绝stringified array、
   CSV/JSON message、boolean、float、zero、negative、unsafe integer、null、object、nested array、missing/extra fields；
3. 1.1 current conditional tuple exact为performance/noise-outlier/scenario/boundary及对应oracle/case IDs；其他tuple、
   1.0带`rejection_input`、1.1缺field、cross-version schema/digest projection全部拒绝；
4. core tests证明只按1.0/1.1 version执行exact field/schema/digest/safe-integer验证，且没有`performance` scenario
   dispatch、`[1,2,100,200,201]`或`1/2` literals；`PROFILE_DOMAIN_SCHEMA_IDS` registry构造必须接受exact 1.0+1.1
   schema IDs，并分别拒绝missing 1.1、extra ID和1.1 version alias；application tests证明只有noise-outlier R消费vector并
   重算，P仍只消费actual parent timing；
5. `reject_error_message`只断言stable diagnostic；把vector塞入message、删除typed field后靠message恢复、同时提供冲突
   message/vector或coherent re-sign均fail closed且zero writes；
6. exact source/package cascade tests依次验证new schema→profile domain/schema registries→generic core/source checkout→
   `config/verification/wp-00-targets.json` exact set→source manifest→noise oracle→oracle manifest/coverage plan/application→
   performance bootstrap、dependency current v1.2、migration current v1→pyproject→wheel archive/unpacked/RECORD。
   `source_manifest` positive必须接受更新后的exact target set并包含1.1 schema path/bytes/digest；missing 1.1、extra target与
   version-alias path均拒绝。每层raw/semantic/nested/protected-closure digest均重算；dependency v1.1和oracle schema1.0
   pre-A bytes必须不变。

#### Historical Human-approved B action provenance and P1 sibling contract

1. Envelope必须exact165 unique relative/no-glob；相对Historical A exact164仅新增
   `config/actions/action-policy-v1.json`，删除该唯一B项必须exact恢复164；builder仍不在allowlist，任何第166项拒绝；
2. controlled P2 packaged-source addition必须改变final `pyproject.toml` builtin action implementation build projection和
   affected implementation digests。测试冻结final upstream projection一次，并断言downstream profile/package pin fields
   被projection排除；若downstream digest反馈上游、需要fixed-point或第二次改变upstream digest则失败；
3. 从builtin refs/module bytes/build projection重算全部implementation digests；
   `config/contracts/action-adapter-registry-v1.json`必须exact匹配，逐项拒绝
   stale/missing/extra implementation row、wrong ref/module、old build digest、reorder/duplicate和coherent partial re-sign；
4. `config/actions/concrete-action-policy-v1.json`必须绑定current adapter registry ID/digest及closed adapter/operation sets。
   default `config/actions/action-policy-v1.json`与local
   `config/actions/action-policy-local-actions-v1.json`必须分别绑定同一current concrete/registry authority并
   各自重算self digest；两policy互不互引，拒绝cross-policy digest、旧pin、capability/operation/action-kind变化或额外edge；
5. `config/security/security-runtime-local-actions-v1.json`只按既有语义绑定local policy current ID/digest。保留default
   policy旧pin的negative fixture必须让P1
   verified child在installation/currentness gate fail closed且零benchmark/action/target write；测试不得通过skip factory、
   remove/relax pin、caller override、ambient checkout、alias或fake coherent chain获得PASS；
6. source/package positive按拓扑验证`core/graph_engineering/__init__.py`、source checkout、test attestation、wp-00 exact set、
   performance/dependency-v1.2/migration/scenario-truth/release-operations current bootstraps、pyproject package/resource pins、
   read-only builder digest、wheel archive/unpacked resources与`RECORD`。每层source/resource/raw hash/size/semantic/nested digest
   正向重算并反向exact；stale/omit/extra/reorder、只正向、archive/installed mismatch全部拒绝；
7. action semantics regression必须证明B前后adapter IDs、capabilities、operation IDs、policy action kinds、external-action gates、
   P1/P2 expected outcomes均不变；oracle input1.0、dependency bootstrap1.1及其它historical no-change files保持pre-B bytes；
8. P2a packaged sources恢复并冻结后，测试强制事件顺序为B chain re-sign完成→P1 currentness sibling rerun PASS→P2a
   scenario issuance。省略、交换、复用pre-B P1结果或P1仍fail时继续P2a均拒绝且P2a records保持missing。

#### Historical Human-approved C dual-runtime and P1 sibling contract

1. Envelope必须exact166 unique relative/no-glob；相对Historical B exact165只新增
   `config/security/security-runtime-v1.json`，删除该唯一C项必须exact恢复165，任何第167项拒绝；
2. exact graph shared prefix必须是`pyproject.toml` builtin implementation provenance→
   `config/contracts/action-adapter-registry-v1.json`→`config/actions/concrete-action-policy-v1.json`，随后default branch
   必须是`config/actions/action-policy-v1.json`→`config/security/security-runtime-v1.json`，local branch必须是
   `config/actions/action-policy-local-actions-v1.json`→`config/security/security-runtime-local-actions-v1.json`；
3. 两runtime分别重算并验证current policy ID/digest/self digest；测试逐项拒绝default/local runtime互换、cross-policy pin、
   runtime互引、旧policy digest、missing/extra edge、cycle、fixed-point、caller override及coherent partial re-sign；
4. default policy已重签而default runtime仍保留旧pin的negative fixture必须让`scripts/evidence_utils.py` currentness与P1
   verified child在任何evidence/benchmark/action/target write前fail closed；不得通过skip factory、remove/relax pin、
   ambient checkout或consumer rewrite取得PASS；
5. `scripts/evidence_utils.py`必须保持read-only consumer：验证它加载default runtime并exact核验default-policy ID/digest，
   同时断言该path不在166项allowlist、实施diff中未修改且在C当时无法成为第167项。`scripts/build_backend.py`同样保持只读且不在
   allowlist；
6. 两runtime current后，source/package positive必须把两个分支都纳入source checkout、wp-00 exact set、performance、
   dependency-v1.2、migration、scenario-truth、release-operations current bootstraps、pyproject package/resource pins、
   read-only builder、wheel archive/unpacked resources与`RECORD`。逐层正向重算且反向exact校验source/resource/raw
   SHA-256/size/semantic/nested/RECORD binding；stale/omit/extra/reorder或single-direction-only均拒绝；
7. 事件顺序必须是P2a packaged sources恢复并冻结→shared prefix及两policy重签→两runtime拓扑重签→
   `evidence_utils` currentness PASS→P1 currentness sibling PASS→P2a scenario issuance。省略、交换或复用pre-C结果均拒绝；
8. regression证明C只关闭`GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001`，不改变adapter IDs、capabilities、
   operation IDs、policy action kinds、external-action gates、P1/P2 expected outcomes或历史bytes；无pin bypass/weakening。

#### Historical Human-approved D WP07A exact build baseline contract

1. Historical D revision的Envelope必须exact167 unique relative/no-glob；相对Historical C exact166只新增
   `tests/security/test_wp07a_action_contract_security.py`，删除该唯一D项必须exact恢复166，且D revision拒绝第168项；
2. 先保存D前失败证据：获批P2a sources/`pyproject.toml`、C action chain、factory/WP08 currentness、package/wheel均current，
   扩大security run exact 17/18 PASS，唯一失败为
   `WP07AActionContractSecurityTests.test_gew_act_001b_installation_anchor_rejects_re_signed_registry_and_provenance_substitutions`
   仍期待`b9e8e75bca0436651a723da05d9bcea27f06768666c8c1d9f9fc6b9b80707944`；
3. 用与runtime-under-test分离的mechanical projection重算current `pyproject.toml`完整SHA-256，并只把该预计算literal替换
   historical expected。diff必须证明该WP07A文件除exact constant外byte-identical，implementation/config/其它tests无D change；
4. 禁止让assertion用同一次`_action_build_manifest_digest`调用派生expected、接受ambient/caller value、只比prefix、loose
   compare或skip/delete baseline assertion；这些negative mutations必须被meta-test或source inspection拒绝；
5. named method必须继续执行并通过dependency add/replace/remove、declared-import add/replace/remove、build-mapping change、
   entrypoint change及registry implementation/capability/operation/provenance substitution attacks，不能删case或放宽exception；
6. 严格顺序执行named WP07A method→WP08 security→evidence currentness→package/archive/unpacked/`RECORD`→clean wheel→
   P1 currentness sibling；任一失败即不得运行`p2a-cumulative-r2`。全部通过后才恢复该cumulative selector；
7. `p2a-cumulative-r2`必须保持P2a exact plan226/oracle113/dynamic `226 valid / 48 missing / passed=false`，static-only
   `0 valid / 274 missing / passed=false`；D不能新增、删除、替换或waive任何CoverageRecord/oracle；
8. `GEW-REMAINING54-P2A-CAND-R1-001` full installed closure、`GEW-REMAINING54-P2A-CAND-R1-002` exact task
   namespace/branch/ref、`GEW-REMAINING54-P2A-CAND-R1-003` generic assertion evaluator/`required_fact_ids`、
   `GEW-REMAINING54-P2A-CAND-R1-004` executable cumulative selector counts、
   `GEW-REMAINING54-P2A-CAND-R1-005` R task/factory/root attack binding全部保持OPEN；001/002/003/005 focused GREEN只作为
   新review输入，004等待本D与cumulative-r2。仅独立Candidate reviewer的fresh verdict可关闭这些stable IDs。

#### Historical E1 sealed/quiescent/reopen contract retained by F1

1. Historical E1 revision的Envelope为exact167 unique relative/no-glob，E1新增target count exact0；D仍是相对C唯一新增
   `tests/security/test_wp07a_action_contract_security.py`，删除D恢复166，且E1 revision拒绝第168项；Current F1另增一个
   dependency-security application source形成exact168；
2. RED使用valid current API而非人工leak：执行代表binding的current execution/observation与现有close路径，证明stale context
   拒绝但live handles未被逐binding释放；扩大到226时deterministic active-handle/lifecycle counters单调累积。保存trigger
   evidence：first cumulative 4.086s C provenance fail-closed后修复；second exact7200s `TimeoutExpired`无receipt；FD4→885/
   maxRSS7.20GB/teardown FD4；same-root plan0.546s/base7.801s/authorities4.904s/observations226.608s/
   factory1.085ms/issuance114.974s/dynamic>545.166s/timeout900s；
3. unit state-machine tests断言exact transitions `OPEN→SEALED(g)→QUIESCED(g)→REOPENED(g,purpose)→SEALED(g+1)→
   QUIESCED(g+1)`，purpose exact为issue/use/precommit/gate，finalize/revoke只到`PERMANENTLY_CLOSED`。missing transition、
   wrong purpose、old generation、double/out-of-order/terminal transition均拒绝；
4. seal tests验证process-local opaque identity，不存在dict/JSON/pickle/export/reconstruct API；caller mapping、copy/deepcopy、
   forged object、clone、share、serialized bytes、other process token、old/replayed seal均拒绝。seal exact绑定current
   installation/provenance/source/package/wheel/`RECORD`、runtime-attested root identity、task/object/target/action/command状态、
   record/observation digests及profile/scenario/oracle identity；core/source scan不得含机器absolute root path；
5. quiesce正向逐类证明repository/object/action/Git/launcher/session handles与live FD关闭、deterministic active handle count=0，
   private-root bytes/hash与root identity保持；不得通过删除/复制/recreate root假装释放。FD baseline-return作为diagnostic，
   不把FD4/885或7.20GB写成engine threshold；
6. runtime-owned reopen port每次只打开seal绑定的same root，同一时刻`active_reopened_binding_count`只允许0或1。每个
   issue/use/precommit/gate在业务验证前都全量重读closure/state，phase结束必须生成下一generation、撤销旧seal并quiesce。
   并发barrier测试证明第二binding不能同时reopen，释放后可有限继续，无deadlock或共享repository；
7. 226-binding positive按strict serial执行execute→seal/quiesce→lazy reopen issue→requiesce→reopen use→requiesce→
   reopen precommit→requiesce→reopen gate→requiesce。断言113 oracle identities unique/current、P1 sibling current、dynamic
   `226 valid / 48 missing / passed=false`、static `0 valid / 274 missing / passed=false`。机械构造repository-root、task、
   target、branch/ref、action-root、command-root六个identity集合并分别断言cardinality exact226；六维combined binding tuple
   cardinality也须exact226，任意两个bindings（包括跨Profile）在每一维均不得共享identity；action/mutation/launcher replay=0；
8. tamper matrix逐项覆盖root/installation/provenance/source/package/wheel/RECORD/task/object/target/action/command/record/
   observation same-path/coherent replacement、wrong root/ref、missing/extra、symlink、cross-binding/profile seal/root。
   所有attack必须先于issue/use/precommit/gate write失败，task/event/snapshot/object/ref/action/target/input mutation与replay均0；
9. replay/concurrency matrix覆盖reopen同一seal两次、concurrent reopen两个bindings、purpose reorder、reopen后不quiesce、
   prior-generation replay、action/mutation/launcher replay及finalize/revoke后reopen；全部fail closed并回到handle baseline；
10. resource acceptance只使用deterministic lifecycle/active-handle counters与FD baseline-return诊断。total runtime与heartbeat
    limit来自`config/profiles/scenario-truth-policy-registry-v1.json` testability data；测试必须证明提高limit不能替代RED→GREEN，
    engine不得硬编码机器RSS/FD阈值；
11. exact affected selectors覆盖`tests/unit/test_wp08_scenario_truth.py`、
    `tests/contract/test_wp08_remaining54_contracts.py`、`tests/integration/test_wp08_scenario_truth.py`、
    `tests/integration/test_wp08_release_coverage.py`与`tests/security/test_wp08_remaining54_authority.py`，并重跑source/package/
    installed wheel currentness。D的WP07A→WP08 security/evidence/package/wheel/P1顺序必须先完成；
12. 五个Candidate findings继续OPEN，001/002/003/005 focused GREEN仅作fresh inputs；
    `GEW-REMAINING54-P2A-CAND-R1-004`须增加E1 lifecycle/counters/226 cumulative evidence。只有独立Candidate reviewer可关闭。
13. stable finding `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001`在本author artifact中只标记
    **ADDRESSED / pending independent reviewer resolution**；测试/author不得标记resolved或closed。

#### Current Human-approved F1 dependency-security rehydrate/current-seal contract

1. Envelope必须current exact168 unique relative/no-glob；F1相对Historical E1 exact167只新增
   `application/graph_engineering/application/dependency_security.py`，删除F1项恢复167，任何第169项拒绝；
2. generic typed seal/reopen authority由product/runtime owner拥有且opaque、process-local，并覆盖existing exact
   `DependencySecurityObservation` 1.0与1.1。factory必须从current issued observation机械提取descriptor与immutable snapshot；
   1.0当且仅当source factory `_graph is None`，1.1当且仅当`_graph`为same-binding exact
   `DependencyGraphObservationFactory`；quiesced state不持有live repository/category；
   caller mapping/bytes/equality不能构造seal或current authority；
3. `DependencySecurityObservationFactory`、typed observation与downstream graph/category assessment必须类型和identity分离。
   1.1 seal必须从issued frozen graph inputs保存唯一advisory selector、graph policy/remediation/installation、before/after graph及
   disposition bodies；rehydrate用fresh registry/physical closures/applicability/residual与fresh graph factory重算，执行
   `from_graph_authorities`→`observe_graph`并全投影exact compare后才原子`LIVE`。`DependencyGraphAssessmentFactory`/Evidence仍是
   distinct downstream consumer，不能替代ObservationFactory、Observation、seal或issuer；same-path/slot-tamper继续由
   strict source-seal negatives fail closed，不新增target或security exception；
4. P/R正向均绑定same private root/task/category/current installed closure。每次issue/use/precommit/gate都按fresh registry→
   physical closure parser reread→applicability/residual→generic observe顺序exact比较后才签发下一current seal；resolver/network
   count必须exact0，但physical closure reread count必须存在且不能被0次resolver断言替代；
5. P↔R、forged/cloned/serialized/stale seal、wrong factory/observation、cross-root/task/category/installation、same-path/
   coherent replacement、missing/extra closure、finalize/revoke后rehydrate全部fail closed；task/event/snapshot/object/ref/action/
   target/input zero-write、zero-mutation、resolver/network/action/command replay exact0；
6. source/currentness必须断言new application source属于`core/graph_engineering/__init__.py::_SOURCE_FILES`与
   source-checkout attestation exact set，并由`pyproject.toml` package/protected-source mapping进入archive/unpacked wheel与
   `RECORD`；dependency bootstrap1.2不含application source protected-member字段，只对其actual
   schema/registry/source-artifact/source-attestation/history inputs验真且输入不变时bytes/digest不变；performance bootstrap
   只在其actual protected files（含`application/graph_engineering/application/profile_coverage.py`）变化时重算；pyproject、
   C双runtime与D baseline均验证currentness，但只有对应actual projection变化才重签。action build projection剔除
   dependency-advisory/performance-benchmark tables；测试不得强制制造C/D hash变化，也不得接受任何真实stale pin；
7. 校验当前 config-owned `cumulative_runtime_limit_seconds=14400`、`heartbeat_interval_seconds=60` 与2026-09-10 Human批准一致；旧agent-only86400不获追认；
   提高limit不得替代seal/quiesce/reopen、four-phase reread、exclusive reopen、active-handle归零或zero-replay gate；
8. **Agent audit assertion（无Human authority effect）：**index25只由plan顺序+stack context推定且没有完整last-binding日志；
   evidence/report不得称其为direct observation。`tests/support/wp08_dependency_security.py`与
   `tests/support/wp08_migration_rehearsal.py`是pre-existing dirty且未授权，本轮diff必须不包含它们。
9. Routine finding `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001`只由independent reviewer决定是否resolved；author artifact
   必须保持**ADDRESSED / pending independent reviewer resolution**，并机械证明Envelope仍byte-identical exact168。
10. 原mandatory/scenario/real-E2E candidates、scenario/plan/oracle不得因rehydrate实现而变化；特别机械断言
    `GEW-PRO-DEPENDENCY-SECURITY-ARTIFACTS-R`仍选择`GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P`，且
    `request_digest`保持`sha256-jcs-v1:e9315eb7ced2072939c95533b7f8aeb53e11e1e1c137d5e462c69c5130a9b938`；
    substitute candidate/digest必须拒绝。既有`_task_projection` profile/category/task revision/snapshot/invalidation
    discriminator与schemas/graph contract不放宽。
11. Routine finding `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002`只由independent reviewer决定是否resolved；author
    artifact保持**ADDRESSED / pending independent reviewer resolution**且`authority_effect=none`。

### 12.6 Remaining54 P2 local scenario truth

#### Schema/config/factory RED→GREEN

先为ADR-0008 exact 5 schema pairs、policy/fixture/bootstrap与assessment1.3建立contract tests。正向验证所有nested
digests、protected paths/raw hashes、Profile/scenario exact sets、task/six pins；反向逐一覆盖missing/extra/reorder/
duplicate/alias、unknown row、same-path replacement、coherent re-sign、RECORD/archive/unpacked/source mismatch。factory
construction前失败，durable与target零写。

authority tests覆盖consumer-local `eq=False` identity、foreign/clone/`object.__new__`、cross-task/profile/scenario、
closed factory、old token与non-serializable authority。每binding fresh private root/branch/ref/targets；symlink escape、target
alias、共享mutable root、wrong expected ref与branch substitution在mutation前拒绝。

assessment1.3 tests断言只存在`scenario_truth_projection`，不与1.1/1.2 projections并存；generic/unsupported Profile/
mandatory column使用1.3均拒绝。issue/precommit hooks后重算policy/fixture/branch/target/nested body；crash-before-commit最多
留下unreferenced CAS，不写task event/ref；restart从唯一current referenced CAS+fresh factory恢复，mutation/action replay=0。

#### Exact P2 scenario matrix

| Profile/scenario | Positive oracle | Required rejection vectors |
|---|---|---|
| new-feature / multi-target | two exact roles各自A→B、acceptance/regression/fresh target全通过 | missing/extra/alias role、one-target-only、cross-branch、partial success、stale/wrong rollback |
| hotfix / emergency-baseline | emergency authority+impact/containment+A baseline均早于patch，B minimal且rollback-ready | late/missing/B baseline、authority stale、impact/rollback omission |
| hotfix / production-like-gate | local-production-like fixture完整impact/health/rollback gate通过 | production flag提升、自报health、gate omission、environment/target alias |
| refactor / behavior-characterization | ordered A/B output/error/side-effect vectors exact | case omit/add/reorder、expected alias、behavior delta |
| refactor / architecture-invariant | behavior先通过，B required/forbidden edges exact | forbidden/missing edge、path alias、count/set-only比较、skip behavior |
| refactor / nonfunctional-target | behavior通过且config integer comparator满足、fresh B | hardcoded/float threshold、environment drift、metric miss、behavior regression |
| incident / detection | injected signal与impact scope exact | missing/stale/wrong signal、scope/severity substitution |
| incident / containment | affected隔离、unaffected byte-exact、residual+owner current | over/under containment、unaffected mutation、authority/fence/target stale |
| incident / recovery | known+contained effect经authorized compensation和fresh service verify恢复 | unknown/uncontained、original action replay、partial/stale service、follow-up omission |
| incident / unknown-effects | inner exact=`blocked-owner-route`、unknown claim保留、no replay/recovery/service-restored | replay/recovery、consume claim、empty/foreign owner、fabricated restored state |

`unknown-effects` P的outer result仅证明correct block；test必须显式断言没有incident completion/recovery success。
incident scenario recovery oracle file exact为`profile-incident-response-scenario-recovery-v1.json`，并做mandatory recovery
member byte-identical unchanged/dual-path no-alias test。

四个selectors依次运行，数量门逐步断言226/113/48、230/115/44、236/118/38、244/122/30。每批前做RED，批后做
source/package/currentness与previous-record regression；不得并行运行mutable target，不得为通过修改Support Matrix。

### 12.7 Remaining54 P3 offline release operations

#### Schema, artifact and simulator contract

先对ADR-0009 exact 8 schema pairs、policy/fixture/bootstrap、assessment1.4与adapter registration做RED。artifact positive
从current installed wheel bytes重算raw hash/size/RECORD/source/build/protected closure；negative覆盖label-only、wrong
RECORD/source/build、member omit/add/reorder、same-path replacement与coherent re-sign。

local simulator contract tests只允许private-root apply/query/restore。验证stage write、durability、active pointer CAS、
generation与manifest一致；path escape/symlink/user root、unknown operation、foreign claim/fence/receipt、wrong generation/
artifact在mutation前拒绝。DNS/socket/proxy/HTTP/subprocess probe exact=0。

fault matrix在`before-stage-write`, `after-stage-durable`, `before-active-switch`, `after-active-switch-durable`,
`before-health-observe`逐点crash/return-loss。query只接受完整A、staged-B+active-A、active-B；mixed/corrupt拒绝。unknown
不replay apply；same claim query/reconcile后才能authorized restore，fresh artifact+health exact A。每cut断言journal/claim/
receipt与target mutation delta，重复query/reconcile/restore按现有idempotency contract。

assessment1.4仅release-operations使用且只带`release_operations_projection`。precommit hooks后final query/health；restart
用fresh factory从唯一referenced CAS重验，apply/restore replay=0，允许只读query/health。foreign/clone/stale、CAS/config/
artifact/target replacement均fail closed且durable/target不再变化。

#### Mandatory24 and scenario30

mandatory 12 columns × P/R各自unique task。每列继续断言existing typed evidence rules，并加release policy/artifact/target
currentness。recovery/rollback必须same claim/receipt+restored A；real-E2E P实际执行一次local apply/query/health且mutation
delta=1，R wrong expected generation在apply前delta=0。所有evidence标记`authoritative-local-release-simulator`，assert
`production/staging/released` promotion path不存在。完成门exact为268/134/6 missing。

scenario test：artifact-provenance闭合installed bytes；health-gate只接受active-B后的完整local predicates；partial-deploy
先证明不能完成release，再query/reconcile/restore A+fresh health，outer P只表示处理正确。R逐一覆盖caller digest/PASS、
stale health、predicate subset、staged-as-active、apply replay、wrong claim/generation、missing rollback authority、partial
restore与 fabricated success。完成后plan274/oracle137。

#### Final Candidate sequence

先执行build-authority/resource closure gate：Envelope必须current exact168 unique relative/no-glob targets。Historical A相对
historical159只新增Spec列出的五项并形成164；Historical B只新增`config/actions/action-policy-v1.json`并形成165；
Historical C只新增`config/security/security-runtime-v1.json`并形成166；Historical D只新增
`tests/security/test_wp07a_action_contract_security.py`并形成167；Historical E1不新增target并保持167，删除D项仍
exact恢复166，且D/E1 revisions未授权第168项。Current F1只新增dependency-security application source形成168；删除F1
恢复167，任何第169项拒绝。1.0 schema与
dependency v1.1 pre-A raw hashes保持不变；
dependency current v1.2和migration current v1 pins必须更新。验证1.1 schema/oracle→
`core/graph_engineering/core/profiles.py`的profile domain registry→profile schema registry→generic core/source checkout→
`config/verification/wp-00-targets.json` exact set/source manifest→oracle manifest/plan/application→performance/dependency/
migration current bootstraps→`pyproject.toml`对27 oracle
vectors、13 schema pairs、新1.1 input schema及相关resources的选择→只读builder current raw digest→wheel archive/unpacked/
RECORD完整级联与双向exact。分别注入stale/missing/extra/reorder、version alias、message-encoded vector、
schema/oracle/bootstrap/pyproject/builder replacement、archive/unpacked mismatch及checkout fallback，全部必须在factory/
record issuance前拒绝。

随后验证C graph：final P2 packaged sources/pyproject builtin build projection→adapter registry→concrete policy→
default policy→default runtime，以及local policy→local runtime；两runtime再进入source/wp-00/all current bootstraps→
pyproject package pins→read-only builder→wheel/RECORD。default old-runtime-pin negative必须同时复现`evidence_utils`
currentness与P1 verified child正确fail-closed；两runtime整链重签后必须先通过`evidence_utils` currentness，再复跑P1
currentness sibling PASS，之后才允许P2a继续。任意pin bypass/weakening、digest cycle、extra edge、stale intermediate或
single-direction-only验证均失败。`scripts/evidence_utils.py`与`scripts/build_backend.py`明确不在allowlist且不得修改。

然后执行D exact baseline repair及上述WP07A→WP08 security/evidence/package/wheel/P1 sibling序列；只在全部PASS后进入
E1 RED→state machine/typed port→runtime adapter→226 lazy-reopen GREEN与negative/resource gates。E1全部PASS后才运行
`p2a-cumulative-r2`，并把五个OPEN Candidate findings与fresh evidence提交独立review。不得由本author自行关闭finding、
复用D前17/18结果代替fresh 18/18、复用pre-E1 contexts或提高timeout掩盖resource lifecycle失败。

在fresh source-attested root严格串行生成274 distinct records，检查274 unique task IDs、137 independent oracle identities、
all current。dynamic gate exact `274 valid / 0 missing / passed=true`，invalid/stale/duplicate为空；static-only candidate
exact `0 valid / 274 missing / passed=false`。随后测试gate-consumed finalize/revoke、pre-gate abort、foreign/clone decision、
terminal拒绝、immutable records与durable signatures不变，method `OK`后120秒内自然退出。

最后依次运行affected unit/contract/integration/security/E2E、existing migration/dependency/performance selectors、package
resources、clean installed wheel、lint、type与architecture scan；全部strict serial、stop-on-first、无network、无用户repo、
无真实deploy/release、无WP-10、无DB/GraphRef变化。独立Candidate reviewer必须重哈希exact source manifest并返回zero
open findings，才可报告可逆交付完成；commit/push/merge/deploy/release仍需另行授权。

## 13. Risk Paths 与组合覆盖

- `full-planned`：完整 artifacts/loops/evidence；
- `compact-planned`：减少可选表达但不减少 authority/digest/review/verification；
- emergency：压缩时间与文档表现，保留 intent、action authority、unknown recovery、rollback。

每 runtime 至少完整完成一个 `full-planned`、`compact-planned`、`emergency`；这些可以与九类 real E2E 配对。pairwise
组合仅减少重复执行，不减少每类 12 个 mandatory case。冻结 coverage manifest 由
ReleaseCoverageGate 逐项读取，missing/stale/digest mismatch 即 FAIL。

## 14. Packaging、Upgrade 与 Supply Chain

`GEW-PKG-001～100` 覆盖：

- build wheel 内容/namespace/import boundary，仓库内外与 decoy packages；
- exact interpreter/wheelhouse/dependency hashes/provenance/SBOM/license/vulnerability checks；
- clean macOS/Linux 两次安装得到相同 ReleaseInstallManifest；
- no source checkout、no old project、no ambient index/config、offline verified install；
- Skill install/canonical locator/PATH shadow/duplicate executable/compatibility handshake；
- staged upgrade 在 install/doctor/compatibility/export/migration/switch/post-switch 每点失败；
- prior CLI/repository 保持可用，unresolved action/unsupported platform/tamper fail closed；
- uninstall 不删除未明确选择的数据，owner-only permissions 不弱化。

## 15. Non-functional 与 PMF 验证

| ID | 目标 | 判定方式 |
|---|---|---|
| GEW-NFR-001 | 无 daemon/background | runtime exit 后 event/head 不变，无产品常驻进程 |
| GEW-NFR-002 | 平台中立 | core dependency/import scan；fake third runtime contract |
| GEW-NFR-003 | 数据逻辑分离 | 改用户/项目/环境只改 config/fixtures；code scan 无路径/port/threshold |
| GEW-NFR-004 | 可审计重放 | fresh repository 从 events 生成 byte-identical snapshot/completion |
| GEW-NFR-005 | 用户简单性 | clean user 通过自然语言/Skill 完成代表任务，无 daemon/DB 管理 |
| GEW-NFR-006 | 诊断性 | capability/blocked/unknown 给稳定 code、evidence、next route，不泄密 |
| GEW-PMF-001 | interruption quality | 只在定义边界中断；routine findings 无 Human gate |
| GEW-PMF-002 | outcome trust | Owner 可从摘要定位 intent、actions、tests、target state、residual risk |
| GEW-PMF-003 | counter-evidence | Agent 主动记录失败假设、非采用证据与下一实验，不只报告成功 |
| GEW-PMF-004 | data minimization | aggregate 不含 source/prompt/secret/body；task-level consent/retention 生效 |

具体 PMF 目标值由版本化产品实验配置决定；本测试验证采集与判断机制，不把阈值硬编码到
engine。产品发布还需要 Human 与 Agent 共同审阅 PMF counter-evidence，不能由测试 PASS 代替。

## 16. Entry、Exit 与缺陷策略

### 16.1 Work-package entry

- upstream artifact digests/current authority valid；
- test IDs、fixtures、oracle 和 failure injection points 已审阅；
- 外部 action 默认为 disabled；测试数据 classification/cleanup 明确；
- 依赖 WP 的 release-blocking tests PASS；下游 candidate 必须读取并绑定 prerequisite 的 exact
  source manifest（path + declared digest + self-digest）、command evidence、candidate exit 与 verdict
  四元组，验证四者内部 source/command/exit/governing binding 一致、PASS、zero findings、全部
  disposition closed 与独立 reviewer。该历史 prerequisite 有自己的 source identity；下游候选另行
  绑定当前 source，禁止错误要求两者整仓 digest 相同，否则 revision pointer 更新会自失效。
  missing/tampered/REVISE/binding mismatch 均使 verifier fail closed，不能只在未参与证据链的 state
  metadata 中写 `PASS`。

### 16.2 Work-package exit

- 新增/受影响 unit、contract、integration、failure/security tests 全部 PASS；
- independent reviewer PASS，blocking finding=0；
- coverage/trace/evidence/current implementation digest 一致；
- full regression 没有新增 flaky、skip、xfail 或 waiver；
- docs/config/schema/fixtures 与实现同步。

### 16.3 Release exit

- 九类 × 12 mandatory cases 全部 PASS，九个 real E2E 均有 fresh evidence；
- Codex、Hermes Telegram、Hermes Discord contract 与三 risk paths coverage PASS；
- macOS/Linux install/upgrade、repository crash/migration、action unknown、security/privacy、
  compatibility 和 Candidate/Completion suites PASS；
- 所有 FR/NFR trace 到至少一个正向与一个拒绝/失败证据；
- zero unresolved blocker、zero flaky、zero waiver、zero unapproved external action；
- independent Candidate Review PASS，Completion Gate 绑定真实 target state。

缺陷 severity：P0 为越权/数据损坏/重复不可逆动作/秘密泄露；P1 为虚假完成/不可恢复/
determinism divergence/九类核心失败；P2 为 routine 正确性/兼容；P3 为不影响决策的表现。
P0/P1 必须回到 owning WP 并失效受影响 evidence；不能延期到发布后。

## 17. 停止与升级条件

出现以下任一情况停止自动推进：测试证明批准架构无法满足可靠性；需要新增 daemon/远程服务/
跨 runtime/multi-user；需要外部资源或凭据但无 action authority；三轮 stable finding 无 digest
progress；PMF counter-evidence 要求改变产品范围。其余 routine defect 自动修订与复验。

## 18. Test Plan 退出条件

- 测试覆盖全部 FR/NFR、ADRs、WP、九类、三路径、两个 runtime/channel；
- oracle 不依赖被测实现的同一逻辑；并发/crash/unknown side effect 可重复注入；
- release matrix 要求“所有必选场景通过”，无抽样或 waiver 漏洞；
- evidence/identity/privacy/authority 规则可机械验证；
- 独立 Test Plan Reviewer PASS；
- 未执行任何尚未授权的测试外部动作。


## 2026-09-10 approved Candidate defect repair

Regression matrix: in-root/out-of-root file and directory symlinks before execute, after P observation, at restore and after restore must reject without new mutations; normal files remain valid. Actual R receipts must reject omission, replacement/clone, reordering, stale target, foreign task/factory/installation and P substitution. Exercise issue/use/precommit/gate, assert unchanged durable state and no issuance or replay on rejection; valid P and R remain distinct. Assert future config limit 14400 and heartbeat 60, with source-attestation/bootstrap currentness intact. Run focused unit/security/contract/integration suites only; a bounded regression PASS is not a cumulative gate PASS.

Current governing budget: **14400 seconds (4 hours)** for future separately authorized cumulative runs; heartbeat remains 60 seconds. Historical 12600/86400 values and old receipts are retained as history, not current authority. Monitoring remains PAUSED and no automatic rerun is authorized.

Revision 2 regression selection additionally requires the existing
`test_multi_target_positive_uses_quiescent_binding_lifecycle` for both P and R:
generation 0 through all four phases to generation 4 and terminal closure, with
unchanged R receipts/state and zero replay. The R coverage authority must retain
its exact process-local scenario issuer independently of restarted category
assessment state; no missing-factory shortcut is permitted. The revision 1
independent review and its failing normal-R reopen result remain preserved.

### P2b bounded acceptance matrix — 2026-09-11

The authorized run scope is bounded native tests only, strict serial fresh roots,
with a finite timeout per command and first-failure diagnosis. No cumulative
selector, launch supervisor or monitoring restoration is permitted. The original
P2a receipt remains bound to its committed source, not the new working tree.

- RED: guarded fixture must not complete with the generic A-to-B/three-boolean
  contract; missing hotfix oracle members and four plan bindings must be observed.
- Baseline P: genuine installation-owned local emergency grant, exact impact and
  containment scope, actual A reads, zero prior mutations, minimal B within the
  configured byte budget, ready rollback and fresh B all share one binding.
- Baseline negatives: missing receipt, B/late capture, cloned/foreign/re-signed or
  stale receipt; missing/stale authority; impact/containment omission/substitution;
  wrong rollback or excessive patch. Assert failure before first patch when the
  invalid prerequisite exists before execution, unchanged input/control/targets,
  zero task/event/CAS/ref/action writes and zero issued completion evidence.
- Local gate P: fresh candidate JSON health predicates and the complete ordered
  impact/health/rollback gate produce explicit local/non-production proof.
  Negatives cover production elevation, self-reported health, failed/missing/
  stale health/control, skipped/reordered gate and environment/target aliases.
- Post-patch faults: inject target/control drift between patch and final gate;
  require no observation/assessment/coverage issuance and truthful nonzero
  mutation accounting where a patch already occurred. Never issue a zero-write
  rejection receipt for such an execution.
- Typed closure: each P/R is distinct; factory owns every exact ordered installed
  rejection receipt. Reject missing/extra/reordered/duplicate/cloned/foreign or
  stale receipt, altered false flags, P substitution and missing original issuer.
- Currentness: change binding, installation, fixture, baseline proof, control,
  environment, health predicate, gate order or target at issue/use/precommit/gate.
  All false/currentness substitutions fail closed with no further writes.
- Restart: unique referenced CAS with a fresh factory restores proof only after
  complete installed/current checks, no mutation/action/command replay; altered
  or coherently re-signed proof and foreign/duplicate/unreferenced CAS fail.
- Lifecycle: bounded four-phase tests for each new P/R binding plus retained P2a,
  strict serial reopen, distinct root/task/branch/ref/targets, no-follow path
  checks and terminal invalidation; resource handles return to the local baseline.
- Counts/package: exact existing bindings/oracles retained plus four/two additions;
  plan230/oracle115, two exact hotfix oracle paths, closed schema/package/source
  membership and current pins. Preserve frozen old assessment/oracle bytes.
- Report: separate measured bounded tests from future cumulative coverage.
  Independent review must not call this 230-valid, Remaining54-complete, production
  ready, deployed or committed.

### P2b cumulative entry bounded tests — 2026-09-12

- Registration/dispatch: distinct P2a/P2b selectors and callable parents/children;
  invalid, extra or foreign handoff arguments fail before invoking either child.
  Parent forwards exact current registry timeout/heartbeat and validates P2b
  receipt shape, selector, new/retained/dynamic/static counts and boolean statuses.
- Preflight: expected plan/oracle counts, unique oracle keys and all new IDs;
  count mismatch, duplicated oracle, missing or substituted hotfix ID and unknown
  checkpoint stop before any performance sibling or binding execution.
- Simulated orchestration: test-only doubles for installed plan, P1, bindings,
  observations and gate; explicitly labeled unit/control-flow evidence. Exercise
  P2a226 and P2b230, actual iteration/new-retained accounting, g0/issue/use/
  precommit/gate generations, unique identity checks and strict-serial counters.
  Cover invalid/stale/missing/duplicate or falsely passing gate results, identity
  collision, execution mismatch, early exception, consumed finalization versus
  abort, reversed cleanup and non-returning FD/handle checks. No real cumulative
  child or performance sibling may run in this suite.
- Runtime limits: existing timeout, heartbeat, child failure and wrong receipt
  selector tests stay passing; a P2b parent must use the same immutable limits.
- Real bounded evidence: guarded unit/contracts, both-hotfix quiescent P/R
  lifecycle/zero-replay and retained P2a quiescent lifecycle; offline isolated
  wheel/packaging and architecture/diff checks. Do not select the full release
  coverage integration module or a cumulative selector. Each command at most
  600 seconds, strict serial and fail-fast; preserve and diagnose every failure.
- Acceptance: report completed bounded tests separately from actual cumulative
  execution, which is not authorized. Plan230/oracle115 is still configuration
  shape; no 230-valid receipt may be fabricated from simulated tests.

### P2b real-loader omission regression — 2026-09-12

- RED: the existing P2b installed-plan contract calls the real `_verified_plan`
  instead of loading the plan directly. Preserve the observed113-versus115
  failure before implementing the fix; no workload is invoked.
- Exact checkpoint oracle: original P2a113 is unchanged, P2b adds exactly the two
  approved full hotfix identity tuples and nothing else. Default current-source
  callers use P2b; explicit P2a remains113. Unknown/non-string checkpoints fail.
- Real installed loader: default and explicit P2b accept the real230/115 plan;
  explicit P2a rejects that installation. This assertion must not mock the loader.
- Real entry boundary: invoke the actual P2b cumulative child with real contract,
  installation and oracle loading. Replace only the first P1 work call with a
  distinctive stop sentinel and assert checkpoint routing. Separately invoke the
  actual P1 sibling with its real loader, stopping at its first scenario attack.
  Guard all subprocess and binding launches; no resulting receipt is acceptance.
- Negative closure: missing, extra, duplicate and same-count changes to each of
  oracle/profile/selector-kind/column/scenario fields are rejected for both
  checkpoints. These malformed plan doubles test validation only, not execution.
- Retain simulated lifecycle/dispatch/receipt/cleanup negatives and enforce the
  new explicit checkpoint arguments, plus selected real hotfix/P2a lifecycle,
  unit/security/contracts, offline packaging and architecture/diff checks.
  Commands are fail-fast, strict serial and explicitly bounded to at most600s.
- Preserve every previous result. This repair may establish bounded loader
  readiness only; a fresh230-binding run and its actual receipt remain pending
  separate Human authority and later independent acceptance.

### P2c bounded acceptance matrix — 2026-09-14

- Documentation gate: exact amendment, ADR-0008 trace, unchanged Intent Baseline,
  exact174 allowlist and four-document contract pass independent artifact review
  before implementation files change.
- RED/config: the current 230/115 plan is missing exactly the six refactor-debt
  P/R bindings and three exact oracle paths. Requiring `refactor_contract` and
  `refactor_proof` for those rows fails before implementation. Schema negatives
  cover missing/extra/reordered fields, duplicate case/edge/metric IDs, unknown
  gate/comparator, unsafe path, bool/float integer substitution and coherent
  fixture/bootstrap/package re-sign attempts.
- Behavior P: read exact A before mutation and fresh B after mutation; both carry
  the installed ordered case IDs/input digests and exact output/error/side-effect
  vectors, equal to the frozen expectation and each other. R covers case omit,
  add and reorder, expected-vector alias, any output/error/side-effect delta and
  caller-reported equality. Require no later gate result after this gate fails.
- Architecture P: behavior gate succeeds first; fresh B then has every exact
  required directed edge and no forbidden directed edge. R covers forbidden and
  missing edges, reversed/aliased paths, same edge count, same node set and skip/
  reorder of the behavior gate. Assert architecture evaluation count is zero on
  behavior failure and no later gate executes on architecture failure.
- Nonfunctional P: behavior succeeds first; fresh B environment and metric ID are
  exact, observed value is a safe integer and the installed generic comparator
  satisfies the config-owned safe-integer threshold; B is reread after gates.
  R covers hardcoded/substituted or float/bool threshold, environment drift,
  missing/wrong/noninteger metric, comparator miss and behavior regression.
  Assert metric evaluation count is zero whenever behavior fails.
- Proof/authority: conditional proof has exact A/B observations, ordered successful
  gates and fresh-B/config bindings. Reject missing/extra/reordered/cloned/foreign
  or stale proof/receipt, altered result flags and P substitution. Issue/use/
  precommit/gate reread fixture/bootstrap/source/package/target; CAS restart uses
  fresh factory and unique referenced object with zero mutation/action replay.
- Failure accounting: pre-mutation request/config attacks leave target/task/event/
  CAS/ref/action/input unchanged. Injected post-write target/environment drift
  issues no observation/assessment/coverage record and reports nonzero mutations;
  it is not accepted into the zero-write rejection closure.
- Counts/currentness: exact prior230/115 retained plus six/three additions yields
  plan236/oracle118 and 38 missing. Oracle paths are exactly the behavior,
  architecture and nonfunctional members. Re-run selected P2a multi-target and
  P2b hotfix lifecycle/currentness/loader regressions plus scenario bootstrap,
  package/wheel/RECORD and architecture/diff checks; protected files unchanged.
- Execution boundary: strict serial, fresh private root per binding, native test
  command timeout at most600 seconds, stop on first failure/timeout. Do not run a
  cumulative selector, performance workload or monitor. Unit/control-flow tests
  and plan shape must never be reported as a 236-valid cumulative receipt.
- Review: independent implementation and Candidate reviewers receive exact source
  manifests and measured bounded results. Any unresolved finding keeps all six
  current sub-batch bindings missing and routes to the reducer/Human as required.

### P2d bounded acceptance matrix — 2026-09-14

- Documentation gate: exact P2d amendment, unchanged ADR-0008/Intent Baseline,
  exact174 allowlist and four-document contract pass independent artifact review
  before implementation files change.
- RED/config: current236/118 is missing exactly eight incident P/R bindings and
  four exact oracle paths. Requiring closed `incident_contract`/`incident_proof`
  fails before implementation. Schema/config negatives cover missing, extra,
  reordered or duplicate gates/actions/roles/predicates; unknown kinds; unsafe
  scalars/paths; and coherent fixture/bootstrap/package re-sign attempts.
- Detection P: installed fresh signal, exact impact roles and exact severity are
  observed and bound. R covers missing/wrong/stale signal, wrong scope, severity
  substitution and caller-provided detection/pass claims. No containment or
  recovery result may appear after detection failure.
- Containment P: detection is known; affected roles are exactly isolated;
  unaffected observations remain byte-exact; authority, fence, residual state and
  owner route are current. R covers over/under containment, any unaffected
  mutation, stale/foreign authority or fence, stale target and caller scope flags.
  Recovery evaluation count is zero on containment failure.
- Recovery P: only a known and contained effect consumes the authorized
  compensation; the original action is forbidden; all service predicates are
  freshly and completely observed; follow-up and residual facts are nonempty. R
  covers unknown/uncontained input, original-action replay, missing/partial/stale
  predicates, fabricated restored state and missing follow-up.
- Unknown-effects P: inner outcome is exactly `blocked-owner-route`; unknown claim
  and residual state remain; route equals the installed nonempty owner; action,
  replay, recovery, compensation, service-restored, target mutations and ordered
  transitions are empty. R covers any such action/claim, consumed claim, empty or
  foreign owner and fabricated restored state. Outer P only proves correct block.
- Proof/authority: conditional proof binds exact observation, ordered successful
  gates/actions, mutation accounting, owner route and inner outcome. Reject
  missing/extra/reordered/cloned/foreign/stale proof/receipt, altered results and
  P substitution. Issue/use/precommit/gate reread fixture/bootstrap/source/package
  and targets; CAS restart uses a fresh factory with zero action/mutation replay.
- Failure accounting: pre-mutation request/config attacks leave target/task/event/
  CAS/ref/action/input unchanged. Injected post-write drift yields no observation,
  assessment or coverage and truthful nonzero mutations. Unknown-effects P is an
  explicit zero-mutation success condition, not a zero-write rejection alias.
- Counts/oracles: prior236/118 plus eight/four additions gives plan244/oracle122
  and 30 missing. Exact new paths are detection, containment, scenario-recovery
  and unknown-effects. Assert mandatory incident recovery bytes remain SHA-256
  `6e223a032f5549ce5489bd11877ec1309c437cf858568539e437da694024527c`.
- Regression/currentness: rerun selected P2a multi-target, P2b guarded/hotfix and
  P2c refactor lifecycle/currentness/loader cases plus scenario bootstrap,
  package/wheel/RECORD and architecture/diff checks; protected files unchanged.
- Execution boundary: strict serial, fresh private root per binding, each native
  test command at most600 seconds, stop on first failure/timeout. Do not run a
  cumulative selector, performance workload or monitor. Unit/control-flow tests
  and plan shape are not a 244-valid cumulative receipt.
- Review: independent implementation, verification, Candidate and technical
  reviewers consume exact source manifests and measured bounded results. Any
  unresolved finding keeps all eight current sub-batch bindings missing and
  routes to the reducer/Human as required.

### P3 mandatory24 verification — 2026-09-21

Scope is the [mandatory24 Plan](../plans/2026-08-13-graph-engineering-workflow.md#p3-mandatory24-bounded-implementation-plan--2026-09-21)
and [Spec](../specs/graph-engineering-workflow.md#p3-mandatory24-bounded-contract--2026-09-21),
within the approved PRD and Positioning. Every CUJ below is required. There is no
new percentage threshold: acceptance is exact behavior and evidence closure.
Template test counts, pyramids and millisecond examples do not override the
approved serial <=600s native / <=300s canonical per-command budgets.

| CUJ | Required positive behavior | Required rejection / invalidation |
|---|---|---|
| M24-C1, columns normal/boundary/revise/authority/drift/invalidation/artifacts/review/target | Each independent P commits one current release 1.4 assessment and restores from fresh-process captured sources with exact column joins. | Missing, duplicate, wrong-shape or coherent re-signed foreign controls; wrong selector/pins/revision/epoch; wrong body/review lineage, authority, budget, output/artifact set or target must reject with zero restore writes. |
| M24-C2, recovery/rollback | Partial apply is queried, authorized compensation restores exact A with fresh health; recovery proof is task-bound; rollback assessment is PASS/action-coordinator; cold reconstruction is read-only. | Wrong original/restore claim, authority, receipt, generation, mapping, incomplete A or health; generic recovered label alone; second restore or replay; generic NOT_REQUESTED digest used for rollback. |
| M24-C3, real-e2e | Actual local simulator apply/query/health with P mutation delta=1 and sealed task-bound facts. | Actual stale generation/artifact request rejects before apply, delta=0; Git authority, caller PASS, test doubles, forged/cloned/foreign seals and stale predecessor rejected. Post-write faults cannot count as zero-write R. |
| M24-C4, all 24 bindings | Unique task/request/execution/observation/record/root; exact installed plan and independent oracle; issue/use/precommit/reopen verification is current. | Mixed 1.0–1.3 projections in 1.4, foreign profile/column/scenario/task/CAS, stale release state or resource pins; R must have no successful assessment. |
| M24-C5, lifecycle | Actual revoke/abort and quiescent reopen, with source owners released within the existing teardown bound; finalize remains denied without the exact consumed combined-gate decision. | Reuse after revoke/abort, partial or forged finalize decisions, deleted/replaced/symlinked or swapped retained roots, leaked handles and borrowed identities. |
| M24-C6, compatibility | Normal RS-C cold behavior, complete artifact provenance, shared budgets, two captures, installation/package closure and affected prior profile behavior remain valid. | Oversized/deep/multiplied candidates, escaped rereads, cross-capture changes, coherent re-signing, fixture-as-wheel substitution, old schema/Support Matrix/threshold mutation. |
| M24-C7, configuration | Exact 268 bindings / 134 oracles with 24 distinct new mandatory IDs and twelve independent oracle members. | Missing/extra/duplicate IDs, scenario registrations, static PASS or a configuration-only claim of cumulative dynamic acceptance. |

Testing layers and ownership:

- Unit tests cover pure captured column reconstruction and exact shape/type/digest
  joins at the lowest effective layer, using real validators and synthetic
  controlled bytes. They do not mock the validator under test.
- Integration tests use real TaskApplication, repository/CAS, runner provenance,
  retained namespace, ActionCoordinator and release factory. Fresh-process tests
  destroy the live issuer context; cold reads must show zero task/event/snapshot/
  object/ref/action/target/input writes and zero apply/restore replay.
- Local real-E2E tests execute the existing simulator adapter in fresh private
  roots. No Git substitution or mocked simulator success. Negative tests observe
  actual rejection and mutation counters. Network/DNS/socket/proxy use stays zero.
- Focused compatibility tests exercise affected category/coverage consumers and
  package/source authority. Existing exhaustive RS-C tests are rerun only where
  changed inputs invalidate their evidence. No new tests merely mirror prose.

Fixtures contain synthetic IDs and installation-pinned artifact bytes, no real
PII or credentials. Each binding owns its root, task and mutable authority;
cleanup closes owners and releases all handles. Never parallelize mutable
executions. External services are absent, not mocked into a release-success
claim. Local/native execution is the verification environment; CI may replay the
same portable tests. Staging/production/canary/monitoring are not authorized.

TDD sequence is a failing behavior test before the implementation that satisfies
it. Selectors are recorded exactly, run serially and stop at first failure;
failures/timeouts/skips cannot be accepted as PASS. Freeze the actual method
inventory for canonical evidence after implementation, respecting 300s per
command and current Policy freshness. Each row's P/R result and changed-input
regressions must be present before independent verification review. These are
bounded per-binding results, not a combined 268/274 execution. Successful combined
finalization and its subsequent finalized-state reuse checks for real combined
candidates remain deferred to separately authorized cumulative verification.
For the new real bounded candidates, assert no combined decision, rejected
finalize and exact-capability abort. Separately run the existing synthetic
test_consumed_cumulative_gate_finalizes_instead_of_aborting unit regression to
verify the helper routes a consumed decision to finalize, not abort. Its double
is helper-level evidence only; it neither runs a cumulative workload nor proves
real release acceptance or real post-gate currentness.

Security, integrity, recovery and backward compatibility are in scope through
these CUJs. Performance workloads and thresholds, accessibility, real production
release and cumulative acceptance are excluded by authority. No unresolved test
decision remains; newly discovered contract ambiguity returns to the design
review node, while routine test corrections remain in this bounded graph.
### P3 scenario6 verification — 2026-09-22

Scope is the approved [scenario6 Plan](../plans/2026-08-13-graph-engineering-workflow.md#p3-scenario6-bounded-implementation-plan--2026-09-22)
and [Spec](../specs/graph-engineering-workflow.md#p3-scenario6-bounded-contract--2026-09-22),
following existing PRD/Positioning and ADR0009. Every critical journey below is
required; no arbitrary line-coverage or test-count target replaces it. Existing
unittest tooling, real local SQLite/CAS and the actual simulator are used.
Only fault boundaries are patched; issuer/PASS/source authority is never mocked.

| CUJ / tasks | Positive evidence | Negative evidence |
|---|---|---|
| S6-PROV / S6-02 | Actual applied B equals installed manifest/provenance and raw fixture bytes | Caller PASS/digest, coherent fake provenance, stale/foreign/cloned evidence or byte substitution rejected. |
| S6-HEALTH / S6-02 | Active B, exact generation/artifact, complete fresh local predicate vector | Stale observation, missing predicate, staged-as-active, forged success rejected. |
| S6-PARTIAL / S6-02 | Partial state first fails success; original claim/receipt query+reconcile; separately authorized restore A then fresh health | Replay, wrong claim/generation, missing restore authority, partial restore, fabricated success rejected with truthful residual state. |
| S6-LIFE / S6-03 | All six records issue→oracle→coverage→quiesce→fresh source reopen→gate→terminal | Stale/root/task/scenario/clone substitution and post-terminal reopen rejected; all phases add zero action replay. |
| S6-COLD / S6-03 | All three P assessments restore in a fresh interpreter with actual typed sources | Per-scenario source/currentness drift and partial restore-source corruption reject; no SQL/CAS/target changes on read. |
| S6-CONFIG / S6-04 | Six unique selectors/requests and three oracles; configured274/137/0 missing | Old268/134 immutable semantic comparison, no aliases/duplicates or caller-supplied success substitution. |
| S6-COMPAT / S6-05 | Affected mandatory normal/boundary/recovery/rollback/real-e2e, installed-wheel/package/static gates | Protected schema1.0–1.4/dependency1.1/SupportMatrix/helper/threshold bytes unchanged. |

Canonical scenario R tests must reject at the release-evidence authority boundary,
preserve the candidate and all durable/target state, and report the exact installed
oracle error. R has no accepted assessment. The scenario-specific attack tests
are additional actual operations, not inferred from that single canonical rejection.
For partial paths snapshot mutation counters before rejection/read, separately
report bounded setup apply/restore and final active/staged/generation state.

Unit/contract tests cover exact config/model contracts; integration tests exercise
the full action/evidence/assessment/coverage joins. Local E2E is the actual private
simulator lifecycle plus three fresh-interpreter recovery checks, not external
deployment. Synthetic fixture bytes contain no PII. Each binding has a fresh
private root/task/branch/ref; close producer and consumer source ports, native
leases and descriptors, and assert baseline return on success and injected failure.

Run RED before product implementation, then GREEN focused methods. All execution
is strictly serial and stops on first failure. Native command timeout≤600s;
canonical command≤300s (use a smaller wrapper deadline), zero skipped or expected
failure tests. Split long batches at whole independent methods/roles; do not raise
limits, skip checks, reuse stale evidence, or substitute a static count for a gate.
Once the selected tree is staged, any source/pin change invalidates its canonical
evidence. Canonical records bind exact command digest, Policy, Manifest and tree.

Network, real staging/production, credentials, monitoring, performance workloads,
cumulative274 execution and WP10 are out of scope. Resource limits/currentness,
security substitution, cleanup, compatibility and restart are in scope; UI/accessibility
and external deployment are not applicable. There is no unresolved testability
choice; a failure or inadequate evidence is resolved before independent review.
Review the exact implementation, then verification and Candidate; no commit in
this execution authority. Record actual method outcomes/durations in detached
evidence rather than pre-marking the Plan checkboxes as passed.

### P3 cumulative274 verification design — 2026-09-23

#### Scope and critical journeys

Implements [readiness Plan](../plans/2026-08-13-graph-engineering-workflow.md#p3-cumulative274-readiness-plan--2026-09-23)
and [Spec](../specs/graph-engineering-workflow.md#p3-cumulative274-entry-design--2026-09-23).
Current approval permits design and independent review only. The tests below are
proposed for separately approved implementation; the full run additionally needs
launch approval. Require coverage of every applicable CUJ, not a new numerical
line-coverage threshold. A mocked orchestration result never counts as actual
cumulative acceptance.

| CUJ | Risk and assertions | Lowest effective proof / phase |
|---|---|---|
| C274-J1 | All274 case IDs/full rows and137 oracle identities/digests match independent expectations; missing, duplicate and same-count substitution reject before P1 or action | Contract + unit / I1–I3. |
| C274-J2 | Exact new parent/child selector dispatch, private child marker, current registry14400/60 limits, no accidental launch | Unit with mocked launcher / I1–I3. |
| C274-J3 | Four currentness phases run serially with isolated identities; actual factory retains authority and rejects stale/foreign evidence without replay | Existing bounded integration plus orchestration doubles / I3; actual all274 / R2. |
| C274-J4 | Actual combined gate is full PASS only on exact current record set; static evidence remains full missing/FAIL | Unit routing and actual incomplete-factory negative / I3; actual full positive / R2. |
| C274-J5 | Consumed decision finalizes, incomplete/static/foreign decisions cannot authorize finalize; abort and reverse cleanup preserve failures | Unit fault matrix + actual incomplete factory / I3; consumed actual full factory / R2. |
| C274-J6 | Timeout, cancellation, child failure, malformed receipt and cleanup failure yield no success; child is stopped/reaped before root deletion | Unit fake process/clock + bounded real trivial child / I3, no benchmark launch. |
| C274-J7 | Exact receipt types, identities, plan digest, P1 evidence and resource closure validated; bool-as-int, extra/missing/forged fields reject | Unit + installed contracts / I3. |
| C274-J8 | Historical partial selectors/default behavior, protected files and source/resource closure remain intact | Existing legacy unit/contract and read-only diff / I3. |

#### Proposed test identities and commands

Add `Cumulative274EntryTests` in `tests/unit/test_wp08_scenario_truth.py` with
these methods (names are planned, not yet implemented):

- `test_exact_preflight_rejects_before_any_work` — mutate each identity/row/digest, including matching counts and swapped P/R requests; assert P1, binding and subprocess mocks uncalled.
- `test_selector_dispatch_and_installed_limits` — exact parent/child mapping, wrong marker/selector rejection and14400/60 forwarding; launcher mocked.
- `test_simulated_full_gate_and_static_negative` — exercise orchestration order and record set with clearly synthetic doubles; no acceptance claim.
- `test_terminal_routing_uses_consumed_decision` — actual decision identity semantics represented in doubles; distinguish failed consumed combined gate from unconsumed partial/static gate and foreign decision; do not access private engine state.
- `test_partial_setup_and_cleanup_failures_remain_failures` — fail each acquisition/issue/use/precommit/gate/close stage; acquired resources closed, primary/cleanup errors retained.
- `test_timeout_cancel_and_failed_child_are_reaped` — fake clock/process boundary checks plus a short real inert child, no fixture or performance child; check reap precedes control-root deletion.
- `test_exact_receipt_rejects_tampering` — mutate every specified field, identity, scalar type and P1 evidence; no extra keys and no positive authority from JSON.

Add `Remaining54P3CumulativeContractsTest` in
`tests/contract/test_wp08_remaining54_contracts.py`:
`test_c274_identity_and_installed_oracle_closure`, and
`test_legacy_selectors_reject_current_plan_without_launch`.
Expected identities must be independent of loaded plan rows. Check the frozen
inventory and approved plan hash; resolve actual installed oracle bytes through
existing validators. Do not blindly copy all loaded rows into expectations.

Add `WP08ReleaseCoverageTests.test_c274_incomplete_factory_aborts_without_replay`
in `tests/integration/test_wp08_release_coverage.py`: use one actual current
release binding with the full installed274 plan, actual issued record/factory and
actual failed gate. Assert273 missing, invalid/stale0, denied finalize, exact
abort capability, permanently closed lifecycle, zero extra simulator actions and
resource baseline return. This is incomplete-gate evidence only.

Retain these existing method selectors as focused regressions:

- `tests.unit.test_wp08_scenario_truth.CumulativeEntryTests.test_simulated_p2a_and_p2b_complete_serial_orchestration`
- `tests.unit.test_wp08_scenario_truth.CumulativeEntryTests.test_receipt_tampering_and_parent_limits`
- `tests.unit.test_wp08_scenario_truth.OracleClosureEntryTests.test_real_cumulative_entry_loads_plan_before_p1_work`
- `tests.unit.test_wp08_scenario_truth.OracleClosureEntryTests.test_real_p1_sibling_loads_plan_before_performance_work`
- `tests.contract.test_wp08_remaining54_contracts.Remaining54P3FoundationContractsTest.test_p3_configuration_package_and_missing_count_closures_are_current`
- `tests.integration.test_wp08_release_coverage.WP08ReleaseCoverageTests.test_release_normal_quiescent_binding_reopens_without_live_session`
- `tests.integration.test_wp08_release_coverage.WP08ReleaseCoverageTests.test_release_normal_rejection_quiescent_binding_reopens_without_live_session`

Future command construction is exact-method based. For each selector above,
copy the existing attested-child harness from detached
`p3-s6-canonical-plan-r0.json` job0, replace only the selector list, expected test
count and diagnostic label. Run argv `[.venv/bin/python, -B, -c, <harness>]`;
use600s native limit and290s inner/300s outer canonical limit. The harness issues
a fresh installation attestation, launches the project interpreter with
`-X gew_installation_control_root=<private-root>`, loads the named unittest method,
requires exactly one executed test and zero skips/expected failures/unexpected
successes, and closes the temporary root. Never invoke unittest discovery or a
whole performance/cumulative module. Record generated argv/harness digests in
a new detached plan before execution; do not alter the existing harness record.

After exact staging under a future Manifest, capture each canonical job via the
frozen workflow `check_workflow.py evidence --project-root <root> --manifest
<root>/.workflow/manifest.json --policy <root>/config/workflow-policy.json
--command-id <unique-id> --output <new-detached-evidence> -- .venv/bin/python -B
-c <harness>`. Read actual exit code, timeout, counts and input bindings. Run
strictly serial and stop on first failure. Source edits invalidate affected
checks; do not expand or repeat passing checks without a concrete reason.

#### Layer budgets, mocks and synthetic data

Unit/contract checks use real validators and installed documents but mock all
cumulative child launches and expensive binding execution. Inert process tests
use synthetic wait/exit behavior only. Bounded integration uses actual SQLite,
CAS, scoped local simulator authorities and fresh sources with no network;
selected one-binding methods remain native<=600s/canonical<=300s. Split methods
if needed rather than extending limits. All fixtures are synthetic and private;
shared roots or real user repositories are prohibited. Close each acquired owner
in reverse order and assert no live lease/reopen handle remains.

The actual R2 run has no authority/factory/gate/currentness mocks. It includes
P1 sibling performance evidence and every binding in a fresh attested interpreter,
14400s total with60s heartbeat. Require the exact Spec receipt only after both
gates and successful terminal cleanup. Actual opaque R coverage stays in its
originating child; do not synthesize a cross-process execution authority from JSON.

#### Design checks, compatibility and phase exit

For this documentation-only batch, run `git diff --check`, verify only the four
authorized documents changed, independently rehash identity/impact inventories,
check relative documentation links/anchors and symbol references, and replay
saved reducer records against frozen inputs. No runtime tests are required for
prose edits; no new implementation test is claimed as run.

For future I3, verify all non-target tracked files unchanged from the approved
base and compare protected schemas, plan/oracle rows, source lists, bootstrap
pins and package resource pairs. Existing paths require no new package member.
Run relevant existing packaging/source-closure checks if the input comparison
shows a dependency was actually affected; otherwise retain the comparison as
evidence instead of rerunning unrelated wheel builds. Test/evidence helpers and
installation attestation enforcement remain unchanged.

No staging/production environment or remote CI launch is part of this scope.
Security, local recovery and compatibility are in scope; UI/accessibility,
production performance claims and deployment are out of scope. The local
cumulative run is acceptance verification, not evidence of real deployment.
No public API/schema issue is open; discovery before implementation returns to
scope review. Future workload feasibility is intentionally unresolved until an
authorized R2 attempt; a timeout is a failed result, not a reason to relax limits.

Traceability: I1/I2→J1/J2/J4/J5/J6/J7; I3→all bounded CUJs; I4→captured evidence
and independent review; R1/R2→actual J3/J4/J5 and full receipt. References:
[PRD](../prd/graph-engineering-workflow.md),
[Positioning](../positioning/graph-engineering-workflow.md), the above Plan/Spec
and [Impact](../impact/graph-engineering-workflow.md#p3-cumulative274-design-impact--2026-09-23).

### C274-RUN-001 focused regression — 2026-09-25

Reproduce the actual missing-root failure with a real quiescent release binding,
not a fake projection. Cover mandatory P/R and at least one scenario through
the same projection call used before cumulative factory construction. Validate
exact six-field identity, unchanged generation/purpose/reader and reopen counts
and FD count across identity reads, identity stability before/after issue and
use/precommit, defensive returned values, and refusal after termination.

Reject fake reader and foreign real reader/record/authority/lifecycle association;
reject changed result/installed task or selector metadata. After producer setup,
guard simulator invoke and lifecycle reopen/run during identity-only calls. Verify
real distinct bindings produce distinct resource fields; separately test that
shared resource identities remain rejected even when logical task labels differ.
Retain generic/real-E2E and cumulative orchestration/cleanup regressions with mocked
launch. Split real cases into independent commands if needed to stay<=300s; never
run the actual P1 benchmark or cumulative workload as part of this repair.

Check non-target tracked bytes against460ace6, compile changed Python, validate
workflow and capture fresh staged-tree evidence. Independent review must distinguish
bounded repair verification from a new actual274 gate acceptance.

### C274-RUN-002 pure reuse verification

Critical journeys: repeated valid reads in one operation preserve exact derived
data while invoking protected loaders every time; changed input bytes reject
after a previous hit; same-bytes physical/source replacement still rejects;
foreign capability stays invalid; cache result mutation cannot affect later
reads; next phase/thread/process starts with no shared memo; nested operations
remain isolated; successful and exceptional exits release memo retention.

Use actual installation acquisition in focused tests, wrapping pure parsers only
to observe computation reuse. In-memory semantic corruption fixtures exercise
validation errors; existing physical cold-replacement/attestation and real
lifecycle tests verify that mocks do not substitute for the trust boundary.
Test real P and R mandatory dependency bindings and a graph rejection scenario
where applicable. Confirm generation/expected purpose and action/resolver replay
boundaries across issue/use/precommit/gate. Use no user data or external network.

First retain meaningful RED for absent operation reuse, then GREEN with native
verified test delivery. Keep the runtime source protected; no mocking of the
authority boundary to make performance pass. Measure same normal-P/R setup and
observation separately without profiler before/after; supplement with pure-parser
call counts and saved source hashes. A single timing pair is indicative and not
a p95 estimate; prior comparable full-run timing provides context, not a substitute
for baseline. Each command<=300s and strict serial. Avoid multi-binding commands
whose measured aggregate would exceed this bound.

Run changed-file compilation, workflow and protected non-target source checks,
affected tests and independent evidence review. All pass claims bind current
source/evidence. No full cumulative/P1 rerun or commit follows automatically.


#### Revision 4 coverage partition after bounded timeout

Retain the failed P four-phase attempt. Exercise quiescent normal P observation
(issue, generation 1, next purpose use) and close in one command. Exercise real
normal R and vulnerable-graph R separately through issue/use/precommit/gate,
with the real factory, gate and abort. Add a separate live normal P factory/gate
command to check P record consumption and currentness without a quiescent owner.
No command may bypass lifecycle order or serialize/forge opaque authority.

This partitions coverage across real paths; it does not prove same-instance
quiescent P four-phase completion. That combination and full274 acceptance remain
unverified. Retain this limitation in verification and Candidate reports.

Count pure-parser work only while an actual operation is active, grouped by
operation identity: one parse per used slot per phase, separate owners across
phases, empty entries after exit. Protected loaders/preflight stay live; calls
outside an operation must not be mistaken for cache misses inside a phase.
Existing cold-replacement, cross-owner/type/key and exception cases remain.
Every successful real binding command must close resources and assert no private
reopen handles remain. Capture per-stage elapsed diagnostics to locate a failure
without retrying a whole passing suite. Preserve 290/300-second limits and fail
fast. Timeout evidence cannot prove finally cleanup; record observed process
status separately and preserve unproven temporary roots.

### C274-RUN-003 installation readiness verification

CUJ PIN-A: before any benchmark launch, load the real performance registry from
an attested checkout, compare all 38 protected resources with current bytes and
pyproject pins, and require the production build backend's package inputs to
contain the same protected resource and bootstrap bytes. No workload simulation
or benchmark child may substitute for successful factory initialization.
CUJ PIN-B: reuse existing five-loader stale-byte contracts; add a focused regression
for changed protected source bytes and a same-byte-replaced installation root
in a disposable attested copy
when no existing equivalent covers the performance input. Rejection must leave
the original checkout unchanged. Restored valid input must initialize successfully.
CUJ PIN-C: verify offline wheel resource consistency through the existing backend
and exact Manifest/staged-file equality, no tracked unstaged inputs, unchanged
non-target files, and current source/policy binding. Serial native commands<=290s
and canonical<=300s; fail fast. Capture RED before configuration changes and
canonical GREEN after all edits. No full274/P1 benchmark, network or limit changes.


## WP-09 local product learning — test design R2, 2026-10-02

### W9-T1 Scope and present status

This is a design of future tests under FR-13, GEW-PMF-001–004 and Spec W9. No WP09
product test has run. Current work verifies only the five-file design changes.
W9-D1/W9-D2 and implementation authority precede new tests/code; evidence names
below are proposed test IDs, not existing passing cases. Real data and full274/P1
repetition are excluded. All critical journeys below require positive and refusal
coverage before WP09 completion; no invented percentage/line-count target applies.

### W9-T2 Critical journeys and observable oracles

| IDs / requirement | Journey | Observable success and refusal |
|---|---|---|
| W9-C01 / PMF004 | explicit owner grant, no default consent | grant binds task/head/generation/metric set; absent/expired/wrong-owner grants cause zero metric reads and zero PMF rows |
| W9-C02 / PMF001,002 | bounded genuine committed capture | same source head, consent generation, context version/digest, relation dependency vector and policy yield identical semantic output; PRD boundary/window included; missing endpoints or incomplete observations remain unknown, not zero |
| W9-C03 / PMF002 | terminal outcome and self-report | completed/canceled/failure remain distinct; owner abandonment and repeat relation are labeled self-report; inactivity and resume never fabricate abandonment/recovery |
| W9-C04 / PMF003 | learning from unfavorable evidence | synthetic supported, mixed, counter-evidence and insufficient-data cohorts give exact configured outcomes/denominators; unfavorable rules cannot be dropped |
| W9-C05 / PMF004 | revoke/expiry concurrent with publication | deterministic barriers before final commit show one legal ordering; no old-generation response or later handle use after revocation linearizes |
| W9-C06 / PMF004 | retention and guarded deletion | explicit GC uses real current security subject/decision; hold, rollback dependency or unresolved claim yields suppressed-but-blocked; allowed deletion and tombstone atomic |
| W9-C07 / PMF002,004 | restart, duplicate request and crash recovery | replay same exact request does not add sample; changed request digest rejected; each crash cut yields complete pre/post state, never partial consent/aggregate |
| W9-C08 / NFR01,06 | authorized local runtime and offline report | real runtime gateway identity; foreign owner/runtime/lineage denied, no daemon/network/content export; old owner operations preserve compatibility |
| W9-C09 / NFR07 | configurable rules and admission limits | change installed config in a newly valid fixture changes bounds/rules, not code; unknown/tampered policy rejected; same config/report input deterministic |
| W9-C10 / NFR06 | installed closure and source substitution | source and built wheel load all new schemas/config; same-path replacement, wrong digest and missing resource reject before collection |

FR13 P integrates C01–C10 in a local synthetic owner session: grant → collect →
record context → verify old aggregate/report is rejected as stale → explicitly
collect again with the new context binding → report unfavorable evidence → revoke
→ denied report → guarded purge/restart. FR13 R is an independently prepared task/root exercising foreign
identity, invalid source and revoked consent; it cannot reuse P authority objects.
No fixture may directly fabricate an issued runtime, retention decision, committed
completion record or trusted aggregate to claim integration success.

### W9-T3 Layer and mock policy

| Layer | Proposed files | Real boundaries / allowed doubles | Per-command ceiling |
|---|---|---|---|
| unit | `tests/unit/test_wp09_learning.py` | pure schemas, rational metrics, buckets and rule truth tables; immutable minimized fixtures only | native290s / recorder300s |
| contract | `tests/contract/test_wp09_learning_contracts.py` | exact runtime operation/schema versions, valid installed registry; no strings asserted as a substitute for behavior | native290s / recorder300s |
| integration | `tests/integration/test_wp09_learning.py` | real synthetic SQLite transactions, TaskApplication/runtime identity and repository source heads; fault injection only at named storage boundaries | native290s / recorder300s |
| security | `tests/security/test_wp09_learning_privacy.py` | real security-subject issuance/retention/purge authorization, adversarial inputs, bounded-reader sentinels | native290s / recorder300s |
| packaging | existing `tests/unit/test_wp00_packaging.py` plus focused wheel consumer | actual built wheel and protected config resources, no import-only fake | native290s / recorder300s |

Serial commands with fresh private roots. A2 freezes exact class/method selectors,
expected test count and command argv after the implementation boundary is known;
no unconstrained discovery or total-suite rerun is authorized by this table. Record
failures and stop the batch; only diagnosed changed inputs justify a targeted new
attempt within current authority and budget. No automatic timeout increase.

### W9-T4 Required adversarial matrix

- Rejected unknown keys, raw body in a nominal code field, oversized UTF-8,
  bool-as-int, negative count, NaN/Infinity, forged digest and duplicate source row.
  Synthetic canary text must be absent from rows, reports, errors, logs and receipts.
- Source head changes during read/write; missing transaction rows; cross-task
  event/authority/context substitution; coherent caller-made hashes; cold replay
  under a foreign runtime; CAS content must not be copied into learning buffers.
- Admission tests at exactly each configured bound and one beyond, including
  aggregate multi-task budget. Use a fetch/parse sentinel and real oversized row
  proving rejection before materialization, not merely after allocating a blob.
- Consent expiry, regrant, disallowed metric set, revoke and source/context changes
  during report assembly. Retained immutable handles revalidate; an earlier grant
  object cannot authorize later use. Regrant does not restore erased observations.
- Hold/rollback/unresolved-action state changes between retention evaluation and
  consume/delete. Crash before/after every durable write and after authorization
  acquisition. Tombstone/row/receipt consistency checked from a fresh process.
- Duration events in reverse order, no terminal event, no PRD boundary, missing
  review mapping, zero known denominator and undersized cohort all retain explicit
  unknown/insufficient-data semantics. Test valid zero only with a complete window.
- Same-owner prior-task relation with missing/revoked consent at either end is not
  usable. Self-reported abandonment cannot overwrite machine completion or become
  a causal claim. Policy-selected experiment includes all unfavorable findings.

### W9-T5 Current design checks and future evidence

Current checks: parse Manifest/approval; exact five-file diff; unchanged PRD/Intent,
Policy and all code/config; resolve document links and inspected source symbols;
check `git diff --check`; run existing workflow `check` with explicit project Policy;
independent Spec/Impact/Plan/Test Plan review with retained actual reducer decisions.
No new product tests are needed to validate these reversible document changes.

Future evidence binds exact commit/tree, installed policy/schema digests, source
head vectors, consent generation and command outcomes. At most minimized synthetic
codes/digests/counts are retained; never dump full environments or real user data.
Candidate evidence must be current for implemented bytes. C274 r6 remains historical
accepted evidence and cannot substitute for any WP09 case or new-tree regression.

### W9-T6 Acceptance and exclusions

Design exit: reviewed coherent proposal, precise implementation gates and no hidden
schema/collection authority. Implementation exit: all ten CUJs and FR13 P/R covered,
no open blocker, current privacy/retention and packaging evidence, independent
review. Product-market-fit judgment and real experiment thresholds require owner
participation; neither synthetic tests nor generated hypotheses establish PMF.
Unknown metric fields may be reported honestly, but a permanently unimplemented
required metric cannot be counted as complete WP09 coverage. W9-D2 must resolve
source mappings before claiming the implementation ready.

### W9-T7 R1 source-time and context oracles

Time matrix: a valid issuer-bound same-domain trusted pair yields the configured
trusted bucket; ordered caller-provided RFC3339 timestamps, even with valid event
chain digests, yield unknown trusted elapsed and at most a separately labeled
caller-reported bucket. Missing provenance/endpoint, invalid syntax, absent offset,
incompatible domains, forged trusted labels and reverse order yield unavailable
trusted duration. Inject both syntactically valid arbitrary values and invalid
strings through real runtime/event storage, not a trusted fixture constructor.
Existing repository trusted-clock expiry tests are separate and cannot certify
those caller timestamps. If the trusted-duration source is not implemented, its
positive fixture cannot be used to claim real-source WP09 coverage.

Context matrix: collect at fixed source head, consent generation and policy with
context version N/digest A. Change only context via the real owner operation to
N+1/digest B: the old aggregate is stale, and new collection identity differs.
Place deterministic barriers after capture and before final collect/report publish;
change local context, change the related task's context, revoke the related task's
consent, or expire/regrant either end. Verify exact dependency-vector mismatch,
E_STALE/E_CONSENT and no stale response or persisted publication. Race context CAS
writers: one expected-version winner, one conflict, idempotent same-request replay.
Reject self/foreign/unconsented relations and traversal outside the explicit bounded
set. Deleting context and returning to the empty state must not reuse an old version
or resurrect an earlier report. Owner context does not mutate authoritative outcome.


## WP09 approved exact verification inventory — 2026-10-04

Supersedes W9-T3 pending selectors and the A2 R2 four-unavailable-metric slice. Main Spec source supplement supplies the three metrics and positive/refusal matrix; W9-C01–C10, prior privacy/race/retention contracts continue. Fourth stage-authority metric remains unavailable. 67 new tests and 65 existing methods, each exact selector run once per required RED/GREEN state; not claimed executed. No skips or zero collection can yield PASS. Native clock capability probes do not replace product tests.

Every selector below uses `.venv/bin/python -B scripts/run_wp09_tests.py --test SELECTOR --timeout-seconds 290`, expected exactly one test, zero failures/skips for GREEN.

- `tests.unit.test_wp09_learning.LearningTests.test_closed_fields`
- `tests.unit.test_wp09_learning.LearningTests.test_rational_denominators`
- `tests.unit.test_wp09_learning.LearningTests.test_duplicate_identity`
- `tests.unit.test_wp09_learning.LearningTests.test_window_unknown_vs_zero`
- `tests.unit.test_wp09_learning.LearningTests.test_counter_evidence_rules`
- `tests.unit.test_wp09_learning.LearningTests.test_caller_time_not_trusted`
- `tests.unit.test_wp09_learning.LearningTests.test_context_relation_identity`
- `tests.unit.test_wp09_learning.LearningTests.test_boundary_limits`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_six_operations`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_explicit_consent_parser`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_unknown_schema_policy`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_installed_resource_binding`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_legacy_owner_operations`
- `tests.contract.test_wp09_learning_contracts.LearningContractTests.test_replay_request_conflict`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_fr13_positive`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_fr13_refusal`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_prospective_regrant`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_context_cas_stale_recollect`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_relation_endpoint_currentness`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_source_head_race`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_revoke_publish_race`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_schema_upgrade_restart`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_schema_upgrade_crash`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_migration_no_pmf_export`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_terminal_vs_self_report`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_source_mapping_unknowns`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_failure_recovery_sequence`
- `tests.integration.test_wp09_learning.LearningIntegrationTests.test_caller_time_provenance`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_foreign_identity_before_read`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_expired_consent_no_read`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_corrupt_chain_rejected`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_preallocation_bounds`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_cas_body_not_copied`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_canary_absent`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_retained_handle_currentness`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_legal_hold`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_authority_consumption`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_purge_crash_restart`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_clock_rollback`
- `tests.security.test_wp09_learning_privacy.LearningPrivacyTests.test_tampered_installed_policy`
- `tests.contract.test_wp03_connection.ConnectionFactoryTests.test_policy_and_capability_are_closed_and_fail_on_durability_weakening`
- `tests.contract.test_wp03_connection.ConnectionFactoryTests.test_open_contract_pragmas_roles_modes_and_symlink_fail_closed`
- `tests.contract.test_wp03_connection.ConnectionFactoryTests.test_connection_is_thread_and_fork_bound_and_transactions_are_explicit`
- `tests.contract.test_wp03_connection.ConnectionFactoryTests.test_busy_retry_is_finite_and_failed_transaction_has_no_partial_write`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_atomic_commit_replay_catalog_cas_and_idempotent_recovery`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_before_commit_fault_is_old_and_after_commit_fault_is_recoverable_new`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_corruption_or_missing_committed_object_blocks_integrity`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_replay_binds_index_columns_and_transaction_revision_and_head`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_snapshot_is_derived_and_can_only_be_repaired_from_valid_committed_head`
- `tests.conformance.test_wp03_repository.RepositoryConformanceTests.test_real_process_kill_exposes_only_old_before_commit_or_new_after_commit`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_011_public_export_is_complete_and_clears_durable_hold`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_012_migration_held_export_reuses_exact_exclusive_token`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_013_bundle_tamper_or_missing_object_fails_validation`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_014_import_replays_exact_history_and_objects_in_isolated_root`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_015_activation_recovery_exposes_only_verified_active_or_blocked`
- `tests.integration.test_wp06_migration_repository.WP06MigrationRepositoryTests.test_gew_mig_016_stale_restore_creates_gap_and_never_lowers_fence`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_017_fault_schedule_is_exact_sorted_and_executable`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_018_interrupted_export_hold_requires_explicit_recovery`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_019_concurrent_public_exports_do_not_reenter_or_partial_publish`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_020_sigkill_before_verifying_preserves_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_021_sigkill_after_verifying_rolls_back_to_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_022_sigkill_before_active_rolls_back_to_old_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_023_sigkill_after_active_preserves_new_active`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_024_two_process_activation_has_one_authority`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_025_command_shared_scope_cannot_cross_activation_switch`
- `tests.integration.test_wp06_migration_failure.WP06MigrationFailureTests.test_gew_mig_026_corrupt_history_publishes_stable_explicit_blocked`
- `tests.unit.test_wp07_owner_turns.WP07OwnerTurnTests.test_gew_rt_045_each_owner_turn_is_one_exact_versioned_operation`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_001_runtime_identity_is_exact_immutable_and_digest_bound`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_002_owner_and_lineage_proofs_bind_one_runtime_instance`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_003_capability_handshake_is_exact_and_compatible`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_004_capability_missing_or_version_mismatch_rejects_session`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_005_runtime_adapter_protocol_requires_every_port`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_006_agent_and_reviewer_results_are_request_and_identity_bound`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_007_tool_and_human_ports_preserve_prepared_refs_and_pending`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_008_presentation_segments_bind_one_delivery_receipt`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_009_canonical_executable_locator_rejects_symlink_mode_and_digest`
- `tests.unit.test_wp07_runtime_contract.WP07RuntimeContractTests.test_gew_rt_010_session_rejects_cross_runtime_owner_or_lineage`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_raw_tool_output_is_purged_after_extraction_with_tombstone`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_holds_and_unresolved_actions_block_purge`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_secret_body_persistence_and_unknown_category_fail_closed`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_purge_decision_must_be_revalidated_against_current_hold_snapshot`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_current_purge_is_consumed_exactly_once`
- `tests.security.test_wp05a_retention_and_extensions.RetentionTests.test_current_unresolved_claim_is_read_from_repository`
- `tests.security.test_wp05a_retention_and_extensions.ExtensionGateTests.test_builtin_data_descriptor_can_pass_but_non_builtin_executable_is_rejected`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_performance_installation_closure_matches_packaged_resources`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_performance_installation_rejects_source_drift_and_replaced_root`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_project_requires_supported_python_and_exact_approved_runtime_dependency`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_console_script_uses_installed_distribution_namespace`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_responsibility_roots_map_to_one_namespace`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_core_does_not_import_forbidden_layers`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_runtime_files_do_not_bind_reference_project`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_source_manifest_closes_profile_oracle_input_generation_two`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_build_backend_rejects_unowned_and_symlinked_package_inputs`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_build_backend_rejects_internal_and_external_symlink_ancestors`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_build_backend_rejects_mapping_traversal`
- `tests.unit.test_wp00_packaging.PreflightConfigurationReuseTests.test_fresh_reads_exact_text_and_detached_toml_values`
- `tests.unit.test_wp00_packaging.PreflightConfigurationReuseTests.test_warm_read_and_parse_failures_and_replaced_parser`
- `tests.unit.test_wp00_packaging.PreflightConfigurationReuseTests.test_nested_exception_cleanup_and_separate_operations`
- `tests.unit.test_wp00_packaging.PreflightConfigurationReuseTests.test_copied_context_thread_and_fork_do_not_reuse_parent`
- `tests.unit.test_wp00_packaging.PreflightConfigurationReuseTests.test_all_affected_installation_closures_match_real_wheel`
- `tests.unit.test_wp00_packaging.DependencyLocationReuseTests.test_location_slots_reuse_only_within_phase_and_kind`
- `tests.unit.test_wp00_packaging.DependencyLocationReuseTests.test_location_failed_changed_and_reverted_input_reparses`
- `tests.unit.test_wp00_packaging.DependencyLocationReuseTests.test_location_parser_and_projector_substitution_cannot_hit`
- `tests.unit.test_wp00_packaging.DependencyLocationReuseTests.test_location_nested_thread_fork_and_baseexception_cleanup`
- `tests.unit.test_wp00_packaging.DependencyLocationReuseTests.test_application_phase_owns_location_lifetime`
- `tests.unit.test_wp00_packaging.PackagingContractTests.test_wp09_installed_resources_and_tamper`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_native_monotonic`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_cross_process_domain`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_changed_domain`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_forged_provider`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_integer_and_backward`
- `tests.unit.test_wp09_learning_clock.ClockProviderTests.test_wall_clock_independence`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_run_terminal`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_pause_resume`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_duplicate_transaction`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_rollback_and_crash`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_restart_start_sample`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_late_grant_unknown`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_source_gap`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_revoke_commit_race`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_context_preserves_observation`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_review_verdicts`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_review_no_double_count`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_forged_review_binding`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_reapproval_window`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_real_human_interruptions`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_pre_post_approval_grants`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_non_decision_waits`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_repeat_wait_entry`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_missing_boundary`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_no_consent_no_sampling`
- `tests.integration.test_wp09_learning_metric_sources.LearningMetricSourceTests.test_wheel_real_provider`

Also run the approved architecture, source, build/reproducibility, explicit-project-policy workflow and git diff checks after relevant code changes. Clock tests exercise actual installed provider and genuine source/channel while controlled doubles cover error conditions; no fake issued runtime or fabricated authorization. Consent off asserts zero clock/extra metric reads. Linux support requires native Linux evidence; do not silently skip a required platform claim. Freeze/source-hash execution inputs per Candidate protocol.

## WP09 report completion test design — R1, 2026-10-08

### R9-T1 Scope and critical journeys

This is design-only under [Spec R9](../specs/graph-engineering-workflow.md#wp09-report-completion-design--r0-2026-10-08),
[ADR0013](../adr/0013-learning-hypothesis-report-decisions.md) and
[Plan R9](../plans/2026-08-13-graph-engineering-workflow.md). All following new
methods/fixtures are proposed, not implemented, collected or passing. Owner
implementation authority precedes tests/code. Cover every critical journey below;
no arbitrary percentage/line count or test-pyramid count substitutes for oracles.
Scope includes configured report decisions, closure, genuine cohort/lifecycle,
privacy/currentness and valid configuration variation. Real user data, native Linux,
owner upgrades, WP10/WP11, full274/P1, monitoring and irreversible actions are excluded.

| CUJ / upstream | Required behavior | New selectors below / existing regression |
|---|---|---|
| RC01 /W9-C04 | exact four hypothesis outcomes with insufficient precedence | U01–04,I01–04; existing rational rule tests |
| RC02 /W9-C02,04 | counts/unknown/excluded/ref unions, no overlap double counting or unfavorable omission | U08–10,I05–06; existing source/reapproval/relation tests |
| RC03 /W9.7 | closed group/rule/suggestion partition; missing/duplicate/cyclic references refuse before task sources | U05–07,C01–04,S01; existing malformed-source refusal |
| RC04 /FR13 P/R | genuine owner lifecycle and independently prepared refusal root | I07,S01–02; existing retention/purge/clock tests |
| RC05 /W9-C05,07 | replay/currentness/config/revoke publication remains atomic | I09,S03–04; existing consent expiry/context/head/ordering races |
| RC06 /W9-C09 | count/UTF-8/reference admission before oversized report/config output allocation | U10,C01–02,S05; existing shared capture budget tests |
| RC07 /PMF004 | no body/prompt/secret in outputs, receipts/errors; no implied experiment action | S06; existing PMF/authority privacy tests |
| RC08 /W9-C09 | valid installed config changes rules/bounds without engine edits | I08,W02; tamper refusal is a separate negative |
| RC09 /W9-C10 | exact installed/source resource closure, old bytes/versions preserved | C05–08,W01–04; existing wheel/authority/migration tests |

### R9-T2 Layers and test construction

Use unittest and the existing exact single-test runner. Proposed37 methods:
10 unit,8 contract,9 integration,6 security and4 installed-wheel integration.
Put arithmetic at the pure layer, reference/schema checks at contracts and real
process/SQLite/installed facts at integration/security/wheel. Counts reflect risk,
not a mandated pyramid. Native child<=290s and recorder<=300s for every method;
no unmeasured per-layer latency promises. Run serially, fail-fast, with no skipped
tests; each named argv must attest collected1/executed1 and the exact selector.

Mock only the external synthetic agent/reviewer output port, rejection/fault
inputs and controlled negative corruptions. Source/DB/identity/resource validation,
public learning operations, installed loader and completion gate remain real.
Exception for bounded retention/expiry tests, including I07: permit the existing
controlled repository-clock fixture in isolated synthetic roots to advance the
trusted retention/consent clock past the configured age/expiry. Keep the actual
retention decision, issued purge authorization, consumption, atomic deletion and
tombstone paths intact. This fixture is not a trusted elapsed-source measurement;
do not replace native elapsed observation clocks or claim real90-day retention
duration evidence. No production age/expiry, timeout or policy limit is changed.
Typed artifact authoring/registration and genuine independent review records may
use existing production services, but no direct committed completion/aggregate or
security/authority insertion may count as a positive result. A synthetic task reaches
completed only through the normal runner/completion gate under an issued runtime,
with all required evidence and current bindings. Genuine cancel uses existing
retention/task application path. Fixture helpers reuse services rather than add
test-only production completion ports. Missing production seam is an exception.

### R9-T3 Exact outcome and lifecycle oracles

For the existing synthetic completion rule threshold1/2,min_samples2:
I01 uses two genuinely completed tasks: numerator2/denominator2, supports.
I02 uses two genuinely canceled tasks:0/2,counter-evidence, both task references
retained and its configured investigation suggestion returned. I03 uses three
eligible tasks, two completed and one canceled, with two valid synthetic required
rules gte1/2 and gte3/4,min_samples2: same2/3 denominator for each, supports and
counter respectively, group mixed; its union of unfavorable references is exact.
I04 uses one eligible task with min_samples2: insufficient-data. Include a second
rule whose known samples support; insufficient precedence must still win. These
fixture thresholds are synthetic test inputs, not new real product policy.

I05 adds genuinely incomplete completion and completion-omitted live consent:
the former is unknown, the latter excluded; neither changes the known denominator.
I06 shares one rule between two hypotheses, retaining exactly one report rule and
original cohort task identity/counts; every hypothesis's required rules are present
and counter-reference unions are sorted/unique, never multiplied sample counts.
U09 asserts mixed success/failure samples under one threshold keep that rule's
supports/counter decision. Tests must fail if rules are omitted or their thresholds,
numerators/denominators, hypothesis precedence or catalog reference is changed.

I07 follows the same genuine P owner/root: grant → collect → context change → old
aggregate/report stale refusal → fresh collect with new context → unfavorable
report with enough samples → revoke → denied report → guarded purge → actual process
restart and tombstone/no-resurrection assertions. Capture original action/task
receipt/event bytes and verify report/context/revoke/purge does not rewrite them.
Use only the retention-clock fixture allowance above to reach the genuine purge
age inside this method's290s child; record exact configured age and keep the
retention-authority refusal cases intact rather than suppressing their checks.
The R root is independently prepared, with distinct issued runtime/authority objects,
and exercises foreign or revoked identity before metric access; never reuse P proof.

I08/W02 use two independently valid pinned source/installed configurations and
the same semantic eligible cohort, with exact identical engine-module hashes.
Vary the configured completion threshold/minimum and a smaller report/hypothesis
bound: record changed decision/suggestion or admission refusal as configured,
without changing engine code. Fixture source heads/cohort/policy digests may differ;
do not copy a retained aggregate/consent across them. Tampering a returned map or
monkeypatching loader trust does not establish a positive variation.

S04 uses independent processes and barriers for report-first and revoke-first
transaction order. Production BEGIN IMMEDIATE excludes concurrent writes; assert
that exclusion instead of releasing the lock to invent an interleaving. Revoke-first
publishes no old-generation response/receipt; report-first remains a consistent
earlier result and subsequent retained handle/replay refuses. S03 changes valid
installed config and verifies old consent/report replay cannot return a new-looking
suggestion; new consent/capture returns the exact new configuration.

S05 covers exactly-at/one-over hypothesis/catalog/reference/output byte bounds,
including multi-hypothesis duplicate reference overhead and UTF-8 sizing. A
fetch/parse/summary-buffer sentinel must prove rejection before the disallowed
materialization/growth, not a large allocation followed by rejection. S06 places
canaries in genuine synthetic task/artifact/authorization bodies, then inspects
report, error, receipt and persisted learning bytes; no prompt/body/secret copy or
catalog execution side effect. I09 preserves exact replay output/receipt and
sample count, rejects changed request digests and stale sources.

### R9-T4 Exact new selector inventory

The following stable IDs define the37 proposed methods, in this order:

- U01 `tests.unit.test_learning_reports.LearningReportUnitTests.test_all_support`
- U02 `tests.unit.test_learning_reports.LearningReportUnitTests.test_all_counter`
- U03 `tests.unit.test_learning_reports.LearningReportUnitTests.test_mixed`
- U04 `tests.unit.test_learning_reports.LearningReportUnitTests.test_insufficient_precedence`
- U05 `tests.unit.test_learning_reports.LearningReportUnitTests.test_empty_required_rules_rejected`
- U06 `tests.unit.test_learning_reports.LearningReportUnitTests.test_unknown_verdict_rejected`
- U07 `tests.unit.test_learning_reports.LearningReportUnitTests.test_duplicate_rule_rejected`
- U08 `tests.unit.test_learning_reports.LearningReportUnitTests.test_input_order_invariance`
- U09 `tests.unit.test_learning_reports.LearningReportUnitTests.test_ratio_semantics_unchanged`
- U10 `tests.unit.test_learning_reports.LearningReportUnitTests.test_counter_union_bounds`
- C01 `tests.contract.test_learning_reports.LearningReportContractTests.test_policy_v12_closed`
- C02 `tests.contract.test_learning_reports.LearningReportContractTests.test_experiments_v11_closed`
- C03 `tests.contract.test_learning_reports.LearningReportContractTests.test_required_rule_coverage`
- C04 `tests.contract.test_learning_reports.LearningReportContractTests.test_suggestion_partition_cycles`
- C05 `tests.contract.test_learning_reports.LearningReportContractTests.test_legacy_versions_preserved`
- C06 `tests.contract.test_learning_reports.LearningReportContractTests.test_report_v12_closed`
- C07 `tests.contract.test_learning_reports.LearningReportContractTests.test_owner_input_unchanged`
- C08 `tests.contract.test_learning_reports.LearningReportContractTests.test_installed_resource_closure`
- I01 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_supported_cohort`
- I02 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_counter_cohort`
- I03 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_mixed_hypothesis`
- I04 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_insufficient_cohort`
- I05 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_unknown_vs_excluded`
- I06 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_overlap_no_duplicates`
- I07 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_fr13_full_owner_journey`
- I08 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_valid_installed_config_changes`
- I09 `tests.integration.test_learning_reports.LearningReportIntegrationTests.test_report_retry_idempotent`
- S01 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_no_consent_no_source_read`
- S02 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_foreign_endpoint_no_read`
- S03 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_config_change_stale_replay`
- S04 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_revoke_report_process_race`
- S05 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_report_preallocation_limit`
- S06 `tests.security.test_learning_reports.LearningReportPrivacyTests.test_no_content_in_reports_or_receipts`
- W01 `tests.integration.test_learning_reports_wheel.LearningReportWheelTests.test_installed_hypothesis_report`
- W02 `tests.integration.test_learning_reports_wheel.LearningReportWheelTests.test_installed_valid_config_variation`
- W03 `tests.integration.test_learning_reports_wheel.LearningReportWheelTests.test_legacy_resources_preserved`
- W04 `tests.integration.test_learning_reports_wheel.LearningReportWheelTests.test_missing_or_replaced_resource_refused`

Existing regression inventory is the exact49 new_selectors plus162
regression_selectors in unchanged
`config/verification/authorized-stage-learning-boundary-v1.json` (raw SHA256
`c49537731976405f99f903ab7d14db98a8cc82beb2bac53029996bd2032f3074`).
This is an explicit211-method list, not discovery. Also see its complete method
names in [the authorized-stage Test Plan](authorized-stage-learning.md).
Freeze the concatenated37+211 list as248 distinct selectors in the detached
design inventory and future proposed boundary configuration. Keep existing method
names even where active-version assertions must become explicit legacy-version
tests. Verify AST/collector identities once after authoring; no renamed/removed
regression, optional skips or import-only pass.

Every test argv is exactly:

```text
.venv/bin/python -B scripts/run_wp09_tests.py --test <exact-selector> --timeout-seconds 290
```

Six future static argv:

- `.venv/bin/python -B scripts/check_architecture.py`
- `.venv/bin/python -B scripts/check_sources.py lint`
- `.venv/bin/python -B scripts/check_sources.py type`
- `.venv/bin/python -B scripts/verify_build.py`
- `.venv/bin/python -B scripts/verify_reproducible_build.py`
- `git diff --check`

### R9-T5 Data, installations and cleanup

Use synthetic task identities and private temporary source/installation/repository
roots. The proposed `tests/fixtures/learning-report-config-variants-v1.json` holds
bounded variant inputs; test-only helpers construct and independently validate
their exact complete policy/experiment documents before attestation/build. Retain
actual source/pin/resource/RECORD identity; no original checkout source changes while
tests run. Engine hashes agree across valid variants; each uses fresh consent and
normal source capture. Stop/reap child groups before deleting a fixture root.

Local macOS native/offline wheel fixtures are current scope. CI/Linux/staging/
production are not executed or certified by this design. New configuration tests
may build/install isolated package fixtures, not upgrade the Owner's installation.
The sibling workflow project is not a runtime dependency and need not be readable.

### R9-T6 Non-functional and compatibility boundaries

Security, privacy, byte/count admission, report atomicity, recovery and versioned
installed closure are in scope. Old learning1.0/1.1 bytes/validators, owner input1.0,
authority receipts, genuine category sources and migration regressions remain.
No PMF schema migration; export stays refused after PMF initialization/purge.
HTTP throughput, GUI/accessibility, causal PMF claims, native Linux and real
install upgrade/release performance are outside this local report increment.
This does not waive their later product acceptance. No timeout or revision-budget
extension can substitute for a failing/unfinished result.

### R9-T7 Design and future execution gates

Current design checks: JSON/Manifest structure, document references, exact six-file
scope, frozen selector uniqueness/count and independent artifact review/reducer.
No tests are added merely to compare prose. After separate implementation approval,
keep meaningful RED/GREEN evidence, verify before staging, then exact Candidate
scope/argv preflight before expensive canonical capture. Run all254 declared
commands on the final frozen product tree, serial and fail-fast; no concurrent
source/pin edits. Retain all failures/retries and use changed inputs/concrete
diagnosis for relevant recapture. Fresh evidence is required for changed product
bytes, not for a historical unchanged push. Candidate review and irreversible
authority remain separate. Any newly required API/target/data/budget/predicate is
an Owner decision before proceeding. There are no unspecified product outcomes.

### R9-T8 References and history

[Positioning](../positioning/graph-engineering-workflow.md), [PRD](../prd/graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md), [ADR0013](../adr/0013-learning-hypothesis-report-decisions.md),
[Impact](../impact/graph-engineering-workflow.md), [Plan](../plans/2026-08-13-graph-engineering-workflow.md).
2026-10-08 R0: owner-approved detailed design proposes37 new/211 existing tests,
six statics and genuine C04/C09/FR13 exit oracles; no implementation or test PASS
is inferred from method names or historical increment evidence.
2026-10-08 R1: resolve independent R9-TIME-01 by explicitly permitting the existing
synthetic repository clock for bounded retention/expiry only; same37/211 selectors,
real purge/retention/elapsed authority and290/300 ceilings retained.


## Security trust bootstrap test design — B1, 2026-10-08

### B1-T1 Scope and critical journeys

[Spec B1](../specs/graph-engineering-workflow.md#security-trust-bootstrap-design--b1-2026-10-08),
[ADR0014](../adr/0014-security-trust-bootstrap.md), [Impact](../impact/graph-engineering-workflow.md)
and [Plan B1](../plans/2026-08-13-graph-engineering-workflow.md) are upstream.
Current authority is design only: all25 new bootstrap tests below are proposed,
unimplemented/unexecuted. Retain exact37 report and211 regression methods and their
real positive source requirements. Require all critical journeys/oracles below;
no arbitrary line-coverage ratio or test-count pyramid replaces them.

| CUJ / Spec | Exit oracle | Selectors |
|---|---|---|
| BC01 / C01 | attested resource closure, immutable atomic install/replay, no partial writes | C01–02,I01,I05,S03,W02–03 |
| BC02 / C02,S4 | real issued same-owner/current approvals derive empty executable state; invalid initial approvals/replay publish nothing | C03,I02,S01–02,S05,W01 |
| BC03 / C03 | same original request preserves evolved state; conflicts/foreign/reapproval refuse | I03,I06,I10,S01,S04 |
| BC04 / C04 | failures/races/currentness and marker corruption refuse before publishing trust | I04–06,I09,S03–06 |
| BC05 / C05 | optional old/new no-PMF migration preserves provenance, destination currentness and PMF refusal | I08,C04 + retained migration/PMF selectors |
| BC06 / C06,R9-T2 | real collect/report/lifecycle, variants and installed positives with no SQL/private seal bypass | I07,S07,W01,W04 + all retained report acceptance |

### B1-T2 Layers, bounds and mocks

4 contract tests exercise real closed schema/parser/resource/projection validation;
10 integration tests use actual SQLite, installation/task/runtime services, durable
fault/restart/race control and local report lifecycle.7 security tests establish
negative admission/currentness/minimization/hold invariants.4 installed-wheel tests
use a fresh actual installed child and RECORD-attested runtime/resource path.
There is no new pure arithmetic to justify additional unit tests; the retained10
report unit tests remain. unittest and the existing single-test runner are used.
Each exact method must collect1/execute1/skip0. Every layer has the existing native
290s ceiling and canonical300s; no invented lower per-layer latency promises.

Mock only external typed agent/reviewer outputs, explicit fault callbacks and
controlled negative corruption. Do not mock production schema/resource/identity/
receipt validation, security issuer, actual DB transaction or completion/retention
gates. A source fixture may use the existing test-only source attestation issuer
on a complete private copied root. Positive runtime comes from real
RunningDistributionProbe/ExecutableLocator/RuntimeAdapterFactory/RuntimeSession
and its issued RuntimeContext; test helpers cannot construct a private runtime seal.
Direct trust/completion SQL inserts and unconditional PassingValidator cannot
establish any new positive. SQL corruption is allowed only as a negative mutation
after production services created the installation/task/scope source it corrupts;
initial-derivation refusals occur before task security initialization, after genuine
installation and task-source creation. It cannot manufacture an accepted source
or repaired trust row. R9's existing repository-clock exception
is confined to synthetic retention/consent expiry; elapsed clocks remain native.

### B1-T3 Exact bootstrap selector inventory

In this order, the25 methods are:

- C01 `tests.contract.test_security_bootstrap.SecurityBootstrapContractTests.test_descriptor_closed`
- C02 `tests.contract.test_security_bootstrap.SecurityBootstrapContractTests.test_receipts_closed`
- C03 `tests.contract.test_security_bootstrap.SecurityBootstrapContractTests.test_scope_target_projection`
- C04 `tests.contract.test_security_bootstrap.SecurityBootstrapContractTests.test_legacy_resource_bytes_preserved`
- I01 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_installation_atomic_replay`
- I02 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_task_derivation_empty_authority`
- I03 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_retry_preserves_evolved_state`
- I04 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_task_crash_restart`
- I05 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_installation_crash_restart`
- I06 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_parallel_initialization`
- I07 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_genuine_learning_lifecycle`
- I08 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_migration_roundtrip`
- I09 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_legacy_roots_distinguishable`
- I10 `tests.integration.test_security_bootstrap.SecurityBootstrapIntegrationTests.test_scope_reapproval_refused`
- S01 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_foreign_unissued_runtime_refused`
- S02 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_caller_trust_payload_refused`
- S03 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_missing_replaced_resources_refused`
- S04 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_stale_sources_race`
- S05 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_partial_marker_corruption_refused`
- S06 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_bounded_before_materialization`
- S07 `tests.security.test_security_bootstrap.SecurityBootstrapSecurityTests.test_receipts_minimized_holds_preserved`
- W01 `tests.integration.test_security_bootstrap_wheel.SecurityBootstrapWheelTests.test_installed_bootstrap_learning`
- W02 `tests.integration.test_security_bootstrap_wheel.SecurityBootstrapWheelTests.test_installed_resource_closure`
- W03 `tests.integration.test_security_bootstrap_wheel.SecurityBootstrapWheelTests.test_installed_substitution_refused`
- W04 `tests.integration.test_security_bootstrap_wheel.SecurityBootstrapWheelTests.test_installed_legacy_config_variants`

The immutable detached security-trust-bootstrap-test-inventory-r0.json freezes
these25 plus the unchanged37 report/211 regression selectors and all279 argv.
No alias, rename, skip, directory discovery or import-only pass. Existing211
class/method identities are verified by AST; future selectors are explicit planned
methods, not claimed collected. This273-test boundary is distinct from the excluded
historical full274/P1 profile. Final canonical inventory adds the same six statics.

### B1-T4 Concrete behavior and fault oracles

C01 admits a closed30-other-member descriptor and rejects unknown/duplicate/dangling
paths, wrong raw/semantic identities and self-hash cycles; actual full31 vector is
receipt-bound. C02 validates exact receipt shapes/domains/references and rejects
unknown fields, mismatched initial state/source digests. C03 validates the sole
aggregate scope target/nonempty approved baselines and empty execution fields using
existing identity/schema contracts. C04 compares all26 existing resource bytes and
foundation/learning contract versions, independently of new package mappings.

I01 initialize/retry returns one original install receipt and exact manifest/marker,
no new rows on repeat. I02 creates real task, freezes scope, approves PRD and uses
issued same-owner initializer; assert empty authority/registries, real derived binding,
no task revision/event change and action/disclosure refusal.

I02 also exercises initial refusals, before any task security row/receipt exists,
with an exact same-owner issued context and correct current CAS selectors:

| Initial-source defect / B1-S4,B1-C02 | Existing selector | Construction and exit oracle |
|---|---|---|
| No committed PRD approval / approval still draft | I02 | Normal TaskApplication-created task/frozen scope without PRD approval; a draft artifact is not approval. initialize_task refuses. |
| Missing frozen scope / scope remains drafted | I02 | Normal scope draft before approval; no approved frozen source. Refuse, never freeze/adopt it. |
| Missing scope approval record/event or ambiguous frozen approval | I02,S05 | Negative mutation of a genuine service-created scope/approval, deleting its approval reference or introducing conflicting scoped rows. Refuse even if caller supplies the original valid snapshot selector. |
| Duplicate baseline kinds / baseline reference not backed by committed approval | I02,S05 | Negative mutation of a genuine task's current references or approval association; exercise duplicate kinds and an unapproved reference independently. Refuse, never deduplicate/adopt/copy caller baselines. |
| Invalid replay / snapshot-only identity, scope or baseline provenance | I02,S05 | Corrupt event/transaction/head linkage, or substitute a locally digest-consistent snapshot projection that disagrees with the committed event replay. Refuse; a self-consistent snapshot alone cannot issue trust. |

For each case record exact task row/revision/snapshot/event/transaction/source bytes
immediately before calling initialize_task; assert neither task_security_states nor
security_bootstrap_task_receipts acquires a row and all recorded source bytes remain
identical after refusal/reopen. Existing installation receipt stays exact. No repair,
new task event, revision change or replacement source is allowed. Give each mutation
an independently valid unmutated fixture/control case, without treating the mutated
root as positive evidence. S05 repeats relevant corruption admission through the
new service; preexisting regression refusal at another API is not this oracle.
All cases are subcases of existing named methods, same25/37/211 inventory and
290/300 ceilings; use immutable resource/wheel fixture reuse within a method and
fresh service-created task/root state, not additional timeout allowances.

I03 uses actual task
events and real PMF registration to evolve security state; retry original selectors
returns original receipt without changing current bytes/subject flags; another
request ID/digest refuses. I04 faults immediately before state INSERT, between state
and task receipt INSERT, before COMMIT, and after durable COMMIT before response;
fresh reopen sees neither state/receipt or both, exact retry recognized once.
I05 repeats the analogous manifest/marker/install receipt fault cuts and asserts
unknown/partial prior states are refused, never repaired. Inject faults via the
existing repository callback mechanism; after-commit lost-response cuts are
application callback boundaries, never fabricated SQL commits.

I06 two processes with genuine distinct issued runtimes for the same durable
owner/kind/lineage contend using barrier-controlled real locks: same request yields
one creation/two identical receipts; different request has one creation/one conflict,
no deadlock/partial row/duplicate receipt. I07 uses grant → prospective completion/
cancel → collect → report → real revoke/deny/purge/tombstone/restart with actual
retention subject/fence consumption. I08 exports a legitimately bootstrapped no-PMF
root, imports with current destination manager/resources, checks exact original
receipt bytes/history and newly guarded issuance; mutated origin/resource/task
reference refuses. A second PMF-initialized/purged root still refuses export.
I09 unmarked historical root uses existing API but is explicitly not bootstrap
positive; any receipt table without marker or marker without tables refuses on all
four issuer entry points. I10 real PRD reapproval/scope change fails current issuer/
initializer replay without overwriting state; ordinary unchanged-scope snapshot
evolution from I03 remains valid. Refusal must preserve the original receipt/state.

S01 wrong/unissued/closed/PID-thread-invalid contexts and foreign owner/kind/lineage
refuse before task-body capture. S02 attempts caller manifest/registry/policy/state/
targets/authority/clock arguments and direct production setter/private-seal paths;
only defined selectors/issued context accepted, no trust rows written. S03 actual
missing/replaced schema/policy/manifest/RECORD and descriptor references refuse;
same semantic content with unauthorized installed raw bytes is not accepted.
S04 barriers at capture/precommit/issuance change actual activation/task/scope/
baseline/resources; final guard refuses and rolls back, no stale publication.
S05 remove marker while retaining receipts, remove receipt with marker, introduce
unreceipted state, invalid digest/partial namespaces/unknown marker; bootstrap and
all issuer entry points refuse without legacy fallback. S06 use real finite
WorkContext admission plus instrumented task-body/capture boundary to establish
oversized rows/resources/receipts/counts rejected before materialization/allocation,
not merely eventual rejection; no enlarged production profile. S07 sensitive
sentinel in legitimate external task bodies never appears in receipts/errors,
and actual hold/claim/retention state survives retry and blocks purge normally.

W01 actual installed production bootstrap/runtime/task/completion/learning lifecycle,
without sibling reference or SQL trust writes. W02 verifies exactly31 resources,
real RECORD closure and matching source/wheel validation. W03 actual absent/replaced/
ambiguous installed resource or changed distribution refuses before writes/use.
W04 legacy schemas stay exact; separately valid installed two-known-rule config
variant changes genuine decisions/bounds with identical engine hashes, new consent
and normal source capture. Unattested replacement is a negative, not a variant.

### B1-T5 Exact argv and evidence

Each test uses exactly:

```text
.venv/bin/python -B scripts/run_wp09_tests.py --test <exact-selector> --timeout-seconds 290
```

Six statics retain argv exactly: `.venv/bin/python -B scripts/check_architecture.py`,
`.venv/bin/python -B scripts/check_sources.py lint`, `.venv/bin/python -B scripts/check_sources.py type`,
`.venv/bin/python -B scripts/verify_build.py`, `.venv/bin/python -B scripts/verify_reproducible_build.py`,
`git diff --check`. Order:25 bootstrap methods,37 report methods,211 exact regressions,
six statics; strictly serial/fail-fast. Each retains success/failure, exact selector/
argv/counts, source/resource/tree binding and actual elapsed time. No full-suite
discovery or timeout-budget increase. Snapshot/recorder work uses the existing
canonical300 ceiling; do not substitute a native PASS for final canonical evidence.

### B1-T6 Data, environments and cleanup

Only synthetic task/owner/scope IDs, sentinel bodies and private temporary roots.
Reuse production services in proposed tests/support/security_bootstrap.py and retained
learning_reports.py. Fixtures reuse a built wheel only within a named method where
its exact bytes remain immutable; each process owns fresh repository/command/runtime
state. Before deletion reap child groups, release locks and close factories. No real
PII, Owner installation upgrades or production data. macOS source/offline installed
wheel current scope; CI/Linux/staging/production evidence remains later authorized
work. No external network/install dependency or sibling runtime requirement.

### B1-T7 Non-functional and open gates

In scope: deterministic trust/currentness/privacy, count/UTF-8 admission, crash/retry,
process races, source/wheel closure and old/new migration compatibility. GUI/accessibility/
HTTP throughput, native Linux/real install upgrade, full274/P1, WP10/WP11/monitoring
are outside this bounded local increment. No lower latency or coverage percentage
is asserted without a configured measurable requirement. Current design runs only
Manifest/links/whitespace/protected-source/inventory checks and independent review.
Product tests begin after concrete Owner implementation approval. Existing report
partial evidence remains partial. Any new file/dependency/authority/trust rule/budget
needs a decision before its affected task. All named behavior oracles are required.

### B1-T8 References and history

[Positioning](../positioning/graph-engineering-workflow.md), [PRD](../prd/graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md), [ADR0014](../adr/0014-security-trust-bootstrap.md),
[Impact](../impact/graph-engineering-workflow.md), [Plan](../plans/2026-08-13-graph-engineering-workflow.md).
2026-10-08 B1: exact25 bootstrap +37 report +211 regression methods/six statics
proposed with unchanged290/300 bounds. No new product test executed or passed.
R1: add explicit initial-source refusal subcases and zero-write/source-preservation
oracles to I02/S05 (GEW-SECURITY-BOOTSTRAP-TEST-PLAN-R0-001); same selector/argv,
target and budget boundary.
