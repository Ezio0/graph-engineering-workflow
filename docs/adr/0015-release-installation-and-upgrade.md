# ADR 0015: Release installation and upgrade

Date: 2026-10-10. Status: six-file design independently accepted; exact slice-A
implementation approved separately and in progress. Cold-launch strict launcher design
is accepted and implementation is in progress. This record grants no install or irreversible authority.

## Context

Accepted ADR0001 already selects Python3.12+, verified local platform bundles,
managed interpreter/uv installer boundary, canonical Skill lookup and staged
whole-tuple upgrade. Current source provides wheel preflight, locator/handshake
and repository migration. uv.lock omits the two declared direct dependency
closures, the old SBOM helper has empty components, and no complete release
manifest or product install/doctor surface exists. Old passes cannot prove these.

## Decision

Refine the accepted boundary into a typed release admission/plan/coordinator
flow, using installation-attested release policy/keys, domain-separated signed
ReleaseInstallManifest, exact METADATA-derived closure, lock/SBOM/provenance and
security evidence. Caller manifests/keys/results cannot grant trust or mutation.
Keep dependency/provider/parser choices and their existing activation blockers.

Separate read-only admission/Doctor (slice A), isolated interpreter/tool/Skill
staging (B), and quiescent repository plus atomic active-tuple publication and
recovery (C). Plan and diagnostic objects do not confer execution authority.
Actual Owner/runtime approval binds the exact operation/plan/prior tuple.

A registered WP10 installation has one authoritative active release reference
binding immutable interpreter/tool/Skill assets and the exact repository leaf
manifest. Existing installation control lock and migration API remain the
coordination boundary; repository-only publication must not bypass the parent
release coordinator. Ordinary commands revalidate the selected tuple under
the shared installation scope. No new task ActionAuthorityLedger kinds/seals
or physical database-copy migration path are introduced.

Retain compatible old tuples and append-only generation/journal provenance.
Verifying tuples do not execute. All staged/failure/crash paths resolve to old,
verified-new or explicitly blocked state; recovery never guesses, retries in
background or erases action history. Incompatible historical source/unmanaged
installs/bootstrap formats are diagnosed as unsupported transition inputs.
They are never silently adopted.

## Alternatives and consequences

Direct wheel installation or matching dependency strings cannot prove exact
interpreter/transitive bytes, license/security freshness or canonical Skill
origin. Independent executable/Skill/repository pointer writes permit mixed
tuples; selected immutable assets and one durable reference avoid that split.
A new parallel migration implementation would lose existing action/retention/
bootstrap invariants; reuse its verified export/import/replay and locks.

The accepted PMF-initialized export restriction remains: upgrading any such
repository through export is blocked, including empty/partial PMF schemas.
Preserve old CLI/data and report the limitation; do not silently omit PMF or
copy physical DB files. Full PMF-compatible upgrades would need a separate
Owner intent/compatibility decision.

This design adds no dependency/version, daemon, network source, real data
or actual installation. Slice A implementation must first freeze exact
code/schema/config/pin/test scope. Production release keys, interpreter/archive/
installer/wheel/provenance/security bytes and native environments remain
explicit prerequisites. Test fixture signatures prove validator behavior,
not production release authority. All planned platform cells and all later
upgrade/native/Skill acceptance remain required.

## Verification

Require closed records and preallocation bounds, genuine physical archive/
METADATA/RECORD byte checks, signed-manifest substitution/refusal and complete
SBOM/lock equality, read-only Doctor with zero clock/task/install writes,
same-bundle twice-clean-install equality, canonical runtime handshake,
fault/SIGKILL/concurrency at every publication boundary, live claim/hold and
PMF-export refusal, old executable/repository usability and data-preserving
uninstall. Missing native evidence is BLOCKED, not replaced with simulation.

## References

[Spec W10](../specs/graph-engineering-workflow.md#wp-10-verified-installation-design),
[ADR0001](0001-core-implementation-and-local-packaging.md),
[ADR0002](0002-local-event-repository-and-coordination.md),
[PRD](../prd/graph-engineering-workflow.md),
[Impact](../impact/graph-engineering-workflow.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[Test Plan](../test-plans/graph-engineering-workflow.md).

## Slice-A implementation gate

Actual private installed console-script testing found that Python writes its initial
package bytecode cache before package initialization. Strict read-only installation
acceptance remains unchanged. The Owner must decide a reviewed launcher design extension
or an explicit acceptance exception, recorded in the detached design-choice request.
No additional packaging target or altered launch architecture is implied by A approval.


### W10-A2 Owner-approved strict launcher amendment

The Owner approved the independently reviewed strict launcher design and then the
exact41-file/313-command implementation amendment. The immutable authority is
`wp10-release-admission-implementation-approval-r1.json`; reviewed design
`wp10-readonly-launcher-design-r1.md` (raw SHA256
`68d158085fcb2ebbd6efc8ceaf344bbba0b64b1dd41a5cf3730e5bb467881699`)
and `wp10-readonly-launcher-design-completion-r1.json` remain in the detached directory.
This supersedes only the previous pending launcher-choice language. G5 is unchanged;
prior failing evidence and all four W10-IMPLEMENTATION-R0 findings remain retained
until independently verified repairs. PRD/Intent, other native cells, B/C, PMF-export
refusal, production trust blockers and separate irreversible action gates remain.

Decision: preserve strict zero-write acceptance through a wheel-owned direct script
that disables import caches before product import. Choose this over accepting cache
changes, shipping version-specific pyc, global startup hooks or test-only suppression.
The finite wrapper is owned by the attested backend and bound to wheel RECORD; exact
custom build configuration replaces this command's console entry to avoid overwrite.
Private fixture spreading must exercise the packaged script, including interpreter
shebang and installed RECORD transformation; actual managed/uv installs remain later.
Bounded bootstrap refusal, callable-attested Requires-Python checking and per-Skill
protocol comparisons are mandatory. Implementation/review is authorized in exact41;
this ADR records a chosen design, not successful tests, actual install or commit authority.


### W10-A3 Owner-approved closed parser trust boundary

The Owner approved the reviewed `wp10-parser-trust-boundary-design-r1.md` (raw
SHA256 `7fd4d4f8f7060f9abb6fd2096537b1cfcda4aa81fcfd857ea5ff47c8a6a84fbb`)
and its concrete implementation request. Immutable approval is
`wp10-release-admission-implementation-approval-r2.json` in the detached directory.
The reviewed twelve-section design, including §4.3.1, is the normative amendment.
PRD/Intent, exact41 targets,313 commands, strict serial/fail-fast, native290/canonical300,
zero writes, diagnostics, dependencies/platforms and B/C exclusions remain unchanged.
This supersedes the selected-member parser strategy, not the retained launcher design.

Build one operation-owned, privately linked Version/_ranges/SpecifierSet closure and
canonicalize_version facade from physically RECORD-verified26.3 source. Validate the
ambient executable surface against its complete source-derived structural graph before
and after use and observation reuse. Exact types precede inspection; never invoke
suspect equality, descriptor, container or regex dispatch. Bind code/defaults/closures,
classes/metaclasses/bases, slots, aliases, containers/constants/singletons, regex and
legitimate generated helpers/caches. Unknown dependency sites/objects refuse. Compute
Requires-Python using private objects, return only a bool, and retain the same owned
provider through the verifier/observation. No ambient fallback, global image cache,
candidate code, package import hook, sys.modules publication, external action or new
persistent schema is permitted. Trusted CPython/stdlib/backend remain the stated base.

Construction has its own closed effects inventory. Omit exactly six overwritten
overload stubs and the enumerated unread annotation-only declarations/imports before
execution; preserve concrete function-code/defaults and future-annotation strings.
Use finite local NamedTuple/ABC/enum/functools/wrapper recipes and a non-caching regex
compiler facade. No private graph may escape into ambient overload/typing/regex
registries; never clear or replace shared registries to repair a leak. Success, failure,
release and repeated construction must preserve ambient bindings and permit private
graph collection. Partial construction and release drop local references/tracebacks.

Preserve implementation r0–r4 and the r4 regex finding. The separately approved exact
task-local Policy exception selects max_revision_cycles5 only for implementationr5;
project Policy and other nodes remain4, with original inputs used for historical replay.
No task/numbering reset, frozen reducer edit or host permission change is authorized.
Non-PASS at r5 stops. Only actual implementation ADVANCE permits canonical313 and
subsequent verification/Candidate review. No completion or commit/push is implied.

Decision: choose the closed source-derived contract plus private constraint execution over repeated member patches, ambient execution after checking, subprocess expansion or a handwritten PEP440 subset. Construction projections preserve executed semantics and avoid global retention. The explicit task-local r5 exception handles recorded non-convergence without resetting history or changing project defaults.


### W10-A4 Owner-approved effective-global-binding repair

The Owner separately approved `wp10-parser-global-binding-repair-request-r0.json`
(raw SHA256 `d64f1b46975b38f15d3c500e7a4e87f7fc1052676d531c930a39d589a089ff22`)
through `wp10-release-admission-implementation-approval-r3.json`. This is a routine
correction to the W10-A3 architecture: resolve reference and live function bindings
independently using globals first, builtins second, then compare effective bindings
without invoking a substituted callable. Preserve explicit name presence, the trusted
import recipe, all private-construction/currentness guarantees and existing regressions.

The r5 independent review resolved eight historical findings and retained
`W10-IMPLEMENTATION-R5-001`; its actual ESCALATE/E_LOOP remains immutable. This new
approval supersedes only the r5 stop/budget for one implementation revision6 with
an exact task-local ceiling6 (previous selected ceiling5); project/default and other
nodes remain4. Preserve the same task, prior digest and exact historical reduction
inputs. Non-PASS at r6 stops. Exact41,313 commands/307 selectors, native290/canonical300,
serial/fail-fast, zero writes, diagnostics and all exclusions remain unchanged.

Add meaningful SOURCE/WHEEL acquisition, public refusal, retained-invalidation and
restoration coverage for `packaging.utils.isinstance` shadowing within existing
W10-016/W10-026 selectors; require zero substituted calls, bounded independently
checked diagnostics, privacy, empty stderr and unchanged inventories. Retain actual
RED/GREEN and run six statics before fresh independent implementationr6 review.
Only actual ADVANCE permits canonical313, verification and Candidate review.

### W10-B1 Retained design authority and isolated staging precision

Slice A completed, independently verified, committed and pushed at
`2a8ecbbabc069fd2897d1bec53bf29dfe9f44222`. Its313 evidence records and immutable
Receipt remain authoritative for that tree. Historical in-progress statements above
do not describe current A status; they preserve the original decisions and gates.

The original six-file WP10 design approval remains valid for routine B clarification,
traceability and testability. Reuse its task, graph, Policy and four-cycle node budget;
retain Spec0/Impact0–1/Plan0/TestPlan0 and review changed bytes at their next revisions.
No new approval or broader routine-change vocabulary is manufactured from task rollover.

[Spec W10B](../specs/graph-engineering-workflow.md#wp-10-isolated-staging-clarification--w10b-2026-10-12)
clarifies already accepted private versioned staging, exact plan authority, physical
post-install verification and normalized manifest versus mandatory local binding.
Installer recipes are installation-owned bounded data, with empty production recipes
until exact supported binaries/argv/offline evidence are supplied and approved.
Stage receipts select no active tuple. C retains repository coordination/publication;
actual Owner/runtime issuer integration must be closed before an implementation request.
New authentication or other material choices retain their Owner gate. No product code,
actual installation, production trust, PMF export, native certification or irreversible
authority follows from this design clarification.

### B0 implementation observation — 2026-10-13

The approved B0 increment implements only closed contracts and owned read-only planning
through the existing source/wheel trust boundary. No new issuer, authentication mechanism,
installer execution, installed normalizer, staged receipt or C publication was introduced.
Production recipes/roots remain empty. Focused observations are retained; same-tree327
evidence and independent graph/Candidate gates determine final B0 acceptance. Full B and
three-platform native acceptance remain separate prerequisites, with no ADR decision
changed by this implementation status note.
