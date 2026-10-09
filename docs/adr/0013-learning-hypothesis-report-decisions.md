# ADR 0013: Learning hypothesis report decisions

Date: 2026-10-08. Status: Owner approved decision semantics; detailed design R0
under independent review. Implements PRD FR-13 / US-12 inside the approved six-file
design stage. Product implementation, commit and installation are unauthorized.

## Context

The receipted `c051c09` increment supplies prospective genuine approved-category
counts with source/currentness/privacy protections. Existing report rules evaluate
completion ratios and retain counter-evidence, but lack hypothesis/next-experiment
mapping. Main Spec W9.7 permits mixed without defining how it relates to the
existing exact rational evaluator. Current real report tests show insufficient
data, not all four genuine cohort decisions or the full FR13 owner journey.

## Decision

Keep evaluate_rule's integer/rational meaning. Group configured required rules
by hypothesis. Any insufficient required rule makes the group insufficient-data;
otherwise opposing supports/counter results make mixed; unanimous results yield
their existing supports/counter decision. A cohort containing successes and
failures alone does not imply mixed. Do not invent a Boolean predicate for
authorized_stage or other count/time metrics.

Configure one bounded next-experiment reference per hypothesis outcome, resolved
against a separate closed planning catalog of opaque IDs/purpose codes. Catalog
entries have no outgoing edges or execution payload; their IDs are disjoint from
reportable experiments. All required rules remain visible. Unknown/dangling IDs,
duplicates, incomplete group coverage, attempted active-ID cycles and unknown
fields fail closed before metric body reads. Suggestions confer no consent,
execution authority or product-direction approval.

Add policy/report contracts1.2 and experiment contract1.1/resources; retain old
bytes and validators. Keep observation1.1, input1.0, PMF1.1, ordering and migration
formats. No DB schema changes. Existing combined policy/source identity includes
the new experiment resource, so config changes require fresh consent and capture.
Report1.2 response is versioned; old response-only consumers must refuse unknown
versions. Do not fabricate new fields in historical reports.

## Alternatives

Changing one threshold rule to yield mixed when samples contain both successes
and failures would erase its rational decision meaning. Unbounded generated prose
or task text in reports would defeat minimization and closed validation. A
general experiment execution graph would add authority/lifecycle semantics not
requested for local recommendations. Keep this planning-reference boundary.

## Consequences and verification

Consumers can identify a configured hypothesis, exact unfavorable evidence and
next experiment without reading task content. The catalog is a recommendation,
not a runnable configuration; actual follow-up experiments need separately
reviewed parameters/authority. Configuration, package registration and pins must
remain exact and current. Multi-hypothesis overlap does not increase samples;
report budget accounts for all summary bytes. Native test<=290s and recorder<=300s
remain unchanged, serial/fail-fast.

Required evidence: genuine supported/mixed/counter/insufficient cohorts; exact
threshold/count/unknown/excluded/reference behavior; full grant/context/stale/
recollect/unfavorable/revoke/deny/purge/restart journey; valid installed config
variation; source/wheel closure, substitution/privacy/currentness refusals and
existing learning/authority/migration regressions. No positive completion or
authority may be inserted directly to satisfy these tests.

PMF-initialized export restriction, prospective unknown legacy windows, Linux
native evidence and WP10/WP11 obligations remain as previously accepted/required.
Detailed fields, errors, resource limits and actor access are in
[Spec R9](../specs/graph-engineering-workflow.md#wp09-report-completion-design--r0-2026-10-08).

## References

[PRD](../prd/graph-engineering-workflow.md), [Positioning](../positioning/graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md), [Impact](../impact/graph-engineering-workflow.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md), [Test Plan](../test-plans/graph-engineering-workflow.md).
