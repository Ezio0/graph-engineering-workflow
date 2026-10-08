# Authorized stage learning implementation plan

## 1. Summary

Design revision0, 2026-10-08. Implements the reviewed [Spec](../specs/authorized-stage-learning.md) through three prospective phases: contracts/order maintenance, consented projection/currentness, and verification/package closure. This document proposes later implementation, not current code/test authority. One root writer owns every file; a separate read-only reviewer reviews exact artifacts/Candidate. Estimate 3–4 working days, not a promised elapsed deadline; actual durations remain “not started” until implementation. Done means every named test and static command passed on the staged tree, independent Candidate review and an explicitly authorized commit with verified receipt.

## 2. Phases

| Phase | Goal | Exit criterion |
| --- | --- | --- |
| P0 | Freeze contracts and same-database order/maintenance | Exact fields/version/resources implemented; atomically preserved old/new states at all fault points |
| P1 | Prospective owner-consented count and report source binding | Nine CUJs covered; stale reports/retries rejected at unchanged task head; zero foreign body reads |
| P2 | Compatibility, boundaries and source/wheel proof | All exact selectors and six static commands pass; package inventory and bootstrap pins agree |

Dependencies follow P0→P1→P2. [Spec §§5–7](../specs/authorized-stage-learning.md) supplies storage/API/error contracts; [Impact](../impact/authorized-stage-learning.md) supplies compatibility and privacy boundaries.

## 3. Task breakdown

All tasks are prospective and not started. Kanban IDs are this table's stable AS-T IDs; no parallel board is required. Root owns code; the independent reviewer has no write ownership.

| ID | Phase/size | Estimate / actual | Work and exact file groups | Depends / blocks |
| --- | --- | --- | --- | --- |
| AS-T01 | P0 / S | 2h / not started | New policy/schema resources, loader's versioned old/new validation, pure projection in core learning; contract/unit test files | none / T02,T04 |
| AS-T02 | P0 / M | 4h / not started | Action storage ordered rows and atomic append; new integration/unit fault and metadata tests | T01 / T03,T04 |
| AS-T03 | P0 / M | 4h / not started | Migration initializer, optional bundle1.2 namespace and current-epoch resealing; old bundles and PMF export guards | T02 / T04,T06 |
| AS-T04 | P1 / M | 4h / not started | PMF window/schema1.1 consent/observation/derive, PRD revision reuse and history category count in storage learning | T01,T02,T03 / T05 |
| AS-T05 | P1 / M | 4h / not started | Shared-budget metadata/body readers, replay/report freshness, live selected-task gates and retention/purge invariants | T04 / T06 |
| AS-T06 | P2 / M | 4h / not started | Bootstrap/source attestation/core resource list/build packaging closure, installed wheel genuine chain; exact regressions | T03,T05 / T07 |
| AS-T07 | P2 / S | 2h / not started | Canonical evidence, scope/hygiene, independent Candidate, concrete next-authority proposal | T06 / separately authorized commit |

- [ ] T01: old experiments validate separately; exact closed new schemas reject extra/unknown fields; config mapping supplies count semantics.
- [ ] T02: sidecar append cannot commit separately from original event; two writers produce unique commit order; original receipt bytes remain.
- [ ] T03: every maintenance/import/reseal fault yields validated old/new state, preserves archived order and refuses unknown formats; PMF still blocks export.
- [ ] T04: only current consent/PRD/epoch approvals count; retry/category duplicates do not inflate; old provenance remains unavailable.
- [ ] T05: report and receipt replay detect new approved event at unchanged task head; body-read instrumentation proves AS-SPEC-01 boundary and both projections are charged before allocation.
- [ ] T06: installed factory/session/human-port path produces same semantics as source; protected source/resource closure and original owner operations pass.
- [ ] T07: exact selected methods are collected/executed once without skips and all required statics pass; Candidate evidence binds same tree.

TDD order: implement meaningful synthetic fixtures/behavior tests before changing their production path; observed initial failures are retained. No tests that only mirror documentation text or implementation strings.

## 4. Dependencies

| Type | Dependency/status | Handling |
| --- | --- | --- |
| Internal | receipted ce476d4 action decision/ledger and current WP09 consent — available | Reuse genuine runtime/installation interfaces; no test-only approvals |
| External | human decision port — synthetic isolated boundary available | Inject only that external port through the actual factory; no live external target |
| Infrastructure | local SQLite/venv/offline wheel toolchain — existing | No new package installation or network dependency |
| Authority | implementation files/tests — pending after design completion | Present this exact reviewed inventory; no code writes before approval |
| Platform | native Linux evidence — outside local boundary | Later environment/authority; never label macOS as Linux proof |

## 5. Risks and mitigations

| Risk | When/likelihood/impact | Mitigation |
| --- | --- | --- |
| Source closure misses new resource | P0/P2, medium/high | Add exact resource paths and refresh all three bootstrap pins; wheel parity and reproducibility checks |
| Existing receipt tests assume old component only | P0/P2, medium/high | Preserve old ledger bytes, schema/input1.0 and run exact old action/migration regressions |
| PMF record growth exceeds16KiB | P1, medium/high | Fixed-size cursor, schema worst-case capacity reservation; never widen budget or truncate |
| Tests accidentally manufacture human approval | P1/P2, medium/high | Genuine factory/session with only external port injection; forged decision negative test and real two-process barriers |
| New files required outside inventory | Any, medium/high | Stop product writes at exact boundary, prepare amendment; routine edits stay within37 files |

## 6. Rollout strategy

Only synthetic isolated initialization/import/upgrade is proposed in this implementation. Percent rollout and production canary do not apply to this local design increment. No real installation, user data, commit/push or release is authorized. A maintenance fault must leave the exact old state or a validated complete new state; transaction rollback is immediate, while restart/retry recovery is measured in tests rather than an invented SLA. A committed unknown/corrupt component blocks the affected endpoint and requires explicit maintenance; do not drop tables or relabel versions. Omit this metric through consent/config for a reversible unavailable fallback; preserve action audit, holds and tombstones.

## 7. Verification plan and exact implementation targets

[Spec §§6–10](../specs/authorized-stage-learning.md) and the [Test Plan](../test-plans/authorized-stage-learning.md) govern runtime semantics. The complete prospective allowlist is exactly these37 files (including all six design files, because implementation will update Manifest/evidence references):

- `.workflow/manifest.json`
- `docs/specs/authorized-stage-learning.md`
- `docs/impact/authorized-stage-learning.md`
- `docs/plans/2026-10-07-authorized-stage-learning.md`
- `docs/test-plans/authorized-stage-learning.md`
- `docs/adr/0012-authorization-learning-window-cursor.md`
- `core/graph_engineering/core/learning.py`
- `application/graph_engineering/application/learning.py`
- `storage/graph_engineering/storage/learning.py`
- `storage/graph_engineering/storage/action_authority.py`
- `storage/graph_engineering/storage/migration.py`
- `core/graph_engineering/__init__.py`
- `pyproject.toml`
- `config/learning/learning-policy-v2.json`
- `config/contracts/schemas/learning-policy-1.1.0.json`
- `config/contracts/schemas/learning-record-1.1.0.json`
- `config/contracts/schemas/learning-report-1.1.0.json`
- `config/verification/authorized-stage-learning-boundary-v1.json`
- `config/verification/wp-00-targets.json`
- `config/migration/migration-rehearsal-installation-bootstrap-v1.json`
- `config/profiles/scenario-truth-installation-bootstrap-v1.json`
- `config/release-operations/release-operations-installation-bootstrap-v1.json`
- `tests/support/source_checkout_attestation.py`
- `tests/support/action_authority.py`
- `tests/unit/test_authorized_stage_learning.py`
- `tests/contract/test_authorized_stage_learning.py`
- `tests/integration/test_authorized_stage_learning.py`
- `tests/integration/test_authorized_stage_learning_wheel.py`
- `tests/security/test_authorized_stage_learning.py`
- `tests/integration/test_wp09_learning.py`
- `tests/integration/test_wp09_learning_metric_sources.py`
- `tests/contract/test_wp09_learning_contracts.py`
- `tests/unit/test_wp09_learning.py`
- `tests/security/test_wp09_learning_privacy.py`
- `tests/integration/test_action_authority.py`
- `tests/integration/test_action_authority_wheel.py`
- `tests/integration/test_wp06_migration_repository.py`

No other file is inferred from git status. Existing old schema/policy files are preserved; new policy is learning-policy-v2.json and new record/policy/report schemas are1.1.0. The future config/verification boundary is populated from the exact detached inventory, not from directory-wide test discovery. Proposed evidence commands are enumerated in the Test Plan; invocation only after implementation authority. Commit/push/deploy/release are absent.

## 8. Open questions

Before implementation begins: independently approve exact selectors and package closure, and resolve any review findings within budget4. There is no unresolved product meaning or API shape for code to guess. If implementation exposes an incompatible contract or needs another target, prepare a concrete amendment under the project scope rule; do not silently extend this plan. Existing approvals remain valid for their unchanged action/scope.

## 9. References

[Spec](../specs/authorized-stage-learning.md), [Impact](../impact/authorized-stage-learning.md), [ADR0012](../adr/0012-authorization-learning-window-cursor.md), [PRD](../prd/graph-engineering-workflow.md), [Positioning](../positioning/graph-engineering-workflow.md). Exact draft inventory is detached wp09-authorized-stage-implementation-inventory-draft-r1.json:37 files,49 proposed new methods,162 AST-verified existing methods and6 static commands. Tests have not been executed in this design stage.

## 10. History

| Date | Change |
| --- | --- |
| 2026-10-08 | Initial plan for the reviewed prospective distinct-category metric; retained approved filename dated proposal2026-10-07. AS-SPEC-01 body gate included in tasks/tests. |
