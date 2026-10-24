# Graph Engineering Workflow — Impact Analysis

## 2026-09-20 RS-C installation-control read impact — proposed R0

Human update (2026-09-20): the owner replied “确认” to the final one-file
request, approving GEW-REMAINING54-P3-COLD-INSTALLATION-CONTROL-V1. The
append-only p3_restart_cold_installation_control_amendment records this exact
extension. Current boundaries are185 product /195 effective /41 selected
targets. The reviewed proposal below is historical; its implementation scope
and all exclusions remain unchanged. Prior RS-C R2 approval stays valid.

The required new write target is exactly
`storage/graph_engineering/storage/migration.py`. It is outside the currently
approved184 product targets and remains unmodified pending Human decision
`GEW-REMAINING54-P3-COLD-INSTALLATION-CONTROL-V1`. Approval would add only
this file: product184 ->185, effective194 ->195 and current Manifest40 ->41.
The proposed change is limited to the two private installation-control reads
specified in Spec RS-C's installation-control amendment and their helper.

Read-only inspection independently confirmed that `_current_manifest` and
`_load_locators` materialize whole files before bounds on every cold currentness
path, including nested connection admission. Skipping those checks, a separate
unbounded context, or checking file size before an unchanged later `read_text`
would leave the required composite cold bound unproved. Existing installation
and repository authority semantics must remain intact.

This source is already packaged and source-attested. After approval, update
the active Manifest and exact authority test before implementation, retaining
the historical184/183/181/179/174 identity chain and equal-cardinality
substitution rejection. Refresh only affected current source/protected-resource,
action/security and bootstrap/pyproject pins through the existing RS cascade.
Package membership, historical bootstraps and read-only dependency bytes remain
unchanged without exception. Pin refreshes are limited to current, explicitly
authorized consumer files whose actual input projection changes.

Focused verification uses existing release integration/unit and Remaining54
authority test files. Main risks are an omitted nested read, an inherited or
foreign lexical owner, growth after stat, premature reservation release and a
weakened manifest/locator/root check. The supplemental Test Plan names each.
No new file, dependency, public API, DB schema, GraphRef, data access, production
action or commit authority is requested. Plan244/oracle122/missing30 and all
performance, cumulative, coverage and WP-10 boundaries remain unchanged.

## 2026-09-20 RS-C source and locator impact — R2

Human update (2026-09-20): the owner's response “继续” to the final R2
API request authorizes GEW-REMAINING54-P3-COLD-SOURCE-READ-API-V1, recorded
in p3_restart_cold_source_read_api_amendment. The not-yet-authorized wording
in the reviewed proposal below is historical and is superseded only for this
exact API, consumers, resource hardening, tests and independent review.
The184/194 boundaries and all irreversible exclusions remain unchanged.

Spec RS-C refines approved RS-4/RS-5. Primary implementation stays in the
already allowed profile_execution.py, release_operations.py and local release
adapter. Tests use existing release unit/integration files and category/runtime
support. The complete ArtifactRecord and LogicalBodyManifest modules/configs
are read-only dependencies. R2 proposes one bounded read API on the existing
TaskRepository plus consumers in existing tasks.py and profile_execution.py;
this additional API requires Human approval before implementation. No new
schema, event, dependency or file is proposed. The product allowlist stays184.

R0 finding GEW-REMAINING54-RS-C-SOURCE-BOUNDS-R0-001 requires bounds before
any task/event/reference/CAS materialization, including the locator. The
proposed exact API and two closed phases are in Spec RS-C-0. Implementation
targets are storage/graph_engineering/storage/repository.py,
application/graph_engineering/application/tasks.py and
application/graph_engineering/application/profile_execution.py, with the already
planned release factory/adapter changes. objects.py, connection.py, leases.py
and storage/actions.py remain read-only. Tests belong to the existing
tests/integration/test_wp08_release_operations.py and
tests/unit/test_wp08_release_operations.py plus existing category/runtime support.
No storage SQL or unchecked connection access moves into application code.

The existing181/183/184 amendments remain intact; RS-AP approved action
provenance only. Do not infer authorization for this second query from its
file already being listed. Until explicit approval and independently reviewed
design, implementation remains blocked; completing this reviewable proposal is allowed.

Cold source validation requires these existing installation inputs to be
explicitly protected rather than accepted as caller documents:
`config/contracts/artifact-contracts-v1.json`,
`config/contracts/artifact-schema-registry-v1.json`, and the four existing
`config/contracts/schemas/{artifact-contract-registry,artifact-lifecycle-event,
artifact-record,logical-body-manifest}-1.0.0.json` files. Resource profile,
cost schedule and schema profile use current installed authority. Actual reused
artifact validator/manifest source modules must also be in the closed source
and wheel projection. Their bytes stay unchanged.

Use only existing authorized loader/source/bootstrap/pyproject/support paths
from the RS provenance cascade below. The release schema vector stays18;
artifact schemas belong to an exact separate existing-contract source closure.
No generic unbounded schema discovery or fallback to checkout paths is allowed.
Re-sign only affected current bootstrap consumers, never historical versions,
plan/oracle values or workload data. If an exact required write target falls
outside184, stop before writing it and identify that path.

Main risks are semantic/raw digest confusion, category labels mistaken for
artifact proof, incomplete independent review linkage, locator reads mistaken
for authority, and marker admission accidentally allowing ordinary member
access. RS-C tests isolate each. A full ArtifactValidator authoring reevaluation
requires independent input/requirement resolvers not supplied by this recovery;
no self-derived validation context may stand in for them. Recovery validates
the existing committed acceptance/body/review contract stated in Spec RS-C.


R2 repairs the composite-read design findings without adding a second data
contract: application/actions.py consumes already captured RS-AP journals;
storage/security.py bounds its existing installed-runtime/task-state reads;
application/security.py and release_operations.py preserve complete current
authority checks. Existing repository.py owns the private reservation ledger,
and profile_execution.py/release_operations.py own its cold lifetime. All are
inside184. No change to storage/actions.py, objects.py, connection.py, leases.py
or core WorkContext APIs is proposed. Public action/security signatures stay
compatible; only the named task/source query is a new storage read contract.

The private ledger shares remaining allowance across exact installed contexts,
retains both nested/outer captures until comparison and charges the handle
projection until close. It must not become an input authority, global mutable
budget or reason to raise configured limits. Existing source/bootstrap/action/
security pins for actually changed readers and consumers must be refreshed
through the established cascade below. Read-only references retain their bytes.
The prior RS-AP review remains evidence for its narrower accepted artifact,
not proof that this stronger composite cold bound already works.

## 2026-09-20 RS-AP authorized storage read impact — R1

Human `p3_restart_action_provenance_amendment` approves exactly one additional
existing source: `storage/graph_engineering/storage/repository.py`, raising
the product allowlist183 ->184. This supersedes only the historical storage
repository read-only exclusion below; journal/lease/connection source files
remain read-only. The existing Spec RS-AP defines the new query and consumer.

The repository owns one parameterized read snapshot and persistent index,
claim outcome, event/transaction and receipt-reference facts. The application
owns current authority and normal/compensated completion joins. No SQL moves
to application, no connection role is weakened, and no schema/event/GraphRef/
dependency is added. Existing read/write APIs keep their behavior. Extracting
the existing event-chain validator into a pure internal helper is allowed to
reuse the same checks for a captured snapshot; normal replay must retain them.

Risks: mixed snapshots, duplicate digest aliases, unchecked outcome/index
columns, invalid transaction references, rejecting valid shared receipt CAS,
mistaking historical original deployment state for current rollback, read-side
clock writes and unbounded collection materialization. Spec RS-AP and Test Plan
RS-AP bind explicit failures and no-write/concurrency/resource checks.

R1 resolves design finding GEW-REMAINING54-RS-AP-CAS-BOUND-R0-001:
the existing CAS verifier reads to EOF before checking size, so the new reader
must not call it. A private bounded reader in `repository.py` validates actual
descriptor size/identity before allocation, limits incremental reads despite
growth and aggregate retained receipt bytes, and preserves no-follow, owner,
mode, path binding and digest checks. Oversized metadata, falsely small
metadata, growth, aggregate overflow and exact-limit acceptance require tests
with byte-count assertions and zero writes/resource leaks. `objects.py` and
`connection.py` stay unchanged; this refinement adds no target or permission.

Update the existing authority security test to subtract precisely this approved
path before validating the unchanged historical183/181/179/174 identity chain.
Preserve the historical exact174 digest and equal-cardinality substitution
attack. Update the active Manifest before editing code. Existing four
p3-foundation-r2 containers retain append-only design/implementation records.

The storage file is already in source/package membership; do not add another
file or change membership. Refresh protected-resource/bootstrap/pyproject pins
only for actual changed projections (including application actions if changed).
Prior source bytes and reviews remain historical; new bundles bind this
amendment. Existing production data, workload/oracle settings and plan244/
oracle122/missing30 remain unchanged. No additional commit or external action
is authorized. Full cold recovery still requires later RS-4/RS-5 completion.

## 2026-09-19 RS-BS prerequisite impact — R0

Authority and design: ADR-0009 RS-BS, Spec RS-BS-1/2, Human
`p3_restart_bridge_security_amendment`. Exact target count grows 181 -> 183
only for `application/graph_engineering/application/security.py` and
`storage/graph_engineering/storage/security.py`. Existing actions.py/tasks.py,
WP-08 release unit/integration tests and authority contract tests are already
allowed. No core graph state, storage schema, new source file, event or GraphRef.

Task reads gain verified event-to-domain ordinal validation; both write paths
use repository head ordinals. Action snapshot production preserves the closed
domain wrapper; legacy action-only behavior remains. Public clock-writing
security issuance stays unchanged; the new doctor read has no write authority.
Main risks: mixed history acceptance, stale load/replay join, dropping unknown
wrapper fields, missing compensation/concrete action write sites, shallow
immutability and accidental trusted_now calls. Tests are explicit in RS-BS.

Source modifications require fresh source-checkout attestation and affected
protected-resource hashes. Recompute release/scenario/performance/migration/
dependency bootstrap or pyproject projections only if their actual inputs
change. Preserve the paired package source/resource ordering. Recompute action
registry/policy/security-runtime cascade only if its actual build/source
projection changes. Existing source membership and schema counts are unchanged
by these two already-packaged security modules. Preserve historical bootstrap
bytes, oracle, workload/noise settings, plan shape 244/122/30 and prior records.

Record this design in new append-only RS-BS arrays in existing docs containers,
and implementation evidence in existing p3-foundation-r2 containers. Capture
upstream RS-1 hashes before supplements; its 27 tests remain historical evidence
only and must not be relabeled as tests of new code. Independent reviews and
actual reducer decisions bind each new raw-byte bundle.

## 2026-09-19 P3 restart design impact — R1

This is a design-only proposal (P3-RS-A), not implementation authorization.
It follows local commit `ff7feda` and preserves Positioning/PRD, the exact179
Envelope, all historical review records, and plan244/oracle122/30 missing.
The current unconditional release restore rejection remains correct until the
complete proposed trust chain is implemented and verified.

The material change is retention across process exit plus a new, explicitly
read-only recovery issuer. The trusted runtime namespace and repository anchor
must remain outside caller evidence. Physical-root binding prevents copied
logical IDs from substituting another simulator. Destroy/abort remains explicit
owner work, not a recovery side effect. Orphan retention is a real disk-lifetime
cost; recovery neither scans nor cleans it. A missing or invalid marker produces
a safe denial, potentially requiring manual owner cleanup.

| Proposed affected layer | Existing implementation targets / compatibility boundary |
|---|---|
| Platform-neutral binding validation | `core/graph_engineering/core/release_operations.py`; adapter-specific physical checks stay out of core |
| Root identity and lifetime | `adapters/graph_engineering/adapters/local_release_simulator.py`; legacy disposable close and v1 target digest unchanged |
| Fresh read-only action and release evidence | `application/graph_engineering/application/actions.py`, `release_operations.py`; no resurrected ActionOutcome or mutation gate |
| Task/CAS/source recovery | `application/graph_engineering/application/profile_execution.py`; read-only reconstruction, no weakened final completion fence |
| Installed resource closure | Existing profile schema registry, release bootstrap, source/wp-00 manifests and pyproject; only actual input projections re-signed |
| Focused tests and support | Existing WP08 release unit/integration/Remaining54 authority-contract files and release/category/runtime test support; no coverage plan/oracle edits |
| Proposed new paths | Two `release-recovery-binding[-input]-1.0.0.json` schemas named in ADR-0009; **not currently allowed and not created** |

Future exact change selection must be a subset of the accepted179 plus those
two proposed schemas, not a blanket edit of every listed consumer. Required and
conditional provenance cascades are listed below. A pin cycle, new storage
API/schema, new file or unverifiable source requires a concrete authority
decision, not a fallback.
Storage journal/lease/repository files are read-only references, not proposed
write targets. Assessment 1.0–1.4 and release-observation 1.0 remain compatible.

### RS provenance cascade (proposed implementation only)

All paths below are exact and project-relative. Derive hashes after actual
inputs are final, without fixed-point or downstream-to-upstream feedback.

| Trigger | Required existing target / closure |
|---|---|
| Binding schema pair | `core/graph_engineering/core/release_operations.py` exact IDs/validator; `config/contracts/profile-schema-registry-v1.json` exact ID/domain/raw mapping; `core/graph_engineering/core/profiles.py` only if closed domain membership requires the new contract |
| Release schemas grow 16 -> 18 | `core/graph_engineering/__init__.py` exact length/uniqueness, not an unbounded vector; `pyproject.toml` release schema sources/resources/package lists; `config/release-operations/release-operations-installation-bootstrap-v1.json` schema vectors and protected closure |
| Shared profile_execution.py / loader / schema-registry change | `config/performance/performance-benchmark-installation-bootstrap-v1.json`, `config/migration/migration-rehearsal-installation-bootstrap-v1.json`, `config/profiles/scenario-truth-installation-bootstrap-v1.json`: current source/resource raw pins, profile-schema semantic/raw pins and closure/bootstrap digests |
| Shared profile-schema registry | `config/security/dependency-advisory-installation-bootstrap-v1.2.json`: current profile-schema pins and bootstrap digest; advisory/history/schema meanings and historical v1/v1.1 bootstrap bytes stay frozen |
| Current bootstrap changes | `pyproject.toml` tool.gew.profile release-operations, performance-benchmark, migration-rehearsal, scenario-truth and dependency-advisory sections: bootstrap semantic/raw pins and actual protected-source projections |
| Source/resource closure | `pyproject.toml` coverage-execution-plan source-checkout/package member lists and hashes; `config/verification/wp-00-targets.json` membership; `tests/support/source_checkout_attestation.py`, `tests/support/runtime_resources.py`, `tests/support/runtime_distribution.py` only where their actual enumerations/loaders change; scripts/build_backend.py stays read-only |

Conditional action branch: `pyproject.toml` built-in action implementation
projection -> `config/contracts/action-adapter-registry-v1.json` ->
`config/actions/concrete-action-policy-v1.json` -> BOTH
`config/actions/action-policy-v1.json` and
`config/actions/action-policy-local-actions-v1.json` -> respectively
`config/security/security-runtime-v1.json` and
`config/security/security-runtime-local-actions-v1.json` -> the current
bootstrap/package consumers above. Re-sign a branch only when its own actual
frozen projection changes, not whenever an unrelated pyproject table changes.
Connector/action schema registries stay unchanged: no new operation is proposed.

Plan bindings/oracle members, Support Matrix, scenario policy/fixture/oracle
values, performance benchmark registry/noise vector/thresholds and historical
dependency bootstrap versions remain untouched. The current performance
BOOTSTRAP is a required provenance consumer, not benchmark workload data or
permission to run a scenario. Same-date Test Plan gives bounded selectors and
new closed-factory checks; no performance/cumulative execution is needed.

Primary risks and required proof: path/hard-link/root substitution (fresh
descriptor identity); self-signed root metadata (durable target digest anchor);
revival after deletion/close (exact lifecycle and marker eligibility); mixed
action/claim/compensation receipts (full joins); old source issuers (fresh durable
source reconstruction); lost counter meaning (new read-only epoch); read/write
races (shared lock order and final closure); cleanup on error (zero recovery
writes); same-process tests mislabeled cold restart (exec-based fresh process).
A host/repository-wide malicious rollback is not solved by local hashes.

Implementation rollback, if later required, restores fail-closed recovery and
preserves retained bytes for explicit owner disposal; it must not rewrite
committed evidence, silently migrate old roots or restore action replay.
No data migration, DB/event/GraphRef change, dependency, daemon, service/port,
credential, production operation, WP-10 or network is proposed. Cold recovery
does not constitute the missing 30 records or a cumulative acceptance result.


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

## 2026-09-10 approved memory-repair impact

`GEW-REMAINING54-LOSSLESS-TRACE-MEMORY-REPAIR` adds six exact targets to
historical exact168; approval is `批准先修复`. The prior baseline below remains
historical; this supplement governs the repair before coding. Native samples
found interpreter-finalization GC with a 75.8 GiB footprint, but did not identify
every live object. Isolated document construction independently reproduced global
trace retention; schema loads retained trace memory until their context died.
Do not claim the entire process footprint has been attributed to one object.

Affected code: WorkContext trace representation, WP-05 action-document fixture
helpers and existing WP-08 action-setup call sites. Full trace contents and live
list behavior, work budgets, exception precedence and temporary-unit accounting
remain unchanged. Unread consecutive events use lossless runs; inspecting the
whole trace still allocates the whole list. Short-lived fixture contexts prevent
process-global accumulation without discarding a caller-owned context's audit.
No schema/API, dependency, persistent state, gate, or installation-trust change;
the source file is already included in the installed package. Revalidate actual
source/currentness inputs; do not modify unrelated pins or WP-07a gate policy.

This is a hotfix under the existing approved PRD, not a new feature or architecture
choice. Required regressions precede implementation and independent review follows
verification. No commit is authorized (any later authorized commit must record the
hotfix exception). Cumulative execution and monitoring remain stopped; focused
tests are not a Remaining54/Candidate pass.

## 2026-09-17 P3 foundation bounded impact

`GEW-REMAINING54-P3-FOUNDATION-BOUNDED-V1` uses the current exact174 Envelope;
exact168 is retained only as historical F1 lineage. No target is added. The
affected surface is limited to ADR-0009 foundation contracts, installed
policy/fixture/bootstrap and package currentness, local private-root simulator
and health observation, existing ActionCoordinator wiring, release-only
assessment 1.4, and focused tests. The plan/oracle shape stays 244/122 with 30
missing release bindings, so no release CoverageRecord is created. Local
simulator evidence is not staging, production, deployment or release evidence.
Mandatory/scenario coverage, cumulative/performance workload, monitoring,
network, WP-10, commit/push/merge/deploy/release remain outside this impact.
The occupied historical `p3-foundation-*-r1.json` records are immutable; new
review-record targets require a separate authority expansion.

Security impact is intentionally local but strict: callers cannot mint accepted
artifact/evidence objects or invoke mutation directly; the simulator exposes no
caller path and binds its directory descriptor, owner, mode and inode. Partial
failure creates a durable queryable staged state and uses the existing
claim-compensation protocol to restore A, without treating staged B as no-effect
or replaying apply. No new durable schema, dependency, external process or
network capability is introduced.

The installed fixture registry, rather than a caller byte argument, owns the two
simulated artifact byte vectors and their identities. Coordinator-owned gate
arming and outcome tracking prevent direct target mutation and forged result
promotion. Health is bound to the terminal typed observation; partial/manual
state requires rollback before final evidence can pass. Because the private root
has no authorized durable reopen locator in this sub-batch, restart of stored
release evidence intentionally fails closed instead of accepting a destroyed or
drifted target. This is a known foundation limitation, not a coverage PASS.
Production issuance is additionally confined to an opaque process-local seal
granted only after `from_installation()` verifies the current protected closure.
Direct constructors and document-validation factories have zero issuance
authority, and cannot be injected into the release category oracle.

## 1. 文档控制

| 项目 | 内容 |
|---|---|
| 产品 | Graph Engineering Workflow |
| 版本 | v1 Reviewed，implementation-alignment revision 30 |
| 状态 | Historical Independent Impact Review PASS；F1 routine source/observation traceability R1 candidate |
| 日期 | 2026-09-06 |
| Author | Codex `/root` |
| 上游定位 | [Positioning v2 Approved](../positioning/graph-engineering-workflow.md) |
| Intent Baseline | [PRD v2 Approved](../prd/graph-engineering-workflow.md) |
| 技术设计 | [Tech Spec v1 Approved](../specs/graph-engineering-workflow.md) |
| Positioning digest | `968d4b574008b53ce79f7fe4c1e1b3d5f71d44bca890425848f388577883f799` |
| PRD digest | `594b4437301853919ce3b4aa93e703a395ed45bff924ea6266b3a8e202a30be7` |
| Tech Spec | current governing implementation-alignment revision 36；revision 24 recovery binding仅为historical lineage |
| Authority task | `GEW-IMPACT-V1` |
| 当前授权 | `GEW-REMAINING54-V1` 仅授权本仓库本地/离线文档、实现、验证与独立审核；不授权真实deploy/release、network、WP-10、commit/push/merge/外部通信 |

本文评估按批准设计构建 v1 对仓库结构、用户、状态数据、外部系统、安全、兼容性、
运行、测试和后续交付的影响。它不重新选择产品范围，也不把“尚无代码”等同于
“没有影响”。

## 2. 执行摘要

### 2.1 结论

这是绿地实现，但属于高基础性、高可靠性要求的架构变更：当前仓库没有已发布代码、
运行时、用户数据或兼容承诺，因此 v1 不产生传统的存量迁移和 breaking change；然而
首个实现会建立持久状态格式、Graph/Artifact/Authority 契约、Skill 分发方式和外部动作
安全边界，后续版本将依赖这些接口。

Impact 结论为：

- 产品范围不变，无 Intent Baseline 或 Authority 扩张；
- 仓库内几乎所有未来模块都是新增，现有批准文档只增加下游追踪，不修改语义；
- 用户体验影响高：从对话式 Agent 使用方式变为有状态、可恢复、只在必要边界中断的
  Skill-first 交付流程；
- 状态、并发、动作恢复、安全和隐私影响高，必须在第一条可执行路径前实现确定性底线；
- v1 无存量数据迁移，但首版即必须具备 schema version、export/import 和失败回退；
- 原 implementation-entry set 的 ADR-0001～0003 已完成；WP-05 后续暴露的 expired-lease
  recovery conflict 已由 Human Owner 补充批准 ADR-0005。ADR-0005 的 independent review 与
  exact transaction/concurrency/crash recovery verification 仍是 expired-lease compensation 的
  blocking gate；通过前该路径必须 fail closed，不能由其他 Plan、配置或 capability 声明替代。

### 2.2 影响等级

| 维度 | 等级 | 理由 |
|---|---|---|
| 产品意图 | 低 | 完全沿用批准的 Positioning/PRD，不新增用户或任务类别 |
| 用户工作流 | 高 | 引入需求冻结、自主 Graph、必要边界升级和真实动作验证 |
| 代码与模块 | 高 | 新建核心、应用、存储、adapter、Skill、配置和测试层 |
| 数据与兼容 | 高 | 首次定义 durable event/state/object 和迁移契约 |
| 安全与隐私 | 高 | 涉及本地源码、凭据引用、外部工具和可能的生产动作 |
| 运行与部署 | 中 | 本地安装、无 daemon；仍需跨 macOS/Linux 和 runtime 兼容 |
| 既有用户迁移 | 无 | 当前无已发布版本、用户状态或运行时 |
| 可逆性 | 中 | 文档和本地实现可逆；外部动作必须另行授权并按动作评估 |

## 3. 当前状态与变化边界

### 3.1 当前仓库

当前仓库已有 WP-00～03 的 independently reviewed PASS implementation；WP-03 r8 已证明
descriptor-bound repository、SQLite transaction/replay、objects、locks、leases/claims、独立
publication lock tier 与 digest-bound evidence。WP-04A 新增 ArtifactContract registry、十类
ArtifactRecord validators、logical-body manifest/lifecycle/dependency invalidation 与 exact fixture
matrix；后续 review revisions 进一步新增 canonical actor identity、authoritative target/trace closure、per-entry
manifest binding、charged physical-byte limits、factory-only lifecycle/validation evidence 与逐
subcase mutation manifest，并把 authoritative input 精确绑定到 task/baseline tuple，已经独立
PASS。WP-04 r3 新增 application command/query、in-request Runner、durable RunnerSnapshot、
finding convergence、failure routing 与 attested Completion Gate，目前处于本地 candidate
verification/review；r3 进一步把 reducer-owned transition 从 public API 移除，以不暴露 issuer 的
registered runner channel、one-use exact authority、durable two-transaction review、application-owned
PASS derivation 和 gate-internal completion 阻止伪造通过，并把
REVISE 后 same-digest PASS 视为不收敛。仍没有 Codex/Hermes Skill、真实 runtime adapter、真实外部 action、安装器/
release、用户数据或已发布兼容消费者；WP-04 只使用 deterministic fake adapters，不扩大网络、
凭据或用户项目写入边界。

旧项目 `/Users/ezio/Documents/MyProjects/agent-engineering-workflow` 仅为只读背景，不能
修改、复制为隐式依赖或成为安装/测试/运行前置条件。

### 3.2 本次变化

本次交付将从零建立：

1. 平台中立的 Graph Kernel、reducer、policy、validation 与 invalidation；
2. application runner、命令/查询服务和恢复编排；
3. backend-neutral repository ports 与一个 v1 本地 backend；
4. Codex/Hermes runtime adapters 和各自完整 Skill 入口；
5. 九类 Profile、三条风险路径、标准 Artifact Contracts 和安全策略配置；
6. 安装、升级、诊断、迁移、测试和审计能力。

本次不包含未授权的目标项目修改、外部通信、commit、push、merge、deploy 或 release。

## 4. 仓库与模块影响

### 4.1 预计新增结构

| 区域 | 责任 | 主要上游需求 | 耦合约束 |
|---|---|---|---|
| `core/` | Graph、typed state、reducer、policy、digest、budget、invalidation | FR-03～FR-08、FR-10～FR-12 | 不能导入 runtime、厂商 SDK 或环境值 |
| `application/` | task use cases、runner、commands、queries、recovery、completion | FR-01、FR-05、FR-08、FR-15、FR-17 | 只能通过 ports 调用外部能力 |
| `storage/` | event repository、catalog、lease/claim、objects、migration backend | FR-03、FR-08、FR-15、FR-16 | 必须通过统一 conformance/crash suite |
| `adapters/` | Codex、Hermes、Git、tool/connector、secret provider 适配 | FR-01、FR-02、FR-07、FR-11、FR-17 | 不得拥有 universal Graph 语义 |
| `config/` | graph、profile、overlay、policy、schema、capability 与 defaults | FR-04、FR-12、FR-14、FR-18 | 所有用户/环境值在此或外部配置 |
| `skills/` | Codex/Hermes 触发、交互、核心 CLI 调用和结果呈现 | FR-01、NFR-01 | 薄入口；不能绕过 core gate |
| `scripts/` | doctor、migration、验证、开发与发布辅助命令 | FR-16 | 可重复、非交互优先、无隐藏业务规则 |
| `tests/unit/` | reducer、policy、schema、digest、routing、budget 单元/模型测试 | 全部确定性要求 | 不依赖网络或真实 runtime |
| `tests/integration/` | repository、runtime、action、recovery、九类 E2E | FR-01、FR-08、FR-14～FR-17 | 必须覆盖真实工具链和失败注入 |
| `tests/fixtures/` | Graph、事件、authority、profile、corruption 与安全样本 | 验证策略 | 测试值不得进入 engine logic |

目录是责任边界，不代表九套类别引擎。九类任务通过共享核心上的配置化 Profile/子图
实现，但每类的 completion、rollback 和真实 E2E 必须独立验收。

### 4.2 现有文件影响

| 文件/区域 | 影响 | 处理 |
|---|---|---|
| `AGENTS.md` | 约束所有后续设计和实现 | 保持产品/交付/架构边界；语义变化需 Human |
| `docs/CONVENTIONS.md` | 决定目录、命名和数据逻辑分离 | 实现和文档均遵循；不为工具方便绕过 |
| Positioning/PRD | 已批准上游 | 只读语义输入；digest 变化失效全部下游 |
| Tech Spec | 已批准设计输入 | ADR 只能在其允许的实现集合内选择 |
| `.workflow/delivery/` | 当前为任务级设计审计记录 | 不视为已实现产品 runtime，也不进入发行包 |
| `.gitignore` | 未来需区分可版本化配置与本地 runtime state | `.workflow/runtime/`、secret、cache 保持忽略；规范/测试 fixtures 可追踪 |

WP-04 新增的 application snapshot wrapper 不替代 event stream 权威性：domain snapshot 与 runner
projection 都由 repository transaction digest 保护，读取时先 replay authoritative event chain；domain
event revision 与 repository transaction revision 分开存储。Candidate object 可能在引用 transaction
前已 durable；若随后 commit 失败，它保持未引用对象并由后续 recovery/retention 处理，不被当成
已通过产物。

## 5. 用户与工作流影响

### 5.1 Human Owner

正向影响：

- 在 Codex 或 Hermes 内完成需求发现、批准、状态查看、必要决策和结果接收；
- PRD 后不再逐阶段审文档，routine findings 由独立 Agent Loops 收敛；
- commit、push、merge、deploy、release 和会话外通信仍逐动作控制；
- runtime 中断后可以从本地 durable state 恢复，不需要手工搬运上下文。

新增负担与可见行为：

- 首次使用需安装本地核心和至少一个 Skill；
- 需要显式批准 PRD/Intent Baseline，以及真正发生时的重大选择或不可逆动作；
- 被阻塞、未知副作用或不收敛时会收到结构化决定请求，而不是模糊失败；
- 任务绑定创建它的 runtime，另一 runtime 不能接续。

### 5.2 目标项目与项目参与者

目标项目在 PRD 批准前只受只读 discovery；批准后也仅允许 Envelope 和动作级授权覆盖
的变更。系统必须读取目标项目自己的规范和工具链，因此不同语言/框架只改变配置、
adapter 或项目命令，不改变核心代码。

v1 只有一位 Owner；其他 Telegram/Discord 用户、其他 Codex/Hermes 会话或项目参与者
不能注入正式输入、批准或读取敏感任务材料。若未来需要多人协作，这是新的产品意图，
不是 adapter 小改动。

### 5.3 九类任务

| Profile | 特有影响面 |
|---|---|
| 新项目/功能交付 | 新目录与 Git realization、scaffold、目标环境状态 |
| Bug 修复 | reproduction fixture、行为边界与回归保护 |
| Hotfix | 紧急 baseline、最小变更、生产授权与快速 rollback |
| 重构/技术债 | 行为基线、非功能质量证据和范围漂移风险 |
| 数据库/架构迁移 | schema/data integrity、兼容窗口、前滚/回滚次序 |
| 依赖/安全修复 | 依赖图、暴露面、供应链和残余风险 |
| 性能优化 | 可重复基线、环境可比性和非目标回归 |
| 发布/运维 | 制品 provenance、环境权限、健康与回滚状态 |
| 事故响应 | 遏制/恢复优先、未知副作用和事后补齐证据 |

共享节点不会消除上述类别影响；Support Matrix 和 ReleaseCoverageGate 必须逐类证明。

WP-08 coverage fixture 的规模化验证会为每个 stable binding 使用独立、config-owned
`task_id`，并把该 identity 绑定到 selector/request/plan/oracle digest。Historical pre-E1 Option C曾允许fixture
资源层按Profile复用disposable repository/application stack；该历史优化不适用于Human-approved E1或current
cumulative。E1要求每binding独占fresh private repository root、task、target、branch/ref、action root与command root，
临时攻击probe当场关闭且任何维度不得跨binding/profile共享。该隔离不改变生产repository、DB、GraphRef，也不降低
combined gate、zero-write或freshness语义。为避免完整matrix的
consumer-local identity graph 延迟进程回收，CoverageRecord factory 对每个 candidate 提供两个
互斥的单调终态：exact combined gate 消费完成后 finalize，或在尚无 combined gate decision 时
由 factory 在 register/gate/finalize 同一锁内冻结 current generation 与完整 authority/record projection、
把 `abort-prepared` state、frozen snapshot/version 与 one-shot capability identity 作为一个原子 tuple 存入
consumer-local table 后 abort uncommitted candidate。冻结后不再接受 registration 或 gate/finalize；tuple
提交后若 return 丢失，同一 factory/candidate 重复 prepare 取回同一个 capability，不新签或改变 snapshot；
abort 不伪造/生成 gate decision；
partial/foreign/clone/错误 candidate capability 与替换后的 decision/record set 均 fail closed。
finalize/abort 都不会删除 immutable record documents 或合法 gate decision，也不会修改 durable
task/event/snapshot/object/ref、ActionCoordinator journal/claim 或 target；只撤销该 consumer-local
candidate 的进程内签发/currentness capability 和释放强引用，因此没有 DB migration、GraphRef
变更、外部权限、网络或部署影响。abort 后不可 reopen/re-register/finalize/gate，finalized 后不可
abort；并发由 factory-local 线性化点选择唯一分支。in-process injected exception 允许同一 factory
对象幂等继续已选择分支的 cleanup；process termination 会销毁 local capability，restart 不能从
record bytes/digest 重建或继续 authority，只保留无 use authority 的 durable documents。

## 6. 数据、状态与迁移影响

### 6.1 新增持久数据

| 数据 | 敏感性 | 生命周期/影响 |
|---|---|---|
| Task identity、ProjectScope、GraphRef | internal/confidential | 任务全生命周期；绑定 Owner/runtime/targets |
| event stream、snapshot、catalog | internal/confidential | 恢复和审计权威；损坏时 fail closed |
| Authority、Action Journal、claims/leases | confidential | 控制副作用；未协调 action 禁止清理 |
| artifact/evidence metadata | internal/confidential | digest、trace、trust 与 invalidation |
| artifact/evidence bodies | 按内容分类 | 内容寻址、最小化、RetentionPolicy 控制 |
| runtime binding | confidential | Codex/Hermes lineage、Hermes channel/user refs |
| PMF aggregates | internal | 只保留最小任务级聚合，不保存源码/prompt body |
| secret references | secret reference | 只保存 provider/key ref，不保存 secret value |

### 6.2 一致性与恢复影响

- event stream 是权威事实，snapshot 和 catalog 必须可重建；
- task commit、catalog delta、resource lease/action claim 必须具有规定的原子可见性；
- 外部调用跨越本地事务，必须由 prepared digest、durable started event、claim、receipt
  和 reconciliation 组成可恢复协议；
- non-idempotent 或状态未知动作不能自动重放；
- content object 必须在引用可见前完成 digest、durability 和权限验证；
- restore 不能仅恢复文件，还必须证明 schema、Graph/Profile 和 runtime capability 兼容。
- runtime 请求结束后不触发新工作；下一次同 lineage 调用从 exact RunnerSnapshot 继续。routine
  finding 的 open/closed 事实同时进入 reducer event stream，详细 finding/review lineage 进入 runner
  projection；两者不一致时 fail closed；
- Completion Gate 读取 validated Candidate Review/Completion Record 类型而非 caller 自报 verdict，
  失败评估为纯读，只有 application boundary 对 current snapshot 重算全部条件通过才提交
  `task.completed`；普通 caller 无 reducer-owned transition public API，one-use authority 与
  event/review correspondence mismatch 在 repository 写入前拒绝。
- 评审多一个原子持久化步骤：`node.review_recorded` 保持 node 在 `reviewing`，随后 PASS/REVISE/
  ESCALATE/BLOCKED 消费该 durable record；停止或崩溃时下一调用从该 record 恢复，不重复请求 reviewer。

### 6.3 迁移与回滚

v1 无旧数据导入要求。首版开始必须提供：

- 所有 persistent object 的 schema version；
- backend-neutral export/import bundle；
- 隔离 dry-run、完整重放和 integrity scan；
- 原 backend/配置的可执行回退；
- 进行中 action/lease/claim 的迁移阻塞规则；
- 迁移后 task graph/profile version 不静默变化。

存储实现可以替换，但 event/repository semantics 是批准契约，不能通过迁移改写历史或
降低 durability。

## 7. 接口与依赖影响

### 7.1 内部稳定接口

首个实现将建立以下长期兼容面：

- RuntimeAdapter、Agent/Tool/Secret ports；
- TaskRepository、TaskCatalog、ResourceLeaseRepo、ObjectRepository、MigrationRepository；
- command/event/reducer schemas；
- Graph/Profile/Overlay/Artifact/Evidence/Authority contracts；
- CLI exit code、machine-readable output 与 Skill invocation contract；
- export bundle 和 migration contract。

这些接口必须版本化。实现语言内部函数不是自动的公共 API；只有显式标记并进入
compatibility matrix 的接口才承诺兼容。

### 7.2 外部依赖

| 依赖 | 影响与失败方式 |
|---|---|
| Git | v1 唯一正式 VCS；identity、worktree/common-dir、命令和目标状态均需适配 |
| Codex | Skill、subagent/reviewer、tool invocation 和 lineage 能力需探测 |
| Hermes | Skill、Telegram/Discord pairing/allowlist、session/thread 和 delivery receipt |
| OS/filesystem | macOS/Linux 权限、atomicity、lock、fsync、path canonicalization 差异 |
| 核心实现语言/本地运行时 | 候选由 ADR 比较；其版本、分发与依赖影响 Skill 开箱即用和升级 |
| 项目工具链 | build/test/lint/security/performance 命令由项目配置提供 |
| 外部 connectors | 能力、身份、幂等、fencing、target query 和 disclosure 差异 |
| secret provider | 凭据只通过 reference/最小注入；不可用时相关 action blocked |

外部能力缺失必须成为可诊断的 capability mismatch；不能用 prompt 猜测或降低门槛。

## 8. 安全、隐私与权限影响

### 8.1 主要威胁变化

本产品从“生成建议”进入“可真实操作”，新增或放大的威胁包括：

- prompt injection 诱导扩大目标或绕过动作批准；
- 伪造 Owner、跨 runtime/session 复用批准；
- path traversal、symlink escape、shell argument 注入；
- lease 过期或崩溃导致重复/冲突副作用；
- expired lease 下错误授予 replacement lease、创建第二 claim、提前释放 original claim，或把
  compensation recovery 误用为 original action replay；
- artifact/evidence digest 替换和陈旧证据串用；
- model、connector、诊断导出造成源码或秘密外泄；
- extension/adapter 以高权限执行未声明副作用；
- archive/purge 误删 rollback、legal hold 或未知 action 所需事实。

### 8.2 必须先于真实动作落地的控制

以下不是后续加固项，而是第一条 action path 的前置：

1. canonical Owner/runtime/target identity 与 ProjectScope binding；
2. Intent/Authority/action/snapshot digest 绑定；
3. prepare → authorize → execute gate → reconcile；
4. global resource lease、monotonic fence 与 durable UnresolvedActionClaim；
5. DataDisclosurePlan、secret reference、redaction 和 owner-only repository permission；
6. schema/policy/extension safety validation；
7. independent review、evidence freshness 与 deterministic Completion Gate。

ADR-0005 增加的 expired-lease compensation 不是上述 lease/claim 控制的例外。它必须复用
original exact unresolved claim 的同 task/lease、完整 resources/latest fences，使用单独 rollback
authority 与 call-span locks，并在 started/receipt durable 后通过 fresh target verification；验证前
不能消费 claim，且禁止 replacement lease、second claim、普通 action 或 original replay。

实现若暂不具备其中任一控制，只能阻止对应真实动作，不能以 beta 标记继续。

### 8.3 权限边界

Impact/ADR/Plan/Test Plan 和本地产品实现是可逆仓库变更，可在批准 Envelope 内自动
收敛。commit、push、merge、deploy、release、生产操作及会话外通信始终需要各自授权；
实现阶段也不能因为测试需要而假定拥有真实外部资源权限。

Human Owner 对 ADR-0005 的补充授权只允许实现 compensation-only recovery transition；不授权
任何真实外部动作，也不扩大 commit、push、merge、deploy、release、生产操作或外部通信权限。

## 9. 可靠性、性能与运行影响

### 9.1 可靠性

可靠性优先会增加初始实现和测试成本，但避免把不可恢复状态带入所有九类任务：

- repository 必须通过 transaction/crash/corruption conformance；
- reducer 对相同 event history 必须产生唯一 snapshot；
- runner 每个恢复点必须区分未执行、已执行、失败和 unknown；
- recovery compensation 的 started、receipt、fresh verification 与 claim consumption 必须分别
  durable/auditable；任一 crash 或 unverifiable target state 均保留 original claim 和资源冻结；
- reviewer finding、budget 耗尽和 capability loss 必须有明确 route；
- “完成”是确定性 predicate，不是 Agent 自报状态。

### 9.2 性能

v1 是单机、无 daemon、面向个人/项目负责人交互式任务，不以高吞吐为首要目标。
性能风险主要来自大 artifact/evidence、长 event stream、九类矩阵和外部 tool latency。
设计需支持 snapshot、内容寻址去重、分页 query 和可配置 retention，但不得通过跳过
fsync、验证、review 或 evidence 来换取速度。

性能阈值属于配置和后续真实基线，不写入 engine logic。Test Plan 应定义可重复的
启动、resume、replay、query 和大型任务基线。

### 9.3 运维

- 无常驻服务，不需要 server deployment、端口或后台 scheduler；
- 安装/升级需要 local doctor、兼容矩阵、备份和失败回退；
- Hermes gateway 可能常驻，但仅是既有 transport，不代表 Graph runner 后台继续；
- 日志与诊断默认本地、结构化、脱敏；外发另需授权；
- support 需要可读的 blocked reason、integrity report 和 bundle export，而不是要求用户
  手工修改状态文件。

## 10. 兼容性与发布影响

### 10.1 兼容性承诺

| 维度 | v1 结论 |
|---|---|
| 既有产品版本 | 无 |
| OS | macOS/Linux；Windows 仅 WSL，不承诺原生 |
| VCS | Git；非 Git fail closed |
| Runtime | Codex、Hermes 各自完整支持，单任务不可跨 runtime |
| Hermes 渠道 | Telegram、Discord 均需契约验证 |
| 技术栈 | core 中立；项目命令和能力通过配置/adapter |
| 存储 | v1 backend 可选择，但 bundle/repository contract 必须 backend-neutral |
| Graph/Schema | 任务开始后锁定版本；升级需显式兼容或迁移 |

### 10.2 发布门槛影响

v1 不能以“框架可表达”宣称九类支持。发布需要：

- 九类冻结 Support Matrix 的全部 required cases 通过；
- 每类至少一个真实项目/真实工具链 E2E；
- full/compact/emergency 三条风险路径和两个 runtime 的代表覆盖；
- crash、unknown action、authority、privacy、security、migration 和 recovery suite 通过；
- 未验证 integration 明确标记，但类别核心路径不能缺失；
- Candidate Review 和 Completion Gate PASS。

这会显著扩大 Test Plan 和 release evidence，但属于已批准的产品成功标准，不能降级为
抽样通过。

## 11. 需求影响追踪

| 需求组 | 主要影响区域 | 关键风险/验证 |
|---|---|---|
| FR-01～FR-02 | `skills/`、runtime adapters、identity/binding | Codex/Hermes parity、Owner/lineage 隔离 |
| FR-03～FR-04 | core、storage、config schemas | replay、typed edge、route/join/fallback/budget |
| FR-05～FR-06 | review loops、invalidation、artifact graph | 收敛、finding responsibility、intent drift |
| FR-07～FR-08 | authority、action、lease/claim、recovery | digest swap、expiry、crash、non-idempotent unknown |
| FR-09～FR-10 | ArtifactContracts、Evidence、Completion Gate | 标准产物完整、拒绝虚假完成 |
| FR-11～FR-13 | privacy、retention、diagnostics、PMF | secret leak、over-disclosure、最小聚合 |
| FR-14 | profiles、overlays、support matrix | 九类和三路径逐项全部通过 |
| FR-15 | ProjectScope、catalog、commands、concurrency | new/existing/multi-target、冲突和生命周期 |
| FR-16 | packaging、doctor、migration | macOS/Linux、备份、兼容和回退 |
| FR-17 | tool/connector adapters、Action Journal | 真实执行、目标验证、授权与回滚 |
| FR-18 | extension manifest/loader | 来源、schema、capability 和 invariant isolation |
| NFR-01 | packaging、Skill、local runner | 开箱安装、无 daemon、按需执行 |
| NFR-02 | repository、Completion Gate、failure routes | fail closed、真实完成和明确阻塞 |
| NFR-03 | event replay、action reconciliation、migration | 崩溃恢复、unknown 副作用和回退 |
| NFR-04 | core/ports/adapters 分层 | core 不依赖 Codex、Hermes 或厂商实现 |
| NFR-05 | config/schema/fixtures | 用户、环境、阈值、命令与拓扑不进入 engine logic |
| NFR-06 | privacy、retention、disclosure | 最小披露、secret reference、redaction 和隔离 |
| NFR-07 | event/evidence/review/audit | digest chain、状态重放和决定追踪 |
| NFR-08 | version/capability/migration | 不兼容时明确阻塞，禁止 best-effort 猜测 |

所有 18 个 FR 和 8 个 NFR 都有受影响区域。Plan 必须进一步把每项 Must 映射到工作包
和 Test Plan case；Impact 映射不能替代实现追踪。

## 12. 测试与证据影响

### 12.1 必需测试层

| 层 | 目的 |
|---|---|
| schema/contract | 拒绝缺字段、未知版本、弱化安全和类型不匹配 |
| property/model | reducer、route、invalidation、lifecycle 全状态组合 |
| repository conformance | atomicity、CAS、idempotency、crash、corruption、migration |
| adapter contract | Codex、Hermes、Git、tool、secret、connector capability |
| security/privacy | identity、path/shell、digest、secret、disclosure、extension |
| recovery/failure injection | runtime stop、lease expiry、unknown action、stale evidence |
| profile E2E | 九类正常/边界/失败/恢复/真实项目 |
| risk path E2E | full/compact/emergency 保留不变底线 |
| install/upgrade | clean install、backup、dry-run migration、rollback |
| Candidate/Completion | 独立性、全部证据、真实目标状态和拒绝伪完成 |

### 12.2 测试环境与数据

- tests 默认使用隔离 temp roots 和 fake adapters，不访问用户真实仓库或凭据；
- 真实 E2E 使用专用 fixture projects、明确 target boundary 和一次性资源；
- Telegram/Discord contract test 不能使用真实用户消息作为 fixture；
- corruption/crash 测试必须可重复注入每个 durable step；
- 性能和 PMF 样本是 data/fixture，不嵌入 engine prompt 或评分函数；
- 会产生外部副作用的测试仍需单独 authority，不因“测试”自动豁免。

## 13. 风险登记

| ID | 风险 | 可能性 | 影响 | 缓解/验证 | Owner |
|---|---|---:|---:|---|---|
| IMP-R01 | 共享核心掩盖某类任务缺口 | 中 | 高 | 九类独立 completion/rollback/real E2E | Profile/Release Gate loop |
| IMP-R02 | event/storage 实现无法满足 crash 原子性 | 中 | 严重 | ADR、conformance suite、故障注入 | Storage loop |
| IMP-R03 | runtime/Owner identity 不稳定导致越权或无法恢复 | 中 | 严重 | capability/lineage contract、拒绝模糊 identity | Adapter/Security loop |
| IMP-R04 | 无原生 fencing 的 tool 出现重复副作用 | 中 | 严重 | call-span lock + durable claim + reconciliation | Action loop |
| IMP-R05 | Skill 变厚并复制核心规则 | 中 | 高 | dependency scan、thin adapter contract、parity tests | Runtime loop |
| IMP-R06 | 文档/Graph 复杂度抵消用户价值 | 中 | 高 | 安全默认图、按需呈现、PMF 反证、Human interruption metrics | Product learning loop |
| IMP-R07 | 九类全部支持使 v1 周期过长 | 高 | 高 | 共用安全 primitives、垂直切片、逐类 evidence；不降低发布声明 | Plan loop |
| IMP-R08 | 本地源码/凭据被模型或 connector 过度外发 | 中 | 严重 | classification、DataDisclosurePlan、redaction、secret refs | Privacy loop |
| IMP-R09 | schema/Graph 升级使进行中任务失效 | 中 | 高 | version lock、bundle migration、兼容矩阵、rollback | Migration loop |
| IMP-R10 | extension 破坏 invariant 或供应链安全 | 中 | 高 | source/trust ADR、manifest validation、capability isolation | Extension loop |
| IMP-R11 | 测试矩阵庞大但证据不可维护或 fixture teardown 失控 | 中 | 高 | versioned case/task IDs、content-addressed evidence、E1每binding fresh private repository/application stack、seal/quiesce/reopen active-handle归零、combined coverage gate | Verification loop |
| IMP-R12 | 产品可靠但未满足 PMF | 中 | 严重 | 最小真实指标、反证、复用/授权意愿和人类负担观测 | Human + Agent |
| IMP-R13 | dependency-security 把 package integrity 或 fixture label 冒充 vulnerability/fix truth | 中 | 严重 | ADR-0006 installation-pinned offline advisory/source authority、WP08A exact closure、use/precommit/restart currentness、zero-network probes | Profile + Security loops |
| IMP-R14 | performance 把child自报、噪声或不同硬件结果冒充可比benchmark truth | 中 | 严重 | ADR-0007 parent-monotonic protected command、exact fingerprint、integer median/MAD/cross-products、correctness与currentness probes | Profile + Verification loops |

风险 Owner 指责任 Agent Loop，不代表自动获得外部操作权限。IMP-R02、R03、R04、R08
是任何真实动作前的 blocking risk；R01、R07、R11 是宣称九类 v1 支持前的 blocking risk。

## 14. ADR 判断

### 14.1 实现前必须完成

| ADR | 决策范围 | 为什么需要 ADR | Human 边界 |
|---|---|---|---|
| `0001-core-implementation-and-local-packaging.md` | 核心语言/版本、模块边界、CLI/library、安装与 Skill 定位方式、依赖策略 | 影响全部模块、macOS/Linux 安装、runtime adapters 和长期维护 | 若引入 daemon、远程控制面或改变 Skill-first 才升级 Human |
| `0002-local-event-repository-and-coordination.md` | file-journal、SQLite 或其他合格 v1 backend，object storage、事务/durability、task/resource lease、fencing/claim/迁移，以及基于existing migration ledger的WP-08 rehearsal observation authority | 直接决定最重要的可靠性、恢复和并发行为；generic migration receipt本身不构成task-bound scenario truth | **Disposition: Human Owner Accepted revision 6 rehearsal amendment；Blocking:** independent architecture review/schema/TDD前，migration四个scenario pairs保持missing；不得新增DB schema、真实activation、WP10或用户数据访问 |
| `0003-deterministic-contract-stack.md` | canonical JSON、schema validation、typed model、受限 route/policy expression 和 digest conformance | 跨越 Graph、event、authority、artifact、extension 与证据，是安全和兼容基础 | 若允许任意代码/模型解释 deterministic rule 则升级 Human |
| `0005-recovery-claim-compensation.md` | expired lease 下复用 original exact unresolved claim 的 compensation-only transaction、attempt idempotency、receipt 与 verified claim consumption | 普通 live-lease/claim protocol 无法同时保证 durable start、no replay、无 second claim 和验证前持续冻结 | **Disposition: Human Owner Accepted，independent review pending；Blocking:** ADR review 与 exact transaction/concurrency/crash tests PASS 前，expired-lease compensation 必须 fail closed，只能 query/manual；不得以 live-only compensation 宣称 WP-05 完成 |
| `0006-offline-dependency-advisory-authority.md` | installation-pinned offline advisory/source registry、WP08A closure、applicability/fixed/regression/residual authority、monotonic update、coverage lifecycle，以及exact METADATA-derived graph与explicit unavailable-fix disposition | package closure不自动证明transitive reachability；missing fix也不能自动授权unavailable/owner route | **Disposition: Human Owner Accepted revision 8 R2 additive offline-v2 full-snapshot/cffi transitive amendment；Blocking:** same independent reviewer must close `WP08-DEP-OPTION1-DOCS-ARCH-R1-001` before schema/TDD；禁止old-source omission、mixed snapshot、threshold downgrade、direct/caller advisory或graph、online resolver/scanner、activation/WP10或partial gate finalize |
| `0007-offline-performance-benchmark-authority.md` | installation-pinned benchmark registry、parent-monotonic完整StructuredCommand计时、exact environment/correctness/sample/statistics authority与performance baseline/target/rollback | generic runner/command result不定义可信duration、noise或跨环境可比性；child elapsed/PASS与repository wall clock不能成为performance truth | **Disposition: Human Owner Accepted A1+B1 and Option B durable category-assessment integration，independent architecture review pending；Blocking:** review/schema/TDD gate PASS前，performance 24 mandatory CoverageRecords保持missing；禁止child自报duration、cross-hardware normalization、外部benchmark服务或新增dependency |

0001～0003 已完成原批准架构选择；0005 是 Human Owner 针对 WP-05 recovery conflict 的补充
决定；0006 是 Human Owner 针对 WP-08 dependency-security truth/source authority 的补充决定；
0007 是 Human Owner 针对 WP-08 performance duration/statistics/environment authority 的补充决定。
0005/0006/0007 目前均以各自独立 review 与实现验证为 blocking item。可靠性优先于少量开发便利；
每个 ADR 必须列出候选方案、验证证据、后果和回退条件。architecture gate 是否关闭必须分别评估
ADR-0005 的 recovery verification、ADR-0006 的 registry/observation/zero-network verification 与
ADR-0007 的 clock/environment/statistics/currentness verification。

ADR-0006 不扩大 ADR-0004：受影响生产面限于新的 versioned advisory/source/input/observation contracts、
installation bootstrap/protected resources、dependency-security application authority、WP-08 coverage
plan/oracles 与 factory-local lifecycle capability。后者不拥有 caller repository/application/target lifetime，
也不产生持久 lifecycle row。`packaging==26.3`、wheel/RECORD/METADATA/closure budget 继续只在 build/install/package-
verification boundary；core、runtime、user repository 与 install target 不新增 parser/import/network。
applicability/residual truth由该boundary的factory-issued same-registry/advisory/source + before/after closure
identity计算，residual rows覆盖current registry全部active及历史superseded/revoked advisory identities；
evaluation universe exact由high-water的active identity set确定，与rows中非inactive identities双向相等。历史
identity产生inactive row且不要求其source仍active/time-valid、不进入residual set；new revision可作为
new active identity，旧superseded/revoked identity不复活。active advisory必须引用active/time-valid source。
caller bool/list/omission、duplicate row或伪造inactive identity为active不进入application/core。

新增10组source/digest-input schemas与registry/bootstrap/observation protected pins，但每个nested digest只
排除自身derived field并包含child body/digest，避免局部重签隐藏替换。registry status high-water为closed
sorted unique source/advisory identity states；genesis、forward和rollback generation/previous digest exact，
source有效期使用repository clock的half-open interval。
candidate generation中new/unchanged/changed status的status-generation exact为candidate/prior/candidate，且
不得超过registry generation；source失活必须同步使引用advisory失活，防止永久阻塞或dangling authority。

current→candidate update/revocation比较复用既有installation-verification boundary，不新增WP-08 DB、head
pointer或transaction；downgrade/skip/wrong previous/high-water decrease/resurrection/clock rollback拒绝，
rollback只发布更高 generation并保留deny。失败回退为 authority 未注册、24 IDs missing；未提交 gate 的
candidate 用 exact abort capability 永久失效其 use authority，但保留 immutable audit documents。不修改
既有 146 records、durable task/action/target 或 WP08A 历史 tuple/evidence。

ADR-0007 不改变 StructuredCommand 或 repository clock 的既有语义：parent benchmark observer只在每次
factory-attested launcher完整调用的立即前后读取consumer-local monotonic clock；repository wall-clock
high-water仍只服务expiry。child只返回correctness digest，不能返回duration、samples、PASS或target verdict。
受影响生产面限于新的versioned benchmark registry/bootstrap/source-input schemas、environment/correctness/
sample/statistics/final observations、performance application authority与12个oracles/24 plan bindings；不新增
第三方dependency、DB、GraphRef、category policy、network或外部benchmark backend。

Human-approved Option B 复用现有 `task.category_assessed`、TaskApplication category precommit 与
`category-completion-assessment` CAS EvidenceRef。既有1.0 source/input pair保持冻结；新增exact 1.1 source/input
pair只做profile-discriminated演进：performance assessment内嵌closed `performance_evidence_projection`，绑定task revision/snapshot/epoch、
GraphRef six pins、factory/install/environment/session、A→B→A generation/history、samples/statistics/comparisons与
final observation；非performance assessment禁止该字段。现有单一event与DB/ObjectRepository schema不变，
不增加generic task evidence API、表、head pointer或持久authority。

assessment object在现有commit中成为task-unique referenced CAS；precommit于全部hooks后重读并重算projection，
restart从唯一current EvidenceRef重读同一bytes并zero launcher重算。commit前失败最多留下可回收unreferenced CAS，
task/event/snapshot/ref/action/target保持不变。foreign/clone/stale/reorder/alias/coherent resign、source history断链、
CAS replacement或任一current pin漂移都不能签发assessment、coverage或写durable state。这是performance typed
evidence integration，不扩大CategoryFacts、storage transaction、Option C或coverage lifecycle。

environment fingerprint exact绑定OS/architecture/CPU、Python/distribution/RECORD、command/toolchain、fixture与
safe environment projection；baseline/candidate/rollback必须byte-exact相同，禁止cross-hardware normalization。
warmup/repetition与noise/target/rollback ratios全部来自config exact integers；odd repetition的integer median/
MAD与整数cross-products可从durable ordered samples确定性重算。noise超限、correctness mismatch、target miss、
environment drift、sample substitution或current protected member变化均fail closed。rollback继续由既有
ActionCoordinator恢复source/code target，再以same environment重测；benchmark authority不拥有mutation。

performance Slice B获授权后只把plan从170扩为194、oracles从85扩为97；combined gate仍为
`194 valid / 80 missing / passed=false`，static evidence为`0/274`。它复用Option C、strict serial/private
roots以及combined gate后的finalize/revoke或pre-gate one-shot abort，不形成新的lifecycle边界。失败回退为
factory不注册、24 IDs保持missing；既有170 records与durable state不变。

ADR-0002 revision 6不改变migration ledger、repository table或activation state machine。新增生产面只限
protected migration rehearsal registry/fixture/transform manifest/bootstrap、7组source/input schemas、consumer-local
`MigrationRehearsalFactory`与task assessment typed projection。factory在disposable private root复用existing
InstallationMigrationRepository，forward A→B与backward B→A都使用更高manifest generation/epoch；partial-data
逐row记录approved disposition，crash cut只接受完整old/new。restart从task唯一referenced CAS重算且zero migration
replay；真实installation、用户repo、DB schema、GraphRef、network与WP10不受影响。四scenario pairs使plan/oracles
从`208/104`到`216/108`，gate为`216/58/false`；失败回退为factory不注册、八records missing，existing217
candidate records/durable state不变。

ADR-0006 revision 7增加两个data-only protected registries、5组source/input schemas与existing final/bootstrap的
1.1 branches。graph observation从WP08A verified METADATA/WHEEL/RECORD closure确定性派生ordered nodes/edges与
advisory reachability，不导入resolver/scanner。fix-unavailable只由current explicit disposition row与residual
owner route授权，缺数据永远fail closed。现有advisory/applicability/residual/update semantics保持；dependency
task projection与migration共同使用category assessment1.2 closed union，仍是单一既有event/CAS transaction。
两个scenario pairs完成后combined plan/oracles/gate为`220/110/220 valid,54 missing,false`；失败回退不删除
registry history、已有records或WP08A evidence，也不联网补证。

revision 8 R2只扩展versioned config-owned source/advisory数据与受保护安装pins：generation-1 registry、
offline-v1 artifact/attestation/bootstrap/schema bytes与history原样保留；generation-2新增immutable
`source:dependency-advisory:offline-v2@1`完整snapshot及v2 attestation。v1 source与packaging revision 1在gen2
high-water转为superseded，active v2 universe由语义保持的packaging revision 2与cffi revision 1组成，二者都必须
解析到active/time-valid v2 source/artifact/attestation。影响面包括两代advisory registry/high-water/raw+semantic
digests、additive packaging disposition revision、versioned bootstrap source-snapshot history、schema branch、package/
source protected closure及currentness checks；DB、GraphRef、runtime dependency与WP10不变。新增fixed closure只绑定
当前离线`cffi==2.0.0` wheel/RECORD pin与既有regression/residual policies。

schema impact exact为revision 7五组dependency pairs加revision 8唯一bootstrap1.2 source/input pair，累计六组；
不得同时声称no-new-schema。历史/current registry paths分别冻结为
`config/security/dependency-advisory-registry-v1.json`与
`config/security/dependency-advisory-registry-v2.json`，source_snapshot_history与protected closure双向绑定各自
v1/v2 snapshot+attestation，禁止alternate path或alias。

package/source产物必须同时ship/protect v1与v2 artifacts、attestations、对应registry/bootstrap/schema历史；删除old
source、把gen1 registry配v2 snapshot、把gen2 registry配v1或delta snapshot、artifact-attestation cross-pair、history
remove/reorder/replace、same-path replacement与coherent re-sign均在issuance前fail closed且zero writes。这样增加的
成本是双代不可变bytes与history closure；回退仍保留gen1/v1全套bytes并让四IDs missing，不得覆盖历史文件。

权威 transitive path固定为`graph-engineering-workflow@0.1.0→cryptography@50.0.0→cffi@2.0.0`，来自两条
current physical METADATA edges且最少三节点。正向风险是registry/high-water/bootstrap任一漏同步导致fail closed，
或before affected与after approved closure被错误折叠；安全回退是四IDs继续missing、已有216 records与历史registry
bytes保持immutable。禁止把root→packaging direct path、raw/normalized alias、caller advisory/graph或threshold
两节点降级作为修复。所有这些拒绝发生在assessment/observation/record之前，task/action/target/input零写；
restart从task current CAS重建，graph/action replay与network calls均为0。最终数量仍为
`220/110/220 valid,54 missing,false`、static`0/274`。

assessment1.2 source/input pair同时获批但profile-discriminated：migration与dependency graph各自exact一个projection，
performance继续1.1，其他Profile继续1.0；cross-branch/dual projection全部拒绝。package/build/source attestation必须
把新增schemas、registries、fixtures与bootstraps加入ordered protected closure/RECORD，archive/unpacked/source
replacement或coherent re-sign在issuance前拒绝。两批沿用Option C、combined gate、finalize/revoke和pre-gate
abort；terminal及拒绝路径不写task/action/target，不形成新lifecycle authority。

#### Remaining54 P1/P2/P3 impact amendment

Historical Human-approved A author R0 suite为ADR-0007 revision 5、ADR-0008 revision 4、ADR-0009 revision 4、Spec revision 28、
Historical Impact revision 22、Plan revision 27与Test Plan revision 35。Routine finding
`GEW-REMAINING54-ORACLE-CASCADE-A-R1-001`保持**CLOSED**；Historical A R1 suite为ADR-0007 revision 6、
Historical ADR-0008 revision 5、ADR-0009 revision 5、Spec revision 29、Impact revision 23、Plan revision 28与Test Plan revision 36。
Historical Human-approved B suite为ADR-0007 revision 7、ADR-0008 revision 6、ADR-0009 revision 6、Spec revision 30、
Impact revision 24、Plan revision 29与Test Plan revision 37。Routine finding
`GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001`由C关闭。Historical Human-approved C suite为
ADR-0007 revision 8、ADR-0008 revision 7、ADR-0009 revision 7、Spec revision 31、Impact revision 25、
Plan revision 30与Test Plan revision 38。Historical Human-approved D suite为ADR-0007 revision 9、
ADR-0008 revision 8、ADR-0009 revision 8、Spec revision 32、Impact revision 26、Plan revision 31与
Test Plan revision 39。Historical initial E1 suite为ADR-0007 revision 10、ADR-0008 revision 9、ADR-0009 revision 9、
Spec revision 33、Impact revision 27、Plan revision 32与Test Plan revision 40。Historical E1 R3 suite为ADR-0007
revision 11、ADR-0008 revision 10、ADR-0009 revision 10、Spec revision 34、Impact revision 28、Plan revision 33与
Test Plan revision 41。Independently accepted F1 R0 suite为ADR-0007 revision 12、ADR-0008 revision 11、
ADR-0009 revision 11、Spec revision 35、Impact revision 29、Plan revision 34与Test Plan revision 42。Current routine
traceability R1 suite为ADR-0007 revision 13、ADR-0008 revision 12、ADR-0009 revision 12、Spec revision 36、
本文Impact revision 30、Plan revision 35与Test Plan revision 43；
Positioning/PRD不变。当前
plan220/oracle110/dynamic gate `220 valid / 54 missing / false` 的54项精确拆为：performance 4；new-feature
multi-target 2；hotfix 4；refactor-debt 6；incident-response 8；release-operations mandatory 24 + scenarios 6。

代码影响限于新增通用 scenario truth core/application、release operations core/application与local simulator adapter，
并扩展既有 profile assessment/coverage/restart glue。数据影响是versioned config/schema/oracle members与task-local CAS
projection；不新增或迁移SQLite table、event kind、GraphRef字段，不修改用户数据。assessment 1.3/1.4 additive closed
branches保持1.0～1.2兼容；旧task照旧读取，cross-version projection拒绝。

文件系统影响只在安装资源读取与test-owned private roots。P2每个binding独占task/branch/ref/targets；P3每个binding
独占simulator root/stage/active slots。不得访问用户repo、real staging/production、network或ambient artifact。source/
package protection需要把新增config/schemas/modules加入ordered target manifest、wheel RECORD和fresh source/build
attestation；这会改变新candidate package digest，但不会改既有v1/v2 advisory历史或WP08A evidence。

安全影响集中在三点：第一，caller/scenario label不能成为truth，必须由installation-pinned factory重建；第二，partial/
unknown effect不允许自动replay，incident unknown-effects只形成`blocked-owner-route`，release partial-deploy只在query+
authorized restore+fresh health后算处理成功；第三，本地production-like/release simulator evidence带明确local kind，不能
提升为production authority。所有拒绝要求task/event/snapshot/object/ref/action/target/input零写及network count=0。

兼容/发布数量按批次单调演进：P1 `224/112/50 missing`；P2四子批最终`244/122/30`；P3 mandatory
`268/134/6`；P3 scenarios最终plan274/oracle137/dynamic gate `274 valid / 0 missing / true`。static-only gate保持
`0 valid / 274 missing / false`。只有最终exact combined decision可finalize；前序失败不删除已通过records，当前批
全部IDs继续missing。

主要风险与控制：

| 风险 | 影响 | 控制/回退 |
|---|---|---|
| local结果被误称production | 虚假发布保证 | closed evidence kind、production flag拒绝、文档/API不暴露提升路径 |
| scenario target/branch共享 | 跨case污染与假current | unique task/private root/ref/fence；alias/symlink/cross-task零写拒绝 |
| unknown/partial自动重放 | 重复副作用 | existing claim/query/reconcile；inner blocked/partial绝不等于success |
| schema union混用 | 旧task被错误解释 | 1.3/1.4 profile discriminator、single projection、旧bytes冻结 |
| oracle命名碰撞 | incident recovery被替换 | scenario recovery使用`profile-incident-response-scenario-recovery-v1.json` |
| 测试时长/资源泄漏 | non-convergence | strict serial selectors、private root cleanup、每method `OK`后<120s自然退出 |

回退边界为删除尚未采用的新增1.3/1.4、registries、adapter与tests，使相应IDs保持missing；不得修改Support Matrix、
waive case、回退为static/caller truth，或改用真实环境补证。

Historical R1 target-boundary impact只增加`pyproject.toml`并把Envelope增至157；historical R2只统一revision links；
historical R3再且仅增加performance registry/bootstrap并把Envelope增至159。R3性能数据语义继续有效：registry内
config-owned noise ceiling为`1/2`，P为真实parent timing完整success，R frozen vector只证明fail-closed；core仍只有通用
integer median/MAD/cross-product，不含threshold或sample。
P继续由parent `monotonic_ns`真实测量完整`StructuredCommand`并满足完整success；R vector
`[1,2,100,200,201]`只以median100、MAD99及`99*2 > 100*1`证明fail-closed，不产生真实性能结论。

Historical A把Envelope增至164，exact新增1.1 oracle input schema、generic profile-coverage/source-checkout core、dependency
current v1.2 bootstrap与migration current v1 bootstrap五项。1.0 schema raw bytes/history不变；1.1新增typed
`rejection_input={kind:"integer-vector",values:[positive safe integers]}`。noise oracle中的values必须是真正numeric
`[1,2,100,200,201]`并进入oracle digest，不能藏在`reject_error_message`；message只保留诊断。core影响只限
1.0/1.1 exact field/version/schema/digest与safe-integer验证，performance application负责解释vector和重算median/MAD。

Source/package影响沿1.1 schema→profile domain/schema registries→generic core/source checkout→wp-00 exact targets/
source manifest→oracle/manifest/plan/application→
performance bootstrap、dependency current v1.2 bootstrap、migration current v1 bootstrap pin/digest→pyproject→只读builder→
wheel archive/unpacked/RECORD双向级联。dependency v1.1是historical且不得修改。其余affected config/application/test路径
均已逐项列入Historical Spec revision 29的164 closure，其中必须exact包含已授权的`core/graph_engineering/core/profiles.py`与
`config/verification/wp-00-targets.json`：前者把1.1 schema ID加入`PROFILE_DOMAIN_SCHEMA_IDS`并保持1.0+1.1 exact，后者把
1.1 schema path加入wp-00 exact set，使source manifest纳入新schema。遗漏任一路径会让registry构造或source/package
attestation失去闭包；missing/extra/version alias、stale/omit/reorder、1.0 replacement、message payload、checkout fallback
或package mismatch都保持对应IDs missing。Historical A不改变Positioning/PRD、P/R semantics、DB/GraphRef、dependency、
网络、WP-10或不可逆权限；`scripts/build_backend.py`仍不在allowlist。Historical B authority lineage为
`GEW-REMAINING54-ACTION-PROVENANCE-B`；Historical A authority为`GEW-REMAINING54-ORACLE-REJECTION-INPUT-A`，routine
closure `GEW-REMAINING54-ORACLE-CASCADE-A-R1-001`保持CLOSED。

Historical B把Envelope从164增至165，唯一新增`config/actions/action-policy-v1.json`。P2新增packaged sources使
`pyproject.toml` builtin implementation build projection与derived implementation digests变化；adapter registry、concrete
policy及两份current action policies因此必须拓扑重签。default policy旧pin让P1 verified child fail closed是正确防护，
不是可删障碍。绕过factory、弱化/删除installation pin、caller override、ambient checkout fallback或伪造coherent chain会把
stale implementation提升为current，风险不可接受且明确禁止。

Historical B impact graph为`pyproject.toml` builtin provenance→`config/contracts/action-adapter-registry-v1.json`→
`config/actions/concrete-action-policy-v1.json`→`config/actions/action-policy-v1.json`与
`config/actions/action-policy-local-actions-v1.json`分支→`config/security/security-runtime-local-actions-v1.json`→
source checkout/wp-00/current performance、dependency、migration、scenario-truth、release-operations bootstraps→
pyproject package/resource pins→只读builder→wheel archive/unpacked/RECORD。下游pin fields不进入上游builtin build
projection，且default/local policies互不互引，因此无digest环；只允许由final current sources按拓扑单向重算和反向验证。
already-in-Historical-B-165 source/package/test paths由Historical Spec revision 30逐项冻结，按值不变的pin仍须重验但不得人为修改历史文件。

Historical B要求P2a source恢复并冻结后先完成整链重签，再复跑P1 currentness sibling；只有P1 sibling再次通过才可继续P2a。
B不改变action semantics/capabilities/operations、P1/P2目标、外部动作gate或历史bytes，并在当时不授权第166路径。遗漏/额外路径、
错误edge direction、self/cross-policy cycle、stale intermediate digest、仅正向不反向、package/RECORD mismatch均保持P1/P2
records missing且零action/target mutation。

Historical C把Envelope从165增至166，唯一新增`config/security/security-runtime-v1.json`；删除该唯一C项精确恢复165，
且在C当时不存在第167个path。它关闭`GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001`：B重签default policy后，旧default
runtime pin正确fail closed，但B未授权该current consumer进入可变闭包。C仅补齐该runtime target，不改变action semantics、
capabilities、operations、external-action gates、P1/P2目标或任何历史bytes。

C impact graph共享`pyproject.toml` builtin provenance→`config/contracts/action-adapter-registry-v1.json`→
`config/actions/concrete-action-policy-v1.json`前缀，随后精确分叉：default policy
`config/actions/action-policy-v1.json`→default runtime `config/security/security-runtime-v1.json`；local policy
`config/actions/action-policy-local-actions-v1.json`→local runtime
`config/security/security-runtime-local-actions-v1.json`。两份runtime current后共同进入已在166内的source checkout、
`config/verification/wp-00-targets.json`、performance/dependency-v1.2/migration/scenario-truth/release-operations current
bootstraps、package pins、只读builder、wheel archive/unpacked resources与`RECORD`。两个runtime不得互引，下游不得反馈
上游，故无digest环；只允许按拓扑单向重算并对source/resource/raw hash/size/semantic/nested/RECORD pins反向exact验证。

`scripts/evidence_utils.py`是default runtime的只读consumer并须验证current default-policy pin；它不在allowlist且不得修改。
default policy重签而default runtime仍是旧pin时，evidence collection与P1 verified child必须在任何evidence/action/target
write前fail closed，禁止以consumer rewrite、factory bypass或installation-pin weakening恢复。P2a恢复顺序固定为final packaged
sources→shared prefix与两policy→拓扑重签两runtime→`evidence_utils` currentness test→P1 currentness sibling PASS→
P2a scenario issuance；省略或换序保持相关records missing。Historical C authority lineage为
`GEW-REMAINING54-ACTION-RUNTIME-C`。

Historical D把Envelope从166增至exact167，唯一新增`tests/security/test_wp07a_action_contract_security.py`；删除D项精确恢复
166，且D authority revision拒绝第168个path。影响严格限于历史WP07A测试的一个expected constant：获批P2a scenario sources与
`pyproject.toml`合法改变build projection，且C action chain完成重签后factory/WP08 currentness和package/wheel均PASS；
扩大security run 17/18的唯一失败，是该测试仍将`_action_build_manifest_digest(pyproject.toml)`与旧
`b9e8e75bca0436651a723da05d9bcea27f06768666c8c1d9f9fc6b9b80707944`比较。

D只允许把旧literal更新为current approved build projection的独立预计算exact digest。必须保留dependency、declared
imports、build mapping、entrypoint、registry与provenance substitution attacks；禁止skip/remove assertion、loose/prefix
comparison、ambient/caller/runtime-self-derived expected或回退合法P2a files。因此产品语义、action authority、实现/config、
P1/P2结果与安全姿态均不变，风险只是在变更顺序错误时让stale test继续阻断，不能通过弱化测试规避。

Candidate findings `GEW-REMAINING54-P2A-CAND-R1-001`、`GEW-REMAINING54-P2A-CAND-R1-002`、
`GEW-REMAINING54-P2A-CAND-R1-003`、`GEW-REMAINING54-P2A-CAND-R1-004`、
`GEW-REMAINING54-P2A-CAND-R1-005`全部保持OPEN，等待新的独立Candidate reviewer；001/002/003/005 focused GREEN
只是修订证据，004仍需D后cumulative selector。恢复顺序固定为exact WP07A baseline update→named WP07A method→WP08
security/evidence/package/wheel/P1 sibling→`p2a-cumulative-r2`。D不改变P2a plan226/oracle113/dynamic 226/48/false或
static 0/274/false。Historical D authority lineage为`GEW-REMAINING54-WP07A-BUILD-BASELINE-D`。

Historical E1不改变target boundary：当时Envelope仍exact167 unique relative/no-glob，D仍是相对C唯一新增test，删除D恢复166，
且E1 revision拒绝第168项。Current F1单独增加dependency-security application source形成exact168；它不合并隔离边界，
每binding继续使用唯一fresh private repository root、task、target、branch/ref和
action/command roots，禁止跨binding/profile共享repository。

资源影响从“226套live contexts一直保留到gate”改成process-local opaque authority分段持有。execution/observation后seal
绑定current installation/provenance/source/package/wheel/`RECORD`、runtime-attested root identity（core不硬编码absolute
path）、task/object/target/action/command状态和record/observation digests；quiesce释放repository/object/action/Git/
launcher/session handles与live FDs，同时保留private-root bytes。后续issue/use/precommit/gate由runtime-owned typed port
strict-serial reopen同一root，全量重读/比较后才验证，完成即新generation seal并再次quiesce。同一时间最多一个reopened
binding；finalize/revoke永久关闭。

安全影响是新增必须fail-closed的process-local capability lifecycle。seal不可serialized/portable/caller-created/cloned/
shared/replayed；wrong root/ref、same-path/coherent replacement、missing/extra closure、double/concurrent/out-of-order reopen、
cross-binding/profile reuse、action/mutation replay、currentness cache/skip、symlink和terminal reopen全部zero write/mutation/
replay拒绝。进程退出后不能从seal bytes恢复；existing durable restart只能经fresh factory currentness建立新process-local
authority，不得重执行action。core只有platform-neutral state machine/typed port，actual filesystem/repository/action reopen
留runtime/test adapter，不新增DB schema/table、GraphRef lifecycle、dependency、daemon或WP10。

触发证据：`p2a-cumulative-r2` first 4.086s C provenance fail-closed后修复，second exact7200s TimeoutExpired无receipt；
retained contexts FD4→885/maxRSS7.20GB、teardown FD4；same-root probe plan0.546s/base7.801s/226 authorities4.904s/
observations226.608s/factory1.085ms/issuance114.974s/dynamic>545.166s并900s timeout。影响判断是live accumulation加三次
currentness passes而非single binding stuck，不能抬高runtime/heartbeat掩盖。RSS/FD只作diagnostic；deterministic lifecycle/
active-handle counters与FD baseline-return才是resource acceptance，机器阈值不进engine。

正向226-binding lifecycle保持plan226/oracle113/dynamic226/48/false、static0/274/false与P1 sibling current；测试必须
机械断言repository-root、task、target、branch/ref、action-root、command-root六个identity集合各有exact226 unique成员，
combined binding tuple也有226 unique成员，任意维度都不跨binding/profile共享。全部cross-binding/profile substitution
negative保持zero write/mutation/replay。D顺序保持。五个Candidate findings仍OPEN，仅独立reviewer可关闭；R1-004新增E1 closure。
Current authority lineage为`GEW-REMAINING54-PROCESS-LOCAL-QUIESCENT-REOPEN-E1`。

Stable finding `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001`在本author revision中为
**ADDRESSED / pending independent reviewer resolution**；只有independent reviewer可以标记resolved。

F1的产品/数据影响限于一个现有application module变为可修改target：
`application/graph_engineering/application/dependency_security.py`。它只允许generic typed
`DependencySecurityObservationFactory` rehydrate/current-seal API，并保持factory、typed observation与downstream
graph/category assessment三者身份分离。rehydrate必须same private root/task/category/current installed closure；
issue/use/precommit/gate四阶段全量重读，opaque runtime-owned seal不可caller构造或portable。P↔R、forged/stale、
cross-root/task/category/installation、terminal与same-path attacks均在zero write/mutation/resolver/network/action replay下拒绝。

Routine version traceability correction不增加API或schema：existing exact `DependencySecurityObservation` 1.0与1.1都可由同一
generic typed rehydrate/current-seal contract恢复。1.0对应无graph factory，1.1对应same-binding exact
`DependencyGraphObservationFactory`；1.1必须从issued frozen graph inputs取唯一selector，并用fresh current installation graph
policy/remediation、before/after graph与disposition重建后全投影exact compare。`DependencyGraphAssessmentFactory`/Evidence保持
distinct downstream consumer且不能替代Observation authority。既有`_task_projection` discriminator、mandatory/real-E2E
candidates、`GEW-PRO-DEPENDENCY-SECURITY-ARTIFACTS-R`的
`request_digest=sha256-jcs-v1:e9315eb7ced2072939c95533b7f8aeb53e11e1e1c137d5e462c69c5130a9b938`、scenario、plan和oracle
均不变。

installation/source影响按实际闭包而非虚构的bootstrap pin传播：new application source由
`core/graph_engineering/__init__.py::_SOURCE_FILES`、source-checkout attestation、`pyproject.toml` package/protected-source
mapping、archive/unpacked wheel与`RECORD`绑定。dependency bootstrap1.2不含application source protected-member字段，只验证
自身schema/registry/source-artifact/source-attestation/history；其输入不变时1.2/schema/history bytes与digest不变。
performance bootstrap只对其真实protected files（包括`application/graph_engineering/application/profile_coverage.py`）变化重算。
pyproject、C双runtime与D baseline均须currentness验证，但仅actual projection变化才重签；action build projection剔除
dependency-advisory/performance-benchmark tables，因此C/D可以在验证后保持原digest。不引入schema、dependency、DB、GraphRef或daemon。
Routine finding `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001`由author标记
**ADDRESSED / pending independent reviewer resolution**，`authority_effect=none`。
Routine finding `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002`也由author标记
**ADDRESSED / pending independent reviewer resolution**，`authority_effect=none`；无target/schema/security-posture影响。
当前 config-owned 14400/60 来自 2026-09-10 Human 对 future budget 的明确批准，旧 agent-only 86400 不获追认；
这些数据不能替代lifecycle/currentness gates。**Agent audit note（无Human authority effect）：**index25只由plan顺序与stack
推定且缺少完整last-binding日志，不是direct observation；两个pre-existing dirty、未授权support files保持未修改。

### 14.2 延后但有明确触发条件

| 事项 | Disposition | 触发条件 |
|---|---|---|
| extension 包签名与来源策略 | 在实现 FR-18 loader 前创建独立 ADR | 首个第三方或非内置 extension 进入可执行范围 |
| Ed25519 provider dependency | ADR-0004 r5 已选择 PyCA `cryptography==50.0.0`；core 保持 verifier port，adapter boundary 承担 provider | WP-10 必须 exact pin wheel/source/RECORD hashes 与 attestation；离线缺失或 mismatch 时 install mutation 为零 |
| Wheel metadata parser dependency | ADR-0004 r6 已选择 PyPA `packaging==26.3`；仅 build/install/package-verification boundary 使用，core 不 import | WP-10 必须 exact pin distribution/wheel/source/RECORD/attestation 与离线 dependency closure；禁止 runtime network/fallback |
| Coverage byte protocol / physical wheel closure | ADR-0004 r7 固定 pipe-bound exact runner/module/callable bytes 与全 closure/physical ZIP 计费校验 | verification 竞态或 wheel hidden/duplicate/exhausted 状态 fail closed；不扩大 WP-10 或 executable authority |
| remote/hosted storage | v1 排除，不建 ADR | 产品方向请求远程控制面或多设备共享 |
| 多 Owner / 跨 runtime transfer | v1 排除，不建 ADR | Positioning/PRD 发生明确意图变化 |
| 非 Git VCS | v1 排除，不建 ADR | 产品范围变化 |

### 14.3 不需要 ADR

- Codex/Hermes 最低版本：由 capability contract、兼容矩阵和安装时探测管理；
- secret provider 优先级：由 adapter capability 与项目配置决定，secret value 不入状态；
- PMF 阈值、loop budget、timeout、freshness：属于可版本化配置数据；
- 具体项目 build/test 命令和 vendor connector：属于 ProjectScope/config/adapter；
- 文档模板和 compact 合并方式：受 ArtifactContract 约束的配置/asset。

## 15. 交付顺序影响

Impact 建议的依赖顺序是：

```text
ADR-0001 implementation platform
        ├── ADR-0003 deterministic contracts
        └── ADR-0002 repository/coordination
                 │
                 ├── ADR-0005 recovery-claim compensation
                 │        └── independent review + exact crash/concurrency evidence
                 ├── ADR-0006 offline dependency advisory authority
                 │        └── independent review + exact source/closure/currentness evidence
                 ├── ADR-0007 offline performance benchmark authority
                 │        └── independent review + exact clock/environment/statistics evidence
                 └── Plan + Test Plan
                        │
                        ├── vertical slice: create/discover/approve/review
                        ├── durable graph + recovery + authority/action
                        ├── Codex/Hermes parity
                        ├── nine Profile completion semantics
                        └── release/migration/candidate verification
```

Plan 可以按风险垂直切片实现，但不能把安全底线留到所有功能之后。首个会调用真实 tool
的 slice 必须已经具备 §8.2 的全部控制；首个发布 Candidate 必须满足九类完整门槛。

## 16. 回滚与停止条件

由于当前是绿地文档阶段，Impact/ADR 修订可通过恢复上一 revision 回滚，不影响用户或
外部系统。进入实现后：

- 单个 code slice 应可通过版本控制回退，但已写新 schema 的测试状态必须用迁移/备份
  恢复，不能手工删 event；
- 任何 target action 的回滚按其 prepared rollback plan 和单独 authority 执行；
- 若 repository 无法通过 crash conformance、identity 无法稳定绑定、或真实动作无法
  可靠 reconciliation，停止对应交付路径并返回设计节点；
- 若九类覆盖只能通过缩小冻结矩阵实现，视为产品意图变化并返回 Human；
- 若复杂度指标和真实使用持续反证 PMF，Agent 提出范围/体验实验，但不自行改定位。

## 17. Candidate 退出条件

本文只有在以下条件满足后才能进入 ADR node：

- 现状、变化边界、模块、用户、数据、接口、安全、运行和兼容影响完整；
- 18 个 FR、8 个 NFR 与九类/三路径影响有追踪；
- breaking/migration 结论与绿地状态一致，但已定义首版后的兼容责任；
- 风险有明确 owner、缓解和 blocking 分类；
- 每个 Tech Spec 待确认项都有 ADR、延后或非 ADR disposition；
- 独立 Impact Reviewer 返回 PASS；
- 没有改变批准的 Intent、Authority 或重大架构边界。

## 18. 批准状态

本文原始 Impact 已通过 Independent Impact Review；0001～0003 与 Plan 已获批准。WP-05 暴露的
expired-lease compensation conflict 已由 Human Owner 接受 ADR-0005 方案，但 ADR-0005 的独立
review、实现和 exact evidence 仍是该 recovery path 的 blocking gate；通过前只能 fail closed。
其余计划内本仓库可逆实现可继续推进；commit、push、merge、deploy、release、外部通信仍需
单独授权。


## 2026-09-10 approved Candidate defect repair

Hotfix classification: approved existing-contract repair, not a new PRD intent or architecture scope. Affected surfaces are local scenario observer/path validation, coverage authority, installed fixture expectations and their existing schema/pin closure, test fixtures and regression tests. The previously accepted P/R boundary is retained: R proves only fail-closed rejection, never P success. No database, event, GraphRef, dependency, user-root or network change. Existing historical review and run records remain immutable evidence; this supplement supersedes agent-only 86400-second prose, not the historical facts.

Current governing budget: **14400 seconds (4 hours)** for future separately authorized cumulative runs; heartbeat remains 60 seconds. Historical 12600/86400 values and old receipts are retained as history, not current authority. Monitoring remains PAUSED and no automatic rerun is authorized.

### P2b bounded continuation impact — 2026-09-11

Human authorized only documentation, implementation, bounded tests and independent
review of the two hotfix scenarios. P2a commit
`6c3e67c011925fb41d49d0781c3fd06e619d708b` preserves all accepted prior bytes,
approvals and runtime evidence. New source invalidates reuse of that receipt as
current cumulative evidence; it does not invalidate its historical acceptance.

Affected layers are existing scenario core/application factories, profile
assessment/coverage consumers and private test contexts; guarded fixture and
observation shapes are conditional additions to existing authorized schema pairs.
Only the two hotfix fixture/policy rows gain guarded behavior. P2a and inactive
P2c/P2d fixtures retain their semantics. Registry/bootstrap/package pins may
change only where actual protected inputs change. The exact174 source-edit
allowlist is unchanged; the prior commit-only exception for the two protected
support files is exhausted and grants no editing permission.

Risks: baseline captured too late; authority/control substitution; false health or
production claims; proof clone/foreign reuse; loss of proof on CAS restoration or
quiescent reopen; incomplete R vectors; partial patch mistaken for zero-write
rejection. Mitigation is pre-mutation identity receipts, current same-root reads,
closed typed proof validation, exact ordered complete rejection aggregation and
fresh-root bounded regression. Local fixture authority is explicitly synthetic
and installation-owned, not real production authorization.

No new database/event/GraphRef/API endpoint, dependency, daemon, external service,
runtime adapter or production operation is introduced. This is an implementation
refinement of ADR-0008, not a new architectural direction. Preserve historical
assessment versions and the P2a no-follow path walk. Any necessary new target,
material architecture or authority change returns to Human before implementation.

### P2b cumulative entry impact — 2026-09-12

Authority: `p2b_cumulative_entry_amendment`. This is acceptance-harness work for
the two already accepted hotfix scenarios, not new product intent or architecture.
Primary code target is `tests/support/wp08_release_coverage.py`; unit/contract
targets are the existing scenario-truth unit and Remaining54 contract modules.
The current Spec, Plan and Test Plan and append-only existing delivery records
carry design and evidence. Only actual affected provenance/package/bootstrap pins
may be reconciled inside the unchanged exact174 allowlist.

Shared orchestration risks are cross-checkpoint count drift, premature expensive
execution, misrouted parent/child selectors, partial evidence presented as full,
and loss of cleanup on exceptions. Mitigate with immutable fixture expectations,
preflight before P1/bindings, exact receipt validation, independent P2a/P2b dispatch
tests and fast simulated success/failure lifecycle tests. Retain selected real
hotfix and P2a lifecycle regressions; simulations prove wiring only.

Production plan230/oracle115, installed scenarios, budgets, schemas, approved
Intent Baseline, protected three files and old records stay unchanged except
mechanically necessary actual pins. This entry is not a real run: no cumulative
receipt, monitor restoration, commit/push, P2c/P2d/P3, network or WP10 is allowed.

### P2b oracle closure repair impact — 2026-09-12

This is a bounded acceptance-harness defect repair, authorized by
`p2b_oracle_repair_amendment`, not a new product feature or architecture decision.
The primary source changes stay in the existing release-coverage fixture,
scenario-truth unit tests and Remaining54 contracts. Update the existing Spec,
Impact, Plan and Test Plan; append new repair-specific workflow siblings only.
No new target, PRD, ADR, production source/configuration or budget is required.

The expectation helper also serves existing no-argument installed-plan callers
and an integration contract. Its default must represent current P2b115; explicit
P2a retains its exact historical113. The cumulative P1 sibling is a second real
loader consumer and must inherit the same explicit checkpoint. Risks are
accidental P2a promotion, a count-only bypass, self-derived expectations and
mocked tests hiding another loader call. Cover them with independent frozen
identity sets, exact substitutions and real loader/boundary regressions.
The protected three files, original Envelope and every prior launch/review record
remain unchanged. No cumulative/performance workload or automatic retry occurs.

### P2c bounded continuation impact — 2026-09-14

The Human-approved change is limited to three refactor-debt scenario pairs and
their three oracle members. Affected layers are the existing scenario fixture and
observation schema pairs, policy/fixture/bootstrap protected configuration,
scenario core/application factories, scenario coverage fixture, profile plan,
package/source-currentness pins, focused tests and append-only delivery records.
Only actual changed provenance/package/bootstrap projections may be re-signed,
inside the unchanged exact174 allowlist. P2a/P2b evidence remains historical and
must not be rewritten or presented as current P2c evidence.

Primary risks are treating ordered behavior as a set, comparing graph counts
instead of exact directed edges, embedding a threshold in code, accepting floats
or booleans as integers, trusting caller-reported equality, evaluating a later
gate after an earlier failure, losing the refactor proof across CAS/restart, or
calling post-mutation rejection a zero-write result. Mitigation is a protected
config-owned closed contract, exact A-before/B-after observations, canonical path
and edge identity, generic integer comparator dispatch, ordered fail-fast gate
results, conditional typed proof validation and explicit mutation accounting.

No database/event/GraphRef/API, dependency, daemon, runtime adapter, network,
real repository or production operation changes. The existing assessment 1.3
projection and one task-referenced CAS remain the durable carrier. This refines
ADR-0008 implementation without a new ADR. A needed target expansion, Support
Matrix change, material architecture choice, cumulative execution, P2d/P3 work
or irreversible action returns to Human first.

### P2d bounded continuation impact — 2026-09-14

The Human-approved change is limited to four incident-response P/R pairs and
their four oracle members. Affected layers are the existing scenario fixture and
observation schema pairs, policy/fixture/bootstrap protected configuration,
scenario core/application factories, scenario coverage fixture, profile plan,
package/source-currentness pins, focused tests and append-only delivery records.
Only actual changed provenance/package/bootstrap projections may be re-signed
inside the unchanged exact174 allowlist. P2a/P2b/P2c evidence remains historical.

Primary risks are trusting a caller detection/severity claim, losing exact impact
scope, over- or under-containing, mutating an unaffected target, using stale
authority/fence/service evidence, replaying the original action as recovery,
accepting partial recovery, consuming an unknown claim, or treating a blocked
unknown effect as service restoration. Mitigation is a closed config-owned
incident contract, exact fresh observations, ordered fail-fast gates, explicit
action and mutation vectors, conditional typed proof validation and exact inner
outcome/owner-route binding.

The unknown-effects path is intentionally not the normal A-to-B mutation path:
its P evidence proves a zero-mutation `blocked-owner-route` outcome with the
unknown claim retained and no replay/recovery/restored claim. This is distinct
from R evidence, which proves malformed or unsafe requests fail closed. The
scenario recovery oracle uses its unique `scenario-recovery` filename; the
mandatory incident recovery oracle is protected byte-for-byte.

No database/event/GraphRef/API, dependency, daemon, runtime-adapter, network,
real-repository or production operation changes. The existing assessment 1.3
projection and task-referenced CAS remain the durable carriers. ADR-0008 already
freezes these semantics, so no ADR change is needed. Target expansion, Support
Matrix change, cumulative/performance execution, P3 or irreversible work returns
to Human first.

### P3 mandatory24 impact — 2026-09-21

Authority is `p3_mandatory24_bounded_amendments[0]`; the
[Spec amendment](../specs/graph-engineering-workflow.md#p3-mandatory24-bounded-contract--2026-09-21)
is the source contract. Affected existing modules are release/category execution,
coverage and their private test fixtures; installed execution-plan/oracle/package
closures; focused native tests; and authorized delivery records. Twelve new oracle
files are within the approved path ceiling. Exact implementation targets must be
selected from the same 195 paths before writes; this list is not an expansion.

The highest risks are a normal-only check removed without reconstructing other
column proofs; source reads escaping the two captures; forged or duplicate
controls; accepting a restored action as fresh mutation authority; double restore;
Git or caller facts masquerading as local release execution; 1.4 accepted without
its live/cold currentness joins; and a configuration count mistaken for cumulative
acceptance. Mitigations are the closed source table, pure captured validation,
exact identity-sealed private dispatch, journal/claim/receipt joins, read-only
completed-restore adoption, explicit mutation counters and per-binding lifecycle
checks. Rejecting a mutated target must not publish zero-write rejection evidence.

The original schema versions, generic category policy, Support Matrix, performance
thresholds and previous profile semantics stay unchanged. No schema migration,
DB/event/GraphRef/API/dependency, daemon, network, real-target deployment or new
adapter is required. Build-backend and evidence utilities remain outside the
allowlist. Pin refresh uses existing machinery and changes only affected entries;
re-signing a changed input never substitutes for tests or independent review.

Validation covers all twelve P/R pairs, cold P joins and adversarial source
mutations, rollback no-replay, actual release real-E2E, lifecycle revocation and
affected existing regressions. No cumulative/performance workload is executed.
Retain failed attempts and all prior records. A failed sub-batch publishes no
accepted partial result; repair stays within the reviewed contract or returns
to the relevant design node. Commit remains a separate human decision.
### P3 scenario6 impact — 2026-09-22

The approved bounded amendment adds three scenario P/R pairs and three oracle
members to the committed268/134 baseline. The initial exact34 targets are frozen
in Manifest and are a subset of the existing195 allowlist; unused targets are
removed before Candidate. Review/evidence records remain detached and immutable.

Affected consumers are release observation/currentness, category boundary
assessment, coverage reader/runner, execution-plan selectors, source attestation,
bootstrap/package closure and focused tests. There is no data migration, event,
GraphRef, public API, dependency, real environment or network change. Existing
268 binding values and134 oracle meanings must remain exact. New selectors and
oracles require package/resource closure updates; other pins change only when
their input projection changes. Preserve SupportMatrix, schema1.0–1.4, historical
dependency1.1, build/evidence helpers, performance thresholds and read budgets.

Main risks: selecting a generic boundary proof instead of the scenario; accepting
caller PASS as release evidence; mislabelling compensation as deployment success;
losing original claim/receipt joins after restart; leaking source-port resources;
or changing unrelated old counts/semantics. Mitigation is exact scenario/request
binding, opaque issuer validation, explicit action/residual-state assertions,
fresh-process typed recovery, currentness attack tests and package/protected-byte
comparisons to commit0713fc9. Rejected completion/read/reopen must cause zero new
mutation even when the scenario setup already performed bounded actions.

Recovery from a failed development check keeps its evidence and stops subsequent
verification; fix within the approved targets then recapture affected evidence.
If a staged source changes after canonical capture, restage and recapture before
creating a new Candidate. No deployment rollback procedure applies: this batch
does not publish or deploy. A future commit remains separately authorized.

### P3 cumulative274 design impact — 2026-09-23

Scope: [cumulative274 Spec](../specs/graph-engineering-workflow.md#p3-cumulative274-entry-design--2026-09-23)
under the unchanged approved PRD v2. Direct approval is design/review only;
implementation, workload execution and commit remain separate decisions.

The current entry graph has historical 226/113 and 230/115 cumulative checkpoints;
its default oracle closure describes 244/122. Configured state is now274/137.
The new selector must have its own exact expected closure, receipt validator,
full-gate expectations and safe terminal routing. Do not globally change defaults
or reinterpret historical partial results. Dispatch for current release mandatory
and scenario bindings already exists; the new entry composes these actual paths.

| Surface | Proposed impact | Required evidence |
|---|---|---|
| `tests/support/wp08_release_coverage.py` | New explicit selector, exact preflight/receipt, full-run orchestration, parent cancellation cleanup; retain old selectors | Wrong input rejects before launch; positive routing, failure cleanup and historical compatibility checks. |
| `tests/unit/test_wp08_scenario_truth.py` | Focused mocked-launch entry/receipt/deadline tests | Exact identity/type checks, no accidental workload; bad selector/receipt cannot pass. |
| `tests/contract/test_wp08_remaining54_contracts.py` | Current274 independent closure and legacy rejection contracts | All binding/oracle rows and installed digests checked; historical selectors reject newer plan without execution. |
| `tests/integration/test_wp08_release_coverage.py` | Bounded actual-factory incomplete-gate/abort and currentness regressions | No fake authority promoted to actual full coverage; zero replay and deterministic cleanup. |
| Four current design documents | Current scope, decisions and implementation/launch proposals | Independent per-artifact review and immutable reducer results. |
| `.workflow/manifest.json` in a future implementation batch | Exact implementation targets and verification scope | New implementation approval before changing; no mutation in this design batch. |

`p3-c274-impact-inventory-r0.json` records actual baseline SHA-256s and membership
checks: the four proposed Python targets are absent from production `_SOURCE_FILES`
and test attestor `SOURCE_FILES`, and all existing installation bootstraps have
no references to them. Thus these edits do not require production source/package
list changes, new wheel resources or bootstrap repinning. Existing verified test
capture still binds changed test/support bytes to the Candidate. Recheck this
closure after implementation; a newly discovered transitive production change
invalidates this impact conclusion and requires expanded authority.

Read-only dependency surfaces include the installed274 plan/137 oracles, Support
Matrix, registry limits, `CoverageRecordFactory`/`ReleaseCoverageGate`, lifecycle
ports, source attestation issuer and existing verified-byte test/evidence runners.
No build helper, evidence helper, schema1.0–1.4, dependency1.1, package manifest,
core API, DB/event/GraphRef contract or external adapter change is proposed.

The new receipt stays internal test-runner JSON, never an executable authority.
No migration or rollout is needed. Additive selector isolation is the rollback
boundary: leave it unavailable until its evidence passes; retain original
selectors and old records. A design-only amendment requires no runtime rollback.

Risks: acceptance from counts alone (exact installed identity/row/digest joins);
wrong lifecycle selection (actual consumed-decision identity plus bounded
factory negative proof); cancellation orphaning child/control resources (parent
stop/reap before deleting roots); broad default oracle changes (explicit selector
and legacy tests); runtime overrun (14400-second total including P1, no increased
budget). RSS/FD diagnostics cannot replace deterministic lifetime checks.

Residual limitation: bounded tests cannot establish274 cumulative acceptance or
4-hour feasibility. Only a separately authorized actual run can do that. A failed
attempt remains failed; do not patch sources during execution or automatically
rerun. The design introduces no material architecture decision, so no new ADR is
required; discovery of one returns to the human before implementation.

### C274-RUN-001 repair impact — 2026-09-25

Actual run r1 at commit460ace6 failed after274 observations and before factory
construction. All274 closes returned without a reported cleanup error; the
post-success global FD baseline assertion was not reached. Preserve failed logs
and independent diagnosis; no cumulative acceptance is claimed.

The repair affects only the test support projection and targeted unit/integration
coverage, with corresponding design/plan/test-plan and Manifest registration.
No production source, package resource, schema, registry, budget, authority gate,
PRD or positioning change is needed. The principal risk is treating reconstructible
recovery data as authority or masking shared physical roots with task labels.
Exact registered reader/record/lifecycle linkage and resource-only uniqueness
regressions address that risk. A bounded green result is source readiness only.

### C274-RUN-002 pure computation impact

The previous full run timed out at14400s after274 record issuances; preserve its
failed result. This increment moves deterministic installation parsing behind
an operation-local memo in application dependency security and wraps each
coverage lifecycle phase with the private scope. All physical resource acquisition,
source integrity, currentness/capability checks and subprocess preflight remain.

Main risks: incomplete pure keys, mutable result poisoning, inherited/thread-local
state surviving a phase, and accidentally caching live validation. Exact verified
bytes plus schema inputs, detached results, PID/thread binding, bounded two-slot
retention and finally cleanup address these. Mutation/failure/cross-phase tests
must prove the boundaries. No core/schema/resource/dependency version changes are
planned; if mandatory integrity artifacts fall outside the approved exact target
list, enumerate and obtain scope expansion before editing them.

The first increment may have limited benefit because preflight and I/O remain.
Representative timing is performance evidence, not274 acceptance. Commit and full
run remain separate.

### C274-RUN-003 installation closure impact

Run r3 at c8128eb failed after 3.896s in P1 registry initialization, before full274
binding execution. Of 38 protected performance resources, only profile_coverage.py
had a stale pin. Both implementation and Candidate review missed this reverse
dependency; the prior plan-only launch preflight did not initialize this registry.
The integrity rejection is correct and must remain intact. Preserve failed run
and independent diagnosis records. Configuration changes affect the bootstrap
JSON and pyproject performance metadata; package resource validation is therefore
required. No engine/runtime algorithm, timing limit, PRD or ADR change is needed.
Add a permanent installation-closure regression and use existing provenance
negative checks. Evidence must distinguish configuration consistency from actual
benchmark/cumulative acceptance.


## WP-09 local product learning — design impact R1, 2026-10-02

Authority: `GEW-WP09-LOCAL-LEARNING-DESIGN-V1`, owner “批准开始”. Current
changes are exactly Manifest plus the four main design artifacts. PRD/Intent,
Positioning, all code/configuration, Policy budget4, committed history and the
accepted C274 r6 receipt remain unchanged. This is design readiness, not WP09 exit.

### Existing dependencies and observed gaps

Spec W9.4 records inspected interfaces. Runtime query authorization and committed
source integrity are reusable; neither existing `TaskRepository.replay` nor
`lifecycle_facts` supplies a bounded PMF collector. `pmf-aggregate` retention
configuration exists, but no PMF subject registration, consent table or learning
application does. New work must not weaken existing query or purge authorities.
FR-13 and PMF001–004 require all four: minimized observations, owner context,
negative learning evidence and consent/retention. Counting successful C274 tests
would satisfy none of those product requirements.

### Architecture decision and compatibility

W9-D1 recommends four same-database tables (consents, aggregates, owner context,
tombstones). This needs an explicit owner architecture decision and ADR before
implementation. Main event rows/CAS must not contain disposable PMF metric bodies;
audit integrity and telemetry deletion have different lifetimes. Existing approved
retention semantics and current security-subject bindings apply. Same-database
transactions avoid a new cross-database revoke/publish race; no new dependency is
proposed. Existing repository schema upgrade/downgrade behavior must be inspected
and tested, rather than adding `CREATE TABLE` during an ordinary query. This local
schema proposal is not authorization for WP10 installation or activation.

Existing owner operations and graph/event schemas remain compatible. New learning
operations require explicit versioned parsing/dispatch tests. Unknown PMF schema or
policy blocks learning without breaking ordinary task execution. No default grant,
background capture or historical metric backfill. No source imports from the
reference project, new network access, production data or external telemetry.

### Candidate implementation boundary, not write authority

The following is the bounded implementation inventory to reconcile after W9-D1.
Existing paths are dependencies, not permission to edit them during this task.
An exact approved subset, including any generated pin closure, must precede code.

| Group | Candidate paths | Why |
|---|---|---|
| core | `core/graph_engineering/core/learning.py` (new) | closed projection/rule/error contracts |
| application | `application/graph_engineering/application/learning.py` (new), `owner_turns.py`, `runtime.py`, `security.py` in that directory | authenticated operations, generation/currentness, subject issuance |
| storage | `storage/graph_engineering/storage/learning.py` (new), `repository.py`, `connection.py`, `security.py`, `migration.py` in that directory | bounded committed reader, atomic grant/revoke/purge, approved schema transition |
| configuration | `config/learning/learning-policy-v1.json`, `learning-experiments-v1.json` (new); `config/contracts/schemas/learning-input-1.0.0.json`, `learning-record-1.0.0.json`, `learning-report-1.0.0.json`, `learning-policy-1.0.0.json` (new) | closed schema resources and configurable admission/rules; synthetic experiment has no product-success claim |
| installation | `core/graph_engineering/__init__.py`, `scripts/build_backend.py`, `pyproject.toml`; active dependency, migration, performance, scenario-truth and release-operations bootstraps only if their protected source closure changes | package new resources, exact installed pins and source/wheel parity; never rewrite historical bootstrap versions |
| tests | `tests/unit/test_wp09_learning.py`, `tests/contract/test_wp09_learning_contracts.py`, `tests/integration/test_wp09_learning.py`, `tests/security/test_wp09_learning_privacy.py` (new), existing `tests/unit/test_wp00_packaging.py` as needed | meaningful public behavior, adversarial source/consent, packaging |
| architecture | proposed `docs/adr/0010-local-product-learning-storage.md` (new) | record W9-D1 after human decision, not created under current five-file scope |

The full list is deliberately **not represented as a frozen implementation
allowlist**: exact schema migration resources and transitive pin changes depend on
W9-D1 and a source-closure audit. Spec W9-D2 blocks implementation until every such
path is enumerated and reviewed. No broad glob grants code-write authority.
A first pure-contract slice can be scoped separately if storage remains undecided;
it would not complete FR-13 or be presented as usable product learning.

### Risks, invalidation and rollback

- Privacy risk: task IDs, timestamps and hashes remain linkable metadata. Enforce
  field closure and owner-only access; no raw text logging, including exceptions.
- Integrity risk: a valid hash without trusted source binding is not authority.
  Whole-window completeness, source-head and consent-generation checks are required.
- Resource risk: generic replay/CAS copies can exceed a PMF bound. Reject before
  allocation and fail the entire request instead of reporting truncated totals.
- Retention risk: revocation, expiry, legal hold and consumed purge authority must
  remain distinct. Suppression is immediate; blocked physical deletion is visible.
- Measurement risk: explicit windows, known denominators and self-report labels
  prevent “unknown = zero”, success-only sampling and false causal claims.

Schema/policy/source changes invalidate derived learning views and report handles;
they do not invalidate historical C274 evidence for its original commit. New code
would require its own verification, never reuse that receipt as proof of changed
bytes. Design-only changes here require format, scope, links and independent
artifact review; no product tests or four-hour rerun are relevant.

Roll back this design by reverting only its supplement and Manifest after any
separately authorized commit. Future product rollback must disable collection,
suppress derived views and preserve migration compatibility and audit tombstones;
never delete raw task event history to implement PMF deletion. No migration or
real-data rollout is being performed now.

R1 source clarification: existing event timestamps are caller-reported despite
valid chain digests; a future trusted duration source may expand W9-D2 targets and
must be reviewed before code. Consent-expiry trusted time cannot certify historical
duration. Owner-context versions/digests and both-end relation dependencies now join
aggregate/report identity and atomic currentness checks; task-head binding alone
is insufficient. These refine existing privacy/traceability goals, not data authority.


## WP09 implementation authority and impact — 2026-10-04

Owner explicitly approved the reviewed 38-file boundary, synchronous consent-gated observation and export restriction. This supersedes earlier design-only and unavailable-three-metric statements. Event schemas/CAS bodies stay unchanged; observation state is a separate closed column within pmf_aggregates. Review application/tasks.py semantics, storage commit/recover atomicity, source clock privacy and migration pre-output guard. Fourth stage-authority metric remains unavailable.

Exact target inventory:

- `.workflow/manifest.json`
- `application/graph_engineering/application/learning.py`
- `application/graph_engineering/application/owner_turns.py`
- `application/graph_engineering/application/runtime.py`
- `application/graph_engineering/application/security.py`
- `application/graph_engineering/application/tasks.py`
- `config/contracts/schemas/learning-input-1.0.0.json`
- `config/contracts/schemas/learning-policy-1.0.0.json`
- `config/contracts/schemas/learning-record-1.0.0.json`
- `config/contracts/schemas/learning-report-1.0.0.json`
- `config/learning/learning-experiments-v1.json`
- `config/learning/learning-policy-v1.json`
- `config/migration/migration-rehearsal-installation-bootstrap-v1.json`
- `config/profiles/scenario-truth-installation-bootstrap-v1.json`
- `config/release-operations/release-operations-installation-bootstrap-v1.json`
- `core/graph_engineering/__init__.py`
- `core/graph_engineering/core/learning.py`
- `docs/adr/0010-local-product-learning-storage.md`
- `docs/impact/graph-engineering-workflow.md`
- `docs/plans/2026-08-13-graph-engineering-workflow.md`
- `docs/specs/graph-engineering-workflow.md`
- `docs/test-plans/graph-engineering-workflow.md`
- `pyproject.toml`
- `scripts/run_wp09_tests.py`
- `storage/graph_engineering/storage/connection.py`
- `storage/graph_engineering/storage/learning.py`
- `storage/graph_engineering/storage/learning_clock.py`
- `storage/graph_engineering/storage/migration.py`
- `storage/graph_engineering/storage/repository.py`
- `storage/graph_engineering/storage/security.py`
- `tests/contract/test_wp09_learning_contracts.py`
- `tests/integration/test_wp09_learning.py`
- `tests/integration/test_wp09_learning_metric_sources.py`
- `tests/security/test_wp09_learning_privacy.py`
- `tests/support/source_checkout_attestation.py`
- `tests/unit/test_wp00_packaging.py`
- `tests/unit/test_wp09_learning.py`
- `tests/unit/test_wp09_learning_clock.py`

Four new product modules include storage learning_clock.py. Release-operations bootstrap additionally binds application/tasks.py. Refresh only actual changed active pins and pyproject metadata; preserve historical bootstrap bytes. Unknown provider/domain causes unavailable, never fake clock authority. Do not execute owner-data migration. Accepted export restriction applies even to empty/partial PMF schema or tombstones, checked under the same exclusive token before mkdir, backup or holds.

## WP09 report completion impact — R0, 2026-10-08

Scope: approved six-file design only for [Spec R9](../specs/graph-engineering-workflow.md#wp09-report-completion-design--r0-2026-10-08)
and [ADR0013](../adr/0013-learning-hypothesis-report-decisions.md). PRD FR13/US12 and
Intent remain unchanged. The proposed implementation adds configured hypothesis
decisions and planning references; its targets/argv need separate owner approval.

| Component | Proposed change and effect | Required verification |
|---|---|---|
| core learning | pure reduction across required rule decisions; evaluate_rule untouched | precedence/empty/unknown/duplicate/input-order truth tables |
| installed learning loader | active policy1.2, experiments1.1, report1.2; exact closed cross-reference validation and old validators retained | valid config changes behavior; malformed/dangling/cyclic/duplicate/oversized config refuses |
| transactional report | sorted hypotheses/catalog projection, bounded unfavorable-reference union; preserve counts and final guards | four genuine cohorts, privacy/currentness/replay/receipt/crash and full FR13 P/R journey |
| config and schema resources | five additive versioned resources; policy limits add hypothesis/catalog bounds | active/legacy exact formats, old resource bytes preserved and known schema ceilings |
| package/source registration | include five resources in source lists and wheel mapping; three active bootstrap initializer pins refresh | exact source/wheel closure and stale/missing/substituted resources reject |
| test-only fixtures | genuine multiple tasks/completion gate; separate valid installed configurations | no fabricated completion/aggregate/security authority, no loader trust monkeypatch |

No PMF table/schema/order/bundle changes. Observation and derived record1.1,
input1.0, PMF1.1, authority receipts and category counting remain intact. Policy
digest changes when installed rules/hypotheses/catalog changes: old consent and
captures cannot silently cross configuration epochs. Fresh explicit consent is
required; old owner input shape is compatible, old1.1-only report consumers must
refuse unknown output1.2. This is a report contract change, not an automatic
consumer/owner-installation upgrade. Historical report/policy resources still
validate their original formats without invented hypothesis fields.

### Exact proposed implementation closure

The [Plan](../plans/2026-08-13-graph-engineering-workflow.md) will freeze the exact
allowlist. Expected seams are the six design targets; core/application/storage
learning and core initializer; pyproject; the five new resources; verification
source inventory and report boundary input; three active initializer-pinning
bootstraps; source attestation test helper; genuine report test helper; five report
test files and existing authorized-stage contract tests. Do not modify other
runtime, completion-gate, authority, repository/migration code, trust provider,
historical resources or config/workflow-policy.json.

The existing authorized-stage contract tests assert active policy1.1, ten resource
bodies and experiment1.0. Future implementation must preserve the same selectors
while testing old versions from their retained resources and new active resources
exactly; do not delete their schema/privacy/source-vector checks or pretend active
versions remain old. The other211 existing selectors remain the regression
boundary, with the additional report tests named in the new Test Plan.

Observed current dependency edges: core initializer raw hash is pinned by
migration-rehearsal, scenario-truth and release-operations bootstrap resources.
Each bootstrap's raw/semantic digest and protected-vector mirrors are embedded
in pyproject. New schema/config resources enter core and test attestation source
lists, pyproject owned-root mapping and config/verification/wp-00-targets.json.
Learning module changes are covered by source attestation rather than an invented
extra bootstrap pin. Recompute only affected active digests/mirrors; inspect the
whole closed resource vectors and preserve historical versions byte-for-byte.

### Risk and containment

Rule overlap could overcount samples: summaries reference the retained per-rule
denominators and never sum them. Favorable-only filtering could hide counter
evidence: exact rule/group coverage rejects omissions and retains sorted references.
Catalog/config changes could replay a stale suggestion: digest/consent/cohort and
final source guards refuse old handles/requests. Config/resource allocations could
exceed report bounds: explicit count/reference/byte admission precedes buffering.
Caller configurations could bypass attestation: only newly valid installed
synthetic fixtures prove positive variation; altered returned maps are not authority.

No real-data or deployment impact is authorized. PMF migration-export restriction
remains even after purge. No native Linux, clean install/upgrade, current full274/P1,
WP10/WP11 acceptance or product-market fit claim follows from this report work.
Unknown newly required target/API/security/predicate is an owner exception before
implementation. Detected integrity failures refuse rather than truncate/retry;
uncommitted changes stay reviewable and historical failed evidence is retained.


## Security trust bootstrap impact — B1, 2026-10-08

### B1-I1 Scope and necessity

[Spec B1](../specs/graph-engineering-workflow.md#security-trust-bootstrap-design--b1-2026-10-08)
and [ADR0014](../adr/0014-security-trust-bootstrap.md) realize the Owner-approved
missing installation/task initializer. PRD FR13/R9 report decisions and genuine
positive evidence are unchanged. Current six-file design authority excludes product
implementation/testing. Prior report r1 partial evidence and ESCALATE remain.

### B1-I2 Call paths and modules

New application/security_bootstrap.py orchestrates installation-owned loader,
issued RuntimeContext validation, bounded durable task/scope/baseline derivation,
receipt issuance and owned-transaction CAS. Existing storage/security.py gains
private bounded initial writers, optional receipt DDL/read validation and immutable
receipt result handling; it does not expose caller-supplied trust-map setters.
storage/repository.py supplies bounded owned-transaction recovery/projection reuse.
application/security.py adds marker-bearing provenance/currentness admission to all
four issuance/read entry points. Existing snapshot evolution/PMF subject registration
remain, and retries preserve evolved state bytes. No task graph reducer/event,
base connection schema or runtime adapter change is planned.

storage/migration.py adds explicit exclusive maintenance and complete optional
receipt namespace/marker codec validation, bounded repository digest inclusion and
atomic import initialization. Old unmarked roots/bundles remain compatible; new
receipt-bearing roots cannot fall back when their marker/table is missing. Origins
are historical metadata; destination trust still requires actual current attestation.
No new PMF export permission or new blanket bootstrap export prohibition.

### B1-I3 Exact future file and resource closure

The immutable detached security-trust-bootstrap-implementation-inventory-r0.json
lists48 unique prospective targets: retained31 plus17 additional files. Actual
future Manifest must narrow to changed/staged members, never manufacture diffs.
All31 installation resource paths are enumerated there;26 existing bytes are pinned
and5 new closed descriptor/registry/schema resources are proposed. Existing runtime,
foundation registry,15 foundation schemas,6 policies and3 work/schema profiles are
load-only; their bytes are not mutable targets. Source-attestation additions are
the exact27 missing members (including the new application module). Both core
initializer and test source inventory agree; pyproject installs every required
resource with exact RECORD membership. WP00 registers every actually new file
under its existing owned roots, preserving those roots and all prior membership.
This includes the five new bootstrap descriptor/registry/schema resources and
config/verification/security-trust-bootstrap-boundary-v1.json, as well as new
source/test modules. The optional schema marker is created explicitly, never on
generic open.

Refresh only the affected protected-resource hashes and dependent raw/semantic
closure/bootstrap digests in the three named active migration/scenario/release
bootstraps and pyproject mirrors. Preserve each vector's paths/order/counts and
all unaffected hashes. Loader and package membership are separate obligations;
an installed byte that was never attested is not trusted. No dependencies/network
services or sibling runtime reference are added. Another necessary target or
contract change is an Owner decision before code, not an implicit plan permission.

### B1-I4 Data, audit and privacy

Initial state retains the existing closed1.0.0 shape with one approved scope target,
empty executable authorities and empty destination/data/evidence/retention registries.
Two append-only receipt namespaces retain minimized IDs, digests and origin epoch;
no task/artifact content, reviewer prompt, absolute environment path or time sample.
Receipts are correlatable owner-only metadata governed by existing repository
access/retention/backup rules. New receipts are not authorization capabilities.
Later holds/claims/retention subjects cannot be erased by initialization/retry.
No new trusted wall/elapsed clock or positive source is invented.

### B1-I5 Failure and compatibility impact

Additional refusal surfaces: absent/mismatched attested resource, duplicate/partial
receipt state, wrong owner/runtime lineage, changed scope/baseline, stale CAS,
replaced installation and bounds. Legacy unmarked roots preserve existing behavior
but are distinguishable and cannot count as new positive bootstrap evidence.
Marker-bearing rows require receipt/currentness on every issuer entry point.
Normal revision/snapshot evolution is allowed; reapproval/rebase requires a separate
authorized transition, so existing bootstrap state is never silently refreshed.
No legacy report/policy/input bytes are rewritten and learning PMF1.1/report1.2 stay.

Installation and task creation each use a transaction/receipt boundary. Same-request
lost-response retry returns the original receipt; conflicting request refuses.
Install lock precedes DB transaction, shared command scope precedes task/issuer work.
No nested exclusive acquisition inside a task transaction. Migration no-PMF roundtrip
preserves old origin bytes while validating current destination facts. PMF export
stays blocked even after purge. Partial imported namespaces fail closed.

### B1-I6 Verification boundary and regression

Future bootstrap contracts, real SQLite/runtime fault/race tests, security refusal
and actual wheel tests supplement retained37 report tests and211 exact regressions.
The new Test Plan freezes each selector/argv; no directory discovery, skip/zero
collection PASS, native timeout extension or full274/P1 suite. Genuine cohorts and
FR13 P/R use production initializers and actual completion/retention services.
The old SQL helper remains historical regression setup, not positive evidence for
new tests. Owner installation upgrade/data access/Linux are not exercised here.

Current design checks verify links/Manifest/whitespace/allowlist/inventory and compare
every protected report/Intent byte. No bootstrap product tests are run or claimed.
After new implementation authority, exact combined final-tree evidence and fresh
independent implementation/Candidate review supersede incomplete report evidence.

### B1-I7 Rollout, risk and authority

Future initial use is isolated local synthetic source/wheel roots only. No production
canary, upgrade, deploy or external communication. Resource/receipt mismatch blocks
initialization or use; no auto-repair/fallback. Optional receipts require export/import
coverage to avoid silently dropping audit rows. Preserve unaccepted code/evidence
for review; any later rollback is confined to then-authorized targets. No estimate
is presented as measured latency or an acceptance result.

Design → independent review/reducer → concrete48-target implementation extension
and exact bounded argv → Owner decision. Commit, push, merge, release and later
WP10/WP11 remain separate. This resolves design/testability only; it does not itself
resolve the pending genuine-positive implementation or full final evidence findings.

### B1-I8 References and history

[Positioning](../positioning/graph-engineering-workflow.md), [PRD](../prd/graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md), [ADR0014](../adr/0014-security-trust-bootstrap.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md), [Test Plan](../test-plans/graph-engineering-workflow.md).
2026-10-08 B1: narrow Owner-approved trust initialization design; actual implementation
target/resource/pin closure identified, retained product and authority unchanged.
R1: clarify complete WP00 owned-root membership for new configuration resources
and verification boundary as well as modules (GEW-SECURITY-BOOTSTRAP-IMPACT-R0-001).

## WP-10 verified installation impact — W10, 2026-10-10

### W10-I1 Scope and upstream

This impact analysis derives from independently reviewed [Spec W10](../specs/graph-engineering-workflow.md#wp-10-verified-installation-design)
and [ADR0015](../adr/0015-release-installation-and-upgrade.md), refining accepted
ADR0001/0002 and PRD FR16/NFR01/NFR08. Current authority remains exact six-file
design/review. Slice A below is a proposed next implementation request, not current
code/testing/installation authority. Slice A does not complete WP10 or WP11.

### W10-I2 Call paths and first-slice ownership

| Layer | Proposed slice A change | Invariants and verification |
|---|---|---|
| core/release_installation.py | closed signed manifest/policy/resource/diagnostic models, pure exact closure comparisons | no filesystem, platform command, network, installer or task-state dependency; nested unknowns/digests/ranges/counts fail closed |
| adapters/release_installation.py | installation-owned policy capture, local bounded byte/archive/metadata admission, read-only Doctor | actual private source/wheel attestation and packaged parser; no caller trust map, artifact execution/extraction, writable clock or root initialization |
| application/release_installation.py and application/cli.py | orchestrate check/Doctor and stable bounded JSON/exit routing | existing capabilities/owner-flow protocol preserved; no install-apply or maintenance-authority issuer in A |
| core initializer, pyproject and build backend | register exact resources/modules and expose reusable checked physical wheel observation if required by adapter | preserve existing parser attestation, preallocation/currentness checks and wheel/source namespace boundary; no permissive parser or ambient fallback |
| supply-chain helper | additional release-input mode compares exact graph/lock/SBOM/provenance/license/security bytes | old WP00 minimal mode stays explicitly minimal; no claim its empty components certify releases |
| tests/support and new test modules | private attested release roots, actual archives/wheels/RECORD and subprocess CLI oracles | fixture signatures test validation only; no injected provider/seal, fabricated installation authority or production-key mutation |

Slice A's CLI can inspect an existing control root but does not open a writable
repository, call initialization/migration or `strict_trusted_now`, change retained
clock high-water values, or create missing control/Skill/data paths. Production
release sources/keys initially remain empty and refuse real admission. Positive
cases use newly attested private fixture installations whose installed resources
explicitly authorize only their synthetic artifacts; changing their installed
configuration invalidates old observations. A trust flag or returned dictionary
cannot substitute for this source/wheel boundary.

### W10-I3 Exact proposed closure and transitive pins

The Plan freezes the exact prospective paths for A: the six design files; three
new release_installation modules; existing application CLI, core initializer,
pyproject, build_backend and verify_supply_chain; four new release-installation
policy/registry resources, seven new closed schemas; WP00 source inventory and a
new verification boundary; four affected active bootstrap resources; existing
source_checkout_attestation helper; five new test modules, one support module
and one fixture JSON. No uv.lock/dependency/version change is included in A.
The checked-in incomplete uv.lock remains a genuine release blocker; release
admission must reject its incomplete closure when offered as bundle input.

New owned resources require both source attestation membership and wheel RECORD/
owned mapping membership. Register all new code/config/test paths under existing
WP00 roots; do not change the roots or remove old members. The core initializer
is directly pinned by migration-rehearsal, scenario-truth and release-operations
bootstraps. The proposed build_backend.py seam is additionally pinned by the active
performance-benchmark bootstrap (build_backend_source/build_backend_raw_sha256 and
its protected_resources row); its protected_closure_digest/bootstrap_digest and
pyproject performance-benchmark mirrors are also affected. Thus the future allowlist
contains all four bootstraps. Refresh only actual affected raw/semantic hashes and pyproject
mirrors after source/packaging changes, checking preserved order/counts/unaffected
entries. No historical bootstrap/resource bytes or dependency advisory trust
registries are mutable targets. Read-only reused migration/clock/locator/security/
parser code remains protected except the named build-backend observation seam.

### W10-I4 Later installation and migration impact

B/C require a new exact implementation inventory and Owner authority after A.
They add the explicit owner-only release coordinator/journal/active reference,
immutable interpreter/tool/Skill staging and dispatcher integration with existing
installation lock/migration entry points. They must preserve the accepted existing
ActiveRepositoryManifest version, task receipts, action history, leases, fencing,
retention holds and trust bootstrap. Release selection binds one immutable leaf;
repository-only publication cannot bypass registered release coordination.

Historical unregistered roots retain old semantics and do not become registered
by observation. Adoption needs the exact supported old release/bootstrap protocol
and verified migration path. PMF-initialized export still refuses, including
empty/partial schema and purged histories; neither omitted learning data nor a
physical DB copy is an alternative. Full PMF migration is outside this design.
A checks absence/compatibility honestly; it does not rewrite old locators or Skills.

### W10-I5 Data, security and privacy

Bundle bytes, metadata, signatures and paths are untrusted. Installed policy/keys/
resource ceilings and actual platform/parser/distribution ownership are separate
trust inputs. Limits precede JSON/ZIP/tar traversal, cumulative hashing, expansion
accounting and report formation. Archive paths, duplicate members, hardlinks,
symlinks, device entries, normalization collisions and swapped parent/files refuse;
A reads streams for validation without executing or extracting interpreter/installer.
A process-local admission observation is not install authority or durable approval.

Read-only time observation cannot advance repository clock facts; absent/invalid/
backward or insufficiently bound security freshness yields blocked/rejected.
Reports contain minimized opaque IDs/digests/status/route, not absolute paths,
source content, raw parser errors, executable output or secrets. No new product
telemetry, network, background process or real user-data access is introduced.
Later installation journals are owner-only audit metadata, subject to explicit
retention/data-preserving uninstall and existing claims/holds, not task payloads.

### W10-I6 Risks, compatibility and containment

| Risk | Consequence | Containment / oracle |
|---|---|---|
| signature valid but closure incomplete | unlisted transitive code executes later | actual METADATA-derived bidirectional equality across wheels/lock/SBOM and exact provenance/security binding |
| ambient parser/config/PATH or caller policy | substitutes a different accepted installation | attested provider/parser/current physical bytes, swapped-root tests, outside-checkout installed subprocess |
| Doctor performs normal service initialization | hidden task/control/clock writes | full synthetic before/after file/content/metadata inventory plus missing-root and clock-row oracles |
| source/package pin churn | old tests or protected trust inputs silently drift | recompute named vectors only, current package per producing task, retained273 regression selectors and six static checks |
| multiple mutable activation pointers | mixed CLI/Skill/repository execution after crash | deferred B/C single-reference protocol with real crash/concurrency tests; no A acceptance claim |
| fixture PASS mistaken for native release support | unjustified platform/release statement | fixtures clearly synthetic; all three native cells and supplied exact production artifacts remain mandatory later |

No public install/upgrade format is claimed already stable or implemented. New A
commands are additive; malformed input uses the new bounded diagnostic/error model.
Existing public CLI JSON outputs and task behavior retain their original contracts.
No production performance/latency result or security policy waiver is inferred.

### W10-I7 Verification, rollout and authority

Design uses whitespace, links, Manifest/schema checks, exact allowlist/protected
hashes and independent reviews, with no product tests/build/install execution.
Future A uses the exact Test Plan selectors (new behavioral contracts/integration/
security/wheel checks plus retained273 and six statics), native290/canonical300,
strict serial fail-fast, zero skip/zero-test PASS. Current tree edits invalidate
prior current-tree evidence; the pushed bootstrap evidence remains historical.

Future A rollout is confined to private synthetic source/wheel roots and offline
byte fixtures. No production canary applies. Any integrity/resource/currentness
failure refuses rather than repairs roots or relaxes policy. Unaccepted changes
remain reviewable with rejected evidence retained. B/C, production artifact admission,
Owner install/data, all native acceptance, full274/P1, WP11, commit/push/merge/release/
deploy/external communication require their own applicable authorization.

### W10-I8 References and history

[Positioning](../positioning/graph-engineering-workflow.md), [PRD](../prd/graph-engineering-workflow.md),
[Spec](../specs/graph-engineering-workflow.md), [ADR0015](../adr/0015-release-installation-and-upgrade.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md), [Test Plan](../test-plans/graph-engineering-workflow.md).
2026-10-10 R0: scoped release admission and read-only Doctor impact, later atomic
installation integration retained; no product mutation or acceptance claimed.
R1: include the active performance-benchmark build-backend pin/closure and pyproject
mirrors in the four-bootstrap prospective dependency closure (W10-IMPACT-R0-001).

### W10-A implementation observation

The exact A Envelope is approved; implementation and private source/wheel verification
are in progress. The11 new owned resources and three modules are registered in source
attestation and wheel mappings. Changes to the initializer/backend require the four
active bootstrap vectors and pyproject mirrors to refresh together; the performance
protected set remains38 entries. Historical WP07/WP08 gate captures remain historical.
No dependency, lock, license policy or production trust/source activation is changed.

Cold installed console-script testing found initial `.pyc` creation before package
initialization. This is an observed incompatibility with Spec G5, not a passing Doctor
zero-write result. `wp10-admission-readonly-launcher-design-choice-r0.json` records the
material launcher/acceptance choice for the Owner. No extra launcher/test target or
packaging architecture change is authorized by the current39-file Envelope. Other
bounded admission/Doctor verification may continue; Candidate completion cannot.


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

The only additions to the original39 paths are `tests/unit/test_wp00_packaging.py`
and `scripts/verify_build.py`. The first updates the existing packaging contract for
the declared direct script; the second narrowly verifies its standard wheel location,
executable regular-file mode, RECORD binding and absence of conflicting entry points.
No new launcher source path is added: the already attested backend owns generation.
Metadata consumers that discover this command through console entry points must use
the declared direct-script route; callable/command interfaces remain intact. Existing
installed source ownership, active pin refresh direction and historical pins remain.
All1313 other tracked inputs are protected. Canonical evidence is invalidated by these
source changes; earlier275 regression passes/6 statics are preflight history only.


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

Impact is confined to the existing owned backend, release adapter, regression selectors and affected active pin consumers in exact41. No new source/config/dependency path, database migration, real Owner/installation data or runtime reference repository is introduced. Construction work remains inside existing read/hash/resource ceilings; timeout is failure.


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

## WP-10 isolated staging impact — W10B, 2026-10-12

### W10B-I1 Current authority and baseline

[Spec W10B](../specs/graph-engineering-workflow.md#wp-10-isolated-staging-clarification--w10b-2026-10-12)
refines the existing A/B/C architecture under the retained six-file documentation/
review authority. Spec4 passed independent review and actual frozen reduction; no
node budget was reset. A's accepted313-command tree is committed/pushed at
`2a8ecbbabc069fd2897d1bec53bf29dfe9f44222`. Its evidence remains historical for that
tree. This design does not recertify changed code or authorize implementation.

### W10B-I2 Dependency steps and code ownership

The first concrete future request is **B0 contracts and read-only planning only**.
It can be implemented with private attested synthetic inputs while genuine binaries,
installation authority issuance and native environments remain missing. B0 neither
spawns an installer nor produces staged assets/receipts. Full B still requires actual
stage, physical closure, twice-clean-install equality and all planned native cells.

| Future producer / consumer | Exact prospective responsibility and boundary |
|---|---|
| new core/release_staging.py | closed StageRequest, existing-meaning InstallPlan, recipe/policies/target registry/StageContext/envelope/diagnostic projections; pure unique recipe selection, no paths or process logic in core |
| new application/release_staging.py | factory-owned ReleaseInstaller planning lifetime, fresh A observation and target/context binding; stage/reopen unavailable in B0; no authority issuer or mutation |
| new adapters/release_staging.py | owned12-resource acquisition, actual read-only platform/target/ancestor/absence observations, private context digest; no extraction/process creation/write API |
| existing application/cli.py | install-plan bundle/manifest/request/operation parsing and read-only JSON; unsupported apply cannot issue authority or invoke an installer; A behavior retained |
| initializer / build_backend / pyproject | register exact new source/resources through actual SOURCE/WHEEL ownership, retain A11 and historical resources and strict launcher/parser contract |
| source_checkout_attestation / WP00 inventory | include newly necessary source/resource/test members before package verification, with genuine private fixture attestation |
| four current bootstrap vectors | recompute only changed real protected inputs/closure digests/mirrors in migration/scenario-truth/release-operations/performance; preserve unaffected entries/order and historical vectors |
| test support / five new modules | real private SOURCE/WHEEL origins, independent expected projections and physical refusal/read-only inventories; synthetic trust never enters production |

The future exact inventory is derived in the [Plan](../plans/2026-08-13-graph-engineering-workflow.md).
No migration, action ledger, clock, runtime adapter or locator source is a B0 target.
scripts/verify_build.py is read-only validation of the unchanged strict wrapper, not
a prospective write target; scripts/verify_supply_chain.py's A implementation is retained.
No extra target may be added merely to repair a scope failure after implementation starts.

### W10B-I3 Data, schema and packaging closure

Add proposed StagePolicy, InstallerPolicy and StageTargetRegistry configuration;
production recipes/roots remain empty. Register eight new closed schemas for
stage-request/install-plan/stage-context/stage-plan-envelope/stage-policy/
installer-policy/stage-target-registry/stage-diagnostic plus their distinct registry.
These12 resource members are separate from A's11 release-admission resources.
Do not widen existing A diagnostic/schema1.0.0 enums or reinterpret its policy_digest.

StageContext additionally binds all policy/recipe digests and the registry plus
physically reobserved target binding. InstallPlan.policy_digest remains ReleasePolicy;
its nested deterministic record is not a capability. Root paths/OS identities live in
configuration/private observations, not engine literals or public output. New-install
absence/parent facts require fresh observation; unknown/upgraded prior tuples remain
unavailable until C, not accepted from caller JSON. Planning must not create target,
candidate/control/cache roots, initialize DB/clock facts or touch native Skill state.

Future package updates must register new physical source bytes and their owned resource
map before any source/wheel test. Recompute acyclic pyproject/bootstraps using actual
changed inputs only; preserve source-build projection exclusions and existing wheel
RECORD/strict-launcher rules. Historical dependency1.0/1.1 and WP07a/WP08a pins keep
their historical meaning; no fake refresh of unchanged values. Build and verify current
packages inside producing tasks, then freeze the final tree for exact serial evidence.

### W10B-I4 Compatibility and retained protections

No PRD/Intent, protocol/runtime support matrix, dependency version, DB schema/table,
GraphRef or task action kind changes. Existing A APIs/CLI and strict no-cache launch
acceptance remain. New plan APIs are not published installation/upgrade capability.
No saved bool, plan/envelope JSON, fixture callback or receipt becomes consent.
Owner/runtime issuer integration is a later mutating-B prerequisite, not a task-ledger
shortcut. Local runtime HumanDecisionRequest is task-bound; do not repurpose its
authorize_task or configured human_status as an installation grant.

### W10B-I5 Risks, verification and later prerequisites

| Risk | Evidence / mitigation before future acceptance |
|---|---|
| wrong or ambiguous installer recipe | exact unique match and signed argv-policy projection; independent policy/recipe substitutions after planning refuse |
| environment config masquerades as trust | owned registry and actual no-follow observations; unconfigured roots/foreign ownership/unsupported prior tuple refuse; paths stay private |
| package/source pin cycle or partial registration | verify each producing task's source/wheel closure; final327 proposed commands freeze all inputs before acceptance |
| B0 mistaken for installation completion | zero installer calls/writes; honest unavailable stage/apply/reopen/native/C capabilities; full B obligations retain separate evidence |
| future physical RECORD equality loses data | B1 must verify actual rows first, then normalize both hash and size only for declared templates; distinct prefix-length roots and raw bindings are mandatory |
| repeated evidence overhead | retain actual313 timing observation; no frozen recorder edit or weakened snapshots/parallel product runs; do not rerun product tests during design |

B0 uses source/wheel physical fixtures, not mocks of its own verifier. Future real B
requires supplied exact interpreter/installer/argv, complete artifact/trust/security
closure, measured finite ceilings, supported bootstrap formats and native environments.
These are explicit unmet prerequisites, not reasons to block B0 documentation or its
later separately approved synthetic/read-only implementation. B0 cannot close B-G2/G3/G4.

C remains responsible for installation control contexts, quiescent migration, atomic
active selection, crash recovery and monotone history. PMF-initialized export remains
blocked; there is no DB-copy or omitted-table bypass. WP11, full274/P1, monitoring,
real Owner installations/data and commit/push/merge/deploy/release remain excluded.

### W10B-I6 Rollout and traceability

No production rollout/rollback applies to design or B0's private read-only tests.
Future producing code needs its own exact file/command authority, TDD and independent
implementation/verification/Candidate review. A later commit/push also needs separate
authority; historical approvals do not authorize new delivery actions.

Trace to [PRD](../prd/graph-engineering-workflow.md),
[ADR0015](../adr/0015-release-installation-and-upgrade.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md) and
[Test Plan](../test-plans/graph-engineering-workflow.md).
Current six-file design protects all1348 other tracked files. New source/schema/config/
tests below this boundary are proposed inventory only, not current changes or PASS.

### W10B B0 implementation observation — 2026-10-13

The approved implementation adds three planning modules, eight schemas plus registry,
three intentionally unconfigured production resources and the exact327 verification
inventory. Existing CLI/launcher, source attestation, package mappings, four current
bootstrap mirrors and packaging assertions were updated within the approved forty paths.
All1337 protected tracked files, including dependency, resource/Policy, locator, storage
and clock inputs, remain unchanged. No build/supply-chain verifier was edited.

Focused SOURCE/WHEEL observations cover successful plans, altered resources/target state,
missing prerequisites, fake/PID/thread/operation handles and cold command refusals. Actual
fixture inventories include directories, environment, synthetic task DB/high-water clock,
locator and Skill files; planning leaves them unchanged and execution counters stay zero.
An observed trust-source exception escaping a retained-plan check was normalized to
currentness with sticky invalidation. This is a routine contract repair inside B0.
Final same-tree327 evidence and independent gates are pending at this source freeze.

B0 provider-entry checks additionally bind the original owned-input class methods and
plan-session construction/serialization/close methods before acquisition. Focused
substitution probes observe zero replacement calls; fresh restored acquisition succeeds.
When those trusted providers are unavailable, the existing finite trust-error diagnostic
remains the fallback rather than calling a substituted provider to format a report.
## WP-10 local installation authority impact — W10H, 2026-10-13

### W10H-I1 Scope and approval

The Owner approved the new exact six-file direct local foreground-terminal authority
design in `GEW-WP10-INSTALLATION-AUTHORITY-DESIGN-V1`. [Spec W10H](../specs/graph-engineering-workflow.md#wp-10-local-installation-authority-design--w10h-2026-10-13)
and ADR0015 received independent Spec PASS and actual frozen reducer ADVANCE before
this Impact. Prior Spec4/four-cycle design history and B0's committed/pushed327
evidence remain immutable. No PRD/Intent change, production implementation,
terminal interaction, actual installation or irreversible action occurs here.

The proposed H0 implementation is an authority dependency, not full B1: actual
local terminal producer, owned grant and genuine internal one-use consumer, with
all producing public/library ports still unavailable. No task action is fabricated.

### W10H-I2 Exact future producers and consumers

[wp10-h0-prospective-targets-r0.json](../../.workflow/delivery/GEW-REMAINING54-V1/detached/wp10-h0-prospective-targets-r0.json)
enumerates33 prospective files:17 existing,16 new. This is a future inventory, not
current write authority; the approved design may change only its existing six paths.

| Future surface | Change and downstream effect |
|---|---|
| new core/application/adapters `installation_authority.py` modules | closed policy/challenge/diagnostic; owned grant/permit sequencing; attested terminal OS/I/O/deadlines; no storage, runtime callback or installer |
| existing application `release_staging.py` | explicit authorize_local and sealed same-owner/operation internal consumption; preserve plan behavior and unavailable stage/reopen |
| existing adapter `release_staging.py` | owned current approval-context acquisition from genuine PlanningSession; configured Owner UID and actual requested display roots, rechecked against every configured root and existing physical binding |
| existing core `__init__.py` and test attestation support | include exactly three new module sources and five new resource sources in matching SOURCE_FILES inventories; preserve existing ordered source subsequences and four-command bytecode guard |
| five new owned resources | one approval policy, one closed schema registry and three schemas (policy/challenge/diagnostic); no serializable authority schema |
| existing pyproject | package all five resources through owned-root-files; module roots already package new modules automatically |
| four existing installation-bootstrap mirrors | refresh only actual changed active bytes/digests/closure consumers for package/source inventory; preserve historical embedded vectors and unchanged backend/parser/A semantics |
| existing wp-00 targets + new installation-authority verification boundary | enumerate exact33 paths and future347 commands; no original B0 boundary mutation or Policy change |
| new synthetic fixture, test support and five test modules | private real PTY workers, truthful SOURCE/WHEEL bindings and independently derived response/physical/no-write oracles |
| existing wp00 packaging test | assert exact new five-resource/three-module wheel closure and RECORD membership, retaining A11/B0 twelve-resource assertions |
| six existing design/Manifest paths | describe H0 implementation scope and register only after its separate approval |

New resource paths: `config/release-installation/installation-approval-policy-v1.json`,
`config/contracts/installation-approval-schema-registry-v1.json`, and
`config/contracts/schemas/installation-approval-{policy,challenge,diagnostic}-1.0.0.json`
(the JSON inventory expands each exact path). The latter three schemas are separate
closed domain projections. B0 StageContext/InstallPlan/StagePlanEnvelope and A's
schemas/resource order are not modified or reinterpreted. New owned input acquisition
rechecks both the separate approval resource closure and existing genuine plan context.

### W10H-I3 Compatibility and packaging closure

No CLI syntax or public read-only result changes. install-apply must reject before
prompt; runtime/Skill must not fall back to local terminal approval. H0 adds a library
dependency, not an authenticated runtime capability. No RuntimeInvocationPorts field,
RuntimeSession task authorization, ActionAuthorityLedger kind, task/security event,
DB/schema, migration journal, durable clock or native Skill/locator change is needed.

Owned module composition precedes entry to the bounded authorization operation;
it must not introduce lazy bytecode writes inside the no-write window. Keep actual
cold CLI probes without `-B` as well as library workers: an explicit test flag alone
cannot prove public command behavior. Unsupported terminal primitives refuse only
the new local authority entry, never break existing read-only planning/admission.

`scripts/build_backend.py` is a read-only dependency, not a proposed target: current
owned module-root/resource packaging already supplies the required mechanism. No
backend/provider/parser change is assumed necessary. If implementation needs it or
any other unlisted target, preserve the failure and request that concrete expansion
before editing it. No unrelated pin is refreshed simply because it is historical.

### W10H-I4 Risks, invariants and evidence

| Risk | Mitigation and observable refusal |
|---|---|
| terminal alias mistaken for human identity | configured root UID==real/effective UID; retained descriptor foreground/session facts; explicitly exclude hostile same-UID/root from identity claim |
| task human result silently promoted | distinct installation producer, no task creation/action grant/security write; noninteractive missing host port refuses |
| stale/partial prompt or ambient input accepted | exact safe display digest, nonce grammar, bounded nonblocking I/O, post-wait full revalidation and no automatic retry |
| provider/global or cleanup substitution | original provider/code/global/descriptors checked before calls, zero replacement calls, sticky invalidation and captured cleanup |
| grant replay or failed handoff restores use | same owned operation/plan; monotonic expiration; consume-before-transfer; no refund, reconstruction or copy |
| synthetic PTY mistaken for native installation | actual private terminal operation proves only local producer/consumer; all installer/native/C prerequisites remain separate |
| package inventory/pin propagation omitted | exact33 prospective inventory, SOURCE/WHEEL origin/currentness and old A/B0 vectors plus four actual pin consumers |

Before/after inventories cover private fixture old tool/repository/control/locator/
Skill roots, configured candidates and input/policy bytes. Authorized terminal output
is transient and bounded, not a target write or durable audit. No real Owner data,
secrets or raw terminal transcript enters evidence. Challenge/grant private metadata
is discarded on close/process exit; future actual B/C execution audit is not invented.

### W10H-I5 Verification and stopping boundaries

Prospective tests add20 meaningful methods to the321 retained B0/A/earlier selectors;
341 methods plus six unchanged static commands gives347. Exact argv and expectation
objects are in [wp10-h0-test-inventory-r0.json](../../.workflow/delivery/GEW-REMAINING54-V1/detached/wp10-h0-test-inventory-r0.json).
All321 existing selectors resolve uniquely by AST without import/execution. New
methods are absent until approved implementation. Native290/canonical300, serial
fail-fast, zero skips, same-tree evidence and independent Candidate review remain.

Production interaction limits8192/80/120/30 and small private fixture limits8192/80/15/15
follow Spec W10H; they do not certify installer performance. Actual private PTY
worker cleanup/deadline/foreground tests must pass, never skip as native success.
Current design validation is documentation/Manifest/link/hash/protected-file checks,
not a product test run or package build. Missing concrete port, new auth model,
extra target/dependency, nonconvergence or native blocker returns with exact evidence.
No H0 code/test execution begins before its separate exact implementation approval.

Human-approved H0 fixture-time correction — 2026-10-14: private wait/grant15/15s,
test-worker wall45s replace the original1/1/10s fixture limits only. Actual mandatory
plan revalidation measured1.0773–1.0943s plus0.1095–0.1116s new-input validation.
Preserve original short-wait/expiry negatives in separately attested fixtures, all
currentness/deadline checks, production120/30, byte ceilings, exact33/347, serial
native290/canonical300 and four-cycle history. No implementation/terminal-positive
PASS is inferred; the signed request/approval and independent affected-design review
are retained in detached records. This supplement amends timing data, not scope.

## WP-10 isolated staging execution impact — W10E, 2026-10-16

### W10E-I1 Approved basis and present boundary

The Owner approved the exact six-document staging-design Envelope. Spec revision3
passed independent review with actual ADVANCE; immutable findings001..005 are
resolved, not erased. This Impact follows that accepted W10E contract. H0 is complete,
committed/Receipt-verified/pushed at `c9a158e`; its341 tests/six statics are historical
evidence for that tree, not a pass for future stage code. Only the six design files
may change now;1387 tracked files remain protected. No product execution occurs.

### W10E-I2 Exact prospective implementation surface

The complete proposed inventory is
[wp10-b1-staging-prospective-targets-r2.json](../../.workflow/delivery/GEW-REMAINING54-V1/detached/wp10-b1-staging-prospective-targets-r2.json):
40 unique paths,21 existing and19 new. Its observed hashes are preparation data;
freeze actual inputs after design completion and separate implementation approval.
Earlier38/39 drafts are retained and superseded, not independent write permissions.

| Exact path group | Future change / reason | Protected compatibility |
| --- | --- | --- |
| the six approved design files | Manifest/status/traceability for the eventual implementation task | current design approval never authorizes product files |
| new core/graph_engineering/core/staging_execution.py | six closed records, projections, expected-member mapping, exact normalized bytes and pure timing decisions | no filesystem/process/authentication logic in core |
| new application/graph_engineering/application/staging_execution.py | stage/reopen state machine, private execution provenance and owned read-only result | no new task authority or activation behavior |
| new adapters/graph_engineering/adapters/staging_execution.py | owned execution resources, actual candidate/archives/process/inventory/fsync | no caller runner/writer/clock or arbitrary destination |
| existing adapters/graph_engineering/adapters/release_installation.py | narrowly admit signed StageGeneratedTemplate build inputs through the genuine A path | template-free A output/projections/read-only behavior retained; all other unsupported build input remains refused |
| existing adapters/graph_engineering/adapters/release_staging.py | join owned admitted templates with the selected recipe before returning a plan; expose owned internal stage inputs | unchanged StageContext/envelope fields and projection; no fabricated ReleaseObservation |
| existing application/graph_engineering/application/release_staging.py | compose genuine consume with stage/reopen and owned observations | read-only plan unchanged; only local install becomes stage-capable after implementation approval |
| existing application/graph_engineering/application/cli.py | bounded local install-apply inputs, fresh actual plan equality/local decision and honest stage diagnostic | old check/Doctor/install-plan arguments and cold launcher remain |
| existing application and adapters installation_authority.py | internal captured access to original permit challenge/facts/deadline needed by stage; preserve closure/lifetime tests | no new public grant constructor, clock injection, deadline renewal, runtime issuer or wider Owner trust |
| existing core/graph_engineering/__init__.py and pyproject.toml | three modules/seven owned execution resources/source membership/pins | preserve old SOURCE_FILES ordered subsequence, published resource orders, strict launcher and existing provenance parse memo semantics |
| existing tests/support/source_checkout_attestation.py and tests/unit/test_wp00_packaging.py | genuine fresh SOURCE/WHEEL fixtures and package inventory expectations | no manual seal/RECORD trust bypass, skip or changed source verifier |
| existing config/verification/wp-00-targets.json; new config/verification/wp10-staging-execution-boundary-v1.json | exact owned package and later366-command boundary | frozen workflow and original retained argv stay unchanged |
| four existing migration/scenario-truth/release-operations/performance installation-bootstrap mirrors | refresh only actually affected current source/core/package pins | unchanged historical dependency/evidence bytes; unused mirror remains byte-identical and is explicitly narrowed from actual Manifest |
| five new tests, new tests/support/staging_execution.py, new tests/fixtures/staging-execution-v1.json and tests/fixtures/staging_process_v1.c |19 behavioral selectors, real private physical process/terminal fixtures and independent oracles | synthetic helper is not actual Python/uv/native certification; no real Owner data |

The seven new owned resources are
`config/contracts/staging-execution-schema-registry-v1.json` and schemas under
`config/contracts/schemas/`: installed-release-manifest-1.0.0.json,
installation-binding-1.0.0.json, stage-receipt-1.0.0.json,
stage-generated-template-1.0.0.json, stage-execution-diagnostic-1.0.0.json and
stage-execution-binding-1.0.0.json. Their new registry has exact raw schema hashes;
existing A/B0/H0 registries and projection identities are not widened.

### W10E-I3 Required cross-layer changes

**Template admission is an implementation prerequisite.** Current A refuses all
build-inputs before B0 can plan. The future A adapter must keep its real signed/raw/
provenance/resource validation, then admit only the closed template subset. Retain
its _ReadFile descriptors and exact bytes in real ReleaseObservation currentness.
The new schema/parser/provider dependencies must be captured before calls and on
retained use. B0 then requires recipe/template bijection, including unused-template
refusal, before any terminal prompt. A plan fabricated by a fixture is insufficient.

**Expected installation is derived before mutation.** Accepted purelib wheels and
supported .data/purelib/scripts mappings, unique ownership, declared metadata,
directory closure and canonical installed RECORD references determine the table.
Installer output cannot define its own expected set. Generated bytes must match
the exact signed template; normalized57-byte vector and literal/ref distinction
remain normative. Ordinary bytes cannot be normalized to hide differences.

**Execution provenance is separate from semantics and authority.** Capture the
actual original consumed permit challenge with its plan/operation facts. The private
StageExecutionBinding is written before receipt, self-digested and linked from it.
Four exact metadata records replace W10B's unimplemented three-record proposal.
Reopen needs new genuine authority, preserves original binding bytes and never
reconstructs consent from a hash. Two clean roots retain distinct physical/execution
bindings but equal semantic manifests. No new ledger/database or user identity field.

**Process and durability are execution semantics.** Execution cutoff X, kill K and
final D derive from the original window; no extra timeout field or renewed grant.
Closed argv/env and reserved verified footprints assume the trusted installer,
not a malicious-program OS sandbox/quota. Unconfirmed group liveness means blocked,
not claimed reap. Captured revocation cleanup can signal an owned group after expiry;
filesystem deletion still needs current authority and confirmed ownership/liveness.
Receipt is last, all files/directories are fsynced and final facts are rechecked.

### W10E-I4 API, data and migration compatibility

Published A/B0/H0 schemas, diagnostic bodies, signature/plan projections and old
resource order remain. A now accepts a newly specified supported template subset
only after separate implementation; this behavioral extension is explicit.
Unsupported non-template build inputs retain phase_unavailable; recognizable invalid
templates use the existing appropriate input/trust/closure failures. New execution
diagnostics have their own schema and staged code; no old unavailable capability map
is silently reused for success. CLI only returns stage-only status after real success.

No repository schema, migration/export, active tuple, runtime locator, installed Skill
bootstrap, action authorization, clock-high-water or retention history changes.
Therefore no data migration/rollback procedure is introduced by this design or its
first stage increment. Production recipes and roots stay empty/refused. Unsupported
archive layouts, missing native primitives and genuine release inputs remain blockers.
Adding another future path/dependency/budget/security choice requires a concrete
authority decision; a broad directory group does not grant extra paths.

### W10E-I5 Risks and verification consequences

| Development risk | Likelihood / impact | Concrete control |
| --- | --- | --- |
| unsupported template bridge makes stage success unreachable | observed / high | real A→B0 SOURCE/WHEEL positives; malformed/unused/swapped templates refuse before authority |
| self-consistent installer RECORD hides missing/extra files | medium / high | independent prederived table, cross-distribution and directory collision oracles |
| validation cost spends grant/worker bound | observed H0 cost / high | measure genuine focused stage paths, eliminate only proven redundant work while preserving fresh barriers; never automatically raise limits or cache trust across human wait |
| child timeout leaves unsafe cleanup or false success | medium / high | native TERM-ignoring/output/interrupt cases plus pure unconfirmed-state model; original X/K/D timestamps independently observed |
| receipt/provenance conflated with reusable authority | medium / high | actual consumed challenge equality, preserved origin on fresh reopen, copied/foreign/PID/thread/replayed refusal |
| package/pin drift breaks cold installed entry | medium / high | fresh physical package closure, deterministic build and unchanged cold launcher tests; actual pins only |
| synthetic process mistaken for genuine installer proof | medium / high | explicit helper/native limitations; no production config activation or offline/platform certification claim |

The prospective test inventory contains19 new+341 retained selectors and six
statics,366 commands. Retained347 argv are byte-for-byte preserved as JSON arrays.
Tests use real source/wheel acquisition, private terminal/process/filesystem inputs,
not mocked admission or caller-created grants. No product tests run now. Future
focused evidence is distinct from final same-tree canonical evidence and review.

### W10E-I6 Delivery, recovery and unchanged blockers

Spec→Impact→Plan→Test Plan is the approved reversible design graph, with independent
reviews and frozen reducer. This Impact does not claim later nodes passed. Completion
must yield a precise implementation request; implementation, tests/builds and every
irreversible action remain separately authorized. Changes after evidence invalidate
that evidence and require the appropriate same-tree capture, never relabeling old PASS.

Actual release interpreter/installer/closure/trust and all three native environments
are still missing for genuine acceptance. The private helper can verify orchestration
and refusal without downloading them, but cannot close those later gates. C, PMF-export
restrictions, unattended auth and production operations remain unchanged. Failed roots
retain explicit blocked status; no automatic deletion/retry or old asset migration.

### W10E-I7 References

[Spec W10E](../specs/graph-engineering-workflow.md#wp-10-isolated-staging-execution-design--w10e-2026-10-16),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[Test Plan](../test-plans/graph-engineering-workflow.md),
[ADR0015](../adr/0015-release-installation-and-upgrade.md),
[PRD/Intent](../prd/graph-engineering-workflow.md).
Detached approved request, Spec3 verdict/actual ADVANCE, prospective targets-r2,
test-inventory-r0 and current protected input hashes are the exact supporting inputs.

### W10E private native-window amendment impact

After exact Owner approval, the new private ExecutionFixture uses process total4s
(execution2s, forced-kill3s, original final bound4s capped by original G). The old
private/production configuration, original grant deadline and all other resource
or authority boundaries are unchanged. Nine existing approved paths are affected:
five design documents, the new fixture JSON/support/C and verification boundary.
There is no engine algorithm, schema, dependency, backend or target expansion.

The native delayed-exit and scheduling-pause fixtures become3s and5s to exercise
the same execution-cutoff/overdue semantics. Per-case elapsed time and aggregate
selector timing must be remeasured under original45/290/300 bounds; no passing
claim or higher quota is inferred. Prior failures and source-binding clarification
remain in immutable detached records. The compiler is never overlapped with an
execution worker, and unknown child state still preserves an unaccepted root.

## WP-10 release activation impact — W10C, 2026-10-22

### W10C-I1 Baseline and delivery boundary

Spec6 independently passed after its three Spec5 findings were resolved; the
actual frozen reducer advanced to Impact. Original installation-design task,
its12 historical entries and all new rejected/accepted records remain. The Owner
approved task-only ceiling4→10. Default Policy4 and exact six-file documentation/
review authority are unchanged. B1 at7dd244e remains pushed with366 checks; this
Impact neither reuses that evidence for changed code nor claims C implementation.

W10C's first proposed C0 increment is pure validation of six closed records,
reference/tuple links and finite transition chains. Valid data is still untrusted;
no owned current plan, filesystem observation, grant, terminal, installation or
repository selection is created. Later C1/C2/C3 compose the existing architecture
through independently scoped implementations. Initial registration, recursive
recovery of a recovering operation, uninstall, actual bootstrap lifetime and real
native release acceptance are not claimed by the bounded C0 format.

### W10C-I2 Exact prospective C0 footprint

[Prospective targets-r0](../../.workflow/delivery/GEW-REMAINING54-V1/detached/wp10-activation-design-c0-prospective-targets-r0.json)
contains28 unique exact paths:15 existing and13 new. Its hashes are authoring-time
observations, not final implementation inputs or write authority. Freeze current
bytes after all design nodes pass and the concrete implementation request exists.
Only optional unchanged mirrors may be narrowed with reviewed alignment; an
additional file is an explicit target expansion, not inferred directory access.

| Exact group | Change and reason | Compatibility / exclusion |
| --- | --- | --- |
| the six currently approved design files | Manifest and Spec/ADR/Impact/Plan/Test Plan traceability for later C0 | no implementation authority from current task |
| new core/graph_engineering/core/release_activation.py | six pure shapes/self domains; four W10C-S5 interfaces and acyclic chain rules | existing WorkContext/canonical/digest and migration/stage validators; no storage or authority issuer |
| new config/contracts/release-activation-schema-registry-v1.json | six exact schema IDs/raw hashes, its own registry digest | do not widen existing A/B/H/E registries or schemas |
| new config/contracts/schemas/{activation-intent,release-tuple-manifest,active-release-reference,release-transition-record,release-transition-receipt,activation-diagnostic}-1.0.0.json | exact field/type/null/enum/limit contracts from Spec6 | no invented operational capability; all extra fields rejected |
| core/graph_engineering/__init__.py and pyproject.toml | include new core and seven owned resources through established SOURCE/WHEEL provenance/resource closure | preserve old ordered source subsequence, old resources and cold launcher/backend/dependencies |
| tests/support/source_checkout_attestation.py and tests/unit/test_wp00_packaging.py | genuine attested test source membership and package inventory assertions | never fake a seal/RECORD or bypass provenance |
| config/verification/wp-00-targets.json; new config/verification/wp10-activation-contract-boundary-v1.json | exact new membership and378-command verification boundary | unchanged recorder, six statics and all366 retained command objects/argv |
| four existing installation-bootstrap mirrors named in prospective inventory | refresh only actually affected package/core/current pins | no dependency/evidence rewrite; retain any unused mirror byte-for-byte |
| new tests/unit/test_release_activation.py, tests/contract/test_release_activation.py, tests/security/test_release_activation.py |12 behavioral methods, fixed independent vectors, package and refusal evidence | no new PTY/process/native fixture or real Owner data |
| new tests/fixtures/release-activation-contract-v1.json | handwritten records/edges/known hashes with explicit expected outcomes | test data cannot grant currentness/activation or populate production roots |

The four possible mirrors are config/migration/migration-rehearsal-installation-
bootstrap-v1.json, config/profiles/scenario-truth-installation-bootstrap-v1.json,
config/release-operations/release-operations-installation-bootstrap-v1.json and
config/performance/performance-benchmark-installation-bootstrap-v1.json. Full
literal paths, rather than wrapped prose, are authoritative in the JSON inventory.
No application/adapters/CLI, migration storage, authority module, root registry,
installer policy, uv.lock or build backend is in the proposed product footprint.

### W10C-I3 Contracts, source ownership and data effects

Use one new schema registry with the six exact kind→schema/projection mappings.
Core record validation returns None; relationship checks accept explicit bounded
untrusted linked records, not a physical reader or callback. Reuse the original
stage/leaf self-digest rules and charge cumulative work, including the bounded
non-recover source bundle in recover validation. No recursive recovery nesting.
Duplicate JSON keys are refused by existing bounded readers before core mapping;
C0 does not introduce an alternative parser or a new trusted acquisition path.

The preparation→reference→publication record sequence is acyclic. A reference
binds the already persisted preparation hash; the later publication hashes that
reference. Tests must independently distinguish a missing publication crash prefix
from a completed receipt, and a direct unresolved blocked chain from actual
blocked-reference publication. Pure success must not acquire a handle/grant or
make any C capability available. Counters use existing JCS safe integer bounds.

The new core/source/resources extend package closure and therefore can invalidate
current package pins, even without a runtime CLI change. Retain deterministic
wheel ownership and source membership. Read-only SOURCE/WHEEL/package tests must
use genuine attested fixtures and the unchanged strict launcher. Do not replace
old physical tests with a model just because C0 itself is pure.

No repository data/schema migration, active pointer, journal writer, executable/
Skill bootstrap, lock semantics or authorization implementation changes in C0.
Existing initialized PMF refusal, fences, action audit, claims/holds and legacy
behavior remain. Rollback of uncommitted C0 work is code/evidence repair only;
no user data or live installation rollback is authorized or necessary.

### W10C-I4 Later integration dependencies

| Later boundary | Existing source / required adaptation | Prerequisite before implementation |
| --- | --- | --- |
| C1 inspection and registration | owned B1 stage closure, runtime locator/handshake and actual installation-control identity | exact compatible old/new bootstrap/lifetime protocol, finite physical read policy and no legacy fallback |
| C2 purpose authority and leaf preparation | H0 local OS/Owner UID patterns plus migration export/import/replay/fence seeding | fresh exact C-purpose displays/consumer; current H0 install grant remains unusable; separate leaf preparation from current independent repository publication |
| C3 publication/commands/recovery | existing shared/exclusive installation lock, RestoreGap/action reconciliation and retention | complete fsync/replace/SIGKILL/concurrent dispatch/recovery oracles and explicit compatibility/data-loss refusal |
| genuine B/C/native acceptance | actual CPython/uv/wheels/lock/SBOM/provenance/security/trust and production recipes/roots | all three native cells; no helper or pure contract substitution |

These are dependency observations, not broad implementation targets or approval.
Any new material authentication/architecture choice returns to Owner with concrete
options; routine precision uses the existing approved design graph.

### W10C-I5 Risks and verification effects

| Development risk | Likelihood / impact | Required control |
| --- | --- | --- |
| mutually dependent digest links or fake completed prefixes | observed Spec5 gap / high | immutable known vectors for preparation/reference/publication/receipt and swapped-link negatives |
| permissive operation/state relations | observed Spec5 gap / high | handwritten exhaustive state table, skipped/terminal/wrong-purpose/source-tail rejection |
| syntactically valid data treated as permission/currentness | medium / high | None-only pure API, no-I/O/no-authority sentinels, unchanged CLI capabilities |
| new resource/source closure invalidates unrelated current pins | observed prior increments / high | genuine package membership, retained SOURCE/WHEEL checks and only actual affected mirror updates |
| full verification cost causes repeated unnecessary capture | observed B1 capture / medium | focused12+six first, independent implementation ADVANCE, then one exact378 capture; repeat only for changed inputs/failures/invalid evidence |
| bounded v1 limitations mistaken for complete recovery/native support | medium / high | explicit gates/unsupported paths in diagnostics, tests and final report |

[Prospective inventory](../../.workflow/delivery/GEW-REMAINING54-V1/detached/wp10-activation-design-c0-test-inventory-r0.json)
adds12 to360 retained methods plus six statics:378 total. All366 retained command
objects/argv are unchanged. New selectors are pure contract/package checks; retained
commands still include genuine private build/process/PTY journeys, requiring later
explicit execution approval. No product tests run in this documentation phase.

### W10C-I6 Delivery and retention

Current sequence is Spec6→Impact3→Plan2→TestPlan2 with independent verdicts and
actual frozen decisions, preserving findings/history/budgets. After design COMPLETE,
prepare one exact C0 implementation/test request; neither completion nor the
current budget amendment authorizes product writes/builds/tests. Retain rejected
Spec5, its actual REVISE, Spec6 unchanged independent PASS and the corrected state
metadata plus actual ADVANCE; no changed verdict or rewritten prior state.
No commit/push/deployment/release permission follows. Protect all1406 tracked
files outside the six-file current design boundary.

### W10C-I7 References

[Spec W10C](../specs/graph-engineering-workflow.md#wp-10-release-activation-and-recovery-clarification--w10c-2026-10-22),
[ADR0015](../adr/0015-release-installation-and-upgrade.md),
[Plan](../plans/2026-08-13-graph-engineering-workflow.md),
[Test Plan](../test-plans/graph-engineering-workflow.md),
[PRD/Intent](../prd/graph-engineering-workflow.md).

### W10C C0 implementation scope alignment — 2026-10-22

Owner approval activates the separate C0 implementation Envelope. Actual changed
subset is27 of28: performance-benchmark-installation-bootstrap-v1.json is unchanged
and excluded from the active Manifest. Three other mirrors refresh only current
protected-resource hashes and derived closure/self digests. Frozen schema profile
supports length-bounded token schemas; core retains exact lexical/ref/digest rules.
Old non-mirror resource bodies/order and source subsequence remain protected.
No application/adapter/migration/authorization/CLI target was added.12 intermediate
focused passes are not final378 proof; acceptance uses the new task's own evidence.

## W10C C0 test-observability scope amendment

The current canonical4 W10E-010 flood case failed with trust_rejected; the one
approved diagnostic subsequently passed all ten cases without reproduction.
Root cause remains unknown. Proposed scope adds only
tests/support/staging_execution.py and tests/integration/test_staging_execution.py
to the original28 allowed paths (30 allowed,29 actual changed); update existing
Manifest, boundary, Spec, Impact, Plan and Test Plan accordingly. Native/process
limits, expected failures, production code and runtime authority remain unchanged.
Two test files leave the protected set only after approval; retain the original
1397-file baseline and verify the other1395 byte-for-byte. Budget exception is
C0-task-local4→10; global Policy stays4. Invalidate implementation4 completion
for changed inputs, preserve all seven history entries, and continue at
implementation5 and later verification2 without resetting counters. No commit,
push or real activation authority is requested.
