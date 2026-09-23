# ADR-0009: Offline Release Operations Simulator Authority

## 2026-09-19 RS-BS: same-task bridge and zero-write security reads — R0

Status: Human approved the two prerequisite design changes and the exact two
security source paths in `p3_restart_bridge_security_amendment`. This supplement
is pending independent design review; implementation follows only its PASS.
The earlier P3-RS-A R1 design is accepted by the implementation amendment;
its original proposal wording below is historical. RS-1 binding implementation
has a scoped PASS, not a cold-recovery completion claim.

Decision: retain the existing closed four-field task wrapper and distinguish
domain event ordinals from repository event ordinals in the application layer.
Action state remains authoritative in the existing journal/claim rows. Action
commits on a domain task preserve domain and runner exactly and advance only
the outer repository revision. Legacy action-only snapshots retain their
existing action_state projection. Malformed/extra-field domain wrappers reject;
there is no stripping, conversion, migration or adoption of old malformed rows.

A second, data-only security read path uses the existing doctor connection and
its SQLite read-only enforcement. It does not read or advance trusted time and
cannot issue a TaskSecurityContext, action outcome, gate, lease or purge fence.
The current mutation/security issuance path is unchanged.

Rejected: widening the task wrapper with optional action_state; assigning
repository ordinals to core DomainEvent; adding no-op domain events; calling
the clock-writing reader in recovery; using private SQL from the action layer.
No core state-machine, database schema, event kind or GraphRef change is needed.

The exact rules and tests are Spec RS-BS-1/2 and Test Plan RS-BS. The additional
allowed targets are application/security.py and storage/security.py at their
full package paths in the Human record (181 -> 183). All other restrictions,
including 244/122/30, normal-only recovery and no commit/network, are unchanged.

## 2026-09-19 P3 restart design proposal — R1, not implementation authority

The Human reply `批准 开始吧` approves the previously requested **restart-safe
recovery design review only**. The local foundation commit is
`ff7feda40cc7e8d68c3a2f48dafe58adf0396400`; its accepted implementation
artifact is `sha256:8e3916c256deedc62e315b0962bf384c741b9790650abdb835854cd9600c6490`.
The accepted foundation and one consumed local-commit authorization remain
historical. No implementation, product test, coverage issuance, cumulative or
performance run, monitor, commit, network, WP-10 or external action starts here.

This supplement is a proposed material architecture choice, **P3-RS-A**:
retain a runtime-owned private simulator root and recover an already committed
assessment through a fresh, read-only authority. It does not change approved
product intent or claim the current fail-closed restart is already implemented.
The exact179 Envelope is unchanged. Design records use append-only siblings in
the existing four `docs-*-r1.json` containers, not new workflow paths.

### Problem and choice

The current root belongs to `TemporaryDirectory` and `close()` removes it.
`target_digest` currently covers logical fixture/resource/target IDs, not the
physical root. Deployment outcomes, phase bookkeeping and source issuers are
process-local. `restore_projection()` therefore correctly refuses authority;
`CategoryExecutionApplication.restart()`, which takes an existing application
and reissues its old sources, is not a cold-process recovery proof.

| Choice | Consequence | Recommendation |
|---|---|---|
| P3-RS-A: retained root, repository-bound identity, read-only cold recovery | New lifetime/identity contract; recovers only a completed, committed assessment with all live sources revalidated | Recommend for the next bounded foundation slice |
| P3-RS-B: process-local quiesce/reopen only | No portable recovery; useful for resource release but cannot satisfy the cold-process goal | Keep E1 semantics, do not relabel as restart completion |
| Path/digest-only restore, or automatic apply/restore replay | A copied root or stale projection can manufacture authority; unknown effects may be repeated | Reject |

### Proposed trust and lifetime boundary

The trusted local runtime supplies the repository command scope and a private
retention namespace; neither is obtained from assessment JSON, a caller path,
an environment fallback or a directory scan. Before any action is prepared,
the installed simulator factory creates one exclusive child for a task/target,
writes and fsyncs a closed **release recovery binding**, and derives a new
versioned target digest from that binding. Existing task security binding,
prepared action, journal, claim resource set and eventual assessment must all
bind that exact target digest. A serialized binding is a lookup and validation
input, never a capability. The fresh runtime opens the exact configured parent
and child with no-follow descriptor-relative operations and compares actual
physical identity to the binding and its repository-anchored digest.

This uses the existing trusted repository as an anchor, not a secret embedded in
a fixture and not a second mutable authority database. A coherently re-signed
copied descriptor cannot replace the target digest already committed there.
Compromise or coherent rollback of the entire trusted repository and host
namespace is outside this local simulator trust model; hashes do not defeat an
attacker controlling both. Cross-machine/filesystem copying is deliberately
unsupported. An unavailable identity/locking/fsync primitive fails closed.

Retained mode is opt-in at original creation. Legacy disposable roots, existing
1.0 logical target digests and foundation projections remain validation-only
after loss of their live issuer; no in-place adoption or migration is allowed.
R1's first supported cold-assessment column is exactly `normal`, with ordinary
apply-B and completed partial-compensation-to-A release histories. Other columns
remain unsupported; no twelve-column recovery or coverage is claimed. Spec RS-2
defines control scope -> retained-root gate -> per-call repository locks,
replacing R0's incompatible repository-before-root order without changing
storage. RS-4 adds a new full cold-source validator: the existing normal-column
helper alone is not complete provenance proof.
Retained handle close releases descriptors but not bytes. Explicit owner
finalize/abort destroys only its exact root, first durably removing the binding
under the same exclusive lifecycle lock; interruption leaves an ineligible
orphan, never a re-openable terminal root. Recovery never performs cleanup,
creates a missing directory, fixes metadata or upgrades a schema.

### Proposed recovery sequence and limit

```text
trusted runtime scope + configured retained namespace
  -> current task's unique assessment CAS reference + fresh installed factory
  -> exact retained binding / physical identity / exclusive read-only lease
  -> current journal + original claim + receipt [+ compensation attempt]
  -> fresh artifact bytes + state + health + current generic category sources
  -> final unchanged task/source/action/root observation
  -> new process-local read-only evidence handle (same historical CAS bytes)
```

A fresh process must not receive any old factory/session/outcome/source issuer.
It may reconstruct history only from the current task's already committed
assessment and independently revalidated durable sources. It cannot manufacture
an `ActionOutcome`, arm a mutation gate, call `reconcile`, renew a claim or
restart an interrupted apply/restore. Uncommitted, executing, unknown, partial
without completed compensation, missing-reference and terminal/revoked cases
stay blocked with zero recovery writes. A completed compensated history can be
read only if the original compensated action, its original claim, the unique
recovery attempt and the actual restore journal/receipt all agree, and fresh
state/health prove the exact recorded A state.

Historical phase transitions stay historical: recovery neither recreates
`last_execution`/`original_binding` nor claims to observe past phases again.
Freshness belongs to a new runtime lease/observation epoch; old observer
counters cannot establish freshness across processes. The immutable 1.4 bytes,
digests and one-task-reference rule remain unchanged.

### Decision still required after design review

Accepting P3-RS-A, its retained-root lifetime and cold read-only issuer is a
material architecture decision, not implied by permission to write this design.
Its proposed implementation also needs **exactly two new schema paths** added
to the Envelope, after acceptance, for a versioned closed runtime binding:

- `config/contracts/schemas/release-recovery-binding-1.0.0.json`
- `config/contracts/schemas/release-recovery-binding-input-1.0.0.json`

These files are proposals only and must not be created in this design turn.
The associated installed schema/resource/bootstrap/source pin cascade uses
existing targets; no DB schema, event kind, GraphRef change, dependency, daemon,
new task reference or new evidence schema version is proposed. If implementation
cannot meet the exact boundary, stop and identify the concrete additional need.

Next implementation authority, if granted, should cover only this restart
foundation, RED-first bounded serial tests and independent review, maintaining
244 plan bindings / 122 oracle bindings / 30 missing. It must not include the
24 mandatory bindings, three scenario pairs, cumulative/performance execution,
monitoring, commit/push, network, real deployment/release or WP-10.


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

## Status

Accepted decision，revision 12 remaining54 F1 routine traceability R1 candidate，2026-09-06。Human Owner 已批准 P3：使用 installation-pinned artifact、
本地 filesystem deployment simulator 与无网络 health observer，补齐 `release-operations` 的 exact 24 mandatory
P/R records 和 `artifact-provenance`、`health-gate`、`partial-deploy` 三个 scenario pairs。该批准只允许 disposable
local simulation；它不授权真实 build publication、staging/production、网络/socket health check、WP-10、真实 deploy/
release、DB schema、GraphRef API、新 dependency、commit、push、merge 或外部通信。

本 ADR 的独立 architecture review、schema/bootstrap conformance 与 TDD 是 implementation blocking gate。未关闭前，
release-operations 30 IDs 保持 missing；`local-simulator` evidence 绝不升级为 `production-deployed` 或真实 release proof。

### 2026-09-17 P3 foundation bounded continuation

Human approval `GEW-REMAINING54-P3-FOUNDATION-BOUNDED-V1` enters only the first
P3 foundation sub-batch. Historical exact168 references below describe the F1
lineage; the current source-edit boundary is the existing exact174 Envelope and
this continuation adds no target. The sub-batch is limited to the eight schema
pairs, installed policy/fixture/bootstrap closure, protected local artifact
manifest, private filesystem simulator, filesystem-only health observation,
existing ActionCoordinator integration, assessment 1.4 validation, bounded
serial tests and independent review. The execution plan remains exactly
244 bindings / 122 oracle bindings / 30 missing, and all 30 release IDs remain
missing. Mandatory24, the three scenario pairs, cumulative/performance runs,
monitoring, network, WP-10, commit, push, merge, deploy and release remain
prohibited. Existing `p3-foundation-*-r1.json` records belong to historical F2
and are immutable; persisting this sub-batch's review requires separately
authorized append-only record paths and may not overwrite them.

Foundation hardening binds every mutation to a one-shot opaque capability armed
only after the durable ActionCoordinator start commit. Artifact, deployment and
health bodies are factory-issued typed values; final evidence schemas reference
their exact closed schemas rather than accepting open nested objects. The private
root is descriptor-relative, owner/mode/inode checked, no-follow, and rechecked
after every injected hook. A staged-B/active-A unknown remains manual, never
reconciles as no-effect, and may return to exact A only through the original
claim's single authorized compensation bound to its receipt and current state.
The production factory authority is an opaque process-local seal granted only
after the exact `from_installation()` path validates the protected closure.
Direct construction and `from_documents()` are validation-only seams, and the
category oracle rejects their results even after coherent caller re-signing.

### Remaining54 docs review and authority lineage

| Finding / authority revision | Revision 12 disposition |
|---|---|
| `GEW-REMAINING54-DOCS-ARCH-R1-001` | Historical R1 closure：target boundary当时只增加`pyproject.toml`，使P3 resources由现有只读`scripts/build_backend.py`进入wheel/RECORD/source manifest。 |
| `GEW-REMAINING54-DOCS-TRACE-R2-001` | Historical R2 closure：当时current suite为ADR-0007 r3、ADR-0008 r2、本文ADR-0009 r2、Spec r26、Impact r20、Plan r25、Test Plan r33。 |
| `GEW-REMAINING54-PERFORMANCE-NOISE-AUTHORITY-R3` | Historical R3 authority retained；不改变P3语义，Envelope当时增至159。 |
| `GEW-REMAINING54-ORACLE-REJECTION-INPUT-A` | Historical A不改变P3 simulator语义；Envelope当时exact增至164，新增1.1 oracle input schema、两个generic core sources及dependency/migration current bootstraps。Historical A author R0 suite为ADR-0007 r5、ADR-0008 r4、本文ADR-0009 r4、Spec r28、Impact r22、Plan r27、Test Plan r35。1.0 bytes/history与historical dependency v1.1不变，P3 artifact provenance继续要求current source/package/bootstrap/wheel/RECORD closure保护。 |
| `GEW-REMAINING54-ORACLE-CASCADE-A-R1-001` | **CLOSED / Historical A routine R1**：把当时已在164 Envelope内的`core/graph_engineering/core/profiles.py`与`config/verification/wp-00-targets.json`补入exact affected cascade，关闭schema-domain registry与source-manifest遗漏；不改变P3 simulator语义、A五项target delta或authority。Historical A R1 suite为ADR-0007 r6、ADR-0008 r5、本文ADR-0009 r5、Spec r29、Impact r23、Plan r28、Test Plan r36。 |
| `GEW-REMAINING54-ACTION-PROVENANCE-B` | **Historical Human-approved B**：Envelope从164增至165且只新增`config/actions/action-policy-v1.json`；Historical B尚未把default runtime纳入可变闭包。Historical B suite为ADR-0007 r7、ADR-0008 r6、本文ADR-0009 r6、Spec r30、Impact r24、Plan r29、Test Plan r37。 |
| `GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001` | **CLOSED by C**：default policy重签后的default runtime旧pin会正确fail closed；C加入唯一runtime target，完成双runtime与下游artifact/package closure。 |
| `GEW-REMAINING54-ACTION-RUNTIME-C` | **Historical Human-approved C**：Envelope从165增至166且只新增`config/security/security-runtime-v1.json`；P3仍只消费local simulator authority。Historical C suite为ADR-0007 r8、ADR-0008 r7、本文ADR-0009 r7、Spec r31、Impact r25、Plan r30、Test Plan r38。 |
| `GEW-REMAINING54-WP07A-BUILD-BASELINE-D` | **Historical Human-approved D**：Envelope从166增至167且只新增`tests/security/test_wp07a_action_contract_security.py`，只修复历史stale exact build baseline；P3/真实deploy-release边界不变。删除D项恢复166。Historical D suite为ADR-0007 r9、ADR-0008 r8、本文ADR-0009 r8、Spec r32、Impact r26、Plan r31、Test Plan r39。 |
| `GEW-REMAINING54-PROCESS-LOCAL-QUIESCENT-REOPEN-E1` | **Historical Human-approved E1 R3**：不增加target，Envelope保持exact167；process-local sealed/quiesced/reopened authority释放per-binding live resources，不改变P3 simulator或真实deploy/release禁止。Historical initial E1 suite为ADR-0007 r10、ADR-0008 r9、本文ADR-0009 r9、Spec r33、Impact r27、Plan r32、Test Plan r40；Historical E1 R3 suite为ADR-0007 r11、ADR-0008 r10、本文ADR-0009 r10、Spec r34、Impact r28、Plan r33、Test Plan r41。 |
| `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：E1/current cumulative不得复用pre-E1 per-Profile repository/application stack；226 bindings的repository-root/task/target/branch-ref/action-root/command-root六维各自exact unique且禁止cross-binding/profile substitution。 |
| `GEW-REMAINING54-F1-DEPENDENCY-SECURITY-REHYDRATE` | **Current Human-approved F1**：只新增`application/graph_engineering/application/dependency_security.py`，Envelope exact167→168；generic typed rehydrate/current-seal不改变P3 simulator或真实deploy/release禁止。Independently accepted F1 R0 suite为ADR-0007 r12、ADR-0008 r11、本文ADR-0009 r11、Spec r35、Impact r29、Plan r34、Test Plan r42。 |
| `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：routine F1 source-closure traceability correction保持P3 simulator、artifact rules、exact168 Envelope和全部deny byte-for-byte语义不变；current package/wheel/RECORD验证按真实source/manifest inputs闭合，`authority_effect=none`。Current R1 suite为ADR-0007 r13、ADR-0008 r12、本文ADR-0009 r12、Spec r36、Impact r30、Plan r35、Test Plan r43。 |
| `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002` | **ADDRESSED by author，pending independent reviewer resolution**：generic typed Observation 1.0/1.1 rehydrate correction的`authority_effect=none`；不改变P3 simulator、release evidence、scenario/plan/oracle或任何真实deploy/release禁止。 |

Historical B只修复以下configuration provenance：`pyproject.toml` builtin implementation projection→
`config/contracts/action-adapter-registry-v1.json`→`config/actions/concrete-action-policy-v1.json`→
`config/actions/action-policy-v1.json`与`config/actions/action-policy-local-actions-v1.json`分支→
`config/security/security-runtime-local-actions-v1.json`→既有source/wp-00/current bootstraps/package/wheel/RECORD pins。
Historical B尚缺default runtime。C冻结完整current graph：`pyproject.toml` builtin provenance→
`config/contracts/action-adapter-registry-v1.json`→`config/actions/concrete-action-policy-v1.json`，随后default policy
`config/actions/action-policy-v1.json`→`config/security/security-runtime-v1.json`，local policy
`config/actions/action-policy-local-actions-v1.json`→`config/security/security-runtime-local-actions-v1.json`。两runtime共同
进入source checkout/`config/verification/wp-00-targets.json`、performance/dependency-v1.2/migration/scenario-truth/
release-operations current bootstraps、package pins、只读`scripts/build_backend.py`、wheel archive/unpacked/`RECORD` pins。
该有向图禁止下游digest反馈上游或fixed-point重签；所有ID/digest/raw/size/RECORD必须正反向exact。
`scripts/evidence_utils.py`只读验证default runtime，不在allowlist。P2a packaged-source恢复冻结后依次完成双runtime重签、
consumer currentness与P1 sibling。本修订不改变P3 local simulator语义、不授权真实deployment/release；C exact166，
删除C项恢复165且无第167路径。

D不改变P3或local simulator。已获批P2a sources/pyproject与C action chain current后，factory/WP08/package/wheel均PASS；
扩大security run 17/18唯一失败是历史WP07A测试仍冻结旧
`_action_build_manifest_digest(pyproject.toml)` expected
`b9e8e75bca0436651a723da05d9bcea27f06768666c8c1d9f9fc6b9b80707944`。D只授权在
`tests/security/test_wp07a_action_contract_security.py`换成current approved projection的exact constant；必须保留
dependency/import/build-mapping/entrypoint/registry/provenance substitution attacks，禁止skip/loose/ambient expected。
执行顺序为WP07A named method→WP08 security/evidence/package/wheel/P1 sibling→`p2a-cumulative-r2`。
`GEW-REMAINING54-P2A-CAND-R1-001`、`GEW-REMAINING54-P2A-CAND-R1-002`、
`GEW-REMAINING54-P2A-CAND-R1-003`、`GEW-REMAINING54-P2A-CAND-R1-004`、
`GEW-REMAINING54-P2A-CAND-R1-005`全部保持OPEN，须由独立Candidate reviewer关闭；P2a计数仍226/113/48，
static仍0/274。Historical D当时exact167，删除D项恢复166，且其authority revision未授权第168路径；不扩大真实deploy/release权限。

E1保留每binding唯一fresh private repository root/task/target/branch/ref/action/command roots，只改变process-local handle
lifecycle。触发证据为`p2a-cumulative-r2`第一次4.086s C provenance fail-closed后修复、第二次exact7200s
`TimeoutExpired`无receipt；retained contexts FD4→885/maxRSS7.20GB、teardown FD4；same-root probe
plan0.546s/base7.801s/226 authorities4.904s/observations226.608s/factory1.085ms/issuance114.974s/
dynamic>545.166s、900s timeout，证明resource accumulation+三次currentness passes而非single-binding stuck。

execution/observation后opaque seal绑定current installation/provenance/source/package/wheel/`RECORD`、runtime-attested root
identity（core无absolute-path data）、task/object/target/action/command状态和record/observation digests。quiesce释放repository/
object/action/Git/launcher/session/live FDs且保留root bytes；后续issue/use/precommit/gate由runtime-owned typed port strict-serial
reopen同一root，全量重验后执行，再seal/quiesce。同一时刻最多一个reopen；seal不可serialized/portable/forged/cloned/
shared/replayed，禁止action/mutation replay、currentness skip/cache、cross-binding repository及terminal reopen。

core只定义平台中立状态机/port，runtime/test adapter负责actual reopen；不新增DB/GraphRef/dependency/daemon/WP10或P3
authority。RED证明valid close仍积累resources；226-binding GREEN保持226/113/48/static0与P1 sibling，negative tamper/reopen/
symlink/cross-binding全部zero write/mutation/replay。resource proof用lifecycle/active-handle counters和FD baseline-return，不把
机器RSS/FD阈值硬编码进engine；timeout/heartbeat属于testability config且不可抬高掩盖。D顺序保留、五个Candidate
findings保持OPEN，其中R1-004需E1闭环后由独立reviewer处理。Historical E1当时Envelope为exact167且未授权第168路径；
Current F1只增加dependency-security application source形成exact168，不改变本ADR的P3边界。

## Context

冻结 Support Matrix 已含 release-operations 24 mandatory IDs 和三个 scenario pairs，但 current execution plan 未签发
其中任何一个。P1+P2 完成后的 exact state 为 plan244 / oracle122 / dynamic gate 244 valid, 30 missing, false。

现有 generic Profile machinery 可表达十二列，但 release truth 还需要证明：artifact bytes 的来源闭包、被部署 artifact
与观察 target 的同一性、health gate、partial deployment 的 query/reconcile/rollback，以及 restart 不重放 deploy。
真实 environment 被本轮排除，所以只能对已标记的 local simulator target 作这些断言。

## Decision Drivers

1. artifact provenance 必须从 current installed bytes 与 source/build/package attestations派生；
2. deploy/rollback/query 必须经过现有 action-scoped prepare→authorize→execute→reconcile 协议；
3. health truth 必须读取 local simulator state，不允许网络、自报 PASS 或 caller truth；
4. partial deploy 必须保留可查询中间状态并确定性恢复，不能跳成成功；
5. mandatory/scenario evidence 都要 task-bound、CAS referenced、restart zero replay；
6. 不启用 WP-10、真实 release 或新的 durable repository schema。

## Decision

采用 **protected local artifact manifest + action-protocol filesystem simulator + local health observer + release-specific
task assessment projection**。

### 1. Closed policy, fixture and installation closure

新增 `urn:gew:release-operations-policy-registry:v1`，root exact fields/order 为：

`schema_version, registry_id, artifact_policy, health_policy, deployment_policy, rollback_policy, scenarios,
registry_digest`。

policy 固定 artifact required provenance fields、allowed local operation IDs、ordered deployment phases、health predicates、
partial-deploy fault points、rollback preconditions、integer budgets、owner routes与 exact three-scenario set。所有路径、phase、
health值、budgets、timeouts 和 thresholds 均为 config data；core 不硬编码。任何 missing/extra/reorder/duplicate/alias、
unknown operation/fault、empty owner route或 same ID/body replacement均拒绝。

新增 `urn:gew:release-simulator-fixture-registry:v1`。fixtures 仅描述 private temp root 中的 immutable A manifest、candidate
B artifact identity、stage/active slots、health state vectors、fault schedule与 expected rollback A；不包含用户项目、凭据、
真实 URL/port或外部环境。P/R/task 各自得到 fresh root，mutable slots 永不共享。

`urn:gew:release-operations-installation-bootstrap:1.0.0` exact pin policy/fixture registries、下述 8 schema pairs、Profile
schema registry、approved Profile/coverage/semantic policies、Support Matrix、execution plan、action/adapter/connector registries、
installed distribution/version/RECORD、source/build/package attestation、artifact protected closure与 ordered protected member
digest。只从 installed resource byte pipe 加载；ambient checkout、caller path/digest、external artifact、index或 network
fallback全部禁止。

### 2. Exact schemas and assessment 1.4

Profile schema registry增加以下 8 组 source/digest-input pairs：

| Contract | Source schema | Digest-input schema |
|---|---|---|
| release policy registry | `urn:gew:schema:release-operations-policy-registry:1.0.0` | `urn:gew:schema:release-operations-policy-registry-input:1.0.0` |
| simulator fixture registry | `urn:gew:schema:release-simulator-fixture-registry:1.0.0` | `urn:gew:schema:release-simulator-fixture-registry-input:1.0.0` |
| artifact manifest | `urn:gew:schema:release-artifact-manifest:1.0.0` | `urn:gew:schema:release-artifact-manifest-input:1.0.0` |
| health observation | `urn:gew:schema:release-health-observation:1.0.0` | `urn:gew:schema:release-health-observation-input:1.0.0` |
| deployment observation | `urn:gew:schema:release-deployment-observation:1.0.0` | `urn:gew:schema:release-deployment-observation-input:1.0.0` |
| final release observation | `urn:gew:schema:release-operations-observation:1.0.0` | `urn:gew:schema:release-operations-observation-input:1.0.0` |
| installation bootstrap | `urn:gew:schema:release-operations-installation-bootstrap:1.0.0` | `urn:gew:schema:release-operations-installation-bootstrap-input:1.0.0` |
| category assessment 1.4 | `urn:gew:schema:category-completion-assessment:1.4.0` | `urn:gew:schema:category-completion-assessment-input:1.4.0` |

每个 digest-input 只排除自身 derived digest。1.4 是 release-only closed union：仅 `profile_id=release-operations` 的
mandatory/scenario tasks 可携带唯一 `release_operations_projection`；不得携带1.1/1.2/1.3任何其它 projection。
assessment 1.0～1.3 bytes与语义保持冻结。不存在把 release projection回填到generic 1.0的兼容捷径。

`release_artifact_manifest` exact绑定 artifact ID/version/raw SHA-256/size、installed wheel/distribution/RECORD、source
manifest、build attestation、logical member closure与 provenance digest。artifact bytes必须来自 bootstrap 保护的当前
installation；名称/版本相同但 bytes、RECORD、source或build不同均拒绝。

`release_health_observation` exact绑定 task/target/generation、policy、active artifact、local state raw digest、ordered
predicate results、observed outcome与 digest。observer只读 private filesystem state；不得调用 DNS/socket/proxy、HTTP、
subprocess或 caller health callback。

`release_deployment_observation` exact绑定 action ID/claim/journal/receipt、expected/current generation、artifact、ordered
stage transitions、fault/reconcile state、before/after target与 digest。`release_operations_observation` 包含完整 artifact/
deployment/health/rollback/current target bodies与digests、GraphRef six pins、task revision/snapshot/epoch、installation pins、
factory seal、owner route、scenario/column outcome及 final digest。

### 3. Local simulator action boundary

新增 platform adapter `local-release-simulator-v1`，只允许三个 config-bound operation IDs：

- `local-release-simulator.apply`：在 private root 中写 staged slot，经 fsync/rename/CAS generation切换 active pointer；
- `local-release-simulator.query`：只读返回 exact stage/active/generation/artifact/health state；
- `local-release-simulator.restore`：仅对原 action 的 exact claim/receipt/expected current generation恢复 A。

adapter locator 必须由 factory 创建并验证位于 test-owned private root；绝不接受用户路径、symlink escape、absolute caller
target或 environment expansion。每个 action 仍走 existing `ActionCoordinator`、resource claims/fences、prepared authority、
journal、receipt与 reconcile；caller不能直调 mutation。query 可重试；apply/restore 不因 unknown自动重放。

当前 foundation 的 target-visible gate 只有 one-shot consume 面；durable-start
后的 arming/binding保存在 coordinator-owned registry。artifact issuer 只接受
installed fixture/artifact ID，实际 bytes/version/distribution fields来自raw-pinned
fixture registry，不接受caller bytes，也不把独立package pins伪装成这些fixture
bytes的wheel provenance。ActionOutcome必须由同一coordinator签发并重新绑定current
journal/claim/receipt，health expectation只能从typed terminal observation派生。

fault schedule exact覆盖 `before-stage-write`, `after-stage-durable`, `before-active-switch`, `after-active-switch-durable`,
`before-health-observe`。每个 cut 的 query只接受完整 A、durable staged-B+active-A 或 active-B；mixed bytes、pointer/manifest
不一致、generation rollback与unowned residue fail closed。unknown effect保留原 claim并 route owner；只有 query证明效果后
才能 reconcile。rollback 仅在 fresh current state匹配 receipt后执行，最终 health+artifact必须exact恢复A。

### 4. Mandatory and scenario truth

24 mandatory bindings继续使用冻结十二列语义，但每个 P/R 的 task-local release projection必须同时绑定 current artifact、
simulator target和适用 release facts：

- `normal/boundary/revise/authority/drift/invalidation/artifacts/review/target` 使用既有 typed column contract，并附加 release
  policy/artifact/target currentness；
- `recovery/rollback` 必须消费 same-action claim/receipt、query/reconcile与 exact restored-A health；
- `real-e2e` 必须真实调用一次 **local simulator** apply/query/health（P mutation delta=1），R 在 wrong expected generation/
  stale artifact下于 apply前拒绝（delta=0）；其 evidence kind明确为 `authoritative-local-release-simulator`，不是 production；
- 所有 P/R 保持 unique task/request/execution/observation/record，不共享 mutable root、action authority或target。

三个 scenario meanings exact 为：

| Scenario | P meaning | R meaning |
|---|---|---|
| `artifact-provenance` | B artifact manifest与 current installed wheel/RECORD/source/build/protected closure逐字节闭合，deployed active artifact exact等于该manifest | name/version label、caller digest、wrong RECORD/source/build、missing/extra/reordered member、same-path/coherent re-sign被拒绝且零mutation |
| `health-gate` | apply B 后由 local observer读取active-B state，全部 config-owned health predicates通过，fresh reobserve仍current后才允许scenario record | 自报PASS、stale/pre-switch health、只比较部分predicate、wrong artifact/generation或任一fail被拒绝；不得标记healthy/released |
| `partial-deploy` | 注入config fault得到可查询partial state；不得宣告release成功。系统对exact claim query/reconcile，执行authorized restore并证明active-A artifact与health恢复，外层P仅表示partial-deploy处理正确 | 跳过query、重放apply、把staged-B当active、wrong claim/generation、无rollback authority、部分恢复或把partial当成功被拒绝 |

### 5. Currentness, restart and lifecycle

issue/use/precommit/restart/coverage每次重读 task/current GraphRef、policy/fixture/bootstrap/schema/action registries、artifact/
RECORD/source/build bytes、journal/claim/receipt、simulator generation/pointer/slots/health与 nested digests。precommit在所有
hooks后 final query+health reobserve，消费token后无 target-sensitive callback。

Foundation尚未拥有可持久化且可重新打开的private-root authority；因此stored
release projection在restart时即使schema/digest/install pins成立也必须fail closed。
只有未来单独授权的设计能重开并fresh读取target/journal/claim/receipt/artifact/health
后，才可满足下述portable restart目标；当前244/122/30状态不声称该目标已完成。

assessment仍只提交既有 `task.category_assessed` 与一个 task-unique referenced CAS。restart从 current task唯一 ref重读
1.4 bytes并以 fresh installation/factory重验；apply/restore replay count exact为0，仅query/health只读重验。missing/duplicate
ref、CAS replacement、foreign/clone/stale factory/action/observer、post-observation artifact/target/policy replacement均拒绝，
且 task/event/snapshot/object/ref/action/target/input零写；DNS/socket/proxy count exact 0。

release records与前244 records共用现有 CoverageRecordFactory lifecycle。P3先加入24 mandatory records与12 oracle members，
达到 plan268/oracle134/gate `268 valid / 6 missing / false`；再加入6 scenario records与3 oracle members，最终 exact：

- production plan bindings `274`，unique task IDs `274`；
- independent oracle bindings `137`；
- dynamic combined gate `274 valid / 0 missing / passed=true`，invalid/stale/duplicate均为空；
- static-only substitute仍 `0 valid / 274 missing / passed=false`，即 static acceptance count exact为0；
- exact combined decision后才允许 finalize/revoke；abort/finalized terminal语义与 <120s teardown不变。

任何子批失败则该批 IDs 全部保持 missing，已通过的244或268 records保持immutable/current；禁止 partial/sharded gate、
waiver、修改Support Matrix或从真实环境补证。

## Alternatives Considered

| Alternative | Disposition | Reason |
|---|---|---|
| action-protocol local filesystem simulator | Adopted | 能证明artifact/action/health/rollback闭包而不触及真实环境 |
| 真实 staging/production | Rejected for this authority | 需要新的network、target、credential、deploy/release authority |
| fixture label或静态 manifest 直接 PASS | Rejected | 不能证明 action/current target/health/partial recovery |
| socket/HTTP localhost health | Rejected | 本批准要求无网络；filesystem observer足够表达本地模拟状态 |
| 启用 WP-10 install/upgrade/release | Rejected | P3只闭合WP-08 coverage，不扩大产品交付阶段 |

## Consequences

### Positive

- release-operations 24 mandatory 与3 scenario pairs拥有实际 local action、artifact、health、rollback证据；
- action unknown/partial state继承既有claim/fence/reconcile安全语义；
- final 274/137 dynamic gate可以零missing完成，同时明确不是生产release；
- config-owned policy与private roots保持data-logic separation及用户数据隔离。

### Costs and limitations

- local simulator只能证明协议和状态机，不能证明特定云、集群或真实服务可发布；
- 新增8组schema pairs、adapter/config/bootstrap和严格fault/currentness矩阵；
- full 274-record strict-serial candidate验证成本较高，不能用并发mutable target或static shortcut降低。

## Rollback

若实现或review不收敛，停止注册release factories/adapter，移除尚未采用的1.4/config/schema/code/tests，保留既有 plan244、
assessment1.0～1.3、action/repository/GraphRef semantics与所有通过records。不得回退为真实deploy、网络health、WP-10、
caller PASS或partial deployment成功。

## Mandatory24 implementation refinement — 2026-09-21

The approved mandatory24 amendment implements sections 4–5 in a bounded batch.
The current RS-C retained-source implementation already supports cold normal
assessment reads; the earlier foundation-only restart paragraph is historical.
The new batch extends that captured-source mechanism to the other eleven
mandatory columns under the same owner lifetime, limits and two-capture rule.
It issues 24 mandatory bindings / twelve oracles only; the six scenario bindings
and any cumulative gate execution remain outside this authorization.

The [Spec mandatory24 amendment](../specs/graph-engineering-workflow.md#p3-mandatory24-bounded-contract--2026-09-21)
defines exact per-column joins, private adoption of completed release rollback,
and a factory-sealed local real-execution authority. These are implementation
refinements of the adopted simulator/action-protocol boundary, with no new public
contract, database, event, GraphRef, dependency or runtime adapter. Completed
restore adoption verifies the existing action; it cannot execute a second restore.
The Git real-E2E authority remains exclusive to its existing profiles.

Artifact provenance distinguishes installed fixture bytes from distribution and
package-resource provenance. Cold historical handles carry no mutation or live
evidence authority. Configuration 268/134 is not a dynamic acceptance claim.
### Scenario6 bounded clarification — 2026-09-22

The approved scenario6 amendment completes the three already-installed scenario
identities through the existing simulator, opaque release evidence and
assessment1.4. Artifact provenance refers to installed fixture bytes; package
and wheel closure stays separate. Health success requires active B and all
installed predicates. Partial-deploy P denotes query/reconciliation and an
independently authorized restore to A followed by fresh health, never deployment
success. Its rejection/read paths add zero mutations; prior partial/restore
mutations remain visible rather than being labelled zero.

No new public API or durable schema is selected. The private coverage reader may
admit the exact three scenario selectors after binding their installed IDs and
typed source closure. P recovery reconstructs assessment1.4 in a fresh process;
R retains its opaque issued rejection record while reopening every source port.
Configured274/137 is not cumulative acceptance. Existing local-only authority,
resource limits, source currentness and separate irreversible gates are unchanged.
