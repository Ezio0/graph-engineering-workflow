# ADR-0008: Local Profile Scenario Truth Authority

## Status

Accepted decision，revision 12 remaining54 F1 routine traceability R1 candidate，2026-09-06。Human Owner 已批准 P2：在完全本地、离线、
disposable target 范围内，为 `new-feature`、`hotfix`、`refactor-debt` 与 `incident-response` 的十个尚缺
scenario pairs 建立 config-owned、installation-pinned、factory-issued truth authority。该批准不改变 Positioning
或 PRD Intent Baseline，不授权真实 staging/production、网络、WP-10、数据库 schema、GraphRef API、新 dependency、
commit、push、merge、deploy、release 或外部通信。

实现以本 ADR、Spec、Impact、Plan 与 Test Plan 的独立 architecture review PASS 为 blocking gate。gate 未关闭时，
20 个 P/R stable IDs 保持 missing；任何 fixture label、caller assertion、静态 `PASS`、另一个 Profile 的证据或
未经 currentness 重验的历史 observation 都不能补位。

### Remaining54 docs review and authority lineage

| Finding / authority revision | Revision 12 disposition |
|---|---|
| `GEW-REMAINING54-DOCS-ARCH-R1-001` | Historical R1 closure：Envelope由156增至157 targets，唯一新增`pyproject.toml`；P2 resources必须经现有只读`scripts/build_backend.py`进入wheel/RECORD/source manifest。 |
| `GEW-REMAINING54-DOCS-TRACE-R2-001` | Historical R2 closure：当时current suite为ADR-0007 r3、本文ADR-0008 r2、ADR-0009 r2、Spec r26、Impact r20、Plan r25、Test Plan r33。 |
| `GEW-REMAINING54-PERFORMANCE-NOISE-AUTHORITY-R3` | Historical R3 authority retained；不改变P2语义，Envelope当时增至159。 |
| `GEW-REMAINING54-ORACLE-REJECTION-INPUT-A` | Historical A不改变P2 truth语义；Envelope当时exact增至164，新增1.1 oracle input schema、两个generic core sources及dependency/migration current bootstraps。Historical A author R0 suite为ADR-0007 r5、本文ADR-0008 r4、ADR-0009 r4、Spec r28、Impact r22、Plan r27、Test Plan r35。1.0 bytes/history与historical dependency v1.1不变，P2继续受current source/package/bootstrap/wheel/RECORD closure保护。 |
| `GEW-REMAINING54-ORACLE-CASCADE-A-R1-001` | **CLOSED / Historical A routine R1**：把当时已在164 Envelope内的`core/graph_engineering/core/profiles.py`与`config/verification/wp-00-targets.json`补入exact affected cascade，关闭schema-domain registry与source-manifest遗漏；不改变P2 truth语义、A五项target delta或authority。Historical A R1 suite为ADR-0007 r6、本文ADR-0008 r5、ADR-0009 r5、Spec r29、Impact r23、Plan r28、Test Plan r36。 |
| `GEW-REMAINING54-ACTION-PROVENANCE-B` | **Historical Human-approved B**：Envelope从164增至165且只新增`config/actions/action-policy-v1.json`。P2 packaged sources改变builtin provenance，B冻结两份policy重签但尚未授权default runtime consumer。Historical B suite为ADR-0007 r7、本文ADR-0008 r6、ADR-0009 r6、Spec r30、Impact r24、Plan r29、Test Plan r37。 |
| `GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001` | **CLOSED by C**：default policy重签会使未同步default runtime pin正确fail closed；C新增唯一runtime target并完成default/local双runtime branches、`evidence_utils` currentness与P1 sibling恢复顺序。 |
| `GEW-REMAINING54-ACTION-RUNTIME-C` | **Historical Human-approved C**：Envelope从165增至166且只新增`config/security/security-runtime-v1.json`；P2a恢复先双runtime重签、验证read-only consumer与P1 sibling。Historical C suite为ADR-0007 r8、本文ADR-0008 r7、ADR-0009 r7、Spec r31、Impact r25、Plan r30、Test Plan r38。 |
| `GEW-REMAINING54-WP07A-BUILD-BASELINE-D` | **Historical Human-approved D**：Envelope从166增至167且只新增`tests/security/test_wp07a_action_contract_security.py`；只可修正stale exact WP07A build-projection baseline，保留全部attack assertions。删除D项恢复166。Historical D suite为ADR-0007 r9、本文ADR-0008 r8、ADR-0009 r8、Spec r32、Impact r26、Plan r31、Test Plan r39。 |
| `GEW-REMAINING54-PROCESS-LOCAL-QUIESCENT-REOPEN-E1` | **Historical Human-approved E1 R3**：Envelope保持exact167；每binding保留fresh private root，以process-local opaque sealed→quiesced→reopened authority释放live resources并逐phase全量currentness。Historical initial E1 suite为ADR-0007 r10、本文ADR-0008 r9、ADR-0009 r9、Spec r33、Impact r27、Plan r32、Test Plan r40；Historical E1 R3 suite为ADR-0007 r11、本文ADR-0008 r10、ADR-0009 r10、Spec r34、Impact r28、Plan r33、Test Plan r41。 |
| `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：pre-E1 per-Profile shared repository/application仅是Historical，不适用于E1/current cumulative；E1对226 bindings机械断言repository-root/task/target/branch-ref/action-root/command-root各自exact unique、跨binding/profile不共享。 |
| `GEW-REMAINING54-F1-DEPENDENCY-SECURITY-REHYDRATE` | **Current Human-approved F1**：只新增`application/graph_engineering/application/dependency_security.py`，Envelope exact167→168；允许generic typed `DependencySecurityObservationFactory` rehydrate/current-seal API，不改变E1 isolation/lifecycle或P2/P3 truth。Independently accepted F1 R0 suite为ADR-0007 r12、本文ADR-0008 r11、ADR-0009 r11、Spec r35、Impact r29、Plan r34、Test Plan r42。 |
| `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：F1 R0把new application source误写为dependency bootstrap1.2 protected member。本R1按实现事实修正source-attestation/package closure及各真实projection currentness；`authority_effect=none`，authority/API/target count均不变。Current R1 suite为ADR-0007 r13、本文ADR-0008 r12、ADR-0009 r12、Spec r36、Impact r30、Plan r35、Test Plan r43。 |
| `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002` | **ADDRESSED by author，pending independent reviewer resolution**：Human F1只授权generic typed Observation rehydrate，没有schema1.0-only或GraphAssessment-only route。R1支持既有exact Observation 1.0/1.1，并保持GraphAssessment为独立downstream consumer；`authority_effect=none`。 |

Historical B记录：P2a增加的packaged sources会改变`pyproject.toml` builtin implementation build projection及adapter
implementation digests；旧default policy pin导致P1 verified child fail closed是预期currentness保护。B恢复链只写到
`pyproject.toml` provenance→`config/contracts/action-adapter-registry-v1.json`→
`config/actions/concrete-action-policy-v1.json`→`config/actions/action-policy-v1.json`与
`config/actions/action-policy-local-actions-v1.json`分支→`config/security/security-runtime-local-actions-v1.json`→已授权
source/wp-00/bootstrap/package/wheel/RECORD closure单向重签；不得绕开installation pins、制造digest环或修改action能力。

C关闭default runtime遗漏并冻结完整current graph：`pyproject.toml` builtin provenance→
`config/contracts/action-adapter-registry-v1.json`→`config/actions/concrete-action-policy-v1.json`，随后default policy
`config/actions/action-policy-v1.json`→`config/security/security-runtime-v1.json`，local policy
`config/actions/action-policy-local-actions-v1.json`→`config/security/security-runtime-local-actions-v1.json`。两runtime再共同
进入source checkout/`config/verification/wp-00-targets.json`、performance/dependency-v1.2/migration/scenario-truth/
release-operations current bootstraps、package pins、只读`scripts/build_backend.py`、wheel archive/unpacked/`RECORD`闭包。
`scripts/evidence_utils.py`只读消费default runtime，必须测试currentness但不在allowlist、不得修改。
P2a packaged-source恢复并冻结后先完成双runtime拓扑重签与反向验证，再运行`evidence_utils` currentness和P1 sibling；
全部通过后才继续P2a scenario issuance。C exact166，删除C项恢复165，无第167 path。

D不改变P2 truth/action语义。已获批P2a sources/pyproject与C链current后，factory/WP08/package/wheel均PASS；扩大
security run 17/18唯一失败是历史WP07A测试仍期待旧`_action_build_manifest_digest(pyproject.toml)`常量
`b9e8e75bca0436651a723da05d9bcea27f06768666c8c1d9f9fc6b9b80707944`。D仅授权在
`tests/security/test_wp07a_action_contract_security.py`替换该exact baseline；dependency/import/build-mapping/
entrypoint/registry/provenance substitution attacks必须保持，禁止skip、loose/prefix或ambient/runtime-derived expected。
随后按WP07A named method→WP08 security/evidence/package/wheel/P1 sibling→`p2a-cumulative-r2`执行。
`GEW-REMAINING54-P2A-CAND-R1-001`、`GEW-REMAINING54-P2A-CAND-R1-002`、
`GEW-REMAINING54-P2A-CAND-R1-003`、`GEW-REMAINING54-P2A-CAND-R1-004`、
`GEW-REMAINING54-P2A-CAND-R1-005`均保持OPEN等待独立Candidate reviewer；focused GREEN不构成closure。
P2a仍为226/113/48且static 0/274。Historical D当时exact167，删除D项恢复166，且其authority revision无第168路径。

E1处理的不是单一binding语义缺陷，而是同进程保留226套live contexts造成的资源生命周期问题。两次
`p2a-cumulative-r2`分别在4.086s因C provenance正确fail closed（后已修复），以及exact7200s
`TimeoutExpired`且无receipt。representative retained contexts为FD4→885、maxRSS7.20GB，teardown回FD4；same-root
probe为plan0.546s/base7.801s/226 authorities4.904s/observations226.608s/factory1.085ms/issuance114.974s/
dynamic>545.166s并在900s timeout。这证明live accumulation叠加plan/base/issuance三次currentness passes，而非单binding
stuck，禁止以抬高timeout代替修复。

每binding继续拥有唯一fresh private repository root、task、target、branch/ref、action/command roots。process-local opaque
authority状态机为`open→sealed→quiesced→reopened→sealed→quiesced`，finalize/revoke后进入不可逆
`permanently-closed`。execution/observation完成后seal绑定current installation/provenance/source/package/wheel/`RECORD`、
runtime-attested root identity（平台中立core不得出现机器absolute path）、task/object/target/action/command状态及record/
observation digests。quiesce关闭并释放repository/object/action/Git/launcher/session handles和全部live FDs，但不得删除或
重建该binding private-root bytes。

issue/use/precommit/gate各phase只能由runtime-owned typed reopen port在单binding strict serial下重开同一root，先从bytes与
handles全量重读并exact比较seal closure、root identity和当前状态，成功后才允许验证；phase完成产生下一generation seal、
使旧seal失效并再次quiesce。同一时刻最多一个reopened binding。seal/capability不可序列化、portable、caller构造、clone、
share或replay；禁止action/mutation replay、currentness cache/skip、cross-binding/profile repository共享、wrong/double/
concurrent/out-of-order reopen及terminal reopen。跨进程恢复不得反序列化seal，只能沿existing factory currentness建立新
process-local authority且不能重执行已完成action。

core只定义平台中立lifecycle与typed port；actual filesystem/repository/object/action/Git/launcher/session reopen/close由
runtime/test adapter实现。不新增DB schema/table、dependency、daemon、GraphRef lifecycle或WP10。RED先用valid current
API证明close后stale/226 contexts资源累积；GREEN在226 exact bindings上execute→seal/quiesce→lazy reopen
issue/use/precommit/gate并逐次requiesce，保持dynamic226/48/false、static0/274/false、113 oracle unique/current与P1 sibling
current。negative覆盖所有closure/state same-path/coherent tamper、wrong root/ref、missing/extra、forged/cloned/serialized
seal、reopen order/concurrency/replay/terminal/symlink/cross-binding，全部write/mutation/replay=0。资源断言使用deterministic
lifecycle/active-handle counters与FD baseline-return诊断；engine不含机器RSS/FD阈值，runtime/heartbeat来自testability
config且不可调高掩盖失败。D序列不变，五个Candidate IDs仍OPEN，R1-004新增E1闭环后再交独立reviewer。

### Current F1 dependency-security rehydrate/current-seal authority

F1仅把`application/graph_engineering/application/dependency_security.py`加入allowed targets，使Historical D/E1的
exact167变为current exact168；删除这一项精确恢复167，不存在第169项。`DependencySecurityObservationFactory`
可以提供generic typed rehydrate/current-seal API，但factory与`DependencySecurityObservation`必须是不同类型与身份：
factory只从同一binding current issued observation机械提取descriptor/immutable snapshot并按其existing exact schema
（1.0.0或1.1.0）重水化typed observation，签发product/runtime-owner控制的opaque process-local current seal；quiesced state
不持有live repository/category。
下游graph/category assessment仍是独立consumer，不能作为factory输入、seal替代物或authority issuer。

rehydrate必须exact绑定同一fresh private repository root、task revision/snapshot/epoch、`dependency-security` category及
current installed closure。`issue`、`use`、`precommit`、`gate`四个phase每次都从installation bytes全量重读
`config/security/dependency-advisory-installation-bootstrap-v1.2.json`、new application source、source/package/
wheel/`RECORD`、task/category/root state；顺序为fresh registry→physical closure parser reread→applicability/residual→
generic observe exact compare。resolver/network执行exact0不等于physical parser reread为0。mandatory、scenario与
dependency-security real-E2E继续使用原有candidate、scenario和oracle选择；只要其current issued source是
`DependencySecurityObservationFactory`/`DependencySecurityObservation`，rehydrate就按exact 1.0或1.1 schema执行。
1.1 selector只能从issued frozen graph inputs机械提取，随后从fresh current installation重建graph policy/remediation、before/after
graph及disposition并全量exact比较。`DependencyGraphAssessmentFactory`/Evidence仍是独立downstream consumer，不能代替
ObservationFactory、Observation、seal或issuer。不得cache、跳过或只验证digest label。P与R都必须保留各自
typed observation/oracle identity，P↔R substitution、caller mapping、forged/cloned/serialized/stale seal、cross-root/
task/category/installation、same-path replacement及finalize/revoke后调用全部fail closed，且zero task/action/target write、
zero mutation、zero resolver/network、zero action/command replay。

现有`_task_projection`的profile/category/task revision/snapshot/invalidation discriminator不得放宽；原mandatory/real-E2E
candidates保持不变，`GEW-PRO-DEPENDENCY-SECURITY-ARTIFACTS-R`继续选择
`GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P`，其R
`request_digest=sha256-jcs-v1:e9315eb7ced2072939c95533b7f8aeb53e11e1e1c137d5e462c69c5130a9b938`；禁止修改
scenario/plan/oracle来制造通过。

source/provenance currentness按实际成员闭合：new application source由`core/graph_engineering/__init__.py`的
`_SOURCE_FILES`与source-checkout attestation绑定，并经`pyproject.toml` package/protected-source mapping进入archive/unpacked
wheel与`RECORD`验证。`config/security/dependency-advisory-installation-bootstrap-v1.2.json`没有application source
protected-member字段；它只对自身实际schema/registry/source-artifact/source-attestation/history inputs验真，这些输入不变时
bootstrap1.2/schema/history bytes与digest保持不变。performance bootstrap的真实protected files包含
`application/graph_engineering/application/profile_coverage.py`，仅其真实成员变化时才重算。`pyproject.toml`、C的
default/local policy-runtime双分支与D exact WP07A baseline全部验证currentness，但只有各自实际input projection变化时才重签；
action build projection明确剔除dependency-advisory与performance-benchmark tables，因此不得强制制造C/D digest变化，也不得跳过或
放宽任何pin。
`config/profiles/scenario-truth-policy-registry-v1.json`中的当前上限为 Human 在 2026-09-10 批准的 `cumulative_runtime_limit_seconds=14400`，
`heartbeat_interval_seconds=60`不变。旧 agent-only 86400 不获追认；这些 config-owned 数据不能替代seal/quiesce/reopen、
four-phase full reread、exclusive reopen、active-handle或zero-replay gates。

**Agent audit note（无Human authority effect）：**旧诊断中的“index25”不是direct observation：它只由plan顺序与stack
context推定，缺少完整last-binding日志，因此不得写成已直接观测的binding index或精确stall位置。本author另确认已dirty且
不在Envelope的`tests/support/wp08_dependency_security.py`与`tests/support/wp08_migration_rehearsal.py`保持未修改；该事实不是
Human F1批准内容，也不扩大authority。

## Context

冻结 Support Matrix 有 29 个 scenario × `{P,R}`。当前 production plan 已有 220 records / 110 oracle bindings，
仍缺的 P2 范围 exact 为：

- `new-feature`: `multi-target`（2 records / 1 oracle）；
- `hotfix`: `emergency-baseline`, `production-like-gate`（4 / 2）；
- `refactor-debt`: `behavior-characterization`, `architecture-invariant`, `nonfunctional-target`（6 / 3）；
- `incident-response`: `detection`, `containment`, `recovery`, `unknown-effects`（8 / 4）。

现有 generic boundary evidence 只能证明 scenario identity；它不能证明多 target 原子边界、emergency baseline、
production-like gate、行为等价、architecture invariant、非功能目标或事故状态转换的真实结果。另一方面，本轮明确
排除真实环境和外部动作，因此需要一个只对 disposable local state 有效、不会升级成真实生产证明的 authority。

## Decision Drivers

1. scenario truth 必须来自 protected installation/config 与 fresh local observations，而不是 caller body；
2. 每个 P/R binding 保持 unique task、branch/target 与 current authority，不能跨任务复用；
3. policy、阈值、fixture、target 数量、状态机和 owner route 全部配置化；
4. observation/assessment 必须可从 task 唯一 referenced CAS 重验，restart 不重放 action；
5. `unknown-effects` 必须 fail closed 并 route owner，不能冒充 service recovered；
6. 不新增 DB table/event kind、GraphRef pin、网络或第三方 dependency。

## Decision

采用 **closed scenario policy + frozen local fixture + consumer-local observation factory + task-local CAS projection**。

### 1. Exact scenario policy and installation closure

新增 `urn:gew:scenario-truth-policy-registry:v1`。root exact fields/order 为：

`schema_version, registry_id, profiles, scenarios, registry_digest`。

`profiles` canonical exact 为 `incident-response, hotfix, new-feature, refactor-debt`；`scenarios` 与本 ADR Context
列出的十个 `(profile_id, scenario_id)` 双向 exact。每个 row 固定：Profile/version、scenario ID、fixture ID/digest、
required target roles、ordered phase IDs、required fact IDs、success outcome、blocked outcome（若适用）、owner route
policy、branch isolation policy、mutation budget、rollback/compensation requirements 和 row digest。任何 missing/extra/
duplicate/reorder/alias、unknown enum、caller-supplied threshold/owner/phase 或 same ID/body replacement 均拒绝。

新增 `urn:gew:scenario-truth-fixture-registry:v1`，只保存无用户数据的 deterministic local fixtures。target roles、
source trees、expected output vectors、architecture edge allow/deny set、integer nonfunctional thresholds、incident signals、
service state和 fault schedule 都由 fixture/config 拥有。engine 只实现通用 exact-set、ordered transition、digest、整数比较
和状态机验证，不包含 Profile-specific 值。

`urn:gew:scenario-truth-installation-bootstrap:1.0.0` exact pin：policy/fixture registries、其 schema pairs、Profile schema
registry、approved Profile/coverage/semantic policies、Support Matrix、execution plan、local source/build attestation、installed
distribution version/RECORD、protected member ordered set/digest，以及下述 observation/assessment schema。factory 只从
当前 installed resource byte pipe 加载；不接受 caller path、ambient checkout、`PYTHONPATH` shadow 或 network fallback。

### 2. Exact schema evolution

Profile schema registry 增加以下 5 组 source/digest-input pairs；每个 input projection 只排除本 record 唯一 derived
digest 字段，parent 保留完整 nested body 与 child digest：

| Contract | Source schema | Digest-input schema |
|---|---|---|
| scenario policy registry | `urn:gew:schema:scenario-truth-policy-registry:1.0.0` | `urn:gew:schema:scenario-truth-policy-registry-input:1.0.0` |
| scenario fixture registry | `urn:gew:schema:scenario-truth-fixture-registry:1.0.0` | `urn:gew:schema:scenario-truth-fixture-registry-input:1.0.0` |
| scenario truth observation | `urn:gew:schema:scenario-truth-observation:1.0.0` | `urn:gew:schema:scenario-truth-observation-input:1.0.0` |
| installation bootstrap | `urn:gew:schema:scenario-truth-installation-bootstrap:1.0.0` | `urn:gew:schema:scenario-truth-installation-bootstrap-input:1.0.0` |
| category assessment 1.3 | `urn:gew:schema:category-completion-assessment:1.3.0` | `urn:gew:schema:category-completion-assessment-input:1.3.0` |

已有 assessment 1.0/1.1/1.2 bytes 与语义保持冻结。1.3 是 profile-discriminated closed union：仅上述十个
boundary scenario tasks 可携带唯一 `scenario_truth_projection`；不得同时携带 `performance_evidence_projection`、
`migration_rehearsal_projection` 或 `dependency_graph_projection`。generic/其它 Profile 不得使用 1.3。

`scenario_truth_observation` exact fields/order 为：`schema_version, evidence_kind, task_id, task_revision,
snapshot_digest, invalidation_epoch, profile_id, profile_version, scenario_id, graph_ref_pins, installation_pins,
policy_row, fixture_row, branch_binding, before_targets, ordered_transitions, after_targets, assertion_results,
rollback_or_compensation, owner_route, scenario_outcome, observation_digest`。所有 target rows exact sorted/unique，
transition rows必须连续引用 previous state digest；unknown effect 不允许产生 fabricated after-state。

### 3. Issuance, branches and currentness

`ScenarioTruthRegistryFactory.from_installation()` 是唯一 registry issuer；`ScenarioTruthObservationFactory` 为
`eq=False` consumer-local opaque object，由前者对 exact task/profile/scenario 创建。authority 只以 factory-local strong
identity table存在，不能序列化、复制、跨 factory/task 使用，不能由 bytes、自算 digest、dataclass equality、
`object.__new__` 或 caller mapping 提升。

每个 binding 使用 fresh private root、unique task ID 与 unique branch/ref namespace。source baseline 来自 installed
fixture，禁止读取或写入用户项目。多个 target role 各有独立 path/identity/fence；scenario policy 决定允许的 ordered
mutations。跨 task branch、共享 mutable target、foreign ref、wrong expected ref、target alias/symlink escape、少/多 target
都在首个 mutation 前拒绝。P 与 R 不能共享 mutable repo、branch、target、factory 或 token。

issue/use/precommit/restart/coverage 每次重读 current TaskSnapshot revision/snapshot/epoch、GraphRef six pins、policy/
fixture/bootstrap/schema/install/RECORD/source bytes、branch refs、全部 target bytes与 observation nested digests。precommit
在 hooks/callbacks 后、token 消费前完成 final reobserve；其后不执行 target-sensitive callback。

assessment 使用既有 `task.category_assessed` 和 task 唯一 `EvidenceRef` 指向一个 CAS object。1.3 projection 内嵌完整
observation，不新增 event/table/API。restart 只能从 current task 唯一 referenced CAS (`require_referenced=true`) 重解，
使用 fresh factory/current installation 重新签发 local use authority；local mutation/action replay count exact 为 0。
missing/duplicate ref、foreign/clone/stale factory、CAS coherent replacement、post-observation policy/fixture/target/ref变化均
fail closed且 task/event/snapshot/object/ref/action/target/input 零写。

### 4. Frozen scenario meanings

| Profile/scenario | P meaning | R meaning |
|---|---|---|
| `new-feature/multi-target` | 两个 config-owned target roles 从同一 A baseline 经独立 fenced transition 达到各自 exact B，全部 acceptance/regression/fresh target checks通过；任一失败则整体不完成 | target 缺失/alias、只改一个、cross-branch ref、partial success、wrong rollback或 stale target 被首个未授权 mutation前拒绝 |
| `hotfix/emergency-baseline` | emergency authority、impact/containment和 A baseline 在任何 patch 前 current；minimal B、rollback readiness、fresh target均绑定同一 lineage | late/missing/stale baseline、baseline 来自 B、无 emergency authority或 rollback readiness缺失被拒绝 |
| `hotfix/production-like-gate` | config-owned local production-like fixture 对 B 执行完整 impact/health/rollback gate并通过；结果明确标记 `local-production-like`，不声称真实 production | caller `production=true`、省略 gate、health stale/fail、target/profile/environment alias 或把本地结果提升为 production proof 被拒绝 |
| `refactor-debt/behavior-characterization` | A/B 对 ordered input corpus 的 output/error/side-effect digest vectors exact 相等 | 少/多/reorder case、expected vector alias、任一行为差异或 caller 自报等价被拒绝 |
| `refactor-debt/architecture-invariant` | B 的 import/dependency/layer edges 与 config-owned required/forbidden exact rules相符，且 A/B行为仍等价 | forbidden edge、missing required edge、path alias、只比较计数/节点集或跳过行为门被拒绝 |
| `refactor-debt/nonfunctional-target` | B 在行为等价前提下满足 config-owned integer metric comparator，fresh target仍为B | hardcoded/float threshold、环境漂移、target miss、行为回归或只证明 metric 不证明行为被拒绝 |
| `incident-response/detection` | config signal被准确识别并绑定 impact scope；未检测、错 scope或 caller severity均拒绝 | 缺失/错误/过期 signal、scope substitution或未验证 detection claim被拒绝 |
| `incident-response/containment` | known effect经 authorized local containment 后 affected target隔离、unaffected target保持 exact、residual risk与owner明确 | 越界 containment、遗漏 affected、改变 unaffected、无 authority/fence或 target stale被拒绝 |
| `incident-response/recovery` | 仅对 known+contained effect执行 authorized compensation，fresh service verification证明恢复，follow-up/postmortem/residual facts完整 | unknown/uncontained effect、重复原 action、缺 verification/follow-up、service stale或把部分恢复当成功被拒绝 |
| `incident-response/unknown-effects` | **内层结果必须是 `blocked-owner-route`**：不重放原 action、不执行 recovery、不声称 service restored；保存 unknown claim/residual state并路由 config-owned nonempty owner。外层 P CoverageRecord仅表示“阻断行为被正确证明” | 任何 replay、自动 recovery、`service-restored`、空/替换 owner route、消费 unknown claim或把未知解释为成功均拒绝 |

incident mandatory column `recovery` 的 oracle member 已存在为
`config/test-oracles/profile-incident-response-recovery-v1.json`。scenario `recovery` 必须使用不冲突的新 member
`config/test-oracles/profile-incident-response-scenario-recovery-v1.json`；禁止覆盖、alias 或重解释 mandatory member。

### 5. P/R, oracle and lifecycle integration

每个 scenario P/R 都有 distinct task/request/execution/observation/CoverageRecord；一对共享一个独立 frozen oracle member，
十个新 oracle members exact 对应十个 scenario。P record 的 `COMPLETED` 表示 scenario contract被正确证明；对于
`unknown-effects`，它不表示 incident recovery/completion。R record只能由独立 rejection oracle证明 expected failure，
不能复用 P observation 或 generic rejection label。

P2 按 new-feature → hotfix → refactor-debt → incident-response 四个 sub-slice 严格串行加入 2、4、6、8 records；
production plan/oracle/gate 从 `224/112/224 valid,50 missing,false`（P1 后）依次到：

- `226/113/226 valid,48 missing,false`；
- `230/115/230 valid,44 missing,false`；
- `236/118/236 valid,38 missing,false`；
- `244/122/244 valid,30 missing,false`。

每批失败则该批全部 IDs 保持 missing，上一批 immutable/current。Historical pre-E1 Option C曾按Profile复用repository；
该历史复用不适用于E1/current cumulative。E1改为每binding独占fresh private repository root并保持strict serial，继续使用
coverage factory `active-uncommitted → abort...` / `combined-gate-consumed → finalized`
生命周期；在最终274-record combined gate前只允许 one-shot abort，不允许 partial/sharded gate 冒充完成。

## Alternatives Considered

| Alternative | Disposition | Reason |
|---|---|---|
| config-owned local truth authority | Adopted | 满足离线范围，并能证明真实 local state transition/currentness |
| generic scenario ID 即 truth | Rejected | 只能证明 membership，不能证明 scenario语义 |
| 使用用户项目或真实 staging/production | Rejected for this authority | 超出已批准 target/action/network 范围 |
| 每个 Profile 写硬编码 evaluator | Rejected | 违反 data-logic separation，难以封闭 policy identity |
| unknown effect 自动 replay/recover | Rejected | 会把未知副作用升级为重复动作或虚假恢复 |

## Consequences

### Positive

- 十个未覆盖场景获得可重算、task-bound、installation-pinned 的真实本地证据；
- Profile 值留在 config，core 保持通用 exact comparison/state-transition 逻辑；
- branch/target isolation 与 zero-write rejection 阻止跨场景污染；
- unknown-effect 路径明确 fail closed，不制造恢复成功。

### Costs and limitations

- local production-like、incident、multi-target fixtures 不是实际生产环境证明；
- 需要新增 5 组 schema pairs、两份 registry/config、bootstrap、两层实现和系统性 currentness attacks；
- strict serial/private roots 会增加测试时长；不得通过共享 mutable state、并行 target mutation或 waiver 缩短。

## Rollback

若 architecture review、TDD 或 independent Candidate review 不收敛，停止注册 scenario factory，删除未采用的新
1.3/config/schema/code/tests，保持既有 assessment 1.0～1.2、plan220+已通过 P1（若已完成）与所有历史 records
不变。不得回退为 caller truth、静态 PASS、真实环境访问或 unknown-effect replay。


## 2026-09-10 approved Candidate defect repair

The owner explicitly approved the two existing-contract repairs and future 14400-second budget. This is not approval of prior agent-only 86400-second changes and does not retroactively accept run 72241. The local opaque issuer and deterministic currentness architecture are unchanged; existing fixture/coverage interfaces are tightened to enforce the already required rejection evidence.

Current governing budget: **14400 seconds (4 hours)** for future separately authorized cumulative runs; heartbeat remains 60 seconds. Historical 12600/86400 values and old receipts are retained as history, not current authority. Monitoring remains PAUSED and no automatic rerun is authorized.
