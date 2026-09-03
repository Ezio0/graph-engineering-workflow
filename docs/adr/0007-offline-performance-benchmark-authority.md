# ADR-0007: Offline Performance Benchmark Observation Authority

## Status

Accepted decision，documentation candidate，2026-08-30。Human Owner 已批准 WP-08
`performance` 使用 A1+B1：由 parent observer 以 `monotonic_ns` 对每次 factory-attested
`StructuredCommand` 完整调用计时（包含 process startup），child 只返回 correctness digest；统计使用
config-owned exact integer warmup/repetition、integer median 与 deterministic MAD/noise ceiling，并以整数
交叉乘法比较 baseline/target tolerance。environment fingerprint 必须 exact 相同，禁止跨硬件归一化。
Human Owner 另批准 Option B：Slice B 的 final performance observation 与 exact 24 mandatory bindings 使用
现有 `task.category_assessed` / `category-completion-assessment` durable path；完整 performance typed evidence
projection 内嵌于 task-unique assessment CAS object，不新增 generic task event、DB/storage schema 或通用 evidence
API。

实现仍以本 ADR 的独立 architecture review PASS、exact schema/bootstrap conformance 与 TDD 为 blocking
gate。gate 未关闭时，`GEW-PRO-PERFORMANCE-*-P/R` 的 24 个 mandatory bindings 保持 missing，不能签发
production-backed `CoverageRecord`。

本决定不修改 Positioning/PRD Intent Baseline，也不扩大 ADR-0004、ADR-0005 或 ADR-0006。它不授权网络、
外部 benchmark 服务、用户仓库、deploy/release、WP-10、数据库/GraphRef/category-policy 变更或新的
dependency。benchmark 阈值、样本、命令、路径和环境值全部是 versioned config/fixture data，不进入 engine
logic。

## Context

WP-08 `performance` Profile 已冻结 `repeatable-baseline`、`comparable-measurement`、
`correctness-regression`、`performance-target-proved`、`regressions-excluded` 与
`performance-baseline-restored`，并有 exact 24 mandatory IDs 与三个 scenario pairs：
`stable-baseline`、`noise-outlier`、`correctness-regression`。Slice3 的 category authority 可以从 durable
runner/artifact/review/target/action records 派生通用 facts；WP-07A `StructuredCommand` 也能固定 executable、
cwd、request、bounded subprocess、output 与 process reaping。

这些能力仍不定义 duration 的测量所有者、计时窗口、warmup/repetition、统计判定、环境可比性或 baseline/
target/rollback 关系。`storage.clock` 的 repository wall-clock high-water 用于 expiry，不是 duration clock；
child 自报 elapsed/PASS 也不能成为 performance authority。使用在线 benchmark 服务、外部 calibration 或
硬件归一化则会扩大 disclosure、dependency 与环境 trust boundary。因此需要一个 installation-pinned、
完全离线、factory-issued、consumer-local benchmark observation authority。

## Decision Drivers

1. duration 必须由 parent-owned clock 围绕 exact protected command invocation 产生，不能由 caller、fixture
   或 child 自报；
2. correctness 与 performance 必须同时成立；更快但 correctness digest 不匹配永远 fail closed；
3. environment、fixture/sample、source/code、toolchain、command、warmup/repetition/statistics 与 ratios 必须
   进入同一 digest/currentness 链；
4. v1 只比较 exact environment fingerprint，不进行跨机器、跨硬件或跨 toolchain 归一化；
5. 全部统计使用 exact integers 和配置数据，不能依赖 float、随机 bootstrap、ambient load heuristic 或
   engine hardcode；
6. use/precommit/restart 必须重读 current installation 与 durable evidence、重算统计并拒绝 replacement；
7. 复用 Option C unique task identity、serial private roots、combined gate 与 finalize/revoke/abort lifecycle。

## Decision

采用 **installation-pinned benchmark registry + parent-timed protected StructuredCommand sequence +
consumer-local opaque benchmark observation authority**。

### 1. Closed benchmark registry and config-owned policy

versioned registry 只通过 exact schema 解码为 recursive immutable data。root exact fields/order 为：

`schema_version, registry_id, environment_policy, statistics_policies, benchmark_cases, registry_digest`。

`environment_policy` exact 绑定 policy ID、required fingerprint field IDs、safe environment name allowlist 与
policy digest。v1 required fingerprint 至少包含 OS family/release、machine architecture、CPU identity、logical
CPU count、Python implementation/version/cache tag、Python executable raw SHA-256、installed distribution
version/RECORD digest、command registry/runtime-policy/executable raw digests、fixture root identity、locale、
timezone 与 safe static environment projection。缺失字段、空/unknown identity 或无法无网络读取时拒绝。
baseline、candidate、rollback 的完整 fingerprint body/digest 必须 byte-exact 相同；不允许字段子集比较、
caller equivalence、容差匹配、跨硬件校准或 normalization。

每个 `statistics_policy` exact fields/order 为：

`statistics_policy_id, warmup_count, repetition_count, noise_ceiling_numerator,
noise_ceiling_denominator, target_ratio_numerator, target_ratio_denominator,
rollback_ratio_numerator, rollback_ratio_denominator, statistics_policy_digest`。

所有 count/ratio members 都是 exact JSON integers，拒绝 bool/float/string/subclass coercion。`warmup_count`
为非负；`repetition_count` 为 odd、至少 3 且受 installation-owned bounded maximum 限制；ratio numerator/
denominator 都为正，denominator 非零。actual values 只存在 versioned config，不硬编码于 engine。

每个 `benchmark_case` exact fields/order 为：

`benchmark_case_id, profile_id, profile_version, command_id, command_registry_digest,
command_runtime_policy_digest, parameter_projection, fixture_id, fixture_digest,
sample_set_id, sample_set_digest, baseline_source_identity, candidate_source_identity,
correctness_policy_id, expected_correctness_digest, statistics_policy_id,
environment_policy_id, benchmark_case_digest`。

v1 profile exact 为 `performance`。case、fixture/sample、command、source/code 与 policy identities canonical
sorted/unique；unknown/extra/missing/duplicate/alias/reorder 或 same ID/version body mutation拒绝。child output
allowlist exact 只有 `correctness_digest`；不能返回 elapsed、samples、PASS、ratio、environment truth 或
target verdict。

### 2. Exact schemas, digest projections and installation bootstrap

Profile schema registry 必须双向 exact 登记下列 9 组 source/digest-input schemas，且 source/input member
path 与 raw SHA-256 都由 installation bootstrap 固定：

| Contract | Source schema ID | Digest-input schema ID |
|---|---|---|
| benchmark case | `urn:gew:schema:performance-benchmark-case:1.0.0` | `urn:gew:schema:performance-benchmark-case-input:1.0.0` |
| benchmark registry | `urn:gew:schema:performance-benchmark-registry:1.0.0` | `urn:gew:schema:performance-benchmark-registry-input:1.0.0` |
| installation bootstrap | `urn:gew:schema:performance-benchmark-installation-bootstrap:1.0.0` | `urn:gew:schema:performance-benchmark-installation-bootstrap-input:1.0.0` |
| environment observation | `urn:gew:schema:performance-environment-observation:1.0.0` | `urn:gew:schema:performance-environment-observation-input:1.0.0` |
| correctness observation | `urn:gew:schema:performance-correctness-observation:1.0.0` | `urn:gew:schema:performance-correctness-observation-input:1.0.0` |
| measurement sample | `urn:gew:schema:performance-measurement-sample:1.0.0` | `urn:gew:schema:performance-measurement-sample-input:1.0.0` |
| sample-set observation | `urn:gew:schema:performance-sample-set-observation:1.0.0` | `urn:gew:schema:performance-sample-set-observation-input:1.0.0` |
| statistics observation | `urn:gew:schema:performance-statistics-observation:1.0.0` | `urn:gew:schema:performance-statistics-observation-input:1.0.0` |
| final performance observation | `urn:gew:schema:performance-observation:1.0.0` | `urn:gew:schema:performance-observation-input:1.0.0` |

每个 digest-input projection 只排除该 record 自身唯一 derived digest field；parent 必须包含完整 nested child
body 与 child digest。bootstrap exact pin registry member/raw/semantic digest、9 pairs、Profile schema registry、
command registry/runtime policy、executable/cwd source identity、fixture/sample members、installed distribution
root/version/RECORD/source/build attestation、protected-member ordered list/digest 与 bootstrap digest。

loader 只从 protected installation byte pipe 读取，不接受 caller path/digest、ambient `PYTHONPATH`、project
shadow 或 network fallback。registry/bootstrap/schema/fixture/sample/command protected member missing/extra/
duplicate/reorder、same-path replacement、RECORD/archive/unpacked tamper、nested digest omission或 coherent
content+digest re-sign但 installation pin未变均在 authority issuance 前拒绝。

### 3. Parent-owned measurement sequence

`PerformanceBenchmarkRegistryFactory.from_installation()` 是唯一 registry issuer；
`PerformanceBenchmarkObservationFactory` 只能由该 exact current factory创建。两者为 `eq=False`、
consumer-local opaque objects，使用 factory-local strong identity/closure issuance table；禁止 public bytes
promotion、module-global `id()` authority、dataclass equality/hash、`object.__new__` clone 或 foreign owner。

factory 只接受 `StructuredCommandLauncher.require_attested()` 通过的 launcher 与 exact case binding。每个
baseline/candidate/rollback sequence 严格 serial：

1. 重读 installation registry/bootstrap/schemas、fixture/sample/source、command executable/cwd 与 environment，
   签发 before-environment observation；
2. 按 config exact `warmup_count` 执行 warmup。每次在调用 `launcher.execute(...)` **立即之前**取
   parent-owned `monotonic_ns` start，在该完整调用返回**立即之后**取 end；窗口包含 process startup、child
   execution、output collection与reap。warmup duration 不进入统计，但 invocation/result/correctness digests 与
   iteration index进入 sample-set provenance；
3. 按 odd exact `repetition_count` 执行 measurement，窗口相同；每次 `end > start`，duration=`end-start`
   为 positive safe integer nanoseconds；
4. child 的成功 result output exact 为单字段 `correctness_digest`，且每次与 config expected digest exact
   相同。nonzero/timeout/cancel/unknown/malformed/extra output、correctness mismatch或 secret leakage 都使整个
   sequence fail closed；
5. 最后重读所有 current identities并签发 after-environment observation；before/after 与 baseline/candidate/
   rollback full fingerprint必须exact相同。final reobserve后不再执行 environment/target-sensitive callback。

clock capability由 factory consumer-local持有，只调用 stdlib built-in monotonic clock；caller clock、wall
clock、repository expiry clock、persisted timestamp或 child elapsed值不能成为 input。start/end与clock
capability identity不序列化为 restart authority。process termination 后本地 clock/launcher authority消失；
restart只能从 durable exact observations和current installation重新签发 use authority，不重放 benchmark。

### 4. Integer median, MAD and exact target comparison

measurement samples 按 exact iteration index `0..repetition_count-1` 存储，不能 missing/extra/duplicate/reorder。
统计函数复制 duration vector并按 integer value排序；因为 count 为 odd，median exact 为中间值。MAD exact为
对每个 sample计算 `abs(duration-median)` 后排序并取中间值。warmup durations绝不进入这两个 vectors。

baseline、candidate、rollback 每个 sample set先独立通过 noise ceiling：

`mad * noise_ceiling_denominator <= median * noise_ceiling_numerator`。

任一侧不满足即 outcome=`inconclusive-noise`，整个 performance observation fail closed；不能删 outlier、重抽
直到通过、扩大阈值、使用 float/rounding 或把 inconclusive解释为PASS。

candidate target exact lower-is-better comparison为：

`candidate_median * target_ratio_denominator <= baseline_median * target_ratio_numerator`。

rollback restored comparison为：

`restored_median * rollback_ratio_denominator <= baseline_median * rollback_ratio_numerator`。

所有运算使用 exact non-negative integers；wire values受 safe-integer schema限制，内部交叉乘积不得 overflow/
truncate/coerce。statistics observation绑定原始ordered samples、sorted projection、median、deviations、MAD、
policy ratios、两侧cross-products与 outcome；caller median/MAD/ratio/PASS不作为 input。

### 5. Baseline, target, correctness and rollback authority

baseline与candidate必须引用同一 benchmark case、fixture/sample、command/toolchain、statistics policy、
correctness policy和exact environment fingerprint；只允许 approved source/code identity发生 A→B 变化。
baseline observation必须先current，candidate observation随后current。performance PASS 同时要求：两侧noise
通过、所有 invocations correctness digest exact、candidate ratio通过、fresh target observer证明B source/code
identity、durable runner/artifact/review facts与current TaskSnapshot/GraphRef six pins一致。

rollback不在 benchmark factory内执行。它继续走 existing `ActionPolicy`/`ActionCoordinator` action-scoped
prepared→authorized→execute/reconcile flow，把 disposable target从B恢复到exact A source/code identity；unknown
只query/reconcile/owner route，不replay。fresh restored target后重新执行完整 rollback benchmark sequence，
要求same environment/case/correctness、noise通过与rollback ratio通过，才签发
`performance-baseline-restored`。target恢复但correctness/noise/ratio未通过仍是 unresolved owner route。

### 6. Currentness, precommit and restart

registry issue、sequence start、每次 invocation前后、observation issue、category assessment、coverage observe/
factory/gate、commit前与restart都重新读取 current registry/bootstrap/schema/fixture/sample/command/source bytes，
验证 executable/cwd descriptor identity、environment fingerprint、TaskSnapshot revision/snapshot/epoch、GraphRef
six pins、durable command results与 object refs，并从 ordered samples重算median/MAD/cross-products。

precommit在现有 resource/target fence内、全部 hooks/callbacks 后执行最终 current revalidation与fresh target
observe；消费token后无 target/environment-sensitive callback。restart只从task唯一exact object ref重读 immutable
evidence并在current installation重新签发local authority；不能从 caller bytes、自算 digest、old token/cache或
foreign factory恢复，也不能自动重跑 benchmark。

`performance` assessment 使用现有 `task.category_assessed` 的 exact task-unique `EvidenceRef`：
`evidence_type=category-completion-assessment`、`trust=factory-attested`、`source_ref` 为 assessment canonical
bytes 的 CAS object digest、`evidence_id=digest` 为 assessment semantic digest。既有
`urn:gew:schema:category-completion-assessment:1.0.0` / input pair保持冻结供非performance使用；新增
`urn:gew:schema:category-completion-assessment:1.1.0` 与
`urn:gew:schema:category-completion-assessment-input:1.1.0` 作为 profile-discriminated schema evolution。当且仅当
`profile_id=performance` 时，1.1 assessment 必须内嵌一个 closed `performance_evidence_projection`；其他
Profile不能使用1.1或携带该字段。它不是新的 task event 或 storage record kind，也不计为第十个benchmark
authority schema stem。

该 projection exact fields/order 为：`schema_version, evidence_kind, task_id, task_revision, snapshot_digest,
invalidation_epoch, profile_id, profile_version, column_id, graph_ref_pins, installation_pins,
benchmark_case_digest, factory_seal_digest, environment_observation, session_pins, source_history,
sample_sets, statistics_observations, comparisons, final_observation, projection_digest`。其中
`graph_ref_pins` 是 exact six-pin tuple；`installation_pins` 固定 registry/bootstrap/schema registry、distribution
root/version、singular RECORD raw digest、ordered protected closure、source/build attestation、command registry/
runtime policy/executable/cwd；`session_pins` 固定 factory/install/environment/launcher/command/request identities
与 consumer-local session digest。所有 nested body 与 child digest 都保留，`projection_digest` 的 digest-input
只排除自身。

`source_history` 是 ordered A→B→A exact triple，generation 必须为连续 `1,2,3`，A genesis 的 previous digest
为空，B 与 restored-A 分别绑定前一 observation digest；每项绑定 source/code tree、target observation、mutation/
rollback receipt 与 current generation。label-only A、同root异bytes、skip/reorder/duplicate generation、wrong
previous digest、B冒充restored-A或foreign history全部拒绝。`sample_sets` 保存每阶段config-owned warmup provenance、
ordered measurement samples与correctness observations；`statistics_observations` 保存重算的sorted durations、
median、deviations、MAD、noise cross-products/outcome；`comparisons` 保存target与rollback的exact integer products/
outcome；`final_observation` 绑定完整 before/after/restored closure、correctness regression facts与上述所有child
digests。

assessment issuer只能消费同一 consumer-local factory签发且仍current的 projection seal；它重新计算 nested
digests、statistics/comparisons、assessment digest与CAS digest。`TaskApplication.complete_category` 在现有
category precommit transaction/fence内、所有 hooks 后再次重读 current TaskSnapshot、GraphRef six pins、factory/
installation/environment/session/command/source target，并 byte-exact 重算 projection；随后只提交既有
`task.category_assessed` event及其单一 assessment object reference。失败或crash在commit前最多留下可回收的
unreferenced CAS bytes，task/event/snapshot/reference/action/target 均不变；commit后 EvidenceRef、assessment 与
projection 同时可见。

restart从 current task 唯一 `category-completion-assessment` EvidenceRef 解析 `source_ref`，以
`require_referenced=true` 重读CAS bytes，重算object/assessment/projection及每个nested digest，并绑定 current
task revision/snapshot/invalidation epoch、profile/column、GraphRef six pins与 installation/environment/session
pins。成功只在该 consumer-local factory重新签发 use authority，launcher invocation count必须为零；缺失、
重复、foreign/clone/stale、alias、A/B/A reorder、nested coherent re-sign、CAS replacement或current pin变化均
拒绝且zero write。

environment/config/fixture/source/command delete/replace/touch-with-identity-change、clock substitution、start/end
alias、sample omit/add/reorder、warmup混入、correctness mismatch、coherent observation/statistics re-sign、foreign/
clone/cross-case/cross-task、post-observation replacement均zero assessment/execution/observation/CoverageRecord；
task/event/snapshot/object/ref/action/target/input不变。所有路径包裹DNS/socket/proxy probe且调用exact为零。

### 7. WP-08 coverage integration

本 authority 现获授权补 `performance` mandatory 12-column P/R batch 与 Slice B final observation。前11 columns继续消费Slice3 distinct typed
durable sources；real-E2E使用本ADR的 benchmark authorities。24 bindings保持config-owned unique task IDs、
独立request/execution/observation/CoverageRecord与12个独立oracle members。Option C只允许同Profile共享
disposable repository/application资源；task/current authority不能共享，benchmark/Git fixture隔离且strict
serial/private-root。

P fixture：在同一exact environment先测A baseline，经ActionCoordinator/GitNativeAdapter一次expected-ref mutation
到B，测B candidate；correctness、noise、target与fresh B observation全部通过，restart重解current evidence且
zero replay。R fixture使用stale expected A/actual C，在native mutation和benchmark launch前拒绝，mutation/
invocation/task增量为零；benchmark-specific rejection matrix另证明noise超限、correctness regression、target
miss、environment drift都不能签发P execution，只有exact isolated rejection oracle可签发R record。

current 170 records增加24后，plan exact为194、oracle bindings为97，combined gate预期
`194 valid / 80 missing / passed=false`，static evidence仍`0/274`，不得签发WP-08 exit。复用既有 factory-owned
coverage lifecycle：exact combined gate后才能finalize/revoke；pre-gate candidate只能走approved one-shot abort。
finalized/aborted后所有 benchmark/current/restart/coverage入口拒绝，immutable records与durable task/action/
target不变。

## Alternatives Considered

| Alternative | Disposition | Reason |
|---|---|---|
| parent observer以monotonic clock计完整protected command（A1） | Adopted | 不新增dependency；测量边界可由现有launcher identity与process lifecycle强制 |
| child内部自计inner workload（A2） | Rejected for v1 | child timing成为新的truth source，需要额外harness/parser/calibration authority |
| external `pyperf`/benchmark service | Rejected for v1 | 新dependency/toolchain或network/disclosure边界 |
| integer median + MAD + cross-products（B1） | Adopted | deterministic、无float/随机性、可完整重算 |
| bootstrap/confidence interval/trimmed adaptive model（B2） | Rejected for v1 | 引入随机/rounding/sample-size语义与更大统计contract |
| 跨硬件归一化 | Rejected | calibration与等价模型无当前authority；不同fingerprint必须fail closed |
| fixture/command自报PASS或duration | Rejected | 无法证明测量所有者、currentness与正确性 |

## Consequences

### Positive

- performance结论绑定真实本地protected command、exact environment与可复算integer samples；
- noise、correctness、target与rollback各自有独立fail-closed predicate；
- 不引入network、外部服务、第三方统计dependency或硬件阈值engine hardcode；
- 与Slice3 durable facts、Option C和coverage lifecycle一致。

### Costs and limitations

- 指标是完整command wall duration，包含process startup，不代表inner-function microbenchmark；
- exact fingerprint使不同机器/硬件/toolchain的结果不可比较；
- serial warmup/repetition增加focused runtime；inconclusive必须修复环境/fixture或由Human批准新config，不能自动
  重抽；
- v1只支持lower-is-better elapsed latency；其它metric需要新的Human-approved authority revision。

## Rollback

若实现或独立review无法闭合clock、environment、statistics或currentness authority，停止签发全部performance
observation/CoverageRecord，使24 mandatory IDs保持missing；删除尚未采用的新增config/schema实现，不修改既有
170 records、combined gate/lifecycle、durable task/action/target或WP08A历史tuple。不得回退为child自报、fake
duration、跨环境比较或static fixture PASS。
