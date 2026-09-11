# ADR-0007: Offline Performance Benchmark Observation Authority

## Status

Accepted decision，revision 13 remaining54 F1 routine traceability R1 candidate，2026-09-06。Human Owner 已批准 WP-08
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

Human Owner 于 2026-09-03 另批准 P1：在不新增 benchmark authority schema、registry、dependency 或 action 的
前提下，复用本 ADR 的 existing installation-pinned factory，补齐 `noise-outlier` 与
`correctness-regression` 两个 scenario P/R pairs。P 仍必须是完整performance success：outlier保留且exact MAD在
ceiling内，同时candidate correctness保持exact、target与fresh B通过；R证明noise超限、correctness mismatch或操纵证据不能
获得performance observation/target PASS。

Human Owner 同日进一步批准 R3：existing statistics policy 的noise ceiling由config-owned `1/1`收紧为`1/2`，并把
existing benchmark registry与installation bootstrap加入exact target boundary。P path仍只能消费parent observer用
真实`monotonic_ns`测得的完整`StructuredCommand`调用时长，且必须同时满足noise、correctness、target、fresh B与
current environment的完整performance success。R path只允许消费已获授权oracle JSON冻结的负向vector
`[1,2,100,200,201]`；其median=`100`、MAD=`99`，所以`99*2 > 100*1`，只能确定性证明
`inconclusive-noise` fail-closed，绝不得冒充真实测量或performance PASS。该vector和ceiling均属于config data；core
只实现通用integer median/MAD与cross-product逻辑，不得硬编码任何数值。

Human Owner 随后明确批准推荐 A：保留`profile-coverage-oracle-input:1.0.0`原始bytes与历史语义不变，新增closed
`1.1.0`。1.1 digest input在1.0 exact fields基础上新增required typed field：

```json
"rejection_input": {
  "kind": "integer-vector",
  "values": [1, 2, 100, 200, 201]
}
```

`kind` exact为`integer-vector`；`values`必须是non-empty ordered JSON array，每项是`1..9007199254740991`的真正
integer，不接受string、boolean、float、null、object、nested array或unsafe integer。array顺序与重复值均属于digest
input。`reject_error_message`只保留稳定诊断文本，禁止编码、拼接、解析或恢复vector。core `profile_coverage`只执行
1.0/1.1 exact field/version/schema/digest dispatch和typed safe-integer验证，不理解performance、scenario或任何sample；
performance application才可读取1.1 `rejection_input`并用通用performance statistics authority重算median/MAD。

### Remaining54 docs review and authority lineage

| Finding / authority revision | Revision 13 disposition |
|---|---|
| `GEW-REMAINING54-DOCS-ARCH-R1-001` | Historical R1 closure：Human Owner当时只增加`pyproject.toml`，并要求两个P1 oracle vectors经现有只读`scripts/build_backend.py`进入wheel/RECORD/source manifest。 |
| `GEW-REMAINING54-DOCS-TRACE-R2-001` | Historical R2 closure：当时current links统一为ADR-0007 r3、ADR-0008 r2、ADR-0009 r2、Spec r26、Impact r20、Plan r25与Test Plan r33。 |
| `GEW-REMAINING54-PERFORMANCE-NOISE-AUTHORITY-R3` | Historical R3 authority retained：Envelope从157增至159，只增加benchmark registry/bootstrap；noise ceiling=`1/2`，P是真实parent timing完整success，R frozen vector只证明fail-closed。 |
| `GEW-REMAINING54-ORACLE-REJECTION-INPUT-A` | Human-approved A authority保持有效：Historical A Envelope从159增至164，exact只增加1.1 input schema、两个generic core sources、dependency current v1.2 bootstrap与migration current v1 bootstrap；1.0 bytes/history与historical dependency v1.1保持不变。Historical A author R0 suite为ADR-0007 r5、ADR-0008 r4、ADR-0009 r4、Spec r28、Impact r22、Plan r27、Test Plan r35。 |
| `GEW-REMAINING54-ORACLE-CASCADE-A-R1-001` | **CLOSED / Historical A routine R1**：A R0 affected cascade遗漏了当时已在164 Envelope内的`core/graph_engineering/core/profiles.py`与`config/verification/wp-00-targets.json`。Historical revision 6补齐两条exact path、`PROFILE_DOMAIN_SCHEMA_IDS`的1.0+1.1 exact构造语义及wp-00 target/source-manifest closure；不改变五项A delta或任何authority。Historical A R1 suite为ADR-0007 r6、ADR-0008 r5、ADR-0009 r5、Spec r29、Impact r23、Plan r28、Test Plan r36。 |
| `GEW-REMAINING54-ACTION-PROVENANCE-B` | **Historical Human-approved B**：Envelope从164增至165且只新增`config/actions/action-policy-v1.json`。Historical revision 7冻结default/local action policies的有向provenance/currentness链，但尚未把default runtime纳入可变闭包。Historical B suite为ADR-0007 r7、ADR-0008 r6、ADR-0009 r6、Spec r30、Impact r24、Plan r29、Test Plan r37。 |
| `GEW-REMAINING54-ACTION-RUNTIME-CASCADE-B-R1-001` | **CLOSED by C**：B只授权default policy，遗漏其current consumer `config/security/security-runtime-v1.json`，使default policy重签后runtime旧pin正确fail closed。C把该唯一runtime target加入Envelope并冻结双runtime branches、read-only evidence consumer与P1 sibling顺序。 |
| `GEW-REMAINING54-ACTION-RUNTIME-C` | **Historical Human-approved C**：Envelope从165增至166且只新增`config/security/security-runtime-v1.json`；删除C项恢复165。Historical C suite为ADR-0007 r8、ADR-0008 r7、ADR-0009 r7、Spec r31、Impact r25、Plan r30、Test Plan r38。 |
| `GEW-REMAINING54-WP07A-BUILD-BASELINE-D` | **Historical Human-approved D**：Envelope从166增至167且只新增`tests/security/test_wp07a_action_contract_security.py`；只允许更新其stale exact build-projection expected constant并保留全部substitution attacks。删除D项恢复166。Historical D suite为ADR-0007 r9、ADR-0008 r8、ADR-0009 r8、Spec r32、Impact r26、Plan r31、Test Plan r39。 |
| `GEW-REMAINING54-PROCESS-LOCAL-QUIESCENT-REOPEN-E1` | **Historical Human-approved E1 R3**：不新增target，Envelope保持exact167；冻结per-binding fresh-root process-local sealed→quiesced→reopened authority与strict serial full-currentness gate。Historical initial E1 suite为ADR-0007 r10、ADR-0008 r9、ADR-0009 r9、Spec r33、Impact r27、Plan r32、Test Plan r40；Historical E1 R3 suite为ADR-0007 r11、ADR-0008 r10、ADR-0009 r10、Spec r34、Impact r28、Plan r33、Test Plan r41。 |
| `GEW-REMAINING54-E1-REPOSITORY-ISOLATION-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：所有pre-E1 per-Profile repository/application共享表述只保留为Historical且不适用于E1/current cumulative；E1正向矩阵机械证明226个binding在repository-root/task/target/branch-ref/action-root/command-root六维各自exact unique且绝不跨binding/profile共享。 |
| `GEW-REMAINING54-F1-DEPENDENCY-SECURITY-REHYDRATE` | **Current Human-approved F1**：Envelope只新增`application/graph_engineering/application/dependency_security.py`，exact167→168；允许generic typed dependency-security rehydrate/current-seal API，不改变performance P/R、E1 lifecycle或任何non-goal。Independently accepted F1 R0 suite为ADR-0007 r12、ADR-0008 r11、ADR-0009 r11、Spec r35、Impact r29、Plan r34、Test Plan r42。 |
| `GEW-REMAINING54-F1-SOURCE-CLOSURE-TRACE-R1-001` | **ADDRESSED by author，pending independent reviewer resolution**：routine traceability correction仅把F1源码闭包改为实际source-attestation/package/wheel/RECORD关系，并要求各bootstrap/projection只按其真实输入currentness决定是否重签；`authority_effect=none`，authority/API/target count均不变。Current R1 suite为ADR-0007 r13、ADR-0008 r12、ADR-0009 r12、Spec r36、Impact r30、Plan r35、Test Plan r43。 |
| `GEW-REMAINING54-F1-OBSERVATION-VERSION-TRACE-R1-002` | **ADDRESSED by author，pending independent reviewer resolution**：agent-added v1.0-only/routing限定不属于Human F1；generic typed rehydrate必须覆盖既有exact Observation 1.0/1.1，GraphAssessment仍是不可替代的downstream consumer。`authority_effect=none`，performance语义和R request digest不变。 |

### Historical B action provenance authority

P2新增packaged sources后，`pyproject.toml`的builtin action implementation build projection及其derived implementation
digests发生变化；因此adapter registry必须从current builtin source/build provenance重算。若default
`config/actions/action-policy-v1.json`仍保留旧concrete-policy/registry pins，P1 verified child在installation/currentness
gate正确fail closed。该拒绝是安全性质，不允许通过跳过、删除、放宽或伪造installation pins“修复”。

B只授权拓扑化、单向的current config重签：`pyproject.toml` builtin implementation provenance →
`config/contracts/action-adapter-registry-v1.json` → `config/actions/concrete-action-policy-v1.json` → 分支到
newly authorized `config/actions/action-policy-v1.json`与既有
`config/actions/action-policy-local-actions-v1.json`；local policy再被
`config/security/security-runtime-local-actions-v1.json`精确绑定。随后这些current bytes/digests进入已在165内的source
checkout/wp-00 target set、current performance/dependency/migration/scenario-truth/release-operations bootstraps、
`pyproject.toml` package selection、只读builder、wheel archive/unpacked resources与`RECORD` pins。

该图的上游builtin build projection排除只承载下游profile/package pins的字段；下游config digest不得反馈写入自身上游
projection，因此无digest环、无需fixed-point或反复试签。实现只能按上述边的拓扑顺序由current source bytes单向重算，
并对每条ID/digest/raw hash/size/RECORD binding做反向核验。P2a packaged-source恢复并冻结后必须完成整链重签，然后先重跑
P1 currentness sibling；P1通过后才可继续P2a scenario issuance。Historical B未增加第166个path，且不允许修改
`scripts/build_backend.py`。

### Human-approved C dual-runtime provenance authority

C沿用B shared prefix，但将policy之后的currentness冻结为两个互不互引的exact runtime分支：

- `pyproject.toml` builtin implementation provenance →
  `config/contracts/action-adapter-registry-v1.json` →
  `config/actions/concrete-action-policy-v1.json`；
- default branch：concrete policy → `config/actions/action-policy-v1.json` →
  `config/security/security-runtime-v1.json`；
- local branch：concrete policy → `config/actions/action-policy-local-actions-v1.json` →
  `config/security/security-runtime-local-actions-v1.json`。

两份runtime current后才共同进入已在166内的source checkout/wp-00/current performance、dependency、migration、
scenario-truth、release-operations bootstraps、package pins、只读builder、wheel archive/unpacked/`RECORD`闭包。
`scripts/evidence_utils.py`只读消费default runtime并须验证其current policy pin；它不在Envelope allowlist，不得修改或以
consumer rewrite替代runtime重签。default policy变更而default runtime仍保留旧pin时，evidence collector与P1 verified
child都必须在任何evidence/action/target write前fail closed。

重签按shared prefix→两policy→各自runtime→共同下游拓扑执行；两个runtime不能互引，下游不得反馈上游，因此无digest环。
P2a packaged-source恢复并冻结后，必须依次完成双runtime重签、`evidence_utils` currentness测试和P1 currentness sibling；
全部通过后才可继续P2a scenario issuance。C只新增`config/security/security-runtime-v1.json`，使Envelope exact166；
删除该项恢复165，无第167 path，不改变action语义、权限或`scripts/build_backend.py`只读边界。

### Human-approved D historical WP07A baseline repair authority

P2a获批scenario sources与`pyproject.toml` build projection落定、C action chain完成合法重签后，factory/WP-08
currentness及package/wheel检查均已通过；扩大后的security run为17/18，唯一失败是历史WP-07A方法
`WP07AActionContractSecurityTests.test_gew_act_001b_installation_anchor_rejects_re_signed_registry_and_provenance_substitutions`
仍把`_action_build_manifest_digest(pyproject.toml)`冻结为旧expected
`b9e8e75bca0436651a723da05d9bcea27f06768666c8c1d9f9fc6b9b80707944`。该失败是stale test baseline，不能通过
回退合法P2a sources或弱化C installation currentness处理。

D只授权在`tests/security/test_wp07a_action_contract_security.py`把该旧常量替换为当前获批build projection的exact
digest。dependency、declared-import、build-mapping、entrypoint、registry与provenance substitution attacks必须原样保持
严格；禁止删除/skip assertion、prefix/loose compare、ambient/caller expected，或让测试用同一次runtime调用自算expected。
这不改变`_action_build_manifest_digest`算法、action/product语义、P1/P2目标或任何实现/config。

`GEW-REMAINING54-P2A-CAND-R1-001`、`GEW-REMAINING54-P2A-CAND-R1-002`、
`GEW-REMAINING54-P2A-CAND-R1-003`、`GEW-REMAINING54-P2A-CAND-R1-004`与
`GEW-REMAINING54-P2A-CAND-R1-005`全部继续**OPEN**，只有独立Candidate reviewer可关闭；001/002/003/005的
focused检查GREEN不等于finding closure，004仍等待D gate和新的cumulative selector。
恢复顺序固定为：精确更新WP07A baseline→运行上述WP07A方法→运行WP08 security/evidence/package/wheel及P1
currentness sibling→恢复`p2a-cumulative-r2`。D后P2a数量保持plan226/oracle113/dynamic 226 valid/48 missing/false，
static-only保持0 valid/274 missing/false。Historical D当时形成exact167；删除唯一D项恢复166，且其authority revision不授权第168路径。

### Human-approved E1 process-local quiescent reopen authority

E1由两次`p2a-cumulative-r2`失败触发：第一次4.086s时C provenance正确fail closed并已修复；第二次exact 7200s
`TimeoutExpired`且无receipt。representative retained contexts从FD4增长至885、maxRSS 7.20GB，teardown回FD4；same-root
phase probe为plan0.546s、base7.801s、226 authorities4.904s、226 observations226.608s、factory1.085ms、
issuance114.974s、dynamic超过545.166s并在900s timeout。证据指向live resource accumulation叠加三次currentness
passes，而非某一binding卡死；不能通过提高timeout掩盖。

E1保持每binding唯一fresh private repository root、task、target、branch/ref及action/command roots，并引入process-local opaque
`open→sealed→quiesced→reopened→sealed→quiesced` lifecycle。execution/observation后seal exact绑定current installation/
provenance/source/package/wheel/`RECORD`、runtime-attested root identity（core不得硬编码绝对路径）、task/object/target/
action/command状态与record/observation digests。quiesce释放repository/object/action/Git/launcher/session及全部live FDs，
但保留该binding private-root bytes。

后续issue/use/precommit/gate只能在单binding严格串行下，由runtime-owned typed reopen port打开同一root；它先全量重读并
比较seal closure与状态，成功后才验证，结束时产生下一generation seal并再次quiesce。同一时刻至多一个reopened binding。
seal/capability不可序列化、portable、caller构造、clone、share或replay；不得重执行action/mutation、缓存/跳过currentness、
跨binding/profile共享repository、double/concurrent/out-of-order reopen。finalize/revoke后永久关闭，禁止reopen。core只定义
平台中立状态机/typed port；真实files/repository/action reopening属于runtime/test adapter，不新增DB/GraphRef/dependency/
daemon/WP10。

E1 RED须用valid current API证明close后stale/226 contexts资源累积；GREEN须在exact226 bindings执行execute→seal/quiesce→
lazy reopen issue/use/precommit/gate，并保持226 valid/48 missing/false、113 unique current oracles、static0/274和P1 sibling
current。negative覆盖root/installation/source/package/wheel/RECORD/task/object/target/action/command tamper、wrong root/ref、
missing/extra、forged/cloned/serialized seal、double/concurrent/out-of-order reopen、replay、terminal reopen、symlink/
cross-binding，全部write/mutation/replay=0。资源证明用deterministic lifecycle/active-handle counters与FD baseline-return诊断；
engine不得硬编码RSS/FD阈值，runtime/heartbeat只由testability config控制。D顺序保持，五个Candidate findings仍OPEN，
其中`GEW-REMAINING54-P2A-CAND-R1-004`增加E1 closure；仅独立Candidate reviewer可关闭。

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

R3 current registry exact配置为`noise_ceiling_numerator=1`、`noise_ceiling_denominator=2`。数值只存在于
versioned registry/bootstrap/oracle resources；engine不得根据scenario ID或sample内容选择、放宽或硬编码阈值。

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
独立request/execution/observation/CoverageRecord与12个独立oracle members。Historical pre-E1 Option C曾允许同Profile
共享disposable repository/application资源；该历史优化不适用于Human-approved E1或current cumulative。E1要求每binding
独占fresh private repository root、task、target、branch/ref、action root与command root，benchmark/Git fixture亦不跨
binding/profile共享且strict serial。

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

### 8. Remaining54 P1 scenario closure

P1 exact stable IDs 为：

- `GEW-PSC-PERFORMANCE-NOISE-OUTLIER-P/R`；
- `GEW-PSC-PERFORMANCE-CORRECTNESS-REGRESSION-P/R`。

两对使用既有 benchmark registry/bootstrap、9组 benchmark schema、assessment 1.1
`performance_evidence_projection`、parent-owned monotonic clock、integer median/MAD、correctness oracle、source
A→B→A history和currentness/restart rules。只新增两个 independent frozen oracle members；ceiling与R negative
vector属于versioned config/oracle data，不新增schema或engine threshold，core只执行通用计算。

`noise-outlier` P 必须由parent observer以真实`monotonic_ns`测量每次完整factory-attested `StructuredCommand`（含process
startup），保存全部odd repetitions且不注入oracle vector；independent重算后baseline/candidate noise均满足`1/2`，
correctness、target、fresh B与current environment也必须全部通过。R exact消费oracle 1.1 JSON typed
`rejection_input.values`冻结的
`[1,2,100,200,201]`，重算median=`100`、deviations=`[99,98,0,100,101]`、MAD=`99`，并以
`99*2=198 > 100*1=100`得到`inconclusive-noise`。R只证明fail-closed；删outlier、reorder、重抽、扩大阈值、
float/rounding、caller MAD、从`reject_error_message`解析vector或把该vector当作P timing均必须拒绝，且绝不签发
performance PASS。

`correctness-regression` P 必须在同一exact environment与case中让所有candidate invocation返回expected
correctness digest，且noise/target/fresh B均通过；scenario强调performance improvement不能跳过correctness gate。
R让至少一个candidate invocation mismatch，或尝试替换expected digest、忽略失败iteration、只比较duration、caller
自报correct或coherent re-sign observation；sequence必须在statistics/target success前fail closed。

A current digest cascade必须从new schema及source bytes单向重算并双向核验：1.1 schema进入
`core/graph_engineering/core/profiles.py`的domain IDs与`config/contracts/profile-schema-registry-v1.json`；
`core/graph_engineering/core/profile_coverage.py`按version选择1.0或1.1 projection/schema，
`core/graph_engineering/core/source_checkout.py`把1.1 schema与current sources加入source attestation，
`config/verification/wp-00-targets.json`使source manifest纳入1.1 schema；
performance oracle JSON、oracle manifest、coverage plan与application consumers重算nested digests；performance bootstrap、
dependency current v1.2 bootstrap与migration current v1 bootstrap更新current schema/source/profile-registry pins和各自
bootstrap/protected-closure digests；historical dependency v1.1 bytes绝不修改。随后`pyproject.toml`选择全部current
resources，现有`scripts/build_backend.py`只按current raw SHA-256作为只读、不可修改且不在allowlist的build authority
input；wheel archive、unpacked resources、`RECORD`与source manifest必须对相同bytes/hash/size双向exact。

Historical A五个新增targets exact为`config/contracts/schemas/profile-coverage-oracle-input-1.1.0.json`、
`core/graph_engineering/core/profile_coverage.py`、`core/graph_engineering/core/source_checkout.py`、
`config/security/dependency-advisory-installation-bootstrap-v1.2.json`与
`config/migration/migration-rehearsal-installation-bootstrap-v1.json`。当时已在164且当前仍在166内的affected cascade
targets exact包括
`config/contracts/profile-schema-registry-v1.json`、performance registry/bootstrap、coverage plan、oracle manifest、
performance noise oracle、performance/profile-coverage applications、profile coverage oracle runner、core public export、
`core/graph_engineering/core/profiles.py`、`config/verification/wp-00-targets.json`、`pyproject.toml`及对应authorized
verification targets。Historical B另且仅新增`config/actions/action-policy-v1.json`，在当时不得据此推断任何第166条path。
`profiles.py`的`PROFILE_DOMAIN_SCHEMA_IDS`必须exact包含
1.0与1.1 profile-coverage oracle input schema IDs；wp-00 targets exact set必须包含1.1 schema path，使
source manifest只接受更新后的exact set并纳入同一1.1 schema bytes。任一missing/extra/reorder、version alias、
1.0 replacement、vector-in-message、stale pin/digest、checkout fallback或archive/unpacked mismatch都在factory issuance与
CoverageRecord前fail closed。Historical A Envelope为exact164；Historical B Envelope为exact165 unique
project-relative/no-glob targets，删除B唯一项恢复exact164；Current C Envelope为exact166，删除C唯一项恢复165，
除此之外不扩大任何action。

两对的 P/R task、request、execution、observation、CoverageRecord均独立；restart从各自task唯一 referenced CAS
重新验证现有 performance projection，launcher replay count=0。foreign/clone/stale factory、sample/current source/
environment/target post-observation replacement、oracle alias与 cross-scenario substitution均 zero task/event/snapshot/
object/ref/action/target/input writes，DNS/socket/proxy exact 0。

P1 完成后 production plan从220增至224，oracle bindings从110增至112，combined dynamic gate exact为
`224 valid / 50 missing / passed=false`；static-only substitute仍 `0 valid / 274 missing / passed=false`。任一 pair
未收敛则该pair两个IDs均保持missing，既有220 records与 coverage lifecycle不变。

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
