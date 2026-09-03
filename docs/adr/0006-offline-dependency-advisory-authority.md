# ADR-0006: Offline Dependency Advisory Observation Authority

## Status

Accepted decision，revision 8 R3 additive offline-v2 provenance amendment，2026-09-02；Human Owner 已批准 WP-08
`dependency-security` 使用安装固定、完全离线的 advisory registry 与 factory-issued current observation
authority、uncommitted coverage candidate 的 consumer-local abort/revoke 终态，以及从 exact installed
METADATA/wheel closure 派生的 ordered dependency graph 与 explicit config-owned fix-unavailable disposition。
实现仍以本 ADR 的独立 architecture review PASS、exact contract/schema conformance 与 TDD
为 blocking gate；该 gate 未关闭时，`GEW-PRO-DEPENDENCY-SECURITY-REAL-E2E-P/R` 不得签发
production-backed `CoverageRecord`。

本决定不修订 ADR-0004。ADR-0004 r6/r7 的 `packaging==26.3`、物理 wheel/RECORD/METADATA
校验和 closure budgets 继续保持 `build/install/package-verification-only`；本 ADR 只在该只读
结果之上增加 WP-08 dependency-security advisory/observation authority，不授予 installation、
activation、deploy、release、网络或第三方 executable authority。

### Review r1 finding disposition

| Finding | Revision 2 closure |
|---|---|
| `GEW-ADR0006-R1-001` | §3～4 冻结 WP08A-bound closure/applicability/residual issuers、exact input identity 与全 registry residual recomputation；caller truth/omission/clone/cross-advisory/replacement 全部 fail closed |
| `GEW-ADR0006-R1-002` | §1、§5 冻结 genesis/update/rollback、closed high-water/status transition、half-open source time 与 existing installation-verification comparison boundary |
| `GEW-ADR0006-R1-003` | §2 冻结 10 组 source/digest-input schema IDs、nested self-digest projection 与 registry/bootstrap/observation protected pins/attack closure |

### Lifecycle amendment r4 finding disposition

| Finding | Revision 5 closure |
|---|---|
| `GEW-ADR0006-R4-R1-001` | §6 分离同一进程 injected exception retry 与 process termination；后者销毁 local authority，restart 不得从 bytes/digest 重建 |
| `GEW-ADR0006-R4-R1-002` | §6 改为 factory 在 prepare-abort 线性化锁内冻结 exact generation/完整 current projection 后才签发 one-shot capability；freeze 后 registration/gate/finalize 拒绝 |

### Lifecycle amendment r5 finding disposition

| Finding | Revision 6 closure |
|---|---|
| `GEW-ADR0006-R5-R1-001` | §6 把 `abort-prepared` state、frozen snapshot/version 与 cap identity 作为同锁原子 tuple；return 丢失时 exact retry 返回同一 stored capability，不新签或改变 projection |

### Revision 8 architecture finding disposition

| Finding | Revision 8 R2 closure |
|---|---|
| `WP08-DEP-OPTION1-DOCS-ARCH-R1-001` | §8以additive immutable `source:dependency-advisory:offline-v2@1`完整快照替代复用v1 source；generation-1 registry/v1 artifact/attestation/bootstrap/schema bytes保持历史exact，generation-2 active advisories全部解析到active/time-valid v2 artifact+attestation，并由versioned bootstrap history双向绑定 |

## Context

WP-08 的 `dependency-security` Profile 要求 applicability/exposure、upgrade/fix、security
regression、residual exposure、target verification 与 `dependency-state-restored` rollback。
当前 Slice3 authority 已能为 normal、boundary、revise、authority、drift、invalidation、
recovery、artifacts、review、target 与 rollback 读取并重验 durable typed facts；WP-08A 也能
完全离线地验证 wheel filename/tag、PEP 508 requirements、物理 ZIP、METADATA/WHEEL/RECORD、
dependency closure 与 closure-wide limits。

这些能力仍不能回答某个 verified package/version 是否受某 advisory 影响、修复 closure 是否获
批准、security regression 是否通过或 residual exposure 是否被诚实记录。把测试 JSON 中的字符串
直接解释成“vulnerable/fixed”会伪造 scanner authority；使用在线 advisory/scanner 又扩大 v1 的
network、source 与 disclosure 边界。因此需要一个独立、可安装证明、数据型且 fail-closed 的离线
advisory authority。

## Decision Drivers

1. advisory/source/affected-version/fixed-closure 结论必须来自安装固定 authority，而不是 caller
   mapping、测试常量或 command 自报 PASS；
2. wheel/requirement 解析必须复用 ADR-0004 r6/r7 的 exact offline boundary，不在 core 或 runtime
   另写 parser，也不跨越 WP-10 activation block；
3. registry、observation、task/GraphRef、target、regression 与 residual-exposure facts 必须逐项
   current、可重启解析且在 commit 前最终重验；
4. update/revocation 单调、无 runtime feed、无网络 fallback；无法证明 currentness 时 zero issuance、
   zero task/action/target mutation；
5. 保持 Option C 的 per-binding unique task identity/per-Profile shared repository，以及 coverage candidate
   在一次性 combined `ReleaseCoverageGate` 后 finalize、或在 pre-gate 阶段 abort 的互斥 lifecycle。

## Decision

采用 **installation-pinned closed advisory registry + WP-08A verified offline closure observation +
consumer-local opaque observation authority**。

### 1. Closed advisory registry, genesis and status high-water

版本化数据成员为 `config/security/dependency-advisory-registry-v1.json`，只允许由 exact input schema
解码成递归 immutable data。registry 根 exact fields/order 为：

`schema_version, registry_id, generation, update_kind, previous_registry_digest,
rollback_of_registry_digest, revocation_high_water, source_records, advisories, registry_digest`。

genesis exact 为 `generation=1`、`update_kind=genesis`、`previous_registry_digest=null`、
`rollback_of_registry_digest=null`。forward candidate exact 为 current generation + 1、
`update_kind=forward`、previous digest=current digest、rollback-of=null。rollback candidate 也只能是
current generation + 1、`update_kind=rollback`、previous digest=current digest，并以 non-null
`rollback_of_registry_digest` 指向一个已验证历史 registry；禁止 generation downgrade、skip 或回写旧 head。

`revocation_high_water` exact fields/order 为
`generation, source_states, advisory_states, high_water_digest`。`generation` 必须等于 registry generation；
两个 state arrays 分别按 `(source_id,source_revision)` 与 `(advisory_id,advisory_revision)` canonical
升序、exact unique，且必须与 `source_records`/`advisories` identity set 双向完全相等。state entry exact
fields 为对应 identity、`status`、`status_generation`。source/advisory status enum exact 为
`active|superseded|revoked`；transition 只允许 `active→active|superseded|revoked`、
`superseded→superseded|revoked`、`revoked→revoked`；status generation 只能按下述 exact rules 生成，任何删除、复活、
降级、减少或同 identity 多状态均拒绝。genesis 的所有 state 为 active、status generation=1。对任一
candidate generation `g=current+1`，exact generation rules 为：新 identity 必须 status=active 且
`status_generation=g`；既有 identity 若 status 不变必须 byte-exact 保留 prior `status_generation`；若发生
允许的 status transition 必须 `status_generation=g`；所有 row 均满足
`1 <= status_generation <= registry generation`。future generation、用旧 generation记录新 transition 或
无 transition却推进 status generation均拒绝。

每个 `source_record` exact fields/order 为 `source_id, source_revision, issuer_id, issued_at, not_before,
not_after, source_artifact_raw_sha256, source_attestation_digest, source_record_digest`。stored status 只在
high-water；source 可用于 issuance 的 exact 条件是 state active 且 repository-owned clock 满足
`not_before <= clock < not_after`。每个 advisory exact fields/order 为 `advisory_id, advisory_revision,
source_id, source_revision, ecosystem, distribution_name, affected_version_specifiers, applicability_kind,
fixed_closures, residual_exposure_policy_id, security_regression_policy_id, advisory_digest`；其 state 也只在
high-water。source/advisory record bytes 一经发布 immutable。

fixed closure exact fields/order 为 `closure_id, root_distribution_name, root_version,
required_distribution_pins, security_regression_command_id, closure_digest`。pin exact 绑定 normalized name、
version、wheel raw SHA-256 与 RECORD digest。v1 ecosystem exact `pypi`、applicability kind exact
`verified-offline-closure-member`。所有 arrays 按 schema canonical key 排序且 unique；duplicate、alias、
unknown/extra/missing/ambiguous member 拒绝，不做 caller normalization。业务 advisory/specifier/pin/source/
expiry/command/policy 数据只在 config。

### 2. Exact schema pairs, nested digests and installation bootstrap

`config/contracts/profile-schema-registry-v1.json` 必须双向 exact 登记下列 10 组 source/digest-input schema；
source schema 与 input schema 都是 protected member，均绑定 raw SHA-256：

| Contract | Source schema ID | Digest-input schema ID |
|---|---|---|
| source record | `urn:gew:schema:dependency-advisory-source-record:1.0.0` | `urn:gew:schema:dependency-advisory-source-record-input:1.0.0` |
| fixed closure | `urn:gew:schema:dependency-fixed-closure:1.0.0` | `urn:gew:schema:dependency-fixed-closure-input:1.0.0` |
| advisory record | `urn:gew:schema:dependency-advisory-record:1.0.0` | `urn:gew:schema:dependency-advisory-record-input:1.0.0` |
| status high-water | `urn:gew:schema:dependency-advisory-status-high-water:1.0.0` | `urn:gew:schema:dependency-advisory-status-high-water-input:1.0.0` |
| registry | `urn:gew:schema:dependency-advisory-registry:1.0.0` | `urn:gew:schema:dependency-advisory-registry-input:1.0.0` |
| installation bootstrap | `urn:gew:schema:dependency-advisory-installation-bootstrap:1.0.0` | `urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.0.0` |
| offline closure observation | `urn:gew:schema:dependency-offline-closure-observation:1.0.0` | `urn:gew:schema:dependency-offline-closure-observation-input:1.0.0` |
| applicability observation | `urn:gew:schema:dependency-applicability-observation:1.0.0` | `urn:gew:schema:dependency-applicability-observation-input:1.0.0` |
| residual exposure observation | `urn:gew:schema:dependency-residual-exposure-observation:1.0.0` | `urn:gew:schema:dependency-residual-exposure-observation-input:1.0.0` |
| final security observation | `urn:gew:schema:dependency-security-observation:1.0.0` | `urn:gew:schema:dependency-security-observation-input:1.0.0` |

每个 digest-input projection 只排除该 record 自身唯一 derived digest field；不得排除 identity、status、
source/provenance、child record 或 child digest。parent digest 必须包含 canonical nested child body 与 child
digest：fixed closure 包含所有 pin bytes；advisory 包含 fixed closures/closure digests；high-water 包含完整
state rows；registry 只排除 `registry_digest` 并包含 source/advisory/high-water bodies及其 digests；bootstrap
只排除 `bootstrap_digest`；closure/applicability/residual/final observation 分别只排除自身 observation
digest，且包含所有上游 child digests。未知 projection、漏 child digest、只摘要 IDs 或 caller 重签拒绝。

installation bootstrap exact pin registry member/raw/semantic digest/generation、10 pairs 的 source/input member
path/raw SHA、profile schema-registry ID/digest、source artifacts raw/attestation digests、distribution root/
version/RECORD digest、build/source checkout attestation、protected-member ordered list/digest 和
`bootstrap_digest`。loader 只通过 protected installation byte pipe 读取；source checkout 与 installed wheel
必须证明同一 projection，不互相 fallback，不读取 ambient project/PYTHONPATH shadow。registry/bootstrap/
schema/observation member missing/extra/duplicate/reorder、RECORD/archive/unpacked tamper、same-path replacement、
coherent content+digest re-sign但 installation pins 未变均 fail closed。

### 3. WP08A-bound closure, applicability and residual issuers

`DependencyAdvisoryRegistryFactory.from_installation()` 是唯一 registry issuer，产生 factory-owned、
consumer-local、`eq=False` opaque authority及其 source/advisory identities。禁止 global `id()` table、
equality/hash、public bytes promotion、clone 或 foreign factory。

`DependencyOfflineClosureObservationFactory` 位于 ADR-0004 r6/r7 的 build/install/package-verification
boundary。它只封装一次成功 `preflight_offline_candidate`，exact 绑定 parser `packaging==26.3`
origin/version/RECORD/source/build attestation、candidate/dependency open-fd physical identities、raw/METADATA/
WHEEL/RECORD/requirement edges、closure charges/limits、semantic digest与前后 descriptor/parent-entry recheck。
before/after observations分别使用不同 one-use capabilities并绑定各自 closure identity；无install/activate API。

同一 boundary 的 `DependencyApplicabilityObservationFactory` exact inputs 为：同一 registry factory签发的
current registry authority、selected advisory identity、selected source identity、before closure observation、
after closure observation与 repository-owned clock。它逐对象要求 `_authority is self`/exact capability，
要求 advisory.source identity exact 指向 source、registry/high-water identity set包含且状态active、时间满足
half-open interval，并用 boundary-owned `packaging==26.3` 计算 before affected match、after approved fixed-
closure match。输出 exact 绑定 registry/advisory/source digests 与 before/after closure digests/identities；
caller bool、specifier result、mapping、list或 omitted field 不构成 input。

`DependencyResidualExposureFactory` 必须消费同一 current registry authority与同一 before/after closure
observations，按 registry canonical advisory order遍历**全部** current advisory identities，包括必须永久
保留的 superseded/revoked 历史 identity。row exact disposition enum为
`inactive|not-applicable|fixed|residual`：inactive advisory直接产生绑定其high-water status/digest的inactive
row，不解释affected specifier，也不要求其historical source仍active/time-valid；active advisory必须引用
同一registry中active且满足half-open time的source，否则整个issuance fail closed。installation validator还
要求任何source转为superseded/revoked时，所有引用它的active advisories在同candidate同步转为
superseded/revoked，禁止active→inactive-source dangling reference。

evaluation universe exact定义为high-water中`status=active`的canonical sorted-unique advisory identity set；
它必须与rows中非inactive identities双向相等。active row由parser boundary计算
`not-applicable|fixed|residual`，绑定 matched distribution/version/specifier、
approved closure ID/null与 advisory/source/closure digests。residual set只能由 disposition=residual rows
deterministic sorted-unique派生；row count/identity set必须与current registry**全部advisory identities**双向
exact，inactive rows不能进入residual set。caller residual bool/list/count、遗漏unrelated/historical advisory、
duplicate row、伪造inactive identity为active、foreign/clone observation、cross-advisory/source、coherent
re-sign或after-closure replacement全部拒绝。新advisory revision可以作为new active identity按candidate
generation签发；旧superseded/revoked identity永不转回active。

### 4. Final dependency-security observation and currentness

`DependencySecurityObservationFactory` 只能消费上述 same-factory registry/applicability/residual/closure
authorities、current TaskSnapshot/GraphRef、durable security-regression record、target observer、ActionCoordinator
journal/claim/reconcile与 repository clock。final immutable observation绑定 stable test/selector/request/oracle/
unique task、revision/snapshot/epoch/six pins、registry/bootstrap/source/advisory、before applicability、after
fixed closure、完整 residual evaluation rows/set/policy、regression、target/action facts和所有 child digests。

registry issue、applicability/residual issue、category assessment、coverage observe/factory/gate、commit前与
restart 每次都重新 byte-pipe 读取 bootstrap/registry/10 schema pairs/source bytes，重新 preflight before/after
closure，重算 selected applicability与全 registry residual rows/set；不能信任 persisted bool/list或 issuance-
time cache。precommit 在 resource/target fence内全部 hooks后执行这些重算与 fresh target observe，再消费
one-use token；消费后无 target-sensitive hook。restart只从 task唯一 exact object ref和current installation
重新签发 local authority，不能从 bytes/foreign token/old registry/cache恢复。

任何 caller omission、foreign/clone/cross-advisory、expired/revoked/superseded/stale、clock rollback、alias/
duplicate、coherent re-sign、registry/schema/source/closure delete/replace或 post-observation replacement均
zero assessment/execution/observation/CoverageRecord，task/event/snapshot/object/ref/action/Git/input不变。

P path要求 before applicability match、B approved fixed closure、regression PASS，且 full residual observation
按 registry policy 为 empty或 exact owner-routed recorded residual；R path stale C/unapproved closure在 mutation
前拒绝，随后才可签发 exact isolated rejection record。

### 5. Existing installation-verification update and revocation boundary

WP-08 不新增 registry head DB、activation pointer或 update transaction。current→candidate 比较完全归属既有
build/install installation-verification boundary：它从 current installed/source-attested head与 candidate
descriptor分别读取 exact bytes，在任何 installation mutation前验证 generation/status/high-water；WP-10
ReleaseInstallManifest/activation仍blocked。WP-08 runtime只读取 current head，不接受 candidate。

candidate必须 current generation + 1且 previous digest exact；high-water identity是 prior superset、状态仅按
允许 transition；新identity/unchanged/changed status的status-generation分别exact为candidate generation/
prior value/candidate generation，并受`<= registry generation`上界；revoked不复活。source/advisory body
immutable；更正新增 revision。active advisory必须引用active/time-valid source，source失活candidate必须同步
使所有引用advisory失活。
affected set或 fixed closure变化是新 advisory revision，fixed closure扩张仍需 Human authority。任何
downgrade、generation skip、wrong/null previous digest、high-water generation mismatch/decrease/remove、status
resurrection、source clock rollback/expiry、同 revision body mutation均在 installation mutation前拒绝。

rollback也由同一 boundary验证并发布 current+1 的 higher-generation head，previous指向current、rollback-of
指向已验证历史内容，且合并保留 current全部 source/advisory identities、revocation states与deny high-water；
不能回写旧generation或恢复revoked entry。head变化立即使旧 observation/assessment/coverage stale。所有
路径禁止 DNS/socket/proxy/index/OSV/GitHub fallback。

### 6. WP-08 coverage and lifecycle integration

本 authority 只补 `dependency-security` mandatory 12-column P/R batch。前 11 columns 继续消费 Slice3
production sources；rollback 继续走 installed `ActionPolicy`/`ActionCoordinator` prepared→authorized→
execute/reconcile + fresh restored-target verification。real-E2E 使用本 ADR 的 advisory/closure authority，
不能用 static fixture、自报 PASS 或 WP08A preflight alone 代替。

24 个 binding 保持 config-owned unique task IDs、独立 request/execution/observation/CoverageRecord；同一
Profile 可以按 Option C 共用 disposable repository/application 资源，但 authority/task/target identity
不能共用，Git/wheelhouse fixture 单独隔离。当前 146 records 增加后 plan 为 170、oracle bindings 为
85，combined gate 预期 `170 valid / 104 missing / passed=false`，static evidence 仍 `0/274`。

每个 coverage candidate 的 factory-owned lifecycle 只能选择一个 consumer-local、单调终态：
`active-uncommitted → abort-prepared → aborting → aborted`，或
`active-uncommitted → combined-gate-consumed → closing → finalized`。只有 exact combined gate 消费该
candidate 的完整 current record identity set 后才允许 `finalize_after_gate`。尚无 combined gate decision、
尚未进入 finalize 分支的 uncommitted candidate 才能调用 `prepare_abort_uncommitted_candidate`。factory
在 register/gate/finalize 共用锁内冻结 exact current candidate generation、plan digest、完整 ordered
registered-authority/issued-record identity projection 及其 canonical digest，并把 `(state=abort-prepared,
frozen generation/projection snapshot+version, one-shot abort-capability identity)` 作为不可分割 tuple 原子
存入 factory-local closure/table；只有 tuple 已提交才向 caller 返回 stored capability。该 capability exact
绑定 factory identity、candidate、frozen generation/
projection digest，不能由 bytes、caller mapping、相等 dataclass、clone、foreign/partial/wrong candidate
推导或转移；caller 不能提交或覆盖 projection。register 先线性化时 identity 必须进入 frozen snapshot；
prepare 先线性化时后续 register/gate/finalize 全拒绝。

prepare 在 tuple commit 前发生 injected exception 时不留下 state/snapshot/capability，candidate保持 active；
tuple commit 后到 return 前异常或 return 丢失时，同一 factory/candidate 重复 prepare 必须返回 table 中同一
capability object identity，不重新签发、不改变 snapshot/version。foreign/clone/different snapshot retry拒绝；
capability 被 abort 消费后 prepare 永久拒绝，但同一个 capability 的 abort retry仍幂等。

`abort_uncommitted_candidate` 原子消费 exact one-shot capability 与 frozen snapshot，先进入 `aborting`，
立即使 execution/observation/current/restart/factory/gate/register
全部 fail closed，再只撤销 factory-local issuance/capability tables、registered authority identity graph 与
强引用并进入 `aborted`。它不调用、生成或伪造 `ReleaseCoverageGate` assessment/decision，不删除 immutable
record documents，也不写 durable task/event/snapshot/object/ref/action/target。exact capability 在
同一进程/同一 factory 对象的 `abort-prepared/aborting/aborted` 重试幂等；foreign/clone/wrong/partial
capability 拒绝且不能影响另一个 candidate。

prepare-abort 与 gate consumption/finalize 共用 factory-local 线性化锁：gate/finalize 先赢则 prepare/abort
拒绝；prepare 先赢则 gate/finalize 拒绝。in-process injected exception 在 prepare 线性化点前保留
active-uncommitted；prepare 后、consume 前保持 abort-prepared；consume 后保持 aborting，同一 factory
对象只可用已签发 exact capability 开始/继续 cleanup。process termination 会销毁全部 local factory/
capability，restart 不得从 bytes、record documents 或 digest 重建、重试或恢复 authority；durable documents
只保持非权威 audit bytes。finalized candidate 不能 abort；aborted candidate 不能 gate、finalize、
re-register 或 reopen。两个终态都保留 immutable audit documents；只有 finalize 分支保留先前合法的
gate decision。该 amendment 只补 ADR-0006 已有 coverage lifecycle，不新建 ADR，也不新增 repository/
DB/GraphRef/network/WP10/external authority 边界。

### 7. Offline dependency graph and explicit unavailable-fix amendment

现有 closure/applicability authority只证明 distribution/version membership，不把 caller edges、fixture label或
METADATA requirement字符串自动提升为完整 dependency graph truth。revision 7 增加 installation-pinned
`DependencyGraphObservationFactory` 与 remediation disposition authority；两者仍位于 ADR-0004 r6/r7 的
build/install/package-verification-only boundary，不实现 resolver/scanner、不访问 index/network、不安装或
激活 dependency。

新增 protected data members 固定为：

- `config/security/dependency-graph-policy-registry-v1.json`，registry identity
  `urn:gew:dependency-graph-policy-registry:v1`；
- `config/security/dependency-remediation-disposition-registry-v1.json`，registry identity
  `urn:gew:dependency-remediation-disposition-registry:v1`；
- revision 7 installation bootstrap exact pin上述两个registry member/raw/semantic digests、现有 advisory
  registry/generation、Profile schema registry、distribution root/version、singular RECORD、source/build
  attestation与ordered protected closure。

graph-policy registry root exact order为`schema_version, registry_id, root_distribution_policy,
marker_environment_policy, edge_order_policy, registry_digest`。remediation registry root exact order为
`schema_version, registry_id, dispositions, registry_digest`；disposition rows canonical sorted/unique，exact
fields/order为`disposition_id, advisory_id, advisory_revision, graph_policy_digest, status, reason_code,
residual_policy_id, owner_route, expires_at, disposition_digest`。status v1 exact enum仅
`approved-fixed-closure|approved-unavailable`。missing fix、empty fixed closure、unknown package、command failure
或网络不可达永远不能推导`approved-unavailable`；只有current、time-valid、same-advisory exact config row可授权，
且 unavailable 必须非空 residual owner route。

Profile schema registry 在现有10 pairs之外双向 exact增加以下5组source/digest-input pairs；existing 1.0 final
observation/bootstrap保持冻结，graph scenarios使用1.1 versions：

| Contract | Source schema ID | Digest-input schema ID |
|---|---|---|
| graph-policy registry | `urn:gew:schema:dependency-graph-policy-registry:1.0.0` | `urn:gew:schema:dependency-graph-policy-registry-input:1.0.0` |
| closure graph observation | `urn:gew:schema:dependency-closure-graph-observation:1.0.0` | `urn:gew:schema:dependency-closure-graph-observation-input:1.0.0` |
| remediation disposition registry | `urn:gew:schema:dependency-remediation-disposition-registry:1.0.0` | `urn:gew:schema:dependency-remediation-disposition-registry-input:1.0.0` |
| final security observation v1.1 | `urn:gew:schema:dependency-security-observation:1.1.0` | `urn:gew:schema:dependency-security-observation-input:1.1.0` |
| installation bootstrap v1.1 | `urn:gew:schema:dependency-advisory-installation-bootstrap:1.1.0` | `urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.1.0` |

每个 input 只排除自身 derived digest，parent 保留完整 child body/digest。bootstrap 1.1 固定既有10 pairs及
新增5 pairs、两个新增registries与其digests，不允许1.0/1.1 cross-use、member omission、extra、alias、duplicate、
reorder或coherent全套重签绕过installation identity。

`DependencyGraphObservationFactory` 只消费同一 registry factory、current WP08A closure observation及其
open-fd/RECORD/METADATA identities。它从 closure 中每个 verified distribution 的 exact normalized
METADATA `Requires-Dist` rows读取 edge；marker 只能由 registry固定 environment按`packaging==26.3` boundary
求值。node identity exact绑定 normalized name、version、wheel raw SHA、METADATA/RECORD digest；edge identity
exact绑定parent/child、original requirement bytes、normalized specifier/extras/marker与requirement row digest。
root、nodes与edges按registry policy canonical sorted/unique；从root可达node/edge set必须与closure双向exact，
missing/extra/duplicate/cycle alias、wrong parent、marker environment substitution、caller graph/list或只比较node
set全部拒绝。graph observation同时绑定advisory reachability path；selected advisory distribution必须由root经
ordered exact edges可达，direct/transitive身份不可由label替代。

`DependencySecurityObservationFactory` 的1.1 branch只接受same-factory current graph authority、advisory/source/
applicability/residual authorities与current remediation registry/disposition。`transitive-dependency` P必须证明
至少一条长度大于1的exact reachable path、affected before node、approved fixed after closure、regression PASS与
fresh target；R使用foreign/missing/reordered/断链path在mutation前拒绝。`fix-unavailable` P必须证明affected
reachable node、current `approved-unavailable` disposition、没有被approved fixed closure冒充、完整 residual row
与exact owner route；它不执行升级或伪造fix PASS。R缺disposition、wrong advisory/revision、expired/foreign/
clone owner route或从missing fix推断 unavailable 时zero mutation。

task durable path复用ADR-0002 revision 6同时定义的
`category-completion-assessment:1.2.0` / input pair。`profile_id=dependency-security` 且scenario exact为上述graph
cases时，assessment只允许并要求closed `dependency_graph_projection`：task/revision/snapshot/epoch/six pins、
factory/advisory/bootstrap/两个registry、before/after closure、完整nodes/edges/reachability path、selected
disposition/residual rows/owner route、regression/target/action facts、all nested bodies/digests与projection digest。
其他dependency-security mandatory/vulnerable-graph仍使用既有1.0 path；migration branch、performance1.1或任意
cross-branch字段拒绝。它继续只提交既有`task.category_assessed`与单一referenced CAS，不新增table/event/
generic evidence API/DB/GraphRef。

issue、use、precommit、restart、coverage observer/factory/gate都重新byte-pipe读取current bootstrap/advisory/
graph/remediation registries与schemas，重新WP08A preflight并重建nodes/edges/path、applicability/residual/
disposition。precommit在全部hooks后fresh重算；restart只从task唯一current ref重读CAS并zero graph resolver/
mutation replay。foreign/clone/stale factory/graph/disposition、cross-advisory、edge omit/add/reorder、marker/env drift、
registry/RECORD/METADATA replacement、expired disposition、wrong owner route、coherent re-sign或post-observation
replacement全部zero assessment/execution/observation/CoverageRecord，task/event/snapshot/object-ref/action/Git/
target/input不变。DNS/socket/proxy/index/scanner calls exact为零。

本 amendment exact覆盖`GEW-PSC-DEPENDENCY-SECURITY-TRANSITIVE-DEPENDENCY-P/R`与
`GEW-PSC-DEPENDENCY-SECURITY-FIX-UNAVAILABLE-P/R`四个records。migration rehearsal先完成时plan为216/oracles
108；两批合并后plan exact `220`、oracle bindings `110`、combined gate
`220 valid / 54 missing / passed=false`、static evidence`0/274`。每个record仍有独立Option C task/request/
execution/observation/oracle；coverage lifecycle复用exact combined gate后的finalize/revoke与pre-gate one-shot
abort。terminal后graph/remediation/current/restart/gate全部拒绝，immutable records和durable state不变。

### 8. Config-owned transitive advisory binding amendment

Human Owner 已选择保留真实 transitive 语义，不把 direct dependency 或 scenario label 当作传递证明。revision 8
只增加一个 config-owned offline advisory，并沿用 §1 的 monotonic registry/high-water、§2 的 bootstrap
protected closure 与 §7 的 graph/final-observation contracts。schema增量exact为：revision 7既有五组dependency
source/input pairs保持不变，revision 8只增加bootstrap 1.2 source/input这一组，因此相对revision 7累计六组；
不增加其他schema、runtime dependency、network、DB、GraphRef、WP-10或activation authority。

两个registry成员project-relative path exact且无alias：immutable generation-1 historical member为
`config/security/dependency-advisory-registry-v1.json`；current generation-2 member为
`config/security/dependency-advisory-registry-v2.json`。发布后的current head exact为forward generation 2：
`update_kind=forward`、
`previous_registry_digest=sha256-jcs-v1:46f950a2b2e2ad86df560f14ec4564ea1945bb3464ff11e801af215391d55fb6`、
`rollback_of_registry_digest=null`。generation-1 registry member、
`config/security/dependency-advisory-source-v1.json`、
`config/security/dependency-advisory-source-attestation-v1.json`及其bootstrap/schema/protected pins全部保留原始
bytes/digests/history，不允许原地改写或只保留digest。

generation 2新增immutable完整快照：
`config/security/dependency-advisory-source-v2.json`，identity
`urn:gew:dependency-advisory-source-artifact:v2`；以及
`config/security/dependency-advisory-source-attestation-v2.json`，identity
`urn:gew:dependency-advisory-source-attestation:v2`。对应source record exact identity为
`source:dependency-advisory:offline-v2@1`，issuer、artifact raw/semantic digest、attestation digest、record digest与
half-open有效期`2026-01-01T00:00:00Z <= clock < 2027-01-01T00:00:00Z`全部config-owned、immutable且current
比较完整row。v2 artifact 是完整snapshot，不是delta：其canonical identity set exact包含
`advisory:example-dependency:security-v1@2`与`advisory:cffi:security-v1@1`，且attestation双向绑定该artifact
ID/raw/semantic digest、source identity/revision与offline provenance。

generation-2 high-water exact为：旧`source:dependency-advisory:offline-v1@1`从active转为
`superseded/status_generation=2`，新v2 source为`active/status_generation=2`；旧packaging advisory revision 1
转为`superseded/status_generation=2`，新增语义保持但source改为v2的packaging revision 2与cffi revision 1均为
`active/status_generation=2`。registry仍保留全部v1 source/advisory immutable rows；active evaluation universe
exact只有packaging revision 2与cffi revision 1，且每个active advisory的`source_id/source_revision`都必须解析到
同一registry中的active、time-valid v2 source完整row及匹配的v2 artifact+attestation。fix-unavailable使用新增
packaging revision 2的same-advisory disposition row；旧revision-1 disposition/history保留但不能授权generation-2
active observation。source/advisory arrays与两类high-water arrays继续canonical sorted-unique。

current generation-2 bootstrap新增
`config/security/dependency-advisory-installation-bootstrap-v1.2.json`，identity
`urn:gew:dependency-advisory-installation-bootstrap:v1.2`，并以revision 8唯一新增的exact source/input schema pair
`urn:gew:schema:dependency-advisory-installation-bootstrap:1.2.0` /
`urn:gew:schema:dependency-advisory-installation-bootstrap-input:1.2.0`扩展1.1 graph projection；1.0/1.1
bootstrap与schemas继续作为历史protected bytes。1.2的`source_snapshot_history` rows按generation exact绑定
`1→config/security/dependency-advisory-registry-v1.json→v1 artifact→v1 attestation`与
`2→config/security/dependency-advisory-registry-v2.json→v2 artifact→v2 attestation`的member path、ID、source revision、raw/semantic/
attestation/registry digests；current bootstrap及graph bootstrap同时protect/ship v1与v2 artifact、attestation、
两代registry bytes和历史bootstrap/schema bytes。新增bootstrap schema branch要求history closed、ordered、
contiguous、双向exact且current generation row=2；旧bootstrap/schema bytes继续仅解释generation 1，不被重签。
两个registry member不能通过symlink、alternate path、same basename或caller alias互换；history row与protected
closure必须对上述project-relative path、registry generation/digest及对应snapshot/attestation双向exact。
old-source omission、v1 registry配v2 snapshot、v2 registry配v1或delta snapshot、artifact/attestation交叉、history
remove/reorder/replace、同path replacement或全套coherent re-sign但protected history pins未变，全部在registry/
applicability/graph/final issuance前拒绝并保持zero writes。

新增 cffi advisory body 的配置语义冻结为：`ecosystem=pypi`、`distribution_name=cffi`、
`affected_version_specifiers=[">=2.0.0,<3.0.0"]`、
`applicability_kind=verified-offline-closure-member`、
`residual_exposure_policy_id=policy:dependency-residual-owner-route-v1`、
`security_regression_policy_id=policy:dependency-security-regression-v1`。approved fixed closure exact 为
`closure:cffi:2.0.0`，`root_distribution_name=cffi`、`root_version=2.0.0`、
`security_regression_command_id=command:dependency-security-regression-v1`，且只有一个 pin：
`cffi==2.0.0`、wheel raw SHA-256
`828d3c089a39a57b70b98df41c62ac0949e4880a0995fadc0b6ae821a0bc035f`、RECORD raw SHA-256
`35619973c5fc1e8b00151fb14445bd6f091f616a3cdee1eb7e477cf7d29916d0`。before phase 必须由 affected
specifier判定受影响；after phase 必须独立匹配上述 approved fixed closure、regression PASS 与 fresh target。
相同版本号不允许把 before/after closure identity、phase、physical bytes或observation digest折叠成同一事实。

`transitive-dependency` 的 selected advisory 必须是上述 cffi identity，不接受 caller advisory。ordered
reachability path exact 为：

1. `distribution:graph-engineering-workflow@0.1.0`；
2. `distribution:cryptography@50.0.0`；
3. `distribution:cffi@2.0.0`。

对应 physical edges 只能来自 current verified METADATA rows：root 的 `cryptography==50.0.0` 与
cryptography 的 `cffi>=2.0.0`。path 必须至少三节点、两条连续 current edges，并与 current closure graph的
nodes/edges双向exact。现有 packaging advisory 的 `root→packaging` direct path、normalized/raw alias、caller
拼装或重签 advisory/graph/path、以及把阈值降为两节点全部拒绝；不得为通过测试修改 graph-policy 的
root/marker/edge order。

P observation exact task-bound到 unique transitive P task、current TaskSnapshot six pins、generation-2
advisory/bootstrap/graph registry、cffi advisory/source、before/after closures、ordered path、applicability、完整
residual rows、regression与fresh target。issue/use/precommit/restart/coverage/gate每次重读受保护安装bytes并重建；
restart只从task唯一current CAS ref恢复local authority，graph/action replay均为0且无网络。R的raw advisory alias、
direct packaging substitution、missing/duplicate/reordered edge、foreign/clone/stale graph、source/high-water漂移、
fixed-closure pin或phase mismatch必须在assessment/observation/record之前拒绝，task/event/snapshot/object/ref/
action/target/input writes均为0。

本 amendment 不改变四个 SliceB IDs、plan/oracle 数量或 gate 语义：完成 transitive 与 fix-unavailable 两对后
仍必须 exact 为 plan `220`、oracle bindings `110`、`220 valid / 54 missing / passed=false`，static evidence
`0/274`。任何实现失败都保持四IDs missing；禁止用 direct alias、阈值降级、caller advisory/graph、online
resolver/scanner 或 partial gate finalize 填补缺口。

## Invariants

- registry、source、advisory、closure、task 与 observation authority 均为 exact installation/current
  identity；self-digest 或 caller JSON 不能自我授权；
- applicability 与 residual exposure 只能由 WP08A-bound issuers从 same-factory registry/advisory/source及
  before/after closure identity计算；full residual rows覆盖current registry全量，caller truth/omission拒绝；
- WP08A parser/physical verification success 只证明 package closure，不单独证明 vulnerability/fix；
- advisory applicability、fixed closure、security regression 与 residual exposure 四类事实缺一不可；
- no network/no fallback/no activation；DNS/socket/proxy call count 必须为零；
- issue/use/precommit/restart 都重新读取 current authority，不接受 issuance-time cache；
- genesis、forward、higher-generation rollback 与 closed status high-water exact；comparison归属既有
  installation-verification boundary，WP-08无新head DB；revoked authority不复活；
- R rejection 先于任何 mutation，P/R 都不能改变用户 repository、安装目标或外部系统；
- combined gate、Option C unique tasks 与 coverage lifecycle 不因本 authority 分片或放宽；pre-gate abort
  不构成 gate decision，abort/finalize 互斥且 terminal candidate 永不重新授权。

## Options Considered

### Installation-pinned offline advisory registry plus WP08A closure — accepted

在不联网、不激活 dependency 的前提下，把 advisory truth、source provenance 与真实 offline wheel
closure 合并成可重放 current authority。代价是新增 registry/input/observation contracts、bootstrap
protected members 与严格 update/revocation matrix。

### Treat a fixture label or project command PASS as vulnerability truth — rejected

字符串和 command 只能证明 fixture/command 自称什么；不能证明 advisory source、affected version、
fixed closure 或 residual exposure，会把测试 double 冒充 scanner/authority。

### Reuse WP08A preflight as the complete security oracle — rejected

WP08A 证明物理 package/metadata/dependency closure integrity，不含 advisory/applicability/fixedness
语义。扩大其结论还会越过 ADR-0004 的 build/install/package-verification-only 边界。

### Online OSV/vendor/GitHub advisory or scanner — rejected for v1

会引入 DNS/network、remote freshness/identity、secret/proxy、availability、disclosure 与 external
communication authority；这些不在当前 Authority Envelope。未来若需要必须新开 architecture/Human
gate，不能成为 fallback。

### Defer all dependency-security coverage — safe fallback, not selected delivery path

保持 gate missing 是安全的，但不能完成 Human 已批准的 WP-08 dependency-security vertical slice。
实现/review 不收敛时仍回退到此状态，而不是伪发 record。

### Consumer-local pre-gate abort for uncommitted candidate — accepted amendment

partial P/R 或验证中止的 candidate 尚未产生 combined gate decision，却可能持有完整 opaque authority
graph。由签发 factory 自己的 exact capability 选择 abort 终态，可以在不改变 durable delivery state、
不伪造 gate 结论的前提下永久撤销 use authority，并使 cleanup 可确定收敛。

### Treat partial assessment as gate decision, or force process/repository shutdown — rejected

把 partial records 当作 combined decision 会弱化 `ReleaseCoverageGate`；关闭 caller-owned repository、
daemon 化、强制退出或依赖 GC 则会隐藏 lifecycle 缺口并改变 Option C/production resource ownership。
两者都不能作为 cleanup 手段。

## Consequences

- 新增版本化 advisory registry、source/input/observation schemas、installation bootstrap 与 protected
  source/package closure；业务 advisory 数据只在 config；
- application boundary 新增 registry/closure/observation factory，core 只持有 frozen universal facts；
- source checkout、installed wheel、archive/RECORD、expiry/revocation 和 same-path replacement attacks
  进入 mandatory test matrix；
- dependency-security E2E 成本高于 generic Profile column，但仍完全离线、disposable、serial；
- coverage factory 增加 consumer-local abort capability 与单调 terminal state；没有新持久 schema/row，
  immutable records 与合法 gate decision 的 audit bytes 不变；
- revision 7 只再增加 protected graph/remediation registries、五组 versioned source/input contracts、
  installation bootstrap 1.1 projection 与 category-completion-assessment 1.2 dependency branch；它不增加
  resolver/scanner、generic task evidence API、repository row/table 或 caller-owned graph truth；
- revision 8只再增加bootstrap 1.2 source/input一组（revision 7五组加本组累计六组），以及两个无alias的
  generation-specific registry members、v2完整source snapshot/attestation与双代protected history；v1 bytes不变；
- 本 ADR 不新增 DB/GraphRef pin、network、daemon、external scanner、deployment 或 ReleaseInstallManifest。

## Validation and Rollback

实现前先建立 production-path RED，覆盖 canonical A→B、stale C rejection，以及 missing/extra/duplicate/
alias advisory、wrong/expired/revoked source、foreign/clone issuer、affected/fixed specifier substitution、
closure/member/RECORD/METADATA/packaging parser drift、budget exhaustion、regression/result replacement、
caller residual bool/list/omission、cross-advisory/source、full residual row缺失、registry coherent re-sign、
same-path replacement、use/precommit/restart mutation、
DNS/socket/proxy attempts。所有拒绝均要求 zero task/event/snapshot/object/ref/action/Git/input mutation。

schema matrix还必须逐一删除/替换10组source/input pair，改变 nested child body/digest、错误排除child digest、
registry/bootstrap/protected-member pin、observation child digest；update matrix覆盖genesis非1/non-null previous、
generation downgrade/skip、wrong previous、high-water decrease/removal、invalid status transition/resurrection、
`not_before <= clock < not_after`边界/clock rollback及higher-generation rollback。

验证还必须证明 24 distinct records、12 distinct oracles、unique task IDs、serial/Option C digest equality、
combined `170/104/false`，以及 lifecycle 两条互斥分支：exact combined decision 后 finalize/revoke；无
combined decision 的 exact candidate abort/revoke。abort matrix覆盖 foreign/clone/partial/wrong candidate、
projection substitution、重复、并发 gate/finalize、prepare/consume/逐 registry cleanup 的 in-process
injected-exception cuts；尤其覆盖 tuple commit 前、tuple 后 return 前、lost-return same-cap retry、consume 后
prepare reject/same-cap abort retry，以及独立 process-termination 后 authority 不可恢复。每个 rejection zero writes，
terminal 后所有 use/current/restart/register/gate 入口拒绝，immutable documents/durable
signatures不变。两条分支 cleanup 均 <120s，且 WP08A focused regression保持 parser boundary与WP10 block。

revision 7 graph/remediation matrix additionally covers exact METADATA-derived root/nodes/ordered edges、
direct-versus-transitive reachability、marker environment、advisory path、explicit remediation disposition、
residual owner route 与 assessment 1.2 projection。missing/extra/reordered edge、wrong parent、cycle alias、
foreign/clone/stale graph factory、1.0/1.1 cross-use、expired/wrong-advisory disposition、missing-fix inference、
caller graph/owner route、METADATA/RECORD/registry/bootstrap replacement及coherent re-sign全部必须在mutation前
zero-write拒绝；restart从task唯一CAS重建且graph resolver/action replay均为零。完成四records后，连同已批准
migration rehearsal eight records，production plan/oracle/gate必须exact为`220/110/220 valid,54 missing,false`，
static evidence保持`0/274`，不能签发WP-08 exit。

若 implementation、contract conformance 或 independent review 不通过，rollback 是不注册/禁用
dependency advisory observation factory、保留既有 146 immutable coverage records 与 audit objects、让
dependency-security 24 IDs 继续 missing；已创建但未提交 gate 的 candidate 只可用 exact abort capability
永久失效，不能 fabricated gate/finalize/reopen。若 registry 已发布，使用更高 generation rollback head并
保留 revocation high-water；不得删除历史 observation、恢复 revoked advisory、联网补证或把 WP08A
preflight 降级为 vulnerability PASS。

revision 7未收敛时的局部rollback是不注册graph/remediation factories、bootstrap 1.1、assessment 1.2
dependency branch及四个scenario bindings；corrected final217的`208 valid / 66 missing / false` records与既有
dependency-security mandatory/vulnerable-graph evidence保持current，新增四IDs继续missing。不得删除或重签
历史advisory/closure/coverage records，也不得以online resolver/scanner或WP10 activation补齐缺口。

## Traceability

- PRD FR-04、FR-05、FR-09、FR-10、FR-14、FR-17、FR-18；
- Spec §7.2、§11.2；Impact §14；Plan WP-08/WP-08A；Test Plan §12、§14；
- ADR-0003 deterministic contracts；ADR-0004 r6/r7 package parser and physical closure。
