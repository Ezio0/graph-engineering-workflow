# Graph Engineering Workflow — Impact Analysis

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
