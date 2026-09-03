# ADR-0005: Recovery-Claim Compensation

## Status

Accepted — revision 2，2026-08-14；Human Owner decision
`GEW-WP05-RECOVERY-CLAIM-DECISION`；review r1 findings WP05-ADR5-R1-001～004 revised，
independent re-review pending。

### Review r1 finding disposition

| Finding ID | Disposition | Verification anchor |
|---|---|---|
| `WP05-ADR5-R1-001` | Resolved in author revision 2：expired lease 只有三类 exact transaction，其他 commit 仍要求 live/latest | Spec §5.4.1 transaction table 与 §8.4.1 authoritative reference |
| `WP05-ADR5-R1-002` | Resolved in author revision 2：稳定 attempt ID、transaction replay CAS 与 start-committed no-auto-replay state machine | Spec §5.4.1、§8.4.1；Test Plan §10.2 attempt/concurrency/crash cases |
| `WP05-ADR5-R1-003` | Resolved in author revision 2：三个 backend-neutral ports 的 revisions、events、payload、delta、claim/reducer state、recovery/rejection 已冻结 | Spec §5.1 与 §5.4.1；claim lifecycle 在 reconcile 前始终 unresolved |
| `WP05-ADR5-R1-004` | Resolved in author revision 2：Impact 登记 ADR-0005 disposition/blocking gate并移除 three-ADR-complete 结论 | Impact §14.1、§15、§18 |

## Context

一个非幂等 action 在 `action.execution_started` 与 durable `UnresolvedActionClaim` 提交后
可能崩溃。原 lease 随后可以过期，但 claim 必须继续冻结完整资源集，避免未知副作用被
普通新 action 覆盖。目标 reconciliation 能证明已执行或未执行时无需补偿；无法恢复期望
状态、且 Owner 单独批准 rollback 时，需要在不重放原 action 的前提下执行 compensation。

普通 execute 协议不能安全承载这个场景：获取 replacement lease 会与原 claim 冲突并推进
fence；创建第二 claim 会让同一未知副作用拥有两份资源真相；在 target verification 前释放
原 claim 又会打开并发窗口。WP-03 现有“expired lease 只允许 exact claim reconciliation”也
不足以先 durable 记录 compensation start，再跨 tool call 保持资源排他。

Human Owner 已批准一个窄化的 recovery transition。它不启用真实外部 action，也不授权
commit、push、merge、deploy、release 或 external communication。

## Decision

增加 backend-neutral **Recovery-Claim Compensation Transition**。它复用原 action 的唯一
unresolved claim；不是 lease renewal、normal execute、original replay 或第二个 action claim。

进入 transition 前，deterministic gate 必须在持有 installation shared 与原 claim 完整资源集的
call-span exclusive locks 时，于同一 repository coordination boundary 验证：

1. claim 仍为 unresolved，且精确绑定 original action、task、lease identity 和 started event；
2. 请求 task、lease ID、完整 canonical sorted resources 与 claim 完全相等，不能缺失或增加；
3. 每个 fencing token 仍是 repository 的 latest fence；lease 可以 expired，但不得被替代、
   renewed 或 superseded；
4. original action 仍为 `executing/unknown`，禁止调用或重放其 command/tool/payload；
5. compensation 有独立、当前、未 revoked/superseded/expired 的 exact authority，绑定 rollback
   prepared-action digest、Owner/runtime/lineage、同 task、同 target、同完整 resources、当前
   baseline/snapshot、rollback payload、verification plan 和 disclosure plan；
6. action kind 精确为 compensation/rollback，且不能借此执行其他 action class；
7. deterministic fake adapter/target capability 满足当前 Authority Envelope；生产 external action
   仍关闭。

全部通过后，repository transaction 追加 `action.compensation_execution_started`，并把
compensation authority、prepared action、original action、original claim、task、same lease、完整
resources/latest fences、target snapshot 与 disclosure digests 精确绑定。该 transaction 只把原
claim 关联的独立 recovery-attempt substate 标记为 `started`；claim lifecycle state 本身始终为
`unresolved`，因此既有 acquire-many freeze 不变。transaction 不消费 claim、不创建第二 claim、
不授予 lease。只有 started durable 且 call-span locks 仍在持有时，adapter 才能调用 compensation
tool。

repository 从 task、original claim/action/started event、compensation action/authority/prepared
digest、same lease、完整 resources/latest fences 与 expected claim revision 的 exact tuple 派生稳定
`compensation_attempt_id`，并唯一派生 start/receipt/reconcile transaction IDs。start 未提交时，同
attempt/request 可重跑；start 已提交时，同 transaction/request 只返回既有结果而不再次授予 tool
call，任何 distinct start/action/authority fail closed。此后恢复只有 fresh target query、
started-bound receipt、fresh reconciliation 或 Human/manual route，没有 execute/replay edge。

tool 返回或 timeout 后，在释放 call-span locks 前，raw receipt body/digest 与
`action.compensation_receipt_recorded` 必须 durable，且精确绑定 started event、original claim、
compensation action、task、target identity 和 fence set。crash/timeout/ambiguous receipt 不触发
自动 replay；恢复时只允许 fresh target query、再次进入同一 recovery gate 或 Human/manual route。

原 claim 只能在独立 fresh read-only target observation 证明 rollback expected postcondition 后，
由同一 atomic commit 追加 `action.compensation_reconciled` 并消费。verification 失败、陈旧、
identity 不符或状态不确定时，claim 保持 unresolved，资源继续冻结。补偿失败不能恢复原 action
的 replay 权限。

## Invariants

- 同一个未知 original action 始终只有一个 unresolved claim 和一套冻结资源真相；
- start/receipt 只改变独立 recovery-attempt substate；claim lifecycle state 保持 `unresolved`，
  直到 fresh reconciliation transaction 原子写终态；
- recovery request 的 task/lease/resources/fences 必须与 claim byte-for-byte/exact-set 一致；
- expired lease 只在该 compensation-only transition 和既有 reconciliation path 中被接受；
- 不得 acquire normal replacement lease、renew 原 lease或创建第二 claim；
- 不得在 fresh target verification 前消费、释放或缩小原 claim；
- compensation authority 不能推导自 original authority，也不能覆盖其他 action kind；
- started 与 receipt 的 durable points 分离，tool call 不位于 database transaction 内；
- call-span locks 覆盖 started durable → tool call → receipt durable；
- original action 永不由 recovery transition 自动 replay。

## Options Considered

### Reuse the original exact claim — accepted

保留唯一资源真相，允许在 lease expiry 后安全记录补偿进度，并继续使用 WP-03 的 latest-fence、
claim freeze 与 call-span lock 语义。代价是 repository port 和 crash matrix 需要增加窄化 transition。

### Acquire a replacement lease and create a second claim — rejected

replacement lease 会被原 claim 阻止，强行授予又会推进 fence、制造两份冲突所有权，并可能让
原 claim 无法按 latest fence reconciliation。

### Release the original claim before compensation — rejected

这会在补偿调用或验证失败时允许其他 action 进入相同资源，破坏 unknown-effect containment。

### Allow only manual reconciliation and never compensate after expiry — rejected for v1

安全但不能满足已批准的 rollback recovery 能力。Human Owner 已选择实现窄化 recovery transition。

## Consequences

- repository ports、event/action journal schema 与 reducer 需表达 compensation-in-progress、started、
  receipt 和 reconciled，同时保持原 claim identity 不变；
- recovery validation 必须独立于 normal live-lease execute assertion，且只能接受 exact unresolved
  claim/latest fences；
- security state 与 task revision/snapshot 的演进必须与 recovery authority issuance 一致，不能让
  stale security state 被调用方覆盖；
- crash recovery 增加 started 前后、tool effect 前后、receipt durable 前后、target verify 前后和
  claim consumption 前后的 mandatory cases；
- migration/export/doctor 必须保留并验证 recovery-in-progress claim 与相关 receipts/events；
- 该决定不改变 `real_external_actions_enabled=false`，r1 仅使用 deterministic fake target。

## Validation and Rollback

实现必须证明 live 与 expired original lease 都满足 exact claim path；wrong task/lease、missing/extra
resource、stale fence、普通 action kind、original replay、second claim/new lease、缺独立 authority、
锁丢失和 stale target evidence 均在 compensation tool counter 为 0 时拒绝。每个 crash point 后
只能恢复为未调用、claim 仍冻结的 unknown，或 receipt durable 后经 fresh target verification
消费 claim；不能出现 partial claim release。

若实现或 review 不通过，rollback 是禁用 recovery compensation transition，保留原 action journal、
receipt 与 unresolved claim，并路由 target reconciliation/Human manual coordination；不得删除审计
事实、释放 claim 或回退成 replacement lease/second claim 方案。
