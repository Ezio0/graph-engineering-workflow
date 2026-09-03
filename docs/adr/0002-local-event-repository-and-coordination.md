# ADR-0002: Local Event Repository and Coordination

## Status

Accepted — revision 6 migration-rehearsal authority amendment，2026-09-01；Human Owner 已批准
在既有 `InstallationMigrationRepository`/ledger 上建立 WP-08 consumer-local rehearsal authority；
revision 1～5 的 repository、lock、migration 与 activation 语义保持不变。revision 6 实现仍以
独立 architecture review、exact schema/bootstrap conformance 与 TDD 为 blocking gate。

## Context

Human Owner 已批准 backend-neutral event-sourced repository 语义。v1 concrete backend
必须在单机、无 daemon 的条件下原子提交 event/head/snapshot/catalog/lease/action claim，
支持多进程、crash recovery、corruption detection、owner-only state、export/import 和
content-addressed bodies。

最危险的失败不是吞吐不足，而是 partial visibility、重复外部动作、陈旧 lease、未知
副作用后错误解锁，或备份/迁移遗漏 committed state。

## Decision

v1 采用 **单个 SQLite metadata/event database + filesystem content-addressed object
store**：

- SQLite 保存 events、commit heads、snapshots、catalog、schema versions、runtime
  bindings、authorities、actions、reviews、artifact/evidence metadata、leases、monotonic
  fencing counters、durable `UnresolvedActionClaim` 和 migration ledger；
- 一个逻辑安装/Owner scope 使用一个数据库，使所有本地任务的 catalog、resource lease
  和 action claim 处于同一 transaction authority boundary；不为每任务拆库；
- object bodies 以 SHA-256 路径存于同一 data root 的 owner-only filesystem；object writer、
  reader、GC/purge 与 export 全部遵守本 ADR 的 object coordination protocol，不能直接
  操作物理路径；
- SQLite 采用 rollback journal `journal_mode=DELETE`、`synchronous=EXTRA`、foreign keys
  ON、显式短写事务和 configurable busy timeout；禁止 network filesystem 和多主机访问；
- 所有普通、doctor、backup 和 migration connection 都只能由 fail-closed
  `ConnectionFactory` 创建，并在首次事务前完成本 ADR 的统一 open contract；
- doctor 以 capability/conformance 而非偶然系统版本判断可用性，并记录 SQLite/VFS
  version；如果未来启用 WAL，必须要求 **3.51.3+ 或包含官方 WAL-reset 修复的 backport**，
  因为官方披露的旧版 WAL 多连接并发 checkpoint bug 可导致数据库损坏；
- application transaction 使用显式 `BEGIN IMMEDIATE` 获取唯一 writer，执行 revision
  CAS、event/head/snapshot/catalog/lease/claim 一次提交；agent/tool 调用绝不位于 DB
  transaction 内；
- lease/fencing/claim 是应用协议记录，不把 SQLite writer lock 当跨外部调用锁；
- 无原生 fencing adapter 的 call-span lock 使用本 ADR 定义的 process-local mutex + 稳定
  lock inode + OS advisory exclusive lock；进程退出会释放 OS lock，但 durable claim 继续
  冻结资源，直到 reconciliation；
- backup/export、migration/import 和 activation 使用下文的唯一状态机；不得 raw copy、
  rename、unlink 或直接激活活动 `.db`、journal、objects 或历史 bundle；
- repository ports 与 bundle 格式仍保持 backend-neutral；SQLite schema 不是公开 API。

选择 rollback journal 是因为 v1 无 daemon、事务短、写入频率低，可靠性和可恢复性优先
于 reader/writer 吞吐。SQLite 官方将 DELETE + `synchronous=EXTRA` 列为 ACID，并由 hot
journal 自动恢复 interrupted transaction；它也避免 WAL checkpoint、`-wal/-shm` 作为
额外持久单元和当前已知 WAL 多连接缺陷。所有 code 仍必须处理 `SQLITE_BUSY` 并走有限
retry/block route，长读取通过分页和 transaction boundary 控制。

### Connection open contract

`ConnectionFactory.open(role)` 是数据库唯一入口。每次 open 必须：

1. 对 canonical data root 和 database path 执行 no-symlink、owner、mode、local-filesystem、
   regular-file 和 approved VFS/library identity 验证；所有 connection 使用同一 canonical
   path、SQLite library/VFS 和 database identity；
2. 在初始化/maintenance exclusive lock 内设置 `journal_mode=DELETE`；每个 connection 在
   事务前设置并回读 `synchronous=EXTRA`、`foreign_keys=ON`、configured finite
   `busy_timeout` 和 `locking_mode=NORMAL`，并回读 journal mode；任一结果不符即关闭拒绝；
3. macOS 设置并回读 `fullfsync=ON`，Linux 要求本地 VFS `xSync`/filesystem durability
   conformance；doctor 记录 OS、filesystem/VFS、SQLite runtime/compile options 和 sync
   capabilities。无法满足 power-loss contract 时 repository 只读 blocked；
4. connection 绑定创建 PID 和 thread，使用 `check_same_thread` 等效保护；每次操作验证
   PID，fork child 必须丢弃继承 connection 并重新 open，connection 不跨 thread/fork 共享；
5. role 只能控制最小权限/允许语句，不能减弱 PRAGMA。任何活动 connection 期间禁止
   SQLite API 外的 raw copy、move、replace、unlink、VACUUM-into 或 sidecar 操作。

`SQLITE_BUSY` 走由版本化配置给出的有限 retry/backoff，耗尽后产生结构化 blocked；不能
无限等待或在失败后绕过 transaction。每个 transaction 都显式 begin/commit/rollback，
不依赖 Python legacy implicit transaction behavior。

### 全局 lock order 与 call-span lock

installation control directory 与 data root 初始化以下 owner-only、regular、永不删除/
rename 的稳定 lock files；open 使用 `O_NOFOLLOW|O_CLOEXEC` 等效保护并以 `fstat` 验证
device/inode/owner/mode：

- control directory 中唯一的 `installation-maintenance.lock`：普通命令在读取 active manifest
  **之前**取得 shared，并持有到命令全部读取、写入或外部调用结束；upgrade/activation/一致
  export 和 activation recovery 持 exclusive。它的路径、inode 和 installation ID 不随 active
  repository 切换；
- `object-maintenance.lock`：object reader/writer 持 shared；GC/purge 持 exclusive；
- `resources/<sha256(canonical-resource-id)>.lock`：call-span exclusive locks。
- `resources/publication-<sha256(object-digest)>.lock`：同 digest publication/cleanup 的独立
  exclusive tier；它不属于业务 resource ID 空间，不能参与或依赖 canonical resource 字典序。

macOS 与 Linux 都固定使用 `fcntl.lockf` 的 POSIX whole-file record lock（`LOCK_SH`/
`LOCK_EX`，有限等待或 `LOCK_NB` 重试），不能换用语义不同的 `flock`、OFD lock 或仅依赖
文件存在性。一个 PID 内只有 `LockedFileRegistry` 可以 open/close 这些 inode；它为每个
canonical lock ID 保留唯一 descriptor，并在 OS lock 之前取得不可重入的 process-local
read/write mutex。任何其他代码再次 open 或 close 同一 inode 都是 fatal invariant violation，
因为 POSIX record lock 可能因同进程的其他 descriptor close 而释放。

lock handle 绑定创建 PID，acquire/release/状态查询都复核 PID。runtime 在启动时注册
`at_fork`：child hook 把继承 registry 标为 poisoned、关闭继承 descriptors、清空 mutex/
ownership state，且在重新初始化 registry 并重新取得 installation shared lock 前拒绝任何
repository/action API。POSIX record lock 不由 child 继承；child 对继承 handle 的 release 是
错误而不是 unlock，不能影响 parent。`O_CLOEXEC` 确保 exec 不保留 descriptor。若 runtime、
filesystem 或测试不能证明这些语义，所有 mutation 和 external action fail closed。

唯一全局顺序是：

```text
installation-maintenance
  → process-local resource mutexes + OS resource locks（canonical resource ID 升序）
  → per-digest publication lock
  → object-maintenance
  → SQLite transaction
```

不能持 SQLite transaction 等待任何 OS/process lock。多资源获取必须预先规范化、去重、
排序；任一 mutex/lock 失败则按逆序释放全组，不能部分推进。GC/export 不获取 resource
locks；需要同时操作 object 和 DB 时也遵守上述顺序。每个普通命令取得 installation shared
后读取并验证一次 `ActiveRepositoryManifest`，把 installation ID、generation、epoch 和
repository identity 绑定到 command context；所有 connection/commit/action gate 再验证该
tuple，且 shared lock 持到完整调用结束，因此旧 generation 的进程不能跨 activation 继续。

无原生 fencing 的 action 在调用前取得全部 process/OS resource locks，然后在 DB
transaction 中验证 authority/fence 并 durable commit `action.execution_started` + claim；
随后在无 DB transaction 时持锁覆盖完整 tool call；raw receipt object durable 且 receipt
event DB commit 完成后才释放 locks。reconciliation 可以之后发生，claim 在此期间继续
阻止新 action。lock file identity/permission 变化、unlink/replace 尝试或平台不提供该语义
时，对应外部 action fail closed。

object publication API 必须与上述 call-span scope 组合：若当前线程已持有同 registry 的
installation lock，它复用该 scope，不得重入 acquisition；在全部 action resource locks 之后
取得独立 per-digest publication lock，再取得 object shared。standalone caller 仍由 API 自行
取得/释放 installation shared。publication tier 的 rank 固定高于所有业务 resource、低于
object maintenance，因此任何合法 resource ID 的拼写都不改变 lock order。

### Object publication、GC 与 purge

object writer 在 `installation-maintenance shared → required action resources（若有）→
per-digest publication exclusive → object-maintenance shared` 下：

1. 写入该 data root 的受保护 staging directory，以不可预测 `write_id` 命名；写完后验证
   bytes/digest/size/mode，fsync file 和 staging directory；staging 不在 GC candidate 集；
2. 若 final digest path 已存在则验证内容；否则 no-replace atomic rename 到 final path 并
   fsync object directory。整个 staging → final → metadata commit 窗口持续持有 shared
   object lock，因此 GC/purge 不能删除 about-to-be-referenced object；
3. 在同一锁内提交引用 metadata；成功后释放。若 DB commit 失败，final object 是无引用
   orphan，不是 trusted reference；进程 crash 释放 OS lock 后才可由 recovery/GC 处理。

reader 在 shared object lock 内先验证 committed reference/lifecycle，再打开 no-symlink
regular file 并校验 digest。GC/purge 持 exclusive object lock，在 SQLite transaction 中
只把 **无 committed reference、pending writer、export hold、retention/legal hold、claim、
rollback dependency 或 quarantine dependency** 的对象 CAS 为 `deleting`；commit 后删除并
fsync directory，再在新 transaction 标为 `deleted`。crash 留下 `deleting` 时 recovery
幂等完成；任何 active reference 都不能指向 `deleting/deleted`。该状态机和 exclusive lock
共同保证清理不会与新引用竞态。

## Options Considered

### SQLite + filesystem objects — accepted

优点：成熟的 atomic commit/recovery、单 writer/multi-reader、constraints/index/query、
Python stdlib adapter、一个 transaction 覆盖全局 task/catalog/lease/claim metadata。object
store 避免把大正文和二进制塞入数据库，同时保留 content addressing。

缺点：依赖 SQLite/VFS/fsync 正确性；rollback journal 下 reader/writer 互相阻塞时间高于
WAL；需要维护 DB + objects 的一致备份。产品本来就是本地交互式单机且使用短事务，
剩余风险由 busy route、capability gate、verified write protocol 和 conformance suite 控制。

### 纯 filesystem framed event segments — rejected for v1

可审计且概念贴近 append-only event log，但跨 task catalog、多个资源 lease、fencing
counters、claims、head/snapshot 的原子发布需要自建 transaction coordinator、lock order、
crash recovery 和索引重建。可靠性优先下，这比利用 SQLite 更容易产生细微错误。

### SQLite-only including bodies — rejected

事务简单，但大 artifact/evidence 增长、streaming、dedup、quarantine、purge 和导出成本
更高。metadata + immutable objects 保持事务关键区短，并让正文按 retention 独立处理。

### 每任务一个数据库 — rejected

无法在一个本地 authority boundary 内原子维护跨任务资源冲突与 fencing，会重建分布式
协调问题。

### SQLite WAL — rejected for v1

WAL 能提高 reader/writer 并发，但引入 checkpoint 和必须随数据库保留的 `-wal/-shm`；
`synchronous=NORMAL` 还会在 power loss 时丢失 durability。官方 2026 年披露的 WAL-reset
bug 进一步说明多连接/checkpoint 组合需要严格版本门槛。当前工作负载不足以抵消这些
复杂度；未来若实测 rollback journal 阻塞成为 PMF 问题，可用 crash/concurrency 证据
重开 ADR。

## Transaction and Failure Semantics

1. 获取或复用 installation shared，取得必要的 canonical resource locks、per-digest publication
   lock 和 object shared lock，顺序如上；
2. object body（若有）按 publication protocol verified durable；
3. `BEGIN IMMEDIATE`，验证 expected revision、authority、leases/claims/fences；
4. 插入 framed events、transaction idempotency record、new head/snapshot/index deltas；
5. 对 execute-start 同时插入/更新 lease、fence 和 durable claim；
6. commit 返回后才允许相应 graph transition；真实 tool action 还需 Execute Gate；
7. crash 后 SQLite recovery 只暴露旧或新 transaction；objects 中未引用 orphan 不可信但
   可安全 GC；缺少 referenced object 则 integrity blocked。

SQLite lock 只保护本地 metadata transaction。外部系统 concurrency correctness 仍来自
目标原生 precondition/fence，或 call-span OS lock + durable claim；不能用 database commit
推断外部副作用已完成。

## Backup and Export Snapshot

一个成功 bundle 只对应一个 `ExportSnapshotIdentity`：`export_id`、source repository/
activation epoch、SQLite backup head/revision/schema manifest digest 和 object manifest digest。

唯一内部原语 `create_export_snapshot_under_installation_exclusive(lock_owner_token)` 要求调用者
已经持有 installation-maintenance exclusive，并验证 token 的 PID、descriptor/inode、mode、
installation ID 和 ownership generation。它**从不**重新取得或释放 installation lock；递归
进入、shared token、陈旧 generation 或非当前 PID token 一律 fail closed。它自行取得并释放
object-maintenance exclusive，并执行下面 step 2～3。公开 `export()` wrapper 负责取得一次
installation exclusive、调用该原语，并只在 snapshot/hold 已 durable 后释放 installation
lock；migration 则把自己全程持有的 token 传给同一原语，并保持该 exclusive 直到最终
`active|blocked` manifest 已 durable。不存在第二套 snapshot 算法。

完整 bundle 流程为：

1. public export wrapper 或 migration owner 获取唯一 installation-maintenance exclusive，阻止
   新命令和 action start；已有 call-span holder 必须先结束并释放 installation shared lock；
   随后原语验证 ownership token 并取得 object-maintenance exclusive；
2. 原语用 ConnectionFactory/SQLite online backup 写入 staging DB，fsync 并运行 integrity、event
   replay 和 schema checks；**仅从完成的 backup DB** 查询精确 referenced object set、
   versions 和 head，生成 snapshot identity/object manifest；
3. 原语在 live DB 中 durable 写入 `export_hold(export_id, snapshot_identity, object_digests)`；
   GC/purge 必须遵守该 hold。hold commit 后原语只释放 object exclusive；public wrapper 此时
   才释放 installation exclusive，migration owner 绝不释放；
4. 按 manifest 复制 objects 到 staging bundle，每个对象重新验证 size/digest；写入 schemas、
   registry/Graph/Profile manifests 和 canonical bundle manifest，fsync 全部文件/目录；
5. 在隔离 reader 中从 bundle DB 重新导出 manifest 并逐项比对，再 replay/integrity scan；
   只有全部成功才 atomic publish bundle directory/reference，随后清除 live export hold；
6. crash 留下的 hold 默认保留。recovery 只有在证明没有 active exporter，且不存在已发布
   bundle 依赖后才能清除；多保留 object 优于误删。

持续写入、tombstone 或 GC 不能混入 snapshot，因为 step 1～3 固定 backup 与 hold，step 4
以后源任务可以继续但 manifest 不变。raw copy 活动 DB/journal 永远不是合法 backup。

## Migration, Import and Activation

installation control directory 独立于具体 backend，包含上述唯一、稳定的
`installation-maintenance.lock` 和以 fsync + no-replace/atomic-rename 管理的 versioned
`ActiveRepositoryManifest`。manifest
记录 installation ID、monotonic activation generation/epoch、active repository identity、
release/contract versions、mode（`verifying|active|blocked`）、previous ref 和 digest。
resource fencing identity 包含 installation ID + activation epoch + per-resource counter；
installation fencing high-water 不能由普通 backup/import 覆写或降低。control directory
丢失、rollback 或 digest 不一致时所有 external action blocked。

当前 active repository 的 migration 状态机是：

```text
requested → upgrade_locked → quiescence_verified → exported
  → imported_isolated → replayed → compatible → activation_prepared
  → verifying_reference → post_switch_verified → active → completed
```

- 从选择当前 active repository 之前，到 export/import、两次 manifest switch、post-switch
  verification、rollback 或 crash recovery 完成为止，全程持同一个 installation-maintenance
  exclusive；在 `quiescence_verified` 要求无 live task/resource lease、call-span lock、
  `UnresolvedActionClaim` 或 running mutation；否则停止；
- 从当前 head 调用 §Backup 的
  `create_export_snapshot_under_installation_exclusive(current_owner_token)` 生成 verified bundle；
  该调用不得重新取得或释放 installation lock。在隔离 root 导入，执行唯一 schema transform
  path、replay、integrity/conformance 和 compatibility；candidate 设置下一 activation epoch，
  所有 fencing counters 不低于 installation high-water；
- `activation_prepared` 写入 candidate/previous refs、digests 和 rollback record。第一次 atomic
  active-manifest switch 进入 `verifying`，此时 candidate 只读，不能创建 task 或执行 action；
- candidate doctor/post-switch verification 全部通过后，以更高 manifest generation 切换
  `active`。失败则以再高一代 manifest 切回已验证 previous tuple；旧 repository 保留且未
  被 candidate 修改。任一 crash 后，在同一 installation exclusive 下只由最高 valid
  committed manifest 决定恢复目标；exclusive 释放前 manifest 必须为 verified `active` 或
  explicit `blocked`，绝不能把 `verifying` candidate 暴露给普通命令；
- active 后的回退也是一次新 migration/activation，activation epoch 继续递增，绝不把旧
  pointer、DB 或 counter 原样倒回。

历史 bundle/旧 backup 永远先导入 `quarantined_restore`，不能直接 executable activation。
若当前 active audit 可用，系统必须证明 export 后没有遗漏 action，或把所有后续 action/
claim/reconciliation 合并入候选；若无法证明，则生成 installation-wide `restore_gap`，禁止
全部 external action。解除需要逐资源 target-state reconciliation、重新建立高于 high-water
的 fence 和必要 Human action reauthorization；不能因为旧 bundle 中没有 claim 就认为安全。

schema/backend 迁移失败只留下隔离候选和审计记录；active repository 不变。切换只能消费
backend-neutral bundle，SQLite schema/文件布局不能成为另一个 backend 的输入契约。

### WP-08 migration rehearsal authority amendment

Human Owner 批准在**完全 disposable、owner-only private root** 中复用上述 production
`InstallationMigrationRepository`、migration ledger、bundle、active manifest、maintenance lock、epoch/fence
与 crash recovery，建立 `MigrationRehearsalFactory`。它只证明 migration Profile 的 rehearsal truth；不安装
产品、不切换真实 installation、不访问用户 repository，也不授予 WP-10 activation、deploy、release、网络或
外部通信。factory 是 `eq=False`、consumer-local opaque issuer；只能由 exact current installation bootstrap
注册，使用 closure-held strong issuance ledger，不接受 caller mapping、self-digest、相等对象、`object.__new__`
或 module-global identity table。

版本化数据成员固定为：

- `config/migration/migration-rehearsal-registry-v1.json`，registry identity exact 为
  `urn:gew:migration-rehearsal-registry:v1`；
- `config/migration/migration-rehearsal-fixture-v1.json`，包含 canonical A/B schema/version、ordered source rows、
  partial-data case/disposition 与 expected integrity digests；
- `config/migration/migration-rehearsal-transform-manifest-v1.json`，包含唯一 A→B/B→A transform IDs、
  source/target contracts、implementation/source digests、input/output projections 与 compatibility facts；
- `config/migration/migration-rehearsal-installation-bootstrap-v1.json`，bootstrap identity exact 为
  `urn:gew:migration-rehearsal-bootstrap:v1`，固定 registry/fixture/transform、Profile schema registry、
  distribution root/version、singular RECORD、source/build attestation 与 ordered protected closure。

registry 根 exact order 为 `schema_version, registry_id, fixture_manifest, transform_manifest,
compatibility_policy, crash_cut_ids, registry_digest`。transform manifest 根 exact order 为
`schema_version, manifest_id, transforms, manifest_digest`；transform rows 按 stable transform ID canonical
sorted/unique，exact 绑定 source/target contract versions、single transform path、transform code/source digest、
input/output projection、partial-data disposition enum `preserved|defaulted|rejected|owner-route` 与 transform digest。
caller transform、动态 import、任意 executable、best-effort field drop 或 hidden fallback 全部拒绝。

Profile schema registry 必须双向 exact 登记以下 source/digest-input pairs；每个 input projection 只排除自身
唯一 derived digest，parent 保留完整 nested child body/digest：

| Contract | Source schema ID | Digest-input schema ID |
|---|---|---|
| rehearsal fixture manifest | `urn:gew:schema:migration-rehearsal-fixture-manifest:1.0.0` | `urn:gew:schema:migration-rehearsal-fixture-manifest-input:1.0.0` |
| rehearsal transform manifest | `urn:gew:schema:migration-rehearsal-transform-manifest:1.0.0` | `urn:gew:schema:migration-rehearsal-transform-manifest-input:1.0.0` |
| rehearsal registry | `urn:gew:schema:migration-rehearsal-registry:1.0.0` | `urn:gew:schema:migration-rehearsal-registry-input:1.0.0` |
| installation bootstrap | `urn:gew:schema:migration-rehearsal-installation-bootstrap:1.0.0` | `urn:gew:schema:migration-rehearsal-installation-bootstrap-input:1.0.0` |
| step observation | `urn:gew:schema:migration-step-observation:1.0.0` | `urn:gew:schema:migration-step-observation-input:1.0.0` |
| crash-recovery observation | `urn:gew:schema:migration-crash-recovery-observation:1.0.0` | `urn:gew:schema:migration-crash-recovery-observation-input:1.0.0` |
| final rehearsal observation | `urn:gew:schema:migration-rehearsal-observation:1.0.0` | `urn:gew:schema:migration-rehearsal-observation-input:1.0.0` |

`MigrationRehearsalFactory` 只能消费同一 private root 中 factory-issued current repository、bundle、manifest、
ledger/history 与 lock/fence capability：

1. `forward` 从 exact active A export verified bundle，经 registry 唯一 A→B transform 在 isolated repository
   import/replay/integrity/compatibility，按既有状态机发布更高 generation/epoch 的 verified B；
2. `backward` 不是回写旧 pointer，而是 B→A 的新 rehearsal migration，generation/epoch/fence high-water
   继续单调，fresh A target 与 rollback rehearsal observation 同时成立；
3. `partial-data` 对 fixture 中每个 exact field/case 产生 ordered disposition row；任何遗漏、重复、别名、
   caller default、silent truncation 或未授权 owner-route 拒绝；
4. `crash-window` 对状态机每个 config-owned cut 只接受 durable old A 或完整 verified new B；partial manifest、
   mixed objects、`verifying` exposure、epoch decrease、lost claim 或 restore gap 自动解锁均拒绝。

step/crash/final observations self-digested 并 exact 绑定 task unique ID、revision/snapshot/invalidation epoch、
GraphRef six pins、factory/registry/bootstrap/fixture/transform、A/B/A manifest identities与monotonic generations、
ordered ledger states、bundle/object manifests、integrity/compatibility results、partial-data rows、crash cut/outcome、
lease/claim/fence/high-water 与 fresh target bytes。issue、use、category assessment、precommit、coverage
observe/factory/gate 与 restart 每次从 repository/current installation 重读并重算；caller PASS、mapping、history
list、cached manifest 或 label 不构成 input。restart 从 task 唯一 referenced CAS assessment 重解，migration
execution count exact为零。

现有 category completion assessment 1.0 与 performance-only 1.1 pairs 保持冻结。两个同时获批的 WP-08
authority amendments新增 exact
`urn:gew:schema:category-completion-assessment:1.2.0` /
`urn:gew:schema:category-completion-assessment-input:1.2.0` closed union：`profile_id=migration` 时只允许并要求
`migration_rehearsal_projection`；`profile_id=dependency-security` 的 graph/remediation scenarios 只允许并要求
ADR-0006定义的 `dependency_graph_projection`；其他 Profile、cross-branch、同时出现两个 projection 或旧版本
携带这些字段全部拒绝。migration projection保留上述全部 nested bodies/digests，仅排除自身
`projection_digest`。它继续使用既有 `task.category_assessed` event、单一 referenced assessment CAS 与同一
TaskApplication transaction；不新增 table、event、generic evidence API、DB/storage schema或GraphRef pin。

foreign/clone/stale factory/repository/bundle/manifest、wrong root/fixture/transform、ledger omit/reorder/duplicate、
coherent re-sign、epoch/fence/high-water rollback、same-path replacement、task/profile/scenario/cut substitution及
final-observe后 replacement 均在 commit 前拒绝，task/event/snapshot/object-ref/action/target/input 零写；最多
留下可由既有 doctor 回收的 unreferenced CAS。commit 后 assessment/ref/observation 同时可见且 restart current。

该 amendment exact 覆盖 `GEW-PSC-MIGRATION-FORWARD-P/R`、`...-BACKWARD-P/R`、
`...-PARTIAL-DATA-P/R`、`...-CRASH-WINDOW-P/R` 八个 records。以 corrected final217 为起点，migration batch
完成后 plan exact `216`、oracle bindings `108`，combined gate 为
`216 valid / 58 missing / passed=false`，static evidence `0/274`。每个 binding 继续使用 Option C unique task；
per-Profile repository可共享但task/current authority不共享，strict serial/private roots。只有 exact combined
gate 后才能 finalize/revoke；未进入 gate 的 partial candidate 只能走已批准 one-shot abort。finalized/aborted
后 rehearsal current/restart/register/gate 全部拒绝，immutable records 与 durable task/action/target 不变。

## Consequences

- storage implementation 需要 SQLite schema migrations、repository conformance adapter、
  object store 和 lock service；
- data root 必须是本地、owner-only、支持要求的 atomic rename/fsync/locks；doctor 对不合格
  filesystem 明确阻塞；
- 一个 process 可持有多个 connection，但每个 transaction 单 writer，连接不得跨线程
  或 fork 共享，且全部由同一 ConnectionFactory 初始化；
- DB、活动 journal 和 objects 是一个逻辑存储单元，移动/备份必须通过 repository API；
- RetentionPolicy 必须协调 DB tombstone 与 body purge，不删除 unresolved action 所需对象；
- 性能优化不能改成 `synchronous=NORMAL/OFF` 或 network share；这些改变需要新 ADR 和
  reliability evidence。
- migration rehearsal 只增加 protected config/schema、consumer-local application authority 与 existing
  assessment CAS projection；不增加 repository row/table、真实 activation 或用户数据访问。

## Validation and Rollback

Repository conformance 必须在 macOS/Linux 覆盖：

- 每个 object/DB commit/GC/purge step 的 process kill、OS crash simulation 和 disk-full；
- atomic old/new visibility、transaction idempotency、CAS、snapshot rebuild；
- normal/doctor/backup/migration connection 的错误 PRAGMA、VFS/path、thread/fork inheritance；
- same-process/two-process readers/writers、`SQLITE_BUSY`、hot-journal、lease expiry、stale fence；
- same-process thread、independent process、fork-during-call、child unlock/exit、exec、相反
  多资源顺序、部分 lock 失败、lock inode replacement/path attack 和 process crash；不得
  死锁/部分持锁，child 不得释放或延长 parent ownership，call-span lock 丢失后 durable
  claim 仍阻塞第二任务；
- 并发 object writer/metadata commit/GC/purge 的全 crash matrix；成功 reference 永不缺 object；
- journal/synchronous/fullfsync/VFS capability gate；若未来启用 WAL，拒绝未修复版本；
- database corruption、missing object、permission weakening 和 symlink/path attack；
- 持续 write/tombstone/GC 下 export，成功 bundle 必须从内含 DB 导出相同 manifest 并拥有
  全部 digest-valid objects；截断/混合 snapshot 拒绝；
- public export、migration-held export、递归进入以及 export hold 前后 failure injection 不得
  自死锁；migration path 在 verified `active|blocked` manifest durable 前不得释放 installation
  exclusive；
- 两进程 migration、command-versus-switch、stale-generation 和 migration/active-reference
  每步 crash 只能恢复完整 old/new；只能存在一个 installation activation authority，旧 bundle
  activation 不得回退 fencing high-water、遗漏 claims 或在 restore gap 下执行 action；
- rollback/hot-journal lifecycle 和 clean/unclean process exit。
- migration scenario matrix：A→B、monotonic B→A、全部 partial-data dispositions、每个 crash cut old-or-new；
  schema/bootstrap/source/RECORD replacement、foreign/clone/stale/coherent re-sign、history/epoch/fence攻击全部
  zero-write，restart zero migration replay；exact 8 records 后仍保持 `216/58/false`。

若 conformance 无法满足 Tech Spec，ADR 重新打开并比较 WAL SQLite 或 framed file
backend；切换只能通过 backend-neutral export/import，不能改变 event history。

## Sources

- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
- [SQLite WAL](https://www.sqlite.org/wal.html)
- [SQLite locking](https://www.sqlite.org/lockingv3.html)
- [SQLite synchronous PRAGMA](https://www.sqlite.org/pragma.html#pragma_synchronous)
- [Python `sqlite3` transaction control](https://docs.python.org/3/library/sqlite3.html#transaction-control)
- [Python `fcntl` locking](https://docs.python.org/3/library/fcntl.html)

## Traceability

Disposes Tech Spec §20.3、§20.4 and storage parts of §20.1；supports FR-03、FR-06～FR-08、
FR-11、FR-15～FR-17、NFR-02、NFR-03、NFR-06～NFR-08。
