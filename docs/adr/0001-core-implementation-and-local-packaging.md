# ADR-0001: Core Implementation and Local Packaging

## Status

Accepted — revision 2，2026-08-13；Independent ADR Review PASS。

## Context

批准的架构需要一个本地、无 daemon、可从 Codex/Hermes Skill 调用的确定性核心，覆盖
Graph/reducer/policy/schema/digest、event repository、CLI、runtime adapters、测试和
macOS/Linux 安装。实现必须保持平台中立语义，不能把 Codex/Hermes 或用户/环境值写进
核心。

当前仓库是绿地；本机默认 `python3` 为 3.9.6，但已安装 `uv`，可以管理和锁定独立
Python。实现语言选择不得依赖这台机器的偶然环境。

决策驱动因素按优先级为：

1. 正确性、可测试性和恢复语义的实现速度；
2. 本地安装/升级简单，Skill 能稳定发现入口；
3. macOS/Linux 可移植和标准库支持；
4. typed model、JSON/schema、SQLite、subprocess 与 filesystem 生态成熟；
5. 后续维护、调试和 Agent 生成/审核效率；
6. 性能足以支撑交互式单机工作流，不追求高吞吐。

## Decision

v1 核心采用 **Python 3.12+ 的一个分发包**，同时提供 importable library 和稳定的
`graph-engineering` console entry point：

- 使用标准 `pyproject.toml`、锁定依赖和显式 package discovery；
- 源码按批准的仓库规范保留顶层 `core/`、`application/`、`storage/`、`adapters/`，但
  这些 common-name 目录不是可直接 import 的 packages。build backend 用显式 mapping
  将它们分别安装为唯一分发命名空间 `graph_engineering.core`、
  `graph_engineering.application`、`graph_engineering.storage` 和
  `graph_engineering.adapters`；CLI 安装为 `graph_engineering.cli`；
- tests 运行已构建 wheel 或 PEP 660 editable install，不把 repository root 隐式加入
  `sys.path`；console entry point 只能 import 已安装的 `graph_engineering` distribution；
- CLI 是 Skill 和运维命令的唯一进程边界，library API 供同进程测试和组合；
- Codex/Hermes Skills 通过 capability discovery 定位已安装 CLI，不引用本仓库绝对路径；
- 开发与首选安装使用 `uv` 锁定 Python 和依赖；发布产出标准 wheel，但受支持的 v1
  安装必须消费下一节的 verified release bundle，不能只从 wheel metadata 重新解析依赖；
- installer 是产品安装面，`uv` 不是领域/运行时依赖；运行核心不 import 或 shell out 到
  `uv`，其他安装器只有实现同一 bundle/verification contract 才受支持；
- v1 不生成常驻进程、server、端口或隐藏 scheduler；每个命令完成或暂停后进程退出；
- 对外稳定面仅为版本化 CLI、machine-readable output 和显式 ports/contracts，内部
  Python 函数默认不承诺兼容。

选择 3.12+ 而非系统 3.9：它仍处于官方安全支持期，具有明确的现代 transaction/type
行为，同时避免把开发建立在已经临近或到达生命周期末端的系统解释器上。安装必须用
managed/compatible interpreter，不能悄悄回退到不满足版本的系统 Python。

### Release bundle 与可复现安装

每个平台 release bundle 绑定一个 `ReleaseInstallManifest`：

- product/core exact version、CLI protocol version、release ID 和 manifest digest；
- `os + architecture`、精确 CPython patch/build identity 和受信 distribution SHA-256；
- core wheel、全部 runtime dependency wheels、build dependencies 和 Skill assets 的文件名、
  version、source identity、SHA-256 与 size；不接受未列 sdist 或运行时临时 build；
- 从同一 `uv.lock` 导出的 exact constraints/`pylock.toml`、依赖图和 CycloneDX SBOM；
- 受信 source allowlist、licenses、provenance/attestation refs、vulnerability scan result 和
  版本化 release security policy digest；
- Codex/Hermes Skill versions、adapter compatibility 和 repository/schema/graph contract
  compatibility ranges。

首选安装器使用受控 installer version、`--no-config` 和 verified local wheelhouse，指定
精确 `--python` + `--managed-python`、`--no-index`、exact constraints；安装前自行验证
manifest 与所有 bytes，安装后枚举实际 interpreter/distributions 与 manifest 逐项比对。
ambient index、用户 `uv.toml/pyproject.toml`、PATH 中的 Python 或未列依赖不能影响结果。

release 构建按 macOS/Linux 的受支持架构分别产出 bundle。相同 bundle 的两次 clean install
必须得到相同 interpreter/core/dependency manifest；artifact 缺失、hash/provenance 不符、
source 不受信、license/security policy 不通过、平台不受支持或无法取得精确 interpreter
时在安装前 fail closed。安全策略阈值和 source list 是版本化配置，不硬编码进业务逻辑。

### Skill 分发、定位与兼容握手

Codex/Hermes Skill assets 与 Python wheel 分开打包、在同一 ReleaseInstallManifest 中绑定：

- installer 通过 runtime adapter 查询或显式配置目标 Skill root；路径是环境配置，不写进
  core。每个 Skill 安装到 runtime 原生目录并保留版本、asset digest 和卸载记录；
- installer 为每个 Skill 写入 owner-only locator，包含 canonical absolute executable、
  tool-environment/package origin、expected core version、executable/release manifest digest；
  Skill 不使用裸 `graph-engineering` PATH lookup；
- locator resolver 解析 symlink、验证 regular executable、ownership/permissions、分发
  metadata 和 package origin；missing、duplicate、shadowed、moved 或 digest mismatch 拒绝；
- package metadata 是 core version 的唯一来源；source constants 只由 build 从同一 metadata
  生成并在测试中比对，不能出现第二个人工版本真相。

每次可能写 task state 或调用 tool 之前，Skill 调用 `capabilities --format json` 完成握手。
响应至少含 release/core/CLI protocol、runtime adapter、Skill、repository contract/bundle、
schema registry、Graph/Profile/Overlay 和 action protocol versions，以及 capability set、
canonical executable/package origin、data root ref 和 compatibility verdict。Skill request 也
携带自己的 runtime/Skill/protocol versions。任一 required range 不匹配、identity 不唯一
或 capability 缺失时，只允许只读诊断，不得创建/迁移/执行任务。

## Options Considered

### Python 3.12+ package + CLI — accepted

优点：

- 标准库直接提供 `sqlite3`、`hashlib`、`json`、`dataclasses`、`subprocess`、filesystem
  和 Unix locking 基础；
- 与现有 Skill/script 生态和 Agent 编写/审查匹配，能最快建立完整测试闭环；
- PyPA 定义 `pyproject.toml` 与 `[project.scripts]`，`uv` 能隔离安装 tool 并管理 Python；
- 交互式 Graph workload 不需要 native-language throughput。

缺点：需要受控 interpreter/依赖安装；运行时类型安全弱于 Rust；CPython bundling 不是
天然单二进制。通过 locked environment、strict models、schema/property tests 和 wheel
分发缓解。

### Rust binary — rejected for v1

优点是单一 native executable、强静态类型、良好资源控制和跨平台 release artifact。
但 Graph/schema/adapter 迭代、动态配置和 runtime 集成开发成本更高，首版可靠性更依赖
大量正确性测试而非语言内存模型。以后若启动/分发数据证明 Python 包装是主要失败点，
可在不改变 CLI/contracts 的前提下替换实现。

### TypeScript/Node — rejected

JSON 与 Skill 生态友好，但 native/local filesystem locking、SQLite 绑定和单文件分发引入
更多运行时或 native module 选择；Node single-executable 能力仍标为 active development，
不适合作为可靠性优先 v1 的基础。

### Shell/Skill-only — rejected

无法可靠承载 typed reducer、transaction、schema、crash recovery 和跨平台测试；也会
把 deterministic safety 错误地交给 prompt。

## Consequences

正向：

- Plan 可先构建一个 Python package/CLI 垂直切片，再逐层增加 storage 和 adapters；
- 单元、property、integration 和 failure-injection 可使用统一 runner；
- Codex/Hermes 共用同一 executable contract，减少 Skill 漂移。

成本与约束：

- 安装器必须显式管理 Python 3.12+，并支持无兼容 interpreter 时的可诊断失败；
- release pipeline 必须维护 platform bundle、exact wheelhouse、SBOM、许可/供应链扫描和
  compatibility matrix；标准 wheel 仍可被其他工具读取，但不等于受支持的 reproducible install；
- CLI 输出必须区分 human display 与 versioned JSON，stdout/stderr 不得泄露秘密；
- Python 对象不能直接作为持久化真相，必须先通过 deterministic contract stack；
- 多进程正确性不能依赖 GIL，必须依靠 repository transaction、leases 和 claims。

## Staged Upgrade and Rollback

upgrade 由 installer 协调，不原地覆盖 active tool environment：

1. 获取 installation-wide upgrade lock；发现 live task/resource lease、未协调 action claim、
   运行中 migration 或不兼容 retention hold 时停止；
2. 验证新 ReleaseInstallManifest，保留并校验当前 release bundle、canonical executable、
   active repository ref 和可执行 rollback manifest；
3. 通过 Repository API 导出/验证当前 state bundle；把 candidate interpreter/wheels/Skills
   安装到新的 immutable versioned tool/Skill roots，不改 active locator；
4. candidate doctor 在隔离 data root 运行；完成 capability/compatibility、dependency、
   import-boundary 和 state migration dry-run；
5. 按 ADR-0002 在隔离 repository 完成 migration/replay/integrity；生成一个绑定 candidate
   tool、Skills、repository、schema/Graph registry 的 `ActivationManifest`；
6. 以 durable atomic active-reference protocol 切换整个 tuple；启动新 CLI 再验证。成功后
   旧 tool/repository 仍保留到 RetentionPolicy 允许清理；
7. install、doctor、migration、切换或 post-switch verification 任一步失败，active tuple
   保持或恢复旧版本；不得让新 executable 读取未迁移状态，也不得让旧 executable 读取
   已切换的新 schema。

rollback 只能切回与恢复 state 兼容的已验证 tuple。若新版本已执行不可逆外部 action，
回退软件不抹除 action journal/claim，必须先按 action reconciliation 处理。

## Validation and Rollback

实现前/实现中必须证明：

- clean macOS/Linux 环境能安装、运行 doctor、调用 CLI 并卸载；
- 不兼容系统 Python 不会被采用；同一 release bundle 两次安装的 interpreter、core、依赖、
  Skill 和 SBOM manifests 完全一致；tamper/untrusted/missing/unsupported fixtures 全部拒绝；
- wheel inspection 只含 `graph_engineering.*`；在含伪造 `core/application/storage/adapters`
  packages 的 target project 和 source checkout 内外运行 CLI，所有 module 都来自已安装分发；
- Codex/Hermes Skills 在无 source checkout 的 clean environment 定位 canonical executable；
  PATH shadow、duplicate locator 和每类 component version/capability mismatch 在写入前拒绝；
- import boundary scan 证明 core 不导入 runtime/vendor adapters；
- CLI contract、exit codes、signals、crash 和 concurrent invocation 有 integration tests；
- runtime 关闭后无 Graph worker 残留；
- 对 install、doctor、compatibility、migration、activation 和 post-switch 各步骤注入失败，
  旧 CLI/repository 始终完整可用；live/unknown action 阻止 upgrade。

若这些验证失败，可在实现代码出现前重新打开 ADR；若实现后需要替换语言，保留 CLI、
schema、bundle 和 repository ports，使用 contract tests 驱动替换。改变为 daemon/远程
control plane 必须返回 Human，而不是本 ADR 的回滚方案。

## Sources

- [Python Packaging User Guide — command-line tools](https://packaging.python.org/en/latest/guides/creating-command-line-tools/)
- [PyPA `pyproject.toml` specification](https://packaging.python.org/en/latest/specifications/pyproject-toml/)
- [uv tool environments](https://docs.astral.sh/uv/concepts/tools/)
- [uv managed Python](https://docs.astral.sh/uv/guides/install-python/)
- [Python supported versions](https://devguide.python.org/versions/)
- [Node single-executable applications](https://nodejs.org/api/single-executable-applications.html)
- [Cargo build targets](https://doc.rust-lang.org/cargo/commands/cargo-build.html)

## Traceability

Disposes Tech Spec §20.1 and part of §20.5；supports FR-01、FR-03、FR-04、FR-08、FR-12、
FR-16、NFR-01、NFR-04、NFR-05 and NFR-08。
