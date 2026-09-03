# ADR-0004: Extension Source and Capability Trust

## Status

Accepted，revision 7（verified-byte execution and physical wheel closure amendment），2026-08-22；Human Owner approval；independent
reviewer `codex:/root/wp08a_adr_reviewer_r4` PASS，zero findings。

ADR-0004 architecture gate 已关闭。§5.2 的 ADR-0003 independent revision 与 contract conformance
gate 未关闭时，所有 non-built-in executable extension loader 仍必须 fail closed。

### Revision history and finding disposition

| Revision | Disposition | Summary |
|---|---|---|
| r1 | REVISE，`scope_changed=false` | 初始候选冻结 trust boundary，但 package/signature cycle、provenance wire、trust transaction、executable semantic boundary 与 network plane 仍不充分 |
| r2 | REVISE，`scope_changed=false` | non-cyclic package 与 network plane 已闭合；package identity、production/installation provenance separation、closed trust reducer/ledger 与 executable output contracts 仍需收敛 |
| r3 | Proposed — Review Pending | Human 授权的 final consolidated author revision；仅机械闭合 r2 四项 open finding，等待一次最终独立审核 |
| r4 | Accepted | Human 另行授权的最小修正统一 PACKAGE-001 export identity wire field；Human Owner approved；independent reviewer `codex:/root/wp08a_adr_reviewer_r4` PASS，zero findings |
| r5 | Accepted amendment | Human Owner 批准 PyCA `cryptography==50.0.0`（Python ≥3.12）作为 v1 Ed25519 provider；不改变 package、authority、network 或 executable gate |
| r6 | Accepted amendment | Human Owner 批准 PyPA `packaging==26.3` 作为 v1 wheel filename/tag/requirement parser；仅限 package/install boundary，不改变 trust、authority、network、WP-10 或 executable gate |
| r7 | Accepted amendment | Human Owner 批准 coverage verification 使用 descriptor/pipe-bound exact bytes，且 wheel preflight 对物理 ZIP 与全 closure 统一计费；不改变 extension executable gate 或 WP-10 authority |

### Accepted amendment — Ed25519 provider（2026-08-20）

v1 选择 PyCA `cryptography==50.0.0` 提供 Ed25519 primitive。core 只定义平台中立、无 I/O 的 verifier
port 与 exact request/result contract；PyCA import、provider identity/version/origin 检查和 primitive 调用
只能位于 adapter/installation boundary。provider 不解析 trust policy、不决定 authority、不读 bundle、
不发布 activation，也不能解释 signature failure 为成功。

ReleaseInstallManifest 必须 exact pin distribution name/version、候选 wheel 与 source artifact raw hashes、
distribution metadata/RECORD、provider adapter implementation digest 和独立 source/build attestation；任一
缺失、重复、shadow、origin/version/hash/attestation 不符均 fail closed。当前批准只允许 dependency 声明与
本地候选验证；WP-10 未经 supply-chain/install-manifest transaction 固定真实 artifacts 前，不得作正式
安装或 release 声明，也不得启用 provider fallback。

trust plane、package discovery、install、revocation 与 update 不得联网下载 provider、key、package 或
metadata；runtime 也不得自动安装、解析 index 或回退到 OpenSSL CLI、系统 keychain、其他 Python package
或自研 Ed25519。dependency 更新只能经 WP-10 的 Owner-authorized supply-chain/install-manifest 流程。
provider 缺失时返回 stable unavailable/mismatch，install mutation 为零。ADR-0003 revision/conformance
未 Accepted 前，全部 non-built-in executable kind 仍 fail closed；本 amendment 仅允许满足完整 trust
contract 的 data-only bundle 进入后续 activation gate。

### Accepted amendment — standard wheel metadata parser（2026-08-21）

v1 wheel filename normalization、PEP 508 `Requires-Dist` 解析和 interpreter tag 比较使用 PyPA
`packaging==26.3`。该依赖只允许位于 build/install/package-verification adapter boundary；core trust、
authority、reducer 与 task semantics 不得 import 或依赖它。解析器输入仍受 descriptor/ZIP/member/bytes
bounds 与 exact METADATA/WHEEL/RECORD validation 约束；解析成功不授予 installation、activation 或
execution authority。

trust plane 与 runtime 不得联网下载、fallback 或从 package index 补齐 `packaging` 或 dependency
closure。当前只批准本地离线候选验证与 exact dependency 声明；`packaging` distribution/wheel/source、
RECORD hashes、source/build attestation 及全 wheelhouse closure 仍必须由 WP-10 ReleaseInstallManifest
固定后才能形成正式安装或 release 证据。版本更新仅能经 WP-10 Owner-authorized supply-chain/install-
manifest transaction。

### Accepted amendment — verified bytes and physical wheel closure（2026-08-22）

coverage verification child 只能接收父进程从 canonical source manifest target descriptor 读取并固定的
runner、test module 与 callable bytes。child 必须从 pipe 内存加载和编译这些 exact bytes，禁止对目标
runner/module/callable 使用 filesystem import fallback，并在 resolve、execute 与 receipt 前后复核 module、
callable source/code、runner 与 observed-result digest；任一 copy/digest/launch/load/resolve/execute/receipt
竞态或替换均不得发行 execution record。父进程还必须在发行前后复核同一 canonical manifest 未改变。

wheel preflight 除单 member bounds 外，必须在遍历或分配前按版本化配置统一计费整个离线 dependency
closure 的 wheel 数、aggregate bytes、dependency edges、depth 与 requirement 数；耗尽即 fail closed。
ZIP local headers、data descriptors、central directory、EOCD 与 RECORD 必须形成 exact 一对一 physical-member
集合，不能隐藏、重复或用 alternate path encoding 绕过。METADATA/WHEEL 的受支持 identity fields、
`Metadata-Version`、`Root-Is-Purelib` 与 tags 必须 singular/exact，再由 `packaging==26.3` 解析 requirement、
name、version 与 tag。该 amendment 仍不授予正式 installation/release 或 non-built-in executable authority。

| Stable finding ID | r4 disposition | Normative closure |
|---|---|---|
| `GEW-ADR4-PACKAGE-001` | Resolved in candidate r4 | §2.1～2.4：manifest/source/input/nested/reconstruction/golden/rejection 全部只接受 exact `exported_identities` |
| `GEW-ADR4-PROVENANCE-001` | Preserved from r3 | §2.5～2.6：attestation-production policy 与 installation verification policy 分离；installation tuple 仅进入 ingest ledger |
| `GEW-ADR4-TRUST-001` | Preserved from r3 | §3.1：closed policy/projection/reducer、四类 append-only records、chain/head atomicity；publisher revocation 仅经 Owner transaction 生效 |
| `GEW-ADR4-SEMANTIC-001` | Preserved from r3 | §5.1～5.2：closed output envelope/payload union/classification/consumer/promotion transitions；双 ADR gate 前全部 executable fail closed |
| `GEW-ADR4-NETWORK-001` | Preserved closed from r2 | §9.1：offline trust plane 与 authorized task action plane 分离；discovery/install/revocation 绝对无网 |

## Context

FR-18 要求在本地加载 node、edge、policy、template 和 adapter 扩展，并在加载前验证输入输出、
权限、副作用、失败和验证契约。Spec §11.2 还要求 manifest 绑定 exact version、package digest、
compatibility 与 task-start version lock，且扩展不能覆写 core invariant。Impact §14.2 将首个第三方
或非内置 extension 进入可执行范围定义为必须先完成独立 ADR 的触发条件。

ADR-0003 已把 wire data、schema、digest 和 bounded expression 固定为 deterministic contract
stack，并明确禁止不可信输入向同一 Python 进程注入 callable、class、module 或 code object；若要
执行第三方代码，必须使用独立进程或等价的外部 capability isolation 与可独立验证的 code
attestation。ADR-0001/0002 则要求本地、无 daemon、Skill-first 的 CLI 边界，以及稳定 control-root
installation authority、原子 activation 和可恢复审计。

WP-07A r6 的独立 review verdict 为 PASS、零 findings；其固定前置 tuple 包含：

- source manifest digest `c1cb7956796ed7a0795d09ba15e18d64d6b533fd2d3fb2b5a0acfbfcd83c91e5`；
- command evidence digest `2edd6cab97b0786a1618345d9825c1eec99d981c01ea407d3fa9be90579d2461`；
- candidate exit digest `e134798a497c1942622669470c19cf11b8088cc5bed5b5b564d6059925ad40c1`；
- reviewer `codex:/root/wp07a_reviewer_r5`。

该证据只证明 built-in action adapter 的安装来源、实现 provenance、结构化启动、receipt/
observation 与无 staging archive loading 边界可复用；它不自动信任 extension，也不授权真实外部
动作、网络、用户 repository、secret 或新的 capability。

需要收敛的核心问题是：签名只能证明“谁发布了哪些 bytes”，不能证明代码安全；普通 Python
import 或仅靠 argv allowlist 也无法阻止任意第三方 executable 使用宿主进程权限。因此来源、
安装、capability enforcement、adapter/executable invocation 与 revocation 必须形成一个不可跳过的
联合 gate。

## Decision Drivers

优先级如下：

1. extension 不能扩大 Authority Envelope、绕过 core invariant 或伪造 completion；
2. 无法证明来源、兼容性、capability containment 或当前 revocation 状态时 fail closed；
3. 通用语义保持 platform-neutral，环境路径、命令、limits 和 provider availability 全部来自配置；
4. 保持 local-only、no-daemon、Skill-first；不得引入在线 marketplace 或后台更新；
5. package、installation、activation、task pin 和 action receipt 可重放、可审计、可回滚；
6. 签名、provenance 和 secrets 遵循最小披露与最小留存。

## Candidate Decision

采用 **offline signed immutable extension bundle + installation trust policy + default-deny
capability intersection + attested out-of-process execution**。签名是必要的来源条件，但不是执行
权限；只有来源、安装、兼容、capability、authority 和 revocation 六个 gate 同时满足，扩展才可
进入某一次 task operation。

### 1. Extension classes and trust boundary

extension 分为两类，不允许通过字段伪装互换：

| Class | Examples | Execution rule |
|---|---|---|
| deterministic data | node/edge topology、template、schema、GEEL policy | 只能解码为 ADR-0003 的 frozen data/contracts；不能携带 callable、import path、bytecode 或 native code |
| executable | predicate、validator、transform、adapter/connector | 禁止导入产品 Python 进程；只能经 factory-attested isolation provider 在独立、短生命周期进程中执行 |

built-in product component 不通过 extension loader 获得身份；它继续由 exact release/install
manifest、distribution provenance 和 closed built-in registry 证明。non-built-in package 不能声明
built-in namespace、identity、schema ID、predicate ID、error code 或 adapter kind，也不能用更高版本
号覆盖它们。

所有 non-built-in package，包括本地开发包，都使用相同签名和 capability gate。本地开发者可由
Owner 通过显式 installation-policy update 加入一把 development publisher key；不存在“本地路径
默认可信”或 debug bypass。

### 2. Package format, source, signature and provenance

v1 package 是 bounded `GEW Extension Bundle v1`：一个离线、不可变、内容寻址的 ZIP Profile
archive。它不是 Python wheel，也不参与 import resolution。reader 在信任任何 member bytes 前枚举
整个 central directory，并拒绝 duplicate physical/logical members、重复或歧义 encoding、绝对/
父目录路径、symlink/hardlink/device、encrypted/data-descriptor/ZIP64/unknown compression、尾随
数据、CRC/digest 不符、大小/数量/ratio 越界和读取前后 archive identity 变化。v1 唯一允许 stored
mode；资源 limits 来自版本化 installation policy，不写入 engine logic。

#### 2.1 Closed non-cyclic wire layout

archive exact member set 是：

```text
META-INF/extension-package-manifest.json
META-INF/source-attestation.json
META-INF/build-attestation.json
META-INF/publisher-signature.json
payload/<manifest-enumerated canonical relative members>
```

不得有 directory entry、extra metadata member 或 unlisted payload。四个 `META-INF` members 名称、
大小上限和 stored mode 固定，不进入 payload entry list。物理 archive raw digest 只有在四个记录和
全部 payload 已写完后才可计算；它写入 installation ingest/ledger record，**不进入 archive 内任何
record、publisher signature 或 package identity**。因此 archive bytes 不自我引用；同一语义 bundle
的不同 physical encoding 仍因 v1 ZIP Profile 唯一编码要求而拒绝，而不是被当成等价输入。

v1 physical profile 固定为：local/central header version 2.0、general-purpose flag 仅 UTF-8 bit、
compression method `stored(0)`、DOS timestamp `1980-01-01T00:00:00`、空 extra/comment、Unix create-
system、regular data mode `0444` 或 executable mode `0555`、CRC/size/name 在 local 与 central header
完全相等；无 data descriptor、ZIP64、encryption 或 archive comment。member 顺序先是上列四个
`META-INF` exact order，再是按 Unicode scalar path order 的 payload；central directory 顺序必须与
local headers 相同。任一不一致不是可 canonicalize 的输入，而是拒绝。

依赖图只能沿下列方向，任何 back-edge、同级互引或 digest alias 都拒绝：

```text
source materials -> SourceAttestation
payload members -> ExtensionPayloadRoot
SourceAttestation + payload root + build materials -> BuildAttestation
source/build attestations + payload root + extension declarations -> ExtensionPackageManifest
manifest/build/payload digests -> ExtensionSignatureStatement -> publisher signature
complete archive bytes -> installation ingest raw digest (outside publisher-signed package identity)
```

`SourceAttestation` 不包含 payload/package/signature digest；`BuildAttestation` 可包含 payload root 和
package identity projection，但不包含 package manifest/signature/archive digest；package manifest 不含
publisher signature/signature-record/archive digest；signature record 不进入任何被签 projection。

`ExtensionPackageManifest v1` exact top-level fields 为：

```text
schema_version, extension_id, extension_version, publisher_id, release_id, package_class,
source_attestation_digest, build_attestation_digest, payload_root_digest,
package_identity_digest, extension_points[], exported_identities[], input_schema_ids[],
output_schema_ids[], contract_registry_digest, compatibility,
requested_capabilities[], operation_classes[], ordered_resources[], side_effects[],
idempotency_semantics, failure_semantics, verification_semantics,
executable_contract,
signing_suite, publisher_key_id, revocation_sequence_floor, manifest_digest
```

字段按 kind 使用 closed conditional schema；data-only package 的 `executable_contract` 必须 exact null，
executable package 必须是完整 closed object。所有 array 都有 canonical ordering/uniqueness rules；空、missing 与 wildcard 不
互换。`ExtensionPublisherSignature v1` exact fields 是 §2.2 statement 的七个 fields，加
`signature` 与 `signature_record_digest`，不能有其他 member。

#### 2.2 Domain-separated projections

全部 semantic digest 使用 ADR-0003 七-member envelope。r2 冻结以下 closed projection registry；
schema/projection ID 任一变化都需要新的 major version，不能 runtime 推断：

| Record | Contract/schema/projection | Exact projected body |
|---|---|---|
| payload root | `extension-payload-root` / `extension-payload-root-input:1.0.0` / `extension-payload-root:1.0.0` | exact `schema_version="1.0.0"` and ordered `entries[]`；每项 exact `path,kind,size,raw_digest,executable` |
| package identity | `extension-package-identity` / `extension-package-identity-input:1.0.0` / `extension-package-identity:1.0.0` | complete identity source minus only `/package_identity_digest`；逐字段定义如下 |
| source attestation | `extension-source-attestation` / `extension-source-attestation-input:1.0.0` / `extension-source-attestation:1.0.0` | complete record minus only `/attestation_digest` |
| build attestation | `extension-build-attestation` / `extension-build-attestation-input:1.0.0` / `extension-build-attestation:1.0.0` | complete record minus only `/attestation_digest` |
| package manifest | `extension-package-manifest` / `extension-package-manifest-input:1.0.0` / `extension-package-manifest:1.0.0` | complete record minus only `/manifest_digest` |
| signature record | `extension-publisher-signature` / `extension-publisher-signature-input:1.0.0` / `extension-publisher-signature:1.0.0` | complete record minus only `/signature_record_digest`；`signature` 保留 |

每个 projection 的 contract type 完整形式是 `urn:gew:contract:<name>`，schema 与 projection 完整
形式分别是 `urn:gew:schema:<name>:1.0.0` 和
`urn:gew:digest-projection:<name>:1.0.0`。raw member digest 只允许
`sha256-raw-v1:<64-lowercase-hex>`；不能填入 semantic digest 字段。

`ExtensionPayloadRootInput v1` 只有且必须有 `schema_version,entries`；source schema 与 digest-input
schema 是同一个 `$id="urn:gew:schema:extension-payload-root-input:1.0.0"`，因为 digest 不写回 body。
任何其他 `schema_version`、省略 version、在外层/entry 重复 version 或把 version 排除出 body 都拒绝。

`ExtensionPackageIdentitySource v1` 的 `$id` 是
`urn:gew:schema:extension-package-identity:1.0.0`，exact required fields 按 wire name 为：

```text
schema_version, publisher_id, extension_id, extension_version, release_id,
package_class, extension_points, exported_identities,
input_schema_ids, output_schema_ids, contract_registry_digest,
compatibility, requested_capabilities, operation_classes, ordered_resources,
side_effects, idempotency_semantics, failure_semantics, verification_semantics,
executable_contract, package_identity_digest
```

`ExtensionPackageIdentityDigestInput v1` 的 `$id` 是
`urn:gew:schema:extension-package-identity-input:1.0.0`，具有完全相同字段、nested schemas、required
set 与 `unevaluatedProperties:false`，唯一差异是根级 `package_identity_digest` property/required entry
不存在且被禁止。projection ID 是
`urn:gew:digest-projection:extension-package-identity:1.0.0`；projected body 逐字段原样保留前述顺序表中的
`schema_version` 到 `executable_contract` 全部 20 fields，只删除一次根级
`package_identity_digest`，不删除、重排、normalize 或重算任何 nested value。

closed nested shapes 是：`extension_points[]` = `{kind,id,contract_digest}`；
`exported_identities[]` = `{kind,id,contract_digest}`；`compatibility` =
`{core_version_range,cli_protocol_range,schema_profile_range,geel_range,runtime_capabilities_digest}`；
`executable_contract` 是 data-only package 的 exact JSON `null`，或 executable package 的
`{locator,raw_digest,entry_protocol,isolation_profiles}`。其余 arrays/items 与 semantic objects 由 package-
identity schema 中对应 closed `$defs` 定义，canonical sorted/unique，不能由 manifest 自带 schema
替换。manifest 的同名 declarations 必须逐字段重建该 digest-input body并 exact-equal
`package_identity_digest`；build attestation 绑定同一 digest，不能只信 caller 提供的 digest string。
manifest、source schema、digest-input schema 与 reconstruction map 对 export identity list 使用且只使用
exact `exported_identities`；loader 不执行 rename、alias、fallback 或兼容映射。
`package_class` exact enum 只有 `data-only` 或 `executable`；不允许 `mixed`，同时包含 data/executable
exports 的 bundle 必须按独立 package identities 拆分，避免 data-only trust path 携带 executable bytes。

其余 `$defs` exact shapes 是：`requested_capabilities[]` =
`{capability_id,parameter_schema_id,parameter_constraint_digest}`；`operation_classes[]` =
`{operation_class,resource_schema_id,authority_class,side_effect_class}`；`ordered_resources[]` =
`{resource_class,selector_schema_id}`；`side_effects[]` =
`{effect_class,idempotency_class,reconciliation_contract_digest}`；三个 `*_semantics` 都使用 exact
`{contract_id,contract_version,contract_digest}`。schema-ID arrays 是 canonical unique strings；这些 nested
fields 也全部进入 package-identity projected body，不能只 hash 它们的 caller-provided summary。

source/build attestation 另各有 closed signing-statement projection：
`extension-source-attestation-signing-statement:1.0.0` 与
`extension-build-attestation-signing-statement:1.0.0`，只从 complete record 删除
`/attestation_signature` 和 `/attestation_digest`，其他字段一字不动。它们与上表 self-digest
projection 是两个不同 registry entries，不能共用或 runtime 删除任意字段。

Ed25519 实际签名输入不是 signature record 的 self-digest，而是唯一
`ExtensionSignatureStatement`：

```json
{
  "build_attestation_digest": "sha256-jcs-v1:<64hex>",
  "manifest_digest": "sha256-jcs-v1:<64hex>",
  "payload_root_digest": "sha256-jcs-v1:<64hex>",
  "publisher_id": "<gew-id>",
  "publisher_key_id": "<gew-id>",
  "schema_version": "1.0.0",
  "signing_suite": "ed25519-sha256-gew-jcs-v1"
}
```

签名 message 是 exact bytes
`UTF8("GEW-EXTENSION-SIGNATURE-V1") || 0x00 || JCS(statement)`。signature record 包含该
statement 的全部字段、unpadded base64url `signature` 与 derived `signature_record_digest`；它不能
携带替代 preimage、certificate chain、embedded public key 或额外 signed attributes。

v1 suite 只允许 Ed25519 raw 32-byte public key 与 64-byte signature；wire encoding 为 canonical
unpadded base64url。SHA-256 只用于上游 raw/semantic digests，不对 Ed25519 message 再做隐式 hash。
验证器、crypto provider、schema 与 golden corpus 由产品 ReleaseInstallManifest 固定；provider
missing/mismatch 时 blocked，不切换算法。

#### 2.3 Unique build, sign and verify order

publisher build/sign 唯一顺序是：

1. canonicalize source identity/materials，生成 source signing-statement，由 source-attestor role 签名，
   插入 signature 后计算 source-attestation self-digest；
2. 构建 payload；按 Unicode-scalar canonical path 排序全部 entries，计算 raw digests/payload root；从
   frozen declarations 与 executable raw digest 构造 §2.2 identity digest-input，计算 package identity；
3. 生成 build signing-statement，绑定 source attestation、payload root、recipe/toolchain/dependency
   materials，由 builder role 签名，插入 signature 后计算 build-attestation self-digest；
4. 生成 package manifest，绑定 source/build attestation digests、payload root、完整 extension contracts，
   最后计算 manifest self-digest；
5. 生成 signature statement，由 publisher-release role Ed25519 key 签名，插入 signature 后计算
   signature-record self-digest；
6. 按 §2.1 固定 member order/mode/timestamps/attributes 写 archive；最后计算 ingest raw digest，仅供接收
   方 ledger 使用。

installer 唯一验证顺序相反但不猜测：完整物理枚举/bounds → payload raw digest/root → source
attestation → build attestation/product linkage → package manifest/self-digest → signature statement/
publisher signature → trust/revocation/validity → compatibility/capability → immutable install re-read。
后一步失败不得把前一步“部分通过”写成 active/trusted；只有 ingest attempt 与非披露 failure 可记录。

#### 2.4 Normative golden and rejection vectors

Golden `ADR4-PKG-GOLDEN-001` 的 payload 是 exact UTF-8 bytes `hello`，member
`payload/hello.txt`。它的 raw digest 是
`sha256-raw-v1:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`；payload-root
七-member envelope 的 JCS SHA-256 是
`sha256-jcs-v1:7f05ee9a843ddd9a9a822f21f7932ace1763756f093cca164285ba35a0191c4a`。
该 golden 的 exact projected body 是：

```json
{"entries":[{"executable":false,"kind":"data","path":"payload/hello.txt","raw_digest":"sha256-raw-v1:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5}],"schema_version":"1.0.0"}
```

唯一 digest preimage 是下列单行 JSON 的 exact UTF-8 bytes（无 BOM、newline 或 trailing byte）：

```json
{"algorithm":"sha-256","body":{"entries":[{"executable":false,"kind":"data","path":"payload/hello.txt","raw_digest":"sha256-raw-v1:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","size":5}],"schema_version":"1.0.0"},"canonicalizer":"urn:gew:canonicalizer:jcs-input:1.0.0","contract_type":"urn:gew:contract:extension-payload-root","digest_domain":"urn:gew:digest:semantic:1.0.0","projection_id":"urn:gew:digest-projection:extension-payload-root:1.0.0","schema_id":"urn:gew:schema:extension-payload-root-input:1.0.0"}
```

不得使用 entry-list-only hash、raw concatenation、另一个 `schema_version`、source schema ID 或在 hash
前移除 version；不存在第二个兼容 preimage。

Field-name golden `ADR4-PKG-GOLDEN-002` 的 exact JCS object fragment 是
`{"exported_identities":[]}`。key bytes、plural form 与 underscore 全部属于 wire contract；任何其他
export-list field name 都是 unknown property，不参与 reconstruction，也不能产生 package identity。

Golden `ADR4-SIG-GOLDEN-001` 使用 §2.2 statement，其中 build/manifest/payload digests 分别是
64 个 `0`、`1`、`2`；`publisher_id="publisher.example"`、`publisher_key_id="key-1"`。domain-
separated message SHA-256 必须为
`cac97c1d2f710eadd81bcb3ec77f33727f8c99dfd747c4dd73b1016db0e06816`。Ed25519 primitive
还必须通过 RFC 8032 test vector 1：seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`，public key
`d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`，empty message，signature
`e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b`。
同一 seed/public key 对该 domain-separated statement 的 exact signature 是
`236c91c0f9853632b9af47ea1cec6118668c9ee4a224dcd0bb786486663ee2673df2eb53aaaac9a3bb3f517f96ba9f123f38ece230527acda2246f18101aae0b`；
实现必须同时验证 message hash 与 signature，不能只跑 RFC primitive vector。

以下 exact rejection vector IDs 是 loader conformance 的 mandatory set：

| ID | Mutation | Required result |
|---|---|---|
| `ADR4-PKG-R-001` | manifest 包含 archive/signature digest，或 build attestation 回指 manifest | `E_EXTENSION_DIGEST_CYCLE`，零 install mutation |
| `ADR4-PKG-R-002` | signature member 被 payload root/manifest 枚举 | `E_EXTENSION_DIGEST_CYCLE` |
| `ADR4-PKG-R-003` | duplicate member、unlisted member、directory/symlink、unknown ZIP feature | `E_EXTENSION_ARCHIVE_PROFILE` |
| `ADR4-PKG-R-004` | payload entry reorder/path normalization/raw digest substitution | `E_EXTENSION_PAYLOAD_ROOT` |
| `ADR4-PKG-R-005` | projection 多删/少删字段、contract/schema/projection/domain substitution | `E_EXTENSION_PROJECTION` |
| `ADR4-PKG-R-006` | null separator missing/doubled、JCS bytes replaced、statement field substituted | `E_EXTENSION_SIGNATURE_INPUT` |
| `ADR4-PKG-R-007` | self-consistent re-sign with embedded/untrusted key or suite | `E_EXTENSION_TRUST_ROOT` |
| `ADR4-PKG-R-008` | archive identity/member bytes change between enumerate/read/re-read | `E_EXTENSION_SOURCE_CHANGED` |
| `ADR4-PKG-R-009` | `exported_identities` missing/renamed/substituted（包括把 key 缩写成 `exported` + `_ids`），或 source/input/nested/projection 不一致 | `E_EXTENSION_PACKAGE_IDENTITY`；无 alias/compatibility path |
| `ADR4-PKG-R-010` | payload-root version missing/moved/substituted，或 entry-list-only/alternate preimage | `E_EXTENSION_PAYLOAD_ROOT` |

#### 2.5 Attestation-production contracts

`SourceAttestation v1` 是 closed self-digested record，exact fields 为：

```text
schema_version, attestation_id, source_type, source_id, source_revision,
source_tree_digest, ordered_materials[{uri,digest}], source_recipe_digest,
attestor_id, attestor_key_id, issued_at, not_before, not_after,
production_policy_id, production_policy_digest, previous_attestation_digest?,
attestation_signature, attestation_digest
```

`BuildAttestation v1` exact fields 为：

```text
schema_version, attestation_id, builder_id, builder_key_id, build_id,
source_attestation_digest, extension_id, extension_version,
payload_root_digest, package_identity_digest,
ordered_materials[{name,digest}], build_recipe_digest, toolchain_digest,
dependency_lock_digest, sbom_digest, started_at, finished_at,
not_before, not_after, production_policy_id, production_policy_digest,
attestation_signature, attestation_digest
```

`package_identity_digest` 是 extension ID/version、publisher ID、exported IDs、contract/schema
digests 和 compatibility declarations 的独立 ADR-0003 projection；它不含 source/build/manifest/
signature/archive digest，所以 build attestation 可在 package manifest 前生成。`ordered_materials` 按
exact URI/name Unicode-scalar order，duplicate、missing、extra、order change 或 digest type confusion
拒绝。source subject 必须与全部 source materials/recipe 对应；build subject 必须同时绑定 exact
source attestation、payload product、package identity、toolchain、dependency lock 与 SBOM，不能把
“使用了某 source”替代“产出了该 product”。

attestation signature 使用与 §2.2 相同的 null-separated domain rule，但 source/build domains 分别为
`GEW-EXTENSION-SOURCE-ATTESTATION-V1` 和 `GEW-EXTENSION-BUILD-ATTESTATION-V1`，签名输入为 complete
record 去掉 `attestation_signature` 与 `attestation_digest` 后的 ADR-0003 JCS projection。source-
attestor、builder、publisher-release、provenance-policy 是四种独立 policy roles；可由同一 key 承担
仅当 trust policy 显式列出对应每个 role，不能因 publisher role 自动继承。package 内 embedded key
永不成为 trust root。

这里的 `production_policy_*` 指发布方产生 provenance 时使用的
`ExtensionAttestationProductionPolicy v1`，不是某台 installation 的 verification policy。其 closed
source schema exact fields 是：

```text
schema_version, policy_id, issuer_id, issuer_key_id,
allowed_source_types, required_source_material_kinds,
allowed_attestor_ids, allowed_builder_ids, allowed_build_recipe_digests,
allowed_toolchain_digests, dependency_and_sbom_rules,
maximum_attestation_lifetime, issued_at, not_before, not_after,
policy_signature, policy_digest
```

source/input schema IDs 是 `urn:gew:schema:extension-attestation-production-policy:1.0.0` 与
`urn:gew:schema:extension-attestation-production-policy-input:1.0.0`；self-digest projection
`urn:gew:digest-projection:extension-attestation-production-policy:1.0.0` 只删除 `/policy_digest` 并保留
signature。独立 signing-statement projection
`urn:gew:digest-projection:extension-attestation-production-policy-signing-statement:1.0.0` 只删除
`/policy_signature` 与 `/policy_digest`，使用 null-separated
`GEW-EXTENSION-ATTESTATION-PRODUCTION-POLICY-V1` domain。

source/build attestations 只绑定该 production policy ID/digest；不得出现 `installation_id`、installation
trust generation/digest、Owner identity/decision、verification time 或 local revocation high-water。
production policy 由 `provenance-policy` role 签名，但该签名只证明发布 policy provenance，不使任何
installation 信任它。某 installation 是否接受该 production policy，由 §3.1 当前
`ExtensionTrustPolicy` 的 independently configured allowed digest/role/ceiling 决定。
production policy body 不作为 bundle member 自动加载；Owner 必须先把 bounded local body 经
`register-production-policy` transaction 写入 installation trust material store，policy 中只引用其 exact
ID/digest。bundle 仅引用未知 production policy 时 fail closed。

trust root 的 wire item 是 closed `ExtensionTrustKeyEntry v1`：exact fields
`publisher_id,key_id,ed25519_public_key,roles[],source_classes[],namespaces[],extension_kinds[],
allowed_production_policy_digests[],capability_ceiling_digest,not_before,not_after,status,added_generation,
revocation_sequence`。array canonical
sorted/unique；key bytes 必须是 32-byte canonical base64url。初始空 policy/head 由产品
ReleaseInstallManifest 与 installation SecurityRuntime 的 bootstrap attestation 绑定；任何非空 key
只能经 §3.1 transaction 加入。package/attestation 自带 key、OS keychain 中同名 key、另一个 control
root 或 publisher 网络服务都不是 trust root。

verify 时先以当前 installation trust generation 验证 source role/key、时间窗和 revocation，再验证
build role/key及其 subject/material/product linkage，最后验证 publisher-release signature。`issued_at /
started_at / finished_at / not_before / not_after` 是 UTC canonical timestamps；必须满足 source issued
≤ build started ≤ build finished ≤ package ingest、且 verification time 同时位于 source/build validity
window。clock 来自 installation SecurityRuntime 的 durable observation；clock unavailable/rollback/
outside window 时拒绝。

validity 只决定某次新 install/activate 是否可接受，不把 key expiry 当作追溯撤销；之后是否阻止已
pin task 只由显式 revocation、compatibility 或 current task policy决定。revocation record 对 key、source
attestation、builder、build attestation、package/version/digest 均可定向，按 §7 monotonic high-water
处理；任何 target 在 verify 顺序中被撤销即停止。

#### 2.6 Installation verification policy and ingest record

installation verification policy 是 §3.1 的当前 committed `ExtensionTrustPolicy`，独立于 package 的
production policy。它可以比 production policy 更严格，不能因 production policy、attestation 或
publisher signature 自我一致就被替换或扩张。验证器从当前 installation head 取得 exact policy/
role/source/capability/revocation tuple，再验证 production policy、attestations、package 和 signature。

成功或失败的本地验证只生成 self-digested `ExtensionIngestVerificationRecord v1`，exact fields 为：

```text
schema_version, installation_id, ingest_id, archive_raw_digest,
payload_root_digest, package_identity_digest, source_attestation_digest,
build_attestation_digest, manifest_digest, signature_record_digest,
verification_policy_generation, verification_policy_digest,
revocation_high_water, verifier_implementation_digest, verified_at,
owner_identity, owner_decision_digest, owner_authority_digest,
decision, reason_code, record_digest
```

record source/input schema IDs 分别是 `urn:gew:schema:extension-ingest-verification:1.0.0` 与
`urn:gew:schema:extension-ingest-verification-input:1.0.0`；projection
`urn:gew:digest-projection:extension-ingest-verification:1.0.0` 只删除 `/record_digest`。该 record 进入
installation append-only ledger，不进入 bundle、package identity、attestation、publisher signature 或
task Authority Envelope。bundle 由此不能取得 installation authority；复制一个 accepted record 到
另一 installation、generation 或 archive tuple 必须拒绝并重新验证。

### 3. Installation and activation

#### 3.1 Installation trust-policy transaction

`ExtensionTrustPolicy` 的 authority 不来自 policy file 自摘要，而来自 stable control root 中唯一的
`InstallationTrustRepository`。每次变更必须是 Owner-authorized、installation-exclusive、append-
only transaction；Skill、package、publisher、task Owner string 或普通 repository write 都不能创建
trust。

`ExtensionTrustPolicy v1` 是 closed self-digested record，exact fields 为：

```text
schema_version, installation_id, generation, previous_policy_digest,
revocation_high_water, revocations[], trust_keys[], production_policies[], source_rules[],
namespace_rules[], extension_kind_rules[], capability_ceilings[],
compatibility_floors[], resource_policy_digest,
reducer_id, reducer_version, reducer_implementation_digest, policy_digest
```

source/input schema IDs 分别为 `urn:gew:schema:extension-trust-policy:1.0.0` 与
`urn:gew:schema:extension-trust-policy-input:1.0.0`；projection
`urn:gew:digest-projection:extension-trust-policy:1.0.0` 只删除根级 `/policy_digest`。所有 arrays 使用
各自 closed `$defs`、canonical sorted/unique；package 不能提供 schema/reducer。`generation` 必须是
previous + 1，`previous_policy_digest` 必须等于 current head；revocation high-water 永不降低。

唯一 genesis 是 ReleaseInstallManifest 绑定的 generation `0` policy/head：
`previous_policy_digest=null`、revocation high-water `0`、所有 rule/key/revocation arrays 为空；它由产品
bootstrap attestation 安装，不接受普通 operation。首个 Owner transaction 产生 generation `1`；其他
generation 出现 null previous 或重建 genesis 均拒绝。

policy nested item shapes 也冻结：`revocations[]` =
`{target_kind,target_identity_digest,input_kind,input_digest,reason_code,local_sequence,
effective_generation,owner_decision_digest}`；`trust_keys[]` 使用 §2.5 `ExtensionTrustKeyEntry`；
`production_policies[]` = `{policy_id,policy_digest,issuer_id,status,added_generation}`；`source_rules[]` =
`{source_type,allowed_source_ids,required_material_kinds,rule_mode}`；`namespace_rules[]` =
`{publisher_id,namespace_prefix,allowed_extension_kinds}`；`extension_kind_rules[]` =
`{extension_kind,data_allowed,executable_allowed,required_isolation_profiles}`；`capability_ceilings[]` =
`{subject_kind,subject_id,capability_set_digest}`；`compatibility_floors[]` =
`{component_kind,compatibility_policy_digest}`。每个 item `unevaluatedProperties:false`，字段缺失/extra、
duplicate identity、ambiguous overlap 或非 canonical order 均拒绝整份 policy。

唯一 reducer 是产品 ReleaseInstallManifest attested 的 closed
`gew.extension-trust-policy-reducer/1.0.0/<implementation-digest>`。输入只能是 exact committed
policy/head、下列 operation union、当前 Owner decision/Authority Envelope 和 stable installation token；
输出只能是 candidate policy 或 stable reject code。operation union 是：

```text
add-key, retire-key, rotate-key, register-production-policy,
retire-production-policy, set-source-rule, set-namespace-rule,
set-extension-kind-rule, set-capability-ceiling, set-compatibility-floor,
apply-local-revocation, apply-publisher-revocation
```

每项有 closed kind-specific old/new/target fields。reducer exact-equality 检查 expected old value，拒绝
unknown/wildcard/duplicate/conflict。policy 可按当前 Owner authority 收紧；放宽限制、加入 trust
identity/role/namespace/source/capability 是 authority expansion，必须由 exact Owner decision 与当前
Authority Envelope 覆盖。普通 task approval、publisher statement 或 package signature不能复用。

ledger 有四种且仅四种 append-only record schema，均带 common
`schema_version,record_type,installation_id,transaction_id,record_sequence,previous_record_digest,
expected_head_digest,owner_identity,owner_decision_digest,owner_authority_digest,created_at,record_digest`：

| Record type | Exact additional fields | Head effect |
|---|---|---|
| `ExtensionTrustPreparedRecord` | `expected_generation,expected_policy_digest,expected_revocation_high_water,candidate_generation,candidate_policy_digest,candidate_revocation_high_water,ordered_operations_digest` | none；candidate 不可执行 |
| `ExtensionTrustCommitRecord` | `prepared_record_digest,candidate_generation,candidate_policy_digest,candidate_revocation_high_water,committed_at` | atomic publish candidate head |
| `ExtensionTrustAbortRecord` | `prepared_record_digest,observed_head_digest,reason_code,aborted_at` | none；保留 old head |
| `ExtensionTrustRollbackRecord` | `prepared_record_digest,rollback_of_record_digest,restore_content_from_policy_digest,candidate_generation,candidate_policy_digest,candidate_revocation_high_water,committed_at` | atomic publish higher-generation rollback head |

四类 source/input schema 和 projection IDs 分别使用
`urn:gew:schema:extension-trust-{prepared|commit|abort|rollback}[-input]:1.0.0` 与
`urn:gew:digest-projection:extension-trust-{prepared|commit|abort|rollback}:1.0.0`；每个 projection 只
删除自身 `/record_digest`。`ExtensionTrustPolicyHead v1` exact fields 是
`schema_version,installation_id,generation,policy_digest,revocation_high_water,terminal_record_digest,
ledger_sequence,previous_head_digest,head_digest`，projection 只删除 `/head_digest`。

transaction 在唯一 stable control-root installation exclusive token 下执行：验证 exact chain/head →
reducer 生成 candidate → durable append prepared → 在一个 authoritative storage transaction 中写
candidate policy、append commit **或 rollback** record、CAS 更新 head → durability barrier → exact
重读/post-verify → 释放 token。abort 只能 append 并保持 head 不变。commit/rollback record、candidate
policy 与 new head 缺任一项都不是 committed；backend 不得用“最高 generation”猜测。

crash recovery 规则固定为：

- head/terminal record/policy 均未推进：使用完整 old policy；孤立 body/prepared 不可执行；
- commit/rollback record、policy 与 head 同时存在且 chain exact：使用完整 new policy；
- prepared 已写但无 terminal record/head CAS：append abort record 后保留 old head；
- head、generation、previous digest、record sequence/chain、terminal record 或 high-water 任一分歧：blocked，
  不选择最大 generation、不覆盖或删除 divergent record；
- post-verify 失败：再走 prepared + **higher-generation rollback record/head**，恢复先前可恢复的 policy
  content，但携带当前最大 revocation high-water 和所有已生效 deny；不得倒退 head/generation。

publisher-signed revocation statement 只是 bounded local untrusted input：先按 current policy 验证
publisher/key/target/sequence/signature，再由 Owner 明确授权 `apply-publisher-revocation`，经上述唯一
installation-exclusive reducer/transaction 提升 local high-water。statement 本身、copy 到 control root
或 publisher sequence 更高都不能直接改变 policy/head。local emergency revocation 同样只能走
`apply-local-revocation` transaction。

同一 stable shared/exclusive lock 保证 policy 切换与 task command 不交错。新 key/更大 ceiling 不改变
已存在 task 的 frozen authority/capabilities/version pin；task 若要采用必须显式 rebase/reapproval。
remove/revoke/tighten 在下一个 open/resume/dispatch/invoke gate 立即使不满足的 task blocked；已 started/
unknown action 继续保留 claim，只允许 query/reconcile/manual。policy rollback 不复活 revoked package，
也不抹除 task event、receipt、claim 或 audit fact。

#### 3.2 Package installation and activation

package installation 是显式 Owner-authorized local CLI use case，不是 Skill 指令或 extension code：

1. 在唯一配置的 stable control root 取得 ADR-0002 installation exclusive token；
2. descriptor-safe 地读取 bounded bundle，验证完整 member set、raw/file/manifest digests、签名、
   provenance、trust policy、revocation 和 compatibility；
3. 在未激活的 owner-only staging root 解码 deterministic contracts，检查 namespace/conflict、
   dependency closure、capability ceiling 和 executable isolation availability；
4. 复制到 immutable content-addressed version root，逐项重读验证，写 append-only install ledger；
5. 生成 self-digested `ExtensionActivationManifest`，原子切换 active extension-set reference；
6. 运行 read-only doctor，失败则切回完整旧 active set，保留失败记录供审计。

loader 只解析已激活 manifest 中的 content-addressed roots；不得从 current working directory、
`PATH`、`PYTHONPATH`、用户 site-packages、source checkout、临时目录或 package-declared locator
搜索。不得直接执行 archive/staging bytes。root、owner/mode、device/inode、member set 和 digest 在
load、session open 和每次 executable invocation 前复核。

多个版本可以 side-by-side 安装，但同一个 active extension-set 中 `(publisher, extension_id,
exported_id)` 唯一。dependency cycle、diamond 中的 version/digest 分歧、同名 shadow、duplicate
publisher identity 或 built-in collision 全部拒绝，不按 search order 猜测。

task 创建时把完整 active extension-set digest、每个 package/version/digest、contract registry、
capability profile 和 revocation high-water 冻结进 Graph/task state。resume/replay 必须解析 exact
pin；不得静默采用后来安装的版本。

### 4. Capability sandbox and allowlist

有效 capability 是以下 exact intersection，任一集合缺失即空而不是继承：

```text
package requested capabilities
∩ publisher/key capability ceiling
∩ installation extension policy
∩ task Authority Envelope
∩ runtime/adapter capability handshake
∩ operation-specific resource and side-effect authorization
∩ isolation-provider enforceable capabilities
```

capability IDs、参数 schema 和 monotonic safety rules 是版本化配置/contract。extension 不能新增
解释器可执行的 capability kind；unknown、wildcard、negative rule、环境相关默认值和请求/实际
不相等均拒绝。授权只覆盖当前 invocation，并绑定 owner/runtime/lineage、task/run/node、package/
executable、operation、ordered resources/latest fences、target、input/output schema、预算、timeout、
secret refs 和 idempotency key。

deterministic data extension 在 decode 后只有 data authority。它不能注册 Python validator/
predicate；自定义 predicate、validator 和 transform 属于 executable class。

executable extension 必须由 closed `CapabilityIsolationProvider` 执行。provider 是 platform-
neutral port 的 installation-attested implementation；只有能由 OS/VM/Wasm 等独立机制证明下列
约束时才可声明支持：

- 独立短生命周期进程；无 daemon、background worker 或 runtime-close 后残留；
- default-deny filesystem/network/process/device/IPC；只暴露当前 invocation 的 bounded inputs 和
  明确 allowlisted resources；
- `shell=false` 的结构化 locator/argv，canonical executable digest、cwd、sanitized environment；
- secret 仅按批准 reference 临时解析并最小注入，value/value digest 不进入 state、receipt 或日志；
- 配置化 CPU/time/memory/output/member/depth limits，timeout/cancel/over-limit 时终止整个 process
  group 并有界 reap；
- typed request/result protocol，输出在 copy/digest/persist 前校验、redact 和 leak scan。

某平台没有可证明满足请求 capability 的 provider 时，仅 data extension 可用；executable extension
返回 stable capability mismatch。不得以“本地用户已经能运行代码”、签名已通过或 subprocess
本身作为 sandbox 证明。

### 5. Adapter and executable trust

`ExtensionAdapterFactory` 只能由 installation authority 构造，输入是 active manifest、trust
policy、revocation ledger、closed capability/isolation registry 与当前 command scope。package 不能
传入自签 registry、factory、provider object、command locator 或 verifier。

每次 issue/invoke 必须重新验证：

- exact package/file/executable/implementation/provenance digest；
- task pin、current activation generation 和 revocation high-water；
- protocol/schema/contract compatibility 与 capability intersection；
- current owner/runtime/lineage、operation authority、resources/latest fences 和 target identity；
- isolation provider identity、配置 digest 和实际启动的 executable bytes。

request、invocation、receipt 和 fresh observation 使用 ADR-0003 self-digested closed schemas，绑定
同一 package/executable/operation/authority/full-fence tuple。ActionCoordinator 继续使用 WP-05/
WP-07A 的 durable-start、claim、call-span lock、raw-receipt-first 和 fresh reconciliation 协议；
extension 不能宣布 action 完成、消费 claim、realize target 或生成更大 authority。不可验证、超时或
ambiguous result 保持 unresolved/manual，不自动 replay 非幂等 executable。

#### 5.1 Executable output semantics and consumption boundary

每次 executable result 只能解码为 closed self-digested `ExtensionExecutionOutput v1`。source schema
`urn:gew:schema:extension-execution-output:1.0.0` exact fields 是：

```text
schema_version, output_id, output_kind,
classification_id, classification_version, classification_registry_digest,
consumer_id, consumer_version, consumer_implementation_digest,
package_identity_digest, manifest_digest, executable_raw_digest,
invocation_digest, input_digest,
task_id, run_id, node_id, owner_binding_digest, runtime_binding_digest,
lineage_digest, authority_digest, operation_class,
ordered_resources, ordered_fences, target_identity_digest,
isolation_provider_digest, session_digest, started_at, finished_at,
advisory, payload, output_digest
```

`run_id/node_id/target_identity_digest` 是 required field，允许的 kind-specific schema 可要求 exact value
或 JSON `null`，不能省略。`advisory` 必须是 `true`。digest-input schema
`urn:gew:schema:extension-execution-output-input:1.0.0` 只移除/禁止根级 `/output_digest`；projection
`urn:gew:digest-projection:extension-execution-output:1.0.0` 保留其他全部 fields。output 先执行 bounds、
structured redaction/leak scan，再进入该 envelope；通过只表示“可交给绑定 consumer 检查”，不授予
state mutation 或 trust promotion。

`payload` 是由 `output_kind` discriminator 选择的 closed one-of；不得混合 fields：

| `output_kind` | Exact payload fields | Bound advisory meaning |
|---|---|---|
| `node-candidate` | `artifact_candidates[],evidence_candidates[],diagnostics[]` | candidate artifacts/evidence only |
| `predicate-advisory` | `facts[],explanation_digest`；fact = `schema_id,body,body_digest` | untrusted facts，不是 route boolean |
| `validator-advisory` | `findings[],verdict_candidate`；finding = `finding_id,severity,evidence_digest,required_change_digest` | candidate findings/verdict |
| `transform-candidate` | `source_digest,output_schema_id,candidate_body,candidate_body_digest` | new candidate body，不覆写 source |
| `adapter-query-result` | `query_request_digest,query_receipt_digest,observation_candidate` | untrusted query observation |
| `adapter-mutation-result` | `prepared_action_digest,raw_receipt_digest,result_class` | receipt/ambiguous result，不是 success truth |
| `presentation-candidate` | `presentation_schema_id,redacted_body,redacted_body_digest` | local redacted presentation only |

`ExtensionOutputClassificationRegistry v1` 是 product built-in closed self-digested registry，exact fields
`schema_version,registry_id,registry_version,entries,registry_digest`。每个 entry exact fields 是
`classification_id,classification_version,output_kind,payload_schema_id,consumer_id,consumer_version,
consumer_implementation_digest,allowed_promotion_kind,rejection_codes,authority_effect,routing_effect,
completion_effect`；后三项必须 const `none`。source/input projection 只删除 `/registry_digest`。package/
output 不能注册 classification/consumer，也不能选择 request 未绑定的 entry。

逐类边界如下：

| Executable kind | Allowed output | Only permitted built-in consumer | Forbidden direct effect |
|---|---|---|---|
| node/agent loop | candidate artifact/evidence body、diagnostic | Artifact/Evidence application use case，经 contract/reviewer/current task gate | event commit、authority、routing、completion |
| predicate | advisory fact set与解释，不是 trusted boolean | deterministic fact validator；如需 route，只能把验证后的 fact 作为 GEEL trusted root 的新 durable input | 直接选择 edge、join、approval 或 completion |
| validator | findings/candidate verdict | closed product validator/review application；必须重算 deterministic checks | 提升 trust、接受自身 schema、关闭 finding/gate |
| transform | candidate transformed body + source/output digests | closed schema/semantic validator 后写成新 candidate artifact | 覆写 source、event/snapshot、GraphRef 或 authority |
| adapter/connector query | raw bounded observation | factory-attested query/recovery coordinator，经 fresh target identity/fence 校验 | route、claim consume、target realization、completion |
| adapter/connector mutation | raw receipt/ambiguous result | WP-05/WP-07A ActionCoordinator；receipt durable 后重新发行 fresh observation并 atomic reconcile | 自报成功、自动 replay、消费 claim、扩张资源/authority |
| presentation | redacted local presentation payload | session-bound presentation facade | durable truth、Owner decision、approval、routing、completion |

extension executable output **永远不能直接影响 authority、routing 或 completion**。纯 data extension
中的已验证 Graph/GEEL policy 可以按 ADR-0003 deterministic semantics 参与 routing；这不是 executable
predicate result。任何 authoritative state transition 都必须由产品内置 reducer/application use case
基于 durable current facts 重新验证并提交，且引用 exact advisory output 只是审计输入之一。

#### 5.2 Consumer promotion and rejection transitions

consumer 不是 output 内字符串授予的身份。application 从 classification registry 解析 exact
`consumer_id/version/implementation_digest`，由 product installation attestation 构造 consumer，并在
调用前/同 transaction 内重验 task/session/package/policy/revocation/fences。output 中 tuple 只作 exact
echo；foreign、stale 或 self-consistent substitution 在 consumer call 前拒绝。

消费只有两个 closed transition：

- `ExtensionOutputRejectedTransition` exact fields：
  `schema_version,output_digest,classification_registry_digest,consumer_id,consumer_version,
  consumer_implementation_digest,task_id,expected_task_revision,reason_code,transaction_id,
  transition_digest`。它可记录非披露 rejection，但不产生 domain candidate；
- `ExtensionOutputPromotedTransition` exact fields：
  `schema_version,output_digest,classification_registry_digest,consumer_id,consumer_version,
  consumer_implementation_digest,task_id,expected_task_revision,current_snapshot_digest,
  promotion_kind,produced_record_ref,produced_record_digest,transaction_id,transition_digest`。promotion 只
  能按 registry 生成 candidate artifact/fact/finding/transformed body/query observation/raw receipt/
  presentation；同一 repository transaction CAS task revision并写 output reference、transition 与 candidate。

两类 source/input schemas 分别使用
`urn:gew:schema:extension-output-{rejected|promoted}[-input]:1.0.0`，projection 只删除各自
`/transition_digest`。promotion 的 `produced_record_digest` 必须由 consumer 从 payload bytes 重算；output
不能传入已有 trusted ref。adapter mutation 仍优先遵守 raw receipt durable ordering，promotion 不消费
claim、不 reconcile target；fresh observation 与 ActionCoordinator 才能推进。predicate promoted fact
只有成为 independently validated durable GEEL trusted-root input 后，才可由后续 deterministic route
transaction 消费；promotion 本身不选择 route。

当前 Accepted ADR-0003 尚未登记上述 source/input schemas、projections、classification/consumer
registries、promotion/rejection semantics，也未允许 non-built-in executable output。故在 **ADR-0004
Accepted、ADR-0003 对这些 exact contracts 的独立 revision Accepted、且相应 conformance gate PASS**
三者全部成立前，所有 non-built-in executable kinds（node、predicate、validator、transform、adapter/
connector query/mutation、presentation）统一 fail closed。任一 gate 缺失时 FR-18 只能加载
deterministic data extension；不存在 advisory executable 例外。

### 6. Core invariant and security floor

extension 永远不能覆盖或降低：

- canonical serialization、schema profile、digest projection、resource limits 和 closed registries；
- graph transition/reducer、authority、lease/fence/claim、review independence、completion gate；
- privacy/redaction、secret reference、retention、migration/activation 和 audit requirements；
- built-in identity、error semantics、capability meaning 或 fail-closed behavior。

扩展 policy 只能在允许的 extension namespace 中增加约束或选择；不能把 deny 变为 allow、把
required evidence 变为 optional，或把 unknown/incompatible 解释为成功。冲突或无法证明 monotonic
safety 时整包拒绝，不做部分 best-effort load。

### 7. Revocation

revocation 有两种 bounded local **input**：publisher-signed `PublisherRevocationStatement` 与 Owner
发起的 local emergency request；两者都不直接生效。statement exact fields 是
`schema_version,publisher_id,publisher_key_id,target_kind,target_identity_digest,publisher_sequence,
reason_code,issued_at,signature,statement_digest`，不包含 installation tuple。验证通过后仍必须由 Owner
授权 §3.1 `apply-publisher-revocation` transaction；emergency request 走
`apply-local-revocation`。reducer 产生 closed `ExtensionRevocationEntry` 并写入 candidate policy，绑定
input digest、target、原因、local effective sequence 与 transaction/Owner decision。只有 committed
policy/head 中的 entry/high-water 是 installation truth。

statement source/input schema IDs 是
`urn:gew:schema:extension-publisher-revocation:1.0.0` 与
`urn:gew:schema:extension-publisher-revocation-input:1.0.0`；self projection 只删除
`/statement_digest`，publisher signing-statement projection 删除 `/signature` 与 `/statement_digest`，
使用 `GEW-EXTENSION-PUBLISHER-REVOCATION-V1` domain。通过这些 wire checks 仍不产生 local state。

删除 input、回滚 active extension set、copy publisher statement 或安装旧 bundle 都不能降低 local
high-water 或恢复已撤销 identity。publisher sequence 只做 statement replay/order 校验，不能替代 local
generation/high-water；另一个 installation 对同一 statement 必须获得自己的 Owner authorization。

revocation 在 install、activate、task create/open/resume、node dispatch 和每次 executable issue/
invoke 前检查。revoked package 不接受新 task 或新 invocation；已 pin task 转为 explicit blocked，
需要 Owner 选择安全 rebase/update/rollback。若已有 durable start/unknown action，保留 receipt、claim
和资源冻结，只允许 factory-attested query/reconcile 或 Human/manual；不得卸载审计材料、自动 replay
或把“已撤销”当作未执行。

key rotation 是显式 installation-policy transaction：新 key 需满足当前 trust policy；continuity
statement 只是 policy 要求时的 bounded local input，最终仍必须有 exact Owner-authorized transaction。
rotation 不改变历史 package
identity；revoked key 签发的新 package/rotation/revocation 记录均拒绝。

### 8. Update, rollback and removal

没有 auto-update、后台检查或网络 fetch。update 只能消费 Owner 明确提供的离线 bundle，并走完整
install/doctor/activation gate。新版本不会原地覆盖旧 bytes；compatibility dry-run 和 dependency
closure 完成后才原子激活。

既有 task 保持 exact version pin；升级它需要显式 task rebase、最小 invalidation 和必要的 Owner
reapproval。若旧 pin 被撤销或不再兼容，task blocked，而不是偷偷迁移。

rollback 切换到仍满足当前 trust/revocation/compatibility 的完整旧 extension-set；不能降低
revocation high-water、删除新版本产生的 events/receipts/claims，或使旧 executable 读取不兼容
state。removal 仅在 retention、task pins、unresolved actions、rollback holds 和审计 references 都
允许后执行；逻辑 tombstone 先于物理 purge。

### 9. Diagnostics, privacy and Skill boundary

所有拒绝生成稳定、非披露 diagnostic：source/signature/provenance、compatibility、capability、
conflict、revoked、sandbox unavailable、execution unresolved 分开分类，但不回显 secret、完整路径、
未授权 package metadata 或其他 Owner/task identity。

#### 9.1 Offline trust plane versus authorized task action plane

v1 明确分离两个 capability plane：

| Plane | Network rule | Authority and evidence |
|---|---|---|
| extension trust plane | **绝对无网络** | Owner 提供的本地 bundle/trust/revocation input；installation exclusive transaction；本地 signature/provenance verification |
| task action plane | default deny；仅对 exact authorized operation 临时开放 | task Authority Envelope + capability intersection + disclosure decision + WP-05/WP-07A action/target/receipt/reconciliation |

package discovery、key discovery、source/build provenance lookup、install、doctor、update、revocation、
rollback 和 removal 都属于 trust plane：不得创建 socket、DNS request、proxy call、package-manager
fetch、transparency-log query、OCSP/CRL request、marketplace search 或 remote fallback。所有 trust root、
revocation statement、bundle 和 proof 必须作为 Owner 明确提供的 bounded local input；缺失/陈旧时
blocked，不从网络补齐。package manifest 请求 network 不能改变此规则。

运行期只有 adapter/connector query 或 mutation 可以请求 network capability；predicate、validator、
transform、node computation、presentation 和 installer 永远不获得 network。有效授权除 §4 intersection
外还必须绑定 exact protocol/host/port 或 connector target identity、DNS/redirect/proxy/TLS policy、
request operation/body digest、allowed response bounds、disclosure plan、secret references、timeout/
idempotency 和 ordered resources/latest fences。环境 locator/endpoint 来自安装或项目配置，不写进
engine，也不能由 package output 替换。

network call 必须走与其他真实 action 相同的 durable prepared/start/claim/call-span/receipt/fresh-
observation/reconcile protocol；read-only remote query 也产生 typed query receipt 与 disclosure audit，
不能成为 package update/revocation side channel。redirect、新 DNS identity、proxy、额外 endpoint、
telemetry、callback 或 response-triggered follow-up 都视为新 target/action，未经 authority 时零 call。
receipt 不等于目标事实，completion 仍只消费 fresh verified observation。

因此 “local-first” 指 trust/control plane 与 durable state 本地，不把已批准的 task external action
伪装成安装能力。任何真实 network/external communication 仍需当前 Authority Envelope 的单独授权；
本 ADR 不授予该权限。

Skill 只负责 discover/locate/versioned CLI envelope 和展示，不解析签名、不决定 capability、不维护
active registry、不宣称完成。每个命令结束或暂停后进程退出；安装、更新、撤销和运行都不创建
daemon、监听端口或远程 control plane；安装、更新与撤销无外部通信，运行期外部通信只允许走
§9.1 的 separately authorized task action plane。

## Invariants

- ADR-0004、§5.2 指定的 ADR-0003 revision 与 contract conformance gate 任一未关闭时，non-built-in
  executable loader 必须拒绝全部 executable kinds；
- package signature、provenance 或 hash 不产生 authority，只证明 exact source tuple；
- bundle digest graph 必须 acyclic；archive raw digest 只进入外部 ingest ledger；
- 不可信 extension code 永不 import 到产品核心 Python 进程；
- executable 只能在 installation-attested、可实际强制请求能力的 isolation provider 中运行；
- capability 是 default-deny exact intersection，不能由 package、Skill 或 adapter 自授；
- trust-policy head/generation 与 revocation high-water 只能经 Owner-authorized installation-exclusive
  append-only transaction 前进；rollback 也创建更高 generation；
- executable output 仅为 advisory/untrusted input，不能直接影响 authority、routing 或 completion；
- task pin 与 revocation high-water 在每次 resume/dispatch/invoke 前复核；
- update/rollback 不降低 revocation、fence、claim、audit 或 security floor；
- trust plane 绝对无网络；task network 仅经 separately authorized action plane；无 daemon、无跨 runtime
  task transfer；环境值只来自版本化配置。

## Options Considered

### Offline signed immutable bundle plus attested isolation — candidate

同时给出可重放来源、原子安装、task pin、offline revocation 和实际 capability containment。代价是
需要 package tooling、trust/revocation ledger、平台 isolation provider 与更大的 conformance/
fault matrix；没有合格 provider 的平台只能加载 data extension。

### Built-in extensions only — rejected as the FR-18 implementation target

安全面最小，也符合当前 gate-before-ADR 状态，但不能实现已批准的本地 non-built-in extension
能力。它仍是本 ADR review 或 implementation 失败时的 rollback state。

### Unsigned local path or TOFU — rejected

开发便利，但路径、owner 或首次观察不是可移植 provenance；会允许 shadow、replacement 和错误
publisher identity，无法支持可信 update/revocation。

### Signed in-process Python plugins — rejected

性能和生态便利，但签名不约束运行时 capability；任意同进程代码可绕过 validator、registry、
redaction 和 authority gate，直接违反 ADR-0003 trust boundary。

### Plain subprocess with argv/filesystem allowlist — rejected

结构化启动降低注入风险，却不能阻止 executable 使用宿主可见的 filesystem、network 或进程能力。
没有独立 enforcement attestation 时不能称为 sandbox。

### Online marketplace, transparency service or remote revocation feed — rejected for v1

可改善分发体验与生态规模，但引入 runtime network、远程状态和后台更新，改变批准的 local/
Skill-first/no-daemon 边界。未来采用必须回到 Human，而不是本 ADR 的实现细节。

## Consequences

正向：

- FR-18 的 data 与 executable extension 拥有明确且不可混淆的 trust path；
- package bytes、publisher、安装 generation、task pin、capability 和 action receipts 可独立重放；
- 无 sandbox provider、撤销或不兼容时保持明确 blocked，不虚假降级；
- extension 无法覆盖 core security floor 或以 Skill prompt 取得权限。

成本与约束：

- 需维护 Ed25519 verification provider、offline provenance、trust/revocation ledger 和 immutable
  content store；
- 每个受支持平台都要独立证明 isolation provider 的实际 enforcement；
- executable extension 的启动和 typed IPC 有额外延迟；
- 本地开发也必须显式签名和安装，不能从 checkout 即时 import；
- revocation 可使 pinned task blocked，需要 Owner 选择 rebase、rollback 或 manual reconciliation。

## Validation and Rollback

ADR Accepted 后的实现至少必须覆盖 `GEW-REQ-FR18-P/R`、`ORA-EXTENSION-POLICY`，并证明：

- §2.4 golden bytes/digests/RFC signature vector 跨独立实现完全相等；全部 `ADR4-PKG-R-001～010`
  产生指定错误并保持零 install mutation；
- exact signed bundle 能安装、pin、load、resume 和 side-by-side update；
- missing/tampered/re-signed-substitution/unknown key/expired key/revoked key、manifest/file/archive digest
  不一致、duplicate/path/link/bounds 攻击均在 install mutation 与 extension call 为零时拒绝；
- source/build attestation 的 wrong role/key/time/order、missing/extra/reordered material、source/product/
  recipe/toolchain/SBOM substitution 与 revocation 在 package signature 通过时仍拒绝；
- production policy 中注入 installation tuple、bundle 自带 verification policy、跨 installation ingest
  record replay、current policy generation/high-water substitution 都拒绝；bundle 永不获得 installation
  authority；
- trust-policy transaction 的 wrong Owner/authority、stale generation/head/high-water、expansion without
  exact decision、每个 durable point crash、divergent chain 与 rollback 都只产生 complete old、complete
  new 或 installation blocked，且 rollback generation/high-water 不倒退；
- prepared/commit/abort/rollback record type/chain/head substitution、非 closed reducer、publisher statement
  未经 Owner transaction 均不能改变 policy/revocation high-water；
- data extension 不产生 callable；executable 在 isolation unavailable、capability missing/extra、wrong
  task/owner/runtime/lineage/resource/fence/target/provider 时零 call/零 write；
- 每种 §5.1 payload union 的 wrong/mixed kind、classification/consumer substitution、forged promotion/
  success/route/authority/completion 与 direct repository call 都不能改变 authoritative state；三重 gate
  任一未关闭时全部 non-built-in executable kind 的 load/call/write counter 为零；
- built-in collision、dependency conflict/cycle、version shadow 和 security-floor override 整包拒绝；
- task-start pin、restart、update、rollback、revocation、unknown action 和 crash cuts 只产生 complete old、
  complete new 或 explicit blocked/unresolved；
- trust-plane socket/DNS/proxy counter 恒为零；task network 的 missing disclosure/authority、wrong target/
  redirect/proxy/receipt/fresh observation 为零 call 或 unresolved，authorized fixture 只调用 exact target；
- no daemon/runtime-exit、secret non-persistence、non-disclosing diagnostics 与 config-swap 成立；
- independent reviewer 验证 exact source manifest、commands、exit evidence 和 candidate verdict。

若 review 或实现未通过，回滚为 **built-in-only + deterministic data extensions disabled by default**：
保留 install/revocation/audit facts，active registry 不发布 non-built-in executable；不得以 unsigned
local path、in-process import 或 unsandboxed subprocess 临时绕过。

## Review and Acceptance Gate

当前候选不改变批准的 local、Skill-first、no-daemon、单 Owner/单 runtime task 或权限边界，因此
没有必须在起草阶段交给 Human 选择的 boundary-level material fork。独立 architecture reviewer
仍必须检查签名 suite、bundle reader、trust-root update、isolation provider contract 与 revocation/
task-pin semantics，以及本 revision 对五个 stable finding 的机械 closure；任何建议允许在线 trust、
daemon、in-process third-party code、unsandboxed
executable 或 capability/authority 扩张，都属于新的 material fork，必须升级 Human。

只有本 ADR 最终独立 review PASS、必要修订完成且 Disposition 被明确改为 Accepted 后，WP-08A 才可
进入下一 architecture gate。全部 executable kinds 还必须等待 §5.2 要求的 ADR-0003 独立 revision
Accepted 和 exact contract conformance PASS；三个 gate 不能互相替代。任何未来 Proposed revision
均不能被实现或测试自动解释为 Accepted；当前 r4 + r5 的 Accepted disposition 以本文顶部状态为准。

## Traceability

- Positioning：local-first、Skill-first、Human authority、no daemon、no online marketplace；
- PRD：FR-18；NFR-02、NFR-04、NFR-05、NFR-06、NFR-08；
- Tech Spec：§3.3、§8.3、§11.1、§11.2、§12、§15；
- Impact：§8.2、§14.2；
- Plan：WP-08A architecture node/output/exit；
- Test Plan：`GEW-REQ-FR18-P/R`、`ORA-EXTENSION-POLICY` 及相关 NFR obligation rows；
- ADR dependencies：ADR-0001、ADR-0002、ADR-0003、ADR-0005；
- predecessor：WP-07A r6 PASS immutable evidence tuple（仅作为已验证 built-in action boundary）。
