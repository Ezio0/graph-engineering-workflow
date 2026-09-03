# ADR-0003: Deterministic Contract Stack

## Status

Accepted — revision 5，2026-08-13；revision 6 trust-boundary clarification，2026-08-14。
Revision 6 status is determined by the digest-bound WP-01 independent review record。

## Context

Graph、event、command、ProjectScope、Authority、Artifact/Evidence、Profile、extension 和
bundle 都需要跨进程/版本一致的结构校验、canonical digest 和有限条件表达。Prompt 或
任意代码执行不能成为 routing、authority、trust、budget 或 completion 的安全边界。

需要同时解决：

- JSON 结构版本和引用；
- Python 内 typed immutable views；
- 跨实现相同 bytes/digest；
- 条件/策略表达可静态验证、无副作用、确定性、可预算；
- schema/condition upgrade 与任务版本锁定。

## Decision

采用四层 deterministic contract stack：

1. **GEW Schema Profile v1**（JSON Schema Draft 2020-12 的冻结子集）定义 wire structure；
2. **递归不可变 Python domain models + explicit codecs** 定义 core 内 typed view；
3. **GEW JCS Input/Digest Profile v1**（RFC 8785 + SHA-256）定义 canonical bytes/digest；
4. **GEEL v1 bounded JSON AST** 定义 route、join、policy 和 completion 条件。

四层各有 exact version 和 manifest digest；任何一层未知或不兼容都在状态读取、route 或
action 前 fail closed。

### Trusted computing base and mutation boundary

本 ADR 的可信计算基（TCB）是经 source/build/install attestation 验证的产品 package、Python
interpreter 与其进程/OS sandbox。非可信输入包括 wire bytes、manifest、配置、模型/工具/adapter
输出、registry 引用和 task state；它们不得向 core 注入 callable、class、module、code object，
也不得新增或覆盖 executable registry item。产品内置 executable 必须从 closed product set
解析、由 manifest digest 锁定，并在 registry load 时冻结实际执行所需的 code/data binding。

本 ADR 的 `immutable` 指 domain/registry **instance** 递归不可变、无 input alias、仅能经验证
factory 构造；不声称能在同一 Python interpreter 内对已经获得任意产品代码执行能力的攻击者
封印 module/class/metaclass。后者已经能改写调用方、校验器与其所谓封印根，属于 TCB compromise，
不能用另一个纯 Python metaclass 充当安全边界。它由 source/wheel digest、受控安装、dependency
allowlist、进程 sandbox 和启动时 attestation 防御，而不是 contract instance API。

若未来要在同一宿主运行第三方 executable，必须重新打开本 ADR并先完成 extension trust ADR，
使用独立进程/wasm 等外部 capability isolation 与可独立验证的 code attestation；不能扩大本
合约层去宣称对任意 same-process code mutation 的防御。

### GEW Schema Profile v1

每个 schema 根必须包含：

- `$schema: "https://json-schema.org/draft/2020-12/schema"`；
- 唯一绝对 `$id: "urn:gew:schema:<kebab-name>:<major>.<minor>.<patch>"`；
- root object 的 required `schema_version` const，与 `$id` 版本完全一致；
- 安全关键 object 使用 `unevaluatedProperties: false`，array 明确 `items/prefixItems` 和
  上限引用，不能依赖 validator 默认行为。

允许的 Draft 2020-12 keywords 冻结为：

| Vocabulary | v1 allowed keywords |
|---|---|
| Core | `$schema`, `$id`, `$defs`, `$ref`, `$comment` |
| Applicator | `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`, `else`, `dependentSchemas`, `prefixItems`, `items`, `contains`, `properties`, `additionalProperties` |
| Validation | `type`, `enum`, `const`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `minLength`, `maxLength`, `minItems`, `maxItems`, `uniqueItems`, `minContains`, `maxContains`, `minProperties`, `maxProperties`, `required`, `dependentRequired` |
| Unevaluated | `unevaluatedProperties`, `unevaluatedItems` |
| Metadata | `title`, `description`, `deprecated`, `readOnly`, `writeOnly`；仅 annotation，不影响 accept/reject |
| Format | `format` 仅允许本 ADR定义的 `gew-*` formats，并且必须 assertion |

boolean schemas 允许。未知 vocabulary/keyword、`pattern/patternProperties` 或其他 regex、
`content*`、`default`、`$vocabulary`、`$anchor`、`$dynamicAnchor/$dynamicRef`、nested `$id`、
`number`、floating `multipleOf` 均拒绝。JSON numeric instance 只允许下文 safe integer，
numeric bounds 也必须是同范围 integer。每个 schema 先通过官方 meta-schema，再通过
GEW Profile linter；schema/profile validator versions 写入 registry manifest。

至少使用 Python validator 和一个独立 Draft 2020-12 implementation 跑同一 schema/instance
corpus；任何 accept/reject 差异使 registry build 失败。

### Closed schema registry

registry manifest 是 immutable、JCS-digested 的 `schema ID → schema body digest` 映射：

- product schema `$id` 只允许上述 `urn:gew:schema:` absolute form，comparison 按 exact
  ASCII bytes；duplicate ID 或 digest 冲突拒绝；
- `$ref` 只允许同 document `#/<JSON-Pointer>`，或 manifest 中 absolute schema ID 加可选
  JSON Pointer fragment；relative URI、anchor fragment、embedded schema ID、recursive/cyclic
  dependency 和未登记 target 拒绝；JSON Pointer 按 RFC escaping exact 解析；
- dialect HTTPS URI 由随产品安装的 built-in meta-schema resource 解析；它是 identifier，
  不是 network permission。任意 HTTPS/file/custom ref 即使本地可访问也拒绝；
- loader 在使用前构造完整 acyclic dependency closure，验证每个 body digest、schema
  profile、ref target 和 resource limits；task 锁定整个 registry manifest digest；
- registry 不配置 retrieve callback，schema load/evaluation 期间 network/filesystem lookup
  capability 不存在。

dependency resource 数、ref depth、schema bytes/nodes 等受 Resource Profile 约束。unknown
pointer、duplicate escaped ID、cycle 或 manifest digest swap 产生稳定 load error。

### GEW JCS Input Profile v1

JSON bytes 必须是无 BOM 的 strict UTF-8/I-JSON。parser 在 JSON escape 解码后、任何 dict
构造前检测 duplicate member name；字符串不得包含 lone surrogate/非 Unicode scalar，且
**不做 Unicode normalization**。JCS property ordering 严格按 RFC 8785 的 UTF-16 code
units，array 顺序不变。

v1 JSON number token 只允许 canonical integer grammar `0|-?[1-9][0-9]*`，明确拒绝 `-0`、
fraction、exponent、NaN/Infinity；数值范围是 `[-9007199254740991, 9007199254740991]`，GEEL
integer 相同。需要其他数值/时间的字段使用 assertion formats：

| Format | 唯一 lexical form |
|---|---|
| `gew-bigint` | `0|-?[1-9][0-9]*`，`-0` 拒绝 |
| `gew-decimal` | `-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?`，负零拒绝、无 exponent/多余尾零 |
| `gew-timestamp` | valid Gregorian `YYYY-MM-DDTHH:MM:SS(.fraction)?Z`；UTC only、秒 00～59、fraction 1～9 位且末位非零 |
| `gew-duration` | `PT(0|[1-9][0-9]*)(.fraction)?S`；非负 seconds、fraction 末位非零 |
| `gew-id` | 1～255 ASCII chars：`[a-z][a-z0-9]*(?:[._:/-][a-z0-9]+)*` |
| `gew-opaque-ref` | 2～4096 chars canonical unpadded base64url；decoded payload 是 1～3072 bytes strict UTF-8 Unicode scalar sequence；不直接显示原值 |

format validator 还执行 calendar、range、negative-zero 和 decode validity；regex 表仅描述
词法，不使用 JSON Schema regex engine。codec 不接受可转换的相近形式。RFC official
vectors、normalization-distinct Unicode、supplementary-plane keys、escaped duplicate、lone
surrogate、安全整数边界、negative zero 和各 format 等价形式均有 golden cases。

`gew-opaque-ref` 只允许 RFC 4648 URL-safe alphabet `A-Z a-z 0-9 - _`，禁止 `=` padding、
whitespace 和长度 `mod 4 == 1`。decoder 必须验证最后 quantum 的 unused pad bits 全为零，
再以 strict UTF-8 解码并拒绝 surrogate；decoded string 不做 normalization，也没有未声明的
control-character trimming。最后以同一 canonical base64url encoder 对 decoded bytes 重编码，
结果必须与输入 byte-for-byte 相同。由此 `YQ` 合法，而可解码到相同 bytes 的 `YR`、`YS`、
`YT` 均拒绝。

### Recursive immutable domain models

decode 顺序固定为 strict parse → Schema Profile validation → semantic validators → deep
copy/freeze → typed dataclass。JSON object 转为无外部 alias 的 immutable `FrozenMap`，array
转 tuple，scalar 保持 exact JSON type；set、mutable dict/list 或调用方 buffer 不进入 model。
`frozen=True` 只保护字段本身，因此 codec 必须递归冻结，并在 encode 时从 immutable tree
生成新的 JSON value。

codec 使用 exact type checks：Python `bool` 不能满足 integer，integer 不能满足 boolean，
不做 string/number/enum coercion。encode → validate → decode 必须 round-trip 等价且 digest
不变；`repr`、pickle、Python object hash/iteration order 永不作为 wire/digest 输入。

### Semantic digest envelope

一个 semantic JSON contract 的 SHA-256 preimage **唯一**为下列整个 object 的 JCS UTF-8
bytes，而不是字段字符串拼接：

```json
{
  "algorithm": "sha-256",
  "body": {},
  "canonicalizer": "urn:gew:canonicalizer:jcs-input:1.0.0",
  "contract_type": "urn:gew:contract:<type>",
  "digest_domain": "urn:gew:digest:semantic:1.0.0",
  "projection_id": "urn:gew:digest-projection:<name>:1.0.0",
  "schema_id": "urn:gew:schema:<name>:1.0.0"
}
```

上面七个且仅七个 members 是 authoritative envelope definition；全部 required，不能增加或
省略。`body` 是由 digest-input schema 验证的 JSON value，不是预编码 string/bytes；schema
version 已包含在 exact schema ID。没有自摘要字段时也使用
`urn:gew:digest-projection:identity:1.0.0`，不能省略。结果文本为
`sha256-jcs-v1:<64 lowercase hex>`。algorithm、domain、type、schema、projection、
canonicalizer 或 body 任一变化均改变 preimage。所有 contract 发布完整 source record、
projected body、preimage bytes 和 digest golden vectors。

自摘要 record 不允许通过实现约定猜测“哪些字段不 hash”。closed registry 为每个 contract
绑定一个 immutable `DigestProjection`：source schema ID、digest-input schema ID、唯一 derived
field JSON Pointer、操作 `top-level-derived-field-v1`、envelope contract type 和 projection
digest。v1 derived field 必须是一个 top-level required digest string。digest-input schema 是
独立、登记且 digest-locked 的 exact schema：相对 source schema，它只移除该 derived property
定义和 required entry，并继续禁止该 property/其他 unknown property；不是运行时改写 schema。
已批准 contract 的冻结表是：

| Contract | Derived field omitted | Fields explicitly retained |
|---|---|---|
| `EventEnvelope` | `/event_digest` | `/previous_event_digest` and all event identity/payload fields |
| `ProjectScope` | `/scope_digest` | `/discovery_digest` and all target/constraint fields |
| `GraphDefinition` | `/digest` | graph/profile/schema/registry refs and complete topology |
| `ProfileDefinition` | `/digest` | schema/graph/overlay/completion/rollback/support fields |
| `RiskOverlayDefinition` | `/digest` | overlay changes, risk and compatibility fields |
| `ArtifactContract` | `/contract_digest` | body/evidence digest requirements and all contract rules |
| `PreparedActionRecord` | `/prepared_action_digest` | baseline/snapshot/payload/authority/target fields |
| `TaskSnapshot` | `/snapshot_digest` | committed head/event digest and complete reduced state |
| `EvidenceRecord` | `/evidence_digest` | `/content_digest` and all provenance/freshness fields |
| `CompletionRecord` | `/completion_digest` | `/snapshot_digest` and all gate/evidence results |

若 concrete schema 使用不同字段名，registry build 必须先更新本表/ADR，不得创建隐式别名。

两种 projection 的算法完全分开：

- **identity creation/verification**：candidate 就是 complete source record；先由同一个 source/
  digest-input schema 与不依赖 digest identity 的 semantic validators 验证，然后 candidate 的
  deep immutable JSON copy 成为 `body`。record 没有 derived digest field；
- **self-digest creation**：输入 `candidate_without_digest`，它必须根本不存在 derived key；先
  由 digest-input schema 和 pre-digest semantic validators 验证，deep copy 原样成为 `body`，
  构造上面七-member envelope、JCS/hash，随后在 fresh copy 中插入唯一 derived key/digest，
  用 source schema 验证 complete record，再执行依赖 identity 的 semantic validators；
- **self-digest verification**：strict parse complete record → source schema 与 digest lexical
  validation → 保存 expected digest → fresh deep copy 后断言并删除恰好一个 configured
  top-level derived key → 用 digest-input schema/pre-digest validators 验证该 candidate → candidate
  原样成为 `body` → 构造七-member envelope/JCS/hash → constant-time compare → identity-dependent
  semantic validators → freeze。

creation candidate 中 key 已存在（即使 null/空串/placeholder）、verification complete record
中 key 缺失、projection 多删/修改任何 value、source/digest-input schema pair 不匹配都立即
拒绝。projection 自身不接受“有或无”两种输入；creation 不调用 deletion，verification 必须
删除一次。registry build 用 structural diff 证明 schema pair 只具有上述一项差异。

arbitrary binary body 使用独立 `sha256-raw-v1:<hex>`（直接 hash exact raw bytes）命名空间；
它只能出现在 `object_body_digest` 字段。引用它的 semantic metadata 仍经上述 envelope
绑定 object kind、media type、size、sensitivity 和 raw digest。schema 禁止把 raw digest
填入 semantic digest 字段，避免 type confusion。

### GEEL v1 normative AST

每个 AST node 是 exact-property JSON object，通用形状为：

| Node | Required fields | Signature |
|---|---|---|
| literal | `op="literal"`, `value` | → exact JSON scalar |
| path | `op="path"`, `root`, `tokens` | trusted root × path → value/error |
| all/any | `op`, `args`（`minItems: 1`） | non-empty `bool[] → bool` |
| not | `op`, `arg` | `bool → bool` |
| eq/ne | `op`, `left`, `right` | same-type JSON values → bool |
| lt/lte/gt/gte | `op`, `left`, `right` | two integer or two string → bool |
| contains | `op`, `container`, `value` | array × value → bool |
| in | `op`, `value`, `container` | value × array → bool |
| length | `op`, `value` | string/array/object → integer |
| exists | `op`, `root`, `tokens` | path existence → bool |
| is_type | `op`, `value`, `expected` | value × `null|boolean|integer|string|array|object` → bool |
| predicate | `op`, `predicate_id`, `version`, `args` | built-in signature → declared type/error |

`root` 是 Graph validator 声明的 fixed trusted roots（如 `input`、`snapshot`）；`tokens` 是
static array of object-key strings 或 nonnegative array indices，禁止 dynamic path。load 时
解析每条 path 的 schema type 和 allowlist。missing 与 null 不同：path missing 返回
`E_PATH_MISSING`，穿过错误 container 返回 `E_PATH_TYPE`；`exists` 对 missing 返回 false，
但 invalid root/token/type 仍 error。

没有 coercion/truthiness。eq/ne 要求 operand type 相同并按递归 JSON value equality；不同
type 返回 `E_TYPE`。order 只允许同类 safe integer，或按 Unicode scalar value sequence
比较的 string。contains 仅表示 array membership，in 是参数反向；不提供 substring。
length 对 string 计 Unicode scalar、array 计 element、object 计 member。

空 `all/any` 在 AST load 时以 `E_SCHEMA` 拒绝，不定义 vacuous truth。JSON object member 的
serialization order 永远不决定求值。每个 multi-operand node 的唯一 evaluation sequence 是：

| Operator | Operand sequence |
|---|---|
| `all`, `any` | `args[0]..args[n-1]` |
| `not` | `arg` |
| `eq`, `ne`, `lt`, `lte`, `gt`, `gte` | `left`, then `right` |
| `contains` | `container`, then `value`; membership compares array index 0..n-1 |
| `in` | `value`, then `container`; membership compares array index 0..n-1 |
| `length`, `is_type` | `value` |
| `predicate` | `args[0]..args[n-1]`, then the predicate body |

`literal/path/exists` 没有 expression child；path token 按 array index 顺序读取。所有 operands
**eager** 求值，不 short-circuit，并按上表收集 error；完整 evaluation 成功后第一个 operand
error 胜出，只有无 child error 才执行 operator type/combine step。

错误阶段和优先级同样冻结：bounded parse/shape 超限 `E_LIMIT` → AST Schema Profile validation
`E_SCHEMA` → operator/predicate registry resolution `E_OPERATOR` → static root/path/signature/type
validation（相应 `E_PATH_*`/`E_TYPE`）→ runtime evaluation。前一阶段有 error 就不进入后一阶段。

Schema Profile evaluator 必须穷举当前 instance 的全部失败并先规范化为下述 error record；
`rule_id` 对 validation keyword 是 `schema/<exact-keyword>`，对 format 是
`format/<exact-gew-format>`，其他 rule 必须来自 task exact-pin 的 immutable
`ErrorRuleRegistry`。registry 使用 exact stable ID 集合，不含 message template/rank；未知、缺失
或 digest mismatch 在 evaluation 前 fail closed。schema 同阶段 winner 按下列 tuple 升序：
`(instance_path JCS bytes, rule_id UTF-8 bytes, definition_path JCS bytes, source_id UTF-8 bytes)`。
因此不依赖 schema/member serialization 或 validator 迭代顺序；完全相同 tuple 必须产生完全
相同 record，否则 implementation conformance failure。

runtime 每项工作先收费；若预算不足，`E_BUDGET` 立即终止并优先于尚未完成的 eager semantic
errors。若预算充足，则按 operand sequence 取第一 error；child error 优先于当前 operator 的
`E_TYPE`，path error 在该 path node 内优先于 predicate/operator error。predicate 输入完成且
类型正确后才调用；其声明 error 是 `E_PREDICATE`。

error taxonomy 固定为 `E_SCHEMA`、`E_OPERATOR`、`E_TYPE`、`E_PATH_MISSING`、`E_PATH_TYPE`、
`E_PREDICATE`、`E_BUDGET`、`E_LIMIT`。evaluation result 只有以下两个 exact-property shapes；
`value` 与 `error` 互斥，没有可选 detail/message/actual value：

```json
{"schema_version":"1.0.0","status":"ok","value":true}
```

```json
{
  "error": {
    "code": "E_SCHEMA",
    "definition_path": [],
    "evaluation_path": [],
    "instance_path": [],
    "phase": "schema",
    "rule_id": "schema/type",
    "source_id": "urn:gew:schema:geel-expression:1.0.0"
  },
  "schema_version": "1.0.0",
  "status": "error"
}
```

所有 path 都是 JSON array：object key 用 string、array/operand index 用 nonnegative safe integer；
不用 JSON Pointer string。`definition_path` 指 schema/AST/predicate definition，`instance_path`
指被检查 input，`evaluation_path` 是从 GEEL root 按上表 child sequence 的 index path；不适用
时必须是 `[]`，不能省略。`phase` exact enum 为 `limit|schema|registry|static|runtime|budget`；
`source_id` 是 exact schema ID、GEEL digest 或 predicate ID；`rule_id` 是上述 registry ID。
每个 code/phase 合法组合和 stable rule ID 由同一 ErrorRuleRegistry schema 约束。诊断性自然
语言只能作为不参与 route/digest 的另一个 display record。安全条件 error 永不转换为
true/false；Policy/Route Engine fail closed，并按配置的 error code route，无 route 则 blocked。

明确禁止循环、递归、assignment、I/O、network、filesystem、clock、random、environment、
reflection、dynamic property、regex 和任意 function call。时间只读取 event/snapshot 中的
canonical timestamp。

### Resource Profile and executable registry

安装的 immutable `ResourceProfile` 配置为 raw document/schema bytes、UTF-8/string scalars、
parse tokens/depth、object properties、array items、registry resources/ref depth、schema
locations、AST nodes/depth、path tokens、result bytes 和 abstract temporary units 提供全部
**有限 hard limits**，另提供 finite `work_budget`。project/task override 只能逐项降低。

task 还 exact-pin 一个 versioned、JCS-digested `CostSchedule`。它是 exact-property object：
`schema_version`、`schedule_id`、`coefficients`；`coefficients` 必须包含下表每个 event ID 恰好
一次，禁止 unknown/missing key。每个 coefficient 是 `1..9007199254740991` 的 integer，
ResourceProfile limit/budget 也在此正整数范围。schedule 先经 schema/digest 验证；零、负数、
fraction、overflow 或不完整 schedule 在读取任何不可信工作输入前拒绝。默认数值在配置，
engine 只实现下述通用计数算法。

#### Normative count model

`measure(v)=(nodes,members,items,string_scalars,canonical_bytes)` 定义如下：每个 JSON value
（含每个 scalar/container）计一个 node；object 的每个 key/value association 计一个 member，
key Unicode scalar 计入 string_scalars；array 每个 element 计一个 item；string value 的 Unicode
scalar 计入 string_scalars；`canonical_bytes` 是该 value 按 JCS 编码后的 byte length。遍历 object
严格用 JCS key order、array 用 index。所有 counts 都是数学非负整数，与实现缓存/容器无关。

JSON lexical token 是每个 `{ } [ ] : ,` punctuator，或一个完整 string、number、`true`、
`false`、`null` token；whitespace 不是 token但仍是 input byte。schema location 是能独立应用
于 instance 的 root/boolean/schema-object location；keyword dispatch 是在一个
`(schema location, instance location)` invocation 中检查一个 present allowed keyword。ref edge
是 registry closure 中一个 literal `$ref` occurrence；ref invocation 是运行时沿该 edge 一次。

每个 charge event 的 `count` 和 order 完全冻结：

| Event ID | Exact count / traversal |
|---|---|
| `parse.input_byte`, `parse.token`, `parse.string_scalar`, `parse.member`, `parse.item`, `parse.container` | 分别是 raw UTF-8 bytes；按 source byte order 的 lexical tokens；string/key escape 解码后的 scalars；source order members/items；每个 `{`/`[` container |
| `registry.resource`, `registry.schema_byte`, `registry.schema_location`, `registry.ref_edge`, `registry.pointer_token`, `registry.digest_compare` | closure 按 schema ID UTF-8 order；各 resource exact bytes/location/ref occurrence/pointer token；每个 manifest body 一次 digest compare |
| `schema.instance_visit`, `schema.keyword`, `schema.property`, `schema.item`, `schema.branch`, `schema.ref`, `schema.format` | 每次 schema-location/instance-location invocation；每个 present keyword dispatch；properties/dependent/unevaluated 检查的每个 instance member；items/contains/unevaluated 检查的每个 instance item；每个 allOf/anyOf/oneOf/not/if-then-else declared branch；每个 ref invocation；每个 format invocation |
| `format.scalar`, `format.decoded_byte` | format input 的全部 Unicode scalars；opaque-ref 的 decoded bytes，其他 format 为 0；不因早期 lexical failure少计 input scalars |
| `compare.base`, `compare.node`, `compare.member`, `compare.item`, `compare.string_scalar`, `compare.canonical_byte` | 每次 equality/order 一个 base，再对两 operand 的 `measure` 各 component 之和收费；即使类型/首项已不同也收完整 measure |
| `unique.pair` | `uniqueItems` array 对所有 `0 <= i < j < n` 各一次；每 pair 另执行完整 compare events |
| `geel.node`, `geel.operand`, `geel.path_token`, `geel.membership_item` | 按 §GEEL operand sequence 每个被访问 AST node、child operand、path token、contains/in array index；eager 全量，不因已有 error/匹配少计 |
| `executable.base`, `executable.input_node`, `executable.input_scalar`, `executable.input_byte` | 每次 predicate/validator/transform 一个 base，并按全部 validated inputs 的 measure nodes/string_scalars/canonical_bytes；manifest 必须为这四项逐项声明正整数 multiplier |
| `canonical.value`, `canonical.member`, `canonical.item`, `canonical.string_scalar`, `canonical.output_byte`, `digest.input_byte` | 每次 result/envelope canonicalization 按 measure 各 component；digest 对 exact preimage 每 byte |
| `result.field`, `result.node`, `result.output_byte` | exact result record 的 top-level+nested object members、measure nodes、JCS bytes |

非 executable event 的 multiplier 恒为 1；四个 executable events 使用 built-in manifest 对应
event 的显式 `1..9007199254740991` multiplier，禁止默认、零、负数或 unknown key。每个 event
charge 为 `coefficient[event_id] × count × multiplier`。arithmetic 使用数学非负整数；实现可用
arbitrary precision，或在部分积大于剩余 budget 时标记 exact `over-budget`，不得 wrap/
saturate。work balance 在实际读取、比较、调用或分配前原子扣减；余额不足时不执行该 event
对应工作并返回 `E_BUDGET`。

#### Recursive charge-event emission

所有 charge **逐 occurrence、内联、永不跨 occurrence/event ID 聚合**。`count == 0` 不 emit；
正 count 只 emit 一条。一个 public parse/load/validate/evaluate/canonicalize operation 创建一个
`WorkContext(initial_balance)` 和 root operation frame `operation_path=[]`。每当下面算法调用 child
operation，按 parent 实际 child-call 顺序从 0 开始分配 ordinal，并令 child path 为
`parent_path + [ordinal]`；非 operation 的普通循环不创建 frame。全 trace 的 `event_ordinal`
从 0 严格递增，失败 attempt 也占一个 ordinal。

每次 `emit(event_id,count,multiplier)` 生成以下 exact-property attempt record。所有数值字段用
canonical unsigned decimal string；`status="charged"` 时 `post_balance` required，
`status="rejected"` 时禁止 `post_balance`：

```json
{
  "amount": "3",
  "coefficient": "1",
  "count": "3",
  "event_id": "compare.node",
  "event_ordinal": "12",
  "multiplier": "1",
  "operation_path": [0, 2],
  "post_balance": "7",
  "pre_balance": "10",
  "status": "charged"
}
```

`emit` 顺序是：验证 event/count/multiplier → 执行该 occurrence 的 hard-limit/temp acquire check
→ 计算 amount → append attempt。hard limit 失败直接产生 `E_LIMIT`，不 append charge attempt；
balance 足够则 atomic subtract/`charged` 后才执行工作；不足则 append `rejected`（无 subtract）并
以 `rule_id="budget/<event_id>"`、当前 definition/instance/evaluation paths 返回 `E_BUDGET`。
不再 emit 任何后续 event。对应 input 已在先前安全步骤中解析出来不代表当前 semantic work
已经执行；OS guard 仍只作第二层。

operation 的规范 emitter 如下；表中“child”必须在该位置完整 emit 后才回到 parent：

1. **strict parse**：先逐 raw byte emit `parse.input_byte(1)`；lexer source-order 每识别一个
   token emit `parse.token(1)`，container token 再 emit `parse.container(1)`，string/key 每成功
   解码一个 scalar emit `parse.string_scalar(1)`，每遇到 member/item 在其 value 前 emit对应
   event。无效 lexical unit 只计此前完成 occurrence；parse error 随即停止。
2. **registry load**：resource 依 schema ID UTF-8 order。每 resource 依次 emit resource(1)、
   schema_byte(total positive bytes)、schema_location(按 definition JCS traversal 每个 1)、
   ref_edge(按 definition path 每个 1，并紧接其 pointer_token逐个 1)、digest_compare(1)。
3. **schema `validate(location,instance)`**：emit instance_visit(1)，再按 present keyword UTF-8
   byte order逐 keyword emit schema.keyword(1)。`$ref` 随即 emit schema.ref(1)并 inline child
   `validate(target,instance)`；`format` emit schema.format(1)并 inline format child；property/
   item keyword 按 instance JCS key/index，每项 emit schema.property/item(1)并 inline适用 child
   validate；combinator 按 schema array index/`not`/`if`,`then`,`else` 顺序，每 branch emit
   schema.branch(1)并 inline child validate；`uniqueItems` 按 `(i,j)` lexicographic 每 pair先 emit
   `unique.pair(1)`，再 inline compare child。其他 keyword 不创建 child。`contains` 全 items。
4. **format**：按 input scalar order每个 emit format.scalar(1)；opaque-ref decode 后按 byte order
   每个 emit format.decoded_byte(1)，然后执行 canonical re-encode comparison。
5. **compare**：依次 emit `compare.base(1)`、`compare.node`、`compare.member`、`compare.item`、
   `compare.string_scalar`、`compare.canonical_byte`；后五项各用两 operand measure component sum，
   零项跳过。这里明确发生在所属 `unique.pair` 或 GEEL membership event **之后**。
6. **GEEL evaluate**：进入 node emit geel.node(1)；按 §GEEL sequence，每 child 先 emit
   geel.operand(1)再 inline evaluate child；path逐 token emit geel.path_token(1)。operand 完成后，
   equality/order inline compare child；membership 按 index先 emit membership_item(1)，再 inline
   compare child；predicate inline executable child。eager semantic error 暂存，budget error
   立即终止。
7. **executable**：按 base、input_node、input_scalar、input_byte 顺序各 emit 一个正 count event；
   counts 聚合该 single invocation 的全部 validated inputs，随后才调用 body。
8. **result/canonical/digest**：构建 exact result 时依次 emit result.field、result.node；每写一个
   output byte emit result.output_byte(1)。canonicalize child 依次按 complete value measure emit
   canonical.value/member/item/string_scalar，写每个 JCS byte emit canonical.output_byte(1)；若
   caller 请求 digest，canonical child 完成后进入 digest child，按 preimage byte order逐 byte
   emit digest.input_byte(1)，然后才 update SHA-256。

上述列表定义 operation boundary 和 nesting，取代任何“按全局 event ID/表 row 排序”的解释。
例如 unique pair trace 必然是 `unique.pair → compare.base → compare.*`，schema ref/format child
必然插在触发 event 后、下一个 sibling keyword 前。golden trace 必须包含每个 attempt 的所有
字段，以及最终 result/error record。

Schema combinator 为收费和 error collection 全量遍历 declared branches；`contains` 全 items。
`uniqueItems` 总是全 unordered pairs。predicate/validator/transform multiplier 只能作用于上面
四个 input counts，不能使用 measured time、callback 或 data-dependent branch；缺失/无效
manifest formula 即 executable 不可加载。

#### Normative temporary units

temporary units 是 hard limit、不是 work coefficient；抽象 acquire/release 与实现 allocator
无关。parse 在读 `{`/`[` 时 acquire 1 frame，到对应 close 后 release；解码 string token 前
acquire 其 raw token byte length，到 strict UTF-8/scalar validation 后 release；container 每
保留一个 member acquire 2、每 item acquire 1，到该 container freeze 后 release；JCS object
ordering acquire member count 个 sort units，到 order 确定后 release；schema combinator 在每个
branch result 产生时 acquire 1，到组合结果决定后全 release；recursive compare 每进入一对
values acquire 1 stack unit，退出该 pair release；result/canonical buffer 在写 byte 前 acquire 1，
完整 bytes 被 hash/交给 caller 后 release。某时刻 units 是所有 live acquisition 的数学和，
每次 acquire 前比较 limit；任何实现即使 streaming/caching 不同也使用这条抽象 lifetime。

`E_LIMIT` 仅表示 raw/shape/depth/count/result/temp hard limit：parse 按 input byte/token order，
post-parse tree 按 JCS object key/array index，registry 按 ID，AST 按上节 operand sequence 找到
第一处 over-limit。`E_BUDGET` 仅表示 cumulative abstract work 的下一笔原子 charge 不足。
任何可继续的 phase 都先做 hard-limit check，再 charge，再运行并记录 semantic error；因此
limit 优先于同一 operation 的 budget，budget 优先于未完成的 semantic result。不得返回部分
boolean/validation success。OS timeout/memory guard 只是第二层 fail-closed termination，触发即
implementation fault/blocked，不能映射为 PASS 或替代上述 deterministic errors。

在 extension source/capability ADR 完成前，可执行 predicate、semantic validator 和 migration
transform registry **只允许产品内置、versioned、digest-locked IDs**。extension/config 只能
引用已批准 ID，不能新增/override executable operator/predicate/validator 或 dynamic import。
内置 implementation 通过无 I/O/clock/random/environment capability tests。引入第三方
executable item 必须重新打开本 ADR 并先完成 extension trust ADR。

## Options Considered

### JSON Schema + dataclasses + JCS + bounded AST — accepted

每一层职责单一：schema 负责结构，dataclass 负责内部类型，JCS 负责 digest bytes，AST
负责有限逻辑。它支持语言中立的 wire contract，同时能在 Python 中快速实现并独立测试。

### Pydantic models as wire/schema truth — rejected as canonical layer

开发体验好，但把 wire/schema、coercion 和 Python library version 耦合；隐式 coercion 也
不适合安全关键对象。未来可以在 adapter/display 层使用，但不能代替显式 JSON Schema、
semantic validators 或 JCS。

### CEL/JSONLogic/JMESPath — rejected for v1 core

现成语言减少 parser 工作，但各实现的类型、numeric、missing/path、function 和 extension
语义不同，容易引入不需要的运算面。GEEL v1 的操作集很小，可直接生成 exhaustive tests；
若后续采用标准语言，必须通过同一 golden vector 并另写 ADR。

### Python expressions / `eval` / model interpretation — rejected

不能静态限制副作用、环境访问或跨版本语义；扩大 prompt injection 和 code execution 面，
也无法形成平台中立 digest/compatibility contract。

### Protobuf-only — rejected

适合 typed binary exchange，但 Graph/Profile/extension authoring、human inspection 和现有
JSON config 不够直接，也不能单独解决 policy expression。未来可作为 transport 编码，
但不改变 canonical semantic JSON。

## Versioning and Compatibility

- schema、GEEL、semantic validator、canonicalization、Resource Profile 各自使用完整 semver
  ID，但 task/record **exact pin** ID、body digest 与整个 registry manifest digest；resume
  必须装有 exact pinned artifacts，不能用 semver range 猜测兼容；
- `$id` version 与 instance `schema_version` 必须 exact 一致。unknown major/minor/patch、未知
  property/keyword 或 manifest item 全部拒绝；没有 implicit forward/backward compatibility；
- compatibility 是 release manifest 中显式、方向化、测试证明的 reader/writer matrix：
  `reader-version → accepted exact writer contract IDs`。old reader/new writer、new reader/old
  writer 分开声明；可选字段增加也产生新 exact schema，旧 reader 只有 matrix 明确列入才读；
- artifact/event 同时记录 exact schema、GEEL、validator、canonicalizer、Resource Profile 和
  registry manifest refs；Graph/Profile 也锁定相同 registry；
- migration transform 是内置 immutable registry entry：stable ID、semver、body/code digest、
  exact source/target contract IDs、input/output schema、cost、纯函数 capability 声明。它无
  I/O/clock/random/environment，不得调用 model/tool；
- 每个 source→target pair 只允许一条 manifest-declared transform path；零条或多条都拒绝。
  先验证 old object/digest，逐 transform 生成/验证 intermediate，最终按 new JCS/digest；
  provenance 记录 old/new digest、每步 transform ID/version/digest、registry manifest、顺序、
  actor、transaction 和 result。重复/跨进程运行必须逐 bytes 相同。

## Consequences

- 所有 config、fixtures、event 和 bundle 必须有 schema 与 golden canonical bytes；
- Python 类型检查不替代 runtime schema/semantic validation；
- GEEL 表达比通用语言冗长，但安全、可审计且可机械穷举；
- 新 operator 是 architecture-sensitive extension：必须定义类型、错误、budget、golden
  vectors 和安全审查，不能由项目任意注册；
- 大整数和 decimal 以 string 表达会增加 schema 明确度和 codec 工作，但避免跨语言漂移；
- external schema/extension source policy 仍按 Impact 触发条件在 FR-18 loader 前另立 ADR。

## Validation and Rollback

必须有：

- Schema Profile corpus 由 Python 与至少一个独立 Draft 2020-12 implementation 执行，
  覆盖 vocabulary/keyword/format/numeric/unknown cases，load 和 instance 结果完全一致；
- offline registry 覆盖 relative/absolute refs、registered HTTPS dialect ID、duplicate `$id`、
  JSON Pointer、cycle/dynamic/remote/unregistered target 和 digest swap，且证明零网络访问；
- RFC 8785 vectors和 normalization-distinct Unicode、supplementary key、surrogate、escaped
  duplicate、安全 integer、negative zero、decimal/timestamp/duration/ID canonical forms 在
  两个实现产生相同 bytes/digest 或相同拒绝；
- opaque-ref vectors 对 canonical `YQ` 和非零 unused-pad-bit aliases `YR/YS/YT`、padding、
  alphabet、length、UTF-8 与 size 边界给出跨实现相同 accept/reject；
- 每类 semantic/raw contract 发布 exact preimage bytes + digest vectors；domain/type/schema/
  canonicalizer 任一变化都改变 digest，unframed/type-confused input 拒绝；
- EventEnvelope、ProjectScope、Profile 和其他每个自摘要 contract 发布 source、exact projected
  body、projection ID、JCS preimage 和 digest；omission/null/placeholder 差异全部拒绝；
- 每个 domain model 的 nested mutation/alias、bool-vs-int、round-trip property tests；
- GEEL 每个 operator/type/path/missing/error truth table，包括 eager `all/any` error precedence、
  empty all/any、permuted JSON member order、每个 operator 的多重同时失败、Unicode length、
  heterogeneous collection；两个 evaluator result bytes 完全一致；
- Resource Profile 的每项 limit 做 boundary/over-one fixture；所有超限在 bounded resources
  内稳定 `E_LIMIT/E_BUDGET`，不返回部分结果；cost vectors 覆盖 parse、refs、formats、schema
  combinators、nested equality、large uniqueItems、eager GEEL、predicate、result 和 temp units；
- nested schema-ref/format、multi-pair uniqueItems、GEEL membership/eager error、executable、
  canonicalization/digest 发布逐 event charge trace；在每一 event 前后截断 budget 都产生相同
  charged/rejected record、balance、operation path 和 `E_BUDGET`；
- 新增/override/mismatched executable registry item 在执行前拒绝；内置 item 证明无
  I/O/clock/random/environment capability；
- compatibility matrix 覆盖 old/new reader/writer、unknown exact version、property addition、
  missing registry；migration 重复/跨进程的 bytes、transform provenance 和唯一 path；
- security cases：schema bomb、deep/wide graph、large collection、digest confusion 和恶意
  extension predicate。

若 JCS library 或 GEEL implementation 不能通过 golden suite，阻止所有依赖 digest/route
的执行并重新打开 ADR；不能临时改用普通 `json.dumps(sort_keys=True)` 或 Python `eval`。

## Sources

- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [JSON Schema Validation 2020-12](https://json-schema.org/draft/2020-12/json-schema-validation)
- [python-jsonschema versioned validators](https://python-jsonschema.readthedocs.io/en/stable/validate/)
- [python-jsonschema referencing and offline registries](https://python-jsonschema.readthedocs.io/en/stable/referencing/)
- [Python dataclasses](https://docs.python.org/3/library/dataclasses.html)

## Traceability

Disposes Tech Spec §20.2；supports FR-03～FR-08、FR-10～FR-12、FR-14、FR-18 and
NFR-02～NFR-08。
