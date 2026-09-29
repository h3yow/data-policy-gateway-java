# 数据访问策略网关（Data Policy Gateway）

对数据读取结果执行**字段级授权/脱敏**与**记录级可见性过滤**的策略执行引擎。支持运行中更新策略版本，
保证并发读取不观察到半更新状态、同一次响应与其审计记录归属同一策略版本；
求值失败、字段映射缺失、脱敏异常、记录级条件无法求值一律**失败关闭**；
拒绝原因可区分、判定结果可复现；同一 requestId 的重复提交/重试（即使期间策略已更新）
**原样复现首次结果**。

## 1. 快速开始

```bash
mvn spring-boot:run        # 启动，自动装载初始策略 v1
mvn test                   # 运行全部 54 个单测/集成测试
```

发起一次读取（ANALYST 角色：`nationalId`/`salary` 越权被剥离，`phone`/`email` 哈希）：

```bash
curl -s -X POST http://localhost:8080/api/data/query \
  -H 'Content-Type: application/json' \
  -d '{
    "requestId":"req-001",
    "subject":{"subjectId":"u-1","attributes":{"role":"ANALYST"}},
    "resource":{"resourceType":"customer","resourceId":"*","attributes":{}},
    "action":"READ"
  }'
```

运行中发布新策略版本（`expectedParentVersion` 为乐观条件）：

```bash
curl -s -X POST 'http://localhost:8080/api/policies?expectedParentVersion=v1' \
  -H 'Content-Type: application/json' \
  -d '{"version":"v2","rules":[ ... ]}'
```

## 2. 策略模型

策略由不可变的版本化定义（`PolicyDefinition`）组成：

```
PolicyDefinition(version, rules[])
  └─ PolicyRule(ruleId, subjectConditions, resourceType, action,
                fieldPolicies[], defaultVisible, recordCondition?)
       ├─ FieldPolicy(fieldName, visible, maskingType, maskingParams)
       └─ RecordVisibilityCondition(terms[])
            └─ RecordConditionTerm(fieldName, operator, valueSource,
                                   referenceKey?, expectedValue?)
```

- **匹配维度**：主体属性（`subjectConditions` 全部键值满足，如 `role=ADMIN`）
  + 目标资源（`resourceType`）+ 访问动作（`READ`/`WRITE`）。
- **命中规则**：按规则在策略中的**声明顺序，首条命中生效**（确定性、可复现）。
- **字段判定**：
  - `visible=true` → 放行，按 `maskingType` 脱敏；
  - `visible=false` → **显式拒绝（越权）**，字段从响应中剥离，仅作为判定依据进审计；
  - 规则未覆盖该字段：`defaultVisible=true` 时显式兜底放行；
    否则按 `FIELD_MAPPING_MISSING` **失败关闭**。

### 2.0 记录级可见性（recordCondition）

命中规则可携带一个 `recordCondition`：它对**每条记录的内容**求值，
不满足条件的记录**整条不出现**（而不是返回一条被掏空字段的记录）；
未声明 `recordCondition` 的规则不过滤记录（如 ADMIN 看全部）。

- **模型**：`RecordVisibilityCondition` 由若干 `RecordConditionTerm` 组成，term 之间 **AND**。
  每个 term 的左值取自记录字段 `fieldName`，算子为 `EQ` / `NOT_EQ` / `IN`（右值逗号分隔）；
  右值来源 `valueSource`：
  - `RECORD`：与字面量 `expectedValue` 比较；
  - `SUBJECT`：与主体属性 `referenceKey` 的值比较（如 `record.department == subject.department`）。
- **与字段级的关系（同一策略版本一起生效）**：字段级判定与记录级过滤在**同一次请求、
  同一个不可变快照、同一条命中规则**上先后执行——先按记录条件决定“哪些记录出现”，
  再对出现的记录逐字段剥离/脱敏；二者不是各判各的。响应中的可见记录、字段结果与审计记录
  必然来自**同一策略版本**。
- **没有任何记录命中条件不是拒绝**：请求仍然放行，只是 `records` 为空；
  这与“整单拒绝（空记录集 + 403 + denyReason）”有本质区别。
- **失败关闭**：见 2.1 的 `RECORD_CONDITION_FAILED`。

### 2.1 可区分的拒绝原因（`DenyReason`）

| 原因码 | 含义 | 处置 |
|---|---|---|
| `POLICY_NO_MATCH` | 主体/资源/动作**策略不匹配**（无任何规则命中） | 整单 403 |
| `FIELD_FORBIDDEN` | 命中规则但字段被**显式拒绝（越权）** | 仅剥离该字段，请求继续 |
| `FIELD_MAPPING_MISSING` | 字段在命中规则中**无映射**且未显式兜底 | 失败关闭，整单 403 |
| `MASKING_FAILED` | 脱敏规则执行异常 | 失败关闭，整单 403 |
| `RECORD_CONDITION_FAILED` | 记录级条件依赖字段在记录中缺失（无此键或值为 null）、**条件本身无法求值**（如引用的主体属性缺失、算子/条件项非法）、或**同一批记录结构不一致**（键集合不同） | 失败关闭，整单 403，**不返回任何记录**（连能算出来的那部分也不返回） |
| `EVALUATION_FAILED` | 策略求值异常 / 无策略可用 / 数据源异常 | 失败关闭，整单 403 |

“记录级条件失败关闭”与“字段没权限（FIELD_FORBIDDEN，剥离后继续）”、
“整条策略不匹配（POLICY_NO_MATCH）”是三个不同的稳定枚举码，
同时出现在 HTTP 响应与审计记录中，排查时一眼能区分。

“越权”与“策略不匹配”是两个稳定、可区分的枚举码，均出现在 HTTP 响应与审计记录中。

### 2.2 初始策略 v1（customer 资源，READ）

| 规则 | 角色 | 可见字段 | 处理 |
|---|---|---|---|
| `r-admin-read` | ADMIN | 全部 | `nationalId`/`phone`/`email` 局部掩码 |
| `r-analyst-read` | ANALYST | 除 `nationalId`、`salary` 外 | `phone`/`email` 哈希；越权字段剥离 |
| `r-guest-read` | GUEST | `id`/`name`/`department` | 其余字段显式拒绝 |

示例记录级策略 `v2`（`BootstrapPolicyInitializer.v2RecordScoped()`）：字段级策略与 v1 相同，
分析人员规则 `r-analyst-read-dept` 额外携带条件 `record.department == subject.department`
——分析人员只能看到自己所属部门的客户；ADMIN 规则不带条件，仍可看全部。
请求主体需带上部门属性：

```bash
curl -s -X POST http://localhost:8080/api/data/query \
  -H 'Content-Type: application/json' \
  -d '{
    "requestId":"req-dept-1",
    "subject":{"subjectId":"u-1","attributes":{"role":"ANALYST","department":"ENGINEERING"}},
    "resource":{"resourceType":"customer","resourceId":"*","attributes":{}},
    "action":"READ"
  }'
```

## 3. 脱敏规则（`MaskingType`）

| 类型 | 行为 | 参数 |
|---|---|---|
| `NONE` | 原样返回 | — |
| `FULL_MASK` | 整体替换为 `****` | — |
| `PARTIAL_MASK` | 保留前 `prefix` 位、后 `suffix` 位，中间以 `*` 替换 | `prefix`、`suffix`（非负整数） |
| `HASH` | SHA-256 不可逆哈希（同一输入输出稳定，可复现） | — |

脱敏参数缺失/非法、或保留范围覆盖整个值（内容可还原）时，**不返回明文近似值**，
而是抛 `MASKING_FAILED`，由网关失败关闭。异常消息不携带字段值。

## 4. 一致性与安全保证

1. **不可变快照 + 单引用发布**：策略每次发布构造完整的 `PolicySnapshot`，
   通过 `volatile` 引用一次性切换；读线程要么看到旧版本、要么看到新版本，
   绝不观察到半更新状态（见 `PolicyStoreTest.concurrentReadersNeverSeeTornState`）。
2. **请求级版本归属**：网关在请求开始抓取一次快照，求值、过滤/脱敏、审计
   全部引用同一快照，因此**响应与审计记录必然同版本**。
3. **版本单调，拒绝回退**：版本号 `vN` 按 N 单调比较。新版本必须严格高于当前版本；
   `expectedParentVersion` 与当前不一致（指向未知/过期版本）时返回 **409**；
   版本号无法解析同样拒绝。绝不静默回退。
4. **失败关闭**：无策略、求值异常、字段映射缺失、脱敏异常、数据源异常，
   以及记录级条件无法求值/批内结构不一致，一律整单拒绝（空记录集），**不返回部分数据**。
5. **无字段值侧信道**：未授权字段不会出现在响应体、异常消息或应用日志中；
   审计只记录元数据（主体、资源、动作、策略版本、命中规则、原因码），不记录字段名/值。
6. **幂等审计**：以 `requestId` 为幂等键（`AuditService.putIfAbsent`），
   重试、重复提交、越权重试都**最多一条**审计；允许与拒绝都审计，不重不漏。
7. **结果幂等（复现首次结果）**：网关以 requestId 为键把首次的不可变 `StoredOutcome`
   （放行记录/脱敏值或拒绝原因+版本）存入 `IdempotentResultStore`
   （`ConcurrentHashMap.computeIfAbsent`，同键的执行体全局至多运行一次）。
   同一 requestId 重复提交或重试时，**即使期间策略已经更新**，也原样返回首次结果——
   同样的可见记录、同样的脱敏值，或同样的拒绝原因；响应与审计始终同版本，
   审计不会因重试重复或缺失。新 requestId 才会按当前新版本判定。

执行序列（`DataAccessGateway`）：requestId 幂等取首次结果 → 抓取快照 → 取数
（仅用于收集字段名）→ 纯函数字段级求值 → **记录级条件过滤（同快照同规则）**
→ 逐字段剥离/脱敏（任一异常即整单失败关闭）→ 幂等审计 → 返回。原始数据不离开网关组件。

## 5. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/data/query` | 执行一次字段级授权 + 记录级可见性读取；拒绝返回 403 + `denyReason` + 空 `records` |
| POST | `/api/policies?expectedParentVersion=` | 发布新版本（可携带 `recordCondition`）；回退/父版本不匹配返回 409 |
| GET | `/api/policies/current` | 查询当前生效版本 |

403 响应体示例（不含任何数据字段）：

```json
{ "requestId":"req-x", "allowed":false, "policyVersion":"v1",
  "denyReason":"POLICY_NO_MATCH", "records":[] }
```

## 6. 验证方法

| 测试类 | 覆盖点 |
|---|---|
| `MaskerTest` | 四种脱敏规则、哈希稳定性、参数异常/保留范围过大的失败关闭 |
| `PolicyStoreTest` | 顺序推进、回退拒绝、未知父版本拒绝、非法版本拒绝、并发读写无半更新 |
| `PolicyEvaluatorTest` | 无匹配 vs 显式越权 vs 映射缺失的可区分原因、动作/资源匹配、首条命中稳定性 |
| `DataAccessGatewayTest` | 端到端脱敏/剥离、拒绝原因区分、映射缺失失败关闭、重试审计幂等（允许与拒绝） |
| `FailClosedTest` | 脱敏异常整单拒绝、无策略失败关闭、无数据源失败关闭 |
| `DataAccessGatewayConcurrencyTest` | 8 读线程 ×200 请求与 19 次版本发布并发：响应与审计同版本、回退全被拒、审计不重不漏 |
| `RecordVisibilityEvaluatorTest` | 记录级条件命中/不命中整条过滤、无条件原样返回、依赖字段缺失/值为 null、主体属性缺失、批内结构不一致的失败关闭、IN/NOT_EQ 算子 |
| `RecordLevelAccessGatewayTest` | 网关端到端：部门条件过滤、字段级叠加（剥离+哈希同时生效）、管理员全量、零命中放行空集、依赖缺失/主体属性缺失/结构不一致的 `RECORD_CONDITION_FAILED` 与其他原因可区分、**策略更新后同 requestId 重试复现首次放行结果与首次拒绝**（审计不重不漏、响应与审计同版本） |
| `RecordLevelConcurrencyTest` | 8 读线程 ×150 请求与记录级条件在 ENGINEERING/FINANCE 间翻转的 19 次发布并发：每次响应的记录集合与其版本条件语义一致（不新旧混用）、响应与审计同版本、每请求恰好一条审计 |
| `DataAccessWebIntegrationTest` | HTTP 端到端：字段不出现在 403 响应、409 版本冲突、缺 requestId 返回 400、HTTP 发布带 `recordCondition` 的策略并整条过滤、条件不可求值返回 403 + `RECORD_CONDITION_FAILED` |

### 6.1 手工验证边界与失败场景

1. **条件命中/不命中**：发布 `v2RecordScoped()`，以 `role=ANALYST, department=ENGINEERING`
   查询，只返回 ENGINEERING 客户（`C001`）；`department=FINANCE` 只返回 `C002`；
   ADMIN 仍返回全部 3 条。
2. **零命中不是拒绝**：`department=SALES`（数据中无此部门客户）→ 200、`allowed=true`、
   `records=[]`，审计 `allowed=true`。
3. **依赖字段缺失**：让某条记录不含 `department` 键 → 403
   `RECORD_CONDITION_FAILED`，所有记录均不返回。
4. **条件不可求值**：ANALYST 主体不带 `department` 属性 → 403
   `RECORD_CONDITION_FAILED`（规则本身命中，故区别于 `POLICY_NO_MATCH`；
   也不是字段越权的 `FIELD_FORBIDDEN`）。
5. **批内结构不一致**：同一批记录键集合不同 → 403 `RECORD_CONDITION_FAILED`，不返回部分数据。
6. **更新期间并发**：见 `RecordLevelConcurrencyTest`，响应记录永远与其版本条件自洽。
7. **更新后重复提交**：同一 requestId 首次在 v2 放行（或拒绝），发布 v3 后重试，
   仍返回 v2 的首次记录集（或首次拒绝原因与版本）；新 requestId 才体现 v3 语义；
   该 requestId 的审计始终只有一条且版本为首次版本。

单测日志统一打印**请求输入、策略版本与判定依据**（`basis=...`），例如：

```
policy decision basis: requestId=req-1, policyVersion=v1, matchedRuleId=r-analyst-read, overallDenyReason=null
access denied: requestId=req-x, policyVersion=v2, reason=RECORD_CONDITION_FAILED, detail=...
record filter test: input=同批记录键集合不一致, basis='结构不一致 -> 整单拒绝，不返回部分数据', reason=RECORD_CONDITION_FAILED
record-level concurrency test: input=8 readers x150 requests during v1->v20 record-policy flips ..., failures=0
```
