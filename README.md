# 数据访问策略网关（Data Policy Gateway）

对数据读取结果执行**字段级授权/脱敏**与**记录级可见性过滤**的策略执行引擎。支持运行中更新策略版本，
保证并发读取不观察到半更新状态、同一次响应与其审计记录归属同一策略版本；
求值失败、字段映射缺失、记录条件无法求值、脱敏异常一律**失败关闭**；
拒绝原因可区分、判定结果可复现；同一请求标识的重试/重复提交（含并发）**重放首次结果**。

## 1. 快速开始

```bash
mvn spring-boot:run        # 启动，自动装载初始策略 v1
mvn test                   # 运行全部 55 个单测/集成测试
```

发起一次读取。ANALYST 必须带所属部门 `department`：v1 的记录级条件为
`record.department == subject.department`，因此 ENGINEERING 部门的分析人员**只看到 1 条本部门客户**；
同时 `nationalId`/`salary` 越权被剥离，`phone`/`email` 哈希：

```bash
curl -s -X POST http://localhost:8080/api/data/query \
  -H 'Content-Type: application/json' \
  -d '{
    "requestId":"req-001",
    "subject":{"subjectId":"u-1","attributes":{"role":"ANALYST","department":"ENGINEERING"}},
    "resource":{"resourceType":"customer","resourceId":"*","attributes":{}},
    "action":"READ"
  }'
```

同一 `requestId` 重复提交（即使期间已发布新策略版本）会原样复现首次响应：
同样的可见记录、同样的脱敏结果，或同样的拒绝原因；审计不重复、不缺失。

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
                fieldPolicies[], defaultVisible,
                recordCondition?)          # 记录级可见性条件，可缺省
       ├─ FieldPolicy(fieldName, visible, maskingType, maskingParams)
       └─ RecordVisibilityCondition(terms[])   # AND 语义
              └─ RecordConditionTerm(field, operator,
                                     expectedValue? | expectedFromSubjectAttribute?)
```

- **匹配维度**：主体属性（`subjectConditions` 全部键值满足，如 `role=ADMIN`）
  + 目标资源（`resourceType`）+ 访问动作（`READ`/`WRITE`）。
- **命中规则**：按规则在策略中的**声明顺序，首条命中生效**（确定性、可复现）。
- **字段判定**：
  - `visible=true` → 放行，按 `maskingType` 脱敏；
  - `visible=false` → **显式拒绝（越权）**，字段从响应中剥离，仅作为判定依据进审计；
  - 规则未覆盖该字段：`defaultVisible=true` 时显式兜底放行；
    否则按 `FIELD_MAPPING_MISSING` **失败关闭**。
- **记录判定**：见下节。

### 2.0 记录级可见性语义（`recordCondition`）

`recordCondition` 挂在**规则**上，与字段级策略属于同一条规则、同一份策略版本：

- 条件由若干 `RecordConditionTerm` 组成，**全部成立（AND）** 时记录可见；
  当前支持 `EQ`：`record[field] == 期望值`。右值二选一：
  - `expectedValue`：字面量；
  - `expectedFromSubjectAttribute`：取主体属性，表达“只看本部门”
    （如 `record.department == subject.department`）。
- **不满足条件的记录整条消失**——返回的是过滤后的记录集，而不是字段被掏空的记录；
  没有任何记录命中时返回空集，请求仍为允许（allowed=true）。
- `recordCondition` 缺省/空：该规则不做记录级过滤（管理员看全部），旧策略定义零改动兼容。
- **两层一起判定，不各判各的**：网关在请求开始抓取一次不可变快照，字段级判定、
  记录级过滤、字段剥离/脱敏、审计全部引用同一快照。因此一次响应中的
  **可见记录、字段结果与审计记录必然来自同一个策略版本**，不会出现“字段按 v2、
  记录按 v1”的混用。

判定顺序（同快照内）：规则匹配 → 字段级整体拒绝判定 → **记录级过滤** → 逐字段剥离/脱敏。

### 2.0.1 记录条件无法求值时：整单失败关闭

以下情况**不返回任何记录**（包括本来能算出来的那部分），原因码为
`RECORD_CONDITION_UNEVALUABLE`：

| 触发场景 | detail 示例（只含字段名等元数据，不含字段值） |
|---|---|
| 条件引用的字段在记录中不存在 | `record condition references field absent in records: 'region'` |
| 同一批记录结构不一致（字段集合不完全相同） | `record structure inconsistent across the batch` |
| 右值引用的主体属性缺失（如分析人员没带 department） | `record condition requires missing subject attribute: 'department'` |
| 条件字段值/右值为 null，无法判定相等 | `record condition evaluation error: IllegalStateException` |
| 条件项定义非法（同时/都未给两种右值、运算符为空） | `record condition term ... must provide exactly one of ...` |

### 2.1 可区分的拒绝原因（`DenyReason`）

| 原因码 | 含义 | 处置 |
|---|---|---|
| `POLICY_NO_MATCH` | 主体/资源/动作**策略不匹配**（无任何规则命中） | 整单 403 |
| `FIELD_FORBIDDEN` | 命中规则但字段被**显式拒绝（越权）** | 仅剥离该字段，请求继续 |
| `FIELD_MAPPING_MISSING` | 字段在命中规则中**无映射**且未显式兜底 | 失败关闭，整单 403 |
| `RECORD_CONDITION_UNEVALUABLE` | 记录级条件**无法求值**（依赖字段缺失/结构不一致/右值缺失等） | 失败关闭，整单 403，零记录 |
| `MASKING_FAILED` | 脱敏规则执行异常 | 失败关闭，整单 403 |
| `EVALUATION_FAILED` | 策略求值异常 / 无策略可用 / 数据源异常 | 失败关闭，整单 403 |

排查时可一眼区分三类拦截：**整条策略都不匹配**（`POLICY_NO_MATCH`）、
**字段没权限**（`FIELD_FORBIDDEN`，仅剥离不整单拒绝）、
**记录条件算不出来**（`RECORD_CONDITION_UNEVALUABLE`，整单拒绝且零记录）。
所有原因码均出现在 HTTP 响应与审计记录中。

### 2.2 初始策略 v1（customer 资源，READ）

| 规则 | 角色 | 记录级可见性 | 可见字段 | 处理 |
|---|---|---|---|---|
| `r-admin-read` | ADMIN | 无条件（全部记录） | 全部 | `nationalId`/`phone`/`email` 局部掩码 |
| `r-analyst-read` | ANALYST | `department == subject.department`（仅本部门） | 除 `nationalId`、`salary` 外 | `phone`/`email` 哈希；越权字段剥离 |
| `r-guest-read` | GUEST | 无条件 | `id`/`name`/`department` | 其余字段显式拒绝 |

带记录级条件的规则 JSON 示例：

```json
{
  "ruleId": "r-analyst-read",
  "subjectConditions": {"role": "ANALYST"},
  "resourceType": "customer",
  "action": "READ",
  "defaultVisible": false,
  "recordCondition": {
    "terms": [
      {"field": "department", "operator": "EQ",
       "expectedFromSubjectAttribute": "department"}
    ]
  },
  "fieldPolicies": [ ... ]
}
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
2. **请求级版本归属（记录层 + 字段层同源）**：网关在请求开始抓取一次快照，
   规则匹配、记录级过滤、字段求值、剥离/脱敏、审计全部引用同一快照，
   因此**同一次响应的可见记录、字段结果与审计必然同版本**，不新旧混用。
3. **版本单调，拒绝回退**：版本号 `vN` 按 N 单调比较。新版本必须严格高于当前版本；
   `expectedParentVersion` 与当前不一致（指向未知/过期版本）时返回 **409**；
   版本号无法解析同样拒绝。绝不静默回退。
4. **失败关闭**：无策略、求值异常、字段映射缺失、**记录条件无法求值**、脱敏异常、
   数据源异常，一律整单拒绝（空记录集），**不返回部分数据**。
5. **无字段值侧信道**：未授权字段与被过滤记录不会出现在响应体、异常消息或应用日志中；
   审计只记录元数据（主体、资源、动作、策略版本、命中规则、原因码），不记录字段名/值。
   记录条件失败的 detail 也只含字段名（如 `'department'`），不含字段值。
6. **单次执行 + 结果重放（幂等响应）**：以 `requestId` 为键（`ResponseReplayStore`，
   single-flight + `CompletableFuture`）：
   - 同一标识**并发**提交：只有首次实际求值，其余线程等待并拿到完全相同的输出；
   - 同一标识**更新后重试**：直接复现首次的可见记录、脱敏结果或拒绝原因（及版本号），
     **不重新求值**——即使中间已发布新版本；
   - 审计以同一 `requestId` 幂等（`ConcurrentHashMap.putIfAbsent`），
     重试、重复提交、越权重试都**最多一条**；允许与拒绝都审计，不重不漏。

执行序列（`DataAccessGateway`）：按 requestId 单次执行/重放 → 抓取快照 → 取数
→ 字段级求值 → 记录级过滤（条件不可求值即整单失败关闭）→ 逐字段剥离/脱敏
（任一异常即整单失败关闭）→ 幂等审计 → 返回。原始数据不离开网关组件。

## 5. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/data/query` | 执行一次字段级授权 + 记录级可见性读取；拒绝返回 403 + `denyReason` + 空 `records`；同 `requestId` 重放首次结果 |
| POST | `/api/policies?expectedParentVersion=` | 发布新版本；回退/父版本不匹配返回 409 |
| GET | `/api/policies/current` | 查询当前生效版本 |

403 响应体示例（不含任何数据字段；记录条件无法求值时使用专门原因码）：

```json
{ "requestId":"req-x", "allowed":false, "policyVersion":"v1",
  "denyReason":"RECORD_CONDITION_UNEVALUABLE", "records":[] }
```

## 6. 验证方法

| 测试类 | 覆盖点 |
|---|---|
| `MaskerTest` | 四种脱敏规则、哈希稳定性、参数异常/保留范围过大的失败关闭 |
| `PolicyStoreTest` | 顺序推进、回退拒绝、未知父版本拒绝、非法版本拒绝、并发读写无半更新 |
| `PolicyEvaluatorTest` | 无匹配 vs 显式越权 vs 映射缺失的可区分原因、动作/资源匹配、首条命中稳定性 |
| `RecordVisibilityEvaluatorTest` | 记录条件命中/不命中整条过滤、字面量与主体属性右值、null/空条件、依赖字段缺失、主体属性缺失、同批结构不一致、条件值为 null、条件项非法——全部边界要么正确过滤要么整单失败关闭 |
| `DataAccessGatewayTest` | 端到端脱敏/剥离、拒绝原因区分、映射缺失失败关闭、重试审计幂等（允许与拒绝） |
| `RecordLevelAccessGatewayTest` | 分析人员仅见本部门/管理员见全部、记录过滤与字段剥离哈希叠加、缺条件字段/结构不一致/主体属性缺失的 `RECORD_CONDITION_UNEVALUABLE` 整单拒绝、策略 v1→v2 后同标识重试复现首次可见记录与首次拒绝（含审计不重不漏） |
| `RecordVisibilityConcurrencyTest` | 更新前后两阶段 8×100 并发读取：每条响应记录数/字段/审计同版本自洽；16 个同 requestId 在更新窗口内并发/延迟提交：single-flight 全部复现首次（v1/1 条）、审计恰好一条 |
| `FailClosedTest` | 脱敏异常整单拒绝、无策略失败关闭、无数据源失败关闭 |
| `DataAccessGatewayConcurrencyTest` | 8 读线程 ×200 请求与 19 次版本发布并发：响应与审计同版本、回退全被拒、审计不重不漏 |
| `DataAccessWebIntegrationTest` | HTTP 端到端：字段不出现在 403 响应、记录级部门过滤与重放、记录条件无法求值 403 专码、409 版本冲突、缺 requestId 返回 400 |

手工验证记录级失败关闭（ANALYST 不带 `department`，预期 403 + `RECORD_CONDITION_UNEVALUABLE`）：

```bash
curl -s -X POST http://localhost:8080/api/data/query \
  -H 'Content-Type: application/json' \
  -d '{"requestId":"req-manual-1",
       "subject":{"subjectId":"u-1","attributes":{"role":"ANALYST"}},
       "resource":{"resourceType":"customer","resourceId":"*","attributes":{}},
       "action":"READ"}'
# -> {"requestId":"req-manual-1","allowed":false,"policyVersion":"v1",
#     "denyReason":"RECORD_CONDITION_UNEVALUABLE","records":[]}
```

手工验证更新后重放：先用 `req-manual-2` + ANALYST/ENGINEERING 查到 1 条记录，
再 `POST /api/policies?expectedParentVersion=v1` 发布去掉记录级条件的 v2，
用**同一个 requestId** 重试——仍返回 v1 的 1 条记录与哈希脱敏，审计仅一条。

单测日志统一打印**请求输入、策略版本与判定依据**（`basis=...`），例如：

```
policy decision basis: requestId=req-1, policyVersion=v1, matchedRuleId=r-analyst-read, overallDenyReason=null
record visibility test: input=3 rows(department), condition=department==subject.department, basis='命中保留、不命中整条过滤（不是掏空）'
access denied: requestId=req-x, policyVersion=v1, reason=RECORD_CONDITION_UNEVALUABLE, detail=..., auditWritten=true
record visibility duplicate: input=16 same-requestId submissions around v1->v2, basis='single-flight + 重放首次：全部 v1/1 条'
```
