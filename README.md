# 数据访问策略网关（Data Policy Gateway）

对数据读取结果执行**字段级授权与脱敏**的策略执行引擎。支持运行中更新策略版本，
保证并发读取不观察到半更新状态、同一次响应与其审计记录归属同一策略版本；
求值失败、字段映射缺失、脱敏异常一律**失败关闭**；拒绝原因可区分、判定结果可复现。

## 1. 快速开始

```bash
mvn spring-boot:run        # 启动，自动装载初始策略 v1
mvn test                   # 运行全部 36 个单测/集成测试
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
                fieldPolicies[], defaultVisible)
       └─ FieldPolicy(fieldName, visible, maskingType, maskingParams)
```

- **匹配维度**：主体属性（`subjectConditions` 全部键值满足，如 `role=ADMIN`）
  + 目标资源（`resourceType`）+ 访问动作（`READ`/`WRITE`）。
- **命中规则**：按规则在策略中的**声明顺序，首条命中生效**（确定性、可复现）。
- **字段判定**：
  - `visible=true` → 放行，按 `maskingType` 脱敏；
  - `visible=false` → **显式拒绝（越权）**，字段从响应中剥离，仅作为判定依据进审计；
  - 规则未覆盖该字段：`defaultVisible=true` 时显式兜底放行；
    否则按 `FIELD_MAPPING_MISSING` **失败关闭**。

### 2.1 可区分的拒绝原因（`DenyReason`）

| 原因码 | 含义 | 处置 |
|---|---|---|
| `POLICY_NO_MATCH` | 主体/资源/动作**策略不匹配**（无任何规则命中） | 整单 403 |
| `FIELD_FORBIDDEN` | 命中规则但字段被**显式拒绝（越权）** | 仅剥离该字段，请求继续 |
| `FIELD_MAPPING_MISSING` | 字段在命中规则中**无映射**且未显式兜底 | 失败关闭，整单 403 |
| `MASKING_FAILED` | 脱敏规则执行异常 | 失败关闭，整单 403 |
| `EVALUATION_FAILED` | 策略求值异常 / 无策略可用 / 数据源异常 | 失败关闭，整单 403 |

“越权”与“策略不匹配”是两个稳定、可区分的枚举码，均出现在 HTTP 响应与审计记录中。

### 2.2 初始策略 v1（customer 资源，READ）

| 规则 | 角色 | 可见字段 | 处理 |
|---|---|---|---|
| `r-admin-read` | ADMIN | 全部 | `nationalId`/`phone`/`email` 局部掩码 |
| `r-analyst-read` | ANALYST | 除 `nationalId`、`salary` 外 | `phone`/`email` 哈希；越权字段剥离 |
| `r-guest-read` | GUEST | `id`/`name`/`department` | 其余字段显式拒绝 |

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
   一律整单拒绝（空记录集），**不返回部分数据**。
5. **无字段值侧信道**：未授权字段不会出现在响应体、异常消息或应用日志中；
   审计只记录元数据（主体、资源、动作、策略版本、命中规则、原因码），不记录字段名/值。
6. **幂等审计**：以 `requestId` 为幂等键（`ConcurrentHashMap.putIfAbsent`），
   重试、重复提交、越权重试都**最多一条**审计；允许与拒绝都审计，不重不漏。

执行序列（`DataAccessGateway`）：抓取快照 → 取数（仅用于收集字段名）→ 纯函数求值
→ 逐字段剥离/脱敏（任一异常即整单失败关闭）→ 幂等审计 → 返回。原始数据不离开网关组件。

## 5. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/data/query` | 执行一次字段级授权读取；拒绝返回 403 + `denyReason` + 空 `records` |
| POST | `/api/policies?expectedParentVersion=` | 发布新版本；回退/父版本不匹配返回 409 |
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
| `DataAccessWebIntegrationTest` | HTTP 端到端：字段不出现在 403 响应、409 版本冲突、缺 requestId 返回 400 |

单测日志统一打印**请求输入、策略版本与判定依据**（`basis=...`），例如：

```
policy decision basis: requestId=req-1, policyVersion=v1, matchedRuleId=r-analyst-read, overallDenyReason=null
access denied: requestId=req-x, policyVersion=v1, reason=POLICY_NO_MATCH, detail=...
concurrency test: input=8 readers x200 requests during v1->v20 updates ..., failures=0
```
