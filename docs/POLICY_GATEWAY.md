# 数据访问策略网关（Data Policy Gateway）

在数据读取出口处执行**字段级授权与脱敏**，并保证策略更新期间的判定结果
**可解释、可复现**。

- Java 21 / Spring Boot 3.4，无外部中间件依赖（内存存储，便于演示与测试）。
- 所有策略值对象不可变；判定逻辑是无副作用的纯函数。

---

## 1. 策略模型

### 1.1 判定输入

一次读取判定（`AccessRequest`）由四元组构成：

| 输入 | 说明 |
| --- | --- |
| `subject` | 主体 `id` + 属性表（如 `role=analyst`、`department=risk`） |
| `resource` | 逻辑资源坐标 `type:id`（如 `customer:c-1001`） |
| `action` | `READ` / `WRITE` |
| `fields` | 请求的逻辑字段列表；空列表表示“资源映射的全部字段” |
| `requestId` | 幂等键；重试必须复用同一个值 |

### 1.2 策略结构

- `Policy(version, rules)`：带**单调递增版本号**的不可变规则集。
- `PolicyRule(priority, matchResource, matchAction, matchAttributes, fields)`：
  - 规则按 `priority` 降序求值，**第一条全部条件匹配的规则胜出**（单命中）。
  - `matchResource="*"` 表示任意资源类型；`matchAction=null` 表示任意动作。
  - `matchAttributes` 是主体必须**全部**满足的精确属性条件。
- `FieldRule(field, effect, maskName)` 的三种字段效果：
  - `ALLOW`：明文返回；
  - `MASK`：经命名脱敏规则处理后返回；
  - `DENY`：字段不可见。

### 1.3 默认拒绝（fail-closed）

- 请求字段在命中规则中**没有声明** → 按 `FIELD_UNAUTHORIZED` 拒绝。
- 没有任何规则匹配该主体/资源/动作 → `POLICY_NOT_MATCHED`。
- 即默认姿态是“全部拒绝”，不存在“没配就放行”。

### 1.4 可区分的拒绝原因（`DenyReason`）

拒绝响应与审计记录只携带**稳定原因码**，原因码互不混淆，且消息里
**绝不出现字段名或字段值**：

| 原因码 | 语义 |
| --- | --- |
| `FIELD_UNAUTHORIZED` | 有规则命中，但其中一个请求字段被显式拒绝或未声明（越权） |
| `POLICY_NOT_MATCHED` | 没有任何规则适用于该主体/资源/动作（策略不匹配） |
| `EVALUATION_FAILED` | 求值器内部异常，失败关闭 |
| `FIELD_MAPPING_MISSING` | 授权字段在资源数据中缺失映射，失败关闭 |
| `MASKING_RULE_ERROR` | 脱敏规则不存在或执行异常，失败关闭 |
| `RESOURCE_NOT_FOUND` | 目标资源不存在 |
| `INVALID_REQUEST` | 请求体不合法（在接触任何策略/数据之前拒绝） |

`FIELD_UNAUTHORIZED` 与 `POLICY_NOT_MATCHED` 的区分是刻意的：前者表示
“策略知道你是谁，但这个字段不给你”，后者表示“当前策略对你这个请求
没有任何适用条款”。

### 1.5 可解释性

每个判定结果（`EvaluationResult`）都带有：

- `policyVersion`：判定所依据的精确策略版本；
- `matchedRuleId`：命中规则的坐标（`rule[priority=..,index=..]`）；
- `verdicts`：逐字段效果（ALLOW/MASK/DENY）+ 脱敏规则名 + 判定依据文本；
- `basis`：人类可读的判定依据（命中条件、字段数量）。

测试日志通过 `policy-eval` / `policy-decision` 两类事件打印
**请求输入（主体属性、资源、动作、请求字段集合）、策略版本与判定依据**。

---

## 2. 脱敏规则

内置规则（`StandardMaskingRules`，均为无状态、线程安全）：

| 注册名（默认配置） | 效果 | 示例 |
| --- | --- | --- |
| `tail-4` | 保留末 4 位，头部替换为 `*` | `110101-1234` → `*******1234` |
| `head-2` | 保留前 2 位，尾部替换为 `*` | `Alice Zhang` → `Al*********` |
| `email` | 邮箱本地部分仅留首字符 | `alice@example.com` → `a****@example.com` |
| `null` | 置空 | `x` → `null` |
| `redacted` | 固定占位符 | `x` → `REDACTED` |

规则约定：

1. `null` 输入恒为 `null`；非字符串输入先 `String.valueOf`。
2. 任何规则内部异常都包装为 `MaskingException`，**绝不**把原始值带进异常消息。
3. 策略安装时会校验所有 `MASK` 字段引用的规则名存在；**引用未知脱敏规则
   的策略无法成为活动版本**（安装返回 400，当前版本不变）。
4. 投影阶段规则缺失/抛错 → 整个请求以 `MASKING_RULE_ERROR` 失败关闭。

---

## 3. 一致性与失败语义保证

### 3.1 更新原子性：读者看不到半更新

- `Policy` 是不可变值对象，`InMemoryPolicyRepository` 通过**单个
  `volatile` 引用交换**发布新版本。
- 读者在请求开始时 `pin()` 住一个不可变快照；更新前开始的请求用完整旧版本
  求值到底，更新后开始的请求看到完整新版本。**半更新状态在结构上不可能**。

### 3.2 版本钉住：响应与审计同属一个版本

`DefaultDataAccessService` 的生命周期：

1. 先 `pin()` 策略快照，之后数据加载、字段求值、脱敏投影与审计写入
   **全部使用同一版本号**。
2. 审计事件（`AuditEvent`）与响应都带 `policyVersion`；并发测试逐请求
   断言二者版本一致。

### 3.3 版本纪律：拒绝回退与未知版本，绝不静默回退

安装新版本必须满足 `newVersion == currentVersion + 1`，否则：

- `newVersion <= current` → `PolicyVersionException`（rollback refused）；
- `newVersion > current + 1` → `PolicyVersionException`（version gap refused，
  即拒绝“指向未知版本”的更新）；
- 传入 `expectedBase` 且不等于当前版本 → 409（乐观并发控制）。

冲突响应明确给出 `attemptedVersion` 与 `currentVersion`，活动版本不变。

### 3.4 失败关闭：异常请求不返回部分数据

- 求值器对自身任何 `RuntimeException` 兜底为 `EVALUATION_FAILED` 拒绝结果，
  而不是抛出/放行。
- 投影结果先写入局部 Map，**所有字段都成功后才整体返回**；字段映射缺失或
  脱敏异常时直接拒绝，调用方不可能拿到半成品响应。
- 控制器全局异常处理（`GlobalExceptionHandler`）对外只输出稳定原因码，
  不回传堆栈、解析器原文或任何字段数据。

### 3.5 未授权字段不出现

未授权字段在以下位置均不出现，且有测试保证：

- **响应体**：投影器只遍历“已授权字段”，DENY 字段根本不会被迭代；
- **异常信息**：拒绝消息是固定模板 `access denied: <REASON>`，不含字段名；
- **审计/日志**：只记录 `requestedFieldCount`、`allowedFieldCount` 与依据，
  不记录被拒绝字段的名字与值。

### 3.6 审计恰好一次 + 重试可复现

- 审计存储以 `requestId` 为主键，重复 append 直接抛
  `DuplicateAuditException`（“重复审计”在存储层即不可发生）。
- 服务层为每个 `requestId` 保存**终态结果**：
  - 并发重复请求通过 `inflight`（`putIfAbsent` + `CompletableFuture`）
    合并为一次执行；
  - 事后重试直接重放首次的终态（同一版本、同一投影数据），响应
    `retry=true`，**不产生第二条审计**；
  - 因此即使重试发生在策略更新之后，返回的仍是首次判定的版本与结果
    （可复现）。

---

## 4. HTTP API

### 读取（授权 + 脱敏）

`POST /api/v1/data/read`

```json
{
  "requestId": "req-001",
  "subject": {"id": "u-1", "attributes": {"role": "analyst"}},
  "resourceType": "customer",
  "resourceId": "c-1001",
  "action": "READ",
  "fields": ["name", "email", "region"]
}
```

成功 200：

```json
{
  "requestId": "req-001",
  "resourceType": "customer",
  "resourceId": "c-1001",
  "policyVersion": 1,
  "retry": false,
  "fields": {"name": "Alice Zhang", "email": "a****@example.com", "region": "cn-north"}
}
```

拒绝 403（字段级越权，注意无字段名/值泄漏）：

```json
{"requestId": "req-002", "reason": "FIELD_UNAUTHORIZED",
 "policyVersion": 1, "message": "access denied: FIELD_UNAUTHORIZED"}
```

### 策略管理

- `GET /api/v1/policies/current`：查看当前版本与规则数。
- `POST /api/v1/policies/install`：原子安装新版本。

```json
{
  "expectedBase": 1,
  "policy": {
    "version": 2,
    "rules": [
      {"priority": 100, "matchResource": "customer", "matchAction": "READ",
       "matchAttributes": {"role": "admin"},
       "fields": [{"field": "name", "effect": "ALLOW"},
                  {"field": "ssn", "effect": "ALLOW"}]},
      {"priority": 10, "matchResource": "customer", "matchAction": "READ",
       "matchAttributes": {"role": "analyst"},
       "fields": [{"field": "name", "effect": "ALLOW"},
                  {"field": "email", "effect": "MASK", "maskName": "email"},
                  {"field": "ssn", "effect": "DENY"}]}
    ]
  }
}
```

回退/跳版本/陈旧基线 → 409：

```json
{"attemptedVersion": 1, "currentVersion": 2,
 "message": "policy rollback refused: attempted=1 current=2"}
```

### 审计核查（不含敏感字段）

- `GET /api/v1/audit/events`：全部审计事件。
- `GET /api/v1/audit/events/{requestId}`：按幂等键查询。

---

## 5. 验证方法

### 5.1 运行测试

```bash
mvn test
```

共 7 个测试类、35+ 用例，覆盖：

| 测试类 | 覆盖点 |
| --- | --- |
| `StandardMaskingRulesTest` | 各脱敏规则的输出、null 处理 |
| `FieldProjectorTest` | ALLOW/MASK 投影；DENY 字段不输出；映射缺失、规则异常、未知规则名均失败关闭 |
| `InMemoryPolicyRepositoryTest` | 顺序安装、回退拒绝、跳版本拒绝、乐观基线、钉住快照跨更新稳定 |
| `PolicyEvaluatorTest` | admin 全字段、analyst 脱敏、越权字段、角色不匹配、动作不匹配（原因码可区分且稳定） |
| `InMemoryAuditEventStoreTest` | 重复 append 拒绝、64 线程并发追加恰好一次 |
| `DefaultDataAccessServiceTest` | 端到端授权/脱敏；重试重放且审计一次；三类拒绝原因可区分；脱敏故障失败关闭；16 线程并发读与更新并存时**响应/审计版本逐一对齐** |
| `DataAccessIntegrationTest` | MockMvc 全链路：读取、拒绝、重试标记、策略回退/坏规则拒绝、合法版本升级后判定变化 |

判定日志示例（单元测试输出中可见）：

```
policy-eval requestId=.. subject={role=analyst} resource=customer:c-1001 action=READ
  fields=[ssn] policyVersion=1 allowed=false denyReason=FIELD_UNAUTHORIZED
  matchedRule=null basis=no... / field-unauthorized under rule[..]
policy-decision requestId=.. subjectId=u-analyst resource=customer:c-1001 action=READ
  policyVersion=1 allowed=false denyReason=FIELD_UNAUTHORIZED requestedFieldCount=1 ...
```

### 5.2 手工冒烟

```bash
mvn spring-boot:run            # 如 8080 被占用: -Dspring-boot.run.arguments=--server.port=8081

# analyst 读取（email 被脱敏、ssn 不在结果中）
curl -s -X POST localhost:8081/api/v1/data/read -H 'Content-Type: application/json' -d '{
  "requestId":"s1","subject":{"id":"u","attributes":{"role":"analyst"}},
  "resourceType":"customer","resourceId":"c-1001","action":"READ",
  "fields":["name","email","region"]}'

# 越权字段
curl -s -X POST localhost:8081/api/v1/data/read -H 'Content-Type: application/json' -d '{
  "requestId":"s2","subject":{"id":"u","attributes":{"role":"analyst"}},
  "resourceType":"customer","resourceId":"c-1001","action":"READ","fields":["ssn"]}'

# 安装 v2 / 尝试回退
curl -s localhost:8081/api/v1/policies/current
curl -s -X POST localhost:8081/api/v1/policies/install -H 'Content-Type: application/json' \
  -d '{"expectedBase":2,"policy":{"version":1,"rules":[]}}'   # 409 rollback refused

# 审计版本核对
curl -s localhost:8081/api/v1/audit/events/s2
```

启动时种子数据：资源 `customer:c-1001`（name/email/region/ssn）与
v1 策略（admin 全允许；analyst 允许 name/region、email 脱敏、ssn 拒绝）。

---

## 6. 关键类索引

| 包 | 类 | 职责 |
| --- | --- | --- |
| `model` | `Policy` / `PolicyRule` / `FieldRule` / `EvaluationResult` / `AuditEvent` / `DenyReason` | 不可变领域模型与稳定原因码 |
| `policy` | `InMemoryPolicyRepository` | volatile 原子发布、版本纪律、快照钉住 |
| `policy` | `PolicyEvaluator` | 纯函数式规则匹配与字段判定（失败关闭） |
| `mask` | `StandardMaskingRules` / `InMemoryMaskingRegistry` / `FieldProjector` | 脱敏规则、注册表、授权投影（失败关闭） |
| `audit` | `InMemoryAuditEventStore` | requestId 去重的恰好一次审计 |
| `datasource` | `InMemoryResourceDataSource` | 演示用后端数据源 |
| `service` | `DefaultDataAccessService` | 版本钉住、幂等/重放、审计编排 |
| `web` | `DataAccessController` / `PolicyAdminController` / `AuditQueryController` / `GlobalExceptionHandler` | HTTP 边界与安全错误映射 |
