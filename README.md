# data-policy-gateway-java

数据读取出口的**字段级授权 + 脱敏**策略网关（Spring Boot 3.4 / Java 21）。

核心能力：

- 按**主体属性 × 目标资源 × 访问动作**做字段级可见性判定；
  越权（`FIELD_UNAUTHORIZED`）与策略不匹配（`POLICY_NOT_MATCHED`）原因可区分。
- 策略运行中更新：不可变快照 + 单次引用交换，读者不会看到半更新状态；
  同一次响应与审计记录归属同一策略版本；回退与跳版本更新被明确拒绝。
- 求值失败、字段映射缺失、脱敏异常一律**失败关闭**，不返回部分数据；
  基于 `requestId` 的幂等保证重试不产生重复审计、结果可复现。
- 未授权字段不会出现在响应、异常消息或日志中。

## 快速开始

```bash
mvn test            # 全部单元/集成测试
mvn spring-boot:run # 启动（种子资源 customer:c-1001 + v1 策略）
```

## 文档

策略模型、脱敏规则、一致性保证、HTTP API 与验证方法见
[`docs/POLICY_GATEWAY.md`](docs/POLICY_GATEWAY.md)。
