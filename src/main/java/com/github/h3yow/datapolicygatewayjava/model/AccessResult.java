package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一次访问的执行结果。拒绝时 records 为空列表，不携带任何受保护数据。
 *
 * @param requestId     请求标识（幂等键）
 * @param policyVersion 响应与审计共同归属的策略版本
 * @param allowed       是否放行
 * @param denyReason    拒绝原因（允许时为 null）
 * @param reasonDetail  原因说明（不得包含字段值）
 * @param matchedRuleId 命中规则（审计判定依据）
 * @param records       已过滤/脱敏后的记录
 */
public record AccessResult(String requestId,
                           String policyVersion,
                           boolean allowed,
                           DenyReason denyReason,
                           String reasonDetail,
                           String matchedRuleId,
                           List<Map<String, Object>> records) {
}
