package com.github.h3yow.datapolicygatewayjava.gateway;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

import java.util.List;
import java.util.Map;

/**
 * 一次请求首次执行的不可变结果快照，用于同 requestId 重复提交/重试时<b>原样复现</b>。
 *
 * <p>即使重试发生在策略更新之后，也必须返回首次的放行结果（同样的可见记录与脱敏值）
 * 或首次的拒绝（同样的原因码、同一策略版本）。
 *
 * @param allowed       首次判定是否放行
 * @param policyVersion 首次判定依据的策略版本
 * @param matchedRuleId 首次命中规则
 * @param denyReason    首次拒绝原因（放行时为 null）
 * @param reasonDetail  首次拒绝说明
 * @param records       首次放行时已过滤/脱敏的记录（拒绝时为空列表）
 */
public record StoredOutcome(boolean allowed,
                            String policyVersion,
                            String matchedRuleId,
                            DenyReason denyReason,
                            String reasonDetail,
                            List<Map<String, Object>> records) {
}
