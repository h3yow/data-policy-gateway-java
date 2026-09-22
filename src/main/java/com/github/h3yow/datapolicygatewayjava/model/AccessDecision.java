package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Map;

/**
 * 一次访问的整体判定结果。
 *
 * @param policyVersion 判定所依据的策略版本
 * @param matchedRuleId 命中的规则；无匹配为 null
 * @param fields        每个字段的判定
 * @param denyReason    整体拒绝原因；允许时为 null
 */
public record AccessDecision(String policyVersion,
                             String matchedRuleId,
                             Map<String, FieldDecision> fields,
                             DenyReason denyReason,
                             String reasonDetail) {

    public boolean allowed() {
        return denyReason == null;
    }
}
