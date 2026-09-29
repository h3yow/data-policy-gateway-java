package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一条策略规则：按主体属性条件 + 资源类型 + 动作匹配，
 * 命中后给出字段级策略与未列出字段的默认可见性。
 *
 * @param ruleId         规则标识（用于审计中的判定依据）
 * @param subjectConditions 主体属性需全部满足的键值条件
 * @param resourceType   目标资源类型
 * @param action         访问动作
 * @param fieldPolicies  字段策略列表
 * @param defaultVisible 未被 fieldPolicies 覆盖字段的默认可见性
 * @param recordCondition 记录级可见性条件；null 表示该规则不做记录级过滤
 */
public record PolicyRule(String ruleId,
                         Map<String, String> subjectConditions,
                         String resourceType,
                         AccessAction action,
                         List<FieldPolicy> fieldPolicies,
                         boolean defaultVisible,
                         RecordVisibilityCondition recordCondition) {

    /** 兼容无记录级条件的规则（等价于 recordCondition=null）。 */
    public PolicyRule(String ruleId,
                      Map<String, String> subjectConditions,
                      String resourceType,
                      AccessAction action,
                      List<FieldPolicy> fieldPolicies,
                      boolean defaultVisible) {
        this(ruleId, subjectConditions, resourceType, action,
                fieldPolicies, defaultVisible, null);
    }
}
