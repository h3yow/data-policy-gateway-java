package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Map;

/**
 * 一条策略规则：按主体属性条件 + 资源类型 + 动作匹配，
 * 命中后给出记录级可见性条件与字段级策略，以及未列出字段的默认可见性。
 *
 * @param ruleId         规则标识（用于审计中的判定依据）
 * @param subjectConditions 主体属性需全部满足的键值条件
 * @param resourceType   目标资源类型
 * @param action         访问动作
 * @param fieldPolicies  字段策略列表
 * @param defaultVisible 未被 fieldPolicies 覆盖字段的默认可见性
 * @param recordCondition 记录级可见性条件；null 表示不做记录级过滤（仅字段级）
 * @param recordVisibilityEnabled 记录级过滤的显式启用开关：只有它为 {@code true}
 *                                且 {@code recordCondition} 非空时，记录级过滤才生效。
 *                                仅声明条件不启用——保证未主动启用的在服策略行为不变。
 */
public record PolicyRule(String ruleId,
                         Map<String, String> subjectConditions,
                         String resourceType,
                         AccessAction action,
                         List<FieldPolicy> fieldPolicies,
                         boolean defaultVisible,
                         RecordVisibilityCondition recordCondition,
                         boolean recordVisibilityEnabled) {

    /** 不含记录级条件的便捷构造器（等价于 recordCondition=null 且未启用，保持旧策略定义兼容）。 */
    public PolicyRule(String ruleId,
                      Map<String, String> subjectConditions,
                      String resourceType,
                      AccessAction action,
                      List<FieldPolicy> fieldPolicies,
                      boolean defaultVisible) {
        this(ruleId, subjectConditions, resourceType, action, fieldPolicies,
                defaultVisible, null, false);
    }

    /**
     * 携带记录级条件但<b>不启用</b>的便捷构造器：条件只是预置定义，
     * 记录级过滤必须经 {@link #withRecordVisibilityEnabled()} 或全参构造器显式启用，
     * 避免“条件存在即生效”误伤在服流量。
     */
    public PolicyRule(String ruleId,
                      Map<String, String> subjectConditions,
                      String resourceType,
                      AccessAction action,
                      List<FieldPolicy> fieldPolicies,
                      boolean defaultVisible,
                      RecordVisibilityCondition recordCondition) {
        this(ruleId, subjectConditions, resourceType, action, fieldPolicies,
                defaultVisible, recordCondition, false);
    }

    /** 返回启用了记录级过滤的副本（其余字段不变）。 */
    public PolicyRule withRecordVisibilityEnabled() {
        return new PolicyRule(ruleId, subjectConditions, resourceType, action,
                fieldPolicies, defaultVisible, recordCondition, true);
    }

    /** 记录级过滤是否对本规则实际生效（显式启用且条件存在）。 */
    public boolean recordVisibilityActive() {
        return recordVisibilityEnabled && recordCondition != null;
    }
}
