package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 可区分的拒绝原因（用于响应错误码与审计）。
 */
public enum DenyReason {
    /** 主体/资源/动作没有任何策略规则匹配（策略不匹配）。 */
    POLICY_NO_MATCH,
    /** 命中显式拒绝规则（越权）。 */
    FIELD_FORBIDDEN,
    /** 策略求值过程发生异常，失败关闭。 */
    EVALUATION_FAILED,
    /** 响应字段在策略中缺失映射，失败关闭。 */
    FIELD_MAPPING_MISSING,
    /** 脱敏规则执行异常，失败关闭。 */
    MASKING_FAILED,
    /** 记录级可见性条件无法求值（依赖字段缺失/结构不一致/比较失败），失败关闭。 */
    RECORD_CONDITION_UNEVALUABLE
}
