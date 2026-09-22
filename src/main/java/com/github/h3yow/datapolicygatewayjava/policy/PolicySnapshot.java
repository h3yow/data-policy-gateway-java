package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;

/**
 * 不可变策略快照：一次读取从头到尾（响应 + 审计）只使用同一快照。
 */
public final class PolicySnapshot {

    private final PolicyDefinition definition;

    public PolicySnapshot(PolicyDefinition definition) {
        this.definition = definition;
    }

    public PolicyDefinition definition() {
        return definition;
    }

    public String version() {
        return definition.version();
    }
}
