package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;

/**
 * 某一版本的完整策略定义（不可变）。
 */
public record PolicyDefinition(String version, List<PolicyRule> rules) {
}
