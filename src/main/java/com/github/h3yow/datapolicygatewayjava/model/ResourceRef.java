package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Map;

/**
 * 目标资源引用：资源类型 + 可选实例属性（用于实例级判定）。
 */
public record ResourceRef(String resourceType, String resourceId, Map<String, String> attributes) {
}
