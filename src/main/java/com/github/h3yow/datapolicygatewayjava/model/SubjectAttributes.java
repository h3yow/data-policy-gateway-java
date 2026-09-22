package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Map;

/**
 * 访问主体及其属性（如 role、department、region）。
 */
public record SubjectAttributes(String subjectId, Map<String, String> attributes) {
}
