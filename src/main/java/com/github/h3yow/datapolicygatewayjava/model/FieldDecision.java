package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 单个字段的判定结果（用于解释与审计）。
 */
public record FieldDecision(String fieldName,
                            boolean allowed,
                            boolean masked,
                            MaskingType maskingType,
                            DenyReason denyReason,
                            String reasonDetail) {
}
