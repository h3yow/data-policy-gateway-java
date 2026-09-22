package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Map;

/**
 * 单个字段的授权与脱敏策略。
 *
 * @param fieldName      字段名
 * @param visible        是否可见；false 表示显式拒绝（越权）
 * @param maskingType    可见时的脱敏方式
 * @param maskingParams  脱敏参数（如保留前后位数）
 */
public record FieldPolicy(String fieldName,
                          boolean visible,
                          MaskingType maskingType,
                          Map<String, String> maskingParams) {
}
