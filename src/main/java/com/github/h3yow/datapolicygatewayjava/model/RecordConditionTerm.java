package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 记录级可见性条件的单个原子项。
 *
 * <p>左值固定取自记录字段 {@code fieldName}；右值由 {@code valueSource} 决定取自
 * 主体属性（{@code referenceKey} 为主体属性键），或是 {@code expectedValue} 字面量。
 *
 * @param fieldName     条件依赖的记录字段名
 * @param operator      比较算子
 * @param valueSource   右值来源（字面量 / 主体属性）
 * @param referenceKey  右值取自主体属性时的属性键；字面量右值时为 null
 * @param expectedValue 右值字面量；IN 时为逗号分隔候选集合；取自主体属性时为 null
 */
public record RecordConditionTerm(String fieldName,
                                  ConditionOperator operator,
                                  ConditionValueSource valueSource,
                                  String referenceKey,
                                  String expectedValue) {
}
