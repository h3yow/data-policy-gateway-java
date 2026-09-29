package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 条件右值的来源：记录字段，或主体属性。
 */
public enum ConditionValueSource {
    /** 取自当前被判定记录的字段值。 */
    RECORD,
    /** 取自访问主体的属性值。 */
    SUBJECT
}
