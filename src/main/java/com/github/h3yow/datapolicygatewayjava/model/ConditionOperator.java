package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 记录级可见性条件支持的比较算子。
 */
public enum ConditionOperator {
    /** 左值与右值（字符串形式）相等。 */
    EQ,
    /** 左值与右值（字符串形式）不相等。 */
    NOT_EQ,
    /** 左值包含在右值候选集合中（右值以逗号分隔给出）。 */
    IN
}
