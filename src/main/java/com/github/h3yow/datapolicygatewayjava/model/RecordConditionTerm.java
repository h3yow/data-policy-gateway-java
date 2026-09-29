package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 记录级可见性条件的一个最小判定项（AND 语义）。
 *
 * <p>对一条记录求：{@code record[field] <op> expected}。期望值二选一：
 * <ul>
 *   <li>{@code expectedValue}：字面量（如角色为 ANALYST 时限定部门 "ENGINEERING"）；</li>
 *   <li>{@code expectedFromSubjectAttribute}：取主体属性作为右值
 *       （如 record.department == subject.department，实现“只看本部门”）。</li>
 * </ul>
 * 主体缺少被引用属性 / 记录缺少被引用字段 / 比较无法求值，均视为不可求值（失败关闭）。
 *
 * @param field                          被判定的记录字段名
 * @param operator                       比较运算符
 * @param expectedValue                  字面量期望值（与 expectedFromSubjectAttribute 二选一）
 * @param expectedFromSubjectAttribute   主体属性键名（与 expectedValue 二选一）
 */
public record RecordConditionTerm(String field,
                                  ConditionOperator operator,
                                  String expectedValue,
                                  String expectedFromSubjectAttribute) {
}
