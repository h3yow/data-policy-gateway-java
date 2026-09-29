package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;

/**
 * 一条规则上的记录级可见性条件。
 *
 * <p>{@code terms} 之间是 AND 语义：全部成立该记录才可见；
 * {@code terms} 为 null/空表示该规则不做记录级过滤（所有记录可见）。
 *
 * @param terms 原子条件项，AND 组合
 */
public record RecordVisibilityCondition(List<RecordConditionTerm> terms) {
}
