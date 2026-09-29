package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;

/**
 * 一条规则的记录级可见性条件：{@code terms} 全部成立时记录才可见（AND 语义）。
 *
 * <p>不成立的记录整条被过滤（不返回被掏空的记录）；条件无法求值则整单失败关闭。
 * {@code null} 表示该规则不做记录级过滤（仅字段级判定，保持向后兼容）。
 *
 * @param terms 判定项列表；空列表表示“所有记录均可见”
 */
public record RecordVisibilityCondition(List<RecordConditionTerm> terms) {
}
