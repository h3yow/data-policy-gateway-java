package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 记录级可见性求值器。
 *
 * <p>对命中规则的 {@link RecordVisibilityCondition} 逐记录求值，与字段级判定共享同一份
 * 策略快照（由网关保证）。语义：
 * <ol>
 *   <li>条件为 {@code null} 或不含任何判定项：所有记录可见（不做记录级过滤）；</li>
 *   <li><b>结构一致性</b>：同一批记录必须具有完全一致的字段集合；只要有一条记录
 *       字段多/少一个，即视为结构不一致，<b>整单失败关闭</b>，不返回部分数据；</li>
 *   <li>条件引用的字段必须存在于（一致的）记录结构中，引用的主体属性必须存在，
 *       否则条件无法求值，<b>整单失败关闭</b>；</li>
 *   <li>逐记录求值：所有判定项（AND）成立 → 记录可见；任一项不成立 → 整条记录过滤，
 *       不是返回被掏空的记录；求值过程中出现 null 值/类型无法比较等 → 失败关闭；</li>
 *   <li>失败原因说明只允许出现字段名等元数据，<b>绝不携带字段值</b>。</li>
 * </ol>
 */
@Component
public class RecordVisibilityEvaluator {

    public RecordVisibilityResult evaluate(List<Map<String, Object>> records,
                                           SubjectAttributes subject,
                                           RecordVisibilityCondition condition) {
        try {
            if (condition == null || condition.terms() == null || condition.terms().isEmpty()) {
                return RecordVisibilityResult.visible(records);
            }
            List<RecordConditionTerm> terms = condition.terms();

            // 1. 条件定义本身必须可解释；非法配置按失败关闭（detail 只含字段名元数据）
            for (RecordConditionTerm term : terms) {
                String invalid = validateTerm(term);
                if (invalid != null) {
                    return RecordVisibilityResult.failClosed(invalid);
                }
            }

            // 2. 同批记录结构一致性：所有记录的字段集合必须完全相同
            Set<String> structure = null;
            for (int i = 0; i < records.size(); i++) {
                Map<String, Object> row = records.get(i);
                if (row == null) {
                    return RecordVisibilityResult.failClosed(
                            "record structure inconsistent: null record at index " + i);
                }
                Set<String> keys = new LinkedHashSet<>(row.keySet());
                if (structure == null) {
                    structure = keys;
                } else if (!structure.equals(keys)) {
                    return RecordVisibilityResult.failClosed(
                            "record structure inconsistent across the batch");
                }
            }
            if (structure == null) {
                structure = Set.of();
            }

            // 3. 条件依赖的字段必须存在于记录结构中（任一缺失都无法求值整批）
            for (RecordConditionTerm term : terms) {
                if (!structure.contains(term.field())) {
                    return RecordVisibilityResult.failClosed(
                            "record condition references field absent in records: '"
                                    + term.field() + "'");
                }
            }

            // 4. 主体属性形式的右值在批处理开始前统一解析（缺失即失败关闭）
            Map<String, String> subjectAttrs = subject == null ? null : subject.attributes();
            String[] expectedValues = new String[terms.size()];
            for (int i = 0; i < terms.size(); i++) {
                RecordConditionTerm term = terms.get(i);
                if (term.expectedValue() != null) {
                    expectedValues[i] = term.expectedValue();
                } else {
                    String attrKey = term.expectedFromSubjectAttribute();
                    if (subjectAttrs == null || !subjectAttrs.containsKey(attrKey)) {
                        return RecordVisibilityResult.failClosed(
                                "record condition requires missing subject attribute: '"
                                        + attrKey + "'");
                    }
                    expectedValues[i] = subjectAttrs.get(attrKey);
                }
            }

            // 5. 逐记录求值；不满足条件的整条过滤
            List<Map<String, Object>> visible = new ArrayList<>(records.size());
            for (Map<String, Object> row : records) {
                if (matchesAll(row, terms, expectedValues)) {
                    visible.add(row);
                }
            }
            return RecordVisibilityResult.visible(visible);
        } catch (RuntimeException e) {
            // 任何意外都不能造成“部分数据”，失败关闭且不携带字段值
            return RecordVisibilityResult.failClosed(
                    "record condition evaluation error: " + e.getClass().getSimpleName());
        }
    }

    private String validateTerm(RecordConditionTerm term) {
        if (term == null) {
            return "record condition contains a null term";
        }
        if (term.field() == null || term.field().isBlank()) {
            return "record condition term requires a field name";
        }
        if (term.operator() == null) {
            return "record condition term requires an operator for field '" + term.field() + "'";
        }
        boolean hasLiteral = term.expectedValue() != null;
        boolean hasSubjectRef = term.expectedFromSubjectAttribute() != null
                && !term.expectedFromSubjectAttribute().isBlank();
        if (hasLiteral == hasSubjectRef) {
            return "record condition term on field '" + term.field()
                    + "' must provide exactly one of expectedValue/"
                    + "expectedFromSubjectAttribute";
        }
        return null;
    }

    private boolean matchesAll(Map<String, Object> row,
                               List<RecordConditionTerm> terms,
                               String[] expectedValues) {
        for (int i = 0; i < terms.size(); i++) {
            RecordConditionTerm term = terms.get(i);
            Object actual = row.get(term.field());
            if (actual == null) {
                // null 值无法可靠判定相等：视为不可求值，由上层失败关闭
                throw new IllegalStateException("null value on condition field");
            }
            String expected = expectedValues[i];
            if (expected == null) {
                throw new IllegalStateException("null expected value on condition field");
            }
            if (!compare(actual, term.operator(), expected)) {
                return false;
            }
        }
        return true;
    }

    private boolean compare(Object actual, ConditionOperator operator, String expected) {
        String actualText = actual.toString();
        return switch (operator) {
            case EQ -> actualText.equals(expected);
        };
    }
}
