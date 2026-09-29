package com.github.h3yow.datapolicygatewayjava.visibility;

import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.ConditionValueSource;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 记录级可见性求值器：在字段级处理之前按规则上的 {@code recordCondition} 过滤记录。
 *
 * <p>纯函数、无状态。求值发生在网关内部（需要记录值），但原始记录不会离开网关组件。
 *
 * <p>失败关闭约定：
 * <ul>
 *   <li>条件依赖的字段在某条记录中不存在 → {@link RecordVisibilityException}；</li>
 *   <li>条件本身无法求值（右值引用的主体属性缺失、算子未知等）→ 同样抛出；</li>
 *   <li>同一批记录结构不一致（键集合不同）→ 整批拒绝。</li>
 * </ul>
 */
@Component
public class RecordVisibilityEvaluator {

    /**
     * 按命中规则的记录级条件过滤一批记录。
     *
     * @return 可见记录（保持原顺序）；规则无条件时原样返回
     */
    public List<Map<String, Object>> filter(PolicyRule matchedRule,
                                            SubjectAttributes subject,
                                            List<Map<String, Object>> records) {
        RecordVisibilityCondition condition =
                matchedRule == null ? null : matchedRule.recordCondition();
        if (condition == null || condition.terms() == null || condition.terms().isEmpty()) {
            // 规则未声明记录级条件：不做记录级过滤
            return records;
        }
        List<RecordConditionTerm> terms = condition.terms();

        // 1. 同一批记录结构必须一致（键集合完全相同），否则整批拒绝
        Set<String> referenceKeys = null;
        int index = 0;
        for (Map<String, Object> row : records) {
            Set<String> keys = row.keySet();
            if (referenceKeys == null) {
                referenceKeys = new HashSet<>(keys);
            } else if (!referenceKeys.equals(new HashSet<>(keys))) {
                throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                        "records in the same batch have inconsistent field sets at index "
                                + index);
            }
            index++;
        }

        // 2. 逐条求值；任一条件项无法求值即整单失败关闭，绝不只返回一部分记录
        List<Map<String, Object>> visible = new ArrayList<>(records.size());
        for (Map<String, Object> row : records) {
            if (evaluateTerms(terms, row, subject)) {
                visible.add(row);
            }
        }
        return visible;
    }

    private boolean evaluateTerms(List<RecordConditionTerm> terms,
                                  Map<String, Object> row,
                                  SubjectAttributes subject) {
        for (RecordConditionTerm term : terms) {
            if (!evaluateTerm(term, row, subject)) {
                return false;
            }
        }
        return true;
    }

    private boolean evaluateTerm(RecordConditionTerm term,
                                 Map<String, Object> row,
                                 SubjectAttributes subject) {
        if (term == null || term.fieldName() == null || term.operator() == null
                || term.valueSource() == null) {
            throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                    "malformed record visibility condition term");
        }
        // 条件依赖字段在该记录中不存在（键缺失，区别于值为 null）→ 无法求值 → 失败关闭
        if (!row.containsKey(term.fieldName())) {
            throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                    "record condition references missing field '" + term.fieldName() + "'");
        }
        Object actual = row.get(term.fieldName());
        if (actual == null) {
            // 依赖字段值为 null：条件无法被可靠求值，按失败关闭处理
            throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                    "record condition field '" + term.fieldName() + "' has null value");
        }
        String actualText = actual.toString();

        ConditionValueSource source = term.valueSource();
        if (source == ConditionValueSource.SUBJECT) {
            String key = term.referenceKey();
            Map<String, String> attrs = subject == null ? null : subject.attributes();
            if (key == null || attrs == null || !attrs.containsKey(key) || attrs.get(key) == null) {
                throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                        "record condition references missing subject attribute '"
                                + key + "'");
            }
            return compare(term.operator(), actualText, attrs.get(key));
        }
        if (term.expectedValue() == null) {
            throw new RecordVisibilityException(DenyReason.RECORD_CONDITION_FAILED,
                    "record condition literal expected value is missing for field '"
                            + term.fieldName() + "'");
        }
        return compare(term.operator(), actualText, term.expectedValue());
    }

    private boolean compare(ConditionOperator operator, String actual, String expected) {
        return switch (operator) {
            case EQ -> actual.equals(expected);
            case NOT_EQ -> !actual.equals(expected);
            case IN -> Arrays.stream(expected.split(","))
                    .map(String::trim)
                    .anyMatch(actual::equals);
        };
    }
}
