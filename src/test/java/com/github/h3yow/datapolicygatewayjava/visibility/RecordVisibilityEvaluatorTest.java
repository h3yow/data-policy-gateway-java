package com.github.h3yow.datapolicygatewayjava.visibility;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.ConditionValueSource;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 记录级可见性求值器单测：条件命中/不命中、依赖字段缺失、条件不可求值、批内结构不一致。
 */
class RecordVisibilityEvaluatorTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordVisibilityEvaluatorTest.class);

    private final RecordVisibilityEvaluator evaluator = new RecordVisibilityEvaluator();

    private Map<String, Object> row(String id, String department) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("department", department);
        return m;
    }

    private PolicyRule ruleWith(RecordVisibilityCondition condition) {
        return new PolicyRule("r-test", Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                List.of(new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of())),
                false, condition);
    }

    private RecordConditionTerm deptEqSubject() {
        return new RecordConditionTerm("department", ConditionOperator.EQ,
                ConditionValueSource.SUBJECT, "department", null);
    }

    private SubjectAttributes analyst(String department) {
        return new SubjectAttributes("u-1",
                department == null ? Map.of("role", "ANALYST")
                        : Map.of("role", "ANALYST", "department", department));
    }

    @Test
    void matchingAndNonMatchingConditionsFilterWholeRecords() {
        PolicyRule rule = ruleWith(
                new RecordVisibilityCondition(List.of(deptEqSubject())));
        List<Map<String, Object>> batch = List.of(
                row("C1", "ENGINEERING"), row("C2", "FINANCE"),
                row("C3", "ENGINEERING"));

        List<Map<String, Object>> visible =
                evaluator.filter(rule, analyst("ENGINEERING"), batch);
        log.info("record filter test: input=subject.department=ENGINEERING over "
                + "[ENGINEERING, FINANCE, ENGINEERING], basis='EQ 命中整条保留，不命中整条消失'");

        assertEquals(2, visible.size(), "不满足条件的记录必须整条不出现");
        assertEquals("C1", visible.get(0).get("id"));
        assertEquals("C3", visible.get(1).get("id"));
    }

    @Test
    void noConditionRulesReturnAllRecords() {
        PolicyRule rule = new PolicyRule("r-test", Map.of("role", "ADMIN"),
                "customer", AccessAction.READ,
                List.of(new FieldPolicy("id", true, MaskingType.NONE, Map.of())), false);
        List<Map<String, Object>> batch = List.of(row("C1", "A"), row("C2", "B"));
        List<Map<String, Object>> visible = evaluator.filter(rule, analyst("A"), batch);
        assertSame(batch, visible, "无记录级条件时应原样返回");
    }

    @Test
    void missingDependentFieldFailsClosed() {
        PolicyRule rule = ruleWith(new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("region", ConditionOperator.EQ,
                        ConditionValueSource.RECORD, null, "EAST"))));
        List<Map<String, Object>> batch = List.of(row("C1", "ENGINEERING"));

        RecordVisibilityException ex = assertThrows(RecordVisibilityException.class,
                () -> evaluator.filter(rule, analyst(null), batch));
        log.info("record filter test: input=条件依赖 region 字段但记录无此键, "
                + "basis='依赖缺失 -> 失败关闭', reason={}", ex.reason());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
    }

    @Test
    void nullDependentValueFailsClosed() {
        PolicyRule rule = ruleWith(
                new RecordVisibilityCondition(List.of(deptEqSubject())));
        Map<String, Object> nullDept = new LinkedHashMap<>();
        nullDept.put("id", "C1");
        nullDept.put("department", null);

        RecordVisibilityException ex = assertThrows(RecordVisibilityException.class,
                () -> evaluator.filter(rule, analyst("ENGINEERING"), List.of(nullDept)));
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
    }

    @Test
    void missingSubjectAttributeFailsClosed() {
        PolicyRule rule = ruleWith(
                new RecordVisibilityCondition(List.of(deptEqSubject())));
        List<Map<String, Object>> batch = List.of(row("C1", "ENGINEERING"));

        RecordVisibilityException ex = assertThrows(RecordVisibilityException.class,
                () -> evaluator.filter(rule, analyst(null), batch));
        log.info("record filter test: input=条件引用 subject.department 但主体无该属性, "
                + "basis='条件不可求值 -> 失败关闭', reason={}", ex.reason());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
    }

    @Test
    void inconsistentBatchStructureFailsClosedForWholeBatch() {
        PolicyRule rule = ruleWith(
                new RecordVisibilityCondition(List.of(deptEqSubject())));
        Map<String, Object> shortRow = new LinkedHashMap<>();
        shortRow.put("id", "C9");
        // 第二条比第一条少一个键 -> 同批结构不一致
        List<Map<String, Object>> batch = List.of(row("C1", "ENGINEERING"), shortRow);

        RecordVisibilityException ex = assertThrows(RecordVisibilityException.class,
                () -> evaluator.filter(rule, analyst("ENGINEERING"), batch));
        log.info("record filter test: input=同批记录键集合不一致, "
                + "basis='结构不一致 -> 整单拒绝，不返回部分数据', reason={}", ex.reason());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
    }

    @Test
    void inAndNotEqOperators() {
        PolicyRule inRule = ruleWith(new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.IN,
                        ConditionValueSource.RECORD, null, "FINANCE,SALES"))));
        List<Map<String, Object>> batch = List.of(
                row("C1", "ENGINEERING"), row("C2", "FINANCE"), row("C3", "SALES"));
        List<Map<String, Object>> visible =
                evaluator.filter(inRule, analyst(null), batch);
        assertEquals(2, visible.size());
        assertEquals("C2", visible.get(0).get("id"));

        PolicyRule notEqRule = ruleWith(new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.NOT_EQ,
                        ConditionValueSource.RECORD, null, "FINANCE"))));
        List<Map<String, Object>> visible2 =
                evaluator.filter(notEqRule, analyst(null), batch);
        assertEquals(2, visible2.size());
        assertTrue(visible2.stream().noneMatch(r -> "C2".equals(r.get("id"))));
    }
}
