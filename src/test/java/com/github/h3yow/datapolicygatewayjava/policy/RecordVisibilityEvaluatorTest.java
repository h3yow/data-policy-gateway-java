package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 记录级可见性求值器边界用例：
 * 条件命中/不命中、字面量与主体属性右值、依赖字段缺失、主体属性缺失、
 * 同批结构不一致、条件为空/null 以及条件值为 null 的失败关闭。
 * 日志只打印字段名与判定依据，不打印字段值。
 */
class RecordVisibilityEvaluatorTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordVisibilityEvaluatorTest.class);

    private final RecordVisibilityEvaluator evaluator = new RecordVisibilityEvaluator();

    private SubjectAttributes subject(Map<String, String> attrs) {
        return new SubjectAttributes("u-1", attrs);
    }

    private Map<String, Object> row(String id, String department) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("id", id);
        r.put("department", department);
        return r;
    }

    private RecordVisibilityCondition departmentEqLiteral(String value) {
        return new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.EQ, value, null)));
    }

    private RecordVisibilityCondition departmentEqSubjectAttr() {
        return new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.EQ, null, "department")));
    }

    @Test
    void matchingRecordsAreKeptAndNonMatchingAreFilteredOutEntirely() {
        List<Map<String, Object>> records = List.of(
                row("C001", "ENGINEERING"), row("C002", "FINANCE"),
                row("C003", "ENGINEERING"));
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST", "department", "ENGINEERING")),
                departmentEqSubjectAttr());
        log.info("record visibility test: input=3 rows(department), condition=department==subject.department, "
                + "basis='命中保留、不命中整条过滤（不是掏空）'");

        assertFalse(result.failClosed());
        assertEquals(2, result.visibleRecords().size());
        assertEquals(List.of("C001", "C003"),
                result.visibleRecords().stream().map(r -> r.get("id")).toList());
    }

    @Test
    void literalExpectedValueAlsoFilters() {
        List<Map<String, Object>> records = List.of(
                row("C001", "FINANCE"), row("C002", "SALES"));
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST")), departmentEqLiteral("FINANCE"));
        log.info("record visibility test: input=2 rows, condition=department=='FINANCE', "
                + "basis='字面量右值命中一条'");

        assertFalse(result.failClosed());
        assertEquals(1, result.visibleRecords().size());
        assertEquals("C001", result.visibleRecords().get(0).get("id"));
    }

    @Test
    void nullOrEmptyConditionKeepsAllRecords() {
        List<Map<String, Object>> records = List.of(
                row("C001", "A"), row("C002", "B"));
        RecordVisibilityResult r1 = evaluator.evaluate(records,
                subject(Map.of("role", "ADMIN")), null);
        RecordVisibilityResult r2 = evaluator.evaluate(records,
                subject(Map.of("role", "ADMIN")),
                new RecordVisibilityCondition(List.of()));
        log.info("record visibility test: input=2 rows, condition=null/空, "
                + "basis='不做记录级过滤，全部可见'");

        assertFalse(r1.failClosed());
        assertFalse(r2.failClosed());
        assertEquals(2, r1.visibleRecords().size());
        assertEquals(2, r2.visibleRecords().size());
    }

    @Test
    void missingConditionFieldInRecordsFailsClosedForWholeBatch() {
        List<Map<String, Object>> records = List.of(
                Map.of("id", "C001"), Map.of("id", "C002"));
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST", "department", "ENGINEERING")),
                departmentEqSubjectAttr());
        log.info("record visibility test: input=2 rows(no department field), "
                + "condition=department==subject.department, basis='依赖字段缺失 -> 整单失败关闭'");

        assertTrue(result.failClosed());
        assertTrue(result.reasonDetail().contains("department"));
        assertEquals(0, result.visibleRecords().size(), "失败关闭不得返回部分记录");
    }

    @Test
    void missingSubjectAttributeFailsClosedForWholeBatch() {
        List<Map<String, Object>> records = List.of(row("C001", "ENGINEERING"));
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST")), departmentEqSubjectAttr());
        log.info("record visibility test: input=1 row, subject 无 department 属性, "
                + "basis='主体右值缺失 -> 整单失败关闭'");

        assertTrue(result.failClosed());
        assertTrue(result.reasonDetail().contains("subject attribute"));
    }

    @Test
    void inconsistentRecordStructureAcrossBatchFailsClosed() {
        List<Map<String, Object>> records = new ArrayList<>();
        records.add(row("C001", "ENGINEERING"));
        Map<String, Object> extra = row("C002", "ENGINEERING");
        extra.put("phone", "13800000000");
        records.add(extra);
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST", "department", "ENGINEERING")),
                departmentEqSubjectAttr());
        log.info("record visibility test: input=2 rows(字段集合不一致), "
                + "basis='同批结构不一致 -> 整单失败关闭，不返回任何一条'");

        assertTrue(result.failClosed());
        assertTrue(result.reasonDetail().contains("structure inconsistent"));
        assertEquals(0, result.visibleRecords().size());
    }

    @Test
    void nullConditionValueInARecordFailsClosed() {
        Map<String, Object> nullDept = new LinkedHashMap<>();
        nullDept.put("id", "C009");
        nullDept.put("department", null);
        List<Map<String, Object>> records = List.of(
                row("C001", "ENGINEERING"), nullDept);
        RecordVisibilityResult result = evaluator.evaluate(records,
                subject(Map.of("role", "ANALYST", "department", "ENGINEERING")),
                departmentEqSubjectAttr());
        log.info("record visibility test: input=2 rows(第二条 department=null), "
                + "basis='条件值无法判定相等 -> 失败关闭，不放任 null 误判'");

        assertTrue(result.failClosed());
        assertEquals(0, result.visibleRecords().size());
    }

    @Test
    void malformedTermFailsClosed() {
        // 同时给了字面量和主体属性 → 条件定义不可解释
        RecordVisibilityCondition bad = new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.EQ,
                        "ENGINEERING", "department")));
        RecordVisibilityResult result = evaluator.evaluate(
                List.of(row("C001", "ENGINEERING")),
                subject(Map.of("role", "ANALYST", "department", "ENGINEERING")), bad);
        log.info("record visibility test: input=同时给出两种右值的条件项, "
                + "basis='条件本身无法解释 -> 失败关闭'");

        assertTrue(result.failClosed());
    }
}
