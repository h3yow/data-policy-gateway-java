package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.DataSource;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.gateway.IdempotentResultStore;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.visibility.RecordVisibilityEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 网关端到端：记录级可见性 + 字段级叠加 + 失败关闭原因可区分 + 更新后重复提交复现首次结果。
 */
class RecordLevelAccessGatewayTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordLevelAccessGatewayTest.class);

    private PolicyStore policyStore;
    private AuditService auditService;
    private DataAccessGateway gateway;

    /** 可定制记录内容的 customer 数据源（返回可变副本）。 */
    private static class FixedDataSource implements DataSource {
        private final List<Map<String, Object>> rows;

        FixedDataSource(List<Map<String, Object>> rows) {
            this.rows = rows;
        }

        @Override
        public boolean supports(String resourceType) {
            return InMemoryDataSource.RESOURCE_TYPE.equals(resourceType);
        }

        @Override
        public List<Map<String, Object>> fetch(ResourceRef resource) {
            return rows.stream().<Map<String, Object>>map(LinkedHashMap::new).toList();
        }
    }

    private AccessRequest analystRequest(String requestId, String department) {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("role", "ANALYST");
        if (department != null) {
            attrs.put("department", department);
        }
        return new AccessRequest(requestId,
                new SubjectAttributes("u-analyst", attrs),
                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                AccessAction.READ);
    }

    private AccessRequest adminRequest(String requestId) {
        return new AccessRequest(requestId,
                new SubjectAttributes("u-admin", Map.of("role", "ADMIN")),
                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                AccessAction.READ);
    }

    private void setUpWith(List<Map<String, Object>> rows) {
        policyStore = new PolicyStore();
        policyStore.publish(BootstrapPolicyInitializer.v1(), null);
        policyStore.publish(BootstrapPolicyInitializer.v2RecordScoped(), "v1");
        auditService = new AuditService();
        gateway = new DataAccessGateway(policyStore, new PolicyEvaluator(),
                new RecordVisibilityEvaluator(), new Masker(), auditService,
                new IdempotentResultStore(), List.of(new FixedDataSource(rows)));
    }

    private List<Map<String, Object>> standardRows() {
        // 与内置数据源键集合一致：id/name/nationalId/phone/email/salary/department
        return List.of(
                fullRow("C001", "Zhang Wei", "ENGINEERING"),
                fullRow("C002", "Li Na", "FINANCE"),
                fullRow("C003", "Wang Fang", "ENGINEERING"));
    }

    private Map<String, Object> fullRow(String id, String name, String department) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("name", name);
        m.put("nationalId", "110101199001011234");
        m.put("phone", "13800001111");
        m.put("email", name.toLowerCase().replace(" ", "") + "@example.com");
        m.put("salary", 12000);
        m.put("department", department);
        return m;
    }

    @Test
    void analystOnlySeesOwnDepartmentRecordsWithFieldPoliciesStacked() {
        setUpWith(standardRows());

        AccessResult result = gateway.execute(analystRequest("rec-1", "ENGINEERING"));
        log.info("record-level test: input=ANALYST department=ENGINEERING, policyVersion=v2, "
                + "basis='记录条件 department==subject.department 过滤 + 字段级 phone/email 哈希、"
                + "nationalId/salary 剥离'");

        assertEquals("v2", result.policyVersion());
        assertEquals("r-analyst-read-dept", result.matchedRuleId());
        assertEquals(2, result.records().size(), "只能看到本部门 2 条记录");
        assertEquals(List.of("C001", "C003"),
                result.records().stream().map(r -> r.get("id")).toList());
        for (Map<String, Object> row : result.records()) {
            assertFalse(row.containsKey("nationalId"), "记录级与字段级必须同时生效：越权字段仍剥离");
            assertFalse(row.containsKey("salary"));
            assertEquals(64, ((String) row.get("phone")).length(), "哈希脱敏仍生效");
        }
    }

    @Test
    void adminRuleWithoutRecordConditionSeesAllRecords() {
        setUpWith(standardRows());
        AccessResult result = gateway.execute(adminRequest("rec-admin-1"));
        assertEquals(3, result.records().size(), "管理员规则无记录级条件，可见全部");
        assertEquals("r-admin-read", result.matchedRuleId());
    }

    @Test
    void noRecordMatchesConditionReturnsEmptySetWithoutDenial() {
        setUpWith(standardRows());
        AccessResult result = gateway.execute(analystRequest("rec-empty-1", "SALES"));
        log.info("record-level test: input=ANALYST department=SALES, basis='无记录命中条件 -> "
                + "放行但记录集为空（不是拒绝）'");
        assertTrue(result.allowed());
        assertEquals(0, result.records().size());
        AuditRecord audit = auditService.findByRequestId("rec-empty-1").orElseThrow();
        assertTrue(audit.allowed());
        assertEquals("v2", audit.policyVersion());
    }

    @Test
    void missingConditionFieldFailsClosedWithDistinctReasonAndAudit() {
        // 批内记录都不含条件依赖键 department（注意：不是值为 null，而是键不存在）。
        // v2 analyst 规则显式映射了 department，字段级不会 FIELD_MAPPING_MISSING；
        // 记录级条件求值时发现 department 键不存在 -> RECORD_CONDITION_FAILED。
        Map<String, Object> noDept1 = new LinkedHashMap<>();
        noDept1.put("id", "X1");
        noDept1.put("name", "A");
        Map<String, Object> noDept2 = new LinkedHashMap<>();
        noDept2.put("id", "X2");
        noDept2.put("name", "B");
        setUpWith(List.of(noDept1, noDept2));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("rec-missing-1", "ENGINEERING")));
        log.info("record-level test: input=记录缺少条件依赖字段 department, "
                + "basis='依赖缺失整单拒绝', denyReason={}", ex.reason());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
        assertEquals("v2", ex.policyVersion());
        AuditRecord audit = auditService.findByRequestId("rec-missing-1").orElseThrow();
        assertFalse(audit.allowed());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, audit.denyReason());
    }

    @Test
    void missingSubjectAttributeIsDistinctFromFieldForbiddenAndNoMatch() {
        setUpWith(standardRows());
        // ANALYST 但没有 department 属性：规则命中（不是 POLICY_NO_MATCH），
        // 条件引用的主体属性缺失（不是 FIELD_FORBIDDEN）
        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("rec-noattr-1", null)));
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
        assertTrue(ex.reason() != DenyReason.POLICY_NO_MATCH);
        assertTrue(ex.reason() != DenyReason.FIELD_FORBIDDEN);
    }

    @Test
    void inconsistentBatchStructureRejectsWholeBatch() {
        List<Map<String, Object>> rows = new java.util.ArrayList<>(standardRows());
        Map<String, Object> shortRow = new LinkedHashMap<>();
        shortRow.put("id", "C999");
        shortRow.put("name", "Short");
        rows.add(shortRow);
        setUpWith(rows);

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("rec-inconsistent-1", "ENGINEERING")));
        log.info("record-level test: input=同批记录结构不一致, basis='整单拒绝空记录集', "
                + "denyReason={}", ex.reason());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, ex.reason());
    }

    @Test
    void retryAfterPolicyUpdateReplaysFirstOutcomeForAllowed() {
        setUpWith(standardRows());
        AccessRequest req = analystRequest("rec-replay-ok", "ENGINEERING");

        AccessResult first = gateway.execute(req);
        assertEquals(2, first.records().size());
        assertEquals("v2", first.policyVersion());

        // 发布 v3：分析人员规则改为只允许 FINANCE（语义翻转）
        policyStore.publish(flippedPolicy("v3"), "v2");
        AccessResult replay = gateway.execute(req);

        log.info("record-level test: input=同 requestId 在 v3 发布后重试, "
                + "basis='必须复现 v2 首次结果（2 条 ENGINEERING 记录）'");
        assertEquals(first.policyVersion(), replay.policyVersion());
        assertEquals(first.records().size(), replay.records().size());
        assertEquals(List.of("C001", "C003"),
                replay.records().stream().map(r -> r.get("id")).toList());
        // 全新 requestId 在 v3 下应观察到新语义：只有 FINANCE 记录（C002）可见
        AccessResult fresh = gateway.execute(analystRequest("rec-fresh-after-v3", "ENGINEERING"));
        assertEquals("v3", fresh.policyVersion());
        assertEquals(1, fresh.records().size(), "v3 条件为 department==FINANCE，仅 C002 可见");
        assertEquals("C002", fresh.records().get(0).get("id"));
        // 审计不重不漏：重试只保留首次一条
        long count = auditService.all().stream()
                .filter(a -> a.requestId().equals("rec-replay-ok")).count();
        assertEquals(1, count);
        AuditRecord audit = auditService.findByRequestId("rec-replay-ok").orElseThrow();
        assertEquals("v2", audit.policyVersion(), "响应与审计同属首次版本");
    }

    @Test
    void retryAfterPolicyUpdateReplaysFirstDenial() {
        // v2 下主体缺 department 属性 -> 首次整单拒绝
        setUpWith(standardRows());
        AccessRequest req = analystRequest("rec-replay-deny", null);
        AccessDeniedException first = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(req));
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, first.reason());
        assertEquals("v2", first.policyVersion());

        // v3 移除记录级条件（等价 v1 语义，全部记录参与字段级判定）；重试仍必须复现首次拒绝
        policyStore.publish(new com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition(
                "v3", List.of(BootstrapPolicyInitializer.adminRule(),
                        BootstrapPolicyInitializer.analystRule(),
                        BootstrapPolicyInitializer.guestRule())), "v2");

        AccessDeniedException replay = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(req));
        log.info("record-level test: input=首次拒绝后发布无条件 v3 再重试, "
                + "basis='复现首次拒绝原因与版本', reason={}, policyVersion={}",
                replay.reason(), replay.policyVersion());
        assertEquals(DenyReason.RECORD_CONDITION_FAILED, replay.reason());
        assertEquals("v2", replay.policyVersion());
        long count = auditService.all().stream()
                .filter(a -> a.requestId().equals("rec-replay-deny")).count();
        assertEquals(1, count, "拒绝重试审计不重复");
    }

    /** v3：分析人员记录条件翻转为字面量 department==FINANCE（ENGINEERING 主体将看不到任何记录）。 */
    private com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition flippedPolicy(String v) {
        return new com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition(v, List.of(
                BootstrapPolicyInitializer.adminRule(),
                new com.github.h3yow.datapolicygatewayjava.model.PolicyRule(
                        "r-analyst-read-dept", Map.of("role", "ANALYST"),
                        "customer", AccessAction.READ,
                        BootstrapPolicyInitializer.analystRule().fieldPolicies(),
                        false,
                        new com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition(
                                List.of(new com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm(
                                        "department",
                                        com.github.h3yow.datapolicygatewayjava.model.ConditionOperator.EQ,
                                        com.github.h3yow.datapolicygatewayjava.model.ConditionValueSource.RECORD,
                                        null, "FINANCE")))),
                BootstrapPolicyInitializer.guestRule()));
    }
}
