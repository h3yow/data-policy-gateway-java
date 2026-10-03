package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.gateway.ResponseReplayStore;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.policy.RecordVisibilityEvaluator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 记录级可见性网关端到端用例（均基于<b>显式启用</b>记录级过滤的策略版本）：
 * <ul>
 *   <li>条件命中/不命中：分析人员只见本部门客户，管理员见全部，过滤与字段剥离/脱敏叠加；</li>
 *   <li>条件依赖字段缺失 / 同批结构不一致：整单拒绝，空记录，原因码可区分；</li>
 *   <li>策略更新后同一 requestId 重试/重复提交：复现首次结果（放行或拒绝），审计不重不漏。</li>
 * </ul>
 * 在服 v1（未启用记录级）的兼容性回归见 {@link ServingPolicyCompatibilityTest}。
 */
class RecordLevelAccessGatewayTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordLevelAccessGatewayTest.class);

    private static final String CUSTOMER = InMemoryDataSource.RESOURCE_TYPE;

    /** 指定版本号的“启用记录级过滤”策略：与在服 v1 字段级一致，ANALYST 叠加本部门过滤。 */
    private static PolicyDefinition recordLevelPolicy(String version) {
        return new PolicyDefinition(version, List.of(
                BootstrapPolicyInitializer.adminRule(),
                BootstrapPolicyInitializer.analystRuleWithRecordVisibility(),
                BootstrapPolicyInitializer.guestRule()));
    }

    private AccessRequest analystRequest(String requestId, String department) {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("role", "ANALYST");
        if (department != null) {
            attrs.put("department", department);
        }
        return new AccessRequest(requestId,
                new SubjectAttributes("u-analyst", attrs),
                new ResourceRef(CUSTOMER, "*", Map.of()), AccessAction.READ);
    }

    private AccessRequest adminRequest(String requestId) {
        return new AccessRequest(requestId,
                new SubjectAttributes("u-admin", Map.of("role", "ADMIN")),
                new ResourceRef(CUSTOMER, "*", Map.of()), AccessAction.READ);
    }

    // ---- 1. 条件命中/不命中 + 与字段级叠加 ----

    @Test
    void analystSeesOnlyOwnDepartmentRecordsWithFieldControlsApplied() {
        PolicyStore store = new PolicyStore();
        store.publish(recordLevelPolicy("v1"), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), new ResponseReplayStore());

        // ENGINEERING 部门：数据源 3 条中仅 C001 属于 ENGINEERING
        AccessResult result = gateway.execute(analystRequest("req-rec-1", "ENGINEERING"));
        log.info("record-level test: input=ANALYST department=ENGINEERING, policyVersion=v1, "
                + "basis='record.department==subject.department 过滤 + nationalId/salary 剥离 + phone/email 哈希', "
                + "recordCount={}", result.records().size());

        assertTrue(result.allowed());
        assertEquals("v1", result.policyVersion());
        assertEquals(1, result.records().size(), "只应看到本部门 1 条记录");
        Map<String, Object> row = result.records().get(0);
        assertEquals("C001", row.get("id"));
        // 记录级过滤与字段级叠加：越权字段依然剥离
        assertFalse(row.containsKey("nationalId"));
        assertFalse(row.containsKey("salary"));
        assertEquals(64, ((String) row.get("phone")).length());
        assertEquals(64, ((String) row.get("email")).length());

        // FINANCE 部门：只见 C002
        AccessResult finance = gateway.execute(analystRequest("req-rec-2", "FINANCE"));
        assertEquals(1, finance.records().size());
        assertEquals("C002", finance.records().get(0).get("id"));

        // 不存在的部门：零条（而不是掏空记录），请求整体仍允许
        AccessResult none = gateway.execute(analystRequest("req-rec-3", "NO_SUCH_DEPT"));
        assertTrue(none.allowed());
        assertEquals(0, none.records().size());

        AuditRecord a1 = audit.findByRequestId("req-rec-1").orElseThrow();
        assertEquals("v1", a1.policyVersion());
        assertTrue(a1.allowed());
    }

    @Test
    void adminWithoutRecordConditionSeesAllRecords() {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), new ResponseReplayStore());

        AccessResult result = gateway.execute(adminRequest("req-rec-admin"));
        log.info("record-level test: input=ADMIN, policyVersion=v1, "
                + "basis='管理员规则无记录级条件，见全部 3 条', recordCount={}",
                result.records().size());

        assertEquals(3, result.records().size());
        assertTrue(result.records().stream().anyMatch(r -> "C001".equals(r.get("id"))));
        assertTrue(result.records().stream().anyMatch(r -> "C003".equals(r.get("id"))));
    }

    // ---- 2. 失败关闭与可区分原因 ----

    private Map<String, Object> customerRow(String id, String department) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("name", "Name " + id);
        row.put("department", department);
        row.put("phone", "13800000000");
        row.put("email", id + "@example.com");
        row.put("nationalId", "110101199001011234");
        row.put("salary", 1000);
        return row;
    }

    private PolicyRule analystRuleWith(RecordVisibilityCondition condition) {
        return new PolicyRule("r-analyst", Map.of("role", "ANALYST"),
                CUSTOMER, AccessAction.READ,
                List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("name", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("phone", true, MaskingType.HASH, Map.of()),
                        new FieldPolicy("email", true, MaskingType.HASH, Map.of()),
                        new FieldPolicy("nationalId", false, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", false, MaskingType.NONE, Map.of())),
                false, condition, true);
    }

    private DataAccessGateway gatewayWith(PolicyStore store, MutableDataSource source,
                                          AuditService audit, ResponseReplayStore replay) {
        return new DataAccessGateway(store, new PolicyEvaluator(),
                new RecordVisibilityEvaluator(), new Masker(), audit,
                List.of(source), replay);
    }

    @Test
    void missingConditionFieldFailsClosedWholeBatchWithDistinctReason() {
        MutableDataSource source = new MutableDataSource(CUSTOMER);
        // 记录里没有 region 字段
        source.setData(List.of(customerRow("C001", "ENGINEERING")));
        PolicyStore store = new PolicyStore();
        store.publish(new PolicyDefinition("v1", List.of(analystRuleWith(
                new RecordVisibilityCondition(List.of(
                        new RecordConditionTerm("region", ConditionOperator.EQ,
                                "EAST", null)))))), null);
        AuditService audit = new AuditService();
        ResponseReplayStore replay = new ResponseReplayStore();
        DataAccessGateway gateway = gatewayWith(store, source, audit, replay);

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("req-rec-missing", "ENGINEERING")));
        log.info("record-level test: input=条件引用 region 但记录无该字段, policyVersion=v1, "
                + "basis='依赖字段缺失整单拒绝，零记录', denyReason={}", ex.reason());

        assertEquals(DenyReason.RECORD_CONDITION_UNEVALUABLE, ex.reason());
        assertEquals("v1", ex.policyVersion());
        AuditRecord a = audit.findByRequestId("req-rec-missing").orElseThrow();
        assertFalse(a.allowed());
        assertEquals(DenyReason.RECORD_CONDITION_UNEVALUABLE, a.denyReason());
        // 必须能与“策略不匹配”“字段越权”区分
        assertNotEquals(DenyReason.POLICY_NO_MATCH, ex.reason());
        assertNotEquals(DenyReason.FIELD_FORBIDDEN, ex.reason());
    }

    @Test
    void inconsistentBatchStructureFailsClosedWithNoPartialRecords() {
        MutableDataSource source = new MutableDataSource(CUSTOMER);
        // 第二条记录缺少 phone 字段：并集字段仍被规则覆盖（字段级判定通过），
        // 但两条记录结构不一致，必须由记录级判定兜底整单拒绝
        Map<String, Object> missingField = customerRow("C002", "ENGINEERING");
        missingField.remove("phone");
        source.setData(List.of(customerRow("C001", "ENGINEERING"), missingField));
        PolicyStore store = new PolicyStore();
        store.publish(new PolicyDefinition("v1", List.of(analystRuleWith(
                BootstrapPolicyInitializer.analystOwnDepartmentCondition()))), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = gatewayWith(store, source, audit,
                new ResponseReplayStore());

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("req-rec-inconsistent", "ENGINEERING")));
        log.info("record-level test: input=同批 2 条记录字段集合不一致, policyVersion=v1, "
                + "basis='结构不一致整单拒绝，不返回任何一条（含本来能算的 C001）', denyReason={}",
                ex.reason());

        assertEquals(DenyReason.RECORD_CONDITION_UNEVALUABLE, ex.reason());
        assertEquals(1, audit.all().size());
    }

    @Test
    void missingSubjectAttributeIsRecordUnevaluableNotNoMatch() {
        PolicyStore store = new PolicyStore();
        store.publish(recordLevelPolicy("v1"), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), new ResponseReplayStore());

        // 角色命中 r-analyst-read，但主体缺少 department 属性：条件无法求值
        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("req-rec-noattr", null)));
        log.info("record-level test: input=ANALYST 无 department 属性, policyVersion=v1, "
                + "basis='规则命中但记录条件右值缺失 -> RECORD_CONDITION_UNEVALUABLE（区别于 POLICY_NO_MATCH）', "
                + "denyReason={}", ex.reason());

        assertEquals(DenyReason.RECORD_CONDITION_UNEVALUABLE, ex.reason());
        AuditRecord a = audit.findByRequestId("req-rec-noattr").orElseThrow();
        assertEquals("r-analyst-read", a.matchedRuleId(), "规则确实命中");
    }

    // ---- 3. 更新后重复提交复现首次结果 ----

    @Test
    void replayAfterPolicyUpdateReproducesFirstVisibleRecords() {
        PolicyStore store = new PolicyStore();
        store.publish(recordLevelPolicy("v1"), null);
        AuditService audit = new AuditService();
        ResponseReplayStore replay = new ResponseReplayStore();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), replay);

        // 首次：v1 下 ANALYST 只见本部门 1 条
        AccessResult first = gateway.execute(analystRequest("req-replay-1", "ENGINEERING"));
        assertEquals("v1", first.policyVersion());
        assertEquals(1, first.records().size());

        // 运行中发布 v2：ANALYST 规则去掉记录级条件（见全部）并调整脱敏
        PolicyRule analystV2 = new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"), CUSTOMER, AccessAction.READ,
                List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("name", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("phone", true, MaskingType.FULL_MASK, Map.of()),
                        new FieldPolicy("email", true, MaskingType.FULL_MASK, Map.of()),
                        new FieldPolicy("nationalId", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", true, MaskingType.NONE, Map.of())),
                false, null);
        store.publish(new PolicyDefinition("v2",
                List.of(BootstrapPolicyInitializer.adminRule(), analystV2,
                        BootstrapPolicyInitializer.guestRule())), "v1");

        // 用同一 requestId 重试：必须复现首次（v1、1 条、哈希脱敏、字段剥离）
        AccessResult retried = gateway.execute(analystRequest("req-replay-1", "ENGINEERING"));
        log.info("record-level test: input=req-replay-1 策略 v1->v2 后同标识重试, "
                + "basis='重放首次：v1/1 条/哈希/剥离，而非 v2 的 3 条/全掩码', "
                + "first(v={},n={}) retry(v={},n={})",
                first.policyVersion(), first.records().size(),
                retried.policyVersion(), retried.records().size());

        assertEquals(first.policyVersion(), retried.policyVersion());
        assertEquals(first.records().size(), retried.records().size());
        assertEquals(1, retried.records().size());
        assertEquals("C001", retried.records().get(0).get("id"));
        assertEquals(64, ((String) retried.records().get(0).get("phone")).length(),
                "必须复现首次的哈希脱敏，而不是 v2 的 FULL_MASK");
        assertFalse(retried.records().get(0).containsKey("nationalId"),
                "必须复现首次的字段剥离结果");
        long auditCount = audit.all().stream()
                .filter(a -> a.requestId().equals("req-replay-1")).count();
        assertEquals(1, auditCount, "重放不得重复审计");
    }

    @Test
    void replayAfterPolicyUpdateReproducesFirstDenyReason() {
        PolicyStore store = new PolicyStore();
        store.publish(recordLevelPolicy("v1"), null);
        AuditService audit = new AuditService();
        ResponseReplayStore replay = new ResponseReplayStore();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), replay);

        // 首次：缺 department 属性 -> v1 下 RECORD_CONDITION_UNEVALUABLE 拒绝
        AccessDeniedException first = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("req-replay-deny", null)));
        assertEquals("v1", first.policyVersion());
        assertEquals(DenyReason.RECORD_CONDITION_UNEVALUABLE, first.reason());

        // 发布 v2：ANALYST 规则不再需要 department（无记录级条件）
        PolicyRule analystV2 = new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"), CUSTOMER, AccessAction.READ,
                List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("name", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("phone", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("email", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("nationalId", false, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", false, MaskingType.NONE, Map.of())),
                false, null);
        store.publish(new PolicyDefinition("v2",
                List.of(BootstrapPolicyInitializer.adminRule(), analystV2,
                        BootstrapPolicyInitializer.guestRule())), "v1");

        // 同标识重试：仍复现首次拒绝（v1 + 同样原因），而不是按 v2 放行
        AccessDeniedException retried = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(analystRequest("req-replay-deny", null)));
        log.info("record-level test: input=req-replay-deny v1->v2 后同标识重试, "
                + "basis='重放首次拒绝原因与版本', first(v={},r={}) retry(v={},r={})",
                first.policyVersion(), first.reason(),
                retried.policyVersion(), retried.reason());

        assertEquals(first.policyVersion(), retried.policyVersion());
        assertEquals(first.reason(), retried.reason());
        long auditCount = audit.all().stream()
                .filter(a -> a.requestId().equals("req-replay-deny")).count();
        assertEquals(1, auditCount, "拒绝重放也不得重复/缺失审计");
    }
}
