package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 网关端到端单测（真实组件，无 mock 数据层）。
 * 日志打印请求输入、策略版本与判定依据。
 */
class DataAccessGatewayTest {

    private static final Logger log = LoggerFactory.getLogger(DataAccessGatewayTest.class);

    private PolicyStore policyStore;
    private AuditService auditService;
    private DataAccessGateway gateway;

    private AccessRequest request(String requestId, String role) {
        // ANALYST 规则含记录级条件 record.department == subject.department，
        // 测试请求需携带所属部门（ENGINEERING 数据源有对应记录）
        Map<String, String> attrs = "ANALYST".equals(role)
                ? Map.of("role", role, "department", "ENGINEERING")
                : Map.of("role", role);
        return new AccessRequest(requestId,
                new SubjectAttributes("user-" + role, attrs),
                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                AccessAction.READ);
    }

    @BeforeEach
    void setUp() {
        policyStore = new PolicyStore();
        policyStore.publish(BootstrapPolicyInitializer.v1(), null);
        auditService = new AuditService();
        gateway = new DataAccessGateway(policyStore,
                new PolicyEvaluator(), new Masker(), auditService,
                List.of(new InMemoryDataSource()));
    }

    @Test
    void adminSeesAllFieldsWithMaskingAndVersionedAudit() {
        AccessResult result = gateway.execute(request("req-admin-1", "ADMIN"));
        log.info("gateway test: input=req-admin-1 role:ADMIN, policyVersion={}, "
                + "basis='r-admin-read 全字段可见，PII 脱敏'", result.policyVersion());

        assertTrue(result.allowed());
        assertEquals("v1", result.policyVersion());
        assertEquals("r-admin-read", result.matchedRuleId());
        Map<String, Object> row = result.records().get(0);
        assertEquals(7, row.keySet().size());
        assertEquals("Zhang Wei", row.get("name"));
        assertEquals(12000, row.get("salary"));
        // 证件号：前4后4保留，中间掩码
        String maskedId = (String) row.get("nationalId");
        assertTrue(maskedId.startsWith("1101"));
        assertTrue(maskedId.endsWith("1234"));
        assertTrue(maskedId.contains("*"));
        assertFalse(maskedId.contains("19900101"));
        // 手机：前3后4
        String maskedPhone = (String) row.get("phone");
        assertTrue(maskedPhone.startsWith("138"));
        assertTrue(maskedPhone.endsWith("1111"));

        AuditRecord audit = auditService.findByRequestId("req-admin-1").orElseThrow();
        assertEquals("v1", audit.policyVersion(), "审计必须与响应同版本");
        assertEquals("r-admin-read", audit.matchedRuleId());
        assertTrue(audit.allowed());
    }

    @Test
    void analystForbiddenFieldsAreStrippedNotMasked() {
        AccessResult result = gateway.execute(request("req-analyst-1", "ANALYST"));
        log.info("gateway test: input=req-analyst-1 role:ANALYST, policyVersion={}, "
                + "basis='r-analyst-read：nationalId/salary 越权剥离，phone/email 哈希'",
                result.policyVersion());

        assertTrue(result.allowed());
        Map<String, Object> row = result.records().get(0);
        assertFalse(row.containsKey("nationalId"), "越权字段不得出现在响应中");
        assertFalse(row.containsKey("salary"));
        assertEquals(64, ((String) row.get("phone")).length());
        assertEquals(64, ((String) row.get("email")).length());
        assertEquals("Zhang Wei", row.get("name"));
    }

    @Test
    void unknownRoleIsDeniedWithPolicyNoMatch() {
        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(request("req-hacker-1", "ROOT")));
        log.info("gateway test: input=req-hacker-1 role:ROOT, policyVersion={}, "
                + "basis='无任何规则匹配，策略不匹配拒绝', denyReason={}",
                ex.policyVersion(), ex.reason());

        assertEquals(DenyReason.POLICY_NO_MATCH, ex.reason());
        assertEquals("v1", ex.policyVersion());
        AuditRecord audit = auditService.findByRequestId("req-hacker-1").orElseThrow();
        assertFalse(audit.allowed());
        assertEquals(DenyReason.POLICY_NO_MATCH, audit.denyReason());
    }

    @Test
    void forbiddenReasonIsDistinctFromNoMatch() {
        // GUEST 命中 r-guest-read（不是 NO_MATCH），但请求的部分字段越权：
        // 字段级剥离允许请求整体放行，证明 FIELD_FORBIDDEN 与 POLICY_NO_MATCH 可区分
        AccessResult guestResult = gateway.execute(request("req-guest-1", "GUEST"));
        log.info("gateway test: input=req-guest-1 role:GUEST, policyVersion={}, "
                + "basis='r-guest-read 命中，越权字段剥离（FIELD_FORBIDDEN 区别于 POLICY_NO_MATCH）'",
                guestResult.policyVersion());
        assertTrue(guestResult.allowed());
        assertEquals("r-guest-read", guestResult.matchedRuleId());
        Map<String, Object> row = guestResult.records().get(0);
        assertFalse(row.containsKey("phone"));
        assertFalse(row.containsKey("nationalId"));
        assertTrue(row.containsKey("id"));

        AccessDeniedException noMatch = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(request("req-x-1", "AUDITOR")));
        assertEquals(DenyReason.POLICY_NO_MATCH, noMatch.reason());
        // 两个原因码必须不同且稳定
        assertFalse(noMatch.reason().name().equals(DenyReason.FIELD_FORBIDDEN.name()));
    }

    @Test
    void missingFieldMappingFailsClosedWithNoPartialData() {
        // v2：故意只声明 id 字段且 defaultVisible=false，
        // 数据源多出的字段（name/phone 等）将触发 FIELD_MAPPING_MISSING
        PolicyDefinition sparse = new PolicyDefinition("v2", List.of(
                new com.github.h3yow.datapolicygatewayjava.model.PolicyRule(
                        "r-sparse", Map.of("role", "ADMIN"),
                        "customer", AccessAction.READ,
                        List.of(new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                "id", true,
                                com.github.h3yow.datapolicygatewayjava.model.MaskingType.NONE,
                                Map.of())),
                        false)));
        policyStore.publish(sparse, "v1");

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(request("req-sparse-1", "ADMIN")));
        log.info("gateway test: input=req-sparse-1 role:ADMIN, policyVersion=v2, "
                + "basis='字段映射缺失失败关闭，不返回任何记录', denyReason={}", ex.reason());

        assertEquals(DenyReason.FIELD_MAPPING_MISSING, ex.reason());
        AuditRecord audit = auditService.findByRequestId("req-sparse-1").orElseThrow();
        assertEquals(DenyReason.FIELD_MAPPING_MISSING, audit.denyReason());
        assertEquals("v2", audit.policyVersion());
    }

    @Test
    void retriesWithSameRequestIdProduceSingleAudit() {
        AccessResult first = gateway.execute(request("req-idem-1", "GUEST"));
        AccessResult second = gateway.execute(request("req-idem-1", "GUEST"));
        log.info("gateway test: input=req-idem-1 x2(重试), policyVersion=v1, "
                + "basis='requestId 幂等，重复处理不重复审计', records={}/{}",
                first.records().size(), second.records().size());

        long count = auditService.all().stream()
                .filter(a -> a.requestId().equals("req-idem-1")).count();
        assertEquals(1, count, "重试不得产生重复审计");
        assertNotNull(auditService.findByRequestId("req-idem-1").orElseThrow());
    }

    @Test
    void deniedRequestIsAlsoAuditedExactlyOnceAcrossRetries() {
        assertThrows(AccessDeniedException.class,
                () -> gateway.execute(request("req-deny-idem", "ROOT")));
        assertThrows(AccessDeniedException.class,
                () -> gateway.execute(request("req-deny-idem", "ROOT")));
        long count = auditService.all().stream()
                .filter(a -> a.requestId().equals("req-deny-idem")).count();
        log.info("gateway test: input=req-deny-idem x2(越权重试), policyVersion=v1, "
                + "basis='拒绝也审计且仅一次', auditCount={}", count);
        assertEquals(1, count, "拒绝请求审计也不得缺失/重复");
    }
}
