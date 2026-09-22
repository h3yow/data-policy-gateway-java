package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.DataSource;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 失败关闭行为测试：
 * <ul>
 *   <li>v1 策略对 ADMIN 的 phone 配置了非法 PARTIAL_MASK 参数 → 脱敏异常 → 整单 MASKING_FAILED；</li>
 *   <li>异常不携带字段值；</li>
 *   <li>拒绝仍写且只写一条审计。</li>
 * </ul>
 */
class FailClosedTest {

    private static final Logger log = LoggerFactory.getLogger(FailClosedTest.class);

    private AccessRequest adminRequest(String id) {
        return new AccessRequest(id,
                new SubjectAttributes("u-admin", Map.of("role", "ADMIN")),
                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                AccessAction.READ);
    }

    @Test
    void maskingFailureClosesWholeRequestWithAudit() {
        PolicyStore store = new PolicyStore();
        // v1: 正常初始化
        store.publish(BootstrapPolicyInitializer.v1(), null);
        // v2: phone 使用保留范围过大的脱敏参数，运行中必然触发 MaskingException
        com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition v2 =
                new com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition("v2", List.of(
                        new com.github.h3yow.datapolicygatewayjava.model.PolicyRule(
                                "r-broken-mask", Map.of("role", "ADMIN"), "customer",
                                AccessAction.READ,
                                List.of(
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "id", true, MaskingType.NONE, Map.of()),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "name", true, MaskingType.NONE, Map.of()),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "department", true, MaskingType.NONE, Map.of()),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "phone", true, MaskingType.PARTIAL_MASK,
                                                Map.of("prefix", "99", "suffix", "99")),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "email", true, MaskingType.NONE, Map.of()),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "nationalId", true, MaskingType.NONE, Map.of()),
                                        new com.github.h3yow.datapolicygatewayjava.model.FieldPolicy(
                                                "salary", true, MaskingType.NONE, Map.of())),
                                false)));
        store.publish(v2, "v1");

        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store, new PolicyEvaluator(),
                new Masker(), audit, List.of(new InMemoryDataSource()));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(adminRequest("req-mask-fail")));
        log.info("fail-closed test: input=req-mask-fail role:ADMIN policyVersion=v2, "
                + "basis='phone 脱敏参数非法 -> 整单失败关闭，不返回部分数据', denyReason={}",
                ex.reason());

        assertEquals(DenyReason.MASKING_FAILED, ex.reason());
        assertEquals("v2", ex.policyVersion());
        // 异常消息不得包含任何真实手机号片段
        assertFalse(ex.getMessage() != null && ex.getMessage().contains("1380000"));
        // 审计存在、拒绝、原因一致
        var record = audit.findByRequestId("req-mask-fail").orElseThrow();
        assertFalse(record.allowed());
        assertEquals(DenyReason.MASKING_FAILED, record.denyReason());
        assertEquals("v2", record.policyVersion());
    }

    @Test
    void noPolicyLoadedFailsClosed() {
        PolicyStore empty = new PolicyStore();
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(empty, new PolicyEvaluator(),
                new Masker(), audit, List.of(new InMemoryDataSource()));

        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(adminRequest("req-no-policy")));
        log.info("fail-closed test: input=req-no-policy, policyVersion=null, "
                + "basis='无策略可用失败关闭', denyReason={}", ex.reason());
        assertEquals(DenyReason.EVALUATION_FAILED, ex.reason());
        assertTrue(audit.findByRequestId("req-no-policy").isPresent());
    }

    @Test
    void unsupportedResourceFailsClosedWithoutLeak() {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store, new PolicyEvaluator(),
                new Masker(), audit, List.of(new InMemoryDataSource()));

        AccessRequest req = new AccessRequest("req-bad-resource",
                new SubjectAttributes("u-admin", Map.of("role", "ADMIN")),
                new ResourceRef("secret_table", "*", Map.of()),
                AccessAction.READ);
        AccessDeniedException ex = assertThrows(AccessDeniedException.class,
                () -> gateway.execute(req));
        log.info("fail-closed test: input=req-bad-resource resource:secret_table, "
                + "basis='无数据源失败关闭', denyReason={}", ex.reason());
        assertEquals(DenyReason.EVALUATION_FAILED, ex.reason());
    }
}
