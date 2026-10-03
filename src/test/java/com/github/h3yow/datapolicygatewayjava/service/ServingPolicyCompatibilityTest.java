package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.gateway.ResponseReplayStore;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.policy.RecordVisibilityEvaluator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 在服策略兼容性回归（本次 bugfix 的核心）：
 * <ul>
 *   <li>现网分析人员只带角色、不带部门的请求，在当前在服 v1 下必须保持原有返回
 *       （放行 + 字段级剥离/脱敏 + 全部记录），不得被记录级能力误伤；</li>
 *   <li>仅声明记录级条件但未显式启用（recordVisibilityEnabled=false）的规则，
 *       记录级过滤不生效；</li>
 *   <li>主动启用（opt-in）后同一请求才按记录级条件过滤/失败关闭。</li>
 * </ul>
 */
class ServingPolicyCompatibilityTest {

    private static final Logger log =
            LoggerFactory.getLogger(ServingPolicyCompatibilityTest.class);

    private static final String CUSTOMER = InMemoryDataSource.RESOURCE_TYPE;

    /** 现网分析人员的既有调用形态：只带 role，不带 department。 */
    private static AccessRequest legacyAnalystRequest(String requestId) {
        return new AccessRequest(requestId,
                new SubjectAttributes("u-analyst", Map.of("role", "ANALYST")),
                new ResourceRef(CUSTOMER, "*", Map.of()), AccessAction.READ);
    }

    private static DataAccessGateway gateway(PolicyStore store, AuditService audit,
                                             ResponseReplayStore replay) {
        return new DataAccessGateway(store, new PolicyEvaluator(),
                new RecordVisibilityEvaluator(), new Masker(), audit,
                List.of(new InMemoryDataSource()), replay);
    }

    @Test
    void roleOnlyAnalystKeepsOriginalResultUnderServingV1() {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        ResponseReplayStore replay = new ResponseReplayStore();
        DataAccessGateway gateway = gateway(store, audit, replay);

        AccessResult result = gateway.execute(legacyAnalystRequest("req-legacy-1"));
        log.info("serving-compat test: input=ANALYST 仅 role 无 department, policyVersion=v1, "
                + "basis='在服策略未启用记录级 -> 保持原有返回：放行/3 条/字段级剥离+哈希', "
                + "recordCount={}", result.records().size());

        assertTrue(result.allowed(), "原本能成功的请求必须继续放行");
        assertEquals("v1", result.policyVersion());
        assertEquals("r-analyst-read", result.matchedRuleId());
        assertEquals(3, result.records().size(), "未启用记录级过滤：全部记录原样返回");
        Map<String, Object> row = result.records().get(0);
        // 字段级行为与记录级能力引入前完全一致
        assertFalse(row.containsKey("nationalId"), "越权字段仍被剥离");
        assertFalse(row.containsKey("salary"));
        assertEquals(64, ((String) row.get("phone")).length(), "手机仍为哈希");
        assertEquals(64, ((String) row.get("email")).length());

        AuditRecord a = audit.findByRequestId("req-legacy-1").orElseThrow();
        assertTrue(a.allowed());
        assertEquals("v1", a.policyVersion());

        // 同标识重试：复现首次结果，审计不重复
        AccessResult retried = gateway.execute(legacyAnalystRequest("req-legacy-1"));
        assertEquals(3, retried.records().size());
        assertEquals(1, audit.all().stream()
                .filter(r -> r.requestId().equals("req-legacy-1")).count());
    }

    @Test
    void analystWithDepartmentAlsoUnfilteredUnderServingV1() {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = gateway(store, audit, new ResponseReplayStore());

        AccessRequest withDept = new AccessRequest("req-legacy-2",
                new SubjectAttributes("u-analyst",
                        Map.of("role", "ANALYST", "department", "ENGINEERING")),
                new ResourceRef(CUSTOMER, "*", Map.of()), AccessAction.READ);
        AccessResult result = gateway.execute(withDept);
        log.info("serving-compat test: input=ANALYST department=ENGINEERING, policyVersion=v1, "
                + "basis='在服 v1 不启用记录级：即使带了 department 也不做过滤', recordCount={}",
                result.records().size());

        assertTrue(result.allowed());
        assertEquals(3, result.records().size(),
                "在服 v1 下记录级未启用，带不带部门都返回全部记录");
    }

    @Test
    void declaredButNotEnabledConditionDoesNotFilter() {
        // 规则声明了记录级条件但未显式启用（7 参构造器）：过滤不得生效
        PolicyRule declaredOnly = new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"), CUSTOMER, AccessAction.READ,
                List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("name", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("phone", true, MaskingType.HASH, Map.of()),
                        new FieldPolicy("email", true, MaskingType.HASH, Map.of()),
                        new FieldPolicy("nationalId", false, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", false, MaskingType.NONE, Map.of())),
                false, BootstrapPolicyInitializer.analystOwnDepartmentCondition());
        PolicyStore store = new PolicyStore();
        store.publish(new PolicyDefinition("v1", List.of(
                BootstrapPolicyInitializer.adminRule(), declaredOnly,
                BootstrapPolicyInitializer.guestRule())), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = gateway(store, audit, new ResponseReplayStore());

        AccessResult result = gateway.execute(legacyAnalystRequest("req-legacy-3"));
        log.info("serving-compat test: input=规则仅声明条件未启用, policyVersion=v1, "
                + "basis='presence != enablement：未启用不过滤、不失败关闭', recordCount={}",
                result.records().size());

        assertTrue(result.allowed());
        assertEquals(3, result.records().size(), "仅声明条件不启用：不做记录级过滤");
    }

    @Test
    void optInV2EnablesRecordLevelForSameRequest() {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = gateway(store, audit, new ResponseReplayStore());

        // 在服 v1：只带角色的既有请求放行 3 条
        AccessResult before = gateway.execute(legacyAnalystRequest("req-legacy-4a"));
        assertEquals(3, before.records().size());

        // 团队按自己的节奏发布 v2 主动启用记录级
        store.publish(BootstrapPolicyInitializer.v2(), "v1");

        // 启用后：带部门的请求按本部门过滤
        AccessRequest withDept = new AccessRequest("req-legacy-4b",
                new SubjectAttributes("u-analyst",
                        Map.of("role", "ANALYST", "department", "ENGINEERING")),
                new ResourceRef(CUSTOMER, "*", Map.of()), AccessAction.READ);
        AccessResult filtered = gateway.execute(withDept);
        log.info("serving-compat test: input=v1->v2 启用后 ANALYST/ENGINEERING, "
                + "basis='opt-in 后记录级生效：只见本部门 1 条', recordCount={}",
                filtered.records().size());
        assertEquals("v2", filtered.policyVersion());
        assertEquals(1, filtered.records().size());
        assertEquals("C001", filtered.records().get(0).get("id"));

        // 同标识重试 v1 时代的请求：仍复现首次（v1、3 条），不受 v2 影响
        AccessResult replayed = gateway.execute(legacyAnalystRequest("req-legacy-4a"));
        assertEquals("v1", replayed.policyVersion());
        assertEquals(3, replayed.records().size());
    }
}
