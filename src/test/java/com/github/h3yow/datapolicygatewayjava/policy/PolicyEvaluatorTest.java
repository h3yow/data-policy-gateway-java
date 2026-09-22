package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessDecision;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldDecision;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 求值器单测：验证拒绝原因可区分、稳定。日志打印请求输入、策略版本与判定依据。
 */
class PolicyEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyEvaluatorTest.class);

    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    private SubjectAttributes subject(String role) {
        return new SubjectAttributes("user-1", Map.of("role", role));
    }

    private ResourceRef resource() {
        return new ResourceRef("customer", "C001", Map.of());
    }

    private PolicySnapshot snapshot(String version, List<PolicyRule> rules) {
        return new PolicySnapshot(new PolicyDefinition(version, rules));
    }

    private PolicyRule simpleRule(String ruleId, String role, List<FieldPolicy> fields,
                                  boolean defaultVisible) {
        return new PolicyRule(ruleId, Map.of("role", role), "customer",
                AccessAction.READ, fields, defaultVisible);
    }

    @Test
    void noMatchingRuleGivesPolicyNoMatch() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r1", "ADMIN", List.of(), false)));
        AccessDecision d = evaluator.evaluate(subject("GUEST"), resource(),
                AccessAction.READ, Set.of("id", "name"), snap);
        log.info("evaluate test: input=role:GUEST resource:customer action:READ fields=[id,name], "
                + "policyVersion=v1, basis='无规则匹配', denyReason={}", d.denyReason());

        assertEquals(DenyReason.POLICY_NO_MATCH, d.denyReason());
        assertNull(d.matchedRuleId());
        assertFalse(d.allowed());
        for (FieldDecision fd : d.fields().values()) {
            assertEquals(DenyReason.POLICY_NO_MATCH, fd.denyReason());
        }
    }

    @Test
    void explicitForbiddenFieldIsDistinguishable() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r1", "ANALYST", List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", false, MaskingType.NONE, Map.of())),
                        false)));
        AccessDecision d = evaluator.evaluate(subject("ANALYST"), resource(),
                AccessAction.READ, Set.of("id", "salary"), snap);
        log.info("evaluate test: input=role:ANALYST fields=[id,salary], policyVersion=v1, "
                + "basis='命中 r1，salary 显式拒绝（越权）', overallAllow={}, fieldReason={}",
                d.allowed(), d.fields().get("salary").denyReason());

        assertTrue(d.allowed(), "字段级越权仅剥离字段，不整体拒绝");
        assertTrue(d.fields().get("id").allowed());
        FieldDecision salary = d.fields().get("salary");
        assertFalse(salary.allowed());
        assertEquals(DenyReason.FIELD_FORBIDDEN, salary.denyReason());
    }

    @Test
    void missingFieldMappingFailsClosed() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r1", "ADMIN", List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of())), false)));
        AccessDecision d = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.READ, Set.of("id", "nationalId"), snap);
        log.info("evaluate test: input=role:ADMIN fields=[id,nationalId], policyVersion=v1, "
                + "basis='nationalId 无映射且 defaultVisible=false，失败关闭', denyReason={}",
                d.denyReason());

        assertEquals(DenyReason.FIELD_MAPPING_MISSING, d.denyReason());
        assertFalse(d.allowed());
        assertEquals(DenyReason.FIELD_MAPPING_MISSING,
                d.fields().get("nationalId").denyReason());
    }

    @Test
    void defaultVisibleExplicitlyAllowsUnmappedFields() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r1", "ADMIN", List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of())), true)));
        AccessDecision d = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.READ, Set.of("id", "name"), snap);
        log.info("evaluate test: input=role:ADMIN fields=[id,name], policyVersion=v1, "
                + "basis='defaultVisible=true 显式兜底放行', allow={}", d.allowed());

        assertTrue(d.allowed());
        assertTrue(d.fields().get("name").allowed());
        assertFalse(d.fields().get("name").masked());
    }

    @Test
    void visibleFieldRecordsMaskingDecision() {
        PolicySnapshot snap = snapshot("v2", List.of(
                simpleRule("r1", "ADMIN", List.of(
                        new FieldPolicy("phone", true, MaskingType.HASH, Map.of())), false)));
        AccessDecision d = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.READ, Set.of("phone"), snap);
        log.info("evaluate test: input=role:ADMIN field=phone, policyVersion=v2, "
                + "basis='可见且需 HASH 脱敏', masked={}, type={}",
                d.fields().get("phone").masked(), d.fields().get("phone").maskingType());

        assertTrue(d.allowed());
        assertTrue(d.fields().get("phone").masked());
        assertEquals(MaskingType.HASH, d.fields().get("phone").maskingType());
    }

    @Test
    void actionAndResourceMustBothMatch() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r1", "ADMIN", List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of())), false)));
        AccessDecision writeDecision = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.WRITE, Set.of("id"), snap);
        log.info("evaluate test: input=role:ADMIN action:WRITE, policyVersion=v1, "
                + "basis='动作不匹配', denyReason={}", writeDecision.denyReason());
        assertEquals(DenyReason.POLICY_NO_MATCH, writeDecision.denyReason());

        ResourceRef order = new ResourceRef("order", "O1", Map.of());
        AccessDecision otherResource = evaluator.evaluate(subject("ADMIN"), order,
                AccessAction.READ, Set.of("id"), snap);
        log.info("evaluate test: input=role:ADMIN resource:order, policyVersion=v1, "
                + "basis='资源不匹配', denyReason={}", otherResource.denyReason());
        assertEquals(DenyReason.POLICY_NO_MATCH, otherResource.denyReason());
    }

    @Test
    void firstMatchingRuleWinsAndResultIsStable() {
        PolicySnapshot snap = snapshot("v1", List.of(
                simpleRule("r-first", "ADMIN", List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of())), false),
                simpleRule("r-second", "ADMIN", List.of(
                        new FieldPolicy("id", false, MaskingType.NONE, Map.of())), false)));
        AccessDecision d1 = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.READ, Set.of("id"), snap);
        AccessDecision d2 = evaluator.evaluate(subject("ADMIN"), resource(),
                AccessAction.READ, Set.of("id"), snap);
        log.info("evaluate test: input=role:ADMIN two matching rules, policyVersion=v1, "
                + "basis='按声明顺序首条命中，求值可复现', matched={}/{}",
                d1.matchedRuleId(), d2.matchedRuleId());
        assertEquals("r-first", d1.matchedRuleId());
        assertEquals(d1.matchedRuleId(), d2.matchedRuleId());
        assertEquals(d1.fields().get("id").allowed(), d2.fields().get("id").allowed());
    }
}
