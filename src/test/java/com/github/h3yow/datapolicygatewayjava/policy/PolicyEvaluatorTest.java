package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.config.DemoPolicyFactory;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.EvaluationResult;
import com.github.h3yow.datapolicygatewayjava.model.FieldEffect;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.Subject;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyEvaluatorTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyEvaluatorTest.class);

    private final PolicyEvaluator evaluator = new PolicyEvaluator();

    private AccessRequest request(String role, List<String> fields) {
        return new AccessRequest("req-" + role + "-" + fields.hashCode(),
                new Subject("u-1", Map.of("role", role)),
                new ResourceRef("customer", "c-1001"),
                AccessAction.READ, fields);
    }

    private void logDecision(AccessRequest req, EvaluationResult result) {
        log.info("policy-eval requestId={} subject={} resource={} action={} fields={} "
                        + "policyVersion={} allowed={} denyReason={} matchedRule={} basis={}",
                req.requestId(), req.subject().attributes(), req.resource().canonical(),
                req.action(), req.fields(), result.policyVersion(), result.allowed(),
                result.denyReason(), result.matchedRuleId(), result.basis());
    }

    @Test
    void adminGetsAllFieldsInClear() {
        AccessRequest req = request("admin",
                List.of("name", "email", "region", "ssn"));
        EvaluationResult result = evaluator.evaluate(req, new DemoPolicyFactory().version1());
        logDecision(req, result);
        assertTrue(result.allowed());
        assertEquals(1L, result.policyVersion());
        assertTrue(result.verdicts().stream()
                .allMatch(v -> v.effect() == FieldEffect.ALLOW));
    }

    @Test
    void analystGetsMaskedEmailAndNoSsnVerdict() {
        AccessRequest req = request("analyst", List.of("name", "email", "region"));
        EvaluationResult result = evaluator.evaluate(req, new DemoPolicyFactory().version1());
        logDecision(req, result);
        assertTrue(result.allowed());
        assertEquals(FieldEffect.MASK,
                result.verdicts().get(1).effect());
        assertEquals("email", result.verdicts().get(1).maskName());
    }

    @Test
    void analystRequestingSsnIsFieldUnauthorized() {
        AccessRequest req = request("analyst", List.of("ssn"));
        EvaluationResult result = evaluator.evaluate(req, new DemoPolicyFactory().version1());
        logDecision(req, result);
        assertFalse(result.allowed());
        assertEquals(DenyReason.FIELD_UNAUTHORIZED, result.denyReason());
        assertTrue(result.verdicts().isEmpty());
    }

    @Test
    void unknownRoleIsPolicyNotMatched() {
        AccessRequest req = request("guest", List.of("name"));
        EvaluationResult result = evaluator.evaluate(req, new DemoPolicyFactory().version1());
        logDecision(req, result);
        assertFalse(result.allowed());
        assertEquals(DenyReason.POLICY_NOT_MATCHED, result.denyReason());
    }

    @Test
    void writeActionIsPolicyNotMatched() {
        AccessRequest req = new AccessRequest("req-write",
                new Subject("u-2", Map.of("role", "admin")),
                new ResourceRef("customer", "c-1001"),
                AccessAction.WRITE, List.of("name"));
        EvaluationResult result = evaluator.evaluate(req, new DemoPolicyFactory().version1());
        logDecision(req, result);
        assertEquals(DenyReason.POLICY_NOT_MATCHED, result.denyReason());
    }
}
