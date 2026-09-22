package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.EvaluationResult;
import com.github.h3yow.datapolicygatewayjava.model.FieldEffect;
import com.github.h3yow.datapolicygatewayjava.model.FieldRule;
import com.github.h3yow.datapolicygatewayjava.model.FieldVerdict;
import com.github.h3yow.datapolicygatewayjava.model.Policy;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.Subject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Pure, side-effect-free policy evaluation against one immutable
 * {@link Policy} snapshot.
 *
 * <p>Matching order: rules are already sorted by descending priority; the
 * first rule whose resource type, action and required subject attributes
 * all match wins for the whole request. Within the winning rule, each
 * requested field is mapped to its {@link FieldRule}; fields absent from
 * the rule are denied by default (fail-closed default-deny).
 *
 * <p>Every unexpected condition is converted into a denied
 * {@link EvaluationResult} ({@link DenyReason#EVALUATION_FAILED}) rather
 * than thrown, so an evaluator bug can never leak data.
 */
public class PolicyEvaluator {

    public PolicyEvaluator() {
    }

    public EvaluationResult evaluate(AccessRequest request, Policy policy) {
        long version = policy == null ? -1L : policy.version();
        try {
            return doEvaluate(request, policy);
        } catch (RuntimeException ex) {
            // Deliberately do not include ex.getMessage(): it may reference
            // request payload contents. The basis only carries coordinates.
            String basis = "evaluation-error action=" + request.action()
                    + " resourceType=" + request.resource().type();
            return EvaluationResult.deny(version, DenyReason.EVALUATION_FAILED, basis);
        }
    }

    private EvaluationResult doEvaluate(AccessRequest request, Policy policy) {
        long version = policy.version();
        List<PolicyRule> rules = policy.rules();

        PolicyRule matched = null;
        int matchedIndex = -1;
        for (int i = 0; i < rules.size(); i++) {
            PolicyRule rule = rules.get(i);
            if (matches(rule, request)) {
                matched = rule;
                matchedIndex = i;
                break;
            }
        }

        if (matched == null) {
            String basis = "no-rule-matched resourceType=" + request.resource().type()
                    + " action=" + request.action();
            return EvaluationResult.deny(version, DenyReason.POLICY_NOT_MATCHED, basis);
        }

        String ruleId = "rule[priority=" + matched.priority() + ",index=" + matchedIndex + "]";

        Map<String, FieldRule> fieldRules = new HashMap<>();
        for (FieldRule fr : matched.fields()) {
            fieldRules.put(fr.field(), fr);
        }

        List<FieldVerdict> verdicts = new ArrayList<>();
        for (String requestedField : request.fields()) {
            FieldRule fr = fieldRules.get(requestedField);
            if (fr == null || fr.effect() == FieldEffect.DENY) {
                // Default-deny + explicit deny. The denied field NAME is not
                // propagated into the denial basis.
                String basis = "field-unauthorized under " + ruleId
                        + " deniedCount includes this request";
                return EvaluationResult.deny(version,
                        DenyReason.FIELD_UNAUTHORIZED, basis);
            }
            String verdictReason = ruleId + " effect=" + fr.effect()
                    + (fr.effect() == FieldEffect.MASK ? " mask=" + fr.maskName() : "");
            verdicts.add(new FieldVerdict(requestedField, fr.effect(),
                    fr.effect() == FieldEffect.MASK ? fr.maskName() : null,
                    verdictReason));
        }

        String basis = "matched " + ruleId
                + " resourceType=" + matched.matchResource()
                + " action=" + (matched.matchAction() == null ? "*" : matched.matchAction())
                + " requiredAttributes=" + matched.matchAttributes().keySet()
                + " fieldCount=" + verdicts.size();
        return EvaluationResult.allow(version, verdicts, ruleId, basis);
    }

    private boolean matches(PolicyRule rule, AccessRequest request) {
        if (!"*".equals(rule.matchResource())
                && !rule.matchResource().equals(request.resource().type())) {
            return false;
        }
        AccessAction wanted = rule.matchAction();
        if (wanted != null && wanted != request.action()) {
            return false;
        }
        Subject subject = request.subject();
        for (Map.Entry<String, String> required : rule.matchAttributes().entrySet()) {
            String actual = subject.attribute(required.getKey());
            if (actual == null || !actual.equals(required.getValue())) {
                return false;
            }
        }
        return true;
    }
}
