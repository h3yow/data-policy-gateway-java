package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessDecision;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldDecision;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 策略求值器：针对一次访问给出字段级判定。
 *
 * <p>纯函数、无状态，只操作字段元数据，不接触任何字段值，因此求值过程不可能泄露数据。
 *
 * <p>判定规则（稳定、可复现）：
 * <ol>
 *   <li>按规则在策略中的声明顺序，选取第一条同时满足 资源类型 + 动作 + 全部主体属性条件 的规则；</li>
 *   <li>没有任何规则匹配 → 整体拒绝 {@link DenyReason#POLICY_NO_MATCH}（策略不匹配）；</li>
 *   <li>命中规则时逐字段判定：
 *     <ul>
 *       <li>显式 {@code visible=false} → 字段被剥离，判定 {@link DenyReason#FIELD_FORBIDDEN}（越权），
 *           字段不会出现在响应中，仅作为判定依据进入审计；</li>
 *       <li>规则未覆盖该字段：规则 {@code defaultVisible=true} 时按未脱敏放行（需显式声明）；
 *           否则按 {@link DenyReason#FIELD_MAPPING_MISSING} <b>失败关闭</b>；</li>
 *       <li>可见字段按其 {@code maskingType} 在后续阶段脱敏。</li>
 *     </ul>
 *   </li>
 * </ol>
 */
@Component
public class PolicyEvaluator {

    public AccessDecision evaluate(SubjectAttributes subject,
                                   ResourceRef resource,
                                   AccessAction action,
                                   Set<String> requestedFields,
                                   PolicySnapshot snapshot) {
        String version = snapshot.version();
        try {
            List<PolicyRule> rules = snapshot.definition().rules();
            PolicyRule matched = null;
            if (rules != null) {
                for (PolicyRule rule : rules) {
                    if (matches(rule, subject, resource, action)) {
                        matched = rule;
                        break;
                    }
                }
            }

            if (matched == null) {
                Map<String, FieldDecision> fields = new LinkedHashMap<>();
                for (String field : requestedFields) {
                    fields.put(field, new FieldDecision(
                            field, false, false, null,
                            DenyReason.POLICY_NO_MATCH, "no policy rule matched"));
                }
                return new AccessDecision(version, null, fields,
                        DenyReason.POLICY_NO_MATCH,
                        "no policy rule matched subject/resource/action");
            }

            Map<String, FieldPolicy> policyByName = new LinkedHashMap<>();
            for (FieldPolicy fp : matched.fieldPolicies()) {
                policyByName.put(fp.fieldName(), fp);
            }

            Map<String, FieldDecision> fields = new LinkedHashMap<>();
            DenyReason failClosed = null;
            String failDetail = null;
            for (String field : requestedFields) {
                FieldPolicy fp = policyByName.get(field);
                FieldDecision fd;
                if (fp == null) {
                    if (matched.defaultVisible()) {
                        fd = new FieldDecision(field, true, false, null, null,
                                "allowed by rule defaultVisible");
                    } else {
                        fd = new FieldDecision(field, false, false, null,
                                DenyReason.FIELD_MAPPING_MISSING,
                                "field not mapped in matched rule");
                        if (failClosed == null) {
                            failClosed = DenyReason.FIELD_MAPPING_MISSING;
                            failDetail = "field '" + field + "' has no policy mapping";
                        }
                    }
                } else if (!fp.visible()) {
                    fd = new FieldDecision(field, false, false, null,
                            DenyReason.FIELD_FORBIDDEN, "explicitly forbidden by rule");
                } else {
                    boolean masked = fp.maskingType() != null
                            && fp.maskingType() != com.github.h3yow.datapolicygatewayjava.model.MaskingType.NONE;
                    fd = new FieldDecision(field, true, masked, fp.maskingType(), null,
                            masked ? "allowed with masking " + fp.maskingType() : "allowed");
                }
                fields.put(field, fd);
            }

            return new AccessDecision(version, matched.ruleId(), fields, failClosed, failDetail);
        } catch (RuntimeException e) {
            // 求值本身出现任何意外：失败关闭（异常消息不携带字段值）
            Map<String, FieldDecision> fields = new LinkedHashMap<>();
            for (String field : requestedFields) {
                fields.put(field, new FieldDecision(field, false, false, null,
                        DenyReason.EVALUATION_FAILED, "evaluation error"));
            }
            return new AccessDecision(version, null, fields,
                    DenyReason.EVALUATION_FAILED, "policy evaluation failed: " + e.getClass().getSimpleName());
        }
    }

    static boolean matches(PolicyRule rule,
                           SubjectAttributes subject,
                           ResourceRef resource,
                           AccessAction action) {
        if (rule.action() != action) {
            return false;
        }
        if (rule.resourceType() != null
                && !rule.resourceType().equals("*")
                && !rule.resourceType().equals(resource.resourceType())) {
            return false;
        }
        Map<String, String> conditions = rule.subjectConditions();
        if (conditions != null) {
            Map<String, String> actual = subject.attributes();
            for (Map.Entry<String, String> condition : conditions.entrySet()) {
                if (actual == null || !condition.getValue().equals(actual.get(condition.getKey()))) {
                    return false;
                }
            }
        }
        return true;
    }
}
