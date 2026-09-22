package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.FieldRule;
import com.github.h3yow.datapolicygatewayjava.model.Policy;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Builds the demo policy sets.
 *
 * <p>v1 model (resource type {@code customer}):
 * <ul>
 *   <li>priority 100, role=admin, READ: all four fields in clear.</li>
 *   <li>priority 10,  role=analyst, READ: name/region allowed; email
 *       masked; ssn denied.</li>
 * </ul>
 * Any other subject/action/resource combination matches no rule and is
 * denied with POLICY_NOT_MATCHED.
 */
@Component
public class DemoPolicyFactory {

    public Policy version1() {
        PolicyRule admin = new PolicyRule(100, "customer", AccessAction.READ,
                Map.of("role", "admin"),
                List.of(
                        FieldRule.allow("name"),
                        FieldRule.allow("email"),
                        FieldRule.allow("region"),
                        FieldRule.allow("ssn")
                ));
        PolicyRule analyst = new PolicyRule(10, "customer", AccessAction.READ,
                Map.of("role", "analyst"),
                List.of(
                        FieldRule.allow("name"),
                        FieldRule.mask("email", "email"),
                        FieldRule.allow("region"),
                        FieldRule.deny("ssn")
                ));
        return new Policy(1L, List.of(admin, analyst));
    }

    /**
     * v2 demo update: analysts lose region visibility too. Used by tests
     * and by operators exercising the install endpoint.
     */
    public Policy version2() {
        PolicyRule admin = new PolicyRule(100, "customer", AccessAction.READ,
                Map.of("role", "admin"),
                List.of(
                        FieldRule.allow("name"),
                        FieldRule.allow("email"),
                        FieldRule.allow("region"),
                        FieldRule.allow("ssn")
                ));
        PolicyRule analyst = new PolicyRule(10, "customer", AccessAction.READ,
                Map.of("role", "analyst"),
                List.of(
                        FieldRule.allow("name"),
                        FieldRule.mask("email", "email"),
                        FieldRule.deny("region"),
                        FieldRule.deny("ssn")
                ));
        return new Policy(2L, List.of(admin, analyst));
    }
}
