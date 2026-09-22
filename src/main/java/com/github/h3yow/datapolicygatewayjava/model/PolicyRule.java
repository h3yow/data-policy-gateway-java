package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * One matching rule inside a {@link Policy}. A rule matches when the
 * subject carries every required attribute, the resource type matches and
 * the action matches. Higher {@code priority} rules are evaluated first.
 *
 * @param priority         evaluation order (higher first)
 * @param matchResource    resource type this rule applies to, {@code "*"} = any
 * @param matchAction      action this rule applies to, {@code null} = any
 * @param matchAttributes attributes the subject must carry (exact values)
 * @param fields          field-level decisions
 */
public record PolicyRule(
        int priority,
        String matchResource,
        AccessAction matchAction,
        Map<String, String> matchAttributes,
        List<FieldRule> fields
) {

    public PolicyRule {
        Objects.requireNonNull(matchResource, "matchResource");
        matchAttributes = Map.copyOf(matchAttributes == null ? Map.of() : matchAttributes);
        fields = List.copyOf(fields == null ? List.of() : fields);
    }
}
