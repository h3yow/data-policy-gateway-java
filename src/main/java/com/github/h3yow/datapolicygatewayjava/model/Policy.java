package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Comparator;
import java.util.List;
import java.util.Objects;

/**
 * An immutable, versioned set of policy rules.
 *
 * <p>Once published a policy instance never changes: updates install a new
 * instance with a strictly greater version, so readers holding a reference
 * always observe a consistent snapshot.
 */
public record Policy(long version, List<PolicyRule> rules) {

    public Policy {
        if (version < 1) {
            throw new IllegalArgumentException("policy version must be >= 1");
        }
        Objects.requireNonNull(rules, "rules");
        rules = rules.stream()
                .sorted(Comparator.comparingInt(PolicyRule::priority).reversed())
                .toList();
    }
}
