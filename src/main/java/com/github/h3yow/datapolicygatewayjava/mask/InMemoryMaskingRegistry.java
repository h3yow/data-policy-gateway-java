package com.github.h3yow.datapolicygatewayjava.mask;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Static, thread-safe registry of masking rules. Unknown rule names are a
 * fail-closed configuration error ({@link MaskingException}) both at
 * policy-install validation time and at projection time.
 */
public class InMemoryMaskingRegistry implements MaskingRegistry {

    private final Map<String, MaskingRule> rules;

    public InMemoryMaskingRegistry() {
        this.rules = new ConcurrentHashMap<>();
    }

    public InMemoryMaskingRegistry(Map<String, MaskingRule> rules) {
        this.rules = new ConcurrentHashMap<>();
        if (rules != null) {
            rules.forEach((name, rule) -> register(Objects.requireNonNull(name),
                    Objects.requireNonNull(rule)));
        }
    }

    public final void register(String name, MaskingRule rule) {
        Objects.requireNonNull(name, "mask name");
        Objects.requireNonNull(rule, "mask rule");
        if (!name.equals(rule.name())) {
            throw new IllegalArgumentException(
                    "mask rule name mismatch: key=" + name + " rule=" + rule.name());
        }
        rules.put(name, rule);
    }

    @Override
    public MaskingRule resolve(String name) {
        MaskingRule rule = rules.get(name);
        if (rule == null) {
            // No value content in the message - name itself is policy config.
            throw new MaskingException("unknown masking rule", name);
        }
        return rule;
    }

    @Override
    public boolean contains(String name) {
        return rules.containsKey(name);
    }
}
