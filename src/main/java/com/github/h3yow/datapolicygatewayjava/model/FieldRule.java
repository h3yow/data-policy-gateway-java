package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Objects;

/**
 * Decision for a single logical field.
 *
 * @param field    logical field name
 * @param effect   allow / mask / deny
 * @param maskName name of the masking rule when {@code effect == MASK},
 *                 otherwise {@code null}
 */
public record FieldRule(String field, FieldEffect effect, String maskName) {

    public FieldRule {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(effect, "effect");
        if (effect == FieldEffect.MASK && (maskName == null || maskName.isBlank())) {
            throw new IllegalArgumentException("mask rule requires a maskName");
        }
    }

    public static FieldRule allow(String field) {
        return new FieldRule(field, FieldEffect.ALLOW, null);
    }

    public static FieldRule deny(String field) {
        return new FieldRule(field, FieldEffect.DENY, null);
    }

    public static FieldRule mask(String field, String maskName) {
        return new FieldRule(field, FieldEffect.MASK, maskName);
    }
}
