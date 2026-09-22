package com.github.h3yow.datapolicygatewayjava.model;

/**
 * The per-field outcome of an evaluation.
 *
 * @param field    logical field name
 * @param effect   allow / mask / deny
 * @param maskName masking rule name when {@code effect == MASK}, else null
 * @param reason   human-explainable basis of the decision (rule coordinates),
 *                 never a field value
 */
public record FieldVerdict(String field, FieldEffect effect,
                           String maskName, String reason) {

    public FieldVerdict {
        if (effect == FieldEffect.MASK && (maskName == null || maskName.isBlank())) {
            throw new IllegalArgumentException("mask verdict requires a maskName");
        }
    }
}
