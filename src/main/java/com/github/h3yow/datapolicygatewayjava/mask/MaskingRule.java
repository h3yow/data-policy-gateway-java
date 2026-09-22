package com.github.h3yow.datapolicygatewayjava.mask;

/**
 * A named masking transformation applied to a single field value.
 * Implementations must never throw unchecked exceptions for ordinary
 * values; any failure is wrapped in {@link MaskingException}.
 */
public interface MaskingRule {

    String name();

    Object apply(Object value);
}
