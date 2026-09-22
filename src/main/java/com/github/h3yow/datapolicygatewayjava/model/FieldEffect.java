package com.github.h3yow.datapolicygatewayjava.model;

/**
 * Field-level effect decided by a policy rule.
 */
public enum FieldEffect {
    /** Field value is returned as-is. */
    ALLOW,
    /** Field is returned after applying a masking rule. */
    MASK,
    /** Field is not visible and must never leave the gateway. */
    DENY
}
