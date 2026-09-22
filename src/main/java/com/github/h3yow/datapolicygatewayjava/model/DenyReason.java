package com.github.h3yow.datapolicygatewayjava.model;

/**
 * Distinguishable, stable denial reason codes.
 *
 * <p>Messages attached to these reasons must never carry field names or
 * field values: denied fields are sensitive by definition.
 */
public enum DenyReason {
    /** A policy matched but it explicitly hides one of the requested fields. */
    FIELD_UNAUTHORIZED,
    /** No policy rule is applicable to the subject/resource/action tuple. */
    POLICY_NOT_MATCHED,
    /** The policy evaluator itself failed (fail-closed). */
    EVALUATION_FAILED,
    /** A requested field is not present in the resource field mapping. */
    FIELD_MAPPING_MISSING,
    /** A masking rule could not be applied (fail-closed). */
    MASKING_RULE_ERROR,
    /** The target resource does not exist in the backing data source. */
    RESOURCE_NOT_FOUND,
    /** The submitted data is malformed. */
    INVALID_REQUEST
}
