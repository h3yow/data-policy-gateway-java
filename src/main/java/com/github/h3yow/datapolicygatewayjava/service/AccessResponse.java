package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.Map;

/**
 * Successful response: only authorized (and possibly masked) fields are
 * present, plus the exact policy version for reproducibility.
 */
public record AccessResponse(
        String requestId,
        ResourceRef resource,
        long policyVersion,
        boolean retry,
        Map<String, Object> fields
) {

    public AccessResponse {
        fields = Map.copyOf(fields == null ? Map.of() : fields);
    }
}
