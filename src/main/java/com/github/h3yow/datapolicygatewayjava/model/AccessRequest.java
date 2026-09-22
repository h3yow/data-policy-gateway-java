package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Objects;

/**
 * An inbound field-level data access request.
 *
 * @param requestId caller-supplied idempotency key; retries must repeat it
 * @param subject   requesting principal and its attributes
 * @param resource  target resource
 * @param action    access action
 * @param fields    logical fields requested (empty = all mapped fields)
 */
public record AccessRequest(
        String requestId,
        Subject subject,
        ResourceRef resource,
        AccessAction action,
        List<String> fields
) {

    public AccessRequest {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(action, "action");
        fields = List.copyOf(fields == null ? List.of() : fields);
    }
}
