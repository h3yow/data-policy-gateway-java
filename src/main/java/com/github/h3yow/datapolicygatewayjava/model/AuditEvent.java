package com.github.h3yow.datapolicygatewayjava.model;

import java.time.Instant;
import java.util.Objects;

/**
 * One audit record. Note what it deliberately does <b>not</b> contain:
 * field values and names of denied fields.
 *
 * @param sequence      per-request monotonic sequence (0 for the first attempt)
 * @param retry         whether this is a repeated delivery of the same requestId
 */
public record AuditEvent(
        String requestId,
        long sequence,
        boolean retry,
        Instant occurredAt,
        Subject subject,
        ResourceRef resource,
        AccessAction action,
        long policyVersion,
        boolean allowed,
        DenyReason denyReason,
        String matchedRuleId,
        int requestedFieldCount,
        int allowedFieldCount,
        String basis
) {

    public AuditEvent {
        Objects.requireNonNull(requestId, "requestId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(action, "action");
    }
}
