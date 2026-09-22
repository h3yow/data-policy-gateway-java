package com.github.h3yow.datapolicygatewayjava.audit;

import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;

import java.util.List;
import java.util.Optional;

/**
 * Append-only audit sink with idempotency support.
 */
public interface AuditEventStore {

    /**
     * Append exactly one event for a first-time request. Retries must call
     * {@link #findByRequestId(String)} first and must NOT append again.
     */
    void append(AuditEvent event);

    /** @return the previously stored event for a requestId, if any */
    Optional<AuditEvent> findByRequestId(String requestId);

    List<AuditEvent> all();
}
