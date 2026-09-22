package com.github.h3yow.datapolicygatewayjava.audit;

import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, in-memory audit store.
 *
 * <p>Exactly-once-per-requestId is enforced structurally:
 * {@link #append(AuditEvent)} refuses a second event with the same
 * requestId, so even a buggy caller can neither double-audit nor (through
 * the append/check ordering) miss an audit for a completed request.
 */
public class InMemoryAuditEventStore implements AuditEventStore {

    private final ConcurrentHashMap<String, AuditEvent> byRequestId = new ConcurrentHashMap<>();
    // Guarded by its own monitor; append + order-list update happen together.
    private final List<AuditEvent> ordered = new ArrayList<>();
    private final Object orderLock = new Object();

    @Override
    public void append(AuditEvent event) {
        Objects.requireNonNull(event, "event");
        AuditEvent existing = byRequestId.putIfAbsent(event.requestId(), event);
        if (existing != null) {
            throw new DuplicateAuditException(
                    "audit event already exists for requestId=" + event.requestId());
        }
        synchronized (orderLock) {
            ordered.add(event);
        }
    }

    @Override
    public Optional<AuditEvent> findByRequestId(String requestId) {
        return Optional.ofNullable(byRequestId.get(requestId));
    }

    @Override
    public List<AuditEvent> all() {
        synchronized (orderLock) {
            return List.copyOf(ordered);
        }
    }
}
