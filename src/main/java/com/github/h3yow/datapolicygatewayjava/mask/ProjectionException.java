package com.github.h3yow.datapolicygatewayjava.mask;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * Fail-closed projection failure. Messages never carry field values, and
 * for FIELD_MAPPING_MISSING / FIELD_UNAUTHORIZED they never carry names.
 */
public class ProjectionException extends RuntimeException {

    private final DenyReason reason;

    public ProjectionException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ProjectionException(DenyReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }
}
