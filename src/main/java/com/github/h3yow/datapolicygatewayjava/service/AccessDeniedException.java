package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * A fail-closed denial. Its message intentionally contains only the stable
 * reason code and request coordinates — never field names or values.
 */
public class AccessDeniedException extends RuntimeException {

    private final DenyReason reason;
    private final long policyVersion;
    private final String requestId;

    public AccessDeniedException(DenyReason reason, long policyVersion,
                                 String requestId, String message) {
        super(message);
        this.reason = reason;
        this.policyVersion = policyVersion;
        this.requestId = requestId;
    }

    public DenyReason reason() {
        return reason;
    }

    public long policyVersion() {
        return policyVersion;
    }

    public String requestId() {
        return requestId;
    }
}
