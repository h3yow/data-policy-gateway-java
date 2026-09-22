package com.github.h3yow.datapolicygatewayjava.audit;

/**
 * Signals an attempted double append for one requestId. Treating this as
 * fatal rather than silently ignored keeps the "no double audit"
 * invariant testable.
 */
public class DuplicateAuditException extends RuntimeException {

    public DuplicateAuditException(String message) {
        super(message);
    }
}
