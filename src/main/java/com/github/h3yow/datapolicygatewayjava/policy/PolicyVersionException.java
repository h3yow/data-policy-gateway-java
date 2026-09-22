package com.github.h3yow.datapolicygatewayjava.policy;

/**
 * Raised when a policy update would roll back, skip a version or conflicts
 * with an optimistic base. Never silently falls back.
 */
public class PolicyVersionException extends RuntimeException {

    private final long attemptedVersion;
    private final long currentVersion;

    public PolicyVersionException(String message, long attemptedVersion, long currentVersion) {
        super(message);
        this.attemptedVersion = attemptedVersion;
        this.currentVersion = currentVersion;
    }

    public long attemptedVersion() {
        return attemptedVersion;
    }

    public long currentVersion() {
        return currentVersion;
    }
}
