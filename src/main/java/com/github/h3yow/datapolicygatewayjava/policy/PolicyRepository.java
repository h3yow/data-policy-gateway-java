package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.Policy;

/**
 * Versioned, atomic policy storage.
 */
public interface PolicyRepository {

    /** @return the current policy snapshot; never null after initial install */
    Policy current();

    /**
     * Atomically install a new policy version.
     *
     * @param newPolicy    policy whose version must be exactly current+1
     * @param expectedBase if non-null, the update is accepted only when the
     *                     current version equals this value (optimistic guard)
     * @throws PolicyVersionException on rollback, forward gap or stale base
     */
    void install(Policy newPolicy, Long expectedBase);

    /**
     * Pin a specific (must be current) version for the duration of one read,
     * guaranteeing response and audit share the same version.
     */
    Policy pin();
}
