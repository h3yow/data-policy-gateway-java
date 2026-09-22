package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.Policy;

import java.util.Objects;

/**
 * In-memory {@link PolicyRepository}.
 *
 * <p>Consistency model:
 * <ul>
 *   <li>Each {@link Policy} is an immutable value object; the repository
 *       publishes it through a single {@code volatile} reference swap.</li>
 *   <li>A reader that captured {@link #current()} before an update keeps
 *       evaluating against the complete old snapshot; a reader after the
 *       swap sees the complete new snapshot. A half-updated state is
 *       therefore structurally impossible.</li>
 *   <li>Installs are serialized so version arithmetic (must be exactly
 *       {@code current + 1}) and the optional optimistic base check race
 *       free. Rollback and unknown-version jumps are rejected explicitly,
 *       never silently accepted or re-based.</li>
 * </ul>
 */
public class InMemoryPolicyRepository implements PolicyRepository {

    private volatile Policy snapshot;

    public InMemoryPolicyRepository(Policy initial) {
        Objects.requireNonNull(initial, "initial policy");
        if (initial.version() != 1L) {
            throw new IllegalArgumentException("initial policy must be version 1");
        }
        this.snapshot = initial;
    }

    @Override
    public Policy current() {
        Policy p = snapshot;
        if (p == null) {
            throw new IllegalStateException("no policy installed");
        }
        return p;
    }

    @Override
    public void install(Policy newPolicy, Long expectedBase) {
        Objects.requireNonNull(newPolicy, "newPolicy");
        synchronized (this) {
            long currentVersion = snapshot.version();
            if (expectedBase != null && expectedBase != currentVersion) {
                throw new PolicyVersionException(
                        "stale update base: expected current=" + expectedBase
                                + " but current=" + currentVersion,
                        newPolicy.version(), currentVersion);
            }
            if (newPolicy.version() <= currentVersion) {
                throw new PolicyVersionException(
                        "policy rollback refused: attempted=" + newPolicy.version()
                                + " current=" + currentVersion,
                        newPolicy.version(), currentVersion);
            }
            if (newPolicy.version() != currentVersion + 1) {
                throw new PolicyVersionException(
                        "policy version gap refused: attempted=" + newPolicy.version()
                                + " expected=" + (currentVersion + 1),
                        newPolicy.version(), currentVersion);
            }
            // single volatile publish: readers never observe a partial state
            this.snapshot = newPolicy;
        }
    }

    @Override
    public Policy pin() {
        // The returned reference is immutable, so holding it for the whole
        // request pins the evaluation and the audit record to one version.
        return current();
    }
}
