package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.config.DemoPolicyFactory;
import com.github.h3yow.datapolicygatewayjava.model.Policy;
import com.github.h3yow.datapolicygatewayjava.policy.InMemoryPolicyRepository;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyRepository;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyVersionException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InMemoryPolicyRepositoryTest {

    private static final Logger log = LoggerFactory.getLogger(InMemoryPolicyRepositoryTest.class);

    private PolicyRepository repository;
    private DemoPolicyFactory factory;

    @BeforeEach
    void setUp() {
        factory = new DemoPolicyFactory();
        repository = new InMemoryPolicyRepository(factory.version1());
    }

    @Test
    void installsStrictlyNextVersion() {
        Policy v2 = factory.version2();
        repository.install(v2, null);
        log.info("policy-update from=1 to={} result=accepted", v2.version());
        assertEquals(2L, repository.current().version());
    }

    @Test
    void refusesRollback() {
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> repository.install(factory.version1(), null));
        log.info("policy-update attempted={} current={} result=refused reason=rollback",
                ex.attemptedVersion(), ex.currentVersion());
        assertEquals(1L, repository.current().version());
    }

    @Test
    void refusesVersionGap() {
        Policy v3 = new Policy(3L, List.of());
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> repository.install(v3, null));
        log.info("policy-update attempted={} current={} result=refused reason=gap",
                ex.attemptedVersion(), ex.currentVersion());
        assertEquals(1L, repository.current().version());
    }

    @Test
    void refusesStaleOptimisticBase() {
        Policy v2 = factory.version2();
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> repository.install(v2, 99L));
        log.info("policy-update attempted={} base=99 current={} result=refused reason=stale-base",
                ex.attemptedVersion(), ex.currentVersion());
        assertEquals(1L, repository.current().version());
    }

    @Test
    void acceptsMatchingOptimisticBase() {
        repository.install(factory.version2(), 1L);
        assertEquals(2L, repository.current().version());
    }

    @Test
    void pinnedSnapshotRemainsStableAcrossUpdates() {
        Policy pinned = repository.pin();
        repository.install(factory.version2(), null);
        // The old pinned reference stays internally consistent forever.
        assertEquals(1L, pinned.version());
        assertEquals(2L, repository.current().version());
        log.info("policy-pin pinnedVersion={} currentVersion={} consistent=true",
                pinned.version(), repository.current().version());
    }
}
