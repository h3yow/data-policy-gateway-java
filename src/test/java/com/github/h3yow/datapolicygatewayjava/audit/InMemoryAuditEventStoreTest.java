package com.github.h3yow.datapolicygatewayjava.audit;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.Subject;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryAuditEventStoreTest {

    private static final Logger log = LoggerFactory.getLogger(InMemoryAuditEventStoreTest.class);

    private AuditEvent event(String requestId) {
        return new AuditEvent(requestId, 0L, false, Instant.now(),
                new Subject("u-1", Map.of("role", "analyst")),
                new ResourceRef("customer", "c-1"),
                AccessAction.READ, 1L, true, null, "rule[x]", 1, 1, "test");
    }

    @Test
    void duplicateAppendIsRejected() {
        InMemoryAuditEventStore store = new InMemoryAuditEventStore();
        store.append(event("dup-1"));
        assertThrows(DuplicateAuditException.class, () -> store.append(event("dup-1")));
        assertEquals(1, store.all().size());
        log.info("audit-dedupe requestId=dup-1 appends=2 accepted=1");
    }

    @Test
    void concurrentDistinctAppendsAreAllVisibleExactlyOnce() throws Exception {
        int n = 64;
        InMemoryAuditEventStore store = new InMemoryAuditEventStore();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger rejected = new AtomicInteger();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    store.append(event("c-" + idx));
                } catch (DuplicateAuditException e) {
                    rejected.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        log.info("audit-concurrent attempts={} stored={} rejected={}",
                n, store.all().size(), rejected.get());
        assertEquals(n, store.all().size());
        assertEquals(0, rejected.get());
    }
}
