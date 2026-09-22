package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 策略存储单测：版本推进、回退拒绝、未知父版本拒绝、并发读取不出现半更新。
 */
class PolicyStoreTest {

    private static final Logger log = LoggerFactory.getLogger(PolicyStoreTest.class);

    private PolicyStore store;

    private static PolicyDefinition def(String version) {
        PolicyRule rule = new PolicyRule("rule-" + version, Map.of("role", "ADMIN"),
                "customer", AccessAction.READ, List.of(), false);
        return new PolicyDefinition(version, List.of(rule));
    }

    @BeforeEach
    void setUp() {
        store = new PolicyStore();
        store.publish(def("v1"), null);
    }

    @Test
    void publishesHigherVersion() {
        store.publish(def("v2"), "v1");
        log.info("policy test: input=v2 with expectedParent=v1, basis='顺序推进', current={}",
                store.current().version());
        assertEquals("v2", store.current().version());
        assertEquals("rule-v2", store.current().definition().rules().get(0).ruleId());
    }

    @Test
    void rejectsRollback() {
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> store.publish(def("v1"), null));
        log.info("policy test: input=v1(current=v1), basis='相同/回退版本拒绝', message={}",
                ex.getMessage());
        assertTrue(ex.getMessage().contains("rollback"));
        assertEquals("v1", store.current().version(), "回退必须被拒绝且当前版本不变");
    }

    @Test
    void rejectsLowerRollback() {
        store.publish(def("v5"), null);
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> store.publish(def("v2"), null));
        log.info("policy test: input=v2(current=v5), basis='低版本回退拒绝', message={}",
                ex.getMessage());
        assertEquals("v5", store.current().version());
        assertTrue(ex.getMessage().contains("rollback"));
    }

    @Test
    void rejectsUnknownParentVersion() {
        PolicyVersionException ex = assertThrows(PolicyVersionException.class,
                () -> store.publish(def("v2"), "v99"));
        log.info("policy test: input=v2 with expectedParent=v99(current=v1), "
                + "basis='指向未知版本拒绝', message={}", ex.getMessage());
        assertTrue(ex.getMessage().contains("does not match"));
        assertEquals("v1", store.current().version());
    }

    @Test
    void rejectsUnparseableVersion() {
        assertThrows(PolicyVersionException.class,
                () -> store.publish(def("abc"), null));
        assertThrows(PolicyVersionException.class,
                () -> store.publish(def(""), null));
        log.info("policy test: input='abc'/blank, basis='未知版本格式拒绝', current={}",
                store.current().version());
    }

    @Test
    void concurrentReadersNeverSeeTornState() throws InterruptedException {
        // 一个写线程持续发布新版本；多个读线程拿到的快照必须始终自洽
        int readerCount = 6;
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger errors = new AtomicInteger();
        AtomicReference<Throwable> firstError = new AtomicReference<>();

        Thread writer = new Thread(() -> {
            try {
                start.await();
                for (int i = 2; i <= 30; i++) {
                    store.publish(def("v" + i), "v" + (i - 1));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        List<Thread> readers = new java.util.ArrayList<>();
        for (int r = 0; r < readerCount; r++) {
            Thread reader = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 2000; i++) {
                        PolicySnapshot snapshot = store.current();
                        assertNotNull(snapshot);
                        // 版本号与内容必须来自同一个快照（无半更新）
                        String expectedRule = "rule-" + snapshot.version();
                        if (!expectedRule.equals(snapshot.definition().rules().get(0).ruleId())) {
                            errors.incrementAndGet();
                            firstError.compareAndSet(new AssertionError(
                                    "torn snapshot: version=" + snapshot.version()
                                            + " but rule=" + snapshot.definition()
                                            .rules().get(0).ruleId()), null);
                        }
                    }
                } catch (Throwable t) {
                    errors.incrementAndGet();
                    firstError.compareAndSet(t, null);
                }
            });
            readers.add(reader);
        }

        readers.forEach(Thread::start);
        writer.start();
        start.countDown();
        writer.join();
        for (Thread t : readers) {
            t.join();
        }

        log.info("policy test: input=v2..v30 publish + {} readers x2000 reads, "
                + "basis='不可变快照原子发布', errors={}", readerCount, errors.get());
        assertEquals(0, errors.get(),
                firstError.get() == null ? "torn state observed" : firstError.get().getMessage());
        assertEquals("v30", store.current().version());
    }
}
