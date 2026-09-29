package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.DataSource;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.gateway.IdempotentResultStore;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.ConditionValueSource;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.visibility.RecordVisibilityEvaluator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 记录级策略更新与并发读取：
 * <ul>
 *   <li>版本在 v1..vN 间交替，分析人员规则的记录条件在 department==ENGINEERING /
 *       department==FINANCE 两种语义间翻转；</li>
 *   <li>8 个读线程并发查询（各自独立 requestId），期间 1 个写线程持续发布新版本；</li>
 *   <li>每次响应的记录集合必须与其 policyVersion 的条件语义一致（不新旧混着来），
 *       审计与响应必须同版本、同 requestId、恰好一条。</li>
 * </ul>
 */
class RecordLevelConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordLevelConcurrencyTest.class);

    /** 固定三行、每行恰好 7 个键（与 v1/v2 字段映射一致）。 */
    private static final List<Map<String, Object>> ROWS = List.of(
            row("C001", "ENGINEERING"), row("C002", "FINANCE"),
            row("C003", "ENGINEERING"));

    private static Map<String, Object> row(String id, String department) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("name", "n-" + id);
        m.put("nationalId", "110101199001011234");
        m.put("phone", "13800001111");
        m.put("email", id.toLowerCase() + "@example.com");
        m.put("salary", 1000);
        m.put("department", department);
        return m;
    }

    private static final DataSource DATA_SOURCE = new DataSource() {
        @Override
        public boolean supports(String resourceType) {
            return InMemoryDataSource.RESOURCE_TYPE.equals(resourceType);
        }

        @Override
        public List<Map<String, Object>> fetch(ResourceRef resource) {
            return ROWS.stream().<Map<String, Object>>map(LinkedHashMap::new).toList();
        }
    };

    /**
     * @param version v1 无记录级条件（全部 3 条）；偶数版本限定 ENGINEERING（C001,C003），
     *                奇数版本（>=3）限定 FINANCE（C002）。
     */
    private static PolicyDefinition def(String version, int order) {
        PolicyRule analyst;
        if (order == 1) {
            analyst = BootstrapPolicyInitializer.analystRule();
        } else {
            String dept = (order % 2 == 0) ? "ENGINEERING" : "FINANCE";
            analyst = new PolicyRule("r-analyst-read-dept",
                    Map.of("role", "ANALYST"), "customer", AccessAction.READ,
                    BootstrapPolicyInitializer.analystRule().fieldPolicies(), false,
                    new RecordVisibilityCondition(List.of(new RecordConditionTerm(
                            "department", ConditionOperator.EQ,
                            ConditionValueSource.RECORD, null, dept))));
        }
        return new PolicyDefinition(version, List.of(
                BootstrapPolicyInitializer.adminRule(), analyst,
                BootstrapPolicyInitializer.guestRule()));
    }

    @Test
    void concurrentReadsDuringRecordPolicyUpdatesStayVersionConsistent() throws Exception {
        PolicyStore store = new PolicyStore();
        store.publish(def("v1", 1), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store, new PolicyEvaluator(),
                new RecordVisibilityEvaluator(), new Masker(), audit,
                new IdempotentResultStore(), List.of(DATA_SOURCE));

        final int versions = 20;
        final int readerThreads = 8;
        final int requestsPerReader = 150;

        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger failures = new AtomicInteger();
        Map<String, String> failureMessages = new ConcurrentHashMap<>();
        AtomicInteger requestSeq = new AtomicInteger();

        Thread writer = new Thread(() -> {
            try {
                start.await();
                for (int i = 2; i <= versions; i++) {
                    store.publish(def("v" + i, i), "v" + (i - 1));
                }
            } catch (Throwable t) {
                failures.incrementAndGet();
                failureMessages.put("writer", t.toString());
            }
        });

        List<Thread> readers = new java.util.ArrayList<>();
        for (int r = 0; r < readerThreads; r++) {
            Thread reader = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < requestsPerReader; i++) {
                        String requestId = "rconc-" + requestSeq.incrementAndGet();
                        AccessRequest request = new AccessRequest(requestId,
                                new SubjectAttributes("u-analyst",
                                        Map.of("role", "ANALYST", "department", "ENGINEERING")),
                                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                                AccessAction.READ);
                        AccessResult result = gateway.execute(request);

                        long order = Long.parseLong(result.policyVersion().substring(1));
                        List<String> ids = result.records().stream()
                                .map(row -> (String) row.get("id")).sorted().toList();
                        List<String> expected = expectedIds(order);

                        if (!ids.equals(expected)) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-records",
                                    "version=" + result.policyVersion()
                                            + " records=" + ids + " expected=" + expected);
                        }
                        AuditRecord a = audit.findByRequestId(requestId).orElse(null);
                        if (a == null) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-audit-missing", "missing");
                        } else if (!a.policyVersion().equals(result.policyVersion()) || !a.allowed()) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-audit",
                                    "auditVersion=" + (a == null ? null : a.policyVersion()));
                        }
                    }
                } catch (Throwable t) {
                    failures.incrementAndGet();
                    failureMessages.put("reader", t.toString());
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

        int total = readerThreads * requestsPerReader;
        log.info("record-level concurrency test: input={} readers x{} requests during "
                        + "v1->v{} record-policy flips, basis='响应记录与版本条件语义一致+审计同版本': "
                        + "auditCount={}, failures={}",
                readerThreads, requestsPerReader, versions, audit.all().size(), failures.get());

        assertEquals(0, failures.get(), () -> failureMessages.toString());
        assertEquals(total, audit.all().size(), "每个请求恰好一条审计");
        assertTrue(audit.all().stream().allMatch(a -> a.policyVersion() != null));
    }

    private static List<String> expectedIds(long order) {
        if (order == 1) {
            return List.of("C001", "C002", "C003");
        }
        return (order % 2 == 0) ? List.of("C001", "C003") : List.of("C002");
    }
}
