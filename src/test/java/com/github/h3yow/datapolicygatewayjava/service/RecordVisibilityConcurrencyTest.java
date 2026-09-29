package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
import com.github.h3yow.datapolicygatewayjava.gateway.ResponseReplayStore;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.SubjectAttributes;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.policy.RecordVisibilityEvaluator;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 记录级可见性相关的并发/重复提交用例：
 * <ol>
 *   <li>更新期间并发读取：每条响应要么整体属于旧版本、要么整体属于新版本，
 *       记录过滤结果/字段结果/审计三者同版本，拒绝原因稳定；</li>
 *   <li>同一 requestId 并发重复提交 + 期间发布新版本：只执行首次，所有调用复现同一结果，
 *       审计恰好一条。</li>
 * </ol>
 */
class RecordVisibilityConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(RecordVisibilityConcurrencyTest.class);

    /** v2 语义：ANALYST 无记录级条件（可见全部 3 条），用于和 v1（只见本部门 1 条）区分。 */
    private static PolicyDefinition v2Def() {
        PolicyRule analystV2 = new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"), "customer", AccessAction.READ,
                List.of(
                        new FieldPolicy("id", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("name", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("department", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("phone", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("email", true, MaskingType.NONE, Map.of()),
                        new FieldPolicy("nationalId", false, MaskingType.NONE, Map.of()),
                        new FieldPolicy("salary", false, MaskingType.NONE, Map.of())),
                false, null);
        return new PolicyDefinition("v2", List.of(
                BootstrapPolicyInitializer.adminRule(), analystV2,
                BootstrapPolicyInitializer.guestRule()));
    }

    private static AccessRequest analystReq(String requestId) {
        return new AccessRequest(requestId,
                new SubjectAttributes("u-analyst",
                        Map.of("role", "ANALYST", "department", "ENGINEERING")),
                new ResourceRef("customer", "*", Map.of()), AccessAction.READ);
    }

    @Test
    void concurrentReadsDuringRecordPolicyUpdateAreVersionCoherent() throws Exception {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), new ResponseReplayStore());

        final int threads = 8;
        final int perPhase = 100;
        AtomicInteger failures = new AtomicInteger();
        Map<String, String> failureMessages = new ConcurrentHashMap<>();
        AtomicInteger v1Responses = new AtomicInteger();
        AtomicInteger v2Responses = new AtomicInteger();
        AtomicInteger seq = new AtomicInteger();

        // 阶段 1：8 线程并发读 v1
        CountDownLatch phase1Done = runRound(gateway, audit, 1, threads, perPhase,
                seq, failures, failureMessages, v1Responses, v2Responses);
        phase1Done.await();

        // 运行中发布 v2（ANALYST 由 1 条变 3 条）
        store.publish(v2Def(), "v1");

        // 阶段 2：新一批 8 线程并发读 v2
        CountDownLatch phase2Done = runRound(gateway, audit, 2, threads, perPhase,
                seq, failures, failureMessages, v1Responses, v2Responses);
        phase2Done.await();

        int total = threads * perPhase * 2;
        log.info("record visibility concurrency: input={} readers x{} requests before v1->v2 "
                        + "and same after (ANALYST 1 record -> 3 records), "
                        + "basis='快照原子切换 + 同版本记录数/字段/审计自洽': "
                        + "v1={}, v2={}, auditCount={}, failures={}",
                threads, perPhase, v1Responses.get(), v2Responses.get(),
                audit.all().size(), failures.get());

        assertEquals(0, failures.get(), () -> failureMessages.toString());
        assertEquals(total, audit.all().size(), "每个请求恰好一条审计");
        assertEquals(threads * perPhase, v1Responses.get(), "阶段 1 必须全部完整属于 v1");
        assertEquals(threads * perPhase, v2Responses.get(), "阶段 2 必须全部完整属于 v2");
        assertEquals("v2", store.current().version());
    }

    private CountDownLatch runRound(DataAccessGateway gateway,
                                    AuditService audit,
                                    int phase,
                                    int threads,
                                    int perPhase,
                                    AtomicInteger seq,
                                    AtomicInteger failures,
                                    Map<String, String> failureMessages,
                                    AtomicInteger v1Responses,
                                    AtomicInteger v2Responses) {
        CountDownLatch roundStart = new CountDownLatch(1);
        CountDownLatch roundDone = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            Thread t = new Thread(() -> {
                try {
                    roundStart.await();
                    String expectedVersion = phase == 1 ? "v1" : "v2";
                    int expectedCount = phase == 1 ? 1 : 3;
                    for (int i2 = 0; i2 < perPhase; i2++) {
                        String requestId = "rv-conc-p" + phase + "-" + seq.incrementAndGet();
                        String responseVersion;
                        boolean allowed;
                        int recordCount;
                        try {
                            AccessResult result = gateway.execute(analystReq(requestId));
                            responseVersion = result.policyVersion();
                            allowed = true;
                            recordCount = result.records().size();
                        } catch (AccessDeniedException e) {
                            responseVersion = e.policyVersion();
                            allowed = false;
                            recordCount = -1;
                        }

                        AuditRecord a = audit.findByRequestId(requestId).orElse(null);
                        if (a == null) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId, "audit missing");
                            continue;
                        }
                        // 记录过滤结果 + 字段结果 + 审计必须同一版本
                        if (!a.policyVersion().equals(responseVersion)) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId,
                                    "version mismatch response=" + responseVersion
                                            + " audit=" + a.policyVersion());
                        }
                        if (a.allowed() != allowed) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId, "allowed mismatch");
                        }
                        if (!allowed || !expectedVersion.equals(responseVersion)
                                || recordCount != expectedCount) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId,
                                    "expected " + expectedVersion + "/" + expectedCount
                                            + " rows but got " + responseVersion + "/"
                                            + recordCount + " allowed=" + allowed);
                        }
                        if ("v1".equals(responseVersion)) {
                            v1Responses.incrementAndGet();
                        } else if ("v2".equals(responseVersion)) {
                            v2Responses.incrementAndGet();
                        }
                    }
                } catch (Throwable th) {
                    failures.incrementAndGet();
                    failureMessages.put("reader", th.toString());
                } finally {
                    roundDone.countDown();
                }
            });
            t.start();
        }
        roundStart.countDown();
        return roundDone;
    }

    @Test
    void concurrentDuplicateSubmissionsDuringUpdateReplayFirstOutcome() throws Exception {
        PolicyStore store = new PolicyStore();
        store.publish(BootstrapPolicyInitializer.v1(), null);
        AuditService audit = new AuditService();
        ResponseReplayStore replay = new ResponseReplayStore();
        DataAccessGateway gateway = new DataAccessGateway(store,
                new PolicyEvaluator(), new RecordVisibilityEvaluator(), new Masker(),
                audit, List.of(new InMemoryDataSource()), replay);

        final String requestId = "rv-dup-same-id";
        final int threads = 16;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        Map<Integer, String> versions = new ConcurrentHashMap<>();
        Map<Integer, Integer> counts = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();

        // 一半线程先起跑，稍后发布 v2，再放行剩余线程：混合“在途并发”与“更新后重试”
        List<Thread> callers = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int index = i;
            callers.add(new Thread(() -> {
                try {
                    start.await();
                    if (index >= threads / 2) {
                        Thread.sleep(30); // 确保 v2 已发布后再发
                    }
                    try {
                        AccessResult result = gateway.execute(analystReq(requestId));
                        versions.put(index, result.policyVersion());
                        counts.put(index, result.records().size());
                    } catch (AccessDeniedException e) {
                        failures.incrementAndGet();
                    }
                } catch (Throwable t) {
                    failures.incrementAndGet();
                } finally {
                    done.countDown();
                }
            }));
        }
        callers.forEach(Thread::start);
        start.countDown();
        Thread.sleep(10);
        store.publish(v2Def(), "v1");
        done.await();

        log.info("record visibility duplicate: input={} same-requestId submissions around "
                        + "v1->v2, basis='single-flight + 重放首次：全部 v1/1 条', versions={}, counts={}",
                threads, versions, counts);

        assertEquals(0, failures.get());
        long distinctVersions = versions.values().stream().distinct().count();
        assertEquals(1, distinctVersions, "所有响应必须复现同一首次版本，不得新旧混合");
        long distinctCounts = counts.values().stream().distinct().count();
        assertEquals(1, distinctCounts, "所有响应必须复现同一首次记录集合");
        assertEquals(1, counts.values().iterator().next());
        assertEquals("v1", versions.values().iterator().next(),
                "首次发生在 v1，更新后提交也必须复现 v1 结果");
        long auditCount = audit.all().stream()
                .filter(a -> a.requestId().equals(requestId)).count();
        assertEquals(1, auditCount, "同一 requestId 恰好一条审计");
    }
}
