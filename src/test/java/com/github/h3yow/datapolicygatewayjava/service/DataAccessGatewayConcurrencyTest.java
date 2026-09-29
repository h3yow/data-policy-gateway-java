package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.data.InMemoryDataSource;
import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.gateway.DataAccessGateway;
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
import com.github.h3yow.datapolicygatewayjava.policy.PolicySnapshot;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyVersionException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发场景测试：
 * <ul>
 *   <li>一个线程持续发布新版本（其中穿插回退尝试，必须全部被拒绝）；</li>
 *   <li>多个读线程并发查询，任何响应与其审计记录必须归属同一策略版本；</li>
 *   <li>每次请求的判定结果必须自洽（同版本下结果可复现），拒绝原因只能是稳定枚举；</li>
 *   <li>每个 requestId 恰好一条审计。</li>
 * </ul>
 */
class DataAccessGatewayConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(DataAccessGatewayConcurrencyTest.class);

    /** 构造与 v1 结构等价、仅版本号不同的策略，模拟运行中更新。 */
    private static PolicyDefinition versionedDef(String version) {
        List<PolicyRule> rules = List.of(
                BootstrapPolicyInitializer.adminRule(),
                BootstrapPolicyInitializer.analystRule(),
                BootstrapPolicyInitializer.guestRule());
        return new PolicyDefinition(version, rules);
    }

    @Test
    void concurrentReadsDuringPolicyUpdatesStayVersionConsistent() throws Exception {
        PolicyStore policyStore = new PolicyStore();
        policyStore.publish(versionedDef("v1"), null);
        AuditService auditService = new AuditService();
        DataAccessGateway gateway = new DataAccessGateway(
                policyStore, new PolicyEvaluator(), new Masker(), auditService,
                List.of(new InMemoryDataSource()));

        final int versions = 20;
        final int readerThreads = 8;
        final int requestsPerReader = 200;

        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger rollbackRejections = new AtomicInteger();
        AtomicInteger failures = new AtomicInteger();
        Map<String, String> failureMessages = new ConcurrentHashMap<>();
        AtomicInteger allowedCount = new AtomicInteger();
        AtomicInteger deniedCount = new AtomicInteger();
        Map<String, AtomicInteger> denyReasonCounts = new ConcurrentHashMap<>();

        Thread writer = new Thread(() -> {
            try {
                start.await();
                for (int i = 2; i <= versions; i++) {
                    policyStore.publish(versionedDef("v" + i), "v" + (i - 1));
                    // 每个新版本后尝试一次回退，必须被明确拒绝
                    try {
                        policyStore.publish(versionedDef("v" + (i - 1)), null);
                        failures.incrementAndGet();
                        failureMessages.put("rollback-accepted", "rollback was accepted at v" + i);
                    } catch (PolicyVersionException expected) {
                        rollbackRejections.incrementAndGet();
                    }
                }
            } catch (Throwable t) {
                failures.incrementAndGet();
                failureMessages.put("writer", t.toString());
            }
        });

        List<Thread> readers = new java.util.ArrayList<>();
        AtomicInteger requestSeq = new AtomicInteger();
        for (int r = 0; r < readerThreads; r++) {
            final String role = (r % 3 == 0) ? "ADMIN" : (r % 3 == 1) ? "ANALYST" : "GUEST";
            Thread reader = new Thread(() -> {
                try {
                    start.await();
                    for (int i = 0; i < requestsPerReader; i++) {
                        // 每 10 个请求里混入一个越权角色，验证拒绝路径也稳定
                        String useRole = (i % 10 == 9) ? "UNAUTH_ROLE" : role;
                        // ANALYST 规则含记录级条件，需要主体携带 department 属性
                        Map<String, String> subjectAttrs = "ANALYST".equals(useRole)
                                ? Map.of("role", useRole, "department", "ENGINEERING")
                                : Map.of("role", useRole);
                        String requestId = "conc-" + requestSeq.incrementAndGet();
                        AccessRequest request = new AccessRequest(requestId,
                                new SubjectAttributes("u-" + useRole, subjectAttrs),
                                new ResourceRef(InMemoryDataSource.RESOURCE_TYPE, "*", Map.of()),
                                AccessAction.READ);
                        String responseVersion;
                        boolean allowed;
                        DenyReason reason = null;
                        try {
                            AccessResult result = gateway.execute(request);
                            allowed = true;
                            responseVersion = result.policyVersion();
                            allowedCount.incrementAndGet();
                        } catch (AccessDeniedException e) {
                            allowed = false;
                            responseVersion = e.policyVersion();
                            reason = e.reason();
                            deniedCount.incrementAndGet();
                            denyReasonCounts.computeIfAbsent(reason.name(),
                                    k -> new AtomicInteger()).incrementAndGet();
                        }

                        // 校验 1：审计必须存在，且与响应同版本
                        AuditRecord audit = auditService.findByRequestId(requestId).orElse(null);
                        if (audit == null) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-missing-audit", "audit missing");
                            continue;
                        }
                        if (!audit.policyVersion().equals(responseVersion)) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-version-mismatch",
                                    "response=" + responseVersion + " audit=" + audit.policyVersion());
                        }
                        if (audit.allowed() != allowed) {
                            failures.incrementAndGet();
                            failureMessages.put(requestId + "-decision-mismatch",
                                    "response allowed=" + allowed + " audit allowed=" + audit.allowed());
                        }

                        // 校验 2：无论当时读到哪个版本，判定结果必须自洽
                        PolicySnapshot snap = null;
                        // 用审计版本对应的规则语义复核（v1..vN 规则语义一致）
                        if (useRole.equals("UNAUTH_ROLE")) {
                            if (allowed || reason != DenyReason.POLICY_NO_MATCH) {
                                failures.incrementAndGet();
                                failureMessages.put(requestId + "-unauth",
                                        "unauth role allowed or wrong reason: " + reason);
                            }
                        } else {
                            if (!allowed) {
                                failures.incrementAndGet();
                                failureMessages.put(requestId + "-spurious-deny",
                                        "known role denied with " + reason);
                            }
                        }
                    }
                } catch (Throwable t) {
                    failures.incrementAndGet();
                    failureMessages.put("reader-" + role, t.toString());
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

        int totalRequests = readerThreads * requestsPerReader;
        log.info("concurrency test: input={} readers x{} requests during v1->v{} updates "
                        + "(with rollback attempts), basis='快照一致性+版本归属+幂等审计': "
                        + "allowed={}, denied={}, denyReasons={}, rollbackRejected={}, "
                        + "auditCount={}, failures={}",
                readerThreads, requestsPerReader, versions,
                allowedCount.get(), deniedCount.get(), denyReasonCounts,
                rollbackRejections.get(), auditService.all().size(), failures.get());

        assertEquals(0, failures.get(), () -> failureMessages.toString());
        assertEquals(totalRequests, auditService.all().size(), "每个请求恰好一条审计");
        assertEquals(totalRequests, allowedCount.get() + deniedCount.get());
        assertEquals(versions - 1, rollbackRejections.get(), "每次回退尝试都必须被拒绝");
        assertEquals("v" + versions, policyStore.current().version());
        // 越权请求的拒绝原因稳定且唯一
        long unauthRequests = readerThreads * (requestsPerReader / 10);
        assertEquals(unauthRequests,
                denyReasonCounts.getOrDefault(DenyReason.POLICY_NO_MATCH.name(),
                        new AtomicInteger()).get());
        assertFalse(denyReasonCounts.containsKey(DenyReason.FIELD_FORBIDDEN.name()),
                "本场景 GUEST 的字段级越权应表现为剥离后放行，而非整体拒绝");
        assertTrue(auditService.all().stream().allMatch(a -> a.policyVersion() != null));
    }
}
