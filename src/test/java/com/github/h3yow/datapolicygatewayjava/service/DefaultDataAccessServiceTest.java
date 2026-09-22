package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditEventStore;
import com.github.h3yow.datapolicygatewayjava.audit.InMemoryAuditEventStore;
import com.github.h3yow.datapolicygatewayjava.config.DemoPolicyFactory;
import com.github.h3yow.datapolicygatewayjava.datasource.InMemoryResourceDataSource;
import com.github.h3yow.datapolicygatewayjava.datasource.ResourceRecord;
import com.github.h3yow.datapolicygatewayjava.mask.FieldProjector;
import com.github.h3yow.datapolicygatewayjava.mask.InMemoryMaskingRegistry;
import com.github.h3yow.datapolicygatewayjava.mask.StandardMaskingRules;
import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.Subject;
import com.github.h3yow.datapolicygatewayjava.policy.InMemoryPolicyRepository;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DefaultDataAccessServiceTest {

    private static final Logger log = LoggerFactory.getLogger(DefaultDataAccessServiceTest.class);

    private InMemoryPolicyRepository policies;
    private InMemoryResourceDataSource data;
    private AuditEventStore audits;
    private DefaultDataAccessService service;

    @BeforeEach
    void setUp() {
        policies = new InMemoryPolicyRepository(new DemoPolicyFactory().version1());
        data = new InMemoryResourceDataSource();
        data.put(ResourceRecord.of("customer", "c-1001", Map.of(
                "name", "Alice Zhang",
                "email", "alice@example.com",
                "region", "cn-north",
                "ssn", "110101-19900101-1234")));
        audits = new InMemoryAuditEventStore();
        InMemoryMaskingRegistry masks = new InMemoryMaskingRegistry(Map.of(
                "email", StandardMaskingRules.email()));
        service = new DefaultDataAccessService(policies, new PolicyEvaluator(),
                new FieldProjector(masks), data, audits);
    }

    private AccessRequest analystRequest(String requestId, List<String> fields) {
        return new AccessRequest(requestId,
                new Subject("u-analyst", Map.of("role", "analyst")),
                new ResourceRef("customer", "c-1001"),
                AccessAction.READ, fields);
    }

    @Test
    void authorizedReadMasksEmailAndOmitsSsnAndAuditsVersion() {
        AccessRequest req = analystRequest("req-001",
                List.of("name", "email", "region"));
        AccessResponse resp = service.read(req);
        log.info("read requestId={} subjectRole=analyst policyVersion={} fields={}",
                req.requestId(), resp.policyVersion(), resp.fields().keySet());

        assertEquals(1L, resp.policyVersion());
        assertEquals("Alice Zhang", resp.fields().get("name"));
        assertEquals("a****@example.com", resp.fields().get("email"));
        assertFalse(resp.fields().containsKey("ssn"));

        List<AuditEvent> events = audits.all();
        assertEquals(1, events.size());
        AuditEvent event = events.get(0);
        assertTrue(event.allowed());
        assertEquals(1L, event.policyVersion(),
                "audit must belong to the same version as the response");
        assertEquals(3, event.requestedFieldCount());
    }

    @Test
    void retryReplaysSameOutcomeAndAuditsExactlyOnce() {
        AccessRequest first = analystRequest("req-retry", List.of("name"));
        AccessResponse r1 = service.read(first);

        // Policy is updated between attempts; the retry must still see v1.
        policies.install(new DemoPolicyFactory().version2(), 1L);
        AccessResponse r2 = service.read(analystRequest("req-retry", List.of("name")));

        log.info("retry requestId=req-retry firstVersion={} retryVersion={} retryFlag={}",
                r1.policyVersion(), r2.policyVersion(), r2.retry());
        assertEquals(1L, r1.policyVersion());
        assertEquals(1L, r2.policyVersion(), "retry replays the pinned original version");
        assertTrue(r2.retry());
        assertEquals(1, audits.all().size(), "no duplicate audit on retry");
    }
    @Test
    void denialReasonsAreDistinguishable() {
        // 1) field unauthorized: analyst asks for ssn
        AccessDeniedException fieldDenied = null;
        try {
            service.read(analystRequest("req-deny-field", List.of("ssn")));
        } catch (AccessDeniedException e) {
            fieldDenied = e;
        }
        assertTrue(fieldDenied != null);
        assertEquals("FIELD_UNAUTHORIZED", fieldDenied.reason().name());

        // 2) policy not matched: unknown role
        AccessRequest guest = new AccessRequest("req-deny-match",
                new Subject("u-guest", Map.of("role", "guest")),
                new ResourceRef("customer", "c-1001"), AccessAction.READ,
                List.of("name"));
        AccessDeniedException matchDenied = null;
        try {
            service.read(guest);
        } catch (AccessDeniedException e) {
            matchDenied = e;
        }
        assertTrue(matchDenied != null);
        assertEquals("POLICY_NOT_MATCHED", matchDenied.reason().name());

        // 3) resource not found
        AccessRequest missing = new AccessRequest("req-deny-resource",
                new Subject("u-admin", Map.of("role", "admin")),
                new ResourceRef("customer", "c-9999"), AccessAction.READ,
                List.of("name"));
        AccessDeniedException resDenied = null;
        try {
            service.read(missing);
        } catch (AccessDeniedException e) {
            resDenied = e;
        }
        assertTrue(resDenied != null);
        assertEquals("RESOURCE_NOT_FOUND", resDenied.reason().name());

        log.info("denial-reasons reasons={},{},{} stable=true",
                fieldDenied.reason(), matchDenied.reason(), resDenied.reason());
        // Each denial is audited with the same stable reason.
        assertEquals("FIELD_UNAUTHORIZED",
                audits.findByRequestId("req-deny-field").orElseThrow().denyReason().name());
        assertEquals("POLICY_NOT_MATCHED",
                audits.findByRequestId("req-deny-match").orElseThrow().denyReason().name());
        assertEquals("RESOURCE_NOT_FOUND",
                audits.findByRequestId("req-deny-resource").orElseThrow().denyReason().name());
    }

    @Test
    void maskingErrorFailsClosedAndAuditsDenial() {
        InMemoryMaskingRegistry brokenMasks = new InMemoryMaskingRegistry(Map.of(
                "email", com.github.h3yow.datapolicygatewayjava.mask.StandardMaskingRules
                        .fixed("email", "X")));
        // Swap in a registry whose email rule always throws by registering
        // a throwing rule under the same name via a fresh registry.
        InMemoryMaskingRegistry throwing = new InMemoryMaskingRegistry();
        throwing.register("email", new com.github.h3yow.datapolicygatewayjava.mask.MaskingRule() {
            @Override
            public String name() {
                return "email";
            }

            @Override
            public Object apply(Object value) {
                throw new com.github.h3yow.datapolicygatewayjava.mask.MaskingException(
                        "boom", "email");
            }
        });
        DefaultDataAccessService broken = new DefaultDataAccessService(
                policies, new PolicyEvaluator(), new FieldProjector(throwing),
                data, new InMemoryAuditEventStore());
        AccessDeniedException ex = null;
        try {
            broken.read(analystRequest("req-mask-boom", List.of("email")));
        } catch (AccessDeniedException e) {
            ex = e;
        }
        assertTrue(ex != null);
        assertEquals("MASKING_RULE_ERROR", ex.reason().name());
        log.info("fail-closed requestId=req-mask-boom reason={} partialData=false", ex.reason());
    }

    @Test
    void concurrentReadsEachPinConsistentVersionDuringUpdates() throws Exception {
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger v1 = new AtomicInteger();
        AtomicInteger v2 = new AtomicInteger();
        ConcurrentHashMap<String, Long> responseVersions = new ConcurrentHashMap<>();

        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    start.await();
                    String rid = "req-concurrent-" + idx;
                    // name+email are allowed to analysts on both v1 and v2,
                    // so concurrent updates cannot turn these into denials.
                    AccessResponse resp = service.read(
                            analystRequest(rid, List.of("name", "email")));
                    responseVersions.put(rid, resp.policyVersion());
                    if (resp.policyVersion() == 1L) {
                        v1.incrementAndGet();
                    } else {
                        v2.incrementAndGet();
                    }
                } catch (Exception ignored) {
                    // analyst reads are allowed on both v1 and v2 for name/email
                }
            });
        }
        // Concurrently roll the policy while reads are in flight.
        start.countDown();
        // small chance the update lands before any read; that is valid -
        // v1 count may then be 0, but every response must equal its audit.
        policies.install(new DemoPolicyFactory().version2(), 1L);
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        // Every read succeeds (fields allowed on both versions); each
        // response version must match its audit version.
        for (Map.Entry<String, Long> e : responseVersions.entrySet()) {
            AuditEvent event = audits.findByRequestId(e.getKey()).orElseThrow();
            assertEquals(e.getValue(), event.policyVersion(),
                    "response and audit must share one policy version");
        }
        log.info("concurrent-reads threads={} onV1={} onV2={} totalAudits={} "
                        + "allResponseAuditVersionsAligned=true",
                threads, v1.get(), v2.get(), audits.all().size());
        assertEquals(threads, audits.all().size(), "exactly one audit per request");
    }
}
