package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.audit.AuditEventStore;
import com.github.h3yow.datapolicygatewayjava.datasource.ResourceDataSource;
import com.github.h3yow.datapolicygatewayjava.datasource.ResourceRecord;
import com.github.h3yow.datapolicygatewayjava.mask.FieldProjector;
import com.github.h3yow.datapolicygatewayjava.mask.ProjectionException;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.EvaluationResult;
import com.github.h3yow.datapolicygatewayjava.model.Policy;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * Default {@link DataAccessService}.
 *
 * <p>Request lifecycle (each step is fail-closed):
 * <ol>
 *   <li>Deduplicate on {@code requestId}: concurrent duplicate deliveries
 *       coalesce onto one execution; retries replay the stored outcome and
 *       never produce a second audit record.</li>
 *   <li>Pin one immutable {@link Policy} snapshot. Every later step, and
 *       the audit record, uses that same version.</li>
 *   <li>Load the resource, resolve the requested field list, evaluate.</li>
 *   <li>Project (mask) fields. Any mapping/masking failure denies the
 *       whole request — partial payloads are impossible.</li>
 *   <li>Append exactly one {@link AuditEvent}, then return.</li>
 * </ol>
 */
public class DefaultDataAccessService implements DataAccessService {

    private static final Logger log = LoggerFactory.getLogger(DefaultDataAccessService.class);

    private final PolicyRepository policyRepository;
    private final PolicyEvaluator evaluator;
    private final FieldProjector projector;
    private final ResourceDataSource dataSource;
    private final AuditEventStore auditStore;

    private final ConcurrentHashMap<String, CompletableFuture<Outcome>> inflight =
            new ConcurrentHashMap<>();
    /** Terminal outcomes for replay by retries. Same version + same data. */
    private final ConcurrentHashMap<String, Outcome> completed =
            new ConcurrentHashMap<>();

    public DefaultDataAccessService(PolicyRepository policyRepository,
                                    PolicyEvaluator evaluator,
                                    FieldProjector projector,
                                    ResourceDataSource dataSource,
                                    AuditEventStore auditStore) {
        this.policyRepository = Objects.requireNonNull(policyRepository);
        this.evaluator = Objects.requireNonNull(evaluator);
        this.projector = Objects.requireNonNull(projector);
        this.dataSource = Objects.requireNonNull(dataSource);
        this.auditStore = Objects.requireNonNull(auditStore);
    }

    @Override
    public AccessResponse read(AccessRequest request) {
        Objects.requireNonNull(request, "request");

        // Completed retry: replay the exact terminal outcome without any
        // second evaluation or audit append.
        Outcome cached = completed.get(request.requestId());
        if (cached != null) {
            logReplay(request, cached);
            return toResponse(request, cached, true);
        }

        // Concurrent duplicate: coalesce onto the first execution so only
        // one of the racing threads evaluates and audits.
        CompletableFuture<Outcome> mine = new CompletableFuture<>();
        CompletableFuture<Outcome> existing = inflight.putIfAbsent(request.requestId(), mine);
        try {
            Outcome outcome;
            boolean retry;
            if (existing == null) {
                // Re-check under ownership: the previous owner may have
                // finished (published to completed) in the window above.
                Outcome raced = completed.get(request.requestId());
                if (raced != null) {
                    inflight.remove(request.requestId(), mine);
                    logReplay(request, raced);
                    return toResponse(request, raced, true);
                }
                retry = false;
                try {
                    outcome = execute(request);
                } catch (RuntimeException ex) {
                    mine.completeExceptionally(ex);
                    throw ex;
                }
                completed.put(request.requestId(), outcome);
                mine.complete(outcome);
            } else {
                retry = true;
                outcome = joinOutcome(request.requestId(), existing);
            }
            return toResponse(request, outcome, retry);
        } finally {
            // Only the owner removes its (completed) future.
            if (existing == null) {
                inflight.remove(request.requestId(), mine);
            }
        }
    }

    private void logReplay(AccessRequest request, Outcome outcome) {
        log.info("policy-decision-replay requestId={} subjectId={} resource={} action={} "
                        + "policyVersion={} allowed={} denyReason={} matchedRule={} "
                        + "requestedFieldCount={} allowedFieldCount={} basis={}",
                request.requestId(), request.subject().id(),
                request.resource().canonical(), request.action(),
                outcome.policyVersion(), outcome.denyReason() == null,
                outcome.denyReason(), outcome.matchedRuleId(),
                outcome.requestedFieldCount(), outcome.allowedFieldCount(),
                outcome.basis());
    }

    private Outcome joinOutcome(String requestId, CompletableFuture<Outcome> future) {
        try {
            return future.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AccessDeniedException(DenyReason.EVALUATION_FAILED, -1L, requestId,
                    "interrupted while waiting for in-flight request");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof AccessDeniedException ade) {
                throw ade;
            }
            throw new AccessDeniedException(DenyReason.EVALUATION_FAILED, -1L, requestId,
                    "in-flight request failed");
        }
    }

    private AccessResponse toResponse(AccessRequest request, Outcome outcome, boolean retry) {
        if (outcome.denyReason() != null) {
            throw new AccessDeniedException(outcome.denyReason(),
                    outcome.policyVersion(), request.requestId(),
                    "access denied: " + outcome.denyReason());
        }
        return new AccessResponse(request.requestId(), request.resource(),
                outcome.policyVersion(), retry, outcome.fields());
    }

    private Outcome execute(AccessRequest request) {
        // 1) Pin policy version BEFORE any observation.
        Policy policy = policyRepository.pin();
        long version = policy.version();

        // 2) Load data first so "all fields" can be expanded; missing
        //    resource is a distinguishable, auditable denial.
        Optional<ResourceRecord> loaded = dataSource.load(request.resource());
        if (loaded.isEmpty()) {
            return denyAndAudit(request, version, DenyReason.RESOURCE_NOT_FOUND,
                    null, 0, "resource not found");
        }
        ResourceRecord record = loaded.get();

        List<String> requestedFields = request.fields().isEmpty()
                ? new ArrayList<>(record.data().keySet())
                : request.fields();
        AccessRequest effective = request.fields().isEmpty()
                ? new AccessRequest(request.requestId(), request.subject(),
                request.resource(), request.action(), requestedFields)
                : request;

        // 3) Evaluate against the pinned snapshot.
        EvaluationResult evaluation;
        try {
            evaluation = evaluator.evaluate(effective, policy);
        } catch (RuntimeException ex) {
            return denyAndAudit(effective, version, DenyReason.EVALUATION_FAILED,
                    null, requestedFields.size(), "evaluator threw");
        }
        if (!evaluation.allowed()) {
            return denyAndAudit(effective, version, evaluation.denyReason(),
                    null, requestedFields.size(), evaluation.basis());
        }

        // 4) Project (mask) with fail-closed semantics. Build fully before
        //    auditing/returning so partial data can never escape.
        Map<String, Object> projected;
        try {
            projected = projector.project(record.data(), requestedFields, evaluation);
        } catch (ProjectionException ex) {
            return denyAndAudit(effective, version, ex.reason(),
                    null, requestedFields.size(), ex.getMessage());
        } catch (RuntimeException ex) {
            return denyAndAudit(effective, version, DenyReason.MASKING_RULE_ERROR,
                    null, requestedFields.size(), "projection failed unexpectedly");
        }

        int allowedCount = (int) evaluation.verdicts().stream()
                .filter(v -> v.effect() != null).count();
        Outcome ok = new Outcome(version, null, projected, evaluation.matchedRuleId(),
                requestedFields.size(), allowedCount, evaluation.basis());
        audit(request, version, true, null, evaluation.matchedRuleId(),
                requestedFields.size(), allowedCount, evaluation.basis());
        return ok;
    }

    private Outcome denyAndAudit(AccessRequest request, long version, DenyReason reason,
                                 String matchedRuleId, int requestedFieldCount,
                                 String basis) {
        audit(request, version, false, reason, matchedRuleId,
                requestedFieldCount, 0, basis);
        return new Outcome(version, reason, Map.of(), matchedRuleId,
                requestedFieldCount, 0, basis);
    }

    private void audit(AccessRequest request, long version, boolean allowed,
                       DenyReason reason, String matchedRuleId,
                       int requestedFieldCount, int allowedFieldCount, String basis) {
        AuditEvent event = new AuditEvent(
                request.requestId(), 0L, false, Instant.now(),
                request.subject(), request.resource(), request.action(),
                version, allowed, reason, matchedRuleId,
                requestedFieldCount, allowedFieldCount, basis);
        auditStore.append(event);
        // Structured decision log: input coordinates + version + basis.
        // Deliberately no field values and no denied field names.
        log.info("policy-decision requestId={} subjectId={} resource={} action={} "
                        + "policyVersion={} allowed={} denyReason={} matchedRule={} "
                        + "requestedFieldCount={} allowedFieldCount={} basis={}",
                request.requestId(), request.subject().id(),
                request.resource().canonical(), request.action(),
                version, allowed, reason, matchedRuleId,
                requestedFieldCount, allowedFieldCount, basis);
    }

    /**
     * Terminal outcome of one request execution. Retries replay this exact
     * object (same policy version, same projected fields) guaranteeing
     * response/audit consistency and reproducibility.
     */
    private record Outcome(
            long policyVersion,
            DenyReason denyReason,
            Map<String, Object> fields,
            String matchedRuleId,
            int requestedFieldCount,
            int allowedFieldCount,
            String basis
    ) {
    }
}
