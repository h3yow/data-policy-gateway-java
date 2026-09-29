package com.github.h3yow.datapolicygatewayjava.gateway;

import com.github.h3yow.datapolicygatewayjava.audit.AuditRecord;
import com.github.h3yow.datapolicygatewayjava.audit.AuditService;
import com.github.h3yow.datapolicygatewayjava.data.DataAccessException;
import com.github.h3yow.datapolicygatewayjava.data.DataSource;
import com.github.h3yow.datapolicygatewayjava.masking.Masker;
import com.github.h3yow.datapolicygatewayjava.masking.MaskingException;
import com.github.h3yow.datapolicygatewayjava.model.AccessDecision;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.FieldDecision;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicySnapshot;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import com.github.h3yow.datapolicygatewayjava.policy.RecordVisibilityEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.RecordVisibilityResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 数据访问策略执行入口。
 *
 * <p>记录级可见性与字段级授权在<b>同一次求值、同一份策略快照</b>下共同生效：
 * <ol>
 *   <li>从 {@link PolicyStore} 抓取一个不可变快照；无策略可用 → 失败关闭；</li>
 *   <li>从数据源取数（原始数据不离开本组件），用同一快照做字段级求值；
 *       整体拒绝（无匹配/映射缺失）→ 审计后拒绝，不产出任何记录；</li>
 *   <li>用同一快照下命中规则的记录级条件过滤记录：不满足条件的记录整条消失；
 *       条件无法求值（依赖字段缺失、结构不一致等）→ {@code RECORD_CONDITION_UNEVALUABLE}
 *       整单失败关闭，绝不只返回一部分能算出来的记录；</li>
 *   <li>对过滤后保留的记录逐字段剥离/脱敏：显式禁止字段剥离，脱敏异常失败关闭；</li>
 *   <li>无论放行还是拒绝，首次执行以 requestId 幂等写一条与响应<b>同版本</b>的审计记录；</li>
 *   <li>同一 requestId 的重复提交/重试（含并发）由 {@link ResponseReplayStore} 重放首次
 *       输出——同样的可见记录、脱敏结果或拒绝原因，不重新求值、不重复审计。</li>
 * </ol>
 */
@Component
public class DataAccessGateway {

    private static final Logger log = LoggerFactory.getLogger(DataAccessGateway.class);

    private final PolicyStore policyStore;
    private final PolicyEvaluator evaluator;
    private final RecordVisibilityEvaluator recordEvaluator;
    private final Masker masker;
    private final AuditService auditService;
    private final List<DataSource> dataSources;
    private final ResponseReplayStore replayStore;

    @Autowired
    public DataAccessGateway(PolicyStore policyStore,
                             PolicyEvaluator evaluator,
                             RecordVisibilityEvaluator recordEvaluator,
                             Masker masker,
                             AuditService auditService,
                             List<DataSource> dataSources,
                             ResponseReplayStore replayStore) {
        this.policyStore = policyStore;
        this.evaluator = evaluator;
        this.recordEvaluator = recordEvaluator;
        this.masker = masker;
        this.auditService = auditService;
        this.dataSources = dataSources;
        this.replayStore = replayStore;
    }

    /** 不含记录级/重放组件的便捷构造器（测试/旧装配使用，内部创建默认实例）。 */
    public DataAccessGateway(PolicyStore policyStore,
                             PolicyEvaluator evaluator,
                             Masker masker,
                             AuditService auditService,
                             List<DataSource> dataSources) {
        this(policyStore, evaluator, new RecordVisibilityEvaluator(), masker,
                auditService, dataSources, new ResponseReplayStore());
    }

    public AccessResult execute(AccessRequest request) {
        validate(request);
        log.info("access request received: requestId={}, subjectId={}, resource={}/{}, action={}",
                request.requestId(), request.subject().subjectId(),
                request.resource().resourceType(), request.resource().resourceId(),
                request.action());

        // 单次执行 + 重放：同 requestId 的并发/重试只产生一次首次求值与一条审计
        RequestOutcome outcome = replayStore.computeIfAbsent(request.requestId(),
                () -> computeOutcome(request));
        return applyOutcome(request.requestId(), outcome);
    }

    private AccessResult applyOutcome(String requestId, RequestOutcome outcome) {
        if (outcome instanceof RequestOutcome.Allowed allowed) {
            return allowed.result();
        }
        RequestOutcome.Denied denied = (RequestOutcome.Denied) outcome;
        throw new AccessDeniedException(requestId, denied.policyVersion(),
                denied.reason(), denied.detail());
    }

    /**
     * 首次执行：抓取快照 → 取数 → 字段级判定 → 记录级过滤 → 字段剥离/脱敏 → 幂等审计。
     * 全程只引用一个快照，因此记录过滤结果、字段结果与审计必然属于同一策略版本。
     */
    private RequestOutcome computeOutcome(AccessRequest request) {
        // 1. 抓取快照：整次请求（记录过滤 + 字段结果 + 审计）只引用它
        PolicySnapshot snapshot = policyStore.current();
        if (snapshot == null) {
            return deny(request, null, null, DenyReason.EVALUATION_FAILED,
                    "no policy available");
        }
        String version = snapshot.version();

        // 2. 取数（原始数据不对外暴露）
        List<Map<String, Object>> rawRecords;
        try {
            DataSource source = findDataSource(request.resource().resourceType());
            rawRecords = source.fetch(request.resource());
        } catch (DataAccessException e) {
            return deny(request, version, null, DenyReason.EVALUATION_FAILED,
                    "data source error");
        }
        Set<String> requestedFields = collectFieldNames(rawRecords);

        // 3. 字段级判定（同一份快照）
        AccessDecision decision;
        try {
            decision = evaluator.evaluate(request.subject(), request.resource(),
                    request.action(), requestedFields, snapshot);
        } catch (RuntimeException e) {
            return deny(request, version, null, DenyReason.EVALUATION_FAILED,
                    "evaluation error");
        }
        log.info("policy decision basis: requestId={}, policyVersion={}, matchedRuleId={}, "
                        + "overallDenyReason={}",
                request.requestId(), version, decision.matchedRuleId(), decision.denyReason());

        // 4. 字段级整体拒绝（策略不匹配 / 映射缺失 / 求值失败）：不产出任何记录
        if (!decision.allowed()) {
            return deny(request, version, decision.matchedRuleId(),
                    decision.denyReason(), decision.reasonDetail());
        }
        PolicyRule matchedRule = findRule(snapshot, decision.matchedRuleId());

        // 5. 记录级可见性过滤（同一快照、同一命中规则的条件）
        RecordVisibilityCondition recordCondition = matchedRule == null
                ? null : matchedRule.recordCondition();
        RecordVisibilityResult recordResult;
        try {
            recordResult = recordEvaluator.evaluate(rawRecords, request.subject(),
                    recordCondition);
        } catch (RuntimeException e) {
            return deny(request, version, decision.matchedRuleId(),
                    DenyReason.RECORD_CONDITION_UNEVALUABLE,
                    "record condition evaluation error");
        }
        if (recordResult.failClosed()) {
            return deny(request, version, decision.matchedRuleId(),
                    DenyReason.RECORD_CONDITION_UNEVALUABLE, recordResult.reasonDetail());
        }

        // 6. 对可见记录逐字段剥离/脱敏；任一字段异常即整单失败关闭
        List<Map<String, Object>> safeRecords;
        try {
            safeRecords = applyDecision(decision, matchedRule, recordResult.visibleRecords());
        } catch (MaskingException e) {
            return deny(request, version, decision.matchedRuleId(),
                    DenyReason.MASKING_FAILED, "masking rule failed");
        } catch (RuntimeException e) {
            return deny(request, version, decision.matchedRuleId(),
                    DenyReason.EVALUATION_FAILED, "field processing error");
        }

        // 7. 放行 + 幂等审计（与响应同版本、同规则）
        AuditRecord record = new AuditRecord(request.requestId(), Instant.now(),
                request.subject().subjectId(), request.resource().resourceType(),
                request.resource().resourceId(), request.action().name(),
                version, decision.matchedRuleId(), true, null, "allowed");
        boolean firstWrite = auditService.record(record);
        log.info("access allowed: requestId={}, policyVersion={}, matchedRuleId={}, "
                        + "recordCount={}, auditWritten={}",
                request.requestId(), version, decision.matchedRuleId(),
                safeRecords.size(), firstWrite);
        return new RequestOutcome.Allowed(new AccessResult(request.requestId(), version,
                true, null, null, decision.matchedRuleId(), safeRecords));
    }

    private RequestOutcome deny(AccessRequest request,
                                String version,
                                String matchedRuleId,
                                DenyReason reason,
                                String detail) {
        // 拒绝也必须审计；幂等保证重试不重复。重放路径不会进入本方法。
        AuditRecord record = new AuditRecord(request.requestId(), Instant.now(),
                request.subject() == null ? null : request.subject().subjectId(),
                request.resource() == null ? null : request.resource().resourceType(),
                request.resource() == null ? null : request.resource().resourceId(),
                request.action() == null ? null : request.action().name(),
                version, matchedRuleId, false, reason, detail);
        boolean firstWrite = auditService.record(record);
        // 日志只打印原因码，不打印字段名/字段值
        log.warn("access denied: requestId={}, policyVersion={}, reason={}, detail={}, "
                        + "auditWritten={}",
                request.requestId(), version, reason, detail, firstWrite);
        return new RequestOutcome.Denied(request.requestId(), version, reason, detail);
    }

    private List<Map<String, Object>> applyDecision(AccessDecision decision,
                                                    PolicyRule matchedRule,
                                                    List<Map<String, Object>> visibleRecords) {
        Map<String, FieldPolicy> policyByName = new LinkedHashMap<>();
        if (matchedRule != null) {
            for (FieldPolicy fp : matchedRule.fieldPolicies()) {
                policyByName.put(fp.fieldName(), fp);
            }
        }

        List<Map<String, Object>> result = new ArrayList<>(visibleRecords.size());
        for (Map<String, Object> raw : visibleRecords) {
            Map<String, Object> safe = new LinkedHashMap<>();
            for (Map.Entry<String, Object> entry : raw.entrySet()) {
                String field = entry.getKey();
                FieldDecision fd = decision.fields().get(field);
                if (fd == null) {
                    // 求值与取数之间字段集合不一致：失败关闭
                    throw new IllegalStateException("unevaluated field encountered");
                }
                if (!fd.allowed()) {
                    // 显式越权字段：直接剥离，值不进入响应、日志、异常
                    continue;
                }
                FieldPolicy fp = policyByName.get(field);
                Object value = entry.getValue();
                if (fp != null && fp.visible() && fp.maskingType() != null) {
                    value = masker.mask(value, fp.maskingType(), fp.maskingParams());
                }
                safe.put(field, value);
            }
            result.add(safe);
        }
        return result;
    }

    private PolicyRule findRule(PolicySnapshot snapshot, String ruleId) {
        if (ruleId == null) {
            return null;
        }
        for (PolicyRule rule : snapshot.definition().rules()) {
            if (ruleId.equals(rule.ruleId())) {
                return rule;
            }
        }
        return null;
    }

    private DataSource findDataSource(String resourceType) {
        for (DataSource source : dataSources) {
            if (source.supports(resourceType)) {
                return source;
            }
        }
        throw new DataAccessException("no data source for resource type: " + resourceType, null);
    }

    private Set<String> collectFieldNames(List<Map<String, Object>> records) {
        Set<String> names = new LinkedHashSet<>();
        for (Map<String, Object> row : records) {
            names.addAll(row.keySet());
        }
        return names;
    }

    private void validate(AccessRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        if (request.requestId() == null || request.requestId().isBlank()) {
            throw new IllegalArgumentException("requestId is required for idempotent audit");
        }
        if (request.subject() == null || request.resource() == null || request.action() == null) {
            throw new IllegalArgumentException("subject, resource and action are required");
        }
    }
}
