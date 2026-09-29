package com.github.h3yow.datapolicygatewayjava.gateway;

import com.github.h3yow.datapolicygatewayjava.model.AccessResult;

/**
 * 一次请求的最终判定输出（放行结果或拒绝），以 requestId 为键缓存后用于重放。
 *
 * <p>缓存的输出与首次审计记录属于同一策略版本；重试/重复提交时原样复现，
 * 不再重新求值、不重复审计。
 */
public sealed interface RequestOutcome permits RequestOutcome.Allowed, RequestOutcome.Denied {

    /** 首次判定放行。 */
    record Allowed(AccessResult result) implements RequestOutcome {
    }

    /** 首次判定拒绝。 */
    record Denied(String requestId,
                  String policyVersion,
                  com.github.h3yow.datapolicygatewayjava.model.DenyReason reason,
                  String detail) implements RequestOutcome {
    }
}
