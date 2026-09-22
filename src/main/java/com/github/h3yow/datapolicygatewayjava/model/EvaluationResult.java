package com.github.h3yow.datapolicygatewayjava.model;

import java.util.List;
import java.util.Objects;

/**
 * Result of evaluating a request against one pinned policy version.
 *
 * <p>Either all requested fields are visible (possibly masked), or the
 * result is a denial carrying a stable {@link DenyReason}. A denied result
 * contains no field values and no denied field names.
 */
public record EvaluationResult(
        long policyVersion,
        boolean allowed,
        DenyReason denyReason,
        List<FieldVerdict> verdicts,
        String matchedRuleId,
        String basis
) {

    public EvaluationResult {
        Objects.requireNonNull(verdicts, "verdicts");
        verdicts = List.copyOf(verdicts);
    }

    public static EvaluationResult allow(long version, List<FieldVerdict> verdicts,
                                         String matchedRuleId, String basis) {
        return new EvaluationResult(version, true, null, verdicts, matchedRuleId, basis);
    }

    public static EvaluationResult deny(long version, DenyReason reason, String basis) {
        Objects.requireNonNull(reason, "denyReason");
        return new EvaluationResult(version, false, reason, List.of(), null, basis);
    }
}
