package com.github.h3yow.datapolicygatewayjava.mask;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.EvaluationResult;
import com.github.h3yow.datapolicygatewayjava.model.FieldEffect;
import com.github.h3yow.datapolicygatewayjava.model.FieldVerdict;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Projects raw resource data into the response payload.
 *
 * <p>Guarantees:
 * <ul>
 *   <li>Only fields present in the allowed evaluation are emitted; denied
 *       fields cannot appear because they are never iterated.</li>
 *   <li>A field declared visible but absent from the raw mapping aborts the
 *       whole response with {@link ProjectionException}
 *       ({@link DenyReason#FIELD_MAPPING_MISSING}): no partial data.</li>
 *   <li>Any masking failure aborts the whole response with
 *       {@link DenyReason#MASKING_RULE_ERROR}: no partial/unmasked data.</li>
 * </ul>
 */
public class FieldProjector {

    private final MaskingRegistry registry;

    public FieldProjector(MaskingRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    /**
     * Fail-closed projection.
     *
     * @throws ProjectionException FIELD_MAPPING_MISSING / MASKING_RULE_ERROR
     */
    public Map<String, Object> project(Map<String, Object> rawData,
                                       List<String> allowedFields,
                                       EvaluationResult evaluation) {
        Objects.requireNonNull(rawData, "rawData");
        Objects.requireNonNull(evaluation, "evaluation");
        if (!evaluation.allowed()) {
            throw new IllegalArgumentException("projection requires an allowed evaluation");
        }
        Map<String, FieldVerdict> verdictByField = new LinkedHashMap<>();
        for (FieldVerdict v : evaluation.verdicts()) {
            verdictByField.put(v.field(), v);
        }

        // Build into a local map first; it is only returned after every
        // field succeeded, so callers can never observe partial output.
        Map<String, Object> projected = new LinkedHashMap<>();
        for (String field : allowedFields) {
            FieldVerdict verdict = verdictByField.get(field);
            if (verdict == null || verdict.effect() == FieldEffect.DENY) {
                // Defensive in depth: service layer denies earlier. Name is
                // intentionally not included in the outward message.
                throw new ProjectionException(DenyReason.FIELD_UNAUTHORIZED,
                        "unauthorized field encountered during projection");
            }
            if (!rawData.containsKey(field)) {
                throw new ProjectionException(DenyReason.FIELD_MAPPING_MISSING,
                        "field mapping missing in resource data");
            }
            Object rawValue = rawData.get(field);
            if (verdict.effect() == FieldEffect.ALLOW) {
                projected.put(field, rawValue);
            } else if (verdict.effect() == FieldEffect.MASK) {
                try {
                    MaskingRule rule = registry.resolve(verdict.maskName());
                    projected.put(field, rule.apply(rawValue));
                } catch (MaskingException e) {
                    throw new ProjectionException(DenyReason.MASKING_RULE_ERROR,
                            "masking rule could not be applied");
                } catch (RuntimeException e) {
                    throw new ProjectionException(DenyReason.MASKING_RULE_ERROR,
                            "masking rule failed unexpectedly");
                }
            }
        }
        return Map.copyOf(projected);
    }
}
