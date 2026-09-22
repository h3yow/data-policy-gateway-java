package com.github.h3yow.datapolicygatewayjava.mask;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.EvaluationResult;
import com.github.h3yow.datapolicygatewayjava.model.FieldEffect;
import com.github.h3yow.datapolicygatewayjava.model.FieldVerdict;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FieldProjectorTest {

    private static final Logger log = LoggerFactory.getLogger(FieldProjectorTest.class);

    private final InMemoryMaskingRegistry registry =
            new InMemoryMaskingRegistry(Map.of(
                    "email", StandardMaskingRules.email(),
                    "boom", new MaskingRule() {
                        @Override
                        public String name() {
                            return "boom";
                        }

                        @Override
                        public Object apply(Object value) {
                            throw new MaskingException("deliberate failure", "boom");
                        }
                    }));

    private EvaluationResult evaluation(FieldVerdict... verdicts) {
        return EvaluationResult.allow(1L, List.of(verdicts), "rule[priority=10,index=0]",
                "test basis");
    }

    @Test
    void projectsAllowedAndMaskedFieldsOnly() {
        EvaluationResult eval = evaluation(
                new FieldVerdict("name", FieldEffect.ALLOW, null, "rule effect=ALLOW"),
                new FieldVerdict("email", FieldEffect.MASK, "email", "rule effect=MASK mask=email"));
        FieldProjector projector = new FieldProjector(registry);
        Map<String, Object> raw = Map.of("name", "Alice", "email", "alice@example.com",
                "ssn", "secret");
        Map<String, Object> out = projector.project(raw, List.of("name", "email"), eval);
        log.info("project input-fields={} output={}", List.of("name", "email"), out);
        assertEquals("Alice", out.get("name"));
        assertEquals("a****@example.com", out.get("email"));
        assertFalse(out.containsKey("ssn"), "denied field must never be projected");
    }

    @Test
    void missingFieldMappingFailsClosed() {
        EvaluationResult eval = evaluation(
                new FieldVerdict("ghost", FieldEffect.ALLOW, null, "rule effect=ALLOW"));
        FieldProjector projector = new FieldProjector(registry);
        ProjectionException ex = assertThrows(ProjectionException.class,
                () -> projector.project(Map.of("name", "Alice"),
                        List.of("ghost"), eval));
        log.info("projection result=denied reason={}", ex.reason());
        assertEquals(DenyReason.FIELD_MAPPING_MISSING, ex.reason());
    }

    @Test
    void maskingFailureFailsClosedWithNoPartialPayload() {
        EvaluationResult eval = evaluation(
                new FieldVerdict("name", FieldEffect.ALLOW, null, "rule effect=ALLOW"),
                new FieldVerdict("email", FieldEffect.MASK, "boom", "rule effect=MASK mask=boom"));
        FieldProjector projector = new FieldProjector(registry);
        ProjectionException ex = assertThrows(ProjectionException.class,
                () -> projector.project(
                        Map.of("name", "Alice", "email", "alice@example.com"),
                        List.of("name", "email"), eval));
        assertEquals(DenyReason.MASKING_RULE_ERROR, ex.reason());
        log.info("projection result=denied reason={} partialPayloadLeaked=false", ex.reason());
    }

    @Test
    void unknownMaskNameAtProjectionFailsClosed() {
        InMemoryMaskingRegistry empty = new InMemoryMaskingRegistry();
        EvaluationResult eval = evaluation(
                new FieldVerdict("email", FieldEffect.MASK, "ghost-rule",
                        "rule effect=MASK mask=ghost-rule"));
        FieldProjector projector = new FieldProjector(empty);
        ProjectionException ex = assertThrows(ProjectionException.class,
                () -> projector.project(Map.of("email", "a@b.com"),
                        List.of("email"), eval));
        assertEquals(DenyReason.MASKING_RULE_ERROR, ex.reason());
        assertTrue(ex.getMessage().contains("masking rule"));
    }
}
