package com.github.h3yow.datapolicygatewayjava.mask;

import com.github.h3yow.datapolicygatewayjava.mask.MaskingException;
import com.github.h3yow.datapolicygatewayjava.mask.MaskingRule;
import com.github.h3yow.datapolicygatewayjava.mask.StandardMaskingRules;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class StandardMaskingRulesTest {

    private static final Logger log = LoggerFactory.getLogger(StandardMaskingRulesTest.class);

    @Test
    void tailKeepMasksHeadAndKeepsTail() {
        MaskingRule rule = StandardMaskingRules.tailKeep(4);
        Object out = rule.apply("110101-1234");
        log.info("test-input rule={} in=110101-1234 out={}", rule.name(), out);
        assertEquals("*******1234", out);
    }

    @Test
    void headKeepMasksTailAndKeepsHead() {
        MaskingRule rule = StandardMaskingRules.headKeep(2);
        Object out = rule.apply("Alice Zhang");
        log.info("test-input rule={} in=AliceZhang out={}", rule.name(), out);
        assertEquals("Al*********", out);
    }

    @Test
    void emailKeepsFirstCharAndDomain() {
        MaskingRule rule = StandardMaskingRules.email();
        Object out = rule.apply("alice@example.com");
        log.info("test-input rule={} out={}", rule.name(), out);
        assertEquals("a****@example.com", out);
    }

    @Test
    void nulledReturnsNullAndFixedReturnsToken() {
        assertNull(StandardMaskingRules.nulled().apply("anything"));
        assertEquals("REDACTED",
                StandardMaskingRules.fixed("redacted", "REDACTED").apply("x"));
    }

    @Test
    void nullInputStaysNullForAllRules() {
        for (MaskingRule rule : new MaskingRule[]{
                StandardMaskingRules.tailKeep(4),
                StandardMaskingRules.headKeep(2),
                StandardMaskingRules.email()}) {
            assertNull(rule.apply(null));
        }
    }
}
