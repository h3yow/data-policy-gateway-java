package com.github.h3yow.datapolicygatewayjava.masking;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 脱敏规则单测：日志打印输入（测试环境为合成数据）、规则类型与判定依据。
 */
class MaskerTest {

    private static final Logger log = LoggerFactory.getLogger(MaskerTest.class);

    private final Masker masker = new Masker();

    @Test
    void noneReturnsOriginalValue() {
        Object result = masker.mask("hello", MaskingType.NONE, Map.of());
        log.info("mask test: input='hello', rule=NONE, basis='原样返回', result='{}'", result);
        assertEquals("hello", result);
    }

    @Test
    void fullMaskReplacesEntireValue() {
        Object result = masker.mask("secret-value", MaskingType.FULL_MASK, Map.of());
        log.info("mask test: input='secret-value', rule=FULL_MASK, basis='整体替换', result='{}'", result);
        assertEquals("****", result);
        assertFalse("secret-value".equals(result));
    }

    @Test
    void partialMaskKeepsPrefixAndSuffix() {
        String id = "110101199001011234";
        Object result = masker.mask(id, MaskingType.PARTIAL_MASK,
                Map.of("prefix", "4", "suffix", "4"));
        log.info("mask test: input='{}', rule=PARTIAL_MASK(prefix=4,suffix=4), "
                + "basis='保留前4后4', result='{}'", id, result);
        assertEquals("1101" + "*".repeat(id.length() - 8) + "1234", result);
        assertFalse(result.toString().contains("19900101"));
    }

    @Test
    void hashIsStableAndIrreversible() {
        Object r1 = masker.mask("13800001111", MaskingType.HASH, Map.of());
        Object r2 = masker.mask("13800001111", MaskingType.HASH, Map.of());
        log.info("mask test: input='13800001111', rule=HASH, basis='SHA-256 稳定哈希', result='{}'", r1);
        assertEquals(r1, r2, "相同输入哈希必须稳定可复现");
        assertEquals(64, r1.toString().length());
        assertFalse(r1.toString().contains("1380000"));
    }

    @Test
    void nullValueRemainsNull() {
        assertNull(masker.mask(null, MaskingType.FULL_MASK, Map.of()));
    }

    @Test
    void partialMaskFailsClosedWhenParamsMissing() {
        MaskingException ex = assertThrows(MaskingException.class,
                () -> masker.mask("13800001111", MaskingType.PARTIAL_MASK, Map.of()));
        log.info("mask test: input='13800001111', rule=PARTIAL_MASK, basis='参数缺失失败关闭', "
                + "denyReason={}", ex.reason());
        assertEquals(DenyReason.MASKING_FAILED, ex.reason());
    }

    @Test
    void partialMaskFailsClosedWhenCoverageTooLarge() {
        // 保留范围几乎覆盖全部 -> 内容可还原，必须失败关闭而不是近似明文返回
        MaskingException ex = assertThrows(MaskingException.class,
                () -> masker.mask("ab", MaskingType.PARTIAL_MASK,
                        Map.of("prefix", "1", "suffix", "1")));
        log.info("mask test: input='ab', rule=PARTIAL_MASK(prefix=1,suffix=1), "
                + "basis='保留范围过大失败关闭', denyReason={}", ex.reason());
        assertEquals(DenyReason.MASKING_FAILED, ex.reason());
        assertTrue(ex.getMessage() != null && !ex.getMessage().contains("ab"));
    }
}
