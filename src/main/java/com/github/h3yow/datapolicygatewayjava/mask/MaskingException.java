package com.github.h3yow.datapolicygatewayjava.mask;

/**
 * Raised when a masking rule cannot be applied or configured.
 * Fail-closed callers map this to MASKING_RULE_ERROR.
 */
public class MaskingException extends RuntimeException {

    private final String maskName;

    public MaskingException(String message, String maskName) {
        super(message);
        this.maskName = maskName;
    }

    public MaskingException(String message, String maskName, Throwable cause) {
        super(message, cause);
        this.maskName = maskName;
    }

    public String maskName() {
        return maskName;
    }
}
