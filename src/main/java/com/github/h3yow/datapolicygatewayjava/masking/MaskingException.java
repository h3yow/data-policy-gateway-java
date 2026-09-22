package com.github.h3yow.datapolicygatewayjava.masking;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * 脱敏执行异常。
 */
public class MaskingException extends RuntimeException {

    private final DenyReason reason;

    public MaskingException(DenyReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }
}
