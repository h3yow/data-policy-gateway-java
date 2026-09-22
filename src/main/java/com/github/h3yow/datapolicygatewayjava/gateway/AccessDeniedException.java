package com.github.h3yow.datapolicygatewayjava.gateway;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * 访问被拒绝。异常消息只含稳定的拒绝原因码，不含任何字段名/字段值。
 */
public class AccessDeniedException extends RuntimeException {

    private final DenyReason reason;
    private final String policyVersion;
    private final String requestId;

    public AccessDeniedException(String requestId,
                                 String policyVersion,
                                 DenyReason reason,
                                 String detail) {
        super(reason.name());
        this.requestId = requestId;
        this.policyVersion = policyVersion;
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }

    public String policyVersion() {
        return policyVersion;
    }

    public String requestId() {
        return requestId;
    }
}
