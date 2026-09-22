package com.github.h3yow.datapolicygatewayjava.policy;

/**
 * 策略版本更新非法（回退或指向未知版本）。
 */
public class PolicyVersionException extends RuntimeException {
    public PolicyVersionException(String message) {
        super(message);
    }
}
