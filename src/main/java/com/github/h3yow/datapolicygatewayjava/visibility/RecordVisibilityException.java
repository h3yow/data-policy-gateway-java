package com.github.h3yow.datapolicygatewayjava.visibility;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * 记录级可见性判定失败（失败关闭）。
 *
 * <p>触发情形：条件依赖字段在记录中不存在、条件本身无法求值、同一批记录结构不一致。
 * 异常消息只包含字段名/算子等元数据，绝不包含字段值。
 */
public class RecordVisibilityException extends RuntimeException {

    private final DenyReason reason;

    public RecordVisibilityException(DenyReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DenyReason reason() {
        return reason;
    }
}
