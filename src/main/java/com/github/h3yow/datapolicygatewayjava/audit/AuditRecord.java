package com.github.h3yow.datapolicygatewayjava.audit;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

import java.time.Instant;

/**
 * 审计记录：只记录判定元数据，绝不记录字段值。
 */
public record AuditRecord(String requestId,
                          Instant timestamp,
                          String subjectId,
                          String resourceType,
                          String resourceId,
                          String action,
                          String policyVersion,
                          String matchedRuleId,
                          boolean allowed,
                          DenyReason denyReason,
                          String reasonDetail) {
}
