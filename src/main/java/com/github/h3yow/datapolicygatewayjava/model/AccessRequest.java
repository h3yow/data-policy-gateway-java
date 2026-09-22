package com.github.h3yow.datapolicygatewayjava.model;

/**
 * 一次数据访问请求。
 */
public record AccessRequest(String requestId,
                            SubjectAttributes subject,
                            ResourceRef resource,
                            AccessAction action) {
}
