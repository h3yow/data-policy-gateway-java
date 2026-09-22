package com.github.h3yow.datapolicygatewayjava.web.dto;

import java.util.Map;

public record AccessResponseDto(
        String requestId,
        String resourceType,
        String resourceId,
        long policyVersion,
        boolean retry,
        Map<String, Object> fields
) {
}
