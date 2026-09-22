package com.github.h3yow.datapolicygatewayjava.web.dto;

import java.util.List;

public record AccessRequestDto(
        String requestId,
        SubjectDto subject,
        String resourceType,
        String resourceId,
        String action,
        List<String> fields
) {
}
