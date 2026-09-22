package com.github.h3yow.datapolicygatewayjava.web.dto;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import com.github.h3yow.datapolicygatewayjava.model.Subject;
import com.github.h3yow.datapolicygatewayjava.service.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.service.AccessResponse;
import com.github.h3yow.datapolicygatewayjava.model.DenyReason;

/**
 * Conversion between transport DTOs and the domain model. All malformed
 * input is rejected here with {@link DenyReason#INVALID_REQUEST} before any
 * policy or data is touched.
 */
public final class DtoMapper {

    private DtoMapper() {
    }

    public static AccessRequest toDomain(AccessRequestDto dto) {
        if (dto == null) {
            throw invalid("missing request body");
        }
        if (isBlank(dto.requestId())) {
            throw invalid("requestId is required");
        }
        SubjectDto sdto = dto.subject();
        if (sdto == null || isBlank(sdto.id())) {
            throw invalid("subject.id is required");
        }
        if (isBlank(dto.resourceType()) || isBlank(dto.resourceId())) {
            throw invalid("resourceType and resourceId are required");
        }
        AccessAction action;
        try {
            action = AccessAction.valueOf(
                    dto.action() == null ? "" : dto.action().trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw invalid("unknown action: " + dto.action());
        }
        Subject subject = new Subject(sdto.id(), sdto.attributes());
        ResourceRef resource = new ResourceRef(dto.resourceType(), dto.resourceId());
        return new AccessRequest(dto.requestId(), subject, resource, action, dto.fields());
    }

    public static AccessResponseDto toDto(AccessResponse response) {
        return new AccessResponseDto(
                response.requestId(),
                response.resource().type(),
                response.resource().id(),
                response.policyVersion(),
                response.retry(),
                response.fields());
    }

    private static AccessDeniedException invalid(String message) {
        // No policy version exists yet for malformed input.
        return new AccessDeniedException(DenyReason.INVALID_REQUEST, -1L, null, message);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
