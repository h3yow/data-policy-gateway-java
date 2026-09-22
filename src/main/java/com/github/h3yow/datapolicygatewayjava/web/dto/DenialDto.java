package com.github.h3yow.datapolicygatewayjava.web.dto;

/**
 * Stable, distinguishable denial representation. Contains no field names.
 */
public record DenialDto(
        String requestId,
        String reason,
        long policyVersion,
        String message
) {
}
