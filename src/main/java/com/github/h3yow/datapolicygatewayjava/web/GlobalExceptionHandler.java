package com.github.h3yow.datapolicygatewayjava.web;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyVersionException;
import com.github.h3yow.datapolicygatewayjava.service.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.web.dto.DenialDto;
import com.github.h3yow.datapolicygatewayjava.web.dto.PolicyVersionErrorDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Centralized failure mapping.
 *
 * <p>Bodies are deliberately small: stable reason code, policy version and
 * a fixed message. Stack traces, denied field names and values are never
 * serialized to clients.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<DenialDto> handleDenied(AccessDeniedException ex) {
        DenialDto body = new DenialDto(ex.requestId(), ex.reason().name(),
                ex.policyVersion(), "access denied: " + ex.reason().name());
        // FIELD_UNAUTHORIZED vs POLICY_NOT_MATCHED vs ... stay distinguishable
        // via the reason code; nothing sensitive is logged here.
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(PolicyVersionException.class)
    public ResponseEntity<PolicyVersionErrorDto> handleVersion(PolicyVersionException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new PolicyVersionErrorDto(ex.attemptedVersion(),
                        ex.currentVersion(), ex.getMessage()));
    }

    @ExceptionHandler({IllegalArgumentException.class, HttpMessageNotReadableException.class})
    public ResponseEntity<DenialDto> handleBadRequest(Exception ex) {
        // Generic message outwards; raw parser messages can echo payloads.
        return ResponseEntity.badRequest()
                .body(new DenialDto(null, DenyReason.INVALID_REQUEST.name(), -1L,
                        "invalid request"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<DenialDto> handleUnexpected(Exception ex) {
        // Fail-closed catch-all. Log class/message server-side only.
        log.error("unexpected gateway error type={} message={}",
                ex.getClass().getSimpleName(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new DenialDto(null, DenyReason.EVALUATION_FAILED.name(), -1L,
                        "internal policy error"));
    }
}
