package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.gateway.AccessDeniedException;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyVersionException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 统一异常处理。
 *
 * <p>安全约定：错误响应体只包含 requestId、policyVersion、稳定原因码与简短说明，
 * 不包含字段名、字段值、堆栈等可能泄露受保护数据的信息。
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleDenied(AccessDeniedException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("requestId", ex.requestId());
        body.put("allowed", false);
        body.put("policyVersion", ex.policyVersion());
        body.put("denyReason", ex.reason().name());
        // 永远是空记录集，不返回部分数据
        body.put("records", List.of());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
    }

    @ExceptionHandler(PolicyVersionException.class)
    public ResponseEntity<Map<String, Object>> handleBadVersion(PolicyVersionException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "POLICY_VERSION_REJECTED");
        body.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "BAD_REQUEST");
        body.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }
}
