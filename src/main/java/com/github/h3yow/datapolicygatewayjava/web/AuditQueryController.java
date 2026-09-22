package com.github.h3yow.datapolicygatewayjava.web;

import com.github.h3yow.datapolicygatewayjava.audit.AuditEventStore;
import com.github.h3yow.datapolicygatewayjava.model.AuditEvent;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Read-only audit inspection for verification. The projection strips even
 * subject attributes: only decision coordinates and counts are exposed,
 * never field values or denied field names.
 */
@RestController
@RequestMapping("/api/v1/audit")
public class AuditQueryController {

    private final AuditEventStore store;

    public AuditQueryController(AuditEventStore store) {
        this.store = store;
    }

    @GetMapping("/events")
    public List<Map<String, Object>> all() {
        return store.all().stream().map(AuditQueryController::toView).toList();
    }

    @GetMapping("/events/{requestId}")
    public Map<String, Object> byRequestId(@PathVariable String requestId) {
        return store.findByRequestId(requestId)
                .map(AuditQueryController::toView)
                .orElseGet(() -> Map.of("requestId", requestId, "exists", false));
    }

    static Map<String, Object> toView(AuditEvent e) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("requestId", e.requestId());
        view.put("retry", e.retry());
        view.put("occurredAt", e.occurredAt().toString());
        view.put("subjectId", e.subject().id());
        view.put("resource", e.resource().canonical());
        view.put("action", e.action());
        view.put("policyVersion", e.policyVersion());
        view.put("allowed", e.allowed());
        view.put("denyReason", e.denyReason());
        view.put("matchedRuleId", e.matchedRuleId());
        view.put("requestedFieldCount", e.requestedFieldCount());
        view.put("allowedFieldCount", e.allowedFieldCount());
        view.put("basis", e.basis());
        return view;
    }
}
