package com.github.h3yow.datapolicygatewayjava.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class DataAccessIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(DataAccessIntegrationTest.class);

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper om;

    private long currentVersion() throws Exception {
        String json = mvc.perform(get("/api/v1/policies/current"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return om.readTree(json).get("version").asLong();
    }

    private String readPayload(String requestId, String role, List<String> fields)
            throws Exception {
        return om.writeValueAsString(Map.of(
                "requestId", requestId,
                "subject", Map.of("id", "u-1", "attributes", Map.of("role", role)),
                "resourceType", "customer",
                "resourceId", "c-1001",
                "action", "READ",
                "fields", fields));
    }

    @Test
    void adminReadReturnsAllFieldsWithVersion() throws Exception {
        long v = currentVersion();
        String body = readPayload("http-admin-1", "admin",
                List.of("name", "email", "region", "ssn"));
        log.info("http-request POST /read role=admin policyVersionBefore={}", v);
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyVersion").value((int) v))
                .andExpect(jsonPath("$.fields.ssn").value("110101-19900101-1234"))
                .andExpect(jsonPath("$.fields.email").value("alice@example.com"));
    }

    @Test
    void analystReadMasksAndNeverReturnsSsn() throws Exception {
        String body = readPayload("http-analyst-1", "analyst",
                List.of("name", "email", "region"));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fields.email").value("a****@example.com"))
                .andExpect(jsonPath("$.fields.ssn").doesNotExist());
    }

    @Test
    void analystAskingForSsnGetsDistinguishableFieldDenial() throws Exception {
        String body = readPayload("http-analyst-denied", "analyst", List.of("ssn"));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FIELD_UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value(
                        "access denied: FIELD_UNAUTHORIZED"));
    }

    @Test
    void guestReadGetsPolicyNotMatched() throws Exception {
        String body = readPayload("http-guest", "guest", List.of("name"));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("POLICY_NOT_MATCHED"));
    }

    @Test
    void retryWithSameRequestIdIsFlaggedAndNotReaudited() throws Exception {
        String body = readPayload("http-retry-1", "analyst", List.of("name"));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retry").value(false));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retry").value(true));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void policyRollbackInstallIsRejectedWithConflict() throws Exception {
        long v = currentVersion();
        Map<String, Object> policy = new HashMap<>();
        policy.put("version", v);
        policy.put("rules", List.of());
        String install = om.writeValueAsString(Map.of(
                "expectedBase", v, "policy", policy));
        log.info("http-request POST install version={} (rollback) expected=409", v);
        mvc.perform(post("/api/v1/policies/install")
                        .contentType(MediaType.APPLICATION_JSON).content(install))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.attemptedVersion").value((int) v))
                .andExpect(jsonPath("$.currentVersion").value((int) v));
        mvc.perform(get("/api/v1/policies/current"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) v));
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void installWithUnknownMaskRuleIsRejected() throws Exception {
        long v = currentVersion();
        String badPolicy = om.writeValueAsString(Map.of(
                "policy", Map.of(
                        "version", v + 1,
                        "rules", List.of(Map.of(
                                "priority", 1,
                                "matchResource", "customer",
                                "matchAction", "READ",
                                "matchAttributes", Map.of("role", "analyst"),
                                "fields", List.of(Map.of(
                                        "field", "email",
                                        "effect", "MASK",
                                        "maskName", "no-such-rule")))))));
        mvc.perform(post("/api/v1/policies/install")
                        .contentType(MediaType.APPLICATION_JSON).content(badPolicy))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/api/v1/policies/current"))
                .andExpect(jsonPath("$.version").value((int) v));
    }

    private Map<String, Object> fieldDoc(String name, String effect, String mask) {
        Map<String, Object> f = new HashMap<>();
        f.put("field", name);
        f.put("effect", effect);
        f.put("maskName", mask);
        return f;
    }

    private Map<String, Object> ruleDoc(int priority, String role,
                                        List<Map<String, Object>> fields) {
        Map<String, Object> r = new HashMap<>();
        r.put("priority", priority);
        r.put("matchResource", "customer");
        r.put("matchAction", "READ");
        r.put("matchAttributes", Map.of("role", role));
        r.put("fields", fields);
        return r;
    }

    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    void validVersionBumpInstallChangesSubsequentDecisions() throws Exception {
        long v = currentVersion();
        Map<String, Object> policyDoc = new HashMap<>();
        policyDoc.put("version", v + 1);
        policyDoc.put("rules", List.of(
                ruleDoc(100, "admin", List.of(
                        fieldDoc("name", "ALLOW", null),
                        fieldDoc("email", "ALLOW", null),
                        fieldDoc("region", "ALLOW", null),
                        fieldDoc("ssn", "ALLOW", null))),
                ruleDoc(10, "analyst", List.of(
                        fieldDoc("name", "ALLOW", null),
                        fieldDoc("email", "MASK", "email"),
                        fieldDoc("region", "DENY", null),
                        fieldDoc("ssn", "DENY", null)))));
        String install = om.writeValueAsString(
                Map.of("expectedBase", v, "policy", policyDoc));
        mvc.perform(post("/api/v1/policies/install")
                        .contentType(MediaType.APPLICATION_JSON).content(install))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value((int) (v + 1)));

        // analyst region was allowed on v1; after the bump it is unauthorized
        String body = readPayload("http-after-bump", "analyst", List.of("region"));
        mvc.perform(post("/api/v1/data/read")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.reason").value("FIELD_UNAUTHORIZED"))
                .andExpect(jsonPath("$.policyVersion").value((int) (v + 1)));
    }
}
