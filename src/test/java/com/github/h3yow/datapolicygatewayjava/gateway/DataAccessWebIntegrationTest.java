package com.github.h3yow.datapolicygatewayjava.gateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.h3yow.datapolicygatewayjava.config.BootstrapPolicyInitializer;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web 层集成测试：端到端 HTTP 验证响应内容、拒绝原因码与策略管理接口。
 */
@SpringBootTest
class DataAccessWebIntegrationTest {

    private static final Logger log = LoggerFactory.getLogger(DataAccessWebIntegrationTest.class);

    @Autowired
    private WebApplicationContext wac;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private PolicyStore policyStore;

    private MockMvc mvc;

    @AfterEach
    void resetPolicy() {
        // 恢复初始 v1，保证测试之间相互独立、结果可复现
        policyStore.resetForTests();
        policyStore.publish(BootstrapPolicyInitializer.v1(), null);
    }

    private MockMvc mvc() {
        if (mvc == null) {
            mvc = MockMvcBuilders.webAppContextSetup(wac).build();
        }
        return mvc;
    }

    private String queryBody(String requestId, String role) {
        return queryBody(requestId, Map.of("role", role));
    }

    private String queryBody(String requestId, Map<String, String> attributes) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("requestId", requestId);
        body.put("subject", Map.of("subjectId", "u-" + attributes.get("role"),
                "attributes", attributes));
        body.put("resource", Map.of("resourceType", "customer",
                "resourceId", "*", "attributes", Map.of()));
        body.put("action", "READ");
        try {
            return objectMapper.writeValueAsString(body);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void analystQueryStripsForbiddenFieldsOverHttp() throws Exception {
        MvcResult result = mvc().perform(post("/api/data/query")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(queryBody("web-analyst-1", "ANALYST")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.policyVersion").value("v1"))
                .andExpect(jsonPath("$.matchedRuleId").value("r-analyst-read"))
                .andReturn();
        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        JsonNode row = json.get("records").get(0);
        List<String> returnedFields = new java.util.ArrayList<>();
        row.fieldNames().forEachRemaining(returnedFields::add);
        log.info("web test: input=web-analyst-1 role:ANALYST, policyVersion=v1, "
                + "basis='HTTP 端到端越权字段剥离', returnedFields={}", returnedFields);

        assertFalse(row.has("nationalId"), "证件号不得出现在 HTTP 响应");
        assertFalse(row.has("salary"), "薪资不得出现在 HTTP 响应");
        assertTrue(row.has("phone"));
        assertEquals(64, row.get("phone").asText().length(), "手机应为哈希");
    }

    @Test
    void unauthorizedRoleGetsForbiddenWithReasonAndEmptyRecords() throws Exception {
        MvcResult result = mvc().perform(post("/api/data/query")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(queryBody("web-root-1", "ROOT")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.denyReason").value("POLICY_NO_MATCH"))
                .andExpect(jsonPath("$.records").isArray())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        log.info("web test: input=web-root-1 role:ROOT, policyVersion=v1, "
                + "basis='HTTP 越权返回 403 + 稳定原因码 + 空记录', body={}", body);

        JsonNode json = objectMapper.readTree(body);
        assertEquals(0, json.get("records").size());
        // 异常响应中不得夹带任何敏感字段名/值
        assertFalse(body.contains("nationalId"));
        assertFalse(body.contains("110101"));
    }

    @Test
    void policyRollbackOverHttpIsRejectedWith409() throws Exception {
        // 构造一个合法 v2 发布，再尝试回退 v1
        String v2 = """
                {"version":"v2","rules":[{"ruleId":"r-v2-guest","resourceType":"customer",
                "action":"READ","defaultVisible":false,
                "subjectConditions":{"role":"GUEST"},
                "fieldPolicies":[{"fieldName":"id","visible":true,
                "maskingType":"NONE","maskingParams":{}}]}]}
                """;
        // v2 规则字段不全（缺 name 等），但仅用于版本管理接口验证，不发起数据查询
        mvc().perform(post("/api/policies").contentType(MediaType.APPLICATION_JSON).content(v2))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyVersion").value("v2"));

        String v1 = v2.replace("v2", "v1").replace("r-v2-guest", "r-v1-guest");
        MvcResult result = mvc().perform(post("/api/policies")
                        .contentType(MediaType.APPLICATION_JSON).content(v1))
                .andExpect(status().isConflict())
                .andReturn();
        log.info("web test: input=publish v1 after v2, basis='HTTP 回退被明确拒绝 409', body={}",
                result.getResponse().getContentAsString());
        assertTrue(result.getResponse().getContentAsString().contains("rollback"));

        mvc().perform(get("/api/policies/current"))
                .andExpect(jsonPath("$.policyVersion").value("v2"));

        // 指向未知父版本也必须 409
        MvcResult mismatch = mvc().perform(post("/api/policies")
                        .param("expectedParentVersion", "v99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(v2.replace("v2", "v3").replace("r-v2-guest", "r-v3-guest")))
                .andExpect(status().isConflict())
                .andReturn();
        log.info("web test: input=publish v3 expectedParent=v99, basis='未知父版本拒绝 409', body={}",
                mismatch.getResponse().getContentAsString());
        assertTrue(mismatch.getResponse().getContentAsString().contains("does not match"));
    }

    /**
     * 通过 HTTP 发布带记录级条件的 v2（JSON 反序列化 recordCondition），
     * 再以 ENGINEERING 分析人员查询：只剩 2 条 ENGINEERING 记录，且字段级哈希/剥离仍生效。
     */
    @Test
    void recordScopedPolicyOverHttpFiltersWholeRecords() throws Exception {
        String v2 = """
                {"version":"v2","rules":[
                  {"ruleId":"r-admin-read","resourceType":"customer","action":"READ",
                   "defaultVisible":false,"subjectConditions":{"role":"ADMIN"},
                   "fieldPolicies":[
                     {"fieldName":"id","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"name","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"department","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"nationalId","visible":true,"maskingType":"PARTIAL_MASK",
                      "maskingParams":{"prefix":"4","suffix":"4"}},
                     {"fieldName":"phone","visible":true,"maskingType":"PARTIAL_MASK",
                      "maskingParams":{"prefix":"3","suffix":"4"}},
                     {"fieldName":"email","visible":true,"maskingType":"PARTIAL_MASK",
                      "maskingParams":{"prefix":"2","suffix":"5"}},
                     {"fieldName":"salary","visible":true,"maskingType":"NONE","maskingParams":{}}]},
                  {"ruleId":"r-analyst-read-dept","resourceType":"customer","action":"READ",
                   "defaultVisible":false,"subjectConditions":{"role":"ANALYST"},
                   "recordCondition":{"terms":[
                     {"fieldName":"department","operator":"EQ",
                      "valueSource":"SUBJECT","referenceKey":"department"}]},
                   "fieldPolicies":[
                     {"fieldName":"id","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"name","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"department","visible":true,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"phone","visible":true,"maskingType":"HASH","maskingParams":{}},
                     {"fieldName":"email","visible":true,"maskingType":"HASH","maskingParams":{}},
                     {"fieldName":"nationalId","visible":false,"maskingType":"NONE","maskingParams":{}},
                     {"fieldName":"salary","visible":false,"maskingType":"NONE","maskingParams":{}}]}]}
                """;
        mvc().perform(post("/api/policies")
                        .param("expectedParentVersion", "v1")
                        .contentType(MediaType.APPLICATION_JSON).content(v2))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.policyVersion").value("v2"));

        MvcResult result = mvc().perform(post("/api/data/query")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(queryBody("web-record-1",
                                Map.of("role", "ANALYST", "department", "ENGINEERING"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.policyVersion").value("v2"))
                .andReturn();
        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        List<String> ids = new java.util.ArrayList<>();
        json.get("records").forEach(r -> ids.add(r.get("id").asText()));
        log.info("web test: input=ANALYST department=ENGINEERING under record-scoped v2, "
                + "basis='HTTP 记录级过滤整条消失 + 字段级哈希/剥离', ids={}", ids);

        // 内置数据：C001=ENGINEERING, C002=FINANCE, C003=SALES -> 仅 C001 整条可见
        assertEquals(List.of("C001"), ids, "非本部门记录必须整条不出现");
        JsonNode first = json.get("records").get(0);
        assertFalse(first.has("nationalId"));
        assertFalse(first.has("salary"));
        assertEquals(64, first.get("phone").asText().length());
    }

    @Test
    void missingSubjectAttributeForRecordConditionGets403WithDistinctReason() throws Exception {
        // 发布记录级 v2 后，以无 department 属性的 ANALYST 查询：规则命中但条件不可求值
        mvc().perform(post("/api/policies").param("expectedParentVersion", "v1")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                        BootstrapPolicyInitializer.v2RecordScoped())))
                .andExpect(status().isOk());

        MvcResult result = mvc().perform(post("/api/data/query")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(queryBody("web-record-deny-1", "ANALYST")))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.denyReason").value("RECORD_CONDITION_FAILED"))
                .andExpect(jsonPath("$.records").isArray())
                .andReturn();
        String body = result.getResponse().getContentAsString();
        log.info("web test: input=ANALYST without department attr under record-scoped v2, "
                + "basis='HTTP 条件不可求值 403，原因码区别于 NO_MATCH/FIELD_FORBIDDEN', body={}",
                body);
        assertEquals(0, objectMapper.readTree(body).get("records").size());
        assertFalse(body.contains("nationalId"));
    }

    @Test
    void missingRequestIdIsRejectedAsBadRequest() throws Exception {
        String body = queryBody("ignored", "ADMIN").replace("ignored", "");
        mvc().perform(post("/api/data/query")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        log.info("web test: input=blank requestId, basis='幂等键缺失 -> 400 失败关闭'");
    }
}