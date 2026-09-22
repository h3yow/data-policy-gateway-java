package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 策略管理接口：发布新版本 / 查询当前版本。
 */
@RestController
@RequestMapping("/api/policies")
public class PolicyAdminController {

    private final PolicyStore policyStore;

    public PolicyAdminController(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    /**
     * 发布新版本。回退或 expectedParentVersion 不匹配时返回 409，绝不静默回退。
     */
    @PostMapping
    @ResponseStatus(HttpStatus.OK)
    public Map<String, String> publish(@RequestBody PolicyDefinition definition,
                                       @RequestParam(required = false) String expectedParentVersion) {
        policyStore.publish(definition, expectedParentVersion);
        return Map.of("policyVersion", policyStore.current().version(), "status", "PUBLISHED");
    }

    @GetMapping("/current")
    public Map<String, String> current() {
        PolicySnapshot snapshot = policyStore.current();
        if (snapshot == null) {
            return Map.of("policyVersion", "NONE");
        }
        return Map.of("policyVersion", snapshot.version());
    }
}
