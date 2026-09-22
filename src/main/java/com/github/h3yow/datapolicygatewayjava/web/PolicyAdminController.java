package com.github.h3yow.datapolicygatewayjava.web;

import com.github.h3yow.datapolicygatewayjava.mask.MaskingRegistry;
import com.github.h3yow.datapolicygatewayjava.model.FieldRule;
import com.github.h3yow.datapolicygatewayjava.model.Policy;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyRepository;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyVersionException;
import com.github.h3yow.datapolicygatewayjava.web.dto.PolicyInstallRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Policy inspection and atomic installation. Installation additionally
 * validates that every referenced masking rule exists, so a broken policy
 * can never become the active version.
 */
@RestController
@RequestMapping("/api/v1/policies")
public class PolicyAdminController {

    private final PolicyRepository repository;
    private final MaskingRegistry maskingRegistry;

    public PolicyAdminController(PolicyRepository repository,
                                 MaskingRegistry maskingRegistry) {
        this.repository = repository;
        this.maskingRegistry = maskingRegistry;
    }

    @GetMapping("/current")
    public Map<String, Object> current() {
        Policy p = repository.current();
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("version", p.version());
        view.put("ruleCount", p.rules().size());
        return view;
    }

    @PostMapping("/install")
    public Map<String, Object> install(@RequestBody PolicyInstallRequest request) {
        if (request == null || request.policy() == null) {
            throw new IllegalArgumentException("policy is required");
        }
        validateMaskingRules(request.policy());
        repository.install(request.policy(), request.expectedBase());
        return Map.of(
                "version", request.policy().version(),
                "installed", true);
    }

    private void validateMaskingRules(Policy policy) {
        for (PolicyRule rule : policy.rules()) {
            for (FieldRule fr : rule.fields()) {
                if (fr.effect().name().equals("MASK")
                        && !maskingRegistry.contains(fr.maskName())) {
                    throw new IllegalArgumentException(
                            "policy references unknown masking rule");
                }
            }
        }
    }
}
