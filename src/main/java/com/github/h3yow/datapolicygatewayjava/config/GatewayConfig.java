package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.audit.AuditEventStore;
import com.github.h3yow.datapolicygatewayjava.audit.InMemoryAuditEventStore;
import com.github.h3yow.datapolicygatewayjava.datasource.InMemoryResourceDataSource;
import com.github.h3yow.datapolicygatewayjava.datasource.ResourceDataSource;
import com.github.h3yow.datapolicygatewayjava.mask.FieldProjector;
import com.github.h3yow.datapolicygatewayjava.mask.InMemoryMaskingRegistry;
import com.github.h3yow.datapolicygatewayjava.mask.MaskingRegistry;
import com.github.h3yow.datapolicygatewayjava.mask.MaskingRule;
import com.github.h3yow.datapolicygatewayjava.mask.StandardMaskingRules;
import com.github.h3yow.datapolicygatewayjava.policy.InMemoryPolicyRepository;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyEvaluator;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyRepository;
import com.github.h3yow.datapolicygatewayjava.service.DataAccessService;
import com.github.h3yow.datapolicygatewayjava.service.DefaultDataAccessService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

@Configuration
public class GatewayConfig {

    @Bean
    MaskingRegistry maskingRegistry() {
        InMemoryMaskingRegistry registry = new InMemoryMaskingRegistry(Map.ofEntries(
                Map.entry("tail-4", StandardMaskingRules.tailKeep(4)),
                Map.entry("head-2", StandardMaskingRules.headKeep(2)),
                Map.entry("email", StandardMaskingRules.email()),
                Map.entry("null", StandardMaskingRules.nulled()),
                Map.entry("redacted", StandardMaskingRules.fixed("redacted", "REDACTED"))
        ));
        // sanity check that all built-ins expose stable names
        for (String name : new String[]{"tail-4", "head-2", "email", "null", "redacted"}) {
            MaskingRule rule = registry.resolve(name);
            if (!rule.name().equals(name)) {
                throw new IllegalStateException("masking rule name mismatch: " + name);
            }
        }
        return registry;
    }

    @Bean
    InMemoryResourceDataSource resourceDataSource() {
        return new InMemoryResourceDataSource();
    }

    @Bean
    AuditEventStore auditEventStore() {
        return new InMemoryAuditEventStore();
    }

    @Bean
    PolicyEvaluator policyEvaluator() {
        return new PolicyEvaluator();
    }

    @Bean
    FieldProjector fieldProjector(MaskingRegistry registry) {
        return new FieldProjector(registry);
    }

    @Bean
    InitialPolicyProvider initialPolicyProvider(DemoPolicyFactory factory) {
        return factory::version1;
    }

    @Bean
    PolicyRepository policyRepository(InitialPolicyProvider provider) {
        return new InMemoryPolicyRepository(provider.initialPolicy());
    }

    @Bean
    DataAccessService dataAccessService(PolicyRepository policyRepository,
                                        PolicyEvaluator evaluator,
                                        FieldProjector projector,
                                        InMemoryResourceDataSource dataSource,
                                        AuditEventStore auditStore) {
        return new DefaultDataAccessService(policyRepository, evaluator, projector,
                dataSource, auditStore);
    }
}
