package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.policy.PolicyStore;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * 启动时装载初始策略版本 {@code v1}。
 *
 * <p>v1 模型（资源类型 customer，动作 READ；规则按声明顺序首条命中生效）：
 * <ul>
 *   <li>{@code r-admin-read}：role=ADMIN → 全字段可见，证件号/手机/邮箱/薪资脱敏；</li>
 *   <li>{@code r-analyst-read}：role=ANALYST → 基础字段可见，手机/邮箱哈希，
 *       证件号与薪资显式禁止（FIELD_FORBIDDEN，越权）；</li>
 *   <li>{@code r-guest-read}：role=GUEST → 仅 id/name/department 可见，其余显式禁止。</li>
 * </ul>
 * 任何字段未被规则覆盖且 defaultVisible=false → FIELD_MAPPING_MISSING 失败关闭；
 * 角色不匹配任何规则 → POLICY_NO_MATCH。
 */
@Component
@Order(0)
public class BootstrapPolicyInitializer implements ApplicationRunner {

    private final PolicyStore policyStore;

    public BootstrapPolicyInitializer(PolicyStore policyStore) {
        this.policyStore = policyStore;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (policyStore.current() == null) {
            policyStore.publish(v1(), null);
        }
    }

    public static PolicyDefinition v1() {
        return new PolicyDefinition("v1", List.of(adminRule(), analystRule(), guestRule()));
    }

    public static PolicyRule adminRule() {
        return new PolicyRule("r-admin-read",
                Map.of("role", "ADMIN"),
                "customer", AccessAction.READ,
                List.of(
                        field("id", true, MaskingType.NONE, Map.of()),
                        field("name", true, MaskingType.NONE, Map.of()),
                        field("department", true, MaskingType.NONE, Map.of()),
                        field("nationalId", true, MaskingType.PARTIAL_MASK,
                                Map.of("prefix", "4", "suffix", "4")),
                        field("phone", true, MaskingType.PARTIAL_MASK,
                                Map.of("prefix", "3", "suffix", "4")),
                        field("email", true, MaskingType.PARTIAL_MASK,
                                Map.of("prefix", "2", "suffix", "5")),
                        field("salary", true, MaskingType.NONE, Map.of())),
                false);
    }

    public static PolicyRule analystRule() {
        return new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                List.of(
                        field("id", true, MaskingType.NONE, Map.of()),
                        field("name", true, MaskingType.NONE, Map.of()),
                        field("department", true, MaskingType.NONE, Map.of()),
                        field("phone", true, MaskingType.HASH, Map.of()),
                        field("email", true, MaskingType.HASH, Map.of()),
                        field("nationalId", false, MaskingType.NONE, Map.of()),
                        field("salary", false, MaskingType.NONE, Map.of())),
                false);
    }

    public static PolicyRule guestRule() {
        return new PolicyRule("r-guest-read",
                Map.of("role", "GUEST"),
                "customer", AccessAction.READ,
                List.of(
                        field("id", true, MaskingType.NONE, Map.of()),
                        field("name", true, MaskingType.NONE, Map.of()),
                        field("department", true, MaskingType.NONE, Map.of()),
                        field("phone", false, MaskingType.NONE, Map.of()),
                        field("email", false, MaskingType.NONE, Map.of()),
                        field("nationalId", false, MaskingType.NONE, Map.of()),
                        field("salary", false, MaskingType.NONE, Map.of())),
                false);
    }

    private static FieldPolicy field(String name, boolean visible,
                                     MaskingType masking, Map<String, String> params) {
        return new FieldPolicy(name, visible, masking, params);
    }
}
