package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.model.AccessAction;
import com.github.h3yow.datapolicygatewayjava.model.ConditionOperator;
import com.github.h3yow.datapolicygatewayjava.model.FieldPolicy;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import com.github.h3yow.datapolicygatewayjava.model.PolicyRule;
import com.github.h3yow.datapolicygatewayjava.model.RecordConditionTerm;
import com.github.h3yow.datapolicygatewayjava.model.RecordVisibilityCondition;
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
 *
 * <p><b>记录级可见性是显式开启（opt-in）能力</b>：当前在服的 v1 不启用任何记录级过滤，
 * 只带角色、不带部门等条件的既有调用方行为与引入该能力前完全一致。
 * 需要记录级过滤时，按自己的节奏发布 {@link #v2()}（或经管理接口提交
 * {@code recordVisibilityEnabled=true} 的规则）才会生效。
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

    /**
     * 记录级可见性的可选启用版本：与 v1 唯一的差别是 ANALYST 规则启用了
     * “仅见本部门记录”的记录级过滤（{@code recordVisibilityEnabled=true}）。
     * 默认不装载；团队确认调用方已携带 department 属性后，再发布此版本启用。
     */
    public static PolicyDefinition v2() {
        return new PolicyDefinition("v2", List.of(adminRule(),
                analystRuleWithRecordVisibility(), guestRule()));
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

    /**
     * ANALYST 记录级可见性条件：record.department == subject.department。
     * 仅在规则同时设置 {@code recordVisibilityEnabled=true} 时才生效；
     * 启用后主体缺少 department 属性时条件无法求值，由网关整单失败关闭。
     */
    public static RecordVisibilityCondition analystOwnDepartmentCondition() {
        return new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.EQ,
                        null, "department")));
    }

    /**
     * 在服的 ANALYST 规则：纯字段级（不启用记录级过滤）。
     * 只带 role、不带 department 的既有调用方保持原有返回。
     */
    public static PolicyRule analystRule() {
        return new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                analystFieldPolicies(),
                false);
    }

    /**
     * 显式启用记录级过滤的 ANALYST 规则：字段级策略与 {@link #analystRule()} 相同，
     * 叠加 record.department == subject.department 的记录级过滤（opt-in）。
     */
    public static PolicyRule analystRuleWithRecordVisibility() {
        return new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                analystFieldPolicies(),
                false,
                analystOwnDepartmentCondition(),
                true);
    }

    private static List<FieldPolicy> analystFieldPolicies() {
        return List.of(
                field("id", true, MaskingType.NONE, Map.of()),
                field("name", true, MaskingType.NONE, Map.of()),
                field("department", true, MaskingType.NONE, Map.of()),
                field("phone", true, MaskingType.HASH, Map.of()),
                field("email", true, MaskingType.HASH, Map.of()),
                field("nationalId", false, MaskingType.NONE, Map.of()),
                field("salary", false, MaskingType.NONE, Map.of()));
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
