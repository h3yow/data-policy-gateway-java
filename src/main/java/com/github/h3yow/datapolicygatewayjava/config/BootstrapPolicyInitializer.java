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
 *       证件号与薪资显式禁止（FIELD_FORBIDDEN，越权）；<b>不挂记录级条件</b>——
 *       这是当前正在服务的策略，只带角色不带部门的既有调用保持原返回（全部客户记录，
 *       字段级剥离/脱敏照旧），记录级可见性不会顺带影响这批线上流量；</li>
 *   <li>{@code r-guest-read}：role=GUEST → 仅 id/name/department 可见，其余显式禁止。</li>
 * </ul>
 * 任何字段未被规则覆盖且 defaultVisible=false → FIELD_MAPPING_MISSING 失败关闭；
 * 角色不匹配任何规则 → POLICY_NO_MATCH。
 *
 * <p>记录级可见性是<b>按版本主动启用（opt-in）</b>的能力：只有新发布的策略版本在规则上
 * 显式声明 {@code recordCondition} 时才生效（见
 * {@link #recordVisibilityOptInDefinition(String)}）；规则缺省该条件时记录过滤完全不介入。
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

    /**
     * 当前正在服务的初始策略 v1：字段级授权/脱敏生效，<b>不含任何记录级条件</b>。
     * 既有调用方（包括只带 role=ANALYST、不带 department 的分析人员）的返回与此版本保持一致。
     */
    public static PolicyDefinition v1() {
        return new PolicyDefinition("v1", List.of(adminRule(), analystRule(), guestRule()));
    }

    /**
     * 主动启用记录级可见性的策略版本工厂：字段级规则与 {@link #v1()} 完全一致，
     * 仅 ANALYST 规则额外声明 {@code record.department == subject.department}。
     * 业务方按自己的节奏发布新版本（如 v2）时使用；在服的旧版本零改动、行为不变。
     */
    public static PolicyDefinition recordVisibilityOptInDefinition(String version) {
        return new PolicyDefinition(version,
                List.of(adminRule(), analystRuleWithRecordVisibility(), guestRule()));
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
        // 在服 v1 的 ANALYST 规则：只有字段级授权/脱敏，不挂记录级条件。
        // 只带角色不带部门的既有调用保持原返回（全部客户记录，字段控制照旧）。
        return new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                analystFieldPolicies(),
                false);
    }

    /**
     * 主动启用记录级可见性的 ANALYST 规则：字段级策略与 {@link #analystRule()} 完全相同，
     * 额外要求 {@code record.department == subject.department}（仅本部门）。
     * 主体缺少 department 属性时条件无法求值，由网关整单失败关闭。
     */
    public static PolicyRule analystRuleWithRecordVisibility() {
        return new PolicyRule("r-analyst-read",
                Map.of("role", "ANALYST"),
                "customer", AccessAction.READ,
                analystFieldPolicies(),
                false,
                analystOwnDepartmentCondition());
    }

    /** ANALYST 记录级可见性：仅可见 record.department == subject.department 的客户记录。 */
    public static RecordVisibilityCondition analystOwnDepartmentCondition() {
        return new RecordVisibilityCondition(List.of(
                new RecordConditionTerm("department", ConditionOperator.EQ,
                        null, "department")));
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
