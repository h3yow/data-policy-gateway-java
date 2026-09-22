package com.github.h3yow.datapolicygatewayjava.policy;

import com.github.h3yow.datapolicygatewayjava.model.PolicyDefinition;
import org.springframework.stereotype.Component;

/**
 * 策略存储。
 *
 * <p>一致性保证：
 * <ul>
 *   <li>策略以<b>不可变快照</b>（{@link PolicySnapshot}）形式发布，{@code volatile} 引用
 *       保证所有读线程要么完整看到旧版本、要么完整看到新版本，永远不会观察到半更新状态；</li>
 *   <li>读取方在请求开始时抓取一次快照，整次请求（响应与审计）都归属该版本；</li>
 *   <li>发布必须经过版本检查（{@code synchronized}）：新版本必须严格高于当前版本；
 *       携带 {@code expectedParentVersion} 时必须与当前版本精确一致；
 *       版本号缺失/无法解析视为未知版本，一律拒绝，绝不静默回退。</li>
 * </ul>
 */
@Component
public class PolicyStore {

    private volatile PolicySnapshot current;

    /**
     * @return 当前策略快照；系统尚未装载任何策略时返回 null（调用方应失败关闭）
     */
    public PolicySnapshot current() {
        return current;
    }

    /**
     * 发布新策略版本。
     *
     * @param definition            新策略定义（不可变）
     * @param expectedParentVersion 乐观条件：必须等于当前版本；null 表示不校验（仅限初始化/无条件推进）
     */
    public synchronized void publish(PolicyDefinition definition, String expectedParentVersion) {
        if (definition == null) {
            throw new PolicyVersionException("policy definition must not be null");
        }
        long newOrder = parseVersionOrder(definition.version());
        PolicySnapshot existing = this.current;

        if (existing == null) {
            if (expectedParentVersion != null && !expectedParentVersion.isBlank()) {
                throw new PolicyVersionException(
                        "no policy initialized, expected parent version '"
                                + expectedParentVersion + "' does not exist");
            }
        } else {
            long currentOrder = parseVersionOrder(existing.version());
            if (expectedParentVersion != null && !expectedParentVersion.isBlank()
                    && !expectedParentVersion.equals(existing.version())) {
                // 指向未知/已过期的父版本
                throw new PolicyVersionException(
                        "expected parent version '" + expectedParentVersion
                                + "' does not match current version '" + existing.version() + "'");
            }
            if (newOrder <= currentOrder) {
                // 回退或重复发布：明确拒绝
                throw new PolicyVersionException(
                        "policy version rollback rejected: new version '" + definition.version()
                                + "' is not higher than current version '" + existing.version() + "'");
            }
        }
        // 先构造完整快照，再一次性发布引用
        this.current = new PolicySnapshot(definition);
    }

    /**
     * 重置为初始 v1 策略。仅供测试隔离使用：每个集成测试都从同一版本状态开始，
     * 保证判定结果可复现。
     */
    public synchronized void resetForTests() {
        this.current = null;
    }
    static long parseVersionOrder(String version) {
        if (version == null || version.isBlank()) {
            throw new PolicyVersionException("policy version must not be blank");
        }
        String digits = version.startsWith("v") || version.startsWith("V")
                ? version.substring(1) : version;
        try {
            long order = Long.parseLong(digits.trim());
            if (order < 1) {
                throw new PolicyVersionException("policy version must be >= 1: " + version);
            }
            return order;
        } catch (NumberFormatException e) {
            throw new PolicyVersionException("unknown policy version format: " + version);
        }
    }
}
