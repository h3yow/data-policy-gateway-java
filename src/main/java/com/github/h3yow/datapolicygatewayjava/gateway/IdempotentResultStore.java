package com.github.h3yow.datapolicygatewayjava.gateway;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 请求结果幂等存储：以 requestId 为键缓存首次 {@link StoredOutcome}。
 *
 * <p>{@link #computeIfAbsent} 保证同一个 requestId 的并发提交只有一个线程真正执行，
 * 其余线程（以及更新策略后的重试）拿到的都是首次结果。
 */
@Component
public class IdempotentResultStore {

    private final ConcurrentMap<String, StoredOutcome> outcomes = new ConcurrentHashMap<>();

    /**
     * 已有首次结果则直接返回（{@code executed=false}）；否则以当前线程执行 producer
     * 并缓存其结果（{@code executed=true}）。每个 requestId 的 producer 至多执行一次。
     */
    public StoredOutcome computeIfAbsent(String requestId,
                                         java.util.function.Supplier<StoredOutcome> producer) {
        // ConcurrentHashMap.computeIfAbsent 对同一键的 mapping function 保证至多执行一次；
        // producer 内不得再回写本 Map（它只做取数/求值/审计），避免递归更新。
        return outcomes.computeIfAbsent(requestId, key -> {
            StoredOutcome outcome = producer.get();
            if (outcome == null) {
                throw new IllegalStateException("stored outcome must not be null");
            }
            return outcome;
        });
    }

    public Optional<StoredOutcome> find(String requestId) {
        return Optional.ofNullable(outcomes.get(requestId));
    }

    /** 测试用：清空缓存。 */
    public void clear() {
        outcomes.clear();
    }
}
