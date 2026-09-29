package com.github.h3yow.datapolicygatewayjava.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * 请求结果重放存储。
 *
 * <p>以 {@code requestId} 为幂等键，实现“单次执行 + 结果重放”：
 * <ul>
 *   <li>同一请求标识<b>并发</b>提交时，只有一个线程执行 loader（single-flight），
 *       其余线程等待同一 {@link CompletableFuture}，拿到完全相同的 {@link RequestOutcome}；</li>
 *   <li>同一请求标识<b>稍后重试</b>（即使中间策略已发布新版本）时，直接复现首次输出：
 *       同样的可见记录、脱敏结果，或同样的拒绝原因与策略版本，绝不重新求值；</li>
 *   <li>loader 抛出的运行时异常会传播给所有等待者，并从缓存移除占位，
 *       允许客户端修正请求后用同一标识重试（此类异常发生在任何审计写入之前）。</li>
 * </ul>
 */
@Component
public class ResponseReplayStore {

    private static final Logger log = LoggerFactory.getLogger(ResponseReplayStore.class);

    private final ConcurrentHashMap<String, CompletableFuture<RequestOutcome>> outcomes =
            new ConcurrentHashMap<>();

    public Optional<RequestOutcome> find(String requestId) {
        CompletableFuture<RequestOutcome> future = outcomes.get(requestId);
        if (future == null || !future.isDone() || future.isCompletedExceptionally()) {
            return Optional.empty();
        }
        try {
            return Optional.of(future.get());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (ExecutionException e) {
            return Optional.empty();
        }
    }

    /**
     * 单次执行语义：首次调用执行 loader；同 requestId 的并发/后续调用重放首次结果。
     */
    public RequestOutcome computeIfAbsent(String requestId, Callable<RequestOutcome> loader) {
        CompletableFuture<RequestOutcome> created = new CompletableFuture<>();
        CompletableFuture<RequestOutcome> existing = outcomes.putIfAbsent(requestId, created);
        if (existing != null) {
            // 已有在途或已完成的首次执行：等待并重放其结果
            return joinOutcome(requestId, existing);
        }
        try {
            RequestOutcome outcome = loader.call();
            created.complete(outcome);
            return outcome;
        } catch (RuntimeException | Error e) {
            created.completeExceptionally(e);
            outcomes.remove(requestId, created);
            throw e;
        } catch (Exception e) {
            created.completeExceptionally(e);
            outcomes.remove(requestId, created);
            throw new IllegalStateException(e);
        }
    }

    private RequestOutcome joinOutcome(String requestId, CompletableFuture<RequestOutcome> future) {
        try {
            RequestOutcome outcome = future.get();
            log.info("idempotent replay: requestId={}, outcome={}",
                    requestId, outcome.getClass().getSimpleName());
            return outcome;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while awaiting first execution", e);
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new IllegalStateException(cause);
        }
    }

    /** 测试用：清空缓存。 */
    public void clear() {
        outcomes.clear();
    }
}
