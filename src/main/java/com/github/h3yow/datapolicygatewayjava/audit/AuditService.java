package com.github.h3yow.datapolicygatewayjava.audit;

import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 审计服务。
 *
 * <p>关键约定：
 * <ul>
 *   <li>以 {@code requestId} 为幂等键：同一请求无论执行多少次（重试、重复提交），
 *       最多只有一条审计记录；</li>
 *   <li>允许与拒绝（含失败关闭）都必须审计，不允许审计缺失；</li>
 *   <li>审计内容只包含判定元数据（主体、资源、动作、策略版本、命中规则、拒绝原因），
 *       <b>绝不记录字段名清单与字段值</b>，避免敏感数据经日志侧信道泄露。</li>
 * </ul>
 */
@Component
public class AuditService {

    private final Map<String, AuditRecord> byRequestId = new ConcurrentHashMap<>();
    private final List<AuditRecord> appendLog = new CopyOnWriteArrayList<>();

    /**
     * 幂等写入。
     *
     * @return 本次是否真正写入；false 表示该 requestId 已有审计记录（重复请求被吞掉）
     */
    public boolean record(AuditRecord record) {
        AuditRecord existing = byRequestId.putIfAbsent(record.requestId(), record);
        if (existing == null) {
            appendLog.add(record);
            return true;
        }
        return false;
    }

    public Optional<AuditRecord> findByRequestId(String requestId) {
        return Optional.ofNullable(byRequestId.get(requestId));
    }

    public List<AuditRecord> all() {
        return List.copyOf(appendLog);
    }

    /** 测试用：清空审计存储。 */
    public void clear() {
        byRequestId.clear();
        appendLog.clear();
    }
}
