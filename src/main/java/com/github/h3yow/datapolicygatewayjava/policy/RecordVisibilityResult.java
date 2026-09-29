package com.github.h3yow.datapolicygatewayjava.policy;

import java.util.List;
import java.util.Map;

/**
 * 记录级可见性判定结果。
 *
 * <p>两种形态：
 * <ul>
 *   <li>{@code failClosed=false}：条件成功求值，{@code visibleRecords} 为过滤后的记录
 *       （保持原顺序；不满足条件的记录整条消失）；</li>
 *   <li>{@code failClosed=true}：条件无法求值，调用方必须整单拒绝，
 *       {@code reasonDetail} 只含字段名等元数据、绝不含字段值。</li>
 * </ul>
 */
public final class RecordVisibilityResult {

    private final boolean failClosed;
    private final String reasonDetail;
    private final List<Map<String, Object>> visibleRecords;

    private RecordVisibilityResult(boolean failClosed,
                                   String reasonDetail,
                                   List<Map<String, Object>> visibleRecords) {
        this.failClosed = failClosed;
        this.reasonDetail = reasonDetail;
        this.visibleRecords = visibleRecords;
    }

    public static RecordVisibilityResult visible(List<Map<String, Object>> records) {
        return new RecordVisibilityResult(false, null, records);
    }

    public static RecordVisibilityResult failClosed(String detail) {
        return new RecordVisibilityResult(true, detail, List.of());
    }

    public boolean failClosed() {
        return failClosed;
    }

    public String reasonDetail() {
        return reasonDetail;
    }

    public List<Map<String, Object>> visibleRecords() {
        return visibleRecords;
    }
}
