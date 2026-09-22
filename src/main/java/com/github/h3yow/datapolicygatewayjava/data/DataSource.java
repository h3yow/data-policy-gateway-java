package com.github.h3yow.datapolicygatewayjava.data;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.List;
import java.util.Map;

/**
 * 数据源接口：返回原始记录。策略网关在此结果之上做字段级授权与脱敏。
 */
public interface DataSource {

    boolean supports(String resourceType);

    List<Map<String, Object>> fetch(ResourceRef resource);
}
