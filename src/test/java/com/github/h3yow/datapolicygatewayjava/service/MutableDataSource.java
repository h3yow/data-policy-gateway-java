package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.data.DataSource;
import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 测试用可变数据源：可在测试中替换底层记录，用于构造记录级过滤的边界数据
 * （缺字段、结构不一致等）。fetch 返回全新可变副本。
 */
class MutableDataSource implements DataSource {

    private final String resourceType;
    private volatile List<Map<String, Object>> data = List.of();

    MutableDataSource(String resourceType) {
        this.resourceType = resourceType;
    }

    void setData(List<Map<String, Object>> rows) {
        this.data = rows;
    }

    @Override
    public boolean supports(String resourceType) {
        return this.resourceType.equals(resourceType);
    }

    @Override
    public List<Map<String, Object>> fetch(ResourceRef resource) {
        return data.stream().<Map<String, Object>>map(LinkedHashMap::new).toList();
    }
}
