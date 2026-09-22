package com.github.h3yow.datapolicygatewayjava.data;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 内存数据源（演示与测试用）：内置 customer 资源数据。
 *
 * <p>真实部署中替换为数据库/服务适配器即可，策略层不感知数据来源。
 */
@Component
public class InMemoryDataSource implements DataSource {

    public static final String RESOURCE_TYPE = "customer";

    private static final List<Map<String, Object>> DATA = List.of(
            record("C001", "Zhang Wei", "110101199001011234",
                    "13800001111", "zhangwei@example.com", 12000, "ENGINEERING"),
            record("C002", "Li Na", "310110199505052345",
                    "13900002222", "lina@example.com", 18000, "FINANCE"),
            record("C003", "Wang Fang", "440106199808083456",
                    "13700003333", "wangfang@example.com", 9000, "SALES"));

    private static Map<String, Object> record(String id, String name, String nationalId,
                                              String phone, String email, int salary,
                                              String department) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("name", name);
        row.put("nationalId", nationalId);
        row.put("phone", phone);
        row.put("email", email);
        row.put("salary", salary);
        row.put("department", department);
        return row;
    }

    @Override
    public boolean supports(String resourceType) {
        return RESOURCE_TYPE.equals(resourceType);
    }

    @Override
    public List<Map<String, Object>> fetch(ResourceRef resource) {
        if (!supports(resource.resourceType())) {
            throw new DataAccessException("unsupported resource type: " + resource.resourceType(), null);
        }
        // 返回全新的可变副本，避免下游处理污染底层数据
        return DATA.stream()
                .<Map<String, Object>>map(LinkedHashMap::new)
                .toList();
    }
}
