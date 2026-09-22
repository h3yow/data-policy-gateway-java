package com.github.h3yow.datapolicygatewayjava.datasource;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.Map;

/**
 * A resource as returned by the backing system: identity, the set of mapped
 * logical field names and the raw values.
 */
public record ResourceRecord(ResourceRef ref, Map<String, Object> data) {

    public ResourceRecord {
        data = Map.copyOf(data == null ? Map.of() : data);
    }

    public static ResourceRecord of(String type, String id, Map<String, Object> data) {
        return new ResourceRecord(new ResourceRef(type, id), data);
    }
}
