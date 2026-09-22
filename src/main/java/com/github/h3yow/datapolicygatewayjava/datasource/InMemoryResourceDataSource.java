package com.github.h3yow.datapolicygatewayjava.datasource;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory demo data source keyed by the canonical resource coordinate.
 */
public class InMemoryResourceDataSource implements ResourceDataSource {

    private final Map<String, ResourceRecord> records = new ConcurrentHashMap<>();

    public void put(ResourceRecord record) {
        Objects.requireNonNull(record, "record");
        records.put(record.ref().canonical(), record);
    }

    @Override
    public Optional<ResourceRecord> load(ResourceRef ref) {
        return Optional.ofNullable(records.get(ref.canonical()));
    }
}
