package com.github.h3yow.datapolicygatewayjava.datasource;

import com.github.h3yow.datapolicygatewayjava.model.ResourceRef;

import java.util.Optional;

/**
 * Backing data store. Sits behind the gateway: its raw output must only be
 * released after field-level authorization and masking.
 */
public interface ResourceDataSource {

    Optional<ResourceRecord> load(ResourceRef ref);
}
