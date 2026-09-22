package com.github.h3yow.datapolicygatewayjava.service;

import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;

/**
 * Orchestrates one data access: pins a policy version, authorizes fields,
 * loads + masks data, and writes exactly one audit record. Idempotent on
 * requestId.
 */
public interface DataAccessService {

    AccessResponse read(AccessRequest request);
}
