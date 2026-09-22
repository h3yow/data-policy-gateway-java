package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.model.Policy;

/**
 * Supplies the immutable v1 policy installed at startup.
 */
@FunctionalInterface
public interface InitialPolicyProvider {

    Policy initialPolicy();
}
