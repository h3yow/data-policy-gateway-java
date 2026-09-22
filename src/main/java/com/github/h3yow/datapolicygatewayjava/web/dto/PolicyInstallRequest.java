package com.github.h3yow.datapolicygatewayjava.web.dto;

import com.github.h3yow.datapolicygatewayjava.model.Policy;

/**
 * Policy installation payload. {@code expectedBase} optionally pins the
 * version the updater believes is current.
 */
public record PolicyInstallRequest(Long expectedBase, Policy policy) {
}
