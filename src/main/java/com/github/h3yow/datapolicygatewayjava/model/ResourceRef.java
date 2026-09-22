package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Objects;

/**
 * Logical resource targeted by an access request, e.g. {@code customer:123}.
 */
public record ResourceRef(String type, String id) {

    public ResourceRef {
        Objects.requireNonNull(type, "resource type");
        Objects.requireNonNull(id, "resource id");
    }

    public String canonical() {
        return type + ":" + id;
    }
}
