package com.github.h3yow.datapolicygatewayjava.model;

import java.util.Map;
import java.util.Objects;

/**
 * Immutable description of the requesting principal: an id plus a set of
 * policy-matching attributes (role, department, clearance level, ...).
 */
public record Subject(String id, Map<String, String> attributes) {

    public Subject {
        Objects.requireNonNull(id, "subject id");
        attributes = Map.copyOf(attributes == null ? Map.of() : attributes);
    }

    public String attribute(String key) {
        return attributes.get(key);
    }
}
