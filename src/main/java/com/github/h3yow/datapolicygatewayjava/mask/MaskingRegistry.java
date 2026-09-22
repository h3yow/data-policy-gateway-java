package com.github.h3yow.datapolicygatewayjava.mask;

/**
 * Lookup of masking rules by name.
 */
public interface MaskingRegistry {

    /**
     * @throws MaskingException with fail-closed semantics when unknown
     */
    MaskingRule resolve(String name);

    boolean contains(String name);
}
