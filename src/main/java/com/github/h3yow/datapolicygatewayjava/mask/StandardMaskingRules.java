package com.github.h3yow.datapolicygatewayjava.mask;

import java.util.Objects;

/**
 * Built-in masking rule factory methods. Each rule is stateless and
 * thread-safe. Every rule converts non-string input via
 * {@code String.valueOf} and treats {@code null} as {@code null}.
 */
public final class StandardMaskingRules {

    private StandardMaskingRules() {
    }

    /** Keep last N characters, replace the head with {@code *}. */
    public static MaskingRule tailKeep(int chars) {
        if (chars < 0) {
            throw new IllegalArgumentException("chars must be >= 0");
        }
        return new AbstractMaskingRule("tail-" + chars) {
            @Override
            protected String doApply(String value) {
                if (value.length() <= chars) {
                    return "*".repeat(Math.max(value.length(), 1));
                }
                int head = value.length() - chars;
                return "*".repeat(head) + value.substring(head);
            }
        };
    }

    /** Keep first N characters, replace the tail with {@code *}. */
    public static MaskingRule headKeep(int chars) {
        if (chars < 0) {
            throw new IllegalArgumentException("chars must be >= 0");
        }
        return new AbstractMaskingRule("head-" + chars) {
            @Override
            protected String doApply(String value) {
                if (value.length() <= chars) {
                    return "*".repeat(Math.max(value.length(), 1));
                }
                return value.substring(0, chars) + "*".repeat(value.length() - chars);
            }
        };
    }

    /** Fixed token, independent of input (null stays null). */
    public static MaskingRule fixed(String token) {
        return fixed("fixed", token);
    }

    /** Fixed token under an explicit rule name. */
    public static MaskingRule fixed(String name, String token) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(token, "token");
        return new AbstractMaskingRule(name) {
            @Override
            protected String doApply(String value) {
                return token;
            }
        };
    }

    /** Email local-part masking: {@code a****@example.com}; non-emails are fully masked. */
    public static MaskingRule email() {
        return new AbstractMaskingRule("email") {
            @Override
            protected String doApply(String value) {
                int at = value.indexOf('@');
                if (at <= 0) {
                    return "*".repeat(Math.max(value.length(), 1));
                }
                String local = value.substring(0, at);
                String domain = value.substring(at);
                String head = local.substring(0, 1);
                return head + "*".repeat(Math.max(local.length() - 1, 1)) + domain;
            }
        };
    }

    /** Null everything out. */
    public static MaskingRule nulled() {
        return new MaskingRule() {
            @Override
            public String name() {
                return "null";
            }

            @Override
            public Object apply(Object value) {
                return null;
            }
        };
    }

    /**
     * Template that normalizes null handling and guarantees every failure
     * surfaces as a {@link MaskingException} (fail-closed).
     */
    private abstract static class AbstractMaskingRule implements MaskingRule {

        private final String name;

        AbstractMaskingRule(String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public final Object apply(Object value) {
            if (value == null) {
                return null;
            }
            try {
                return doApply(String.valueOf(value));
            } catch (MaskingException e) {
                throw e;
            } catch (RuntimeException e) {
                // Do not embed value into message: values are sensitive.
                throw new MaskingException("masking rule failed", name, e);
            }
        }

        protected abstract String doApply(String value);
    }
}
