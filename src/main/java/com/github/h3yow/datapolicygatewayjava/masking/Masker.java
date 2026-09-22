package com.github.h3yow.datapolicygatewayjava.masking;

import com.github.h3yow.datapolicygatewayjava.model.DenyReason;
import com.github.h3yow.datapolicygatewayjava.model.MaskingType;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Map;

/**
 * 脱敏执行器。
 *
 * <p>支持的规则：
 * <ul>
 *   <li>{@code NONE}：原样返回；</li>
 *   <li>{@code FULL_MASK}：整体替换为固定掩码 {@code ****}；</li>
 *   <li>{@code PARTIAL_MASK}：保留前 {@code prefix} 位与后 {@code suffix} 位，中间以
 *       {@code *} 替换；参数缺失或非法时失败关闭（抛 {@link MaskingException}），
 *       绝不返回原值；</li>
 *   <li>{@code HASH}：SHA-256 不可逆哈希。</li>
 * </ul>
 *
 * <p>null 原样返回（空值不含可识别信息）；任何异常都包装成 {@link DenyReason#MASKING_FAILED}，
 * 由上层失败关闭。
 */
@Component
public class Masker {

    private static final String FULL_MASK_TOKEN = "****";

    public Object mask(Object value, MaskingType type, Map<String, String> params) {
        if (value == null) {
            return null;
        }
        try {
            return switch (type) {
                case NONE -> value;
                case FULL_MASK -> FULL_MASK_TOKEN;
                case PARTIAL_MASK -> partialMask(value.toString(), params);
                case HASH -> sha256(value.toString());
            };
        } catch (MaskingException e) {
            throw e;
        } catch (RuntimeException e) {
            // 不把原始值带入异常消息
            throw new MaskingException(DenyReason.MASKING_FAILED,
                    "masking rule " + type + " failed", e);
        }
    }

    private String partialMask(String text, Map<String, String> params) {
        if (params == null) {
            throw new MaskingException(DenyReason.MASKING_FAILED,
                    "PARTIAL_MASK requires prefix/suffix params", null);
        }
        final int prefix = parseNonNegative(params.get("prefix"), "prefix");
        final int suffix = parseNonNegative(params.get("suffix"), "suffix");
        if (prefix + suffix >= text.length()) {
            // 保留范围覆盖/超出原文会导致内容可还原，按失败关闭处理
            throw new MaskingException(DenyReason.MASKING_FAILED,
                    "PARTIAL_MASK prefix+suffix must be smaller than value length", null);
        }
        int maskedLength = text.length() - prefix - suffix;
        return text.substring(0, prefix)
                + "*".repeat(maskedLength)
                + text.substring(text.length() - suffix);
    }

    private int parseNonNegative(String raw, String name) {
        if (raw == null) {
            throw new MaskingException(DenyReason.MASKING_FAILED,
                    "PARTIAL_MASK missing param: " + name, null);
        }
        try {
            int v = Integer.parseInt(raw.trim());
            if (v < 0) {
                throw new MaskingException(DenyReason.MASKING_FAILED,
                        "PARTIAL_MASK param must be non-negative: " + name, null);
            }
            return v;
        } catch (NumberFormatException e) {
            throw new MaskingException(DenyReason.MASKING_FAILED,
                    "PARTIAL_MASK param not an integer: " + name, e);
        }
    }

    private String sha256(String text) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new MaskingException(DenyReason.MASKING_FAILED, "SHA-256 unavailable", e);
        }
    }
}
