package com.github.h3yow.datapolicygatewayjava.web.dto;

public record PolicyVersionErrorDto(
        long attemptedVersion,
        long currentVersion,
        String message
) {
}
