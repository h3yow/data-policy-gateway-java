package com.github.h3yow.datapolicygatewayjava.data;

/**
 * 底层数据访问异常。
 */
public class DataAccessException extends RuntimeException {
    public DataAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}
