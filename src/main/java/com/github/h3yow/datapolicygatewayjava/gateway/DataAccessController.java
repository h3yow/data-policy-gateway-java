package com.github.h3yow.datapolicygatewayjava.gateway;

import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.model.AccessResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 数据访问接口。拒绝由 {@code ApiExceptionHandler} 转成 403 + 稳定原因码。
 */
@RestController
@RequestMapping("/api/data")
public class DataAccessController {

    private final DataAccessGateway gateway;

    public DataAccessController(DataAccessGateway gateway) {
        this.gateway = gateway;
    }

    @PostMapping("/query")
    public ResponseEntity<AccessResult> query(@RequestBody AccessRequest request) {
        return ResponseEntity.status(HttpStatus.OK).body(gateway.execute(request));
    }
}
