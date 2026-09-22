package com.github.h3yow.datapolicygatewayjava.web;

import com.github.h3yow.datapolicygatewayjava.model.AccessRequest;
import com.github.h3yow.datapolicygatewayjava.service.AccessResponse;
import com.github.h3yow.datapolicygatewayjava.service.DataAccessService;
import com.github.h3yow.datapolicygatewayjava.web.dto.AccessRequestDto;
import com.github.h3yow.datapolicygatewayjava.web.dto.AccessResponseDto;
import com.github.h3yow.datapolicygatewayjava.web.dto.DtoMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/data")
public class DataAccessController {

    private final DataAccessService service;

    public DataAccessController(DataAccessService service) {
        this.service = service;
    }

    @PostMapping("/read")
    public AccessResponseDto read(@RequestBody AccessRequestDto dto) {
        AccessRequest request = DtoMapper.toDomain(dto);
        AccessResponse response = service.read(request);
        return DtoMapper.toDto(response);
    }
}
