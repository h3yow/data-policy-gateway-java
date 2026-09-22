package com.github.h3yow.datapolicygatewayjava.config;

import com.github.h3yow.datapolicygatewayjava.datasource.InMemoryResourceDataSource;
import com.github.h3yow.datapolicygatewayjava.datasource.ResourceRecord;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * Seeds demo customer records used by the smoke tests and manual curls.
 */
@Configuration
public class DemoDataInitializer {

    @Bean
    ApplicationRunner seedRunner(InMemoryResourceDataSource dataSource) {
        return args -> dataSource.put(ResourceRecord.of("customer", "c-1001", Map.of(
                "name", "Alice Zhang",
                "email", "alice@example.com",
                "region", "cn-north",
                "ssn", "110101-19900101-1234"
        )));
    }
}
