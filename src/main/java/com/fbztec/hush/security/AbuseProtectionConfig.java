package com.fbztec.hush.security;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

// not a web-slice component on purpose: controller tests stay free of the filters
@Configuration
@EnableConfigurationProperties(RateLimitProperties.class)
public class AbuseProtectionConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    SecurityHeadersFilter securityHeadersFilter() {
        return new SecurityHeadersFilter();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    RateLimitFilter rateLimitFilter(RateLimitProperties properties, MeterRegistry meters) {
        return new RateLimitFilter(properties, meters);
    }
}
