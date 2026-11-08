package com.fbztec.hush.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Allowed requests per client IP and minute for each route, and how many failed lookups
 * (unknown, expired or revealed id) one IP may cause per 10 minutes.
 * Values live in application.properties only.
 */
@ConfigurationProperties("hush.ratelimit")
public record RateLimitProperties(
        int create,
        int meta,
        int reveal,
        int failures) {
}
