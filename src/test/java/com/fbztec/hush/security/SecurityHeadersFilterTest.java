package com.fbztec.hush.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityHeadersFilterTest {

    private MockHttpServletResponse call(String path) throws Exception {
        return call(path, false, "hush.example");
    }

    private MockHttpServletResponse call(String path, boolean secure, String host) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
        request.setServletPath(path);
        request.setSecure(secure);
        request.setServerName(host);
        MockHttpServletResponse response = new MockHttpServletResponse();
        new SecurityHeadersFilter().doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void hstsOnlyOnHttpsOutsideLocalhost() throws Exception {
        assertThat(call("/", true, "hush.example").getHeader("Strict-Transport-Security"))
                .isEqualTo("max-age=31536000");
        assertThat(call("/", false, "hush.example").getHeader("Strict-Transport-Security")).isNull();
        assertThat(call("/", true, "localhost").getHeader("Strict-Transport-Security")).isNull();
    }

    @Test
    void apiResponsesAreNeverCached() throws Exception {
        MockHttpServletResponse response = call("/api/secrets/abc");

        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Content-Security-Policy")).contains("script-src 'self'", "frame-ancestors 'none'");
        assertThat(response.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(response.getHeader("Referrer-Policy")).isEqualTo("no-referrer");
    }

    @Test
    void staticPagesGetTheHardeningHeadersButKeepTheirCaching() throws Exception {
        MockHttpServletResponse response = call("/app.js");

        assertThat(response.getHeader("Content-Security-Policy")).isNotNull();
        assertThat(response.getHeader("Cache-Control")).isNull();
    }
}
