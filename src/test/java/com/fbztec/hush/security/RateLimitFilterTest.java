package com.fbztec.hush.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitFilterTest {

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    private RateLimitFilter filter(int create, int meta, int reveal, int failures) {
        return new RateLimitFilter(new RateLimitProperties(create, meta, reveal, failures), meters);
    }

    private MockHttpServletResponse call(RateLimitFilter filter, String method, String path, String ip, int status)
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setServletPath(path);
        request.setRemoteAddr(ip);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, new MockFilterChain() {
            @Override
            public void doFilter(jakarta.servlet.ServletRequest req, jakarta.servlet.ServletResponse res) {
                ((HttpServletResponse) res).setStatus(status);
            }
        });
        return response;
    }

    @Test
    void blocksAfterTheLimitWithRetryAfter() throws Exception {
        RateLimitFilter filter = filter(2, 60, 20, 10);

        assertThat(call(filter, "POST", "/api/secrets", "10.0.0.1", 201).getStatus()).isEqualTo(201);
        assertThat(call(filter, "POST", "/api/secrets", "10.0.0.1", 201).getStatus()).isEqualTo(201);
        MockHttpServletResponse blocked = call(filter, "POST", "/api/secrets", "10.0.0.1", 201);

        assertThat(blocked.getStatus()).isEqualTo(429);
        assertThat(Long.parseLong(blocked.getHeader("Retry-After"))).isPositive();
        assertThat(blocked.getContentAsString()).contains("429 TOO_MANY_REQUESTS");
        assertThat(meters.counter("hush.ratelimit.rejected", "route", "create").count()).isEqualTo(1);
    }

    @Test
    void repeatedWrongPassphrasesBurnTheFailureBudget() throws Exception {
        RateLimitFilter filter = filter(10, 60, 20, 3);

        for (int i = 0; i < 3; i++) {
            assertThat(call(filter, "POST", "/api/secrets/s" + i + "/reveal", "10.0.0.1", 403).getStatus())
                    .isEqualTo(403);
        }
        assertThat(call(filter, "POST", "/api/secrets/any/reveal", "10.0.0.1", 200).getStatus()).isEqualTo(429);
    }

    @Test
    void parallelFailingLookupsCannotOvershootTheFailureBudget() throws Exception {
        RateLimitFilter filter = filter(10, 60, 20, 3);
        CountDownLatch inFlight = new CountDownLatch(3);
        CountDownLatch release = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newFixedThreadPool(3)) {
            List<Future<Integer>> slow = new ArrayList<>();
            for (int i = 0; i < 3; i++) {
                String path = "/api/secrets/s" + i + "/reveal";
                slow.add(pool.submit(() -> {
                    MockHttpServletRequest request = new MockHttpServletRequest("POST", path);
                    request.setServletPath(path);
                    request.setRemoteAddr("10.0.0.1");
                    MockHttpServletResponse response = new MockHttpServletResponse();
                    filter.doFilter(request, response, (req, res) -> {
                        inFlight.countDown();
                        try {
                            release.await();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        ((HttpServletResponse) res).setStatus(403);
                    });
                    return response.getStatus();
                }));
            }
            int fourth;
            try {
                assertThat(inFlight.await(10, TimeUnit.SECONDS)).isTrue();
                fourth = call(filter, "POST", "/api/secrets/s3/reveal", "10.0.0.1", 403).getStatus();
            } finally {
                release.countDown(); // never leave the pool blocked, even when an assertion fails
            }
            // the 3 in-flight attempts hold the whole budget: a 4th parallel one is refused right away
            assertThat(fourth).isEqualTo(429);
            for (Future<Integer> result : slow) {
                assertThat(result.get(10, TimeUnit.SECONDS)).isEqualTo(403);
            }
        }
    }

    @Test
    void successfulLookupsGiveTheirReservedFailureTokenBack() throws Exception {
        RateLimitFilter filter = filter(10, 60, 20, 3);
        for (int i = 0; i < 6; i++) {
            assertThat(call(filter, "GET", "/api/secrets/ok" + i, "10.0.0.1", 200).getStatus()).isEqualTo(200);
        }
    }

    @Test
    void ipsAreIndependentAndForwardedHeaderIsIgnored() throws Exception {
        RateLimitFilter filter = filter(1, 60, 20, 10);

        assertThat(call(filter, "POST", "/api/secrets", "10.0.0.1", 201).getStatus()).isEqualTo(201);
        assertThat(call(filter, "POST", "/api/secrets", "10.0.0.2", 201).getStatus()).isEqualTo(201);

        // spoofing X-Forwarded-For must not grant a fresh budget
        MockHttpServletRequest spoofed = new MockHttpServletRequest("POST", "/api/secrets");
        spoofed.setServletPath("/api/secrets");
        spoofed.setRemoteAddr("10.0.0.1");
        spoofed.addHeader("X-Forwarded-For", "9.9.9.9");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(spoofed, response, new MockFilterChain());
        assertThat(response.getStatus()).isEqualTo(429);
    }

    @Test
    void ipv6AddressesOfOneSlash64ShareABudget() throws Exception {
        RateLimitFilter filter = filter(1, 60, 20, 10);

        assertThat(call(filter, "POST", "/api/secrets", "2001:db8:1:2:0:0:0:1", 201).getStatus()).isEqualTo(201);
        // another address of the same /64, written in compressed form
        assertThat(call(filter, "POST", "/api/secrets", "2001:db8:1:2::ffff", 201).getStatus()).isEqualTo(429);
        // a different /64 has its own budget
        assertThat(call(filter, "POST", "/api/secrets", "2001:db8:1:3::1", 201).getStatus()).isEqualTo(201);
        assertThat(RateLimitFilter.clientKey("10.0.0.1")).isEqualTo("10.0.0.1");
    }

    @Test
    void repeatedFailedLookupsAreBlockedEvenBelowTheRequestLimit() throws Exception {
        RateLimitFilter filter = filter(10, 60, 20, 3);

        for (int i = 0; i < 3; i++) {
            assertThat(call(filter, "GET", "/api/secrets/dead" + i, "10.0.0.1", 404).getStatus()).isEqualTo(404);
        }
        // the budget is spent: even a lookup that would succeed is refused, on both lookup routes
        assertThat(call(filter, "GET", "/api/secrets/any", "10.0.0.1", 200).getStatus()).isEqualTo(429);
        assertThat(call(filter, "POST", "/api/secrets/any/reveal", "10.0.0.1", 200).getStatus()).isEqualTo(429);
        // creating is not a lookup
        assertThat(call(filter, "POST", "/api/secrets", "10.0.0.1", 201).getStatus()).isEqualTo(201);
    }

    @Test
    void otherPathsAreNotLimited() throws Exception {
        RateLimitFilter filter = filter(1, 1, 1, 1);
        for (int i = 0; i < 5; i++) {
            assertThat(call(filter, "GET", "/actuator/health", "10.0.0.1", 200).getStatus()).isEqualTo(200);
        }
    }
}
