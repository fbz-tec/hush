package com.fbztec.hush.security;

import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Per client IP limits on the three secret routes, plus a budget of failed lookups so that probing
 * ids stays slow even below the request limits.
 * The IP is the TCP peer address on purpose: there is no proxy, so X-Forwarded-For is attacker-controlled.
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);
    private static final String BASE = "/api/secrets";
    private static final Duration FAILURE_WINDOW = Duration.ofMinutes(10);

    enum Route { CREATE, META, REVEAL }

    private static final class Client {
        final Bucket create;
        final Bucket meta;
        final Bucket reveal;
        final Bucket failures;
        volatile long lastSeenNanos = System.nanoTime();

        Client(RateLimitProperties p) {
            create = bucket(p.create(), Duration.ofMinutes(1));
            meta = bucket(p.meta(), Duration.ofMinutes(1));
            reveal = bucket(p.reveal(), Duration.ofMinutes(1));
            failures = bucket(p.failures(), FAILURE_WINDOW);
        }

        Bucket forRoute(Route route) {
            return switch (route) {
                case CREATE -> create;
                case META -> meta;
                case REVEAL -> reveal;
            };
        }

        private static Bucket bucket(int capacity, Duration period) {
            return Bucket.builder()
                    .addLimit(limit -> limit.capacity(capacity).refillGreedy(capacity, period))
                    .build();
        }
    }

    private final RateLimitProperties properties;
    private final MeterRegistry meters;
    // shortcut: in-memory, valid for a single instance; move to a shared store if the app is scaled out
    private final Map<String, Client> clients = new ConcurrentHashMap<>();

    public RateLimitFilter(RateLimitProperties properties, MeterRegistry meters) {
        this.properties = properties;
        this.meters = meters;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Route route = route(request);
        if (route == null) {
            chain.doFilter(request, response);
            return;
        }

        String ip = request.getRemoteAddr();
        MDC.put("ip", ip); // picked up by the log pattern, also for the service logs of this request
        try {
            Client client = clients.computeIfAbsent(clientKey(ip), k -> new Client(properties));
            client.lastSeenNanos = System.nanoTime();

            ConsumptionProbe probe = client.forRoute(route).tryConsumeAndReturnRemaining(1);
            if (!probe.isConsumed()) {
                reject(response, route, probe.getNanosToWaitForRefill());
                return;
            }
            boolean lookup = route != Route.CREATE;
            if (!lookup) {
                chain.doFilter(request, response);
                return;
            }
            // a failure token is reserved up front, so a parallel burst cannot all pass a check made before
            // any of them failed; it is handed back when the lookup turns out not to be a failure
            ConsumptionProbe failures = client.failures.tryConsumeAndReturnRemaining(1);
            if (!failures.isConsumed()) {
                reject(response, route, failures.getNanosToWaitForRefill());
                return;
            }
            boolean failed = false;
            try {
                chain.doFilter(request, response);
                // any 404 on a lookup (unknown, expired, revealed: indistinguishable) burns the failure budget,
                // and so does a wrong passphrase (403 on reveal): guessing stays slow across secrets too
                int status = response.getStatus();
                failed = status == HttpServletResponse.SC_NOT_FOUND
                        || route == Route.REVEAL && status == HttpServletResponse.SC_FORBIDDEN;
            } finally {
                if (!failed) {
                    client.failures.addTokens(1);
                }
            }
        } finally {
            MDC.remove("ip");
        }
    }

    // an IPv6 user owns a whole /64: one bucket per address would let them rotate past every limit
    static String clientKey(String ip) {
        if (ip.indexOf(':') < 0) {
            return ip;
        }
        try {
            InetAddress address = InetAddress.getByName(ip); // an IP literal: no DNS lookup
            byte[] bytes = address.getAddress();
            return bytes.length == 16 ? HexFormat.of().formatHex(bytes, 0, 8) + "::/64" : address.getHostAddress();
        } catch (UnknownHostException e) {
            return ip;
        }
    }

    private static Route route(HttpServletRequest request) {
        String path = request.getServletPath();
        if (!path.startsWith(BASE)) {
            return null;
        }
        String rest = path.substring(BASE.length());
        String method = request.getMethod();
        if (rest.isEmpty()) {
            return "POST".equals(method) ? Route.CREATE : null;
        }
        String[] parts = rest.startsWith("/") ? rest.substring(1).split("/", -1) : new String[]{"", ""};
        if (parts.length == 1 && !parts[0].isEmpty() && "GET".equals(method)) {
            return Route.META;
        }
        if (parts.length == 2 && !parts[0].isEmpty() && "reveal".equals(parts[1]) && "POST".equals(method)) {
            return Route.REVEAL;
        }
        return null;
    }

    private void reject(HttpServletResponse response, Route route, long nanosToWait) throws IOException {
        long retryAfter = Math.max(1, Duration.ofNanos(nanosToWait).plusMillis(999).toSeconds());
        meters.counter("hush.ratelimit.rejected", "route", route.name().toLowerCase()).increment();
        log.warn("Rate limit exceeded: route={} retryAfter={}s", route, retryAfter);

        response.setStatus(429);
        response.setHeader("Retry-After", Long.toString(retryAfter));
        response.setContentType("application/json");
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        // same shape as ErrorResponse; hand-written because the path may hold a client-controlled id
        response.getWriter().write("{\"apiPath\":\"uri=" + BASE + "\",\"errorCode\":\"429 TOO_MANY_REQUESTS\","
                + "\"errorMessage\":\"Too Many Requests\",\"errorTime\":\"" + Instant.now() + "\"}");
    }

    // drop clients idle for longer than the slowest refill window so the map cannot grow forever
    @Scheduled(fixedDelay = 60_000)
    public void evictIdleClients() {
        long limit = System.nanoTime() - FAILURE_WINDOW.toNanos();
        clients.values().removeIf(client -> client.lastSeenNanos - limit < 0);
    }
}
