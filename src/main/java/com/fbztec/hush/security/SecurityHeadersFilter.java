package com.fbztec.hush.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Hardening headers on every response. HSTS is deliberately absent until the app is served over TLS.
 */
public class SecurityHeadersFilter extends OncePerRequestFilter {

    // the frontend has no inline script/style and no third-party resource; the favicon is a data: URI
    static final String CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            + "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        response.setHeader("Content-Security-Policy", CSP);
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "no-referrer");
        if (request.getServletPath().startsWith("/api/secrets")) {
            // the reveal response holds the secret in clear: it must not land in any cache
            response.setHeader("Cache-Control", "no-store");
        }
        chain.doFilter(request, response);
    }
}
