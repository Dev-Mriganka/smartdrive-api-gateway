package com.smartdrive.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Security headers filter to add comprehensive security headers
 * Protects against XSS, clickjacking, MIME sniffing, and other attacks
 */
@Component
@Slf4j
public class SecurityHeadersFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();

            // Security headers for protection against common attacks
            response.getHeaders().add("X-Content-Type-Options", "nosniff");
            response.getHeaders().add("X-Frame-Options", "DENY");
            response.getHeaders().add("X-XSS-Protection", "1; mode=block");
            response.getHeaders().add("Referrer-Policy", "strict-origin-when-cross-origin");
            response.getHeaders().add("Permissions-Policy",
                    "geolocation=(), microphone=(), camera=(), payment=(), usb=()");

            // Content Security Policy - restrictive but functional
            response.getHeaders().add("Content-Security-Policy",
                    "default-src 'self'; " +
                            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                            "style-src 'self' 'unsafe-inline'; " +
                            "img-src 'self' data: https:; " +
                            "font-src 'self' data:; " +
                            "connect-src 'self' ws: wss:; " +
                            "frame-ancestors 'none'");

            // HTTPS Strict Transport Security (only if using HTTPS)
            if (exchange.getRequest().getHeaders().getFirst("X-Forwarded-Proto") != null &&
                    exchange.getRequest().getHeaders().getFirst("X-Forwarded-Proto").equals("https")) {
                response.getHeaders().add("Strict-Transport-Security",
                        "max-age=31536000; includeSubDomains; preload");
            }

            // Remove server information headers
            response.getHeaders().remove("Server");
            response.getHeaders().add("Server", "SmartDrive-Gateway");

            // Cache control for sensitive endpoints
            String path = exchange.getRequest().getPath().value();
            if (path.contains("/auth/") || path.contains("/api/v1/users/")) {
                response.getHeaders().add("Cache-Control", "no-store, no-cache, must-revalidate, private");
                response.getHeaders().add("Pragma", "no-cache");
                response.getHeaders().add("Expires", "0");
            }

            log.debug("✅ Security headers added for path: {}", path);
        }));
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE; // Run last to ensure headers are set
    }
}
