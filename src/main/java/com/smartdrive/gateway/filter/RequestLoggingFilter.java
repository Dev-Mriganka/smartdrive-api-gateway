package com.smartdrive.gateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Simple request logging filter for debugging gateway routing
 */
@Component
@Slf4j
public class RequestLoggingFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        String method = request.getMethod() != null ? request.getMethod().name() : "UNKNOWN";
        
        log.info("🌐 GATEWAY REQUEST: {} {}", method, path);
        
        return chain.filter(exchange)
            .doOnSuccess(v -> log.info("✅ GATEWAY RESPONSE: {} {} - SUCCESS", method, path))
            .doOnError(error -> log.error("❌ GATEWAY RESPONSE: {} {} - ERROR: {}", method, path, error.getMessage()));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE; // Run this first to log all requests
    }
}
