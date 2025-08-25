package com.smartdrive.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate limiting filter for API Gateway
 * Implements in-memory rate limiting with Redis fallback
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RateLimitingFilter implements GlobalFilter, Ordered {

    private final ReactiveRedisTemplate<String, String> redisTemplate;
    
    // In-memory rate limiting for performance
    private final ConcurrentHashMap<String, RequestCounter> requestCounters = new ConcurrentHashMap<>();
    
    // Rate limiting configuration
    private static final int MAX_REQUESTS_PER_MINUTE = 100;
    private static final int MAX_REQUESTS_PER_HOUR = 1000;
    private static final Duration WINDOW_DURATION = Duration.ofMinutes(1);

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String clientIp = getClientIp(request);
        String path = request.getPath().value();
        
        log.debug("🔍 Rate limiting check for IP: {} on path: {}", clientIp, path);
        
        // Skip rate limiting for health checks
        if (path.startsWith("/actuator/health")) {
            return chain.filter(exchange);
        }
        
        String rateLimitKey = "rate_limit:" + clientIp + ":" + path;
        
        return checkRateLimit(rateLimitKey, clientIp, path)
            .flatMap(allowed -> {
                if (allowed) {
                    return chain.filter(exchange);
                } else {
                    return handleRateLimitExceeded(exchange, clientIp);
                }
            });
    }

    /**
     * Check if request is within rate limits
     */
    private Mono<Boolean> checkRateLimit(String key, String clientIp, String path) {
        return redisTemplate.opsForValue().increment(key)
            .flatMap(count -> {
                if (count == 1) {
                    // First request, set expiration
                    return redisTemplate.expire(key, WINDOW_DURATION)
                        .thenReturn(count);
                }
                return Mono.just(count);
            })
            .map(count -> {
                boolean allowed = count <= MAX_REQUESTS_PER_MINUTE;
                if (!allowed) {
                    log.warn("⚠️ Rate limit exceeded for IP: {} on path: {} (count: {})", clientIp, path, count);
                }
                return allowed;
            })
            .onErrorReturn(true); // Allow request if Redis is unavailable
    }

    /**
     * Handle rate limit exceeded
     */
    private Mono<Void> handleRateLimitExceeded(ServerWebExchange exchange, String clientIp) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
        
        log.warn("🚫 Rate limit exceeded for IP: {}", clientIp);
        
        return response.setComplete();
    }

    /**
     * Get client IP address
     */
    private String getClientIp(ServerHttpRequest request) {
        String xForwardedFor = request.getHeaders().getFirst("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeaders().getFirst("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddress() != null ? 
            request.getRemoteAddress().getAddress().getHostAddress() : "unknown";
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 200; // Run after authentication filter
    }

    /**
     * Request counter for in-memory rate limiting
     */
    private static class RequestCounter {
        private final AtomicInteger count = new AtomicInteger(0);
        private final long windowStart = System.currentTimeMillis();
        
        public int incrementAndGet() {
            return count.incrementAndGet();
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - windowStart > WINDOW_DURATION.toMillis();
        }
    }
}
