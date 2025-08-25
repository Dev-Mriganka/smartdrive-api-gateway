package com.smartdrive.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Global authentication filter for API Gateway
 * Validates JWT tokens and propagates user context
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        log.debug("🔍 Processing request: {} {}", request.getMethod(), path);
        
        // Skip authentication for public endpoints
        if (isPublicEndpoint(path)) {
            log.debug("✅ Public endpoint - skipping authentication: {}", path);
            return chain.filter(exchange);
        }
        
        return ReactiveSecurityContextHolder.getContext()
            .map(context -> context.getAuthentication())
            .flatMap(authentication -> {
                if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
                    Jwt jwt = (Jwt) authentication.getPrincipal();
                    return addUserContextHeaders(exchange, jwt, chain);
                } else {
                    log.warn("⚠️ No valid JWT authentication found for: {}", path);
                    return chain.filter(exchange);
                }
            })
            .switchIfEmpty(chain.filter(exchange));
    }

    /**
     * Add user context headers to downstream services
     */
    private Mono<Void> addUserContextHeaders(ServerWebExchange exchange, Jwt jwt, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        // Extract user information from JWT
        String userId = jwt.getSubject();
        String username = jwt.getClaimAsString("preferred_username");
        List<String> roles = jwt.getClaimAsStringList("roles");
        
        log.debug("👤 User context - ID: {}, Username: {}, Roles: {}", userId, username, roles);
        
        // Add user context headers for downstream services
        ServerHttpRequest modifiedRequest = request.mutate()
            .header("X-User-ID", userId)
            .header("X-User-Username", username != null ? username : "")
            .header("X-User-Roles", roles != null ? String.join(",", roles) : "")
            .header("X-User-Email", jwt.getClaimAsString("email"))
            .build();
        
        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Check if endpoint is public (no authentication required)
     */
    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/auth/oauth2/") ||
               path.startsWith("/auth/.well-known/") ||
               path.startsWith("/auth/api/v1/users/register") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/actuator/info");
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100; // Run after security filters
    }
}
