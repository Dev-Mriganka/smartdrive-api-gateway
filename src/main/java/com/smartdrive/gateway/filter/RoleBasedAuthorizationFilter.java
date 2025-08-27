package com.smartdrive.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;


@Component
@RequiredArgsConstructor
@Slf4j
public class RoleBasedAuthorizationFilter implements GlobalFilter, Ordered {

    // Define route-to-role mappings
    private static final Map<String, List<String>> ROUTE_ROLE_MAPPINGS = Map.of(
        "/api/v1/admin/", List.of("SMARTDRIVE_ADMIN"),
        "/api/v1/users/", List.of("SMARTDRIVE_USER", "SMARTDRIVE_ADMIN"),
        "/api/v1/files/admin/", List.of("SMARTDRIVE_ADMIN"),
        "/api/v1/ai/premium/", List.of("SMARTDRIVE_PREMIUM", "SMARTDRIVE_ADMIN")
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        log.debug("🔍 Authorization check for path: {}", path);
        
        // Skip authorization for public endpoints
        if (isPublicEndpoint(path)) {
            log.debug("✅ Public endpoint - skipping authorization: {}", path);
            return chain.filter(exchange);
        }
        
        return ReactiveSecurityContextHolder.getContext()
            .map(context -> context.getAuthentication())
            .cast(JwtAuthenticationToken.class)
            .flatMap(authentication -> {
                Jwt jwt = authentication.getToken();
                List<String> userRoles = jwt.getClaimAsStringList("roles");
                
                if (hasRequiredRole(path, userRoles)) {
                    log.debug("✅ Authorization granted for path: {} with roles: {}", path, userRoles);
                    return chain.filter(exchange);
                } else {
                    log.warn("❌ Authorization denied for path: {} with roles: {}", path, userRoles);
                    return handleForbidden(exchange);
                }
            })
            .switchIfEmpty(chain.filter(exchange));
    }

    /**
     * Check if user has required role for the path
     */
    private boolean hasRequiredRole(String path, List<String> userRoles) {
        if (userRoles == null) {
            return false;
        }
        
        // Check each route pattern
        for (Map.Entry<String, List<String>> entry : ROUTE_ROLE_MAPPINGS.entrySet()) {
            if (path.startsWith(entry.getKey())) {
                List<String> requiredRoles = entry.getValue();
                
                // User needs at least one of the required roles
                return userRoles.stream()
                    .anyMatch(userRole -> requiredRoles.contains(userRole));
            }
        }
        
        // Default: require any authenticated user
        return !userRoles.isEmpty();
    }

    /**
     * Handle forbidden access
     */
    private Mono<Void> handleForbidden(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        
        String errorMessage = """
            {
                "error": "Forbidden",
                "message": "Insufficient permissions for this resource",
                "timestamp": "%s"
            }
            """.formatted(java.time.Instant.now());
        
        byte[] bytes = errorMessage.getBytes(StandardCharsets.UTF_8);
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }

    /**
     * Check if endpoint is public
     */
    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/auth/oauth2/") ||
               path.startsWith("/auth/.well-known/") ||
               path.equals("/api/v1/users/register") ||
               path.startsWith("/api/v1/users/verify-email") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/actuator/info");
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 150; // After auth, before rate limiting
    }
}