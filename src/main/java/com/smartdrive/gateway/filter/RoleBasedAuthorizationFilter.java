package com.smartdrive.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;


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
        
        log.info("🔍 RoleBasedAuthorizationFilter: Authorization check for path: {}", path);
        
        // Skip authorization for public endpoints
        if (isPublicEndpoint(path)) {
            log.debug("✅ Public endpoint - skipping authorization: {}", path);
            return chain.filter(exchange);
        }
        
        // Try to get JWT from Authorization header
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            try {
                // Decode JWT payload manually to extract roles
                String[] tokenParts = token.split("\\.");
                if (tokenParts.length == 3) {
                    String payload = tokenParts[1];
                    // Add padding if needed
                    payload += "=".repeat((4 - payload.length() % 4) % 4);
                    
                    String decodedPayload = new String(java.util.Base64.getDecoder().decode(payload));
                    
                    // Simple JSON parsing to extract roles
                    if (decodedPayload.contains("\"roles\":")) {
                        int rolesStart = decodedPayload.indexOf("\"roles\":") + 8;
                        int rolesEnd = decodedPayload.indexOf("]", rolesStart) + 1;
                        String rolesJson = decodedPayload.substring(rolesStart, rolesEnd);
                        
                        log.info("🔍 Extracted roles from JWT: {}", rolesJson);
                        
                        // Extract roles - simplified parsing
                        List<String> userRoles = extractRolesFromJson(rolesJson);
                        
                        if (hasRequiredRole(path, userRoles)) {
                            log.info("✅ Authorization granted for path: {} with roles: {}", path, userRoles);
                            return chain.filter(exchange);
                        } else {
                            log.warn("❌ Authorization denied for path: {} with roles: {}", path, userRoles);
                            return handleForbidden(exchange);
                        }
                    }
                }
            } catch (Exception e) {
                log.warn("❌ Error parsing JWT token: {}", e.getMessage());
                return handleForbidden(exchange);
            }
        }
        
        log.warn("❌ No valid JWT token found for path: {}", path);
        return handleForbidden(exchange);
    }

    /**
     * Extract roles from JSON array string
     */
    private List<String> extractRolesFromJson(String rolesJson) {
        try {
            // Simple extraction - look for quoted strings in the array
            return java.util.Arrays.stream(rolesJson.replace("[", "").replace("]", "").split(","))
                .map(String::trim)
                .map(role -> role.replace("\"", ""))
                .filter(role -> !role.isEmpty())
                .toList();
        } catch (Exception e) {
            log.warn("❌ Error extracting roles from JSON: {}", e.getMessage());
            return List.of();
        }
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
                // Handle both with and without ROLE_ prefix
                return userRoles.stream()
                    .anyMatch(userRole -> {
                        String roleWithoutPrefix = userRole.startsWith("ROLE_") 
                            ? userRole.substring(5) 
                            : userRole;
                        return requiredRoles.contains(roleWithoutPrefix);
                    });
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
               path.startsWith("/api/v1/auth/") ||
               path.equals("/api/v1/users/register") ||
               // path.equals("/api/v1/users/create-admin") || // REMOVED: Now requires authentication
               path.startsWith("/api/v1/users/verify-email") ||
               path.startsWith("/api/v1/users/profile/email") ||
               path.startsWith("/api/v1/users/exists/") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/actuator/info");
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 150; // After auth, before rate limiting
    }
}