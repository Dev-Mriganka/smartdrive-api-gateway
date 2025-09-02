package com.smartdrive.gateway.filter;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Industry Standard JWT Validation Filter
 * 
 * Following Netflix/Amazon/Google patterns:
 * 1. Gateway handles JWT validation (no auth service calls)
 * 2. Multi-layer caching strategy
 * 3. Token blacklist checking
 * 4. User context injection
 * 5. Performance-optimized
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class IndustryStandardJWTFilter implements GlobalFilter, Ordered {

    private final JwtDecoder jwtDecoder;
    private final RedisTemplate<String, Object> redisTemplate;
    
    // Cache keys
    private static final String JWT_VALIDATION_CACHE = "gateway:jwt:validation:";
    private static final String BLACKLIST_CACHE = "gateway:blacklist:";
    private static final String USER_CONTEXT_CACHE = "gateway:user:";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        // Skip public endpoints
        if (isPublicEndpoint(path)) {
            return addPublicHeaders(exchange, chain);
        }
        
        String token = extractBearerToken(request);
        if (token == null) {
            return unauthorizedResponse(exchange, "Missing or invalid Authorization header");
        }
        
        return validateTokenWithCaching(token)
            .flatMap(jwt -> {
                if (jwt == null) {
                    return unauthorizedResponse(exchange, "Invalid or expired token");
                }
                return addAuthenticatedHeaders(exchange, jwt, chain);
            })
            .onErrorResume(error -> {
                log.error("JWT validation error: {}", error.getMessage());
                return unauthorizedResponse(exchange, "Token validation failed");
            });
    }

    /**
     * Multi-layer token validation with caching
     * Layer 1: In-memory cache (fastest)
     * Layer 2: Redis cache (fast)
     * Layer 3: JWT decode + validate (slower)
     */
    private Mono<Jwt> validateTokenWithCaching(String token) {
        return Mono.fromCallable(() -> {
            String tokenHash = String.valueOf(token.hashCode());
            
            // Layer 1: Check if validation result is cached in Redis
            Boolean cachedValidation = getCachedValidation(tokenHash);
            if (Boolean.FALSE.equals(cachedValidation)) {
                log.debug("🚫 Token validation cache hit: INVALID");
                return null;
            }
            
            // Layer 2: Check token blacklist
            if (isTokenBlacklisted(token)) {
                log.debug("🚫 Token is blacklisted");
                cacheValidationResult(tokenHash, false, 300); // Cache for 5 minutes
                return null;
            }
            
            // Layer 3: JWT validation (expensive operation)
            try {
                Jwt jwt = jwtDecoder.decode(token);
                
                // Check expiry
                if (jwt.getExpiresAt().isBefore(Instant.now())) {
                    log.debug("🚫 Token expired");
                    cacheValidationResult(tokenHash, false, 60); // Cache for 1 minute
                    return null;
                }
                
                // Cache successful validation
                cacheValidationResult(tokenHash, true, 300); // Cache for 5 minutes
                cacheUserContext(jwt, 600); // Cache user context for 10 minutes
                
                log.debug("✅ Token validation successful for user: {}", jwt.getSubject());
                return jwt;
                
            } catch (JwtException e) {
                log.debug("🚫 JWT validation failed: {}", e.getMessage());
                cacheValidationResult(tokenHash, false, 300);
                return null;
            }
        });
    }

    /**
     * Check if token is blacklisted (with caching)
     */
    private boolean isTokenBlacklisted(String token) {
        try {
            // Quick parse to get token ID without full validation
            String[] parts = token.split("\\.");
            if (parts.length != 3) return true;
            
            String payload = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
            String jti = extractJsonValue(payload, "jti");
            
            if (jti == null) return false;
            
            // Check Redis blacklist with caching
            String cacheKey = BLACKLIST_CACHE + jti;
            Boolean cached = (Boolean) redisTemplate.opsForValue().get(cacheKey);
            
            if (cached != null) {
                return cached;
            }
            
            // Check actual blacklist
            boolean isBlacklisted = redisTemplate.hasKey("authservice:blacklist:access:" + jti) ||
                                   redisTemplate.hasKey("authservice:blacklist:refresh:" + jti);
            
            // Cache result for 60 seconds
            redisTemplate.opsForValue().set(cacheKey, isBlacklisted, 60, TimeUnit.SECONDS);
            
            return isBlacklisted;
            
        } catch (Exception e) {
            log.warn("Error checking token blacklist: {}", e.getMessage());
            return false; // Fail open for availability
        }
    }

    /**
     * Get cached validation result
     */
    private Boolean getCachedValidation(String tokenHash) {
        try {
            String key = JWT_VALIDATION_CACHE + tokenHash;
            return (Boolean) redisTemplate.opsForValue().get(key);
        } catch (Exception e) {
            log.warn("Error getting cached validation: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Cache validation result
     */
    private void cacheValidationResult(String tokenHash, boolean isValid, int ttlSeconds) {
        try {
            String key = JWT_VALIDATION_CACHE + tokenHash;
            redisTemplate.opsForValue().set(key, isValid, ttlSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("Error caching validation result: {}", e.getMessage());
        }
    }

    /**
     * Cache user context for faster lookups
     */
    private void cacheUserContext(Jwt jwt, int ttlSeconds) {
        try {
            String userId = jwt.getSubject();
            String key = USER_CONTEXT_CACHE + userId;
            
            UserContext context = UserContext.builder()
                .userId(userId)
                .email(jwt.getClaimAsString("email"))
                .roles(jwt.getClaimAsStringList("roles"))
                .build();
                
            redisTemplate.opsForValue().set(key, context, ttlSeconds, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("Error caching user context: {}", e.getMessage());
        }
    }

    /**
     * Add authenticated user headers (industry standard)
     */
    private Mono<Void> addAuthenticatedHeaders(ServerWebExchange exchange, Jwt jwt, GatewayFilterChain chain) {
        String userId = jwt.getSubject();
        String email = jwt.getClaimAsString("email");
        List<String> roles = jwt.getClaimAsStringList("roles");
        
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
            // Standard headers
            .header("X-User-ID", userId)
            .header("X-User-Email", email != null ? email : "")
            .header("X-User-Roles", roles != null ? String.join(",", roles) : "")
            
            // Security headers
            .header("X-Token-Subject", userId)
            .header("X-Token-Issued-At", String.valueOf(jwt.getIssuedAt().getEpochSecond()))
            .header("X-Token-Expires-At", String.valueOf(jwt.getExpiresAt().getEpochSecond()))
            
            // Internal service headers
            .header("X-Internal-Auth", "gateway-validated")
            .header("X-Request-ID", generateRequestId())
            .header("X-Validated-By", "SmartDrive-Gateway")
            .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Add public headers for non-authenticated requests
     */
    private Mono<Void> addPublicHeaders(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
            .header("X-Request-Type", "public")
            .header("X-Request-ID", generateRequestId())
            .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Generate unauthorized response
     */
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange, String message) {
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        
        String body = String.format("{\"error\":\"unauthorized\",\"message\":\"%s\"}", message);
        org.springframework.core.io.buffer.DataBuffer buffer = 
            exchange.getResponse().bufferFactory().wrap(body.getBytes());
            
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    /**
     * Extract Bearer token from Authorization header
     */
    private String extractBearerToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    /**
     * Check if endpoint is public (no auth required)
     */
    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/oauth2/") || // Add JWKS endpoint
               path.startsWith("/api/v1/auth/") ||
               path.startsWith("/api/auth/") ||
               path.equals("/api/v1/users/register") ||
               path.startsWith("/api/v1/users/verify-email") ||
               path.startsWith("/api/v1/users/profile/email") ||
               path.startsWith("/api/v1/users/exists/") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/swagger-ui/") ||
               path.startsWith("/v3/api-docs");
    }

    /**
     * Extract JSON value from JWT payload (simple implementation)
     */
    private String extractJsonValue(String json, String key) {
        try {
            String pattern = "\"" + key + "\":\"";
            int start = json.indexOf(pattern);
            if (start == -1) return null;
            start += pattern.length();
            int end = json.indexOf("\"", start);
            if (end == -1) return null;
            return json.substring(start, end);
        } catch (Exception e) {
            return null;
        }
    }

    private String generateRequestId() {
        return java.util.UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public int getOrder() {
        return -100; // High priority
    }

    /**
     * User context for caching
     */
    public static class UserContext {
        private String userId;
        private String email;
        private List<String> roles;
        
        public static UserContextBuilder builder() {
            return new UserContextBuilder();
        }
        
        // Builder pattern implementation
        public static class UserContextBuilder {
            private String userId;
            private String email;
            private List<String> roles;
            
            public UserContextBuilder userId(String userId) {
                this.userId = userId;
                return this;
            }
            
            public UserContextBuilder email(String email) {
                this.email = email;
                return this;
            }
            
            public UserContextBuilder roles(List<String> roles) {
                this.roles = roles;
                return this;
            }
            
            public UserContext build() {
                UserContext context = new UserContext();
                context.userId = this.userId;
                context.email = this.email;
                context.roles = this.roles;
                return context;
            }
        }
        
        // Getters
        public String getUserId() { return userId; }
        public String getEmail() { return email; }
        public List<String> getRoles() { return roles; }
    }
}
