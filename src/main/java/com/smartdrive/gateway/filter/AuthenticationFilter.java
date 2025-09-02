package com.smartdrive.gateway.filter;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import com.smartdrive.gateway.config.GatewayJWTCacheService;
import com.smartdrive.gateway.config.GatewayTokenBlacklistService;
import com.smartdrive.gateway.config.SecretsConfig;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final SecretsConfig secretsConfig;
    private final JwtDecoder jwtDecoder;
    private final GatewayTokenBlacklistService blacklistService;
    private final GatewayJWTCacheService jwtCacheService;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();

        log.debug("🔍 Enhanced auth processing: {} {}", request.getMethod(), path);

        // Skip for public endpoints
        if (isPublicEndpoint(path)) {
            return addPublicHeaders(exchange, chain);
        }

        // Industry Standard: Gateway validates JWT directly
        String token = extractBearerToken(request);
        if (token == null) {
            log.warn("⚠️ No JWT token found for protected path: {}", path);
            return unauthorizedResponse(exchange);
        }

        return validateTokenIndustryStandard(token)
            .flatMap(jwt -> {
                if (jwt == null) {
                    return unauthorizedResponse(exchange);
                }
                return addAuthenticatedUserHeaders(exchange, jwt, chain);
            })
            .onErrorResume(error -> {
                log.error("❌ JWT validation failed for path {}: {}", path, error.getMessage());
                return unauthorizedResponse(exchange);
            });
    }

    /**
     * Add headers for authenticated requests
     */
    private Mono<Void> addAuthenticatedUserHeaders(ServerWebExchange exchange, Jwt jwt, GatewayFilterChain chain) {
        String userId = jwt.getSubject();
        String email = jwt.getClaimAsString("email");
        List<String> roles = jwt.getClaimAsStringList("roles");
        String path = exchange.getRequest().getPath().value();

        // Generate signature for internal authentication
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String signature = generateSignature(userId, path, timestamp);

        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .header("X-User-Email", email != null ? email : "")
                .header("X-User-Roles", roles != null ? String.join(",", roles) : "")
                .header("X-Internal-Auth", secretsConfig.getInternalSecret())
                .header("X-Gateway-Signature", signature)
                .header("X-Gateway-Timestamp", timestamp)
                .header("X-Forwarded-By", "SmartDrive-Gateway")
                .header("X-Request-ID", generateRequestId())
                .build();

        log.debug("✅ User context headers added for user: {}", email);
        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Add headers for public requests (still need internal auth for verification
     * endpoints)
     */
    private Mono<Void> addPublicHeaders(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();

        // Generate signature for public requests (no userId)
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String signature = generateSignature("", path, timestamp);

        // Add internal auth and signature headers for service-to-service validation
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-Internal-Auth", secretsConfig.getInternalSecret())
                .header("X-Gateway-Signature", signature)
                .header("X-Gateway-Timestamp", timestamp)
                .header("X-Forwarded-By", "SmartDrive-Gateway")
                .header("X-Request-ID", generateRequestId())
                .build();

        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Generate HMAC signature for request validation
     */
    private String generateSignature(String userId, String path, String timestamp) {
        try {
            String data = userId + "|" + path + "|" + timestamp;
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretsConfig.getSignatureSecret().getBytes(),
                    "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(signature);
        } catch (Exception e) {
            log.error("❌ Failed to generate signature", e);
            return "invalid";
        }
    }

    private boolean isPublicEndpoint(String path) {
        return path.startsWith("/auth/oauth2/") ||
                path.startsWith("/auth/.well-known/") ||
                path.startsWith("/api/v1/auth/") ||
                path.equals("/api/v1/users/register") ||
                path.startsWith("/api/v1/users/verify-email") ||
                path.startsWith("/api/v1/users/profile/email") ||
                path.startsWith("/api/v1/users/exists/") ||
                path.startsWith("/actuator/health") ||
                path.startsWith("/actuator/info");
    }

    /**
     * Try to manually extract JWT when Spring Security context is not available
     */
    private Mono<Void> tryManualJwtExtraction(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String authHeader = request.getHeaders().getFirst("Authorization");
        String path = request.getPath().value();
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            try {
                // Manually parse JWT payload to extract user info
                String[] tokenParts = token.split("\\.");
                if (tokenParts.length == 3) {
                    String payload = tokenParts[1];
                    // Add padding if needed for base64 decoding
                    payload += "=".repeat((4 - payload.length() % 4) % 4);
                    
                    String decodedPayload = new String(Base64.getDecoder().decode(payload));
                    log.debug("🔍 Manual JWT payload extraction: {}", decodedPayload);
                    
                    // Extract user info using simple JSON parsing
                    String userId = extractJsonValue(decodedPayload, "sub");
                    String email = extractJsonValue(decodedPayload, "email");
                    String rolesJson = extractJsonArray(decodedPayload, "roles");
                    
                    if (userId != null) {
                        log.info("⚙️ Manual JWT extraction successful for user: {} (path: {})", email, path);
                        return addManualAuthHeaders(exchange, userId, email, rolesJson, chain);
                    }
                }
            } catch (Exception e) {
                log.warn("⚠️ Manual JWT extraction failed: {}", e.getMessage());
            }
        }
        
        log.warn("⚠️ No valid JWT found, using minimal headers for path: {}", path);
        return addPublicHeaders(exchange, chain);
    }
    
    /**
     * Add headers based on manually extracted JWT
     */
    private Mono<Void> addManualAuthHeaders(ServerWebExchange exchange, String userId, 
                                          String email, String rolesJson, 
                                          GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String signature = generateSignature(userId, path, timestamp);
        
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .header("X-User-Email", email != null ? email : "")
                .header("X-User-Roles", rolesJson != null ? rolesJson.replace("[", "").replace("]", "").replace("\"", "") : "")
                .header("X-Internal-Auth", secretsConfig.getInternalSecret())
                .header("X-Gateway-Signature", signature)
                .header("X-Gateway-Timestamp", timestamp)
                .header("X-Forwarded-By", "SmartDrive-Gateway")
                .header("X-Request-ID", generateRequestId())
                .build();

        log.debug("⚙️ Manual auth headers added for user: {}", email);
        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }
    
    /**
     * Extract simple JSON string value
     */
    private String extractJsonValue(String json, String key) {
        try {
            String searchPattern = "\"" + key + "\":\"";
            int start = json.indexOf(searchPattern);
            if (start != -1) {
                start += searchPattern.length();
                int end = json.indexOf("\"", start);
                if (end != -1) {
                    return json.substring(start, end);
                }
            }
        } catch (Exception e) {
            log.debug("Error extracting {}: {}", key, e.getMessage());
        }
        return null;
    }
    
    /**
     * Extract JSON array as string
     */
    private String extractJsonArray(String json, String key) {
        try {
            String searchPattern = "\"" + key + "\":[";
            int start = json.indexOf(searchPattern);
            if (start != -1) {
                start += searchPattern.length() - 1; // Keep the [
                int end = json.indexOf("]", start) + 1; // Include the ]
                if (end > start) {
                    return json.substring(start, end);
                }
            }
        } catch (Exception e) {
            log.debug("Error extracting {}: {}", key, e.getMessage());
        }
        return null;
    }

    /**
     * Generate unique request ID for tracing
     */
    /**
     * Industry Standard JWT validation with multi-layer caching
     */
    private Mono<Jwt> validateTokenIndustryStandard(String token) {
        return Mono.fromCallable(() -> {
            String tokenHash = String.valueOf(token.hashCode());
            
            // Layer 1: Check validation cache
            Boolean cachedResult = jwtCacheService.getCachedValidationResult(tokenHash);
            if (Boolean.FALSE.equals(cachedResult)) {
                log.debug("🚫 JWT validation cache hit: INVALID");
                return null;
            }
            
            // Layer 2: Check token blacklist
            String tokenId = extractTokenId(token);
            if (tokenId != null && blacklistService.isTokenBlacklisted(tokenId)) {
                log.debug("🚫 Token is blacklisted: {}", tokenId.substring(0, 8) + "...");
                jwtCacheService.cacheValidationResult(tokenHash, false, 300);
                return null;
            }
            
            // Layer 3: JWT validation (expensive operation)
            try {
                Jwt jwt = jwtDecoder.decode(token);
                
                // Check expiry
                if (jwt.getExpiresAt().isBefore(Instant.now())) {
                    log.debug("🚫 Token expired");
                    jwtCacheService.cacheValidationResult(tokenHash, false, 60);
                    return null;
                }
                
                // Cache successful validation
                int ttl = (int) (jwt.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());
                jwtCacheService.cacheValidationResult(tokenHash, true, Math.min(ttl, 300));
                
                // Cache user context
                var contextInfo = new GatewayJWTCacheService.UserContextInfo(
                    jwt.getSubject(),
                    jwt.getClaimAsString("email"),
                    jwt.getClaimAsStringList("roles").toArray(new String[0]),
                    jwt.getIssuedAt().getEpochSecond(),
                    jwt.getExpiresAt().getEpochSecond()
                );
                jwtCacheService.cacheUserContext(jwt.getSubject(), contextInfo, Math.min(ttl, 600));
                
                log.debug("✅ JWT validation successful for user: {}", jwt.getSubject());
                return jwt;
                
            } catch (Exception e) {
                log.debug("🚫 JWT validation failed: {}", e.getMessage());
                jwtCacheService.cacheValidationResult(tokenHash, false, 300);
                return null;
            }
        });
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
     * Extract token ID (jti) from JWT without full validation
     */
    private String extractTokenId(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;
            
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
            return extractJsonValue(payload, "jti");
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Generate unauthorized response
     */
    private Mono<Void> unauthorizedResponse(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private String generateRequestId() {
        return java.util.UUID.randomUUID().toString().substring(0, 8);
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }
}
