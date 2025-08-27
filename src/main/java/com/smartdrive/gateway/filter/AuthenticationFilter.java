package com.smartdrive.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;


@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${gateway.internal.auth.secret:gateway-secret-2024}")
    private String internalAuthSecret;

    @Value("${gateway.signature.secret:signature-secret-2024}")
    private String signatureSecret;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        log.debug("🔍 Enhanced auth processing: {} {}", request.getMethod(), path);
        
        // Skip for public endpoints
        if (isPublicEndpoint(path)) {
            return addPublicHeaders(exchange, chain);
        }
        
        return ReactiveSecurityContextHolder.getContext()
            .map(context -> context.getAuthentication())
            .cast(JwtAuthenticationToken.class)
            .flatMap(authentication -> {
                Jwt jwt = authentication.getToken();
                return addAuthenticatedUserHeaders(exchange, jwt, chain);
            })
            .switchIfEmpty(chain.filter(exchange));
    }

    /**
     * Add headers for authenticated requests
     */
    private Mono<Void> addAuthenticatedUserHeaders(ServerWebExchange exchange, Jwt jwt, GatewayFilterChain chain) {
        String userId = jwt.getSubject();
        String username = jwt.getClaimAsString("preferred_username");
        String email = jwt.getClaimAsString("email");
        List<String> roles = jwt.getClaimAsStringList("roles");
        String path = exchange.getRequest().getPath().value();
        
        // Generate signature for internal authentication
        String timestamp = String.valueOf(Instant.now().getEpochSecond());
        String signature = generateSignature(userId, path, timestamp);
        
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
            .header("X-User-ID", userId)
            .header("X-User-Username", username != null ? username : "")
            .header("X-User-Email", email != null ? email : "")
            .header("X-User-Roles", roles != null ? String.join(",", roles) : "")
            .header("X-Internal-Auth", internalAuthSecret)
            .header("X-Gateway-Signature", signature)
            .header("X-Gateway-Timestamp", timestamp)
            .header("X-Forwarded-By", "SmartDrive-Gateway")
            .build();
        
        log.debug("✅ User context headers added for user: {}", username);
        return chain.filter(exchange.mutate().request(modifiedRequest).build());
    }

    /**
     * Add headers for public requests (still need internal auth for verification endpoints)
     */
    private Mono<Void> addPublicHeaders(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().value();
        
        // Add internal auth header for service-to-service calls
        ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
            .header("X-Internal-Auth", internalAuthSecret)
            .header("X-Forwarded-By", "SmartDrive-Gateway")
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
            SecretKeySpec secretKeySpec = new SecretKeySpec(signatureSecret.getBytes(), "HmacSHA256");
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
               path.equals("/api/v1/users/register") ||
               path.startsWith("/api/v1/users/verify-email") ||
               path.startsWith("/actuator/health") ||
               path.startsWith("/actuator/info");
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }
}