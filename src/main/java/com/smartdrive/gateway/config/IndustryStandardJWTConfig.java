package com.smartdrive.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;



/**
 * Industry Standard JWT Configuration for API Gateway
 * 
 * Following Netflix/Amazon/Google patterns:
 * 1. Gateway validates JWTs locally (no auth service calls)
 * 2. Shared secret for JWT validation (faster than JWK endpoint)
 * 3. Redis caching for token blacklists
 * 4. Performance-optimized configuration
 */
@Configuration
@EnableCaching
@Slf4j
public class IndustryStandardJWTConfig {

    @Value("${jwt.secret:your-256-bit-secret-key-here-must-be-at-least-32-characters-long}")
    private String jwtSecret;

    @Value("${jwt.issuer:smartdrive-auth-service}")
    private String expectedIssuer;

    /**
     * Configure JWT Decoder for gateway-level validation
     * Using RSA public key for asymmetric JWT validation
     */
    @Bean("gatewayJwtDecoder")
    public JwtDecoder jwtDecoder() {
        log.info("🔧 Configuring Industry Standard JWT Decoder for Gateway with RSA validation");
        
        try {
            // Use RSA public key validation for asymmetric JWTs
            // This will automatically fetch the public key from the JWKS endpoint
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri("http://auth-service:8082/oauth2/jwks")
                    .build();
            
            log.info("✅ JWT Decoder configured with RSA public key validation via JWKS");
            return decoder;
        } catch (Exception e) {
            log.error("❌ Failed to configure JWT Decoder with JWKS: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to configure JWT Decoder", e);
        }
    }

    /**
     * Configure RedisTemplate for gateway caching
     * Used for token blacklists and validation caching
     */
    @Bean
    public RedisTemplate<String, Object> gatewayRedisTemplate(RedisConnectionFactory connectionFactory) {
        log.info("🔧 Configuring Gateway Redis Template");

        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connectionFactory);

        // Use String serializer for keys (better performance)
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());

        // Use JSON serializer for values
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        template.setHashValueSerializer(new GenericJackson2JsonRedisSerializer());

        // Enable transaction support
        template.setEnableTransactionSupport(true);

        template.afterPropertiesSet();

        log.info("✅ Gateway Redis Template configured successfully");
        return template;
    }

    /**
     * Token blacklist checker service
     * Industry standard: Gateway checks blacklist directly
     */
    @Bean
    public GatewayTokenBlacklistService gatewayTokenBlacklistService(
            RedisTemplate<String, Object> redisTemplate) {
        log.info("🔧 Configuring Gateway Token Blacklist Service");
        return new GatewayTokenBlacklistService(redisTemplate);
    }

    /**
     * JWT validation cache service
     * Multi-layer caching for optimal performance
     */
    @Bean
    public GatewayJWTCacheService gatewayJWTCacheService(
            RedisTemplate<String, Object> redisTemplate) {
        log.info("🔧 Configuring Gateway JWT Cache Service");
        return new GatewayJWTCacheService(redisTemplate);
    }
}
