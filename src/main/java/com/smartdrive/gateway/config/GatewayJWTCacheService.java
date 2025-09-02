package com.smartdrive.gateway.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Gateway JWT Validation Cache Service
 * 
 * Industry standard implementation:
 * - Cache JWT validation results to avoid repeated decoding
 * - Multi-layer caching for optimal performance
 * - Smart TTL based on token expiry
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GatewayJWTCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    private static final String JWT_VALIDATION_PREFIX = "gateway:jwt:validation:";
    private static final String USER_CONTEXT_PREFIX = "gateway:user:context:";

    /**
     * Cache JWT validation result
     * TTL is based on token expiry to avoid caching invalid tokens
     */
    public void cacheValidationResult(String tokenHash, boolean isValid, int ttlSeconds) {
        try {
            String key = JWT_VALIDATION_PREFIX + tokenHash;
            redisTemplate.opsForValue().set(key, isValid, ttlSeconds, TimeUnit.SECONDS);
            
            log.debug("💾 Cached JWT validation: {} -> {} (TTL: {}s)", 
                tokenHash, isValid, ttlSeconds);
        } catch (Exception e) {
            log.warn("⚠️ Error caching JWT validation: {}", e.getMessage());
        }
    }

    /**
     * Get cached JWT validation result
     * Returns null if not cached
     */
    public Boolean getCachedValidationResult(String tokenHash) {
        try {
            String key = JWT_VALIDATION_PREFIX + tokenHash;
            Boolean result = (Boolean) redisTemplate.opsForValue().get(key);
            
            if (result != null) {
                log.debug("🚄 JWT validation cache hit: {} -> {}", tokenHash, result);
            }
            
            return result;
        } catch (Exception e) {
            log.warn("⚠️ Error getting cached JWT validation: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Cache user context extracted from JWT
     * This avoids re-parsing JWT payload for subsequent requests
     */
    public void cacheUserContext(String userId, UserContextInfo context, int ttlSeconds) {
        try {
            String key = USER_CONTEXT_PREFIX + userId;
            redisTemplate.opsForValue().set(key, context, ttlSeconds, TimeUnit.SECONDS);
            
            log.debug("💾 Cached user context for: {} (TTL: {}s)", userId, ttlSeconds);
        } catch (Exception e) {
            log.warn("⚠️ Error caching user context: {}", e.getMessage());
        }
    }

    /**
     * Get cached user context
     */
    public UserContextInfo getCachedUserContext(String userId) {
        try {
            String key = USER_CONTEXT_PREFIX + userId;
            Object cached = redisTemplate.opsForValue().get(key);
            
            if (cached instanceof UserContextInfo) {
                log.debug("🚄 User context cache hit for: {}", userId);
                return (UserContextInfo) cached;
            }
            
            return null;
        } catch (Exception e) {
            log.warn("⚠️ Error getting cached user context: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Invalidate caches for a specific user (called on user changes)
     */
    public void invalidateUserCaches(String userId) {
        try {
            String userContextKey = USER_CONTEXT_PREFIX + userId;
            redisTemplate.delete(userContextKey);
            
            log.debug("🧹 Invalidated user caches for: {}", userId);
        } catch (Exception e) {
            log.warn("⚠️ Error invalidating user caches: {}", e.getMessage());
        }
    }

    /**
     * Clear all JWT validation caches (for maintenance)
     */
    public void clearAllValidationCaches() {
        try {
            var validationKeys = redisTemplate.keys(JWT_VALIDATION_PREFIX + "*");
            var contextKeys = redisTemplate.keys(USER_CONTEXT_PREFIX + "*");
            
            int deletedValidation = 0;
            int deletedContext = 0;
            
            if (validationKeys != null && !validationKeys.isEmpty()) {
                redisTemplate.delete(validationKeys);
                deletedValidation = validationKeys.size();
            }
            
            if (contextKeys != null && !contextKeys.isEmpty()) {
                redisTemplate.delete(contextKeys);
                deletedContext = contextKeys.size();
            }
            
            log.info("🧹 Cleared JWT caches - Validation: {}, Context: {}", 
                deletedValidation, deletedContext);
                
        } catch (Exception e) {
            log.warn("⚠️ Error clearing JWT validation caches: {}", e.getMessage());
        }
    }

    /**
     * Get cache statistics for monitoring
     */
    public JWTCacheStats getCacheStats() {
        try {
            var validationKeys = redisTemplate.keys(JWT_VALIDATION_PREFIX + "*");
            var contextKeys = redisTemplate.keys(USER_CONTEXT_PREFIX + "*");
            
            int validationCacheSize = validationKeys != null ? validationKeys.size() : 0;
            int contextCacheSize = contextKeys != null ? contextKeys.size() : 0;
            
            return new JWTCacheStats(validationCacheSize, contextCacheSize);
        } catch (Exception e) {
            log.warn("⚠️ Error getting JWT cache stats: {}", e.getMessage());
            return new JWTCacheStats(0, 0);
        }
    }

    /**
     * User Context Information for caching
     */
    public static class UserContextInfo {
        private String userId;
        private String email;
        private String[] roles;
        private long tokenIssuedAt;
        private long tokenExpiresAt;

        public UserContextInfo() {}

        public UserContextInfo(String userId, String email, String[] roles, 
                              long tokenIssuedAt, long tokenExpiresAt) {
            this.userId = userId;
            this.email = email;
            this.roles = roles;
            this.tokenIssuedAt = tokenIssuedAt;
            this.tokenExpiresAt = tokenExpiresAt;
        }

        // Getters and Setters
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }

        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }

        public String[] getRoles() { return roles; }
        public void setRoles(String[] roles) { this.roles = roles; }

        public long getTokenIssuedAt() { return tokenIssuedAt; }
        public void setTokenIssuedAt(long tokenIssuedAt) { this.tokenIssuedAt = tokenIssuedAt; }

        public long getTokenExpiresAt() { return tokenExpiresAt; }
        public void setTokenExpiresAt(long tokenExpiresAt) { this.tokenExpiresAt = tokenExpiresAt; }
    }

    /**
     * JWT Cache Statistics
     */
    public static class JWTCacheStats {
        private final int validationCacheSize;
        private final int contextCacheSize;

        public JWTCacheStats(int validationCacheSize, int contextCacheSize) {
            this.validationCacheSize = validationCacheSize;
            this.contextCacheSize = contextCacheSize;
        }

        public int getValidationCacheSize() { return validationCacheSize; }
        public int getContextCacheSize() { return contextCacheSize; }

        @Override
        public String toString() {
            return String.format("JWTCacheStats{validation=%d, context=%d}", 
                validationCacheSize, contextCacheSize);
        }
    }
}
