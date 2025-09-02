package com.smartdrive.gateway.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Gateway Token Blacklist Service
 * 
 * Industry standard implementation:
 * - Gateway checks blacklists directly (no auth service calls)
 * - Multi-layer caching for performance
 * - Shared Redis with auth service for consistency
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GatewayTokenBlacklistService {

    private final RedisTemplate<String, Object> redisTemplate;

    // Cache prefixes (shared with auth service)
    private static final String AUTH_BLACKLIST_PREFIX = "authservice:blacklist:";
    private static final String GATEWAY_CACHE_PREFIX = "gateway:blacklist:cache:";

    /**
     * Check if token is blacklisted with multi-layer caching
     * Layer 1: Gateway cache (60 seconds)
     * Layer 2: Auth service blacklist (persistent)
     */
    public boolean isTokenBlacklisted(String tokenId) {
        if (tokenId == null) {
            return false;
        }

        try {
            // Layer 1: Check gateway cache first (fastest)
            String cacheKey = GATEWAY_CACHE_PREFIX + tokenId;
            Boolean cachedResult = (Boolean) redisTemplate.opsForValue().get(cacheKey);
            
            if (cachedResult != null) {
                log.debug("🚄 Gateway blacklist cache hit for token: {} -> {}", 
                    tokenId.substring(0, 8) + "...", cachedResult);
                return cachedResult;
            }

            // Layer 2: Check auth service blacklist
            boolean isBlacklisted = checkAuthServiceBlacklist(tokenId);
            
            // Cache result for 60 seconds (balance between performance and accuracy)
            redisTemplate.opsForValue().set(cacheKey, isBlacklisted, 60, TimeUnit.SECONDS);
            
            if (isBlacklisted) {
                log.debug("🚫 Token is blacklisted: {}", tokenId.substring(0, 8) + "...");
            }
            
            return isBlacklisted;

        } catch (Exception e) {
            log.warn("⚠️ Error checking token blacklist for {}: {}", 
                tokenId.substring(0, 8) + "...", e.getMessage());
            
            // Fail open for availability - don't block valid users due to cache issues
            return false;
        }
    }

    /**
     * Check auth service blacklist (access and refresh tokens)
     */
    private boolean checkAuthServiceBlacklist(String tokenId) {
        try {
            // Check both access and refresh token blacklists
            String accessKey = AUTH_BLACKLIST_PREFIX + "access:" + tokenId;
            String refreshKey = AUTH_BLACKLIST_PREFIX + "refresh:" + tokenId;
            
            Boolean isAccessBlacklisted = redisTemplate.hasKey(accessKey);
            Boolean isRefreshBlacklisted = redisTemplate.hasKey(refreshKey);
            
            return Boolean.TRUE.equals(isAccessBlacklisted) || 
                   Boolean.TRUE.equals(isRefreshBlacklisted);
                   
        } catch (Exception e) {
            log.warn("⚠️ Error checking auth service blacklist: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Clear gateway cache for a specific token (called when token is blacklisted)
     */
    public void clearGatewayCache(String tokenId) {
        try {
            String cacheKey = GATEWAY_CACHE_PREFIX + tokenId;
            redisTemplate.delete(cacheKey);
            log.debug("🧹 Cleared gateway cache for token: {}", tokenId.substring(0, 8) + "...");
        } catch (Exception e) {
            log.warn("⚠️ Error clearing gateway cache: {}", e.getMessage());
        }
    }

    /**
     * Get cache statistics (for monitoring)
     */
    public CacheStats getCacheStats() {
        try {
            var cacheKeys = redisTemplate.keys(GATEWAY_CACHE_PREFIX + "*");
            int cacheSize = cacheKeys != null ? cacheKeys.size() : 0;
            
            var blacklistKeys = redisTemplate.keys(AUTH_BLACKLIST_PREFIX + "*");
            int blacklistSize = blacklistKeys != null ? blacklistKeys.size() : 0;
            
            return new CacheStats(cacheSize, blacklistSize);
        } catch (Exception e) {
            log.warn("⚠️ Error getting cache stats: {}", e.getMessage());
            return new CacheStats(0, 0);
        }
    }

    /**
     * Cache statistics class
     */
    public static class CacheStats {
        private final int gatewayCacheSize;
        private final int blacklistSize;

        public CacheStats(int gatewayCacheSize, int blacklistSize) {
            this.gatewayCacheSize = gatewayCacheSize;
            this.blacklistSize = blacklistSize;
        }

        public int getGatewayCacheSize() { return gatewayCacheSize; }
        public int getBlacklistSize() { return blacklistSize; }

        @Override
        public String toString() {
            return String.format("CacheStats{gateway=%d, blacklist=%d}", 
                gatewayCacheSize, blacklistSize);
        }
    }
}
