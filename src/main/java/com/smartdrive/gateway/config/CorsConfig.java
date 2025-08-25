package com.smartdrive.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;

/**
 * CORS configuration for API Gateway
 * Handles cross-origin requests from frontend applications
 */
@Configuration
@Slf4j
public class CorsConfig {

    @Bean
    public CorsWebFilter corsWebFilter() {
        log.info("🌐 Configuring CORS for API Gateway");
        
        CorsConfiguration corsConfig = new CorsConfiguration();
        
        // Allowed origins (configure based on your frontend URLs)
        corsConfig.setAllowedOriginPatterns(Arrays.asList(
            "http://localhost:3000",  // React development
            "http://localhost:4200",  // Angular development
            "http://localhost:8080",  // Vue development
            "https://smartdrive.local", // Production domain
            "https://*.smartdrive.com"  // Wildcard for subdomains
        ));
        
        // Allowed HTTP methods
        corsConfig.setAllowedMethods(Arrays.asList(
            "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));
        
        // Allowed headers
        corsConfig.setAllowedHeaders(Arrays.asList(
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "Access-Control-Request-Method",
            "Access-Control-Request-Headers",
            "X-User-ID",
            "X-User-Username",
            "X-User-Roles",
            "X-User-Email"
        ));
        
        // Exposed headers (headers that can be read by the client)
        corsConfig.setExposedHeaders(Arrays.asList(
            "X-User-ID",
            "X-User-Username",
            "X-User-Roles",
            "X-User-Email",
            "X-Rate-Limit-Remaining",
            "X-Rate-Limit-Reset"
        ));
        
        // Allow credentials (cookies, authorization headers)
        corsConfig.setAllowCredentials(true);
        
        // Max age for preflight requests (in seconds)
        corsConfig.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);
        
        log.info("✅ CORS configuration applied successfully");
        return new CorsWebFilter(source);
    }
}
