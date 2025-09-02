package com.smartdrive.gateway.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Fallback controller for circuit breaker scenarios
 * Provides graceful degradation when services are unavailable
 */
@RestController
@RequestMapping("/fallback")
@Slf4j
public class FallbackController {

    /**
     * Auth service fallback
     */
    @RequestMapping(value = "/auth", method = { RequestMethod.GET, RequestMethod.POST })
    public Mono<ResponseEntity<Map<String, Object>>> authFallback() {
        log.warn("⚠️ Auth service is unavailable - using fallback");
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", "Authentication service is temporarily unavailable");
        response.put("timestamp", LocalDateTime.now());
        response.put("service", "auth-service");
        response.put("status", "FALLBACK");
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * User service fallback
     */
    @RequestMapping("/users")
    public Mono<ResponseEntity<Map<String, Object>>> userFallback() {
        log.error("🚨 USER SERVICE FALLBACK TRIGGERED - Circuit breaker activated!");
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", "User management service is temporarily unavailable");
        response.put("timestamp", LocalDateTime.now());
        response.put("service", "user-service");
        response.put("status", "FALLBACK");
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * File storage service fallback
     */
    @GetMapping("/files")
    public Mono<ResponseEntity<Map<String, Object>>> fileFallback() {
        log.warn("⚠️ File storage service is unavailable - using fallback");
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", "File storage service is temporarily unavailable");
        response.put("timestamp", LocalDateTime.now());
        response.put("service", "file-storage-service");
        response.put("status", "FALLBACK");
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * AI service fallback
     */
    @GetMapping("/ai")
    public Mono<ResponseEntity<Map<String, Object>>> aiFallback() {
        log.warn("⚠️ AI service is unavailable - using fallback");
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", "AI service is temporarily unavailable");
        response.put("timestamp", LocalDateTime.now());
        response.put("service", "ai-service");
        response.put("status", "FALLBACK");
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }

    /**
     * Search service fallback
     */
    @GetMapping("/search")
    public Mono<ResponseEntity<Map<String, Object>>> searchFallback() {
        log.warn("⚠️ Search service is unavailable - using fallback");
        
        Map<String, Object> response = new HashMap<>();
        response.put("error", "Service Unavailable");
        response.put("message", "Search service is temporarily unavailable");
        response.put("timestamp", LocalDateTime.now());
        response.put("service", "search-service");
        response.put("status", "FALLBACK");
        
        return Mono.just(ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(response));
    }
}
