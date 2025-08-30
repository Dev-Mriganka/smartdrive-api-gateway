package com.smartdrive.gateway.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Test controller to debug gateway response issues
 */
@RestController
@RequestMapping("/test")
@Slf4j
public class TestController {

    @GetMapping("/admin")
    public Mono<ResponseEntity<Map<String, Object>>> testAdmin() {
        log.info("🧪 Test admin endpoint called");
        return Mono.just(ResponseEntity.ok(Map.of(
            "message", "Test admin endpoint works",
            "timestamp", java.time.Instant.now().toString()
        )));
    }
    
    @GetMapping("/gateway")
    public Mono<ResponseEntity<Map<String, Object>>> testGateway() {
        log.info("🧪 Test gateway endpoint called");
        return Mono.just(ResponseEntity.ok(Map.of(
            "message", "Gateway is responding",
            "timestamp", java.time.Instant.now().toString()
        )));
    }
}
