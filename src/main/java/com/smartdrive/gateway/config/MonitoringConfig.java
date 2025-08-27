package com.smartdrive.gateway.config;

import io.micrometer.core.aop.TimedAspect;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import reactor.core.publisher.Mono;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Monitoring configuration for API Gateway
 * Provides custom metrics and health checks
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class MonitoringConfig {

    private final MeterRegistry meterRegistry;
    private final ReactiveRedisTemplate<String, String> redisTemplate;

    // Custom counters for monitoring
    private final ConcurrentHashMap<String, AtomicLong> requestCounters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> errorCounters = new ConcurrentHashMap<>();

    @Bean
    public TimedAspect timedAspect(MeterRegistry registry) {
        return new TimedAspect(registry);
    }

    @Bean
    public HealthIndicator redisHealthIndicator() {
        return new HealthIndicator() {
            @Override
            public Health health() {
                return redisTemplate.execute(connection -> connection.ping())
                    .map(result -> {
                        if (result != null) {
                            return Health.up()
                                .withDetail("service", "redis")
                                .withDetail("status", "connected")
                                .build();
                        } else {
                            return Health.down()
                                .withDetail("service", "redis")
                                .withDetail("status", "disconnected")
                                .build();
                        }
                    })
                    .onErrorReturn(Health.down()
                        .withDetail("service", "redis")
                        .withDetail("error", "connection failed")
                        .build())
                    .block();
            }
        };
    }

    @Bean
    public HealthIndicator gatewayHealthIndicator() {
        return new HealthIndicator() {
            @Override
            public Health health() {
                long totalRequests = requestCounters.values().stream()
                    .mapToLong(AtomicLong::get)
                    .sum();
                
                long totalErrors = errorCounters.values().stream()
                    .mapToLong(AtomicLong::get)
                    .sum();
                
                double errorRate = totalRequests > 0 ? (double) totalErrors / totalRequests : 0.0;
                
                return Health.up()
                    .withDetail("service", "gateway")
                    .withDetail("total_requests", totalRequests)
                    .withDetail("total_errors", totalErrors)
                    .withDetail("error_rate", String.format("%.2f%%", errorRate * 100))
                    .build();
            }
        };
    }

    /**
     * Increment request counter
     */
    public void incrementRequestCounter(String service) {
        requestCounters.computeIfAbsent(service, k -> new AtomicLong()).incrementAndGet();
        meterRegistry.counter("gateway.requests", "service", service).increment();
    }

    /**
     * Increment error counter
     */
    public void incrementErrorCounter(String service, String errorType) {
        errorCounters.computeIfAbsent(service, k -> new AtomicLong()).incrementAndGet();
        meterRegistry.counter("gateway.errors", "service", service, "type", errorType).increment();
    }

    /**
     * Record response time
     */
    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    /**
     * Stop timer and record metrics
     */
    public void stopTimer(Timer.Sample sample, String service, String status) {
        sample.stop(Timer.builder("gateway.response_time")
            .tag("service", service)
            .tag("status", status)
            .register(meterRegistry));
    }
}