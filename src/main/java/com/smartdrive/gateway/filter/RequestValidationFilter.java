package com.smartdrive.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Request validation filter for API Gateway
 * Validates incoming requests for security and compliance
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RequestValidationFilter implements GlobalFilter, Ordered {

    // Maximum request size (10MB)
    private static final int MAX_REQUEST_SIZE = 10 * 1024 * 1024;
    
    // Allowed content types
    private static final List<String> ALLOWED_CONTENT_TYPES = Arrays.asList(
        MediaType.APPLICATION_JSON_VALUE,
        MediaType.APPLICATION_FORM_URLENCODED_VALUE,
        MediaType.MULTIPART_FORM_DATA_VALUE,
        MediaType.TEXT_PLAIN_VALUE
    );
    
    // SQL injection patterns
    private static final Pattern SQL_INJECTION_PATTERN = Pattern.compile(
        "(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT|JAVASCRIPT|VBSCRIPT|ONLOAD|ONERROR|ONCLICK)",
        Pattern.CASE_INSENSITIVE
    );
    
    // XSS patterns
    private static final Pattern XSS_PATTERN = Pattern.compile(
        "(?i)(<script|javascript:|vbscript:|onload|onerror|onclick|<iframe|<object|<embed)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().value();
        
        log.debug("🔍 Validating request: {} {}", request.getMethod(), path);
        
        // Skip validation for health checks
        if (path.startsWith("/actuator/health")) {
            return chain.filter(exchange);
        }
        
        // Validate content type
        if (!isValidContentType(request)) {
            return handleInvalidRequest(exchange, "Invalid content type", HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        }
        
        // Validate request size
        if (!isValidRequestSize(request)) {
            return handleInvalidRequest(exchange, "Request too large", HttpStatus.PAYLOAD_TOO_LARGE);
        }
        
        // Validate headers for malicious content
        if (containsMaliciousContent(request)) {
            return handleInvalidRequest(exchange, "Malicious content detected", HttpStatus.BAD_REQUEST);
        }
        
        // Validate user agent
        if (!isValidUserAgent(request)) {
            return handleInvalidRequest(exchange, "Invalid user agent", HttpStatus.BAD_REQUEST);
        }
        
        log.debug("✅ Request validation passed for: {}", path);
        return chain.filter(exchange);
    }

    /**
     * Validate content type
     */
    private boolean isValidContentType(ServerHttpRequest request) {
        String contentType = request.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE);
        if (contentType == null) {
            return true; // Allow requests without content type (GET requests)
        }
        
        return ALLOWED_CONTENT_TYPES.stream()
            .anyMatch(allowed -> contentType.toLowerCase().startsWith(allowed.toLowerCase()));
    }

    /**
     * Validate request size
     */
    private boolean isValidRequestSize(ServerHttpRequest request) {
        String contentLength = request.getHeaders().getFirst(HttpHeaders.CONTENT_LENGTH);
        if (contentLength == null) {
            return true;
        }
        
        try {
            long size = Long.parseLong(contentLength);
            return size <= MAX_REQUEST_SIZE;
        } catch (NumberFormatException e) {
            log.warn("⚠️ Invalid content length header: {}", contentLength);
            return false;
        }
    }

    /**
     * Check for malicious content in headers
     */
    private boolean containsMaliciousContent(ServerHttpRequest request) {
        return request.getHeaders().entrySet().stream()
            .anyMatch(entry -> {
                String headerName = entry.getKey();
                List<String> headerValues = entry.getValue();
                
                return headerValues.stream()
                    .anyMatch(value -> 
                        SQL_INJECTION_PATTERN.matcher(value).find() ||
                        XSS_PATTERN.matcher(value).find()
                    );
            });
    }

    /**
     * Validate user agent
     */
    private boolean isValidUserAgent(ServerHttpRequest request) {
        String userAgent = request.getHeaders().getFirst(HttpHeaders.USER_AGENT);
        if (!StringUtils.hasText(userAgent)) {
            return false;
        }
        
        // Block common malicious user agents
        String lowerUserAgent = userAgent.toLowerCase();
        return !lowerUserAgent.contains("sqlmap") &&
               !lowerUserAgent.contains("nmap") &&
               !lowerUserAgent.contains("nikto") &&
               !lowerUserAgent.contains("wget") &&
               !lowerUserAgent.contains("curl") &&
               !lowerUserAgent.contains("python-requests");
    }

    /**
     * Handle invalid request
     */
    private Mono<Void> handleInvalidRequest(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        
        String errorResponse = String.format("""
            {
                "error": "%s",
                "message": "%s",
                "timestamp": "%s"
            }
            """, status.getReasonPhrase(), message, java.time.Instant.now());
        
        byte[] bytes = errorResponse.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        
        log.warn("❌ Request validation failed: {} - {}", exchange.getRequest().getPath(), message);
        
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 50; // Run early in the filter chain
    }
}