package com.smartdrive.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.server.WebFilter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Security configuration for API Gateway
 * Acts as JWT resource server for token validation
 */
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {

    /**
     * Configure security filter chain for API Gateway
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        log.info("🔐 Configuring API Gateway security filter chain");

        http
                // Disable CSRF for API endpoints
                .csrf(ServerHttpSecurity.CsrfSpec::disable)

                // Configure CORS - MUST be before authorization
                .cors(Customizer.withDefaults())

                // Configure authorization - PERMITALL FIRST!
                .authorizeExchange(exchanges -> exchanges
                        // Allow CORS preflight requests (OPTIONS) - MUST BE FIRST!
                        .pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()

                        // Public endpoints - completely bypass security
                        .pathMatchers("/auth/oauth2/**", "/auth/.well-known/**", "/oauth2/token/refresh").permitAll()
                        .pathMatchers("/actuator/health", "/actuator/info").permitAll()
                        .pathMatchers(
                                org.springframework.http.HttpMethod.POST,
                                "/api/v1/users/register")
                        .permitAll()
                        .pathMatchers(
                                org.springframework.http.HttpMethod.GET,
                                "/api/v1/users/verify-email")
                        .permitAll()
                        .pathMatchers("/api/v1/auth/login").permitAll()

                        // Admin endpoints (require admin role)
                        .pathMatchers("/auth/api/v1/admin/**").hasRole("SMARTDRIVE_ADMIN")

                        // All other endpoints require authentication
                        .anyExchange().authenticated())

                // Configure OAuth2 resource server
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        log.info("✅ API Gateway security filter chain configured successfully");
        return http.build();
    }

    /**
     * CSRF token filter for logging (optional)
     */
    @Bean
    public WebFilter csrfTokenFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> token = exchange.getAttribute(CsrfToken.class.getName());
            if (token != null) {
                return token.flatMap(t -> {
                    log.debug("🛡️ CSRF Token: {}", t.getToken());
                    return chain.filter(exchange);
                });
            }
            return chain.filter(exchange);
        };
    }
}
