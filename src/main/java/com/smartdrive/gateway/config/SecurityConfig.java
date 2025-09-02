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

                // Configure authorization - CRITICAL: ORDER MATTERS!
                .authorizeExchange(exchanges -> exchanges
                        // 1. CORS preflight requests - MUST BE FIRST!
                        .pathMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()

                        // 2. Health and actuator endpoints
                        .pathMatchers("/actuator/**").permitAll()
                        .pathMatchers("/fallback/**").permitAll()

                        // 3. Auth service endpoints - completely public
                        .pathMatchers("/auth/**").permitAll()
                        .pathMatchers("/oauth2/**").permitAll()

                        // 4. Auth endpoints - MUST BE BEFORE /api/** pattern!
                        .pathMatchers("/api/v1/auth/**").permitAll()
                        .pathMatchers("/api/auth/**").permitAll()
                        
                        // 5. Social auth endpoints - completely public  
                        .pathMatchers("/api/v1/auth/social/**").permitAll()
                        
                        // 6. SPECIFIC public endpoints (most specific)
                        .pathMatchers(
                                org.springframework.http.HttpMethod.POST,
                                "/api/v1/users/register")
                        .permitAll()
                        
                        .pathMatchers(
                                org.springframework.http.HttpMethod.GET,
                                "/api/v1/users/verify-email")
                        .permitAll()
                        
                        // 7. All authenticated API endpoints - require valid JWT
                        .pathMatchers("/api/**").authenticated()

                        // 7. Everything else - allow (for static resources, etc.)
                        .anyExchange().permitAll())

                // JWT validation handled by IndustryStandardJWTFilter
                // No OAuth2 resource server configuration to avoid conflicts
                ;

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