package com.smartdrive.gateway.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.server.WebFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
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

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Value("${gateway.jwt.audience:smartdrive-api}")
    private String audience;

    /**
     * Configure security filter chain for API Gateway
     */
    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        log.info("🔐 Configuring API Gateway security filter chain");
        
        http
            // Disable CSRF for API endpoints
            .csrf(ServerHttpSecurity.CsrfSpec::disable)
            
            // Configure CORS
            .cors(Customizer.withDefaults())
            
            // Add security headers
            .headers(headers -> headers
                .frameOptions().disable()
                .contentTypeOptions().disable()
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000)
                    .includeSubdomains(true)
                    .preload(true)
                )
            )
            
            // Configure authorization
            .authorizeExchange(exchanges -> exchanges
                // Public endpoints (no authentication required)
                .pathMatchers(
                    "/auth/oauth2/**",
                    "/auth/.well-known/**",
                    "/auth/api/v1/users/register",
                    "/api/v1/users/register",
                    "/api/v1/users/verify-email",
                    "/actuator/health",
                    "/actuator/info"
                ).permitAll()
                
                // Admin endpoints (require admin role)
                .pathMatchers("/auth/api/v1/admin/**").hasRole("SMARTDRIVE_ADMIN")
                
                // All other endpoints require authentication
                .anyExchange().authenticated()
            )
            
            // Configure OAuth2 resource server with custom JWT validator
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                    .validator(jwtValidator())
                )
            );
        
        log.info("✅ API Gateway security filter chain configured successfully");
        return http.build();
    }

    /**
     * Custom JWT validator with issuer and audience validation
     */
    @Bean
    public OAuth2TokenValidator<Jwt> jwtValidator() {
        OAuth2TokenValidator<Jwt> issuerValidator = new JwtIssuerValidator(issuerUri);
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<String>("aud", audience);
        OAuth2TokenValidator<Jwt> timestampValidator = new JwtTimestampValidator();
        
        return new DelegatingOAuth2TokenValidator<>(
            issuerValidator, 
            audienceValidator, 
            timestampValidator
        );
    }

    /**
     * Custom JWT authentication converter
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");
        
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        
        return jwtAuthenticationConverter;
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
