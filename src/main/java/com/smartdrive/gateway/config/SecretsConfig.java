package com.smartdrive.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;

/**
 * Configuration for gateway secrets with validation
 * Centralizes secret management and validation
 */
@Configuration
@ConfigurationProperties(prefix = "gateway.security")
@Validated
@Data
@Slf4j
public class SecretsConfig {

    @NotBlank(message = "Internal auth secret cannot be blank")
    @Size(min = 32, message = "Internal auth secret must be at least 32 characters")
    private String internalSecret;

    @NotBlank(message = "Signature secret cannot be blank")
    @Size(min = 32, message = "Signature secret must be at least 32 characters")
    private String signatureSecret;

    @NotBlank(message = "JWT signing key cannot be blank")
    @Size(min = 256, message = "JWT signing key must be at least 256 bits")
    private String jwtSigningKey;

    /**
     * Validates secrets on startup
     */
    public void validateSecrets() {
        log.info("🔐 Validating gateway security configuration...");

        if (isWeakSecret(internalSecret)) {
            log.warn("⚠️ Internal secret appears to be weak or default. Consider using a stronger secret.");
        }

        if (isWeakSecret(signatureSecret)) {
            log.warn("⚠️ Signature secret appears to be weak or default. Consider using a stronger secret.");
        }

        log.info("✅ Gateway security configuration validated");
    }

    /**
     * Check if secret appears to be weak or default
     */
    private boolean isWeakSecret(String secret) {
        if (secret == null)
            return true;

        // Check for common weak patterns
        String lowerSecret = secret.toLowerCase();
        return lowerSecret.contains("password") ||
                lowerSecret.contains("secret") ||
                lowerSecret.contains("key") ||
                lowerSecret.contains("default") ||
                lowerSecret.contains("test") ||
                lowerSecret.contains("123") ||
                lowerSecret.length() < 32;
    }
}
