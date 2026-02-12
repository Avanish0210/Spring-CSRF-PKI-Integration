package com.oracle.hospitality.hdp.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration properties for CSRF protection.
 *
 * Binds to the 'csrf' prefix in application.yml.
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "csrf")
@Validated
public class CsrfConfigurationProperties {

    /**
     * Enable or disable CSRF protection globally.
     * Default: true (enabled in production)
     */
    @NotNull
    private Boolean enabled = true;

    /**
     * Token configuration
     */
    private TokenConfig token = new TokenConfig();

    /**
     * Location of the RSA public key for token verification.
     * Supports: classpath:, file:, or direct PEM string
     */
    @NotBlank
    private String publicKeyLocation = "classpath:keys/csrf-public-key.pem";

    /**
     * Maximum age of CSRF tokens in seconds (default: 10 minutes)
     */
    @Positive
    private Integer maxAgeSeconds = 600;

    /**
     * Expected issuer claim in the JWT token
     */
    @NotBlank
    private String issuer = "hdp-csrf-issuer";

    /**
     * Enable origin/referer validation
     */
    private Boolean validateOrigin = false;

    /**
     * Allowed origins for CSRF validation
     */
    private List<String> allowedOrigins = new ArrayList<>();

    /**
     * Token-specific configuration
     */
    @Data
    public static class TokenConfig {
        /**
         * HTTP header name for CSRF token
         */
        @NotBlank
        private String headerName = "X-CSRF-Token";
    }
}

