package com.oracle.hospitality.hdp.gateway.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Configuration for CSRF security components.
 *
 * Loads the RSA public key for JWT token verification.
 */
@Slf4j
@Configuration
public class CsrfSecurityConfig {

    private final CsrfConfigurationProperties csrfConfig;
    private final ResourceLoader resourceLoader;

    public CsrfSecurityConfig(CsrfConfigurationProperties csrfConfig, ResourceLoader resourceLoader) {
        this.csrfConfig = csrfConfig;
        this.resourceLoader = resourceLoader;
    }

    /**
     * Loads the RSA public key from the configured location.
     *
     * Supports:
     * - classpath: resources
     * - file: filesystem paths
     * - Direct PEM string (if starts with "-----BEGIN")
     *
     * @return PublicKey for JWT verification
     * @throws RuntimeException if key cannot be loaded
     */
    @Bean
    public PublicKey csrfPublicKey() {
        try {
            String keyLocation = csrfConfig.getPublicKeyLocation();
            String pemContent;

            // Check if it's a direct PEM string
            if (keyLocation.startsWith("-----BEGIN")) {
                log.info("Loading public key from direct PEM string");
                pemContent = keyLocation;
            } else {
                // Load from resource (classpath: or file:)
                log.info("Loading public key from: {}", keyLocation);
                Resource resource = resourceLoader.getResource(keyLocation);

                if (!resource.exists()) {
                    throw new IllegalStateException("Public key resource not found: " + keyLocation);
                }

                pemContent = readResourceContent(resource);
            }

            return parsePublicKey(pemContent);

        } catch (IOException e) {
            throw new IllegalStateException("Failed to load CSRF public key", e);
        }
    }

    /**
     * Reads resource content as string (Java 8 compatible).
     */
    private String readResourceContent(Resource resource) throws IOException {
        java.io.InputStream is = resource.getInputStream();
        java.io.ByteArrayOutputStream result = new java.io.ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = is.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toString(StandardCharsets.UTF_8.name());
    }

    /**
     * Parses a PEM-formatted public key string into a PublicKey object.
     *
     * @param pemContent PEM-formatted public key
     * @return PublicKey object
     * @throws IllegalStateException if parsing fails
     */
    private PublicKey parsePublicKey(String pemContent) {
        try {
            // Remove PEM headers and whitespace
            String publicKeyPEM = pemContent
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            // Decode Base64
            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);

            // Generate PublicKey
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            PublicKey publicKey = keyFactory.generatePublic(keySpec);

            log.info("Successfully loaded RSA public key for CSRF validation");
            return publicKey;

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA algorithm not available", e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid public key format", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid Base64 encoding in public key", e);
        }
    }

    /**
     * ObjectMapper bean for JSON serialization.
     * Used for error responses.
     */
    @Bean
    public com.fasterxml.jackson.databind.ObjectMapper objectMapper() {
        return new com.fasterxml.jackson.databind.ObjectMapper()
                .findAndRegisterModules();
    }
}
