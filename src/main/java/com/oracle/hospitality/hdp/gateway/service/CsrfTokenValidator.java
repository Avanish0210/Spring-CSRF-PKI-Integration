package com.oracle.hospitality.hdp.gateway.service;

import com.oracle.hospitality.hdp.gateway.config.CsrfConfigurationProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import java.security.interfaces.RSAPublicKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;

/**
 * Service for validating CSRF tokens.
 *
 * Validates JWT tokens signed with RS256 algorithm against the configured
 * public key.
 */
@Slf4j
@Service
public class CsrfTokenValidator {

    private final CsrfConfigurationProperties csrfConfig;
    private final PublicKey publicKey;

    public CsrfTokenValidator(CsrfConfigurationProperties csrfConfig, PublicKey publicKey) {
        this.csrfConfig = csrfConfig;
        this.publicKey = publicKey;
    }

    /**
     * Validates a CSRF token against the provided headers.
     *
     * @param token     The CSRF token to validate
     * @param headers   HTTP headers from the request
     * @param username  The authenticated username (from idcs_remote_user or JWT)
     * @param sessionId The session ID (from idcs_session_id header)
     * @return ValidationResult indicating success or failure with reason
     */
    public ValidationResult validate(String token, HttpHeaders headers, String username, String sessionId) {
        try {
            // Parse and verify JWT signature
            Claims claims = Jwts.parser()
                    .verifyWith((RSAPublicKey) publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.trace("CSRF token parsed successfully. Claims: {}", claims);

            // Validate issuer
            String issuer = claims.getIssuer();
            if (!csrfConfig.getIssuer().equals(issuer)) {
                log.warn("Invalid issuer. Expected: {}, Got: {}", csrfConfig.getIssuer(), issuer);
                return ValidationResult.failure("Invalid issuer");
            }

            // Validate expiration
            Instant expiration = claims.getExpiration().toInstant();
            if (Instant.now().isAfter(expiration)) {
                log.warn("Token expired at: {}", expiration);
                return ValidationResult.failure("Token expired");
            }

            // Validate issued-at time (must not be older than max age)
            Instant issuedAt = claims.getIssuedAt().toInstant();
            Instant maxAge = Instant.now().minusSeconds(csrfConfig.getMaxAgeSeconds());
            if (issuedAt.isBefore(maxAge)) {
                log.warn("Token issued too long ago. IssuedAt: {}, MaxAge: {}", issuedAt, maxAge);
                return ValidationResult.failure("Token too old");
            }

            // Validate subject (username)
            String subject = claims.getSubject();
            if (!constantTimeEquals(username, subject)) {
                log.warn("Username mismatch. Expected: {}, Got: {}", username, subject);
                return ValidationResult.failure("Username mismatch");
            }

            // Validate session ID
            String tokenSessionId = claims.get("session_id", String.class);
            if (!constantTimeEquals(sessionId, tokenSessionId)) {
                log.warn("Session ID mismatch");
                return ValidationResult.failure("Session ID mismatch");
            }

            // Validate User-Agent hash
            String userAgent = headers.getFirst(HttpHeaders.USER_AGENT);
            String expectedHash = hashUserAgent(userAgent);
            String tokenHash = claims.get("user_agent_hash", String.class);

            if (!constantTimeEquals(expectedHash, tokenHash)) {
                log.warn("User-Agent hash mismatch");
                return ValidationResult.failure("User-Agent mismatch");
            }

            log.trace("CSRF token validation successful for user: {}", username);
            return ValidationResult.success();

        } catch (JwtException e) {
            log.warn("JWT validation failed: {}", e.getMessage());
            return ValidationResult.failure("Invalid token signature or format");
        } catch (Exception e) {
            log.error("Unexpected error during CSRF validation", e);
            return ValidationResult.failure("Token validation error");
        }
    }

    /**
     * Hashes the User-Agent string using SHA-256.
     *
     * @param userAgent The User-Agent header value
     * @return Hex-encoded SHA-256 hash
     */
    private String hashUserAgent(String userAgent) {
        if (userAgent == null || userAgent.trim().isEmpty()) {
            return "";
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(userAgent.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available", e);
            throw new RuntimeException("Failed to hash User-Agent", e);
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     *
     * @param a First string
     * @param b Second string
     * @return true if strings are equal
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }

        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);

        return MessageDigest.isEqual(aBytes, bBytes);
    }

    /**
     * Converts byte array to hex string (Java 8 compatible).
     *
     * @param bytes Byte array to convert
     * @return Hex string
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Result of CSRF token validation.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String reason;

        private ValidationResult(boolean valid, String reason) {
            this.valid = valid;
            this.reason = reason;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult failure(String reason) {
            return new ValidationResult(false, reason);
        }

        public boolean isValid() {
            return valid;
        }

        public String getReason() {
            return reason;
        }
    }
}
