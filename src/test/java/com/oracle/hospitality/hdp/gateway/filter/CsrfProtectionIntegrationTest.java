package com.oracle.hospitality.hdp.gateway.filter;

import io.jsonwebtoken.Jwts;
import java.security.interfaces.RSAPrivateKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import java.util.UUID;

/**
 * Integration tests for CSRF protection.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class CsrfProtectionIntegrationTest {

    @Autowired
    private WebTestClient webTestClient;

    private PrivateKey privateKey;
    private static final String TEST_USERNAME = "integrationuser";
    private static final String TEST_SESSION_ID = "integration-session-123";
    private static final String TEST_USER_AGENT = "Integration Test Browser";
    private static final String CSRF_HEADER = "X-CSRF-Token";

    @BeforeEach
    void setUp() throws Exception {
        privateKey = loadPrivateKey();
    }

    @Test
    void testGetRequestDoesNotRequireCsrfToken() {
        webTestClient.get()
                .uri("/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .exchange()
                .expectStatus().isNotFound(); // 404 because route doesn't exist, but CSRF passed
    }

    @Test
    void testPostRequestWithValidTokenSucceeds() {
        String token = createValidToken();

        webTestClient.post()
                .uri("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isNotFound(); // 404 because route doesn't exist, but CSRF passed
    }

    @Test
    void testPostRequestWithoutTokenReturns403() {
        webTestClient.post()
                .uri("/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.error").isEqualTo("missing_csrf_token");
    }

    @Test
    void testPostRequestWithExpiredTokenReturns403() {
        String token = createExpiredToken();

        webTestClient.post()
                .uri("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody()
                .jsonPath("$.error").isEqualTo("invalid_csrf_token");
    }

    @Test
    void testS2SRequestBypassesCsrf() {
        webTestClient.post()
                .uri("/api/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer s2s-token")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isNotFound(); // 404 because route doesn't exist, but CSRF bypassed
    }

    @Test
    void testPutRequestRequiresCsrfToken() {
        webTestClient.put()
                .uri("/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void testDeleteRequestRequiresCsrfToken() {
        webTestClient.delete()
                .uri("/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void testPatchRequestRequiresCsrfToken() {
        webTestClient.patch()
                .uri("/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void testOptionsRequestBypassesCsrf() {
        webTestClient.options()
                .uri("/api/test")
                .exchange()
                .expectStatus().isNotFound(); // 404 because route doesn't exist, but CSRF bypassed
    }

    @Test
    void testTokenWithWrongUsernameReturns403() {
        String token = createTokenWithUsername("wronguser");

        webTestClient.post()
                .uri("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void testTokenWithWrongSessionIdReturns403() {
        String token = createTokenWithSessionId("wrong-session");

        webTestClient.post()
                .uri("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=test")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"test\":\"data\"}")
                .exchange()
                .expectStatus().isForbidden();
    }

    // Helper methods

    private String createValidToken() {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer("hdp-csrf-issuer-test")
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey)
                .compact();
    }

    private String createExpiredToken() {
        Instant past = Instant.now().minusSeconds(700);
        return Jwts.builder()
                .issuer("hdp-csrf-issuer-test")
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(past))
                .expiration(Date.from(past.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey)
                .compact();
    }

    private String createTokenWithUsername(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer("hdp-csrf-issuer-test")
                .subject(username)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey)
                .compact();
    }

    private String createTokenWithSessionId(String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer("hdp-csrf-issuer-test")
                .subject(TEST_USERNAME)
                .claim("session_id", sessionId)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey)
                .compact();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    private String hashUserAgent(String userAgent) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(userAgent.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String privateKeyPEM = """
                MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
                MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
                NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
                qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
                p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
                ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
                VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
                laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
                sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
                mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
                dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
                ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
                DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
                N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
                0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
                t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
                AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
                48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
                DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
                xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
                mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
                2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
                et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
                VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
                TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
                dn/RsYEONbwQSjIfMPkvxF+8HQ==
                """.replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
