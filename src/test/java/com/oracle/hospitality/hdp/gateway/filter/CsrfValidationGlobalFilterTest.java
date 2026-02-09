package com.oracle.hospitality.hdp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.config.CsrfConfigurationProperties;
import com.oracle.hospitality.hdp.gateway.service.CsrfTokenValidator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Unit tests for CsrfValidationGlobalFilter.
 */
@ExtendWith(MockitoExtension.class)
class CsrfValidationGlobalFilterTest {

    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_SESSION_ID = "session-123";
    private static final String TEST_USER_AGENT = "Mozilla/5.0 Test Browser";
    private static final String CSRF_HEADER = "X-CSRF-Token";

    @Mock
    private GatewayFilterChain filterChain;

    private CsrfValidationGlobalFilter filter;
    private CsrfConfigurationProperties csrfConfig;
    private CsrfTokenValidator tokenValidator;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws Exception {
        // Load test keys
        privateKey = loadPrivateKey();
        publicKey = loadPublicKey();

        // Setup configuration
        csrfConfig = new CsrfConfigurationProperties();
        csrfConfig.setEnabled(true);
        csrfConfig.setIssuer("hdp-csrf-issuer-test");
        csrfConfig.setMaxAgeSeconds(600);
        csrfConfig.getToken().setHeaderName(CSRF_HEADER);

        // Create validator
        tokenValidator = new CsrfTokenValidator(csrfConfig, publicKey);

        // Create object mapper
        objectMapper = new ObjectMapper();

        // Create filter
        filter = new CsrfValidationGlobalFilter(csrfConfig, tokenValidator, objectMapper);

        // Mock filter chain to return completed mono
        when(filterChain.filter(any(ServerWebExchange.class)))
                .thenReturn(Mono.empty());
    }

    @Test
    void testSafeMethodsBypassCsrfValidation() {
        // Test GET
        ServerWebExchange exchange = createExchange(HttpMethod.GET, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testOptionsMethodBypassesCsrfValidation() {
        ServerWebExchange exchange = createExchange(HttpMethod.OPTIONS, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testHeadMethodBypassesCsrfValidation() {
        ServerWebExchange exchange = createExchange(HttpMethod.HEAD, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testS2SCallBypassesCsrfValidation() {
        // S2S call: no cookie, has Authorization header
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer s2s-token")
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testDisabledCsrfBypassesValidation() {
        csrfConfig.setEnabled(false);

        ServerWebExchange exchange = createExchange(HttpMethod.POST, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testMissingCsrfTokenReturns403() {
        ServerWebExchange exchange = createExchange(HttpMethod.POST, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testValidTokenProceeds() {
        String token = createValidToken();
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testExpiredTokenReturns403() {
        String token = createExpiredToken();
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testInvalidSignatureReturns403() {
        // Create token with wrong issuer to make signature invalid
        String token = createTokenWithWrongIssuer();
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testUsernameMismatchReturns403() {
        String token = createTokenWithUsername("wronguser");
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testSessionIdMismatchReturns403() {
        String token = createTokenWithSessionId("wrong-session");
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testUserAgentMismatchReturns403() {
        String token = createTokenWithUserAgent("Different Browser");
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testTooOldTokenReturns403() {
        // Create token issued 11 minutes ago (older than max age of 10 minutes)
        String token = createTokenIssuedAt(Instant.now().minusSeconds(660));
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testPostMethodRequiresCsrfToken() {
        ServerWebExchange exchange = createExchange(HttpMethod.POST, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testPutMethodRequiresCsrfToken() {
        ServerWebExchange exchange = createExchange(HttpMethod.PUT, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testPatchMethodRequiresCsrfToken() {
        ServerWebExchange exchange = createExchange(HttpMethod.PATCH, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testDeleteMethodRequiresCsrfToken() {
        ServerWebExchange exchange = createExchange(HttpMethod.DELETE, null);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testMissingUsernameHeaderReturns403() {
        String token = createValidToken();
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=abc")
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testMissingSessionIdHeaderReturns403() {
        String token = createValidToken();
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/test")
                .header(CSRF_HEADER, token)
                .header("idcs_remote_user", TEST_USERNAME)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=abc")
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, filterChain))
                .verifyComplete();

        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    // Helper methods

    private ServerWebExchange createExchange(HttpMethod method, String csrfToken) {
        MockServerHttpRequest.BaseBuilder<?> builder = MockServerHttpRequest
                .method(method, "/api/test")
                .header("idcs_remote_user", TEST_USERNAME)
                .header("idcs_session_id", TEST_SESSION_ID)
                .header(HttpHeaders.USER_AGENT, TEST_USER_AGENT)
                .header(HttpHeaders.COOKIE, "session=abc");

        if (csrfToken != null) {
            builder.header(CSRF_HEADER, csrfToken);
        }

        return MockServerWebExchange.from(builder.build());
    }

    private String createValidToken() {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createExpiredToken() {
        Instant past = Instant.now().minusSeconds(700);
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(past))
                .expiration(Date.from(past.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createTokenWithWrongIssuer() {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer("wrong-issuer")
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createTokenWithUsername(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(username)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createTokenWithSessionId(String sessionId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(TEST_USERNAME)
                .claim("session_id", sessionId)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createTokenWithUserAgent(String userAgent) {
        Instant now = Instant.now();
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(userAgent))
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String createTokenIssuedAt(Instant issuedAt) {
        return Jwts.builder()
                .issuer(csrfConfig.getIssuer())
                .subject(TEST_USERNAME)
                .claim("session_id", TEST_SESSION_ID)
                .claim("user_agent_hash", hashUserAgent(TEST_USER_AGENT))
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(issuedAt.plusSeconds(600)))
                .id(UUID.randomUUID().toString())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    private String hashUserAgent(String userAgent) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(userAgent.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
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

    private PublicKey loadPublicKey() throws Exception {
        String publicKeyPEM = """
                MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
                4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
                +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
                kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
                0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
                cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
                mwIDAQAB
                """.replaceAll("\\s+", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
