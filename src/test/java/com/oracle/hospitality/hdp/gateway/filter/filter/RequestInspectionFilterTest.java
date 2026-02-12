package com.oracle.hospitality.hdp.gateway.filter.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.config.CsrfConfigurationProperties;
import com.oracle.hospitality.hdp.gateway.filter.RequestInspectionFilter;
import com.oracle.hospitality.hdp.gateway.service.CsrfTokenValidator;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
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
 * Unit tests for RequestInspectionFilter.
 */
@ExtendWith(MockitoExtension.class)
class RequestInspectionFilterTest {

    private static final String TEST_USERNAME = "testuser";
    private static final String TEST_SESSION_ID = "session-123";
    private static final String TEST_USER_AGENT = "Mozilla/5.0 Test Browser";
    private static final String CSRF_HEADER = "X-CSRF-Token";

    @Mock
    private WebFilterChain filterChain;

    private RequestInspectionFilter filter;
    private CsrfConfigurationProperties csrfConfig;
    private CsrfTokenValidator tokenValidator;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws Exception {
        privateKey = loadPrivateKey();
        publicKey = loadPublicKey();

        csrfConfig = new CsrfConfigurationProperties();
        csrfConfig.setEnabled(true);
        csrfConfig.setIssuer("hdp-csrf-issuer-test");
        csrfConfig.setMaxAgeSeconds(600);
        csrfConfig.getToken().setHeaderName(CSRF_HEADER);

        tokenValidator = new CsrfTokenValidator(csrfConfig, publicKey);
        filter = new RequestInspectionFilter("test-env", tokenValidator, csrfConfig, new ObjectMapper());

        when(filterChain.filter(any(ServerWebExchange.class))).thenReturn(Mono.empty());
    }

    @Test
    void testSafeMethodsBypassCsrfValidation() {
        ServerWebExchange exchange = createExchange(HttpMethod.GET, null);
        StepVerifier.create(filter.filter(exchange, filterChain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isNull(); // No error set
    }

    @Test
    void testValidTokenProceeds() {
        String token = createValidToken();
        ServerWebExchange exchange = createExchange(HttpMethod.POST, token);
        StepVerifier.create(filter.filter(exchange, filterChain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isNull();
    }

    @Test
    void testMissingCsrfTokenReturns403() {
        ServerWebExchange exchange = createExchange(HttpMethod.POST, null);
        StepVerifier.create(filter.filter(exchange, filterChain)).verifyComplete();
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void testS2SCallBypassesCsrfValidation() {
        MockServerHttpRequest request = MockServerHttpRequest
                .post("/api/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer s2s-token")
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);
        StepVerifier.create(filter.filter(exchange, filterChain)).verifyComplete();
    }

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
        String privateKeyPEM = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKjMzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvuNMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZqgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulgp2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlRZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwiVuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskVlaAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83HmQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwYdgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cwta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQDM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2TN0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPvt8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDUAhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISLDY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnKxt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEAmNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfzet6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhrVBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicDTQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cncdn/RsYEONbwQSjIfMPkvxF+8HQ==";
        byte[] encoded = Base64.getDecoder().decode(privateKeyPEM.replaceAll("\\s+", ""));
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private PublicKey loadPublicKey() throws Exception {
        String publicKeyPEM = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc mwIDAQAB";
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM.replaceAll("\\s+", ""));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
