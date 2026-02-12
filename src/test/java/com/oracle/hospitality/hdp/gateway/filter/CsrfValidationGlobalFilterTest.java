package com.oracle.hospitality.hdp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.config.CsrfProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.io.ResourceLoader;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class CsrfValidationGlobalFilterTest {

    private CsrfValidationGlobalFilter filter;
    private CsrfProperties properties;
    private GatewayFilterChain chain;
    private PrivateKey privateKey;

    private static final String PRIVATE_KEY_PEM = "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj" +
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu" +
            "NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ" +
            "qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg" +
            "p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR" +
            "ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi" +
            "VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV" +
            "laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8" +
            "sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H" +
            "mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY" +
            "dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw" +
            "ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ" +
            "DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T" +
            "N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t" +
            "0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv" +
            "t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU" +
            "AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk" +
            "48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL" +
            "DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK" +
            "xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA" +
            "mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh" +
            "2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz" +
            "et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr" +
            "VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD" +
            "TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc" +
            "dn/RsYEONbwQSjIfMPkvxF+8HQ==";

    @BeforeEach
    void setUp() throws Exception {
        properties = new CsrfProperties();
        properties.setPublicKeyLocation("classpath:keys/csrf-public-key.pem");
        properties.setIssuer("hdp-csrf-issuer");

        ObjectMapper mapper = new ObjectMapper();
        ResourceLoader mockLoader = mock(ResourceLoader.class);
        org.springframework.core.io.Resource mockRes = mock(org.springframework.core.io.Resource.class);

        String pubKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt1SU1LfVLPHCozMxH2Mo\n" +
                "4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u\n" +
                "+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh\n" +
                "kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ\n" +
                "0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg\n" +
                "cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc\n" +
                "mwIDAQAB\n" +
                "-----END PUBLIC KEY-----";

        when(mockRes.getInputStream()).thenReturn(new java.io.ByteArrayInputStream(pubKey.getBytes()));
        when(mockLoader.getResource(any())).thenReturn(mockRes);

        filter = new CsrfValidationGlobalFilter(properties, mapper, mockLoader);
        chain = mock(GatewayFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        byte[] encoded = Base64.getDecoder().decode(PRIVATE_KEY_PEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    @Test
    void testSafeMethodBypasses() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/test").build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void testS2SCallBypasses() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/test")
                .header("Authorization", "Bearer token")
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void testMissingTokenReturns403() {
        MockServerHttpRequest request = MockServerHttpRequest.post("/api/test")
                .header("Cookie", "session=123")
                .build();
        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
    }

    @Test
    void testValidTokenProceeds() throws Exception {
        String userAgent = "Mozilla/5.0";
        String username = "john";
        String sessionId = "sess1";
        String hash = hashUserAgent(userAgent);

        String token = Jwts.builder()
                .issuer("hdp-csrf-issuer")
                .subject(username)
                .claim("session_id", sessionId)
                .claim("user_agent_hash", hash)
                .issuedAt(new Date())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        MockServerHttpRequest request = MockServerHttpRequest.post("/api/test")
                .header("Cookie", "session=123")
                .header("X-CSRF-Token", token)
                .header("idcs_remote_user", username)
                .header("idcs_session_id", sessionId)
                .header(HttpHeaders.USER_AGENT, userAgent)
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);

        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        verify(chain, times(1)).filter(exchange);
    }

    @Test
    void testMismatchedUserReturns403() throws Exception {
        String token = Jwts.builder()
                .issuer("hdp-csrf-issuer")
                .subject("john")
                .issuedAt(new Date())
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        MockServerHttpRequest request = MockServerHttpRequest.post("/api/test")
                .header("Cookie", "session=123")
                .header("X-CSRF-Token", token)
                .header("idcs_remote_user", "wrong_user")
                .build();

        ServerWebExchange exchange = MockServerWebExchange.from(request);
        StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();
        assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
    }

    private String hashUserAgent(String userAgent) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(userAgent.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }
}
