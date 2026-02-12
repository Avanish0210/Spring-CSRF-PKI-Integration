package com.oracle.hospitality.hdp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.config.CsrfProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;

@Slf4j
@Component
public class CsrfValidationGlobalFilter implements GlobalFilter, Ordered {

    private final CsrfProperties properties;
    private final ObjectMapper objectMapper;
    private final ResourceLoader resourceLoader;
    private PublicKey publicKey;

    private static final Set<HttpMethod> UNSAFE_METHODS = Set.of(HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH,
            HttpMethod.DELETE);

    public CsrfValidationGlobalFilter(CsrfProperties properties, ObjectMapper objectMapper,
            ResourceLoader resourceLoader) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.resourceLoader = resourceLoader;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!properties.isEnabled()) {
            return chain.filter(exchange);
        }

        HttpMethod method = exchange.getRequest().getMethod();
        if (method == null || !UNSAFE_METHODS.contains(method)) {
            return chain.filter(exchange);
        }

        HttpHeaders headers = exchange.getRequest().getHeaders();
        if (isS2SCall(headers)) {
            return chain.filter(exchange);
        }

        String token = headers.getFirst(properties.getHeaderName());
        if (token == null || token.isBlank()) {
            return errorResponse(exchange, "missing_csrf_token", "Invalid or missing CSRF token");
        }

        try {
            if (publicKey == null) {
                this.publicKey = loadPublicKey();
            }

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // 1. Issuer check
            if (!properties.getIssuer().equals(claims.getIssuer())) {
                return errorResponse(exchange, "invalid_csrf_token", "Invalid issuer");
            }

            // 2. Sub match idcs_remote_user
            String sub = claims.getSubject();
            String idcsUser = headers.getFirst("idcs_remote_user");
            if (idcsUser == null || !idcsUser.equals(sub)) {
                return errorResponse(exchange, "invalid_csrf_token", "User mismatch");
            }

            // 3. session_id match idcs_session_id
            String sessionId = claims.get("session_id", String.class);
            String idcsSession = headers.getFirst("idcs_session_id");
            if (idcsSession == null || !idcsSession.equals(sessionId)) {
                return errorResponse(exchange, "invalid_csrf_token", "Session mismatch");
            }

            // 4. user_agent_hash match SHA-256(User-Agent)
            String userAgent = headers.getFirst(HttpHeaders.USER_AGENT);
            String tokenHash = claims.get("user_agent_hash", String.class);
            if (userAgent == null || !hashUserAgent(userAgent).equals(tokenHash)) {
                return errorResponse(exchange, "invalid_csrf_token", "User-Agent mismatch");
            }

            // 5. Age check (iat older than 10 mins)
            Instant iat = claims.getIssuedAt().toInstant();
            if (iat.plusSeconds(properties.getMaxAgeSeconds()).isBefore(Instant.now())) {
                return errorResponse(exchange, "invalid_csrf_token", "Token expired (iat)");
            }

            return chain.filter(exchange);

        } catch (Exception e) {
            log.error("CSRF Validation failed: {}", e.getMessage());
            return errorResponse(exchange, "invalid_csrf_token", "Invalid or missing CSRF token");
        }
    }

    private boolean isS2SCall(HttpHeaders headers) {
        String cookie = headers.getFirst("Cookie");
        if (cookie != null && !cookie.isBlank())
            return false;
        String auth = headers.getFirst("Authorization");
        if (auth != null && !auth.isBlank()) {
            // S2S check: typically Bearer token without session cookie
            return auth.startsWith("Bearer ");
        }
        return true; // Internal/local call
    }

    private String hashUserAgent(String userAgent) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(userAgent.getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(hash);
    }

    private PublicKey loadPublicKey() throws Exception {
        Resource resource = resourceLoader.getResource(properties.getPublicKeyLocation());
        String pem = new String(resource.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        String publicKeyPEM = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }

    private Mono<Void> errorResponse(ServerWebExchange exchange, String error, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, String> body = Map.of(
                "error", error,
                "message", message,
                "timestamp", Instant.now().toString());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(body);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            return response.setComplete();
        }
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
