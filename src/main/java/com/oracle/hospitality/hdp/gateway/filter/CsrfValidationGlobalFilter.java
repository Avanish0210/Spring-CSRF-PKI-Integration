package com.oracle.hospitality.hdp.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.config.CsrfConfigurationProperties;
import com.oracle.hospitality.hdp.gateway.service.CsrfTokenValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Global filter for CSRF token validation.
 * 
 * This filter validates CSRF tokens for unsafe HTTP methods (POST, PUT, PATCH,
 * DELETE).
 * Safe methods (GET, OPTIONS, HEAD) and service-to-service calls bypass
 * validation.
 * 
 * Order: -100 (executes early in the filter chain, before routing)
 */
@Slf4j
@Component
public class CsrfValidationGlobalFilter implements GlobalFilter, Ordered {

    private static final Set<HttpMethod> UNSAFE_METHODS = Set.of(
            HttpMethod.POST,
            HttpMethod.PUT,
            HttpMethod.PATCH,
            HttpMethod.DELETE);

    private static final Set<HttpMethod> SAFE_METHODS = Set.of(
            HttpMethod.GET,
            HttpMethod.HEAD,
            HttpMethod.OPTIONS);

    private static final String IDCS_REMOTE_USER_HEADER = "idcs_remote_user";
    private static final String IDCS_SESSION_ID_HEADER = "idcs_session_id";

    private final CsrfConfigurationProperties csrfConfig;
    private final CsrfTokenValidator tokenValidator;
    private final ObjectMapper objectMapper;

    public CsrfValidationGlobalFilter(
            CsrfConfigurationProperties csrfConfig,
            CsrfTokenValidator tokenValidator,
            ObjectMapper objectMapper) {
        this.csrfConfig = csrfConfig;
        this.tokenValidator = tokenValidator;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        HttpMethod method = request.getMethod();

        // Skip if CSRF protection is disabled
        if (!csrfConfig.getEnabled()) {
            log.trace("CSRF protection is disabled");
            return chain.filter(exchange);
        }

        // Skip safe methods
        if (SAFE_METHODS.contains(method)) {
            log.trace("Safe method {}, bypassing CSRF validation", method);
            return chain.filter(exchange);
        }

        // Skip if not an unsafe method
        if (!UNSAFE_METHODS.contains(method)) {
            log.trace("Method {} is not subject to CSRF validation", method);
            return chain.filter(exchange);
        }

        HttpHeaders headers = request.getHeaders();

        // Skip service-to-service calls
        if (isS2SCall(headers)) {
            log.trace("Service-to-service call detected, bypassing CSRF validation");
            return chain.filter(exchange);
        }

        // This is a UI call with an unsafe method - validate CSRF token
        log.debug("Validating CSRF token for {} {}", method, request.getPath());

        String csrfToken = headers.getFirst(csrfConfig.getToken().getHeaderName());

        // Missing token
        if (csrfToken == null || csrfToken.isBlank()) {
            log.warn("Missing CSRF token for {} {}", method, request.getPath());
            return rejectRequest(exchange, "missing_csrf_token", "CSRF token is required");
        }

        // Extract user information from headers
        String username = headers.getFirst(IDCS_REMOTE_USER_HEADER);
        String sessionId = headers.getFirst(IDCS_SESSION_ID_HEADER);

        // Validate required headers
        if (username == null || username.isBlank()) {
            log.warn("Missing {} header", IDCS_REMOTE_USER_HEADER);
            return rejectRequest(exchange, "missing_user_header", "User identification header missing");
        }

        if (sessionId == null || sessionId.isBlank()) {
            log.warn("Missing {} header", IDCS_SESSION_ID_HEADER);
            return rejectRequest(exchange, "missing_session_header", "Session identification header missing");
        }

        // Validate the token
        CsrfTokenValidator.ValidationResult result = tokenValidator.validate(
                csrfToken, headers, username, sessionId);

        if (!result.isValid()) {
            log.warn("CSRF token validation failed: {}", result.getReason());
            return rejectRequest(exchange, "invalid_csrf_token",
                    "Invalid or expired CSRF token: " + result.getReason());
        }

        log.trace("CSRF token validation successful for user: {}", username);
        return chain.filter(exchange);
    }

    /**
     * Determines if the request is a service-to-service call.
     * 
     * S2S calls are identified by:
     * 1. No Cookie header present
     * 2. Authorization header present (for authenticated S2S)
     * 3. OR no Authorization and no Cookie (for internal/local calls)
     *
     * @param headers Request headers
     * @return true if this is an S2S call
     */
    private boolean isS2SCall(HttpHeaders headers) {
        String cookie = headers.getFirst(HttpHeaders.COOKIE);
        String authorization = headers.getFirst(HttpHeaders.AUTHORIZATION);

        // If Cookie is present, this is a browser/UI call
        if (cookie != null && !cookie.isBlank()) {
            return false;
        }

        // No cookie present - check authorization
        if (authorization != null && !authorization.isBlank()) {
            return isS2SCallBasedOnAuth(authorization);
        }

        // No cookie, no auth - assume internal/local call
        return true;
    }

    /**
     * Additional validation for S2S calls based on Authorization header.
     * 
     * This can be customized based on your S2S authentication mechanism.
     * For example, check for specific token patterns, client credentials, etc.
     *
     * @param authorization Authorization header value
     * @return true if this is a valid S2S authorization
     */
    private boolean isS2SCallBasedOnAuth(String authorization) {
        // Default implementation: any Bearer token without Cookie is considered S2S
        // Customize this based on your specific S2S authentication requirements
        return authorization.startsWith("Bearer ");
    }

    /**
     * Rejects the request with a 403 Forbidden response and JSON error body.
     *
     * @param exchange ServerWebExchange
     * @param error    Error code
     * @param message  Error message
     * @return Mono<Void>
     */
    private Mono<Void> rejectRequest(ServerWebExchange exchange, String error, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("error", error);
        errorBody.put("message", message);
        errorBody.put("timestamp", Instant.now().toString());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorBody);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize error response", e);
            // Fallback to plain text
            String fallbackMessage = String.format("{\"error\":\"%s\",\"message\":\"%s\"}", error, message);
            DataBuffer buffer = response.bufferFactory()
                    .wrap(fallbackMessage.getBytes(StandardCharsets.UTF_8));
            return response.writeWith(Mono.just(buffer));
        }
    }

    @Override
    public int getOrder() {
        return -100; // Execute early, before routing
    }
}
