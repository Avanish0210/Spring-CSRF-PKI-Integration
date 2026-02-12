package com.oracle.hospitality.hdp.gateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.hospitality.hdp.gateway.common.GatewayConstants;
import com.oracle.hospitality.hdp.gateway.config.CsrfConfigurationProperties;
import com.oracle.hospitality.hdp.gateway.model.RequestContext;
import com.oracle.hospitality.hdp.gateway.service.CsrfTokenValidator;
import io.micrometer.common.util.StringUtils;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.event.Level;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.*;

import static com.oracle.hospitality.hdp.gateway.common.GatewayConstants.*;

/**
 * Primary filter for inspecting incoming requests and enforcing CSRF
 * protection.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "ROUTING_MODE", havingValue = "true", matchIfMissing = true)
public class RequestInspectionFilter implements WebFilter, Ordered {

    private final String thisEnvironment;
    private final CsrfTokenValidator csrfTokenValidator;
    private final CsrfConfigurationProperties csrfConfig;
    private final ObjectMapper objectMapper;

    public RequestInspectionFilter(@Value("${THIS_ENVIRONMENT:dev}") String thisEnvironment,
            CsrfTokenValidator csrfTokenValidator,
            CsrfConfigurationProperties csrfConfig,
            ObjectMapper objectMapper) {
        this.thisEnvironment = thisEnvironment;
        this.csrfTokenValidator = csrfTokenValidator;
        this.csrfConfig = csrfConfig;
        this.objectMapper = objectMapper;
    }

    @Override
    public int getOrder() {
        return GatewayConstants.ORDER_OF_HOTEL_INSPECTOR;
    }

    @Override
    @NonNull
    public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        try {
            inspectRequest(exchange);
        } catch (CsrfValidationException e) {
            return rejectRequest(exchange, e.getError(), e.getMessage());
        } catch (Exception e) {
            log.error("Request inspection failed: {}", e.getMessage());
            return rejectRequest(exchange, "bad_request", e.getMessage());
        }

        RequestContext context = getRequestContext(exchange);

        exchange.getResponse().beforeCommit(() -> {
            exchange.getResponse().getHeaders().set(HDR_NAME_REQUEST_ID, context.requestTraceId());
            return Mono.empty();
        });

        return chain.filter(mutateRequest(exchange, context));
    }

    private void inspectRequest(ServerWebExchange exchange) {
        val headers = exchange.getRequest().getHeaders();
        val hotelId = normalizeHotelId(getHotelIdFromHeaders(headers));
        val enterpriseId = normalizeEnterpriseId(headers.getFirst(HDR_NAME_ENTERPRISE_ID));
        val tracingKey = getOrGenerateTraceId(headers);
        boolean cookiePresent = headers.containsKey(HttpHeaders.COOKIE);

        // --- CSRF Validation ---
        validateCsrf(exchange, headers, cookiePresent);

        RequestContext context = new RequestContext(
                hotelId,
                cookiePresent,
                headers.containsKey(HttpHeaders.AUTHORIZATION),
                headers.getFirst(HDR_NAME_SSD_ID),
                headers.getFirst(HDR_NAME_TARGET_ENV),
                tracingKey,
                parseLogLevel(headers.getFirst(HDR_NAME_LOG_LEVEL)),
                headers.keySet(),
                enterpriseId,
                Map.of(),
                isServiceToService(headers));

        exchange.getAttributes().put("gatewayContext", context);
    }

    private RequestContext getRequestContext(ServerWebExchange exchange) {
        return (RequestContext) exchange.getAttributes().get("gatewayContext");
    }

    private void validateCsrf(ServerWebExchange exchange, HttpHeaders headers, boolean cookiePresent) {
        if (csrfConfig.getEnabled() && cookiePresent && !isServiceToService(headers)
                && isUnsafeMethod(exchange.getRequest().getMethod())) {
            log.debug("UI request detected. Validating CSRF.");

            String token = headers.getFirst(csrfConfig.getToken().getHeaderName());
            String user = headers.getFirst("idcs_remote_user");
            String session = headers.getFirst("idcs_session_id");

            if (StringUtils.isBlank(token))
                throw new CsrfValidationException("missing_csrf_token", "CSRF token is required");
            if (StringUtils.isBlank(user) || StringUtils.isBlank(session))
                throw new CsrfValidationException("missing_identity_headers", "User identity headers missing");

            var result = csrfTokenValidator.validate(token, headers, user, session);
            if (!result.isValid())
                throw new CsrfValidationException("invalid_csrf_token", result.getReason());
        }
    }

    private Mono<Void> rejectRequest(ServerWebExchange exchange, String error, String message) {
        org.springframework.http.server.reactive.ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(org.springframework.http.MediaType.APPLICATION_JSON);

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("error", error);
        errorBody.put("message", message);
        errorBody.put("timestamp", java.time.Instant.now().toString());

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorBody);
            org.springframework.core.io.buffer.DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (Exception e) {
            log.error("Failed to serialize error response", e);
            return Mono.error(new ResponseStatusException(HttpStatus.FORBIDDEN, message));
        }
    }

    private static class CsrfValidationException extends RuntimeException {
        private final String error;

        public CsrfValidationException(String error, String message) {
            super(message);
            this.error = error;
        }

        public String getError() {
            return error;
        }
    }

    private ServerWebExchange mutateRequest(ServerWebExchange exchange, RequestContext context) {
        return exchange.mutate().request(builder -> {
            if (StringUtils.isBlank(exchange.getRequest().getHeaders().getFirst(HDR_NAME_REQUEST_ID))) {
                builder.header(HDR_NAME_REQUEST_ID, context.requestTraceId());
            }
        }).build();
    }

    private boolean isServiceToService(HttpHeaders headers) {
        // Simple heuristic: Auth header present and no Cookie
        return headers.containsKey(HttpHeaders.AUTHORIZATION) && !headers.containsKey(HttpHeaders.COOKIE);
    }

    private boolean isUnsafeMethod(@Nullable HttpMethod method) {
        return method != null && (method == HttpMethod.POST || method == HttpMethod.PUT ||
                method == HttpMethod.PATCH || method == HttpMethod.DELETE);
    }

    private String getHotelIdFromHeaders(HttpHeaders headers) {
        return Optional.ofNullable(headers.getFirst(HDR_NAME_HDP_HOTEL_ID))
                .orElse(Optional.ofNullable(headers.getFirst(HDR_NAME_HOTEL_ID))
                        .orElse(headers.getFirst(HDR_NAME_CHAIN_ID)));
    }

    private String normalizeHotelId(String id) {
        return (id == null || id.isBlank() || id.equals(NON_SHARDED_ROUTING_HOTEL_ID)) ? null : id;
    }

    private String normalizeEnterpriseId(String id) {
        return (id == null || id.isBlank()) ? null : id.toUpperCase().trim();
    }

    private Level parseLogLevel(String level) {
        try {
            return level == null ? null : Level.valueOf(level.toUpperCase());
        } catch (Exception e) {
            return null;
        }
    }

    private String getOrGenerateTraceId(HttpHeaders headers) {
        String id = headers.getFirst(HDR_NAME_REQUEST_ID);
        if (StringUtils.isBlank(id))
            id = headers.getFirst(HDR_NAME_TRACING_KEY);
        return StringUtils.isBlank(id) ? UUID.randomUUID().toString() : id;
    }
}
