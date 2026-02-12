package com.oracle.hospitality.hdp.gateway.model;

import com.oracle.hospitality.hdp.gateway.common.GatewayConstants;
import java.util.Map;
import java.util.Set;
import org.slf4j.event.Level;

/**
 * Metadata gathered from the request during inspection.
 */
public record RequestContext(
        String hotelId,
        boolean cookiePresent,
        boolean authHeaderPresent,
        String ssdId,
        String targetEnv,
        String requestTraceId,
        Level logLevel,
        Set<String> headers,
        String cfgEnterpriseId,
        Map<String, Map<String, String>> hotelRoutes,
        boolean isOracleS2S) {
}
