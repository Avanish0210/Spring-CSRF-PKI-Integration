package com.oracle.hospitality.hdp.gateway.common;

import org.springframework.http.HttpHeaders;

public class GatewayConstants {
    public static final int ORDER_OF_HOTEL_INSPECTOR = -200;

    public static final String HDR_NAME_REQUEST_ID = "X-Request-Id";
    public static final String HDR_NAME_ENTERPRISE_ID = "X-Enterprise-Id";
    public static final String HDR_NAME_HOTEL_ID = "X-Hotel-Id";
    public static final String HDR_NAME_HDP_HOTEL_ID = "X-HDP-Hotel-Id";
    public static final String HDR_NAME_CHAIN_ID = "X-Chain-Id";
    public static final String HDR_NAME_TARGET_ENV = "X-Target-Environment";
    public static final String HDR_NAME_AUTHORIZATION = HttpHeaders.AUTHORIZATION;
    public static final String HDR_NAME_COOKIE = HttpHeaders.COOKIE;
    public static final String HDR_NAME_LOG_LEVEL = "X-Log-Level";
    public static final String HDR_NAME_TRACING_KEY = "X-Tracing-Key";
    public static final String HDR_NAME_SSD_ID = "X-SSD-Id";

    public static final String NON_SHARDED_ROUTING_HOTEL_ID = "NONE";
}
