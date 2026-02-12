package com.oracle.hospitality.hdp.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "csrf")
public class CsrfProperties {
    private boolean enabled = true;
    private String headerName = "X-CSRF-Token";
    private String publicKeyLocation = "classpath:keys/csrf-public-key.pem";
    private int maxAgeSeconds = 600;
    private String issuer = "hdp-csrf-issuer";
}
