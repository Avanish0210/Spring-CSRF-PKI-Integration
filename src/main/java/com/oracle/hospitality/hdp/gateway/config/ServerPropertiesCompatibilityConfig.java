package com.oracle.hospitality.hdp.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;

@Configuration
public class ServerPropertiesCompatibilityConfig {
    @Bean
    @ConditionalOnMissingBean(org.springframework.boot.autoconfigure.web.ServerProperties.class)
    public org.springframework.boot.autoconfigure.web.ServerProperties serverPropertiesCompatibilityBridge() {
        return new org.springframework.boot.autoconfigure.web.ServerProperties();
    }
}
