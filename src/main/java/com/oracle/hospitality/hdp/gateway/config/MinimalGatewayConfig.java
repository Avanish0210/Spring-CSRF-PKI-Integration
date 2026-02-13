package com.oracle.hospitality.hdp.gateway.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Minimal Gateway configuration to replace GatewayAutoConfiguration
 * This provides essential Gateway beans needed for routing to work.
 */
@Configuration
public class MinimalGatewayConfig {

    @Bean
    public RouteLocatorBuilder routeLocatorBuilder(ConfigurableApplicationContext applicationContext) {
        return new RouteLocatorBuilder(applicationContext);
    }

    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("example-service", r -> r
                        .path("/api/**")
                        .filters(f -> f.stripPrefix(1))
                        .uri("http://localhost:8081"))
                .build();
    }
}
