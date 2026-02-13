package com.oracle.hospitality.hdp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = {
    org.springframework.cloud.autoconfigure.LifecycleMvcEndpointAutoConfiguration.class,
    org.springframework.cloud.autoconfigure.RefreshAutoConfiguration.class,
    org.springframework.cloud.client.discovery.simple.SimpleDiscoveryClientAutoConfiguration.class,
    org.springframework.cloud.client.discovery.simple.reactive.SimpleReactiveDiscoveryClientAutoConfiguration.class,
    org.springframework.cloud.client.loadbalancer.LoadBalancerAutoConfiguration.class,
    org.springframework.cloud.gateway.config.GatewayAutoConfiguration.class
})
public class ServicesRouterGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ServicesRouterGatewayApplication.class, args);
    }
}
