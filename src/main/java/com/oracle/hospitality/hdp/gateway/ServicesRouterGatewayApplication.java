package com.oracle.hospitality.hdp.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Main application class for Services Router Gateway.
 * 
 * This gateway implements stateless CSRF protection using asymmetric PKI (RS256 signed JWT tokens).
 * 
 * @author Oracle Hospitality
 * @version 1.0.0
 */
@SpringBootApplication
public class ServicesRouterGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(ServicesRouterGatewayApplication.class, args);
    }
}
