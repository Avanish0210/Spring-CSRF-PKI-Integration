package org.springframework.boot.autoconfigure.web;

/**
 * Compatibility shim for ServerProperties
 * 
 * This class provides compatibility between Spring Cloud Gateway 4.3.x and Spring Boot 4.0.1.
 * In Spring Boot 4.0, ServerProperties was moved to org.springframework.boot.web.server.autoconfigure.ServerProperties.
 * This class provides a type alias for Spring Cloud Gateway's expectations.
 * 
 * Note: This is a compatibility layer. The actual ServerProperties class is in
 * org.springframework.boot.web.server.autoconfigure.ServerProperties.
 */
public class ServerProperties extends org.springframework.boot.web.server.autoconfigure.ServerProperties {
    // This class exists to satisfy Spring Cloud Gateway's expectations
    // It extends the actual ServerProperties from Spring Boot 4.0.1
}
