package org.springframework.boot.autoconfigure.web.embedded;

import org.springframework.boot.web.server.WebServerFactoryCustomizer;

/**
 * Compatibility shim for NettyWebServerFactoryCustomizer
 * 
 * This class provides compatibility between Spring Cloud Gateway 4.3.x and Spring Boot 4.0.1.
 * In Spring Boot 4.0, NettyWebServerFactoryCustomizer was removed and replaced with NettyServerCustomizer.
 * This interface provides the expected type for Spring Cloud Gateway's NettyConfiguration.
 * 
 * Note: This is a compatibility layer. The actual customization is handled by Spring Boot 4.0's
 * NettyServerCustomizer mechanism.
 * 
 * Using raw type to avoid dependency on classes that may have been moved/renamed in Spring Boot 4.0.
 */
@SuppressWarnings("rawtypes")
public interface NettyWebServerFactoryCustomizer extends WebServerFactoryCustomizer {
    // This interface exists to satisfy Spring Cloud Gateway's expectations
    // The actual implementation is provided by Spring Boot's auto-configuration
}
