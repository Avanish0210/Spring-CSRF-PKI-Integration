package org.springframework.boot.web.embedded.netty;

import reactor.netty.http.server.HttpServer;

import java.util.function.Function;

/**
 * Compatibility shim for NettyServerCustomizer
 * 
 * This class provides compatibility between Spring Cloud Gateway 4.3.x and Spring Boot 4.0.1.
 * In Spring Boot 4.0, NettyServerCustomizer is a functional interface for customizing Netty servers.
 * This interface provides the expected type for Spring Cloud Gateway's NettyConfiguration.
 * 
 * Note: This is a compatibility layer. The actual NettyServerCustomizer is in
 * org.springframework.boot.reactor.netty.NettyServerCustomizer in Spring Boot 4.0.
 */
@FunctionalInterface
public interface NettyServerCustomizer extends Function<HttpServer, HttpServer> {
    // This interface exists to satisfy Spring Cloud Gateway's expectations
    // It's a functional interface that customizes HttpServer instances
}
