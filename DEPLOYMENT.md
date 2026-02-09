# Deployment Guide

This guide covers deploying the Services Router Gateway to various environments.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Local Development](#local-development)

- [Security Checklist](#security-checklist)

## Prerequisites

### Required
- Java 25 JDK
- Maven 3.8+
- RSA public key for CSRF validation

### Optional
- Docker 20.10+
- Kubernetes 1.24+
- kubectl CLI
- Helm 3.0+

## Local Development

### 1. Clone and Build

```bash
git clone <repository-url>
cd services-router-gateway
mvn clean install
```

### 2. Configure for Development

Create `application-local.yml`:

```yaml
server:
  port: 8080

csrf:
  enabled: false  # Disable for local development

spring:
  cloud:
    gateway:
      routes:
        - id: local-backend
          uri: http://localhost:8081
          predicates:
            - Path=/api/**
```

### 3. Run Locally

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local
```

Or with custom port:

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=local -Dserver.port=9090
```



## Security Checklist

Before deploying to production, verify:

- [ ] Public key is stored securely (vault/secrets manager)
- [ ] Private key is NEVER in this repository or deployment
- [ ] CSRF protection is enabled (`csrf.enabled=true`)
- [ ] TLS/HTTPS is configured for all external traffic
- [ ] Actuator endpoints are secured or disabled in production
- [ ] Resource limits are configured (CPU, memory)
- [ ] Health checks are configured
- [ ] Logging is configured for security events
- [ ] Monitoring and alerting are set up
- [ ] Key rotation procedure is documented
- [ ] Confluence "Secure Store Inventory" is updated
- [ ] Security scan passed (container image)
- [ ] Penetration testing completed (if required)

## Monitoring

### Prometheus Metrics

The gateway exposes Prometheus metrics at `/actuator/prometheus`:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'gateway'
    metrics_path: '/actuator/prometheus'
    static_configs:
      - targets: ['gateway:8080']
```

### Key Metrics to Monitor

- `http_server_requests_seconds_count{uri="/api/**"}` - Request count
- `http_server_requests_seconds_sum{uri="/api/**"}` - Request duration
- `jvm_memory_used_bytes` - Memory usage
- `process_cpu_usage` - CPU usage

### Logging

Configure structured logging for CSRF events:

```yaml
logging:
  pattern:
    console: '{"timestamp":"%d{yyyy-MM-dd HH:mm:ss}","level":"%level","logger":"%logger","message":"%message"}%n'
  level:
    com.oracle.hospitality.hdp.gateway.filter.CsrfValidationGlobalFilter: INFO
```

## Troubleshooting
      
### Application won't start

Check logs for any exceptions during startup, specifically related to:
- Public key loading
- Configuration errors

### Health check failing

Test manually:
```bash
curl http://localhost:8080/actuator/health
```

Check:
- Application started successfully
- Port is accessible
- No errors in logs

### High memory usage

Adjust JVM settings:
```bash
export JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC"
```

---

**Last Updated**: 2026-02-06  
**Version**: 1.0.0
