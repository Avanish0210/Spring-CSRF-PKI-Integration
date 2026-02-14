# services-router-gateway

Standard Spring Cloud Gateway with **Stateless CSRF Protection** for Oracle Hospitality HDP.

## Overview
- Spring Boot: 4.0.1
- Spring Framework: 7.0.x
- Spring Cloud Gateway: configured via `application.yml`
- Java: 17+ (tested with Java 21)
- Stateless CSRF: RS256-signed JWT validated against an RSA public key

## Features
- Stateless CSRF validation (no server-side session)
- Verifies `idcs_remote_user`, `idcs_session_id`, `User-Agent` hash, issuer, iat/exp
- Bypasses CSRF for safe methods (GET/OPTIONS/HEAD) and S2S calls (Authorization header without Cookie)
- Global CORS and route configuration via `spring.cloud.gateway.*`
- JSON error responses with request trace id header passthrough

## Configuration (application.yml)
Key properties under `csrf`:
| Property | Description | Default |
|----------|-------------|---------|
| `csrf.enabled` | Global toggle | `true` |
| `csrf.token.header-name` | Header for CSRF token | `X-CSRF-Token` |
| `csrf.public-key-location` | RSA Public Key path | `classpath:keys/csrf-public-key.pem` |
| `csrf.max-age-seconds` | Token TTL | `600` |
| `csrf.issuer` | Valid token issuer | `hdp-csrf-issuer` |
| `csrf.validate-origin` | Enable origin/referer validation | `false` |
| `csrf.allowed-origins` | Allowed origins list | `[]` |

Gateway routes and CORS:
```yaml
spring:
  cloud:
    gateway:
      globalcors:
        cors-configurations:
          '[/**]':
            allowedOrigins: "*"
            allowedMethods: [GET, POST, PUT, PATCH, DELETE, OPTIONS]
            allowedHeaders: "*"
            exposedHeaders: [X-CSRF-Token]
            maxAge: 3600
      routes:
        - id: example-service
          uri: http://localhost:8081
          predicates:
            - Path=/api/**
          filters:
            - StripPrefix=1
```

## Token Format
The gateway expects a JWT signed with the corresponding private key containing:
```json
{
  "iss": "hdp-csrf-issuer",
  "sub": "<username>",
  "session_id": "<session_id>",
  "user_agent_hash": "<SHA-256 hash of User-Agent>",
  "iat": <timestamp>,
  "exp": <timestamp>,
  "jti": "<unique-id>"
}
```

## Validation Logic
Rejections (403 Forbidden) occur if:
- Token is missing for unsafe methods (POST/PUT/DELETE/PATCH) in UI calls.
- Signature validation fails.
- `sub` does not match `idcs_remote_user` header.
- `session_id` does not match `idcs_session_id` header.
- `user_agent_hash` does not match the actual `User-Agent` header.
- Token is older than 10 minutes.
- Issuer does not match `csrf.issuer`.

## Headers Expected
- `X-CSRF-Token`: JWT for unsafe methods (UI flows)
- `idcs_remote_user`: authenticated username
- `idcs_session_id`: session identifier
- `User-Agent`: used to compute and verify `user_agent_hash`
- `Authorization`: if present without `Cookie`, treated as S2S and CSRF bypasses

## Generate Keys
Use OpenSSL to generate RSA key pair, then place the public key where configured:
```bash
# Windows
generate-keys.bat
# Copy public key to resources if needed
copy keys\csrf-public-key.pem src\main\resources\keys\csrf-public-key.pem
```

## Build and Run
```bash
# Build
mvn clean package -DskipTests

# Run packaged jar (preferred)
java -jar target/services-router-gateway-1.0.0-SNAPSHOT.jar

# Alternatively (can be heavier on memory)
mvn -DskipTests spring-boot:run
```

Service listens on `http://localhost:8080` by default.

## Tests
```bash
mvn test
```
Integration tests exercise CSRF flows with valid/invalid tokens and S2S bypass behavior.

## Troubleshooting
- JSON Web Key: ensure `csrf.public-key-location` points to a readable PEM with `-----BEGIN PUBLIC KEY-----` header.
- Missing Gateway beans: do not exclude `GatewayAutoConfiguration`; the app relies on Spring Cloud Gateway auto-config.
- Bean override error: avoid defining beans that duplicate Gateway’s provided beans (e.g., `routeLocatorBuilder`).
- Memory errors using `spring-boot:run`: prefer running the packaged jar (`java -jar`) or adjust JVM memory settings.

```bash
mvn spring-boot:run
```
