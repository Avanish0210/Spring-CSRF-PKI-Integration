# Services Router Gateway

A production-grade Spring Cloud Gateway implementing **stateless CSRF protection** using asymmetric PKI (RS256 signed JWT tokens).

## 🔒 Security Features

- **Stateless CSRF Protection**: No server-side session storage required
- **Asymmetric Cryptography**: RS256 (RSA with SHA-256) for token signing
- **Short-lived Tokens**: 10-minute TTL with issued-at validation
- **Multi-factor Validation**: Username, session ID, and User-Agent hash verification
- **Service-to-Service Bypass**: Automatic detection and bypass for S2S calls
- **Constant-time Comparison**: Protection against timing attacks

## 📋 Table of Contents

- [How CSRF Protection Works](#how-csrf-protection-works)
- [Configuration](#configuration)
- [Token Format](#token-format)
- [Validation Rules](#validation-rules)
- [Header Preservation](#header-preservation)
- [Getting Started](#getting-started)
- [Testing](#testing)
- [Production Deployment](#production-deployment)
- [Troubleshooting](#troubleshooting)

## 🛡️ How CSRF Protection Works

### Overview

This gateway implements a **stateless CSRF protection mechanism** that validates JWT tokens signed with RSA private keys. The frontend application fetches CSRF tokens from a token-issuing service and includes them in requests.

### Flow Diagram

```
┌─────────┐                 ┌──────────────┐                ┌─────────┐
│ Browser │                 │   Gateway    │                │ Backend │
└────┬────┘                 └──────┬───────┘                └────┬────┘
     │                             │                             │
     │  1. GET /csrf-token         │                             │
     ├────────────────────────────>│                             │
     │                             │                             │
     │  2. JWT Token (signed)      │                             │
     │<────────────────────────────┤                             │
     │                             │                             │
     │  3. POST /api/resource      │                             │
     │     X-CSRF-Token: <JWT>     │                             │
     ├────────────────────────────>│                             │
     │                             │                             │
     │                             │  4. Validate Token          │
     │                             │     - Signature             │
     │                             │     - Claims                │
     │                             │     - Expiration            │
     │                             │                             │
     │                             │  5. Forward Request         │
     │                             ├────────────────────────────>│
     │                             │                             │
     │                             │  6. Response                │
     │                             │<────────────────────────────┤
     │                             │                             │
     │  7. Response                │                             │
     │<────────────────────────────┤                             │
     │                             │                             │
```

### Key Concepts

1. **Token Issuance**: A separate service (not included in this gateway) issues CSRF tokens signed with a private key
2. **Token Validation**: This gateway validates tokens using the corresponding public key
3. **Stateless**: No server-side session storage - all validation data is in the token
4. **Short-lived**: Tokens expire after 10 minutes to limit exposure window

## ⚙️ Configuration

### Application Properties

```yaml
csrf:
  enabled: true                                          # Enable/disable CSRF protection
  token:
    header-name: X-CSRF-Token                           # HTTP header name for token
  public-key-location: classpath:keys/csrf-public-key.pem  # Public key location
  max-age-seconds: 600                                  # Token max age (10 minutes)
  issuer: hdp-csrf-issuer                              # Expected issuer claim
  validate-origin: false                                # Enable origin validation (optional)
  allowed-origins:                                      # Allowed origins (if validate-origin=true)
    - http://localhost:3000
    - https://your-frontend-domain.com
```

### Public Key Location

The `public-key-location` property supports:

- **Classpath**: `classpath:keys/csrf-public-key.pem`
- **Filesystem**: `file:/path/to/csrf-public-key.pem`
- **Direct PEM**: Paste the entire PEM string (starts with `-----BEGIN PUBLIC KEY-----`)

### Environment-Specific Configuration

#### Development (`application-dev.yml`)
```yaml
csrf:
  enabled: false  # Disable for local development
```

#### Testing (`application-test.yml`)
```yaml
csrf:
  enabled: false  # Disable for unit/integration tests
  public-key-location: classpath:keys/csrf-public-key-test.pem
```

#### Production (`application.yml`)
```yaml
csrf:
  enabled: true
  public-key-location: ${CSRF_PUBLIC_KEY_LOCATION}  # From environment variable
```

## 🎫 Token Format

### JWT Structure

```json
{
  "iss": "hdp-csrf-issuer",
  "sub": "<username>",
  "session_id": "<session_id>",
  "user_agent_hash": "<SHA-256 hash of User-Agent>",
  "iat": <unix timestamp when created>,
  "exp": <iat + 600 seconds (10 minutes)>,
  "jti": "<unique token id>"
}
```

### Claims Description

| Claim | Description | Validation |
|-------|-------------|------------|
| `iss` | Issuer identifier | Must match configured issuer |
| `sub` | Username | Must match `idcs_remote_user` header |
| `session_id` | Session identifier | Must match `idcs_session_id` header |
| `user_agent_hash` | SHA-256 hash of User-Agent | Must match hash of current User-Agent |
| `iat` | Issued at timestamp | Must not be older than `max-age-seconds` |
| `exp` | Expiration timestamp | Must be in the future |
| `jti` | Unique token ID | For tracking/auditing |

### Example Token Generation (for testing)

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

String token = Jwts.builder()
    .issuer("hdp-csrf-issuer")
    .subject("john.doe")
    .claim("session_id", "sess-abc-123")
    .claim("user_agent_hash", hashUserAgent("Mozilla/5.0..."))
    .issuedAt(Date.from(Instant.now()))
    .expiration(Date.from(Instant.now().plusSeconds(600)))
    .id(UUID.randomUUID().toString())
    .signWith(privateKey, SignatureAlgorithm.RS256)
    .compact();
```

## ✅ Validation Rules

### 1. Method-Based Validation

| HTTP Method | CSRF Required? |
|-------------|----------------|
| GET | ❌ No |
| HEAD | ❌ No |
| OPTIONS | ❌ No |
| POST | ✅ Yes |
| PUT | ✅ Yes |
| PATCH | ✅ Yes |
| DELETE | ✅ Yes |

### 2. Service-to-Service Detection

S2S calls bypass CSRF validation using this logic:

```java
private boolean isS2SCall(HttpHeaders headers) {
    String cookie = headers.getFirst("Cookie");
    String authorization = headers.getFirst("Authorization");
    
    // If Cookie is present, it's a browser call
    if (cookie != null && !cookie.isBlank()) {
        return false;
    }
    
    // No cookie + Authorization header = S2S call
    if (authorization != null && !authorization.isBlank()) {
        return isS2SCallBasedOnAuth(authorization);
    }
    
    // No cookie, no auth = internal/local call
    return true;
}
```

### 3. Token Validation Steps

1. **Signature Verification**: Validate JWT signature using public key
2. **Issuer Check**: `iss` claim must match configured issuer
3. **Expiration Check**: `exp` must be in the future
4. **Age Check**: `iat` must not be older than `max-age-seconds`
5. **Username Match**: `sub` must equal `idcs_remote_user` header
6. **Session Match**: `session_id` must equal `idcs_session_id` header
7. **User-Agent Match**: `user_agent_hash` must match SHA-256 of current User-Agent

### 4. Error Responses

All CSRF validation failures return **403 Forbidden** with JSON body:

```json
{
  "error": "invalid_csrf_token",
  "message": "Invalid or expired CSRF token: Token expired",
  "timestamp": "2026-02-06T15:21:33Z"
}
```

Error codes:
- `missing_csrf_token`: No X-CSRF-Token header provided
- `invalid_csrf_token`: Token validation failed
- `missing_user_header`: No idcs_remote_user header
- `missing_session_header`: No idcs_session_id header

## 📨 Header Preservation

The gateway preserves all important headers from Karate scenarios:

### Request Headers (Preserved)
- `idcs_remote_user`: User identification
- `idcs_session_id`: Session identification
- `x-chainId`: Chain/tenant identifier
- `x-hdp-hotel-id`: Hotel identifier
- `Cookie`: Session cookies
- `User-Agent`: Browser identification
- `Authorization`: OAuth2/JWT tokens (for S2S)

### Response Headers
- All backend response headers are forwarded
- `x-set-cookie` is **not** forwarded (security best practice)

## 🚀 Getting Started

### Prerequisites

- **Java 25** (or compatible JDK)
- **Maven 3.8+**
- RSA key pair (public key for gateway, private key for token issuer)

### 1. Generate RSA Key Pair

```bash
# Generate private key
openssl genrsa -out csrf-private-key.pem 2048

# Extract public key
openssl rsa -in csrf-private-key.pem -pubout -out csrf-public-key.pem
```

### 2. Configure Public Key

Place `csrf-public-key.pem` in `src/main/resources/keys/` or configure location:

```yaml
csrf:
  public-key-location: file:/secure/path/csrf-public-key.pem
```

### 3. Build the Project

```bash
mvn clean install
```

### 4. Run the Application

```bash
# Development mode (CSRF disabled)
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Production mode (CSRF enabled)
mvn spring-boot:run
```

### 5. Test CSRF Protection

```bash
# Safe method - no CSRF required
curl -X GET http://localhost:8080/api/test

# Unsafe method without token - returns 403
curl -X POST http://localhost:8080/api/test \
  -H "idcs_remote_user: testuser" \
  -H "idcs_session_id: sess-123" \
  -H "Cookie: session=abc"

# Unsafe method with valid token - proceeds
curl -X POST http://localhost:8080/api/test \
  -H "X-CSRF-Token: <valid-jwt-token>" \
  -H "idcs_remote_user: testuser" \
  -H "idcs_session_id: sess-123" \
  -H "User-Agent: curl/7.68.0" \
  -H "Cookie: session=abc"
```

## 🧪 Testing

### Run All Tests

```bash
mvn test
```

### Run Specific Test Class

```bash
mvn test -Dtest=CsrfValidationGlobalFilterTest
```

### Test Coverage

The project includes comprehensive tests:

- **Unit Tests**: `CsrfValidationGlobalFilterTest` (>90% coverage)
  - Safe method bypass
  - S2S call detection
  - Valid token validation
  - Expired token rejection
  - Claims mismatch scenarios
  - Missing header scenarios

- **Integration Tests**: `CsrfProtectionIntegrationTest`
  - Full request flow with WebTestClient
  - Real JWT token generation/validation
  - All HTTP methods
  - Error response validation

### Generate Coverage Report

```bash
mvn jacoco:report
# Open target/site/jacoco/index.html
```

## 🏭 Production Deployment

### 1. Secure Key Management

**❌ DO NOT:**
- Commit private keys to version control
- Store keys in application.yml
- Use sample keys in production

**✅ DO:**
- Store public key in secure vault (HashiCorp Vault, AWS Secrets Manager, etc.)
- Load key from environment variable or secure file system
- Rotate keys periodically
- Update Confluence: "Secure Store Inventory" with CSRF public key location

### 2. Environment Variables

```bash
export CSRF_PUBLIC_KEY_LOCATION=file:/secure/vault/csrf-public-key.pem
export CSRF_ENABLED=true
export CSRF_ISSUER=hdp-csrf-issuer-prod
```



### 3. Monitoring & Logging

Enable structured logging for CSRF events:

```yaml
logging:
  level:
    com.oracle.hospitality.hdp.gateway.filter.CsrfValidationGlobalFilter: INFO
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

Monitor these metrics:
- CSRF validation failures (rate)
- Token expiration events
- S2S bypass rate
- Average validation time

### 4. Rate Limiting (Recommended)

Consider adding rate limiting for CSRF failures to prevent brute force:

```yaml
spring:
  cloud:
    gateway:
      routes:
        - id: api-route
          filters:
            - name: RequestRateLimiter
              args:
                redis-rate-limiter.replenishRate: 10
                redis-rate-limiter.burstCapacity: 20
```

## 🔧 Troubleshooting

### Issue: "Public key resource not found"

**Cause**: Public key file not found at configured location

**Solution**:
1. Verify file exists: `ls -la src/main/resources/keys/csrf-public-key.pem`
2. Check configuration: `csrf.public-key-location`
3. Ensure file is included in JAR: `jar tf target/*.jar | grep csrf-public-key.pem`

### Issue: "Invalid public key format"

**Cause**: Public key is not in correct PEM format

**Solution**:
1. Verify PEM format:
   ```
   -----BEGIN PUBLIC KEY-----
   <base64-encoded-key>
   -----END PUBLIC KEY-----
   ```
2. Re-generate key pair using OpenSSL
3. Ensure no extra whitespace or characters

### Issue: "Token validation failed: Invalid token signature"

**Cause**: Token signed with different private key

**Solution**:
1. Verify public/private key pair match
2. Check issuer claim matches configuration
3. Ensure token-issuing service uses correct private key

### Issue: "Username mismatch"

**Cause**: Token `sub` claim doesn't match `idcs_remote_user` header

**Solution**:
1. Verify token was issued for correct user
2. Check `idcs_remote_user` header is set correctly
3. Ensure no case sensitivity issues

### Issue: "User-Agent mismatch"

**Cause**: User-Agent changed between token issuance and validation

**Solution**:
1. Ensure User-Agent is consistent
2. Check for browser extensions modifying User-Agent
3. Verify hash algorithm matches (SHA-256)

### Issue: CSRF validation on S2S calls

**Cause**: S2S detection logic not recognizing the call

**Solution**:
1. Ensure no `Cookie` header is sent
2. Include `Authorization` header for authenticated S2S
3. Customize `isS2SCallBasedOnAuth()` if needed

## 📚 Additional Resources

- [Spring Cloud Gateway Documentation](https://spring.io/projects/spring-cloud-gateway)
- [JJWT Library](https://github.com/jwtk/jjwt)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

## 📄 License

Copyright © 2026 Oracle Hospitality. All rights reserved.

## 🤝 Contributing

For internal Oracle Hospitality development only. Contact the HDP team for contribution guidelines.

---

**Version**: 1.0.0  
**Last Updated**: 2026-02-06  
**Maintained By**: Oracle Hospitality HDP Team
