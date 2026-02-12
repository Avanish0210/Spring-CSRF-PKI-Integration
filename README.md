# services-router-gateway

Standard Spring Cloud Gateway with **Stateless CSRF Protection** for Oracle Hospitality HDP.

## Features
- **Stateless**: Uses RS256 signed JWT tokens (no session storage).
- **Secure**: Cross-verifies `idcs_remote_user`, `idcs_session_id`, and `User-Agent`.
- **Smart**: Automatically bypasses CSRF for Safe Methods (GET/OPTIONS/HEAD) and Service-to-Service (S2S) calls.
- **Production Ready**: Structured JSON error responses, Java 25, Spring Boot 3.4.

## Configuration
| Property | Description | Default |
|----------|-------------|---------|
| `csrf.enabled` | Global toggle | `true` |
| `csrf.header-name` | Header for CSRF token | `X-CSRF-Token` |
| `csrf.public-key-location` | RSA Public Key path | `classpath:keys/csrf-public-key.pem` |
| `csrf.max-age-seconds` | Token TTL | `600` |
| `csrf.issuer` | Valid token issuer | `hdp-csrf-issuer` |

## Token Format
The gateway expects a JWT signed with the corresponding private key containing:
```json
{
  "iss": "hdp-csrf-issuer",
  "sub": "<username>",
  "session_id": "<session_id>",
  "user_agent_hash": "<SHA-256 hash of User-Agent>",
  "iat": <timestamp>,
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

## How to Run
```bash
mvn spring-boot:run
```
