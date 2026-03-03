[![CI](https://github.com/elyass1911-create/securevault/actions/workflows/ci.yml/badge.svg)](https://github.com/elyass1911-create/securevault/actions/workflows/ci.yml)

# SecureVault v2 - Encrypted Secret Management API with AI Security Monitoring

SecureVault is a Spring Boot backend that demonstrates practical API security patterns: JWT authentication, per-user authorization, encrypted data storage, audit logging, and security-focused integration testing.

This project was built as a portfolio project to show backend and application security fundamentals in a real, runnable codebase.

Core (v1): secure encrypted secret vault with JWT auth, AES-256-GCM encryption, and strict ownership-based access control.
Adds (v2): explainable AI security monitoring with structured events, risk scoring, anomaly detection, and admin monitoring endpoints.

## Security Monitoring Edition (v2)

This version extends the original vault with a local, explainable monitoring pipeline:

- Structured `security_events` for auth/access/secret actions
- Explainable risk scoring (`security_risk_assessments`) for USER/IP subjects
- Statistical anomaly detection with rolling baseline + z-score (`security_incidents`)
- Admin-only monitoring API (`/api/security/*`)
- Integration tests that simulate cross-user access attempts and brute-force behavior

Note: "AI" in this project means explainable local security analytics (rules + statistical anomaly detection), not external LLM calls or paid AI services.

## Key Features

- User registration and login with JWT-based stateless authentication
- Secret CRUD API with strict per-user ownership checks
- Dedicated reveal endpoint for controlled plaintext access
- AES-256-GCM encryption for secrets at rest (IV + ciphertext storage)
- Login rate limiting to reduce brute-force attack risk
- Audit logging for auth and secret-related events
- Centralized API error handling with consistent error responses
- Dockerized local database setup (PostgreSQL)

## Security Highlights

- Authentication: JWT tokens validated by a custom security filter
- Authorization: owner-based access enforced at data layer (`findByIdAndOwnerEmail`)
- IDOR/BOLA protection: cross-user reveal attempts are blocked (expected `404` in current implementation)
- Secret management: no plaintext secret values are persisted in the database
- Configuration hygiene: sensitive values loaded from environment variables, not hardcoded
- Proxy/IP hygiene: forwarded headers are only trusted when explicitly enabled
- Repository hygiene: `.env` is ignored, `.env.example` provided as template
- CI protection: GitHub Actions secret scanning via Gitleaks

## Tech Stack

- Java 21
- Spring Boot 4
- Spring Security
- Spring Data JPA / Hibernate
- PostgreSQL
- H2 (test profile)
- JUnit 5 integration tests
- Maven
- Docker / Docker Compose

## API Overview

Authentication:

- `POST /auth/register`
- `POST /auth/login`

Secrets:

- `GET /api/secrets`
- `POST /api/secrets`
- `GET /api/secrets/{id}`
- `GET /api/secrets/{id}/reveal`
- `PUT /api/secrets/{id}`
- `DELETE /api/secrets/{id}`

Note: `GET /api/secrets` returns metadata only. Plaintext is only returned by `GET /api/secrets/{id}/reveal` for the owning user.

Security Monitoring (ADMIN only):

- `GET /api/security/overview`
- `GET /api/security/incidents?page=&size=`
- `GET /api/security/anomalies?page=&size=`
- `GET /api/security/risk/top?window=24h&limit=10`

Access requirement: all `/api/security/*` endpoints require `ROLE_ADMIN`.

## Quick Demo (Copy/Paste)

Start app and database, then run this minimal flow:

```bash
# 1) Register
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"demo.user@test.com","password":"Password123!"}'

# 2) Login (copy token from response JSON)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo.user@test.com","password":"Password123!"}'

# 3) Create secret (replace <TOKEN>)
curl -X POST http://localhost:8080/api/secrets \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"demo","data":"my first secret"}'

# 4) List metadata only
curl -X GET http://localhost:8080/api/secrets \
  -H "Authorization: Bearer <TOKEN>"

# 5) Reveal plaintext (replace <ID>)
curl -X GET http://localhost:8080/api/secrets/<ID>/reveal \
  -H "Authorization: Bearer <TOKEN>"
```

Tip: `requests.http` in this repo contains the same flow for IDE HTTP clients.

## API Documentation

Interactive API documentation can be enabled explicitly for local/dev usage:

- `http://localhost:8080/swagger-ui.html`

Raw OpenAPI specification:

- `http://localhost:8080/v3/api-docs`

By default (`PUBLIC_DOCS_ENABLED=false`), Swagger/OpenAPI endpoints are disabled and not publicly exposed.

## Architecture

```mermaid
flowchart LR
    Client[Client / Swagger / Tests] -->|HTTP| Sec[Spring Security Filter Chain]
    Sec -->|JWT validated| Ctrl[Controllers]
    Ctrl --> Svc[Service Layer]

    Svc --> Enc[EncryptionService<br/>AES-256-GCM]
    Svc --> Repo[Vault Repositories]

    Svc --> EventSvc[SecurityEventService]
    EventSvc --> EventRepo[(security_events)]

    MonitorCtrl[Admin Monitoring API] --> MonitorSvc[SecurityMonitoringService]
    MonitorSvc --> RiskSvc[RiskScoringService]
    MonitorSvc --> AnomalySvc[AnomalyDetectionService]
    RiskSvc --> RiskRepo[(security_risk_assessments)]
    AnomalySvc --> IncidentRepo[(security_incidents)]
    RiskSvc --> EventRepo
    AnomalySvc --> EventRepo

    Repo --> DB[(PostgreSQL / H2 test profile)]
```

## Risk Scoring Rules (Explainable)

| Rule | Points | Rationale |
|------|--------|-----------|
| `AUTH_LOGIN_FAIL` | +25 each | Repeated failed logins indicate credential attacks |
| `AUTH_RATE_LIMIT_TRIGGERED` | +60 each | Strong signal of brute-force behavior |
| `AUTH_FORBIDDEN` or `SUSPICIOUS_ENUMERATION` | +80 each | High-risk unauthorized access pattern |
| High reveal activity (`SECRET_REVEALED` > 5/window) | +15 | Abnormally high secret access volume |

Scores are computed per subject (`USER` and `IP`) over a configurable window (default: `24h`) and include reason codes.

## Example Responses

`GET /api/security/overview`

```json
{
  "loginFailsLast24h": 8,
  "rateLimitsLast24h": 1,
  "forbiddenLast24h": 1,
  "revealsLast24h": 3,
  "topRiskySubjects": [
    {
      "subjectType": "IP",
      "subjectValue": "203.0.113.77",
      "score": 260,
      "topReasons": ["LOGIN_FAIL_x8", "RATE_LIMIT_x1"]
    }
  ],
  "openIncidents": [
    {
      "incidentId": 12,
      "category": "RULE",
      "severity": "HIGH",
      "subjectType": "USER",
      "subjectValue": "sec-b+123@test.com",
      "reasons": ["CROSS_USER_SECRET_ACCESS_ATTEMPT"]
    }
  ]
}
```

`GET /api/security/incidents?page=0&size=2`

```json
{
  "content": [
    {
      "incidentId": 12,
      "category": "ANOMALY",
      "severity": "MED",
      "subjectType": "IP",
      "subjectValue": "203.0.113.77",
      "reasons": ["ANOMALY_FAILED_LOGINS_PER_HOUR", "Z_SCORE_10.00"]
    }
  ]
}
```

## Running Locally

1. Create a local `.env` file from `.env.example`.
2. Start PostgreSQL:

```bash
docker-compose up -d
```

3. Start the app:

```bash
./mvnw spring-boot:run
```

On Windows PowerShell:

```powershell
.\mvnw.cmd spring-boot:run
```

## Environment Variables

Example values (see `.env.example`):

```env
JWT_SECRET=your-strong-secret
AES_KEY=base64-32-byte-key
DB_PASSWORD=change-me
TRUST_FORWARD_HEADERS=false
PUBLIC_DOCS_ENABLED=false
```

Notes:

- `TRUST_FORWARD_HEADERS=true` only when running behind a trusted reverse proxy that sanitizes `X-Forwarded-For` / `X-Real-IP`.
- `PUBLIC_DOCS_ENABLED=true` enables Swagger/OpenAPI endpoints (recommended only for local/dev).

## Security Design Notes

- Password storage: user passwords are hashed with BCrypt (`BCryptPasswordEncoder`).
- JWT claims: `sub` = user email, custom `role` claim.
- JWT expiry: configurable with `security.jwt.expiration-minutes` (default `60`).
- Refresh tokens: currently not implemented (access-token only).
- Key rotation: JWT/AES key rotation is not automated yet (planned future work).

## Mini Threat Model

- Database leak: mitigated by AES-256-GCM encryption-at-rest for secret payloads.
- IDOR/BOLA: mitigated by owner-scoped repository access and cross-user checks.
- Brute-force login attempts: mitigated by login rate limiting and security event monitoring.
- Stolen token/replay window: reduced by JWT expiration; no refresh-token flow yet.
- Insider/misuse visibility: improved by audit and security-event trails.

## Testing

Run all tests:

```bash
./mvnw clean test
```

Windows PowerShell:

```powershell
.\mvnw.cmd clean test
```

Security integration test included:

- `SecretAuthorizationITTest`
  - User A can reveal own secret (`200`)
  - User B cannot reveal User A secret (`403` or `404`, currently `404`)
- `SecurityMonitoringITTest`
  - Cross-user reveal attempt increases risk and creates incident
  - Brute-force simulation triggers rate-limit and monitoring signals
  - Normal behavior does not create high-severity anomaly for that user

## CI

GitHub Actions runs CI on every push to `main` and on every pull request.

- Build and test pipeline: `./mvnw -B clean test` (Java 21)
- Security pipeline: Gitleaks secret scanning

## Why This Project Is Relevant

This repository demonstrates that I can:

- design secure backend APIs beyond basic CRUD
- implement and verify authorization boundaries (including IDOR/BOLA prevention)
- apply encryption-at-rest and environment-based secret management
- build explainable security analytics (event pipeline, risk scoring, anomaly detection)
- write integration tests for realistic attack scenarios (cross-user access, brute-force)
- deliver production-plausible engineering practices (Dockerized setup, Swagger/OpenAPI, CI + secret scanning)

## Author

Yassin El Founti

B.Sc. IT Student

Backend & Application Security Enthusiast
