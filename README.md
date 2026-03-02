# SecureVault - Security-Focused Secret Management API

SecureVault is a Spring Boot backend that demonstrates practical API security patterns: JWT authentication, per-user authorization, encrypted data storage, audit logging, and security-focused integration testing.

This project was built as a portfolio project to show backend and application security fundamentals in a real, runnable codebase.

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
```

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

## Why This Project Is Relevant

This repository demonstrates that I can:

- design secure backend APIs beyond basic CRUD
- implement and verify authorization boundaries
- apply encryption and environment-based secret management
- write integration tests for real attack scenarios (IDOR/BOLA)
- package and run services in a reproducible local environment

## Author

Yassin El Founti  
Backend Developer (Student, B.Sc. IT - 4th Semester)
