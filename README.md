# SecureVault – Encrypted Secret Management Backend

**SecureVault** is a security-focused Spring Boot backend application for encrypted secret storage.  
The project demonstrates secure backend architecture using JWT authentication, AES-256 encryption, audit logging, and environment-based configuration.

---

## Overview

This application allows authenticated users to securely store, manage, and retrieve encrypted secrets.  
All secrets are encrypted before persistence and decrypted only upon explicit request.

The system is designed to follow backend security best practices and clean architectural principles.

---

## Technology Stack

- Java 21
- Spring Boot
- Spring Security (JWT)
- JPA / Hibernate
- PostgreSQL
- Docker
- Maven

---

## Security Design

### Authentication

- Stateless JWT-based authentication
- Tokens are signed using a configurable secret
- Custom security filter for request validation
- Login endpoint rate limiting

### Encryption

- AES-256-GCM encryption
- Secrets stored as IV + ciphertext
- Decryption only performed on dedicated reveal endpoint
- No plaintext secrets stored in the database

### Data Isolation

- Secrets are strictly isolated per authenticated user
- Ownership validated via user identity in JWT
- No cross-user data access

### Configuration

- No hardcoded secrets
- All sensitive values provided via environment variables
- `.env.example` template provided
- `.env` excluded from version control

---


## API Endpoints

### Authentication

POST /auth/register  
POST /auth/login

---

### Secrets

GET    /api/secrets  
POST   /api/secrets  
GET    /api/secrets/{id}  
GET    /api/secrets/{id}/reveal  
PUT    /api/secrets/{id}  
DELETE /api/secrets/{id}

The standard list endpoint returns metadata only.  
Secret content is revealed exclusively via the `/reveal` endpoint.

---

## Running the Application

### Start PostgreSQL via Docker

docker-compose up -d

---

### Start Spring Boot application

./mvnw spring-boot:run

---

## Environment Variables

Create a `.env` file based on `.env.example`:

JWT_SECRET=your-strong-secret  
AES_KEY=base64-32-byte-key  
DB_PASSWORD=password

No secrets are stored in the repository.

---

## Architectural Goals

This project demonstrates:

- Encryption at rest
- Stateless authentication
- Secure API design
- Proper secret handling
- Clean separation of concerns
- Environment-based configuration
- Basic audit logging

---

## Author

Yassin El Founti  
Backend Developer
