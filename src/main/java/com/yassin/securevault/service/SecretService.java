package com.yassin.securevault.service;

import com.yassin.securevault.dto.SecretCreateRequest;
import com.yassin.securevault.dto.SecretMetaResponse;
import com.yassin.securevault.dto.SecretRevealResponse;
import com.yassin.securevault.dto.SecretUpdateRequest;
import com.yassin.securevault.entity.AuditEventType;
import com.yassin.securevault.entity.Secret;
import com.yassin.securevault.entity.SecurityEventType;
import com.yassin.securevault.entity.SecurityOutcome;
import com.yassin.securevault.entity.SubjectType;
import com.yassin.securevault.exception.SecretNotFoundException;
import com.yassin.securevault.repository.SecretRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class SecretService {

    private final SecretRepository secretRepository;
    private final EncryptionService encryptionService;

    private final AuditService auditService;
    private final RequestInfoService requestInfoService;
    private final SecurityEventService securityEventService;
    private final AnomalyDetectionService anomalyDetectionService;

    public SecretMetaResponse create(String ownerEmail, SecretCreateRequest req, HttpServletRequest request) {
        var enc = encryptionService.encrypt(req.data().getBytes(StandardCharsets.UTF_8));

        Secret secret = Secret.builder()
                .ownerEmail(ownerEmail)
                .title(req.title())
                .iv(enc.iv())
                .ciphertext(enc.ciphertext())
                .build();

        Secret saved = secretRepository.save(secret);

        auditService.log(AuditEventType.SECRET_CREATE, ownerEmail,
                requestInfoService.clientIp(request),
                "SECRET", saved.getId().toString(),
                "created");
        securityEventService.emit(
                SecurityEventType.SECRET_CREATED,
                SecurityOutcome.SUCCESS,
                ownerEmail,
                request,
                "SECRET",
                saved.getId().toString(),
                Map.of("operation", "create")
        );

        return toMeta(saved);
    }

    public List<SecretMetaResponse> list(String ownerEmail, HttpServletRequest request) {
        return secretRepository.findAllByOwnerEmail(ownerEmail).stream()
                .map(this::toMeta)
                .toList();
    }

    public SecretMetaResponse get(String ownerEmail, Long id, HttpServletRequest request) {
        Secret secret = ownedSecretOrThrow(ownerEmail, id, request, "get");

        auditService.log(AuditEventType.SECRET_READ, ownerEmail,
                requestInfoService.clientIp(request),
                "SECRET", secret.getId().toString(),
                "meta-read");

        return toMeta(secret);
    }

    public SecretRevealResponse reveal(String ownerEmail, Long id, HttpServletRequest request) {
        Secret secret = ownedSecretOrThrow(ownerEmail, id, request, "reveal");

        auditService.log(AuditEventType.SECRET_READ, ownerEmail,
                requestInfoService.clientIp(request),
                "SECRET", secret.getId().toString(),
                "reveal");
        securityEventService.emit(
                SecurityEventType.SECRET_REVEALED,
                SecurityOutcome.SUCCESS,
                ownerEmail,
                request,
                "SECRET",
                secret.getId().toString(),
                Map.of("operation", "reveal")
        );

        return toReveal(secret);
    }

    public SecretMetaResponse update(String ownerEmail, Long id, SecretUpdateRequest req, HttpServletRequest request) {
        Secret secret = ownedSecretOrThrow(ownerEmail, id, request, "update");

        secret.setTitle(req.title());

        var enc = encryptionService.encrypt(req.data().getBytes(StandardCharsets.UTF_8));
        secret.setIv(enc.iv());
        secret.setCiphertext(enc.ciphertext());

        Secret saved = secretRepository.save(secret);

        auditService.log(AuditEventType.SECRET_UPDATE, ownerEmail,
                requestInfoService.clientIp(request),
                "SECRET", saved.getId().toString(),
                "updated");
        securityEventService.emit(
                SecurityEventType.SECRET_UPDATED,
                SecurityOutcome.SUCCESS,
                ownerEmail,
                request,
                "SECRET",
                saved.getId().toString(),
                Map.of("operation", "update")
        );

        return toMeta(saved);
    }

    public void delete(String ownerEmail, Long id, HttpServletRequest request) {
        Secret secret = ownedSecretOrThrow(ownerEmail, id, request, "delete");

        secretRepository.delete(secret);

        auditService.log(AuditEventType.SECRET_DELETE, ownerEmail,
                requestInfoService.clientIp(request),
                "SECRET", id.toString(),
                "deleted");
        securityEventService.emit(
                SecurityEventType.SECRET_DELETED,
                SecurityOutcome.SUCCESS,
                ownerEmail,
                request,
                "SECRET",
                id.toString(),
                Map.of("operation", "delete")
        );
    }

    private SecretMetaResponse toMeta(Secret secret) {
        return new SecretMetaResponse(secret.getId(), secret.getTitle(), secret.getCreatedAt(), secret.getUpdatedAt());
    }

    private SecretRevealResponse toReveal(Secret secret) {
        byte[] plaintext = encryptionService.decrypt(secret.getIv(), secret.getCiphertext());
        String data = new String(plaintext, StandardCharsets.UTF_8);
        return new SecretRevealResponse(secret.getId(), secret.getTitle(), data, secret.getCreatedAt(), secret.getUpdatedAt());
    }

    private Secret ownedSecretOrThrow(String ownerEmail, Long id, HttpServletRequest request, String operation) {
        return secretRepository.findByIdAndOwnerEmail(id, ownerEmail)
                .orElseGet(() -> {
                    if (secretRepository.existsById(id)) {
                        securityEventService.emit(
                                SecurityEventType.AUTH_FORBIDDEN,
                                SecurityOutcome.FAIL,
                                ownerEmail,
                                request,
                                "SECRET",
                                String.valueOf(id),
                                Map.of("operation", operation, "status", "cross_user_denied")
                        );
                        securityEventService.emit(
                                SecurityEventType.SUSPICIOUS_ENUMERATION,
                                SecurityOutcome.FAIL,
                                ownerEmail,
                                request,
                                "SECRET",
                                String.valueOf(id),
                                Map.of("operation", operation)
                        );
                        anomalyDetectionService.createRuleIncidentIfNeeded(
                                SubjectType.USER,
                                ownerEmail,
                                "CROSS_USER_SECRET_ACCESS_ATTEMPT",
                                Map.of("secretId", id, "operation", operation)
                        );
                    }
                    throw new SecretNotFoundException(id);
                });
    }
}
