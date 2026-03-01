package com.yassin.securevault.service;

import com.yassin.securevault.entity.AuditEventType;
import com.yassin.securevault.entity.AuditLog;
import com.yassin.securevault.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    public void log(AuditEventType type,
                    String actorEmail,
                    String ipAddress,
                    String resourceType,
                    String resourceId,
                    String details) {

        AuditLog entry = AuditLog.builder()
                .eventType(type)
                .actorEmail(actorEmail)
                .ipAddress(ipAddress)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .details(details)
                .build();

        auditLogRepository.save(entry);
    }
}
