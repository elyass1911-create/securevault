package com.yassin.securevault.service;

import com.yassin.securevault.entity.SecurityEvent;
import com.yassin.securevault.entity.SecurityEventType;
import com.yassin.securevault.entity.SecurityOutcome;
import com.yassin.securevault.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class SecurityEventService {

    private static final Set<String> BLOCKED_METADATA_KEYS = Set.of("secret", "plaintext", "data", "ciphertext", "iv");

    private final SecurityEventRepository securityEventRepository;
    private final RequestInfoService requestInfoService;

    public void emit(
            SecurityEventType type,
            SecurityOutcome outcome,
            String actorEmail,
            HttpServletRequest request,
            String resourceType,
            String resourceId,
            Map<String, ?> metadata
    ) {
        SecurityEvent event = SecurityEvent.builder()
                .eventType(type)
                .outcome(outcome)
                .actorEmail(normalize(actorEmail))
                .ipAddress(request != null ? requestInfoService.clientIp(request) : null)
                .userAgent(request != null ? requestInfoService.userAgent(request) : null)
                .resourceType(resourceType)
                .resourceId(resourceId)
                .metadata(toSafeJson(metadata))
                .build();

        securityEventRepository.save(event);
    }

    private String toSafeJson(Map<String, ?> metadata) {
        if (metadata == null || metadata.isEmpty()) {
            return null;
        }

        Map<String, Object> safe = new LinkedHashMap<>();
        for (Map.Entry<String, ?> entry : metadata.entrySet()) {
            String key = entry.getKey();
            if (key == null) {
                continue;
            }
            String lower = key.toLowerCase();
            if (BLOCKED_METADATA_KEYS.contains(lower)) {
                continue;
            }
            Object value = entry.getValue();
            if (value != null) {
                safe.put(key, truncate(String.valueOf(value), 300));
            }
        }

        if (safe.isEmpty()) {
            return null;
        }

        String raw = safe.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((a, b) -> a + ";" + b)
                .orElse(null);

        return truncate(raw, 1900);
    }

    private String truncate(String input, int maxLen) {
        if (input == null || input.length() <= maxLen) {
            return input;
        }
        return input.substring(0, maxLen);
    }

    private String normalize(String actorEmail) {
        if (actorEmail == null || actorEmail.isBlank()) {
            return null;
        }
        return actorEmail.trim().toLowerCase();
    }
}
