package com.yassin.securevault.dto;

import java.time.Instant;

public record SecretMetaResponse(
        Long id,
        String title,
        Instant createdAt,
        Instant updatedAt
) {}
