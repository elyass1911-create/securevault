package com.yassin.securevault.dto;

import java.time.Instant;

public record SecretRevealResponse(
        Long id,
        String title,
        String data,
        Instant createdAt,
        Instant updatedAt
) {}
