package com.yassin.securevault.dto;

import java.time.Instant;

public record SecretResponse(
        Long id,
        String data,
        Instant createdAt,
        Instant updatedAt
) {}
