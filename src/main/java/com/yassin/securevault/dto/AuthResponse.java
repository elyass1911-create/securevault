package com.yassin.securevault.dto;

public record AuthResponse(
        String accessToken,
        String tokenType
) {}
