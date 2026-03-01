package com.yassin.securevault.dto;

public record RegisterResponse(
        Long id,
        String email,
        String role
) {}
