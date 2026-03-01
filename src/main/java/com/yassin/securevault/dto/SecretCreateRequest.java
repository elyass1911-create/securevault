package com.yassin.securevault.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SecretCreateRequest(
        @NotBlank @Size(max = 120) String title,
        @NotBlank @Size(max = 10_000) String data
) {}
