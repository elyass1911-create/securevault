package com.yassin.securevault.controller;

import com.yassin.securevault.dto.SecretCreateRequest;
import com.yassin.securevault.dto.SecretMetaResponse;
import com.yassin.securevault.dto.SecretRevealResponse;
import com.yassin.securevault.dto.SecretUpdateRequest;
import com.yassin.securevault.service.SecretService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/secrets")
@RequiredArgsConstructor
public class SecretController {

    private final SecretService secretService;

    @PostMapping
    public SecretMetaResponse create(Authentication auth, @Valid @RequestBody SecretCreateRequest req, HttpServletRequest request) {
        return secretService.create(auth.getName(), req, request);
    }

    @GetMapping
    public List<SecretMetaResponse> list(Authentication auth, HttpServletRequest request) {
        return secretService.list(auth.getName(), request);
    }

    @GetMapping("/{id}")
    public SecretMetaResponse get(Authentication auth, @PathVariable Long id, HttpServletRequest request) {
        return secretService.get(auth.getName(), id, request);
    }

    @GetMapping("/{id}/reveal")
    public SecretRevealResponse reveal(Authentication auth, @PathVariable Long id, HttpServletRequest request) {
        return secretService.reveal(auth.getName(), id, request);
    }

    @PutMapping("/{id}")
    public SecretMetaResponse update(Authentication auth, @PathVariable Long id, @Valid @RequestBody SecretUpdateRequest req, HttpServletRequest request) {
        return secretService.update(auth.getName(), id, req, request);
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(Authentication auth, @PathVariable Long id, HttpServletRequest request) {
        secretService.delete(auth.getName(), id, request);
    }
}
