package com.yassin.securevault.controller;

import com.yassin.securevault.dto.AuthResponse;
import com.yassin.securevault.dto.LoginRequest;
import com.yassin.securevault.dto.RegisterRequest;
import com.yassin.securevault.dto.RegisterResponse;
import com.yassin.securevault.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest req,
                                                     HttpServletRequest request) {
        return ResponseEntity.ok(authService.register(req, request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest req,
                                              HttpServletRequest request) {
        return ResponseEntity.ok(authService.login(req, request));
    }
}
