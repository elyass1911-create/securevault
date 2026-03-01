package com.yassin.securevault.service;

import com.yassin.securevault.dto.AuthResponse;
import com.yassin.securevault.dto.LoginRequest;
import com.yassin.securevault.dto.RegisterRequest;
import com.yassin.securevault.dto.RegisterResponse;
import com.yassin.securevault.entity.AuditEventType;
import com.yassin.securevault.entity.Role;
import com.yassin.securevault.entity.User;
import com.yassin.securevault.exception.EmailAlreadyUsedException;
import com.yassin.securevault.exception.InvalidCredentialsException;
import com.yassin.securevault.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    private final AuditService auditService;
    private final RequestInfoService requestInfoService;

    public RegisterResponse register(RegisterRequest req, HttpServletRequest request) {
        String email = req.email().trim().toLowerCase();

        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyUsedException(email);
        }

        User user = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(req.password()))
                .role(Role.USER)
                .build();

        User saved = userRepository.save(user);

        auditService.log(
                AuditEventType.REGISTER_SUCCESS,
                saved.getEmail(),
                requestInfoService.clientIp(request),
                "AUTH",
                saved.getId().toString(),
                "User registered"
        );

        return new RegisterResponse(saved.getId(), saved.getEmail(), saved.getRole().name());
    }

    public AuthResponse login(LoginRequest req, HttpServletRequest request) {
        String email = req.email().trim().toLowerCase();
        String ip = requestInfoService.clientIp(request);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    auditService.log(AuditEventType.LOGIN_FAILED, email, ip, "AUTH", null, "Unknown email");
                    return new InvalidCredentialsException();
                });

        if (!passwordEncoder.matches(req.password(), user.getPasswordHash())) {
            auditService.log(AuditEventType.LOGIN_FAILED, email, ip, "AUTH", user.getId().toString(), "Wrong password");
            throw new InvalidCredentialsException();
        }

        auditService.log(
                AuditEventType.LOGIN_SUCCESS,
                user.getEmail(),
                ip,
                "AUTH",
                user.getId().toString(),
                "Login success"
        );

        String token = jwtService.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponse(token, "Bearer");
    }
}