package com.yassin.securevault.config;

import com.yassin.securevault.entity.SecurityEventType;
import com.yassin.securevault.entity.SecurityOutcome;
import com.yassin.securevault.service.SecurityEventService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final SecurityEventService securityEventService;

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) {
        try {
            securityEventService.emit(
                    SecurityEventType.AUTH_UNAUTHORIZED,
                    SecurityOutcome.FAIL,
                    currentActor(),
                    request,
                    "HTTP",
                    null,
                    Map.of("path", request.getRequestURI())
            );

            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String body = """
                {
                  "timestamp": "%s",
                  "status": 401,
                  "error": "Unauthorized",
                  "message": "Missing or invalid token",
                  "path": "%s"
                }
                """.formatted(Instant.now().toString(), request.getRequestURI());

            response.getWriter().write(body);
        } catch (Exception ignored) {
        }
    }

    private String currentActor() {
        Object principal = SecurityContextHolder.getContext().getAuthentication() != null
                ? SecurityContextHolder.getContext().getAuthentication().getPrincipal()
                : null;
        if (principal == null) {
            return null;
        }
        return String.valueOf(principal);
    }
}
