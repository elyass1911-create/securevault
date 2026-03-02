package com.yassin.securevault.config;

import com.yassin.securevault.entity.SecurityEventType;
import com.yassin.securevault.entity.SecurityOutcome;
import com.yassin.securevault.service.SecurityEventService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityEventService securityEventService;

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) {
        try {
            securityEventService.emit(
                    SecurityEventType.AUTH_FORBIDDEN,
                    SecurityOutcome.FAIL,
                    currentActor(),
                    request,
                    "HTTP",
                    null,
                    Map.of("path", request.getRequestURI())
            );
            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String body = """
                {
                  "timestamp": "%s",
                  "status": 403,
                  "error": "Forbidden",
                  "message": "Not enough permissions",
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
