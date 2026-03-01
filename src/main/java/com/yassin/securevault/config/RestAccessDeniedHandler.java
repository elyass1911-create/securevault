package com.yassin.securevault.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RestAccessDeniedHandler implements AccessDeniedHandler {

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException
    ) {
        try {
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
}