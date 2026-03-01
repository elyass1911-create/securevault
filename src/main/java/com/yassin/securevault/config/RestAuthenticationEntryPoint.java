package com.yassin.securevault.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) {
        try {
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
}