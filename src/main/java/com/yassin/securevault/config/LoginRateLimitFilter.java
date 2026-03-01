package com.yassin.securevault.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equalsIgnoreCase(request.getMethod())
                && request.getRequestURI().equals("/auth/login"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String key = clientIp(request);

        Bucket bucket = buckets.computeIfAbsent(key, k -> newBucket());
        if (!bucket.tryConsume(1)) {
            response.setStatus(429);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);

            String body = """
                {"timestamp":"%s","status":429,"error":"Too Many Requests","message":"Too many login attempts. Please try again later.","path":"%s"}
                """.formatted(Instant.now().toString(), request.getRequestURI());

            response.getWriter().write(body);
            return;
        }

        chain.doFilter(request, response);
    }

    private Bucket newBucket() {
        // 5 Versuche pro Minute pro IP
        Bandwidth limit = Bandwidth.classic(5, Refill.greedy(5, Duration.ofMinutes(1)));
        return Bucket.builder().addLimit(limit).build();
    }

    private String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}