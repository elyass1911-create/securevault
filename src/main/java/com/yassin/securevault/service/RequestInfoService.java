package com.yassin.securevault.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class RequestInfoService {

    private final boolean trustForwardHeaders;

    public RequestInfoService(@Value("${app.security.trust-forward-headers:false}") boolean trustForwardHeaders) {
        this.trustForwardHeaders = trustForwardHeaders;
    }

    public String clientIp(HttpServletRequest request) {
        if (trustForwardHeaders) {
            String xff = request.getHeader("X-Forwarded-For");
            if (xff != null && !xff.isBlank()) {
                return xff.split(",")[0].trim();
            }

            String xRealIp = request.getHeader("X-Real-IP");
            if (xRealIp != null && !xRealIp.isBlank()) {
                return xRealIp.trim();
            }
        }

        return request.getRemoteAddr();
    }

    public String userAgent(HttpServletRequest request) {
        String value = request.getHeader("User-Agent");
        if (value == null || value.isBlank()) {
            return null;
        }
        if (value.length() > 500) {
            return value.substring(0, 500);
        }
        return value;
    }
}
