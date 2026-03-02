package com.yassin.securevault.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class RequestInfoService {

    public String clientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
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
