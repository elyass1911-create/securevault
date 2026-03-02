package com.yassin.securevault.controller;

import com.yassin.securevault.dto.SecurityIncidentResponse;
import com.yassin.securevault.dto.SecurityOverviewResponse;
import com.yassin.securevault.dto.TopRiskSubjectResponse;
import com.yassin.securevault.service.SecurityMonitoringService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class SecurityMonitoringController {

    private final SecurityMonitoringService monitoringService;

    @GetMapping("/overview")
    public SecurityOverviewResponse overview() {
        return monitoringService.overview();
    }

    @GetMapping("/incidents")
    public Page<SecurityIncidentResponse> incidents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return monitoringService.incidents(page, size);
    }

    @GetMapping("/anomalies")
    public Page<SecurityIncidentResponse> anomalies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size
    ) {
        return monitoringService.anomalies(page, size);
    }

    @GetMapping("/risk/top")
    public List<TopRiskSubjectResponse> topRisk(
            @RequestParam(defaultValue = "24h") String window,
            @RequestParam(defaultValue = "10") int limit
    ) {
        return monitoringService.topRisks(parseWindow(window), limit);
    }

    private Duration parseWindow(String window) {
        if (window == null || window.isBlank()) {
            return Duration.ofHours(24);
        }
        String v = window.trim().toLowerCase();
        if (v.endsWith("h")) {
            return Duration.ofHours(Long.parseLong(v.substring(0, v.length() - 1)));
        }
        if (v.endsWith("d")) {
            return Duration.ofDays(Long.parseLong(v.substring(0, v.length() - 1)));
        }
        return Duration.ofHours(24);
    }
}
