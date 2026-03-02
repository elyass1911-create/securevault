package com.yassin.securevault.service;

import com.yassin.securevault.dto.SecurityIncidentResponse;
import com.yassin.securevault.dto.SecurityOverviewResponse;
import com.yassin.securevault.dto.TopRiskSubjectResponse;
import com.yassin.securevault.entity.*;
import com.yassin.securevault.repository.SecurityEventRepository;
import com.yassin.securevault.repository.SecurityIncidentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class SecurityMonitoringService {

    private final SecurityEventRepository eventRepository;
    private final SecurityIncidentRepository incidentRepository;
    private final RiskScoringService riskScoringService;
    private final AnomalyDetectionService anomalyDetectionService;

    @Transactional
    public SecurityOverviewResponse overview() {
        Instant since = Instant.now().minus(Duration.ofHours(24));

        anomalyDetectionService.detectAndPersist(Instant.now());
        List<TopRiskSubjectResponse> topRisks = topRisks(Duration.ofHours(24), 5);
        List<SecurityIncidentResponse> open = mapIncidents(
                incidentRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(0, 10)).getContent()
        );

        return new SecurityOverviewResponse(
                eventRepository.countByEventTypeAndOccurredAtAfter(SecurityEventType.AUTH_LOGIN_FAIL, since),
                eventRepository.countByEventTypeAndOccurredAtAfter(SecurityEventType.AUTH_RATE_LIMIT_TRIGGERED, since),
                eventRepository.countByEventTypeAndOccurredAtAfter(SecurityEventType.AUTH_FORBIDDEN, since),
                eventRepository.countByEventTypeAndOccurredAtAfter(SecurityEventType.SECRET_REVEALED, since),
                topRisks,
                open
        );
    }

    @Transactional
    public List<TopRiskSubjectResponse> topRisks(Duration window, int limit) {
        return riskScoringService.computeAndPersistTopRisks(window, limit).stream()
                .map(assessment -> new TopRiskSubjectResponse(
                        assessment.getSubjectType(),
                        assessment.getSubjectValue(),
                        assessment.getScore(),
                        RiskScoringService.parseReasons(assessment.getTopReasons()),
                        assessment.getComputedAt(),
                        assessment.getWindowStart(),
                        assessment.getWindowEnd()
                ))
                .toList();
    }

    @Transactional
    public Page<SecurityIncidentResponse> incidents(int page, int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<SecurityIncident> data = incidentRepository.findAllByOrderByCreatedAtDesc(pageable);
        return data.map(this::mapIncident);
    }

    @Transactional
    public Page<SecurityIncidentResponse> anomalies(int page, int size) {
        anomalyDetectionService.detectAndPersist(Instant.now());
        Pageable pageable = PageRequest.of(page, size);
        Page<SecurityIncident> data = incidentRepository.findByCategoryOrderByCreatedAtDesc(IncidentCategory.ANOMALY, pageable);
        return data.map(this::mapIncident);
    }

    private List<SecurityIncidentResponse> mapIncidents(List<SecurityIncident> incidents) {
        return incidents.stream().map(this::mapIncident).toList();
    }

    private SecurityIncidentResponse mapIncident(SecurityIncident incident) {
        return new SecurityIncidentResponse(
                incident.getId(),
                incident.getCategory(),
                incident.getSeverity(),
                incident.getSubjectType(),
                incident.getSubjectValue(),
                incident.getWindowStart(),
                incident.getWindowEnd(),
                RiskScoringService.parseReasons(incident.getReasons()),
                incident.getMetricsSnapshot(),
                incident.getCreatedAt()
        );
    }
}
