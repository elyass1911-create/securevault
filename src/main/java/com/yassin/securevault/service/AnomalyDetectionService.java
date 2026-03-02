package com.yassin.securevault.service;

import com.yassin.securevault.entity.*;
import com.yassin.securevault.repository.SecurityEventRepository;
import com.yassin.securevault.repository.SecurityIncidentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AnomalyDetectionService {

    private static final double Z_SCORE_THRESHOLD = 3.0;

    private final SecurityEventRepository eventRepository;
    private final SecurityIncidentRepository incidentRepository;

    @Transactional
    public List<SecurityIncident> detectAndPersist(Instant now) {
        List<SecurityIncident> incidents = new ArrayList<>();
        incidents.addAll(detectFailedLoginAnomalies(now));
        incidents.addAll(detectRevealAnomalies(now));
        return incidents;
    }

    private List<SecurityIncident> detectFailedLoginAnomalies(Instant now) {
        Instant baselineStart = now.minus(7, ChronoUnit.HOURS);
        List<SecurityEvent> all = eventRepository.findByOccurredAtBetween(baselineStart, now);

        Map<String, List<SecurityEvent>> byIp = all.stream()
                .filter(e -> e.getEventType() == SecurityEventType.AUTH_LOGIN_FAIL)
                .filter(e -> e.getIpAddress() != null && !e.getIpAddress().isBlank())
                .collect(Collectors.groupingBy(SecurityEvent::getIpAddress));

        List<SecurityIncident> incidents = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : byIp.entrySet()) {
            String ip = entry.getKey();
            List<Integer> hourly = new ArrayList<>();
            for (int i = 6; i >= 1; i--) {
                Instant sliceStart = now.minus(i, ChronoUnit.HOURS);
                Instant sliceEnd = sliceStart.plus(1, ChronoUnit.HOURS);
                int count = (int) entry.getValue().stream()
                        .filter(e -> !e.getOccurredAt().isBefore(sliceStart) && e.getOccurredAt().isBefore(sliceEnd))
                        .count();
                hourly.add(count);
            }
            int current = hourly.get(hourly.size() - 1);
            List<Integer> baseline = hourly.subList(0, hourly.size() - 1);
            maybeCreateAnomaly(
                    incidents,
                    SubjectType.IP,
                    ip,
                    "ANOMALY_FAILED_LOGINS_PER_HOUR",
                    baseline,
                    current,
                    now.minus(1, ChronoUnit.HOURS),
                    now,
                    Map.of("failedLoginsCurrentHour", current)
            );
        }
        return incidents;
    }

    private List<SecurityIncident> detectRevealAnomalies(Instant now) {
        Instant baselineStart = now.minus(8, ChronoUnit.DAYS);
        List<SecurityEvent> all = eventRepository.findByOccurredAtBetween(baselineStart, now);

        Map<String, List<SecurityEvent>> byUser = all.stream()
                .filter(e -> e.getEventType() == SecurityEventType.SECRET_REVEALED)
                .filter(e -> e.getActorEmail() != null && !e.getActorEmail().isBlank())
                .collect(Collectors.groupingBy(SecurityEvent::getActorEmail));

        List<SecurityIncident> incidents = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : byUser.entrySet()) {
            String email = entry.getKey();
            List<Integer> daily = new ArrayList<>();
            for (int i = 7; i >= 1; i--) {
                Instant sliceStart = now.minus(i, ChronoUnit.DAYS);
                Instant sliceEnd = sliceStart.plus(1, ChronoUnit.DAYS);
                int count = (int) entry.getValue().stream()
                        .filter(e -> !e.getOccurredAt().isBefore(sliceStart) && e.getOccurredAt().isBefore(sliceEnd))
                        .count();
                daily.add(count);
            }
            int current = daily.get(daily.size() - 1);
            List<Integer> baseline = daily.subList(0, daily.size() - 1);
            maybeCreateAnomaly(
                    incidents,
                    SubjectType.USER,
                    email,
                    "ANOMALY_REVEALS_PER_DAY",
                    baseline,
                    current,
                    now.minus(1, ChronoUnit.DAYS),
                    now,
                    Map.of("revealsCurrentDay", current)
            );
        }
        return incidents;
    }

    private void maybeCreateAnomaly(
            List<SecurityIncident> incidents,
            SubjectType subjectType,
            String subjectValue,
            String reason,
            List<Integer> baseline,
            int currentValue,
            Instant windowStart,
            Instant windowEnd,
            Map<String, Object> metrics
    ) {
        if (baseline.isEmpty()) {
            return;
        }

        double mean = baseline.stream().mapToInt(Integer::intValue).average().orElse(0);
        double variance = baseline.stream()
                .mapToDouble(v -> Math.pow(v - mean, 2))
                .average()
                .orElse(0);
        double stddev = Math.sqrt(variance);

        double zScore;
        if (stddev == 0) {
            zScore = currentValue > mean ? 10.0 : 0.0;
        } else {
            zScore = (currentValue - mean) / stddev;
        }

        if (zScore <= Z_SCORE_THRESHOLD) {
            return;
        }

        if (incidentRepository.existsByCategoryAndSubjectTypeAndSubjectValueAndWindowStartAndWindowEnd(
                IncidentCategory.ANOMALY, subjectType, subjectValue, windowStart, windowEnd)) {
            return;
        }

        IncidentSeverity severity = zScore > 6 ? IncidentSeverity.HIGH : IncidentSeverity.MED;
        String reasons = reason + "|Z_SCORE_" + String.format(Locale.ROOT, "%.2f", zScore);
        String snapshot = "mean=" + String.format(Locale.ROOT, "%.2f", mean)
                + ",stddev=" + String.format(Locale.ROOT, "%.2f", stddev)
                + ",current=" + currentValue
                + ",metric=" + metrics;

        SecurityIncident incident = SecurityIncident.builder()
                .category(IncidentCategory.ANOMALY)
                .severity(severity)
                .subjectType(subjectType)
                .subjectValue(subjectValue)
                .windowStart(windowStart)
                .windowEnd(windowEnd)
                .reasons(reasons)
                .metricsSnapshot(snapshot)
                .createdAt(Instant.now())
                .build();

        incidents.add(incidentRepository.save(incident));
    }

    @Transactional
    public void createRuleIncidentIfNeeded(
            SubjectType subjectType,
            String subjectValue,
            String reason,
            Map<String, Object> metrics
    ) {
        if (subjectValue == null || subjectValue.isBlank()) {
            return;
        }
        Instant now = Instant.now();
        Instant windowStart = now.minus(Duration.ofHours(24));
        Instant windowEnd = now;

        if (incidentRepository.existsByCategoryAndSubjectTypeAndSubjectValueAndWindowStartAndWindowEnd(
                IncidentCategory.RULE, subjectType, subjectValue, windowStart, windowEnd)) {
            return;
        }

        SecurityIncident incident = SecurityIncident.builder()
                .category(IncidentCategory.RULE)
                .severity(IncidentSeverity.HIGH)
                .subjectType(subjectType)
                .subjectValue(subjectValue)
                .windowStart(windowStart)
                .windowEnd(windowEnd)
                .reasons(reason)
                .metricsSnapshot(metrics.toString())
                .createdAt(now)
                .build();

        incidentRepository.save(incident);
    }
}
