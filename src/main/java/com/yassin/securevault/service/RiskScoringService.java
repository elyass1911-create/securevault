package com.yassin.securevault.service;

import com.yassin.securevault.entity.SecurityEvent;
import com.yassin.securevault.entity.SecurityEventType;
import com.yassin.securevault.entity.SecurityRiskAssessment;
import com.yassin.securevault.entity.SubjectType;
import com.yassin.securevault.repository.SecurityEventRepository;
import com.yassin.securevault.repository.SecurityRiskAssessmentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class RiskScoringService {

    private static final int LOGIN_FAIL_POINTS = 25;
    private static final int RATE_LIMIT_POINTS = 60;
    private static final int FORBIDDEN_POINTS = 80;
    private static final int HIGH_REVEAL_POINTS = 15;
    private static final int HIGH_REVEAL_THRESHOLD = 5;

    private final SecurityEventRepository securityEventRepository;
    private final SecurityRiskAssessmentRepository assessmentRepository;

    @Transactional
    public List<SecurityRiskAssessment> computeAndPersistTopRisks(Duration window, int limit) {
        Instant now = Instant.now();
        Instant start = now.minus(window);
        List<SecurityEvent> events = securityEventRepository.findByOccurredAtAfter(start);

        List<SecurityRiskAssessment> assessments = new ArrayList<>();
        assessments.addAll(buildAssessments(events, SubjectType.USER, start, now));
        assessments.addAll(buildAssessments(events, SubjectType.IP, start, now));

        assessments.sort(Comparator.comparingInt(SecurityRiskAssessment::getScore).reversed());
        List<SecurityRiskAssessment> top = assessments.stream()
                .limit(Math.max(limit, 0))
                .toList();

        if (!top.isEmpty()) {
            assessmentRepository.deleteByComputedAtBefore(now.minus(Duration.ofDays(7)));
            assessmentRepository.saveAll(top);
        }

        return top;
    }

    private List<SecurityRiskAssessment> buildAssessments(
            List<SecurityEvent> events,
            SubjectType subjectType,
            Instant windowStart,
            Instant windowEnd
    ) {
        Map<String, List<SecurityEvent>> grouped = events.stream()
                .filter(event -> subjectValue(event, subjectType) != null)
                .collect(Collectors.groupingBy(event -> subjectValue(event, subjectType)));

        List<SecurityRiskAssessment> out = new ArrayList<>();
        for (Map.Entry<String, List<SecurityEvent>> entry : grouped.entrySet()) {
            String subject = entry.getKey();
            List<SecurityEvent> subjectEvents = entry.getValue();

            int loginFails = countByType(subjectEvents, SecurityEventType.AUTH_LOGIN_FAIL);
            int rateLimits = countByType(subjectEvents, SecurityEventType.AUTH_RATE_LIMIT_TRIGGERED);
            int forbiddens = countByType(subjectEvents, SecurityEventType.AUTH_FORBIDDEN)
                    + countByType(subjectEvents, SecurityEventType.SUSPICIOUS_ENUMERATION);
            int reveals = countByType(subjectEvents, SecurityEventType.SECRET_REVEALED);

            int score = 0;
            List<String> reasons = new ArrayList<>();

            if (loginFails > 0) {
                score += loginFails * LOGIN_FAIL_POINTS;
                reasons.add("LOGIN_FAIL_x" + loginFails);
            }
            if (rateLimits > 0) {
                score += rateLimits * RATE_LIMIT_POINTS;
                reasons.add("RATE_LIMIT_x" + rateLimits);
            }
            if (forbiddens > 0) {
                score += forbiddens * FORBIDDEN_POINTS;
                reasons.add("FORBIDDEN_OR_ENUM_x" + forbiddens);
            }
            if (reveals > HIGH_REVEAL_THRESHOLD) {
                score += HIGH_REVEAL_POINTS;
                reasons.add("HIGH_REVEAL_ACTIVITY");
            }

            if (score <= 0) {
                continue;
            }

            out.add(SecurityRiskAssessment.builder()
                    .subjectType(subjectType)
                    .subjectValue(subject)
                    .score(score)
                    .topReasons(joinReasons(reasons))
                    .windowStart(windowStart)
                    .windowEnd(windowEnd)
                    .computedAt(Instant.now())
                    .build());
        }
        return out;
    }

    private int countByType(List<SecurityEvent> events, SecurityEventType type) {
        return (int) events.stream().filter(event -> event.getEventType() == type).count();
    }

    private String subjectValue(SecurityEvent event, SubjectType subjectType) {
        if (subjectType == SubjectType.USER) {
            return emptyToNull(event.getActorEmail());
        }
        return emptyToNull(event.getIpAddress());
    }

    private String emptyToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    public static List<String> parseReasons(String csv) {
        if (csv == null || csv.isBlank()) {
            return List.of();
        }
        return Arrays.stream(csv.split("\\|"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private String joinReasons(List<String> reasons) {
        if (reasons == null || reasons.isEmpty()) {
            return "";
        }
        return String.join("|", reasons);
    }
}
