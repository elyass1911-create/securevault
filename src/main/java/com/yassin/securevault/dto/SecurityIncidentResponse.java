package com.yassin.securevault.dto;

import com.yassin.securevault.entity.IncidentCategory;
import com.yassin.securevault.entity.IncidentSeverity;
import com.yassin.securevault.entity.SubjectType;

import java.time.Instant;
import java.util.List;

public record SecurityIncidentResponse(
        Long incidentId,
        IncidentCategory category,
        IncidentSeverity severity,
        SubjectType subjectType,
        String subjectValue,
        Instant windowStart,
        Instant windowEnd,
        List<String> reasons,
        String metricsSnapshot,
        Instant createdAt
) {}
