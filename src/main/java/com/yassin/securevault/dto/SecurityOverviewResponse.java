package com.yassin.securevault.dto;

import java.util.List;

public record SecurityOverviewResponse(
        long loginFailsLast24h,
        long rateLimitsLast24h,
        long forbiddenLast24h,
        long revealsLast24h,
        List<TopRiskSubjectResponse> topRiskySubjects,
        List<SecurityIncidentResponse> openIncidents
) {}
