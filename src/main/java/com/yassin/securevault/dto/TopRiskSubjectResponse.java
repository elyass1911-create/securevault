package com.yassin.securevault.dto;

import com.yassin.securevault.entity.SubjectType;

import java.time.Instant;
import java.util.List;

public record TopRiskSubjectResponse(
        SubjectType subjectType,
        String subjectValue,
        int score,
        List<String> topReasons,
        Instant computedAt,
        Instant windowStart,
        Instant windowEnd
) {}
