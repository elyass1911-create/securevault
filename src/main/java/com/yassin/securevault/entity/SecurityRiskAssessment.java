package com.yassin.securevault.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "security_risk_assessments", indexes = {
        @Index(name = "idx_risk_subject", columnList = "subject_type,subject_value"),
        @Index(name = "idx_risk_score", columnList = "score"),
        @Index(name = "idx_risk_computed", columnList = "computed_at")
})
public class SecurityRiskAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "subject_type", nullable = false, length = 16)
    private SubjectType subjectType;

    @Column(name = "subject_value", nullable = false, length = 320)
    private String subjectValue;

    @Column(name = "score", nullable = false)
    private int score;

    @Column(name = "top_reasons", length = 2000)
    private String topReasons;

    @Column(name = "window_start", nullable = false)
    private Instant windowStart;

    @Column(name = "window_end", nullable = false)
    private Instant windowEnd;

    @Column(name = "computed_at", nullable = false)
    private Instant computedAt;

    @PrePersist
    void onCreate() {
        if (computedAt == null) {
            computedAt = Instant.now();
        }
    }
}
