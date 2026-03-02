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
@Table(name = "security_incidents", indexes = {
        @Index(name = "idx_incident_created", columnList = "created_at"),
        @Index(name = "idx_incident_subject", columnList = "subject_type,subject_value"),
        @Index(name = "idx_incident_severity", columnList = "severity"),
        @Index(name = "idx_incident_category", columnList = "category")
})
public class SecurityIncident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "category", nullable = false, length = 16)
    private IncidentCategory category;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 16)
    private IncidentSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(name = "subject_type", nullable = false, length = 16)
    private SubjectType subjectType;

    @Column(name = "subject_value", nullable = false, length = 320)
    private String subjectValue;

    @Column(name = "window_start", nullable = false)
    private Instant windowStart;

    @Column(name = "window_end", nullable = false)
    private Instant windowEnd;

    @Column(name = "reasons", length = 2000)
    private String reasons;

    @Column(name = "metrics_snapshot", length = 2000)
    private String metricsSnapshot;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
}
