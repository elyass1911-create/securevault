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
@Table(name = "security_events", indexes = {
        @Index(name = "idx_secevent_time", columnList = "occurred_at"),
        @Index(name = "idx_secevent_type", columnList = "event_type"),
        @Index(name = "idx_secevent_actor", columnList = "actor_email"),
        @Index(name = "idx_secevent_ip", columnList = "ip_address")
})
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 64)
    private SecurityEventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", nullable = false, length = 16)
    private SecurityOutcome outcome;

    @Column(name = "actor_email", length = 320)
    private String actorEmail;

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "resource_type", length = 64)
    private String resourceType;

    @Column(name = "resource_id", length = 128)
    private String resourceId;

    @Column(name = "metadata", length = 2000)
    private String metadata;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @PrePersist
    void onCreate() {
        if (occurredAt == null) {
            occurredAt = Instant.now();
        }
    }
}
