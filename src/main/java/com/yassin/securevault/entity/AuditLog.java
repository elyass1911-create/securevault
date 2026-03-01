package com.yassin.securevault.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "idx_audit_actor", columnList = "actor_email"),
        @Index(name = "idx_audit_event", columnList = "event_type"),
        @Index(name = "idx_audit_time", columnList = "created_at")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 50)
    private AuditEventType eventType;

    @Column(name = "actor_email", length = 320)
    private String actorEmail; // kann bei failed login null sein

    @Column(name = "ip_address", length = 64)
    private String ipAddress;

    @Column(name = "resource_type", length = 50)
    private String resourceType; // z.B. "SECRET", "AUTH"

    @Column(name = "resource_id")
    private String resourceId; // z.B. secretId als String

    @Column(name = "details", length = 500)
    private String details; // KEIN secret klartext!

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        this.createdAt = Instant.now();
    }
}
