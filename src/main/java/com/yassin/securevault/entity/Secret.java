package com.yassin.securevault.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
@Entity
@Table(name = "secrets", indexes = {
        @Index(name = "idx_secrets_owner", columnList = "owner_email")
})
public class Secret {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Owner aus JWT (Email)
    @Column(name = "owner_email", nullable = false, length = 320)
    private String ownerEmail;

    @Column(nullable = false, length = 120)
    private String title;

    // AES-GCM IV (12 bytes) + Ciphertext (inkl. Auth Tag)
    @Column(name = "iv", nullable = false, columnDefinition = "bytea")
    private byte[] iv;

    @Column(name = "ciphertext", nullable = false, columnDefinition = "bytea")
    private byte[] ciphertext;

    @Column(nullable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
