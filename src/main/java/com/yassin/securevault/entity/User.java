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
    @Table(
            name = "users",
            uniqueConstraints = @UniqueConstraint(
                    name = "uk_users_email",
                    columnNames = "email"
            )
    )
    public class User {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(nullable = false, length = 320)
        private String email;

        @Column(nullable = false)
        private String passwordHash;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false)
        private Role role;

        @Column(nullable = false, updatable = false)
        private Instant createdAt;

        @PrePersist
        public void onCreate() {
            this.createdAt = Instant.now();
        }
    }
