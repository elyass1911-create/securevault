package com.yassin.securevault.repository;

import com.yassin.securevault.entity.SecurityEvent;
import com.yassin.securevault.entity.SecurityEventType;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, Long> {

    long countByEventTypeAndOccurredAtAfter(SecurityEventType eventType, Instant since);

    List<SecurityEvent> findByOccurredAtAfter(Instant since);

    List<SecurityEvent> findByOccurredAtBetween(Instant start, Instant end);
}
