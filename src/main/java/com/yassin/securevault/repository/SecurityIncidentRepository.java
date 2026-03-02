package com.yassin.securevault.repository;

import com.yassin.securevault.entity.IncidentCategory;
import com.yassin.securevault.entity.SecurityIncident;
import com.yassin.securevault.entity.SubjectType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface SecurityIncidentRepository extends JpaRepository<SecurityIncident, Long> {

    Page<SecurityIncident> findAllByOrderByCreatedAtDesc(Pageable pageable);

    Page<SecurityIncident> findByCategoryOrderByCreatedAtDesc(IncidentCategory category, Pageable pageable);

    boolean existsByCategoryAndSubjectTypeAndSubjectValueAndWindowStartAndWindowEnd(
            IncidentCategory category,
            SubjectType subjectType,
            String subjectValue,
            Instant windowStart,
            Instant windowEnd
    );
}
