package com.yassin.securevault.repository;

import com.yassin.securevault.entity.SecurityRiskAssessment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;

public interface SecurityRiskAssessmentRepository extends JpaRepository<SecurityRiskAssessment, Long> {

    void deleteByComputedAtBefore(Instant threshold);
}
