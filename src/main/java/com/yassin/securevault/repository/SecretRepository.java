package com.yassin.securevault.repository;

import com.yassin.securevault.entity.Secret;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface SecretRepository extends JpaRepository<Secret, Long> {
    List<Secret> findAllByOwnerEmail(String ownerEmail);
    Optional<Secret> findByIdAndOwnerEmail(Long id, String ownerEmail);
}