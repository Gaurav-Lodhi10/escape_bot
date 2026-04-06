
package com.auth_service.auth_service.repository;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.auth_service.auth_service.entity.AuditLog;
 
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {
 
    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(UUID userId, Pageable pageable);
 
    Page<AuditLog> findByEmailOrderByCreatedAtDesc(String email, Pageable pageable);
}
 