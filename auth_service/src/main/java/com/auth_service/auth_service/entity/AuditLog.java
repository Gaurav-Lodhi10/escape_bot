package com.auth_service.auth_service.entity;


import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
 
/**
 * Append-only audit log. Never update or delete rows from this table.
 * Grant the DB user INSERT only on this table — no UPDATE, no DELETE.
 */
@Entity
@Table(
    name = "audit_logs",
    indexes = {
        @Index(name = "idx_audit_user_id", columnList = "userId"),
        @Index(name = "idx_audit_event_type", columnList = "eventType"),
        @Index(name = "idx_audit_created_at", columnList = "createdAt")
    }
)
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {
 
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
 
    @Column(nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private EventType eventType;
 
    private UUID userId;         // nullable — pre-auth events have no userId yet
    private String email;        // capture even for failed logins
    private String ipAddress;
    private String userAgent;
    private String details;      // JSON string for extra context
 
    @Column(nullable = false)
    @Builder.Default
    private boolean success = true;
 
    private String failureReason;
 
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
 
    public enum EventType {
        REGISTER,
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        LOGOUT,
        TOKEN_REFRESH,
        TOKEN_REVOKE,
        PASSWORD_CHANGE,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
        MFA_ENABLED,
        MFA_DISABLED
    }
}
 