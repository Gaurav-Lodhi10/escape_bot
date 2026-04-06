package com.auth_service.auth_service.entity;



import java.time.Instant;
import java.util.UUID;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
 
@Entity
@Table(
    name = "refresh_tokens",
    indexes = {
        @Index(name = "idx_refresh_token_hash", columnList = "tokenHash"),
        @Index(name = "idx_refresh_token_user", columnList = "user_id")
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshToken {
 
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;
 
    /**
     * We store a SHA-256 hash of the actual token — never the raw value.
     * If the DB is compromised, the attacker gets useless hashes.
     */
    @Column(nullable = false, unique = true, length = 64)
    private String tokenHash;
 
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
 
    @Column(nullable = false)
    private Instant expiresAt;
 
    @Column(nullable = false)
    @Builder.Default
    private boolean revoked = false;
 
    private Instant revokedAt;
    private String revokedReason;  // "LOGOUT", "ROTATION", "MANUAL_REVOKE"
 
    @Column(length = 45)
    private String createdByIp;
 
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
 
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
 
    public boolean isValid() {
        return !revoked && !isExpired();
    }
}
 