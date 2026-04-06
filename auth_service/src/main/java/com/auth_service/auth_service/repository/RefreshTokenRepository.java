package com.auth_service.auth_service.repository;

 
import com.auth_service.auth_service.entity.RefreshToken;
import com.auth_service.auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
 
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
 
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {
 
    Optional<RefreshToken> findByTokenHash(String tokenHash);
 
    List<RefreshToken> findAllByUserAndRevokedFalse(User user);
 
    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true, rt.revokedAt = :now, rt.revokedReason = :reason WHERE rt.user = :user AND rt.revoked = false")
    void revokeAllByUser(@Param("user") User user, @Param("now") Instant now, @Param("reason") String reason);
 
    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :cutoff OR rt.revoked = true")
    int deleteExpiredAndRevoked(@Param("cutoff") Instant cutoff);
 
    long countByUserAndRevokedFalse(User user);
}
 