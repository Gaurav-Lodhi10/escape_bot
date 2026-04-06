package com.auth_service.auth_service.repository;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.auth_service.auth_service.entity.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // ── Auth queries (used by AuthService) ────────────────────────────────────

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginAt, u.failedLoginAttempts = 0 WHERE u.id = :id")
    void updateLastLoginAt(@Param("id") UUID id, @Param("loginAt") Instant loginAt);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.email = :email")
    void incrementFailedAttempts(@Param("email") String email);

    @Modifying
    @Query("UPDATE User u SET u.accountLocked = true, u.lockedUntil = :lockedUntil WHERE u.email = :email")
    void lockAccount(@Param("email") String email, @Param("lockedUntil") Instant lockedUntil);

    @Modifying
    @Query("UPDATE User u SET u.accountLocked = false, u.lockedUntil = null, u.failedLoginAttempts = 0 WHERE u.email = :email")
    void unlockAccount(@Param("email") String email);

    // ── Admin queries (used by AdminUserService) ───────────────────────────────

    /**
     * Case-insensitive search across firstName, lastName, email.
     * Supports partial matches — "jo" matches "John", "Joe", "john@test.com".
     */
    @Query("""
            SELECT u FROM User u
            WHERE LOWER(u.firstName) LIKE LOWER(CONCAT('%', :query, '%'))
               OR LOWER(u.lastName)  LIKE LOWER(CONCAT('%', :query, '%'))
               OR LOWER(u.email)     LIKE LOWER(CONCAT('%', :query, '%'))
            """)
    Page<User> searchByQuery(@Param("query") String query, Pageable pageable);

    /** All users — paginated, newest first by default when caller passes Sort.by("createdAt").descending() */
    Page<User> findAll(Pageable pageable);

    /** Filter by account state — useful for admin dashboards */
    Page<User> findByEnabled(boolean enabled, Pageable pageable);

    Page<User> findByAccountLocked(boolean locked, Pageable pageable);

    // ── Stats ─────────────────────────────────────────────────────────────────

    long countByEnabled(boolean enabled);

    long countByAccountLocked(boolean locked);
}