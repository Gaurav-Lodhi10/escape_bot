package com.auth_service.auth_service.service;


import com.auth_service.auth_service.dto.request.UpdateProfileRequest;
import com.auth_service.auth_service.dto.response.UserResponse;
import com.auth_service.auth_service.entity.AuditLog;
import com.auth_service.auth_service.entity.User;
import com.auth_service.auth_service.exception.ResourceNotFoundException;
import com.auth_service.auth_service.repository.RefreshTokenRepository;
import com.auth_service.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Operations a regular authenticated user can perform on their OWN account.
 * No admin privileges required — all methods take the caller's email from
 * the JWT (via @AuthenticationPrincipal) so a user can never touch another
 * user's data.
 *
 * Admin operations (list all users, change roles, etc.) live in AdminUserService.
 */
@Slf4j
@Service
@RequiredArgsConstructor

public class UserService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;

    // ── GET OWN PROFILE ───────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public UserResponse getMyProfile(String email) {
        User user = findByEmailOrThrow(email);
        return toUserResponse(user);
    }

    // ── UPDATE OWN PROFILE ────────────────────────────────────────────────────

    @Transactional
    public UserResponse updateMyProfile(String email, UpdateProfileRequest request,
                                        String ip, String ua) {
        User user = findByEmailOrThrow(email);

        user.setFirstName(request.getFirstName().trim());
        user.setLastName(request.getLastName().trim());

        User saved = userRepository.save(user);
        log.info("Profile updated for user: {}", email);

        auditService.logSuccess(AuditLog.EventType.ACCOUNT_UNLOCKED, saved.getId(), email, ip, ua);
        return toUserResponse(saved);
    }

    // ── DELETE OWN ACCOUNT ────────────────────────────────────────────────────

    /**
     * Soft delete — disables the account and revokes all sessions.
     * Does NOT hard delete the row. Hard delete is admin-only (AdminUserService).
     *
     * Why soft: audit logs reference user_id. Hard-deleting a user orphans audit
     * history, which matters for compliance. Admin can hard delete if needed.
     */
    @Transactional
    public void deleteMyAccount(String email, String ip, String ua) {
        User user = findByEmailOrThrow(email);

        // Revoke all refresh tokens — immediate session termination everywhere
        refreshTokenRepository.revokeAllByUser(user, Instant.now(), "ACCOUNT_DELETED");

        // Soft delete — disable the account
        user.setEnabled(false);
        userRepository.save(user);

        log.info("Account self-deleted (disabled) for user: {}", email);
        auditService.logSuccess(AuditLog.EventType.LOGOUT, user.getId(), email, ip, ua);
    }

    // ── GET SESSION INFO ──────────────────────────────────────────────────────

    /**
     * Returns how many active (non-revoked, non-expired) refresh tokens exist
     * for this user — i.e. how many devices/sessions are currently logged in.
     */
    @Transactional(readOnly = true)
    public long getActiveSessionCount(String email) {
        User user = findByEmailOrThrow(email);
        return refreshTokenRepository.countByUserAndRevokedFalse(user);
    }

    // ── REVOKE ALL OTHER SESSIONS ─────────────────────────────────────────────

    /**
     * "Log out everywhere else" — revokes all refresh tokens so only the
     * current session (with its access token) remains valid until it expires.
     */
    @Transactional
    public void revokeAllSessions(String email, String ip, String ua) {
        User user = findByEmailOrThrow(email);
        refreshTokenRepository.revokeAllByUser(user, Instant.now(), "REVOKE_ALL_SESSIONS");
        log.info("All sessions revoked for user: {}", email);
        auditService.logSuccess(AuditLog.EventType.TOKEN_REVOKE, user.getId(), email, ip, ua);
    }

    // ── HELPERS ───────────────────────────────────────────────────────────────

    private User findByEmailOrThrow(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
    }

    public UserResponse toUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(r -> r.getName().name())
                        .collect(Collectors.toSet()))
                .emailVerified(user.isEmailVerified())
                .mfaEnabled(user.isMfaEnabled())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }
}
