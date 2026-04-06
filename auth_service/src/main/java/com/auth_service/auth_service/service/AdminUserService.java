package com.auth_service.auth_service.service;


import com.auth_service.auth_service.dto.request.AdminUpdateUserRequest;
import com.auth_service.auth_service.dto.response.PagedResponse;
import com.auth_service.auth_service.dto.response.UserResponse;
import com.auth_service.auth_service.dto.response.UserSummaryResponse;
import com.auth_service.auth_service.entity.AuditLog;
import com.auth_service.auth_service.entity.Role;
import com.auth_service.auth_service.entity.User;
import com.auth_service.auth_service.exception.BadRequestException;
import com.auth_service.auth_service.exception.ResourceNotFoundException;
import com.auth_service.auth_service.repository.RefreshTokenRepository;
import com.auth_service.auth_service.repository.RoleRepository;
import com.auth_service.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Admin-only user management operations.
 * Every public method is called only from AdminUserController,
 * which is secured with @PreAuthorize("hasRole('ADMIN')").
 *
 * Separation from UserService is intentional — clear security boundary.
 * UserService = what you can do to yourself.
 * AdminUserService = what an admin can do to any user.
 */
@Slf4j
@Service
@RequiredArgsConstructor

public class AdminUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final AuditService auditService;

    // ── LIST ALL USERS ────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public PagedResponse<UserSummaryResponse> getAllUsers(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<User> users = userRepository.findAll(pageable);
        return PagedResponse.of(users, this::toSummary);
    }

    // ── SEARCH USERS ──────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public PagedResponse<UserSummaryResponse> searchUsers(String query, int page, int size) {
        if (!StringUtils.hasText(query) || query.trim().length() < 2) {
            throw new BadRequestException("Search query must be at least 2 characters");
        }
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<User> users = userRepository.searchByQuery(query.trim(), pageable);
        return PagedResponse.of(users, this::toSummary);
    }

    // ── GET USER BY ID ────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public UserResponse getUserById(UUID userId) {
        User user = findByIdOrThrow(userId);
        return toFullResponse(user);
    }

    // ── UPDATE USER ───────────────────────────────────────────────────────────

    /**
     * Admin can update: roles, accountLocked, enabled.
     * Null fields in the request = "don't change this field".
     * This is a partial update — only non-null fields are applied.
     */
    @Transactional
    public UserResponse updateUser(UUID userId, AdminUpdateUserRequest request,
                                   String adminEmail, String ip, String ua) {
        User user = findByIdOrThrow(userId);
        boolean changed = false;

        // Update roles if provided
        if (request.getRoles() != null && !request.getRoles().isEmpty()) {
            Set<Role> newRoles = new HashSet<>();
            for (String roleName : request.getRoles()) {
                Role.RoleName rn;
                try {
                    rn = Role.RoleName.valueOf(roleName);
                } catch (IllegalArgumentException e) {
                    throw new BadRequestException("Invalid role: " + roleName +
                            ". Valid values: ROLE_USER, ROLE_ADMIN, ROLE_SERVICE");
                }
                Role role = roleRepository.findByName(rn)
                        .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleName));
                newRoles.add(role);
            }
            user.setRoles(newRoles);
            changed = true;
            log.info("Admin {} updated roles for user {}: {}", adminEmail, user.getEmail(), request.getRoles());
        }

        // Lock or unlock account
        if (request.getAccountLocked() != null) {
            user.setAccountLocked(request.getAccountLocked());
            if (request.getAccountLocked()) {
                // Lock indefinitely when admin explicitly locks
                user.setLockedUntil(Instant.now().plusSeconds(365L * 24 * 3600));
                // Revoke all sessions immediately
                refreshTokenRepository.revokeAllByUser(user, Instant.now(), "ADMIN_LOCK");
                auditService.logSuccess(AuditLog.EventType.ACCOUNT_LOCKED, user.getId(), user.getEmail(), ip, ua);
                log.warn("Admin {} locked account: {}", adminEmail, user.getEmail());
            } else {
                user.setLockedUntil(null);
                user.setFailedLoginAttempts(0);
                auditService.logSuccess(AuditLog.EventType.ACCOUNT_UNLOCKED, user.getId(), user.getEmail(), ip, ua);
                log.info("Admin {} unlocked account: {}", adminEmail, user.getEmail());
            }
            changed = true;
        }

        // Enable or disable account
        if (request.getEnabled() != null) {
            user.setEnabled(request.getEnabled());
            if (!request.getEnabled()) {
                // Disabling → revoke all sessions
                refreshTokenRepository.revokeAllByUser(user, Instant.now(), "ADMIN_DISABLE");
                log.warn("Admin {} disabled account: {}", adminEmail, user.getEmail());
            } else {
                log.info("Admin {} enabled account: {}", adminEmail, user.getEmail());
            }
            changed = true;
        }

        if (!changed) {
            throw new BadRequestException("No fields to update — provide at least one of: roles, accountLocked, enabled");
        }

        User saved = userRepository.save(user);
        return toFullResponse(saved);
    }

    // ── LOCK / UNLOCK SHORTCUTS ───────────────────────────────────────────────

    @Transactional
    public UserResponse lockUser(UUID userId, String adminEmail, String ip, String ua) {
        AdminUpdateUserRequest req = new AdminUpdateUserRequest();
        req.setAccountLocked(true);
        return updateUser(userId, req, adminEmail, ip, ua);
    }

    @Transactional
    public UserResponse unlockUser(UUID userId, String adminEmail, String ip, String ua) {
        AdminUpdateUserRequest req = new AdminUpdateUserRequest();
        req.setAccountLocked(false);
        return updateUser(userId, req, adminEmail, ip, ua);
    }

    // ── HARD DELETE USER ──────────────────────────────────────────────────────

    /**
     * Permanent hard delete — removes the user and all their data (cascade).
     * Soft delete (self-requested) lives in UserService.deleteMyAccount().
     *
     * Irreversible. Log the admin's action first in case of disputes.
     */
    @Transactional
    public void hardDeleteUser(UUID userId, String adminEmail, String ip, String ua) {
        User user = findByIdOrThrow(userId);

        // Log before delete — audit log references userId, which will be gone after
        auditService.logEvent(
                AuditLog.EventType.LOGOUT,
                user.getId(),
                user.getEmail(),
                ip, ua, true,
                null,
                "HARD_DELETE by admin: " + adminEmail);

        userRepository.delete(user);
        log.warn("Admin {} hard-deleted user: {} ({})", adminEmail, user.getEmail(), userId);
    }

    // ── STATS ─────────────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public UserStatsResponse getStats() {
        return UserStatsResponse.builder()
                .totalUsers(userRepository.count())
                .activeUsers(userRepository.countByEnabled(true))
                .disabledUsers(userRepository.countByEnabled(false))
                .lockedUsers(userRepository.countByAccountLocked(true))
                .build();
    }

    // ── HELPERS ───────────────────────────────────────────────────────────────

    private User findByIdOrThrow(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + userId));
    }

    private UserSummaryResponse toSummary(User user) {
        return UserSummaryResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .roles(user.getRoles().stream()
                        .map(r -> r.getName().name())
                        .collect(Collectors.toSet()))
                .enabled(user.isEnabled())
                .accountLocked(user.isAccountLocked())
                .createdAt(user.getCreatedAt())
                .lastLoginAt(user.getLastLoginAt())
                .build();
    }

    private UserResponse toFullResponse(User user) {
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

    // ── Inner stats record ────────────────────────────────────────────────────

    @lombok.Builder
    @lombok.Data
    public static class UserStatsResponse {
        private long totalUsers;
        private long activeUsers;
        private long disabledUsers;
        private long lockedUsers;
    }
}
