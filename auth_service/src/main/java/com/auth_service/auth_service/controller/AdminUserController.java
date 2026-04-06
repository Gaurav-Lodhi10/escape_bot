package com.auth_service.auth_service.controller;


import com.auth_service.auth_service.dto.request.AdminUpdateUserRequest;
import com.auth_service.auth_service.dto.response.ApiResponse;
import com.auth_service.auth_service.dto.response.PagedResponse;
import com.auth_service.auth_service.dto.response.UserResponse;
import com.auth_service.auth_service.dto.response.UserSummaryResponse;
import com.auth_service.auth_service.service.AdminUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * Admin-only user management endpoints.
 *
 * @PreAuthorize("hasRole('ADMIN')") is on the class — every single method
 * requires ADMIN role. Spring Security enforces this BEFORE the method runs.
 *
 * Base path: /api/v1/admin/users
 * (SecurityConfig already blocks /api/v1/admin/** without ADMIN role as a
 * first layer — @PreAuthorize is the second layer defence-in-depth.)
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/admin/users")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final AdminUserService adminUserService;

    /**
     * GET /api/v1/admin/users?page=0&size=20
     * Paginated list of all users, newest first.
     */
    @GetMapping
    public ResponseEntity<ApiResponse<PagedResponse<UserSummaryResponse>>> getAllUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        // Cap page size — never let callers request 10k rows
        int safeSize = Math.min(size, 100);
        PagedResponse<UserSummaryResponse> result = adminUserService.getAllUsers(page, safeSize);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    /**
     * GET /api/v1/admin/users/search?query=john&page=0&size=20
     * Search users by name or email (case-insensitive, partial match).
     */
    @GetMapping("/search")
    public ResponseEntity<ApiResponse<PagedResponse<UserSummaryResponse>>> searchUsers(
            @RequestParam String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        int safeSize = Math.min(size, 100);
        PagedResponse<UserSummaryResponse> result = adminUserService.searchUsers(query, page, safeSize);
        return ResponseEntity.ok(ApiResponse.success(result));
    }

    /**
     * GET /api/v1/admin/users/{userId}
     * Full profile of a specific user.
     */
    @GetMapping("/{userId}")
    public ResponseEntity<ApiResponse<UserResponse>> getUserById(
            @PathVariable UUID userId) {

        UserResponse user = adminUserService.getUserById(userId);
        return ResponseEntity.ok(ApiResponse.success(user));
    }

    /**
     * PATCH /api/v1/admin/users/{userId}
     * Partial update — only non-null fields are applied.
     * Can change: roles, accountLocked, enabled.
     *
     * Example body: { "roles": ["ROLE_ADMIN"] }
     * Example body: { "accountLocked": true }
     * Example body: { "enabled": false }
     * Example body: { "roles": ["ROLE_USER"], "enabled": true }
     */
    @PatchMapping("/{userId}")
    public ResponseEntity<ApiResponse<UserResponse>> updateUser(
            @PathVariable UUID userId,
            @Valid @RequestBody AdminUpdateUserRequest request,
            @AuthenticationPrincipal UserDetails adminDetails,
            HttpServletRequest httpRequest) {

        UserResponse user = adminUserService.updateUser(
                userId,
                request,
                adminDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("User updated", user));
    }

    /**
     * POST /api/v1/admin/users/{userId}/lock
     * Locks the account and revokes all sessions immediately.
     */
    @PostMapping("/{userId}/lock")
    public ResponseEntity<ApiResponse<UserResponse>> lockUser(
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails adminDetails,
            HttpServletRequest httpRequest) {

        UserResponse user = adminUserService.lockUser(
                userId,
                adminDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Account locked", user));
    }

    /**
     * POST /api/v1/admin/users/{userId}/unlock
     * Unlocks the account and resets failed login attempts.
     */
    @PostMapping("/{userId}/unlock")
    public ResponseEntity<ApiResponse<UserResponse>> unlockUser(
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails adminDetails,
            HttpServletRequest httpRequest) {

        UserResponse user = adminUserService.unlockUser(
                userId,
                adminDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Account unlocked", user));
    }

    /**
     * DELETE /api/v1/admin/users/{userId}
     * PERMANENT hard delete. Irreversible. Use with caution.
     * Cascades to: refresh_tokens, user_roles.
     * Audit logs retain the userId reference but the user row is gone.
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<ApiResponse<Void>> hardDeleteUser(
            @PathVariable UUID userId,
            @AuthenticationPrincipal UserDetails adminDetails,
            HttpServletRequest httpRequest) {

        adminUserService.hardDeleteUser(
                userId,
                adminDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("User permanently deleted", null));
    }

    /**
     * GET /api/v1/admin/users/stats
     * Quick dashboard numbers: total, active, disabled, locked.
     */
    @GetMapping("/stats")
    public ResponseEntity<ApiResponse<AdminUserService.UserStatsResponse>> getStats() {
        return ResponseEntity.ok(ApiResponse.success(adminUserService.getStats()));
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String xri = request.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) return xri.trim();
        return request.getRemoteAddr();
    }
}