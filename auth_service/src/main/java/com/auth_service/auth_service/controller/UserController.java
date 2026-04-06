package com.auth_service.auth_service.controller;



import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth_service.auth_service.dto.request.UpdateProfileRequest;
import com.auth_service.auth_service.dto.response.ApiResponse;
import com.auth_service.auth_service.dto.response.UserResponse;
import com.auth_service.auth_service.service.UserService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Endpoints a regular authenticated user calls on their OWN account.
 * Every method uses @AuthenticationPrincipal — the email comes from
 * the JWT, not from the URL. A user can never touch another user's data.
 *
 * Base path: /api/v1/users
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * GET /api/v1/users/me
     * Returns the authenticated user's full profile.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> getMyProfile(
            @AuthenticationPrincipal UserDetails userDetails) {

        UserResponse user = userService.getMyProfile(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success(user));
    }

    /**
     * PATCH /api/v1/users/me
     * Update first name and last name.
     * Email and password changes have their own dedicated endpoints.
     */
    @PatchMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> updateMyProfile(
            @Valid @RequestBody UpdateProfileRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {

        UserResponse user = userService.updateMyProfile(
                userDetails.getUsername(),
                request,
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Profile updated", user));
    }

    /**
     * DELETE /api/v1/users/me
     * Soft-deletes (disables) the authenticated user's account and
     * revokes all their sessions.
     */
    @DeleteMapping("/me")
    public ResponseEntity<ApiResponse<Void>> deleteMyAccount(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {

        userService.deleteMyAccount(
                userDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success(
                "Account deleted. You have been logged out of all devices.", null));
    }

    /**
     * GET /api/v1/users/me/sessions
     * Returns the number of active sessions (devices currently logged in).
     */
    @GetMapping("/me/sessions")
    public ResponseEntity<ApiResponse<Long>> getActiveSessions(
            @AuthenticationPrincipal UserDetails userDetails) {

        long count = userService.getActiveSessionCount(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success("Active session count", count));
    }

    /**
     * DELETE /api/v1/users/me/sessions
     * Revokes all refresh tokens — logs out from every device.
     * The current access token remains valid until it expires (max 15 min).
     */
    @DeleteMapping("/me/sessions")
    public ResponseEntity<ApiResponse<Void>> revokeAllSessions(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {

        userService.revokeAllSessions(
                userDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success(
                "All sessions revoked. You have been logged out of all devices.", null));
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String xri = request.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) return xri.trim();
        return request.getRemoteAddr();
    }
}