package com.auth_service.auth_service.controller;

import com.auth_service.auth_service.dto.request.*;
import com.auth_service.auth_service.dto.response.*;
import com.auth_service.auth_service.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/v1/auth/register
     * Public. Creates a new user account.
     * Returns 201 + the new user's profile (no tokens — user must login separately).
     */
    @PostMapping("/register")
    public ResponseEntity<ApiResponse<UserResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        UserResponse user = authService.register(
                request,
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registration successful", user));
    }

    /**
     * POST /api/v1/auth/login
     * Public. Returns accessToken (15 min) + refreshToken (7 days).
     */
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        AuthResponse auth = authService.login(
                request,
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Login successful", auth));
    }

    /**
     * POST /api/v1/auth/refresh
     * Public. Send the refresh token, get a new access token + rotated refresh token.
     * Sending a previously-used refresh token triggers reuse detection and revokes
     * all sessions for that user.
     */
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {

        AuthResponse auth = authService.refresh(
                request,
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Token refreshed", auth));
    }

    /**
     * POST /api/v1/auth/logout
     * Requires valid JWT in Authorization header.
     * Revokes all refresh tokens for this user — logs out from every device.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {

        authService.logout(
                userDetails.getUsername(),
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success("Logged out successfully", null));
    }

    /**
     * POST /api/v1/auth/change-password
     * Requires valid JWT. Forces re-login on all devices after success.
     */
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody ChangePasswordRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest) {

        authService.changePassword(
                userDetails.getUsername(),
                request,
                getClientIp(httpRequest),
                httpRequest.getHeader("User-Agent"));

        return ResponseEntity.ok(ApiResponse.success(
                "Password changed. Please log in again on all devices.", null));
    }

    /**
     * GET /api/v1/auth/me
     * Requires valid JWT. Returns the authenticated user's profile.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserResponse>> me(
            @AuthenticationPrincipal UserDetails userDetails) {

        UserResponse user = authService.getUserProfile(userDetails.getUsername());
        return ResponseEntity.ok(ApiResponse.success(user));
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /**
     * Extracts the real client IP, handling X-Forwarded-For when behind Nginx/proxy.
     * X-Forwarded-For may be a comma-separated list — first value is the original client.
     */
    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String xri = request.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) {
            return xri.trim();
        }
        return request.getRemoteAddr();
    }
}
