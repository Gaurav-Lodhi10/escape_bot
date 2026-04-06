package com.auth_service.auth_service.service;

import com.auth_service.auth_service.dto.request.*;
import com.auth_service.auth_service.dto.response.*;
import com.auth_service.auth_service.entity.*;
import com.auth_service.auth_service.exception.*;
import com.auth_service.auth_service.repository.*;
import com.auth_service.auth_service.util.JwtUtil;
import com.auth_service.auth_service.util.TokenHashUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor

public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCK_DURATION_MINUTES = 30;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenHashUtil tokenHashUtil;
    private final AuditService auditService;
    private final AuthenticationManager authenticationManager;

    @Value("${jwt.refresh-token-expiry-ms}")
    private long refreshTokenExpiryMs;

    // ─── REGISTER ──────────────────────────────────────────────────────────────

    @Transactional
    public UserResponse register(RegisterRequest request, String ip, String ua) {
        if (userRepository.existsByEmail(request.getEmail().toLowerCase())) {
            throw new ConflictException("Registration failed. Please try a different email.");
        }

        Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found — DataInitializer must run first"));

        User user = User.builder()
                .firstName(request.getFirstName().trim())
                .lastName(request.getLastName().trim())
                .email(request.getEmail().toLowerCase().trim())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .roles(Set.of(userRole))
                .build();

        User saved = userRepository.save(user);
        log.info("New user registered: {}", saved.getEmail());
        auditService.logSuccess(AuditLog.EventType.REGISTER, saved.getId(), saved.getEmail(), ip, ua);
        return toUserResponse(saved);
    }

    // ─── LOGIN ─────────────────────────────────────────────────────────────────

    @Transactional
    public AuthResponse login(LoginRequest request, String ip, String ua) {
        String email = request.getEmail().toLowerCase().trim();

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    auditService.logFailure(AuditLog.EventType.LOGIN_FAILURE, email, ip, ua, "USER_NOT_FOUND");
                    return new BadCredentialsException("Invalid email or password");
                });

        if (user.isAccountLocked() && !user.isAccountNonLocked()) {
            auditService.logFailure(AuditLog.EventType.LOGIN_FAILURE, email, ip, ua, "ACCOUNT_LOCKED");
            throw new LockedException("Account is temporarily locked. Try again later.");
        }

        if (user.isAccountLocked() && user.isAccountNonLocked()) {
            userRepository.unlockAccount(email);
            user.setAccountLocked(false);
        }

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, request.getPassword()));
        } catch (AuthenticationException e) {
            handleFailedLogin(user, email, ip, ua);
            throw new BadCredentialsException("Invalid email or password");
        }

        userRepository.updateLastLoginAt(user.getId(), Instant.now());

        Set<String> roles = user.getRoles().stream()
                .map(r -> r.getName().name())
                .collect(Collectors.toSet());

        String accessToken = jwtUtil.generateAccessToken(email, user.getId(), roles);

        // BUG FIX: createRefreshToken now returns both the saved entity AND the raw token
        // string in a record, so we can return the raw token to the client while storing
        // only the hash. Previously, generateRawRefreshToken() was hashing the entity ID
        // (not the original rawToken), making the two hashes completely different.
        RefreshTokenResult tokenResult = createRefreshToken(user, ip);

        auditService.logSuccess(AuditLog.EventType.LOGIN_SUCCESS, user.getId(), email, ip, ua);
        log.info("User logged in: {}", email);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(tokenResult.rawToken())
                .accessTokenExpiresIn(jwtUtil.getAccessTokenExpiryMs())
                .user(toUserResponse(user))
                .build();
    }

    // ─── REFRESH TOKEN ─────────────────────────────────────────────────────────

    @Transactional
    public AuthResponse refresh(RefreshTokenRequest request, String ip, String ua) {
        String rawToken = request.getRefreshToken();
        String tokenHash = tokenHashUtil.hash(rawToken);

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new TokenException("Invalid or expired refresh token"));

        if (stored.isRevoked()) {
            log.warn("Revoked refresh token reuse detected for user: {}", stored.getUser().getEmail());
            refreshTokenRepository.revokeAllByUser(stored.getUser(), Instant.now(), "REUSE_DETECTED");
            auditService.logFailure(AuditLog.EventType.TOKEN_REVOKE,
                    stored.getUser().getEmail(), ip, ua, "REFRESH_TOKEN_REUSE");
            throw new TokenException("Token reuse detected. All sessions have been invalidated.");
        }

        if (stored.isExpired()) {
            throw new TokenException("Refresh token has expired. Please log in again.");
        }

        User user = stored.getUser();

        stored.setRevoked(true);
        stored.setRevokedAt(Instant.now());
        stored.setRevokedReason("ROTATION");
        refreshTokenRepository.save(stored);

        Set<String> roles = user.getRoles().stream()
                .map(r -> r.getName().name())
                .collect(Collectors.toSet());

        String newAccessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getId(), roles);
        RefreshTokenResult newTokenResult = createRefreshToken(user, ip);

        auditService.logSuccess(AuditLog.EventType.TOKEN_REFRESH, user.getId(), user.getEmail(), ip, ua);

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newTokenResult.rawToken())
                .accessTokenExpiresIn(jwtUtil.getAccessTokenExpiryMs())
                .build();
    }

    // ─── LOGOUT ────────────────────────────────────────────────────────────────

    @Transactional
    public void logout(String email, String ip, String ua) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        refreshTokenRepository.revokeAllByUser(user, Instant.now(), "LOGOUT");
        auditService.logSuccess(AuditLog.EventType.LOGOUT, user.getId(), email, ip, ua);
        log.info("User logged out: {}", email);
    }

    // ─── CHANGE PASSWORD ───────────────────────────────────────────────────────

    @Transactional
    public void changePassword(String email, ChangePasswordRequest request, String ip, String ua) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new BadCredentialsException("Current password is incorrect");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPasswordHash())) {
            throw new BadRequestException("New password must be different from current password");
        }

        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);

        refreshTokenRepository.revokeAllByUser(user, Instant.now(), "PASSWORD_CHANGE");
        auditService.logSuccess(AuditLog.EventType.PASSWORD_CHANGE, user.getId(), email, ip, ua);
        log.info("Password changed for user: {}", email);
    }

    // ─── GET PROFILE ───────────────────────────────────────────────────────────

    @Transactional(readOnly = true)
    public UserResponse getUserProfile(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        return toUserResponse(user);
    }

    // ─── PRIVATE HELPERS ───────────────────────────────────────────────────────

    private void handleFailedLogin(User user, String email, String ip, String ua) {
        userRepository.incrementFailedAttempts(email);

        int attempts = user.getFailedLoginAttempts() + 1;
        auditService.logFailure(AuditLog.EventType.LOGIN_FAILURE,
                email, ip, ua, "BAD_CREDENTIALS (attempt " + attempts + ")");

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            Instant lockUntil = Instant.now().plusSeconds(LOCK_DURATION_MINUTES * 60);
            userRepository.lockAccount(email, lockUntil);
            auditService.logFailure(AuditLog.EventType.ACCOUNT_LOCKED, email, ip, ua, "TOO_MANY_FAILED_ATTEMPTS");
            log.warn("Account locked after {} failed attempts: {}", attempts, email);
        }
    }

    /**
     * BUG FIX: previously the rawToken was generated here but only its hash was stored.
     * Then generateRawRefreshToken() was hashing the entity ID — a completely different value.
     * Fix: return both the entity and the rawToken as a record so login/refresh can send
     * the correct raw value back to the client.
     *
     * Flow: generate rawToken → hash it → store hash in DB → return rawToken to client.
     * On refresh: client sends rawToken → we hash it → look up hash in DB. Match.
     */
    private RefreshTokenResult createRefreshToken(User user, String ip) {
        String rawToken = UUID.randomUUID().toString();
        String tokenHash = tokenHashUtil.hash(rawToken);

        RefreshToken token = RefreshToken.builder()
                .tokenHash(tokenHash)
                .user(user)
                .expiresAt(Instant.now().plusMillis(refreshTokenExpiryMs))
                .createdByIp(ip)
                .build();

        refreshTokenRepository.save(token);
        return new RefreshTokenResult(token, rawToken);
    }

    private UserResponse toUserResponse(User user) {
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

    // Simple record to carry both the saved entity and the raw token string together
    private record RefreshTokenResult(RefreshToken entity, String rawToken) {}
}