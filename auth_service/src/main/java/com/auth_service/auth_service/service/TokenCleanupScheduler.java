package com.auth_service.auth_service.service;

import java.time.Instant;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.auth_service.auth_service.repository.RefreshTokenRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Nightly job that removes expired and revoked refresh tokens.
 * Without this, the refresh_tokens table grows forever.
 * Runs at 2 AM every day — low-traffic window.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class TokenCleanupScheduler {

    private final RefreshTokenRepository refreshTokenRepository;

    @Scheduled(cron = "0 0 2 * * *")
    @Transactional
    public void cleanupExpiredTokens() {
        int deleted = refreshTokenRepository.deleteExpiredAndRevoked(Instant.now());
        log.info("Token cleanup complete: removed {} expired/revoked refresh tokens", deleted);
    }
}
