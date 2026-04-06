package com.auth_service.auth_service.service;

import com.auth_service.auth_service.entity.AuditLog;
import com.auth_service.auth_service.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * BUG FIX: logSuccess() and logFailure() previously called this.log() directly.
 * Internal calls bypass Spring's proxy — @Async and @Transactional do nothing.
 * Fix: each public method does its own work directly instead of delegating internally.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuditService {

    private final AuditLogRepository auditLogRepository;

    @Async("auditExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logSuccess(AuditLog.EventType eventType,
                           UUID userId,
                           String email,
                           String ip,
                           String ua) {
        save(eventType, userId, email, ip, ua, true, null, null);
    }

    @Async("auditExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logFailure(AuditLog.EventType eventType,
                           String email,
                           String ip,
                           String ua,
                           String reason) {
        save(eventType, null, email, ip, ua, false, reason, null);
    }

    @Async("auditExecutor")
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void logEvent(AuditLog.EventType eventType,
                         UUID userId,
                         String email,
                         String ip,
                         String ua,
                         boolean success,
                         String failureReason,
                         String details) {
        save(eventType, userId, email, ip, ua, success, failureReason, details);
    }

    // Private — never called directly from outside, never called internally from
    // @Async methods. This is a plain helper, not a Spring-managed method.
    private void save(AuditLog.EventType eventType,
                      UUID userId,
                      String email,
                      String ip,
                      String ua,
                      boolean success,
                      String failureReason,
                      String details) {
        try {
            AuditLog entry = AuditLog.builder()
                    .eventType(eventType)
                    .userId(userId)
                    .email(email)
                    .ipAddress(ip)
                    .userAgent(ua)
                    .success(success)
                    .failureReason(failureReason)
                    .details(details)
                    .build();
            auditLogRepository.save(entry);
        } catch (Exception e) {
            // Swallow — audit must NEVER crash the auth flow
            log.error("Audit write failed [event={}, email={}]: {}", eventType, email, e.getMessage());
        }
    }
}
