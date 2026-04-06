package com.auth_service.auth_service.security;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth_service.auth_service.util.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Runs once per request. Extracts and validates the JWT from the Authorization header.
 * If valid: populates SecurityContext so @AuthenticationPrincipal works in controllers.
 * If invalid or missing: clears SecurityContext and lets Spring Security return 401.
 *
 * Also injects userId and traceId into MDC so every log line in this request
 * automatically includes those values — critical for production debugging.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String token = extractToken(request);

            if (StringUtils.hasText(token) && jwtUtil.validateToken(token)) {
                String email  = jwtUtil.extractEmail(token);
                UUID userId   = jwtUtil.extractUserId(token);
                List<String> roles = jwtUtil.extractRoles(token);

                // Inject into MDC — appears in every log line for this request
                MDC.put("userId", userId.toString());
                MDC.put("traceId", StringUtils.hasText(request.getHeader("X-Trace-Id"))
                        ? request.getHeader("X-Trace-Id")
                        : UUID.randomUUID().toString());

                var authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .toList();

                var authentication = new UsernamePasswordAuthenticationToken(
                        email, null, authorities);
                authentication.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.debug("Authenticated user: {}", email);
            }

        } catch (Exception e) {
            // Never propagate — Spring Security handles the resulting 401
            log.error("JWT filter error: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        } finally {
            filterChain.doFilter(request, response);
            MDC.clear();  // MUST clear — threads are reused, stale MDC leaks between requests
        }
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(header) && header.startsWith(BEARER_PREFIX)) {
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();
        return path.startsWith("/api/v1/auth/register")
                || path.startsWith("/api/v1/auth/login")
                || path.startsWith("/api/v1/auth/refresh")
                || path.startsWith("/actuator/health");
    }
}
