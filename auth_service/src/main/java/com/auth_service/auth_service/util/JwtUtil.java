package com.auth_service.auth_service.util;


import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@Component
public class JwtUtil {

    private final SecretKey signingKey;
    private final long accessTokenExpiryMs;
    private final String issuer;

    public JwtUtil(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
            @Value("${jwt.issuer}") String issuer) {

        // BUG FIX: was double-encoding (Base64 encode then Base64 decode = original bytes
        // but with extra whitespace risk). Use raw UTF-8 bytes directly.
        // Keys.hmacShaKeyFor validates the key is >= 256 bits and throws if not.
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
        this.accessTokenExpiryMs = accessTokenExpiryMs;
        this.issuer = issuer;
    }

    /**
     * Generate a signed access token.
     * Claims: sub=email, userId, roles, jti (unique ID used for blacklisting in Phase 2).
     */
    public String generateAccessToken(String email, UUID userId, Set<String> roles) {
        Instant now = Instant.now();
        Instant expiry = now.plusMillis(accessTokenExpiryMs);

        return Jwts.builder()
        .setSubject(email)
        .setIssuer(issuer)
        .setIssuedAt(Date.from(now))
        .setExpiration(Date.from(expiry))
        .setId(UUID.randomUUID().toString())
        .addClaims(Map.of(
                "userId", userId.toString(),
                "roles", roles
        ))
        .signWith(signingKey)
        .compact();
    }

    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.debug("JWT expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("JWT unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("JWT malformed: {}", e.getMessage());
        } catch (SecurityException e) {
            log.warn("JWT signature invalid: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims empty: {}", e.getMessage());
        }
        return false;
    }

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }

    public UUID extractUserId(String token) {
        return UUID.fromString((String) parseClaims(token).get("userId"));
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return (List<String>) parseClaims(token).get("roles");
    }

    public Instant extractExpiry(String token) {
        return extractClaim(token, Claims::getExpiration).toInstant();
    }

    public boolean isTokenExpired(String token) {
        return extractExpiry(token).isBefore(Instant.now());
    }

    public long getAccessTokenExpiryMs() {
        return accessTokenExpiryMs;
    }

    private <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(parseClaims(token));
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
