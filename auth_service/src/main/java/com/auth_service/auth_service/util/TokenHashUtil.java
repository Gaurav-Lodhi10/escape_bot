package com.auth_service.auth_service.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.springframework.stereotype.Component;

/**
 * Hashes refresh tokens before storing them in the database.
 * If the DB is breached, an attacker gets SHA-256 hashes — useless without the raw tokens.
 *
 * SHA-256 is appropriate here because:
 * - Refresh tokens are already high-entropy UUIDs (not passwords)
 * - We need fast lookup — BCrypt would be too slow for every refresh call
 * - Passwords use BCrypt (in AuthService) — this is only for tokens
 */
@Component
public class TokenHashUtil {

    public String hash(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JVM spec — this branch is unreachable
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
