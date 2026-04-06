package com.auth_service.auth_service.config;



import com.auth_service.auth_service.entity.Role;
import com.auth_service.auth_service.entity.User;
import com.auth_service.auth_service.repository.RoleRepository;
import com.auth_service.auth_service.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Runs on every startup. Order:
 *   1. Seed all three roles (ROLE_USER, ROLE_ADMIN, ROLE_SERVICE) — skips if already present
 *   2. Seed bootstrap admin user — skips if email already exists
 *
 * The admin user is the only way to log in on a fresh system and then
 * create additional users via the admin API.
 *
 * Credentials (overridable via env vars in production):
 *   email    : admin@authservice.com   (or ADMIN_EMAIL env var)
 *   password : Admin@2026              (or ADMIN_PASSWORD env var)
 *
 * Password is hashed with BCrypt(strength=12) — same as every other user.
 * No SHA-256 involved — BCrypt is the single password hashing standard here.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${admin.email:admin@authservice.com}")
    private String adminEmail;

    @Value("${admin.password:Admin@2026}")
    private String adminPassword;

    @Value("${admin.first-name:Admin}")
    private String adminFirstName;

    @Value("${admin.last-name:User}")
    private String adminLastName;

    @Override
    @Transactional
    public void run(String... args) {
        seedRoles();
        seedAdminUser();
    }

    // ── Step 1: Roles ──────────────────────────────────────────────────────────

    private void seedRoles() {
        Arrays.stream(Role.RoleName.values()).forEach(roleName -> {
            if (roleRepository.findByName(roleName).isEmpty()) {
                roleRepository.save(Role.builder().name(roleName).build());
                log.info("Created role: {}", roleName);
            }
        });
        log.info("Roles ready. Total: {}", roleRepository.count());
    }

    // ── Step 2: Bootstrap admin user ──────────────────────────────────────────

    private void seedAdminUser() {
        String email = adminEmail.toLowerCase().trim();

        if (userRepository.existsByEmail(email)) {
            log.info("Admin user already exists: {} — skipping creation", email);
            return;
        }

        Role adminRole = roleRepository.findByName(Role.RoleName.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalStateException(
                        "ROLE_ADMIN not found — seedRoles() must run before seedAdminUser()"));

        Role userRole = roleRepository.findByName(Role.RoleName.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));

        User admin = User.builder()
                .firstName(adminFirstName)
                .lastName(adminLastName)
                .email(email)
                // BCrypt hash — same as every user in this system
                .passwordHash(passwordEncoder.encode(adminPassword))
                .emailVerified(true)
                .enabled(true)
                .roles(new HashSet<>(Set.of(adminRole, userRole)))
                .build();

        userRepository.save(admin);

        log.info("==========================================================");
        log.info("  Bootstrap admin created successfully");
        log.info("  Email    : {}", email);
        log.info("  Password : {}", adminPassword);
        log.info("  Roles    : ROLE_ADMIN, ROLE_USER");
        log.info("  >>> Change this password after first login! <<<");
        log.info("==========================================================");
    }
}