package com.auth_service.auth_service.entity;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
 
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
 
@Entity
@Table(
    name = "users",
    indexes = {
        @Index(name = "idx_users_email", columnList = "email", unique = true)
    }
)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {
 
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(updatable = false, nullable = false)
    private UUID id;
 
    @Column(nullable = false, length = 50)
    private String firstName;
 
    @Column(nullable = false, length = 50)
    private String lastName;
 
    @Column(nullable = false, unique = true, length = 255)
    private String email;
 
    @Column(nullable = false)
    private String passwordHash;   // BCrypt — never raw password
 
    @Column(nullable = false)
    @Builder.Default
    private boolean emailVerified = false;
 
    @Column(nullable = false)
    @Builder.Default
    private boolean mfaEnabled = false;
 
    @Column(nullable = false)
    @Builder.Default
    private boolean accountLocked = false;
 
    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;
 
    @Column(nullable = false)
    @Builder.Default
    private int failedLoginAttempts = 0;
 
    private Instant lockedUntil;
    private Instant lastLoginAt;
 
    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;
 
    @UpdateTimestamp
    @Column(nullable = false)
    private Instant updatedAt;
 
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
 
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<RefreshToken> refreshTokens = new HashSet<>();
 
    // Convenience: full name
    public String getFullName() {
        return firstName + " " + lastName;
    }
 
    public boolean isAccountNonLocked() {
        if (!accountLocked) return true;
        if (lockedUntil != null && Instant.now().isAfter(lockedUntil)) {
            // Lock period expired — auto-unlock logic lives in service,
            // but this gives a live check without a DB call
            return true;
        }
        return false;
    }
}