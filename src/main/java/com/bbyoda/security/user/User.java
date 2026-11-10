package com.bbyoda.security.user;

import com.bbyoda.security.authorization.rbac.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;

/**
 * Core identity entity.
 *
 * Phase 4 additions:
 *   authProvider  → LOCAL | GOOGLE | GITHUB
 *   providerId    → OAuth2 provider's user ID (sub claim for OIDC)
 *   imageUrl      → profile picture URL from OAuth2 provider
 *
 * A user can have at most ONE provider. Account linking (same email,
 * multiple providers) is a Phase 4+ feature tracked separately.
 */
@Entity
@Table(
        name = "users",
        indexes = {
            @Index(name = "idx_user_email", columnList = "email", unique = true),
            @Index(name = "idx_user_provider_id", columnList = "providerId")
        })
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String firstName;

    @Column(nullable = false, length = 100)
    private String lastName;

    @Column(nullable = false, unique = true, length = 255)
    private String email;

    /**
     * Nullable for OAuth2 users — they never set a password.
     * LocalAuthService rejects /auth/login for non-LOCAL providers.
     */
    @Column(length = 60)
    private String password;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Role role;

    // ── OAuth2 provider fields (Phase 4) ───────────────────────────────────

    /**
     * How was this account created?
     * Default LOCAL for backward compatibility with Phase 1/2 data.
     */
    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private AuthProvider authProvider = AuthProvider.LOCAL;

    /**
     * Provider-assigned user ID (Google "sub" claim, GitHub user id).
     * Used to find the user on subsequent OAuth2 logins without relying
     * solely on email (email can change on the provider side).
     */
    @Column(length = 255)
    private String providerId;

    /**
     * Profile picture URL from OAuth2 provider.
     * Null for LOCAL users unless they upload a photo separately.
     */
    @Column(length = 512)
    private String imageUrl;

    // ── Account flags ──────────────────────────────────────────────────────

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true;

    @Builder.Default
    @Column(nullable = false)
    private boolean accountNonLocked = true;

    // ── Audit ──────────────────────────────────────────────────────────────

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // ── UserDetails ────────────────────────────────────────────────────────

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return role.getAuthorities();
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    public String getFullName() {
        return firstName + " " + lastName;
    }
}
