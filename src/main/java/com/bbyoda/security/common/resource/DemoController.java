package com.bbyoda.security.common.resource;

import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import lombok.RequiredArgsConstructor;

import com.bbyoda.security.common.dto.AuthDtos;
import com.bbyoda.security.user.User;
import com.bbyoda.security.user.UserRepository;

@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class DemoController {

    private final UserRepository userRepository;

    @GetMapping("/demo/public")
    public ResponseEntity<Map<String, String>> publicEndpoint() {
        return ResponseEntity.ok(Map.of(
                "message", "Public — no authentication required",
                "phases", "Phase 1 + 2 active"));
    }

    @GetMapping("/demo/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "message", "Authenticated!",
                "user", user.getEmail(),
                "role", user.getRole(),
                "authorities",
                        user.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList()));
    }

    // ── Role-based ─────────────────────────────────────────────────────────

    /**
     * hasRole("ADMIN") → checks for "ROLE_ADMIN" authority.
     * Double-protected: URL rule in SecurityConfig + @PreAuthorize here.
     */
    @GetMapping("/demo/admin-only")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> adminOnly(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of("message", "ROLE_ADMIN confirmed", "user", user.getEmail()));
    }

    @GetMapping("/demo/permission")
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<Map<String, String>> permissionBased(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "message", "'admin:read' permission confirmed (MODERATOR or ADMIN)",
                "user", user.getEmail(),
                "role", user.getRole().name()));
    }

    @GetMapping("/users/me")
    public ResponseEntity<AuthDtos.UserProfileResponse> getMyProfile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(AuthDtos.UserProfileResponse.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .role(user.getRole())
                .enabled(user.isEnabled())
                .accountNonLocked(user.isAccountNonLocked())
                .createdAt(user.getCreatedAt())
                .build());
    }

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuthDtos.UserProfileResponse>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll().stream()
                .map(u -> AuthDtos.UserProfileResponse.builder()
                        .id(u.getId())
                        .firstName(u.getFirstName())
                        .lastName(u.getLastName())
                        .email(u.getEmail())
                        .role(u.getRole())
                        .enabled(u.isEnabled())
                        .accountNonLocked(u.isAccountNonLocked())
                        .createdAt(u.getCreatedAt())
                        .build())
                .toList());
    }
}
