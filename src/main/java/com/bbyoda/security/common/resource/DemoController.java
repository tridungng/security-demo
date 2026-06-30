package com.bbyoda.security.common.resource;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.bbyoda.security.authorization.abac.AbacPolicy;
import com.bbyoda.security.authorization.abac.AbacService;
import com.bbyoda.security.authorization.abac.AttributeContext;
import com.bbyoda.security.authorization.opa.OpaClient;
import com.bbyoda.security.common.dto.AuthDtos.UserProfileResponse;
import com.bbyoda.security.user.User;
import com.bbyoda.security.user.UserRepository;

/**
 * Demo endpoints covering all security layers: Phase 1-4.
 * <p>
 * Test matrix:
 * <p>
 *   GET  /demo/public                          → no token
 *   GET  /demo/protected                       → any valid token
 *   GET  /demo/admin-only                      → ROLE_ADMIN
 *   GET  /demo/permission                      → admin:read authority (MODERATOR or ADMIN)
 * <p>
 *   GET  /demo/abac/document/{id}              → ABAC: owner or admin
 *   GET  /demo/abac/document/{id}/business     → ABAC: owner + business hours
 *   GET  /demo/abac/department/{dept}          → ABAC: same department
 *   GET  /demo/abac/hasPermission/{id}         → uses hasPermission() SpEL
 * <p>
 *   GET  /demo/opa/document/{id}               → OPA policy decision
 * <p>
 *   GET  /users/me                             → own profile
 *   GET  /users                                → ADMIN: all users
 */
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class DemoController {

    private final UserRepository userRepository;
    private final AbacService abacService;
    private final OpaClient opaClient;

    // ── In-memory document store for ABAC demo ─────────────────────────────
    // In a real app this would be a JPA repository with an owner FK.

    @Getter
    @Builder
    public static class Document {
        private final Long id;
        private final String title;
        private final Long ownerId;
        private final String department;
    }

    private static final Map<Long, Document> DOCUMENTS = new ConcurrentHashMap<>(Map.of(
            1L,
                    Document.builder()
                            .id(1L)
                            .title("User's Personal Report")
                            .ownerId(1L)
                            .department("GENERAL")
                            .build(),
            2L,
                    Document.builder()
                            .id(2L)
                            .title("Admin's Policy Document")
                            .ownerId(3L)
                            .department("IT")
                            .build(),
            3L,
                    Document.builder()
                            .id(3L)
                            .title("Shared Team Document")
                            .ownerId(2L)
                            .department("OPERATIONS")
                            .build()));

    // ── Phase 1/2: Basic auth endpoints ───────────────────────────────────

    @GetMapping("/demo/public")
    public ResponseEntity<Map<String, String>> publicEndpoint() {
        return ResponseEntity.ok(Map.of(
                "message", "Public — no auth required",
                "phases", "1 + 2 + 3 + 4 active"));
    }

    @GetMapping("/demo/protected")
    public ResponseEntity<Map<String, Object>> protectedEndpoint(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "message", "Authenticated",
                "user", user.getEmail(),
                "role", user.getRole(),
                //                "provider", user.getAuthProvider(), // Phase 4: shows LOCAL/GOOGLE/GITHUB
                "authorities",
                        user.getAuthorities().stream()
                                .map(GrantedAuthority::getAuthority)
                                .toList()));
    }

    @GetMapping("/demo/admin-only")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> adminOnly(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of("message", "ROLE_ADMIN confirmed", "user", user.getEmail()));
    }

    @GetMapping("/demo/permission")
    @PreAuthorize("hasAuthority('admin:read')")
    public ResponseEntity<Map<String, String>> permissionBased(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "message",
                "'admin:read' permission confirmed — MODERATOR or ADMIN",
                "role",
                user.getRole().name()));
    }

    // ── Phase 3: ABAC endpoints ────────────────────────────────────────────

    /**
     * ABAC: OWNER_OR_ADMIN policy.
     * User can read their own documents; admin can read any.
     * <p>
     * Uses AbacService directly — appropriate when you need the full
     * AttributeContext (e.g. the document's department) for the decision.
     */
    @GetMapping("/demo/abac/document/{id}")
    public ResponseEntity<?> getDocumentAbac(@PathVariable Long id, @AuthenticationPrincipal User user) {
        Document doc = DOCUMENTS.get(id);
        if (doc == null) return ResponseEntity.notFound().build();

        AttributeContext ctx = AttributeContext.builder()
                .subject(user)
                .resourceType("Document")
                .resourceId(id)
                .resourceOwnerId(doc.getOwnerId())
                .resourceDepartment(doc.getDepartment())
                .action("read")
                .build();

        if (!abacService.evaluate(ctx, AbacPolicy.OWNER_OR_ADMIN)) {
            return ResponseEntity.status(403)
                    .body(Map.of("error", "Access denied", "policy", AbacPolicy.OWNER_OR_ADMIN.getDescription()));
        }

        return ResponseEntity.ok(
                Map.of("document", doc, "accessedBy", user.getEmail(), "policyUsed", "OWNER_OR_ADMIN"));
    }

    /**
     * ABAC: OWNER_OR_ADMIN + BUSINESS_HOURS_ONLY (AND composition).
     * Demonstrates allOf() — both policies must pass.
     */
    @GetMapping("/demo/abac/document/{id}/business")
    public ResponseEntity<?> getDocumentBusinessHours(@PathVariable Long id, @AuthenticationPrincipal User user) {
        Document doc = DOCUMENTS.get(id);
        if (doc == null) return ResponseEntity.notFound().build();

        AttributeContext ctx = AttributeContext.builder()
                .subject(user)
                .resourceType("Document")
                .resourceId(id)
                .resourceOwnerId(doc.getOwnerId())
                .action("read")
                .build();

        if (!abacService.allOf(ctx, AbacPolicy.OWNER_OR_ADMIN, AbacPolicy.BUSINESS_HOURS_ONLY)) {
            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error", "Access denied",
                            "policy", "OWNER_OR_ADMIN AND BUSINESS_HOURS_ONLY",
                            "hint", "Try during Mon-Fri 09:00-17:00"));
        }

        return ResponseEntity.ok(Map.of("document", doc, "policyUsed", "OWNER_OR_ADMIN + BUSINESS_HOURS_ONLY"));
    }

    /**
     * ABAC: SAME_DEPARTMENT policy via @PreAuthorize SpEL bean reference.
     * Demonstrates calling AbacService directly from @PreAuthorize.
     */
    @GetMapping("/demo/abac/department/{dept}")
    @PreAuthorize("@abacService.isSameDepartment(authentication.principal, #dept)")
    public ResponseEntity<Map<String, String>> departmentAccess(
            @PathVariable String dept, @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(
                Map.of("message", "Department access granted", "department", dept, "user", user.getEmail()));
    }

    /**
     * ABAC: hasPermission() SpEL — uses ResourcePermissionEvaluator.
     * <p>
     * The second param (ownerId) acts as the resource owner reference.
     * ResourcePermissionEvaluator routes "Document"/"read" to AbacService.isOwnerOrAdmin().
     */
    @GetMapping("/demo/abac/hasPermission/{ownerId}")
    @PreAuthorize("hasPermission(#ownerId, 'Document', 'read')")
    public ResponseEntity<Map<String, String>> hasPermissionDemo(
            @PathVariable Long ownerId, @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "message", "hasPermission('Document', 'read') granted",
                "resourceOwner", String.valueOf(ownerId),
                "user", user.getEmail()));
    }

    // ── Phase 3: OPA endpoints ─────────────────────────────────────────────

    /**
     * OPA: delegates the access decision entirely to Open Policy Agent.
     * <p>
     * OPA evaluates the Rego policy (see opa/authz.rego in resources)
     * against the full AttributeContext and returns allow/deny.
     * <p>
     * Try this after loading the sample policy into OPA:
     *   curl -X PUT localhost:8181/v1/policies/security \
     *     --data-binary @src/main/resources/opa/authz.rego
     */
    @GetMapping("/demo/opa/document/{id}")
    public ResponseEntity<?> getDocumentOpa(@PathVariable Long id, @AuthenticationPrincipal User user) {
        Document doc = DOCUMENTS.get(id);
        if (doc == null) return ResponseEntity.notFound().build();

        boolean allowed = opaClient.isAllowed(user, doc.getOwnerId(), "Document", "read");

        if (!allowed) {
            return ResponseEntity.status(403)
                    .body(Map.of(
                            "error", "OPA denied access",
                            "policyPath", "security/authz/allow"));
        }

        return ResponseEntity.ok(Map.of(
                "document", doc,
                "decidedBy", "OPA",
                "policyPath", "security/authz/allow"));
    }

    /**
     * Phase 3: OPA via Spring Security SpEL.
     * <p>
     * Uses a @PreAuthorize SpEL expression that delegates the authorization decision
     * to the OpaClient Spring bean. Keeps the controller method as a one-liner and
     * delegates policy evaluation to Open Policy Agent (OPA).
     * <p>
     * The SpEL forwards the authenticated principal, resource owner id, resource type
     * and action to OpaClient.isAllowed(...).
     */
    @GetMapping("/demo/opa/spel/{ownerId}")
    @PreAuthorize("@opaClient.isAllowed(authentication.principal, #ownerId, 'Document', 'read')")
    public ResponseEntity<Map<String, String>> opaViaSpel(
            @PathVariable Long ownerId, @AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of("message", "OPA allowed via @PreAuthorize SpEL", "user", user.getEmail()));
    }

    // ── User profile ───────────────────────────────────────────────────────

    @GetMapping("/users/me")
    public ResponseEntity<UserProfileResponse> getMyProfile(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(UserProfileResponse.builder()
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
    public ResponseEntity<List<UserProfileResponse>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll().stream()
                .map(u -> UserProfileResponse.builder()
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
