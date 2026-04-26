package com.bbyoda.security.authorization.abac;

import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.jspecify.annotations.NullMarked;
import java.io.Serializable;

import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.PermissionEvaluator;

import com.bbyoda.security.user.User;
import com.bbyoda.security.authorization.rbac.Role;

@Slf4j
@NullMarked
@Component
@RequiredArgsConstructor
public class ResourcePermissionEvaluator implements PermissionEvaluator {

    private final AbacService abacService;

    @Override
    public boolean hasPermission(
            Authentication authentication, @Nullable Object targetDomainObject, Object permission) {
        if (targetDomainObject == null) return false;

        String type = targetDomainObject.getClass().getSimpleName();

        if (targetDomainObject instanceof OwnedResource owned) {
            return hasPermission(authentication, owned.getOwnerId(), type, permission);
        }

        log.warn("hasPermission called with unrecognised domain object type: {}", type);
        return false;
    }

    @Override
    public boolean hasPermission(
            @Nullable Authentication authentication,
            @Nullable Serializable targetId,
            @Nullable String targetType,
            @Nullable Object permission) {
        if (authentication == null || targetType == null || permission == null) return false;

        if (!(authentication.getPrincipal() instanceof User user)) return false;

        String action = permission.toString().toLowerCase();
        Long resourceId = targetId instanceof Long id ? id : null;

        log.debug(
                "hasPermission check: user={} targetType={} targetId={} action={}",
                user.getEmail(),
                targetType,
                resourceId,
                action);

        return switch (targetType) {

            // Document: owner or admin for read; owner-only or admin for write/delete
            case "Document" ->
                switch (action) {
                    case "read", "write", "delete" -> abacService.isOwnerOrAdmin(user, resourceId);
                    default -> false;
                };

            // Report: restricted to business hours AND owner/admin
            case "Report" ->
                switch (action) {
                    case "read" -> abacService.isOwnerOrAdminDuringBusinessHours(user, resourceId);
                    case "write" -> abacService.isOwnerOrAdmin(user, resourceId);
                    default -> false;
                };

            // Admin resource: ADMIN role only
            case "AdminResource" -> user.getRole() == Role.ADMIN;

            // Unknown type — fail closed
            default -> {
                log.warn("Unknown targetType in hasPermission: {}", targetType);
                yield false;
            }
        };
    }

    public interface OwnedResource {
        Serializable getOwnerId();
    }
}
