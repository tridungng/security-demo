package com.bbyoda.security.authorization.abac;

import com.bbyoda.security.user.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Slf4j
@Service("abacService")
public class AbacService {

    /**
     * Allows access if subject is the owner OR an admin.
     */
    public boolean isOwnerOrAdmin(User subject, Long ownerId) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceOwnerId(ownerId)
                .action("access")
                .build();
        return evaluate(ctx, AbacPolicy.OWNER_OR_ADMIN);
    }

    /**
     * Allows access only during business hours (Mon–Fri, 09:00–17:00).
     */
    public boolean isBusinessHours() {
        AttributeContext ctx =
                AttributeContext.builder().subject(null).action("access").build();
        return evaluate(ctx, AbacPolicy.BUSINESS_HOURS_ONLY);
    }

    /**
     * Combines business-hours check with owner/admin check (AND logic).
     */
    public boolean isOwnerOrAdminDuringBusinessHours(User subject, Long ownerId) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceOwnerId(ownerId)
                .action("access")
                .build();

        return allOf(ctx, AbacPolicy.OWNER_OR_ADMIN, AbacPolicy.BUSINESS_HOURS_ONLY);
    }

    /**
     * Same-department access check.
     */
    public boolean isSameDepartment(User subject, String department) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .subjectDepartment(resolveDepartment(subject))
                .resourceDepartment(department)
                .action("access")
                .build();

        return evaluate(ctx, AbacPolicy.SAME_DEPARTMENT);
    }

    /**
     * Evaluate a single policy against the given context.
     * Logs the decision for audit trail.
     */
    public boolean evaluate(AttributeContext ctx, AbacPolicy policy) {
        boolean result = policy.evaluate(ctx);
        log.debug(
                "ABAC [{}] subject={} resource={}/{} action={} → {}",
                policy.name(),
                ctx.getSubject() != null ? ctx.getSubject().getEmail() : "anonymous",
                ctx.getResourceType(),
                ctx.getResourceId(),
                ctx.getAction(),
                result ? "ALLOW" : "DENY");
        return result;
    }

    /**
     * AND composition - all policies must pass.
     */
    public boolean allOf(AttributeContext ctx, AbacPolicy... policies) {
        return Arrays.stream(policies).allMatch(p -> evaluate(ctx, p));
    }

    /**
     * OR composition - at least one policy must pass.
     */
    public boolean anyOf(AttributeContext ctx, AbacPolicy... policies) {
        return Arrays.stream(policies).anyMatch(p -> evaluate(ctx, p));
    }

    /**
     * Resolves the department for a user.
     */
    private String resolveDepartment(User user) {
        if (user == null) return null;
        return switch (user.getRole()) {
            case ADMIN -> "IT";
            case MODERATOR -> "OPERATIONS";
            case USER -> "GENERAL";
        };
    }
}
