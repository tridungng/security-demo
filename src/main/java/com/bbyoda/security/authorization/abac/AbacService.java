package com.bbyoda.security.authorization.abac;

import com.bbyoda.security.user.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Slf4j
@Service("abacService")
public class AbacService {

    public boolean isOwnerOrAdmin(User subject, Long ownerId) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceOwnerId(ownerId)
                .action("access")
                .build();
        return evaluate(ctx, AbacPolicy.OWNER_OR_ADMIN);
    }

    public boolean isBusinessHours() {
        AttributeContext ctx =
                AttributeContext.builder().subject(null).action("access").build();
        return evaluate(ctx, AbacPolicy.BUSINESS_HOURS_ONLY);
    }

    public boolean isOwnerOrAdminDuringBusinessHours(User subject, Long ownerId) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceOwnerId(ownerId)
                .action("access")
                .build();

        return allOf(ctx, AbacPolicy.OWNER_OR_ADMIN, AbacPolicy.BUSINESS_HOURS_ONLY);
    }

    public boolean isSameDepartment(User subject, String department) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .subjectDepartment(resolveDepartment(subject))
                .resourceDepartment(department)
                .action("access")
                .build();

        return evaluate(ctx, AbacPolicy.SAME_DEPARTMENT);
    }

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

    public boolean allOf(AttributeContext ctx, AbacPolicy... policies) {
        return Arrays.stream(policies).allMatch(p -> evaluate(ctx, p));
    }

    public boolean anyOf(AttributeContext ctx, AbacPolicy... policies) {
        return Arrays.stream(policies).anyMatch(p -> evaluate(ctx, p));
    }

    private String resolveDepartment(User user) {
        if (user == null) return null;
        return switch (user.getRole()) {
            case ADMIN -> "IT";
            case MODERATOR -> "OPERATIONS";
            case USER -> "GENERAL";
        };
    }
}
