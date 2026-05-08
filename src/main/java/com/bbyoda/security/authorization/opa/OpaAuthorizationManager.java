package com.bbyoda.security.authorization.opa;

import com.bbyoda.security.authorization.abac.AttributeContext;
import com.bbyoda.security.user.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.stereotype.Component;
import org.springframework.security.core.Authentication;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.util.function.Supplier;

@Slf4j
@Component
@RequiredArgsConstructor
public class OpaAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    private final OpaClient opaClient;

    @Override
    public AuthorizationResult authorize(
            Supplier<? extends @Nullable Authentication> authentication, RequestAuthorizationContext requestContext) {

        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }

        HttpServletRequest request = requestContext.getRequest();

        User subject = auth.getPrincipal() instanceof User u ? u : null;

        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceType(extractResourceType(request))
                .resourceId(extractResourceId(request))
                .action(request.getMethod().toLowerCase()) // GET->read, POST->write, DELETE->delete
                .clientIp(request.getRemoteAddr())
                .build();

        boolean allowed = opaClient.isAllowed(ctx);
        log.debug(
                "OpaAuthorizationManager: {} {} → {}",
                request.getMethod(),
                request.getRequestURI(),
                allowed ? "ALLOW" : "DENY");

        return new AuthorizationDecision(allowed);
    }

    private String extractResourceType(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.contains("/documents")) return "Document";
        if (path.contains("/reports")) return "Report";
        if (path.contains("/admin")) return "AdminResource";
        return "Unknown";
    }

    private Long extractResourceId(HttpServletRequest request) {
        try {
            String[] parts = request.getRequestURI().split("/");
            for (int i = parts.length - 1; i >= 0; i--) {
                if (!parts[i].isBlank()) {
                    return Long.parseLong(parts[i]);
                }
            }
        } catch (NumberFormatException ignored) {
        }
        return null;
    }
}
