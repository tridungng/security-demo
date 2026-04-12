package com.bbyoda.security.authorization.rbac;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Permission {
    USER_READ("user:read"),
    USER_WRITE("user:write"),
    USER_DELETE("user:delete"),

    ADMIN_READ("admin:read"),
    ADMIN_WRITE("admin:write"),
    ADMIN_DELETE("admin:delete"),

    AUDIT_READ("audit:read");

    private final String authority;
}
