package com.bbyoda.security.authorization.rbac;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Permission {
    USER_READ("user:read"),
    USER_WRITE("user:write"),
    USER_DELETE("user:delete");

    private final String authority;
}
