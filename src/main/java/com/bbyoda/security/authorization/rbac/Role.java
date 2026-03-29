package com.bbyoda.security.authorization.rbac;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER(Set.of(Permission.USER_READ, Permission.USER_WRITE, Permission.USER_DELETE));
//    MODERATOR(),
//    ADMIN();

    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>(permissions.stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getAuthority()))
                .toList());

        authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

        return List.copyOf(authorities);
    }
}
