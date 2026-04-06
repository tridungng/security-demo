package com.bbyoda.security.common.dto;

import com.bbyoda.security.authorization.rbac.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenResponse {
    private String token;

    @Builder.Default
    private String tokenType = "Bearer";

    private long expiresIn;

    private Long userId;
    private String email;
    private String fullName;
    private Role role;
}
