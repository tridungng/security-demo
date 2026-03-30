package com.bbyoda.security.common;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import jakarta.validation.constraints.NotBlank;

import java.time.LocalDateTime;

public class AuthDtos {

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RegisterRequest {

        @NotBlank(message = "First name is required")
        @Size(min = 1, max = 100, message = "First name must be between 1–100 characters")
        private String firstName;

        @NotBlank(message = "Last name is required")
        @Size(min = 1, max = 100, message = "Last name must be between 1–100 characters")
        private String lastName;

        @NotBlank(message = "Email is required")
        @Email(message = "Must be a valid email address")
        private String email;

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 128, message = "Password must be 8–128 characters")
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginRequest {

        @NotBlank(message = "Email is required")
        @Email(message = "Must be a valid email address")
        private String email;

        @NotBlank(message = "Password is required")
        private String password;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserProfileResponse {
        private Long id;
        private String firstName;
        private String lastName;
        private String email;
        private String role;
        private boolean enabled;
        private boolean accountNonLocked;
        private LocalDateTime createdAt;
    }
}
