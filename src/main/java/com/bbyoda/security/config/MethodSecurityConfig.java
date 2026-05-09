package com.bbyoda.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;

import lombok.RequiredArgsConstructor;

import com.bbyoda.security.authorization.abac.ResourcePermissionEvaluator;

@Configuration
@RequiredArgsConstructor
public class MethodSecurityConfig {

    private final ResourcePermissionEvaluator permissionEvaluator;

    @Bean
    static MethodSecurityExpressionHandler methodSecurityExpressionHandler(
            ResourcePermissionEvaluator permissionEvaluator) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setPermissionEvaluator(permissionEvaluator);
        return handler;
    }
}
