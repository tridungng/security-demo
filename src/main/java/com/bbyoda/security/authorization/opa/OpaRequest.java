package com.bbyoda.security.authorization.opa;

import com.bbyoda.security.authorization.abac.AttributeContext;
import com.bbyoda.security.user.User;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.util.Map;

@Getter
@Builder
public class OpaRequest {

    private final Input input;

    @Getter
    @Builder
    public static class Input {
        private final Subject subject;
        private final Resource resource;
        private final String action;
        private final Environment environment;
        private final Map<String, Object> extras;
    }

    @Getter
    @Builder
    public static class Subject {
        private final Long userId;
        private final String role;
        private final String email;
        private final String department;
    }

    @Getter
    @Builder
    public static class Resource {
        private final String type;
        private final Long id;
        private final Long ownerId;
        private final String department;
        private final int classification;
    }

    @Getter
    @Builder
    public static class Environment {
        private final int hour;
        private final String dayOfWeek;
        private final String clientIp;
    }

    public static OpaRequest from(AttributeContext ctx) {
        User user = ctx.getSubject();
        return OpaRequest.builder()
                .input(Input.builder()
                        .subject(Subject.builder()
                                .userId(user != null ? user.getId() : null)
                                .role(user != null ? user.getRole().name() : null)
                                .email(user != null ? user.getEmail() : null)
                                .department(ctx.getSubjectDepartment())
                                .build())
                        .resource(Resource.builder()
                                .type(ctx.getResourceType())
                                .id(ctx.getResourceId())
                                .ownerId(ctx.getResourceOwnerId())
                                .department(ctx.getResourceDepartment())
                                .classification(ctx.getResourceClassification())
                                .build())
                        .action(ctx.getAction())
                        .environment(Environment.builder()
                                .hour(ctx.getRequestTime().getHour())
                                .dayOfWeek(LocalDate.now().getDayOfWeek().name())
                                .clientIp(ctx.getClientIp())
                                .build())
                        .build())
                .build();
    }
}
