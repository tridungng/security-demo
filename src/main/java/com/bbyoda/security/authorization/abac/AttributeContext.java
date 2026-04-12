package com.bbyoda.security.authorization.abac;

import com.bbyoda.security.user.User;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalTime;
import java.util.Map;

@Getter
@Builder
public class AttributeContext {
    private final User subject;

    @Builder.Default
    private final int subjectClearanceLevel = 0;

    private final String resourceType;

    private final Long resourceId;

    private final Long resourceOwnerId;

    private final String resourceDepartment;

    @Builder.Default
    private final int resourceClassification = 0;

    private final String action;

    private final LocalTime requestTime = LocalTime.now();

    private final String clientIp;

    @Builder.Default
    private final Map<String, Object> extras = Map.of();
}
