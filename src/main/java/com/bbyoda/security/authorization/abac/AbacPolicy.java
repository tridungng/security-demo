package com.bbyoda.security.authorization.abac;

import com.bbyoda.security.authorization.rbac.Role;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.DayOfWeek;
import java.time.LocalTime;
import java.util.Set;

@Getter
@RequiredArgsConstructor
public enum AbacPolicy {

    /**
     * OWNER_OR_ADMIN: allow if the subject owns the resource OR is an ADMIN.
     * <p>
     * Classic data isolation rule:
     *   "Users can only see their own data; admins can see everything."
     */
    OWNER_OR_ADMIN("Owner or admin can access") {
        @Override
        public boolean evaluate(AttributeContext ctx) {
            if (ctx.getSubject() == null) return false;

            boolean isAdmin = ctx.getSubject().getRole() == Role.ADMIN;
            boolean isOwner = ctx.getResourceOwnerId() != null
                    && ctx.getResourceOwnerId().equals(ctx.getSubject().getId());

            return isAdmin || isOwner;
        }
    },

    /**
     * BUSINESS_HOURS_ONLY: allow only Monday–Friday, 09:00–17:00.
     * <p>
     * Use case: restrict sensitive report access to working hours.
     * Environment attribute example — decision depends on WHEN, not just WHO.
     */
    BUSINESS_HOURS_ONLY("Access restricted to business hours") {
        private static final LocalTime START = LocalTime.of(9, 0);
        private static final LocalTime END = LocalTime.of(17, 0);
        private static final Set<DayOfWeek> WEEKDAYS =
                Set.of(DayOfWeek.MONDAY, DayOfWeek.TUESDAY, DayOfWeek.WEDNESDAY, DayOfWeek.THURSDAY, DayOfWeek.FRIDAY);

        @Override
        public boolean evaluate(AttributeContext ctx) {
            LocalTime now = ctx.getRequestTime();
            DayOfWeek day = now.atDate(java.time.LocalDate.now()).getDayOfWeek();
            return WEEKDAYS.contains(day) && !now.isBefore(START) && now.isBefore(END);
        }
    },

    /**
     * SAME_DEPARTMENT: allow if subject and resource share the same department.
     * <p>
     * Use case: departmental data isolation (HR can only access HR documents).
     * Subject attribute (department) vs Resource attribute (department).
     */
    SAME_DEPARTMENT("Same department required") {
        @Override
        public boolean evaluate(AttributeContext ctx) {
            if (ctx.getSubject().getRole() == Role.ADMIN) return true;

            String subjectDept = ctx.getSubjectDepartment();
            String resourceDept = ctx.getResourceDepartment();

            if (subjectDept == null || resourceDept == null) return false;
            return subjectDept.equalsIgnoreCase(resourceDept);
        }
    },

    /**
     * SUFFICIENT_CLEARANCE: subject's clearance level must meet or exceed
     * the resource's classification level.
     * <p>
     * Use case: classified document access (government / defense scenarios).
     */
    SUFFICIENT_CLEARANCE("Clearance level insufficient") {
        @Override
        public boolean evaluate(AttributeContext ctx) {
            return ctx.getSubjectClearanceLevel() >= ctx.getResourceClassification();
        }
    },

    /**
     * ADMIN_ONLY: only ADMIN role, regardless of other attributes.
     * Simplest ABAC policy — exists for composability with other policies.
     */
    ADMIN_ONLY("Admin role required") {
        @Override
        public boolean evaluate(AttributeContext ctx) {
            return ctx.getSubject() != null && ctx.getSubject().getRole() == Role.ADMIN;
        }
    };

    private final String description;

    /**
     * Evaluate this policy against the given context.
     *
     * @param ctx all relevant attributes for the access decision
     * @return true = allow, false = deny
     */
    public abstract boolean evaluate(AttributeContext ctx);
}
