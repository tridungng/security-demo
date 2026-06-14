# Load this policy into OPA before testing Phase 3 OPA endpoints:
#
#   docker run -d -p 8181:8181 --name opa openpolicyagent/opa run --server
#
#   curl -X PUT http://localhost:8181/v1/policies/security \
#     -H "Content-Type: text/plain" \
#     --data-binary @src/main/resources/opa/authz.rego

package security.authz

import future.keywords.in

# Default deny — fail-closed
default allow = false

# Admins can do anything
allow if {
    input.subject.role == "ADMIN"
}

# Users can read their own documents
allow if {
    input.action == "read"
    input.resource.type == "Document"
    input.resource.ownerId == input.subject.userId
}

# Users can read their own reports ONLY during business hours
allow if {
    input.action == "read"
    input.resource.type == "Report"
    input.resource.ownerId == input.subject.userId
    input.environment.hour >= 9
    input.environment.hour < 17
    input.environment.dayOfWeek in {"MONDAY","TUESDAY","WEDNESDAY","THURSDAY","FRIDAY"}
}

# Moderators can read any document (but not write/delete)
allow if {
    input.subject.role == "MODERATOR"
    input.action == "read"
    input.resource.type == "Document"
}