package com.bbyoda.security.authorization.opa;

import com.bbyoda.security.user.User;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import lombok.extern.slf4j.Slf4j;

import com.bbyoda.security.authorization.abac.AttributeContext;

@Slf4j
@Service("opaClient")
public class OpaClient {

    private final RestClient restClient;

    @Value("${app.opa.policy-path:/v1/data/security/authz/allow}")
    private String policyPath;

    @Value("${app.opa.fail-closed-on-error:false}")
    private boolean failCloseOnError;

    public OpaClient(@Qualifier("opaRestClient") RestClient restClient) {
        this.restClient = restClient;
    }

    public boolean isAllowed(AttributeContext ctx) {
        OpaRequest request = OpaRequest.from(ctx);
        return queryOpa(request);
    }

    /**
     * Convenience overload for use in {@code @PreAuthorize} expressions.
     * <p>
     * Example:
     * {@code @PreAuthorize("@opaClient.isAllowed(authentication.principal, #ownerId, 'Document', 'read')")}
     */
    public boolean isAllowed(User subject, Long resourceOwnerId, String resourceType, String action) {
        AttributeContext ctx = AttributeContext.builder()
                .subject(subject)
                .resourceType(resourceType)
                .resourceOwnerId(resourceOwnerId)
                .action(action)
                .build();
        return isAllowed(ctx);
    }

    private boolean queryOpa(OpaRequest request) {
        try {
            OpaResponse response =
                    restClient.post().uri(policyPath).body(request).retrieve().body(OpaResponse.class);

            boolean allowed = response != null && response.isAllowed();
            log.info(
                    "OPA decision: path={} input={} → {}",
                    policyPath,
                    request.getInput().getAction(),
                    allowed ? "ALLOW" : "DENY");
            return allowed;
        } catch (RestClientException ex) {
            log.error("OPA unreachable at {}: {}", policyPath, ex.getMessage());
            return !failCloseOnError;
        }
    }
}
