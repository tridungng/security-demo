package com.bbyoda.security.authorization.opa;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import lombok.extern.slf4j.Slf4j;

import com.bbyoda.security.authorization.abac.AttributeContext;
import org.springframework.web.client.RestClientException;

@Slf4j
@Service("opaClient")
public class OpaClient {

    private final RestClient restClient;
    private String policyPath;
    private boolean failCloseOnError;

    public OpaClient(@Qualifier("opaRestClient") RestClient restClient) {
        this.restClient = restClient;
    }

    public boolean isAllowed(AttributeContext ctx) {
        OpaRequest request = OpaRequest.from(ctx);
        return queryOpa(request);
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
