package com.bbyoda.security.authentication.oauth2;

import java.util.Map;

public abstract class OAuth2UserInfo {

    protected final Map<String, Object> attributes;

    protected OAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    /**
     * Provider-assigned user identifier.
     *   Google → "sub" claim (stable, never changes)
     *   GitHub → numeric user ID
     */
    public abstract String getProviderId();

    /** User's display name. May need to be split into first/last. */
    public abstract String getName();

    /** Primary email address. */
    public abstract String getEmail();

    /** Profile picture URL. Null if provider doesn't supply one. */
    public abstract String getImageUrl();
}
