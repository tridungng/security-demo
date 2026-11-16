package com.bbyoda.security.authentication.oauth2;

import java.util.Map;

/**
 * Abstract normalization layer over provider-specific OAuth2 user attributes.
 * <p>
 * Every OAuth2 provider returns user info in different shapes:
 *   Google → { "sub": "...", "email": "...", "given_name": "...", "picture": "..." }
 *   GitHub → { "id": 12345, "email": "...", "name": "Alice Smith", "avatar_url": "..." }
 * Concrete subclasses (GoogleOAuth2UserInfo, GitHubOAuth2UserInfo) adapt
 * each provider's attribute map to this common interface so the rest of
 * the application speaks one language.
 * <p>
 * Phase 6: AzureOAuth2UserInfo, CognitoOAuth2UserInfo etc. are added here.
 */
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

    public Map<String, Object> getAttributes() {
        return attributes;
    }
}
