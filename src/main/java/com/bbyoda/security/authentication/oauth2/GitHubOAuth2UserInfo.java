package com.bbyoda.security.authentication.oauth2;

import java.util.Map;

/**
 * GitHub OAuth2 user attribute adapter.
 * <p>
 * GitHub's /user endpoint returns:
 *   id         → numeric user ID (use as providerId, cast to String)
 *   name       → full display name (may be null for private accounts)
 *   email      → primary email (may be null if user hides it)
 *   avatar_url → profile picture
 *   login      → username handle
 * <p>
 * Email may be null: GitHub lets users hide their email.
 * If email is null, we request it via the separate /user/emails endpoint — Spring Security handles this when scope
 * includes "user:email".
 */
public class GitHubOAuth2UserInfo extends OAuth2UserInfo {

    public GitHubOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getProviderId() {
        Object id = attributes.get("id");
        return id != null ? String.valueOf(id) : null;
    }

    @Override
    public String getName() {
        String name = (String) attributes.get("name");
        return name != null ? name : (String) attributes.get("login");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}
