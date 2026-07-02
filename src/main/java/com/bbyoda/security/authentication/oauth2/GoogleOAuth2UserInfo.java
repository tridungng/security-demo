package com.bbyoda.security.authentication.oauth2;

import java.util.Map;

/**
 * Google OIDC user info attribute adapter.
 * <p>
 * Google's ID token / userinfo endpoint returns:
 *   sub          → stable, globally unique user ID (use as providerId)
 *   email        → user's email
 *   given_name   → first name
 *   family_name  → last name
 *   picture      → profile photo URL
 *   email_verified → boolean
 * <p>
 * We use "sub" (not email) as the identifier because:
 *   • sub never changes even if the user changes their email
 *   • email is not globally unique (theoretical edge cases)
 * <p>
 * PKCE note:
 *   Spring Security 6 enables PKCE automatically for public authorization_code
 *   clients. The code_verifier is stored in the OAuth2AuthorizationRequest
 *   (which we persist in a cookie — see HttpCookieOAuth2AuthorizationRequestRepository).
 */
public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }

    /** True if Google has verified this email address. */
    public boolean isEmailVerified() {
        Object verified = attributes.get("email_verified");
        return Boolean.TRUE.equals(verified);
    }
}
