package com.bbyoda.security.user;

/**
 * Identifies how a User account was created / authenticated.
 * <p>
 * LOCAL     → registered with email + password (Phase 1)
 * GOOGLE    → signed in via Google OAuth2 / OIDC (Phase 4)
 * GITHUB    → signed in via GitHub OAuth2 (Phase 4)
 * <p>
 * Phase 6 additions:
 *   COGNITO, AZURE_AD, GCP_IDENTITY — cloud-managed identities
 * <p>
 * Design note:
 *   A user with provider = GOOGLE has no password in the DB.
 *   If they later try to log in via /auth/login (local), they get a helpful error: "Please sign in with Google".
 *   This avoids the security confusion of allowing password login for accounts that were never given a password.
 */
public enum AuthProvider {
    LOCAL,
    GOOGLE,
    GITHUB,
}
