package com.bbyoda.security.authentication.local;

import com.bbyoda.security.common.dto.AuthDtos;
import com.bbyoda.security.common.dto.TokenResponse;
import com.bbyoda.security.user.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class LocalAuthController {

    private final LocalAuthService authService;

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> registerUser(
            @Valid @RequestBody AuthDtos.RegisterRequest request, HttpServletResponse response) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request, response));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(
            @Valid @RequestBody AuthDtos.LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        return ResponseEntity.ok().body(authService.login(request, httpRequest, httpResponse));
    }

    /**
     * POST /api/v1/auth/refresh
     * Browser auto-sends the HttpOnly cookie — no request body needed.
     * Returns: new access token in body, rotated refresh cookie.
     * 200 OK on success, 401 if token missing/invalid/expired.
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(HttpServletRequest request, HttpServletResponse response) {
        return ResponseEntity.ok(authService.refreshAccessToken(request, response));
    }

    /**
     * POST /api/v1/auth/logout
     * Revokes this device's refresh token. Access token expires naturally.
     * 204 No Content.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request, HttpServletResponse response) {
        authService.logout(request, response);
        return ResponseEntity.noContent().build();
    }

    /**
     * POST /api/v1/auth/logout-all
     * Revokes every refresh token for this user (all devices).
     * Requires valid access token — so user must be authenticated.
     * 204 No Content.
     */
    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal User currentUser, HttpServletResponse response) {
        authService.logoutAll(currentUser, response);
        return ResponseEntity.noContent().build();
    }
}
