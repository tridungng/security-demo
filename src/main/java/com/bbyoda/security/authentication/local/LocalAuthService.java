package com.bbyoda.security.authentication.local;

import com.bbyoda.security.common.exception.InvalidTokenException;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import com.bbyoda.security.authentication.jwt.JwtService;
import com.bbyoda.security.common.dto.TokenResponse;
import com.bbyoda.security.common.dto.AuthDtos.LoginRequest;
import com.bbyoda.security.common.dto.AuthDtos.RegisterRequest;
import com.bbyoda.security.user.UserRepository;
import com.bbyoda.security.authorization.rbac.Role;
import com.bbyoda.security.user.RefreshToken;
import com.bbyoda.security.user.RefreshTokenRepository;
import com.bbyoda.security.user.User;

@Slf4j
@Service
@RequiredArgsConstructor
public class LocalAuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    @Value("${app.security.jwt-expiration}")
    private long jwtExpirationMs;

    @Value("${app.security.refresh-expiration}")
    private long refreshExpirationMs;

    private static final String REFRESH_COOKIE_NAME = "refresh_token";
    private static final String REFRESH_COOKIE_PATH = "/api/v1/auth";

    // ── Register ───────────────────────────────────────────────────────────

    public TokenResponse register(RegisterRequest request, HttpServletResponse httpResponse) {
        log.info("Registration attempt: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            // throw new Exception
        }

        User user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .enabled(true)
                .accountNonLocked(true)
                .build();

        User saved = userRepository.save(user);
        log.info("User registered: id={}", saved.getId());

        return issueTokens(saved, httpResponse, null, null);
    }

    // ── Login ──────────────────────────────────────────────────────────────

    public TokenResponse login(LoginRequest request, HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        log.info("Login attempt: {}", request.getEmail());

        Authentication auth = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getEmail().toLowerCase().trim(), request.getPassword()));

        User user = (User) auth.getPrincipal();
        String ip = extractClientIp(httpRequest);
        String agent = httpRequest.getHeader("User-Agent");

        return issueTokens(user, httpResponse, agent, ip);
    }

    // ── Refresh ────────────────────────────────────────────────────────────

    @Transactional
    public TokenResponse refreshAccessToken(HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        String rawToken = extractRefreshCookie(httpRequest)
                .orElseThrow(() -> new InvalidTokenException("No refresh token cookie present"));

        String tokenHash = jwtService.hashToken(rawToken);

        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHash).orElseThrow(() -> {
            log.warn("Refresh token not found — possible replay attack");
            return new InvalidTokenException("Invalid refresh token");
        });

        if (!stored.isValid()) {
            log.warn(
                    "Revoked/expired refresh token: userId={}", stored.getUser().getId());
            refreshTokenRepository.revokeAllForUser(stored.getUser());
            throw new InvalidTokenException("Refresh token revoked or expired. Please log in again.");
        }

        User user = stored.getUser();
        refreshTokenRepository.deleteByTokenHash(tokenHash);

        return issueTokens(user, httpResponse, httpRequest.getHeader("User-Agent"), extractClientIp(httpRequest));
    }

    // ── Logout ─────────────────────────────────────────────────────────────

    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        extractRefreshCookie(request).ifPresent(raw -> {
            refreshTokenRepository.deleteByTokenHash(jwtService.hashToken(raw));
            log.info("Refresh token revoked on logout");
        });
        clearRefreshCookie(response);
    }

    @Transactional
    public void logoutAll(User currentUser, HttpServletResponse response) {
        refreshTokenRepository.revokeAllForUser(currentUser);
        clearRefreshCookie(response);
        log.info("All sessions revoked for userId={}", currentUser.getId());
    }

    private TokenResponse issueTokens(User user, HttpServletResponse response, String userAgent, String clientIp) {
        String accessToken = jwtService.generateAccessToken(user);
        String rawRefresh = jwtService.generateRefreshTokenValue();

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(jwtService.hashToken(rawRefresh))
                .user(user)
                .expiresAt(Instant.now().plusMillis(refreshExpirationMs))
                .revoked(false)
                .userAgent(userAgent)
                .issuedFromIp(clientIp)
                .build();

        refreshTokenRepository.save(refreshToken);
        setRefreshCookie(response, rawRefresh);

        return TokenResponse.builder()
                .token(accessToken)
                .expiresIn(jwtExpirationMs / 1000)
                .userId(user.getId())
                .email(user.getEmail())
                .fullName(user.getFirstName() + " " + user.getLastName())
                .role(user.getRole())
                .build();
    }

    private void setRefreshCookie(HttpServletResponse response, String rawToken) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, rawToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(Duration.ofMillis(refreshExpirationMs))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(Duration.ZERO)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private Optional<String> extractRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return Optional.empty();
        return Arrays.stream(request.getCookies())
                .filter(c -> REFRESH_COOKIE_NAME.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst();
    }

    private String extractClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) return realIp;
        return request.getRemoteAddr();
    }
}
