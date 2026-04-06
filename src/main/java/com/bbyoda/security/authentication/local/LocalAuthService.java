package com.bbyoda.security.authentication.local;

import com.bbyoda.security.common.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import com.bbyoda.security.authentication.jwt.JwtService;
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
        String cookie = String.format(
                "%s=%s; Max-Age=%d; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Strict",
                REFRESH_COOKIE_NAME, rawToken, refreshExpirationMs / 1000);
        response.addHeader("Set-Cookie", cookie);
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        String cookie = String.format(
                "%s=; Max-Age=0; Path=/api/v1/auth; HttpOnly; Secure; SameSite=Strict", REFRESH_COOKIE_NAME);
        response.addHeader("Set-Cookie", cookie);
    }
}
