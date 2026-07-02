package com.bbyoda.security.common.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Centralised exception → HTTP response mapping for all controllers.
 * <p>
 * Uses <a href="https://datatracker.ietf.org/doc/html/rfc7807">RFC 7807 ProblemDetail</a> (native in Spring 6 / Boot 3):
 * {
 *   "type":   "https://security-demo/errors/bad-credentials",
 *   "title":  "Authentication Failed",
 *   "status": 401,
 *   "detail": "Invalid email or password",
 *   "timestamp": "2024-01-01T00:00:00Z"
 * }
 * <p>
 * Security rules:
 *   • BadCredentials always returns the same generic message (prevents user enumeration — never say "email not found")
 *   • Stack traces never included in responses
 *   • Internal errors logged at ERROR; client errors at WARN
 * <p>
 * Lives in common/exception because it handles exceptions from all packages — authentication/, authorization/, user/,
 * etc.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String BASE = "https://security-demo/errors/";

    // ── Validation ─────────────────────────────────────────────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ProblemDetail> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError fe : ex.getBindingResult().getFieldErrors()) {
            errors.put(fe.getField(), fe.getDefaultMessage());
        }
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.BAD_REQUEST);
        pd.setType(URI.create(BASE + "validation-failed"));
        pd.setTitle("Validation Failed");
        pd.setDetail("One or more fields failed validation");
        pd.setProperty("errors", errors);
        pd.setProperty("timestamp", Instant.now());
        log.warn("Validation failed: {}", errors);
        return ResponseEntity.badRequest().body(pd);
    }

    // ── Authentication ─────────────────────────────────────────────────────

    /**
     * Bad username or password.
     * Generic message only — never leaks whether the email exists.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ProblemDetail> handleBadCredentials(BadCredentialsException ex) {
        log.warn("Authentication failed: {}", ex.getMessage());
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.UNAUTHORIZED);
        pd.setType(URI.create(BASE + "bad-credentials"));
        pd.setTitle("Authentication Failed");
        pd.setDetail("Invalid email or password");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(pd);
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ProblemDetail> handleDisabled(DisabledException ex) {
        log.warn("Login attempt on disabled account");
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setType(URI.create(BASE + "account-disabled"));
        pd.setTitle("Account Disabled");
        pd.setDetail("This account has been disabled. Please contact support.");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(pd);
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ProblemDetail> handleLocked(LockedException ex) {
        log.warn("Login attempt on locked account");
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setType(URI.create(BASE + "account-locked"));
        pd.setTitle("Account Locked");
        pd.setDetail("This account is temporarily locked. Please try again later.");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(pd);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ProblemDetail> handleInvalidToken(InvalidTokenException ex) {
        log.warn("Invalid token: {}", ex.getMessage());
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.UNAUTHORIZED);
        pd.setType(URI.create(BASE + "invalid-token"));
        pd.setTitle("Invalid Token");
        pd.setDetail("Token is missing, expired, or has been revoked. Please log in again.");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(pd);
    }

    // ── Authorization ──────────────────────────────────────────────────────

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ProblemDetail> handleAccessDenied(AccessDeniedException ex) {
        log.warn("Access denied: {}", ex.getMessage());
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.FORBIDDEN);
        pd.setType(URI.create(BASE + "access-denied"));
        pd.setTitle("Access Denied");
        pd.setDetail("You do not have permission to access this resource.");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(pd);
    }

    // ── Business logic ─────────────────────────────────────────────────────

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ProblemDetail> handleEmailExists(EmailAlreadyExistsException ex) {
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.CONFLICT);
        pd.setType(URI.create(BASE + "email-exists"));
        pd.setTitle("Email Already Registered");
        pd.setDetail(ex.getMessage());
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(pd);
    }

    // ── Catch-all ──────────────────────────────────────────────────────────

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ProblemDetail> handleGeneric(Exception ex) {
        log.error("Unhandled exception: {}", ex.getMessage(), ex);
        ProblemDetail pd = ProblemDetail.forStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        pd.setType(URI.create(BASE + "internal-error"));
        pd.setTitle("Internal Server Error");
        pd.setDetail("An unexpected error occurred. Please try again later.");
        pd.setProperty("timestamp", Instant.now());
        return ResponseEntity.internalServerError().body(pd);
    }
}
