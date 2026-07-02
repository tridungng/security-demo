package com.bbyoda.security.common.exception;

/**
 * Thrown when a refresh token is missing, revoked, expired, or not in DB.
 * Caught by GlobalExceptionHandler → 401 Unauthorized.
 */
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
