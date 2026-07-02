package com.bbyoda.security.common.exception;

public class EmailAlreadyExistsException extends RuntimeException {
    public EmailAlreadyExistsException(String email) {
        super("Email address is already registered: " + email);
    }
}
