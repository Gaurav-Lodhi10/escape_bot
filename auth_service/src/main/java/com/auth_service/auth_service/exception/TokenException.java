package com.auth_service.auth_service.exception;

public class TokenException extends RuntimeException {
    public TokenException(String message) {
        super(message);
    }
}
