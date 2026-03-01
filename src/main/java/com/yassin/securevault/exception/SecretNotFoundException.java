package com.yassin.securevault.exception;

public class SecretNotFoundException extends RuntimeException {
    public SecretNotFoundException(Long id) {
        super("Secret not found: " + id);
    }
}
