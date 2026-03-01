package com.yassin.securevault.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.dao.DataIntegrityViolationException;
import java.time.Instant;


@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(SecretNotFoundException.class)
    public ResponseEntity<ApiError> handleSecretNotFound(SecretNotFoundException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(
                new ApiError(Instant.now(), 404, "Not Found", ex.getMessage(), req.getRequestURI())
        );
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiError> handleInvalidCredentials(InvalidCredentialsException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                new ApiError(Instant.now(), 401, "Unauthorized", ex.getMessage(), req.getRequestURI())
        );
    }

    @ExceptionHandler(EmailAlreadyUsedException.class)
    public ResponseEntity<ApiError> handleEmailExists(EmailAlreadyUsedException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                new ApiError(Instant.now(), 409, "Conflict", ex.getMessage(), req.getRequestURI())
        );
    }
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ApiError> handleConstraint(DataIntegrityViolationException ex, HttpServletRequest req) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(
                new ApiError(Instant.now(), 409, "Conflict", "Email already in use", req.getRequestURI())
        );
    }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, HttpServletRequest req) {
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .reduce((a, b) -> a + "; " + b)
                .orElse("Validation failed");

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                new ApiError(Instant.now(), 400, "Bad Request", msg, req.getRequestURI())
        );
    }
}