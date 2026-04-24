package ru.mfa.antivirus.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.http.converter.HttpMessageNotReadableException;

import java.time.OffsetDateTime;
import java.util.Map;

@ControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<?> handleNotFound(NotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of(
                        "timestamp", OffsetDateTime.now().toString(),
                        "error", "Not Found",
                        "message", ex.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(error -> error.getField() + ": " + error.getDefaultMessage())
                .orElse("Validation error");

        return ResponseEntity.badRequest().body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Validation error",
                "message", message));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<?> handleIllegalArg(IllegalArgumentException ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Bad Request",
                "message", ex.getMessage()));
    }

    @ExceptionHandler({
            MethodArgumentTypeMismatchException.class,
            HttpMessageNotReadableException.class,
            MissingServletRequestParameterException.class
    })
    public ResponseEntity<?> handleBadRequest(Exception ex) {
        return ResponseEntity.badRequest().body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Bad Request",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<?> handleConflict(ConflictException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Conflict",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(ForbiddenOperationException.class)
    public ResponseEntity<?> handleForbiddenOp(ForbiddenOperationException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Forbidden",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Forbidden",
                "message", "Access denied"));
    }

    @ExceptionHandler({ BadCredentialsException.class, AuthenticationException.class })
    public ResponseEntity<?> handleAuth(AuthenticationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Unauthorized",
                "message", ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "timestamp", OffsetDateTime.now().toString(),
                "error", "Server Error",
                "message", ex.getMessage()));
    }
}
