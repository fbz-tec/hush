package com.fbztec.hush.exception;

import com.fbztec.hush.dto.ErrorResponse;
import com.fbztec.hush.dto.PassphraseErrorResponse;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.dao.PessimisticLockingFailureException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.validation.method.ParameterValidationResult;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException exception,
                                                                  HttpHeaders headers, HttpStatusCode status,
                                                                  WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        List<FieldError> fieldErrors = exception.getBindingResult().getFieldErrors();
        fieldErrors.forEach(fieldError -> errors.put(fieldError.getField(), fieldError.getDefaultMessage()));
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(HandlerMethodValidationException exception,
                                                                            HttpHeaders headers, HttpStatusCode status,
                                                                            WebRequest request) {
        Map<String, String> errors = new HashMap<>();
        List<ParameterValidationResult> parameterValidationResults = exception.getValueResults();
        parameterValidationResults.forEach(parameterValidationResult -> {
            String paramName = parameterValidationResult.getMethodParameter().getParameterName();
            String errorMessages = parameterValidationResult.getResolvableErrors().stream()
                    .map(MessageSourceResolvable::getDefaultMessage)
                    .collect(Collectors.joining(", "));
            errors.put(paramName, errorMessages);
        });
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleExceptionInternal(Exception exception, Object body, HttpHeaders headers,
                                                             HttpStatusCode statusCode, WebRequest request) {
        // framework errors (malformed JSON, 405, bad version...): same shape as ours, reason phrase only so no internals leak
        HttpStatus status = HttpStatus.valueOf(statusCode.value());
        ErrorResponse errorResponseDto = new ErrorResponse(
                request.getDescription(false),
                status,
                status.getReasonPhrase(),
                Instant.now()
        );
        return new ResponseEntity<>(errorResponseDto, headers, status);
    }

    @ExceptionHandler(SecretNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleSecretNotFound(SecretNotFoundException exception, WebRequest request) {
        // unknown, expired and already revealed all end here: same status, same message
        return error(HttpStatus.NOT_FOUND, exception.getMessage(), request);
    }

    @ExceptionHandler(InvalidPassphraseException.class)
    public ResponseEntity<PassphraseErrorResponse> handleInvalidPassphrase(InvalidPassphraseException exception,
                                                                           WebRequest request) {
        HttpStatus status = HttpStatus.FORBIDDEN;
        return new ResponseEntity<>(new PassphraseErrorResponse(request.getDescription(false), status,
                exception.getMessage(), exception.getAttemptsRemaining(), Instant.now()), status);
    }

    @ExceptionHandler(PessimisticLockingFailureException.class)
    public ResponseEntity<ErrorResponse> handleLockTimeout(PessimisticLockingFailureException exception,
                                                           WebRequest request) {
        // lock_timeout hit (concurrent reveals on one id): nothing to tell the caller
        return error(HttpStatus.SERVICE_UNAVAILABLE, HttpStatus.SERVICE_UNAVAILABLE.getReasonPhrase(), request);
    }

    private static ResponseEntity<ErrorResponse> error(HttpStatus status, String message, WebRequest request) {
        return new ResponseEntity<>(
                new ErrorResponse(request.getDescription(false), status, message, Instant.now()), status);
    }
}
