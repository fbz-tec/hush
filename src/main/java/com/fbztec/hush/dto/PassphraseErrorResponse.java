package com.fbztec.hush.dto;

import org.springframework.http.HttpStatus;

import java.time.Instant;

// attemptsRemaining = 0: the secret has just been destroyed
public record PassphraseErrorResponse(
        String apiPath,
        HttpStatus errorCode,
        String errorMessage,
        int attemptsRemaining,
        Instant errorTime
) { }
