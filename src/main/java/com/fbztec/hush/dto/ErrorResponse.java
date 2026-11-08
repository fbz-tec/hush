package com.fbztec.hush.dto;

import org.springframework.http.HttpStatus;

import java.time.Instant;

public record ErrorResponse(
        String apiPath,
        HttpStatus errorCode,
        String errorMessage,
        Instant errorTime
) { }
