package com.fbztec.hush.controller;

import com.fbztec.hush.dto.RevealResponse;
import com.fbztec.hush.dto.SecretMetadataResponse;
import com.fbztec.hush.exception.InvalidPassphraseException;
import com.fbztec.hush.exception.SecretNotFoundException;
import com.fbztec.hush.service.ISecretService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.hamcrest.Matchers.endsWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(SecretController.class)
class SecretControllerTest {

    @Autowired
    MockMvc mvc;

    @MockitoBean
    ISecretService service;

    @Test
    void createReturns201WithLocation() throws Exception {
        given(service.createSecret(any()))
                .willReturn(new SecretMetadataResponse("abc", Instant.now(), Instant.now(), false));

        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content("{\"secretText\":\"hi\"}"))
                .andExpect(status().isCreated())
                .andExpect(header().string("Location", endsWith("/api/secrets/abc")))
                .andExpect(jsonPath("$.secretId").value("abc"));
    }

    @Test
    void validationErrorKeepsFieldMapShape() throws Exception {
        // app.js reads this map to show errors next to each field
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content("{\"secretText\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.secretText").exists());
    }

    @Test
    void hugeBodyIsRejectedByTheParserNotAfterIt() throws Exception {
        // the ErrorResponse shape (not the @Size field map) proves Jackson stopped reading early
        String body = "{\"secretText\":\"" + "a".repeat(50_000) + "\"}";
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("400 BAD_REQUEST"));
    }

    @Test
    void passphraseOver72BytesIs400() throws Exception {
        // 37 chars but 74 bytes in UTF-8: bcrypt counts bytes
        String body = "{\"secretText\":\"hi\",\"passphrase\":\"" + "é".repeat(37) + "\"}";
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.passphrase").value("must be at most 72 bytes, without line breaks"));
    }

    @Test
    void byteLimitIsMeasuredAfterNfcNormalization() throws Exception {
        given(service.createSecret(any()))
                .willReturn(new SecretMetadataResponse("abc", Instant.now(), Instant.now(), true));
        // 24 x "e + combining acute" = 72 bytes raw... x25 = 75 raw, but NFC "é" x25 = 50 bytes: accepted
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretText\":\"hi\",\"passphrase\":\"" + "é".repeat(25) + "\"}"))
                .andExpect(status().isCreated());
        // U+0958 is 3 bytes but NFC expands it to 6: 24 x = 72 raw, 144 normalized: rejected, not a 500
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretText\":\"hi\",\"passphrase\":\"" + "क़".repeat(24) + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.passphrase").value("must be at most 72 bytes, without line breaks"));
    }

    @Test
    void lineBreakInPassphraseIs400() throws Exception {
        // a password field drops line breaks: such a passphrase could never be typed in the UI
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"secretText\":\"hi\",\"passphrase\":\"two\\nlines\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.passphrase").exists());
    }

    @Test
    void longRevealPassphraseReachesTheServiceAsAWrongAttempt() throws Exception {
        String longPassphrase = "a".repeat(300);
        given(service.revealSecret("abc", longPassphrase)).willThrow(new InvalidPassphraseException(4));

        mvc.perform(post("/api/secrets/abc/reveal").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"passphrase\":\"" + longPassphrase + "\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.attemptsRemaining").value(4));
    }

    @Test
    void passphraseOf72AsciiBytesIsAccepted() throws Exception {
        given(service.createSecret(any()))
                .willReturn(new SecretMetadataResponse("abc", Instant.now(), Instant.now(), true));
        String body = "{\"secretText\":\"hi\",\"passphrase\":\"" + "a".repeat(72) + "\"}";
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated());
    }

    @Test
    void wrongPassphraseReturns403WithAttemptsRemaining() throws Exception {
        given(service.revealSecret("abc", "nope")).willThrow(new InvalidPassphraseException(3));

        mvc.perform(post("/api/secrets/abc/reveal").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"passphrase\":\"nope\"}"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.attemptsRemaining").value(3))
                .andExpect(jsonPath("$.errorMessage").value("Incorrect passphrase"));
    }

    @Test
    void revealWithoutBodyPassesNullPassphrase() throws Exception {
        given(service.revealSecret("abc", null)).willReturn(new RevealResponse("hi"));

        mvc.perform(post("/api/secrets/abc/reveal"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secretText").value("hi"));
        verify(service).revealSecret("abc", null);
    }

    @Test
    void revealPassesPassphraseFromBody() throws Exception {
        given(service.revealSecret("abc", "pass")).willReturn(new RevealResponse("hi"));

        mvc.perform(post("/api/secrets/abc/reveal").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"passphrase\":\"pass\"}"))
                .andExpect(status().isOk());
        verify(service).revealSecret("abc", "pass");
    }

    @Test
    void malformedJsonUsesErrorResponse() throws Exception {
        mvc.perform(post("/api/secrets").contentType(MediaType.APPLICATION_JSON).content("{bad"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("400 BAD_REQUEST"))
                .andExpect(jsonPath("$.errorMessage").value("Bad Request"));
    }

    @Test
    void unavailableSecretReturns404WithoutLeakingTheId() throws Exception {
        given(service.getSecretMetaData("nope"))
                .willThrow(new SecretNotFoundException("Secret not found or no longer available"));

        mvc.perform(get("/api/secrets/nope"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.errorCode").value("404 NOT_FOUND"))
                .andExpect(jsonPath("$.errorMessage").value("Secret not found or no longer available"));
    }
}
