package com.fbztec.hush.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

import java.nio.charset.StandardCharsets;
import java.text.Normalizer;

public record CreateSecretRequest(
        @NotBlank
        @Size(max = 10_000)
        String secretText,
        // optional: null falls back to hush.expiration.delay; 1 min to 7 days
        @Min(60)
        @Max(604_800)
        Long ttlSeconds,
        // optional: null or empty = no passphrase; only its bcrypt hash is stored
        @BcryptPassphrase
        String passphrase
) {
    // bcrypt ignores (Spring: rejects) anything past 72 bytes
    public static final int MAX_PASSPHRASE_BYTES = 72;

    // the default record toString would print the secret and the passphrase into any log of this request
    @Override
    public String toString() {
        return "CreateSecretRequest[secretText=***, ttlSeconds=" + ttlSeconds
                + ", passphrase=" + (passphrase == null ? "null" : "***") + "]";
    }

    // "é" typed as one or two code points (macOS vs Windows) must give the same passphrase
    public static String normalizePassphrase(String passphrase) {
        return Normalizer.normalize(passphrase, Normalizer.Form.NFC);
    }

    // measured on what bcrypt actually receives: NFC can shrink or grow the string
    public static boolean fitsBcrypt(String passphrase) {
        return normalizePassphrase(passphrase).getBytes(StandardCharsets.UTF_8).length <= MAX_PASSPHRASE_BYTES;
    }
}
