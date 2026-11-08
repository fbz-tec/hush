package com.fbztec.hush.dto;

import java.time.Instant;

// no "revealed" flag: a used secret answers like an unknown one (no state oracle)
public record SecretMetadataResponse(
        String secretId,
        Instant createdAt,
        Instant expiresAt,
        boolean passphraseProtected) {
}
