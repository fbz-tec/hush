package com.fbztec.hush.dto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

// records print every component by default: a DEBUG log of a request must not leak its content
class RequestToStringTest {

    @Test
    void createRequestHidesSecretAndPassphrase() {
        String text = new CreateSecretRequest("top-secret-text", 3600L, "my-passphrase").toString();
        assertThat(text).doesNotContain("top-secret-text").doesNotContain("my-passphrase").contains("3600");
    }

    @Test
    void revealRequestHidesPassphrase() {
        assertThat(new RevealRequest("my-passphrase").toString()).doesNotContain("my-passphrase");
    }
}
