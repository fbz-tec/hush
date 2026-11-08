package com.fbztec.hush.service.impl;

import com.fbztec.hush.exception.CryptoException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AesGcmEncryptionServiceTest {

    private final AesGcmEncryptionService service = new AesGcmEncryptionService();

    @BeforeEach
    void setUp() {
        // test-only key, never used outside tests
        ReflectionTestUtils.setField(service, "encryptionKey", "TZa2RxVgat2GN8+O4W88p2LByMR/jF70fSiYaSuqu+k=");
        service.init();
    }

    @Test
    void decryptReturnsOriginalText() {
        String text = "mot de passe: é@ü 🔑";
        assertThat(service.decrypt(service.encrypt(text))).isEqualTo(text);
    }

    @Test
    void sameTextEncryptsDifferentlyEachTime() {
        assertThat(service.encrypt("same")).isNotEqualTo(service.encrypt("same"));
    }

    @Test
    void tamperedCiphertextIsRejected() {
        byte[] bytes = Base64.getDecoder().decode(service.encrypt("secret"));
        bytes[bytes.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(bytes);

        assertThatThrownBy(() -> service.decrypt(tampered)).isInstanceOf(CryptoException.class);
    }
}
