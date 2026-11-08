package com.fbztec.hush.service.impl;

import com.fbztec.hush.exception.CryptoException;
import com.fbztec.hush.service.IEncryptionService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

@Service
public class AesGcmEncryptionService implements IEncryptionService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BYTES = 32;   // AES-256
    private static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits, recommandation NIST
    private static final int GCM_TAG_LENGTH_BITS = 128; // 16 octets d'authentification

    @Value("${hush.encrypt.key}")
    private String encryptionKey;

    private SecretKey secretKey;
    private SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(encryptionKey);
        if (keyBytes.length != KEY_SIZE_BYTES) {
            throw new IllegalStateException("Encryption key must be exactly 32 bytes (AES-256). " +
                    "Got " + keyBytes.length + " bytes. " +
                    "Generate one with: openssl rand -base64 32");
        }
        this.secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        this.secureRandom = new SecureRandom();
    }

    @Override
    public String encrypt(String plaintext) {
        requireNonEmpty(plaintext, "Plaintext to encrypt");
        try {
            return Base64.getEncoder().encodeToString(seal(secretKey, plaintext.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    @Override
    public String decrypt(String encryptedBase64) {
        requireNonEmpty(encryptedBase64, "Ciphertext to decrypt");
        try {
            return new String(open(secretKey, Base64.getDecoder().decode(encryptedBase64)), StandardCharsets.UTF_8);
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Decryption failed (data tampered or wrong key)", e);
        }
    }

    // iv || ciphertext+tag
    private byte[] seal(SecretKey key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        return combined;
    }

    private static byte[] open(SecretKey key, byte[] combined) throws Exception {
        if (combined.length < GCM_IV_LENGTH_BYTES + GCM_TAG_LENGTH_BITS / 8) {
            throw new CryptoException("Ciphertext is too short or corrupted");
        }
        byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH_BYTES);
        byte[] ciphertext = Arrays.copyOfRange(combined, GCM_IV_LENGTH_BYTES, combined.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
        return cipher.doFinal(ciphertext);
    }

    private static void requireNonEmpty(String value, String what) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException(what + " cannot be null or empty");
        }
    }
}
