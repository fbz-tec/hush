package com.fbztec.hush.service;

public interface IEncryptionService {
    String encrypt(String plaintext);
    String decrypt(String encryptedBase64);
}
