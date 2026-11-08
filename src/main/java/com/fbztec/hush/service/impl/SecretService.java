package com.fbztec.hush.service.impl;

import com.fbztec.hush.dto.CreateSecretRequest;
import com.fbztec.hush.dto.RevealResponse;
import com.fbztec.hush.dto.SecretMetadataResponse;
import com.fbztec.hush.entity.Secret;
import com.fbztec.hush.exception.InvalidPassphraseException;
import com.fbztec.hush.exception.SecretNotFoundException;
import com.fbztec.hush.repository.SecretRepository;
import com.fbztec.hush.service.IEncryptionService;
import com.fbztec.hush.service.ISecretService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@Transactional(readOnly = true)
public class SecretService implements ISecretService {

    private static final Logger log = LoggerFactory.getLogger(SecretService.class);
    // same message whatever the reason: unknown, expired and already revealed must look identical
    private static final String UNAVAILABLE = "Secret not found or no longer available";
    static final int MAX_ATTEMPTS = 5;

    private final SecretRepository secretRepository;
    private final IEncryptionService encryptionService;
    private final PasswordEncoder passwordEncoder;

    @Value("${hush.expiration.delay}")
    private Duration expirationDelay;

    public SecretService(SecretRepository secretRepository,
                         IEncryptionService encryptionService,
                         PasswordEncoder passwordEncoder) {
        this.encryptionService = encryptionService;
        this.secretRepository = secretRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Transactional
    @Override
    public SecretMetadataResponse createSecret(CreateSecretRequest createSecretRequest) {
        Secret secret = new Secret();
        // the ID is the only access check: it must be unguessable (122 random bits)
        secret.setId(UUID.randomUUID().toString().replace("-", ""));
        secret.setSecretCiphertext(encryptionService.encrypt(createSecretRequest.secretText()));
        secret.setKeyVersion(1);
        // Postgres stores microseconds: truncate so POST and GET return the same instant
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
        secret.setCreatedAt(now);
        Duration ttl = createSecretRequest.ttlSeconds() == null
                ? expirationDelay
                : Duration.ofSeconds(createSecretRequest.ttlSeconds());
        secret.setExpiresAt(now.plus(ttl));
        String passphrase = createSecretRequest.passphrase();
        if (passphrase != null && !passphrase.isEmpty()) {
            secret.setPassphraseHash(passwordEncoder.encode(CreateSecretRequest.normalizePassphrase(passphrase)));
        }

        secret = secretRepository.save(secret);
        log.info("Secret created: id={}", shortId(secret.getId()));
        return new SecretMetadataResponse(secret.getId(),
                secret.getCreatedAt(),
                secret.getExpiresAt(),
                secret.getPassphraseHash() != null);
    }

    @Override
    public SecretMetadataResponse getSecretMetaData(String secretId) {
        Secret secret = secretRepository.findById(secretId).orElse(null);
        if (secret == null || !isAvailable(secret)) {
            throw unavailable("meta", secretId, secret);
        }
        return new SecretMetadataResponse(secret.getId(),
                secret.getCreatedAt(),
                secret.getExpiresAt(),
                secret.getPassphraseHash() != null);
    }

    // a wrong passphrase must still commit the attempt counter (and the burn on the last one)
    @Transactional(noRollbackFor = InvalidPassphraseException.class)
    @Override
    public RevealResponse revealSecret(String secretId, String passphrase) {
        // dead ids are rejected before taking the row lock: spamming them cannot queue writers
        if (!secretRepository.existsByIdAndRevealedAtIsNullAndExpiresAtAfter(secretId, Instant.now())) {
            throw unavailable("reveal", secretId, secretRepository.findById(secretId).orElse(null));
        }

        Secret secret = secretRepository.findLockedById(secretId).orElse(null);
        // re-check under the lock: a concurrent reveal may have won in between
        if (secret == null || !isAvailable(secret)) {
            throw unavailable("reveal", secretId, secret);
        }
        if (secret.getPassphraseHash() != null) {
            checkPassphrase(secret, passphrase);
        }

        String secretText = encryptionService.decrypt(secret.getSecretCiphertext());
        burn(secret);
        log.info("Secret revealed: id={}", shortId(secretId));
        return new RevealResponse(secretText);
    }

    // runs under the row lock: concurrent attempts are counted one by one
    private void checkPassphrase(Secret secret, String passphrase) {
        if (passphrase == null || passphrase.isEmpty()) {
            throw new InvalidPassphraseException(MAX_ATTEMPTS - secret.getFailedAttempts());
        }
        // over 72 bytes can never match (and would make bcrypt throw): just a wrong attempt
        boolean matches = CreateSecretRequest.fitsBcrypt(passphrase)
                && passwordEncoder.matches(CreateSecretRequest.normalizePassphrase(passphrase), secret.getPassphraseHash());
        if (matches) {
            return;
        }
        int attempts = secret.getFailedAttempts() + 1;
        secret.setFailedAttempts(attempts);
        if (attempts >= MAX_ATTEMPTS) {
            burn(secret);
            log.warn("Secret destroyed after too many attempts: id={}", shortId(secret.getId()));
        }
        throw new InvalidPassphraseException(MAX_ATTEMPTS - attempts);
    }

    // burn after reading: the ciphertext is wiped on commit, only metadata stays
    private static void burn(Secret secret) {
        secret.setRevealedAt(Instant.now());
        secret.setSecretCiphertext("");
        secret.setPassphraseHash(null);
    }

    private static boolean isAvailable(Secret secret) {
        return secret.getRevealedAt() == null && secret.getExpiresAt().isAfter(Instant.now());
    }

    // the real reason only goes to the log, never to the caller
    private static SecretNotFoundException unavailable(String operation, String secretId, Secret secret) {
        String reason = secret == null ? "unknown" : secret.getRevealedAt() != null ? "revealed" : "expired";
        log.warn("Secret unavailable: op={} id={} reason={}", operation, shortId(secretId), reason);
        return new SecretNotFoundException(UNAVAILABLE);
    }

    // a full id is as good as the secret itself while unread: never log more than 6 chars (and no control chars)
    private static String shortId(String secretId) {
        String head = secretId.length() > 6 ? secretId.substring(0, 6) : secretId;
        return head.replaceAll("[^A-Za-z0-9-]", "_");
    }
}
