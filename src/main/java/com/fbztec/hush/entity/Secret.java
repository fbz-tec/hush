package com.fbztec.hush.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.hibernate.annotations.ColumnDefault;

import java.time.Instant;

@Entity
@Table(name = "secrets")
public class Secret {
    @Id
    @Size(max = 64)
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @NotNull
    @Column(name = "secret_ciphertext", nullable = false, length = Integer.MAX_VALUE)
    private String secretCiphertext;

    @NotNull
    @ColumnDefault("1")
    @Column(name = "key_version", nullable = false)
    private Integer keyVersion;

    @NotNull
    @ColumnDefault("now()")
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @NotNull
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revealed_at")
    private Instant revealedAt;

    @Size(max = 60)
    @Column(name = "passphrase_hash", length = 60)
    private String passphraseHash;

    @NotNull
    @ColumnDefault("0")
    @Column(name = "failed_attempts", nullable = false)
    private Integer failedAttempts = 0;

    public String getPassphraseHash() {
        return passphraseHash;
    }

    public void setPassphraseHash(String passphraseHash) {
        this.passphraseHash = passphraseHash;
    }

    public int getFailedAttempts() {
        return failedAttempts;
    }

    public void setFailedAttempts(int failedAttempts) {
        this.failedAttempts = failedAttempts;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getSecretCiphertext() {
        return secretCiphertext;
    }

    public void setSecretCiphertext(String secretCiphertext) {
        this.secretCiphertext = secretCiphertext;
    }

    public Integer getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(Integer keyVersion) {
        this.keyVersion = keyVersion;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getRevealedAt() {
        return revealedAt;
    }

    public void setRevealedAt(Instant revealedAt) {
        this.revealedAt = revealedAt;
    }

}