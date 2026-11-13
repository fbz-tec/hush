CREATE TABLE secrets (
    id                VARCHAR(64) PRIMARY KEY,
    secret_ciphertext TEXT        NOT NULL,
    key_version       INTEGER     NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at        TIMESTAMPTZ NOT NULL,
    revealed_at       TIMESTAMPTZ,
    -- protected <=> passphrase_hash IS NOT NULL (bcrypt, 60 chars)
    passphrase_hash   VARCHAR(60),
    failed_attempts   INTEGER     NOT NULL DEFAULT 0
);

-- the purge deletes every expired row, revealed ones included
CREATE INDEX idx_secrets_expires_at ON secrets (expires_at);
