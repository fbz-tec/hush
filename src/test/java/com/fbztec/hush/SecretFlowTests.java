package com.fbztec.hush;

import com.fbztec.hush.dto.CreateSecretRequest;
import com.fbztec.hush.dto.SecretMetadataResponse;
import com.fbztec.hush.entity.Secret;
import com.fbztec.hush.exception.InvalidPassphraseException;
import com.fbztec.hush.exception.SecretNotFoundException;
import com.fbztec.hush.repository.SecretRepository;
import com.fbztec.hush.service.ISecretService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

// real Postgres in Docker: also checks the Flyway schema matches the entity (ddl-auto=validate)
@SpringBootTest(properties = "hush.encrypt.key=TZa2RxVgat2GN8+O4W88p2LByMR/jF70fSiYaSuqu+k=")
class SecretFlowTests {

    @TestConfiguration(proxyBeanMethods = false)
    static class Postgres {
        @Bean
        @ServiceConnection
        PostgreSQLContainer postgres() {
            return new PostgreSQLContainer("postgres:18.6");
        }
    }

    @Autowired
    ISecretService service;

    @Autowired
    SecretRepository repository;

    @Test
    void secretCanBeRevealedOnlyOnceAndIsWipedAfter() {
        SecretMetadataResponse created = service.createSecret(new CreateSecretRequest("hello", null, null));
        String id = created.secretId();
        assertThat(service.getSecretMetaData(id)).isEqualTo(created);

        assertThat(service.revealSecret(id, null).secretText()).isEqualTo("hello");
        assertThat(repository.findById(id).orElseThrow().getSecretCiphertext()).isEmpty();
        assertThatThrownBy(() -> service.revealSecret(id, null))
                .isInstanceOf(SecretNotFoundException.class);
    }

    @Test
    void unknownExpiredAndRevealedLookLikeTheSame() {
        Instant now = Instant.now();
        save("dead-expired", now.minus(Duration.ofMinutes(1)), null);
        save("dead-revealed", now.plus(Duration.ofDays(1)), now.minus(Duration.ofMinutes(1)));

        for (String id : new String[]{"dead-unknown", "dead-expired", "dead-revealed"}) {
            assertThatThrownBy(() -> service.getSecretMetaData(id))
                    .isInstanceOf(SecretNotFoundException.class)
                    .hasMessage("Secret not found or no longer available");
            assertThatThrownBy(() -> service.revealSecret(id, null))
                    .isInstanceOf(SecretNotFoundException.class)
                    .hasMessage("Secret not found or no longer available");
        }
    }

    @Test
    void concurrentRevealsYieldExactlyOneSuccess() throws Exception {
        String id = service.createSecret(new CreateSecretRequest("race", null, null)).secretId();
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    try {
                        return "race".equals(service.revealSecret(id, null).secretText());
                    } catch (RuntimeException e) {
                        return false;
                    }
                }));
            }
            start.countDown();
            int successes = 0;
            for (Future<Boolean> result : results) {
                if (result.get(30, TimeUnit.SECONDS)) successes++;
            }
            assertThat(successes).isEqualTo(1);
        }
    }

    @Test
    void protectedSecretIsFlaggedAndHashIsStored() {
        SecretMetadataResponse created = service.createSecret(new CreateSecretRequest("hello", null, "correct horse"));
        assertThat(created.passphraseProtected()).isTrue();
        assertThat(service.getSecretMetaData(created.secretId())).isEqualTo(created);

        Secret stored = repository.findById(created.secretId()).orElseThrow();
        assertThat(stored.getPassphraseHash()).startsWith("$2").isNotEqualTo("correct horse");
        assertThat(stored.getFailedAttempts()).isZero();
    }

    @Test
    void emptyPassphraseMeansUnprotected() {
        for (String passphrase : new String[]{null, ""}) {
            SecretMetadataResponse created = service.createSecret(new CreateSecretRequest("hello", null, passphrase));
            assertThat(created.passphraseProtected()).isFalse();
            assertThat(repository.findById(created.secretId()).orElseThrow().getPassphraseHash()).isNull();
        }
    }

    private String protectedSecret(String passphrase) {
        return service.createSecret(new CreateSecretRequest("hello", null, passphrase)).secretId();
    }

    private static int remainingAfter(Runnable reveal) {
        try {
            reveal.run();
        } catch (InvalidPassphraseException e) {
            return e.getAttemptsRemaining();
        }
        throw new AssertionError("expected InvalidPassphraseException");
    }

    @Test
    void wrongPassphraseCountsDownThenRightOneReveals() {
        String id = protectedSecret("pass");
        assertThat(remainingAfter(() -> service.revealSecret(id, "nope"))).isEqualTo(4);

        assertThat(service.revealSecret(id, "pass").secretText()).isEqualTo("hello");
        Secret stored = repository.findById(id).orElseThrow();
        assertThat(stored.getSecretCiphertext()).isEmpty();
        assertThat(stored.getPassphraseHash()).isNull();
    }

    @Test
    void fiveWrongAttemptsDestroyTheSecret() {
        String id = protectedSecret("pass");
        for (int expected = 4; expected >= 0; expected--) {
            assertThat(remainingAfter(() -> service.revealSecret(id, "nope"))).isEqualTo(expected);
        }
        Secret stored = repository.findById(id).orElseThrow();
        assertThat(stored.getSecretCiphertext()).isEmpty();
        assertThat(stored.getRevealedAt()).isNotNull();
        assertThat(stored.getPassphraseHash()).isNull();
        assertThatThrownBy(() -> service.revealSecret(id, "pass")).isInstanceOf(SecretNotFoundException.class);
    }

    @Test
    void missingPassphraseDoesNotSpendAnAttempt() {
        String id = protectedSecret("pass");
        assertThat(remainingAfter(() -> service.revealSecret(id, null))).isEqualTo(5);
        assertThat(remainingAfter(() -> service.revealSecret(id, ""))).isEqualTo(5);
        assertThat(repository.findById(id).orElseThrow().getFailedAttempts()).isZero();
    }

    @Test
    void passphraseIsExactButUnicodeNormalized() {
        String id = protectedSecret("pass");
        assertThat(remainingAfter(() -> service.revealSecret(id, "pass "))).isEqualTo(4);

        String accented = protectedSecret("café");
        assertThat(service.revealSecret(accented, "café").secretText()).isEqualTo("hello");
    }

    @Test
    void overlongPassphraseOnRevealIsAWrongAttempt() {
        String id = protectedSecret("pass");
        assertThat(remainingAfter(() -> service.revealSecret(id, "a".repeat(73)))).isEqualTo(4);
    }

    @Test
    void decomposedPassphraseNearTheLimitStillMatches() {
        String composed = "é".repeat(30); // 60 bytes; NFD form is 90 bytes
        String id = protectedSecret(composed);
        assertThat(service.revealSecret(id, "é".repeat(30)).secretText()).isEqualTo("hello");
    }

    @Test
    void unprotectedSecretIgnoresPassphrase() {
        String id = service.createSecret(new CreateSecretRequest("hello", null, null)).secretId();
        assertThat(service.revealSecret(id, "anything").secretText()).isEqualTo("hello");
    }

    @Test
    void parallelWrongAttemptsAreCappedAtFive() throws Exception {
        String id = protectedSecret("pass");
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            List<Future<String>> results = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    try {
                        service.revealSecret(id, "nope");
                        return "revealed";
                    } catch (RuntimeException e) {
                        return e.getClass().getSimpleName();
                    }
                }));
            }
            start.countDown();
            List<String> outcomes = new ArrayList<>();
            for (Future<String> result : results) {
                outcomes.add(result.get(60, TimeUnit.SECONDS));
            }
            assertThat(outcomes).filteredOn("InvalidPassphraseException"::equals).hasSize(5);
            assertThat(outcomes).filteredOn("SecretNotFoundException"::equals).hasSize(3);
        }
    }

    @Test
    void ttlIsAppliedOrDefaultsToSevenDays() {
        SecretMetadataResponse custom = service.createSecret(new CreateSecretRequest("hi", 3600L, null));
        assertThat(Duration.between(custom.createdAt(), custom.expiresAt())).isEqualTo(Duration.ofHours(1));

        SecretMetadataResponse byDefault = service.createSecret(new CreateSecretRequest("hi", null, null));
        assertThat(Duration.between(byDefault.createdAt(), byDefault.expiresAt())).isEqualTo(Duration.ofDays(7));
    }

    @Test
    void purgeWipesExpiredContentButKeepsRows() {
        Instant now = Instant.now();
        save("purge-expired", now.minus(Duration.ofMinutes(1)), null);
        save("purge-active", now.plus(Duration.ofDays(4)), null);
        Secret protectedExpired = repository.findById("purge-expired").orElseThrow();
        protectedExpired.setPassphraseHash("$2a$10$abcdefghijklmnopqrstuuabcdefghijklmnopqrstuvwxyz01234");
        repository.save(protectedExpired);

        repository.wipeExpired(now);

        Secret expired = repository.findById("purge-expired").orElseThrow();
        assertThat(expired.getSecretCiphertext()).isEmpty();
        // a leaked hash could be cracked offline long after the secret is gone
        assertThat(expired.getPassphraseHash()).isNull();
        assertThat(expired.getRevealedAt()).isNull();
        assertThat(repository.findById("purge-active").orElseThrow().getSecretCiphertext()).isEqualTo("x");
    }

    private void save(String id, Instant expiresAt, Instant revealedAt) {
        Secret secret = new Secret();
        secret.setId(id);
        secret.setSecretCiphertext("x");
        secret.setKeyVersion(1);
        secret.setCreatedAt(Instant.now().minus(Duration.ofDays(3)));
        secret.setExpiresAt(expiresAt);
        secret.setRevealedAt(revealedAt);
        repository.save(secret);
    }
}
