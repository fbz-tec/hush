package com.fbztec.hush.scheduler;

import com.fbztec.hush.repository.SecretRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
public class PurgeScheduler {
    private static final Logger log = LoggerFactory.getLogger(PurgeScheduler.class);

    private final SecretRepository secretRepository;

    public PurgeScheduler(SecretRepository secretRepository) {
        this.secretRepository = secretRepository;
    }

    // every minute: the shortest TTL is 1 minute, an expired secret must not linger on disk
    @Scheduled(fixedDelay = 60_000)
    public void purgeExpiredSecrets() {
        int deleted = secretRepository.deleteExpired(Instant.now());
        if (deleted > 0) {
            log.info("Deleted {} expired secrets", deleted);
        }
    }
}
