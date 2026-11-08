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

    @Scheduled(fixedDelay = 3600_000)
    public void purgeExpiredSecrets() {
        int wiped = secretRepository.wipeExpired(Instant.now());
        log.info("Wiped {} expired secrets", wiped);
    }
}
