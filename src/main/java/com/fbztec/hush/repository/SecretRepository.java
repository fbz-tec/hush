package com.fbztec.hush.repository;

import com.fbztec.hush.entity.Secret;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

public interface SecretRepository extends JpaRepository<Secret, String> {

    // past expiry nothing is kept: the whole row goes, revealed ones included
    @Modifying
    @Transactional
    @Query("delete from Secret s where s.expiresAt < :now")
    int deleteExpired(Instant now);

    // cheap check without row lock or entity loading: probes for dead ids never queue on a lock
    boolean existsByIdAndRevealedAtIsNullAndExpiresAtAfter(String secretId, Instant now);

    // row lock: a concurrent reveal waits, then sees revealedAt set
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<Secret> findLockedById(String secretId);
}
