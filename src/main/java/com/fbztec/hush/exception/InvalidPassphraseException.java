package com.fbztec.hush.exception;

public class InvalidPassphraseException extends RuntimeException {

    private final int attemptsRemaining;

    public InvalidPassphraseException(int attemptsRemaining) {
        super("Incorrect passphrase");
        this.attemptsRemaining = attemptsRemaining;
    }

    public int getAttemptsRemaining() {
        return attemptsRemaining;
    }
}
