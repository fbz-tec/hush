package com.fbztec.hush.dto;

// optional body: only secrets created with a passphrase need one.
// No size check here: the service counts anything over 72 bytes as a wrong attempt, so the
// user gets the usual "wrong passphrase" answer instead of a vague 400.
public record RevealRequest(String passphrase) {

    // the default record toString would print the passphrase into any log of this request
    @Override
    public String toString() {
        return "RevealRequest[passphrase=" + (passphrase == null ? "null" : "***") + "]";
    }
}
