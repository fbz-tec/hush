package com.fbztec.hush.controller;

import com.fbztec.hush.dto.CreateSecretRequest;
import com.fbztec.hush.dto.RevealRequest;
import com.fbztec.hush.dto.RevealResponse;
import com.fbztec.hush.dto.SecretMetadataResponse;
import com.fbztec.hush.service.ISecretService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping(value = "/secrets", version = "1.0")
public class SecretController {

    private final ISecretService service;

    public SecretController(ISecretService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<SecretMetadataResponse> createSecret(@Valid @RequestBody
                                                                   CreateSecretRequest createSecretRequest) {
        SecretMetadataResponse response = service.createSecret(createSecretRequest);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}").buildAndExpand(response.secretId()).toUri();
        return ResponseEntity.created(location).body(response);
    }

    @GetMapping("/{id}")
    public ResponseEntity<SecretMetadataResponse> getSecretMetaData(@PathVariable String id) {
        SecretMetadataResponse response = service.getSecretMetaData(id);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/{id}/reveal")
    public ResponseEntity<RevealResponse> getSecret(@PathVariable String id,
                                                    @RequestBody(required = false) RevealRequest revealRequest) {
        RevealResponse response = service.revealSecret(id, revealRequest == null ? null : revealRequest.passphrase());
        return ResponseEntity.ok(response);
    }
}
