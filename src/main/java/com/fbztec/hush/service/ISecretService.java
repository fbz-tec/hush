package com.fbztec.hush.service;

import com.fbztec.hush.dto.CreateSecretRequest;
import com.fbztec.hush.dto.RevealResponse;
import com.fbztec.hush.dto.SecretMetadataResponse;

public interface ISecretService {

    SecretMetadataResponse createSecret(CreateSecretRequest createSecretRequest);

    SecretMetadataResponse getSecretMetaData(String secretId);

    RevealResponse revealSecret(String secretId, String passphrase);
}
