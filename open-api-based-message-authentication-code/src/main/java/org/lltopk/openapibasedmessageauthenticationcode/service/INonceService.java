package org.lltopk.openapibasedmessageauthenticationcode.service;

public interface INonceService {
    Boolean checkAndSave(String appKey, String nonce);
}
