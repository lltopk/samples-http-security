package org.lltopk.openapibasedmessageauthenticationcode.service;

public interface ISignatureService {
    String sign(String requestParams,String method,String body, String secret);

    boolean verifySignature(String expectedSign, String signature);
}
