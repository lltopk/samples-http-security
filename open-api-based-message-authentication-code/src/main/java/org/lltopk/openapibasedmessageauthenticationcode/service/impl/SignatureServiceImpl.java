package org.lltopk.openapibasedmessageauthenticationcode.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.lltopk.openapibasedmessageauthenticationcode.service.ISignatureService;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
@Service
@Slf4j
public class SignatureServiceImpl implements ISignatureService {

    @Override
    public String sign(String requestParams, String method, String body, String secret) {
        String stringToSign = MessageFormat.format("{0}&{1}&{2}", requestParams,method,body);
        byte[] hash;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(
                    secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(keySpec);
            hash = mac.doFinal(
                    stringToSign.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return bytesToHex(hash);
    }

    @Override
    public boolean verifySignature(String expectedSign, String signature) {
        return MessageDigest.isEqual(expectedSign.getBytes(), signature.getBytes());
    }

    private String bytesToHex(byte[] hash) {
        return null;
    }
}
