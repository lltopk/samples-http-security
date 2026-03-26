package org.lltopk.signaturetokenwithprivatekeyafterauth.config;

import lombok.extern.slf4j.Slf4j;
import org.lltopk.signaturetokenwithprivatekeyafterauth.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.security.KeyPair;
import java.util.Base64;

/**
 * Server RSA key pair configuration.
 * The server generates and manages its own key pair.
 * Clients use the server's public key for encryption.
 */
@Slf4j
@Configuration
public class ServerKeyConfig {

    @Value("${server.rsa.private-key:}")
    private String configuredPrivateKey;

    @Value("${server.rsa.public-key:}")
    private String configuredPublicKey;

    private KeyPair serverKeyPair;

    /**
     * Initialize server key pair.
     * If keys are configured in application.yaml, use them.
     * Otherwise, generate a new key pair at startup.
     */
    @Bean
    public KeyPair serverKeyPair() {
        if (configuredPrivateKey != null && !configuredPrivateKey.isEmpty() &&
            configuredPublicKey != null && !configuredPublicKey.isEmpty()) {
            log.info("Using configured RSA key pair from configuration");
            try {
                byte[] privateKeyBytes = Base64.getDecoder().decode(configuredPrivateKey);
                byte[] publicKeyBytes = Base64.getDecoder().decode(configuredPublicKey);
                
                // Reconstruct KeyPair from configured values
                serverKeyPair = new KeyPair(
                    CryptoUtil.getPublicKeyFromBytes(publicKeyBytes),
                    CryptoUtil.getPrivateKeyFromBytes(privateKeyBytes)
                );
                return serverKeyPair;
            } catch (Exception e) {
                log.error("Failed to load configured key pair, generating new one", e);
            }
        }
        
        log.info("Generating new RSA key pair for server");
        serverKeyPair = CryptoUtil.generateKeyPair();
        log.info("Server public key (Base64): {}", 
            Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded()));
        log.warn("Server private key (Base64, keep secure!): {}", 
            Base64.getEncoder().encodeToString(serverKeyPair.getPrivate().getEncoded()));
        log.warn("Save the above private key to application.yaml server.rsa.private-key for production use.");
        
        return serverKeyPair;
    }

    /**
     * Get server's public key as Base64 string
     */
    public String getServerPublicKeyBase64() {
        if (serverKeyPair == null) {
            serverKeyPair();
        }
        return Base64.getEncoder().encodeToString(serverKeyPair.getPublic().getEncoded());
    }

    /**
     * Get server's private key as Base64 string
     */
    public String getServerPrivateKeyBase64() {
        if (serverKeyPair == null) {
            serverKeyPair();
        }
        return Base64.getEncoder().encodeToString(serverKeyPair.getPrivate().getEncoded());
    }
}
