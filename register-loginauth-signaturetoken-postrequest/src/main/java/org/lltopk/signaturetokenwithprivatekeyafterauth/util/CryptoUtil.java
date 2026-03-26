package org.lltopk.signaturetokenwithprivatekeyafterauth.util;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class CryptoUtil {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_TRANSFORMATION = "RSA/ECB/PKCS1Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int KEY_SIZE = 2048;

    /**
     * Generate RSA key pair
     * @return KeyPair containing public and private keys
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate key pair", e);
            throw new RuntimeException("Failed to generate key pair", e);
        }
    }

    /**
     * Encrypt data using public key
     * @param publicKey public key bytes
     * @param data data to encrypt
     * @return encrypted data as Base64 string
     */
    public static String encryptByPublicKey(byte[] publicKey, byte[] data) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            
            byte[] encryptedData = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            log.error("Encryption error", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt data using private key
     * @param privateKey Base64 encoded private key
     * @param encryptedData Base64 encoded encrypted data
     * @return decrypted data as string
     */
    public static String decryptByPrivateKey(String privateKey, String encryptedData) {
        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);
            
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privKey);
            
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);
        } catch (Exception e) {
            log.error("Decryption error", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }

    /**
     * Sign data using private key
     * @param privateKey private key bytes
     * @param data data to sign
     * @return signature as Base64 string
     */
    public static String signByPrivateKey(byte[] privateKey, byte[] data) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);
            
            Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
            signature.initSign(privKey);
            signature.update(data);
            
            byte[] signBytes = signature.sign();
            return Base64.getEncoder().encodeToString(signBytes);
        } catch (Exception e) {
            log.error("Signing error", e);
            throw new RuntimeException("Signing failed", e);
        }
    }

    /**
     * Verify signature using public key
     * @param publicKey public key bytes
     * @param data original data
     * @param signature signature bytes
     * @return true if signature is valid
     */
    public static boolean verifySignature(byte[] publicKey, byte[] data, byte[] signature) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            PublicKey pubKey = keyFactory.generatePublic(keySpec);
            
            Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
            sig.initVerify(pubKey);
            sig.update(data);
            
            return sig.verify(signature);
        } catch (Exception e) {
            log.error("Signature verification error", e);
            return false;
        }
    }

    /**
     * Generate SHA256 digest
     * @param data input data
     * @return digest as hex string
     */
    public static String sha256Digest(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("Digest error", e);
            throw new RuntimeException("Digest failed", e);
        }
    }

    /**
     * Convert byte array to hex string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    /**
     * Get public key from key pair as Base64 string
     */
    public static String getPublicKeyString(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    }

    /**
     * Get private key from key pair as Base64 string
     */
    public static String getPrivateKeyString(KeyPair keyPair) {
        return Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
    }

    /**
     * Get PublicKey object from bytes
     */
    public static PublicKey getPublicKeyFromBytes(byte[] publicKeyBytes) {
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            log.error("Failed to get public key from bytes", e);
            throw new RuntimeException("Failed to get public key from bytes", e);
        }
    }

    /**
     * Get PrivateKey object from bytes
     */
    public static PrivateKey getPrivateKeyFromBytes(byte[] privateKeyBytes) {
        try {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            log.error("Failed to get private key from bytes", e);
            throw new RuntimeException("Failed to get private key from bytes", e);
        }
    }

    /**
     * Encrypt data using public key object
     */
    public static String encryptByPublicKey(PublicKey publicKey, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedData = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedData);
        } catch (Exception e) {
            log.error("Encryption error", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    /**
     * Decrypt data using private key object
     */
    public static String decryptByPrivateKey(PrivateKey privateKey, String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            return new String(decryptedData);
        } catch (Exception e) {
            log.error("Decryption error", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }
}
