package org.lltopk.signaturetokenwithprivatekeyafterauth.util;

import lombok.extern.slf4j.Slf4j;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Slf4j
public class PasswordUtil {

    private static final int SALT_LENGTH = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Generate random salt
     * @return Base64 encoded salt
     */
    public static String generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * Hash password with salt using SHA-256
     * @param password plain password
     * @param salt Base64 encoded salt
     * @return hashed password as hex string
     */
    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            
            // Combine password and salt
            byte[] saltBytes = Base64.getDecoder().decode(salt);
            byte[] passwordBytes = password.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            
            // Create combined bytes
            byte[] combined = new byte[passwordBytes.length + saltBytes.length];
            System.arraycopy(passwordBytes, 0, combined, 0, passwordBytes.length);
            System.arraycopy(saltBytes, 0, combined, passwordBytes.length, saltBytes.length);
            
            // Hash
            byte[] hash = md.digest(combined);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("Password hashing error", e);
            throw new RuntimeException("Password hashing failed", e);
        }
    }

    /**
     * Verify password against stored hash
     * @param password plain password
     * @param salt Base64 encoded salt
     * @param storedHash stored hash to compare
     * @return true if password matches
     */
    public static boolean verifyPassword(String password, String salt, String storedHash) {
        String hashedPassword = hashPassword(password, salt);
        return hashedHashEquals(storedHash, hashedPassword);
    }

    /**
     * Constant-time hash comparison to prevent timing attacks
     */
    private static boolean hashedHashEquals(String hash1, String hash2) {
        if (hash1.length() != hash2.length()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < hash1.length(); i++) {
            result |= hash1.charAt(i) ^ hash2.charAt(i);
        }
        return result == 0;
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
}
