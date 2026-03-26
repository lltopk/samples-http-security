package org.lltopk.signaturetokenwithprivatekeyafterauth.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

/**
 * Redis-based nonce service for replay attack prevention
 * Stores nonce in Redis with TTL for automatic expiration
 */
@Slf4j
@Service
public class RedisNonceService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${security.replay-prevention.nonce-expire-seconds:300}")
    private int nonceExpireSeconds;

    private static final String NONCE_KEY_PREFIX = "nonce:";

    public RedisNonceService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Check if nonce exists (already used)
     * @param nonce the nonce value
     * @return true if nonce exists (already used), false if nonce is new
     */
    public boolean isNonceExists(String nonce) {
        String key = NONCE_KEY_PREFIX + nonce;
        Boolean exists = redisTemplate.hasKey(key);
        return exists != null && exists;
    }

    /**
     * Save nonce to Redis with TTL
     * @param nonce the nonce value
     * @param timestamp the timestamp when nonce was created
     * @return true if saved successfully
     */
    public boolean saveNonce(String nonce, long timestamp) {
        String key = NONCE_KEY_PREFIX + nonce;
        try {
            redisTemplate.opsForValue().set(key, timestamp, nonceExpireSeconds, TimeUnit.SECONDS);
            log.debug("Nonce saved to Redis: {}, expire in {} seconds", nonce, nonceExpireSeconds);
            return true;
        } catch (Exception e) {
            log.error("Failed to save nonce to Redis: {}", nonce, e);
            return false;
        }
    }

    /**
     * Delete nonce (if needed)
     * @param nonce the nonce value
     */
    public void deleteNonce(String nonce) {
        String key = NONCE_KEY_PREFIX + nonce;
        redisTemplate.delete(key);
    }

    /**
     * Get nonce timestamp (for debugging)
     * @param nonce the nonce value
     * @return timestamp or null if not found
     */
    public Long getNonceTimestamp(String nonce) {
        String key = NONCE_KEY_PREFIX + nonce;
        Object value = redisTemplate.opsForValue().get(key);
        if (value instanceof Long) {
            return (Long) value;
        }
        return null;
    }
}
