package org.lltopk.openapibasedmessageauthenticationcode.service.impl;

import lombok.extern.slf4j.Slf4j;
import org.lltopk.openapibasedmessageauthenticationcode.service.INonceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Slf4j
public class NonceServiceImpl implements INonceService {
    Map<String, String> nonceCache = new ConcurrentHashMap<>();
    @Autowired
    private StringRedisTemplate stringRedisTemplate;
    private Integer timestampExpireMinutes = 5;
    @Override
    public Boolean checkAndSave(String appKey, String nonce) {
        //维度要细化到具体哪个app(appKey)
        String cacheKey = appKey + ":" + nonce;
        long expireAt = System.currentTimeMillis()
                + timestampExpireMinutes * 60 * 1000L;
        // 返回是个布尔值, 若不存在, 则放入缓存并返回true
        return stringRedisTemplate.opsForValue().setIfAbsent(cacheKey,nonce, Duration.of(expireAt, ChronoUnit.MILLIS));
    }
}
